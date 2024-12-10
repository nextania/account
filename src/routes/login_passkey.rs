use actix_web::{
    web::{self, Data},
    Responder,
};
use dashmap::DashMap;
use jsonwebtoken::{encode, EncodingKey, Header};
use lazy_static::lazy_static;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use webauthn_rs::{
    prelude::{
        DiscoverableAuthentication, DiscoverableKey, PublicKeyCredential, RequestChallengeResponse,
    },
    Webauthn,
};

use crate::{
    authenticate::UserJwt,
    constants::{LONG_SESSION, SHORT_SESSION},
    database::{self, passkey::get_collection, session::Session},
    environment::JWT_SECRET,
    errors::{Error, Result},
    utilities::{generate_continue_token_long, get_time_millis, get_time_secs},
};

use super::login::{ActiveEscalation, ACTIVE_ESCALATIONS};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "stage")]
pub enum Login {
    BeginLogin {
        escalate: bool,
        // req'd if escalating an existing session
        token: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    FinishLogin {
        message: PublicKeyCredential,
        continue_token: String,
        persist: Option<bool>,
        friendly_name: Option<String>,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum LoginResponse {
    #[serde(rename_all = "camelCase")]
    BeginLogin {
        continue_token: String,
        message: RequestChallengeResponse,
    },
    FinishLogin {
        token: String,
    },
}

pub struct PendingLogin {
    pub time: u64,
    pub data: DiscoverableAuthentication,
    pub existing_session: Option<Session>,
}

lazy_static! {
    pub static ref PENDING_LOGINS: DashMap<String, PendingLogin> = DashMap::new();
}

pub async fn handle(login: web::Json<Login>, webauthn: Data<Webauthn>) -> Result<impl Responder> {
    let login = login.into_inner();
    match login {
        Login::BeginLogin { escalate, token } => {
            let existing_session = if escalate {
                let Some(token) = token else {
                    return Err(Error::MissingToken);
                };
                let collection = crate::database::session::get_collection();
                let session = collection
                    .find_one(doc! {
                        "token": token.clone()
                    })
                    .await?
                    .ok_or(Error::SessionExpired)?;
                Some(session)
            } else {
                None
            };
            let (rcr, auth_state) = webauthn.start_discoverable_authentication()?;
            let continue_token = generate_continue_token_long();
            PENDING_LOGINS.insert(
                continue_token.clone(),
                PendingLogin {
                    time: get_time_secs(),
                    data: auth_state,
                    existing_session,
                },
            );
            Ok(web::Json(LoginResponse::BeginLogin {
                continue_token,
                message: rcr,
            }))
        }
        Login::FinishLogin {
            message,
            continue_token,
            persist,
            friendly_name,
        } => {
            let pending_login = PENDING_LOGINS.get(&continue_token);
            let pending_login = match pending_login {
                Some(pending_login) => pending_login,
                None => return Err(Error::SessionExpired),
            };
            if get_time_secs() - pending_login.time > 3600 {
                drop(pending_login);
                PENDING_LOGINS.remove(&continue_token);
                return Err(Error::SessionExpired);
            }
            let passkey = get_collection()
                .find_one(doc! {
                    "credential_id": &message.id
                })
                .await?
                .ok_or(Error::CredentialError)?;
            webauthn.finish_discoverable_authentication(
                &message,
                pending_login.data.clone(),
                &[DiscoverableKey::from(passkey.credential)],
            )?;
            let user = database::user::get_collection()
                .find_one(doc! {
                    "id": passkey.user_id.clone()
                })
                .await?
                .ok_or(Error::CredentialError)?;
            if let Some(s) = &pending_login.existing_session {
                if user.id != s.user_id {
                    return Err(Error::UserMismatch);
                }
            }
            let persist = persist.unwrap_or(false);
            let millis = get_time_millis();
            let expires_at = if persist {
                millis + LONG_SESSION
            } else {
                millis + SHORT_SESSION
            };
            let token = encode(
                &Header::default(),
                &UserJwt {
                    id: user.id.clone(),
                    issued_at: millis,
                    expires_at,
                },
                &EncodingKey::from_secret(JWT_SECRET.as_ref()),
            )
            .expect("Unexpected error: failed to encode token");
            if let Some(existing_session) = pending_login.existing_session.clone() {
                ACTIVE_ESCALATIONS.insert(
                    token.clone(),
                    ActiveEscalation {
                        session_id: existing_session.id.clone(),
                        time: get_time_secs(),
                        token: token.clone(),
                        user_id: user.id.clone(),
                    },
                );
            } else {
                let sid = Ulid::new().to_string();
                let session = Session {
                    id: sid,
                    token: token.clone(),
                    friendly_name: friendly_name.unwrap_or("Unknown".to_owned()),
                    user_id: user.id.clone(),
                };
                let sessions = crate::database::session::get_collection();
                sessions.insert_one(session).await?;
            }
            drop(pending_login);
            PENDING_LOGINS.remove(&continue_token);
            Ok(web::Json(LoginResponse::FinishLogin { token }))
        }
    }
}
