use actix_web::{web::{self, Data}, Responder};
use dashmap::DashMap;
use jsonwebtoken::{encode, EncodingKey, Header};
use lazy_static::lazy_static;
use mongodb::bson::{self, doc, Binary};
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use webauthn_rs::{prelude::{PasskeyAuthentication, PublicKeyCredential, RequestChallengeResponse}, Webauthn};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    authenticate::UserJwt, constants::{LONG_SESSION, SHORT_SESSION}, database::{self, passkey::get_collection, session::Session}, environment::JWT_SECRET, errors::{Error, Result}, utilities::generate_continue_token_long
};

use super::login::{ActiveEscalation, ACTIVE_ESCALATIONS};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", tag = "stage")]
#[repr(i8)]
pub enum Login {
    BeginLogin {
        escalate: bool,
        // req'd if escalating an existing session
        token: Option<String>
    } = 1,
    FinishLogin {
        message: PublicKeyCredential,
        continue_token: String,
        persist: Option<bool>,
        friendly_name: Option<String>,
    } = 2,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", tag = "stage")]
#[repr(i8)]
pub enum LoginResponse {
    BeginLogin {
        continue_token: String,
        message: RequestChallengeResponse,
    } = 1,
    FinishLogin {
        token: String,
    } = 2,
}


pub struct PendingLogin {
    pub time: u64,
    pub data: PasskeyAuthentication,
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
                    .await?.ok_or(Error::SessionExpired)?;
                Some(session)
            } else {
                None
            };
            let (rcr, auth_state) = webauthn
                .start_passkey_authentication(&[])?;
            let continue_token = generate_continue_token_long();
            let duration = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Unexpected error: time went backwards");
            PENDING_LOGINS.insert(continue_token.clone(), PendingLogin {
                time: duration.as_secs(),
                data: auth_state,
                existing_session,
            });
            Ok(web::Json(LoginResponse::BeginLogin {
                continue_token,
                message: rcr,
            }))
        }
        Login::FinishLogin { message, continue_token, persist, friendly_name } => {
            let pending_login = PENDING_LOGINS.get(&continue_token);
            let pending_login = match pending_login {
                Some(pending_login) => pending_login,
                None => return Err(Error::SessionExpired),
            };
            let duration = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Unexpected error: time went backwards");
            if duration.as_secs() - pending_login.time > 3600 {
                drop(pending_login);
                PENDING_LOGINS.remove(&continue_token);
                return Err(Error::SessionExpired);
            }
            let auth_result = webauthn
                .finish_passkey_authentication(&message, &pending_login.data)?;
            let credential_id = auth_result.cred_id().as_ref();
            let bin = Binary {
                subtype: bson::spec::BinarySubtype::Generic,
                bytes: credential_id.to_vec(),
            };
            let passkey = get_collection()
                .find_one(doc! {
                    "credential_id": bin
                })
                .await?.ok_or(Error::UserNotFound)?;
            let user = database::user::get_collection()
                .find_one(doc! {
                    "id": passkey.user_id.clone()
                })
                .await?.ok_or(Error::UserNotFound)?;
            if let Some(s) = &pending_login.existing_session {
                if user.id != s.user_id {
                    return Err(Error::UserMismatch);
                }
            }
            let persist = persist.unwrap_or(false);
            let millis = duration.as_millis();
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
                        time: duration.as_secs(),
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
            Ok(web::Json(LoginResponse::FinishLogin {
                token,
            }))
        }
    }
}
