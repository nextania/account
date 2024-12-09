use actix_web::{web, Responder};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64, Engine};
use dashmap::DashMap;
use jsonwebtoken::{encode, EncodingKey, Header};
use lazy_static::lazy_static;
use mongodb::bson::doc;
use opaque_ke::{CredentialFinalization, CredentialRequest, ServerLogin};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};
use ulid::Ulid;

use crate::{
    authenticate::UserJwt,
    constants::{LONG_SESSION, SHORT_SESSION},
    database::{self, session::Session, user::User},
    environment::{JWT_SECRET, SERVICE_NAME},
    errors::{Error, Result},
    opaque::{begin_login, finish_login, Default},
    utilities::{generate_continue_token_long, get_time_millis, get_time_secs},
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "stage")]
pub enum Login {
    BeginLogin {
        email: String,
        message: String,

        escalate: bool,
        // req'd if escalating an existing session
        token: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    FinishLogin {
        message: String,
        continue_token: String,
        persist: Option<bool>,
        friendly_name: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    Mfa {
        code: String,
        continue_token: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum LoginResponse {
    #[serde(rename_all = "camelCase")]
    BeginLogin {
        continue_token: String,
        message: String,
    },
    #[serde(rename_all = "camelCase")]
    FinishLogin {
        mfa_enabled: bool,
        continue_token: Option<String>,
        token: Option<String>,
    },
    Mfa {
        token: String,
    },
}

pub struct PendingLogin {
    pub time: u64,
    pub user: User,
    pub email: String,
    pub data: ServerLogin<Default>,
    pub existing_session: Option<Session>,
}

pub struct PendingMfa {
    pub time: u64,
    pub user: User,
    pub email: String,
    pub persist: Option<bool>,
    pub friendly_name: Option<String>,
    pub existing_session: Option<Session>,
}
pub struct ActiveEscalation {
    pub session_id: String,
    pub user_id: String,
    pub time: u64,
    pub token: String,
}

lazy_static! {
    pub static ref PENDING_LOGINS: DashMap<String, PendingLogin> = DashMap::new();
    pub static ref PENDING_MFAS: DashMap<String, PendingMfa> = DashMap::new();
    pub static ref ACTIVE_ESCALATIONS: DashMap<String, ActiveEscalation> = DashMap::new();
}

pub async fn handle(login: web::Json<Login>) -> Result<impl Responder> {
    let login = login.into_inner();
    match login {
        Login::BeginLogin {
            email,
            message,
            escalate,
            token,
        } => {
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
            let collection = crate::database::user::get_collection();
            let user = collection
                .find_one(doc! {
                    "email": email.clone()
                })
                .await?;
            let password_data = user.clone().map(|x| x.password_data);
            let (data, state) = begin_login(
                email.clone(),
                password_data,
                CredentialRequest::deserialize(&BASE64.decode(message)?)?,
            )
            .await?;
            let continue_token = generate_continue_token_long();
            if let Some(user) = user {
                let pending_login = PendingLogin {
                    time: get_time_secs(),
                    user,
                    email,
                    data: state,
                    existing_session,
                };
                PENDING_LOGINS.insert(continue_token.clone(), pending_login);
            }
            Ok(web::Json(LoginResponse::BeginLogin {
                continue_token,
                message: BASE64.encode(data),
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
            finish_login(
                pending_login.data.clone(),
                CredentialFinalization::deserialize(&BASE64.decode(message)?)?,
            )?;
            let user = pending_login.user.clone();
            if user.mfa_enabled {
                let new_continue_token = generate_continue_token_long();
                let mfa_session = PendingMfa {
                    time: get_time_secs(),
                    user,
                    email: pending_login.email.clone(),
                    persist,
                    friendly_name,
                    existing_session: pending_login.existing_session.clone(),
                };
                PENDING_MFAS.insert(new_continue_token.clone(), mfa_session);
                drop(pending_login);
                PENDING_LOGINS.remove(&continue_token);
                Ok(web::Json(LoginResponse::FinishLogin {
                    mfa_enabled: true,
                    continue_token: Some(new_continue_token),
                    token: None,
                }))
            } else {
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
                Ok(web::Json(LoginResponse::FinishLogin {
                    token: Some(token),
                    continue_token: None,
                    mfa_enabled: false,
                }))
            }
        }
        Login::Mfa {
            code,
            continue_token,
        } => {
            let mfa_session = PENDING_MFAS.get(&continue_token);
            let Some(mfa_session) = mfa_session else {
                return Err(Error::SessionExpired);
            };
            if get_time_secs() - mfa_session.time > 3600 {
                drop(mfa_session);
                PENDING_MFAS.remove(&continue_token);
                return Err(Error::SessionExpired);
            }

            let secret = Secret::Encoded(mfa_session.user.mfa_secret.clone().unwrap());
            let totp = TOTP::new(
                Algorithm::SHA256,
                8,
                1,
                30,
                secret.to_bytes().unwrap(),
                Some(SERVICE_NAME.to_string()),
                mfa_session.email.clone(),
            )
            .expect("Unexpected error: could not create TOTP instance");
            let current_code = totp
                .generate_current()
                .expect("Unexpected error: failed to generate code");
            if current_code != code {
                let codes = database::code::get_collection();
                let code = codes
                    .find_one(doc! {
                        "code": code,
                        "user_id": &mfa_session.user.id
                    })
                    .await?;
                let Some(code) = code else {
                    return Err(Error::IncorrectCode);
                };
                codes
                    .delete_one(doc! {
                        "code": code.code
                    })
                    .await?;
            }
            let persist = mfa_session.persist.unwrap_or(false);
            let millis = get_time_millis();
            let expires_at = if persist {
                millis + 2592000000
            } else {
                millis + 604800000
            };
            let id = mfa_session.user.id.clone();
            let token = encode(
                &Header::default(),
                &UserJwt {
                    id: id.clone(),
                    issued_at: millis,
                    expires_at,
                },
                &EncodingKey::from_secret(JWT_SECRET.as_ref()),
            )
            .expect("Unexpected error: failed to encode token");
            if let Some(existing_session) = mfa_session.existing_session.clone() {
                ACTIVE_ESCALATIONS.insert(
                    token.clone(),
                    ActiveEscalation {
                        session_id: existing_session.id.clone(),
                        time: get_time_secs(),
                        token: token.clone(),
                        user_id: id.clone(),
                    },
                );
            } else {
                let sid = ulid::Ulid::new().to_string();
                let session = Session {
                    id: sid,
                    token: token.clone(),
                    friendly_name: mfa_session
                        .friendly_name
                        .clone()
                        .unwrap_or("Unknown".to_owned()),
                    user_id: id,
                };
                let sessions = crate::database::session::get_collection();
                sessions.insert_one(session).await?;
            }
            drop(mfa_session);
            PENDING_MFAS.remove(&continue_token);
            Ok(web::Json(LoginResponse::Mfa { token }))
        }
    }
}
