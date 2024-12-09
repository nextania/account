use actix_web::{web, Responder};
use async_std::task;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64, Engine};
use dashmap::DashMap;
use jsonwebtoken::{encode, EncodingKey, Header};
use lazy_static::lazy_static;
use mongodb::bson::doc;
use opaque_ke::{RegistrationRequest, RegistrationUpload};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    authenticate::UserJwt,
    constants::{LONG_SESSION, SHORT_SESSION},
    database::{profile::UserProfile, session::Session, user::User},
    environment::{JWT_SECRET, SMTP_ENABLED},
    errors::{Error, Result},
    opaque::{begin_registration, finish_registration},
    utilities::{
        generate_codes, generate_continue_token_long, get_time_millis, get_time_secs,
        send_in_use_email, send_verify_email, validate_captcha, EMAIL_RE, USERNAME_RE,
    },
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "stage")]
pub enum Register {
    #[serde(rename_all = "camelCase")]
    VerifyEmail {
        // stage 1: email & captcha
        email: String,
        captcha_token: String,
    },
    #[serde(rename_all = "camelCase")]
    BeginRegistration {
        // stage 2: email token, password registration begin
        email_token: String,
        // opaque data
        message: String,
    },
    #[serde(rename_all = "camelCase")]
    Register {
        // stage 3: password registration
        // opaque data 2
        continue_token: String,
        message: String,
        friendly_name: Option<String>,
        username: String,
        persist: Option<bool>,
        display_name: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum RegisterResponse {
    #[serde(rename_all = "camelCase")]
    VerifyEmail {
        // if email server disabled, then directly send continue token
        email_enabled: bool,
        email_token: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    BeginRegistration {
        continue_token: String,
        message: String,
        // opaque data
    },
    Register {
        token: String,
        // opaque data 2
    },
}

pub struct PendingRegister {
    pub time: u64,
    pub email: String,
}

lazy_static! {
    pub static ref PENDING_REGISTERS1: DashMap<String, PendingRegister> = DashMap::new();
    pub static ref PENDING_REGISTERS2: DashMap<String, PendingRegister> = DashMap::new();
}

pub async fn handle(register: web::Json<Register>) -> Result<impl Responder> {
    let register = register.into_inner();
    match register {
        Register::VerifyEmail {
            email,
            captcha_token,
        } => {
            validate_captcha(captcha_token).await?;
            if !EMAIL_RE.is_match(email.trim()) {
                return Err(Error::InvalidEmail);
            }
            let collection = crate::database::user::get_collection();
            let user = collection
                .find_one(doc! {
                    "email": email.clone()
                })
                .await?;
            if *SMTP_ENABLED {
                if user.is_some() {
                    task::spawn(send_in_use_email(email.clone()));
                } else {
                    let token = generate_codes().first().unwrap().to_string();
                    task::spawn(send_verify_email(email.clone(), token.clone()));
                    PENDING_REGISTERS1.insert(
                        token,
                        PendingRegister {
                            time: get_time_secs(),
                            email,
                        },
                    );
                }
                Ok(web::Json(RegisterResponse::VerifyEmail {
                    email_enabled: true,
                    email_token: None,
                }))
            } else {
                if user.is_some() {
                    return Err(Error::UserExists);
                }
                let token = generate_continue_token_long();
                PENDING_REGISTERS1.insert(
                    token.clone(),
                    PendingRegister {
                        time: get_time_secs(),
                        email,
                    },
                );
                Ok(web::Json(RegisterResponse::VerifyEmail {
                    email_enabled: false,
                    email_token: Some(token),
                }))
            }
        }
        Register::BeginRegistration { email_token: token, message } => {
            if let Some(session) = PENDING_REGISTERS1.get(&token) {
                let time = get_time_secs();
                if time - session.time > 600 {
                    drop(session);
                    PENDING_REGISTERS1.remove(&token);
                    return Err(Error::SessionExpired);
                }
                let email = session.email.clone();
                let result = begin_registration(
                    email.clone(),
                    RegistrationRequest::deserialize(&BASE64.decode(message)?)?,
                )
                .await?;
                drop(session);
                PENDING_REGISTERS1.remove(&token);
                let continue_token = generate_continue_token_long();
                PENDING_REGISTERS2.insert(
                    continue_token.clone(),
                    PendingRegister {
                        time,
                        email,
                    },
                );
                return Ok(web::Json(RegisterResponse::BeginRegistration {
                    continue_token,
                    message: BASE64.encode(result),
                }));
            }
            Err(Error::SessionExpired)
        }
        Register::Register {
            friendly_name,
            username,
            persist,
            display_name,
            message,
            continue_token: token,
        } => {
            if let Some(session) = PENDING_REGISTERS2.get(&token) {
                if get_time_secs() - session.time > 600 {
                    PENDING_REGISTERS2.remove(&token);
                    return Err(Error::SessionExpired);
                }
                if display_name.trim().len() > 64 {
                    return Err(Error::DisplayNameTooLong);
                }
                if !USERNAME_RE.is_match(username.trim()) {
                    return Err(Error::InvalidUsername);
                }
                let collection = crate::database::user::get_collection();
                let user = collection
                    .find_one(doc! {
                        "username": username.trim()
                    })
                    .await?;
                if user.is_some() {
                    return Err(Error::UsernameAlreadyTaken);
                }
                let password_data =
                    finish_registration(RegistrationUpload::deserialize(&BASE64.decode(message)?)?)?;
                let user_id = Ulid::new().to_string();
                let user_document = User {
                    id: user_id.clone(),
                    mfa_enabled: false,
                    mfa_secret: None,
                    username: username.trim().to_string(),
                    email: session.email.trim().to_string(),
                    password_data,
                    platform_administrator: false,
                };
                let profile_document = UserProfile {
                    id: user_id.clone(),
                    display_name: display_name.trim().to_string(),
                    description: String::new(),
                    website: String::new(),
                    avatar: None,
                };
                let user_collection = crate::database::user::get_collection();
                user_collection.insert_one(user_document).await?;
                let profile_collection = crate::database::profile::get_collection();
                profile_collection.insert_one(profile_document).await?;
                let persist = persist.unwrap_or(false);
                let millis = get_time_millis();
                let expires_at = if persist {
                    millis + LONG_SESSION
                } else {
                    millis + SHORT_SESSION
                };
                let jwt_object = UserJwt {
                    id: user_id.clone(),
                    issued_at: millis,
                    expires_at,
                };
                let token = encode(
                    &Header::default(),
                    &jwt_object,
                    &EncodingKey::from_secret(JWT_SECRET.as_ref()),
                )
                .expect("Unexpected error: failed to encode token");
                let sid = ulid::Ulid::new().to_string();
                let session = Session {
                    id: sid,
                    token: token.clone(),
                    friendly_name: friendly_name.unwrap_or("Unknown".to_owned()),
                    user_id,
                };
                let sessions = crate::database::session::get_collection();
                sessions.insert_one(session).await?;
                PENDING_REGISTERS2.remove(&token);
                return Ok(web::Json(RegisterResponse::Register { token }));
            }
            Err(Error::SessionExpired)
        }
    }
}
