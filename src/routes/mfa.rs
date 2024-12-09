use actix_web::{web, Responder};
use dashmap::DashMap;
use lazy_static::lazy_static;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use totp_rs::{Secret, TOTP};

use crate::{
    authenticate::Authenticate,
    database::{
        code,
        user::{self, User},
    },
    environment::SERVICE_NAME,
    errors::{Error, Result},
    utilities::{generate_codes, get_time_secs, random_number, validate_escalation},
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "stage")]
pub enum Mfa {
    #[serde(rename_all = "camelCase")]
    Toggle { escalation_token: String },
    #[serde(rename_all = "camelCase")]
    EnableVerify {
        code: String,
        continue_token: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum MfaResponse {
    #[serde(rename_all = "camelCase")]
    Enable {
        continue_token: String,
        qr: String,
        secret: String,
        codes: Vec<String>,
    },
    Disable {},
    EnableVerify {},
}

pub struct PendingMfaSetup {
    pub totp: TOTP,
    pub secret: String,
    pub time: u64,
    pub user: User,
}
lazy_static! {
    pub static ref PENDING_MFA_SETUPS: DashMap<String, PendingMfaSetup> = DashMap::new();
}

pub async fn handle(
    jwt: web::ReqData<Result<Authenticate>>,
    mfa: web::Json<Mfa>,
) -> Result<impl Responder> {
    let jwt = jwt.into_inner()?;
    let mfa = mfa.into_inner();
    match mfa {
        Mfa::Toggle { escalation_token } => {
            validate_escalation(escalation_token, jwt.jwt).await?;
            let user = user::get_collection()
                .find_one(doc! {"id": jwt.jwt_content.id})
                .await?
                .ok_or(Error::DatabaseError)?;
            if user.mfa_enabled {
                user::get_collection()
                    .update_one(
                        doc! {
                            "id": user.id.clone(),
                        },
                        doc! {
                            "$set": {
                                "mfa_enabled": false,
                                "mfa_secret": None::<String>
                            }
                        },
                    )
                    .await?;
                code::get_collection()
                    .delete_many(doc! {
                        "user_id": user.id.clone()
                    })
                    .await?;
                Ok(web::Json(MfaResponse::Disable {}))
            } else {
                let secret = random_number(160);
                let totp = TOTP::new(
                    totp_rs::Algorithm::SHA256,
                    8,
                    1,
                    30,
                    secret.clone(),
                    Some(SERVICE_NAME.to_string()),
                    user.username.clone(),
                )
                .expect("Unexpected error: failed to initiate TOTP");
                let qr = totp
                    .get_qr_base64()
                    .expect("Unexpected error: failed to generate QR code");
                let continue_token = ulid::Ulid::new().to_string();
                let code = Secret::Raw(secret.to_vec()).to_encoded().to_string();
                let session = PendingMfaSetup {
                    time: get_time_secs(),
                    user,
                    secret: code.clone(),
                    totp,
                };
                PENDING_MFA_SETUPS.insert(continue_token.clone(), session);
                let codes = generate_codes();
                Ok(web::Json(MfaResponse::Enable {
                    continue_token,
                    qr,
                    secret: code,
                    codes,
                }))
            }
        }
        Mfa::EnableVerify {
            code,
            continue_token,
        } => {
            let enable_session = PENDING_MFA_SETUPS.get(&continue_token);
            if let Some(enable_session) = enable_session {
                if get_time_secs() - enable_session.time > 3600 {
                    drop(enable_session);
                    PENDING_MFA_SETUPS.remove(&continue_token);
                    return Err(Error::SessionExpired);
                }
                let current = enable_session
                    .totp
                    .generate_current()
                    .expect("Unexpected error: failed to generate code");
                if current != code {
                    return Err(Error::IncorrectCode);
                }
                let collection = user::get_collection();
                collection
                    .update_one(
                        doc! {
                            "id": enable_session.user.id.clone(),
                        },
                        doc! {
                            "$set": {
                                "mfa_enabled": true,
                                "mfa_secret": enable_session.secret.clone()
                            }
                        },
                    )
                    .await?;
                drop(enable_session);
                PENDING_MFA_SETUPS.remove(&continue_token);
                Ok(web::Json(MfaResponse::EnableVerify {}))
            } else {
                Err(Error::SessionExpired)
            }
        }
    }
}
