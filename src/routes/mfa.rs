use std::time::{SystemTime, UNIX_EPOCH};

use bcrypt::verify;
use dashmap::DashMap;
use lazy_static::lazy_static;
use mongodb::bson::doc;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use totp_rs::{TOTP, Secret};
use warp::{header::headers_cloned, Filter, Reply, Rejection};

use crate::{
    authenticate::{authenticate, Authenticate},
    database::user::{get_collection, User},
    utilities::{generate_id, random_number},
};

#[derive(Deserialize, Serialize)]
pub struct Mfa {
    password: Option<String>,
    code: Option<String>,
    continue_token: Option<String>,
    stage: i8,
}

#[derive(Deserialize, Serialize)]
pub struct MfaError {
    error: String,
}

#[derive(Deserialize, Serialize)]
pub struct MfaResponse {
    continue_token: Option<String>,
    success: Option<bool>,
    qr: Option<String>,
    secret: Option<String>,
}

pub struct PendingMfaEnable {
    totp: TOTP,
    secret: String,
    time: u64,
    user: User,
}

pub struct PendingMfaDisable {
    user: User,
    time: u64,
}

lazy_static! {
    pub static ref PENDING_MFA_ENABLES: DashMap<String, PendingMfaEnable> = DashMap::new();
    pub static ref PENDING_MFA_DISABLES: DashMap<String, PendingMfaDisable> = DashMap::new();
}

pub fn route() -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::patch()
        .and(
            warp::path!("user" / "mfa")
                .and(headers_cloned().and_then(authenticate))
                .and(warp::body::json())
                .and_then(handle),
        )
        .boxed()
}

pub async fn handle(jwt: Option<Authenticate>, mfa: Mfa) -> Result<impl Reply, warp::Rejection> {
    if let Some(jwt) = jwt {
        if mfa.stage == 1 {
            let collection = get_collection();
            let user = collection
                .find_one(Some(doc! {"id": jwt.jwt_content.id}), None)
                .await;
            if let Ok(user) = user {
                if let Some(user) = user {
                    if let Some(password) = mfa.password {
                        let verified = verify(password, &user.password_hash)
                            .expect("Unexpected error: failed to verify password");
                        if !verified {
                            return Ok(warp::reply::with_status(
                                warp::reply::json(&MfaError {
                                    error: "Password incorrect".to_string(),
                                }),
                                StatusCode::UNAUTHORIZED,
                            ));
                        }
                        if user.mfa_enabled {
                            let continue_token = generate_id();
                            let duration = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .expect("Unexpected error: time went backwards");
                            let login_session = PendingMfaDisable {
                                time: duration.as_secs(),
                                user,
                            };
                            PENDING_MFA_DISABLES.insert(continue_token.clone(), login_session);
                            let response = MfaResponse {
                                continue_token: Some(continue_token),
                                success: None,
                                qr: None,
                                secret: None,
                            };
                            Ok(warp::reply::with_status(
                                warp::reply::json(&response),
                                StatusCode::OK,
                            ))
                        } else {
                            let secret = random_number(160);
                            let totp = TOTP::new(
                                totp_rs::Algorithm::SHA256,
                                8,
                                1,
                                30,
                                secret.clone(),
                                Some("Nextflow Cloud Technologies".to_string()),
                                user.username.clone(),
                            )
                            .expect("Unexpected error: failed to initiate TOTP");
                            let qr = totp
                                .get_qr()
                                .expect("Unexpected error: failed to generate QR code");
                            // let code = base64::encode(secret);
                            let continue_token = generate_id();
                            let duration = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .expect("Unexpected error: time went backwards");
                            let code = Secret::Raw(secret.to_vec()).to_encoded().to_string();
                            let session = PendingMfaEnable {
                                time: duration.as_secs(),
                                user,
                                secret: code.clone(),
                                totp,
                            };
                            PENDING_MFA_ENABLES.insert(continue_token.clone(), session);
                            Ok(warp::reply::with_status(
                                warp::reply::json(&MfaResponse {
                                    continue_token: Some(continue_token),
                                    qr: Some(qr),
                                    secret: Some(code),
                                    success: None,
                                }),
                                StatusCode::OK,
                            ))
                        }
                    } else {
                        Ok(warp::reply::with_status(
                            warp::reply::json(&MfaError {
                                error: "No password".to_string(),
                            }),
                            StatusCode::BAD_REQUEST,
                        ))
                    }
                } else {
                    Ok(warp::reply::with_status(
                        warp::reply::json(&MfaError {
                            error: "User not found".to_string(),
                        }),
                        StatusCode::NOT_FOUND,
                    ))
                }
            } else {
                Ok(warp::reply::with_status(
                    warp::reply::json(&MfaError {
                        error: "Failed to query database".to_string(),
                    }),
                    StatusCode::INTERNAL_SERVER_ERROR,
                ))
            }
        } else if mfa.stage == 2 {
            if let Some(code) = mfa.code {
                if let Some(continue_token) = mfa.continue_token {
                    let enable_session = PENDING_MFA_ENABLES.get(&continue_token);
                    if let Some(enable_session) = enable_session {
                        let duration = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Unexpected error: time went backwards");
                        if duration.as_secs() - enable_session.time > 3600 {
                            drop(enable_session);
                            PENDING_MFA_ENABLES.remove(&continue_token);
                            let error = MfaError {
                                error: "Session expired".to_string(),
                            };
                            return Ok(warp::reply::with_status(
                                warp::reply::json(&error),
                                StatusCode::UNAUTHORIZED,
                            ));
                        }
                        let current = enable_session
                            .totp
                            .generate_current()
                            .expect("Unexpected error: failed to generate code");
                        if current == code {
                            let collection = get_collection();
                            let result = collection
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
                                    None,
                                )
                                .await;
                            if result.is_ok() {
                                drop(enable_session);
                                PENDING_MFA_ENABLES.remove(&continue_token);
                                Ok(warp::reply::with_status(
                                    warp::reply::json(&MfaResponse {
                                        continue_token: None,
                                        qr: None,
                                        secret: None,
                                        success: Some(true),
                                    }),
                                    StatusCode::BAD_REQUEST,
                                ))
                            } else {
                                Ok(warp::reply::with_status(
                                    warp::reply::json(&MfaError {
                                        error: "Failed to update database".to_string(),
                                    }),
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                ))
                            }
                        } else {
                            Ok(warp::reply::with_status(
                                warp::reply::json(&MfaError {
                                    error: "Invalid code".to_string(),
                                }),
                                StatusCode::UNAUTHORIZED,
                            ))
                        }
                    } else {
                        let disable_session = PENDING_MFA_DISABLES.get(&continue_token);
                        if let Some(disable_session) = disable_session {
                            let duration = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .expect("Unexpected error: time went backwards");
                            if duration.as_secs() - disable_session.time > 3600 {
                                drop(disable_session);
                                PENDING_MFA_DISABLES.remove(&continue_token);
                                let error = MfaError {
                                    error: "Session expired".to_string(),
                                };
                                return Ok(warp::reply::with_status(
                                    warp::reply::json(&error),
                                    StatusCode::UNAUTHORIZED,
                                ));
                            }
                            let totp = TOTP::new(
                                totp_rs::Algorithm::SHA256,
                                8,
                                1,
                                30,
                                disable_session.user.mfa_secret.as_ref().unwrap(),
                                Some("Nextflow Cloud Technologies".to_string()),
                                disable_session.user.id.clone(),
                            )
                            .expect("Unexpected error: failed to initiate TOTP");
                            let current = totp
                                .generate_current()
                                .expect("Unexpected error: failed to generate code");
                            if current == code {
                                let collection = get_collection();
                                let result = collection
                                    .update_one(
                                        doc! {
                                            "id": disable_session.user.id.clone(),
                                        },
                                        doc! {
                                            "$set": {
                                                "mfa_enabled": false,
                                                "mfa_secret": None::<String>
                                            }
                                        },
                                        None,
                                    )
                                    .await;
                                if result.is_ok() {
                                    drop(disable_session);
                                    PENDING_MFA_DISABLES.remove(&continue_token);
                                    Ok(warp::reply::with_status(
                                        warp::reply::json(&MfaResponse {
                                            continue_token: None,
                                            qr: None,
                                            secret: None,
                                            success: Some(true),
                                        }),
                                        StatusCode::BAD_REQUEST,
                                    ))
                                } else {
                                    Ok(warp::reply::with_status(
                                        warp::reply::json(&MfaError {
                                            error: "Failed to update database".to_string(),
                                        }),
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                    ))
                                }
                            } else {
                                Ok(warp::reply::with_status(
                                    warp::reply::json(&MfaError {
                                        error: "Invalid code".to_string(),
                                    }),
                                    StatusCode::UNAUTHORIZED,
                                ))
                            }
                        } else {
                            Ok(warp::reply::with_status(
                                warp::reply::json(&MfaError {
                                    error: "No session".to_string(),
                                }),
                                StatusCode::BAD_REQUEST,
                            ))
                        }
                    }
                } else {
                    Ok(warp::reply::with_status(
                        warp::reply::json(&MfaError {
                            error: "No session".to_string(),
                        }),
                        StatusCode::BAD_REQUEST,
                    ))
                }
            } else {
                Ok(warp::reply::with_status(
                    warp::reply::json(&MfaError {
                        error: "No code".to_string(),
                    }),
                    StatusCode::BAD_REQUEST,
                ))
            }
        } else {
            Ok(warp::reply::with_status(
                warp::reply::json(&MfaError {
                    error: "Invalid stage".to_string(),
                }),
                StatusCode::BAD_REQUEST,
            ))
        }
    } else {
        Ok(warp::reply::with_status(
            warp::reply::json(&MfaError {
                error: "Authentication error".to_string(),
            }),
            StatusCode::UNAUTHORIZED,
        ))
    }
}
