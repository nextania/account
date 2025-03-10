use actix_web::{
    web::{self, Data},
    Responder,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64, Engine};
use dashmap::DashMap;
use lazy_static::lazy_static;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use webauthn_rs::{
    prelude::{CreationChallengeResponse, PasskeyRegistration, RegisterPublicKeyCredential},
    Webauthn,
};

use crate::{
    authenticate::Authenticate,
    database::{
        passkey::{self, Passkey},
        user::User,
    },
    errors::{Error, Result},
    utilities::{generate_continue_token_long, get_time_secs, validate_escalation},
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "stage")]
pub enum Register {
    #[serde(rename_all = "camelCase")]
    BeginRegister { escalation_token: String },
    #[serde(rename_all = "camelCase")]
    FinishRegister {
        message: RegisterPublicKeyCredential,
        continue_token: String,
        friendly_name: Option<String>,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum RegisterResponse {
    #[serde(rename_all = "camelCase")]
    BeginRegister {
        continue_token: String,
        message: CreationChallengeResponse,
    },
    FinishRegister {},
}

pub struct PendingRegister {
    pub time: u64,
    pub user: User,
    pub email: String,
    pub data: PasskeyRegistration,
}

lazy_static! {
    pub static ref PENDING_REGISTERS: DashMap<String, PendingRegister> = DashMap::new();
}

pub async fn handle(
    jwt: web::ReqData<Result<Authenticate>>,
    register: web::Json<Register>,
    webauthn: Data<Webauthn>,
) -> Result<impl Responder> {
    let register = register.into_inner();
    match register {
        Register::BeginRegister { escalation_token } => {
            let user_id = validate_escalation(escalation_token, jwt.into_inner()?.jwt).await?;
            let user = crate::database::user::get_collection()
                .find_one(doc! {
                    "id": user_id.clone()
                })
                .await?
                .ok_or(Error::DatabaseError)?;
            let uuid = webauthn_rs::prelude::Uuid::from_bytes(
                Ulid::from_string(&user.id).expect("S").to_bytes(),
            );
            let (ccr, reg_state) =
                webauthn.start_passkey_registration(uuid, &user.username, &user.username, None)?;
            let continue_token = generate_continue_token_long();
            let pending_register = PendingRegister {
                time: get_time_secs(),
                email: user.username.clone(),
                user,
                data: reg_state,
            };
            PENDING_REGISTERS.insert(continue_token.clone(), pending_register);
            Ok(web::Json(RegisterResponse::BeginRegister {
                continue_token,
                message: ccr,
            }))
        }
        Register::FinishRegister {
            message,
            continue_token,
            friendly_name,
        } => {
            let pending_register = PENDING_REGISTERS.get(&continue_token);
            let Some(pending_register) = pending_register else {
                return Err(Error::SessionExpired);
            };
            if get_time_secs() - pending_register.time > 3600 {
                drop(pending_register);
                PENDING_REGISTERS.remove(&continue_token);
                return Err(Error::SessionExpired);
            }
            let auth_result =
                webauthn.finish_passkey_registration(&message, &pending_register.data)?;
            let credential_id = auth_result.cred_id().as_ref().to_vec();
            let user = pending_register.user.clone();
            passkey::get_collection()
                .insert_one(Passkey {
                    id: Ulid::new().to_string(),
                    credential: auth_result,
                    credential_id: BASE64.encode(credential_id),
                    user_id: user.id.clone(),
                    friendly_name: friendly_name.unwrap_or("Passkey".to_string()),
                })
                .await?;
            drop(pending_register);
            PENDING_REGISTERS.remove(&continue_token);
            Ok(web::Json(RegisterResponse::FinishRegister {}))
        }
    }
}
