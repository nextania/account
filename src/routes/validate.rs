use actix_web::{web, Responder};
use serde::{Deserialize, Serialize};

use crate::{authenticate::validate_token, errors::Result, utilities::validate_escalation};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Validate {
    token: String,
    escalation_token: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateResponse {
    escalated: bool,
}

pub async fn handle(validate: web::Json<Validate>) -> Result<impl Responder> {
    let token = validate_token(&validate.token).await;
    if let Err(token) = token {
        Err(token)
    } else {
        let Some(escalation) = &validate.escalation_token else {
            return Ok(web::Json(ValidateResponse {
                escalated: false,
            }));
        };
        let escalation = validate_escalation(escalation.to_string(), validate.token.clone()).await;
        if escalation.is_err() {
            Ok(web::Json(ValidateResponse {
                escalated: false,
            }))
        } else {
            Ok(web::Json(ValidateResponse {
                escalated: true,
            }))
        }
    }
}
