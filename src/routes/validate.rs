use actix_web::{web, Responder};
use serde::{Deserialize, Serialize};

use crate::{authenticate::validate_token, errors::Result};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Validate {
    token: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateResponse {}

pub async fn handle(validate: web::Json<Validate>) -> Result<impl Responder> {
    validate_token(&validate.token).await?;
    Ok(web::Json(ValidateResponse {}))
}
