use actix_web::{web, Responder};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};

use crate::{
    authenticate::Authenticate, database::passkey, errors::Result, utilities::validate_escalation,
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletePasskey {
    pub escalation_token: String,
}

pub async fn handle(
    jwt: web::ReqData<Result<Authenticate>>,
    passkey_id: web::Path<String>,
    delete_passkey: web::Json<DeletePasskey>,
) -> Result<impl Responder> {
    let jwt = jwt.into_inner()?;
    validate_escalation(delete_passkey.escalation_token.clone(), jwt.jwt).await?;
    passkey::get_collection()
        .delete_one(doc! {
            "id": &passkey_id.into_inner(),
            "user_id": jwt.jwt_content.id,
        })
        .await?;
    Ok(web::Json("null"))
}
