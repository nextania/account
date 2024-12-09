use actix_web::{web, Responder};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};

use crate::{authenticate::Authenticate, database::session::get_collection, errors::Result};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutOtherResponse {}

pub async fn handle(
    jwt: web::ReqData<Result<Authenticate>>,
    logout_other: web::Path<String>,
) -> Result<impl Responder> {
    jwt.into_inner()?;
    let sessions = get_collection();
    sessions
        .delete_one(doc! { "id": &logout_other.into_inner() })
        .await?;
    Ok(web::Json(LogoutOtherResponse {}))
}
