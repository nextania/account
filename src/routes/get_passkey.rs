use actix_web::{web, Responder};
use futures_util::StreamExt;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    authenticate::Authenticate,
    database::passkey
    ,
    errors::Result,
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyEntry {
    pub id: String,
    pub friendly_name: String,
}

pub async fn handle(
    jwt: web::ReqData<Result<Authenticate>>,
) -> Result<impl Responder> {
    let jwt = jwt.into_inner()?;
    let passkeys = passkey::get_collection().find(doc! {
        "user_id": jwt.jwt_content.id
    }).await?;
    let passkeys = passkeys.collect::<Vec<_>>().await;
    let mut passkeys = passkeys.into_iter().collect::<std::result::Result<Vec<_>, mongodb::error::Error>>()?;
    passkeys.sort_by(|a, b| Ulid::from_string(&b.id).unwrap().datetime().cmp(&Ulid::from_string(&a.id).unwrap().datetime()));
    let passkeys = passkeys.into_iter().map(|p| PasskeyEntry {
        id: p.id,
        friendly_name: p.friendly_name,
    }).collect::<Vec<_>>();
    Ok(web::Json(passkeys))
}
