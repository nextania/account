use actix_web::{web, Responder};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};

use crate::{
    authenticate::Authenticate,
    database::{files::File, passkey, profile, session, user},
    errors::{Error, Result},
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteResponse {}

// TODO: security concerns? potentially add a grace period
pub async fn handle(
    jwt: web::ReqData<Result<Authenticate>>,
) -> Result<impl Responder> {
    let jwt = jwt.into_inner()?;
    let collection = user::get_collection();
    let sessions = session::get_collection();
    sessions
        .delete_many(doc! { "user_id": &jwt.jwt_content.id })
        .await?;
    collection
        .delete_one(doc! {
            "id": &jwt.jwt_content.id
        })
        .await?;
    let profile = profile::get_collection()
        .find_one(doc! {
            "id": &jwt.jwt_content.id,
        })
        .await?
        .ok_or(Error::DatabaseError)?;
    if let Some(avatar) = profile.avatar {
        if let Ok(avatar) = File::get(&avatar).await {
            avatar.detach().await?;
        }
    }
    profile::get_collection()
        .delete_one(doc! {
            "id": &jwt.jwt_content.id
        })
        .await?;
    passkey::get_collection()
        .delete_many(doc! {
            "user_id": jwt.jwt_content.id
        })
        .await?;
    Ok(web::Json(DeleteResponse {}))
}
