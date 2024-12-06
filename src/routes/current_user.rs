use actix_web::{web, Responder};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};

use crate::{
    authenticate::Authenticate,
    database::profile,
    database::user,
    errors::{Error, Result},
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentUserResponse {
    id: String,
    username: String,
    mfa_enabled: bool,
    display_name: String,
    description: String,
    website: String,
    // TODO: avatar
    avatar: Option<String>,
}

pub async fn handle(jwt: web::ReqData<Result<Authenticate>>) -> Result<impl Responder> {
    let jwt = jwt.into_inner()?;
    let collection = user::get_collection();
    let profile_collection = profile::get_collection();
    let result = collection
        .find_one(doc! {
            "id": jwt.jwt_content.id.clone()
        })
        .await?
        .ok_or(Error::DatabaseError)?;
    let profile_result = profile_collection
        .find_one(doc! {
            "id": jwt.jwt_content.id.clone()
        })
        .await?
        .ok_or(Error::DatabaseError)?;
    Ok(web::Json(CurrentUserResponse {
        avatar: profile_result.avatar,
        description: profile_result.description,
        display_name: profile_result.display_name,
        id: jwt.jwt_content.id,
        mfa_enabled: result.mfa_enabled,
        username: result.username,
        website: profile_result.website,
    }))
}
