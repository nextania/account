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
pub struct UserResponse {
    id: String,
    username: String,
    mfa_enabled: bool,
    display_name: String,
    description: String,
    website: String,
    avatar: Option<String>,
}

pub async fn handle(
    user_id: web::Path<String>,
    jwt: web::ReqData<Result<Authenticate>>,
) -> Result<impl Responder> {
    jwt.into_inner()?;
    let collection = user::get_collection();
    let profile_collection = profile::get_collection();
    let result = collection
        .find_one(doc! {
            "id": user_id.clone()
        })
        .await?;
    let profile_result = profile_collection
        .find_one(doc! {
            "id": user_id.clone()
        })
        .await?;
    let Some(result) = result else {
        return Err(Error::UserNotFound);
    };
    let Some(profile_result) = profile_result else {
        return Err(Error::UserNotFound);
    };
    Ok(web::Json(UserResponse {
        avatar: profile_result.avatar,
        description: profile_result.description,
        display_name: profile_result.display_name,
        id: user_id.to_string(),
        mfa_enabled: result.mfa_enabled,
        username: result.username,
        website: profile_result.website,
    }))
}
