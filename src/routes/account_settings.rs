use actix_web::{web, Responder};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};

use crate::{
    authenticate::Authenticate,
    database::user::get_collection,
    errors::{Error, Result},
    utilities::{validate_escalation, EMAIL_RE, USERNAME_RE},
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSettings {
    username: Option<String>,
    email: Option<String>,
    // destructive actions
    escalation_token: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSettingsResponse {}

pub async fn handle(
    jwt: web::ReqData<Result<Authenticate>>,
    account_settings: web::Json<AccountSettings>,
) -> Result<impl Responder> {
    let jwt = jwt.into_inner()?;
    let account_settings = account_settings.into_inner();
    validate_escalation(account_settings.escalation_token, jwt.jwt).await?;
    let user_collection = get_collection();
    let mut update_query = doc! {};
    if let Some(username) = account_settings.username {
        if !USERNAME_RE.is_match(username.trim()) {
            return Err(Error::InvalidUsername);
        }
        let user = user_collection
            .find_one(doc! {
                "username": username.trim()
            })
            .await?;
        if user.is_some() {
            return Err(Error::UsernameAlreadyTaken);
        }
        update_query.insert("username", username.trim());
    }
    if let Some(email) = account_settings.email {
        if !EMAIL_RE.is_match(email.trim()) {
            return Err(Error::InvalidEmail);
        }
        let user = user_collection
            .find_one(doc! {
                "email": email.trim()
            })
            .await?;
        if user.is_some() {
            return Err(Error::UserExists);
        }
        update_query.insert("email", email);
    }
    user_collection
        .update_one(
            doc! {
                "id": jwt.jwt_content.id.clone()
            },
            doc! {
                "$set": update_query
            },
        )
        .await?;
    Ok(web::Json(AccountSettingsResponse {}))
}
