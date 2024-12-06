use std::env;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref MONGODB_URI: String = env::var("MONGODB_URI").expect("MONGODB_URI must be set");
    pub static ref MONGODB_DATABASE: String =
        env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
    pub static ref CDN_MONGODB_DATABASE: String =
        env::var("CDN_MONGODB_DATABASE").expect("CDN_MONGODB_DATABASE must be set");
    pub static ref JWT_SECRET: String = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    pub static ref HCAPTCHA_SECRET: String =
        env::var("HCAPTCHA_SECRET").expect("HCAPTCHA_SECRET must be set");
    pub static ref CORS_ORIGINS: Vec<String> = env::var("CORS_ORIGINS")
        .expect("CORS_ORIGINS must be set")
        .split(',')
        .map(|s| s.to_string())
        .collect();
    pub static ref HOST: String = env::var("HOST").expect("HOST must be set");
    pub static ref SMTP_USERNAME: Option<String> = env::var("SMTP_USERNAME").ok();
    pub static ref SMTP_PASSWORD: Option<String> = env::var("SMTP_PASSWORD").ok();
    pub static ref SMTP_SERVER: Option<String> = env::var("SMTP_SERVER").ok();
    pub static ref SMTP_FROM: Option<String> = env::var("SMTP_FROM").ok();
    pub static ref SMTP_ENABLED: bool = SMTP_USERNAME.is_some()
        && SMTP_PASSWORD.is_some()
        && SMTP_SERVER.is_some()
        && SMTP_FROM.is_some();
    pub static ref PUBLIC_ROOT: String = env::var("PUBLIC_ROOT").expect("PUBLIC_ROOT must be set");
    pub static ref SERVICE_NAME: String =
        env::var("SERVICE_NAME").expect("SERVICE_NAME must be set");
    pub static ref RP_ID: String = env::var("RP_ID").expect("RP_ID must be set");
}
