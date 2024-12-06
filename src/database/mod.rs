pub mod code;
pub mod files;
pub mod passkey;
pub mod profile;
pub mod session;
pub mod settings;
pub mod user;

use log::info;
use mongodb::{Client, Database};
use once_cell::sync::OnceCell;

use crate::environment::{MONGODB_DATABASE, MONGODB_URI};

static DATABASE: OnceCell<Client> = OnceCell::new();

pub async fn connect() {
    let client = Client::with_uri_str(&*MONGODB_URI)
        .await
        .expect("Failed to connect to MongoDB");
    info!("Database connection successful");
    DATABASE.set(client).expect("Failed to set MongoDB client");
}

pub fn get_connection() -> &'static Client {
    DATABASE.get().expect("Failed to get MongoDB client")
}

pub fn get_database() -> Database {
    get_connection().database(&MONGODB_DATABASE)
}
