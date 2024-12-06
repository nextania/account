// Server configuration

use mongodb::{bson::doc, Collection};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

use crate::opaque::create_server_setup;

static COLLECTION: OnceCell<Collection<Settings>> = OnceCell::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub opaque_server_setup: Vec<u8>,
}

pub fn get_collection() -> Collection<Settings> {
    let collection = COLLECTION.get();
    if let Some(c) = collection {
        c.clone()
    } else {
        let c = super::get_database().collection::<Settings>("settings");
        COLLECTION
            .set(c.clone())
            .expect("Unexpected error: failed to set collection");
        c
    }
}

pub async fn get_settings() -> Settings {
    let collection = get_collection();
    if let Some(settings) = collection.find_one(doc! {}).await.unwrap() {
        settings
    } else {
        let settings = Settings {
            opaque_server_setup: create_server_setup().serialize().as_slice().to_vec(),
        };
        collection.insert_one(&settings).await.unwrap();
        settings
    }
}
