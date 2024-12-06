use mongodb::Collection;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

static COLLECTION: OnceCell<Collection<Passkey>> = OnceCell::new();

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Passkey {
    pub id: String,
    pub credential: webauthn_rs::prelude::Passkey,
    pub credential_id: Vec<u8>,
    pub user_id: String,
    pub friendly_name: String,
}

pub fn get_collection() -> Collection<Passkey> {
    let collection = COLLECTION.get();
    if let Some(c) = collection {
        c.clone()
    } else {
        let c = super::get_database().collection::<Passkey>("passkeys");
        COLLECTION
            .set(c.clone())
            .expect("Unexpected error: failed to set collection");
        c
    }
}
