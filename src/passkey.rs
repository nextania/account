use actix_web::web::Data;
use webauthn_rs::{prelude::Url, Webauthn, WebauthnBuilder};

use crate::environment::{PUBLIC_ROOT, RP_ID, SERVICE_NAME};

pub fn create_webauthn() -> Data<Webauthn> {
    let rp_origin = Url::parse(&PUBLIC_ROOT).expect("Invalid URL");
    let builder = WebauthnBuilder::new(&RP_ID, &rp_origin)
        .expect("Invalid configuration")
        .rp_name(&SERVICE_NAME);
    Data::new(builder.build().expect("Invalid configuration"))
}
