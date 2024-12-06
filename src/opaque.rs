use opaque_ke::{CipherSuite, CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup};
use rand::rngs::OsRng;

use crate::database::settings::get_settings;

pub struct Default;
impl CipherSuite for Default {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

pub fn create_server_setup() -> ServerSetup<Default> {
    let mut rng = OsRng;
    let setup = ServerSetup::<Default>::new(&mut rng);
    setup
}

pub async fn get_server_setup() -> ServerSetup<Default> {
    let settings = get_settings().await;
    ServerSetup::<Default>::deserialize(&settings.opaque_server_setup[..]).unwrap()
}

pub async fn begin_registration(email: String, client_message: RegistrationRequest<Default>) -> crate::errors::Result<Vec<u8>> {
    
    let server_setup = get_server_setup().await;
    let server_registration_start_result = ServerRegistration::<Default>::start(
        &server_setup,
        client_message,
        email.as_bytes(),
    )?;
    Ok(server_registration_start_result.message.serialize().to_vec())

}

pub fn finish_registration(client_message: RegistrationUpload<Default>) -> crate::errors::Result<Vec<u8>> {
    let password_file = ServerRegistration::<Default>::finish(
        client_message,
    );
    Ok(password_file.serialize().to_vec())
}

pub async fn begin_login(email: String, password_data: Option<Vec<u8>>, client_message: CredentialRequest<Default>) -> crate::errors::Result<(Vec<u8>, ServerLogin<Default>)> {
    let password_file = password_data.map(|x| ServerRegistration::<Default>::deserialize(&x)).transpose()?;
    let mut server_rng = OsRng;
    let server_setup = get_server_setup().await;
    let server_login_start_result = ServerLogin::start(
        &mut server_rng,
        &server_setup,
        password_file,
        client_message,
        email.as_bytes(),
        ServerLoginStartParameters::default(),
    )?;
    Ok((server_login_start_result.message.serialize().to_vec(), server_login_start_result.state))
}

pub fn finish_login(state: ServerLogin<Default>, client_message: CredentialFinalization<Default>) -> crate::errors::Result<()> {
    state.finish(client_message)?;
    Ok(())
}
