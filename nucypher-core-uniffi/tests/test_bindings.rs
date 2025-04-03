use ferveo::api::{
    Ciphertext, CiphertextHeader, DkgPublicKey, FerveoVariant, Keypair, SharedSecret,
};

use nucypher_core::{
    Conditions as CoreConditions, Context as CoreContext,
    SessionSecretFactory as CoreSessionSecretFactory,
};

// Import the bindings
uniffi::include_scaffolding!("nucypher-core");

// Test utilities
fn random_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|_| rand::random::<u8>()).collect()
}

#[test]
fn test_dkg_public_key_roundtrip() {
    let keypair = Keypair::random();
    let public_key = keypair.public_key();
    let bytes = public_key.to_bytes();

    let wrapped_key = crate::DkgPublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(wrapped_key.to_bytes(), bytes);
}

#[test]
fn test_ciphertext_roundtrip() {
    let data = random_bytes(32);
    let ciphertext = Ciphertext::try_from(&data[..]).unwrap();
    let bytes = ciphertext.to_bytes();

    let wrapped_ciphertext = crate::Ciphertext::from_bytes(&bytes).unwrap();
    assert_eq!(wrapped_ciphertext.to_bytes(), bytes);
}

#[test]
fn test_ciphertext_header_roundtrip() {
    let data = random_bytes(32);
    let header = CiphertextHeader::try_from(&data[..]).unwrap();
    let bytes = header.to_bytes();

    let wrapped_header = crate::CiphertextHeader::from_bytes(&bytes).unwrap();
    assert_eq!(wrapped_header.to_bytes(), bytes);
}

#[test]
fn test_shared_secret_roundtrip() {
    let data = random_bytes(32);
    let secret = SharedSecret::try_from(&data[..]).unwrap();
    let bytes = secret.to_bytes();

    let wrapped_secret = crate::SharedSecret::from_bytes(&bytes).unwrap();
    assert_eq!(wrapped_secret.to_bytes(), bytes);
}

#[test]
fn test_conditions_roundtrip() {
    let conditions_str = "{'hello': 'world'}";
    let conditions = crate::Conditions::new(conditions_str);
    let conditions2 = crate::Conditions::from_bytes(conditions_str);

    let core_conditions = CoreConditions::new(conditions_str);
    assert_eq!(format!("{}", core_conditions), conditions_str);
}

#[test]
fn test_context_roundtrip() {
    let context_str = "test-context";
    let context = crate::Context::new(context_str);
    let context2 = crate::Context::from_bytes(context_str);

    let core_context = CoreContext::new(context_str);
    assert_eq!(format!("{}", core_context), context_str);
}

#[test]
fn test_session_keys() {
    // Create two random session secrets
    let secret1 = crate::SessionStaticSecret::random().unwrap();
    let secret2 = crate::SessionStaticSecret::random().unwrap();

    let public_key1 = secret1.public_key();
    let public_key2 = secret2.public_key();

    // Test shared secret derivation
    let shared_secret1 = secret1.derive_shared_secret(&public_key2);
    let shared_secret2 = secret2.derive_shared_secret(&public_key1);
}

#[test]
fn test_threshold_message_kit() {
    let keypair = Keypair::random();
    let public_key = keypair.public_key();
    let conditions = crate::Conditions::new("{'hello': 'world'}");

    let auth_data = crate::AuthenticatedData::new(
        &crate::DkgPublicKey::from_bytes(&public_key.to_bytes()).unwrap(),
        &conditions,
    );

    let authorization = random_bytes(32);
    let acp = crate::AccessControlPolicy::new(&auth_data, &authorization);

    let data = random_bytes(32);
    let ciphertext = Ciphertext::try_from(&data[..]).unwrap();
    let wrapped_ciphertext = crate::Ciphertext::from_bytes(&ciphertext.to_bytes()).unwrap();

    let message_kit = crate::ThresholdMessageKit::new(&wrapped_ciphertext, &acp);

    // Test getters
    let header = message_kit.ciphertext_header();
    let returned_acp = message_kit.acp();

    // Test decryption
    let shared_secret = SharedSecret::try_from(&random_bytes(32)[..]).unwrap();
    let wrapped_secret = crate::SharedSecret::from_bytes(&shared_secret.to_bytes()).unwrap();
    let _decrypted = message_kit.decrypt_with_shared_secret(&wrapped_secret);
}

#[test]
fn test_threshold_decryption_request() {
    let ritual_id = 1;
    let variant = FerveoVariant::Standard;

    let data = random_bytes(32);
    let header = CiphertextHeader::try_from(&data[..]).unwrap();
    let wrapped_header = crate::CiphertextHeader::from_bytes(&header.to_bytes()).unwrap();

    let keypair = Keypair::random();
    let public_key = keypair.public_key();
    let conditions = crate::Conditions::new("{'hello': 'world'}");

    let auth_data = crate::AuthenticatedData::new(
        &crate::DkgPublicKey::from_bytes(&public_key.to_bytes()).unwrap(),
        &conditions,
    );

    let authorization = random_bytes(32);
    let acp = crate::AccessControlPolicy::new(&auth_data, &authorization);

    let context = Some(crate::Context::new("test-context"));

    let request = crate::ThresholdDecryptionRequest::new(
        ritual_id,
        variant,
        &wrapped_header,
        &acp,
        context.as_ref(),
    );

    // Test getters
    assert_eq!(request.ritual_id(), ritual_id);
    assert_eq!(request.variant(), variant);
    let _header = request.ciphertext_header();
    let _acp = request.acp();

    // Test encryption
    let secret = crate::SessionStaticSecret::random().unwrap();
    let public_key = secret.public_key();
    let shared_secret = secret.derive_shared_secret(&public_key);

    let encrypted = request.encrypt(&shared_secret, &public_key).unwrap();
    assert_eq!(encrypted.ritual_id(), ritual_id);
    let _decrypted = encrypted.decrypt(&shared_secret).unwrap();
}

#[test]
fn test_threshold_decryption_response() {
    let ritual_id = 1;
    let decryption_share = random_bytes(32);

    let response = crate::ThresholdDecryptionResponse::new(ritual_id, &decryption_share);

    // Test getters
    assert_eq!(response.ritual_id(), ritual_id);
    assert_eq!(response.decryption_share(), decryption_share);

    // Test encryption
    let secret = crate::SessionStaticSecret::random().unwrap();
    let public_key = secret.public_key();
    let shared_secret = secret.derive_shared_secret(&public_key);

    let encrypted = response.encrypt(&shared_secret).unwrap();
    assert_eq!(encrypted.ritual_id(), ritual_id);
    let _decrypted = encrypted.decrypt(&shared_secret).unwrap();
}

#[test]
fn test_encrypt_for_dkg() {
    let keypair = Keypair::random();
    let public_key = keypair.public_key();
    let wrapped_key = crate::DkgPublicKey::from_bytes(&public_key.to_bytes()).unwrap();

    let conditions = crate::Conditions::new("{'hello': 'world'}");
    let data = random_bytes(32);

    let result = crate::encrypt_for_dkg(&data, &wrapped_key, &conditions).unwrap();
    assert!(!result.is_empty());

    for (ciphertext, auth_data) in result {
        let _bytes = ciphertext.to_bytes();
        let _aad = auth_data.aad();
        let _pk = auth_data.public_key();
        let _conditions = auth_data.conditions();
    }
}
