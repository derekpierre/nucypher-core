use std::sync::Arc;

uniffi::include_scaffolding!("nucypher_core_uniffi");

#[derive(Debug, thiserror::Error)]
pub enum NuCypherError {
    #[error("Encryption error")]
    EncryptionError,
    #[error("Decryption error")]
    DecryptionError,
    #[error("Invalid input")]
    InvalidInput,
    #[error("Invalid threshold")]
    InvalidThreshold,
    #[error("Invalid share")]
    InvalidShare,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid metadata")]
    InvalidMetadata,
}

type Result<T, E = NuCypherError> = std::result::Result<T, E>;

pub struct SessionSharedSecret {
    backend: nucypher_core::SessionSharedSecret,
}

pub struct SessionStaticKey {
    backend: nucypher_core::SessionStaticKey,
}

impl SessionStaticKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.backend.to_bytes().to_vec()
    }
}

pub struct SessionStaticSecret {
    backend: nucypher_core::SessionStaticSecret,
}

impl SessionStaticSecret {
    pub fn random() -> SessionStaticSecret {
        Self {
            backend: nucypher_core::SessionStaticSecret::random(),
        }
    }

    pub fn public_key(&self) -> Arc<SessionStaticKey> {
        SessionStaticKey {
            backend: self.backend.public_key(),
        }
        .into()
    }

    pub fn derive_shared_secret(
        &self,
        their_public_key: &SessionStaticKey,
    ) -> Arc<SessionSharedSecret> {
        SessionSharedSecret {
            backend: self.backend.derive_shared_secret(&their_public_key.backend),
        }
        .into()
    }
}

pub struct SessionSecretFactory {
    backend: nucypher_core::SessionSecretFactory,
}

impl SessionSecretFactory {
    pub fn seed_size(&self) -> u64 {
        nucypher_core::SessionSecretFactory::seed_size() as u64
    }

    pub fn from_secure_randomness(seed: &Vec<u8>) -> Result<SessionSecretFactory> {
        let factory = nucypher_core::SessionSecretFactory::from_secure_randomness(seed)
            .map_err(|_| NuCypherError::InvalidInput);
        Ok(Self { backend: factory? })
    }

    pub fn make_key(&self, label: &Vec<u8>) -> Arc<SessionStaticSecret> {
        SessionStaticSecret {
            backend: self.backend.make_key(label),
        }
        .into()
    }
}

pub struct DkgPublicKey {
    backend: ferveo::api::DkgPublicKey,
}

impl DkgPublicKey {
    pub fn new(public_key_bytes: &Vec<u8>) -> Result<DkgPublicKey> {
        let key = ferveo::api::DkgPublicKey::from_bytes(public_key_bytes)
            .map_err(|_| NuCypherError::InvalidInput);
        Ok(Self { backend: key? })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match self.backend.to_bytes() {
            Ok(bytes) => Ok(bytes.to_vec()),
            Err(_) => Err(NuCypherError::InvalidInput),
        }
    }

    pub fn from_bytes(data: &Vec<u8>) -> Result<DkgPublicKey> {
        let key =
            ferveo::api::DkgPublicKey::from_bytes(data).map_err(|_| NuCypherError::InvalidInput);
        Ok(Self { backend: key? })
    }
}
