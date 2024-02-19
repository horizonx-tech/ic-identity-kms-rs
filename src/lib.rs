extern crate aws_sdk_kms;
extern crate ic_agent;

use aws_sdk_kms::{primitives::Blob, types::SigningAlgorithmSpec, Client};
use ic_agent::{export::Principal, Identity, Signature};
use k256::{pkcs8::EncodePublicKey, PublicKey};

pub struct KmsIdentity {
    client: Client,
    key_id: String,
}

impl KmsIdentity {
    pub fn new(client: Client, key_id: String) -> Self {
        KmsIdentity { client, key_id }
    }
}

impl Identity for KmsIdentity {
    fn sender(&self) -> Result<Principal, String> {
        let der = PublicKey::from_sec1_bytes(self.public_key().unwrap().as_slice())
            .map_err(|e| e.to_string())?
            .to_public_key_der();
        let pub_key = der.as_ref().map_err(|e| e.to_string())?;
        Ok(Principal::self_authenticating(pub_key))
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        let request = self
            .client
            .get_public_key()
            .key_id(self.key_id.clone())
            .send();
        let out = futures::executor::block_on(request)
            .map_err(|e| e.to_string())
            .unwrap();
        out.public_key().map(|k| k.as_ref().to_vec())
    }

    fn sign(
        &self,
        content: &ic_agent::agent::EnvelopeContent,
    ) -> Result<ic_agent::Signature, String> {
        let request = self
            .client
            .sign()
            .key_id(self.key_id.clone())
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .message(Blob::new(content.to_request_id().signable()))
            .send();
        let out = futures::executor::block_on(request).map_err(|e| e.to_string())?;
        let public_key = self.public_key().unwrap();
        let sig = Signature {
            delegations: None,
            public_key: Some(public_key),
            signature: Some(out.signature().unwrap().as_ref().to_vec()),
        };
        Ok(sig)
    }
}
