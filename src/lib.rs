extern crate aws_sdk_kms;
extern crate ic_agent;

use async_trait::async_trait;
use aws_sdk_kms::{
    error::SdkError,
    operation::get_public_key::GetPublicKeyError,
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
    Client,
};
use ic_agent::{export::Principal, Identity, Signature};
use sha2::Digest;

#[derive(Clone)]
pub struct KmsIdentity {
    client: Client,
    key_id: String,
    public_key: Vec<u8>,
}

impl KmsIdentity {
    pub async fn new(client: Client, key_id: String) -> Result<Self, SdkError<GetPublicKeyError>> {
        let public_key = client
            .get_public_key()
            .key_id(key_id.clone())
            .send()
            .await?
            .public_key
            .unwrap()
            .as_ref()
            .to_vec();
        Ok(KmsIdentity {
            client,
            key_id,
            public_key,
        })
    }
}

#[async_trait]
impl Identity for KmsIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(self.public_key.clone()))
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        self.public_key.clone().into()
    }

    async fn sign(
        &self,
        content: &ic_agent::agent::EnvelopeContent,
    ) -> Result<ic_agent::Signature, String> {
        let message = content.to_request_id().signable();
        let message_digest = Blob::new(sha2::Sha256::digest(message).to_vec());
        let result = self
            .client
            .sign()
            .key_id(self.key_id.clone())
            .message_type(MessageType::Digest)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .message(message_digest)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .signature()
            .unwrap()
            .as_ref()
            .to_vec();
        let public_key = self.public_key().unwrap();
        let sig = p256::ecdsa::Signature::from_der(result.as_ref()).unwrap();
        let r = sig.r().as_ref().to_bytes();
        let s = sig.s().as_ref().to_bytes();
        let mut bytes = [0u8; 64];
        if r.len() > 32 || s.len() > 32 {
            return Err("Cannot create secp256k1 signature: malformed signature.".to_string());
        }
        bytes[(32 - r.len())..32].clone_from_slice(&r);
        bytes[32 + (32 - s.len())..].clone_from_slice(&s);
        let signature = Some(bytes.to_vec());

        Ok(Signature {
            delegations: None,
            public_key: Some(public_key),
            signature,
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use aws_config::BehaviorVersion;
    use aws_sdk_kms::Client;
    use ic_agent::agent::EnvelopeContent;
    #[tokio::test]
    async fn test_kms_identity() {
        let client: Client =
            Client::new(&aws_config::defaults(BehaviorVersion::latest()).load().await);
        let identity = KmsIdentity::new(client.clone(), "alias/tt".to_string())
            .await
            .unwrap();
        let pub_key = identity.public_key().unwrap();
        println!("{:?}", pub_key);
    }
    #[tokio::test]
    async fn test_sender() {
        let client: Client =
            Client::new(&aws_config::defaults(BehaviorVersion::latest()).load().await);
        let identity = KmsIdentity::new(client.clone(), "alias/tt".to_string())
            .await
            .unwrap();
        let sender = identity.sender().unwrap();
        println!("{:?}", sender.to_string());
    }

    #[tokio::test]
    async fn test_new() {
        let client: Client =
            Client::new(&aws_config::defaults(BehaviorVersion::latest()).load().await);
        KmsIdentity::new(client.clone(), "alias/tt".to_string())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_sign() {
        let client: Client =
            Client::new(&aws_config::defaults(BehaviorVersion::latest()).load().await);
        let identity = KmsIdentity::new(client.clone(), "alias/hideyoshi".to_string())
            .await
            .unwrap();
        let msg = EnvelopeContent::Call {
            nonce: None,
            ingress_expiry: 1,
            sender: Principal::anonymous(),
            canister_id: Principal::anonymous(),
            method_name: "test".to_string(),
            arg: vec![],
        };
        let _ = identity.sign(&msg).await.unwrap();
    }
    #[tokio::test]
    async fn test_with_agent() {
        let client: Client =
            Client::new(&aws_config::defaults(BehaviorVersion::latest()).load().await);
        let identity = KmsIdentity::new(client.clone(), "alias/tt".to_string())
            .await
            .unwrap();
        let _ = ic_agent::Agent::builder()
            .with_url("https://ic0.app")
            .with_identity(identity)
            .build()
            .unwrap();
    }
}
