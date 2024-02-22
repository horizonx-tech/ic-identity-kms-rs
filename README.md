# ic-identity-kms-rs

This is a Rust implementation of the Identity Key Management Service (KMS) for the Internet Computer. This implements the `Identity` trait from the `ic-agent` crate.

## Usage

```rust

use ic_identity_kms_rs::KmsIdentity;
use aws_config::BehaviorVersion;
use aws_sdk_kms::Client;
use ic_agent::Agent;

#[tokio::main]
async fn main() {
    let client: Client =
        Client::new(&aws_config::defaults(BehaviorVersion::latest()).load().await);
    let identity = KmsIdentity::new(client, "alias/sample-key".to_string()).await.unwrap();
    let pub_key = identity.public_key().unwrap();
    let _ = Agent::builder()
        .with_identity(identity)
        .with_url("https://ic0.app")
        .build()
        .unwrap()
        .update(&Principal::anonymous(), "sample_method".to_string())
        .call_and_wait();
}

```
