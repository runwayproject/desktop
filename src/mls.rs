use openmls::prelude::{BasicCredential, CredentialWithKey, KeyPackage, OpenMlsRand};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_traits::types::Ciphersuite;
use openmls_traits::types::SignatureScheme::ED25519;

pub fn create_credentials_openmls() {
    let provider = OpenMlsRustCrypto::default();
    let identity = provider.rand().random_vec(32).unwrap();
    let signer = SignatureKeyPair::new(ED25519).unwrap();
    signer.store(provider.storage()).unwrap();
    let credential = BasicCredential::new(identity);
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    let key_package = KeyPackage::builder()
        .build(ciphersuite, &provider, &signer, credential_with_key.clone())
        .expect("Failed to build KeyPackageBundle");
    println!(
        "Created KeyPackage for identity (32 bytes). Public KeyPackage:\n{:#?}",
        key_package.key_package()
    );
}
