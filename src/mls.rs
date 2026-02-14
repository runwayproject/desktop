use openmls::group::{MlsGroup, MlsGroupCreateConfig, NewGroupError};
use openmls::prelude::{
    BasicCredential, Capabilities, CredentialType, CredentialWithKey, Extension, ExtensionType,
    Extensions, ExternalSender, KeyPackage, OpenMlsRand, SenderRatchetConfiguration,
    UnknownExtension,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{MemoryStorageError, OpenMlsRustCrypto};
use openmls_traits::OpenMlsProvider;
use openmls_traits::types::Ciphersuite;
use openmls_traits::types::SignatureScheme::ED25519;
pub struct IdentityBundle {
    pub ciphersuite: Ciphersuite,
    pub signer: SignatureKeyPair,
    pub credential_with_key: CredentialWithKey,
    pub provider: OpenMlsRustCrypto,
}
pub fn create_keypackage() {
    let identity_bundle = create_identity();

    let key_package = KeyPackage::builder()
        .build(
            identity_bundle.ciphersuite,
            &identity_bundle.provider,
            &identity_bundle.signer,
            identity_bundle.credential_with_key.clone(),
        )
        .expect("Failed to build KeyPackageBundle");

    println!(
        "Created KeyPackage for identity (32 bytes). Public KeyPackage:\n{:#?}",
        key_package.key_package()
    );
}

pub fn create_identity() -> IdentityBundle {
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

    IdentityBundle {
        ciphersuite,
        signer,
        credential_with_key,
        provider,
    }
}

pub fn create_group(identity_bundle: &IdentityBundle) -> MlsGroup {
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .padding_size(100)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
        .with_group_context_extensions(
            Extensions::single(Extension::ExternalSenders(vec![ExternalSender::new(
                identity_bundle.credential_with_key.signature_key.clone(),
                identity_bundle.credential_with_key.credential.clone(),
            )]))
            .expect("failed to create single-element extensions list"),
        )
        .ciphersuite(identity_bundle.ciphersuite)
        .capabilities(Capabilities::new(
            None,
            None,
            Some(&[ExtensionType::Unknown(0xff00)]),
            None,
            Some(&[CredentialType::Basic]),
        ))
        .with_leaf_node_extensions(
            Extensions::single(Extension::Unknown(
                0xff00,
                UnknownExtension(vec![0, 1, 2, 3]),
            ))
            .expect("failed to create single-element extensions list"),
        )
        .expect("failed to configure leaf extensions")
        .use_ratchet_tree_extension(true)
        .build();

    let mut group = MlsGroup::new(
        &identity_bundle.provider,
        &identity_bundle.signer,
        &mls_group_create_config,
        identity_bundle.credential_with_key.clone(),
    )
    .expect("failed to create group");

    return group;
}

pub fn join_from_welcome() {
    
}
