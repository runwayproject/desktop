use anyhow::{Context, Result};
use openmls::group::{MlsGroup, MlsGroupCreateConfig};
use openmls::prelude::{
    BasicCredential, Capabilities, CredentialType, CredentialWithKey, Extension, ExtensionType,
    Extensions, ExternalSender, KeyPackage, OpenMlsRand, SenderRatchetConfiguration,
    UnknownExtension, Welcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
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

    let group = MlsGroup::new(
        &identity_bundle.provider,
        &identity_bundle.signer,
        &mls_group_create_config,
        identity_bundle.credential_with_key.clone(),
    )
    .expect("failed to create group");

    return group;
}

pub fn create_welcome_message(
    group: &mut MlsGroup,
    key_packages: &[KeyPackage],
    provider: &OpenMlsRustCrypto,
    signer: &SignatureKeyPair,
) -> Result<Welcome> {
    let builder = group
        .commit_builder()
        .propose_adds(key_packages.iter().cloned());

    let builder = builder
        .load_psks(provider.storage())
        .context("loading PSKs failed")?;

    let builder = builder
        .build(provider.rand(), provider.crypto(), signer, |_| true)
        .context("building commit failed")?;

    let bundle = builder
        .stage_commit(provider)
        .context("staging commit failed")?;

    let welcome = bundle
        .welcome()
        .cloned()
        .context("no Welcome produced by commit")?;

    group
        .merge_pending_commit(provider)
        .context("merging staged commit into group failed")?;

    Ok(welcome)
}

pub fn join_from_welcome(
    provider: &OpenMlsRustCrypto,
    mls_group_join_config: &openmls::group::MlsGroupJoinConfig,
    welcome: Welcome,
) -> Result<MlsGroup> {
    let staged = openmls::group::StagedWelcome::new_from_welcome(
        provider,
        mls_group_join_config,
        welcome,
        None,
    )
    .context("staging Welcome failed")?;

    let group = staged
        .into_group(provider)
        .context("turning staged Welcome into MlsGroup failed")?;

    Ok(group)
}

pub fn send_application_message(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    signer: &SignatureKeyPair,
    message: &[u8],
) -> Result<openmls::prelude::MlsMessageOut> {
    let out = group
        .create_message(provider, signer, message)
        .context("creating application message failed")?;
    Ok(out)
}

pub fn receive_message(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    message: impl Into<openmls::framing::ProtocolMessage>,
) -> Result<openmls::prelude::ProcessedMessage> {
    let processed = group
        .process_message(provider, message)
        .context("processing incoming message failed")?;
    Ok(processed)
}

pub fn mls_message_out_to_bytes(msg: &openmls::prelude::MlsMessageOut) -> Result<Vec<u8>> {
    let bytes = tls_codec::Serialize::tls_serialize_detached(msg)
        .context("serializing MlsMessageOut failed")?;
    Ok(bytes)
}

pub fn bytes_to_protocol_message(bytes: &[u8]) -> Result<openmls::framing::ProtocolMessage> {
    let (mls_in, rem) =
        <openmls::framing::MlsMessageIn as tls_codec::DeserializeBytes>::tls_deserialize_bytes(
            bytes,
        )
        .context("deserializing MlsMessageIn from bytes failed")?;

    if !rem.is_empty() {
        return Err(anyhow::anyhow!("trailing bytes after MlsMessageIn"));
    }

    let pm = mls_in.try_into_protocol_message().map_err(|e| {
        anyhow::anyhow!("converting MlsMessageIn to ProtocolMessage failed: {:?}", e)
    })?;

    Ok(pm)
}

pub fn mls_message_out_to_protocol_message(
    msg: &openmls::prelude::MlsMessageOut,
) -> Result<openmls::framing::ProtocolMessage> {
    let bytes = mls_message_out_to_bytes(msg)?;
    let pm = bytes_to_protocol_message(&bytes)?;
    Ok(pm)
}
