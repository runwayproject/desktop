use asphalt::mls;
use openmls::prelude::*;

fn main() -> anyhow::Result<()> {
    let creator = mls::create_identity();
    let mut group = mls::create_group(&creator);

    let joiner = mls::create_identity();
    let joiner_kpb = KeyPackage::builder()
        .build(
            joiner.ciphersuite,
            &joiner.provider,
            &joiner.signer,
            joiner.credential_with_key.clone(),
        )
        .expect("failed to build joiner KeyPackageBundle");

    let kp = joiner_kpb.key_package().clone();

    let welcome =
        mls::create_welcome_message(&mut group, &[kp], &creator.provider, &creator.signer)?;

    let join_config = openmls::group::MlsGroupJoinConfig::builder().build();
    let mut joiner_group = mls::join_from_welcome(&joiner.provider, &join_config, welcome)?;

    let plaintext = b"hello from creator";
    let out =
        mls::send_application_message(&mut group, &creator.provider, &creator.signer, plaintext)?;

    let bytes = mls::mls_message_out_to_bytes(&out)?;

    let pm = mls::bytes_to_protocol_message(&bytes)?;

    let processed = mls::receive_message(&mut joiner_group, &joiner.provider, pm)?;

    println!("Processed message: {:#?}", processed);

    let content = processed.into_content();
    match content {
        ProcessedMessageContent::ApplicationMessage(app) => {
            let bytes = app.into_bytes();
            let clean = String::from_utf8_lossy(&bytes);
            println!("Clean message: {}", clean);
        }
        _ => println!("Processed message was not an application message"),
    }

    Ok(())
}
