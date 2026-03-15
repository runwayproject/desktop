use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use asphalt::mls;
use asphalt::transport::{
    ClientPacket, EncryptedBlob, RequestAuth, ServerPacket, auth_signing_payload, decode_packet,
    encode_packet, read_framed, write_framed,
};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signer, SigningKey};
use openmls::group::GroupId;
use openmls::prelude::{KeyPackage, MlsGroup, MlsGroupJoinConfig, ProcessedMessageContent};
use openmls_traits::OpenMlsProvider;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::fs;
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_ACTIVITY: usize = 200;
const BOOTSTRAP_MAGIC: u32 = 0x52575931;
const PERSISTENCE_VERSION: u32 = 1;
const PERSISTENCE_ENVELOPE_VERSION: u32 = 1;
const PERSISTENCE_SALT_LEN: usize = 16;
const PERSISTENCE_NONCE_LEN: usize = 12;
const PERSISTENCE_KEY_LEN: usize = 32;

pub struct ClientState {
    server_addr: String,
    signing_key: SigningKey,
    my_rid: String,
    activity: VecDeque<String>,
    identity: mls::IdentityBundle,
    conversations: HashMap<String, openmls::group::MlsGroup>,
    conversation_members: HashMap<String, Vec<String>>,
    pending_keypackages: HashMap<String, KeyPackage>,
    pending_group_additions: HashMap<String, String>,
    pending_offer_from: Option<String>,
    active_group_id: Option<String>,
    persistence_salt: Vec<u8>,
    state_key: [u8; PERSISTENCE_KEY_LEN],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedClientState {
    version: u32,
    server_addr: String,
    my_rid: String,
    transport_signing_key: Vec<u8>,
    identity: Vec<u8>,
    identity_signature_public_key: Vec<u8>,
    storage_values: HashMap<Vec<u8>, Vec<u8>>,
    conversation_group_ids: HashMap<String, Vec<u8>>,
    conversation_members: HashMap<String, Vec<String>>,
    active_group_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedPersistedState {
    version: u32,
    kdf: String,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationSummary {
    pub group_id: String,
    pub title: String,
    pub member_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientSnapshot {
    pub server_addr: String,
    pub my_rid: String,
    pub active_group_id: Option<String>,
    pub active_group_title: String,
    pub pending_offer_from: Option<String>,
    pub conversations: Vec<ConversationSummary>,
    pub activity: Vec<String>,
    pub members: Vec<String>,
}

impl ClientState {
    pub fn connect(server_addr: impl Into<String>) -> Result<Self> {
        let server_addr = server_addr.into();
        let passphrase = acquire_state_passphrase()?;

        if let Some(state) = Self::load_persisted_state(&server_addr, &passphrase)? {
            return Ok(state);
        }

        let mut secret = [0_u8; 32];
        rand::rng().fill(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        let persistence_salt = random_persistence_salt();
        let state_key = derive_state_key(&passphrase, &persistence_salt)?;

        let auth = make_auth(&signing_key, "issue_rid", b"");
        let rid = match send_client_packet(&server_addr, ClientPacket::IssueRid { auth })? {
            ServerPacket::RidIssued { rid, .. } => rid,
            other => bail!("expected RidIssued response, got {other:#?}"),
        };

        let mut state = Self {
            server_addr,
            signing_key,
            my_rid: rid,
            activity: VecDeque::new(),
            identity: mls::create_identity(),
            conversations: HashMap::new(),
            conversation_members: HashMap::new(),
            pending_keypackages: HashMap::new(),
            pending_group_additions: HashMap::new(),
            pending_offer_from: None,
            active_group_id: None,
            persistence_salt,
            state_key,
        };

        state.log("Connected to relay.");
        state.save_persisted_state()?;
        Ok(state)
    }

    fn load_persisted_state(server_addr: &str, passphrase: &str) -> Result<Option<Self>> {
        let path = persistence_path(server_addr);
        if !path.exists() {
            return Ok(None);
        }

        let bytes =
            fs::read(&path).with_context(|| format!("reading persisted state at {:?}", path))?;
        let encrypted: EncryptedPersistedState = serde_cbor::from_slice(&bytes)
            .context("decoding encrypted persisted state envelope failed")?;

        if encrypted.version != PERSISTENCE_ENVELOPE_VERSION {
            return Ok(None);
        }

        let state_key = derive_state_key(passphrase, &encrypted.salt)?;
        let plaintext = decrypt_persisted_blob(&encrypted, &state_key)
            .context("decrypting persisted state failed")?;
        let persisted: PersistedClientState = serde_cbor::from_slice(&plaintext)
            .context("decoding decrypted persisted state failed")?;

        if persisted.version != PERSISTENCE_VERSION {
            return Ok(None);
        }

        if persisted.transport_signing_key.len() != 32 {
            bail!("persisted transport signing key has invalid length")
        }

        let mut sk_bytes = [0_u8; 32];
        sk_bytes.copy_from_slice(&persisted.transport_signing_key);
        let signing_key = SigningKey::from_bytes(&sk_bytes);

        let identity = mls::create_identity_from_persisted(
            persisted.storage_values,
            persisted.identity,
            persisted.identity_signature_public_key,
        )?;

        let mut conversations: HashMap<String, MlsGroup> = HashMap::new();
        for (app_group_id, mls_group_id_bytes) in &persisted.conversation_group_ids {
            let mls_group_id = GroupId::from_slice(mls_group_id_bytes);
            if let Some(group) = MlsGroup::load(identity.provider.storage(), &mls_group_id)
                .context("loading MLS group from provider storage failed")?
            {
                conversations.insert(app_group_id.clone(), group);
            }
        }

        let active_group_id = persisted
            .active_group_id
            .filter(|group_id| conversations.contains_key(group_id));

        let mut state = Self {
            server_addr: persisted.server_addr,
            signing_key,
            my_rid: persisted.my_rid,
            activity: VecDeque::new(),
            identity,
            conversations,
            conversation_members: persisted.conversation_members,
            pending_keypackages: HashMap::new(),
            pending_group_additions: HashMap::new(),
            pending_offer_from: None,
            active_group_id,
            persistence_salt: encrypted.salt,
            state_key,
        };

        state.log("Loaded local MLS state.");
        Ok(Some(state))
    }

    fn save_persisted_state(&self) -> Result<()> {
        let mut conversation_group_ids = HashMap::new();
        for (app_group_id, group) in &self.conversations {
            conversation_group_ids.insert(app_group_id.clone(), group.group_id().to_vec());
        }

        let storage_values = self
            .identity
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| anyhow::anyhow!("provider storage lock poisoned"))?
            .clone();

        let persisted = PersistedClientState {
            version: PERSISTENCE_VERSION,
            server_addr: self.server_addr.clone(),
            my_rid: self.my_rid.clone(),
            transport_signing_key: self.signing_key.to_bytes().to_vec(),
            identity: extract_identity_bytes(&self.identity.credential_with_key),
            identity_signature_public_key: self.identity.signer.to_public_vec(),
            storage_values,
            conversation_group_ids,
            conversation_members: self.conversation_members.clone(),
            active_group_id: self.active_group_id.clone(),
        };

        let plaintext =
            serde_cbor::to_vec(&persisted).context("encoding persisted state failed")?;
        let encrypted = encrypt_persisted_blob(&plaintext, &self.state_key, &self.persistence_salt)
            .context("encrypting persisted state failed")?;
        let bytes =
            serde_cbor::to_vec(&encrypted).context("encoding encrypted persisted state failed")?;
        let path = persistence_path(&self.server_addr);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating persistence directory at {:?}", parent))?;
        }

        fs::write(&path, bytes)
            .with_context(|| format!("writing persisted state at {:?}", path))?;
        Ok(())
    }

    pub fn snapshot(&self) -> ClientSnapshot {
        let members = match &self.active_group_id {
            Some(active) => self
                .conversation_members
                .get(active)
                .cloned()
                .unwrap_or_default(),
            None => Vec::new(),
        };

        let active_group_title = self
            .active_group_id
            .as_ref()
            .map(|group_id| self.conversation_title(group_id))
            .unwrap_or_else(|| "No group selected".to_string());

        ClientSnapshot {
            server_addr: self.server_addr.clone(),
            my_rid: self.my_rid.clone(),
            active_group_id: self.active_group_id.clone(),
            active_group_title,
            pending_offer_from: self.pending_offer_from.clone(),
            conversations: self.sorted_conversations(),
            activity: self.activity.iter().cloned().collect(),
            members,
        }
    }

    pub fn create_group(&mut self) -> Result<()> {
        let group_id = self.allocate_group_id();
        let group = mls::create_group(&self.identity);
        self.conversations.insert(group_id.clone(), group);
        self.conversation_members
            .insert(group_id.clone(), vec![self.my_rid.clone()]);
        self.active_group_id = Some(group_id.clone());
        self.log(format!(
            "Created group {}. Invite members from the Groups view.",
            short_group_id(&group_id)
        ));
        self.save_persisted_state()?;
        Ok(())
    }

    pub fn add_peer(&mut self, target_rid: String) -> Result<()> {
        let target_rid = target_rid.trim().to_string();
        if target_rid.is_empty() {
            bail!("peer RID cannot be empty")
        }

        let key_package = mls::build_keypackage(&self.identity)?;
        let key_package_bytes = mls::keypackage_to_bytes(&key_package)?;
        let envelope = BootstrapEnvelope {
            magic: BOOTSTRAP_MAGIC,
            payload: BootstrapPayload::KeyPackageOffer {
                from_rid: self.my_rid.clone(),
                key_package: key_package_bytes,
            },
        };

        self.send_bootstrap_envelope(envelope, target_rid.clone())?;
        self.log(format!("Sent KeyPackage to {}.", target_rid));
        Ok(())
    }

    pub fn add_member(&mut self, member_rid: String) -> Result<()> {
        let member_rid = member_rid.trim().to_string();
        if member_rid.is_empty() {
            bail!("member RID cannot be empty")
        }

        let active = self
            .active_group_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no active group selected"))?;

        if let Some(members) = self.conversation_members.get(&active)
            && members.contains(&member_rid)
        {
            bail!(
                "{} is already a member of group {}",
                member_rid,
                short_group_id(&active)
            )
        }

        let maybe_kp = self.pending_keypackages.remove(&member_rid);

        let key_package = match maybe_kp {
            Some(kp) => kp,
            None => {
                self.pending_group_additions
                    .insert(member_rid.clone(), active.clone());
                let envelope = BootstrapEnvelope {
                    magic: BOOTSTRAP_MAGIC,
                    payload: BootstrapPayload::KeyPackageRequest {
                        from_rid: self.my_rid.clone(),
                    },
                };

                self.send_bootstrap_envelope(envelope, member_rid.clone())?;
                self.log(format!(
                    "Requested a KeyPackage from {} for group {}. The member will be added when it arrives.",
                    member_rid,
                    short_group_id(&active)
                ));
                return Ok(());
            }
        };

        self.finalize_add_member(active, member_rid, key_package)
    }

    fn finalize_add_member(
        &mut self,
        group_id: String,
        member_rid: String,
        key_package: KeyPackage,
    ) -> Result<()> {
        let current_members = self
            .conversation_members
            .get(&group_id)
            .cloned()
            .unwrap_or_else(|| vec![self.my_rid.clone()]);

        let (commit, welcome, ratchet_tree) = {
            let group = self
                .conversations
                .get_mut(&group_id)
                .with_context(|| format!("no local group for {}", short_group_id(&group_id)))?;

            let (commit, welcome) = mls::add_members_and_get_commit(
                group,
                &[key_package],
                &self.identity.provider,
                &self.identity.signer,
            )?;
            let ratchet_tree = mls::export_ratchet_tree_to_bytes(group)?;
            (commit, welcome, ratchet_tree)
        };

        let mut updated_members = current_members.clone();
        if !updated_members.contains(&member_rid) {
            updated_members.push(member_rid.clone());
        }

        let welcome_bytes = mls::welcome_to_bytes(&welcome)?;
        let envelope = BootstrapEnvelope {
            magic: BOOTSTRAP_MAGIC,
            payload: BootstrapPayload::Welcome {
                from_rid: self.my_rid.clone(),
                group_id: group_id.clone(),
                members: updated_members.clone(),
                ratchet_tree,
                welcome: welcome_bytes,
            },
        };

        self.send_bootstrap_envelope(envelope, member_rid.clone())?;
        let commit_bytes = mls::mls_message_out_to_bytes(&commit)?;
        let commit_recipients = current_members
            .iter()
            .filter(|rid| {
                rid.as_str() != self.my_rid.as_str() && rid.as_str() != member_rid.as_str()
            })
            .cloned()
            .collect::<Vec<_>>();

        for existing_rid in commit_recipients {
            let envelope = BootstrapEnvelope {
                magic: BOOTSTRAP_MAGIC,
                payload: BootstrapPayload::GroupCommit {
                    from_rid: self.my_rid.clone(),
                    group_id: group_id.clone(),
                    added_rid: Some(member_rid.clone()),
                    commit: commit_bytes.clone(),
                },
            };
            self.send_bootstrap_envelope(envelope, existing_rid)?;
        }

        self.conversation_members
            .insert(group_id.clone(), updated_members);

        self.log(format!(
            "Added {} to group {} and sent Welcome.",
            member_rid,
            short_group_id(&group_id)
        ));
        self.save_persisted_state()?;
        Ok(())
    }

    pub fn select_group(&mut self, group_id: String) -> Result<()> {
        if !self.conversations.contains_key(&group_id) {
            bail!("unknown group {group_id}")
        }

        self.active_group_id = Some(group_id.clone());
        self.save_persisted_state()?;
        Ok(())
    }

    pub fn clear_activity(&mut self) {
        self.activity.clear();
        self.log("Activity cleared.");
    }

    pub fn accept_pending_offer(&mut self) -> Result<()> {
        let Some(from_rid) = self.pending_offer_from.take() else {
            return Ok(());
        };

        self.create_invite_for_target(from_rid)
    }

    pub fn reject_pending_offer(&mut self) {
        if let Some(from_rid) = self.pending_offer_from.take() {
            self.pending_keypackages.remove(&from_rid);
            self.log(format!("Rejected KeyPackage offer from {}.", from_rid));
        }
    }

    pub fn send_message(&mut self, message: String) -> Result<()> {
        let clean = message.trim().to_string();
        if clean.is_empty() {
            return Ok(());
        }

        let target = self.active_group_id.clone().ok_or_else(|| {
            anyhow::anyhow!("no active group. Create a group first or accept an invite")
        })?;

        let group = self.conversations.get_mut(&target).with_context(|| {
            format!(
                "active group {} has no established MLS conversation",
                target
            )
        })?;

        let out = mls::send_application_message(
            group,
            &self.identity.provider,
            &self.identity.signer,
            clean.as_bytes(),
        )?;
        let ciphertext = mls::mls_message_out_to_bytes(&out)?;

        let recipients = self
            .conversation_members
            .get(&target)
            .cloned()
            .unwrap_or_else(|| vec![target.clone()]);

        let mut delivered = Vec::new();
        for recipient_rid in recipients {
            if recipient_rid == self.my_rid {
                continue;
            }

            let blob = EncryptedBlob::new(recipient_rid.clone(), ciphertext.clone());
            match send_client_packet(&self.server_addr, ClientPacket::PutBlob { blob })? {
                ServerPacket::Accepted { rid, .. } => {
                    delivered.push(rid);
                }
                ServerPacket::Error { message } => {
                    self.log(format!(
                        "Server rejected message to {}: {message}",
                        recipient_rid
                    ));
                }
                other => {
                    self.log(format!(
                        "Unexpected response on send to {}: {other:#?}",
                        recipient_rid
                    ));
                }
            }
        }

        self.log(format!(
            "You (group {}): {}",
            short_group_id(&target),
            clean
        ));

        self.save_persisted_state()?;

        Ok(())
    }

    pub fn fetch_messages(&mut self, quiet_empty: bool) -> Result<()> {
        let auth = make_auth(&self.signing_key, "fetch_queued", self.my_rid.as_bytes());
        let response = send_client_packet(
            &self.server_addr,
            ClientPacket::FetchQueued {
                rid: self.my_rid.clone(),
                auth,
            },
        )?;

        match response {
            ServerPacket::QueuedBlobs { blobs, .. } => {
                if blobs.is_empty() {
                    if !quiet_empty {
                        self.log("No queued blobs.");
                    }
                    return Ok(());
                }

                for blob in blobs {
                    self.process_incoming_blob(blob)?;
                }
                self.save_persisted_state()?;
            }
            ServerPacket::Error { message } => {
                self.log(format!("Fetch denied: {message}"));
            }
            other => {
                self.log(format!("Unexpected response on fetch: {other:#?}"));
            }
        }

        Ok(())
    }

    fn sorted_conversations(&self) -> Vec<ConversationSummary> {
        let mut conversations = self
            .conversations
            .keys()
            .cloned()
            .map(|group_id| ConversationSummary {
                title: self.conversation_title(&group_id),
                member_count: self
                    .conversation_members
                    .get(&group_id)
                    .map(|members| members.len())
                    .unwrap_or(0),
                group_id,
            })
            .collect::<Vec<_>>();
        conversations.sort_by(|left, right| left.title.cmp(&right.title));
        conversations
    }

    fn create_invite_for_target(&mut self, target: String) -> Result<()> {
        let key_package = self
            .pending_keypackages
            .remove(&target)
            .with_context(|| format!("no pending KeyPackage from {}", target))?;

        let group_id = self.allocate_group_id();
        let mut group = mls::create_group(&self.identity);
        let welcome = mls::create_welcome_message(
            &mut group,
            &[key_package],
            &self.identity.provider,
            &self.identity.signer,
        )?;

        let welcome_bytes = mls::welcome_to_bytes(&welcome)?;
        let ratchet_tree = mls::export_ratchet_tree_to_bytes(&group)?;
        let envelope = BootstrapEnvelope {
            magic: BOOTSTRAP_MAGIC,
            payload: BootstrapPayload::Welcome {
                from_rid: self.my_rid.clone(),
                group_id: group_id.clone(),
                members: vec![self.my_rid.clone(), target.clone()],
                ratchet_tree,
                welcome: welcome_bytes,
            },
        };

        self.send_bootstrap_envelope(envelope, target.clone())?;
        self.conversations.insert(group_id.clone(), group);
        self.conversation_members
            .insert(group_id.clone(), vec![self.my_rid.clone(), target.clone()]);
        self.active_group_id = Some(group_id.clone());
        self.log(format!(
            "Created group {} and invited {}.",
            short_group_id(&group_id),
            target
        ));
        self.save_persisted_state()?;
        Ok(())
    }

    fn process_incoming_blob(&mut self, blob: EncryptedBlob) -> Result<()> {
        if let Ok(envelope) = serde_cbor::from_slice::<BootstrapEnvelope>(&blob.ciphertext)
            && envelope.magic == BOOTSTRAP_MAGIC
        {
            self.handle_bootstrap_envelope(envelope)?;
            return Ok(());
        }

        let mut decrypted_line: Option<(String, String)> = None;
        for (group_id, group) in &mut self.conversations {
            let pm = match mls::bytes_to_protocol_message(&blob.ciphertext) {
                Ok(pm) => pm,
                Err(_) => continue,
            };

            let processed = match mls::receive_message(group, &self.identity.provider, pm) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let text = match processed.into_content() {
                ProcessedMessageContent::ApplicationMessage(app) => {
                    String::from_utf8_lossy(&app.into_bytes()).to_string()
                }
                _ => "non-application MLS message".to_string(),
            };

            decrypted_line = Some((group_id.clone(), text));
            break;
        }

        if let Some((group_id, line)) = decrypted_line {
            self.active_group_id = Some(group_id.clone());
            self.log(format!("[{}] {}", self.conversation_title(&group_id), line));
        } else {
            self.log(format!(
                "Received {} bytes, but no local group could decrypt it.",
                blob.ciphertext.len()
            ));
        }

        Ok(())
    }

    fn handle_bootstrap_envelope(&mut self, envelope: BootstrapEnvelope) -> Result<()> {
        match envelope.payload {
            BootstrapPayload::KeyPackageRequest { from_rid } => {
                let key_package = mls::build_keypackage(&self.identity)?;
                let key_package_bytes = mls::keypackage_to_bytes(&key_package)?;
                let envelope = BootstrapEnvelope {
                    magic: BOOTSTRAP_MAGIC,
                    payload: BootstrapPayload::KeyPackageOffer {
                        from_rid: self.my_rid.clone(),
                        key_package: key_package_bytes,
                    },
                };

                self.send_bootstrap_envelope(envelope, from_rid.clone())?;
                self.log(format!(
                    "Sent KeyPackage to {} for an existing group invitation.",
                    from_rid
                ));
            }
            BootstrapPayload::KeyPackageOffer {
                from_rid,
                key_package,
            } => {
                let kp = mls::bytes_to_keypackage(&self.identity.provider, &key_package)?;
                if let Some(group_id) = self.pending_group_additions.remove(&from_rid) {
                    self.finalize_add_member(group_id.clone(), from_rid.clone(), kp)?;
                    self.log(format!(
                        "Received KeyPackage from {} and completed the add to group {}.",
                        from_rid,
                        short_group_id(&group_id)
                    ));
                } else {
                    self.pending_keypackages.insert(from_rid.clone(), kp);
                    self.pending_offer_from = Some(from_rid.clone());
                    self.log(format!(
                        "Incoming invite request from {}. Accept or reject it from the sidebar.",
                        from_rid
                    ));
                }
            }
            BootstrapPayload::Welcome {
                from_rid,
                group_id,
                members,
                ratchet_tree,
                welcome,
            } => {
                let welcome = mls::bytes_to_welcome(&welcome)?;
                let ratchet_tree = mls::bytes_to_ratchet_tree(&ratchet_tree)?;
                let join_cfg = MlsGroupJoinConfig::builder().build();
                let group = mls::join_from_welcome(
                    &self.identity.provider,
                    &join_cfg,
                    welcome,
                    Some(ratchet_tree),
                )?;
                self.conversations.insert(group_id.clone(), group);
                self.conversation_members.insert(group_id.clone(), members);
                self.active_group_id = Some(group_id.clone());
                self.log(format!(
                    "Joined group {} from {}. You can now chat.",
                    short_group_id(&group_id),
                    from_rid
                ));
                self.save_persisted_state()?;
            }
            BootstrapPayload::GroupCommit {
                from_rid,
                group_id,
                added_rid,
                commit,
            } => {
                let pm = mls::bytes_to_protocol_message(&commit)?;
                let updated_group = self
                    .conversations
                    .get_mut(&group_id)
                    .with_context(|| format!("received commit for unknown group {}", group_id))?;

                let processed = mls::receive_message(updated_group, &self.identity.provider, pm)?;
                if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                    processed.into_content()
                {
                    mls::merge_staged_commit(
                        updated_group,
                        &self.identity.provider,
                        *staged_commit,
                    )?;
                    if let Some(added_rid) = added_rid {
                        let members = self
                            .conversation_members
                            .entry(group_id.clone())
                            .or_insert_with(|| vec![self.my_rid.clone()]);
                        if !members.contains(&added_rid) {
                            members.push(added_rid.clone());
                        }
                        self.log(format!(
                            "{} added {} to group {}.",
                            from_rid,
                            added_rid,
                            short_group_id(&group_id)
                        ));
                    } else {
                        self.log(format!(
                            "Processed group commit from {} for group {}.",
                            from_rid,
                            short_group_id(&group_id)
                        ));
                    }
                    self.save_persisted_state()?;
                } else {
                    bail!("received non-commit MLS payload in GroupCommit envelope")
                }
            }
        }
        Ok(())
    }

    fn allocate_group_id(&self) -> String {
        loop {
            let candidate = random_group_id();
            if !self.conversations.contains_key(&candidate) {
                return candidate;
            }
        }
    }

    fn conversation_title(&self, group_id: &str) -> String {
        let Some(members) = self.conversation_members.get(group_id) else {
            return format!("Group {}", short_group_id(group_id));
        };

        let others = members
            .iter()
            .filter(|rid| rid.as_str() != self.my_rid.as_str())
            .cloned()
            .collect::<Vec<_>>();

        if others.is_empty() {
            return format!("Group {}", short_group_id(group_id));
        }

        if others.len() <= 2 {
            return others.join(", ");
        }

        format!("{}, {} +{}", others[0], others[1], others.len() - 2)
    }

    fn send_bootstrap_envelope(
        &mut self,
        envelope: BootstrapEnvelope,
        recipient_rid: String,
    ) -> Result<()> {
        let payload =
            serde_cbor::to_vec(&envelope).context("encoding bootstrap envelope failed")?;
        let blob = EncryptedBlob::new(recipient_rid, payload);
        match send_client_packet(&self.server_addr, ClientPacket::PutBlob { blob })? {
            ServerPacket::Accepted { .. } => Ok(()),
            ServerPacket::Error { message } => Err(anyhow::anyhow!(message)),
            other => Err(anyhow::anyhow!(
                "unexpected response while sending bootstrap envelope: {other:#?}"
            )),
        }
    }

    fn log(&mut self, line: impl Into<String>) {
        if self.activity.len() >= MAX_ACTIVITY {
            let _ = self.activity.pop_front();
        }
        self.activity.push_back(line.into());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BootstrapEnvelope {
    magic: u32,
    payload: BootstrapPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum BootstrapPayload {
    KeyPackageRequest {
        from_rid: String,
    },
    KeyPackageOffer {
        from_rid: String,
        key_package: Vec<u8>,
    },
    Welcome {
        from_rid: String,
        group_id: String,
        members: Vec<String>,
        ratchet_tree: Vec<u8>,
        welcome: Vec<u8>,
    },
    GroupCommit {
        from_rid: String,
        group_id: String,
        added_rid: Option<String>,
        commit: Vec<u8>,
    },
}

fn short_group_id(group_id: &str) -> String {
    group_id.chars().take(8).collect()
}

fn random_group_id() -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill(&mut bytes);

    let mut id = String::with_capacity(32);
    for byte in bytes {
        let _ = write!(&mut id, "{:02x}", byte);
    }
    id
}

fn extract_identity_bytes(credential_with_key: &openmls::prelude::CredentialWithKey) -> Vec<u8> {
    credential_with_key.credential.serialized_content().to_vec()
}

fn persistence_path(server_addr: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(server_addr.as_bytes());
    let digest = hasher.finalize();

    let mut suffix = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        let _ = write!(&mut suffix, "{:02x}", byte);
    }

    let mut base = executable_dir();
    base.push(format!("desktop-state-{}.cbor", suffix));
    base
}

fn executable_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn acquire_state_passphrase() -> Result<String> {
    let value = rpassword::prompt_password("State passphrase: ")
        .context("prompting for state passphrase failed")?;
    if value.trim().is_empty() {
        bail!("state passphrase cannot be empty")
    }

    Ok(value)
}

fn encrypt_persisted_blob(
    plaintext: &[u8],
    state_key: &[u8; PERSISTENCE_KEY_LEN],
    salt: &[u8],
) -> Result<EncryptedPersistedState> {
    let mut nonce = vec![0_u8; PERSISTENCE_NONCE_LEN];
    rand::rng().fill(nonce.as_mut_slice());

    let cipher = ChaCha20Poly1305::new(state_key.into());
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow::anyhow!("encrypting persisted state payload failed"))?;

    Ok(EncryptedPersistedState {
        version: PERSISTENCE_ENVELOPE_VERSION,
        kdf: "argon2id".to_string(),
        salt: salt.to_vec(),
        nonce,
        ciphertext,
    })
}

fn decrypt_persisted_blob(
    encrypted: &EncryptedPersistedState,
    state_key: &[u8; PERSISTENCE_KEY_LEN],
) -> Result<Vec<u8>> {
    if encrypted.kdf != "argon2id" {
        bail!("unsupported persisted-state KDF: {}", encrypted.kdf)
    }

    if encrypted.nonce.len() != PERSISTENCE_NONCE_LEN {
        bail!("invalid persisted-state nonce length")
    }

    let cipher = ChaCha20Poly1305::new(state_key.into());
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&encrypted.nonce),
            encrypted.ciphertext.as_ref(),
        )
        .map_err(|_| anyhow::anyhow!("decrypting persisted state payload failed"))?;
    Ok(plaintext)
}

fn derive_state_key(passphrase: &str, salt: &[u8]) -> Result<[u8; PERSISTENCE_KEY_LEN]> {
    if salt.len() != PERSISTENCE_SALT_LEN {
        bail!("invalid persisted-state salt length")
    }

    let mut key = [0_u8; PERSISTENCE_KEY_LEN];
    let params = Params::new(64 * 1024, 3, 1, Some(PERSISTENCE_KEY_LEN))
        .map_err(|e| anyhow::anyhow!("building Argon2id params failed: {e:?}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("deriving state key with Argon2id failed: {e:?}"))?;
    Ok(key)
}

fn random_persistence_salt() -> Vec<u8> {
    let mut salt = vec![0_u8; PERSISTENCE_SALT_LEN];
    rand::rng().fill(salt.as_mut_slice());
    salt
}

fn make_auth(signing_key: &SigningKey, action: &str, body: &[u8]) -> RequestAuth {
    let mut nonce = [0_u8; 16];
    rand::rng().fill(&mut nonce);

    let mut auth = RequestAuth {
        credential_public_key: signing_key.verifying_key().to_bytes().to_vec(),
        nonce: nonce.to_vec(),
        signed_at_unix_ms: unix_ms_now(),
        signature: Vec::new(),
    };

    let payload = auth_signing_payload(action, body, &auth);
    auth.signature = signing_key.sign(&payload).to_bytes().to_vec();
    auth
}

fn send_client_packet(addr: &str, packet: ClientPacket) -> Result<ServerPacket> {
    let mut stream = TcpStream::connect(addr).with_context(|| format!("connect to {}", addr))?;
    let bytes = encode_packet(&packet)?;
    write_framed(&mut stream, &bytes)?;
    let frame = read_framed(&mut stream, 2 * 1024 * 1024)?;
    let response: ServerPacket = decode_packet(&frame)?;
    Ok(response)
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
