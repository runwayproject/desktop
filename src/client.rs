use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use asphalt::mls;
use librunway::relay_client::{fetch_queued, issue_rid, put_blob, rotate_rid};
use librunway::transport::{EncryptedBlob, ServerPacket};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::SigningKey;
use openmls::group::GroupId;
use openmls::prelude::{KeyPackage, MlsGroup, MlsGroupJoinConfig, ProcessedMessageContent};
use openmls_traits::OpenMlsProvider;
use rand::RngExt;
use runway_token::token::parse_token;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

// consts
const MAX_ACTIVITY: usize = 200;
const BOOTSTRAP_MAGIC: u32 = 0x52575931;
const GROUP_CONTROL_MAGIC: u32 = 0x52575932;
const PERSISTENCE_VERSION: u32 = 2; // group-specific messages so bump
const PERSISTENCE_ENVELOPE_VERSION: u32 = 1;
const PERSISTENCE_SALT_LEN: usize = 16;
const PERSISTENCE_NONCE_LEN: usize = 12;
const PERSISTENCE_KEY_LEN: usize = 32;

pub struct ClientState {
    server_addr: String,
    signing_key: SigningKey,
    my_rid: String,
    activity_by_group: HashMap<String, VecDeque<String>>,
    identity: mls::IdentityBundle,
    conversations: HashMap<String, openmls::group::MlsGroup>,
    conversation_members: HashMap<String, Vec<String>>,
    pending_keypackages: HashMap<String, KeyPackage>,
    pending_keypackage_requests: HashMap<String, KeyPackage>,
    pending_group_additions: HashMap<String, String>,
    pending_offer_from: Option<String>,
    active_group_id: Option<String>,
    persistence_salt: Vec<u8>,
    state_key: [u8; PERSISTENCE_KEY_LEN],
}

#[derive(Debug, Clone)]
struct RecipientEndpoint {
    rid: String,
    relay: String,
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
    activity_by_group: HashMap<String, Vec<String>>,
    active_group_id: Option<String>,
    pending_keypackages: HashMap<String, Vec<u8>>,
    pending_keypackages_to_send: HashMap<String, Vec<u8>>,
    pending_group_additions: HashMap<String, String>,
    pending_offer_from: Option<String>,
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
    pub my_token: String,
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
        let is_first_launch = !persistence_path().exists();
        let passphrase = acquire_state_passphrase(is_first_launch)?;

        if let Some(state) = Self::load_persisted_state(passphrase.as_str())? {
            if !relay_eq(&state.server_addr, &server_addr) {
                let path = persistence_path();
                bail!(
                    "persisted state is bound to relay {} but requested {}. remove {:?} to start fresh on a new relay",
                    state.server_addr,
                    server_addr,
                    path
                )
            }
            return Ok(state);
        }

        let signing_key = {
            let mut secret = [0_u8; 32];
            rand::rng().fill(&mut secret);
            let key = SigningKey::from_bytes(&secret);
            secret.zeroize();
            key
        };
        let persistence_salt = random_persistence_salt();
        let state_key = derive_state_key(passphrase.as_str(), &persistence_salt)?;

        let rid = match issue_rid(&server_addr, &signing_key)? {
            ServerPacket::RidIssued { rid, .. } => rid,
            other => bail!("expected RidIssued response, got {other:#?}"),
        };

        let mut state = Self {
            server_addr,
            signing_key,
            my_rid: rid,
            activity_by_group: HashMap::new(),
            identity: mls::create_identity(),
            conversations: HashMap::new(),
            conversation_members: HashMap::new(),
            pending_keypackages: HashMap::new(),
            pending_keypackage_requests: HashMap::new(),
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

    fn load_persisted_state(passphrase: &str) -> Result<Option<Self>> {
        let path = persistence_path();
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
        let mut plaintext = decrypt_persisted_blob(&encrypted, &state_key)
            .context("decrypting persisted state failed")?;
        let mut persisted: PersistedClientState = serde_cbor::from_slice(&plaintext)
            .context("decoding decrypted persisted state failed")?;
        plaintext.zeroize();

        if persisted.version != PERSISTENCE_VERSION {
            bail!(
                "persisted state version {} is unsupported (expected {}); remove {:?} to start fresh or use an older version of Asphalt.",
                persisted.version,
                PERSISTENCE_VERSION,
                path
            )
        }

        if persisted.transport_signing_key.len() != 32 {
            bail!("persisted transport signing key has invalid length")
        }

        let mut sk_bytes = [0_u8; 32];
        sk_bytes.copy_from_slice(&persisted.transport_signing_key);
        let signing_key = SigningKey::from_bytes(&sk_bytes);
        sk_bytes.zeroize();
        persisted.transport_signing_key.zeroize();

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

        let server_addr = persisted.server_addr.clone();
        let mut conversation_members: HashMap<String, Vec<String>> = HashMap::new();
        for (group_id, members) in persisted.conversation_members {
            let mut normalized_members = Vec::new();
            for member in members {
                if let Some(normalized) = normalize_recipient_for_storage(&member, &server_addr)
                    && !normalized_members.contains(&normalized)
                {
                    normalized_members.push(normalized);
                }
            }
            conversation_members.insert(group_id, normalized_members);
        }

        let mut activity_by_group: HashMap<String, VecDeque<String>> = HashMap::new();
        for (group_id, activity) in persisted.activity_by_group {
            if conversations.contains_key(group_id.as_str()) {
                activity_by_group.insert(group_id, activity.into_iter().collect());
            }
        }

        let mut pending_keypackages: HashMap<String, KeyPackage> = HashMap::new();
        for (rid, kp_bytes) in persisted.pending_keypackages {
            match mls::bytes_to_keypackage(&identity.provider, &kp_bytes) {
                Ok(kp) => {
                    if let Some(normalized_rid) = normalize_recipient_for_storage(&rid, &server_addr)
                    {
                        pending_keypackages.insert(normalized_rid, kp);
                    }
                }
                Err(_) => {}
            }
        }
        let mut pending_keypackage_requests: HashMap<String, KeyPackage> = HashMap::new();
        for (rid, kp_bytes) in persisted.pending_keypackages_to_send {
            match mls::bytes_to_keypackage(&identity.provider, &kp_bytes) {
                Ok(kp) => {
                    if let Some(normalized_rid) = normalize_recipient_for_storage(&rid, &server_addr)
                    {
                        pending_keypackage_requests.insert(normalized_rid, kp);
                    }
                }
                Err(_) => {}
            }
        }
        let pending_group_additions: HashMap<String, String> = persisted
            .pending_group_additions
            .into_iter()
            .filter_map(|(rid, group_id)| {
                if !conversations.contains_key(group_id.as_str()) {
                    return None;
                }
                normalize_recipient_for_storage(&rid, &server_addr)
                    .map(|normalized| (normalized, group_id))
            })
            .collect();
        let pending_offer_from = persisted
            .pending_offer_from
            .and_then(|rid| normalize_recipient_for_storage(&rid, &server_addr))
            .filter(|rid| {
                pending_keypackages.contains_key(rid.as_str())
                    || pending_keypackage_requests.contains_key(rid.as_str())
            });

        let mut state = Self {
            server_addr,
            signing_key,
            my_rid: persisted.my_rid,
            activity_by_group,
            identity,
            conversations,
            conversation_members,
            pending_keypackages,
            pending_keypackage_requests,
            pending_group_additions,
            pending_offer_from,
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

        let mut activity_by_group = HashMap::new();
        for (group_id, activity) in &self.activity_by_group {
            activity_by_group.insert(group_id.clone(), activity.iter().cloned().collect());
        }

        let storage_values = self
            .identity
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| anyhow::anyhow!("provider storage lock poisoned"))?
            .clone();

        let mut pending_keypackages_bytes: HashMap<String, Vec<u8>> = HashMap::new();
        for (rid, kp) in &self.pending_keypackages {
            let bytes = mls::keypackage_to_bytes(kp)
                .with_context(|| format!("serializing pending KeyPackage for {rid} failed"))?;
            pending_keypackages_bytes.insert(rid.clone(), bytes);
        }
        let mut pending_keypackages_to_send: HashMap<String, Vec<u8>> = HashMap::new();
        for (rid, kp) in &self.pending_keypackage_requests {
            let bytes = mls::keypackage_to_bytes(kp).with_context(|| {
                format!("serializing outgoing pending KeyPackage for {rid} failed")
            })?;
            pending_keypackages_to_send.insert(rid.clone(), bytes);
        }

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
            activity_by_group,
            active_group_id: self.active_group_id.clone(),
            pending_keypackages: pending_keypackages_bytes,
            pending_keypackages_to_send: pending_keypackages_to_send,
            pending_group_additions: self.pending_group_additions.clone(),
            pending_offer_from: self.pending_offer_from.clone(),
        };

        let plaintext =
            serde_cbor::to_vec(&persisted).context("encoding persisted state failed")?;
        let encrypted = encrypt_persisted_blob(&plaintext, &self.state_key, &self.persistence_salt)
            .context("encrypting persisted state failed")?;
        let bytes =
            serde_cbor::to_vec(&encrypted).context("encoding encrypted persisted state failed")?;
        let path = persistence_path();
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

        let activity = self
            .active_group_id
            .as_ref()
            .and_then(|group_id| self.activity_by_group.get(group_id))
            .map(|history| history.iter().cloned().collect())
            .unwrap_or_default();

        ClientSnapshot {
            server_addr: self.server_addr.clone(),
            my_rid: self.my_rid.clone(),
            my_token: self.build_self_token(),
            active_group_id: self.active_group_id.clone(),
            active_group_title,
            pending_offer_from: self.pending_offer_from.clone(),
            conversations: self.sorted_conversations(),
            activity,
            members,
        }
    }

    pub fn create_group(&mut self) -> Result<()> {
        let group_id = self.allocate_group_id();
        let group = mls::create_group(&self.identity);
        self.conversations.insert(group_id.clone(), group);
        self.conversation_members
            .insert(group_id.clone(), vec![self.qualified_my_rid()]);
        self.active_group_id = Some(group_id.clone());
        self.log(format!(
            "Created group {}. Invite members from the Groups view.",
            short_group_id(&group_id)
        ));
        self.save_persisted_state()?;
        Ok(())
    }

    pub fn add_peer(&mut self, target_rid: String) -> Result<()> {
        let target_rid = normalize_recipient_input(&target_rid, &self.server_addr)?;

        let key_package = mls::build_keypackage(&self.identity)?;
        let key_package_bytes = mls::keypackage_to_bytes(&key_package)?;
        let envelope = BootstrapEnvelope {
            magic: BOOTSTRAP_MAGIC,
            payload: BootstrapPayload::KeyPackageOffer {
                from_rid: self.qualified_my_rid(),
                key_package: key_package_bytes,
            },
        };

        self.send_bootstrap_envelope(envelope, target_rid.clone())?;
        self.log(format!("Sent KeyPackage to {}.", target_rid));
        Ok(())
    }

    pub fn add_member(&mut self, member_rid: String) -> Result<()> {
        let member_rid = normalize_recipient_input(&member_rid, &self.server_addr)?;

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
                        from_rid: self.qualified_my_rid(),
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
            .unwrap_or_else(|| vec![self.qualified_my_rid()]);

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
                from_rid: self.qualified_my_rid(),
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
                !self.rid_matches_self(rid) && rid.as_str() != member_rid.as_str()
            })
            .cloned()
            .collect::<Vec<_>>();

        for existing_rid in commit_recipients {
            let envelope = BootstrapEnvelope {
                magic: BOOTSTRAP_MAGIC,
                payload: BootstrapPayload::GroupCommit {
                    from_rid: self.qualified_my_rid(),
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
        if let Some(active_group_id) = self.active_group_id.clone() {
            self.activity_by_group.remove(&active_group_id);
        }
    }

    pub fn rotate_rid(&mut self) -> Result<()> {
        let old_rid = self.my_rid.clone();
        let response = rotate_rid(&self.server_addr, &self.signing_key, &old_rid)?;

        match response {
            ServerPacket::RidRotated { new_rid, .. } => {
                self.apply_new_rid(old_rid, new_rid, false)?;
                Ok(())
            }
            ServerPacket::Error { message } => {
                if is_rid_missing_error(&message) {
                    self.issue_new_rid(old_rid)
                } else {
                    bail!("RID rotate denied: {message}")
                }
            }
            other => bail!("unexpected response while rotating RID: {other:#?}"),
        }
    }

    pub fn accept_pending_offer(&mut self) -> Result<()> {
        let Some(from_rid) = self.pending_offer_from.take() else {
            return Ok(());
        };

        if let Some(kp) = self.pending_keypackage_requests.remove(&from_rid) {
            let key_package_bytes = mls::keypackage_to_bytes(&kp)?;
            let envelope = BootstrapEnvelope {
                magic: BOOTSTRAP_MAGIC,
                payload: BootstrapPayload::KeyPackageOffer {
                    from_rid: self.qualified_my_rid(),
                    key_package: key_package_bytes,
                },
            };

            self.send_bootstrap_envelope(envelope, from_rid.clone())?;
            self.log(format!("Sent KeyPackage to {}.", from_rid));
            self.save_persisted_state()?;
            Ok(())
        } else {
            self.create_invite_for_target(from_rid)
        }
    }

    pub fn reject_pending_offer(&mut self) -> Result<()> {
        if let Some(from_rid) = self.pending_offer_from.take() {
            if self.pending_keypackage_requests.remove(&from_rid).is_some() {
                self.log(format!("Rejected KeyPackage request from {}.", from_rid));
            } else {
                self.pending_keypackages.remove(&from_rid);
                self.log(format!("Rejected KeyPackage offer from {}.", from_rid));
            }
        }
        self.save_persisted_state()
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
            .unwrap_or_else(|| vec![self.qualified_my_rid()]);

        for recipient_rid in recipients {
            if self.rid_matches_self(&recipient_rid) {
                continue;
            }

            let endpoint = match resolve_recipient_endpoint(&recipient_rid, &self.server_addr) {
                Ok(endpoint) => endpoint,
                Err(err) => {
                    self.log(format!(
                        "Could not resolve recipient {}: {}",
                        recipient_rid, err
                    ));
                    continue;
                }
            };

            let blob = EncryptedBlob::new(endpoint.rid.clone(), ciphertext.clone());
            match put_blob(&endpoint.relay, blob)? {
                ServerPacket::Accepted { .. } => {
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

        self.log_for_group(
            &target,
            format!(
            "You (group {}): {}",
            short_group_id(&target),
            clean
        ),
        );

        self.save_persisted_state()?;

        Ok(())
    }

    pub fn fetch_messages(&mut self, quiet_empty: bool) -> Result<()> {
        let response = fetch_queued(&self.server_addr, &self.signing_key, &self.my_rid)?;

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
                from_rid: self.qualified_my_rid(),
                group_id: group_id.clone(),
                members: vec![self.qualified_my_rid(), target.clone()],
                ratchet_tree,
                welcome: welcome_bytes,
            },
        };

        self.send_bootstrap_envelope(envelope, target.clone())?;
        self.conversations.insert(group_id.clone(), group);
        self.conversation_members
            .insert(group_id.clone(), vec![self.qualified_my_rid(), target.clone()]);
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
        let mut pending_rid_update: Option<(String, String, String)> = None;
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

                    let app_bytes = app.into_bytes();
                    if let Ok(control) = serde_cbor::from_slice::<GroupControlEnvelope>(&app_bytes)
                        && control.magic == GROUP_CONTROL_MAGIC
                    {
                        match control.payload {
                            GroupControlPayload::RidUpdated { old_rid, new_rid } => {
                                pending_rid_update =
                                    Some((group_id.clone(), old_rid, new_rid));
                                break;
                            }
                        }
                    }
                    String::from_utf8_lossy(&app_bytes).to_string()
                }
                _ => "non-application MLS message".to_string(),
            };

            decrypted_line = Some((group_id.clone(), text));
            break;
        }
        
        // handle the rid update extracted from the mls message
        if let Some((group_id, old_rid, new_rid)) = pending_rid_update {
            if self.apply_remote_rid_update(&group_id, &old_rid, &new_rid)? {
                self.log_for_group(
                    &group_id,
                    format!(
                    "Updated member RID in group {} from {} to {}.",
                    short_group_id(&group_id),
                    old_rid,
                    new_rid
                ),
                );
            }
            return Ok(());
        }

        if let Some((group_id, line)) = decrypted_line {
            self.active_group_id = Some(group_id.clone());
            self.log_for_group(
                &group_id,
                format!("[{}] {}", self.conversation_title(&group_id), line),
            );
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
                let from_rid = normalize_recipient_input(&from_rid, &self.server_addr)?;
                // ask the user to accept or reject it
                let key_package = mls::build_keypackage(&self.identity)?;
                self.pending_keypackage_requests
                    .insert(from_rid.clone(), key_package);
                self.pending_offer_from = Some(from_rid.clone());
                self.log(format!(
                    "Incoming KeyPackage request from {}. Accept or reject it from the sidebar.",
                    from_rid
                ));
            }
            BootstrapPayload::KeyPackageOffer {
                from_rid,
                key_package,
            } => {
                let from_rid = normalize_recipient_input(&from_rid, &self.server_addr)?;
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
                let from_rid = normalize_recipient_input(&from_rid, &self.server_addr)?;
                let mut normalized_members = Vec::new();
                for member in members {
                    let normalized = normalize_recipient_input(&member, &self.server_addr)?;
                    if !normalized_members.contains(&normalized) {
                        normalized_members.push(normalized);
                    }
                }

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
                self.conversation_members
                    .insert(group_id.clone(), normalized_members);
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
                let from_rid = normalize_recipient_input(&from_rid, &self.server_addr)?;
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
                        let added_rid = normalize_recipient_input(&added_rid, &self.server_addr)?;
                        let my_qualified_rid = self.qualified_my_rid();
                        let members = self
                            .conversation_members
                            .entry(group_id.clone())
                            .or_insert_with(|| vec![my_qualified_rid.clone()]);
                        if !members.contains(&added_rid) {
                            members.push(added_rid.clone());
                        }
                        self.log_for_group(
                            &group_id,
                            format!(
                            "{} added {} to group {}.",
                            from_rid,
                            added_rid,
                            short_group_id(&group_id)
                        ),
                        );
                    } else {
                        self.log_for_group(
                            &group_id,
                            format!(
                            "Processed group commit from {} for group {}.",
                            from_rid,
                            short_group_id(&group_id)
                        ),
                        );
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
            .filter(|rid| !self.rid_matches_self(rid))
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
        let endpoint = resolve_recipient_endpoint(&recipient_rid, &self.server_addr)?;
        let blob = EncryptedBlob::new(endpoint.rid, payload);
        match put_blob(&endpoint.relay, blob)? {
            ServerPacket::Accepted { .. } => Ok(()),
            ServerPacket::Error { message } => Err(anyhow::anyhow!(message)),
            other => Err(anyhow::anyhow!(
                "unexpected response while sending bootstrap envelope: {other:#?}"
            )),
        }
    }

    fn issue_new_rid(&mut self, old_rid: String) -> Result<()> {
        let response = issue_rid(&self.server_addr, &self.signing_key)?;

        match response {
            ServerPacket::RidIssued { rid, .. } => {
                self.apply_new_rid(old_rid, rid, true)?;
                Ok(())
            }
            ServerPacket::Error { message } => {
                bail!("RID re-issue denied: {message}")
            }
            other => bail!("unexpected response while issuing RID: {other:#?}"),
        }
    }

    fn apply_new_rid(&mut self, old_rid: String, new_rid: String, reissued: bool) -> Result<()> {
        let old_public = rid_with_relay(&old_rid, &self.server_addr);
        let new_public = rid_with_relay(&new_rid, &self.server_addr);
        self.my_rid = new_rid.clone();

        for members in self.conversation_members.values_mut() {
            for rid in members.iter_mut() {
                if rid.as_str() == old_rid.as_str() || rid.as_str() == old_public.as_str() {
                    *rid = new_public.clone();
                }
            }
        }

        self.broadcast_rid_update_via_mls(&old_public, &new_public)?;

        if reissued {
            self.log(format!(
                "Previous RID expired. Issued new RID {}.",
                new_rid
            ));
        } else {
            self.log(format!("Rotated RID from {} to {}.", old_rid, new_rid));
        }

        self.save_persisted_state()?;
        Ok(())
    }

    fn broadcast_rid_update_via_mls(&mut self, old_rid: &str, new_rid: &str) -> Result<()> {
        let payload = serde_cbor::to_vec(&GroupControlEnvelope {
            magic: GROUP_CONTROL_MAGIC,
            payload: GroupControlPayload::RidUpdated {
                old_rid: old_rid.to_string(),
                new_rid: new_rid.to_string(),
            },
        })
        .context("encoding group control RID update payload failed")?;

        let group_ids = self.conversations.keys().cloned().collect::<Vec<_>>();
        for group_id in group_ids {
            let recipients = self
                .conversation_members
                .get(&group_id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|rid| !self.rid_matches_self(rid))
                .collect::<Vec<_>>();

            if recipients.is_empty() {
                continue;
            }

            let out = {
                let Some(group) = self.conversations.get_mut(&group_id) else {
                    continue;
                };
                match mls::send_application_message(
                    group,
                    &self.identity.provider,
                    &self.identity.signer,
                    &payload,
                ) {
                    Ok(out) => out,
                    Err(err) => {
                        self.log(format!(
                            "Could not create RID update MLS message for group {}: {}",
                            short_group_id(&group_id),
                            err
                        ));
                        continue;
                    }
                }
            };

            let ciphertext = match mls::mls_message_out_to_bytes(&out) {
                Ok(bytes) => bytes,
                Err(err) => {
                    self.log(format!(
                        "Could not serialize RID update MLS message for group {}: {}",
                        short_group_id(&group_id),
                        err
                    ));
                    continue;
                }
            };

            for recipient_rid in recipients {
                let endpoint = match resolve_recipient_endpoint(&recipient_rid, &self.server_addr)
                {
                    Ok(endpoint) => endpoint,
                    Err(err) => {
                        self.log(format!(
                            "Could not resolve RID update recipient {}: {}",
                            recipient_rid, err
                        ));
                        continue;
                    }
                };
                let blob = EncryptedBlob::new(endpoint.rid, ciphertext.clone());
                match put_blob(&endpoint.relay, blob)? {
                    ServerPacket::Accepted { .. } => {}
                    ServerPacket::Error { message } => {
                        self.log(format!(
                            "Server rejected RID update to {}: {message}",
                            recipient_rid
                        ));
                    }
                    other => {
                        self.log(format!(
                            "Unexpected response on RID update to {}: {other:#?}",
                            recipient_rid
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    fn apply_remote_rid_update(
        &mut self,
        group_id: &str,
        old_rid: &str,
        new_rid: &str,
    ) -> Result<bool> {
        let Some(members) = self.conversation_members.get_mut(group_id) else {
            return Ok(false);
        };

        let normalized_old = normalize_recipient_for_storage(old_rid, &self.server_addr)
            .unwrap_or_else(|| old_rid.trim().to_string());
        let normalized_new = normalize_recipient_for_storage(new_rid, &self.server_addr)
            .unwrap_or_else(|| new_rid.trim().to_string());

        if normalized_old.is_empty() || normalized_new.is_empty() {
            return Ok(false);
        }

        let had_old = members
            .iter()
            .any(|rid| rid.as_str() == old_rid || rid.as_str() == normalized_old.as_str());
        if !had_old {
            return Ok(false);
        }

        if members
            .iter()
            .any(|rid| rid.as_str() == new_rid || rid.as_str() == normalized_new.as_str())
        {
            members.retain(|rid| {
                rid.as_str() != old_rid && rid.as_str() != normalized_old.as_str()
            });
        } else {
            for rid in members.iter_mut() {
                if rid.as_str() == old_rid || rid.as_str() == normalized_old.as_str() {
                    *rid = normalized_new.clone();
                }
            }
        }

        self.save_persisted_state()?;
        Ok(true)
    }

    fn log_for_group(&mut self, group_id: &str, line: impl Into<String>) {
        let activity = self
            .activity_by_group
            .entry(group_id.to_string())
            .or_default();
        if activity.len() >= MAX_ACTIVITY {
            let _ = activity.pop_front();
        }
        activity.push_back(line.into());
    }

    fn log(&mut self, line: impl Into<String>) {
        if let Some(active_group_id) = self.active_group_id.clone() {
            self.log_for_group(&active_group_id, line);
        }
    }

    fn qualified_my_rid(&self) -> String {
        rid_with_relay(&self.my_rid, &self.server_addr)
    }

    fn rid_matches_self(&self, rid: &str) -> bool {
        recipient_matches_self(rid, &self.my_rid, &self.server_addr)
    }

    fn build_self_token(&self) -> String {
        format!("runway::v1::{}", self.qualified_my_rid())
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupControlEnvelope {
    magic: u32,
    payload: GroupControlPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum GroupControlPayload {
    RidUpdated {
        old_rid: String,
        new_rid: String,
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

fn normalize_recipient_input(input: &str, local_relay: &str) -> Result<String> {
    let endpoint = resolve_recipient_endpoint(input, local_relay)?;
    Ok(rid_with_relay(&endpoint.rid, &endpoint.relay))
}

fn normalize_recipient_for_storage(input: &str, local_relay: &str) -> Option<String> {
    resolve_recipient_endpoint(input, local_relay)
        .ok()
        .map(|endpoint| rid_with_relay(&endpoint.rid, &endpoint.relay))
}

fn resolve_recipient_endpoint(input: &str, local_relay: &str) -> Result<RecipientEndpoint> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("recipient RID cannot be empty")
    }

    if trimmed.starts_with("runway::") {
        let token =
            parse_token(trimmed).map_err(|err| anyhow::anyhow!("invalid runway token: {err}"))?;
        if token.keyserver.is_some() {
            bail!("keyserver segment in token is not supported yet")
        }
        return build_recipient_endpoint(&token.rid, &token.relay);
    }

    if let Some((rid, relay)) = split_rid_and_relay(trimmed) {
        return build_recipient_endpoint(rid, relay);
    }

    build_recipient_endpoint(trimmed, local_relay)
}

fn recipient_matches_self(recipient: &str, my_rid: &str, local_relay: &str) -> bool {
    match resolve_recipient_endpoint(recipient, local_relay) {
        Ok(endpoint) => endpoint.rid == my_rid && relay_eq(&endpoint.relay, local_relay),
        Err(_) => recipient.trim() == my_rid,
    }
}

fn split_rid_and_relay(value: &str) -> Option<(&str, &str)> {
    let at = value.rfind('@')?;
    let rid = value[..at].trim();
    let relay = value[at + 1..].trim();
    if rid.is_empty() || relay.is_empty() {
        return None;
    }
    Some((rid, relay))
}

fn build_recipient_endpoint(rid: &str, relay: &str) -> Result<RecipientEndpoint> {
    let rid = rid.trim();
    let relay = relay.trim();
    if rid.is_empty() {
        bail!("recipient RID cannot be empty")
    }
    if relay.is_empty() {
        bail!("recipient relay cannot be empty")
    }
    if rid.contains('@') {
        bail!("recipient RID segment must not contain '@'")
    }
    if relay.contains('@') {
        bail!("recipient relay must not contain '@'")
    }

    Ok(RecipientEndpoint {
        rid: rid.to_string(),
        relay: relay.to_string(),
    })
}

fn rid_with_relay(rid: &str, relay: &str) -> String {
    format!("{}@{}", rid, relay)
}

fn relay_eq(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn extract_identity_bytes(credential_with_key: &openmls::prelude::CredentialWithKey) -> Vec<u8> {
    credential_with_key.credential.serialized_content().to_vec()
}

fn persistence_path() -> PathBuf {
    let mut base = executable_dir();
    base.push("asphalt.cbor");
    base
}

fn executable_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn acquire_state_passphrase(confirm_twice: bool) -> Result<Zeroizing<String>> {
    let value = Zeroizing::new(
        rpassword::prompt_password("State passphrase: ")
            .context("prompting for state passphrase failed")?,
    );
    if value.trim().is_empty() {
        bail!("state passphrase cannot be empty")
    }

    if confirm_twice {
        let confirmation = Zeroizing::new(
            rpassword::prompt_password("Confirm state passphrase: ")
                .context("prompting for state passphrase confirmation failed")?,
        );
        if confirmation.as_str() != value.as_str() {
            bail!("state passphrases did not match")
        }
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

fn is_rid_missing_error(message: &str) -> bool {
    message.contains("loading rid owner failed") || message.contains("unknown or expired rid")
}
