use anyhow::{Context, Result, bail};
use asphalt::mls;
use asphalt::transport::{
    ClientPacket, EncryptedBlob, RequestAuth, ServerPacket, auth_signing_payload, decode_packet,
    encode_packet, read_framed, write_framed,
};
use ed25519_dalek::{Signer, SigningKey};
use openmls::prelude::{KeyPackage, MlsGroupJoinConfig, ProcessedMessageContent};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_ACTIVITY: usize = 200;
const BOOTSTRAP_MAGIC: u32 = 0x52575931;

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
    active_peer: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientSnapshot {
    pub server_addr: String,
    pub my_rid: String,
    pub active_peer: Option<String>,
    pub pending_offer_from: Option<String>,
    pub peers: Vec<String>,
    pub activity: Vec<String>,
    pub members: Vec<String>,
}

impl ClientState {
    pub fn connect(server_addr: impl Into<String>) -> Result<Self> {
        let server_addr = server_addr.into();

        let mut secret = [0_u8; 32];
        rand::rng().fill(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);

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
            active_peer: None,
        };

        state.log("Connected to relay.");
        Ok(state)
    }

    pub fn snapshot(&self) -> ClientSnapshot {
        let members = match &self.active_peer {
            Some(active) => self
                .conversation_members
                .get(active)
                .cloned()
                .unwrap_or_default(),
            None => Vec::new(),
        };

        ClientSnapshot {
            server_addr: self.server_addr.clone(),
            my_rid: self.my_rid.clone(),
            active_peer: self.active_peer.clone(),
            pending_offer_from: self.pending_offer_from.clone(),
            peers: self.sorted_peers(),
            activity: self.activity.iter().cloned().collect(),
            members,
        }
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
            .active_peer
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no active conversation selected"))?;

        if let Some(members) = self.conversation_members.get(&active)
            && members.contains(&member_rid)
        {
            bail!("{} is already a member of {}", member_rid, active)
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
                    "Requested a KeyPackage from {} for conversation {}. The member will be added when it arrives.",
                    member_rid, active
                ));
                return Ok(());
            }
        };

        self.finalize_add_member(active, member_rid, key_package)
    }

    fn finalize_add_member(
        &mut self,
        active: String,
        member_rid: String,
        key_package: KeyPackage,
    ) -> Result<()> {
        let current_members = self
            .conversation_members
            .get(&active)
            .cloned()
            .unwrap_or_else(|| vec![self.my_rid.clone()]);

        let (commit, welcome, ratchet_tree) = {
            let group = self
                .conversations
                .get_mut(&active)
                .with_context(|| format!("no group for active conversation {}", active))?;

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
                    added_rid: Some(member_rid.clone()),
                    commit: commit_bytes.clone(),
                },
            };
            self.send_bootstrap_envelope(envelope, existing_rid)?;
        }

        self.conversation_members
            .insert(active.clone(), updated_members);

        self.log(format!(
            "Added {} to conversation {} and sent Welcome.",
            member_rid, active
        ));
        Ok(())
    }

    pub fn select_peer(&mut self, peer_rid: String) -> Result<()> {
        if !self.conversations.contains_key(&peer_rid) {
            bail!("unknown peer {peer_rid}")
        }

        self.active_peer = Some(peer_rid.clone());
        self.log(format!("Active peer: {}", peer_rid));
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

        let target = self.active_peer.clone().ok_or_else(|| {
            anyhow::anyhow!("no active peer. Add a peer first and complete the invite handshake")
        })?;

        let group = self.conversations.get_mut(&target).with_context(|| {
            format!("active peer {} has no established MLS conversation", target)
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

        if !delivered.is_empty() {
            self.log(format!("You -> [{}]: {}", delivered.join(", "), clean));
        }

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

    fn sorted_peers(&self) -> Vec<String> {
        let mut peers = self.conversations.keys().cloned().collect::<Vec<_>>();
        peers.sort();
        peers
    }

    fn create_invite_for_target(&mut self, target: String) -> Result<()> {
        if self.conversations.contains_key(&target) {
            self.active_peer = Some(target.clone());
            self.log(format!(
                "Conversation with {} already exists. Selected as active.",
                target
            ));
            return Ok(());
        }

        let key_package = self
            .pending_keypackages
            .remove(&target)
            .with_context(|| format!("no pending KeyPackage from {}", target))?;

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
                members: vec![self.my_rid.clone(), target.clone()],
                ratchet_tree,
                welcome: welcome_bytes,
            },
        };

        self.send_bootstrap_envelope(envelope, target.clone())?;
        self.conversations.insert(target.clone(), group);
        self.conversation_members
            .insert(target.clone(), vec![self.my_rid.clone(), target.clone()]);
        self.active_peer = Some(target.clone());
        self.log(format!(
            "Invite sent to {}. Waiting for them to join.",
            target
        ));
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
        for (peer_rid, group) in &mut self.conversations {
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

            decrypted_line = Some((peer_rid.clone(), text));
            break;
        }

        if let Some((peer, line)) = decrypted_line {
            self.active_peer = Some(peer.clone());
            self.log(format!("{} -> you: {}", peer, line));
        } else {
            self.log(format!(
                "Received {} bytes, but no local conversation could decrypt it.",
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
                if let Some(conversation_key) = self.pending_group_additions.remove(&from_rid) {
                    self.finalize_add_member(conversation_key.clone(), from_rid.clone(), kp)?;
                    self.log(format!(
                        "Received KeyPackage from {} and completed the add to conversation {}.",
                        from_rid, conversation_key
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
                self.conversations.insert(from_rid.clone(), group);
                self.conversation_members.insert(from_rid.clone(), members);
                self.active_peer = Some(from_rid.clone());
                self.log(format!(
                    "Joined conversation with {}. You can now chat.",
                    from_rid
                ));
            }
            BootstrapPayload::GroupCommit {
                from_rid,
                added_rid,
                commit,
            } => {
                let pm = mls::bytes_to_protocol_message(&commit)?;
                let mut updated_conversation: Option<String> = None;

                for (conversation_key, group) in &mut self.conversations {
                    let processed =
                        match mls::receive_message(group, &self.identity.provider, pm.clone()) {
                            Ok(p) => p,
                            Err(_) => continue,
                        };

                    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
                        processed.into_content()
                    {
                        mls::merge_staged_commit(group, &self.identity.provider, *staged_commit)?;
                        updated_conversation = Some(conversation_key.clone());
                        break;
                    }
                }

                if let Some(conversation_key) = updated_conversation {
                    if let Some(added_rid) = added_rid {
                        let members = self
                            .conversation_members
                            .entry(conversation_key.clone())
                            .or_insert_with(|| vec![self.my_rid.clone()]);
                        if !members.contains(&added_rid) {
                            members.push(added_rid.clone());
                        }
                        self.log(format!(
                            "{} added {} to conversation {}.",
                            from_rid, added_rid, conversation_key
                        ));
                    } else {
                        self.log(format!("Processed group commit from {}.", from_rid));
                    }
                } else {
                    self.log(format!(
                        "Received a group commit from {}, but no local conversation matched it.",
                        from_rid
                    ));
                }
            }
        }
        Ok(())
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
        members: Vec<String>,
        ratchet_tree: Vec<u8>,
        welcome: Vec<u8>,
    },
    GroupCommit {
        from_rid: String,
        added_rid: Option<String>,
        commit: Vec<u8>,
    },
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
