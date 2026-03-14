use anyhow::{Context, Result, bail};
use asphalt::mls;
use asphalt::transport::{
    ClientPacket, EncryptedBlob, RequestAuth, ServerPacket, auth_signing_payload, decode_packet,
    encode_packet, read_framed, write_framed,
};
use ed25519_dalek::{Signer, SigningKey};
use openmls::prelude::{KeyPackage, MlsGroupJoinConfig, ProcessedMessageContent};
use rand::RngExt;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::{DefaultTerminal, Frame};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_ACTIVITY: usize = 200;
const BOOTSTRAP_MAGIC: u32 = 0x52575931;
const AUTO_FETCH_INTERVAL: Duration = Duration::from_millis(1200);

pub fn run_client_tui(server_addr: &str) -> Result<()> {
    let mut secret = [0_u8; 32];
    rand::rng().fill(&mut secret);
    let signing_key = SigningKey::from_bytes(&secret);

    let auth = make_auth(&signing_key, "issue_rid", b"");
    let rid = match send_client_packet(server_addr, ClientPacket::IssueRid { auth })? {
        ServerPacket::RidIssued { rid, .. } => rid,
        other => bail!("expected RidIssued response, got {other:#?}"),
    };

    let identity = mls::create_identity();

    let mut app = ClientApp {
        server_addr: server_addr.to_string(),
        signing_key,
        my_rid: rid,
        message_input: String::new(),
        prompt: Prompt::None,
        activity: VecDeque::new(),
        identity,
        conversations: HashMap::new(),
        pending_keypackages: HashMap::new(),
        pending_offer_from: None,
        active_peer: None,
        last_auto_fetch: Instant::now(),
    };

    app.log("Connected. Press F2 to enter a peer RID and send your KeyPackage.");
    app.log("Incoming KeyPackage offer: press y to accept and auto-invite, n to reject.");

    let mut terminal = ratatui::init();
    let run_result = run_loop(&mut terminal, &mut app);
    ratatui::restore();
    run_result
}

fn run_loop(terminal: &mut DefaultTerminal, app: &mut ClientApp) -> Result<()> {
    loop {
        if app.last_auto_fetch.elapsed() >= AUTO_FETCH_INTERVAL {
            let _ = app.fetch_messages(true);
            app.last_auto_fetch = Instant::now();
        }

        terminal.draw(|frame| render(frame, app))?;

        if !event::poll(Duration::from_millis(120))? {
            continue;
        }

        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        if app.handle_prompt_key(key.code)? {
            continue;
        }

        match key.code {
            KeyCode::Esc => return Ok(()),
            KeyCode::Enter => {
                if let Err(err) = app.send_message() {
                    app.log(format!("Send failed: {err:#}"));
                }
            }
            KeyCode::F(5) => {
                if let Err(err) = app.fetch_messages(false) {
                    app.log(format!("Fetch failed: {err:#}"));
                }
            }
            KeyCode::F(2) => {
                app.prompt = Prompt::InviteRid(String::new());
                app.log("Enter peer RID and press Enter.");
            }
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                if let Err(err) = app.accept_pending_offer() {
                    app.log(format!("Accept failed: {err:#}"));
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                app.reject_pending_offer();
            }
            KeyCode::Char('[') => {
                app.select_prev_peer();
            }
            KeyCode::Char(']') => {
                app.select_next_peer();
            }
            KeyCode::Backspace => {
                app.message_input.pop();
            }
            KeyCode::Char(c) => {
                app.message_input.push(c);
            }
            _ => {}
        }
    }
}

fn render(frame: &mut Frame, app: &ClientApp) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(8),
        ])
        .split(frame.area());

    let pending = app
        .pending_offer_from
        .as_ref()
        .map(|rid| format!(" | offer {} (y/n)", rid))
        .unwrap_or_default();

    let active = app
        .active_peer
        .as_ref()
        .map_or("none".to_string(), |s| s.clone());

    let status = format!(
        "RID {} | active {} | peers {}{}",
        app.my_rid,
        active,
        app.conversations.len(),
        pending
    );

    frame.render_widget(
        Paragraph::new(status).block(
            Block::default()
                .title(format!("Runway Client @ {}", app.server_addr))
                .borders(Borders::ALL),
        ),
        layout[0],
    );

    let composer_text = match &app.prompt {
        Prompt::None => app.message_input.clone(),
        Prompt::InviteRid(v) => format!("Invite RID: {}", v),
    };
    let composer_title = match app.prompt {
        Prompt::None => "Message (Enter send | F2 invite RID | [ ] switch peer | F5 fetch)",
        Prompt::InviteRid(_) => "Invite Prompt (Enter confirm | Esc cancel)",
    };
    let composer_style = match app.prompt {
        Prompt::None => Style::default().fg(Color::Cyan),
        Prompt::InviteRid(_) => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    };

    frame.render_widget(
        Paragraph::new(composer_text)
            .style(composer_style)
            .block(Block::default().title(composer_title).borders(Borders::ALL)),
        layout[1],
    );

    let lines = app
        .activity
        .iter()
        .rev()
        .take(80)
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().title("Activity").borders(Borders::ALL)),
        layout[2],
    );
}

struct ClientApp {
    server_addr: String,
    signing_key: SigningKey,
    my_rid: String,
    message_input: String,
    prompt: Prompt,
    activity: VecDeque<String>,
    identity: mls::IdentityBundle,
    conversations: HashMap<String, openmls::group::MlsGroup>,
    pending_keypackages: HashMap<String, KeyPackage>,
    pending_offer_from: Option<String>,
    active_peer: Option<String>,
    last_auto_fetch: Instant,
}

#[derive(Clone)]
enum Prompt {
    None,
    InviteRid(String),
}

impl ClientApp {
    fn handle_prompt_key(&mut self, key: KeyCode) -> Result<bool> {
        match &mut self.prompt {
            Prompt::None => Ok(false),
            Prompt::InviteRid(input) => {
                match key {
                    KeyCode::Esc => {
                        self.prompt = Prompt::None;
                    }
                    KeyCode::Enter => {
                        let rid = input.trim().to_string();
                        self.prompt = Prompt::None;
                        if rid.is_empty() {
                            self.log("Invite cancelled (empty RID).");
                        } else {
                            self.send_keypackage_offer_to(rid)?;
                        }
                    }
                    KeyCode::Backspace => {
                        input.pop();
                    }
                    KeyCode::Char(c) => {
                        input.push(c);
                    }
                    _ => {}
                }
                Ok(true)
            }
        }
    }

    fn send_keypackage_offer_to(&mut self, target_rid: String) -> Result<()> {
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
        let envelope = BootstrapEnvelope {
            magic: BOOTSTRAP_MAGIC,
            payload: BootstrapPayload::Welcome {
                from_rid: self.my_rid.clone(),
                welcome: welcome_bytes,
            },
        };

        self.send_bootstrap_envelope(envelope, target.clone())?;
        self.conversations.insert(target.clone(), group);
        self.active_peer = Some(target.clone());
        self.log(format!(
            "Invite sent to {}. Waiting for them to join.",
            target
        ));
        Ok(())
    }

    fn accept_pending_offer(&mut self) -> Result<()> {
        let Some(from_rid) = self.pending_offer_from.take() else {
            return Ok(());
        };
        self.create_invite_for_target(from_rid)
    }

    fn reject_pending_offer(&mut self) {
        if let Some(from_rid) = self.pending_offer_from.take() {
            self.pending_keypackages.remove(&from_rid);
            self.log(format!("Rejected KeyPackage offer from {}.", from_rid));
        }
    }

    fn send_message(&mut self) -> Result<()> {
        let clean = self.message_input.trim().to_string();
        if clean.is_empty() {
            return Ok(());
        }

        let target = self.active_peer.clone().ok_or_else(|| {
            anyhow::anyhow!("no active peer. Press F2 to send KeyPackage and start a conversation")
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

        let blob = EncryptedBlob::new(target.clone(), ciphertext);
        match send_client_packet(&self.server_addr, ClientPacket::PutBlob { blob })? {
            ServerPacket::Accepted { rid, queued } => {
                self.log(format!("You -> {}: {} (queued {})", rid, clean, queued));
                self.message_input.clear();
            }
            ServerPacket::Error { message } => {
                self.log(format!("Server rejected message: {message}"));
            }
            other => {
                self.log(format!("Unexpected response on send: {other:#?}"));
            }
        }

        Ok(())
    }

    fn fetch_messages(&mut self, quiet_empty: bool) -> Result<()> {
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
            BootstrapPayload::KeyPackageOffer {
                from_rid,
                key_package,
            } => {
                let kp = mls::bytes_to_keypackage(&self.identity.provider, &key_package)?;
                self.pending_keypackages.insert(from_rid.clone(), kp);
                self.pending_offer_from = Some(from_rid.clone());
                self.log(format!(
                    "Incoming invite request from {}. Press y to accept or n to reject.",
                    from_rid
                ));
            }
            BootstrapPayload::Welcome { from_rid, welcome } => {
                let welcome = mls::bytes_to_welcome(&welcome)?;
                let join_cfg = MlsGroupJoinConfig::builder().build();
                let group = mls::join_from_welcome(&self.identity.provider, &join_cfg, welcome)?;
                self.conversations.insert(from_rid.clone(), group);
                self.active_peer = Some(from_rid.clone());
                self.log(format!(
                    "Joined conversation with {}. You can now chat.",
                    from_rid
                ));
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

    fn select_prev_peer(&mut self) {
        self.rotate_active_peer(false);
    }

    fn select_next_peer(&mut self) {
        self.rotate_active_peer(true);
    }

    fn rotate_active_peer(&mut self, forward: bool) {
        if self.conversations.is_empty() {
            self.active_peer = None;
            return;
        }

        let mut peers = self.conversations.keys().cloned().collect::<Vec<_>>();
        peers.sort();

        if self.active_peer.is_none() {
            self.active_peer = Some(peers[0].clone());
            self.log(format!("Active peer: {}", peers[0]));
            return;
        }

        let current = self.active_peer.clone().unwrap_or_default();
        let idx = peers.iter().position(|p| p == &current).unwrap_or(0);
        let next_idx = if forward {
            (idx + 1) % peers.len()
        } else if idx == 0 {
            peers.len() - 1
        } else {
            idx - 1
        };

        self.active_peer = Some(peers[next_idx].clone());
        self.log(format!("Active peer: {}", peers[next_idx]));
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
    KeyPackageOffer {
        from_rid: String,
        key_package: Vec<u8>,
    },
    Welcome {
        from_rid: String,
        welcome: Vec<u8>,
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
