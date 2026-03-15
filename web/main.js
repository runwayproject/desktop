import { invoke } from '@tauri-apps/api/core';
import './styles.css';

const POLL_INTERVAL_MS = 1500;

const elements = {
  connectionSummary: document.querySelector('#connectionSummary'),
  inviteBar: document.querySelector('#inviteBar'),
  inviteRid: document.querySelector('#inviteRid'),
  acceptInviteButton: document.querySelector('#acceptInviteButton'),
  rejectInviteButton: document.querySelector('#rejectInviteButton'),
  refreshButton: document.querySelector('#refreshButton'),
  peerList: document.querySelector('#peerList'),
  activePeerTitle: document.querySelector('#activePeerTitle'),
  clearActivityButton: document.querySelector('#clearActivityButton'),
  activityList: document.querySelector('#activityList'),
  messageForm: document.querySelector('#messageForm'),
  messageInput: document.querySelector('#messageInput'),
  sendButton: document.querySelector('#sendButton'),
  ridValue: document.querySelector('#ridValue'),
  addPeerForm: document.querySelector('#addPeerForm'),
  peerRidInput: document.querySelector('#peerRidInput'),
  statusFacts: document.querySelector('#statusFacts'),
  toast: document.querySelector('#toast'),
};

const state = {
  snapshot: null,
  pollBusy: false,
  toastTimer: null,
};

function showToast(message) {
  elements.toast.textContent = String(message);
  elements.toast.hidden = false;
  window.clearTimeout(state.toastTimer);
  state.toastTimer = window.setTimeout(() => {
    elements.toast.hidden = true;
  }, 3200);
}

async function invokeCommand(command, args = {}) {
  try {
    state.snapshot = await invoke(command, args);
    render();
    return state.snapshot;
  } catch (error) {
    showToast(error);
    throw error;
  }
}

function renderPeers(snapshot) {
  if (!snapshot.peers.length) {
    elements.peerList.className = 'peer-list empty-state';
    elements.peerList.textContent = 'No conversations yet.';
    return;
  }

  elements.peerList.className = 'peer-list';
  elements.peerList.innerHTML = '';

  snapshot.peers.forEach((peerRid) => {
    const button = document.createElement('button');
    button.className = 'peer-pill';
    if (snapshot.activePeer === peerRid) {
      button.classList.add('active');
    }
    button.textContent = peerRid;
    button.addEventListener('click', () => {
      void invokeCommand('select_peer', { peerRid });
    });
    elements.peerList.append(button);
  });
}

function renderActivity(snapshot) {
  if (!snapshot.activity.length) {
    elements.activityList.className = 'activity-list empty-state';
    elements.activityList.textContent = 'Messages and protocol events will appear here.';
    return;
  }

  elements.activityList.className = 'activity-list';
  elements.activityList.innerHTML = '';

  snapshot.activity.forEach((line) => {
    const item = document.createElement('div');
    item.className = 'activity-item';
    item.textContent = line;
    elements.activityList.append(item);
  });

  elements.activityList.scrollTop = elements.activityList.scrollHeight;
}

function renderStatus(snapshot) {
  elements.connectionSummary.textContent = `${snapshot.myRid}@${snapshot.serverAddr}`;
  elements.activePeerTitle.textContent = snapshot.activePeer ?? 'No peer selected';
  elements.ridValue.textContent = snapshot.myRid;

  elements.inviteBar.hidden = !snapshot.pendingOfferFrom;
  if (snapshot.pendingOfferFrom) {
    elements.inviteRid.textContent = snapshot.pendingOfferFrom;
  }

  const facts = [
    ['Server', snapshot.serverAddr],
    ['Known peers', String(snapshot.peers.length)],
    ['Pending offer', snapshot.pendingOfferFrom ?? 'none'],
    ['Ready to send', snapshot.activePeer ? 'yes' : 'select a peer'],
  ];

  elements.statusFacts.innerHTML = '';
  facts.forEach(([label, value]) => {
    const row = document.createElement('div');
    row.className = 'fact-row';

    const dt = document.createElement('span');
    dt.className = 'fact-label';
    dt.textContent = label;

    const dd = document.createElement('span');
    dd.className = 'fact-value';
    dd.textContent = value;

    row.append(dt, dd);
    elements.statusFacts.append(row);
  });

  elements.sendButton.disabled = !snapshot.activePeer;
}

function render() {
  if (!state.snapshot) {
    return;
  }

  renderStatus(state.snapshot);
  renderPeers(state.snapshot);
  renderActivity(state.snapshot);
}

async function pollMessages() {
  if (state.pollBusy) {
    return;
  }

  state.pollBusy = true;
  try {
    await invokeCommand('fetch_messages', { quietEmpty: true });
  } catch {
  } finally {
    state.pollBusy = false;
  }
}

elements.refreshButton.addEventListener('click', () => {
  void invokeCommand('fetch_messages', { quietEmpty: false });
});

elements.clearActivityButton.addEventListener('click', () => {
  void invokeCommand('clear_activity');
});

elements.acceptInviteButton.addEventListener('click', () => {
  void invokeCommand('accept_pending_offer');
});

elements.rejectInviteButton.addEventListener('click', () => {
  void invokeCommand('reject_pending_offer');
});

elements.addPeerForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const targetRid = elements.peerRidInput.value.trim();
  if (!targetRid) {
    showToast('Enter a peer RID first.');
    return;
  }

  await invokeCommand('add_peer', { targetRid });
  elements.peerRidInput.value = '';
});

elements.messageForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const message = elements.messageInput.value;
  if (!message.trim()) {
    return;
  }

  await invokeCommand('send_message', { message });
  elements.messageInput.value = '';
  elements.messageInput.focus();
});

document.querySelectorAll('.nav-btn[data-view]').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.nav-btn[data-view]').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.view').forEach((v) => v.classList.add('hidden'));
    document.querySelector(`#view-${btn.dataset.view}`).classList.remove('hidden');
  });
});

await invokeCommand('get_snapshot');
window.setInterval(() => {
  void pollMessages();
}, POLL_INTERVAL_MS);