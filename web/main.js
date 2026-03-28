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
  activeGroupTitle: document.querySelector('#activeGroupTitle'),
  clearActivityButton: document.querySelector('#clearActivityButton'),
  activityList: document.querySelector('#activityList'),
  messageForm: document.querySelector('#messageForm'),
  messageInput: document.querySelector('#messageInput'),
  sendButton: document.querySelector('#sendButton'),
  ridValue: document.querySelector('#ridValue'),
  myTokenValue: document.querySelector('#myTokenValue'),
  copyTokenButton: document.querySelector('#copyTokenButton'),
  rotateRidButton: document.querySelector('#rotateRidButton'),
  createGroupButton: document.querySelector('#createGroupButton'),
  toggleInviteButton: document.querySelector('#toggleInviteButton'),
  addMemberForm: document.querySelector('#addMemberForm'),
  addMemberButton: document.querySelector('#addMemberButton'),
  memberRidInput: document.querySelector('#memberRidInput'),
  statusFacts: document.querySelector('#statusFacts'),
  toast: document.querySelector('#toast'),
};

const state = {
  snapshot: null,
  pollBusy: false,
  toastTimer: null,
  inviteFormOpen: false,
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
  if (!snapshot.conversations.length) {
    elements.peerList.className = 'peer-list empty-state';
    elements.peerList.textContent = 'No groups yet.';
    return;
  }

  elements.peerList.className = 'peer-list';
  elements.peerList.innerHTML = '';

  snapshot.conversations.forEach((conversation) => {
    const button = document.createElement('button');
    button.className = 'peer-pill';
    if (snapshot.activeGroupId === conversation.groupId) {
      button.classList.add('active');
    }

    const title = document.createElement('span');
    title.className = 'peer-pill-title';
    title.textContent = conversation.title;

    const meta = document.createElement('span');
    meta.className = 'peer-pill-meta';
    meta.textContent = `${conversation.groupId.slice(0, 8)} · ${conversation.memberCount} member${conversation.memberCount === 1 ? '' : 's'}`;

    button.append(title, meta);
    button.addEventListener('click', () => {
      void invokeCommand('select_group', { groupId: conversation.groupId });
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
  elements.activeGroupTitle.textContent = snapshot.activeGroupTitle;
  elements.ridValue.textContent = snapshot.myRid;
  elements.myTokenValue.textContent = snapshot.myToken;

  elements.inviteBar.hidden = !snapshot.pendingOfferFrom;
  if (snapshot.pendingOfferFrom) {
    elements.inviteRid.textContent = snapshot.pendingOfferFrom;
  }

  const facts = [
    ['Server', snapshot.serverAddr],
    ['Known groups', String(snapshot.conversations.length)],
    ['Active group', snapshot.activeGroupId ? snapshot.activeGroupId.slice(0, 8) : 'none'],
    ['Pending offer', snapshot.pendingOfferFrom ?? 'none'],
    ['Ready to send', snapshot.activeGroupId ? 'yes' : 'select a group'],
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

  elements.sendButton.disabled = !snapshot.activeGroupId;
  elements.addMemberButton.disabled = !snapshot.activeGroupId;
  elements.memberRidInput.disabled = !snapshot.activeGroupId;
  elements.toggleInviteButton.disabled = !snapshot.activeGroupId;

  if (!snapshot.activeGroupId) {
    state.inviteFormOpen = false;
  }

  elements.addMemberForm.classList.toggle('hidden', !state.inviteFormOpen);
}

function render() {
  if (!state.snapshot) {
    return;
  }

  renderStatus(state.snapshot);
  renderPeers(state.snapshot);
  renderActivity(state.snapshot);
  renderMembers(state.snapshot);
}

function renderMembers(snapshot) {
  const el = document.querySelector('#membersList');
  if (!snapshot.members || snapshot.members.length === 0) {
    el.className = 'members-list empty-state';
    el.textContent = 'No members';
    return;
  }

  el.className = 'members-list';
  el.innerHTML = '';
  snapshot.members.forEach((m) => {
    const div = document.createElement('div');
    div.className = 'member-item';
    div.textContent = m === snapshot.myRid ? `${m} (you)` : m;
    el.append(div);
  });
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

elements.rotateRidButton.addEventListener('click', () => {
  void invokeCommand('rotate_rid');
});

elements.copyTokenButton.addEventListener('click', async () => {
  const token = state.snapshot?.myToken?.trim();
  if (!token) {
    showToast('Token is not ready yet.');
    return;
  }

  try {
    await navigator.clipboard.writeText(token);
    showToast('Token copied to clipboard.');
  } catch {
    showToast('Unable to copy token.');
  }
});

elements.acceptInviteButton.addEventListener('click', () => {
  void invokeCommand('accept_pending_offer');
});

elements.rejectInviteButton.addEventListener('click', () => {
  void invokeCommand('reject_pending_offer');
});

elements.createGroupButton.addEventListener('click', async () => {
  await invokeCommand('create_group');
});

elements.toggleInviteButton.addEventListener('click', () => {
  if (!state.snapshot?.activeGroupId) {
    showToast('Select a group first.');
    return;
  }

  state.inviteFormOpen = !state.inviteFormOpen;
  elements.addMemberForm.classList.toggle('hidden', !state.inviteFormOpen);
  if (state.inviteFormOpen) {
    elements.memberRidInput.focus();
  }
});

elements.addMemberForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const memberRid = elements.memberRidInput.value.trim();
  if (!memberRid) {
    showToast('Enter a member RID first.');
    return;
  }

  await invokeCommand('add_member', { memberRid });
  elements.memberRidInput.value = '';
  state.inviteFormOpen = false;
  elements.addMemberForm.classList.add('hidden');
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

elements.messageInput.addEventListener('keydown', async (event) => {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    const message = elements.messageInput.value;
    if (!message.trim()) {
      return;
    }

    await invokeCommand('send_message', { message });
    elements.messageInput.value = '';
    elements.messageInput.focus();
  }
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