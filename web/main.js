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
    activityList: document.querySelector('#activityList'),
    messageForm: document.querySelector('#messageForm'),
    messageInput: document.querySelector('#messageInput'),
    sendButton: document.querySelector('#sendButton'),
    addMemberForm: document.querySelector('#addMemberForm'),
    addMemberButton: document.querySelector('#addMemberButton'),
    memberRidInput: document.querySelector('#memberRidInput'),
    membersList: document.querySelector('#membersList'),
    toast: document.querySelector('#toast'),

    fileMenuTrigger: document.querySelector('#fileMenuTrigger'),
    groupMenuTrigger: document.querySelector('#groupMenuTrigger'),
    identityMenuTrigger: document.querySelector('#identityMenuTrigger'),
    helpMenuTrigger: document.querySelector('#helpMenuTrigger'),
    viewMenuTrigger: document.querySelector('#viewMenuTrigger'),

    fileMenu: document.querySelector('#fileMenu'),
    groupMenu: document.querySelector('#groupMenu'),
    identityMenu: document.querySelector('#identityMenu'),
    helpMenu: document.querySelector('#helpMenu'),
    viewMenu: document.querySelector('#viewMenu'),

    copyTokenMenuItem: document.querySelector('#copyTokenMenuItem'),
    rotateRidMenuItem: document.querySelector('#rotateRidMenuItem'),
    ridMenuLabel: document.querySelector('#ridMenuLabel'),
    quitMenuItem: document.querySelector('#quitMenuItem'),

    newGroupMenuItem: document.querySelector('#newGroupMenuItem'),
    inviteMemberMenuItem: document.querySelector('#inviteMemberMenuItem'),
    clearActivityMenuItem: document.querySelector('#clearActivityMenuItem'),
    leaveGroupMenuItem: document.querySelector('#leaveGroupMenuItem'),

    refreshMenuItem: document.querySelector('#refreshMenuItem'),
    aboutMenuItem: document.querySelector('#aboutMenuItem'),
};

const state = {
    snapshot: null,
    pollBusy: false,
    toastTimer: null,
    inviteFormOpen: false,
    openMenu: null,
    activitySignature: null,
};

function computeActivitySignature(activity) {
    if (!Array.isArray(activity) || activity.length === 0) return '__EMPTY__';
    return `${activity.length}:${activity.join('\u001f')}`;
}

function showToast(message) {
    if (!elements.toast) return;
    elements.toast.textContent = String(message);
    elements.toast.hidden = false;
    window.clearTimeout(state.toastTimer);
    state.toastTimer = window.setTimeout(() => {
        elements.toast.hidden = true;
    }, 3200);
}

function showAbout() {
    const aboutLines = [
        '[About] Asphalt - desktop client application for Runway',
        '[About] librunway - Rust library used by Runway for relay/transport functionality'
    ];

    if (!elements.activityList) return;

    elements.activityList.className = 'activity-list';
    aboutLines.forEach((line) => {
        const item = document.createElement('div');
        item.className = 'activity-item';
        item.textContent = line;
        elements.activityList.append(item);
    });
    elements.activityList.scrollTop = elements.activityList.scrollHeight;
}

function closeAllMenus() {
    if (elements.fileMenu) elements.fileMenu.hidden = true;
    if (elements.groupMenu) elements.groupMenu.hidden = true;
    if (elements.identityMenu) elements.identityMenu.hidden = true;
    if (elements.helpMenu) elements.helpMenu.hidden = true;
    if (elements.viewMenu) elements.viewMenu.hidden = true;
    state.openMenu = null;
}

function toggleMenu(menuId) {
    const menu = document.querySelector(`#${menuId}`);
    if (!menu) return;
    if (state.openMenu === menuId) {
        closeAllMenus();
    } else {
        closeAllMenus();
        menu.hidden = false;
        state.openMenu = menuId;
    }
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
    if (!snapshot || !Array.isArray(snapshot.conversations) || snapshot.conversations.length === 0) {
        if (elements.peerList) {
            elements.peerList.className = 'peer-list empty-state';
            elements.peerList.textContent = 'No groups yet.';
        }
        return;
    }

    elements.peerList.className = 'peer-list';
    elements.peerList.innerHTML = '';

    snapshot.conversations.forEach((conversation) => {
        const button = document.createElement('button');
        button.className = 'peer-pill';
        if (snapshot.activeGroupId === conversation.groupId) button.classList.add('active');

        const title = document.createElement('span');
        title.className = 'peer-pill-title';
        title.textContent = conversation.title || conversation.groupId;

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
    const nextSignature = computeActivitySignature(snapshot?.activity);
    if (state.activitySignature === nextSignature) {
        return;
    }

    if (!snapshot || !Array.isArray(snapshot.activity) || snapshot.activity.length === 0) {
        elements.activityList.className = 'activity-list empty-state';
        elements.activityList.textContent = 'Messages and protocol events will appear here.';
        state.activitySignature = nextSignature;
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

    state.activitySignature = nextSignature;
    elements.activityList.scrollTop = elements.activityList.scrollHeight;
}

function renderStatus(snapshot) {
    if (!snapshot) return;
    if (elements.connectionSummary) elements.connectionSummary.textContent = `${snapshot.myRid}@${snapshot.serverAddr}`;
    if (elements.activeGroupTitle) elements.activeGroupTitle.textContent = snapshot.activeGroupTitle || 'No group selected';

    if (elements.ridMenuLabel) {
        const ridText = `RID: ${snapshot.myRid}@${snapshot.serverAddr}`;
        if (elements.ridMenuLabel.textContent !== ridText) {
            elements.ridMenuLabel.textContent = ridText;
        }
    }

    if (elements.inviteBar) elements.inviteBar.hidden = !snapshot.pendingOfferFrom;
    if (snapshot.pendingOfferFrom && elements.inviteRid) elements.inviteRid.textContent = snapshot.pendingOfferFrom;

    if (elements.sendButton) elements.sendButton.disabled = !snapshot.activeGroupId;
    if (elements.addMemberButton) elements.addMemberButton.disabled = !snapshot.activeGroupId;
    if (elements.memberRidInput) elements.memberRidInput.disabled = !snapshot.activeGroupId;

    if (elements.inviteMemberMenuItem) elements.inviteMemberMenuItem.disabled = !snapshot.activeGroupId;
    if (elements.clearActivityMenuItem) elements.clearActivityMenuItem.disabled = !snapshot.activeGroupId;
    if (elements.leaveGroupMenuItem) elements.leaveGroupMenuItem.disabled = !snapshot.activeGroupId;

    if (!snapshot.activeGroupId) state.inviteFormOpen = false;
    if (elements.addMemberForm) elements.addMemberForm.classList.toggle('hidden', !state.inviteFormOpen);
}

function renderMembers(snapshot) {
    const el = elements.membersList;
    if (!el) return;
    if (!snapshot.members || snapshot.members.length === 0) {
        el.className = 'members-list empty-state';
        el.textContent = 'No members';
        return;
    }

    el.className = 'members-list';
    el.innerHTML = '';
    const myCanonicalRid = `${snapshot.myRid}@${snapshot.serverAddr}`;
    snapshot.members.forEach((m) => {
        const div = document.createElement('div');
        div.className = 'member-item';
        div.textContent = m === snapshot.myRid || m === myCanonicalRid ? `${m} (you)` : m;
        el.append(div);
    });
}

function render() {
    if (!state.snapshot) return;
    renderStatus(state.snapshot);
    renderPeers(state.snapshot);
    renderActivity(state.snapshot);
    renderMembers(state.snapshot);
}

async function pollMessages() {
    if (state.pollBusy) return;
    state.pollBusy = true;
    try {
        await invokeCommand('fetch_messages', { quietEmpty: true });
    } catch {
    } finally {
        state.pollBusy = false;
    }
}

if (elements.fileMenuTrigger) elements.fileMenuTrigger.addEventListener('click', () => toggleMenu('fileMenu'));
if (elements.groupMenuTrigger) elements.groupMenuTrigger.addEventListener('click', () => toggleMenu('groupMenu'));
if (elements.identityMenuTrigger) elements.identityMenuTrigger.addEventListener('click', () => toggleMenu('identityMenu'));
if (elements.helpMenuTrigger) elements.helpMenuTrigger.addEventListener('click', () => toggleMenu('helpMenu'));
if (elements.viewMenuTrigger) elements.viewMenuTrigger.addEventListener('click', () => toggleMenu('viewMenu'));

document.addEventListener('click', (event) => {
    const target = event.target;
    const isElement = target instanceof Element;
    const isMenuTrigger = isElement && target.classList.contains('menu-trigger');
    const isInsideMenu = isElement && target.closest('.menu-dropdown');
    if (!isMenuTrigger && !isInsideMenu) closeAllMenus();
});

if (elements.copyTokenMenuItem) {
    elements.copyTokenMenuItem.addEventListener('click', async () => {
        closeAllMenus();
        const token = state.snapshot?.myToken?.trim();
        if (!token) { showToast('Token is not ready yet.'); return; }
        try {
            await navigator.clipboard.writeText(token);
            showToast('Token copied to clipboard.');
        } catch {
            showToast('Unable to copy token.');
        }
    });
}

if (elements.rotateRidMenuItem) elements.rotateRidMenuItem.addEventListener('click', () => { closeAllMenus(); void invokeCommand('rotate_rid'); });
if (elements.quitMenuItem) elements.quitMenuItem.addEventListener('click', () => { closeAllMenus(); window.close(); });

if (elements.aboutMenuItem) elements.aboutMenuItem.addEventListener('click', () => { closeAllMenus(); showAbout(); });

if (elements.newGroupMenuItem) elements.newGroupMenuItem.addEventListener('click', () => { closeAllMenus(); void invokeCommand('create_group'); });
if (elements.inviteMemberMenuItem) elements.inviteMemberMenuItem.addEventListener('click', () => {
    closeAllMenus();
    if (!state.snapshot?.activeGroupId) { showToast('Select a group first.'); return; }
    state.inviteFormOpen = !state.inviteFormOpen;
    elements.addMemberForm.classList.toggle('hidden', !state.inviteFormOpen);
    if (state.inviteFormOpen) elements.memberRidInput.focus();
});
if (elements.clearActivityMenuItem) elements.clearActivityMenuItem.addEventListener('click', () => { closeAllMenus(); void invokeCommand('clear_activity'); });
if (elements.leaveGroupMenuItem) elements.leaveGroupMenuItem.addEventListener('click', () => { closeAllMenus(); showToast('Leave group not yet implemented.'); });

if (elements.refreshMenuItem) elements.refreshMenuItem.addEventListener('click', () => { closeAllMenus(); void invokeCommand('fetch_messages', { quietEmpty: false }); });

if (elements.refreshButton) elements.refreshButton.addEventListener('click', () => { void invokeCommand('fetch_messages', { quietEmpty: false }); });

if (elements.acceptInviteButton) elements.acceptInviteButton.addEventListener('click', () => { void invokeCommand('accept_pending_offer'); });
if (elements.rejectInviteButton) elements.rejectInviteButton.addEventListener('click', () => { void invokeCommand('reject_pending_offer'); });

if (elements.addMemberForm) {
    elements.addMemberForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const memberRid = elements.memberRidInput.value.trim();
        if (!memberRid) { showToast('Enter a member RID first.'); return; }
        await invokeCommand('add_member', { memberRid });
        elements.memberRidInput.value = '';
        state.inviteFormOpen = false;
        elements.addMemberForm.classList.add('hidden');
    });
}

if (elements.messageForm) {
    elements.messageForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const message = elements.messageInput.value;
        if (!message.trim()) return;
        await invokeCommand('send_message', { message });
        elements.messageInput.value = '';
        elements.messageInput.focus();
    });
}

if (elements.messageInput) {
    elements.messageInput.addEventListener('keydown', async (event) => {
        if (event.key === 'Enter' && !event.shiftKey) {
            event.preventDefault();
            const message = elements.messageInput.value;
            if (!message.trim()) return;
            await invokeCommand('send_message', { message });
            elements.messageInput.value = '';
            elements.messageInput.focus();
        }
    });
}

await invokeCommand('get_snapshot');
window.setInterval(() => { void pollMessages(); }, POLL_INTERVAL_MS);
