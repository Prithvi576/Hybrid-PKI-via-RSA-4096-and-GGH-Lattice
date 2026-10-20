const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

const state = {
    machineId: '',
    machines: [],
    messages: [],
    keys: {
        rsa: { ready: false, fingerprint: '', size_bytes: 0 },
        ggh: { ready: false, fingerprint: '', size_bytes: 0 }
    },
    editingId: null
};

function escapeHtml(s) {
    return String(s || '').replace(/[&<>"']/g, c => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[c]));
}

function endpoint(m) {
    if (!m) return '';
    return `${m.host || m.hostname || '127.0.0.1'}:${m.port || 502}`;
}

function initials(name) {
    return (name || 'SC')
        .split(/\s+/)
        .map(s => s[0] || '')
        .join('')
        .slice(0, 2)
        .toUpperCase();
}

function toast(message, error = false) {
    const stack = $('#toastStack');
    if (!stack) return;
    const el = document.createElement('div');
    el.className = 'toast' + (error ? ' error' : '');
    el.innerHTML = `<span class="toast-mark">${error ? '!' : 'i'}</span><span>${escapeHtml(message)}</span>`;
    stack.append(el);
    setTimeout(() => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(5px)';
        setTimeout(() => el.remove(), 220);
    }, 3500);
}

function selected() {
    return state.machines.find(m => m.id === state.machineId) || state.machines[0] || null;
}

async function api(path, method = 'GET', data = null) {
    const opts = {
        method,
        headers: { 'Content-Type': 'application/json' }
    };
    if (data) opts.body = JSON.stringify(data);
    const res = await fetch(path, opts);
    if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `HTTP ${res.status}`);
    }
    return res.json();
}

async function loadMachines() {
    try {
        const list = await api('/api/machines');
        state.machines = Array.isArray(list) ? list : [];
        if (!state.machineId || !state.machines.some(m => m.id === state.machineId)) {
            state.machineId = state.machines[0] ? state.machines[0].id : '';
        }
        renderMachines($('#machineSearch') ? $('#machineSearch').value : '');
        if (state.machineId) {
            await selectMachine(state.machineId);
        } else {
            renderEmptyWorkspace();
        }
    } catch (e) {
        toast(`Failed to load machines: ${e.message}`, true);
    }
}

function renderMachines(filter = '') {
    const listEl = $('#machineList');
    if (!listEl) return;
    listEl.innerHTML = '';
    const q = (filter || '').toLowerCase();
    const filtered = state.machines.filter(m =>
        ((m.name || m.display_name || '') + ' ' + endpoint(m)).toLowerCase().includes(q)
    );
    if ($('#machineCount')) $('#machineCount').textContent = state.machines.length;
    if (!filtered.length) {
        listEl.innerHTML = '<div class="machine-empty">No machines found.<button id="clearSearch">Clear search</button></div>';
        const cs = $('#clearSearch');
        if (cs) cs.onclick = () => { $('#machineSearch').value = ''; renderMachines(); };
        return;
    }
    filtered.forEach(m => {
        const name = m.name || m.display_name || 'Machine';
        const b = document.createElement('button');
        b.className = 'machine-item' + (m.id === state.machineId ? ' selected' : '');
        b.innerHTML = `
            <span class="machine-icon ${name.toLowerCase().includes('gateway') ? 'amber' : name.toLowerCase().includes('control') ? 'violet' : ''}">
                ${escapeHtml(initials(name))}
            </span>
            <span class="machine-copy">
                <b>${escapeHtml(name)}</b>
                <small>${escapeHtml(endpoint(m))}</small>
            </span>
            <span class="online-dot" title="Ready"></span>
            <span class="machine-chevron">›</span>
        `;
        b.onclick = () => selectMachine(m.id);
        listEl.append(b);
    });
}

function renderEmptyWorkspace() {
    $('#currentMachineCrumb').textContent = 'No machine selected';
    $('#headerAvatar').textContent = '—';
    $('#recipientEndpoint').textContent = 'Add a machine to begin';
    $('#contextMachine').textContent = 'None';
    $('#contextEndpoint').textContent = '—';
    $('#targetName').textContent = 'No active recipient';
    $('#targetAddress').textContent = '—';
    $('#messagesList').innerHTML = `
        <div class="empty-chat">
            <div class="empty-art">＋</div>
            <h3>No machines yet</h3>
            <p>Add a recipient SCADA machine to configure keys and start sending signed commands.</p>
            <button class="send-button" id="emptyAdd" style="margin: 15px auto 0;">Add machine</button>
        </div>`;
    const ea = $('#emptyAdd');
    if (ea) ea.onclick = () => openMachineModal();
}

async function selectMachine(id) {
    state.machineId = id;
    const m = selected();
    if (!m) {
        renderEmptyWorkspace();
        return;
    }
    const name = m.name || m.display_name || 'Machine';
    const ep = endpoint(m);
    renderMachines($('#machineSearch') ? $('#machineSearch').value : '');
    $('#currentMachineCrumb').textContent = name;
    $('#headerAvatar').textContent = initials(name);
    $('#recipientEndpoint').textContent = ep;
    $('#contextMachine').textContent = name;
    $('#contextEndpoint').textContent = ep;
    $('#targetName').textContent = name;
    $('#targetAddress').textContent = ep;
    if ($('#statusTcp')) $('#statusTcp').textContent = `Target ${ep}`;

    await Promise.all([loadKeys(id), loadMessages(id)]);
}

async function loadKeys(machineId) {
    try {
        const keys = await api(`/api/keys?machine_id=${encodeURIComponent(machineId)}`);
        state.keys = keys || { rsa: {}, ggh: {} };

        let readyCount = 0;
        // RSA
        const rsaStatus = $('#rsaStatus');
        const rsaDetail = $('#rsaDetail');
        const genRsa = $('#generateRsa');
        if (keys.rsa && keys.rsa.ready) {
            readyCount++;
            rsaStatus.textContent = 'Ready';
            rsaStatus.className = 'key-state ready';
            rsaDetail.textContent = `SHA256: ${keys.rsa.fingerprint.slice(0, 16)}… (512B)`;
            genRsa.innerHTML = 'Regenerate <span>↗</span>';
        } else {
            rsaStatus.textContent = 'Not ready';
            rsaStatus.className = 'key-state pending';
            rsaDetail.textContent = 'Key pair not loaded';
            genRsa.innerHTML = 'Generate key <span>↗</span>';
        }

        // GGH
        const gghStatus = $('#gghStatus');
        const gghDetail = $('#gghDetail');
        const genGgh = $('#generateGgh');
        if (keys.ggh && keys.ggh.ready) {
            readyCount++;
            gghStatus.textContent = 'Ready';
            gghStatus.className = 'key-state ready';
            gghDetail.textContent = `SHA256: ${keys.ggh.fingerprint.slice(0, 16)}… (128B, n=16)`;
            genGgh.innerHTML = 'Regenerate <span>↗</span>';
        } else {
            gghStatus.textContent = 'Not ready';
            gghStatus.className = 'key-state pending';
            gghDetail.textContent = 'Key pair not loaded';
            genGgh.innerHTML = 'Generate key <span>↗</span>';
        }

        if ($('#keyCount')) $('#keyCount').textContent = `${readyCount} / 2`;
        const readyBoth = readyCount === 2;
        $('#channelBadge').innerHTML = readyBoth ? '<i></i> Ready' : '<i></i> Keys Pending';
        $('#channelBadge').style.color = readyBoth ? '#50b58c' : '#d7a454';
        $('#channelTitle').textContent = readyBoth ? 'Hybrid PKI Armed' : 'Keys Pending';
        $('#channelDescription').textContent = readyBoth
            ? 'Both RSA-4096 and GGH Lattice keys are loaded in C++ memory. Commands will be signed and framed.'
            : 'Generate both RSA and GGH keys below before signing commands for this machine.';
    } catch (e) {
        console.error('loadKeys failed', e);
    }
}

async function generateKey(type) {
    if (!state.machineId) {
        toast('Select a machine first.', true);
        return;
    }
    const label = type === 'rsa' ? 'RSA-4096' : 'GGH Lattice';
    const btn = type === 'rsa' ? $('#generateRsa') : $('#generateGgh');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Generating...';
    }
    toast(`Generating ${label} key pair in native C++ backend...`);
    try {
        const res = await api('/api/keys/generate', 'POST', {
            machine_id: state.machineId,
            type: type
        });
        if (res.success) {
            toast(`${label} key pair generated successfully.`);
            await loadKeys(state.machineId);
        } else {
            toast(`Failed: ${res.error || 'Unknown error'}`, true);
        }
    } catch (e) {
        toast(`Key generation error: ${e.message}`, true);
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function loadMessages(machineId) {
    try {
        const msgs = await api(`/api/messages?machine_id=${encodeURIComponent(machineId)}`);
        state.messages = Array.isArray(msgs) ? msgs : [];
        renderMessages();
    } catch (e) {
        console.error('loadMessages failed', e);
    }
}

function renderMessages() {
    const list = $('#messagesList');
    if (!list) return;
    const items = state.messages;
    if ($('#messageCount')) $('#messageCount').textContent = items.length;
    if (!items.length) {
        list.innerHTML = `
            <div class="empty-chat">
                <div class="empty-art">↗</div>
                <h3>Your command channel starts here</h3>
                <p>Select a machine, compose a command, and sign with RSA-4096 + GGH lattice signatures.</p>
                <div class="empty-suggestions">
                    <button data-suggestion="STATUS">STATUS</button>
                    <button data-suggestion="READ_TEMPERATURE">READ_TEMPERATURE</button>
                    <button data-suggestion="OPEN_VALVE">OPEN_VALVE</button>
                </div>
            </div>`;
        $$('[data-suggestion]').forEach(b => b.onclick = () => {
            const input = $('#commandInput');
            input.value = b.dataset.suggestion;
            input.dispatchEvent(new Event('input'));
            input.focus();
        });
        return;
    }

    list.innerHTML = items.map(m => {
        const cmd = m.command || '';
        const time = m.timestamp_utc || m.time || '';
        const seq = m.sequence != null ? `Seq #${m.sequence}` : '';
        const isSent = m.status === 'SentToTcp' || m.status === 'Sent' || m.status === 2;
        const isSending = m.status === 'Sending' || m.status === 1;
        const statusClass = isSent ? 'sent' : (isSending ? 'sending' : 'failed');
        const statusText = isSent ? 'Sent (TCP)' : (isSending ? 'Sending...' : 'Failed (TCP)');

        const rsaInfo = m.rsa_signature_size
            ? `<span>· RSA: ${m.rsa_signature_size}B</span>`
            : '';
        const gghInfo = m.ggh_signature_size
            ? `<span>· GGH: ${m.ggh_signature_size}B</span>`
            : '';

        return `
            <article class="message-row outgoing">
                <div class="message-avatar">PS</div>
                <div class="message-content">
                    <div class="message-meta">
                        <b>You ${seq ? '(' + escapeHtml(seq) + ')' : ''}</b>
                        <span>${escapeHtml(time)}</span>
                    </div>
                    <div class="message-bubble">${escapeHtml(cmd)}</div>
                    <div class="message-status">
                        <span class="status-chip ${statusClass}">${escapeHtml(statusText)}</span>
                        ${rsaInfo}
                        ${gghInfo}
                    </div>
                </div>
            </article>`;
    }).join('');

    // Smooth scroll message container to bottom
    list.scrollTop = list.scrollHeight;
}

async function sendMessage() {
    const input = $('#commandInput');
    const text = (input.value || '').trim();
    if (!text) {
        toast('Enter a SCADA command to send.', true);
        input.focus();
        return;
    }
    const m = selected();
    if (!m) {
        toast('Select a recipient machine first.', true);
        return;
    }
    if (!state.keys.rsa.ready || !state.keys.ggh.ready) {
        toast('Both RSA-4096 and GGH keys must be generated before signing.', true);
        return;
    }

    const btn = $('#signSend');
    btn.disabled = true;
    btn.innerHTML = '<span>⏳</span> Signing & sending...';

    try {
        const res = await api('/api/send', 'POST', {
            machine_id: state.machineId,
            command: text
        });

        input.value = '';
        input.dispatchEvent(new Event('input'));

        if (res.success && res.status === 'SentToTcp') {
            toast('Command signed (RSA-4096 + GGH) and delivered via TCP.');
        } else if (res.status === 'ConnectionFailed') {
            toast(`Command signed successfully, but TCP delivery failed (${endpoint(m)} unreachable).`, true);
        } else {
            toast(`Send failed: ${res.error || res.status || 'Unknown'}`, true);
        }

        await loadMessages(state.machineId);
    } catch (e) {
        toast(`Communication error: ${e.message}`, true);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<span>↗</span> Sign &amp; send <kbd>Ctrl ↵</kbd>';
    }
}

function openMachineModal(id = null) {
    state.editingId = id;
    const m = id ? state.machines.find(x => x.id === id) : null;
    $('#modalTitle').textContent = m ? 'Edit machine' : 'Add a machine';
    $('#modalCopy').textContent = m ? 'Update machine host and port.' : 'Save a SCADA recipient endpoint with host and TCP port.';
    $('#modalSymbol').textContent = m ? '✎' : '＋';
    $('#machineNameInput').value = m ? (m.name || m.display_name || '') : '';
    $('#machineHostInput').value = m ? (m.host || m.hostname || '') : '';
    $('#machinePortInput').value = m ? (m.port || 502) : 502;
    if ($('#machineIdentityInput')) $('#machineIdentityInput').value = m?.identity || '';
    $('#deleteMachine').classList.toggle('hidden', !m);
    $('#saveMachine').textContent = m ? 'Save changes ↗' : 'Save machine ↗';
    $('#modalBackdrop').classList.add('open');
    setTimeout(() => $('#machineNameInput').focus(), 100);
}

function closeMachineModal() {
    $('#modalBackdrop').classList.remove('open');
}

async function deleteSelected() {
    const m = selected();
    if (!m) return;
    if (!confirm(`Delete “${m.name || m.display_name}”?`)) return;
    try {
        await api('/api/machines', 'POST', {
            action: 'delete',
            id: m.id
        });
        toast('Machine removed.');
        closeMachineModal();
        await loadMachines();
    } catch (e) {
        toast(`Failed to delete machine: ${e.message}`, true);
    }
}

function showInfo() { $('#infoBackdrop').classList.add('open'); }
function closeInfo() { $('#infoBackdrop').classList.remove('open'); }

// Event Listeners
$('#generateRsa').onclick = () => generateKey('rsa');
$('#generateGgh').onclick = () => generateKey('ggh');
$('#signSend').onclick = sendMessage;

$('#commandInput').addEventListener('input', () => {
    const n = $('#commandInput').value.length;
    $('#charCount').textContent = `${n} / 2048`;
    $('#draftState').textContent = n ? 'Draft ready' : 'No draft';
});

$('#commandInput').addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        sendMessage();
    }
});

$('#clearCommand').onclick = () => {
    $('#commandInput').value = '';
    $('#commandInput').dispatchEvent(new Event('input'));
    toast('Draft cleared.');
};

$('#machineSearch').addEventListener('input', e => renderMachines(e.target.value));
$('#addMachine').onclick = () => openMachineModal();
$('#machineOptions').onclick = () => selected() ? openMachineModal(state.machineId) : openMachineModal();
$('#footerEdit').onclick = () => selected() ? openMachineModal(state.machineId) : openMachineModal();
$('#closeModal').onclick = closeMachineModal;
$('#cancelModal').onclick = closeMachineModal;

$('#modalBackdrop').addEventListener('click', e => {
    if (e.target === $('#modalBackdrop')) closeMachineModal();
});

$('#machineForm').addEventListener('submit', async e => {
    e.preventDefault();
    const name = $('#machineNameInput').value.trim();
    const host = $('#machineHostInput').value.trim();
    const port = Number($('#machinePortInput').value);
    if (!name || !host || !Number.isInteger(port) || port < 1 || port > 65535) {
        toast('Check the machine name, host, and port.', true);
        return;
    }

    try {
        await api('/api/machines', 'POST', {
            action: state.editingId ? 'update' : 'add',
            id: state.editingId || '',
            name,
            host,
            port
        });
        toast(state.editingId ? 'Machine updated.' : 'Machine added.');
        closeMachineModal();
        await loadMachines();
    } catch (err) {
        toast(`Error saving machine: ${err.message}`, true);
    }
});

$('#deleteMachine').onclick = deleteSelected;
$('#connectionInfo').onclick = showInfo;
$('#closeInfo').onclick = closeInfo;
$('#doneInfo').onclick = closeInfo;
$('#infoBackdrop').addEventListener('click', e => {
    if (e.target === $('#infoBackdrop')) closeInfo();
});

document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
        closeMachineModal();
        closeInfo();
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        $('#machineSearch').focus();
    }
});

// Bootstrap
window.addEventListener('DOMContentLoaded', () => {
    loadMachines();
});
