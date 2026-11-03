import { h, mount, code } from '../dom.js';
import { api } from '../api.js';
import { ROLES } from '../lib/roles.js';
import { formatTs } from '../lib/format.js';
import { pageHeader, card, field, select, table, statusLabel, loading, errorPanel, showStatus, confirmDialog, fieldErrors, busy } from '../ui.js';

const MIN_PASSWORD = 12;
const USERNAME = /^[A-Za-z0-9._-]{3,64}$/;

export async function render(ctx) {
  const listBox = h('div', null, loading());
  const username = h('input', { type: 'text', maxlength: 64, autocomplete: 'off', spellcheck: 'false', required: true });
  const password = h('input', { type: 'password', maxlength: 256, autocomplete: 'new-password', required: true });
  const role = select(ROLES, 'operator');
  const errors = h('div');
  const createBtn = h('button', { type: 'submit', class: 'btn btn-primary' }, 'Create user');

  async function create(e) {
    e.preventDefault();
    const problems = [];
    if (!USERNAME.test(username.value.trim())) problems.push({ field: 'Username', message: '3–64 letters, digits, ., _ or -' });
    if (password.value.length < MIN_PASSWORD) problems.push({ field: 'Password', message: `at least ${MIN_PASSWORD} characters` });
    mount(errors, fieldErrors(problems));
    if (problems.length) return;
    await busy(createBtn, async () => {
      try {
        await api.createUser(username.value.trim(), password.value, role.value);
        showStatus(`User ${username.value.trim()} created as ${role.value}.`, 'success');
        username.value = ''; password.value = '';
        await load();
      } catch (err) {
        password.value = '';
        if (err && err.code === 'VALIDATION_FAILED') { mount(errors, fieldErrors(err.details)); return; }
        throw err;
      }
    });
  }

  async function changeRole(u, newRole, btn) {
    if (newRole === u.role) { showStatus('Role unchanged.', 'info'); return; }
    const { confirmed } = await confirmDialog({
      title: `Change role of ${u.username}?`,
      body: h('p', null, `${u.username}: ${u.role} → ${newRole}. Their permissions change on their next request.`),
      confirmLabel: 'Change role', danger: newRole === 'admin' || u.role === 'admin',
    });
    if (!confirmed) return;
    await busy(btn, async () => {
      await api.updateUser(u.id, { role: newRole, confirm: true });
      showStatus(`${u.username} is now ${newRole}.`, 'success');
      await load();
    });
  }

  async function toggleDisabled(u, btn) {
    const disabling = !u.disabled;
    const { confirmed } = await confirmDialog({
      title: `${disabling ? 'Disable' : 'Enable'} ${u.username}?`,
      body: h('p', null, disabling
        ? `${u.username} will be signed out and unable to sign in until re-enabled.`
        : `${u.username} will be able to sign in again.`),
      confirmLabel: disabling ? 'Disable user' : 'Enable user', danger: disabling,
    });
    if (!confirmed) return;
    await busy(btn, async () => {
      await api.updateUser(u.id, { disabled: disabling, confirm: true });
      showStatus(`${u.username} ${disabling ? 'disabled' : 'enabled'}.`, 'success');
      await load();
    });
  }

  async function setPassword(u, btn) {
    const { confirmed, values } = await confirmDialog({
      title: `Set a new password for ${u.username}`,
      body: h('p', null, 'Use this to recover a locked-out account. Share the password through a safe channel and ask the user to change it.'),
      confirmLabel: 'Set password',
      fields: [{ name: 'password', label: 'New password', type: 'password', required: true, autocomplete: 'new-password', hint: `At least ${MIN_PASSWORD} characters.` }],
    });
    if (!confirmed) return;
    if (values.password.length < MIN_PASSWORD) { showStatus(`Password must be at least ${MIN_PASSWORD} characters.`, 'error'); return; }
    await busy(btn, async () => {
      await api.updateUser(u.id, { password: values.password, confirm: true });
      showStatus(`Password for ${u.username} updated.`, 'success');
    });
  }

  async function load() {
    let res;
    try {
      res = await api.users();
    } catch (err) {
      if (err && err.status === 401) return;
      mount(listBox, errorPanel(err, load));
      return;
    }
    if (!ctx.isCurrent()) return;
    mount(listBox, table({
      caption: 'Users',
      columns: [
        { key: 'username', label: 'Username', rowHeader: true, render: (u) => h('span', null, u.username, u.id === ctx.user.id ? ' (you)' : '') },
        { key: 'role', label: 'Role', render: (u) => {
          if (u.id === ctx.user.id) return u.role;
          const sel = select(ROLES, u.role, { 'aria-label': `Role for ${u.username}` });
          const apply = h('button', { type: 'button', class: 'btn btn-small' }, 'Apply');
          apply.addEventListener('click', () => changeRole(u, sel.value, apply));
          return h('span', { class: 'btn-group' }, sel, apply);
        } },
        { key: 'status', label: 'Status', render: (u) => {
          if (u.disabled) return statusLabel('disabled', 'muted');
          if (u.lockedUntil && Date.parse(u.lockedUntil) > Date.now()) return statusLabel(`locked until ${formatTs(u.lockedUntil)}`, 'bad');
          return statusLabel('active', 'ok');
        } },
        { key: 'createdAt', label: 'Created', render: (u) => formatTs(u.createdAt) },
        { key: 'id', label: 'Id', render: (u) => code(u.id) },
        { key: 'act', label: 'Actions', render: (u) => {
          if (u.id === ctx.user.id) return h('a', { href: '#/account', class: 'btn btn-small' }, 'Account');
          const dis = h('button', { type: 'button', class: ['btn', 'btn-small', u.disabled ? null : 'btn-danger'] }, u.disabled ? 'Enable' : 'Disable');
          dis.addEventListener('click', () => toggleDisabled(u, dis));
          const pw = h('button', { type: 'button', class: 'btn btn-small' }, 'Set password');
          pw.addEventListener('click', () => setPassword(u, pw));
          return h('div', { class: 'btn-group' }, pw, dis);
        } },
      ],
      rows: res.items || [],
      empty: 'No users.',
    }));
  }

  mount(ctx.el,
    pageHeader('Users'),
    card('Create a user',
      h('form', { class: 'form', novalidate: true, on: { submit: create } },
        h('div', { class: 'form-row' },
          field('Username', username),
          field('Initial password', password, `At least ${MIN_PASSWORD} characters.`),
          field('Role', role)),
        errors,
        h('div', null, createBtn)),
      h('p', { class: 'muted small' }, 'Roles: admin (configures, approves, audits), operator (analyzes, requests exceptions, exports), viewer (dashboard and sanitized summaries only). Grant the least privilege needed.')),
    card('Accounts', listBox));
  await load();
}
