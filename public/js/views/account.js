import { h, mount } from '../dom.js';
import { api } from '../api.js';
import { formatTs } from '../lib/format.js';
import { pageHeader, card, field, fieldErrors } from '../ui.js';

export const MIN_PASSWORD = 12;

export function render(ctx) {
  const { user, session } = ctx;
  const current = h('input', { type: 'password', autocomplete: 'current-password', required: true, maxlength: 256 });
  const next = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: MIN_PASSWORD, maxlength: 256 });
  const confirm = h('input', { type: 'password', autocomplete: 'new-password', required: true, maxlength: 256 });
  const errors = h('div');
  const submit = h('button', { type: 'submit', class: 'btn btn-primary' }, 'Change password');

  async function onSubmit(e) {
    e.preventDefault();
    const problems = [];
    if (!current.value) problems.push({ field: 'Current password', message: 'required' });
    if (next.value.length < MIN_PASSWORD) problems.push({ field: 'New password', message: `at least ${MIN_PASSWORD} characters` });
    if (next.value && next.value === current.value) problems.push({ field: 'New password', message: 'must differ from the current password' });
    if (next.value !== confirm.value) problems.push({ field: 'Confirm', message: 'does not match the new password' });
    next.setAttribute('aria-invalid', String(problems.some((p) => p.field === 'New password')));
    confirm.setAttribute('aria-invalid', String(problems.some((p) => p.field === 'Confirm')));
    mount(errors, fieldErrors(problems));
    if (problems.length) return;
    submit.disabled = true;
    try {
      await api.changePassword(current.value, next.value);
      current.value = ''; next.value = ''; confirm.value = '';
      // the server revokes every session of this user after a password change
      ctx.sessionEnded('Password changed. All your sessions were signed out — sign in again with your new password.');
      return;
    } catch (err) {
      const labels = { currentPassword: 'Current password', newPassword: 'New password' };
      if (err && err.code === 'VALIDATION_FAILED') {
        const details = err.details.length ? err.details.map((d) => ({ ...d, field: labels[d.field] || d.field })) : [{ message: err.friendly }];
        mount(errors, fieldErrors(details));
      } else if (err && err.status !== 401) mount(errors, fieldErrors([{ message: err.friendly }]));
    } finally {
      submit.disabled = false;
    }
  }

  mount(ctx.el,
    pageHeader('Account'),
    h('p', { class: 'meta-line' },
      h('span', null, `${user.username} (${user.role})`),
      session && session.expiresAt ? h('span', null, `Session expires ${formatTs(session.expiresAt)}`) : null),
    card('Change password',
      h('form', { class: 'form', novalidate: true, on: { submit: onSubmit } },
        field('Current password', current),
        field('New password', next, `At least ${MIN_PASSWORD} characters.`),
        field('Confirm new password', confirm),
        errors,
        h('div', null, submit))));
}
