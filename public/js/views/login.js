import { h, mount } from '../dom.js';
import { api } from '../api.js';
import { field } from '../ui.js';
import { icon } from '../icons.js';

const GENERIC_FAILURE = 'Invalid username or password.';

export function render(ctx) {
  const username = h('input', { type: 'text', name: 'username', autocomplete: 'username', required: true, maxlength: 64, autocapitalize: 'none', spellcheck: 'false' });
  const password = h('input', { type: 'password', name: 'password', autocomplete: 'current-password', required: true, maxlength: 256 });
  const submit = h('button', { type: 'submit', class: 'btn btn-primary' }, 'Sign in');
  const message = h('div', { class: 'login-message', role: 'alert', 'aria-live': 'assertive' });
  let lockTimer = null;

  function showMessage(text, tone = 'bad') {
    mount(message, text ? h('p', { class: ['status-msg', tone === 'bad' ? 'status-error' : 'status-info'] },
      icon(tone === 'bad' ? 'alert' : 'info'), h('span', null, text)) : null);
  }

  function lockFor(seconds) {
    let left = Math.max(1, Math.ceil(seconds));
    submit.disabled = true;
    const tick = () => {
      showMessage(`Too many sign-in attempts. Try again in ${left} second${left === 1 ? '' : 's'}.`);
      left -= 1;
      if (left < 0) { clearInterval(lockTimer); lockTimer = null; submit.disabled = false; showMessage(''); }
    };
    tick();
    lockTimer = setInterval(tick, 1000);
  }

  const form = h('form', { class: 'form', novalidate: true, 'aria-labelledby': 'page-title', on: { submit: onSubmit } },
    field('Username', username),
    field('Password', password),
    submit);

  async function onSubmit(e) {
    e.preventDefault();
    showMessage('');
    if (!username.value.trim() || !password.value) {
      showMessage('Enter your username and password.');
      (username.value.trim() ? password : username).focus();
      return;
    }
    submit.disabled = true;
    try {
      const res = await api.login(username.value.trim(), password.value);
      password.value = '';
      ctx.setSession(res);
      ctx.navigate('#/dashboard');
    } catch (err) {
      password.value = '';
      if (err && (err.status === 429 || err.code === 'RATE_LIMITED')) {
        lockFor(err.retryAfter || 60);
        return;
      }
      if (err && err.status === 0) showMessage(err.friendly);
      else showMessage(GENERIC_FAILURE);
      submit.disabled = false;
      password.focus();
    }
  }

  mount(ctx.el,
    h('div', { class: 'card login-card' },
      h('p', { class: 'brand' }, h('span', { class: 'brand-mark' }, icon('logo')), 'WAF Studio'),
      h('h1', { id: 'page-title', tabindex: '-1' }, 'Sign in'),
      ctx.loginNotice ? h('p', { class: 'note' }, ctx.loginNotice) : null,
      message,
      form));
  username.focus();
  return () => { if (lockTimer) clearInterval(lockTimer); };
}
