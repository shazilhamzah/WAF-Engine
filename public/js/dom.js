// attack payloads are shown as evidence so data only enters the dom as text

const SVG_NS = 'http://www.w3.org/2000/svg';

const FORBIDDEN_ATTRS = new Set(['innerhtml', 'outerhtml', 'style', 'srcdoc']);
const URL_ATTRS = new Set(['href', 'src', 'action', 'formaction', 'xlink:href']);

export function isSafeUrl(value) {
  const v = String(value).trim();
  if (v.startsWith('#')) return true;
  if (v.startsWith('/') && !v.startsWith('//')) return true;
  if (v.startsWith('blob:')) return true;
  return false;
}

function setAttr(el, name, value) {
  const lower = name.toLowerCase();
  if (FORBIDDEN_ATTRS.has(lower) || lower.startsWith('on')) {
    throw new Error(`dom: attribute "${name}" is not allowed`);
  }
  if (value === null || value === undefined || value === false) return;
  if (URL_ATTRS.has(lower) && !isSafeUrl(value)) {
    throw new Error(`dom: unsafe URL in "${name}"`);
  }
  if (value === true) { el.setAttribute(name, ''); return; }
  el.setAttribute(name, String(value));
}

function applyAttrs(el, attrs) {
  if (!attrs) return;
  for (const [key, value] of Object.entries(attrs)) {
    if (key === 'on') {
      for (const [evt, fn] of Object.entries(value || {})) el.addEventListener(evt, fn);
    } else if (key === 'class') {
      const cls = Array.isArray(value) ? value.filter(Boolean).join(' ') : value;
      if (cls) el.setAttribute('class', cls);
    } else if (key === 'dataset') {
      for (const [k, v] of Object.entries(value || {})) if (v !== undefined && v !== null) el.dataset[k] = String(v);
    } else if (key === 'value' && 'value' in el) {
      el.value = value === null || value === undefined ? '' : String(value);
    } else if ((key === 'checked' || key === 'disabled' || key === 'selected' || key === 'required' || key === 'multiple' || key === 'hidden' || key === 'readOnly') && key in el) {
      el[key] = Boolean(value);
    } else if (key === 'text') {
      el.textContent = value === null || value === undefined ? '' : String(value);
    } else {
      setAttr(el, key, value);
    }
  }
}

function appendChildren(el, children) {
  for (const child of children) {
    if (child === null || child === undefined || child === false || child === true) continue;
    if (Array.isArray(child)) { appendChildren(el, child); continue; }
    if (typeof child === 'object' && typeof child.nodeType === 'number') { el.appendChild(child); continue; }
    el.appendChild(document.createTextNode(String(child)));
  }
}

export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs && (typeof attrs !== 'object' || Array.isArray(attrs) || typeof attrs.nodeType === 'number')) {
    children.unshift(attrs);
    attrs = null;
  }
  applyAttrs(el, attrs);
  appendChildren(el, children);
  // a select's value can only be set once its options exist
  if (attrs && 'value' in attrs && el.tagName === 'SELECT') {
    el.value = attrs.value === null || attrs.value === undefined ? '' : String(attrs.value);
  }
  return el;
}

export function s(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  applyAttrs(el, attrs);
  appendChildren(el, children);
  return el;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

export function mount(el, ...children) {
  clear(el);
  appendChildren(el, children);
  return el;
}

export function code(text, cls) {
  return h('code', { class: cls || 'code' }, text === null || text === undefined ? '' : String(text));
}

let idCounter = 0;
export function uid(prefix = 'f') {
  idCounter += 1;
  return `${prefix}-${idCounter}`;
}
