// keyboard shortcut labels: ⌘ on Apple platforms and Ctrl everywhere else

const platform = (typeof navigator !== 'undefined'
  && ((navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || navigator.userAgent)) || '';

export const IS_MAC = /mac|iphone|ipad|ipod/i.test(platform);

// "mod+k" style ids become the visible label and the aria-keyshortcuts value
export function shortcut(id) {
  const parts = id.split('+');
  const key = parts.pop();
  const mods = parts;
  const visibleKey = key.length === 1 ? key.toUpperCase() : key === 'enter' ? (IS_MAC ? '↩' : 'Enter') : key;
  const label = IS_MAC
    ? `${mods.map((m) => ({ mod: '⌘', shift: '⇧', alt: '⌥' }[m] || m)).join('')}${visibleKey}`
    : [...mods.map((m) => ({ mod: 'Ctrl', shift: 'Shift', alt: 'Alt' }[m] || m)), visibleKey].join('+');
  const aria = [...mods.map((m) => ({ mod: IS_MAC ? 'Meta' : 'Control', shift: 'Shift', alt: 'Alt' }[m] || m)),
    key.length === 1 ? key.toUpperCase() : key === 'enter' ? 'Enter' : key].join('+');
  return { id, label, aria };
}

// a two-key sequence such as "g e"
export function sequence(first, second) {
  return { id: `${first} ${second}`, label: `${first.toUpperCase()} ${second.toUpperCase()}`, aria: `${first.toUpperCase()} ${second.toUpperCase()}` };
}

export function isModEvent(e) {
  return IS_MAC ? e.metaKey && !e.ctrlKey : e.ctrlKey && !e.metaKey;
}

// shortcuts never fire while someone is typing in a field
export function isTypingTarget(el) {
  if (!el || el === document.body) return false;
  if (el.isContentEditable) return true;
  const tag = el.tagName;
  if (tag === 'TEXTAREA' || tag === 'SELECT') return true;
  if (tag !== 'INPUT') return false;
  const type = (el.getAttribute('type') || 'text').toLowerCase();
  return !['checkbox', 'radio', 'button', 'submit', 'reset', 'file', 'range', 'color'].includes(type);
}
