// stale-while-revalidate for list screens: a revisit paints the last response at once and
// refetches in the background. memory only, never storage, and cleared whenever the session changes

const MAX_ENTRIES = 40;
const store = new Map();

export function clearCache() { store.clear(); }

function remember(key, data) {
  store.delete(key);
  store.set(key, data);
  while (store.size > MAX_ENTRIES) store.delete(store.keys().next().value);
}

const same = (a, b) => {
  try { return JSON.stringify(a) === JSON.stringify(b); } catch { return false; }
};

/**
 * paint(data, { stale }) runs with the cached copy first (if any) and again with fresh data
 * when it differs. Without a cached copy a fetch error is thrown to the caller as before; with one,
 * onStaleError(err) is called and the cached screen stays.
 */
export async function swr(key, fetcher, paint, { isCurrent = () => true, onStaleError, skipCache = false } = {}) {
  // skipCache is for reloads right after a change, where the cached copy is known to be old
  const hit = !skipCache && store.has(key) ? store.get(key) : undefined;
  if (hit !== undefined) paint(hit, { stale: true });
  let fresh;
  try {
    fresh = await fetcher();
  } catch (err) {
    if (hit === undefined) throw err;
    if (isCurrent() && onStaleError) onStaleError(err);
    return hit;
  }
  remember(key, fresh);
  if (!isCurrent()) return fresh;
  if (hit === undefined || !same(hit, fresh)) paint(fresh, { stale: false });
  return fresh;
}
