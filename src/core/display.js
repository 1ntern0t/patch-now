// Untrusted-text helpers. Advisory text, package names and versions all come
// from files or servers we do not control. They are DATA, never instructions,
// and are never rendered as HTML anywhere in this project.

// C0/C1 controls (incl. ESC, so ANSI sequences cannot recolor or move the
// cursor), zero-width chars, bidi embeddings/overrides/isolates, line/paragraph
// separators and the BOM.
const UNSAFE_CHARS = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g;

function escapeChar(c) {
  return '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0');
}

// One-line, terminal-safe rendering. Truncates first so the work is bounded.
export function safeText(value, max = 300) {
  let str = typeof value === 'string' ? value : String(value ?? '');
  let cut = false;
  if (str.length > max) {
    str = str.slice(0, max);
    cut = true;
  }
  str = str.replace(UNSAFE_CHARS, escapeChar);
  return cut ? str + '…[truncated]' : str;
}

// JSON output stays lossless (a JSON parser gets the original string back)
// but the raw bytes contain no bidi/control characters that could fool a
// human reading the file in a terminal or editor.
// JSON.stringify already escapes U+0000-U+001F inside strings; the remaining
// unsafe set never occurs outside strings, so escaping it keeps valid JSON.
const UNSAFE_IN_JSON = /[\u007f-\u009f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g;

export function safeJson(value, space = 2) {
  return JSON.stringify(value, null, space).replace(UNSAFE_IN_JSON, escapeChar);
}

// Clamp a string to a maximum length without escaping (for storage).
export function clampText(value, max) {
  const str = typeof value === 'string' ? value : '';
  return str.length > max ? str.slice(0, max) : str;
}
