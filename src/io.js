import { open, lstat, stat, opendir } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join } from 'node:path';
import { addJsonValue } from './core/osv.js';

// File input with hard limits. Only regular files are read (no devices,
// FIFOs or sockets, so /dev/zero or a named pipe cannot hang the tool). The
// size is checked on the opened descriptor and the read itself is capped, so
// a file that grows while we read it cannot exceed the limit either.

export const IO_LIMITS = Object.freeze({
  inventoryBytes: 64 * 1024 * 1024,
  // A single file is decoded into one string; V8 caps strings at ~512M
  // characters, so stay well under that. Bigger dumps: use a directory.
  osvFileBytes: 256 * 1024 * 1024,
  osvDirFileBytes: 16 * 1024 * 1024,
  osvDirFiles: 2000000,
  osvDirDepth: 4,
  osvDirEntries: 5000000,
  kevBytes: 32 * 1024 * 1024
});

export class InputError extends Error {}

// O_NONBLOCK: opening a FIFO for reading would otherwise block until a writer
// appears (before we get the chance to fstat it and refuse it). Regular files
// ignore the flag. noFollow is used for entries found while walking a
// directory, so a symlink swapped in after readdir is refused too.
export async function readLimited(path, maxBytes, { noFollow = false } = {}) {
  let fh;
  let flags = constants.O_RDONLY | (constants.O_NONBLOCK || 0);
  if (noFollow) flags |= constants.O_NOFOLLOW || 0;
  try {
    fh = await open(path, flags);
  } catch (e) {
    throw new InputError(`cannot open ${path}: ${e.code || e.message}`);
  }
  try {
    const st = await fh.stat();
    if (!st.isFile()) throw new InputError(`${path} is not a regular file`);
    if (st.size > maxBytes) throw new InputError(`${path} is ${st.size} bytes, over the ${maxBytes}-byte limit`);
    const buf = Buffer.alloc(Math.min(st.size, maxBytes) + 1);
    let off = 0;
    while (off < buf.length) {
      const { bytesRead } = await fh.read(buf, off, buf.length - off, off);
      if (bytesRead === 0) break;
      off += bytesRead;
    }
    if (off > maxBytes) throw new InputError(`${path} grew past the ${maxBytes}-byte limit while reading`);
    return buf.subarray(0, off);
  } finally {
    await fh.close();
  }
}

export async function readText(path, maxBytes, opts) {
  const buf = await readLimited(path, maxBytes, opts);
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: false }).decode(buf);
  } catch (e) {
    if (e instanceof RangeError) throw new InputError(`${path} is too large to decode`);
    throw e;
  }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  return text;
}

export async function readJson(path, maxBytes) {
  const text = await readText(path, maxBytes);
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new InputError(`${path} is not valid JSON: ${String(e.message).slice(0, 120)}`);
  }
}

// One JSON document, or NDJSON (one record per line).
export function addOsvText(index, text, wanted, label) {
  const trimmed = text.trimStart();
  try {
    addJsonValue(index, JSON.parse(trimmed), wanted);
    return;
  } catch (e) {
    if (!(e instanceof SyntaxError)) throw e;
  }
  let nonEmpty = 0;
  let bad = 0;
  // Walk lines by index instead of split() so a huge file does not also
  // become a huge array of strings.
  for (let pos = 0; pos < trimmed.length;) {
    let end = trimmed.indexOf('\n', pos);
    if (end === -1) end = trimmed.length;
    const line = trimmed.slice(pos, end);
    pos = end + 1;
    if (!line.trim()) continue;
    nonEmpty++;
    try {
      addJsonValue(index, JSON.parse(line), wanted);
    } catch (e) {
      if (!(e instanceof SyntaxError)) throw e;
      bad++;
    }
  }
  if (bad === nonEmpty) throw new InputError(`${label} is neither JSON nor NDJSON`);
  if (bad) index.dropped.set('unparseable NDJSON line', (index.dropped.get('unparseable NDJSON line') || 0) + bad);
}

// Loads a user-supplied OSV dump: a JSON/NDJSON file, or a directory of
// *.json files (for example an unzipped all.zip from the OSV bucket).
// Symlinks inside the directory are NOT followed, so the walk cannot leave the
// directory the user named.
export async function loadOsvPath(path, index, wanted, limits = IO_LIMITS) {
  let st;
  try {
    st = await lstat(path);
  } catch (e) {
    throw new InputError(`cannot read ${path}: ${e.code || e.message}`);
  }
  if (st.isSymbolicLink()) {
    // The top-level path is the user's explicit choice; resolve it once.
    st = await stat(path);
  }
  if (st.isFile()) {
    addOsvText(index, await readText(path, limits.osvFileBytes), wanted, path);
    return { files: 1 };
  }
  if (!st.isDirectory()) throw new InputError(`${path} is not a file or directory`);
  const queue = [[path, 0]];
  let head = 0;
  let files = 0;
  let seen = 0;
  let oversize = 0;
  let unreadable = 0;
  while (head < queue.length) {
    const [dir, depth] = queue[head];
    queue[head++] = null;
    let handle;
    try {
      handle = await opendir(dir);
    } catch (e) {
      if (dir === path) throw new InputError(`cannot read directory ${path}: ${e.code || e.message}`);
      unreadable++;
      continue;
    }
    // opendir streams entries, so a directory with millions of names is not
    // loaded into memory at once; every entry counts against a limit.
    for await (const ent of handle) {
      if (++seen > limits.osvDirEntries) throw new InputError(`more than ${limits.osvDirEntries} entries under ${path}`);
      const p = join(dir, ent.name);
      if (ent.isDirectory()) {
        if (depth + 1 <= limits.osvDirDepth) queue.push([p, depth + 1]);
        continue;
      }
      if (!ent.isFile() || !ent.name.toLowerCase().endsWith('.json')) continue;
      if (++files > limits.osvDirFiles) throw new InputError(`more than ${limits.osvDirFiles} files under ${path}`);
      let text;
      try {
        text = await readText(p, limits.osvDirFileBytes, { noFollow: true });
      } catch (e) {
        if (e instanceof InputError) {
          oversize++;
          continue;
        }
        throw e;
      }
      try {
        addJsonValue(index, JSON.parse(text), wanted);
      } catch (e) {
        if (!(e instanceof SyntaxError)) throw e;
        index.dropped.set('unparseable file', (index.dropped.get('unparseable file') || 0) + 1);
      }
    }
  }
  if (unreadable) index.dropped.set('unreadable subdirectory', unreadable);
  if (oversize) index.dropped.set('file over size limit or unreadable', oversize);
  return { files };
}
