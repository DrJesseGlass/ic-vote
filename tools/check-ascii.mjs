#!/usr/bin/env node
// Assert that every git-tracked file is pure ASCII.
//
// Two reasons this is asserted rather than assumed:
//
//   - The served bundle's sha256 is what the ProvenanceRegistry attests.
//     Non-ASCII bytes hash fine, but they are where an encoding or
//     normalization difference between what a reviewer reads, what an editor
//     saves, and what the canister serves can quietly change that hash.
//   - Homoglyphs. A Cyrillic 'a' in an identifier, a URL, or a hex constant is
//     invisible in review and is a known supply-chain trick. In a repo whose
//     whole claim is "a human reviewed exactly these bytes", characters that
//     are not what they appear to be have no place.
//
// Written in Node rather than as a shell one-liner because the obvious shell
// spelling is not portable and fails OPEN. `grep -P '[^\x00-\x7F]'` works with
// GNU grep and ugrep but BSD grep (macOS /usr/bin/grep) rejects -P and exits 2;
// with stderr redirected to /dev/null, an `if` around it reads that failure as
// "no matches" and the check passes on a file full of non-ASCII. That is
// exactly the fail-open shape this repo's review flagged elsewhere, and it is
// worse here than no check at all, because a green line says something was
// verified. Node is already a hard dependency of this project.
//
// If a legitimate need for non-ASCII arises, widen this deliberately (an
// allowlist of paths) rather than deleting it.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const files = execFileSync("git", ["ls-files", "-z"], { encoding: "buffer" })
  .toString("utf8")
  .split("\0")
  .filter(Boolean);

if (files.length === 0) {
  console.error("FAILED: `git ls-files` returned nothing; is this a git repository?");
  process.exit(1);
}

const offences = [];
for (const file of files) {
  let bytes;
  try {
    bytes = readFileSync(file);
  } catch (e) {
    // A tracked path that cannot be read is not a pass.
    offences.push({ file, line: 0, column: 0, detail: `unreadable: ${e.message}` });
    continue;
  }
  let line = 1;
  let column = 1;
  for (const byte of bytes) {
    if (byte === 0x0a) {
      line++;
      column = 1;
      continue;
    }
    if (byte > 0x7f) {
      offences.push({
        file,
        line,
        column,
        detail: `byte 0x${byte.toString(16).padStart(2, "0")}`,
      });
    }
    column++;
  }
}

if (offences.length > 0) {
  console.error(`FAILED: non-ASCII bytes in ${new Set(offences.map((o) => o.file)).size} file(s)`);
  // One line per offending source line, not per byte: a single accented
  // character is several bytes and would otherwise report several times.
  const seen = new Set();
  for (const o of offences) {
    const key = `${o.file}:${o.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const text = (() => {
      try {
        return readFileSync(o.file, "utf8").split("\n")[o.line - 1]?.trim() ?? "";
      } catch {
        return "";
      }
    })();
    console.error(`  ${o.file}:${o.line}:${o.column}  ${o.detail}  ${text.slice(0, 100)}`);
  }
  process.exit(1);
}

console.log(`  ok    ${files.length} tracked files, ASCII only`);
