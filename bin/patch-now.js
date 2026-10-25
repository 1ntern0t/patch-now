#!/usr/bin/env node
import { main } from '../src/cli.js';

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    process.stderr.write(`patch-now: internal error: ${String(err && err.message).slice(0, 300)}\n`);
    process.exitCode = 2;
  }
);
