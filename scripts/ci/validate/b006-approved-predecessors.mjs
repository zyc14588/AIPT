#!/usr/bin/env node
import { runAsMain } from '../lib/cli.mjs';
import { runApprovedPredecessor, cleanupSnapshots } from '../lib/b006-successor.mjs';
function run(ctx, args) { try { return runApprovedPredecessor(ctx, args); } finally { cleanupSnapshots(); } }
runAsMain(import.meta.url, 'b006-approved-predecessors', run);
