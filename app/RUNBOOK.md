# GitNexus Embedding Runbook

## 1) Build or rebuild index with embeddings
- Initial build: `npx -y gitnexus@latest analyze --embeddings`
- Force reindex: `npx -y gitnexus@latest analyze --embeddings --force`
- Drop and regenerate embeddings: `npx -y gitnexus@latest analyze --embeddings --drop-embeddings --force`

## 2) Common runtime checks
- Index status: `npx -y gitnexus@latest status`
- Platform capabilities: `npx -y gitnexus@latest doctor`
- Check `.gitnexus/` folder exists in repo root.

## 3) Dimension mismatch handling
- Symptom: embedding insert/query fails after changing model or dims.
- Cause: `GITNEXUS_EMBEDDING_DIMS` changed but old embedding schema/index still present.
- Fix:
  1. Set desired env (`GITNEXUS_EMBEDDING_MODEL`, `GITNEXUS_EMBEDDING_DIMS`).
  2. Rebuild with `--drop-embeddings --force`.
  3. Verify with `status` and run a small `query`.

## 4) Missing VECTOR extension fallback
- Symptom: semantic path slower than expected.
- Cause: VECTOR extension unavailable, fallback to exact-scan.
- Validate via `doctor` output (VECTOR index / Semantic mode).
- Mitigation:
  - Install/enable VECTOR extension on target environment.
  - Reduce scope and use lower query limits during fallback mode.
  - Tune `GITNEXUS_SEMANTIC_EXACT_SCAN_LIMIT`.

## 5) Timeout and long-running analyze
- Increase `GITNEXUS_ANALYZE_TIMEOUT_SECONDS` for large repos.
- Use streaming analyze mode in Python wrapper to surface progress.
- For very large repos, tune:
  - `GITNEXUS_EMBEDDING_BATCH_SIZE`
  - `GITNEXUS_EMBEDDING_SUB_BATCH_SIZE`
  - `GITNEXUS_EMBEDDING_THREADS`
