# Changelog

## [0.1.4] - 2026-03-21

### Added
- `Helpers::Similarity` module with pure-Ruby `cosine_similarity(vec_a:, vec_b:)` — guards against nil, empty, mismatched-length, and all-zero vectors
- `Runners::EmbeddingGuard` module with `check_embedding_similarity(input:, threshold:, patterns:)` — generates input embedding via `Legion::LLM.embed`, compares against adversarial pattern embeddings using cosine similarity, returns safe/unsafe verdict with matched pattern and per-pattern details
- `DEFAULT_ADVERSARIAL_PATTERNS` constant with 15 known adversarial prompts (ignore previous instructions, system prompt override, etc.)
- `cache_pattern_embeddings(patterns:)` — pre-computes and memoises pattern embeddings to avoid redundant LLM calls
- Settings-aware threshold resolution via `Legion::Settings.dig(:privatecore, :embedding_guard, :threshold)` with 0.85 fallback
- Graceful degradation when `Legion::LLM` is unavailable (`skipped: true`) or embed fails (`error: :embed_failed`)
- 38 new specs across `helpers/similarity_spec.rb` and `runners/embedding_guard_spec.rb`

## [0.1.3] - 2026-03-20

### Added
- Emit `privatecore.probe_detected` event for safety metrics integration

## [0.1.2] - 2026-03-18

### Changed
- removed unused legion-gaia dependency
- deleted gemfile.lock

## [0.1.1] - 2026-03-14

### Added
- `AuditPrune` actor (Every 3600s) — calls `prune_audit_log` to cap the audit log at `MAX_AUDIT_LOG_SIZE` (1000), keeping the most recent entries

## [0.1.0] - 2026-03-13

### Added
- Initial release
