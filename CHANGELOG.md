# Changelog

## [0.2.0] - 2026-04-17

### Added
- `Helpers::Patterns` module with 18 PII regex patterns (email, phone, SSN, IP, credit card, DOB, MRN, passport, IBAN, driver's license, URL, BTC address, ETH address, ITIN, Aadhaar, API key, bearer token, AWS key)
- Configurable checksum validation for credit card (Luhn), IBAN (mod-97), Aadhaar (Verhoeff), and BTC address (Base58Check)
- `Helpers::Redactor` with 4 redaction modes: `:redact`, `:placeholder`, `:mask`, `:synthetic`
- Round-trip `restore()` for placeholder and synthetic modes with optional `Legion::Cache` persistence
- `Helpers::NerClient` for optional Presidio NER service delegation with configurable fallback (`:silent`, `:transparent`, `:strict`)
- `restore_text` runner method for de-anonymization
- Position offsets (start/end) returned for all detected entities
- All features configurable via `Legion::Settings.dig(:privatecore, ...)`

### Changed
- `Helpers::Boundary` refactored as coordinator delegating to Patterns, Redactor, and NerClient
- `enforce_boundary` and `check_pii` runner methods now accept optional `mode:` and `service_url:` kwargs
- `enforce_boundary` outbound response includes `:detections` and `:mapping` keys
- `check_pii` response includes `:detections` array
- `faraday` added as runtime dependency for NER client
- Only original 4 patterns (email, phone, SSN, IP) enabled by default — new patterns opt-in via settings

## [0.1.6] - 2026-03-30

### Changed
- update to rubocop-legion 0.1.7, resolve all offenses

## [0.1.5] - 2026-03-22

### Changed
- Add legion-cache, legion-crypt, legion-data, legion-json, legion-logging, legion-settings, and legion-transport as runtime dependencies
- Replace direct Legion::Logging calls with injected log helper in runners/privatecore.rb and runners/embedding_guard.rb
- Update spec_helper with real sub-gem helper requires and Helpers::Lex stub

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
