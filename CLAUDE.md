# lex-privatecore

**Level 3 Documentation**
- **Parent**: `/Users/miverso2/rubymine/legion/extensions-agentic/CLAUDE.md`
- **Grandparent**: `/Users/miverso2/rubymine/legion/CLAUDE.md`

## Purpose

Privacy boundary enforcement and cryptographic erasure for the LegionIO cognitive architecture. Strips PII from outbound text via regex patterns (18 types) with optional NER service augmentation, detects boundary probe attempts in inbound text, supports reversible redaction (4 modes), and provides selective memory erasure operations with an audit log.

## Gem Info

- **Gem name**: `lex-privatecore`
- **Version**: `0.1.5`
- **Module**: `Legion::Extensions::Privatecore`
- **Ruby**: `>= 3.4`
- **License**: MIT

## File Structure

```
lib/legion/extensions/privatecore/
  version.rb
  helpers/
    boundary.rb    # Coordinator: delegates to Patterns, Redactor, NerClient; PROBE_PATTERNS, REDACTION_MARKER, MAX_AUDIT_LOG_SIZE
    patterns.rb    # PATTERNS (18 types), detect(), validate_checksum(), Luhn/IBAN/Verhoeff/Base58Check
    redactor.rb    # redact() (4 modes: redact/placeholder/mask/synthetic), restore(), persist_mapping(), retrieve_mapping()
    ner_client.rb  # ENTITY_MAP, analyze(), available?(), build_connection(), NerServiceUnavailable
    erasure.rb     # Erasure class - erase_by_type, erase_by_partition, full_erasure, audit_log
    similarity.rb  # cosine_similarity
  runners/
    privatecore.rb  # enforce_boundary, check_pii, detect_probe, restore_text, erasure_audit, prune_audit_log
    embedding_guard.rb # check_embedding_similarity, cache_pattern_embeddings
  actors/
    audit_prune.rb # AuditPrune - Every 3600s, calls prune_audit_log
spec/
  legion/extensions/privatecore/
    helpers/
      patterns_spec.rb
      redactor_spec.rb
      ner_client_spec.rb
      boundary_spec.rb
    runners/
      privatecore_spec.rb
    actors/
      audit_prune_spec.rb
    client_spec.rb
```

## Key Constants

### Helpers::Boundary

```ruby
PROBE_PATTERNS = [
  /what (?:does|did) .+ tell you/i,
  /share .+ private/i,
  /reveal .+ secret/i,
  /bypass .+ boundary/i,
  /ignore .+ directive/i
]
REDACTION_MARKER   = '[REDACTED]'
MAX_AUDIT_LOG_SIZE = 1000
```

### Helpers::Patterns::PATTERNS (18 types)

| Category | Types |
|----------|-------|
| Contact | `email`, `phone` |
| Government ID | `ssn`, `passport`, `aadhaar` |
| Financial | `credit_card`, `iban`, `btc_address` |
| Network | `ip`, `ipv6`, `mac_address` |
| Authentication | `jwt`, `api_key`, `aws_key` |
| Personal | `dob`, `drivers_license` |
| Medical | `medical_record` |
| Location | `coordinate` |

Each pattern includes a regex. Types with structured checksums (`credit_card`, `iban`, `btc_address`, `aadhaar`) have `validate_checksum()` support via Luhn, IBAN mod-97, Base58Check, and Verhoeff algorithms.

## Settings Schema

```ruby
{
  privatecore: {
    patterns: {
      enabled: [:email, :phone, :ssn, :ip],  # only originals on by default
      available: [...all 18...],
      validation: { credit_card: :regex, iban: :regex, btc_address: :regex, aadhaar: :regex }
    },
    redaction: { mode: :redact, cache_mappings: false, cache_ttl: 3600 },
    ner: { enabled: false, service_url: nil, timeout: 5, fallback: :transparent },
    embedding_guard: { threshold: 0.85 }
  }
}
```

## Redaction Modes

| Mode | Behavior |
|------|----------|
| `:redact` | Replace match with `[REDACTED]` (default, non-reversible) |
| `:placeholder` | Replace with type-tagged token (e.g. `[EMAIL_1]`), reversible via `restore()` |
| `:mask` | Partial mask preserving structure (e.g. `j***@example.com`) |
| `:synthetic` | Replace with realistic synthetic data of the same type |

## Erasure Class

`Helpers::Erasure` maintains an `@audit_log` array. Erasure methods (`erase_by_type`, `erase_by_partition`, `full_erasure`) operate on a passed-in `traces` array (mutating it in-place with `reject!` or `clear`), then record to the audit log.

This design means erasure logic lives here but the memory store is passed in from the caller (typically from `lex-memory`'s consolidation runner).

Audit log entries: `{ action: Symbol, at: Time, **details }` — capped at `MAX_AUDIT_LOG_SIZE` (1000) by the `AuditPrune` actor.

## Actors

| Actor | Interval | Runner Method | What It Does |
|-------|----------|---------------|--------------|
| `AuditPrune` | Every 3600s | `prune_audit_log` | Caps the audit log at `MAX_AUDIT_LOG_SIZE` (1000) by shifting oldest entries off the front |

## enforce_boundary Logic

`:outbound` direction: accepts `mode:` (redaction mode) and `service_url:` (NER endpoint) kwargs. Calls `strip_pii` which returns a hash (`{ cleaned:, detections:, mapping: }`); runner extracts `cleaned` text and detection metadata. Returns cleaned text plus detection details.

`:inbound` direction: calls `detect_probe`, returns `action: :flag_and_log` if probe detected, `:allow` otherwise.

`restore_text`: reverses placeholder/synthetic redaction using the mapping returned by `strip_pii` (only works with reversible modes).

Unknown directions: nil return (caller must handle).

## Integration Points

- **lex-memory**: `Consolidation#erase_by_type` and `erase_by_agent` delegate to this extension's erasure logic
- **lex-extinction**: level 4 (cryptographic erasure) triggers `full_erasure` on all memory traces
- **lex-tick**: outbound text passes through `enforce_boundary` before delivery; inbound signals checked for probes
- **NER/Presidio**: when `ner.enabled` is true, `NerClient` calls an external Presidio (or compatible) service for entity recognition, merging results with regex detections

## Development Notes

- `strip_pii` uses `gsub!` in a loop — modifies a dup of the input, not the original
- The IP pattern will match partial IPs and some non-IP strings (false positives expected); intentionally broad
- Erasure methods receive a live array reference and mutate it — callers must pass the actual store's array
- `@erasure_engine` on the runner is lazily initialized; each runner instance has its own audit log
- `prune_audit_log` uses `shift` in a loop to remove oldest entries first; the `AuditPrune` actor calls this hourly to prevent unbounded growth
