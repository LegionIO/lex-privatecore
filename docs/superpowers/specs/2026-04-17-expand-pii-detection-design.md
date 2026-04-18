# Expand PII Detection from 4 to 20+ Categories

**Issue:** [LegionIO/lex-privatecore#2](https://github.com/LegionIO/lex-privatecore/issues/2)
**Date:** 2026-04-17
**Branch:** `feature/expand-pii-detection`

## Overview

Expand lex-privatecore's PII detection from 4 regex patterns to 18+ categories, add optional Presidio NER delegation with configurable fallback, and introduce multiple redaction modes with round-trip restore capability. All new features are disabled by default — zero behavioral change for existing users until explicitly opted in.

## Architecture: Layered Helper Modules

The existing `Helpers::Boundary` becomes a coordinator over three new focused helpers:

```
Runners::Privatecore (public API — unchanged signatures + new optional kwargs)
  └── Helpers::Boundary (coordinator)
        ├── Helpers::Patterns   (regex registry + optional checksum validation)
        ├── Helpers::Redactor   (4 redaction modes + restore + optional cache)
        └── Helpers::NerClient  (Faraday-based Presidio client + fallback)
```

No changes to LegionIO or any other gem. External consumers use the runner methods; no one calls helpers directly.

## Settings Schema

All configuration under `Legion::Settings.dig(:privatecore, ...)`:

```ruby
{
  privatecore: {
    patterns: {
      enabled: [:email, :phone, :ssn, :ip],  # only originals on by default
      available: [
        :email, :phone, :ssn, :ip, :credit_card, :dob, :mrn, :passport,
        :iban, :drivers_license, :url, :btc_address, :eth_address,
        :itin, :aadhaar, :api_key, :bearer_token, :aws_key
      ],
      validation: {
        credit_card: :regex,   # :regex | :checksum (Luhn)
        iban: :regex,          # :regex | :checksum (IBAN mod-97)
        btc_address: :regex,   # :regex | :checksum (Base58Check)
        aadhaar: :regex        # :regex | :checksum (Verhoeff)
      }
    },
    redaction: {
      mode: :redact,           # :redact | :placeholder | :mask | :synthetic
      cache_mappings: false,   # persist placeholder/synthetic mappings to legion-cache
      cache_ttl: 3600          # seconds, when cache_mappings is true
    },
    ner: {
      enabled: false,
      service_url: nil,        # e.g. "http://presidio:5002/analyze"
      timeout: 5,              # seconds
      fallback: :transparent   # :silent | :transparent | :strict
    },
    embedding_guard: {
      threshold: 0.85
    }
  }
}
```

**Default behavior:** Only the 4 original patterns enabled, `:redact` mode, no NER, no cache, no checksum validation. Identical to current behavior.

## Helpers::Patterns

Registry of all PII patterns with metadata:

```ruby
PATTERNS = {
  email:           { regex: /.../, category: :contact },
  phone:           { regex: /.../, category: :contact },
  ssn:             { regex: /.../, category: :government_id },
  ip:              { regex: /.../, category: :network },
  credit_card:     { regex: /.../, category: :financial,     checksum: :luhn },
  dob:             { regex: /.../, category: :personal },
  mrn:             { regex: /.../, category: :medical },
  passport:        { regex: /.../, category: :government_id },
  iban:            { regex: /.../, category: :financial,     checksum: :iban },
  drivers_license: { regex: /.../, category: :government_id },
  url:             { regex: /.../, category: :network },
  btc_address:     { regex: /.../, category: :crypto,        checksum: :base58check },
  eth_address:     { regex: /.../, category: :crypto },
  itin:            { regex: /.../, category: :government_id },
  aadhaar:         { regex: /.../, category: :government_id, checksum: :verhoeff },
  api_key:         { regex: /.../, category: :credential },
  bearer_token:    { regex: /.../, category: :credential },
  aws_key:         { regex: /.../, category: :credential }
}
```

### Module Methods

- `detect(text, enabled:, validation:)` — returns `[{ type:, category:, start:, end:, match: }]` with position offsets. Only checks patterns in the `enabled` list. Runs checksums only when validation mode is `:checksum` for that pattern type.
- `validate_checksum(type, match)` — dispatches to Luhn, IBAN mod-97, Base58Check, or Verhoeff based on pattern's `checksum` key. Returns boolean.

## Helpers::Redactor

Four redaction modes:

| Mode | Example Input | Example Output |
|------|---------------|----------------|
| `:redact` | `SSN: 123-45-6789` | `SSN: [REDACTED]` |
| `:placeholder` | `SSN: 123-45-6789` | `SSN: [SSN_1]` + mapping `{"[SSN_1]" => "123-45-6789"}` |
| `:mask` | `SSN: 123-45-6789` | `SSN: ***-**-****` |
| `:synthetic` | `SSN: 123-45-6789` | `SSN: 987-65-4321` + mapping `{"987-65-4321" => "123-45-6789"}` |

### Module Methods

- `redact(text, detections:, mode:)` — returns `{ cleaned:, mapping:, detections: }`. Mapping populated for `:placeholder` and `:synthetic` modes.
- `restore(text:, mapping:)` — reverses placeholder/synthetic substitution using the mapping hash.
- `persist_mapping(mapping:, key:)` — stores to `legion-cache` when `cache_mappings: true`. Key defaults to `SecureRandom.uuid`, returned to caller.
- `retrieve_mapping(key:)` — retrieves from cache.

Synthetic generators produce random digits in the correct format per pattern type. Not cryptographically random, just structurally valid.

## Helpers::NerClient

Faraday-based client for Presidio-compatible NER services.

### Request/Response

**Request:** `POST service_url` with `{ text: "...", language: "en" }`

**Response:** Presidio returns `[{ "entity_type": "PERSON", "start": 0, "end": 12, "score": 0.95 }]`

### Entity Type Mapping

```ruby
ENTITY_MAP = {
  "EMAIL_ADDRESS"     => :email,
  "PHONE_NUMBER"      => :phone,
  "US_SSN"            => :ssn,
  "IP_ADDRESS"        => :ip,
  "CREDIT_CARD"       => :credit_card,
  "DATE_TIME"         => :dob,
  "MEDICAL_LICENSE"   => :mrn,
  "PERSON"            => :person_name,
  "ORGANIZATION"      => :organization,
  "LOCATION"          => :location,
  "IBAN_CODE"         => :iban,
  "US_PASSPORT"       => :passport,
  "US_DRIVER_LICENSE"  => :drivers_license,
  "CRYPTO"            => :crypto,
  "NRP"               => :national_id
}
```

NER-only types (`:person_name`, `:organization`, `:location`) have no regex equivalent — they only appear in results when NER is enabled.

### Fallback Behavior (per `ner.fallback` setting)

- `:silent` — log warning, return empty array, caller merges with regex results
- `:transparent` — same as silent but injects `source: :regex_fallback` into the response
- `:strict` — raises `NerServiceUnavailable` error

### Module Methods

- `analyze(text:)` — returns detections in same format as `Patterns.detect`
- `available?` — health check, memoized with short TTL

Faraday is an optional gem dependency — only required at load time when NER is enabled.

## Helpers::Boundary (Updated Coordinator)

Public API preserved, gains optional parameters.

### `strip_pii(text, mode: nil, service_url: nil)`

1. Resolve effective settings (param overrides > Settings > defaults)
2. `Patterns.detect(text, enabled:, validation:)` for regex detections
3. If NER enabled: `NerClient.analyze(text:)`, merge and deduplicate overlapping spans (prefer NER results — they have confidence scores)
4. `Redactor.redact(text, detections:, mode:)` for output
5. Return `{ cleaned:, mapping:, detections:, source: }`

**Breaking change (internal only):** `strip_pii` now returns a hash instead of a string. The only caller is `Runners::Privatecore#enforce_boundary`, which extracts `[:cleaned]`. No external API change.

### `contains_pii?(text, service_url: nil)`

Same detection pipeline, returns boolean. Unchanged contract.

### `detect_probe(text)`

Unchanged.

### Span Deduplication

When regex and NER return overlapping detections for the same text region, prefer the NER result. Non-overlapping detections from both sources are merged into the final list.

## Runner Changes

### Updated Methods (backward-compatible — new optional kwargs)

**`enforce_boundary(text:, direction: :outbound, mode: nil, service_url: nil, **)`**
- Outbound: full detection pipeline with configurable redaction mode. Returns same hash shape, adds `:detections` and `:mapping` keys (additive).
- Inbound: unchanged probe detection.

**`check_pii(text:, service_url: nil, **)`**
- Returns same `{ contains_pii:, stripped: }` shape. Adds `:detections` array with position offsets and types.

**`detect_probe(text:, **)` — unchanged.**

### New Methods

**`restore_text(text:, mapping: nil, mapping_key: nil, **)`**
- If `mapping:` provided, uses it directly
- If `mapping_key:` provided, retrieves from cache
- If neither provided, returns `{ restored: nil, success: false, error: :no_mapping }`
- Returns `{ restored:, success: }`

**`erasure_audit`, `prune_audit_log` — unchanged.**

## Dependencies

- `faraday` added as an optional runtime dependency (only loaded when NER enabled)
- No other new dependencies

## Testing Strategy

### Unit Tests Per Helper

- **Patterns** — each of 18 pattern types: clear match, near-miss, edge case. Checksum validation tested separately for credit card, IBAN, BTC, Aadhaar. Position offsets verified.
- **Redactor** — each mode tested with multi-PII text. Restore round-trip for `:placeholder` and `:synthetic`. Cache persistence with mock `legion-cache`.
- **NerClient** — Faraday stubbed with `Faraday::Adapter::Test`. Tests: successful parse, timeout fallback (all 3 modes), malformed response, entity type mapping.
- **Boundary** (updated) — integration-level: regex-only, NER+regex merge with span deduplication, settings overrides via params.

### Runner Tests

- Existing specs pass unchanged (backward compat validation)
- New specs: `mode:` parameter, `service_url:` parameter, `restore_text` method, detections array in responses

### Test Boundaries

No mocking of internal helpers — tests call through the real code path. Only external boundaries (Faraday, legion-cache) get stubbed.

## File Plan

### New Files

```
lib/legion/extensions/privatecore/helpers/patterns.rb
lib/legion/extensions/privatecore/helpers/redactor.rb
lib/legion/extensions/privatecore/helpers/ner_client.rb
spec/legion/extensions/privatecore/helpers/patterns_spec.rb
spec/legion/extensions/privatecore/helpers/redactor_spec.rb
spec/legion/extensions/privatecore/helpers/ner_client_spec.rb
spec/legion/extensions/privatecore/helpers/boundary_spec.rb
```

### Modified Files

```
lib/legion/extensions/privatecore/helpers/boundary.rb  (coordinator logic)
lib/legion/extensions/privatecore/runners/privatecore.rb (new optional kwargs + restore_text)
lib/legion/extensions/privatecore/client.rb (requires for new helpers)
lib/legion/extensions/privatecore.rb (requires for new helpers)
lex-privatecore.gemspec (faraday optional dep, version bump)
spec/legion/extensions/privatecore/runners/privatecore_spec.rb (new specs added)
```

### Unchanged Files

```
lib/legion/extensions/privatecore/helpers/erasure.rb
lib/legion/extensions/privatecore/helpers/similarity.rb
lib/legion/extensions/privatecore/runners/embedding_guard.rb
lib/legion/extensions/privatecore/actors/audit_prune.rb
spec/legion/extensions/privatecore/actors/audit_prune_spec.rb
spec/legion/extensions/privatecore/client_spec.rb (existing specs pass as-is)
```
