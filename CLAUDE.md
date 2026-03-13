# lex-privatecore

**Level 3 Documentation**
- **Parent**: `extensions-agentic/CLAUDE.md`
- **Grandparent**: `/Users/miverso2/rubymine/legion/CLAUDE.md`

## Purpose

Privacy boundary enforcement and cryptographic erasure for the LegionIO cognitive architecture. Strips PII from outbound text via regex patterns, detects boundary probe attempts in inbound text, and provides selective memory erasure operations with an audit log.

## Gem Info

- **Gem name**: `lex-privatecore`
- **Version**: `0.1.0`
- **Module**: `Legion::Extensions::Privatecore`
- **Ruby**: `>= 3.4`
- **License**: MIT

## File Structure

```
lib/legion/extensions/privatecore/
  version.rb
  helpers/
    boundary.rb  # PII_PATTERNS, PROBE_PATTERNS, REDACTION_MARKER, strip_pii, detect_probe, contains_pii?
    erasure.rb   # Erasure class - erase_by_type, erase_by_partition, full_erasure, audit_log
  runners/
    privatecore.rb # enforce_boundary, check_pii, detect_probe, erasure_audit
spec/
  legion/extensions/privatecore/
    runners/
      privatecore_spec.rb
    client_spec.rb
```

## Key Constants (Helpers::Boundary)

```ruby
PII_PATTERNS = {
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
  phone: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/,
  ssn:   /\b\d{3}-\d{2}-\d{4}\b/,
  ip:    /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/
}
PROBE_PATTERNS = [
  /what (?:does|did) .+ tell you/i,
  /share .+ private/i,
  /reveal .+ secret/i,
  /bypass .+ boundary/i,
  /ignore .+ directive/i
]
REDACTION_MARKER = '[REDACTED]'
```

## Erasure Class

`Helpers::Erasure` maintains an `@audit_log` array. Erasure methods (`erase_by_type`, `erase_by_partition`, `full_erasure`) operate on a passed-in `traces` array (mutating it in-place with `reject!` or `clear`), then record to the audit log.

This design means erasure logic lives here but the memory store is passed in from the caller (typically from `lex-memory`'s consolidation runner).

Audit log entries: `{ action: Symbol, at: Time, **details }` — unbounded.

## enforce_boundary Logic

`:outbound` direction: calls `strip_pii` and `contains_pii?`, returns cleaned text.
`:inbound` direction: calls `detect_probe`, returns `action: :flag_and_log` if probe detected, `:allow` otherwise.

Unknown directions: nil return (caller must handle).

## Integration Points

- **lex-memory**: `Consolidation#erase_by_type` and `erase_by_agent` delegate to this extension's erasure logic
- **lex-extinction**: level 4 (cryptographic erasure) triggers `full_erasure` on all memory traces
- **lex-tick**: outbound text passes through `enforce_boundary` before delivery; inbound signals checked for probes

## Development Notes

- `strip_pii` uses `gsub!` in a loop — modifies a dup of the input, not the original
- The IP pattern will match partial IPs and some non-IP strings (false positives expected); intentionally broad
- Erasure methods receive a live array reference and mutate it — callers must pass the actual store's array
- `@erasure_engine` on the runner is lazily initialized; each runner instance has its own audit log
