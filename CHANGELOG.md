# Changelog

## [0.1.1] - 2026-03-14

### Added
- `AuditPrune` actor (Every 3600s) — calls `prune_audit_log` to cap the audit log at `MAX_AUDIT_LOG_SIZE` (1000), keeping the most recent entries

## [0.1.0] - 2026-03-13

### Added
- Initial release
