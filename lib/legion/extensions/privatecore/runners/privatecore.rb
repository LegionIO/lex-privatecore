# frozen_string_literal: true

module Legion
  module Extensions
    module Privatecore
      module Runners
        module Privatecore
          include Legion::Extensions::Helpers::Lex if Legion::Extensions.const_defined?(:Helpers) &&
                                                      Legion::Extensions::Helpers.const_defined?(:Lex)

          def enforce_boundary(text:, direction: :outbound, **)
            case direction
            when :outbound
              pii_found = Helpers::Boundary.contains_pii?(text)
              stripped = Helpers::Boundary.strip_pii(text)
              log.debug "[privatecore] boundary outbound: length=#{text.length} pii_found=#{pii_found}"
              log.warn '[privatecore] PII stripped from outbound text' if pii_found
              {
                original_length: text.length,
                cleaned:         stripped,
                pii_found:       pii_found,
                direction:       direction
              }
            when :inbound
              probe = Helpers::Boundary.detect_probe(text)
              action = probe ? :flag_and_log : :allow
              log.debug "[privatecore] boundary inbound: probe=#{!probe.nil?} action=#{action}"
              log.warn '[privatecore] PROBE DETECTED in inbound text' if probe
              {
                text:      text,
                probe:     probe,
                direction: direction,
                action:    action
              }
            end
          end

          def check_pii(text:, **)
            has_pii = Helpers::Boundary.contains_pii?(text)
            log.debug "[privatecore] pii check: contains_pii=#{has_pii}"
            {
              contains_pii: has_pii,
              stripped:     Helpers::Boundary.strip_pii(text)
            }
          end

          def detect_probe(text:, **)
            probe = Helpers::Boundary.detect_probe(text)
            log.debug "[privatecore] probe check: detected=#{!probe.nil?}"
            Legion::Events.emit('privatecore.probe_detected', text_length: text.length) if probe && defined?(Legion::Events)
            { probe_detected: probe }
          end

          def erasure_audit(**)
            count = erasure_engine.audit_log.size
            log.debug "[privatecore] erasure audit: entries=#{count}"
            { audit_log: erasure_engine.audit_log, count: count }
          end

          def prune_audit_log(**)
            audit = erasure_engine.audit_log
            cap = Helpers::Boundary::MAX_AUDIT_LOG_SIZE
            pruned = 0
            while audit.size > cap
              audit.shift
              pruned += 1
            end
            log.debug "[privatecore] audit prune: pruned=#{pruned} remaining=#{audit.size}"
            { pruned: pruned, remaining: audit.size }
          end

          private

          def erasure_engine
            @erasure_engine ||= Helpers::Erasure.new
          end
        end
      end
    end
  end
end
