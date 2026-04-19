# frozen_string_literal: true

module Legion
  module Extensions
    module Privatecore
      module Runners
        module Privatecore
          include Legion::Extensions::Helpers::Lex if Legion::Extensions.const_defined?(:Helpers, false) &&
                                                      Legion::Extensions::Helpers.const_defined?(:Lex, false)

          def enforce_boundary(text:, direction: :outbound, mode: nil, service_url: nil, **)
            case direction
            when :outbound
              result = Helpers::Boundary.strip_pii(text, mode: mode, service_url: service_url)
              pii_found = !result[:detections].empty?
              text_length = text.is_a?(String) ? text.length : 0
              log.debug "[privatecore] boundary outbound: length=#{text_length} pii_found=#{pii_found}"
              log.warn '[privatecore] PII stripped from outbound text' if pii_found
              safe_detections = result[:detections].map { |d| d.except(:match) }
              {
                original_length: text_length,
                cleaned:         result[:cleaned],
                pii_found:       pii_found,
                direction:       direction,
                detections:      safe_detections,
                mapping:         result[:mapping],
                mapping_key:     result[:mapping_key]
              }
            when :inbound
              probe = Helpers::Boundary.detect_probe(text)
              action = probe ? :flag_and_log : :allow
              log.debug "[privatecore] boundary inbound: probe=#{probe} action=#{action}"
              log.warn '[privatecore] PROBE DETECTED in inbound text' if probe
              {
                text:      text,
                probe:     probe,
                direction: direction,
                action:    action
              }
            end
          end

          def check_pii(text:, service_url: nil, **)
            result = Helpers::Boundary.strip_pii(text, service_url: service_url)
            has_pii = !result[:detections].empty?
            log.debug "[privatecore] pii check: contains_pii=#{has_pii}"
            safe_detections = result[:detections].map { |d| d.except(:match) }
            {
              contains_pii: has_pii,
              stripped:     result[:cleaned],
              detections:   safe_detections
            }
          end

          def detect_probe(text:, **)
            probe = Helpers::Boundary.detect_probe(text)
            log.debug "[privatecore] probe check: detected=#{probe}"
            Legion::Events.emit('privatecore.probe_detected', text_length: text.is_a?(String) ? text.length : 0) if probe && defined?(Legion::Events)
            { probe_detected: probe }
          end

          def restore_text(text:, mapping: nil, mapping_key: nil, **)
            if mapping
              restored = Helpers::Redactor.restore(text: text, mapping: mapping)
              { restored: restored, success: true }
            elsif mapping_key
              retrieved = Helpers::Redactor.retrieve_mapping(key: mapping_key)
              if retrieved
                restored = Helpers::Redactor.restore(text: text, mapping: retrieved)
                { restored: restored, success: true }
              else
                { restored: nil, success: false, error: :mapping_not_found }
              end
            else
              { restored: nil, success: false, error: :no_mapping }
            end
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
