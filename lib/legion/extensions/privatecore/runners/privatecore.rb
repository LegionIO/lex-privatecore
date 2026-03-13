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
              stripped = Helpers::Boundary.strip_pii(text)
              {
                original_length: text.length,
                cleaned:         stripped,
                pii_found:       Helpers::Boundary.contains_pii?(text),
                direction:       direction
              }
            when :inbound
              probe = Helpers::Boundary.detect_probe(text)
              {
                text:      text,
                probe:     probe,
                direction: direction,
                action:    probe ? :flag_and_log : :allow
              }
            end
          end

          def check_pii(text:, **)
            {
              contains_pii: Helpers::Boundary.contains_pii?(text),
              stripped:      Helpers::Boundary.strip_pii(text)
            }
          end

          def detect_probe(text:, **)
            { probe_detected: Helpers::Boundary.detect_probe(text) }
          end

          def erasure_audit(**)
            { audit_log: erasure_engine.audit_log, count: erasure_engine.audit_log.size }
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
