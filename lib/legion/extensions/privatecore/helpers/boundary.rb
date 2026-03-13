# frozen_string_literal: true

module Legion
  module Extensions
    module Privatecore
      module Helpers
        module Boundary
          # PII patterns to strip before boundary crossing
          PII_PATTERNS = {
            email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
            phone: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/,
            ssn:   /\b\d{3}-\d{2}-\d{4}\b/,
            ip:    /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/
          }.freeze

          # Probe detection patterns (attempts to extract private data)
          PROBE_PATTERNS = [
            /what (?:does|did) .+ tell you/i,
            /share .+ private/i,
            /reveal .+ secret/i,
            /bypass .+ boundary/i,
            /ignore .+ directive/i
          ].freeze

          REDACTION_MARKER = '[REDACTED]'

          module_function

          def strip_pii(text)
            return text unless text.is_a?(String)

            result = text.dup
            PII_PATTERNS.each_value do |pattern|
              result.gsub!(pattern, REDACTION_MARKER)
            end
            result
          end

          def detect_probe(text)
            return false unless text.is_a?(String)

            PROBE_PATTERNS.any? { |p| p.match?(text) }
          end

          def contains_pii?(text)
            return false unless text.is_a?(String)

            PII_PATTERNS.any? { |_, pattern| pattern.match?(text) }
          end
        end
      end
    end
  end
end
