# frozen_string_literal: true

module Legion
  module Extensions
    module Privatecore
      module Helpers
        module Boundary
          PROBE_PATTERNS = [
            /what (?:does|did) .+ tell you/i,
            /share .+ private/i,
            /reveal .+ secret/i,
            /bypass .+ boundary/i,
            /ignore .+ directive/i
          ].freeze

          REDACTION_MARKER    = '[REDACTED]'
          MAX_AUDIT_LOG_SIZE  = 1000

          DEFAULT_ENABLED    = %i[email phone ssn ip].freeze
          DEFAULT_MODE       = :redact

          module_function

          def strip_pii(text, mode: nil, service_url: nil)
            return { cleaned: text, mapping: {}, detections: [], source: :none } unless text.is_a?(String)

            effective_mode    = resolve_setting(mode, :redaction, :mode) || DEFAULT_MODE
            effective_enabled = resolve_setting(nil, :patterns, :enabled) || DEFAULT_ENABLED
            effective_validation = resolve_setting(nil, :patterns, :validation) || {}

            detections = Patterns.detect(text, enabled: effective_enabled, validation: effective_validation)

            if service_url || ner_enabled?
              ner_detections = run_ner(text, service_url)
              detections = merge_detections(detections, ner_detections)
            end

            result = Redactor.redact(text, detections: detections, mode: effective_mode)
            has_ner_detections = detections.any? { |d| d[:source] == :ner }
            has_regex_detections = detections.any? { |d| d[:source] != :ner }
            source =
              if detections.empty?
                :none
              elsif has_ner_detections && has_regex_detections
                :ner_and_regex
              elsif has_ner_detections
                :ner
              else
                :regex
              end
            result.merge(source: source)
          end

          def contains_pii?(text, service_url: nil)
            return false unless text.is_a?(String)

            effective_enabled = resolve_setting(nil, :patterns, :enabled) || DEFAULT_ENABLED
            effective_validation = resolve_setting(nil, :patterns, :validation) || {}

            detections = Patterns.detect(text, enabled: effective_enabled, validation: effective_validation)
            return true unless detections.empty?

            if service_url || ner_enabled?
              ner_detections = run_ner(text, service_url)
              return true unless ner_detections.empty?
            end

            false
          end

          def detect_probe(text)
            return false unless text.is_a?(String)

            PROBE_PATTERNS.any? { |p| p.match?(text) }
          end

          def resolve_setting(override, *keys)
            return override unless override.nil?
            return nil unless defined?(Legion::Settings)

            Legion::Settings.dig(:privatecore, *keys)
          end

          def ner_enabled?
            return false unless defined?(Legion::Settings)

            Legion::Settings.dig(:privatecore, :ner, :enabled) == true
          end

          def run_ner(text, service_url)
            url = service_url || resolve_setting(nil, :ner, :service_url)
            return [] unless url

            timeout  = resolve_setting(nil, :ner, :timeout) || 5
            fallback = resolve_setting(nil, :ner, :fallback) || :transparent
            conn = NerClient.build_connection(service_url: url, timeout: timeout)
            NerClient.analyze(text: text, connection: conn, fallback: fallback, timeout: timeout)
          end

          def merge_detections(regex_detections, ner_detections)
            return regex_detections if ner_detections.empty?
            return ner_detections if regex_detections.empty?

            merged = ner_detections.dup
            regex_detections.each do |rd|
              overlaps = merged.any? do |nd|
                rd[:start] < nd[:end] && rd[:end] > nd[:start]
              end
              merged << rd unless overlaps
            end
            merged.sort_by { |d| d[:start] }
          end
        end
      end
    end
  end
end
