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
            ner_fallback = apply_ner(detections, text, service_url)

            result = Redactor.redact(text, detections: detections, mode: effective_mode)
            source = determine_source(detections, ner_fallback)
            mapping_key = persist_mapping_if_configured(result[:mapping])

            result.merge(source: source, mapping_key: mapping_key)
          end

          def contains_pii?(text, service_url: nil)
            return false unless text.is_a?(String)

            effective_enabled = resolve_setting(nil, :patterns, :enabled) || DEFAULT_ENABLED
            effective_validation = resolve_setting(nil, :patterns, :validation) || {}

            detections = Patterns.detect(text, enabled: effective_enabled, validation: effective_validation)
            return true unless detections.empty?

            if service_url || ner_enabled?
              ner_result = run_ner(text, service_url)
              ner_detections = if ner_result.is_a?(Hash) && ner_result[:fallback]
                                 ner_result[:detections]
                               else
                                 ner_result
                               end
              return true unless ner_detections.empty?
            end

            false
          end

          def detect_probe(text)
            return false unless text.is_a?(String)

            PROBE_PATTERNS.any? { |p| p.match?(text) }
          end

          def apply_ner(detections, text, service_url)
            return false unless service_url || ner_enabled?

            ner_result = run_ner(text, service_url)
            if ner_result.is_a?(Hash) && ner_result[:fallback]
              ner_detections = ner_result[:detections]
              detections.replace(merge_detections(detections, ner_detections))
              true
            else
              detections.replace(merge_detections(detections, ner_result))
              false
            end
          end

          def determine_source(detections, ner_fallback)
            has_ner = detections.any? { |d| d[:source] == :ner }
            has_regex = detections.any? { |d| d[:source] != :ner }

            if detections.empty?
              :none
            elsif ner_fallback
              :regex_fallback
            elsif has_ner && has_regex
              :ner_and_regex
            elsif has_ner
              :ner
            else
              :regex
            end
          end

          def persist_mapping_if_configured(mapping)
            return nil if mapping.empty?
            return nil unless resolve_setting(nil, :redaction, :cache_mappings) == true

            cache_ttl = resolve_setting(nil, :redaction, :cache_ttl) || 3600
            Redactor.persist_mapping(mapping: mapping, key: nil, ttl: cache_ttl)
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

            allow_http = resolve_setting(nil, :ner, :allow_http) == true
            return [] unless allow_http || url.start_with?('https://')

            timeout  = resolve_setting(nil, :ner, :timeout) || 5
            fallback = resolve_setting(nil, :ner, :fallback) || :transparent
            conn = NerClient.build_connection(service_url: url, timeout: timeout)
            NerClient.analyze(text: text, connection: conn, fallback: fallback, timeout: timeout)
          end

          def merge_detections(regex_detections, ner_detections)
            return regex_detections if ner_detections.empty?
            return ner_detections if regex_detections.empty?

            all = regex_detections.map { |d| d.merge(source: :regex) } +
                  ner_detections
            all.sort_by! { |d| [d[:start], -(d[:end] - d[:start])] }

            merged = []
            all.each do |detection|
              if merged.empty? || detection[:start] >= merged.last[:end]
                merged << detection
              else
                prev = merged.last
                det_span = detection[:end] - detection[:start]
                prev_span = prev[:end] - prev[:start]
                merged[-1] = detection if det_span > prev_span
              end
            end
            merged
          end
        end
      end
    end
  end
end
