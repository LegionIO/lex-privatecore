# frozen_string_literal: true

module Legion
  module Extensions
    module Privatecore
      module Helpers
        module Patterns
          PATTERNS = {
            email:           { regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
                               category: :contact },
            phone:           { regex: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/,
                               category: :contact },
            ssn:             { regex: /\b\d{3}-\d{2}-\d{4}\b/,
                               category: :government_id },
            ip:              { regex: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
                               category: :network }
          }.freeze

          module_function

          def detect(text, enabled:, validation:)
            return [] unless text.is_a?(String)

            detections = []
            PATTERNS.each do |type, meta|
              next unless enabled.include?(type)

              text.scan(meta[:regex]) do
                md = Regexp.last_match
                detections << {
                  type:     type,
                  category: meta[:category],
                  start:    md.begin(0),
                  end:      md.end(0),
                  match:    md[0]
                }
              end
            end
            detections
          end
        end
      end
    end
  end
end
