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
                               category: :network },
            credit_card:     { regex: /\b(?:\d[ -]*?){13,19}\b/,
                               category: :financial, checksum: :luhn },
            dob:             { regex: /(?:DOB|date of birth)\s*:\s*(\d{1,4}[-\/]\d{1,2}[-\/]\d{1,4})/i,
                               category: :personal },
            mrn:             { regex: /(?:MRN|medical record)\s*:\s*(\d{5,15})/i,
                               category: :medical },
            passport:        { regex: /\b[A-Z]\d{8}\b/,
                               category: :government_id },
            iban:            { regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/,
                               category: :financial, checksum: :iban },
            drivers_license: { regex: /\b[A-Z]\d{3}[-]?\d{4}[-]?\d{4}\b/,
                               category: :government_id },
            url:             { regex: %r{https?://[^\s<>"{}|\\^`\[\]]+},
                               category: :network },
            btc_address:     { regex: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/,
                               category: :crypto, checksum: :base58check },
            eth_address:     { regex: /\b0x[0-9a-fA-F]{40}\b/,
                               category: :crypto },
            itin:            { regex: /\b9\d{2}-[7-9]\d-\d{4}\b/,
                               category: :government_id },
            aadhaar:         { regex: /\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b/,
                               category: :government_id, checksum: :verhoeff },
            api_key:         { regex: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b/,
                               category: :credential },
            bearer_token:    { regex: /Bearer\s+[A-Za-z0-9\-._~+\/]+=*/,
                               category: :credential },
            aws_key:         { regex: /\bAKIA[0-9A-Z]{16}\b/,
                               category: :credential }
          }.freeze

          module_function

          def detect(text, enabled:, validation:)
            return [] unless text.is_a?(String)

            detections = []
            PATTERNS.each do |type, meta|
              next unless enabled.include?(type)

              text.scan(meta[:regex]) do
                md = Regexp.last_match
                matched_text = md.captures.compact.first || md[0]
                detections << {
                  type:     type,
                  category: meta[:category],
                  start:    md.begin(0),
                  end:      md.end(0),
                  match:    matched_text
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
