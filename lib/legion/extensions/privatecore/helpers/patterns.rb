# frozen_string_literal: true

module Legion
  module Extensions
    module Privatecore
      module Helpers
        module Patterns
          PATTERNS = {
            email:           { regex:    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
                               category: :contact },
            phone:           { regex:    /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/,
                               category: :contact },
            ssn:             { regex:    /\b\d{3}-\d{2}-\d{4}\b/,
                               category: :government_id },
            ip:              { regex:    /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
                               category: :network },
            credit_card:     { regex: /\b(?:\d[ -]*?){13,19}\b/,
                               category: :financial, checksum: :luhn },
            dob:             { regex:    %r{(?:DOB|date of birth)\s*:\s*(\d{1,4}[-/]\d{1,2}[-/]\d{1,4})}i,
                               category: :personal },
            mrn:             { regex:    /(?:MRN|medical record)\s*:\s*(\d{5,15})/i,
                               category: :medical },
            passport:        { regex:    /\b[A-Z]\d{8}\b/,
                               category: :government_id },
            iban:            { regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/,
                               category: :financial, checksum: :iban },
            drivers_license: { regex:    /\b[A-Z]\d{3}-?\d{4}-?\d{4}\b/,
                               category: :government_id },
            url:             { regex:    %r{https?://[^\s<>"{}|\\^`\[\]]+},
                               category: :network },
            btc_address:     { regex: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/,
                               category: :crypto, checksum: :base58check },
            eth_address:     { regex:    /\b0x[0-9a-fA-F]{40}\b/,
                               category: :crypto },
            itin:            { regex:    /\b9\d{2}-[7-9]\d-\d{4}\b/,
                               category: :government_id },
            aadhaar:         { regex: /\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b/,
                               category: :government_id, checksum: :verhoeff },
            api_key:         { regex:    /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b/,
                               category: :credential },
            bearer_token:    { regex:    %r{Bearer\s+[A-Za-z0-9\-._~+/]+=*},
                               category: :credential },
            aws_key:         { regex:    /\bAKIA[0-9A-Z]{16}\b/,
                               category: :credential }
          }.freeze

          module_function

          CHECKSUM_VALIDATORS = {
            luhn:        ->(digits) { luhn_valid?(digits) },
            iban:        ->(text) { iban_valid?(text) },
            verhoeff:    ->(digits) { verhoeff_valid?(digits) },
            base58check: ->(addr) { base58check_valid?(addr) }
          }.freeze

          def detect(text, enabled:, validation:)
            return [] unless text.is_a?(String)

            detections = []
            PATTERNS.each do |type, meta|
              next unless enabled.include?(type)

              text.scan(meta[:regex]) do
                md = Regexp.last_match
                matched_text = md.captures.compact.first || md[0]
                next if validation[type] == :checksum && !validate_checksum(type, matched_text)

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

          def validate_checksum(type, match)
            meta = PATTERNS[type]
            return true unless meta && meta[:checksum]

            validator = CHECKSUM_VALIDATORS[meta[:checksum]]
            return true unless validator

            cleaned = match.gsub(/[\s-]/, '')
            validator.call(cleaned)
          end

          def luhn_valid?(number)
            digits = number.chars.map(&:to_i)
            sum = 0
            digits.reverse.each_with_index do |d, i|
              d *= 2 if i.odd?
              d -= 9 if d > 9
              sum += d
            end
            (sum % 10).zero?
          end

          def iban_valid?(iban)
            rearranged = iban[4..] + iban[0..3]
            numeric = rearranged.chars.map { |c| c.match?(/\d/) ? c : (c.upcase.ord - 55).to_s }.join
            (numeric.to_i % 97) == 1
          end

          VERHOEFF_D = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
            [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
            [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
            [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
            [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
          ].freeze

          VERHOEFF_P = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
            [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
            [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
            [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
          ].freeze

          def verhoeff_valid?(number)
            digits = number.chars.map(&:to_i).reverse
            c = 0
            digits.each_with_index { |d, i| c = VERHOEFF_D[c][VERHOEFF_P[i % 8][d]] }
            c.zero?
          end

          def base58check_valid?(address)
            address.match?(/\A[13][a-km-zA-HJ-NP-Z1-9]{25,34}\z/)
          end
        end
      end
    end
  end
end
