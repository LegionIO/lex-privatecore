# frozen_string_literal: true

require 'securerandom'

module Legion
  module Extensions
    module Privatecore
      module Helpers
        module Redactor
          REDACTION_MARKER = '[REDACTED]'

          module_function

          def redact(text, detections:, mode:)
            return { cleaned: text, mapping: {}, detections: detections } unless text.is_a?(String)
            return { cleaned: text, mapping: {}, detections: detections } if detections.empty?

            mapping = {}
            type_counters = Hash.new(0)
            cleaned = text.dup

            sorted = detections.sort_by { |d| -d[:start] }

            sorted.each do |detection|
              replacement = build_replacement(detection, mode, type_counters, mapping)
              cleaned[detection[:start]...detection[:end]] = replacement
            end

            { cleaned: cleaned, mapping: mapping, detections: detections }
          end

          def build_replacement(detection, mode, type_counters, mapping)
            case mode
            when :redact
              REDACTION_MARKER
            when :placeholder
              type_counters[detection[:type]] += 1
              tag = "[#{detection[:type].upcase}_#{type_counters[detection[:type]]}]"
              mapping[tag] = detection[:match]
              tag
            when :mask
              mask_value(detection[:match])
            when :synthetic
              fake = generate_synthetic(detection[:type], detection[:match])
              mapping[fake] = detection[:match]
              fake
            else
              REDACTION_MARKER
            end
          end

          def mask_value(original)
            original.gsub(/[A-Za-z]/, '*').gsub(/\d/, '*')
          end

          def generate_synthetic(type, original)
            case type
            when :ssn, :itin
              "#{rand(100..999)}-#{rand(10..99)}-#{rand(1000..9999)}"
            when :phone
              "#{rand(200..999)}-#{rand(200..999)}-#{rand(1000..9999)}"
            when :email
              "user#{rand(1000..9999)}@example.net"
            when :credit_card
              generate_luhn_number(16)
            when :ip
              "#{rand(1..254)}.#{rand(0..255)}.#{rand(0..255)}.#{rand(1..254)}"
            when :aadhaar
              "#{rand(2000..9999)} #{rand(1000..9999)} #{rand(1000..9999)}"
            when :passport
              "#{('A'..'Z').to_a.sample}#{rand(10_000_000..99_999_999)}"
            when :aws_key
              "AKIA#{Array.new(16) { (('0'..'9').to_a + ('A'..'Z').to_a).sample }.join}"
            else
              SecureRandom.hex(original.length / 2)
            end
          end

          def generate_luhn_number(length)
            digits = Array.new(length - 1) { rand(0..9) }
            sum = 0
            digits.reverse.each_with_index do |d, i|
              v = i.even? ? d * 2 : d
              v -= 9 if v > 9
              sum += v
            end
            check = (10 - (sum % 10)) % 10
            (digits << check).join
          end
        end
      end
    end
  end
end
