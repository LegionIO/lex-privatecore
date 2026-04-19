# frozen_string_literal: true

require 'faraday'
require 'json'

module Legion
  module Extensions
    module Privatecore
      module Helpers
        module NerClient
          class NerServiceUnavailable < StandardError; end

          ENTITY_MAP = {
            'EMAIL_ADDRESS'     => :email,
            'PHONE_NUMBER'      => :phone,
            'US_SSN'            => :ssn,
            'IP_ADDRESS'        => :ip,
            'CREDIT_CARD'       => :credit_card,
            'DATE_TIME'         => :dob,
            'MEDICAL_LICENSE'   => :mrn,
            'PERSON'            => :person_name,
            'ORGANIZATION'      => :organization,
            'LOCATION'          => :location,
            'IBAN_CODE'         => :iban,
            'US_PASSPORT'       => :passport,
            'US_DRIVER_LICENSE' => :drivers_license,
            'CRYPTO'            => :crypto,
            'NRP'               => :national_id
          }.freeze

          NER_CATEGORIES = {
            person_name:  :personal,
            organization: :entity,
            location:     :location,
            national_id:  :government_id,
            crypto:       :crypto
          }.freeze

          module_function

          def analyze(text:, connection:, fallback: :transparent, timeout: 5)
            response = connection.post do |req|
              req.headers['Content-Type'] = 'application/json'
              req.body = ::JSON.generate(text: text, language: 'en')
              req.options.timeout = timeout
            end

            parse_response(response, text)
          rescue Faraday::Error, ::JSON::ParserError => e
            handle_fallback(fallback, e)
          end

          def available?(connection:)
            response = connection.get('/health')
            response.status == 200
          rescue Faraday::Error => e
            Legion::Logging.warn "[privatecore] NER health check failed: #{e.message}" # rubocop:disable Legion/HelperMigration/DirectLogging
            false
          end

          def build_connection(service_url:, timeout: 5)
            require 'faraday'
            Faraday.new(url: service_url) do |f|
              f.options.timeout = timeout
              f.options.open_timeout = timeout
              f.adapter Faraday.default_adapter
            end
          end

          def parse_response(response, text)
            return [] unless response.status == 200

            entities = ::JSON.parse(response.body)
            entities.filter_map do |entity|
              type = ENTITY_MAP[entity['entity_type']]
              next unless type

              category = NER_CATEGORIES[type] || :unknown

              {
                type:     type,
                category: category,
                start:    entity['start'],
                end:      entity['end'],
                match:    text[entity['start']...entity['end']],
                score:    entity['score'],
                source:   :ner
              }
            end
          end

          def handle_fallback(fallback, error)
            case fallback
            when :strict
              raise NerServiceUnavailable, "NER service unavailable: #{error.message}"
            else
              []
            end
          end
        end
      end
    end
  end
end
