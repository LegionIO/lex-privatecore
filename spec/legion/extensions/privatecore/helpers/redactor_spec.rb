# frozen_string_literal: true

require 'legion/extensions/privatecore/helpers/redactor'

RSpec.describe Legion::Extensions::Privatecore::Helpers::Redactor do
  let(:text) { 'SSN: 123-45-6789 and email john@example.com' }
  let(:detections) do
    [
      { type: :ssn, category: :government_id, start: 5, end: 16, match: '123-45-6789' },
      { type: :email, category: :contact, start: 27, end: 43, match: 'john@example.com' }
    ]
  end

  describe '.redact' do
    context 'mode :redact' do
      it 'replaces all detections with [REDACTED]' do
        result = described_class.redact(text, detections: detections, mode: :redact)
        expect(result[:cleaned]).to eq('SSN: [REDACTED] and email [REDACTED]')
        expect(result[:mapping]).to eq({})
      end
    end

    context 'mode :placeholder' do
      it 'replaces with numbered type tags' do
        result = described_class.redact(text, detections: detections, mode: :placeholder)
        expect(result[:cleaned]).to include('[SSN_1]')
        expect(result[:cleaned]).to include('[EMAIL_1]')
        expect(result[:mapping]['[SSN_1]']).to eq('123-45-6789')
        expect(result[:mapping]['[EMAIL_1]']).to eq('john@example.com')
      end
    end

    context 'mode :mask' do
      it 'replaces with asterisks matching original length' do
        result = described_class.redact(text, detections: detections, mode: :mask)
        expect(result[:cleaned]).to include('***-**-****')
        expect(result[:mapping]).to eq({})
      end
    end

    context 'mode :synthetic' do
      it 'replaces with format-valid fake data and builds mapping' do
        result = described_class.redact(text, detections: detections, mode: :synthetic)
        expect(result[:cleaned]).not_to include('123-45-6789')
        expect(result[:cleaned]).not_to include('john@example.com')
        expect(result[:mapping]).not_to be_empty
        expect(result[:mapping].values).to include('123-45-6789', 'john@example.com')
      end
    end

    it 'preserves detections in the result' do
      result = described_class.redact(text, detections: detections, mode: :redact)
      expect(result[:detections]).to eq(detections)
    end

    it 'handles empty detections' do
      result = described_class.redact('clean text', detections: [], mode: :redact)
      expect(result[:cleaned]).to eq('clean text')
    end

    it 'handles nil text' do
      result = described_class.redact(nil, detections: [], mode: :redact)
      expect(result[:cleaned]).to be_nil
    end
  end

  describe '.restore' do
    it 'reverses placeholder substitution' do
      mapping = { '[SSN_1]' => '123-45-6789', '[EMAIL_1]' => 'john@example.com' }
      redacted = 'SSN: [SSN_1] and email [EMAIL_1]'
      result = described_class.restore(text: redacted, mapping: mapping)
      expect(result).to eq('SSN: 123-45-6789 and email john@example.com')
    end

    it 'returns text unchanged with empty mapping' do
      result = described_class.restore(text: 'unchanged', mapping: {})
      expect(result).to eq('unchanged')
    end
  end

  describe '.persist_mapping' do
    before do
      stub_const('Legion::Cache', Class.new do
        def self.set(key, value, ttl: nil) # rubocop:disable Lint/UnusedMethodArgument
          @store ||= {}
          @store[key] = value
        end

        def self.get(key)
          @store ||= {}
          @store[key]
        end
      end)
    end

    it 'stores mapping in cache and returns a key' do
      mapping = { '[SSN_1]' => '123-45-6789' }
      key = described_class.persist_mapping(mapping: mapping, key: nil, ttl: 3600)
      expect(key).to be_a(String)
      expect(key.length).to eq(36)
    end

    it 'uses provided key' do
      mapping = { '[SSN_1]' => '123-45-6789' }
      key = described_class.persist_mapping(mapping: mapping, key: 'my-key', ttl: 3600)
      expect(key).to eq('my-key')
    end
  end

  describe '.retrieve_mapping' do
    before do
      stub_const('Legion::Cache', Class.new do
        def self.set(key, value, ttl: nil) # rubocop:disable Lint/UnusedMethodArgument
          @store ||= {}
          @store[key] = value
        end

        def self.get(key)
          @store ||= {}
          @store[key]
        end
      end)
    end

    it 'retrieves a previously stored mapping' do
      mapping = { '[SSN_1]' => '123-45-6789' }
      key = described_class.persist_mapping(mapping: mapping, key: 'test-key', ttl: 3600)
      retrieved = described_class.retrieve_mapping(key: key)
      expect(retrieved).to eq(mapping)
    end

    it 'returns nil for missing key' do
      result = described_class.retrieve_mapping(key: 'nonexistent')
      expect(result).to be_nil
    end
  end
end
