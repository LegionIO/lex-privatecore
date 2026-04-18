# frozen_string_literal: true

require 'legion/extensions/privatecore/helpers/patterns'

RSpec.describe Legion::Extensions::Privatecore::Helpers::Patterns do
  let(:enabled) { %i[email phone ssn ip] }
  let(:validation) { {} }

  describe '.detect' do
    it 'detects an email address with position' do
      result = described_class.detect('Contact john@example.com please', enabled: enabled, validation: validation)
      match = result.find { |d| d[:type] == :email }
      expect(match).not_to be_nil
      expect(match[:match]).to eq('john@example.com')
      expect(match[:start]).to eq(8)
      expect(match[:end]).to eq(24)
      expect(match[:category]).to eq(:contact)
    end

    it 'detects a phone number' do
      result = described_class.detect('Call 555-123-4567 now', enabled: enabled, validation: validation)
      match = result.find { |d| d[:type] == :phone }
      expect(match).not_to be_nil
      expect(match[:match]).to eq('555-123-4567')
      expect(match[:category]).to eq(:contact)
    end

    it 'detects an SSN' do
      result = described_class.detect('SSN: 123-45-6789', enabled: enabled, validation: validation)
      match = result.find { |d| d[:type] == :ssn }
      expect(match).not_to be_nil
      expect(match[:match]).to eq('123-45-6789')
      expect(match[:category]).to eq(:government_id)
    end

    it 'detects an IP address' do
      result = described_class.detect('Server at 192.168.1.1 is down', enabled: enabled, validation: validation)
      match = result.find { |d| d[:type] == :ip }
      expect(match).not_to be_nil
      expect(match[:match]).to eq('192.168.1.1')
      expect(match[:category]).to eq(:network)
    end

    it 'returns empty array for clean text' do
      result = described_class.detect('Nothing here', enabled: enabled, validation: validation)
      expect(result).to eq([])
    end

    it 'only checks enabled patterns' do
      result = described_class.detect('john@example.com', enabled: [:phone], validation: validation)
      expect(result).to eq([])
    end

    it 'detects multiple PII in one string' do
      text = 'Email john@example.com or call 555-123-4567'
      result = described_class.detect(text, enabled: enabled, validation: validation)
      types = result.map { |d| d[:type] }
      expect(types).to include(:email, :phone)
    end

    it 'returns empty array for nil input' do
      result = described_class.detect(nil, enabled: enabled, validation: validation)
      expect(result).to eq([])
    end
  end
end
