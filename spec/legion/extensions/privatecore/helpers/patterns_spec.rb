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

    context 'with expanded patterns enabled' do
      let(:enabled) do
        %i[email phone ssn ip credit_card dob mrn passport iban drivers_license
           url btc_address eth_address itin aadhaar api_key bearer_token aws_key]
      end

      it 'detects a credit card number' do
        result = described_class.detect('Card: 4111-1111-1111-1111', enabled: enabled, validation: validation)
        match = result.find { |d| d[:type] == :credit_card }
        expect(match).not_to be_nil
        expect(match[:category]).to eq(:financial)
      end

      it 'detects a credit card without separators' do
        result = described_class.detect('Card: 4111111111111111', enabled: enabled, validation: validation)
        match = result.find { |d| d[:type] == :credit_card }
        expect(match).not_to be_nil
      end

      it 'detects date of birth' do
        result = described_class.detect('DOB: 1990-01-15', enabled: enabled, validation: validation)
        match = result.find { |d| d[:type] == :dob }
        expect(match).not_to be_nil
        expect(match[:category]).to eq(:personal)
      end

      it 'detects date of birth with label' do
        result = described_class.detect('date of birth: 03/15/1990', enabled: enabled, validation: validation)
        match = result.find { |d| d[:type] == :dob }
        expect(match).not_to be_nil
      end

      it 'detects medical record number' do
        result = described_class.detect('MRN: 1234567', enabled: enabled, validation: validation)
        match = result.find { |d| d[:type] == :mrn }
        expect(match).not_to be_nil
        expect(match[:category]).to eq(:medical)
      end

      it 'detects a passport number' do
        result = described_class.detect('Passport: A12345678', enabled: enabled, validation: validation)
        match = result.find { |d| d[:type] == :passport }
        expect(match).not_to be_nil
        expect(match[:category]).to eq(:government_id)
      end

      it 'detects an IBAN code' do
        result = described_class.detect('IBAN: DE89370400440532013000', enabled: enabled, validation: validation)
        match = result.find { |d| d[:type] == :iban }
        expect(match).not_to be_nil
        expect(match[:category]).to eq(:financial)
      end

      it 'detects a drivers license number' do
        result = described_class.detect('DL: D123-4567-8901', enabled: enabled, validation: validation)
        match = result.find { |d| d[:type] == :drivers_license }
        expect(match).not_to be_nil
        expect(match[:category]).to eq(:government_id)
      end

      it 'detects a URL' do
        result = described_class.detect('Visit https://example.com/path?q=1', enabled: enabled, validation: validation)
        match = result.find { |d| d[:type] == :url }
        expect(match).not_to be_nil
        expect(match[:category]).to eq(:network)
      end

      it 'detects a BTC address' do
        result = described_class.detect('Send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', enabled: enabled, validation: validation)
        match = result.find { |d| d[:type] == :btc_address }
        expect(match).not_to be_nil
        expect(match[:category]).to eq(:crypto)
      end

      it 'detects an ETH address' do
        result = described_class.detect('ETH: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18', enabled: enabled, validation: validation)
        match = result.find { |d| d[:type] == :eth_address }
        expect(match).not_to be_nil
        expect(match[:category]).to eq(:crypto)
      end

      it 'detects an ITIN' do
        result = described_class.detect('ITIN: 912-78-1234', enabled: enabled, validation: validation)
        match = result.find { |d| d[:type] == :itin }
        expect(match).not_to be_nil
        expect(match[:category]).to eq(:government_id)
      end

      it 'detects an Aadhaar number' do
        result = described_class.detect('Aadhaar: 2345 6789 0123', enabled: enabled, validation: validation)
        match = result.find { |d| d[:type] == :aadhaar }
        expect(match).not_to be_nil
        expect(match[:category]).to eq(:government_id)
      end

      it 'detects an API key pattern' do
        result = described_class.detect('key: sk_test_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6', enabled: enabled, validation: validation)
        match = result.find { |d| d[:type] == :api_key }
        expect(match).not_to be_nil
        expect(match[:category]).to eq(:credential)
      end

      it 'detects a bearer token' do
        result = described_class.detect('Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U', enabled: enabled, validation: validation)
        match = result.find { |d| d[:type] == :bearer_token }
        expect(match).not_to be_nil
        expect(match[:category]).to eq(:credential)
      end

      it 'detects an AWS access key' do
        result = described_class.detect('AWS key: AKIAIOSFODNN7EXAMPLE', enabled: enabled, validation: validation)
        match = result.find { |d| d[:type] == :aws_key }
        expect(match).not_to be_nil
        expect(match[:category]).to eq(:credential)
      end
    end
  end

  describe '.validate_checksum' do
    context 'Luhn (credit card)' do
      it 'validates a correct Visa number' do
        expect(described_class.validate_checksum(:credit_card, '4111111111111111')).to be true
      end

      it 'rejects an invalid number' do
        expect(described_class.validate_checksum(:credit_card, '4111111111111112')).to be false
      end
    end

    context 'IBAN' do
      it 'validates a correct German IBAN' do
        expect(described_class.validate_checksum(:iban, 'DE89370400440532013000')).to be true
      end

      it 'rejects an invalid IBAN' do
        expect(described_class.validate_checksum(:iban, 'DE00370400440532013000')).to be false
      end
    end

    context 'Verhoeff (Aadhaar)' do
      it 'validates a correct Aadhaar' do
        expect(described_class.validate_checksum(:aadhaar, '234567890124')).to be true
      end

      it 'rejects an invalid Aadhaar' do
        expect(described_class.validate_checksum(:aadhaar, '234567890123')).to be false
      end
    end

    it 'returns true for types without checksum support' do
      expect(described_class.validate_checksum(:email, 'anything')).to be true
    end
  end

  describe '.detect with checksum validation' do
    it 'filters out invalid credit card when checksum enabled' do
      validation = { credit_card: :checksum }
      result = described_class.detect('Card: 4111111111111112', enabled: [:credit_card], validation: validation)
      expect(result).to eq([])
    end

    it 'keeps valid credit card when checksum enabled' do
      validation = { credit_card: :checksum }
      result = described_class.detect('Card: 4111111111111111', enabled: [:credit_card], validation: validation)
      expect(result.size).to eq(1)
    end
  end
end
