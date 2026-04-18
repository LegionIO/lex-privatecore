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
end
