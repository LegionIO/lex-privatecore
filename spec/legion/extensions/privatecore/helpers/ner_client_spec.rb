# frozen_string_literal: true

require 'legion/extensions/privatecore/helpers/ner_client'
require 'faraday'

RSpec.describe Legion::Extensions::Privatecore::Helpers::NerClient do
  let(:service_url) { 'http://presidio:5002/analyze' }

  describe '.analyze' do
    it 'parses a successful Presidio response into detections' do
      stubs = Faraday::Adapter::Test::Stubs.new do |stub|
        stub.post('/analyze') do
          [200, { 'Content-Type' => 'application/json' },
           '[{"entity_type":"PERSON","start":0,"end":4,"score":0.95},
             {"entity_type":"US_SSN","start":16,"end":27,"score":0.99}]']
        end
      end
      conn = Faraday.new(url: service_url) { |f| f.adapter :test, stubs }

      result = described_class.analyze(text: 'John has SSN 123-45-6789', connection: conn)
      expect(result.size).to eq(2)

      person = result.find { |d| d[:type] == :person_name }
      expect(person).not_to be_nil
      expect(person[:start]).to eq(0)
      expect(person[:end]).to eq(4)
      expect(person[:score]).to eq(0.95)

      ssn = result.find { |d| d[:type] == :ssn }
      expect(ssn).not_to be_nil
    end

    it 'returns empty array and source on silent fallback' do
      stubs = Faraday::Adapter::Test::Stubs.new do |stub|
        stub.post('/analyze') { raise Faraday::TimeoutError }
      end
      conn = Faraday.new(url: service_url) { |f| f.adapter :test, stubs }

      result = described_class.analyze(text: 'test', connection: conn, fallback: :silent)
      expect(result).to eq([])
    end

    it 'returns empty array on transparent fallback' do
      stubs = Faraday::Adapter::Test::Stubs.new do |stub|
        stub.post('/analyze') { raise Faraday::ConnectionFailed, 'refused' }
      end
      conn = Faraday.new(url: service_url) { |f| f.adapter :test, stubs }

      result = described_class.analyze(text: 'test', connection: conn, fallback: :transparent)
      expect(result).to be_a(Array)
      expect(result).to eq([])
    end

    it 'raises NerServiceUnavailable on strict fallback' do
      stubs = Faraday::Adapter::Test::Stubs.new do |stub|
        stub.post('/analyze') { raise Faraday::TimeoutError }
      end
      conn = Faraday.new(url: service_url) { |f| f.adapter :test, stubs }

      expect do
        described_class.analyze(text: 'test', connection: conn, fallback: :strict)
      end.to raise_error(Legion::Extensions::Privatecore::Helpers::NerClient::NerServiceUnavailable)
    end

    it 'ignores unknown entity types' do
      stubs = Faraday::Adapter::Test::Stubs.new do |stub|
        stub.post('/analyze') do
          [200, { 'Content-Type' => 'application/json' },
           '[{"entity_type":"UNKNOWN_TYPE","start":0,"end":5,"score":0.9}]']
        end
      end
      conn = Faraday.new(url: service_url) { |f| f.adapter :test, stubs }

      result = described_class.analyze(text: 'test data', connection: conn)
      expect(result).to eq([])
    end

    it 'handles malformed JSON response' do
      stubs = Faraday::Adapter::Test::Stubs.new do |stub|
        stub.post('/analyze') { [200, { 'Content-Type' => 'application/json' }, 'not json'] }
      end
      conn = Faraday.new(url: service_url) { |f| f.adapter :test, stubs }

      result = described_class.analyze(text: 'test', connection: conn, fallback: :silent)
      expect(result).to eq([])
    end
  end

  describe '.available?' do
    it 'returns true when service responds with 200' do
      stubs = Faraday::Adapter::Test::Stubs.new do |stub|
        stub.get('/health') { [200, {}, 'ok'] }
      end
      conn = Faraday.new(url: service_url) { |f| f.adapter :test, stubs }

      expect(described_class.available?(connection: conn)).to be true
    end

    it 'returns false when service is down' do
      stubs = Faraday::Adapter::Test::Stubs.new do |stub|
        stub.get('/health') { raise Faraday::ConnectionFailed, 'refused' }
      end
      conn = Faraday.new(url: service_url) { |f| f.adapter :test, stubs }

      expect(described_class.available?(connection: conn)).to be false
    end
  end
end
