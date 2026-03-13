# frozen_string_literal: true

require 'legion/extensions/privatecore/client'

RSpec.describe Legion::Extensions::Privatecore::Client do
  it 'responds to privatecore runner methods' do
    client = described_class.new
    expect(client).to respond_to(:enforce_boundary)
    expect(client).to respond_to(:check_pii)
    expect(client).to respond_to(:detect_probe)
    expect(client).to respond_to(:erasure_audit)
  end
end
