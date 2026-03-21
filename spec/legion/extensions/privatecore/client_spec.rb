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

  it 'responds to embedding guard runner methods' do
    client = described_class.new
    expect(client).to respond_to(:check_embedding_similarity)
    expect(client).to respond_to(:cache_pattern_embeddings)
  end
end
