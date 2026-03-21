# frozen_string_literal: true

require 'legion/extensions/privatecore/helpers/similarity'

RSpec.describe Legion::Extensions::Privatecore::Helpers::Similarity do
  describe '.cosine_similarity' do
    it 'returns 1.0 for identical vectors' do
      vec = [1.0, 2.0, 3.0]
      expect(described_class.cosine_similarity(vec_a: vec, vec_b: vec)).to be_within(1e-9).of(1.0)
    end

    it 'returns 0.0 for orthogonal vectors' do
      vec_a = [1.0, 0.0]
      vec_b = [0.0, 1.0]
      expect(described_class.cosine_similarity(vec_a: vec_a, vec_b: vec_b)).to be_within(1e-9).of(0.0)
    end

    it 'returns -1.0 for opposite vectors' do
      vec_a = [1.0, 0.0]
      vec_b = [-1.0, 0.0]
      expect(described_class.cosine_similarity(vec_a: vec_a, vec_b: vec_b)).to be_within(1e-9).of(-1.0)
    end

    it 'returns a value close to 1.0 for very similar vectors' do
      vec_a = [1.0, 2.0, 3.0]
      vec_b = [1.1, 2.1, 3.1]
      similarity = described_class.cosine_similarity(vec_a: vec_a, vec_b: vec_b)
      expect(similarity).to be > 0.99
    end

    it 'returns 0.0 for empty vectors' do
      expect(described_class.cosine_similarity(vec_a: [], vec_b: [])).to eq(0.0)
    end

    it 'returns 0.0 when vec_a is nil' do
      expect(described_class.cosine_similarity(vec_a: nil, vec_b: [1.0, 0.0])).to eq(0.0)
    end

    it 'returns 0.0 when vec_b is nil' do
      expect(described_class.cosine_similarity(vec_a: [1.0, 0.0], vec_b: nil)).to eq(0.0)
    end

    it 'returns 0.0 for an all-zero vector' do
      vec_a = [0.0, 0.0, 0.0]
      vec_b = [1.0, 2.0, 3.0]
      expect(described_class.cosine_similarity(vec_a: vec_a, vec_b: vec_b)).to eq(0.0)
    end

    it 'returns 0.0 when vectors have different lengths' do
      vec_a = [1.0, 2.0]
      vec_b = [1.0, 2.0, 3.0]
      expect(described_class.cosine_similarity(vec_a: vec_a, vec_b: vec_b)).to eq(0.0)
    end

    it 'handles single-element vectors' do
      expect(described_class.cosine_similarity(vec_a: [5.0], vec_b: [3.0])).to be_within(1e-9).of(1.0)
    end

    it 'handles negative component vectors correctly' do
      vec_a = [-1.0, -1.0]
      vec_b = [-1.0, -1.0]
      expect(described_class.cosine_similarity(vec_a: vec_a, vec_b: vec_b)).to be_within(1e-9).of(1.0)
    end
  end
end
