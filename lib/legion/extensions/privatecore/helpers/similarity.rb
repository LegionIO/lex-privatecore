# frozen_string_literal: true

module Legion
  module Extensions
    module Privatecore
      module Helpers
        module Similarity
          module_function

          def cosine_similarity(vec_a:, vec_b:)
            return 0.0 if vec_a.nil? || vec_b.nil?
            return 0.0 if vec_a.empty? || vec_b.empty?
            return 0.0 if vec_a.length != vec_b.length

            dot   = vec_a.zip(vec_b).sum { |a, b| a * b }
            mag_a = Math.sqrt(vec_a.sum { |v| v * v })
            mag_b = Math.sqrt(vec_b.sum { |v| v * v })

            return 0.0 if mag_a.zero? || mag_b.zero?

            dot / (mag_a * mag_b)
          end
        end
      end
    end
  end
end
