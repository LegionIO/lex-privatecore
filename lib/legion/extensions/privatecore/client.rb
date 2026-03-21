# frozen_string_literal: true

require 'legion/extensions/privatecore/helpers/boundary'
require 'legion/extensions/privatecore/helpers/erasure'
require 'legion/extensions/privatecore/helpers/similarity'
require 'legion/extensions/privatecore/runners/privatecore'
require 'legion/extensions/privatecore/runners/embedding_guard'

module Legion
  module Extensions
    module Privatecore
      class Client
        include Runners::Privatecore
        include Runners::EmbeddingGuard

        def initialize(**)
          @erasure_engine = Helpers::Erasure.new
        end

        private

        attr_reader :erasure_engine
      end
    end
  end
end
