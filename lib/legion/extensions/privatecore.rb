# frozen_string_literal: true

require 'legion/extensions/privatecore/version'
require 'legion/extensions/privatecore/helpers/boundary'
require 'legion/extensions/privatecore/helpers/erasure'
require 'legion/extensions/privatecore/runners/privatecore'

module Legion
  module Extensions
    module Privatecore
      extend Legion::Extensions::Core if Legion::Extensions.const_defined? :Core
    end
  end
end
