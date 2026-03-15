# frozen_string_literal: true

require 'legion/extensions/actors/every'

module Legion
  module Extensions
    module Privatecore
      module Actor
        class AuditPrune < Legion::Extensions::Actors::Every
          def runner_class
            Legion::Extensions::Privatecore::Runners::Privatecore
          end

          def runner_function
            'prune_audit_log'
          end

          def time
            3600
          end

          def run_now?
            false
          end

          def use_runner?
            false
          end

          def check_subtask?
            false
          end

          def generate_task?
            false
          end
        end
      end
    end
  end
end
