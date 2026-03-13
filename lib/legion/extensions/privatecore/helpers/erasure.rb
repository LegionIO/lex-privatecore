# frozen_string_literal: true

module Legion
  module Extensions
    module Privatecore
      module Helpers
        class Erasure
          attr_reader :audit_log

          def initialize
            @audit_log = []
          end

          def erase_by_type(traces, type)
            erased = traces.count { |t| t[:trace_type] == type }
            traces.reject! { |t| t[:trace_type] == type }
            record_audit(:erase_by_type, type: type, count: erased)
            erased
          end

          def erase_by_partition(traces, partition_id)
            erased = traces.count { |t| t[:partition_id] == partition_id }
            traces.reject! { |t| t[:partition_id] == partition_id }
            record_audit(:erase_by_partition, partition_id: partition_id, count: erased)
            erased
          end

          def full_erasure(traces)
            count = traces.size
            traces.clear
            record_audit(:full_erasure, count: count)
            count
          end

          private

          def record_audit(action, **details)
            @audit_log << { action: action, at: Time.now.utc, **details }
          end
        end
      end
    end
  end
end
