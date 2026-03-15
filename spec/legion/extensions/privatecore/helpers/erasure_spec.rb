# frozen_string_literal: true

require 'legion/extensions/privatecore/helpers/erasure'

RSpec.describe Legion::Extensions::Privatecore::Helpers::Erasure do
  subject(:erasure) { described_class.new }

  let(:traces) do
    [
      { trace_type: :semantic,   content: 'fact one',    partition_id: 'partition-a' },
      { trace_type: :semantic,   content: 'fact two',    partition_id: 'partition-b' },
      { trace_type: :episodic,   content: 'event one',   partition_id: 'partition-a' },
      { trace_type: :procedural, content: 'how-to one',  partition_id: 'partition-c' },
      { trace_type: :firmware,   content: 'rule one',    partition_id: 'partition-a' }
    ]
  end

  describe '#initialize' do
    it 'starts with an empty audit_log' do
      expect(erasure.audit_log).to eq([])
    end
  end

  describe '#erase_by_type' do
    it 'removes all traces of the specified type' do
      erasure.erase_by_type(traces, :semantic)
      types = traces.map { |t| t[:trace_type] }
      expect(types).not_to include(:semantic)
    end

    it 'returns the count of erased traces' do
      count = erasure.erase_by_type(traces, :semantic)
      expect(count).to eq(2)
    end

    it 'mutates the original array in place' do
      erasure.erase_by_type(traces, :semantic)
      expect(traces.size).to eq(3)
    end

    it 'does not remove traces of other types' do
      erasure.erase_by_type(traces, :semantic)
      remaining_types = traces.map { |t| t[:trace_type] }
      expect(remaining_types).to include(:episodic, :procedural, :firmware)
    end

    it 'returns 0 when no traces match the type' do
      count = erasure.erase_by_type(traces, :nonexistent_type)
      expect(count).to eq(0)
    end

    it 'leaves the traces array unchanged when no match' do
      original_size = traces.size
      erasure.erase_by_type(traces, :nonexistent_type)
      expect(traces.size).to eq(original_size)
    end

    it 'works on an empty traces array' do
      count = erasure.erase_by_type([], :semantic)
      expect(count).to eq(0)
    end

    it 'appends an audit entry' do
      erasure.erase_by_type(traces, :semantic)
      expect(erasure.audit_log.size).to eq(1)
    end

    it 'records the correct action in the audit entry' do
      erasure.erase_by_type(traces, :semantic)
      expect(erasure.audit_log.last[:action]).to eq(:erase_by_type)
    end

    it 'records the type in the audit entry' do
      erasure.erase_by_type(traces, :semantic)
      expect(erasure.audit_log.last[:type]).to eq(:semantic)
    end

    it 'records the erased count in the audit entry' do
      erasure.erase_by_type(traces, :semantic)
      expect(erasure.audit_log.last[:count]).to eq(2)
    end

    it 'records a Time in the audit entry' do
      erasure.erase_by_type(traces, :semantic)
      expect(erasure.audit_log.last[:at]).to be_a(Time)
    end
  end

  describe '#erase_by_partition' do
    it 'removes all traces belonging to the specified partition' do
      erasure.erase_by_partition(traces, 'partition-a')
      partition_ids = traces.map { |t| t[:partition_id] }
      expect(partition_ids).not_to include('partition-a')
    end

    it 'returns the count of erased traces' do
      count = erasure.erase_by_partition(traces, 'partition-a')
      expect(count).to eq(3)
    end

    it 'mutates the original array in place' do
      erasure.erase_by_partition(traces, 'partition-a')
      expect(traces.size).to eq(2)
    end

    it 'does not remove traces from other partitions' do
      erasure.erase_by_partition(traces, 'partition-a')
      remaining_partitions = traces.map { |t| t[:partition_id] }
      expect(remaining_partitions).to include('partition-b', 'partition-c')
    end

    it 'returns 0 for a partition with no matching traces' do
      count = erasure.erase_by_partition(traces, 'partition-z')
      expect(count).to eq(0)
    end

    it 'appends an audit entry' do
      erasure.erase_by_partition(traces, 'partition-a')
      expect(erasure.audit_log.size).to eq(1)
    end

    it 'records the correct action in the audit entry' do
      erasure.erase_by_partition(traces, 'partition-a')
      expect(erasure.audit_log.last[:action]).to eq(:erase_by_partition)
    end

    it 'records the partition_id in the audit entry' do
      erasure.erase_by_partition(traces, 'partition-a')
      expect(erasure.audit_log.last[:partition_id]).to eq('partition-a')
    end

    it 'records the count in the audit entry' do
      erasure.erase_by_partition(traces, 'partition-a')
      expect(erasure.audit_log.last[:count]).to eq(3)
    end

    it 'records a Time in the audit entry' do
      erasure.erase_by_partition(traces, 'partition-a')
      expect(erasure.audit_log.last[:at]).to be_a(Time)
    end
  end

  describe '#full_erasure' do
    it 'clears all traces from the array' do
      erasure.full_erasure(traces)
      expect(traces).to be_empty
    end

    it 'returns the count of erased traces' do
      count = erasure.full_erasure(traces)
      expect(count).to eq(5)
    end

    it 'mutates the original array in place' do
      erasure.full_erasure(traces)
      expect(traces.size).to eq(0)
    end

    it 'returns 0 for an already-empty array' do
      count = erasure.full_erasure([])
      expect(count).to eq(0)
    end

    it 'appends an audit entry' do
      erasure.full_erasure(traces)
      expect(erasure.audit_log.size).to eq(1)
    end

    it 'records the correct action in the audit entry' do
      erasure.full_erasure(traces)
      expect(erasure.audit_log.last[:action]).to eq(:full_erasure)
    end

    it 'records the erased count in the audit entry' do
      erasure.full_erasure(traces)
      expect(erasure.audit_log.last[:count]).to eq(5)
    end

    it 'records a Time in the audit entry' do
      erasure.full_erasure(traces)
      expect(erasure.audit_log.last[:at]).to be_a(Time)
    end
  end

  describe 'audit_log accumulation' do
    it 'accumulates multiple entries across different erasure calls' do
      erasure.erase_by_type(traces, :firmware)
      erasure.erase_by_partition(traces, 'partition-b')
      erasure.full_erasure(traces)
      expect(erasure.audit_log.size).to eq(3)
    end

    it 'preserves the order of audit entries' do
      erasure.erase_by_type(traces, :firmware)
      erasure.full_erasure(traces)
      expect(erasure.audit_log.map { |e| e[:action] }).to eq(%i[erase_by_type full_erasure])
    end

    it 'maintains separate audit logs per instance' do
      other = described_class.new
      erasure.full_erasure(traces)
      expect(other.audit_log).to be_empty
    end
  end
end
