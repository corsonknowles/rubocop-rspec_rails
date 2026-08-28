# frozen_string_literal: true

module RuboCop
  module Cop
    module RSpecRails
      # Checks for a hardcoded `id:` passed to a persisting builder.
      #
      # Forcing a primary key in a spec collides with whatever else occupies
      # that row -- fixtures, parallel workers, the table's auto-increment
      # sequence -- and is a common source of flaky, order-dependent
      # failures. Let the database assign the id and reference the returned
      # record.
      #
      # Only `create`, `create!` and `create_list` are flagged: they insert a
      # row, so a forced primary key is an outright collision risk.
      # `create_list` is the worst case, forcing the identical id onto every
      # record it generates. `build` and `build_stubbed` never insert, so
      # they are left alone.
      #
      # Both `id:` and `'id' =>` are flagged: FactoryBot symbolizes override
      # keys and ActiveRecord treats string and symbol attribute keys
      # identically on mass-assignment, so a string-rocket key forces the
      # same primary key.
      #
      # Only literal values are flagged. A value read from another record or
      # a variable (`id: company.id`, `id: company_id`) is a reference, not a
      # magic constant.
      #
      # @example
      #   # bad
      #   create(:company, id: 123)
      #   create(:company, 'id' => 123)
      #   create_list(:company, 3, id: 123)
      #   Company.create!(id: '123456789')
      #
      #   # good - let the database assign the id
      #   company = create(:company)
      #
      #   # good - a transitive record id is a reference, not a constant
      #   create(:employee, id: company.id)
      #
      # @example AllowedFactories: ['money'] (default: [])
      #   # good - a factory that builds a value object rather than a row,
      #   # so `id:` is the object's own identity
      #   create(:money, id: 123)
      #
      # @example AllowedReceivers: ['Reporting::Row'] (default: [])
      #   # good - a constant whose `create` is not ActiveRecord's
      #   Reporting::Row.create(id: 123)
      #
      class HardcodedId < RuboCop::Cop::Base
        MSG = 'Do not pass a hardcoded `id:` to a persisting builder; ' \
              'let the database assign it.'
        RESTRICT_ON_SEND = %i[create create! create_list].freeze

        def on_send(node)
          return if allowed_receiver?(node) || allowed_factory?(node)

          node.arguments.each do |argument|
            # Every call shape (bare trailing kwargs, braced hash, positional
            # hash) parses to a plain `hash` node.
            next unless argument.hash_type?

            argument.pairs.each do |pair|
              add_offense(pair) if hardcoded_id?(pair)
            end
          end
        end
        alias on_csend on_send

        private

        def hardcoded_id?(pair)
          key = pair.key
          return false unless key.type?(:sym, :str)
          return false unless key.value.to_s == 'id'

          pair.value.type?(:int, :str)
        end

        # `::Foo::Bar` and `Foo::Bar` name the same constant, so compare
        # without the leading scope operator.
        def allowed_receiver?(node)
          receiver = node.receiver
          return false unless receiver

          allowed_receivers.include?(receiver.source.delete_prefix('::'))
        end

        def allowed_factory?(node)
          factory = node.first_argument
          return false unless factory&.sym_type?

          allowed_factories.include?(factory.value.to_s)
        end

        def allowed_receivers
          @allowed_receivers ||=
            Array(cop_config['AllowedReceivers'])
              .to_set { |name| name.to_s.delete_prefix('::') }
        end

        def allowed_factories
          @allowed_factories ||=
            Array(cop_config['AllowedFactories']).to_set(&:to_s)
        end
      end
    end
  end
end
