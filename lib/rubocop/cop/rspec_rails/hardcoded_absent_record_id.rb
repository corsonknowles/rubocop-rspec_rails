# frozen_string_literal: true

module RuboCop
  module Cop
    module RSpecRails
      # Checks for a hardcoded id standing in for an absent record.
      #
      # Auto-increment climbs across every example in a run and is not
      # reclaimed by transactional rollback, so the counter eventually
      # reaches the literal. From then on a real row occupies it, the lookup
      # succeeds, and the example stops testing absence -- passing locally,
      # where the counter is low, and failing in CI. A negative id cannot
      # collide, because auto-increment never emits one.
      #
      # An id counts as standing in for an absent record when its own example
      # group either asserts absence (`ActiveRecord::RecordNotFound`, a
      # `:not_found` response) or says so in its description. Both are read
      # from the group the `let` is written in, not the whole file, so a
      # shared id in an outer group is not attributed to a nested example
      # that never uses it.
      #
      # In a list, a literal sitting beside a real `record.id` also qualifies
      # on its own: you would write another `record.id` if you wanted one
      # that exists.
      #
      # Not offenses: a group that builds a record carrying that id, a
      # `RecordNotFound` raised by reloading a row the example just deleted,
      # a literal above `MaxId`, and a group pinning two ids, which are
      # usually pinned to differ from each other.
      #
      # @safety
      #   Autocorrection is unsafe. `-1` is right for a primary key, but it
      #   also changes the value the example feeds to everything else, so an
      #   id matched against a stubbed request URI, a recorded cassette or an
      #   asserted error message needs those updated to match. Some codebases
      #   also reserve `-1` as a sentinel of their own, and an unsigned
      #   column rejects it outright.
      #
      # @example
      #   # bad
      #   context 'when the user does not exist' do
      #     let(:user_id) { 123 }
      #
      #     it { expect { subject }.to raise_error(RecordNotFound) }
      #   end
      #
      #   # bad - the literal is there precisely because no record has it
      #   let(:user_ids) { [user.id, other_user.id, 999_999] }
      #
      #   # good - auto-increment never emits a negative id
      #   context 'when the user does not exist' do
      #     let(:user_id) { -1 }
      #
      #     it { expect { subject }.to raise_error(RecordNotFound) }
      #   end
      #
      #   # good - a deleted record's id is a reference, not a constant
      #   context 'when the user does not exist' do
      #     let(:user_id) { deleted_user.id }
      #   end
      #
      # @example AllowedNames: ['wise_id'] (default: [])
      #   # good - a third-party identifier, not a primary key
      #   context 'when the transfer does not exist' do
      #     let(:wise_id) { 5678 }
      #   end
      #
      # @example MaxId: 1000000 (default)
      #   # good - above MaxId the literal is a deliberate sentinel
      #   let(:user_id) { 9_999_999_999 }
      #
      class HardcodedAbsentRecordId < RuboCop::Cop::RSpec::Base
        extend AutoCorrector

        MSG = 'Use a negative id for a record expected to be absent.'
        RESTRICT_ON_SEND = %i[let let!].freeze

        # `id` itself, or any `<something>_id`, singular or plural.
        ID_NAME = /\A(ids?|.+_ids?)\z/.freeze

        # Each phrase is unambiguous on its own: a bare "missing" or
        # "unknown" reads just as naturally about a header or a flag.
        ABSENT_DESCRIPTION = /
          (does|do|did)\s*n[o']?t\s+exist | \bnot\s+exist |
          \bnot\s+found\b | (cannot|can\s*not|can't|couldn't)\s+be\s+found |
          is\s*n[o']?t\s+found | non-?\s?existent | no\s+such |
          invalid\s+\w*\s*\bid\b | \bid\b\s+is\s+invalid |
          does\s*n[o']?t\s+belong | not\s+belong\s+to |
          unauthorized\s+access |
          (another|other|different)\s+
            (account|company|customer|member|org|person|user)
        /xi.freeze

        NOT_FOUND = /RecordNotFound/.freeze
        NOT_FOUND_STATUS = /\A:?(not_found|404)\z/.freeze
        BUILDERS = %i[build build! build_list build_stubbed
                      build_stubbed_list create create! create_list].freeze
        DEFAULT_MAX_ID = 1_000_000

        # @!method let_definition(node)
        def_node_matcher :let_definition, <<~PATTERN
          (any_block (send nil? {:let :let!} (sym $_) ...) _ $_)
        PATTERN

        def on_send(node)
          name, body = node.parent && let_definition(node.parent)
          return unless body && id_name?(name)
          return if cassette_controlled?(node)

          if body.array_type?
            check_list(node, name, body)
          else
            check_literal(node, name, body)
          end
        end

        private

        # A third-party identifier stored in a `*_id` field is not a primary
        # key the counter can reach, so a name in `AllowedNames` is skipped --
        # a named exception in config beats a path exclude or a disable.
        def id_name?(name)
          name.to_s.match?(ID_NAME) &&
            !Array(cop_config['AllowedNames']).include?(name.to_s)
        end

        def check_literal(node, name, literal)
          value = collidable_id(literal)
          group = value && enclosing_example_group(node)
          return unless group && absent_context?(group)
          return if built_with?(group, name, value) || paired_ids?(group)

          register(literal)
        end

        # Only a lone literal qualifies. Two would both correct to `-1`, and
        # a duplicated id collapses on lookup, changing the asserted count.
        def check_list(node, name, array)
          literals = array.children.select { |item| collidable_id(item) }
          return unless literals.one?

          group = enclosing_example_group(node)
          return unless list_qualifies?(array, group)

          literal = literals.first
          return if group && built_with?(group, name, collidable_id(literal))

          register(literal)
        end

        def list_qualifies?(array, group)
          real_id = array.children.any? { |i| i.send_type? && i.method?(:id) }
          real_id || (!group.nil? && absent_context?(group))
        end

        def register(literal)
          add_offense(literal) do |corrector|
            corrector.replace(literal, literal.str_type? ? "'-1'" : '-1')
          end
        end

        def collidable_id(node)
          CollidableId.in(node, max_id)
        end

        def max_id
          cop_config.fetch('MaxId', DEFAULT_MAX_ID)
        end

        def enclosing_example_group(node)
          node.each_ancestor(:any_block).find { |a| example_group?(a) }
        end

        def absent_context?(group)
          inspect_group(group).absent?
        end

        def built_with?(group, name, value)
          inspect_group(group).builds?(name, value)
        end

        def paired_ids?(group)
          inspect_group(group).paired_ids?
        end

        def inspect_group(group)
          GroupInspector.new(group, max_id)
        end

        # A cassette keys its recorded interactions off the request URI, so
        # an id in the path is what tells two same-route requests apart.
        # Rewriting it makes the example miss the recording.
        def cassette_controlled?(node)
          node.each_ancestor(:any_block).any? do |ancestor|
            example_group?(ancestor) &&
              ancestor.send_node.arguments.any? { |argument| vcr?(argument) }
          end
        end

        def vcr?(argument)
          return true if argument.sym_type? && argument.value == :vcr
          return false unless argument.hash_type?

          argument.pairs.any? do |pair|
            pair.key.type?(:sym, :str) && pair.key.value.to_s == 'vcr'
          end
        end

        # A string id reaches the same column as an integer one, so both
        # count; only the sign and the magnitude matter.
        module CollidableId
          def self.in(node, max_id)
            value = case node.type
                    when :int then node.value
                    when :str then Integer(node.value, exception: false)
                    end
            value if value&.positive? && value <= max_id
          end
        end

        # Answers the group-level questions: does this group say the record
        # is absent, does it build the record, and does it pin two ids?
        class GroupInspector
          include RuboCop::RSpec::Language
          extend RuboCop::AST::NodePattern::Macros

          # @!method let_definition(node)
          def_node_matcher :let_definition, <<~PATTERN
            (any_block (send nil? {:let :let!} (sym $_) ...) _ $_)
          PATTERN

          def initialize(group, max_id)
            @group = group
            @max_id = max_id
          end

          def absent?
            absent_description? || not_found_assertion?(group.body)
          end

          # A group that builds a record carrying this id means the row is
          # meant to exist, so its absence is about something else.
          def builds?(name, value)
            group.each_descendant(:send).any? do |send_node|
              BUILDERS.include?(send_node.method_name) &&
                send_node.each_descendant.any? do |argument|
                  references?(argument, name) || same_id_value?(argument, value)
                end
            end
          end

          # Two ids pinned in one group are usually pinned to differ from
          # each other -- a record and the "other user" it must not match.
          # One shared replacement collapses that and inverts the example.
          def paired_ids?
            own_lets(group.body).count { |_n, body| collidable_id(body) } > 1
          end

          private

          attr_reader :group, :max_id

          def collidable_id(node)
            CollidableId.in(node, max_id)
          end

          def references?(node, name)
            node.send_type? && node.receiver.nil? && node.method?(name)
          end

          # `create(:user, account_id: 1)` beside `let(:account_id) { 1 }`
          # builds the row this id selects, even when the literal is inlined.
          def same_id_value?(node, value)
            node.pair_type? && node.key.type?(:sym, :str) &&
              node.key.value.to_s.match?(ID_NAME) &&
              collidable_id(node.value) == value
          end

          def own_lets(node, found = [])
            return found if node.type?(:any_block) && example_group?(node)

            definition = let_definition(node)
            body = definition&.last
            found << definition if body && !body.array_type?
            node.each_child_node { |child| own_lets(child, found) }
            found
          end

          # Matched against the source so an interpolated description
          # ("when #{model} does not exist") still reads as one.
          def absent_description?
            description = group.send_node.first_argument
            return false unless description&.type?(:str, :dstr, :sym)

            ABSENT_DESCRIPTION.match?(description.source)
          end

          # Scoped to this group: the walk stops at a nested example group,
          # whose assertions belong to whatever that group redefines.
          def not_found_assertion?(node)
            return false if node.type?(:any_block) && example_group?(node)
            return true if node.send_type? && not_found_matcher?(node)

            node.each_child_node.any? { |child| not_found_assertion?(child) }
          end

          def not_found_matcher?(node)
            case node.method_name
            when :raise_error, :raise_exception
              node.arguments.any? { |arg| NOT_FOUND.match?(arg.source) } &&
                !deleted_record_assertion?(node)
            when :have_http_status
              NOT_FOUND_STATUS.match?(node.first_argument&.source.to_s)
            when :be_not_found then true
            else false
            end
          end

          # `expect { record.reload }.to raise_error(RecordNotFound)` asserts
          # that a row the example already holds was deleted by the code under
          # test. That is about the object, not about the literal -- which is
          # usually what selected the row for deletion in the first place.
          def deleted_record_assertion?(node)
            subject = node.each_ancestor(:send).first&.receiver
            return false unless subject&.type?(:any_block)

            subject.body&.send_type? && subject.body.method?(:reload)
          end
        end
      end
    end
  end
end
