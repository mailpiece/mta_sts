module MtaSts
  # status = what this lookup learned; policy = what to honour (§5.1)
  class Result
    attr_reader :status, :policy, :comment

    def initialize(status:, policy: nil, comment: nil)
      @status, @policy, @comment = status, policy, comment
    end

    def found?
      status == "found"
    end

    # "no TXT this time" — not "no policy applies" (see Policy#none?)
    def no_record?
      status == "none"
    end

    def temperror?
      status == "temperror"
    end

    def permerror?
      status == "permerror"
    end

    def enforce?
      policy&.enforce? || false
    end

    def testing?
      policy&.testing? || false
    end

    def allows?(host)
      if policy
        policy.allows?(host)
      else
        true
      end
    end

    def inspect
      "#<#{self.class.name} status: #{status.inspect}, policy: #{policy.inspect}, comment: #{comment.inspect}>"
    end
  end
end
