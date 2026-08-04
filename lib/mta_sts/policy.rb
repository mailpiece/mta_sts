require "simpleidn"

module MtaSts
  class Policy
    class Invalid < StandardError; end

    POLICY_VERSION = "STSv1"
    MODES = %i[ none testing enforce ].freeze
    MAX_AGE = (0..31_557_600) # RFC 8461 §3.2
    WILDCARD = "*."
    TERMINATOR = /\r?\n/ # RFC 8461 §3.2 ABNF: sts-policy-term = LF / CRLF
    DIGITS = /\A\d+\z/

    class << self
      def parse(text, id: nil, domain: nil, fetched_at: Time.now)
        fields = fields_in(text)

        validate_version single(fields, "version")

        new mode: single(fields, "mode"), mx: fields.fetch("mx", []), max_age: single(fields, "max_age"),
          id: id, domain: domain, fetched_at: fetched_at
      end

      def normalize(name)
        name = scrubbed(name).strip.chomp(".")

        if name.start_with?(WILDCARD)
          WILDCARD + ascii(name.delete_prefix(WILDCARD)).downcase
        else
          ascii(name).downcase
        end
      end

      private
        # RFC 8461 §3.2 — ignore unrecognized lines
        def fields_in(text)
          validated_document(text).split(TERMINATOR).each_with_object({}) do |line, fields|
            name, value = line.split(":", 2)

            (fields[name.strip.downcase] ||= []) << value.strip if value
          end
        end

        def validated_document(text)
          text = text.to_s

          if text.valid_encoding?
            text
          else
            raise Invalid, "policy is not valid #{text.encoding}"
          end
        end

        # RFC 8461 §3.2 - a duplicated non-mx field: keep the first, ignore the rest.
        def single(fields, name)
          fields.fetch(name, []).first
        end

        def validate_version(version)
          unless version&.casecmp?(POLICY_VERSION)
            raise Invalid, "version must be #{POLICY_VERSION}, not #{version.inspect}"
          end
        end

        def scrubbed(name)
          name = name.to_s
          name.valid_encoding? ? name : name.scrub
        end

        def ascii(name)
          name.ascii_only? ? name : SimpleIDN.to_ascii(name)
        rescue StandardError
          name
        end
    end

    attr_reader :mode, :mx, :max_age, :id, :domain, :fetched_at

    def initialize(mode:, max_age:, mx: [], id: nil, domain: nil, fetched_at: Time.now)
      @mode = validated_mode(mode)
      @mx = validated_mx(mx)
      @max_age = validated_max_age(max_age)
      @domain = domain && self.class.normalize(domain)
      @id, @fetched_at = id, fetched_at
    end

    def none?
      mode == :none
    end

    def testing?
      mode == :testing
    end

    def enforce?
      mode == :enforce
    end

    def allows?(host)
      if none?
        true
      else
        host = self.class.normalize(host)

        mx.any? { |pattern| matches?(pattern, host) }
      end
    end

    def expires_at
      fetched_at + max_age
    end

    def expired?(now = Time.now)
      now >= expires_at
    end

    def to_s
      lines = [ "version: #{POLICY_VERSION}", "mode: #{mode}" ]
      lines.concat mx.map { |pattern| "mx: #{pattern}" }
      lines << "max_age: #{max_age}"

      lines.map { |line| "#{line}\r\n" }.join
    end

    def inspect
      "#<#{self.class.name} mode: #{mode.inspect}, mx: #{mx.inspect}, max_age: #{max_age.inspect}>"
    end

    private
      def validated_mode(mode)
        if known = MODES.find { |candidate| candidate.to_s == mode.to_s.strip.downcase }
          known
        else
          raise Invalid, "mode must be one of #{MODES.join(", ")}, not #{mode.inspect}"
        end
      end

      # RFC 8461 §3.2 — at least one mx unless mode is none
      def validated_mx(mx)
        patterns = Array(mx).map { |pattern| validated_pattern(pattern) }.uniq

        if patterns.empty? && !none?
          raise Invalid, "mx must name at least one host unless mode is none"
        else
          patterns
        end
      end

      def validated_pattern(pattern)
        normalized = self.class.normalize(pattern)

        if normalized.delete("*.").empty?
          raise Invalid, "mx must name a host, not #{pattern.inspect}"
        else
          normalized
        end
      end

      def validated_max_age(max_age)
        # grammar is 1*DIGIT — not Integer(), which accepts 0x10 / 1_0
        if max_age.to_s.match?(DIGITS) && MAX_AGE.cover?(seconds = max_age.to_i)
          seconds
        else
          raise Invalid, "max_age must be a whole number of seconds in #{MAX_AGE}, not #{max_age.inspect}"
        end
      end

      # RFC 8461 §4.1 — "*." covers exactly one label
      def matches?(pattern, host)
        if pattern.start_with?(WILDCARD)
          label, _, parent = host.partition(".")

          !label.empty? && parent == pattern.delete_prefix(WILDCARD)
        else
          pattern == host
        end
      end
  end
end
