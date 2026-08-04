require "mta_sts/policy"
require "mta_sts/report/result"

module MtaSts
  class Report
    class Invalid < StandardError; end

    REPORT_VERSION = "TLSRPTv1"
    # RFC 8460 §3 has the same ABNF/prose contradiction as RFC 8461 §3.1 (see
    # STS_RECORD) — the literal "v=TLSRPTv1;" prefix is what's enforced.
    REPORT_RECORD = /\Av=#{REPORT_VERSION};/
    FIELD_DELIM = ";"
    RUA_FIELD = "rua=" # RFC 8460 §3
    URI_DELIM = ","
    MAILTO = /\Amailto:/i # RFC 3986 §3.1 — scheme is case-insensitive
    HTTPS = /\Ahttps:/i
    SCHEMES = [ MAILTO, HTTPS ].freeze

    class << self
      def parse(text, domain: nil)
        new rua: uris_in(fields_in(text)), domain: domain
      end

      private
        def fields_in(text)
          fields = validated_record(text).split(FIELD_DELIM).drop(1).map(&:strip)

          if fields.empty?
            raise Invalid, "record must carry at least one field after v=#{REPORT_VERSION}"
          else
            fields
          end
        end

        def validated_record(text)
          text = validated_encoding(text)

          if text.match?(REPORT_RECORD)
            text
          else
            raise Invalid, "record must begin with v=#{REPORT_VERSION};, not #{text.inspect}"
          end
        end

        def validated_encoding(text)
          text = text.to_s

          if text.valid_encoding?
            text
          else
            raise Invalid, "record is not valid #{text.encoding}"
          end
        end

        # RFC 8460 §3 — unknown fields ignored; multiple rua fields allowed
        def uris_in(fields)
          rua_fields = fields.select { |field| field.start_with?(RUA_FIELD) }

          rua_fields.flat_map { |field| destinations_in(field.delete_prefix(RUA_FIELD)) }
        end

        def destinations_in(value)
          value.split(URI_DELIM, -1).map(&:strip)
        end
    end

    attr_reader :rua, :ignored, :domain

    def initialize(rua:, domain: nil)
      @rua, @ignored = validated_destinations(rua)
      @domain = domain && Policy.normalize(domain)
    end

    def mailto
      rua.grep(MAILTO)
    end

    def https
      rua.grep(HTTPS)
    end

    def to_s
      "v=#{REPORT_VERSION}; #{RUA_FIELD}#{rua.join(", ")}"
    end

    def inspect
      "#<#{self.class.name} rua: #{rua.inspect}, ignored: #{ignored.inspect}>"
    end

    private
      def validated_destinations(uris)
        usable, unusable = Array(uris).partition { |uri| supported?(uri) }

        if usable.empty?
          raise Invalid, "rua must name at least one mailto: or https: destination"
        else
          [ usable, unusable ]
        end
      end

      def supported?(uri)
        SCHEMES.any? { |scheme| uri.to_s.match?(scheme) }
      end
  end
end
