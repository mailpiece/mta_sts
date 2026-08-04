module MtaSts
  # `txt` answers discovery; `addresses` answers the fetcher, which resolves the
  # policy host itself so the address it dials is one the caller has judged.
  class FakeResolver
    attr_reader :queries

    def initialize(zone = {})
      @zone = zone.transform_keys { |name| name.to_s.downcase.chomp(".") }
      @queries = []
    end

    def txt(name)
      lookup(name, :txt)
    end

    # As the real one: a family the zone doesn't publish contributes nothing
    # rather than ending the lookup, but a nameserver that misbehaves still does.
    def addresses(name)
      %i[ a aaaa ].flat_map do |type|
        begin
          lookup(name, type)
        rescue MailResolver::NotFound
          []
        end
      end
    end

    private
      def lookup(name, type)
        key = name.to_s.downcase.chomp(".")
        @queries << [ key, type ]

        case records = @zone.dig(key, type)
        when :timeout  then raise MailResolver::Timeout, "timed out resolving #{type.upcase} #{key}"
        when :servfail then raise MailResolver::ServerFailure, "server failure resolving #{type.upcase} #{key}"
        when nil, []   then raise MailResolver::NotFound, "no #{type.upcase} records for #{key}"
        else records
        end
      end
  end
end
