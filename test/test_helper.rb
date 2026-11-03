$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "minitest/autorun"
require "mta_sts"
require_relative "support/fake_resolver"
require_relative "support/fake_fetcher"

module MtaSts
  class TestCase < Minitest::Test
    # Names DNS could be asked about but no host could have
    NOT_HOSTNAMES = [ "a\0b.example", "example.com\r\nx-injected: yes", "a b.example", "a/b.example",
      "#{"a" * 64}.example", ([ "a" * 63 ] * 4).join(".") ].freeze

    private
      def resolver_for(zone)
        FakeResolver.new(zone)
      end

      def fetcher_for(responses)
        FakeFetcher.new(responses)
      end
  end
end
