$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "minitest/autorun"
require "mta_sts"
require_relative "support/fake_resolver"
require_relative "support/fake_fetcher"

module MtaSts
  class TestCase < Minitest::Test
    private
      def resolver_for(zone)
        FakeResolver.new(zone)
      end

      def fetcher_for(responses)
        FakeFetcher.new(responses)
      end
  end
end
