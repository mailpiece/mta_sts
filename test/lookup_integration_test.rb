require_relative "test_helper"
require_relative "support/nameserver"

# DNS through a real loopback nameserver in wire format, with only HTTPS faked.
# These exist because doubles once raised errors only because tests told them to.
class MtaSts::LookupIntegrationTest < MtaSts::TestCase
  POLICY_ID = "20260728T000000Z"
  POLICY_BODY = "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\n"

  # The production resolver pointed at a nameserver we control, and nothing
  # else changed.
  class LocalResolver < MailResolver::Resolver
    def initialize(port, timeouts:)
      super(timeouts: timeouts)
      @port = port
    end

    private
      def options
        { nameserver: "127.0.0.1", port: @port }
      end
  end

  def test_an_nxdomain_from_a_real_nameserver_is_none
    with_nameserver(MtaSts::Nameserver::NXDOMAIN) do |resolver|
      result = lookup(resolver)

      assert_equal "none", result.status
      assert result.no_record?
      assert_nil result.policy
    end
  end

  def test_a_servfail_from_a_real_nameserver_is_temperror_not_none
    with_nameserver(MtaSts::Nameserver::SERVFAIL) do |resolver|
      result = lookup(resolver)

      assert_equal "temperror", result.status
      refute result.no_record?
      assert_nil result.policy
    end
  end

  def test_a_nameserver_that_never_replies_is_temperror_not_none
    without_replies do |resolver|
      result = lookup(resolver)

      assert result.temperror?
      refute result.no_record?
      assert_nil result.policy
    end
  end

  def test_a_record_answered_by_a_real_nameserver_is_found_and_enforced
    record = Resolv::DNS::Resource::IN::TXT.new("v=STSv1; id=#{POLICY_ID}")

    with_nameserver(MtaSts::Nameserver::NOERROR, records: [ record ]) do |resolver|
      result = lookup(resolver)

      assert result.found?
      assert result.enforce?
      assert_equal POLICY_ID, result.policy.id
      assert result.allows?("mx.example.com")
    end
  end

  # The wire hands TXT character-strings over unjoined, so the joining is the
  # resolver's to do before the record can begin with the version.
  def test_a_record_split_across_character_strings_is_joined_and_then_matches
    record = Resolv::DNS::Resource::IN::TXT.new("v=STSv1; ", "id=#{POLICY_ID}")

    with_nameserver(MtaSts::Nameserver::NOERROR, records: [ record ]) do |resolver|
      result = lookup(resolver)

      assert result.found?
      assert_equal POLICY_ID, result.policy.id
    end
  end

  # A CNAME counted as a second record would make §3.1's "exactly one" come
  # out at two and take the domain's policy away.
  def test_a_cname_alongside_the_answer_does_not_count_as_a_second_record
    cname = Resolv::DNS::Resource::IN::CNAME.new(Resolv::DNS::Name.create("elsewhere.example."))
    text = Resolv::DNS::Resource::IN::TXT.new("v=STSv1; id=#{POLICY_ID}")

    with_nameserver(MtaSts::Nameserver::NOERROR, records: [ cname, text ]) do |resolver|
      result = lookup(resolver)

      assert result.found?
      assert_equal POLICY_ID, result.policy.id
    end
  end

  private
    def lookup(resolver)
      MtaSts.lookup("example.com",
        known: nil,
        resolver: resolver,
        fetcher: fetcher_for("mta-sts.example.com" => POLICY_BODY))
    end

    def with_nameserver(rcode, records: [])
      nameserver = MtaSts::Nameserver.new(rcode, records: records)
      yield LocalResolver.new(nameserver.port, timeouts: [ 0.5 ])
    ensure
      nameserver&.close
    end

    # A bound socket nobody serves: the query goes out and no answer ever
    # comes back.
    def without_replies
      socket = UDPSocket.new
      socket.bind("127.0.0.1", 0)
      yield LocalResolver.new(socket.addr[1], timeouts: [ 0.2 ])
    ensure
      socket&.close
    end
end
