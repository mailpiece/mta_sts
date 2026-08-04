require_relative "test_helper"

class MtaSts::ReportingTest < MtaSts::TestCase
  RUA = "mailto:tlsrpt@example.com"
  RECORD = "v=TLSRPTv1; rua=#{RUA}"

  # Of 3,176 surveyed domains publishing TLSRPT, 3,135 also answer with SPF, a
  # site verification token or a DKIM key at the same name.
  UNRELATED = [ "v=spf1 include:_spf.example.com ~all", "google-site-verification=Ab3dEf" ].freeze

  # A dnsruby answer through the real Resolver, for the one thing a fake
  # resolver cannot show: what arrives before Resolver#txt has had its say.
  class StubDns
    def initialize(answer)
      @answer = answer
    end

    def query(name, type)
      if @answer.is_a?(Exception)
        raise @answer
      else
        Struct.new(:answer).new(@answer)
      end
    end
  end

  class StubbedResolver < MailResolver::Resolver
    def initialize(answer)
      @answer = answer
    end

    private
      def resolver
        @stub ||= StubDns.new(@answer)
      end
  end

  def test_a_published_record_is_found_and_answers_where_reports_go
    result = reporting

    assert_equal "found", result.status
    assert result.found?
    refute result.no_record?
    assert_equal [ RUA ], result.rua
    assert_equal [ RUA ], result.report.rua
  end

  def test_every_destination_a_record_names_is_reported
    result = reporting(zone: tlsrpt("v=TLSRPTv1; rua=#{RUA},https://example.com/tlsrpt"))

    assert result.found?
    assert_equal [ RUA, "https://example.com/tlsrpt" ], result.rua
  end

  def test_a_recipient_address_is_looked_up_by_its_domain
    result = reporting(domain: "user@example.com")

    assert result.found?
    assert_equal [ RUA ], result.rua
  end

  def test_a_domain_with_no_txt_records_at_all_publishes_no_reporting_record
    result = reporting(zone: {})

    assert_equal "none", result.status
    assert result.no_record?
    refute result.found?
    assert_nil result.report
  end

  # NXDOMAIN travels as NotFound rather than as a resolver failure, so the name
  # not existing is the domain not asking for reports — not "we couldn't tell".
  def test_a_name_that_does_not_exist_publishes_no_reporting_record
    result = MtaSts.reporting("example.com",
      resolver: StubbedResolver.new(Dnsruby::NXDomain.new("_smtp._tls.example.com")))

    assert result.no_record?
    assert_nil result.report
  end

  def test_unrelated_txt_records_on_their_own_are_no_reporting_record
    result = reporting(zone: tlsrpt(*UNRELATED))

    assert result.no_record?
    assert_nil result.report
  end

  # RFC 8460 §3: "If the number of resulting records is not one, senders MUST
  # assume the recipient domain does not implement TLSRPT."
  def test_two_reporting_records_are_as_unusable_as_none
    result = reporting(zone: tlsrpt(RECORD, "v=TLSRPTv1; rua=mailto:other@example.com"))

    assert result.no_record?
    assert_nil result.report
  end

  # RFC 8460 §3's count is taken after the version filter, not before —
  # counting the whole answer would strand every domain with SPF at the same name.
  def test_a_record_among_unrelated_txt_records_is_still_found
    result = reporting(zone: tlsrpt(RECORD, *UNRELATED))

    assert result.found?
    assert_equal [ RUA ], result.rua
  end

  def test_a_record_answered_after_the_unrelated_ones_is_still_found
    result = reporting(zone: tlsrpt(*UNRELATED, RECORD))

    assert result.found?
    assert_equal [ RUA ], result.rua
  end

  # The version is a prefix through the `;`, so a lookalike record cannot make
  # the count come out at two and take a domain's reporting away.
  def test_a_decoy_record_does_not_hide_the_real_one
    result = reporting(zone: tlsrpt("v=TLSRPTv1 is not a record", "V=TLSRPTv1; rua=mailto:decoy@example.com", RECORD))

    assert result.found?
    assert_equal [ RUA ], result.rua
  end

  # RFC 8460 §3: split character-strings are "concatenated without adding
  # spaces"; dnsruby hands the pieces over unjoined, so Resolver#txt does the joining.
  def test_a_record_split_across_character_strings_is_joined_and_then_matches
    split = Dnsruby::RR.create(%(_smtp._tls.example.com. 60 IN TXT "v=TLSRPTv1; ru" "a=#{RUA}"))

    result = MtaSts.reporting("example.com", resolver: StubbedResolver.new([ split ]))

    assert result.found?
    assert_equal [ RUA ], result.rua
  end

  # temperror is not none: a domain we could not ask about has not told us it
  # stopped wanting reports.
  def test_a_dns_timeout_is_temperror_not_none
    result = reporting(zone: { "_smtp._tls.example.com" => { txt: :timeout } })

    assert_equal "temperror", result.status
    assert result.temperror?
    refute result.no_record?
    assert_nil result.report
  end

  def test_a_server_failure_is_temperror_not_none
    result = reporting(zone: { "_smtp._tls.example.com" => { txt: :servfail } })

    assert result.temperror?
    refute result.no_record?
    assert_nil result.report
  end

  # A record that says TLSRPTv1 and then nothing a report can be sent to is the
  # domain's mistake rather than ours, and permanent until it publishes again.
  def test_a_record_that_names_nowhere_to_report_is_permerror
    [ "v=TLSRPTv1;", "v=TLSRPTv1; rua=", "v=TLSRPTv1; rua=;" ].each do |record|
      result = reporting(zone: tlsrpt(record))

      assert_equal "permerror", result.status, "#{record.inspect} is not a usable record"
      assert result.permerror?
      assert_nil result.report
    end
  end

  # The caller is the store, and an id-less record gives its keying nothing to
  # check itself against — so the report carries whose it is, as a policy does.
  def test_the_report_knows_whose_it_is
    assert_equal "example.com", reporting.report.domain
    assert_equal "example.com", reporting(domain: "user@EXAMPLE.com.").report.domain
  end

  # Every failure is a status, exactly as it is for lookup: a caller asking
  # where to send reports is in the middle of delivering mail.
  def test_reporting_answers_rather_than_raises_whatever_dns_holds
    [ {},
      tlsrpt(*UNRELATED),
      tlsrpt(RECORD, RECORD),
      tlsrpt("v=TLSRPTv1;"),
      tlsrpt(""),
      { "_smtp._tls.example.com" => { txt: :timeout } },
      { "_smtp._tls.example.com" => { txt: :servfail } } ].each do |zone|
      result = reporting(zone: zone)

      refute result.found?, "#{zone.inspect} is not a usable record"
      assert_nil result.report
    end
  end

  # Someone reads this in a log and has to decide whether it is theirs to fix,
  # which takes the name we asked about and what came back.
  def test_the_comment_names_the_record_and_says_what_happened
    assert_match(/asks for TLS reports at #{Regexp.escape(RUA)}/, reporting.comment)
    assert_match(/publishes no usable TLSRPT record/, reporting(zone: {}).comment)
    assert_match(/DNS didn't answer/, reporting(zone: { "_smtp._tls.example.com" => { txt: :timeout } }).comment)
    assert_match(/isn't a usable TLSRPT record/, reporting(zone: tlsrpt("v=TLSRPTv1;")).comment)

    [ {}, tlsrpt(RECORD), tlsrpt("v=TLSRPTv1;"), { "_smtp._tls.example.com" => { txt: :timeout } } ].each do |zone|
      assert_includes reporting(zone: zone).comment, "_smtp._tls.example.com"
    end
  end

  # Discovery and reporting now select their record the same way, so the
  # sharpest discovery cases — the decoy and the leading space — are asserted here too.
  def test_discovery_still_reads_its_records_exactly_as_it_did
    id = "20260728T000000Z"

    hidden = MtaSts.lookup("example.com", known: nil,
      resolver: resolver_for("_mta-sts.example.com" => { txt: [ "v=STSv1 is not a policy", "V=STSv1; id=decoy", "v=STSv1; id=#{id}" ] }),
      fetcher: fetcher_for("mta-sts.example.com" => "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\n"))

    assert hidden.found?
    assert hidden.enforce?
    assert_equal id, hidden.policy.id

    spaced = MtaSts.lookup("example.com", known: nil,
      resolver: resolver_for("_mta-sts.example.com" => { txt: [ " v=STSv1; id=#{id}" ] }),
      fetcher: fetcher_for({}))

    assert spaced.no_record?
    assert_nil spaced.policy
  end

  private
    def reporting(domain: "example.com", zone: tlsrpt(RECORD))
      MtaSts.reporting(domain, resolver: resolver_for(zone))
    end

    def tlsrpt(*records)
      { "_smtp._tls.example.com" => { txt: records } }
    end
end
