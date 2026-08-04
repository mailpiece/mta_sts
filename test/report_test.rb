require_relative "test_helper"

class MtaSts::ReportTest < MtaSts::TestCase
  # Parsing

  def test_a_record_reads_the_destinations_it_publishes
    report = parse("v=TLSRPTv1; rua=mailto:tlsrpt@example.com")

    assert_equal [ "mailto:tlsrpt@example.com" ], report.rua
    assert_empty report.ignored
  end

  def test_several_destinations_are_kept_in_published_order
    report = parse("v=TLSRPTv1; rua=mailto:b@example.com,https://example.com/tlsrpt,mailto:a@example.com")

    assert_equal [ "mailto:b@example.com", "https://example.com/tlsrpt", "mailto:a@example.com" ], report.rua
  end

  def test_whose_report_it_is_comes_from_outside_the_record
    assert_equal "example.com", MtaSts::Report.parse(reporting, domain: "example.com").domain
  end

  def test_a_record_parsed_without_a_domain_belongs_to_nobody_in_particular
    assert_nil parse(reporting).domain
  end

  def test_a_domain_is_normalized_the_way_every_other_name_is
    assert_equal "example.com", MtaSts::Report.parse(reporting, domain: "EXAMPLE.com").domain
    assert_equal "example.com", MtaSts::Report.parse(reporting, domain: "example.com.").domain
    assert_equal "xn--mnchen-3ya.example", MtaSts::Report.parse(reporting, domain: "münchen.example").domain
  end

  def test_a_record_that_is_not_valid_utf8_is_malformed
    assert_invalid(/UTF-8/) { parse(served("v=TLSRPTv1; rua=mailto:tlsrpt@ex\xffample.com")) }
  end

  # The version literal

  def test_a_version_in_the_wrong_case_is_not_a_record
    assert_invalid(/TLSRPTv1/) { parse("V=TLSRPTv1; rua=mailto:tlsrpt@example.com") }
    assert_invalid(/TLSRPTv1/) { parse("v=tlsrptv1; rua=mailto:tlsrpt@example.com") }
  end

  def test_whitespace_around_the_version_equals_is_not_a_record
    assert_invalid(/TLSRPTv1/) { parse("v = TLSRPTv1; rua=mailto:tlsrpt@example.com") }
    assert_invalid(/TLSRPTv1/) { parse("v =TLSRPTv1; rua=mailto:tlsrpt@example.com") }
    assert_invalid(/TLSRPTv1/) { parse("v= TLSRPTv1; rua=mailto:tlsrpt@example.com") }
  end

  def test_a_record_that_does_not_start_with_the_version_is_not_a_record
    assert_invalid(/TLSRPTv1/) { parse(" v=TLSRPTv1; rua=mailto:tlsrpt@example.com") }
    assert_invalid(/TLSRPTv1/) { parse("rua=mailto:tlsrpt@example.com") }
  end

  def test_a_longer_version_is_not_tlsrptv1
    assert_invalid(/TLSRPTv1/) { parse("v=TLSRPTv10; rua=mailto:tlsrpt@example.com") }
  end

  def test_a_version_not_followed_by_a_delimiter_is_not_a_record
    assert_invalid(/TLSRPTv1/) { parse("v=TLSRPTv1 rua=mailto:tlsrpt@example.com") }
  end

  def test_a_record_that_is_only_a_version_is_invalid
    assert_invalid(/TLSRPTv1/) { parse("v=TLSRPTv1") }
  end

  def test_a_version_with_no_field_after_it_is_invalid
    assert_invalid(/at least one field/) { parse("v=TLSRPTv1;") }
  end

  # Field and URI delimiters

  def test_a_trailing_delimiter_is_legal
    assert_equal [ "mailto:tlsrpt@example.com" ], parse("v=TLSRPTv1; rua=mailto:tlsrpt@example.com;").rua
  end

  def test_whitespace_around_the_field_delimiter_is_legal
    report = parse("v=TLSRPTv1;\t rua=mailto:a@example.com \t;\t rua=mailto:b@example.com \t; \t")

    assert_equal [ "mailto:a@example.com", "mailto:b@example.com" ], report.rua
  end

  def test_whitespace_before_the_delimiter_that_ends_the_version_is_not_a_record
    assert_invalid(/TLSRPTv1/) { parse("v=TLSRPTv1 ; rua=mailto:tlsrpt@example.com") }
  end

  def test_whitespace_around_the_uri_delimiter_is_legal
    report = parse("v=TLSRPTv1; rua=mailto:a@example.com \t, \tmailto:b@example.com")

    assert_equal [ "mailto:a@example.com", "mailto:b@example.com" ], report.rua
  end

  def test_no_delimiter_around_the_fields_at_all_is_legal
    assert_equal [ "mailto:tlsrpt@example.com" ], parse("v=TLSRPTv1;rua=mailto:tlsrpt@example.com").rua
  end

  # The rua field name

  def test_a_rua_in_the_wrong_case_is_not_a_rua_field
    assert_invalid(/at least one mailto/) { parse("v=TLSRPTv1; RUA=mailto:tlsrpt@example.com") }
  end

  def test_a_space_before_the_rua_equals_is_not_a_rua_field
    assert_invalid(/at least one mailto/) { parse("v=TLSRPTv1; rua =mailto:tlsrpt@example.com") }
  end

  def test_a_space_after_the_rua_equals_is_stripped_with_the_uri
    assert_equal [ "mailto:tlsrpt@example.com" ], parse("v=TLSRPTv1; rua= mailto:tlsrpt@example.com").rua
  end

  def test_several_rua_fields_are_merged_in_published_order
    report = parse("v=TLSRPTv1; rua=mailto:a@example.com; rua=mailto:b@example.com,mailto:c@example.com")

    assert_equal [ "mailto:a@example.com", "mailto:b@example.com", "mailto:c@example.com" ], report.rua
  end

  # Extensions

  def test_an_unknown_field_is_ignored
    report = parse("v=TLSRPTv1; rua=mailto:tlsrpt@example.com; whatever=1")

    assert_equal [ "mailto:tlsrpt@example.com" ], report.rua
    assert_empty report.ignored
  end

  def test_a_long_underscored_and_dotted_extension_name_is_ignored_rather_than_fatal
    report = parse("v=TLSRPTv1; rua=mailto:tlsrpt@example.com; a1234567890_abcdefg.hijklmn-opq=whatever")

    assert_equal [ "mailto:tlsrpt@example.com" ], report.rua
  end

  def test_an_empty_field_is_ignored_rather_than_fatal
    assert_equal [ "mailto:tlsrpt@example.com" ], parse("v=TLSRPTv1;;rua=mailto:tlsrpt@example.com;;").rua
  end

  # Schemes

  def test_a_mailto_destination_is_accepted
    report = parse("v=TLSRPTv1; rua=mailto:tlsrpt@example.com")

    assert_equal [ "mailto:tlsrpt@example.com" ], report.mailto
    assert_empty report.https
  end

  def test_an_https_destination_is_accepted
    report = parse("v=TLSRPTv1; rua=https://example.com/tlsrpt")

    assert_equal [ "https://example.com/tlsrpt" ], report.https
    assert_empty report.mailto
  end

  def test_the_destinations_are_available_by_scheme
    report = parse("v=TLSRPTv1; rua=mailto:a@example.com,https://example.com/tlsrpt,mailto:b@example.com")

    assert_equal [ "mailto:a@example.com", "mailto:b@example.com" ], report.mailto
    assert_equal [ "https://example.com/tlsrpt" ], report.https
  end

  def test_a_scheme_is_matched_without_regard_to_case_and_kept_as_published
    report = parse("v=TLSRPTv1; rua=MAILTO:tlsrpt@example.com,HTTPS://example.com/tlsrpt")

    assert_equal [ "MAILTO:tlsrpt@example.com", "HTTPS://example.com/tlsrpt" ], report.rua
    assert_equal [ "MAILTO:tlsrpt@example.com" ], report.mailto
    assert_equal [ "HTTPS://example.com/tlsrpt" ], report.https
  end

  def test_a_bare_email_address_is_ignored_but_the_record_still_parses
    report = parse("v=TLSRPTv1; rua=tlsrpt@example.com,mailto:tlsrpt@example.com")

    assert_equal [ "mailto:tlsrpt@example.com" ], report.rua
    assert_equal [ "tlsrpt@example.com" ], report.ignored
  end

  def test_an_unsupported_scheme_is_ignored
    report = parse("v=TLSRPTv1; rua=ftp://example.com/tlsrpt,http://example.com/tlsrpt,mailto:tlsrpt@example.com")

    assert_equal [ "mailto:tlsrpt@example.com" ], report.rua
    assert_equal [ "ftp://example.com/tlsrpt", "http://example.com/tlsrpt" ], report.ignored
  end

  def test_a_record_whose_every_destination_is_ignored_is_invalid
    assert_invalid(/at least one mailto/) { parse("v=TLSRPTv1; rua=tlsrpt@example.com,ftp://example.com/tlsrpt") }
  end

  def test_a_record_with_no_rua_at_all_is_invalid
    assert_invalid(/at least one mailto/) { parse("v=TLSRPTv1; whatever=1") }
  end

  def test_a_rua_naming_no_destination_is_invalid
    assert_invalid(/at least one mailto/) { parse("v=TLSRPTv1; rua=") }
  end

  # Destinations are kept verbatim

  def test_a_percent_encoded_comma_is_kept_undecoded
    report = parse("v=TLSRPTv1; rua=mailto:tlsrpt%2Cops@example.com")

    assert_equal [ "mailto:tlsrpt%2Cops@example.com" ], report.rua
  end

  def test_a_percent_encoded_comma_does_not_split_a_destination_in_two
    assert_equal 1, parse("v=TLSRPTv1; rua=mailto:tlsrpt%2Cops@example.com").rua.size
  end

  def test_an_exclamation_point_is_kept_as_part_of_the_uri
    assert_equal [ "https://example.com/tlsrpt!report" ], parse("v=TLSRPTv1; rua=https://example.com/tlsrpt!report").rua
  end

  def test_a_destination_is_not_validated_beyond_its_scheme
    report = parse("v=TLSRPTv1; rua=mailto:not+an@address@at-all,https://")

    assert_equal [ "mailto:not+an@address@at-all", "https://" ], report.rua
  end

  # Rendering

  def test_a_report_renders_the_record_that_would_publish_it
    rendered = report(rua: [ "mailto:a@example.com", "https://example.com/tlsrpt" ]).to_s

    assert_equal "v=TLSRPTv1; rua=mailto:a@example.com, https://example.com/tlsrpt", rendered
  end

  def test_a_rendered_record_parses_back_to_the_same_destinations
    original = report(rua: [ "mailto:a@example.com", "https://example.com/tlsrpt" ])

    assert_equal original.rua, MtaSts::Report.parse(original.to_s).rua
  end

  def test_what_was_ignored_is_not_rendered_back_out
    round_tripped = MtaSts::Report.parse(parse("v=TLSRPTv1; rua=oops@example.com,mailto:a@example.com").to_s)

    assert_equal [ "mailto:a@example.com" ], round_tripped.rua
    assert_empty round_tripped.ignored
  end

  def test_inspecting_a_report_says_where_reports_go
    assert_equal "#<MtaSts::Report rua: [\"mailto:a@example.com\"], ignored: [\"oops@example.com\"]>",
      parse("v=TLSRPTv1; rua=mailto:a@example.com,oops@example.com").inspect
  end

  # Building one directly, which is the publishing side

  def test_a_report_can_be_built_from_values_rather_than_a_record
    assert_equal [ "mailto:a@example.com" ], MtaSts::Report.new(rua: [ "mailto:a@example.com" ]).rua
  end

  def test_a_report_built_without_a_usable_destination_is_refused_at_construction
    assert_invalid(/at least one mailto/) { MtaSts::Report.new(rua: []) }
    assert_invalid(/at least one mailto/) { MtaSts::Report.new(rua: [ "a@example.com" ]) }
  end

  def test_a_report_built_without_a_domain_belongs_to_nobody_in_particular
    assert_nil MtaSts::Report.new(rua: [ "mailto:a@example.com" ]).domain
  end

  # Records published in the wild, verbatim

  def test_a_space_after_the_comma_and_a_trailing_semicolon
    report = parse("v=TLSRPTv1; rua=mailto:asp1jnnh@tls.eu.dmarcian.com, mailto:dmarc@digia.com;")

    assert_equal [ "mailto:asp1jnnh@tls.eu.dmarcian.com", "mailto:dmarc@digia.com" ], report.rua
  end

  def test_a_local_part_with_a_dash_is_a_destination_like_any_other
    report = parse("v=TLSRPTv1; rua=mailto:tls-rua@mailcheck.service.ncsc.gov.uk")

    assert_equal [ "mailto:tls-rua@mailcheck.service.ncsc.gov.uk" ], report.rua
  end

  def test_a_mailto_without_an_at_sign_is_still_a_mailto
    report = parse("v=TLSRPTv1;rua=mailto:tlsrpt@tuaf.edu.vn,mailto:tuaf.edu.vn")

    assert_equal [ "mailto:tlsrpt@tuaf.edu.vn", "mailto:tuaf.edu.vn" ], report.rua
    assert_empty report.ignored
  end

  def test_a_ruf_smuggled_into_the_rua_list_has_no_supported_scheme_and_is_ignored
    report = parse("v=TLSRPTv1; rua=mailto:mta-sts@naa.gov.au,ruf=mailto:mta-sts@naa.gov.au")

    assert_equal [ "mailto:mta-sts@naa.gov.au" ], report.rua
    assert_equal [ "ruf=mailto:mta-sts@naa.gov.au" ], report.ignored
  end

  def test_an_empty_first_destination_is_ignored_and_the_rest_stands
    report = parse("v=TLSRPTv1;rua=,mailto:rcw7zdfj@tls.eu.dmarcian.com")

    assert_equal [ "mailto:rcw7zdfj@tls.eu.dmarcian.com" ], report.rua
    assert_equal [ "" ], report.ignored
  end

  def test_a_trailing_comma_is_an_empty_destination_and_ignored_the_same_way
    report = parse("v=TLSRPTv1; rua=mailto:emailsecurity@medela.com,")

    assert_equal [ "mailto:emailsecurity@medela.com" ], report.rua
    assert_equal [ "" ], report.ignored
  end

  def test_a_space_after_the_mailto_scheme_is_inside_the_uri_and_stays_there
    report = parse("v=TLSRPTv1; rua=mailto: MTA_STSReport@qualcomm.com")

    assert_equal [ "mailto: MTA_STSReport@qualcomm.com" ], report.rua
  end

  def test_a_semicolon_where_the_scheme_colon_should_be_splits_the_field_and_leaves_no_destination
    assert_invalid(/at least one mailto/) { parse("v=TLSRPTv1; rua=mailto;mtasts@psu.ac.th") }
  end

  def test_a_record_publishing_only_a_ruf_names_no_destination
    assert_invalid(/at least one mailto/) { parse("v=TLSRPTv1;ruf=mailto:smtp-tls-reports@sekoia.io;") }
  end

  def test_an_uppercase_host_is_kept_as_published
    report = parse("v=TLSRPTv1;rua=mailto:0ls9p4jm@TLS.eu.dmarcadvisor.com")

    assert_equal [ "mailto:0ls9p4jm@TLS.eu.dmarcadvisor.com" ], report.rua
  end

  def test_a_trailing_dot_in_the_host_is_kept_as_published
    report = parse("v=TLSRPTv1; rua=mailto:servier.tlsr@emailsecurity.merox.io.")

    assert_equal [ "mailto:servier.tlsr@emailsecurity.merox.io." ], report.rua
  end

  # Results

  def test_a_found_result_carries_the_report_it_found
    found = result(status: "found", report: report)

    assert found.found?
    assert_equal [ "mailto:tlsrpt@example.com" ], found.rua
  end

  def test_each_status_answers_for_itself
    assert result(status: "none").no_record?
    assert result(status: "temperror").temperror?
    assert result(status: "permerror").permerror?

    refute result(status: "none").found?
    refute result(status: "found", report: report).no_record?
  end

  def test_a_result_without_a_report_has_no_destinations
    assert_empty result(status: "none").rua
    assert_empty result(status: "temperror").rua
  end

  def test_a_reporting_result_does_not_answer_delivery_questions
    found = result(status: "found", report: report)

    refute_respond_to found, :allows?
    refute_respond_to found, :enforce?
    refute_respond_to found, :testing?
  end

  def test_a_result_says_what_it_learned
    none = result(status: "none", comment: "example.com publishes no TLSRPT record")

    assert_equal "none", none.status
    assert_nil none.report
    assert_equal "example.com publishes no TLSRPT record", none.comment
  end

  def test_inspecting_a_result_says_what_it_learned_and_what_it_carries
    assert_equal "#<MtaSts::Report::Result status: \"none\", report: nil, comment: \"nothing published\">",
      result(status: "none", comment: "nothing published").inspect
  end

  private
    def parse(text)
      MtaSts::Report.parse(text)
    end

    def report(rua: [ "mailto:tlsrpt@example.com" ], domain: nil)
      MtaSts::Report.new(rua: rua, domain: domain)
    end

    def result(status:, report: nil, comment: nil)
      MtaSts::Report::Result.new(status: status, report: report, comment: comment)
    end

    def reporting
      "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
    end

    def served(text)
      text.b.force_encoding(Encoding::UTF_8)
    end

    def assert_invalid(message, &block)
      assert_match message, assert_raises(MtaSts::Report::Invalid, &block).message
    end
end
