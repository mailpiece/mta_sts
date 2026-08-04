require_relative "test_helper"

class MtaSts::PolicyTest < MtaSts::TestCase
  # Parsing

  def test_a_complete_policy_reads_as_published
    policy = parse(<<~POLICY)
      version: STSv1
      mode: enforce
      mx: mx1.example.com
      mx: mx2.example.com
      max_age: 604800
    POLICY

    assert_equal :enforce, policy.mode
    assert_equal [ "mx1.example.com", "mx2.example.com" ], policy.mx
    assert_equal 604800, policy.max_age
  end

  def test_the_id_and_fetch_time_come_from_outside_the_document
    policy = MtaSts::Policy.parse(enforcing, id: "20260728T000000Z", fetched_at: Time.utc(2026, 7, 28))

    assert_equal "20260728T000000Z", policy.id
    assert_equal Time.utc(2026, 7, 28), policy.fetched_at
  end

  def test_whose_policy_it_is_comes_from_outside_the_document_as_well
    policy = MtaSts::Policy.parse(enforcing, domain: "example.com")

    assert_equal "example.com", policy.domain
  end

  # The publishing side reads a file off disk and has no domain to give —
  # refusing there would be a worse bug than the one `domain` exists to catch.
  def test_a_policy_parsed_without_a_domain_belongs_to_nobody_in_particular
    assert_nil parse(enforcing).domain
  end

  def test_keys_and_the_mode_are_read_without_regard_to_case_or_surrounding_space
    policy = parse("VERSION:  STSv1\n  MoDe :   Enforce  \n  MX:  MX.Example.COM \nMax_Age:604800\n")

    assert_equal :enforce, policy.mode
    assert_equal [ "mx.example.com" ], policy.mx
    assert_equal 604800, policy.max_age
  end

  def test_a_line_without_a_colon_is_skipped_rather_than_fatal
    policy = parse("version: STSv1\n\nthis line says nothing\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\n\n")

    assert_equal :enforce, policy.mode
  end

  def test_an_unknown_key_is_ignored_so_a_later_extension_does_not_break_the_policy
    policy = parse("version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\nextension: whatever\n")

    assert_equal :enforce, policy.mode
  end

  def test_a_repeated_mx_is_dropped_and_the_published_order_kept
    policy = parse("version: STSv1\nmode: enforce\nmx: b.example.com\nmx: a.example.com\nmx: B.EXAMPLE.COM.\nmax_age: 604800\n")

    assert_equal [ "b.example.com", "a.example.com" ], policy.mx
  end

  def test_a_trailing_dot_and_upper_case_are_the_same_host
    assert_equal [ "mx.example.com" ], parse("version: STSv1\nmode: enforce\nmx: MX.Example.Com.\nmax_age: 604800\n").mx
  end

  def test_a_body_that_is_not_valid_utf8_is_a_malformed_policy
    assert_invalid(/UTF-8/) { parse(served("version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\n\xff")) }
  end

  # Dropping the stray byte reads this as mx.example.com: a host the domain
  # never published, allowed by a policy it never wrote.
  def test_an_invalid_byte_in_an_mx_refuses_the_policy_rather_than_naming_the_host_it_would_scrub_to
    scrubbed = nil

    assert_invalid(/UTF-8/) do
      scrubbed = parse(served("version: STSv1\nmode: enforce\nmx: m\xffx.example.com\nmax_age: 604800\n"))
    end

    assert_nil scrubbed, "the policy parsed, and allows? #{scrubbed&.allows?("mx.example.com")} for a host it never named"
  end

  def test_an_invalid_byte_in_the_mode_refuses_the_policy_rather_than_enforcing
    enforcing = nil

    assert_invalid(/UTF-8/) do
      enforcing = parse(served("version: STSv1\nmode: en\xffforce\nmx: mx.example.com\nmax_age: 604800\n"))
    end

    assert_nil enforcing
  end

  def test_a_body_that_is_valid_utf8_parses_whatever_it_says_in_it
    policy = parse(served("version: STSv1\nmode: enforce\nmx: münchen.example\nmax_age: 604800\n"))

    assert_equal [ "xn--mnchen-3ya.example" ], policy.mx
  end

  # Line terminators — the prose says CRLF, the ABNF says LF / CRLF, and the ABNF wins

  def test_a_policy_terminated_with_crlf_parses
    assert_equal :enforce, parse("version: STSv1\r\nmode: enforce\r\nmx: mx.example.com\r\nmax_age: 604800\r\n").mode
  end

  def test_a_policy_terminated_with_bare_lf_parses
    assert_equal :enforce, parse("version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\n").mode
  end

  def test_a_policy_mixing_both_terminators_parses
    assert_equal :enforce, parse("version: STSv1\r\nmode: enforce\nmx: mx.example.com\r\nmax_age: 604800\n").mode
  end

  # Refusing rather than guessing

  def test_a_missing_version_is_invalid
    assert_invalid(/version/) { parse("mode: enforce\nmx: mx.example.com\nmax_age: 604800\n") }
  end

  def test_a_version_that_is_not_stsv1_is_invalid
    assert_invalid(/version/) { parse("version: STSv2\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\n") }
  end

  def test_a_longer_version_is_not_stsv1
    assert_invalid(/version/) { parse("version: STSv10\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\n") }
  end

  def test_the_version_is_matched_without_regard_to_case
    assert_equal :enforce, parse("version: stsv1\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\n").mode
  end

  def test_a_missing_mode_is_invalid
    assert_invalid(/mode/) { parse("version: STSv1\nmx: mx.example.com\nmax_age: 604800\n") }
  end

  def test_an_unknown_mode_is_invalid
    assert_invalid(/mode/) { parse("version: STSv1\nmode: strict\nmx: mx.example.com\nmax_age: 604800\n") }
  end

  def test_a_missing_max_age_is_invalid
    assert_invalid(/max_age/) { parse("version: STSv1\nmode: enforce\nmx: mx.example.com\n") }
  end

  def test_a_max_age_that_is_not_a_whole_number_is_invalid
    assert_invalid(/max_age/) { parse("version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: a week\n") }
  end

  def test_a_negative_max_age_is_invalid
    assert_invalid(/max_age/) { parse("version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: -1\n") }
  end

  # Integer("0x10") is 16, which would read a hex literal as a fortnight and change.
  def test_a_max_age_written_as_a_ruby_literal_is_invalid
    assert_invalid(/max_age/) { parse("version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 0x10\n") }
  end

  def test_a_max_age_above_the_ceiling_is_invalid
    assert_invalid(/max_age/) { parse("version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 31557601\n") }
  end

  def test_the_ceiling_itself_is_allowed
    assert_equal 31557600, parse("version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 31557600\n").max_age
  end

  def test_a_zero_max_age_is_grammatical_and_immediately_expired
    policy = parse("version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 0\n")

    assert_equal 0, policy.max_age
    assert policy.expired?
  end

  def test_a_duplicated_non_mx_field_keeps_only_the_first
    policy = parse("version: STSv1\nmode: enforce\nmode: none\nmx: mx.example.com\nmax_age: 604800\n")
    assert_equal :enforce, policy.mode
  end

  def test_an_mx_naming_no_host_is_invalid
    assert_invalid(/mx/) { parse("version: STSv1\nmode: enforce\nmx:\nmax_age: 604800\n") }
  end

  def test_a_bare_wildcard_names_no_host
    assert_invalid(/mx/) { parse("version: STSv1\nmode: enforce\nmx: *.\nmax_age: 604800\n") }
  end

  def test_an_enforcing_policy_naming_no_host_is_invalid
    assert_invalid(/at least one host/) { parse("version: STSv1\nmode: enforce\nmax_age: 604800\n") }
  end

  def test_a_testing_policy_naming_no_host_is_invalid
    assert_invalid(/at least one host/) { parse("version: STSv1\nmode: testing\nmax_age: 604800\n") }
  end

  def test_a_policy_in_none_mode_need_name_no_host
    policy = parse("version: STSv1\nmode: none\nmax_age: 604800\n")

    assert policy.none?
    assert_empty policy.mx
  end

  # Modes

  def test_each_mode_answers_for_itself
    assert parse("version: STSv1\nmode: none\nmax_age: 604800\n").none?
    assert parse("version: STSv1\nmode: testing\nmx: mx.example.com\nmax_age: 604800\n").testing?
    assert parse("version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\n").enforce?
  end

  # Matching

  def test_an_exact_host_matches
    assert policy(mx: [ "mx.example.com" ]).allows?("mx.example.com")
  end

  def test_a_host_is_compared_without_regard_to_case_or_a_trailing_dot
    assert policy(mx: [ "mx.example.com" ]).allows?("MX.Example.COM.")
  end

  def test_a_host_the_policy_does_not_name_does_not_match
    refute policy(mx: [ "mx.example.com" ]).allows?("mx.attacker.example")
  end

  # The document is refused for bytes like these, but a host is a caller's
  # question, and a question deserves an answer.
  def test_a_host_whose_bytes_are_not_valid_utf8_is_answered_rather_than_refused
    host = served("m\xffx.example.com")

    refute_equal "mx.example.com", MtaSts::Policy.normalize(host)
    refute policy(mx: [ "mx.example.com" ]).allows?(host)
  end

  def test_a_wildcard_covers_one_label
    assert policy(mx: [ "*.example.com" ]).allows?("mx.example.com")
  end

  # Over-matching accepts a host the domain never named, which is the check failing open.
  def test_a_wildcard_does_not_cover_two_labels
    refute policy(mx: [ "*.example.com" ]).allows?("a.b.example.com")
  end

  def test_a_wildcard_does_not_cover_the_bare_domain
    refute policy(mx: [ "*.example.com" ]).allows?("example.com")
  end

  def test_a_wildcard_does_not_match_a_host_that_merely_ends_the_same_way
    refute policy(mx: [ "*.example.com" ]).allows?("mx.notexample.com")
  end

  def test_a_wildcard_does_not_match_an_empty_label
    refute policy(mx: [ "*.example.com" ]).allows?(".example.com")
  end

  def test_any_one_of_several_patterns_is_enough
    assert policy(mx: [ "mx1.example.com", "*.mail.example.com" ]).allows?("a.mail.example.com")
  end

  # A domain in "none" mode withdrew its requirements; answering false would turn
  # that into a refusal to carry its mail at all.
  def test_a_policy_in_none_mode_constrains_nothing
    assert policy(mode: :none, mx: []).allows?("anything.example")
    assert policy(mode: :none, mx: [ "mx.example.com" ]).allows?("mx.attacker.example")
  end

  # Internationalized names

  def test_a_pattern_published_as_a_u_label_matches_the_a_label_dns_carries
    assert policy(mx: [ "münchen.example" ]).allows?("xn--mnchen-3ya.example")
  end

  def test_a_host_given_as_a_u_label_matches_the_a_label_pattern
    assert policy(mx: [ "xn--mnchen-3ya.example" ]).allows?("münchen.example")
  end

  def test_a_wildcard_keeps_its_star_through_the_conversion
    assert_equal [ "*.xn--mnchen-3ya.example" ], policy(mx: [ "*.münchen.example" ]).mx
    assert policy(mx: [ "*.münchen.example" ]).allows?("mx.xn--mnchen-3ya.example")
  end

  def test_different_internationalized_hosts_still_do_not_match
    refute policy(mx: [ "münchen.example" ]).allows?("xn--brln-loa.example")
  end

  # Expiry

  def test_a_policy_expires_a_max_age_after_it_was_fetched
    assert_equal Time.utc(2026, 7, 8), policy(max_age: 604800, fetched_at: Time.utc(2026, 7, 1)).expires_at
  end

  def test_a_policy_is_live_until_its_expiry_and_not_after
    policy = policy(max_age: 604800, fetched_at: Time.utc(2026, 7, 1))

    refute policy.expired?(Time.utc(2026, 7, 7))
    assert policy.expired?(Time.utc(2026, 7, 8))
    assert policy.expired?(Time.utc(2026, 7, 9))
  end

  # Rendering

  def test_a_policy_renders_the_document_that_would_publish_it
    rendered = policy(mode: :enforce, mx: [ "mx1.example.com", "*.example.com" ], max_age: 604800).to_s

    assert_equal "version: STSv1\r\nmode: enforce\r\nmx: mx1.example.com\r\nmx: *.example.com\r\nmax_age: 604800\r\n", rendered
  end

  def test_a_rendered_policy_parses_back_to_the_same_policy
    original = policy(mode: :testing, mx: [ "mx1.example.com", "*.example.com" ], max_age: 86400)
    round_tripped = MtaSts::Policy.parse(original.to_s)

    assert_equal original.mode, round_tripped.mode
    assert_equal original.mx, round_tripped.mx
    assert_equal original.max_age, round_tripped.max_age
  end

  def test_a_policy_in_none_mode_round_trips_without_naming_a_host
    round_tripped = MtaSts::Policy.parse(policy(mode: :none, mx: [], max_age: 86400).to_s)

    assert round_tripped.none?
    assert_empty round_tripped.mx
  end

  def test_inspecting_a_policy_says_what_it_asks_for
    assert_equal "#<MtaSts::Policy mode: :enforce, mx: [\"mx.example.com\"], max_age: 604800>",
      policy(mx: [ "mx.example.com" ]).inspect
  end

  # Building one directly, which is the publishing side

  def test_a_policy_can_be_built_from_values_rather_than_a_document
    built = MtaSts::Policy.new(mode: :enforce, mx: [ "mx.example.com" ], max_age: 604800)

    assert_equal :enforce, built.mode
    assert_equal [ "mx.example.com" ], built.mx
  end

  def test_a_mode_given_as_a_string_is_the_same_mode
    assert_equal :enforce, MtaSts::Policy.new(mode: "Enforce", mx: [ "mx.example.com" ], max_age: 604800).mode
  end

  def test_a_policy_built_with_a_mode_it_cannot_keep_is_refused_at_construction
    assert_invalid(/at least one host/) { MtaSts::Policy.new(mode: :enforce, mx: [], max_age: 604800) }
  end

  def test_a_policy_built_without_a_domain_belongs_to_nobody_in_particular
    assert_nil MtaSts::Policy.new(mode: :enforce, mx: [ "mx.example.com" ], max_age: 604800).domain
  end

  # Whose policy it is only answers the question a lookup asks of it if both
  # names are spelled the one way, which is what `mx` patterns already get.
  def test_a_domain_is_normalized_the_way_every_other_name_is
    assert_equal "example.com", policy(domain: "EXAMPLE.com").domain
    assert_equal "example.com", policy(domain: "example.com.").domain
    assert_equal "xn--mnchen-3ya.example", policy(domain: "münchen.example").domain
  end

  private
    def parse(text)
      MtaSts::Policy.parse(text)
    end

    def policy(mode: :enforce, mx: [ "mx.example.com" ], max_age: 604800, domain: nil, fetched_at: Time.utc(2026, 7, 1))
      MtaSts::Policy.new(mode: mode, mx: mx, max_age: max_age, domain: domain, fetched_at: fetched_at)
    end

    def enforcing
      "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\n"
    end

    # What Fetcher hands over: the bytes the host served, labelled UTF-8 whether
    # or not they are any.
    def served(text)
      text.b.force_encoding(Encoding::UTF_8)
    end

    def assert_invalid(message, &block)
      assert_match message, assert_raises(MtaSts::Policy::Invalid, &block).message
    end
end
