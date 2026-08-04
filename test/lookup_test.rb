require_relative "test_helper"

class MtaSts::LookupTest < MtaSts::TestCase
  NOW = Time.utc(2026, 7, 28, 12, 0, 0)
  POLICY_BODY = "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 604800\n"
  POLICY_ID = "20260728T000000Z"

  def test_a_published_policy_is_found_and_answers_enforce_and_allows
    result = lookup

    assert_equal "found", result.status
    assert result.found?
    assert result.enforce?
    assert result.allows?("mx.example.com")
    refute result.allows?("mx.attacker.example")
    assert_equal :enforce, result.policy.mode
    assert_equal POLICY_ID, result.policy.id
    assert_match(/fetched/, result.comment)
  end

  def test_a_recipient_address_is_looked_up_by_its_domain
    result = lookup(domain: "alice@example.com")

    assert result.found?
    assert_equal POLICY_ID, result.policy.id
  end

  def test_a_domain_with_no_discovery_record_is_none
    result = lookup(zone: {})

    assert_equal "none", result.status
    assert result.no_record?
    refute result.enforce?
    assert result.allows?("anything.example")
    assert_nil result.policy
  end

  def test_several_discovery_records_are_as_unusable_as_none
    result = lookup(zone: {
      "_mta-sts.example.com" => { txt: [
        "v=STSv1; id=one",
        "v=STSv1; id=two"
      ] }
    })

    assert result.no_record?
  end

  def test_a_discovery_record_without_an_id_is_none
    result = lookup(zone: {
      "_mta-sts.example.com" => { txt: [ "v=STSv1" ] }
    })

    assert result.no_record?
  end

  # §3.1 counts only records it recognizes, so a stray TXT under the domain
  # must not hide the real one; this one never reaches a field delimiter.
  def test_a_decoy_record_does_not_hide_the_real_one
    result = lookup(zone: {
      "_mta-sts.example.com" => { txt: [ "v=STSv1 is not a policy", "v=STSv1; id=#{POLICY_ID}" ] }
    })

    assert result.found?
    assert result.enforce?
    assert_equal POLICY_ID, result.policy.id
  end

  # And this one spells the version with a capital that the case-sensitive
  # %s"STSv1" doesn't admit.
  def test_a_miscased_version_decoy_does_not_hide_the_real_one
    result = lookup(zone: {
      "_mta-sts.example.com" => { txt: [ "V=STSv1; id=decoy", "v=STSv1; id=#{POLICY_ID}" ] }
    })

    assert result.found?
    assert result.enforce?
    assert_equal POLICY_ID, result.policy.id
  end

  # §3.1's version is the case-sensitive literal `%s"v=STSv1"`; the *WSP the
  # grammar allows belongs to sts-field-delim, so spacing around the `=` is not a record.
  def test_whitespace_around_the_version_equals_is_not_a_record
    result = lookup(zone: {
      "_mta-sts.example.com" => { txt: [ "v = STSv1; id=#{POLICY_ID}" ] }
    })

    assert result.no_record?
    assert_nil result.policy
  end

  # `sts-id = %s"id="` is a literal on the same terms, so a field spelled with
  # whitespace is not the id and leaves the record without what it carries.
  def test_whitespace_around_the_id_equals_is_not_an_id
    result = lookup(zone: {
      "_mta-sts.example.com" => { txt: [ "v=STSv1; id = #{POLICY_ID}" ] }
    })

    assert result.no_record?
    assert_nil result.policy
  end

  # §3.1 discards records that do not *begin* with the version, and one that
  # begins with a space doesn't.
  def test_a_record_with_leading_whitespace_is_not_a_record
    result = lookup(zone: {
      "_mta-sts.example.com" => { txt: [ " v=STSv1; id=#{POLICY_ID}" ] }
    })

    assert result.no_record?
    assert_nil result.policy
  end

  # Trailing space sits where sts-field-delim allows *WSP; a resolver padding
  # the answer has not changed what the domain published.
  def test_trailing_whitespace_is_still_a_record
    result = lookup(zone: {
      "_mta-sts.example.com" => { txt: [ "v=STSv1; id=#{POLICY_ID} " ] }
    })

    assert result.found?
    assert_equal POLICY_ID, result.policy.id
  end

  # Every spelling accepted beyond the literal is one a stranger can publish to
  # make the count come out at two, which is the whole downgrade.
  def test_a_whitespace_spelled_decoy_does_not_hide_the_real_one
    result = lookup(zone: {
      "_mta-sts.example.com" => { txt: [ "v =STSv1; id=decoy", "v=STSv1; id=#{POLICY_ID}" ] }
    })

    assert result.found?
    assert result.enforce?
    assert_equal [ "mx.example.com" ], result.policy.mx
    refute result.allows?("mx.attacker.example")
  end

  # sts-id is 1*32(ALPHA / DIGIT) and nothing else; callers print this value,
  # so a path or a payload-length id is a record to discard.
  def test_an_id_outside_the_grammar_is_no_id_at_all
    [ "a" * 33, "../../etc/passwd", "2026.01.01", "" ].each do |id|
      result = lookup(zone: discovery(id))

      assert result.no_record?, "id=#{id.inspect} is not an sts-id"
      assert_nil result.policy
    end
  end

  # Two answers to a question the grammar asks once are as good as none — the
  # reading Policy.single gives a policy file that names its mode twice.
  def test_a_record_with_two_ids_is_as_unusable_as_none
    result = lookup(zone: {
      "_mta-sts.example.com" => { txt: [ "v=STSv1; id=20260101; id=20260202" ] }
    })

    assert result.no_record?
    assert_nil result.policy
  end

  # A timeout means we could not ask; reading it as absence hands an attacker
  # a downgrade for the price of a dropped packet.
  def test_a_dns_timeout_is_temperror_not_none
    result = lookup(zone: {
      "_mta-sts.example.com" => { txt: :timeout }
    })

    assert_equal "temperror", result.status
    assert result.temperror?
    refute result.enforce?
    assert_nil result.policy
  end

  # SERVFAIL says nothing about the domain — this read as "publishes no
  # policy" until the resolver learned to tell absence from failure.
  def test_a_server_failure_is_temperror_not_none
    result = lookup(zone: {
      "_mta-sts.example.com" => { txt: :servfail }
    })

    assert_equal "temperror", result.status
    refute result.no_record?
    assert_nil result.policy
  end

  def test_a_broken_policy_file_is_permerror
    result = lookup(bodies: {
      "mta-sts.example.com" => "version: STSv1\nmode: enforce\nmax_age: 604800\n"
    })

    assert_equal "permerror", result.status
    assert result.permerror?
    refute result.enforce?
    assert_nil result.policy
  end

  def test_a_failed_fetch_is_temperror
    result = lookup(bodies: {
      "mta-sts.example.com" => :timeout
    })

    assert result.temperror?
    assert_nil result.policy
  end

  # §5.1: the TXT id is the version marker. An unchanged id means an unchanged
  # file, so there is nothing to fetch — only the lifetime restarts.
  def test_a_matching_id_renews_the_held_policy_without_refetching
    fetcher = fetcher_for("mta-sts.example.com" => POLICY_BODY)

    result = lookup(known: held_policy, fetcher: fetcher, now: NOW + 3600)

    assert result.found?
    assert result.enforce?
    assert_equal [], fetcher.requests
    assert_equal NOW + 3600, result.policy.fetched_at
    assert_match(/unchanged/, result.comment)
  end

  # RFC 8461 §3.1 lets extension fields precede `id`, so `x-id` must not read
  # as the id — least of all when its value matches the policy held.
  def test_an_extension_field_ending_in_id_is_not_the_id
    fetcher = fetcher_for("mta-sts.example.com" => "version: STSv1\nmode: testing\nmx: mx.example.com\nmax_age: 86400\n")

    result = lookup(
      known: held_policy,
      zone: { "_mta-sts.example.com" => { txt: [ "v=STSv1; x-id=#{POLICY_ID}; id=20260728T120000Z" ] } },
      fetcher: fetcher,
      now: NOW + 3600
    )

    assert result.found?
    assert result.testing?
    assert_equal "20260728T120000Z", result.policy.id
    assert_equal [ "mta-sts.example.com" ], fetcher.requests
  end

  def test_a_changed_id_refetches_and_replaces_the_held_policy
    new_body = "version: STSv1\nmode: testing\nmx: mx.example.com\nmax_age: 86400\n"

    result = lookup(
      known: held_policy,
      zone: discovery("20260728T120000Z"),
      bodies: { "mta-sts.example.com" => new_body }
    )

    assert result.found?
    assert result.testing?
    refute result.enforce?
    assert_equal "20260728T120000Z", result.policy.id
    assert_equal :testing, result.policy.mode
  end

  # Only an explicit, successful answer may weaken a policy already held; the
  # four tests below each assert both axes.
  def test_a_dns_timeout_keeps_an_unexpired_held_policy_and_still_reports_temperror
    result = lookup(
      known: held_policy,
      zone: { "_mta-sts.example.com" => { txt: :timeout } },
      now: NOW + 3600
    )

    assert result.temperror?
    refute result.found?
    assert result.enforce?
    assert_equal POLICY_ID, result.policy.id
    assert_match(/stands until/, result.comment)
  end

  # §5.1 keeps a policy in force for its max_age whatever DNS says now —
  # otherwise suppressing one TXT answer would withdraw enforcement.
  def test_a_missing_discovery_record_keeps_an_unexpired_held_policy_and_still_reports_none
    result = lookup(known: held_policy, zone: {}, now: NOW + 3600)

    assert result.no_record?
    refute result.found?
    assert result.enforce?
    assert_equal POLICY_ID, result.policy.id
    assert_match(/stands until/, result.comment)
  end

  def test_a_failed_fetch_keeps_an_unexpired_held_policy_and_still_reports_temperror
    result = lookup(
      known: held_policy,
      zone: discovery("20260728T120000Z"),
      bodies: { "mta-sts.example.com" => :timeout },
      now: NOW + 3600
    )

    assert result.temperror?
    refute result.found?
    assert result.enforce?
    assert_equal POLICY_ID, result.policy.id
  end

  def test_a_broken_policy_file_keeps_an_unexpired_held_policy_and_still_reports_permerror
    result = lookup(
      known: held_policy,
      zone: discovery("20260728T120000Z"),
      bodies: { "mta-sts.example.com" => "not a policy" },
      now: NOW + 3600
    )

    assert result.permerror?
    refute result.found?
    assert result.enforce?
    assert_equal POLICY_ID, result.policy.id
  end

  # Turning enforcement off is a deliberate act by the domain, and it must take
  # effect now rather than whenever the old max_age runs out.
  def test_a_fetched_mode_none_replaces_the_held_policy_immediately
    result = lookup(
      known: held_policy,
      zone: discovery("20260728T120000Z"),
      bodies: { "mta-sts.example.com" => "version: STSv1\nmode: none\nmax_age: 86400\n" }
    )

    assert result.found?
    refute result.enforce?
    assert result.policy.none?
    assert result.allows?("anything.example")
  end

  def test_an_expired_held_policy_is_not_kept_across_a_failure
    result = lookup(
      known: held_policy(fetched_at: NOW - 700_000),
      zone: { "_mta-sts.example.com" => { txt: :timeout } },
      now: NOW
    )

    assert result.temperror?
    assert_nil result.policy
    refute result.enforce?
  end

  # max_age governs reuse, not whether the policy just read applies: zero
  # means "don't cache me", not "don't enforce me".
  def test_a_policy_that_expires_immediately_still_applies_to_this_connection
    result = lookup(bodies: {
      "mta-sts.example.com" => "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 0\n"
    })

    assert result.found?
    assert result.enforce?
    refute result.allows?("mx.attacker.example")
    assert result.policy.expired?(NOW)
  end

  # Both halves of the hazard in one place: the DNS answer is identical, and
  # enforcement turns entirely on whether the caller handed back what it held.
  def test_a_held_policy_survives_a_vanished_record_and_passing_nothing_is_the_downgrade
    vanished = {}

    holding = lookup(known: held_policy, zone: vanished, now: NOW + 3600)
    forgetting = lookup(known: nil, zone: vanished, now: NOW + 3600)

    assert holding.no_record?
    assert holding.enforce?, "§5.1 keeps a held policy in force for its max_age whatever DNS says now"

    assert forgetting.no_record?
    assert_nil forgetting.policy
    refute forgetting.enforce?, "a caller that hands back nothing has nothing left to enforce"
  end

  # Not a style preference: a missing `known:` costs the §5.1 property and says
  # nothing, so the only place to catch it is at the call.
  def test_known_has_no_default_so_omitting_it_cannot_be_silent
    error = assert_raises(ArgumentError) do
      MtaSts.lookup("example.com", resolver: resolver_for(discovery), fetcher: fetcher_for({}))
    end

    assert_match(/known/, error.message)
  end

  # The caller is the store, so the round trip is part of the contract: what a
  # lookup returns has to be what the next one accepts.
  def test_the_returned_policy_can_be_handed_back_as_known
    fetcher = fetcher_for("mta-sts.example.com" => POLICY_BODY)
    first = lookup(fetcher: fetcher)

    second = lookup(known: first.policy, fetcher: fetcher, now: NOW + 3600)

    assert second.found?
    assert_equal [ "mta-sts.example.com" ], fetcher.requests
    assert_match(/unchanged/, second.comment)
  end

  # Ids like "1" or a date stamp collide across domains for free, and renewing
  # against one applies another domain's mx list to this domain's mail.
  def test_a_policy_held_for_another_domain_is_ignored_rather_than_renewed
    fetcher = fetcher_for("mta-sts.example.com" => POLICY_BODY)

    result = lookup(known: another_domains_policy, fetcher: fetcher, now: NOW + 3600)

    assert result.found?
    assert_equal [ "mx.example.com" ], result.policy.mx, "another domain's mx list was applied to this domain"
    assert_equal "example.com", result.policy.domain
    assert_equal [ "mta-sts.example.com" ], fetcher.requests
    assert_match(/fetched/, result.comment)
  end

  # The other routes a foreign policy could travel: every failure hands back
  # what was held, and holding somebody else's is the same as holding none.
  def test_a_policy_held_for_another_domain_does_not_stand_in_for_a_failure_here
    [ { zone: { "_mta-sts.example.com" => { txt: :timeout } } },
      { zone: {} },
      { zone: discovery("20260728T120000Z"), bodies: { "mta-sts.example.com" => :timeout } },
      { zone: discovery("20260728T120000Z"), bodies: { "mta-sts.example.com" => "not a policy" } } ].each do |failure|
      result = lookup(known: another_domains_policy, now: NOW + 3600, **failure)

      assert_nil result.policy, "#{failure.inspect} kept another domain's policy"
      refute result.enforce?
    end
  end

  def test_a_policy_held_for_this_domain_still_renews_without_refetching
    fetcher = fetcher_for("mta-sts.example.com" => POLICY_BODY)

    result = lookup(known: held_policy(domain: "EXAMPLE.com."), fetcher: fetcher, now: NOW + 3600)

    assert result.found?
    assert result.enforce?
    assert_equal [], fetcher.requests
    assert_match(/unchanged/, result.comment)
  end

  # A U-label and the A-label DNS carries are the same domain, and a store
  # keyed by what the caller typed must not read as somebody else's.
  def test_a_domain_stamped_as_a_u_label_is_the_a_label_looked_up
    fetcher = fetcher_for({})

    result = lookup(
      domain: "xn--mnchen-3ya.example",
      known: held_policy(domain: "münchen.example"),
      zone: { "_mta-sts.xn--mnchen-3ya.example" => { txt: [ "v=STSv1; id=#{POLICY_ID}" ] } },
      fetcher: fetcher,
      now: NOW + 3600
    )

    assert result.found?
    assert_equal [], fetcher.requests
  end

  # nil is a policy hand-built or rebuilt without provenance, which is the
  # caller's business — the same trust `known` itself is given.
  def test_a_policy_held_without_a_domain_is_taken_at_the_callers_word
    fetcher = fetcher_for("mta-sts.example.com" => POLICY_BODY)

    renewing = lookup(known: held_policy(domain: nil), fetcher: fetcher, now: NOW + 3600)
    keeping = lookup(known: held_policy(domain: nil), zone: {}, now: NOW + 3600)

    assert renewing.found?
    assert_equal [], fetcher.requests
    assert keeping.no_record?
    assert keeping.enforce?
  end

  # The renewal rebuilds the policy field by field, so a domain dropped there
  # is invisible until the next lookup accepts it for somebody else.
  def test_a_renewed_policy_still_knows_whose_it_is
    renewed = lookup(known: held_policy, now: NOW + 3600).policy

    assert_equal "example.com", renewed.domain

    elsewhere = lookup(
      domain: "other.example",
      known: renewed,
      zone: { "_mta-sts.other.example" => { txt: [ "v=STSv1; id=#{POLICY_ID}" ] } },
      bodies: { "mta-sts.other.example" => "version: STSv1\nmode: enforce\nmx: mx.other.example\nmax_age: 604800\n" },
      now: NOW + 7200
    )

    assert_equal [ "mx.other.example" ], elsewhere.policy.mx
  end

  private
    def lookup(domain: "example.com", zone: discovery, bodies: { "mta-sts.example.com" => POLICY_BODY },
               known: nil, fetcher: nil, now: NOW)
      MtaSts.lookup(domain,
        known: known,
        resolver: resolver_for(zone),
        fetcher: fetcher || fetcher_for(bodies),
        now: now)
    end

    def discovery(id = POLICY_ID)
      { "_mta-sts.example.com" => { txt: [ "v=STSv1; id=#{id}" ] } }
    end

    def held_policy(fetched_at: NOW, domain: "example.com", mx: [ "mx.example.com" ])
      MtaSts::Policy.new(
        mode: :enforce, mx: mx, max_age: 604800,
        id: POLICY_ID, domain: domain, fetched_at: fetched_at)
    end

    # The hazard in one object: a policy carrying an id that collides with this
    # domain's, and an mx list that must not travel with it.
    def another_domains_policy
      held_policy(domain: "other.example", mx: [ "mx.other.example" ])
    end
end
