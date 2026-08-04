# mta_sts

🔒 SMTP MTA Strict Transport Security for Ruby.

Look up a recipient domain's MTA-STS policy before delivering a message, to know whether TLS must be enforced and which servers are legitimate.

**mta_sts** resolves a recipient domain's MTA-STS policy (RFC 8461) and finds out which of its mail servers may be used and whether TLS is optional. It also discovers where the domain wants TLS failure reports sent (RFC 8460 TLSRPT).

For outbound MTAs deciding how to deliver a message: mail servers refusing to downgrade to plaintext or connect to an unlisted host, senders discovering where to submit TLSRPT aggregate reports.

**mta_sts** handles:

- MTA-STS policy lookup (RFC 8461) - which mail servers a domain vouches for, and whether TLS is optional or must be enforced
- status and policy kept as separate axes, so a DNS timeout can't be mistaken for a domain that dropped its policy
- policy persistence handled by the caller - hand back what you kept last time, and get told what to keep next
- TLSRPT record discovery (RFC 8460) - where a domain wants TLS failure reports sent
- injectable resolver and fetcher, with the fetcher validating the resolved address before it dials, since the address is a stranger's choosing
- policy publishing and parsing helpers, for domains serving their own policy

> Resolves a policy and tells you whether to trust a server. What you do with that answer - defer, refuse, downgrade - stays in your code.

## Contents

- [Installation](#installation)
- [Looking Up a Policy](#looking-up-a-policy)
- [Results](#results)
- [Status and Policy Are Separate Axes](#status-and-policy-are-separate-axes)
- [Holding On to a Policy](#holding-on-to-a-policy)
- [TLSRPT Record Discovery](#tlsrpt-record-discovery)
- [Custom Resolver & Fetcher](#custom-resolver--fetcher)
- [Publishing a Policy](#publishing-a-policy)
- [What It Is Strict About](#what-it-is-strict-about)
- [What It Is Not That Strict](#what-it-is-not-that-strict)
- [What It Does Not Check](#what-it-does-not-check)
- [Testing](#testing)
- [History](#history)
- [Contributing](#contributing)
- [Acknowledgments](#acknowledgments)
- [License](#license)

## Installation

Add this line to your application's Gemfile:

```ruby
gem "mta_sts"
```

Requires Ruby >= 3.4

## Looking Up a Policy

```ruby
result = MtaSts.lookup(domain, known:, resolver:, fetcher:, now:)
# => #<MtaSts::Result status:, comment:, policy:>
```

- **domain** - the recipient domain, the part after the `@`
- **known** - the policy this library returned last time, or `nil`. There's no cache here, so this is how a policy survives between calls. Required on purpose: `known: nil` should be a decision, not an omission
- **resolver** - defaults to `MailResolver::Resolver.new`, from the [mailresolver](https://github.com/mailpiece/mailresolver) gem
- **fetcher** - defaults to `MtaSts::Fetcher.new`
- **now** - a `Time`, for expiry; defaults to `Time.now`

```ruby
result = MtaSts.lookup("gmail.com", known: store["gmail.com"])
store["gmail.com"] = result.policy if result.policy

if result.enforce? && !result.allows?(mx_host)
  # the policy names which servers are legitimate, and this is not one of them
end
```

Hand back what you kept, keep what comes back - both halves matter.

## Results

```ruby
result.status              # => "found"
result.policy.mode         # => :enforce
result.policy.mx           # => ["gmail-smtp-in.l.google.com", "*.gmail-smtp-in.l.google.com"]
result.policy.max_age      # => 86400
result.policy.id           # => "20190429T010101"
result.policy.domain       # => "gmail.com"
result.policy.expires_at   # => 2026-07-29 14:03:11 UTC

result.enforce?                                    # => true
result.allows?("alt1.gmail-smtp-in.l.google.com")  # => true
result.allows?("mx.attacker.example")              # => false
```

Two questions get asked at connect time: must TLS be verified and non-optional (`enforce?`), and is this hostname one the domain vouches for (`allows?`).

## Status and Policy Are Separate Axes

`status` describes what this lookup learned. `policy` describes what you must honor. Nothing raises - a result always comes back with a `comment`:

```ruby
result.status   # => "temperror"
result.comment  # => "DNS didn't answer for _mta-sts.example.com"
```

Four statuses, each with a predicate:

- `found` / `found?` - a policy was fetched, or renewed against an unchanged `id`
- `none` / `no_record?` - no `_mta-sts` record seen
- `temperror` / `temperror?` - DNS or the policy host didn't answer
- `permerror` / `permerror?` - the record or policy file is broken

`policy` is present whenever there's one to honor: fresh, renewed, or the `known` one you passed in that hasn't expired.

| what happened                             | status      | policy  | `enforce?` |
| ------------------------------------------ | ----------- | ------- | ---------- |
| fresh fetch, `mode: enforce`               | `found`     | present | true       |
| DNS timeout, held an enforcing policy      | `temperror` | held    | true       |
| TXT record gone, held an enforcing policy  | `none`      | held    | **true**   |
| never had one, no TXT record               | `none`      | nil     | false      |

The third row looks wrong and isn't. §5.1 keeps a policy in force for its `max_age` regardless of what DNS says now - deleting the TXT record does not withdraw enforcement, only serving `mode: none` does.

Use `enforce?` and `allows?` for the connection decision, not `status`:

```ruby
if result.enforce? && !result.allows?(mx)
  defer_or_fail
elsif result.temperror? && !result.policy
  defer # we don't know; don't downgrade
end
```

`temperror` is not `none`. A resolver timeout means "we could not ask"; reading it as "no policy published" hands an attacker a downgrade for the cost of dropping a UDP packet.

## Holding On to a Policy

There's no cache in this library. `lookup` takes the policy you kept last time and hands one back.

```ruby
result = MtaSts.lookup("example.com", known: store["example.com"])
store["example.com"] = result.policy if result.policy
```

Skip that round trip and §5.1 doesn't apply. Three rules govern what comes back:

- A matching `id` renews the expiry without refetching
- A temporary failure keeps a policy that hasn't expired
- A fetched `mode: none` replaces it immediately

A policy also carries the domain it was fetched for. Handing back another domain's policy under the wrong key is ignored rather than enforced. Store that too when you persist:

```ruby
row = { body: policy.to_s, id: policy.id, domain: policy.domain, fetched_at: policy.fetched_at }
MtaSts::Policy.parse(row[:body], id: row[:id], domain: row[:domain], fetched_at: row[:fetched_at])
```

## TLSRPT Record Discovery

Where a domain wants TLS failure reports sent (RFC 8460). One TXT lookup at `_smtp._tls.<domain>` — not report generation or submission.

```ruby
result = MtaSts.reporting("gmail.com")
# => #<MtaSts::Report::Result status:, comment:, report:>

result.status   # => "found"
result.rua      # => ["mailto:tlsrpt@smtp.gmail.com"]
result.report.mailto
result.report.https
result.report.ignored  # destinations that were named but are neither mailto: nor https:
```

Same status vocabulary as policy lookup (`found` / `none` / `temperror` / `permerror`), with `no_record?` for `"none"`. Unknown TXT fields on the name are ignored; only `mailto:` and `https:` destinations are kept.

## Custom Resolver & Fetcher

```ruby
MtaSts.lookup("example.com", known: nil,
  resolver: MyCachingResolver.new,  # DNS, for discovery
  fetcher:  MyPolicyFetcher.new)    # the HTTPS GET
```

- **resolver** - needs one method, `txt`, over [mailresolver](https://github.com/mailpiece/mailresolver) by default. Covers discovery only (`_mta-sts` and `_smtp._tls`). Raise `MailResolver::NotFound` for no such record, `MailResolver::Timeout` or `MailResolver::ServerFailure` for no answer. If your app also uses `mailauth` or talks to DNS itself, build one `MailResolver::Resolver` and pass it everywhere — see mailresolver's README for why.
- **fetcher** - one `GET`, over stdlib `Net::HTTP` by default, certificate verification on. Body size and a total wall-clock budget are capped so a hostile host cannot hold the thread forever.

The fetcher resolves the policy host itself, so that the address it dials is one it has judged:

```ruby
MtaSts::Fetcher.new(
  resolver:  MyResolver.new,                       # needs `addresses` as well as `txt`
  permitted: ->(address) { my_own_opinion(address) })
```

- **permitted** - asked about each resolved address; each one admitted is dialled in turn until the host answers. Defaults to `MtaSts::Fetcher.public_address?`, which admits public unicast and refuses private, loopback, link-local, and other special-use addresses, including ones wrapped or reached through NAT64. A deployment serving policies from inside its own network passes something more permissive.

The recipient domain names the policy host, so where it resolves is chosen by whoever is being sent mail — without this, that's a request to an address of a stranger's choosing.

## Publishing a Policy

```ruby
policy = MtaSts::Policy.new(mode: :enforce, mx: ["mx.example.com"], max_age: 604800)
puts policy.to_s
```
version: STSv1
mode: enforce
mx: mx.example.com
max_age: 604800


And read one back:

```ruby
MtaSts::Policy.parse(File.read("mta-sts.txt"))
# => #<MtaSts::Policy mode: :enforce, mx: ["mx.example.com"], max_age: 604800>
```

## What It Is Strict About

- HTTP 3xx are never followed
- HTTP caching (RFC 7234) is never used. Freshness comes from the TXT `id` and `max_age` only
- Only `200` is a policy
- The certificate is verified against `mta-sts.<domain>`, the policy host name
- The `_mta-sts` discovery record must match the ABNF (`v=STSv1;` case-sensitive, a single well-formed `id`)
- Fetch body size and total time are capped

## What It Is Not That Strict

- `Content-Type: text/plain` is checked but not enforced
- Line terminators may be bare `LF` as well as `CRLF`
- The policy file is read case-insensitively, so `version: stsv1` and `mode: ENFORCE` both parse, though the ABNF spells both case-sensitively. The discovery record is not read this way: strictness is worth more on the record that decides whether a policy exists at all than on the document it leads to

## What It Does Not Check

- **Certificate revocation.** `Net::HTTP` doesn't check it, and this library doesn't wire up OCSP or CRL. Pass your own `fetcher` if you need it.
- **The address the policy host resolves to.** Fetched at whatever address DNS returns. The certificate check is what protects you here.
- **DANE.** A separate mechanism needing DNSSEC validation and the peer certificate mid-handshake, which this library never sees.
- **TLSRPT report generation or submission.** This library finds the `rua`; building and sending aggregate reports is the application's job.
- **Anything about the SMTP connection.** This library opens one socket, to fetch a policy over HTTPS. It never speaks SMTP.

## Testing

```sh
bundle install
rake
```

## History

View the [changelog](CHANGELOG.md).

## Contributing

Everyone is encouraged to help improve this project:

- [Report bugs](https://github.com/mailpiece/mta_sts/issues)
- Fix bugs and submit pull requests
- Write, clarify, or fix documentation
- Suggest or add new features

## Acknowledgments

View the [acknowledgments](ACKNOWLEDGMENTS.md).

## License

MIT. See [LICENSE](LICENSE).