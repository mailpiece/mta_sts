require "mailresolver"
require "mta_sts/version"
require "mta_sts/fetcher"
require "mta_sts/policy"
require "mta_sts/result"
require "mta_sts/report"
require "mta_sts/report/result"

module MtaSts
  DISCOVERY_PREFIX = "_mta-sts."
  POLICY_HOST_PREFIX = "mta-sts."
  REPORTING_PREFIX = "_smtp._tls." # RFC 8460 §3

  # RFC 8461 §3.1's ABNF would admit `v=STSv1 ; id=...`, but its prose discards
  # anything not literally starting "v=STSv1;" — the prose is what everyone implements.
  STS_RECORD = /\Av=STSv1;/
  FIELD_DELIM = ";"
  ID_FIELD = /\Aid=(.*)\z/
  # RFC 8461 §3.1 ABNF: sts-id = 1*32(ALPHA / DIGIT)
  STS_ID = /\A[a-zA-Z0-9]{1,32}\z/

  class << self
    # `known:` is required so omitting it is a decision, not an accident (§5.1).
    def lookup(domain, known:, resolver: MailResolver::Resolver.new, fetcher: Fetcher.new, now: Time.now)
      domain = Policy.normalize(recipient_domain(domain))
      held = usable(known, domain, now)
      id = discover(domain, resolver)

      case
      when id == :unreachable    then unreachable(domain, held)
      when id == :absent         then absent(domain, held)
      when held && held.id == id then renewed(domain, held, now)
      else                            fetched(domain, id, held, fetcher, now)
      end
    end

    # RFC 8460 §3
    def reporting(domain, resolver: MailResolver::Resolver.new)
      domain = Policy.normalize(recipient_domain(domain))

      case record = sole_record("#{REPORTING_PREFIX}#{domain}", matching: Report::REPORT_RECORD, resolver: resolver)
      when :unreachable then unanswered(domain)
      when :absent      then unpublished(domain)
      else                   reported(domain, record)
      end
    end

    private
      def recipient_domain(domain)
        domain.to_s.split("@").last.to_s
      end

      def usable(policy, domain, now)
        policy if policy && !policy.expired?(now) && belongs_to?(policy, domain)
      end

      def belongs_to?(policy, domain)
        policy.domain.nil? || policy.domain == domain
      end

      # RFC 8461 §3.1 — not exactly one usable record means the domain does not implement MTA-STS
      def discover(domain, resolver)
        case record = sole_record("#{DISCOVERY_PREFIX}#{domain}", matching: STS_RECORD, resolver: resolver)
        when :absent, :unreachable then record
        else                            policy_id(record) || :absent
        end
      end

      def sole_record(name, matching:, resolver:)
        records = resolver.txt(name).grep(matching)

        if records.one?
          records.first
        else
          :absent
        end
      rescue MailResolver::NotFound
        :absent
      rescue MailResolver::Error
        :unreachable
      end

      def policy_id(record)
        ids = record.split(FIELD_DELIM).map(&:strip).filter_map { |field| field[ID_FIELD, 1] }

        ids.first if ids.one? && ids.first.match?(STS_ID)
      end

      def unreachable(domain, held)
        outcome(held, status: "temperror",
          comment: "DNS didn't answer for #{DISCOVERY_PREFIX}#{domain}")
      end

      def absent(domain, held)
        outcome(held, status: "none",
          comment: "#{domain} publishes no MTA-STS policy")
      end

      # RFC 8461 §5.1 — matching id renews without refetching
      def renewed(domain, held, now)
        policy = Policy.new(mode: held.mode, mx: held.mx, max_age: held.max_age,
          id: held.id, domain: domain, fetched_at: now)

        found(policy, "policy id #{policy.id} is unchanged; renewed until #{policy.expires_at} without refetching")
      end

      def fetched(domain, id, held, fetcher, now)
        policy = Policy.parse(fetcher.fetch("#{POLICY_HOST_PREFIX}#{domain}"), id: id, domain: domain, fetched_at: now)

        found(policy, "fetched policy id #{id} from #{POLICY_HOST_PREFIX}#{domain}")
      rescue Fetcher::Error => error
        outcome(held, status: "temperror",
          comment: "couldn't fetch the policy for #{domain}: #{error.message}")
      rescue Policy::Invalid => error
        outcome(held, status: "permerror",
          comment: "#{POLICY_HOST_PREFIX}#{domain} served a policy that isn't valid: #{error.message}")
      end

      # §5.1 — only an explicit successful answer may weaken a held policy; status still reports the failure
      def outcome(held, status:, comment:)
        if held
          Result.new(status: status, policy: held,
            comment: "#{comment}; the policy already held stands until #{held.expires_at}")
        else
          Result.new(status: status, comment: comment)
        end
      end

      def found(policy, comment)
        Result.new(status: "found", policy: policy, comment: comment)
      end

      def unanswered(domain)
        Report::Result.new(status: "temperror",
          comment: "DNS didn't answer for #{REPORTING_PREFIX}#{domain}")
      end

      def unpublished(domain)
        Report::Result.new(status: "none",
          comment: "#{domain} publishes no usable TLSRPT record at #{REPORTING_PREFIX}#{domain}")
      end

      def reported(domain, record)
        report = Report.parse(record, domain: domain)

        Report::Result.new(status: "found", report: report,
          comment: "#{REPORTING_PREFIX}#{domain} asks for TLS reports at #{report.rua.join(", ")}")
      rescue Report::Invalid => error
        Report::Result.new(status: "permerror",
          comment: "#{REPORTING_PREFIX}#{domain} isn't a usable TLSRPT record: #{error.message}")
      end
  end
end
