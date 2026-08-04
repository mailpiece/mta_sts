require "ipaddr"
require "net/http"
require "openssl"
require "zlib"
require "mailresolver"
require "mta_sts/version"

module MtaSts
  # HTTPS GET of mta-sts.<domain>/.well-known/mta-sts.txt (RFC 8461 §3.3)
  class Fetcher
    class Error < StandardError; end
    class HttpError < Error; end
    class CertificateError < Error; end
    # A temperror like any other failed fetch, so a policy already held stands.
    class BlockedAddress < Error; end
    class Timeout < Error; end

    # A failure the policy host never answered through
    class Unanswered < StandardError
      attr_reader :failure

      def initialize(failure)
        super(failure.message)
        @failure = failure
      end
    end
    private_constant :Unanswered

    WELL_KNOWN_PATH = "/.well-known/mta-sts.txt"
    PORT = 443
    OPEN_TIMEOUT = 10
    READ_TIMEOUT = 10
    # read_timeout renews per read; this one does not — stops a slow-drip body
    TOTAL_TIMEOUT = 30
    MAX_BODY_BYTES = 64 * 1024
    USER_AGENT = "mta_sts/#{VERSION}"

    # RFC 8461 §3.2 SHOULD text/plain — reported, not enforced
    class Body < String
      attr_reader :content_type

      def initialize(body, content_type: nil)
        super(body)
        @content_type = content_type
      end

      def text_plain?
        content_type.to_s.split(";").first.to_s.strip.casecmp?("text/plain")
      end
    end

    # Special-use IPv4 no policy is published in. RFC 1918, loopback and
    # link-local are left to the IPAddr predicates.
    RESERVED_V4 = %w[
      0.0.0.0/8 100.64.0.0/10 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24
      198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4
    ].map { |range| IPAddr.new(range) }.freeze

    RESERVED_V6 = %w[
      ::/128 64:ff9b:1::/48 100::/64 2001::/32 2001:2::/48 2001:db8::/32
      2002::/16 fec0::/10 ff00::/8
    ].map { |range| IPAddr.new(range) }.freeze

    # RFC 6052 §2.2 with a /96 prefix
    NAT64 = IPAddr.new("64:ff9b::/96")

    class << self
      # The policy host is named by the domain being delivered to, so where it
      # resolves is a stranger's to choose.
      def public_address?(address)
        ip = address.is_a?(IPAddr) ? address : IPAddr.new(address.to_s)

        case
        # No resolver legitimately answers with an address wrapped in another,
        # whatever it wraps.
        when ip.ipv4_mapped? || ipv4_compat?(ip) then false
        when ip.ipv4?                           then public_v4?(ip)
        when NAT64.include?(ip)                 then public_v4?(embedded_v4(ip))
        else                                         public_v6?(ip)
        end
      rescue IPAddr::Error
        false
      end

      private
        # IPAddr#ipv4_compat? is obsolete; reimplemented since the check itself
        # (the deprecated ::a.b.c.d form) is still one we need to catch.
        def ipv4_compat?(ip)
          if ip.ipv6?
            low = ip.to_i & 0xffffffff
            (ip.to_i >> 32).zero? && low != 0 && low != 1
          else
            false
          end
        end

        def public_v4?(ip)
          !(ip.private? || ip.loopback? || ip.link_local? || covered_by?(RESERVED_V4, ip))
        end

        def embedded_v4(ip)
          IPAddr.new(ip.to_i & 0xffffffff, Socket::AF_INET)
        end

        def public_v6?(ip)
          !(ip.private? || ip.loopback? || ip.link_local? || covered_by?(RESERVED_V6, ip))
        end

        def covered_by?(ranges, ip)
          ranges.any? { |range| range.include?(ip) }
        end
    end

    def initialize(open_timeout: OPEN_TIMEOUT, read_timeout: READ_TIMEOUT,
                   total_timeout: TOTAL_TIMEOUT, max_body_bytes: MAX_BODY_BYTES,
                   resolver: MailResolver::Resolver.new, permitted: Fetcher.method(:public_address?))
      @open_timeout = open_timeout
      @read_timeout = read_timeout
      @total_timeout = total_timeout
      @max_body_bytes = max_body_bytes
      @resolver = resolver
      @permitted = permitted
    end

    def fetch(host)
      get(normalize(host))
    end

    private
      def normalize(host)
        host.to_s.downcase.chomp(".")
      end

      def get(host)
        deadline = monotonic_now + @total_timeout
        failure = nil

        # A policy host with several addresses isn't written off because the first
        # is down — the domain published all of them, and any one serves.
        permitted_addresses(host).each do |address|
          break if monotonic_now > deadline

          begin
            return policy_from(host, address, deadline)
          rescue Unanswered => unanswered
            failure = unanswered.failure
          end
        end

        raise failure || Timeout.new("timed out fetching the policy from #{host}")
      end

      # Resolved once here and carried into every connection: resolving again to
      # dial would leave the second answer free to differ from the one judged.
      def permitted_addresses(host)
        addresses = resolve(host).select { |address| @permitted.call(address) }
        raise BlockedAddress, "#{host} resolves to no address a policy may be published at" if addresses.empty?

        addresses
      end

      def resolve(host)
        addresses = @resolver.addresses(host)
        raise Error, "couldn't resolve #{host}" if addresses.empty?

        addresses
      rescue MailResolver::Error => error
        raise Error, "couldn't resolve #{host}: #{error.message}"
      end

      def policy_from(host, address, deadline)
        with_response(host, address) do |response|
          if response.is_a?(Net::HTTPOK)
            body_from(response, host, deadline)
          else
            # RFC 8461 §3.3 MUST NOT follow redirects
            raise HttpError, "#{host} answered #{response.code}"
          end
        end
      end

      # `answered` is the whole distinction the attempt loop turns on
      def with_response(host, address)
        answered = false
        result = nil

        connection(host, address).start do |http|
          http.request(policy_request) do |response|
            answered = true
            result = yield response
          end
        end

        result
      rescue OpenSSL::SSL::SSLError => error
        raise attempt_failure(answered, CertificateError.new("#{host} presented a certificate that didn't verify: #{error.message}"))
      rescue Net::OpenTimeout, Net::ReadTimeout, ::Timeout::Error
        raise attempt_failure(answered, Timeout.new("timed out fetching the policy from #{host}"))
      rescue Net::HTTPBadResponse, Net::ProtocolError, Zlib::Error => error
        raise attempt_failure(answered, HttpError.new("#{host} answered with malformed HTTP: #{error.message}"))
      rescue SystemCallError, SocketError, IOError, EOFError => error
        raise attempt_failure(answered, Error.new("couldn't reach #{host}: #{error.message}"))
      end

      def connection(host, address)
        Net::HTTP.new(host, PORT).tap do |http|
          # Dial the address already judged; the name stays behind for SNI, the
          # Host header, and the certificate the whole fetch rests on.
          http.ipaddr = address
          http.use_ssl = true
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER
          http.verify_hostname = true
          http.min_version = OpenSSL::SSL::TLS1_2_VERSION
          http.open_timeout = @open_timeout
          http.read_timeout = @read_timeout
        end
      end

      # RFC 8461 §3.3 — no HTTP caching; freshness is TXT id + max_age
      def policy_request
        Net::HTTP::Get.new(WELL_KNOWN_PATH, "accept" => "text/plain", "user-agent" => USER_AGENT)
      end

      def attempt_failure(answered, error)
        if answered
          error
        else
          Unanswered.new(error)
        end
      end

      def body_from(response, host, deadline)
        body = +""

        response.read_body do |chunk|
          body << chunk

          if body.bytesize > @max_body_bytes
            raise HttpError, "#{host} sent more than #{@max_body_bytes} bytes of policy"
          end

          if monotonic_now > deadline
            raise Timeout, "#{host} took longer than #{@total_timeout} seconds to send the policy"
          end
        end

        Body.new(body.force_encoding(Encoding::UTF_8), content_type: response["content-type"])
      end

      def monotonic_now
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
  end
end
