require_relative "test_helper"
require "socket"

class MtaSts::FetcherTest < MtaSts::TestCase
  POLICY_HOST = "mta-sts.example.com"

  POLICY = <<~POLICY
    version: STSv1
    mode: enforce
    mx: mx.example.com
    max_age: 604800
  POLICY

  # A real handshake and response. Certificates are self-signed and the trust
  # store handed to the client: one that verifies, one for another name, one nobody trusts.
  class PolicyServer
    attr_reader :cert_store, :requests

    def initialize(hostname: POLICY_HOST, trusted: true, response: nil, hang: false, dribble: nil)
      @certificate, @key = self.class.self_signed(hostname)
      @cert_store = OpenSSL::X509::Store.new
      @cert_store.add_cert(@certificate) if trusted
      @response = response
      @hang = hang
      @dribble = dribble
      @requests = []
      @server = TCPServer.new("127.0.0.1", 0)
      @thread = Thread.new { serve }
    end

    def port
      @server.addr[1]
    end

    def close
      @closing = true
      @server.close
      @thread.join(1)
    end

    def self.response(status, body, content_type: "text/plain", headers: {})
      fields = { "Content-Type" => content_type, "Content-Length" => body.bytesize.to_s, "Connection" => "close" }
      fields.merge!(headers)

      "HTTP/1.1 #{status}\r\n#{fields.map { |name, value| "#{name}: #{value}\r\n" }.join}\r\n#{body}"
    end

    def self.self_signed(hostname)
      key = OpenSSL::PKey::EC.generate("prime256v1")

      certificate = OpenSSL::X509::Certificate.new
      certificate.version = 2
      certificate.serial = 1
      certificate.subject = OpenSSL::X509::Name.parse("/CN=#{hostname}")
      certificate.issuer = certificate.subject
      certificate.public_key = key
      certificate.not_before = Time.now - 3600
      certificate.not_after = Time.now + 3600

      extensions = OpenSSL::X509::ExtensionFactory.new(certificate, certificate)
      certificate.add_extension extensions.create_extension("basicConstraints", "CA:TRUE", true)
      certificate.add_extension extensions.create_extension("subjectAltName", "DNS:#{hostname}")
      certificate.sign key, OpenSSL::Digest.new("SHA256")

      [ certificate, key ]
    end

    private
      def serve
        until @closing
          socket = ssl_server.accept
          handle socket
        end
      rescue StandardError
        # A client that walks away mid-handshake — which is what refusing a
        # certificate looks like from here — is an outcome, not a failure.
        nil
      end

      def ssl_server
        @ssl_server ||= OpenSSL::SSL::SSLServer.new(@server, context).tap do |server|
          server.start_immediately = true
        end
      end

      def context
        OpenSSL::SSL::SSLContext.new.tap do |context|
          context.cert = @certificate
          context.key = @key
        end
      end

      def handle(socket)
        @requests << read_request(socket)
        answer(socket) unless @hang
      rescue StandardError
        # The client hangs up as soon as it has read enough, which is the point
        # of the body cap; a broken pipe here is that test succeeding.
        nil
      end

      def answer(socket)
        if @dribble
          dribble(socket)
        else
          socket.write(@response)
          socket.close
        end
      end

      # Headers at once, then the body a byte at a time, each pause shorter than
      # `read_timeout` — only a deadline over the whole fetch stops it.
      def dribble(socket)
        head, body = @response.split("\r\n\r\n", 2)
        socket.write("#{head}\r\n\r\n")

        body.each_char do |byte|
          socket.write(byte)
          socket.flush
          sleep @dribble
        end

        socket.close
      end

      def read_request(socket)
        lines = []
        while (line = socket.gets) && line.strip != ""
          lines << line.strip
        end
        lines
      end
  end

  # The production fetcher with four substitutions: an ephemeral port for 443,
  # a self-signed root for the CA bundle, loopback DNS, and a caller willing to dial it.
  class LocalFetcher < MtaSts::Fetcher
    def initialize(server:, **options)
      super(resolver: MtaSts::FakeResolver.new(POLICY_HOST => { a: [ "127.0.0.1" ] }),
        permitted: ->(_address) { true }, **options)
      @server = server
    end

    private
      def connection(host, address)
        Net::HTTP.new(host, address == UP ? @server.port : DEAD_PORT).tap do |http|
          http.ipaddr = UP
          http.use_ssl = true
          http.cert_store = @server.cert_store
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER
          http.verify_hostname = true
          http.min_version = OpenSSL::SSL::TLS1_2_VERSION
          http.open_timeout = @open_timeout
          http.read_timeout = @read_timeout
        end
      end
  end

  # The connection is the only place the addresses dialled become visible, so
  # the walk down the address list is asserted through it.
  class RecordingFetcher < LocalFetcher
    attr_reader :dialled

    def initialize(**options)
      super
      @dialled = []
    end

    private
      def connection(host, address)
        @dialled << address
        super
      end
  end

  # Any address but UP dials a closed port, so it refuses on every platform —
  # a down loopback alias would hang for real on macOS.
  DOWN = "127.0.0.2"
  UP = "127.0.0.1"
  DEAD_PORT = TCPServer.open("127.0.0.1", 0) { |server| server.addr[1] }

  def teardown
    @server&.close
  end

  def test_a_policy_is_returned_with_the_media_type_it_was_served_with
    body = fetch(response: PolicyServer.response("200 OK", POLICY))

    assert_equal POLICY, body
    assert_equal "text/plain", body.content_type
    assert body.text_plain?
  end

  # The Host header is where the normalized name becomes visible to the server.
  def test_the_policy_host_is_normalized_before_anything_uses_it
    fetch(response: PolicyServer.response("200 OK", POLICY), host: "MTA-STS.Example.COM.")

    assert_match(/\AHost: #{Regexp.escape(POLICY_HOST)}(:\d+)?\z/, host_header)
  end

  # §3.2 makes the media type a SHOULD, and policies are served in the wild without it.
  def test_a_media_type_that_is_not_text_plain_is_reported_rather_than_refused
    body = fetch(response: PolicyServer.response("200 OK", POLICY, content_type: "application/octet-stream"))

    assert_equal POLICY, body
    refute body.text_plain?
    assert_equal "application/octet-stream", body.content_type
  end

  def test_a_missing_media_type_is_no_obstacle_either
    body = fetch(response: "HTTP/1.1 200 OK\r\nContent-Length: #{POLICY.bytesize}\r\nConnection: close\r\n\r\n#{POLICY}")

    assert_equal POLICY, body
    assert_nil body.content_type
    refute body.text_plain?
  end

  def test_a_status_other_than_200_is_a_failed_fetch_rather_than_an_absent_policy
    error = assert_raises MtaSts::Fetcher::HttpError do
      fetch(response: PolicyServer.response("404 Not Found", "nothing here"))
    end

    assert_includes error.message, "404"
  end

  # Following one would move the fetch to a name the certificate check was never
  # applied to, which §3.3 forbids outright.
  def test_a_redirect_is_refused_rather_than_followed
    error = assert_raises MtaSts::Fetcher::HttpError do
      fetch(response: PolicyServer.response("302 Found", "", headers: { "Location" => "https://elsewhere.example/policy.txt" }))
    end

    assert_includes error.message, "302"
    assert_equal 1, @server.requests.size
  end

  # A misbehaving policy host is a failed fetch, not an exception escaping the
  # Fetcher::Error taxonomy that `MtaSts.lookup` promises never to leak.
  def test_an_answer_that_is_not_http_is_a_fetch_error_rather_than_an_escaped_exception
    error = assert_raises MtaSts::Fetcher::HttpError do
      fetch(response: "this is not http at all\r\n\r\n")
    end

    assert_includes error.message, POLICY_HOST
  end

  def test_a_gzip_body_that_does_not_inflate_is_a_fetch_error_rather_than_an_escaped_exception
    error = assert_raises MtaSts::Fetcher::HttpError do
      fetch(response: PolicyServer.response("200 OK", "not gzip", headers: { "Content-Encoding" => "gzip" }))
    end

    assert_includes error.message, POLICY_HOST
  end

  # The wire hands over raw bytes; read them as UTF-8 or a policy naming its
  # mx as a U-label keeps bytes that can never match a normalized hostname.
  def test_the_body_arrives_as_utf_8_so_a_u_label_mx_name_can_match
    policy = "version: STSv1\nmode: enforce\nmx: münchen.example\nmax_age: 604800\n"

    body = fetch(response: PolicyServer.response("200 OK", policy))

    assert_equal Encoding::UTF_8, body.encoding
    assert MtaSts::Policy.parse(body).allows?("xn--mnchen-3ya.example")
    assert MtaSts::Policy.parse(body).allows?("münchen.example")
  end

  def test_reading_stops_at_the_body_cap
    error = assert_raises MtaSts::Fetcher::HttpError do
      fetch(response: PolicyServer.response("200 OK", "x" * 200), max_body_bytes: 64)
    end

    assert_includes error.message, "64"
  end

  # The certificate has to answer for the name the domain published. A valid
  # certificate for a name of the attacker's choosing is the whole attack.
  def test_a_certificate_issued_for_another_name_does_not_verify
    error = assert_raises MtaSts::Fetcher::CertificateError do
      fetch(response: PolicyServer.response("200 OK", POLICY), hostname: "elsewhere.example")
    end

    assert_includes error.message, POLICY_HOST
  end

  def test_a_certificate_nobody_trusts_does_not_verify
    assert_raises MtaSts::Fetcher::CertificateError do
      fetch(response: PolicyServer.response("200 OK", POLICY), trusted: false)
    end
  end

  def test_a_policy_host_that_never_answers_times_out
    assert_raises MtaSts::Fetcher::Timeout do
      fetch(hang: true, read_timeout: 0.2)
    end
  end

  # One-byte reads never trip `read_timeout`; timed loosely, since the deadline
  # and the byte cap are three orders of magnitude apart.
  def test_a_policy_host_that_dribbles_the_body_gives_up_at_the_deadline
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    error = assert_raises MtaSts::Fetcher::Timeout do
      fetch(response: PolicyServer.response("200 OK", "x" * 10_000), dribble: 0.02,
        read_timeout: 2, total_timeout: 0.3)
    end

    assert_includes error.message, POLICY_HOST
    assert_includes error.message, "0.3 seconds"
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 5
  end

  def test_a_deadline_is_no_obstacle_to_a_policy_served_promptly
    body = fetch(response: PolicyServer.response("200 OK", POLICY), total_timeout: 5)

    assert_equal POLICY, body
    assert_equal "text/plain", body.content_type
  end

  # An unreachable policy host is not evidence about whether the domain
  # publishes a policy — the `_mta-sts` record already answered that.
  def test_a_policy_host_that_cannot_be_reached_is_a_fetch_error
    @server = PolicyServer.new(response: PolicyServer.response("200 OK", POLICY))
    fetcher = LocalFetcher.new(server: @server)
    @server.close

    error = assert_raises MtaSts::Fetcher::Error do
      fetcher.fetch(POLICY_HOST)
    end

    assert_includes error.message, POLICY_HOST
  end

  # Asserted directly: over loopback the server can't show which name SNI
  # carries, the Host header says, and the certificate is checked against.
  def test_the_connection_presents_the_policy_host_name
    http = MtaSts::Fetcher.new.send(:connection, POLICY_HOST, "93.184.216.34")

    assert_equal POLICY_HOST, http.address
    assert_equal 443, http.port
    assert http.use_ssl?
    assert_equal OpenSSL::SSL::VERIFY_PEER, http.verify_mode
    assert http.verify_hostname
    assert_equal OpenSSL::SSL::TLS1_2_VERSION, http.min_version
  end

  # The address dialled is the one that was judged, rather than whatever a
  # second resolution would have answered a moment later.
  def test_the_connection_dials_the_address_that_was_judged
    http = MtaSts::Fetcher.new.send(:connection, POLICY_HOST, "93.184.216.34")

    assert_equal "93.184.216.34", http.ipaddr
  end

  # Where the policy host resolves is chosen by whoever is being sent mail;
  # reaching an inside address is the fetch a stranger would otherwise get for free.
  def test_an_address_the_caller_refuses_is_never_dialled
    @server = PolicyServer.new(response: PolicyServer.response("200 OK", POLICY))
    fetcher = LocalFetcher.new(server: @server, permitted: ->(_address) { false })

    error = assert_raises MtaSts::Fetcher::BlockedAddress do
      fetcher.fetch(POLICY_HOST)
    end

    assert_includes error.message, POLICY_HOST
    assert_empty @server.requests
  end

  def test_the_default_judgement_admits_public_addresses
    assert MtaSts::Fetcher.public_address?("93.184.216.34")
    assert MtaSts::Fetcher.public_address?("2606:2800:220:1:248:1893:25c8:1946")
  end

  def test_the_default_judgement_refuses_everything_a_policy_is_never_published_in
    %w[ 127.0.0.1 ::1 10.0.0.5 172.16.0.1 192.168.1.1 169.254.1.1 fe80::1 fd00::1 fc00::1
        0.0.0.0 100.64.0.1 192.0.0.1 192.88.99.1 198.18.0.1 224.0.0.1 240.0.0.1
        ff02::1 fec0::1 2001:db8::1 100::1 ].each do |address|
      refute MtaSts::Fetcher.public_address?(address), "expected #{address} to be refused"
    end
  end

  # Mapped forms are refused outright — no resolver answers with one — and
  # NAT64 is read through to the IPv4 address it carries.
  def test_the_default_judgement_looks_through_an_address_wrapped_in_another
    assert MtaSts::Fetcher.public_address?("64:ff9b::5db8:d822") # NAT64 of 93.184.216.34

    %w[ ::ffff:127.0.0.1 ::ffff:93.184.216.34 64:ff9b::7f00:1 64:ff9b::a00:5
        64:ff9b:1::7f00:1 64:ff9b:1:7f00:0:1:: 2002:7f00:1:: 2001::7f00:1 ].each do |address|
      refute MtaSts::Fetcher.public_address?(address), "expected #{address} to be refused"
    end
  end

  def test_the_default_judgement_refuses_what_is_not_an_address_at_all
    refute MtaSts::Fetcher.public_address?("not an address")
    refute MtaSts::Fetcher.public_address?("")
    refute MtaSts::Fetcher.public_address?(nil)
  end

  # Nowhere to send the request is a failed fetch, so a policy already held
  # stands rather than being cleared by a name that stopped resolving.
  def test_a_policy_host_that_resolves_to_nothing_is_a_fetch_error
    @server = PolicyServer.new(response: PolicyServer.response("200 OK", POLICY))
    fetcher = LocalFetcher.new(server: @server, resolver: MtaSts::FakeResolver.new)

    error = assert_raises MtaSts::Fetcher::Error do
      fetcher.fetch(POLICY_HOST)
    end

    assert_includes error.message, POLICY_HOST
    assert_empty @server.requests
  end

  # Any published address serves the policy, so one dead machine must not
  # temperror every message to the domain.
  def test_an_address_that_is_down_moves_the_fetch_to_the_next_one
    @server = PolicyServer.new(response: PolicyServer.response("200 OK", POLICY))
    fetcher = recording_fetcher(DOWN, UP)

    assert_equal POLICY, fetcher.fetch(POLICY_HOST)
    assert_equal [ DOWN, UP ], fetcher.dialled
  end

  def test_a_policy_host_with_every_address_down_is_a_fetch_error
    @server = PolicyServer.new(response: PolicyServer.response("200 OK", POLICY))
    fetcher = recording_fetcher(DOWN, "127.0.0.3")

    error = assert_raises MtaSts::Fetcher::Error do
      fetcher.fetch(POLICY_HOST)
    end

    assert_includes error.message, "couldn't reach #{POLICY_HOST}"
    assert_equal [ DOWN, "127.0.0.3" ], fetcher.dialled
  end

  # The last address got closest to an answer, so its failure is the one worth
  # reporting.
  def test_the_failure_of_the_last_address_reached_is_the_one_reported
    @server = PolicyServer.new(response: PolicyServer.response("200 OK", POLICY), trusted: false)
    fetcher = recording_fetcher(DOWN, UP)

    assert_raises MtaSts::Fetcher::CertificateError do
      fetcher.fetch(POLICY_HOST)
    end

    assert_equal [ DOWN, UP ], fetcher.dialled
  end

  # An answer is final however unwelcome; asking the other addresses is
  # shopping around for a better one.
  def test_an_answer_however_unwelcome_ends_the_fetch
    @server = PolicyServer.new(response: PolicyServer.response("404 Not Found", "nothing here"))
    fetcher = recording_fetcher(UP, DOWN)

    error = assert_raises MtaSts::Fetcher::HttpError do
      fetcher.fetch(POLICY_HOST)
    end

    assert_includes error.message, "404"
    assert_equal [ UP ], fetcher.dialled
  end

  # The cap trips after the response arrived, which makes it an answer too.
  def test_a_body_over_the_cap_is_an_answer_that_ends_the_fetch
    @server = PolicyServer.new(response: PolicyServer.response("200 OK", "x" * 200))
    fetcher = recording_fetcher(UP, DOWN, max_body_bytes: 64)

    error = assert_raises MtaSts::Fetcher::HttpError do
      fetcher.fetch(POLICY_HOST)
    end

    assert_includes error.message, "64"
    assert_equal [ UP ], fetcher.dialled
  end

  # A body that won't inflate fails mid-read, but it is still this host having
  # answered.
  def test_a_broken_answer_is_an_answer_that_ends_the_fetch
    @server = PolicyServer.new(response: PolicyServer.response("200 OK", "not gzip", headers: { "Content-Encoding" => "gzip" }))
    fetcher = recording_fetcher(UP, DOWN)

    assert_raises MtaSts::Fetcher::HttpError do
      fetcher.fetch(POLICY_HOST)
    end

    assert_equal [ UP ], fetcher.dialled
  end

  def test_a_policy_host_whose_every_address_is_refused_is_blocked_without_dialling
    @server = PolicyServer.new(response: PolicyServer.response("200 OK", POLICY))
    fetcher = recording_fetcher(UP, DOWN, permitted: ->(_address) { false })

    error = assert_raises MtaSts::Fetcher::BlockedAddress do
      fetcher.fetch(POLICY_HOST)
    end

    assert_includes error.message, "#{POLICY_HOST} resolves to no address a policy may be published at"
    assert_empty fetcher.dialled
  end

  # One deadline covers the whole fetch, not each address in turn; the second
  # address here refuses instantly, so only the deadline explains stopping.
  def test_one_deadline_covers_every_address_of_the_fetch
    @server = PolicyServer.new(hang: true)
    fetcher = recording_fetcher(UP, DOWN, read_timeout: 0.3, total_timeout: 0.2)

    assert_raises MtaSts::Fetcher::Timeout do
      fetcher.fetch(POLICY_HOST)
    end

    assert_equal [ UP ], fetcher.dialled
  end

  private
    def fetch(host: POLICY_HOST, hostname: POLICY_HOST, trusted: true, response: nil, hang: false, dribble: nil, **options)
      @server = PolicyServer.new(hostname: hostname, trusted: trusted, response: response, hang: hang, dribble: dribble)

      LocalFetcher.new(server: @server, **options).fetch(host)
    end

    def host_header
      @server.requests.first.find { |line| line.start_with?("Host:") }
    end

    def recording_fetcher(*addresses, **options)
      RecordingFetcher.new(server: @server,
        resolver: MtaSts::FakeResolver.new(POLICY_HOST => { a: addresses }), **options)
    end
end
