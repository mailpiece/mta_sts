module MtaSts
  # Keyed by policy host: a String is a 200 body, an Integer a bad status,
  # :timeout/:certificate the matching Fetcher errors, an unmentioned host 404s.
  class FakeFetcher
    attr_reader :requests

    def initialize(responses = {})
      @responses = responses.transform_keys { |host| host.to_s.downcase.chomp(".") }
      @requests = []
    end

    def fetch(host)
      key = host.to_s.downcase.chomp(".")
      @requests << key

      case response = @responses[key]
      when :timeout     then raise Fetcher::Timeout, "timed out fetching the policy from #{key}"
      when :certificate then raise Fetcher::CertificateError, "#{key} presented a certificate that didn't verify"
      when Integer      then raise Fetcher::HttpError, "#{key} answered #{response}"
      when nil          then raise Fetcher::HttpError, "#{key} answered 404"
      else Fetcher::Body.new(response, content_type: "text/plain")
      end
    end
  end
end
