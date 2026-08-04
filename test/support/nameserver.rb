require "socket"
require "resolv"

module MtaSts
  # A loopback nameserver answering everything with one rcode, in wire format —
  # what a double can never show, because it only fails the way a test told it to.
  class Nameserver
    NOERROR, SERVFAIL, NXDOMAIN, REFUSED = 0, 2, 3, 5

    def initialize(rcode, records: [])
      @rcode, @records = rcode, records
      @socket = UDPSocket.new
      @socket.bind("127.0.0.1", 0)
      @thread = Thread.new { serve }
    end

    def port
      @socket.addr[1]
    end

    def close
      @thread.kill
      @socket.close
    end

    private
      def serve
        loop do
          message, sender = @socket.recvfrom(4096)
          @socket.send(reply_to(message).encode, 0, sender[3], sender[1])
        end
      rescue IOError, Errno::EBADF
        nil
      end

      def reply_to(message)
        query = Resolv::DNS::Message.decode(message)
        reply = Resolv::DNS::Message.new(query.id)
        reply.qr = 1
        reply.rd = query.rd
        reply.ra = 1
        reply.rcode = @rcode

        query.each_question do |name, typeclass|
          reply.add_question(name, typeclass)
          @records.each { |record| reply.add_answer(name, 60, record) }
        end

        reply
      end
  end
end
