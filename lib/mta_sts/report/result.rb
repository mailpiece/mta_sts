module MtaSts
  class Report
    class Result
      attr_reader :status, :report, :comment

      def initialize(status:, report: nil, comment: nil)
        @status, @report, @comment = status, report, comment
      end

      def found?
        status == "found"
      end

      def no_record?
        status == "none"
      end

      def temperror?
        status == "temperror"
      end

      def permerror?
        status == "permerror"
      end

      def rua
        report&.rua || []
      end

      def inspect
        "#<#{self.class.name} status: #{status.inspect}, report: #{report.inspect}, comment: #{comment.inspect}>"
      end
    end
  end
end
