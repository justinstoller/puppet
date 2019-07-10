module Puppet
  module SSL
    module Validator
      class Interface
        # Array of peer certificates
        # @return [Array<Puppet::SSL::Certificate>] peer certificates
        #
        # @api public
        #
        def peer_certs
          raise NotImplementedError, "Concrete class should have implemented this method"
        end

        # Contains the result of validation
        # @return [Array<String>, nil] nil, empty Array, or Array with messages
        #
        # @api public
        #
        def verify_errors
          raise NotImplementedError, "Concrete class should have implemented this method"
        end

        # Registers the connection to validate.
        #
        # @param [Net::HTTP] connection The connection to validate
        #
        # @return [void]
        #
        # @api public
        #
        def setup_connection(connection)
          raise NotImplementedError, "Concrete class should have implemented this method"
        end
      end
    end
  end
end
