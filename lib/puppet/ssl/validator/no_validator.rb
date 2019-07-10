require 'openssl'
require 'puppet/ssl/validator/interface'

# Performs no SSL verification
#
# @deprecated
# @api private
#
module Puppet
  module SSL
    module Validator
      class NoValidator < Puppet::SSL::Validator::Interface

        def setup_connection(connection)
          connection.verify_mode = OpenSSL::SSL::VERIFY_NONE
        end

        def peer_certs
          []
        end

        def verify_errors
          []
        end
      end
    end
  end
end
