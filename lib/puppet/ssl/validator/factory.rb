
module Puppet
  module SSL
    module Validator
      module Factory
        # Factory method for creating an instance of a null/no validator.
        # This method does not have to be implemented by concrete implementations of this API.
        #
        # @return [Puppet::SSL::Validator::Interface] produces a validator that performs no validation
        #
        # @api public
        #
        def no_validator()
          @@no_validator_cache ||= Puppet::SSL::Validator::NoValidator.new()
        end

        # Factory method for creating an instance of the default Puppet validator.
        # This method does not have to be implemented by concrete implementations of this API.
        #
        # @return [Puppet::SSL::Validator::Interface] produces a validator that performs no validation
        #
        # @api public
        #
        def default_validator()
          Puppet::SSL::Validator::DefaultValidator.new()
        end
      end
    end
  end
end
