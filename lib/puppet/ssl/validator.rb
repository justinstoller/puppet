
require 'puppet/ssl/validator/no_validator'
require 'puppet/ssl/validator/default_validator'
require 'puppet/ssl/validator/factory'
require 'puppet/ssl/validator/interface'

# API for certificate verification
#
# @deprecated
# @api public
module Puppet
  module SSL
    module Validator
      extend Puppet::SSL::Validator::Factory
    end
  end
end
