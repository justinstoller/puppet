require 'securerandom'
require 'digest'

def custom_attribute_content(template, role, user = 'Justin Stoller')
  uuid = SecureRandom.uuid
  password = Digest::MD5.new.hexdigest(uuid)

  custom_attributes = <<EOF
  custom_attributes:
    pp_uuid: "#{uuid}"
    # challengePassword
    1.2.840.113549.1.9.7: "#{password}"
  extension_requests:
    pp_image_name: "#{template}"
    pp_department: "Engineering"
    pp_network: "delivery.puppetlabs.net"
    pp_cluster: "vmpooler"
    pp_project: "Puppet Server"
    pp_role: "#{role}"
EOF
end

test_name "Setup CSRs and Certs for `puppet cert` testing" do

  oid_mapping = <<EOF
oid_mapping:
  1.3.6.1.4.1.34380.1.2.1.1:
    shortname: "pl_ticket"
    longname: "Ticket ID within Puppet Labs Ticket Tracker"
  1.3.6.1.4.1.34380.1.2.1.2:
    shortname: "pl_epic"
    longname: "Epic ID or Feature Link within Puppet Labs"
  1.3.6.1.4.1.34380.1.3.1:
    shortname: "pp_authorization"
    longname: "Certificate Extension Authorization"
  1.3.6.1.4.1.34380.1.3.13:
    shortname: "pp_auth_role"
    longname: "Puppet Node Role Name for Authorization"
EOF

  # All masters, MoM or Compile
  masters = hosts.select {|h| h['roles'].any? {|r| r == 'master' || r =~ /compile/ }}

  create_remote_file(masters,
                     '/etc/puppetlabs/puppet/custom_trusted_oid_mapping.yaml',
                     oid_mapping)


end
