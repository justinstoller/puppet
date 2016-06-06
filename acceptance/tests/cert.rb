require 'securerandom'
require 'digest'

WHITELIST =  %w{uuid password image dept net user cluster proj role auth_role auth}
def custom_attribute_content(role = 'webserver',
                             auth_role = 'puppet infrastructure',
                             user = 'Justin Stoller',
                             uuid = SecureRandom.uuid,
                             password = Digest::MD5.new.hexdigest(uuid),
                             whitelist = WHITELIST)

  custom_attributes = "custom_attributes:\n"
  custom_attributes << "  pp_uuid: '#{uuid}'\n" if whitelist.include?('uuid')
  custom_attributes << "  1.2.840.113549.1.9.7: '#{password}'\n" if whitelist.include?('password') # oid for challengePassword
  custom_attributes << "  1.3.6.1.4.1.34380.1.3.13: '#{auth_role}'\n" if whitelist.include?('auth_role')
  custom_attributes << "  1.3.6.1.4.1.34380.1.3.1: 'true'\n" if whitelist.include?('auth')
  custom_attributes << "extension_requests:\n"
  custom_attributes << "  pp_image_name: 'redhat-7-x86_64'\n" if whitelist.include?('image')
  custom_attributes << "  pp_department: 'Engineering'\n" if whitelist.include?('dept')
  custom_attributes << "  pp_network: 'delivery.puppetlabs.net'\n" if whitelist.include?('net')
  custom_attributes << "  pp_cluster: 'vmpooler'\n" if whitelist.include?('cluster')
  custom_attributes << "  pp_employee: '#{user}'\n" if whitelist.include?('user')
  custom_attributes << "  pp_project: 'Puppet Server'\n" if whitelist.include?('proj')
  custom_attributes << "  pp_role: '#{role}'\n" if whitelist.include?('role')
end

def create_non_root_agent(host, name, custom_cert_info)
  on host, "useradd -Um #{name}"
  on host, "mkdir -p /home/#{name}/.puppetlabs/etc/puppet"
  create_remote_file(host,
                     "/home/#{name}/.puppetlabs/etc/puppet/csr_attributes.yaml",
                     custom_cert_info)

  create_remote_file(host,
                     "/home/#{name}/.puppetlabs/etc/puppet/puppet.conf",
                     "[agent]\n  server=#{master}\n  certname=#{name}.delivery.puppetlabs.net")

  on host, "chown -R #{name}:#{name} /home/#{name}"
  on host, "su - #{name} -c 'puppet agent -t --debug'", :acceptable_exit_codes => [0,1]
end

def create_csr(host, role = 'agent')
  name = "pp" + @user_index.to_s
  custom_cert_info = custom_attribute_content(role = role)
  create_non_root_agent(host, name, custom_cert_info)
  @user_index += 1
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

  create_remote_file(master,
                     '/etc/puppetlabs/puppet/custom_trusted_oid_mapping.yaml',
                     oid_mapping)

  @user_index = 0
  on master, puppet("master")

  step "Create revoked Certs" do
    create_csr(master, 'compile master')
    create_csr(master, 'master of masters')
    2.times { create_csr(master, 'agent') }

    name = "pp" + @user_index.to_s
    custom_cert_info =
      custom_attribute_content('app-frontend',
                               'general infrastructure',
                               'Joe Q Employee')
    create_non_root_agent(master, name, custom_cert_info)
    @user_index += 1

    on master, puppet("cert sign --all")
    4.times do |i|
      on master, puppet("cert clean pp#{i}.delivery.puppetlabs.net")
    end
  end


  step "Create signed Certs" do
    2.times { create_csr(master, 'compile master') }
    create_csr(master, 'compile master')
    create_csr(master, 'puppetdb')
    create_csr(master, 'dashboard')
    10.times { create_csr(master, 'agent') }

    name = "pp" + @user_index.to_s
    custom_cert_info =
      custom_attribute_content('app-frontend',
                               'general infrastructure',
                               'Joe Q Employee')
    create_non_root_agent(master, name, custom_cert_info)
    @user_index += 1

    on master, puppet("cert sign --all")
  end

  step "Create pending CSRs" do
    3.times { create_csr(master, 'agent') }
    create_csr(master, 'compile master')
    create_csr(master, 'master of masters')

    name = "pp" + @user_index.to_s
    custom_cert_info =
      custom_attribute_content('app-frontend',
                               'general infrastructure',
                               'Joe Q Employee')
    create_non_root_agent(master, name, custom_cert_info)
    @user_index += 1

    name = "pp" + @user_index.to_s
    custom_cert_info =
      custom_attribute_content('app-frontend',
                               'general infrastructure',
                               'Joe Q Employee')
    create_non_root_agent(master, name, custom_cert_info)
    @user_index += 1

    3.times do
      name = "pp" + @user_index.to_s
      custom_cert_info =
        custom_attribute_content('a host',
                                 'infrastructure',
                                 'Bob',
                                 SecureRandom.uuid,
                                 Digest::MD5.new.hexdigest(uuid),
                                 WHITELIST.shuffle[0,2])
      create_non_root_agent(master, name, custom_cert_info)
      @user_index += 1
    end
  end
end
