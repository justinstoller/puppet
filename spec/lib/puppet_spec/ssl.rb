require 'openssl'

module PuppetSpec
  module SSL

    PRIVATE_KEY_LENGTH = 2048
    FIVE_YEARS = 5 * 365 * 24 * 60 * 60
    CA_EXTENSIONS = [
      ["basicConstraints", "CA:TRUE", true],
      ["keyUsage", "keyCertSign, cRLSign", true],
      ["subjectKeyIdentifier", "hash", false],
      ["authorityKeyIdentifier", "keyid:always", false]
    ]
    NODE_EXTENSIONS = [
      ["keyUsage", "digitalSignature", true],
      ["subjectKeyIdentifier", "hash", false]
    ]
    DEFAULT_SIGNING_DIGEST = OpenSSL::Digest::SHA256.new
    DEFAULT_REVOCATION_REASON = OpenSSL::OCSP::REVOKED_STATUS_KEYCOMPROMISE


    def self.create_private_key(length = PRIVATE_KEY_LENGTH)
      OpenSSL::PKey::RSA.new(length)
    end

    def self.self_signed_ca(key, name)
      cert = OpenSSL::X509::Certificate.new

      cert.public_key = key.public_key
      cert.subject = OpenSSL::X509::Name.parse(name)
      cert.issuer = cert.subject
      cert.version = 2
      cert.serial = rand(2**128)

      not_before = just_now
      cert.not_before = not_before
      cert.not_after = not_before + FIVE_YEARS

      ext_factory = extension_factory_for(cert, cert)
      CA_EXTENSIONS.each do |ext|
        extension = ext_factory.create_extension(*ext)
        cert.add_extension(extension)
      end

      cert.sign(key, DEFAULT_SIGNING_DIGEST)

      cert
    end

    def self.create_csr(key, name)
      csr = OpenSSL::X509::Request.new

      csr.public_key = key.public_key
      csr.subject = OpenSSL::X509::Name.parse(name)
      csr.version = 2
      csr.sign(key, DEFAULT_SIGNING_DIGEST)

      csr
    end

    def self.sign(ca_key, ca_cert, csr, extensions = NODE_EXTENSIONS)
      cert = OpenSSL::X509::Certificate.new

      cert.public_key = csr.public_key
      cert.subject = csr.subject
      cert.issuer = ca_cert.subject
      cert.version = 2
      cert.serial = rand(2**128)

      not_before = just_now
      cert.not_before = not_before
      cert.not_after = not_before + FIVE_YEARS

      ext_factory = extension_factory_for(ca_cert, cert)
      extensions.each do |ext|
        extension = ext_factory.create_extension(*ext)
        cert.add_extension(extension)
      end

      cert.sign(ca_key, DEFAULT_SIGNING_DIGEST)

      cert
    end

    def self.create_crl_for(ca_cert, ca_key)
      crl = OpenSSL::X509::CRL.new
      crl.version = 1
      crl.issuer = ca_cert.subject

      ef = extension_factory_for(ca_cert)
      crl.add_extension(
        ef.create_extension(["authorityKeyIdentifier", "keyid:always", false]))
      crl.add_extension(
        OpenSSL::X509::Extension.new("crlNumber", OpenSSL::ASN1::Integer(0)))

      not_before = just_now
      crl.last_update = not_before
      crl.next_update = not_before + FIVE_YEARS
      crl.sign(ca_key, DEFAULT_SIGNING_DIGEST)

      crl
    end

    def self.revoke(serial, crl, ca_key)
      revoked = OpenSSL::X509::Revoked.new
      revoked.serial = serial
      revoked.time = Time.now
      revoked.add_extension(
        OpenSSL::X509::Extension.new("CRLReason",
                                     OpenSSL::ASN1::Enumerated(DEFAULT_REVOCATION_REASON)))

      crl.add_revoked(revoked)
      extensions = crl.extensions.group_by{|e| e.oid == 'crlNumber' }
      crl_number = extensions[true].first
      unchanged_exts = extensions[false]

      next_crl_number = crl_number.value.to_i + 1
      new_crl_number_ext = OpenSSL::X509::Extension.new("crlNumber",
                                                        OpenSSL::ASN1::Integer(next_crl_number))

      crl.extensions = unchanged_exts + [new_crl_number_ext]
      crl.sign(ca_key, DEFAULT_SIGNING_DIGEST)

      crl
    end

    def self.create_root_ca(cn)
      key = create_private_key
      cert = self_signed_ca(key, "/CN=#{cn}")
      crl = create_crl_for(cert, key)

      [key, cert, crl]
    end

    def self.create_intermediate_ca(cn, issuer_key, issuer_cert)
      key = create_private_key
      csr = create_csr(key, "/CN=#{cn}")
      cert = sign(issuer_key, issuer_cert, csr, CA_EXTENSIONS)
      crl = create_crl_for(cert, key)

      [key, cert, crl]
    end

    def self.create_signed_node_cert(cn, issuer_key, issuer_cert)
      key = create_private_key
      csr = create_csr(key, "/CN=#{cn}")
      sign(issuer_key, issuer_cert, csr)
    end

    def self.create_revoked_node_cert(cn, issuer_key, issuer_cert, issuer_crl)
      key = create_private_key
      csr = create_csr(key, "/CN=#{cn}")
      cert = sign(issuer_key, issuer_cert, csr)
      revoke(cert.serial, issuer_crl, issuer_key)

      cert
    end

    def self.bundle(*items)
      items.map(&:to_pem).join("\n")
    end

    # Creates a self-signed root ca, then signs two node certs, revoking one of them.
    # Creates an intermediate CA and one node cert off of it.
    # Creates a leaf CA off of the intermediate CA, then signs two node certs revoking one of them.
    # Revokes the intermediate CA.
    # Returns the ca bundle, crl chain, and all the node certs
    def self.create_chained_pki
      root_key, root_cert, root_crl = create_root_ca('root-ca')
      int_key, int_cert, int_crl = create_intermediate_ca('revoked-int-ca', root_key, root_cert)
      leaf_key, leaf_cert, leaf_crl = create_intermediate_ca('leaf-ca', int_key, int_cert)

      unrevoked_root_node_cert = create_signed_node_cert('unrevoked-root-node', root_key, root_cert)
      revoked_root_node_cert = create_revoked_node_cert('revoked-root-node', root_key, root_cert, root_crl)
      unrevoked_int_node_cert = create_signed_node_cert('unrevoked-int-node', int_key, int_cert)
      unrevoked_leaf_node_cert = create_signed_node_cert('unrevoked-leaf-node', leaf_key, leaf_cert)
      revoked_leaf_node_cert = create_revoked_node_cert('revoked-leaf-node', leaf_key, leaf_cert, leaf_crl)

      revoke(int_cert.serial, root_crl, root_key)

      ca_bundle = bundle(root_cert, int_cert, leaf_cert)
      crl_chain = bundle(root_crl, int_crl, leaf_crl)

      {
        :revoked_root_node_cert => revoked_root_node_cert,
        :revoked_leaf_node_cert => revoked_leaf_node_cert,
        :unrevoked_root_node_cert => unrevoked_root_node_cert,
        :unrevoked_int_node_cert  => unrevoked_int_node_cert,
        :unrevoked_leaf_node_cert => unrevoked_leaf_node_cert,
        :ca_bundle => ca_bundle,
        :crl_chain => crl_chain,
      }
    end

   private

    def self.just_now
      Time.now - 1
    end

    def self.extension_factory_for(ca, cert = nil)
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.issuer_certificate  = ca
      ef.subject_certificate = cert if cert

      ef
    end
  end
end
