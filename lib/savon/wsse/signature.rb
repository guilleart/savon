require 'rexml/document'
require "savon/wsse/certs"
require 'savon/wsse/canonicalizer'

module Savon
  class WSSE
    class Signature
      
      class EmptyCanonicalization < RuntimeError; end
      class MissingCertificate < RuntimeError; end
      
      # For a +Savon::WSSE::Certs+ object. To hold the certs we need to sign.
      attr_accessor :certs
      
      # Without a document, the document cannot be signed.
      # Generate the document once, and then set document and recall #to_xml
      attr_accessor :document

      #Dynamic signed parts
      attr_accessor :signed_parts

      #Security Context token
      attr_accessor :sct
      
      #Include certificates in the request? 
      attr_accessor :include_certs


      ExclusiveXMLCanonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#'.freeze
      RSASHA1SignatureAlgorithm = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'.freeze
      HMACSignatureAlgorithm = 'http://www.w3.org/2000/09/xmldsig#hmac-sha1'.freeze

      SHA1DigestAlgorithm = 'http://www.w3.org/2000/09/xmldsig#sha1'.freeze
      
      X509v3ValueType = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'.freeze
      SCTValuetype = 'http://schemas.xmlsoap.org/ws/2005/02/sc/sct'.freeze
      Base64EncodingType = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary'.freeze
      
      SignatureNamespace = 'http://www.w3.org/2000/09/xmldsig#'.freeze
      
      def initialize(certs = Certs.new, options = { })
        @certs = certs
        @signed_parts = options[:signed_parts]
        @sct = Nokogiri::XML(options[:security_token]) if options[:security_token]
        @include_certs = options[:include_certs]
        @include_certs = true if @include_certs.nil?
      end
      
      def have_document?
        !!document
      end

      # Cache "now" so that digests match...
      # TODO: figure out how we might want to expire this cache...
      def now
        @now ||= Time.now.utc
      end
      
      def timestamp_id
        @timestamp_id ||= "Timestamp-#{uid}".freeze
      end
      
      def body_id
        @body_id ||= "Body-#{uid}".freeze
      end

      def to_id
        "_1"
      end

      def security_token_id
        @security_token_id ||= "SecurityToken-#{uid}".freeze
      end
      
      def body_attributes
        {
          "xmlns:u" => WSUNamespace,
          "u:Id" => body_id,
        }
      end
      
      def to_xml
        security = {}.deep_merge(timestamp).deep_merge(signature)
        security.deep_merge!(binary_security_token) if certs.cert && @include_certs

        security.merge! :order! => []
        [ "u:Timestamp", "o:BinarySecurityToken", "Signature" ].each do |key|
          security[:order!] << key if security[key]
        end

        xml = Gyoku.xml({
          "o:Security" => security,
          :attributes! => { "o:Security" => {
             'xmlns:o' => WSENamespace,
             's:mustUnderstand' => "1",
          } },
        })
        xml = add_security_context_token(xml) if @sct
        xml
      end

      def add_security_context_token(xml)
        doc = Nokogiri::XML(xml)
        timestamp_node = doc.at_xpath('//u:Timestamp', "u" => "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
        timestamp_node.add_next_sibling(@sct.child.to_xml)
        return doc.child.to_xml
      end
      
    private
    
      def binary_security_token
        {
          "o:BinarySecurityToken" => Base64.encode64(certs.cert.to_der).gsub("\n", ''),
          :attributes! => { "o:BinarySecurityToken" => {
            "u:Id" => security_token_id,
            'EncodingType' => Base64EncodingType,
            'ValueType' => X509v3ValueType,
            "xmlns:u" => WSUNamespace,
          } }
        }
      end
    
      def signature
        return {} unless have_document?
        
        sig = signed_info.merge(key_info).merge(signature_value)
        sig.merge! :order! => []
        [ "SignedInfo", "SignatureValue", "KeyInfo" ].each do |key|
          sig[:order!] << key if sig[key]
        end

        {
          "Signature" => sig,
          :attributes! => { "Signature" => { "xmlns" => SignatureNamespace } },
        }
      end
    
      def key_info
        value_type = @sct.nil? ? X509v3ValueType : SCTValuetype
        security_token = @sct.nil? ? security_token_id : @sct.child["Id"]
        {
          "KeyInfo" => {
            "o:SecurityTokenReference" => {
              "o:Reference/" => nil,
              :attributes! => { "o:Reference/" => {
                "ValueType" => value_type,
                "URI" => "##{security_token}",
              } }
            },
            :attributes! => { "o:SecurityTokenReference" => { "xmlns" => "" } },
          },
        }
      end
      
      def signature_value
        { "SignatureValue" => the_signature }
      rescue EmptyCanonicalization, MissingCertificate
        {}
      end
    
      def signed_info
        signature_method = @sct.nil? ? RSASHA1SignatureAlgorithm : HMACSignatureAlgorithm
        {
          "SignedInfo" => {
            "CanonicalizationMethod/" => nil,
            "SignatureMethod/" => nil,
            "Reference" => reference_signed_parts,
            :attributes! => {
              "CanonicalizationMethod/" => { "Algorithm" => ExclusiveXMLCanonicalizationAlgorithm },
              "SignatureMethod/" => { "Algorithm" => signature_method },
              "Reference" => { "URI" => ["##{timestamp_id}", "##{to_id}"] },
            },
            :order! => [ "CanonicalizationMethod/", "SignatureMethod/", "Reference" ],
          },
        }
      end

      def reference_signed_parts
        @signed_parts.map{ |part|
          signed_info_transforms.merge(signed_info_digest_method).merge({ "DigestValue" => xml_digest(part)})
        }
      end
    
      # We're going to generate the timestamp ourselves, since WSSE is hard-
      # coded to generate the timestamp section directly within wsse:Security.
      #
      # TODO: Allow for configurability of these timestamps.
      def timestamp
        {
          "u:Timestamp" => {
            "u:Created" => now.xs_datetime,
            "u:Expires" => (now + 60 * 5).xs_datetime,
            :order! => ["u:Created", "u:Expires"],
          },
          :attributes! => { "u:Timestamp" => { "u:Id" => timestamp_id, "xmlns:u" => WSUNamespace } },
        }
      end
      
      def the_signature
        raise MissingCertificate, "Expected a private_key for signing" unless certs.private_key
        xml = canonicalize("SignedInfo")
        if @sct
          signature = OpenSSL::HMAC.digest('sha1', certs.cert.to_der, xml)
        else
          signature = certs.private_key.sign(OpenSSL::Digest::SHA1.new, xml)
        end
        breakpoint
        Base64.encode64(signature).gsub("\n", '') # TODO: DRY calls to Base64.encode64(...).gsub("\n", '')
      end
      
      def canonicalize(xml_element)
        canonicalized_element = Canonicalizer.canonicalize(document, xml_element)
        raise EmptyCanonicalization, "Expected to canonicalize #{xml_element.inspect} within: #{document}" if canonicalized_element.blank?
        canonicalized_element
      end

      def xml_digest(xml_element)
        Base64.encode64(OpenSSL::Digest::SHA1.digest(canonicalize(xml_element))).strip
      end
      
      def signed_info_digest_method
        { "DigestMethod/" => nil, :attributes! => { "DigestMethod/" => { "Algorithm" => SHA1DigestAlgorithm } } }
      end
    
      def signed_info_transforms
        { "Transforms" => { "Transform/" => nil, :attributes! => { "Transform/" => { "Algorithm" => ExclusiveXMLCanonicalizationAlgorithm } } } }
      end
      
      def uid
        OpenSSL::Digest::SHA1.hexdigest([Time.now, rand].collect(&:to_s).join('/'))
      end
    end
  end
end
