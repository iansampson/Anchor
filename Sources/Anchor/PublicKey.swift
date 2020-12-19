//
//  PublicKey.swift
//  
//
//  Created by Ian Sampson on 2020-12-18.
//

import CAnchorBoringSSL
import Foundation

extension X509.Certificate {
    public var publicKey: Data? { // Or Data?
        return _certificate.publicKey.map { Data($0) }
    }
    
    // Make a PublicKey type like the ones in CryptoKit.
    // (Although that requires us to know what kind of key it is.)
    // var derRepresentation: Data
    // var pemRepresentation: String
}

// MARK: - Internal

extension X509._Certificate {
    /// Obtain the public key for this `Certificate`.
    /// - returns: This certificate's `NIOSSLPublicKey`.
    /// Extracts the bytes of this public key in the SubjectPublicKeyInfo format.
    ///
    /// The SubjectPublicKeyInfo format is defined in RFC 5280. In addition to the raw key bytes, it also
    /// provides an identifier of the algorithm, ensuring that the key can be unambiguously decoded.
    /// - returns: The DER-encoded SubjectPublicKeyInfo bytes for this public key.
    
    // TODO: Consider extracting the key when initializing the certificate
    // and saving the data as a constant.
    // if the key cannot be serialized, the certificate is invalid anyway.
    internal var publicKey: [UInt8]? {
        guard let key = CAnchorBoringSSL_X509_get_pubkey(reference) else {
            fatalError("Failed to extract a public key reference")
        }
        
        defer {
            CAnchorBoringSSL_EVP_PKEY_free(key)
        }
        
        guard let bio = CAnchorBoringSSL_BIO_new(CAnchorBoringSSL_BIO_s_mem()) else {
            fatalError("Failed to malloc for a BIO handler")
        }
        
        defer {
            CAnchorBoringSSL_BIO_free(bio)
        }
        
        let rc = CAnchorBoringSSL_i2d_PUBKEY_bio(bio, key)
        
        /// - throws: If an error occurred while serializing the key.
        guard rc == 1 else {
            //throw BoringSSLError.unknownError
            return nil
            // TODO: Does this ever happen?
        }
        
        var dataPtr: UnsafeMutablePointer<CChar>? = nil
        let length = CAnchorBoringSSL_BIO_get_mem_data(bio, &dataPtr)
        
        guard let bytes = dataPtr.map({ UnsafeMutableRawBufferPointer(start: $0, count: length) }) else {
            fatalError("Failed to map bytes from a public key")
        }
        
        let data = Array(bytes)
        
        // Decode DER-encoded SPKI into raw bytes.
        do {
            let node = try ASN1.parse(data)
            let keyInfo = try ASN1.SubjectPublicKeyInfo(asn1Encoded: node)
            return(Array(keyInfo.key.bytes))
        } catch {
            print(error.localizedDescription)
            return nil
        }
        // TODO: Consider throwing errors.
        // Either here or when you initialize the certificate.
        // Note: this doesn’t work for some kinds of keys
        // (including the NIST examples used in tests.)
    }
}
