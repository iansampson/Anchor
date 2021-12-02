//
//  Certificate.swift
//  
//
//  Created by Ian Sampson on 2020-12-17.
//

import CAnchorBoringSSL

// TODO: Namespace to X509.
// To match CryptoKit, e.g. AES.GCM.
// Or make it a type. Certificate<X509>

// MARK: - Public

public enum X509 { }

extension X509 {
    public struct Certificate {
        internal let _certificate: _Certificate
        // TODO: Consider renaming to Storage or Reference.
        public let bytes: [UInt8]
        
        public init<S>(bytes: S, format: SerializationFormat) throws where S : Sequence, S.Element == UInt8 {
            // TODO: Enforce conformance to Contiguous Bytes.
            // TODO: Avoid copying to array.
            let array = Array(bytes)
            self.bytes = array
            _certificate = try _Certificate(bytes: array, format: format)
        }
    }
}

extension X509.Certificate {
    // TODO: Add description
    public enum Error: Swift.Error {
        case failedToDecodeBase64EncodedString
        case failedToLoadCertificate
        case failedToValidateUntrustedCertificate
    }
}

extension X509.Certificate: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.bytes == rhs.bytes
    }
}


// MARK: - Internal

extension X509 {
    internal final class _Certificate {
        internal let _reference: UnsafeMutableRawPointer // <X509>
        
        // TODO: Is this reflection needed?
        // Why not just store the typed pointer?
        internal var reference: UnsafeMutablePointer<CAnchorBoringSSL.X509> {
            return self._reference.assumingMemoryBound(to: CAnchorBoringSSL.X509.self)
        }
        
        private init(withOwnedReference reference: UnsafeMutablePointer<CAnchorBoringSSL.X509>) {
            self._reference = UnsafeMutableRawPointer(reference)
            // Erasing the type for @_implementationOnly import CNIOBoringSSL.
        }
        
        /// Create a Certificate from a buffer of bytes in either PEM or DER format.
        // TODO: Use Data or a Sequence of UInt8 bytes instead of [UInt8].
        
        internal convenience init(bytes: [UInt8], format: SerializationFormat) throws {
            let ref = bytes.withUnsafeBytes { (ptr) -> UnsafeMutablePointer<CAnchorBoringSSL.X509>? in
                let bio = CAnchorBoringSSL_BIO_new_mem_buf(ptr.baseAddress, CInt(ptr.count))!

                defer {
                    CAnchorBoringSSL_BIO_free(bio)
                }

                switch format {
                case .pem:
                    return CAnchorBoringSSL_PEM_read_bio_X509(bio, nil, nil, nil)
                case .der:
                    return CAnchorBoringSSL_d2i_X509_bio(bio, nil)
                }
            }

            if ref == nil {
                throw Certificate.Error.failedToLoadCertificate
            }

            self.init(withOwnedReference: ref!)
        }
        
        deinit {
            CAnchorBoringSSL_X509_free(reference)
        }
    }
}

internal enum BoringSSLError: Error {
    case unknownError
}

/// Extracts the bytes of this certificate in DER format.
///
/// - returns: The DER-encoded bytes for this certificate.
/// - throws: If an error occurred while serializing the certificate.
/*public func toDERBytes() throws -> [UInt8] {
    return try self.withUnsafeDERCertificateBuffer { Array($0) }
}*/
