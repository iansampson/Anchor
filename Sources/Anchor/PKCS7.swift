//
//  PKCS7.swift
//  
//
//  Created by Ian Sampson on 2021-04-09.
//

import CAnchorBoringSSL

public enum PKCS7 { }

extension PKCS7 {
    struct Container {
        let base: _Container
        
        public init<S>(bytes: S, format: SerializationFormat) throws where S :Sequence, S.Element == UInt8 {
            // TODO: Enforce conformance to Contiguous Bytes.
            // TODO: Avoid copying to array.
            let array = Array(bytes)
            //self.bytes = array
            base = try _Container(bytes: array, format: format)
        }
    }
}

extension PKCS7 {
    final class _Container {
        let reference: UnsafeMutablePointer<CAnchorBoringSSL.PKCS7>
        
        init(bytes: [UInt8], format: SerializationFormat) throws {
            let potentialReference = bytes.withUnsafeBytes { pointer -> UnsafeMutablePointer<CAnchorBoringSSL.PKCS7>? in
                let buffer = CAnchorBoringSSL_BIO_new_mem_buf(
                        pointer.baseAddress,
                        CInt(pointer.count))!
                
                defer {
                    CAnchorBoringSSL_BIO_free(buffer)
                }
                
                switch format {
                case .der:
                    let container = CAnchorBoringSSL_d2i_PKCS7_bio(buffer, nil)
                    return container
                case .pem:
                    return CAnchorBoringSSL_PEM_read_bio_PKCS7(buffer, nil, nil, nil)
                }
            }
            
            guard let reference = potentialReference else {
                throw Error.failedToLoadContainer
            }
            
            guard CAnchorBoringSSL_OBJ_obj2nid(reference.pointee.type) == NID_pkcs7_signed else {
                throw Error.missingSignature
            }
            
            // TODO: Check that the container contains data
            //let contents = reference.pointee.d.sign.pointee.contents
            
            self.reference = reference
        }
        
        deinit {
            CAnchorBoringSSL_PKCS7_free(reference)
        }
    }
}

/*extension X509._Chain {
    func validate(_ container: PKCS7._Container) throws {
        // TODO: Initialize BoringSSL for certificate verification
        // BoringSSL has no method PKCS7_verify (by design)
        //CAnchorBoringSSL_PKCS7
    }
}*/

/*extension PKCS7._Container {
    var payload: Int {
        // BoringSSL also doesn’t let you extract the data
        // sign.pointee has no property contents
        // Alternatives: Use OpenSSL
        // or extract the data with your ASN.1 parser
    }
}*/

extension PKCS7 {
    enum Error: Swift.Error {
        case failedToLoadContainer
        case missingSignature
    }
}
