//
//  Trust.swift
//  
//
//  Created by Ian Sampson on 2020-12-17.
//

import CCryptoBoringSSL


// MARK: - Public

extension X509 {
    public struct Chain {
        private var _trust: _Chain
        private var chain: [Certificate]
        
        public init(anchor: Certificate) {
            self._trust = _Chain(anchor: anchor._certificate)
            chain = [anchor]
        }
        
        mutating public func validateAndAppend(certificate: Certificate) throws {
            // Copy on write.
            if !isKnownUniquelyReferenced(&_trust) {
                _trust = _Chain(trustedChain: chain.map { $0._certificate })
                // TODO: Reconstruct context if needed.
            }
            try _trust.validateAndAppend(certificate: certificate._certificate)
            chain.append(certificate)
        }
        
        mutating public func validateAndAppend(certificates: [Certificate]) throws {
            try certificates.forEach {
                try validateAndAppend(certificate: $0)
            }
        }
        
        public func validatingAndAppending(certificate: Certificate) throws -> Self {
            var trust = self
            try trust.validateAndAppend(certificate: certificate)
            // TODO: Is it possible to avoid copying self?
            return trust
        }
    }
}

extension X509.Chain: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.chain == rhs.chain
    }
}


// MARK: - Internal

extension X509.Chain {
    internal final class _Chain {
        internal typealias Certificate = X509.Certificate
        internal typealias _Certificate = X509._Certificate
        
        private let store: UnsafeMutablePointer<X509_STORE>
        // TODO: Do we need to hold onto a reference to the store?
        // Could we just retain a list of certificates and reconstruct
        // the store each time?
        
        internal init(anchor: _Certificate) {
            guard let store = CCryptoBoringSSL_X509_STORE_new() else {
                // TODO: Throw an error.
                fatalError()
            }
            self.store = store
            CCryptoBoringSSL_X509_STORE_add_cert(store, anchor.reference)
        }
        
        internal init(trustedChain: [_Certificate]) {
            guard let store = CCryptoBoringSSL_X509_STORE_new() else {
                // TODO: Throw an error.
                fatalError()
            }
            self.store = store
            trustedChain.forEach { certificate in
                CCryptoBoringSSL_X509_STORE_add_cert(store, certificate.reference)
            }
        }
        
        internal func validateAndAppend(certificate: _Certificate) throws {
            guard let context = CCryptoBoringSSL_X509_STORE_CTX_new() else {
                fatalError()
            }
            
            defer {
                CCryptoBoringSSL_X509_STORE_CTX_free(context)
            }
            
            CCryptoBoringSSL_X509_STORE_CTX_init(context, store, certificate.reference, nil)
            let result = CCryptoBoringSSL_X509_verify_cert(context)
            if result == 1 {
                // If validation suceeds, append certificate to trust chain.
                CCryptoBoringSSL_X509_STORE_add_cert(store, certificate.reference)
            } else {
                //let _ = CCryptoBoringSSL_X509_STORE_CTX_get_error(context)
                // TODO: Retrieve error and cast to an enum.
                throw Certificate.Error.failedToValidateUntrustedCertificate
            }
        }
        
        deinit {
            CCryptoBoringSSL_X509_STORE_free(store)
        }
    }

}
