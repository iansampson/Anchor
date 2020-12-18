//
//  Trust.swift
//  
//
//  Created by Ian Sampson on 2020-12-17.
//

import CCryptoBoringSSL


// MARK: - Public

public struct Trust {
    private var _trust: _Trust
    private var chain: [Certificate]
    
    public init(anchor: Certificate) {
        self._trust = _Trust(anchor: anchor._certificate)
        chain = [anchor]
    }
    
    mutating public func validateAndAppend(certificate: Certificate) throws {
        // Copy on write.
        if !isKnownUniquelyReferenced(&_trust) {
            _trust = _Trust(trustedChain: chain.map { $0._certificate })
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
    
    // TODO: Consider adding an immutable method, i.e. validatingAndAppending
    // or simply appending, which returns a new Trust.
}

extension Trust: Equatable {
    public static func == (lhs: Trust, rhs: Trust) -> Bool {
        lhs.chain == rhs.chain
    }
}

// TODO: Add copy-on-write behavior.

// MARK: - Internal

internal final class _Trust {
    private let store: UnsafeMutablePointer<X509_STORE>
    //private var context: UnsafeMutablePointer<X509_STORE_CTX>?
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
    
    /*internal func validateAndAppend(certificate: _Certificate) throws {
        // Retrieve or create context.
        let context: UnsafeMutablePointer<X509_STORE_CTX>
        if let storedContext = self.context {
            CCryptoBoringSSL_X509_STORE_CTX_cleanup(storedContext)
            context = storedContext
        } else {
            guard let newContext = CCryptoBoringSSL_X509_STORE_CTX_new() else {
                fatalError()
            }
            context = newContext
        }
        
        // Initialize context and verify certificate.
        CCryptoBoringSSL_X509_STORE_CTX_init(context, store, certificate.reference, nil)
        let result = CCryptoBoringSSL_X509_verify_cert(context)
        
        if result == 1 {
            // If validation suceeds, append certificate to trust chain.
            CCryptoBoringSSL_X509_STORE_CTX_init(context, store, certificate.reference, nil)
        } else {
            // Otherwise throw an error.
            throw Certificate.Error.failedToValidateUntrustedCertificate
        }
    }*/
    
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
        //CCryptoBoringSSL_X509_STORE_CTX_free(context)
    }
}

// TODO: Consider renaming anchor to root.
/*func validateChain(leaf: Certificate, intermediate: Certificate, anchor: Certificate) throws {
    // You might have an *array* of trusted certificates in the store.
    // Also the certifcate to be verified is not necessarily a leaf.
    // It might be an intermediate certificate.
    // https://www.openssl.org/docs/man1.0.2/man3/X509_STORE_CTX_init.html

    guard let store = CCryptoBoringSSL_X509_STORE_new() else {
        // TODO: Throw an error.
        fatalError()
    }
    
    guard let context = CCryptoBoringSSL_X509_STORE_CTX_new() else {
        CCryptoBoringSSL_X509_STORE_free(store)
        // Throw error.
        fatalError()
    }
    
    CCryptoBoringSSL_X509_STORE_add_cert(store, anchor._certificate.reference)
    CCryptoBoringSSL_X509_STORE_CTX_init(context, store, intermediate._certificate.reference, nil)
    // Consider whether to use any other (untrusted) certificates in the chain.
    let resultA = CCryptoBoringSSL_X509_verify_cert(context)
    
    guard  resultA == 1 else {
        let _ = CCryptoBoringSSL_X509_STORE_CTX_get_error(context)
        // Or: X509_verify_cert_error_string()
        // https://www.openssl.org/docs/man1.0.2/man3/X509_STORE_CTX_get_error.html
        // TODO: Create an enum using the error types listed at
        // https://www.openssl.org/docs/man1.0.2/man3/X509_STORE_CTX_get_error.html.
        CCryptoBoringSSL_X509_STORE_free(store)
        CCryptoBoringSSL_X509_STORE_CTX_free(context)
        throw Certificate.Error.failedToValidateUntrustedCertificate
    }
    
    // Add trusted certificate to store.
    CCryptoBoringSSL_X509_STORE_add_cert(store, intermediate._certificate.reference)
    
    // Clean up context and verify leaf.
    CCryptoBoringSSL_X509_STORE_CTX_cleanup(context)
    CCryptoBoringSSL_X509_STORE_CTX_init(context, store, leaf._certificate.reference, nil)
    let resultB = CCryptoBoringSSL_X509_verify_cert(context)
    
    guard  resultB == 1 else {
        // TODO: Wrap these in classes and free them on deinit.
        CCryptoBoringSSL_X509_STORE_free(store)
        CCryptoBoringSSL_X509_STORE_CTX_free(context)
        throw Certificate.Error.failedToValidateUntrustedCertificate
    }
    
    // Any need to zero out memory?
    
    CCryptoBoringSSL_X509_STORE_free(store)
    CCryptoBoringSSL_X509_STORE_CTX_free(context)
}*/

// You could consider forking swift-crypto.
// But for now this works.

// Ensure context is not nil. Why would it be?
// We’re holding a reference to it.
