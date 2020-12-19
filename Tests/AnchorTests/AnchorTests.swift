//
//  AnchorTests.swift
//
//
//  Created by Ian Sampson on 2020-12-18.
//

import XCTest
@testable import Anchor

// https://csrc.nist.gov/Projects/pki-testing/X-509-Path-Validation-Test-Suite

final class AnchorTests: XCTestCase {
    var anchorData: Data {
        let url = Resources.nist
            .appendingPathComponent("test1", isDirectory: true)
            .appendingPathComponent("Trust Anchor CP.01.01.crt")
        return try! Data(contentsOf: url)
    }
    
    func testNISTCertificateChains() {
        NIST.tests.forEach {
            let url = Resources.nist
                .appendingPathComponent("test\($0.number)", isDirectory: true)
            do {
                try NIST.validateCertificateChain(at: url)
                switch $0.expectedResult {
                case .valid:
                    return
                case .invalid:
                    XCTFail("Validated invalid chain in Test\($0.number).")
                }
            } catch {
                switch $0.expectedResult {
                case .valid:
                    XCTFail("Test\($0.number) failed with error: \(error.localizedDescription)")
                    return
                case .invalid:
                    // Test succeeded.
                    return
                }
            }
        }
    }
    
    func testBase64() {
        do {
            let string = anchorData.base64EncodedString()
            let certificate = try X509.Certificate(base64Encoded: string, format: .der)
            let encodedString = Data(certificate.bytes).base64EncodedString()
            XCTAssertEqual(string, encodedString)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func testPublicKey() {
        let expectedKey = Data(base64Encoded: "BEUx4Zi1tOwE2hUCBFcE7U+HcnLXYTWyYRbPyIthXQoABxm6aYWN/nfKo7g54CDd1lYUFARwKDHkP3C4j9bDlLYI6ivWrmHp9ZjBL0avUpNyZuV/FOth/sUw9xRPU4EuNQ==")!
        
        do {
            let url = Resources.apple.appendingPathComponent("AppleAppAttestAttestationRootCA.cert")
            let data = try Data(contentsOf: url)
            let certificate = try X509.Certificate(bytes: data, format: .pem)
            XCTAssertEqual(certificate.publicKey, expectedKey)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    static var allTests = [
        ("testNISTCertificateChains", testNISTCertificateChains),
        ("testBase64", testBase64),
        ("testPublicKey", testPublicKey)
    ]
}

// TODO:
// - [ ] Fix Codable conformance
// * Check for memory leaks.
// * Get command line tests working: missing resources
// - Use DataProtocol where applicable
// * Avoid casting between [UInt8] and Data where possible
// or at least avoid copying
// - [ ] Add error descriptions
// - [ ] Document public API
// - [ ] Get publicKey to work with RSA keys (as in the NIST examples)

// - [x] Make API more flexible, allowing for chains of arbitrary length
// as well as intermediate (but untrusted) certificates.
// [x] Consider making Certificate static, e.g. a struct.
// [x] Remove app data and add anonymous tests, including failing certificates.
// [x] Commit.
// [x] Check expiry date
// - [x] Make the API more Swifty (see CryptoKit).
// - [x] Rename CCryptoBoringSSL to AnchorBoringSSL or something similar.
