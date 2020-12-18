//
//  AnchorTests.swift
//
//
//  Created by Ian Sampson on 2020-12-18.
//

import XCTest
@testable import Anchor

// https://csrc.nist.gov/Projects/pki-testing/X-509-Path-Validation-Test-Suite

final class NISTTests: XCTestCase {
    func testCertificateChains() {
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

    static var allTests = [
        ("testCertificateChains", testCertificateChains)
    ]
}

// TODO:
// [x] Make the API more Swifty (see CryptoKit).
// * Rename CCryptoBoringSSL to AnchorBoringSSL or something similar.
// * Check for memory leaks.
// * Get command line tests working: missing resources

// - [x] Make API more flexible, allowing for chains of arbitrary length
// as well as intermediate (but untrusted) certificates.
// [x] Consider making Certificate static, e.g. a struct.
// [x] Remove app data and add anonymous tests, including failing certificates.
// [x] Commit.
// [x] Check expiry date
