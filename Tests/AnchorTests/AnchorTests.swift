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
        do {
            let certificate = try X509.Certificate(bytes: anchorData, format: .der)
            let key = certificate.publicKey
            XCTAssertNotNil(key)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    
    // MARK: - Codable
    
    /*struct CodableData: Codable {
        let data: Data
    }
    
    struct CodableCertificate: Codable {
        let data: X509.Certificate
    }
    
    func testCodable() {
        let url = Resources.nist
            .appendingPathComponent("test1", isDirectory: true)
            .appendingPathComponent("Trust Anchor CP.01.01.crt")
        
        do {
            let data = try Data(contentsOf: url)
            let encoder = JSONEncoder()
            let json = try encoder.encode(CodableData(data: data))
            let certificate = try JSONDecoder().decode(CodableCertificate.self, from: json)
            
            //print(String(data: json, encoding: .utf8)!)
            /*
            
            let json = """
            {
            "certificate": {
            }
            }
            """
            
            let certificate = try JSONDecoder().decode(X509.Certificate.self, from: data)*/
            //let encodedData = try JSONEncoder().encode(certificate)
            //XCTAssertEqual(data, encodedData)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }*/

    static var allTests = [
        ("testNISTCertificateChains", testNISTCertificateChains),
        //("testCodable", testCodable)
        ("testBase64", testBase64)
    ]
}

// TODO:
// - [ ] Fix Codable conformance
// * Check for memory leaks.
// * Get command line tests working: missing resources
// - Use DataProtocol where applicable
// * Avoid casting between [UInt8] and Data where possible
// or at least avoid copying

// - [x] Make API more flexible, allowing for chains of arbitrary length
// as well as intermediate (but untrusted) certificates.
// [x] Consider making Certificate static, e.g. a struct.
// [x] Remove app data and add anonymous tests, including failing certificates.
// [x] Commit.
// [x] Check expiry date
// - [x] Make the API more Swifty (see CryptoKit).
// - [x] Rename CCryptoBoringSSL to AnchorBoringSSL or something similar.
