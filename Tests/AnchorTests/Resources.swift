//
//  Resources.swift
//  
//
//  Created by Ian Sampson on 2020-12-18.
//

import Foundation

enum Resources {
    static let root: URL = Bundle.module.resourceURL!
        .appendingPathComponent("Resources", isDirectory: true)
    static let nist: URL = Resources.root
        .appendingPathComponent("NISTX509PathValidationTestSuite", isDirectory: true)
    static let apple: URL = Resources.root
        .appendingPathComponent("ApplePrivatePKI", isDirectory: true)
}
