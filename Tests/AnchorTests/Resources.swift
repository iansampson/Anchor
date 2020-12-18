//
//  Resources.swift
//  
//
//  Created by Ian Sampson on 2020-12-18.
//

import Foundation

enum Resources {
    static let root: URL = Bundle.module.resourceURL!
    static let nist: URL = Resources.root
        .appendingPathComponent("Resources", isDirectory: true)
        .appendingPathComponent("NISTX509PathValidationTestSuite", isDirectory: true)
}
