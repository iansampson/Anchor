//
//  Certificate+Foundation.swift
//  
//
//  Created by Ian Sampson on 2020-12-18.
//

import Foundation

extension X509.Certificate {
    public init(contentsOf url: URL, format: SerializationFormat) throws {
        let data = try Data(contentsOf: url)
        try self.init(bytes: data, format: format)
    }
}
