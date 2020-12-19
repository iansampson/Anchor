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
    
    public init(base64Encoded string: String, format: SerializationFormat) throws {
        guard let data = Data(base64Encoded: string) else {
            throw Error.failedToDecodeBase64EncodedString
        }
        try self.init(bytes: data, format: format)
    }
}

/*extension X509.Certificate: Codable {
    public init(from decoder: Decoder) throws {
        let data = try Data.init(from: decoder)
        do {
            try self.init(bytes: data, format: .der)
        } catch {
            try self.init(bytes: data, format: .pem)
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        try Data(self.bytes).encode(to: encoder)
    }
}*/
