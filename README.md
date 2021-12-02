# Anchor

A Swift package for validating X.509 certificate chains. Based on BoringSSL.


## Installation

Anchor is distributed with the [Swift Package Manager](https://swift.org/package-manager/).
Add the following code to your `Package.swift` manifest.

``` Swift
let package = Package(
    ...
    dependencies: [
        .package(url: "https://github.com/iansampson/Anchor", .branch("main"))
    ],
    ...
)
```

## Usage

``` Swift
// Load a trusted root certificate in either PEM or DER format
let rootCertificateData = Data(contentsOf: ...)

// Initialize a `Certificate` struct, specifying the format
let rootCertificate = try X509.Certificate(bytes: rootCertificateData, format: .pem)

// Use the root certificate to construct a chain
var chain = X509.Chain(trustAnchor: rootCertificate)

// Load untrusted intermediary or leaf certificates
let intermediaryCertificate = ...
let leafCertificate = ...

// Validate and append them in order
try chain.validateAndAppend(certificates: [intermediaryCertificate, leafCertificate])
```

If the last method returns without throwing an error,
all the certificates have been validated and can be trusted.

Warning: Always initialize the `X509.Chain` with a trusted certificate,
never an untrusted one.

The combination of validation and appending into a single method
is designed to prevent users from accidentally appending
untrusted certificates As long as the root certificate
is trustworthy, the rest of the chain is too.

You can also retrieve a certificate’s public key:

``` Swift
leafCertificate.publicKey // Returns optional Data
```
