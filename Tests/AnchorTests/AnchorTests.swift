import XCTest
@testable import Anchor

final class AnchorTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(Anchor().text, "Hello, World!")
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}
