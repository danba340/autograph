import XCTest

@testable import Autograph

final class KeyPairTests: XCTestCase {
    func testGenerateIdentityKeyPair() throws {
        let emptyKeyPair = Autograph.Bytes(repeating: 0, count: 64)
        let keyPair = try Autograph.generateIdentityKeyPair()
        XCTAssertEqual(keyPair.count, 64)
        XCTAssertNotEqual(keyPair, emptyKeyPair)
    }

    func testGenerateEphemeralKeyPair() throws {
        let emptyKeyPair = Autograph.Bytes(repeating: 0, count: 64)
        let keyPair = try Autograph.generateKeyPair()
        XCTAssertEqual(keyPair.count, 64)
        XCTAssertNotEqual(keyPair, emptyKeyPair)
    }
}
