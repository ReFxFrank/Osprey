import XCTest

@testable import Osprey

final class HexTests: XCTestCase {
    func testRoundTrip() throws {
        let bytes = Data([0x00, 0x01, 0x7F, 0x80, 0xFF, 0xAB])
        XCTAssertEqual(Hex.encode(bytes), "00017f80ffab")
        XCTAssertEqual(try Hex.decode("00017f80ffab"), bytes)
    }

    func testUppercaseDecodes() throws {
        XCTAssertEqual(try Hex.decode("DEADBEEF"), Data([0xDE, 0xAD, 0xBE, 0xEF]))
    }

    func testEmpty() throws {
        XCTAssertEqual(Hex.encode(Data()), "")
        XCTAssertEqual(try Hex.decode(""), Data())
    }

    func testOddLengthIsRejected() {
        XCTAssertThrowsError(try Hex.decode("abc")) { error in
            XCTAssertEqual(error as? HexError, .oddLength(3))
        }
    }

    func testNonHexIsRejected() {
        XCTAssertThrowsError(try Hex.decode("zz")) { error in
            XCTAssertEqual(error as? HexError, .invalidByte(0x7A))
        }
    }

    func testFixedLengthIsEnforced() {
        XCTAssertThrowsError(try Hex.decode("aabb", expecting: 32)) { error in
            XCTAssertEqual(error as? HexError, .unexpectedLength(expected: 32, found: 2))
        }
    }
}
