import XCTest

@testable import Osprey

/// The Swift half of the framing has to agree with `osprey-core`'s Rust half
/// byte for byte; these assertions mirror that crate's own tests.
final class NoiseFramingTests: XCTestCase {
    func testChunkBoundaryMath() {
        XCTAssertEqual(NoiseFraming.maxChunkPayloadLength, 65518)
        XCTAssertEqual(NoiseFraming.maxPlaintextLength, 65519)
    }

    func testEmptyPayloadStillProducesOneFinalChunk() {
        let chunks = NoiseFraming.split(Data())
        XCTAssertEqual(chunks, [Data([0x00])])
    }

    func testSplitAtTheChunkCeiling() {
        let exact = Data(repeating: 7, count: NoiseFraming.maxChunkPayloadLength)
        XCTAssertEqual(NoiseFraming.split(exact).count, 1)

        let oneOver = Data(repeating: 7, count: NoiseFraming.maxChunkPayloadLength + 1)
        XCTAssertEqual(NoiseFraming.split(oneOver).count, 2)

        let exactTwo = NoiseFraming.split(
            Data(repeating: 7, count: NoiseFraming.maxChunkPayloadLength * 2))
        XCTAssertEqual(exactTwo.count, 2)
        XCTAssertEqual(exactTwo[0].first, 0x01)
        XCTAssertEqual(exactTwo[1].first, 0x00)
    }

    func testSplitAndReassembleRoundTrips() throws {
        let payload = Data((0..<200_000).map { UInt8($0 % 251) })
        var reassembled = Data()
        for chunk in NoiseFraming.split(payload) {
            let (isFinal, body) = try NoiseFraming.splitChunkHeader(chunk)
            reassembled.append(body)
            if isFinal { break }
        }
        XCTAssertEqual(reassembled, payload)
    }

    func testUnknownContinuationFlagIsRejected() {
        XCTAssertThrowsError(try NoiseFraming.splitChunkHeader(Data([0x02, 1, 2, 3]))) { error in
            XCTAssertEqual(error as? NoiseFramingError, .badContinuationFlag(0x02))
        }
        XCTAssertThrowsError(try NoiseFraming.splitChunkHeader(Data())) { error in
            XCTAssertEqual(error as? NoiseFramingError, .emptyChunk)
        }
    }

    func testLengthPrefixIsBigEndian() throws {
        XCTAssertEqual(try NoiseFraming.lengthPrefix(0x0102), Data([0x01, 0x02]))
        XCTAssertEqual(try NoiseFraming.frameLength(Data([0xFF, 0xFF])), 65535)
        XCTAssertEqual(try NoiseFraming.frameLength(Data([0x00, 0x05])), 5)
    }

    func testAFrameOverTheNoiseCeilingIsRejected() {
        XCTAssertThrowsError(try NoiseFraming.lengthPrefix(65536)) { error in
            XCTAssertEqual(
                error as? NoiseFramingError, .frameTooLarge(length: 65536, max: 65535))
        }
    }

    func testChunkCeilingMatchesTheAgent() {
        XCTAssertEqual(
            NoiseFraming.maxChunks(forMessageLength: 4 * 1024 * 1024),
            (4 * 1024 * 1024) / 65518 + 2)
    }
}
