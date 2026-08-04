import Foundation

/// One point on the dashboard's charts.
///
/// A view-model type rather than a wire type: `metrics.history` arrives as
/// parallel arrays located by `start_ts + N * interval_ms`, and `metrics.tick`
/// arrives one at a time, but a chart wants a single sequence of timestamped
/// values either way.
public struct MetricSample: Identifiable, Hashable, Sendable {
    /// Sample time in milliseconds, which is also what makes it unique within a
    /// series.
    public let id: Int64
    public let cpuPercent: Double
    public let memUsedBytes: UInt64
    /// `nil` means the agent could not determine throughput for that interval —
    /// an adapter appeared, vanished, or had its counters reset. Distinct from
    /// zero, and charted as a gap rather than as an idle link.
    public let netRxBytesPerSec: UInt64?
    public let netTxBytesPerSec: UInt64?

    public var timestamp: Date { Date(timeIntervalSince1970: Double(id) / 1000) }

    public init(
        atMilliseconds: Int64,
        cpuPercent: Double,
        memUsedBytes: UInt64,
        netRxBytesPerSec: UInt64?,
        netTxBytesPerSec: UInt64?
    ) {
        self.id = atMilliseconds
        self.cpuPercent = cpuPercent
        self.memUsedBytes = memUsedBytes
        self.netRxBytesPerSec = netRxBytesPerSec
        self.netTxBytesPerSec = netTxBytesPerSec
    }
}

extension MetricsTickBody {
    public var sample: MetricSample {
        MetricSample(
            atMilliseconds: ts,
            cpuPercent: cpuPercent,
            memUsedBytes: memUsedBytes,
            netRxBytesPerSec: netRxBytesPerSec,
            netTxBytesPerSec: netTxBytesPerSec)
    }

    /// Per-volume usage, paired up from the body's parallel arrays.
    ///
    /// Truncated to the shortest array rather than trusted to be equal length:
    /// the arrays are only parallel by convention, and reading past the end of
    /// one to label an entry in another would mislabel a volume.
    public var volumes: [VolumeUsage] {
        let count = min(diskLabels.count, min(diskUsedBytes.count, diskTotalBytes.count))
        return (0..<count).map { index in
            VolumeUsage(
                label: diskLabels[index],
                usedBytes: diskUsedBytes[index],
                totalBytes: diskTotalBytes[index])
        }
    }
}

public struct VolumeUsage: Identifiable, Hashable, Sendable {
    public var id: String { label }
    public let label: String
    public let usedBytes: UInt64
    public let totalBytes: UInt64

    public var usedFraction: Double {
        guard totalBytes > 0 else { return 0 }
        return Double(usedBytes) / Double(totalBytes)
    }
}

extension MetricsHistoryBody {
    /// Expand the fixed-cadence arrays into timestamped samples.
    ///
    /// Sample N sits at `startTs + N * intervalMs`; the body carries no
    /// timestamp array, which is what lets a 24-hour backfill fit one message.
    /// A zero interval would stack every point on one instant, so it yields
    /// nothing rather than a misleading vertical line.
    public var samples: [MetricSample] {
        guard intervalMs > 0 else { return [] }
        let count = min(cpuPercent.count, memUsedBytes.count)
        return (0..<count).map { index in
            MetricSample(
                atMilliseconds: startTs + Int64(index) * Int64(intervalMs),
                cpuPercent: cpuPercent[index],
                memUsedBytes: memUsedBytes[index],
                netRxBytesPerSec: index < netRxBytesPerSec.count
                    ? netRxBytesPerSec[index] : nil,
                netTxBytesPerSec: index < netTxBytesPerSec.count
                    ? netTxBytesPerSec[index] : nil)
        }
    }
}

/// Human-readable byte counts, for axis labels and captions.
public enum ByteFormat {
    /// `ByteCountFormatStyle` rather than a shared `ByteCountFormatter`: the
    /// latter is a mutable class, so a `static let` of one is not
    /// concurrency-safe and Swift 6 rejects it outright. The format style is a
    /// value type, so there is nothing to share.
    public static func string(_ bytes: UInt64) -> String {
        Int64(clamping: bytes).formatted(.byteCount(style: .memory))
    }

    public static func rate(_ bytesPerSecond: UInt64?) -> String {
        guard let bytesPerSecond else { return "—" }
        return "\(string(bytesPerSecond))/s"
    }
}
