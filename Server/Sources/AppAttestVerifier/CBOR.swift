import Foundation

/// A decoded CBOR data item (RFC 8949). Only what App Attest needs is supported:
/// definite-length items of every major type, plus tags and simple values.
public indirect enum CBORValue: Equatable, Sendable {
    case unsigned(UInt64)
    /// Negative integer, stored as the raw CBOR argument `n`; the value is `-1 - n`.
    case negative(UInt64)
    case bytes([UInt8])
    case text(String)
    case array([CBORValue])
    case map([(key: CBORValue, value: CBORValue)])
    case tagged(UInt64, CBORValue)
    case bool(Bool)
    case null
    case undefined
    case simple(UInt8)
    case float(Double)

    public static func == (lhs: CBORValue, rhs: CBORValue) -> Bool {
        switch (lhs, rhs) {
        case let (.unsigned(a), .unsigned(b)): return a == b
        case let (.negative(a), .negative(b)): return a == b
        case let (.bytes(a), .bytes(b)): return a == b
        case let (.text(a), .text(b)): return a == b
        case let (.array(a), .array(b)): return a == b
        case let (.map(a), .map(b)):
            return a.count == b.count && zip(a, b).allSatisfy { $0.key == $1.key && $0.value == $1.value }
        case let (.tagged(t1, v1), .tagged(t2, v2)): return t1 == t2 && v1 == v2
        case let (.bool(a), .bool(b)): return a == b
        case (.null, .null), (.undefined, .undefined): return true
        case let (.simple(a), .simple(b)): return a == b
        case let (.float(a), .float(b)): return a == b || (a.isNaN && b.isNaN)
        default: return false
        }
    }

    /// Looks up a text key in a map. Returns nil for non-maps or missing keys.
    public subscript(key: String) -> CBORValue? {
        guard case let .map(pairs) = self else { return nil }
        return pairs.first(where: { $0.key == .text(key) })?.value
    }

    public var bytesValue: [UInt8]? {
        if case let .bytes(b) = self { return b }
        return nil
    }

    public var textValue: String? {
        if case let .text(t) = self { return t }
        return nil
    }

    public var arrayValue: [CBORValue]? {
        if case let .array(a) = self { return a }
        return nil
    }
}

public enum CBORError: Error, Equatable, CustomStringConvertible {
    case unexpectedEnd(offset: Int)
    case indefiniteLengthNotSupported(offset: Int)
    case reservedAdditionalInfo(offset: Int)
    case invalidUTF8(offset: Int)
    case lengthTooLarge(offset: Int)
    case nestingTooDeep
    case trailingBytes(count: Int)

    public var description: String {
        switch self {
        case let .unexpectedEnd(o): return "unexpected end of input at byte \(o)"
        case let .indefiniteLengthNotSupported(o): return "indefinite-length item at byte \(o) is not supported"
        case let .reservedAdditionalInfo(o): return "reserved additional-info value at byte \(o)"
        case let .invalidUTF8(o): return "text string at byte \(o) is not valid UTF-8"
        case let .lengthTooLarge(o): return "declared length at byte \(o) exceeds the remaining input"
        case .nestingTooDeep: return "nesting deeper than the allowed maximum"
        case let .trailingBytes(n): return "\(n) trailing byte(s) after the top-level item"
        }
    }
}

/// Minimal, strict CBOR decoder. Rejects indefinite-length items and trailing bytes.
public struct CBORDecoder {
    private let bytes: [UInt8]
    private var offset = 0
    private let maxDepth: Int

    private init(bytes: [UInt8], maxDepth: Int) {
        self.bytes = bytes
        self.maxDepth = maxDepth
    }

    /// Decodes exactly one CBOR item spanning the whole input.
    public static func decode(_ data: [UInt8], maxDepth: Int = 32) throws -> CBORValue {
        var decoder = CBORDecoder(bytes: data, maxDepth: maxDepth)
        let value = try decoder.readItem(depth: 0)
        if decoder.offset != data.count {
            throw CBORError.trailingBytes(count: data.count - decoder.offset)
        }
        return value
    }

    public static func decode(_ data: Data, maxDepth: Int = 32) throws -> CBORValue {
        try decode([UInt8](data), maxDepth: maxDepth)
    }

    private var remaining: Int { bytes.count - offset }

    private mutating func readByte() throws -> UInt8 {
        guard offset < bytes.count else { throw CBORError.unexpectedEnd(offset: offset) }
        defer { offset += 1 }
        return bytes[offset]
    }

    private mutating func readBytes(_ count: Int) throws -> [UInt8] {
        guard count <= remaining else { throw CBORError.unexpectedEnd(offset: offset) }
        defer { offset += count }
        return Array(bytes[offset..<(offset + count)])
    }

    private mutating func readUInt(byteCount: Int) throws -> UInt64 {
        var value: UInt64 = 0
        for b in try readBytes(byteCount) { value = (value << 8) | UInt64(b) }
        return value
    }

    /// Reads the argument for the given additional info (low 5 bits of the initial byte).
    private mutating func readArgument(_ info: UInt8, at start: Int) throws -> UInt64 {
        switch info {
        case 0...23: return UInt64(info)
        case 24: return try readUInt(byteCount: 1)
        case 25: return try readUInt(byteCount: 2)
        case 26: return try readUInt(byteCount: 4)
        case 27: return try readUInt(byteCount: 8)
        case 31: throw CBORError.indefiniteLengthNotSupported(offset: start)
        default: throw CBORError.reservedAdditionalInfo(offset: start)
        }
    }

    /// Converts a length argument to Int, requiring that at least `minBytesPerElement * n` bytes remain.
    private func checkedLength(_ n: UInt64, minBytesPerElement: Int, at start: Int) throws -> Int {
        guard n <= UInt64(Int.max / max(minBytesPerElement, 1)),
              Int(n) * minBytesPerElement <= remaining
        else { throw CBORError.lengthTooLarge(offset: start) }
        return Int(n)
    }

    private mutating func readItem(depth: Int) throws -> CBORValue {
        guard depth <= maxDepth else { throw CBORError.nestingTooDeep }
        let start = offset
        let initial = try readByte()
        let major = initial >> 5
        let info = initial & 0x1F

        switch major {
        case 0:
            return .unsigned(try readArgument(info, at: start))
        case 1:
            return .negative(try readArgument(info, at: start))
        case 2:
            let n = try checkedLength(try readArgument(info, at: start), minBytesPerElement: 1, at: start)
            return .bytes(try readBytes(n))
        case 3:
            let n = try checkedLength(try readArgument(info, at: start), minBytesPerElement: 1, at: start)
            guard let s = String(bytes: try readBytes(n), encoding: .utf8) else {
                throw CBORError.invalidUTF8(offset: start)
            }
            return .text(s)
        case 4:
            let n = try checkedLength(try readArgument(info, at: start), minBytesPerElement: 1, at: start)
            var items: [CBORValue] = []
            items.reserveCapacity(n)
            for _ in 0..<n { items.append(try readItem(depth: depth + 1)) }
            return .array(items)
        case 5:
            let n = try checkedLength(try readArgument(info, at: start), minBytesPerElement: 2, at: start)
            var pairs: [(key: CBORValue, value: CBORValue)] = []
            pairs.reserveCapacity(n)
            for _ in 0..<n {
                let k = try readItem(depth: depth + 1)
                let v = try readItem(depth: depth + 1)
                pairs.append((k, v))
            }
            return .map(pairs)
        case 6:
            let tag = try readArgument(info, at: start)
            return .tagged(tag, try readItem(depth: depth + 1))
        default: // major 7
            switch info {
            case 20: return .bool(false)
            case 21: return .bool(true)
            case 22: return .null
            case 23: return .undefined
            case 24: return .simple(try readByte())
            case 25: return .float(Double(Float16Bits.decode(UInt16(try readUInt(byteCount: 2)))))
            case 26: return .float(Double(Float(bitPattern: UInt32(try readUInt(byteCount: 4)))))
            case 27: return .float(Double(bitPattern: try readUInt(byteCount: 8)))
            case 31: throw CBORError.indefiniteLengthNotSupported(offset: start)
            case 28...30: throw CBORError.reservedAdditionalInfo(offset: start)
            default: return .simple(info)
            }
        }
    }
}

/// IEEE 754 half-precision decoding without relying on `Float16` (unavailable on some platforms).
enum Float16Bits {
    static func decode(_ h: UInt16) -> Float {
        let sign: Float = (h & 0x8000) != 0 ? -1 : 1
        let exp = Int((h >> 10) & 0x1F)
        let frac = Float(h & 0x3FF)
        switch exp {
        case 0: return sign * frac * powf(2, -24)
        case 31: return frac == 0 ? sign * .infinity : .nan
        default: return sign * (1 + frac / 1024) * powf(2, Float(exp - 15))
        }
    }
}
