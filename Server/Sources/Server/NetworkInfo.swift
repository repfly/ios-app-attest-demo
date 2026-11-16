import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

enum NetworkInfo {
    struct Address {
        let interface: String
        let address: String
    }

    /// Non-loopback IPv4 addresses of interfaces that are up.
    static func lanIPv4Addresses() -> [Address] {
        var result: [Address] = []
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let ifa = cursor {
            defer { cursor = ifa.pointee.ifa_next }
            let flags = Int32(ifa.pointee.ifa_flags)
            guard let sa = ifa.pointee.ifa_addr,
                  sa.pointee.sa_family == UInt8(AF_INET),
                  flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0
            else { continue }

            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(sa, socklen_t(sa.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                let name = String(cString: ifa.pointee.ifa_name)
                let addr = String(decoding: host.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
                result.append(Address(interface: name, address: addr))
            }
        }
        // Prefer en* (Wi-Fi / Ethernet) first.
        return result.sorted { ($0.interface.hasPrefix("en") ? 0 : 1, $0.interface) < ($1.interface.hasPrefix("en") ? 0 : 1, $1.interface) }
    }
}
