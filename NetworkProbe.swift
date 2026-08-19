import Foundation

final class NetworkProbe: Sendable {
    static let shared = NetworkProbe()
    private init() {}
    
    private let commonPorts: [Int: String] = [
        21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP",
        110: "POP3", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 6379: "Redis",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        27017: "MongoDB"
    ]
    
    func probePorts(host: String) async -> [Finding] {
        await withTaskGroup(of: Finding?.self) { group in
            for (port, service) in commonPorts {
                group.addTask {
                    let isOpen = self.testConnection(host: host, port: port, timeout: 2.0)
                    if isOpen {
                        let severity: Finding.Severity = (port == 80 || port == 443) ? .ok : .medium
                        return Finding(severity: severity, description: "Port \(port) (\(service)) OPEN")
                    }
                    return nil
                }
            }
            
            var results: [Finding] = []
            for await finding in group {
                if let finding = finding {
                    results.append(finding)
                }
            }
            return results
        }
    }
    
    private func testConnection(host: String, port: Int, timeout: TimeInterval) -> Bool {
        guard let address = getAddress(for: host) else { return false }
        
        let sock = socket(Int32(address.ss_family), SOCK_STREAM, 0)
        guard sock >= 0 else { return false }
        defer { close(sock) }
        
        let flags = fcntl(sock, F_GETFL, 0)
        _ = fcntl(sock, F_SETFL, flags | O_NONBLOCK)
        
        var addr = address
        let connectResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, socklen_t(MemoryLayout<sockaddr_storage>.size))
            }
        }
        
        if connectResult == 0 { return true }
        
        if errno == EINPROGRESS {
            var fdSet = fd_set()
            fdSetZero(&fdSet)
            fdSetSet(sock, &fdSet)
            
            var timeoutVal = timeval(tv_sec: Int(timeout), tv_usec: 0)
            let selectResult = select(sock + 1, nil, &fdSet, nil, &timeoutVal)
            
            if selectResult > 0 {
                var error: Int32 = 0
                var len = socklen_t(MemoryLayout<Int32>.size)
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len)
                return error == 0
            }
        }
        
        return false
    }
    
    private func fdSetZero(_ set: inout fd_set) {
        set.fds_bits = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    }
    
    private func fdSetSet(_ fd: Int32, _ set: inout fd_set) {
        let intOffset = Int(fd) / 32
        let bitOffset = Int(fd) % 32
        withUnsafeMutablePointer(to: &set.fds_bits) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).bindMemory(to: Int32.self, capacity: 32)
            raw[intOffset] |= (1 << bitOffset)
        }
    }
    
    private func getAddress(for host: String) -> sockaddr_storage? {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let addrInfo = result else {
            return nil
        }
        defer { freeaddrinfo(addrInfo) }
        
        var storage = sockaddr_storage()
        memcpy(&storage, addrInfo.pointee.ai_addr, Int(min(addrInfo.pointee.ai_addrlen, socklen_t(MemoryLayout<sockaddr_storage>.size))))
        
        return storage
    }
}
