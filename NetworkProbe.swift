import Foundation
import Network

class NetworkProbe {
    static func probePorts(host: String, completion: @escaping ([String]) -> Void) {
        let commonPorts: [UInt16: String] = [
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            8080: "HTTP-Alt"
        ]
        
        var results: [String] = []
        let group = DispatchGroup()
        
        for (port, service) in commonPorts {
            group.enter()
            checkPort(host: host, port: port) { isOpen in
                if isOpen {
                    results.append("[!] Port \(port) (\(service)) is OPEN")
                } else {
                    results.append("[✓] Port \(port) (\(service)) is CLOSED")
                }
                group.leave()
            }
        }
        
        group.notify(queue: .main) {
            completion(results)
        }
    }
    
    private static func checkPort(host: String, port: UInt16, completion: @escaping (Bool) -> Void) {
        let hostEndpoint = NWEndpoint.Host(host)
        let portEndpoint = NWEndpoint.Port(rawValue: port) ?? .http
        let connection = NWConnection(host: hostEndpoint, port: portEndpoint, using: .tcp)
        
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                completion(true)
                connection.cancel()
            case .failed, .cancelled:
                completion(false)
            default:
                break
            }
        }
        
        connection.start(queue: .global())
    }
}
