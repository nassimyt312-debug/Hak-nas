import Foundation
import Security

struct Finding: Sendable {
    enum Severity: String, Sendable {
        case info = "INFO"
        case low = "LOW"
        case medium = "MEDIUM"
        case high = "HIGH"
        case critical = "CRITICAL"
        case ok = "OK"
    }
    
    let severity: Severity
    let description: String
}

final class SSLAnalyzer: Sendable {
    static let shared = SSLAnalyzer()
    private init() {}
    
    func checkTLS(url: URL) async -> [Finding] {
        var findings: [Finding] = []
        
        if let redirectFinding = await checkHTTPRedirect(for: url) {
            findings.append(redirectFinding)
        }
        
        let certFindings = await checkCertificate(url: url)
        findings.append(contentsOf: certFindings)
        
        return findings
    }
    
    private func checkHTTPRedirect(for url: URL) async -> Finding? {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        components.scheme = "http"
        guard let httpURL = components.url else { return nil }
        
        do {
            let (_, response) = try await URLSession.shared.data(from: httpURL)
            if let httpResponse = response as? HTTPURLResponse {
                if httpResponse.url?.scheme == "https" {
                    return Finding(severity: .ok, description: "HTTP->HTTPS redirect present")
                } else {
                    return Finding(severity: .high, description: "No HTTPS redirect - data in plaintext")
                }
            }
        } catch {
            return Finding(severity: .info, description: "HTTP connection refused: \(error.localizedDescription)")
        }
        return nil
    }
    
    private func checkCertificate(url: URL) async -> [Finding] {
        await withCheckedContinuation { continuation in
            let delegate = CertDelegate { certs in
                let findings = self.analyzeCertificates(certs)
                continuation.resume(returning: findings)
            }
            let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
            let task = session.dataTask(with: url)
            task.resume()
        }
    }
    
    private func analyzeCertificates(_ certs: [SecCertificate]) -> [Finding] {
        var findings: [Finding] = []
        for cert in certs {
            if let commonName = SecCertificateCopyCommonName(cert) as String? {
                findings.append(Finding(severity: .info, description: "Cert CN: \(commonName)"))
                if commonName.hasPrefix("*.") {
                    findings.append(Finding(severity: .low, description: "Wildcard certificate in use"))
                }
            }
            
            let keys = [kSecPropertyKeyTypeLabel] as CFArray
            if let props = SecCertificateCopyValues(cert, keys, nil) as? [CFString: Any] {
                for (_, value) in props {
                    if let dict = value as? [String: Any],
                       let label = dict[kSecPropertyKeyTypeLabel as String] as? String,
                       label == "Expires",
                       let expiryDate = dict[kSecPropertyKeyValue as String] as? Date {
                        let days = Calendar.current.dateComponents([.day], from: Date(), to: expiryDate).day ?? 0
                        if days < 30 {
                            findings.append(Finding(severity: .high, description: "Cert expires in \(days) days"))
                        }
                    }
                }
            }
        }
        return findings
    }
}

private final class CertDelegate: NSObject, URLSessionDelegate, Sendable {
    private let handler: @Sendable ([SecCertificate]) -> Void
    
    init(_ handler: @escaping @Sendable ([SecCertificate]) -> Void) {
        self.handler = handler
    }
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if let trust = challenge.protectionSpace.serverTrust,
           let certChain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] {
            handler(certChain)
        } else {
            handler([])
        }
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
