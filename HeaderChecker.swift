import Foundation

final class HeaderChecker: Sendable {
    static let shared = HeaderChecker()
    private init() {}
    
    private let securityHeaders: [String: (Finding.Severity, String)] = [
        "Strict-Transport-Security": (.high, "Missing HSTS - downgrade attacks possible"),
        "X-Content-Type-Options": (.medium, "Missing X-Content-Type-Options - MIME sniffing"),
        "X-Frame-Options": (.medium, "Missing X-Frame-Options - clickjacking"),
        "Content-Security-Policy": (.high, "Missing CSP - XSS and injection possible"),
        "X-XSS-Protection": (.low, "Missing X-XSS-Protection header"),
        "Referrer-Policy": (.low, "Missing Referrer-Policy"),
        "Permissions-Policy": (.info, "Missing Permissions-Policy"),
        "Access-Control-Allow-Origin": (.high, "CORS misconfigured if wildcard")
    ]
    
    func checkHeaders(url: URL) async -> [Finding] {
        var findings: [Finding] = []
        
        do {
            let (_, response) = try await URLSession.shared.data(from: url)
            guard let httpResponse = response as? HTTPURLResponse else {
                return [Finding(severity: .high, description: "Invalid HTTP response received")]
            }
            
            findings.append(Finding(severity: .info, description: "Status: \(httpResponse.statusCode)"))
            let serverHeader = httpResponse.value(forHTTPHeaderField: "Server") ?? "hidden"
            findings.append(Finding(severity: .info, description: "Server: \(serverHeader)"))
            
            if serverHeader.contains("Apache") {
                findings.append(Finding(severity: .info, description: "Apache detected - check for known CVEs"))
            } else if serverHeader.contains("nginx") {
                findings.append(Finding(severity: .info, description: "nginx detected - check version CVEs"))
            } else if serverHeader.contains("Microsoft-IIS") {
                findings.append(Finding(severity: .info, description: "IIS detected - check for vulns"))
            }
            
            let allHeaders = httpResponse.allHeaderFields
            for (header, (severity, desc)) in securityHeaders {
                let isPresent = allHeaders.keys.contains { key in
                    (key as? String)?.lowercased() == header.lowercased()
                }
                
                if !isPresent {
                    findings.append(Finding(severity: severity, description: desc))
                } else if header == "Access-Control-Allow-Origin" {
                    if let aco = httpResponse.value(forHTTPHeaderField: "Access-Control-Allow-Origin"), aco == "*" {
                        findings.append(Finding(severity: .high, description: "CORS wildcard: Access-Control-Allow-Origin: *"))
                    }
                }
            }
            
            if httpResponse.value(forHTTPHeaderField: "X-Powered-By") != nil {
                findings.append(Finding(severity: .low, description: "X-Powered-By reveals tech stack"))
            }
        } catch {
            findings.append(Finding(severity: .high, description: "Failed to connect: \(error.localizedDescription)"))
        }
        
        return findings
    }
}
