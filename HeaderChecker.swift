import Foundation

class HeaderChecker {
    static func checkHeaders(url: URL, completion: @escaping ([String]) -> Void) {
        var request = URLRequest(url: url)
        request.httpMethod = "HEAD"
        
        let task = URLSession.shared.dataTask(with: request) { _, response, _ in
            guard let httpResponse = response as? HTTPURLResponse else {
                completion(["[!] Unable to fetch headers"])
                return
            }
            
            var findings: [String] = []
            let securityHeaders = [
                "Strict-Transport-Security",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Content-Security-Policy",
                "X-XSS-Protection"
            ]
            
            for header in securityHeaders {
                if let value = httpResponse.allHeaderFields[header] as? String {
                    findings.append("[✓] \(header): \(value)")
                } else {
                    findings.append("[✕] Missing Header: \(header)")
                }
            }
            
            completion(findings)
        }
        task.resume()
    }
}
