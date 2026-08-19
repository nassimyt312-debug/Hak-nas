import Foundation
import Security

class SSLAnalyzer {
    static func analyze(url: URL, completion: @escaping (String) -> Void) {
        guard let host = url.host else {
            completion("Invalid Host")
            return
        }
        let session = URLSession(configuration: .default, delegate: SSLDelegate(completion: completion), delegateQueue: nil)
        let task = session.dataTask(with: url)
        task.resume()
    }
}

class SSLDelegate: NSObject, URLSessionDelegate {
    let completion: (String) -> Void
    
    init(completion: @escaping (String) -> Void) {
        self.completion = completion
    }
    
    func urlSession(_ session: URLSession, challenge: URLSessionChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            var error: CFError?
            let isTrusted = SecTrustEvaluateWithError(trust, &error)
            completion(isTrusted ? "SSL Certificate Valid" : "SSL Certificate Untrusted")
        } else {
            completion("No SSL Data Available")
        }
        completionHandler(.performDefaultHandling, nil)
    }
}
