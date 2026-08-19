import Foundation

class SSLAnalyzer {
    static func analyze(url: URL, completion: @escaping (String) -> Void) {
        let session = URLSession(configuration: .default)
        let task = session.dataTask(with: url) { _, response, error in
            if let error = error {
                completion("[✕] SSL Error: \(error.localizedDescription)")
                return
            }
            if let httpResponse = response as? HTTPURLResponse {
                completion("[✓] SSL Connection Successful (Status: \(httpResponse.statusCode))")
            } else {
                completion("[✓] SSL Connection Established")
            }
        }
        task.resume()
    }
}
