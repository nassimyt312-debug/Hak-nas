import UIKit
import Foundation
import Security

@MainActor
final class VulnScannerVC: UIViewController {
    
    private let textView = UITextView()
    private let targetField = UITextField()
    private let scanButton = UIButton(type: .system)
    
    private var results: [Finding] = []
    private var isScanning = false
    
    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        setupUI()
    }
    
    private func setupUI() {
        targetField.translatesAutoresizingMaskIntoConstraints = false
        scanButton.translatesAutoresizingMaskIntoConstraints = false
        textView.translatesAutoresizingMaskIntoConstraints = false
        
        targetField.backgroundColor = UIColor(white: 0.1, alpha: 1)
        targetField.layer.cornerRadius = 8
        targetField.textColor = .green
        targetField.placeholder = "https://target.com"
        targetField.keyboardType = .URL
        targetField.autocorrectionType = .no
        targetField.autocapitalizationType = .none
        
        scanButton.setTitle("START SCAN", for: .normal)
        scanButton.backgroundColor = UIColor(red: 0, green: 0.5, blue: 0, alpha: 1)
        scanButton.setTitleColor(.white, for: .normal)
        scanButton.layer.cornerRadius = 8
        scanButton.addTarget(self, action: #selector(startScanTapped), for: .touchUpInside)
        
        textView.backgroundColor = UIColor(white: 0.05, alpha: 1)
        textView.textColor = .green
        textView.font = UIFont(name: "Menlo", size: 12)
        textView.layer.cornerRadius = 8
        textView.isEditable = false
        
        view.addSubview(targetField)
        view.addSubview(scanButton)
        view.addSubview(textView)
        
        NSLayoutConstraint.activate([
            targetField.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 20),
            targetField.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            targetField.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            targetField.heightAnchor.constraint(equalToConstant: 44),
            
            scanButton.topAnchor.constraint(equalTo: targetField.bottomAnchor, constant: 12),
            scanButton.leadingAnchor.constraint(equalTo: targetField.leadingAnchor),
            scanButton.trailingAnchor.constraint(equalTo: targetField.trailingAnchor),
            scanButton.heightAnchor.constraint(equalToConstant: 45),
            
            textView.topAnchor.constraint(equalTo: scanButton.bottomAnchor, constant: 16),
            textView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            textView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            textView.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -16)
        ])
    }
    
    @objc private func startScanTapped() {
        guard !isScanning else { return }
        
        guard let text = targetField.text,
              let url = URL(string: text),
              url.scheme != nil,
              url.host != nil else {
            log("[!] INVALID TARGET URL")
            return
        }
        
        Task {
            await runScan(url: url)
        }
    }
    
    private func runScan(url: URL) async {
        isScanning = true
        scanButton.isEnabled = false
        results.removeAll()
        textView.text = ""
        
        log("═══ INITIALIZING SCAN ═══")
        
        await withTaskGroup(of: (String, [Finding]).self) { group in
            group.addTask {
                let sslFindings = await SSLAnalyzer.shared.checkTLS(url: url)
                return ("SSL/TLS ANALYSIS", sslFindings)
            }
            
            group.addTask {
                let headerFindings = await HeaderChecker.shared.checkHeaders(url: url)
                return ("HTTP HEADERS", headerFindings)
            }
            
            if let host = url.host {
                group.addTask {
                    let netFindings = await NetworkProbe.shared.probePorts(host: host)
                    return ("NETWORK PROBE", netFindings)
                }
            }
            
            for await (section, findings) in group {
                log("── \(section) ──")
                for finding in findings {
                    self.addFinding(finding)
                }
            }
        }
        
        auditLocalAppSecurity()
        
        log("═══ SCAN COMPLETE ═══")
        log("Total findings: \(results.count)")
        
        isScanning = false
        scanButton.isEnabled = true
    }
    
    private func auditLocalAppSecurity() {
        log("── LOCAL APP AUDIT ──")
        
        if Bundle.main.infoDictionary?["NSAppTransportSecurity"] != nil {
            addFinding(Finding(severity: .high, description: "ATS exceptions found - potential transport security risks"))
        }
        
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecReturnAttributes: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess {
            addFinding(Finding(severity: .info, description: "Keychain entries accessible"))
        }
        
        let jailbreakPaths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt"
        ]
        for path in jailbreakPaths {
            if FileManager.default.fileExists(atPath: path) {
                addFinding(Finding(severity: .critical, description: "Jailbreak indicator found: \(path)"))
            }
        }
        
        if UIPasteboard.general.hasStrings {
            addFinding(Finding(severity: .medium, description: "Sensitive data in pasteboard"))
        }
        
        if let urlTypes = Bundle.main.infoDictionary?["CFBundleURLTypes"] as? [[String: Any]] {
            for urlType in urlTypes {
                if let schemes = urlType["CFBundleURLSchemes"] as? [String] {
                    addFinding(Finding(severity: .low, description: "Custom URL scheme: \(schemes.joined(separator: ", "))"))
                }
            }
        }
    }
    
    private func addFinding(_ finding: Finding) {
        results.append(finding)
        log("[\(finding.severity.rawValue)] \(finding.description)")
    }
    
    private func log(_ message: String) {
        textView.text += "\(message)\n"
        if !textView.text.isEmpty {
            let range = NSRange(location: textView.text.count - 1, length: 1)
            textView.scrollRangeToVisible(range)
        }
    }
}
@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        window = UIWindow(frame: UIScreen.main.bounds)
        window?.rootViewController = VulnScannerVC()
        window?.makeKeyAndVisible()
        return true
    }
}
