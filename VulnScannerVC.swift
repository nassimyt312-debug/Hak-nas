import UIKit

class VulnScannerVC: UIViewController, UITableViewDelegate, UITableViewDataSource {
    
    private let urlTextField = UITextField()
    private let scanButton = UIButton(type: .system)
    private let tableView = UITableView()
    private var results: [String] = []
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
    }
    
    private func setupUI() {
        view.backgroundColor = .systemBackground
        title = "Vulnerability Scanner"
        
        urlTextField.placeholder = "https://example.com"
        urlTextField.borderStyle = .roundedRect
        urlTextField.autocapitalizationType = .none
        urlTextField.translatesAutoresizingMaskIntoConstraints = false
        
        scanButton.setTitle("بدء الفحص", for: .normal)
        scanButton.titleLabel?.font = .boldSystemFont(ofSize: 16)
        scanButton.backgroundColor = .systemBlue
        scanButton.setTitleColor(.white, for: .normal)
        scanButton.layer.cornerRadius = 8
        scanButton.addTarget(self, action: #selector(startScan), for: .touchUpInside)
        scanButton.translatesAutoresizingMaskIntoConstraints = false
        
        tableView.delegate = self
        tableView.dataSource = self
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "cell")
        tableView.translatesAutoresizingMaskIntoConstraints = false
        
        view.addSubview(urlTextField)
        view.addSubview(scanButton)
        view.addSubview(tableView)
        
        NSLayoutConstraint.activate([
            urlTextField.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 20),
            urlTextField.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            urlTextField.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            urlTextField.heightAnchor.constraint(equalToConstant: 44),
            
            scanButton.topAnchor.constraint(equalTo: urlTextField.bottomAnchor, constant: 12),
            scanButton.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            scanButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            scanButton.heightAnchor.constraint(equalToConstant: 44),
            
            tableView.topAnchor.constraint(equalTo: scanButton.bottomAnchor, constant: 20),
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
    }
    
    @objc private func startScan() {
        guard let text = urlTextField.text, let url = URL(string: text), url.scheme != nil else {
            results = ["[!] يرجى إدخال رابط صحيح (مثال: https://example.com)"]
            tableView.reloadData()
            return
        }
        
        results = ["[i] جاري بدء فحص الأمان لـ \(url.host ?? text)..."]
        tableView.reloadData()
        
        // فحص رؤوس الأمان HTTP
        HeaderChecker.checkHeaders(url: url) { [weak self] findings in
            DispatchQueue.main.async {
                self?.results.append(contentsOf: findings)
                self?.tableView.reloadData()
            }
        }
        
        // فحص SSL
        SSLAnalyzer.analyze(url: url) { [weak self] result in
            DispatchQueue.main.async {
                self?.results.append(result)
                self?.tableView.reloadData()
            }
        }
        
        // فحص المنافذ Network
        if let host = url.host {
            NetworkProbe.probePorts(host: host) { [weak self] findings in
                DispatchQueue.main.async {
                    self?.results.append(contentsOf: findings)
                    self?.tableView.reloadData()
                }
            }
        }
    }
    
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return results.count
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "cell", for: indexPath)
        cell.textLabel?.text = results[indexPath.row]
        cell.textLabel?.numberOfLines = 0
        cell.textLabel?.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        return cell
    }
}

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        window = UIWindow(frame: UIScreen.main.bounds)
        let nav = UINavigationController(rootViewController: VulnScannerVC())
        window?.rootViewController = nav
        window?.makeKeyAndVisible()
        return true
    }
}
