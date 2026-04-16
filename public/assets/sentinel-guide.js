/**
 * SENTINEL v2 — Bảng hướng dẫn người dùng
 * Được chèn vào renderer qua index.html
 * Tạo GuidePanel ở cạnh phải workspace, bật/tắt bằng nút "Hướng dẫn" trên header
 */
(function () {
  'use strict';

  // ── Dữ liệu hướng dẫn ──────────────────────────────────────────────────────

  const GUIDE_TABS = ['Bắt đầu', 'URL Scan', 'Project Scan', 'Kết quả', 'Lỗ hổng'];

  const GETTING_STARTED = [
    {
      icon: '🛡️',
      title: 'SENTINEL là gì?',
      open: true,
      content: `
        <div class="guide-step"><div class="guide-step-num">1</div>
          <div class="guide-step-text">SENTINEL là công cụ kiểm thử bảo mật web theo chuẩn <strong>OWASP Top 10 — 2025</strong>, chạy trực tiếp trên máy (Electron app), không cần cài server riêng.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">2</div>
          <div class="guide-step-text">Hỗ trợ hai chế độ: <strong>URL Scan</strong> (kiểm thử black-box từ xa) và <strong>Project Scan</strong> (phân tích source code tĩnh).</div>
        </div>
        <div class="guide-tip">
          <span class="guide-tip-icon">💡</span>
          <span class="guide-tip-text"><strong>Khuyến nghị:</strong> Chạy cả hai chế độ để phát hiện đầy đủ lỗ hổng — URL tìm lỗi runtime, Project tìm lỗi source code.</span>
        </div>
      `
    },
    {
      icon: '⚙️',
      title: 'Quy trình sử dụng cơ bản',
      open: false,
      content: `
        <div class="guide-step"><div class="guide-step-num">1</div>
          <div class="guide-step-text">Chọn tab <strong>URL Scan</strong> hoặc <strong>Project Scan</strong> trên thanh điều hướng.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">2</div>
          <div class="guide-step-text">Điền thông tin mục tiêu (URL hoặc thư mục dự án), cấu hình tùy chọn nếu cần.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">3</div>
          <div class="guide-step-text">Nhấn <strong>Bắt đầu quét</strong> — theo dõi tiến trình thời gian thực trong panel log.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">4</div>
          <div class="guide-step-text">Xem kết quả ở tab <strong>Kết quả</strong>, tổng hợp checklist ở tab <strong>Checklist</strong>.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">5</div>
          <div class="guide-step-text">Export báo cáo dạng <code>HTML</code> hoặc <code>JSON</code> để lưu hoặc chia sẻ.</div>
        </div>
      `
    },
    {
      icon: '📁',
      title: 'Lịch sử scan',
      open: false,
      content: `
        <div class="guide-step"><div class="guide-step-num">1</div>
          <div class="guide-step-text">Mỗi lần scan thành công được lưu vào <strong>Lịch sử quét</strong> (tối đa 10 mục).</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">2</div>
          <div class="guide-step-text">Nhấn nút <strong>Lịch sử</strong> ở góc phải header để xem lịch sử và nhấn vào một mục để khôi phục kết quả.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">3</div>
          <div class="guide-step-text">Có thể xóa toàn bộ lịch sử bằng nút <strong>Xóa tất cả</strong> bên trong dropdown.</div>
        </div>
      `
    }
  ];

  const URL_SCAN_GUIDE = [
    {
      icon: '🎯',
      title: 'Nhập URL mục tiêu',
      open: true,
      content: `
        <div class="guide-step"><div class="guide-step-num">1</div>
          <div class="guide-step-text">Nhập URL đầy đủ bao gồm <code>https://</code>, ví dụ: <code>https://example.com</code> hoặc <code>http://localhost:3000</code>.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">2</div>
          <div class="guide-step-text">Nhấn <strong>Enter</strong> hoặc nút <strong>Bắt đầu quét</strong> màu vàng để bắt đầu.</div>
        </div>
        <div class="guide-warn">
          <span class="guide-warn-icon">⚠️</span>
          <span class="guide-warn-text">Chỉ scan URL mà bạn có quyền kiểm thử. Không scan hệ thống của người khác mà không được phép.</span>
        </div>
      `
    },
    {
      icon: '🔬',
      title: 'Crawl Depth & Request Budget',
      open: false,
      content: `
        <div class="guide-step"><div class="guide-step-num">1</div>
          <div class="guide-step-text"><strong>Crawl Depth:</strong> Số lớp link được duyệt từ URL gốc. <code>0</code> = chỉ URL chính; <code>1</code> = URL chính + các link trực tiếp (khuyến nghị); <code>2</code> = sâu hơn, chậm hơn.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">2</div>
          <div class="guide-step-text"><strong>Request Budget:</strong> Tổng số HTTP request tối đa. Budget cao = kiểm tra injection nhiều hơn nhưng tốn thời gian hơn.</div>
        </div>
        <div class="guide-tip">
          <span class="guide-tip-icon">💡</span>
          <span class="guide-tip-text"><strong>Gợi ý:</strong> Depth 1 + Budget 60 là cấu hình cân bằng tốt nhất (~30–60 giây). Dùng Budget 200 cho mục tiêu quan trọng cần kiểm tra kỹ.</span>
        </div>
      `
    },
    {
      icon: '🔑',
      title: 'Xác thực (Authentication)',
      open: false,
      content: `
        <div class="guide-step"><div class="guide-step-num">1</div>
          <div class="guide-step-text">Mở rộng mục <strong>Authentication</strong> để scan các trang yêu cầu đăng nhập.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">2</div>
          <div class="guide-step-text"><strong>Cookie:</strong> Dán cookie từ browser (DevTools → Application → Cookies), dạng <code>session=abc123; token=xyz</code>.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">3</div>
          <div class="guide-step-text"><strong>Bearer Token:</strong> Token JWT, dán giá trị <code>eyJhbGci…</code> (không cần prefix "Bearer").</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">4</div>
          <div class="guide-step-text"><strong>Custom Headers:</strong> JSON object, ví dụ <code>{"X-API-Key": "abc123"}</code>.</div>
        </div>
      `
    }
  ];

  const PROJECT_SCAN_GUIDE = [
    {
      icon: '📂',
      title: 'Chọn thư mục dự án',
      open: true,
      content: `
        <div class="guide-step"><div class="guide-step-num">1</div>
          <div class="guide-step-text">Nhấn nút <strong>Chọn thư mục</strong> để mở hộp thoại chọn thư mục. Chọn thư mục gốc của dự án (chứa <code>package.json</code>, <code>.csproj</code>, v.v.).</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">2</div>
          <div class="guide-step-text">Hoặc dán đường dẫn tuyệt đối vào ô input, ví dụ: <code>C:\\Projects\\my-app</code>.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">3</div>
          <div class="guide-step-text">Nhấn <strong>Quét dự án</strong> — SENTINEL sẽ đọc file cấu hình, dependencies và source code để phân tích.</div>
        </div>
      `
    },
    {
      icon: '🔍',
      title: 'SENTINEL quét gì trong source?',
      open: false,
      content: `
        <div class="guide-step"><div class="guide-step-num">•</div>
          <div class="guide-step-text"><strong>Dependencies:</strong> <code>package.json</code>, <code>package-lock.json</code>, <code>*.csproj</code> — tìm dependencies có CVE hoặc cấu hình lockfile không an toàn.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">•</div>
          <div class="guide-step-text"><strong>Secrets:</strong> Tìm API key, password, token hardcode trong source code và file config.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">•</div>
          <div class="guide-step-text"><strong>Config files:</strong> <code>.env</code>, <code>appsettings.json</code>, v.v. — kiểm tra thông tin nhạy cảm bị expose.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">•</div>
          <div class="guide-step-text"><strong>Logging patterns:</strong> Phát hiện code thiếu error handling hoặc log không đúng cách.</div>
        </div>
        <div class="guide-tip">
          <span class="guide-tip-icon">💡</span>
          <span class="guide-tip-text">Project Scan hoạt động <strong>tĩnh</strong> — không chạy code của bạn, không kết nối mạng, hoàn toàn an toàn.</span>
        </div>
      `
    },
    {
      icon: '🏗️',
      title: 'Tech Stack được hỗ trợ',
      open: false,
      content: `
        <div class="guide-step"><div class="guide-step-num">•</div>
          <div class="guide-step-text"><strong>Node.js / React / Next.js:</strong> Kiểm tra npm deps, JWT config, CORS, hardcoded secrets.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">•</div>
          <div class="guide-step-text"><strong>Spring Boot / Java:</strong> Kiểm tra Actuator endpoints, Maven/Gradle deps CVE, Spring Data REST exposure.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">•</div>
          <div class="guide-step-text"><strong>PHP / Laravel:</strong> Kiểm tra APP_DEBUG, Debugbar/Telescope public, file upload validation.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">•</div>
          <div class="guide-step-text"><strong>Generic:</strong> Bất kỳ dự án nào cũng được phân tích theo checklist bảo mật chung.</div>
        </div>
      `
    }
  ];

  const RESULTS_GUIDE = [
    {
      icon: '📊',
      title: 'Risk Dashboard',
      open: true,
      content: `
        <div class="guide-step"><div class="guide-step-num">1</div>
          <div class="guide-step-text"><strong>Điểm gauge (0–100):</strong> Điểm rủi ro tổng hợp. ≥70 = rủi ro nghiêm trọng, ≥40 = rủi ro cao, ≥15 = rủi ro trung bình.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">2</div>
          <div class="guide-step-text"><strong>Ô severity:</strong> Số lượng lỗi theo mức CRIT / HIGH / MED / LOW.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">3</div>
          <div class="guide-step-text"><strong>Biểu đồ OWASP:</strong> Phân bổ lỗi theo danh mục A01–A10, giúp xác định khu vực yếu nhất.</div>
        </div>
      `
    },
    {
      icon: '🔎',
      title: 'Lọc và tìm kiếm Findings',
      open: false,
      content: `
        <div class="guide-step"><div class="guide-step-num">1</div>
          <div class="guide-step-text"><strong>Tìm kiếm:</strong> Gõ từ khóa để lọc theo tên lỗi hoặc Rule ID (ví dụ: <code>A05-XSS</code>).</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">2</div>
          <div class="guide-step-text"><strong>Lọc severity:</strong> Chỉ xem Critical, High, Medium hoặc Low.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">3</div>
          <div class="guide-step-text"><strong>Lọc collector:</strong> <code>blackbox</code> = quét HTTP, <code>fuzzer</code> = kiểm thử injection, <code>source</code> = phân tích mã nguồn.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">4</div>
          <div class="guide-step-text">Nhấn vào finding card để xem chi tiết: <strong>Vị trí, Payload, Bằng chứng, Khuyến nghị khắc phục</strong>.</div>
        </div>
      `
    },
    {
      icon: '📤',
      title: 'Export báo cáo',
      open: false,
      content: `
        <div class="guide-step"><div class="guide-step-num">1</div>
          <div class="guide-step-text">Nhấn <strong>Xuất HTML</strong> để lưu báo cáo dạng trang web — dễ đọc, có thể mở bằng trình duyệt, phù hợp để gửi cho team.</div>
        </div>
        <div class="guide-step"><div class="guide-step-num">2</div>
          <div class="guide-step-text">Nhấn <strong>Xuất JSON</strong> để lưu dữ liệu thô — phù hợp để tích hợp vào pipeline CI/CD hoặc xử lý tự động.</div>
        </div>
        <div class="guide-tip">
          <span class="guide-tip-icon">💡</span>
          <span class="guide-tip-text">Tên file export được gợi ý tự động theo URL/tên thư mục và ngày scan.</span>
        </div>
      `
    }
  ];

  const VULNS_GUIDE = [
    {
      id: 'A01', name: 'Broken Access Control', sev: 'critical',
      desc: 'Kiểm tra JWT, CSRF token, forced browsing, IDOR — các lỗi cho phép truy cập trái phép.'
    },
    {
      id: 'A02', name: 'Cryptographic Failures', sev: 'high',
      desc: 'Cookie flags, CORS wildcard, HTTP không mã hóa, thiếu security headers (CSP, HSTS, X-Frame-Options).'
    },
    {
      id: 'A03', name: 'Injection / Supply Chain', sev: 'critical',
      desc: 'SQL Injection, XSS, Command Injection, SSTI, npm/NuGet dependencies có CVE.'
    },
    {
      id: 'A04', name: 'Insecure Design', sev: 'medium',
      desc: 'HTTP không mã hóa, sensitive data exposure, thiếu threat model và abuse case design.'
    },
    {
      id: 'A05', name: 'Security Misconfiguration', sev: 'high',
      desc: 'Debug endpoints public (Swagger, phpinfo, Actuator), TRACE method, CORS sai cấu hình.'
    },
    {
      id: 'A07', name: 'Auth & Session Failures', sev: 'critical',
      desc: 'Thiếu rate limiting, account enumeration, session fixation, reset password thiếu throttling.'
    },
    {
      id: 'A08', name: 'Software Integrity Failures', sev: 'high',
      desc: 'Script ngoài không có SRI (Subresource Integrity), thực thi config không tin cậy.'
    },
    {
      id: 'A09', name: 'Logging & Monitoring', sev: 'medium',
      desc: 'Thiếu alerting/monitoring rõ ràng, luồng auth không có audit logging.'
    },
    {
      id: 'A10', name: 'Exception & SSRF', sev: 'medium',
      desc: 'Stack trace lộ ra ngoài, server lỗi 5xx với input thông thường, malformed input handling.'
    },
    {
      id: 'GEN', name: 'Generic Security Checks', sev: 'low',
      desc: 'Thiếu input validation/escaping, headers không đầy đủ, supply chain lockfile version cũ.'
    }
  ];

  // ── Trạng thái panel ────────────────────────────────────────────────────────

  let guideOpen = false;
  let activeTab = 0;
  const sectionState = {}; // { tabIndex_sectionIndex: boolean }

  // ── Render helpers ──────────────────────────────────────────────────────────

  function sevClass(sev) {
    return `guide-sev-${sev}`;
  }

  function renderVulns() {
    return VULNS_GUIDE.map(v => `
      <div class="guide-vuln-item">
        <span class="guide-vuln-id">${v.id}</span>
        <div class="guide-vuln-body">
          <div class="guide-vuln-name">${v.name}</div>
          <div class="guide-vuln-desc">${v.desc}</div>
        </div>
        <span class="guide-vuln-sev ${sevClass(v.sev)}">${v.sev.toUpperCase()}</span>
      </div>
    `).join('');
  }

  function renderSections(sections, tabIdx) {
    return sections.map((sec, idx) => {
      const key = `${tabIdx}_${idx}`;
      const isOpen = sectionState[key] !== undefined ? sectionState[key] : sec.open;
      return `
        <div class="guide-section">
          <div class="guide-section-hdr ${isOpen ? 'open' : ''}" data-key="${key}">
            <span class="guide-section-icon">${sec.icon}</span>
            <span class="guide-section-name">${sec.title}</span>
            <span class="guide-section-caret ${isOpen ? 'open' : ''}">▶</span>
          </div>
          <div class="guide-section-body" style="display: ${isOpen ? 'flex' : 'none'};">
            ${sec.content}
          </div>
        </div>
      `;
    }).join('');
  }

  function renderTabContent() {
    switch (activeTab) {
      case 0: return renderSections(GETTING_STARTED, 0);
      case 1: return renderSections(URL_SCAN_GUIDE, 1);
      case 2: return renderSections(PROJECT_SCAN_GUIDE, 2);
      case 3: return renderSections(RESULTS_GUIDE, 3);
      case 4: return `<div class="guide-vuln-list">${renderVulns()}</div>`;
      default: return '';
    }
  }

  function renderGuidePanel() {
    return `
      <div class="guide-panel" id="sentinel-guide-panel">
        <div class="guide-panel-hdr">
          <div class="guide-panel-title">
            <span class="guide-panel-title-icon">📖</span>
            Hướng dẫn sử dụng
          </div>
          <button class="guide-close-btn" id="guide-close-btn" title="Đóng hướng dẫn">✕</button>
        </div>
        <div class="guide-tabs" id="guide-tabs">
          ${GUIDE_TABS.map((t, i) => `
            <button class="guide-tab ${i === activeTab ? 'active' : ''}" data-tab="${i}">${t}</button>
          `).join('')}
        </div>
        <div class="guide-body" id="guide-body">
          ${renderTabContent()}
        </div>
      </div>
    `;
  }

  // ── DOM manipulation ────────────────────────────────────────────────────────

  function updateWorkspaceClass() {
    if (guideOpen) {
      document.body.classList.add('guide-visible');
    } else {
      document.body.classList.remove('guide-visible');
    }
  }

  function removeGuidePanel() {
    const existing = document.getElementById('sentinel-guide-panel');
    if (existing) existing.remove();
    updateWorkspaceClass();
  }

  function mountGuidePanel() {
    removeGuidePanel();
    const ws = document.querySelector('.workspace');
    if (!ws) return;
    const div = document.createElement('div');
    div.innerHTML = renderGuidePanel();
    const panel = div.firstElementChild;
    ws.appendChild(panel);
    updateWorkspaceClass();
    bindPanelEvents(panel);
  }

  function refreshGuideBody() {
    const body = document.getElementById('guide-body');
    if (!body) return;
    body.innerHTML = renderTabContent();
    bindSectionEvents(body);
  }

  function bindSectionEvents(container) {
    container.querySelectorAll('.guide-section-hdr').forEach(hdr => {
      hdr.addEventListener('click', (e) => {
        e.preventDefault();
        const key = hdr.dataset.key;
        const isOpen = !hdr.classList.contains('open');
        sectionState[key] = isOpen;
        
        hdr.classList.toggle('open', isOpen);
        const caret = hdr.querySelector('.guide-section-caret');
        if (caret) caret.classList.toggle('open', isOpen);
        
        const body = hdr.nextElementSibling;
        if (body && body.classList.contains('guide-section-body')) {
          body.style.display = isOpen ? 'flex' : 'none';
          if (isOpen) {
            body.style.animation = 'none';
            body.offsetHeight; // trigger reflow
            body.style.animation = null;
          }
        }
      });
    });
  }

  function bindPanelEvents(panel) {
    // Close button
    panel.querySelector('#guide-close-btn').addEventListener('click', () => {
      guideOpen = false;
      removeGuidePanel();
      updateGuideBtn();
    });

    // Tabs
    panel.querySelector('#guide-tabs').addEventListener('click', e => {
      const btn = e.target.closest('.guide-tab');
      if (!btn) return;
      activeTab = parseInt(btn.dataset.tab, 10);
      // Re-render tabs active state
      panel.querySelectorAll('.guide-tab').forEach((t, i) => {
        t.classList.toggle('active', i === activeTab);
      });
      refreshGuideBody();
    });

    // Sections (initial bind)
    bindSectionEvents(panel.querySelector('#guide-body'));
  }

  // ── Guide button in header ──────────────────────────────────────────────────

  function updateGuideBtn() {
    const btn = document.getElementById('sentinel-guide-btn');
    if (!btn) return;
    if (guideOpen) {
      btn.classList.add('guide-open');
      btn.innerHTML = '<span class="guide-btn-icon">📖</span> Đóng hướng dẫn';
    } else {
      btn.classList.remove('guide-open');
      btn.innerHTML = '<span class="guide-btn-icon">📖</span> Hướng dẫn';
    }
  }

  function injectGuideButton() {
    // Wait for header-gap to exist
    const headerGap = document.querySelector('.header-gap');
    if (!headerGap || document.getElementById('sentinel-guide-btn')) return;

    const btn = document.createElement('button');
    btn.id = 'sentinel-guide-btn';
    btn.className = 'btn-guide';
    btn.innerHTML = '<span class="guide-btn-icon">📖</span> Hướng dẫn';
    btn.title = 'Mở / đóng bảng hướng dẫn sử dụng';
    btn.style.marginRight = '8px';

    btn.addEventListener('click', () => {
      guideOpen = !guideOpen;
      if (guideOpen) {
        mountGuidePanel();
      } else {
        removeGuidePanel();
      }
      updateGuideBtn();
    });

    headerGap.insertAdjacentElement('afterend', btn);
  }

  // ── Bootstrap ───────────────────────────────────────────────────────────────

  function init() {
    injectGuideButton();
    const observer = new MutationObserver(() => {
      if (guideOpen && !document.getElementById('sentinel-guide-panel')) {
        mountGuidePanel();
      }
    });
    const root = document.getElementById('root');
    if (root) observer.observe(root, { childList: true, subtree: true });
  }

  // Retry injection until React has rendered the app-header
  let attempts = 0;
  const interval = setInterval(() => {
    attempts++;
    if (document.querySelector('.header-gap')) {
      clearInterval(interval);
      init();
    }
    if (attempts > 100) clearInterval(interval);
  }, 100);

})();
