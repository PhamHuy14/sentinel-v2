/**
 * SENTINEL v2 — Hướng dẫn sử dụng (Redesigned)
 * Slide-in sidebar, dùng đúng design tokens của app
 */
(function () {
  'use strict';

  const TABS = ['Bắt đầu', 'URL Scan', 'Dự án', 'Kết quả', 'OWASP'];

  const DATA = {
    0: [ // Bắt đầu
      {
        icon: '🛡️', title: 'SENTINEL là gì?', open: true,
        items: [
          'Công cụ kiểm thử bảo mật theo chuẩn <strong>OWASP Top 10 — 2025</strong>, chạy trực tiếp trên máy (Electron), không cần server riêng.',
          'Hỗ trợ <strong>URL Scan</strong> (black-box từ xa) và <strong>Project Scan</strong> (phân tích source code tĩnh).',
        ],
        tip: 'Chạy cả hai chế độ để phát hiện đầy đủ lỗ hổng — URL tìm lỗi runtime, Project tìm lỗi source code.'
      },
      {
        icon: '⚙️', title: 'Quy trình cơ bản', open: false,
        items: [
          'Chọn tab <strong>Quét Website</strong> hoặc <strong>Quét Mã Nguồn</strong>.',
          'Điền URL hoặc chọn thư mục dự án.',
          'Nhấn <strong>Bắt đầu quét</strong> — theo dõi log thời gian thực.',
          'Xem kết quả ở panel bên phải, xuất báo cáo HTML/JSON.'
        ]
      },
      {
        icon: '📁', title: 'Lịch sử quét', open: false,
        items: [
          'Mỗi lần quét thành công lưu vào <strong>Lịch sử</strong> (tối đa 10 mục).',
          'Nhấn <strong>Lịch sử</strong> ở header để xem và khôi phục kết quả cũ.'
        ]
      }
    ],
    1: [ // URL Scan
      {
        icon: '🎯', title: 'Nhập URL mục tiêu', open: true,
        items: [
          'Nhập URL đầy đủ: <code>https://example.com</code> hoặc <code>http://localhost:3000</code>.',
          'Nhấn <strong>Enter</strong> hoặc nút <strong>Bắt đầu quét website</strong> màu vàng.',
        ],
        warn: 'Chỉ scan URL bạn có quyền kiểm thử. Không scan hệ thống người khác khi chưa được phép.'
      },
      {
        icon: '🔬', title: 'Phạm vi & Cường độ', open: false,
        items: [
          '<strong>Phạm vi (Depth):</strong> 0 = chỉ URL gốc; 1 = URL + link trực tiếp (khuyến nghị); 2 = sâu hơn.',
          '<strong>Cường độ (Budget):</strong> Số HTTP request tối đa. Budget cao = kỹ hơn nhưng chậm hơn.',
        ],
        tip: 'Depth 1 + Budget 60 là cấu hình cân bằng (~30–60 giây). Budget 200 cho mục tiêu quan trọng.'
      },
      {
        icon: '🔑', title: 'Xác thực (Authentication)', open: false,
        items: [
          '<strong>Cookie:</strong> Dán từ DevTools → Application → Cookies (dạng <code>session=abc; token=xyz</code>).',
          '<strong>Bearer Token:</strong> JWT, dán giá trị <code>eyJhbGci…</code> (không cần prefix "Bearer").',
          '<strong>Custom Headers:</strong> JSON, ví dụ <code>{"X-API-Key": "abc123"}</code>.'
        ]
      }
    ],
    2: [ // Project Scan
      {
        icon: '📂', title: 'Chọn thư mục dự án', open: true,
        items: [
          'Nhấn <strong>Chọn thư mục</strong> để mở dialog — chọn thư mục gốc (chứa <code>package.json</code>, <code>.csproj</code>…).',
          'Hoặc dán đường dẫn tuyệt đối vào ô input.',
          'Nhấn <strong>Bắt đầu phân tích</strong> — không chạy code, hoàn toàn an toàn.'
        ]
      },
      {
        icon: '🔍', title: 'SENTINEL kiểm tra gì?', open: false,
        items: [
          '<strong>Dependencies:</strong> <code>package.json</code>, <code>package-lock.json</code> — CVE và lockfile không an toàn.',
          '<strong>Secrets:</strong> API key, password, token hardcode trong source code và config.',
          '<strong>Config files:</strong> <code>.env</code>, <code>appsettings.json</code> — thông tin nhạy cảm bị expose.',
          '<strong>Logging:</strong> Code thiếu error handling hoặc log sai cách.'
        ],
        tip: 'Project Scan hoạt động tĩnh — không kết nối mạng, không thực thi code của bạn.'
      },
      {
        icon: '🏗️', title: 'Tech Stack hỗ trợ', open: false,
        items: [
          '<strong>Node.js / React / Next.js:</strong> npm deps, JWT, CORS, secrets.',
          '<strong>Spring Boot / Java:</strong> Actuator, Maven/Gradle CVE, Spring Data REST.',
          '<strong>PHP / Laravel:</strong> APP_DEBUG, Debugbar/Telescope, file upload.'
        ]
      }
    ],
    3: [ // Kết quả
      {
        icon: '📊', title: 'Risk Dashboard', open: true,
        items: [
          '<strong>Gauge 0–100:</strong> ≥70 = nghiêm trọng, ≥40 = cao, ≥15 = trung bình, <15 = thấp.',
          '<strong>Ô severity:</strong> Số lỗi theo mức CRIT / HIGH / MED / LOW.',
          '<strong>Biểu đồ OWASP:</strong> Phân bổ theo danh mục A01–A10.'
        ]
      },
      {
        icon: '🔎', title: 'Lọc & Tìm kiếm', open: false,
        items: [
          '<strong>Tìm kiếm:</strong> Gõ từ khóa để lọc theo tên lỗi hoặc Rule ID (vd: <code>A05-XSS</code>).',
          '<strong>Lọc severity:</strong> Chỉ xem Critical, High, Medium hoặc Low.',
          'Nhấn finding card để xem chi tiết: <strong>Vị trí, Payload, Bằng chứng, Khuyến nghị</strong>.'
        ]
      },
      {
        icon: '📤', title: 'Export báo cáo', open: false,
        items: [
          '<strong>Xuất HTML:</strong> Báo cáo dạng trang web — dễ đọc, gửi cho team.',
          '<strong>Xuất JSON:</strong> Dữ liệu thô — tích hợp CI/CD hoặc xử lý tự động.'
        ],
        tip: 'Tên file được gợi ý tự động theo URL/tên thư mục và ngày scan.'
      }
    ],
    4: 'vulns' // OWASP
  };

  const VULNS = [
    { id: 'A01', name: 'Broken Access Control',        sev: 'critical', desc: 'IDOR, bypass, thiếu kiểm tra quyền, JWT/CSRF lỗi.' },
    { id: 'A02', name: 'Cryptographic Failures',       sev: 'high',     desc: 'Cookie flags, CORS wildcard, HTTP không mã hóa, thiếu CSP/HSTS.' },
    { id: 'A03', name: 'Injection / Supply Chain',     sev: 'critical', desc: 'SQLi, XSS, Command Injection, SSTI, npm CVE.' },
    { id: 'A04', name: 'Insecure Design',              sev: 'medium',   desc: 'Thiếu rate limit, sensitive data exposure, threat model.' },
    { id: 'A05', name: 'Security Misconfiguration',    sev: 'high',     desc: 'Swagger/Actuator public, TRACE method, CORS sai.' },
    { id: 'A07', name: 'Auth & Session Failures',      sev: 'critical', desc: 'Thiếu rate limiting, account enumeration, session fixation.' },
    { id: 'A08', name: 'Software Integrity Failures',  sev: 'high',     desc: 'Script ngoài thiếu SRI, config không tin cậy.' },
    { id: 'A09', name: 'Logging & Monitoring',         sev: 'medium',   desc: 'Thiếu alerting, auth không có audit log.' },
    { id: 'A10', name: 'SSRF & Exception Handling',    sev: 'medium',   desc: 'Stack trace lộ, SSRF, 5xx với input thông thường.' },
  ];

  let guideOpen = false;
  let activeTab = 0;
  const openSections = {}; // key → boolean

  // ── Render ──────────────────────────────────────────────────────────────────

  function sevColor(sev) {
    if (sev === 'critical') return 'var(--crit)';
    if (sev === 'high')     return 'var(--high)';
    if (sev === 'medium')   return 'var(--med)';
    return 'var(--low)';
  }
  function sevBg(sev) {
    if (sev === 'critical') return 'var(--crit-bg)';
    if (sev === 'high')     return 'var(--high-bg)';
    if (sev === 'medium')   return 'var(--med-bg)';
    return 'var(--low-bg)';
  }
  function sevBorder(sev) {
    if (sev === 'critical') return 'var(--crit-b)';
    if (sev === 'high')     return 'var(--high-b)';
    if (sev === 'medium')   return 'var(--med-b)';
    return 'var(--low-b)';
  }

  function renderVulns() {
    return `<div style="display:flex;flex-direction:column;gap:5px;">` +
      VULNS.map(v => `
        <div style="display:flex;align-items:flex-start;gap:9px;padding:8px 10px;
          background:var(--bg-input);border:1px solid var(--border-dim);
          border-left:3px solid ${sevColor(v.sev)};border-radius:6px;">
          <div style="display:flex;flex-direction:column;gap:1px;min-width:0;flex:1;">
            <div style="display:flex;align-items:center;gap:7px;">
              <span style="font-family:var(--mono);font-size:10px;font-weight:700;color:${sevColor(v.sev)};flex-shrink:0;">${v.id}</span>
              <span style="font-size:11.5px;font-weight:600;color:var(--text);">${v.name}</span>
            </div>
            <div style="font-size:11px;color:var(--text-2);line-height:1.45;margin-top:2px;">${v.desc}</div>
          </div>
          <span style="font-size:9px;font-family:var(--mono);font-weight:700;padding:2px 6px;
            border-radius:3px;border:1px solid ${sevBorder(v.sev)};
            background:${sevBg(v.sev)};color:${sevColor(v.sev)};
            flex-shrink:0;white-space:nowrap;margin-top:1px;">${v.sev.toUpperCase()}</span>
        </div>
      `).join('') +
    `</div>`;
  }

  function renderSections(sections, tabIdx) {
    return sections.map((sec, idx) => {
      const key = `${tabIdx}_${idx}`;
      const isOpen = openSections[key] !== undefined ? openSections[key] : sec.open;

      const itemsHtml = (sec.items || []).map(item => `
        <div style="display:flex;gap:8px;align-items:flex-start;">
          <div style="width:5px;height:5px;border-radius:50%;background:var(--accent-bright);
            flex-shrink:0;margin-top:6px;border:1.5px solid var(--accent);"></div>
          <div style="font-size:12px;color:var(--text-2);line-height:1.55;flex:1;">${item}</div>
        </div>
      `).join('');

      const tipHtml = sec.tip ? `
        <div style="display:flex;gap:7px;align-items:flex-start;
          background:var(--accent-dim);border:1px solid var(--accent-border);
          border-left:3px solid var(--accent-bright);border-radius:6px;padding:8px 10px;margin-top:4px;">
          <span style="font-size:13px;flex-shrink:0;">💡</span>
          <span style="font-size:11.5px;color:var(--text-2);line-height:1.5;">${sec.tip}</span>
        </div>
      ` : '';

      const warnHtml = sec.warn ? `
        <div style="display:flex;gap:7px;align-items:flex-start;
          background:var(--crit-bg);border:1px solid var(--crit-b);
          border-left:3px solid var(--crit);border-radius:6px;padding:8px 10px;margin-top:4px;">
          <span style="font-size:13px;flex-shrink:0;">⚠️</span>
          <span style="font-size:11.5px;color:var(--crit);line-height:1.5;font-weight:500;">${sec.warn}</span>
        </div>
      ` : '';

      return `
        <div class="gd-section" data-key="${key}">
          <button class="gd-section-hdr ${isOpen ? 'open' : ''}" data-key="${key}" type="button">
            <span style="font-size:14px;">${sec.icon}</span>
            <span class="gd-section-name">${sec.title}</span>
            <span class="gd-caret ${isOpen ? 'open' : ''}">▶</span>
          </button>
          <div class="gd-section-body" style="display:${isOpen ? 'flex' : 'none'};">
            ${itemsHtml}${tipHtml}${warnHtml}
          </div>
        </div>
      `;
    }).join('');
  }

  function renderBody() {
    const d = DATA[activeTab];
    if (d === 'vulns') return renderVulns();
    return renderSections(d, activeTab);
  }

  function renderPanel() {
    const tabsHtml = TABS.map((t, i) => `
      <button class="gd-tab ${i === activeTab ? 'active' : ''}" data-tab="${i}" type="button">${t}</button>
    `).join('');

    return `
      <aside id="sentinel-guide-panel" class="gd-panel" role="complementary" aria-label="Hướng dẫn sử dụng">
        <div class="gd-header">
          <div class="gd-header-title">
            <span style="font-size:15px;">📖</span>
            <span>Hướng dẫn</span>
          </div>
          <button class="gd-close" id="gd-close-btn" title="Đóng hướng dẫn" type="button" aria-label="Đóng hướng dẫn">✕</button>
        </div>
        <div class="gd-tabs" id="gd-tabs" role="tablist">${tabsHtml}</div>
        <div class="gd-body" id="gd-body" role="tabpanel">${renderBody()}</div>
      </aside>
    `;
  }

  // ── CSS inject ───────────────────────────────────────────────────────────────

  function injectStyles() {
    if (document.getElementById('sentinel-guide-css')) return;
    const style = document.createElement('style');
    style.id = 'sentinel-guide-css';
    style.textContent = `
/* ── Guide button in header ───────────────────── */
#sentinel-guide-btn {
  display: inline-flex; align-items: center; gap: 5px;
  height: 30px; padding: 0 11px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg-input);
  color: var(--text-2);
  font-size: 12px; font-weight: 500;
  font-family: inherit;
  cursor: pointer;
  transition: background .13s, color .13s, border-color .13s;
  white-space: nowrap;
}
#sentinel-guide-btn:hover {
  background: var(--bg-hover); color: var(--text); border-color: var(--border);
}
#sentinel-guide-btn.guide-open {
  background: var(--accent-dim);
  border-color: var(--accent-border);
  color: var(--accent);
}

/* ── Panel overlay backdrop ───────────────────── */
#gd-backdrop {
  position: fixed; inset: 0; z-index: 80;
  background: rgba(0,0,0,.18);
  animation: gdFadeIn .18s ease both;
}
@keyframes gdFadeIn { from { opacity: 0; } to { opacity: 1; } }

/* ── Guide panel ──────────────────────────────── */
.gd-panel {
  position: fixed;
  top: 44px; right: 0; bottom: 0;
  width: min(340px, calc(100vw - 40px));
  z-index: 81;
  display: flex; flex-direction: column;
  background: var(--bg-card);
  border-left: 1px solid var(--border);
  box-shadow: -4px 0 24px rgba(0,0,0,.12);
  animation: gdSlideIn .22s cubic-bezier(.4,0,.2,1) both;
  overflow: hidden;
}
@keyframes gdSlideIn {
  from { transform: translateX(100%); opacity: .6; }
  to   { transform: translateX(0);   opacity: 1; }
}

/* ── Header ───────────────────────────────────── */
.gd-header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 11px 14px;
  background: var(--bg-panel);
  border-bottom: 2px solid var(--accent-bright);
  flex-shrink: 0;
}
.gd-header-title {
  display: flex; align-items: center; gap: 8px;
  font-size: 12.5px; font-weight: 700; color: var(--text);
  letter-spacing: .02em;
}
.gd-close {
  width: 26px; height: 26px;
  display: flex; align-items: center; justify-content: center;
  border: 1px solid var(--border); border-radius: 6px;
  background: var(--bg-input); color: var(--text-3);
  font-size: 11px; cursor: pointer;
  transition: all .12s;
}
.gd-close:hover { background: var(--crit-bg); color: var(--crit); border-color: var(--crit-b); }

/* ── Tabs ─────────────────────────────────────── */
.gd-tabs {
  display: flex; border-bottom: 1px solid var(--border-dim);
  flex-shrink: 0; overflow-x: auto; scrollbar-width: none;
  background: var(--bg-panel);
}
.gd-tabs::-webkit-scrollbar { display: none; }
.gd-tab {
  flex: 1; min-width: max-content;
  padding: 8px 10px;
  font-size: 11px; font-weight: 500;
  color: var(--text-2);
  background: transparent; border: none;
  border-bottom: 2px solid transparent;
  margin-bottom: -1px;
  cursor: pointer; font-family: inherit;
  transition: all .12s; white-space: nowrap;
}
.gd-tab:hover { color: var(--text); background: var(--bg-hover); }
.gd-tab.active {
  color: var(--accent); border-bottom-color: var(--accent-bright);
  font-weight: 600; background: var(--bg-card);
}

/* ── Body ─────────────────────────────────────── */
.gd-body {
  flex: 1; overflow-y: auto;
  padding: 12px 14px;
  display: flex; flex-direction: column; gap: 8px;
}
.gd-body::-webkit-scrollbar { width: 4px; }
.gd-body::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

/* ── Section ──────────────────────────────────── */
.gd-section {
  border: 1px solid var(--border-dim);
  border-radius: 8px;
  background: var(--bg-input);
  overflow: hidden;
}
.gd-section-hdr {
  display: flex; align-items: center; gap: 8px;
  padding: 9px 11px;
  background: transparent; border: none;
  cursor: pointer; width: 100%; text-align: left;
  font-family: inherit;
  transition: background .1s;
  -webkit-user-select: none; user-select: none;
}
.gd-section-hdr:hover { background: var(--bg-hover); }
.gd-section-hdr.open { background: var(--accent-dim); border-bottom: 1px solid var(--accent-border); }
.gd-section-name {
  flex: 1; font-size: 12px; font-weight: 600; color: var(--text);
}
.gd-caret {
  font-size: 8px; color: var(--text-3);
  transition: transform .15s; flex-shrink: 0;
}
.gd-caret.open { transform: rotate(90deg); color: var(--accent); }
.gd-section-body {
  flex-direction: column; gap: 7px;
  padding: 10px 12px;
  animation: gdFadeIn .15s ease both;
  border-top: 1px solid var(--border-dim);
  background: var(--bg-card);
}
.gd-section-body code {
  font-family: var(--mono); font-size: 11px;
  background: var(--bg-input); padding: 1px 5px;
  border-radius: 4px; color: var(--accent);
  border: 1px solid var(--border);
}
    `;
    document.head.appendChild(style);
  }

  // ── DOM ──────────────────────────────────────────────────────────────────────

  function removePanel() {
    document.getElementById('sentinel-guide-panel')?.remove();
    document.getElementById('gd-backdrop')?.remove();
    document.body.classList.remove('guide-visible');
  }

  function mountPanel() {
    removePanel();
    injectStyles();

    // Backdrop
    const backdrop = document.createElement('div');
    backdrop.id = 'gd-backdrop';
    backdrop.addEventListener('click', () => { guideOpen = false; removePanel(); updateBtn(); });
    document.body.appendChild(backdrop);

    // Panel
    const div = document.createElement('div');
    div.innerHTML = renderPanel();
    const panel = div.firstElementChild;
    document.body.appendChild(panel);
    document.body.classList.add('guide-visible');

    // Close
    panel.querySelector('#gd-close-btn').addEventListener('click', () => {
      guideOpen = false; removePanel(); updateBtn();
    });

    // Tabs
    panel.querySelector('#gd-tabs').addEventListener('click', e => {
      const btn = e.target.closest('.gd-tab');
      if (!btn) return;
      activeTab = parseInt(btn.dataset.tab, 10);
      panel.querySelectorAll('.gd-tab').forEach((t, i) => t.classList.toggle('active', i === activeTab));
      const body = panel.querySelector('#gd-body');
      if (body) { body.innerHTML = renderBody(); bindSections(body); }
    });

    bindSections(panel.querySelector('#gd-body'));
  }

  function bindSections(container) {
    if (!container) return;
    container.querySelectorAll('.gd-section-hdr').forEach(hdr => {
      hdr.addEventListener('click', () => {
        const key = hdr.dataset.key;
        const isOpen = !hdr.classList.contains('open');
        openSections[key] = isOpen;
        hdr.classList.toggle('open', isOpen);
        const caret = hdr.querySelector('.gd-caret');
        if (caret) caret.classList.toggle('open', isOpen);
        const body = hdr.nextElementSibling;
        if (body) body.style.display = isOpen ? 'flex' : 'none';
      });
    });
  }

  function updateBtn() {
    const btn = document.getElementById('sentinel-guide-btn');
    if (!btn) return;
    btn.classList.toggle('guide-open', guideOpen);
    btn.innerHTML = guideOpen
      ? '<span>📖</span> Đóng hướng dẫn'
      : '<span>📖</span> Hướng dẫn';
  }

  function injectBtn() {
    const headerGap = document.querySelector('.header-gap');
    if (!headerGap || document.getElementById('sentinel-guide-btn')) return;
    const btn = document.createElement('button');
    btn.id = 'sentinel-guide-btn';
    btn.type = 'button';
    btn.innerHTML = '<span>📖</span> Hướng dẫn';
    btn.title = 'Mở / đóng bảng hướng dẫn sử dụng';
    btn.addEventListener('click', () => {
      guideOpen = !guideOpen;
      guideOpen ? mountPanel() : removePanel();
      updateBtn();
    });
    headerGap.insertAdjacentElement('afterend', btn);
  }

  // Bootstrap
  let tries = 0;
  const iv = setInterval(() => {
    tries++;
    if (document.querySelector('.header-gap')) { clearInterval(iv); injectBtn(); injectStyles(); }
    if (tries > 100) clearInterval(iv);
  }, 100);

})();
