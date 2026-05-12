import React from 'react';
import { useStore } from '../store/useStore';
import { PROJECT_SCAN_COVERAGE } from '../utils/owasp';

const SCOPE_CARDS = [
  {
    icon: '✓',
    title: 'Thư viện & gói phần mềm',
    desc: 'Kiểm tra gói npm/yarn có lỗ hổng CVE đã biết.',
  },
  {
    icon: '✓',
    title: 'Mật khẩu & khoá bí mật',
    desc: 'Phát hiện API key, token bị nhúng cứng trong code.',
  },
  {
    icon: '✓',
    title: 'File cấu hình & môi trường',
    desc: 'Kiểm tra .env, config file có thông tin nhạy cảm.',
  },
  {
    icon: '✓',
    title: 'Pipeline CI/CD',
    desc: 'Đánh giá bảo mật quy trình build và triển khai.',
  },
  {
    icon: '✓',
    title: 'Ghi log & xử lý lỗi',
    desc: 'Phát hiện log ghi quá nhiều thông tin nhạy cảm.',
  },
];

export const ProjectScanForm: React.FC = () => {
  const { selectedFolder, setSelectedFolder, performProjectScan, isLoading } = useStore();

  const handleBrowse = async () => {
    const result = await window.owaspWorkbench?.pickFolder?.();
    if (result?.ok && result.folderPath) setSelectedFolder(result.folderPath);
  };

  return (
    <>
      {/* ── Tip người mới ── */}
      <div className="onboarding-tip">
        <strong>Gợi ý:</strong> Chọn thư mục chứa mã nguồn chính của bạn
        (ví dụ thư mục <code className="inline-code">src</code> hoặc thư mục gốc dự án).
      </div>

      {/* ── Chọn thư mục ── */}
      <div className="scan-scope-notice">
        <div>
          <div className="scan-scope-title">Project Scan kiểm tra được những nhóm OWASP nào?</div>
          <p className="scan-scope-copy">
            Project Scan đọc source/config/dependency/CI để bắt các lỗi không thể nhìn đầy đủ từ URL Scan, ví dụ weak crypto trong code, dependency cũ, SRI hoặc pipeline integrity.
          </p>
        </div>
        <div className="owasp-chip-grid">
          {PROJECT_SCAN_COVERAGE.map((item) => (
            <span key={item.id} className="owasp-scope-chip" title={item.summary}>
              <strong>{item.id}</strong> {item.name}
            </span>
          ))}
        </div>
      </div>

      <div className="section">
        <div className="section-label">Thư mục mã nguồn</div>

        <div className="field">
          <label className="field-label" htmlFor="folder-path">Đường dẫn thư mục</label>
          <div className="folder-select-row">
            <div className="input-clear-row">
              <input
                id="folder-path"
                type="text"
                value={selectedFolder || ''}
                readOnly
                placeholder="Chưa chọn thư mục nào"
              />
              {selectedFolder && (
                <button
                  type="button"
                  className="btn-clear"
                  title="Xoá thư mục đã chọn"
                  disabled={isLoading}
                  onClick={() => setSelectedFolder('')}
                >✕</button>
              )}
            </div>
            <button
              className="btn-browse"
              onClick={handleBrowse}
              disabled={isLoading}
              type="button"
            >
              📁 Chọn thư mục
            </button>
          </div>
        </div>
      </div>

      {/* ── Phạm vi phân tích ── */}
      <div className="section">
        <div className="section-label">Những gì sẽ được kiểm tra</div>
        <div className="scope-cards">
          {SCOPE_CARDS.map((card, i) => (
            <div key={i} className="scope-card">
              <div className="scope-card-check">{card.icon}</div>
              <div>
                <div className="scope-card-title">{card.title}</div>
                <div className="scope-card-desc">{card.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Sticky CTA ── */}
      <div className="left-panel-cta">
        <button
          className="btn-primary"
          onClick={performProjectScan}
          disabled={isLoading || !selectedFolder}
          title={!selectedFolder ? 'Vui lòng chọn thư mục trước khi phân tích' : 'Bắt đầu phân tích bảo mật (Ctrl+Enter)'}
        >
          {isLoading ? (
            <><span className="spinner-sm" style={{ borderColor: 'rgba(42,54,59,.2)', borderTopColor: 'var(--text)' }} /> Đang phân tích…</>
          ) : (
            <>▶ Bắt đầu phân tích mã nguồn</>
          )}
        </button>
        <p
          className="form-hint-below"
          style={{
            visibility: selectedFolder || isLoading ? 'hidden' : 'visible',
            minHeight: '15px'
          }}
        >
          Chọn thư mục phía trên để kích hoạt nút phân tích
        </p>
      </div>
    </>
  );
};
