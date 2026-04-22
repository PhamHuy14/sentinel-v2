import React from 'react';
import { useStore } from '../store/useStore';

export const ProjectScanForm: React.FC = () => {
  const { selectedFolder, setSelectedFolder, performProjectScan, isLoading } = useStore();

  const handleBrowse = async () => {
    const result = await window.owaspWorkbench?.pickFolder?.();
    if (result?.ok && result.folderPath) setSelectedFolder(result.folderPath);
  };

  const scopeItems = [
    'Phụ thuộc npm/yarn (tra cứu CVE)',
    'Bí mật hardcode và API key',
    'File cấu hình và biến môi trường',
    'Bảo mật pipeline CI/CD',
    'Ghi log và xử lý lỗi',
  ];

  return (
    <>
      <div className="section">
        <div className="section-label">Thư mục dự án</div>
        <div className="quick-help-box">
          Mẹo cho người mới: hãy quét thư mục source chính trước, sau đó quét lại toàn bộ dự án nếu cần.
        </div>
        <div className="field">
          <label className="field-label">Thư mục mã nguồn</label>
          <div style={{ display: 'flex', gap: 10, width: '100%' }}>
            <div className="input-clear-row">
              <input
                type="text"
                value={selectedFolder || ''}
                readOnly
                placeholder="Chưa chọn thư mục"
              />
              {selectedFolder && (
                <button
                  type="button"
                  className="btn-clear"
                  title="Xóa thư mục"
                  disabled={isLoading}
                  onClick={() => setSelectedFolder('')}
                >
                  ✕
                </button>
              )}
            </div>
            <button className="btn-secondary" onClick={handleBrowse} disabled={isLoading} style={{ whiteSpace: 'nowrap' }}>
              Chọn thư mục
            </button>
          </div>
        </div>
      </div>

      <div className="section">
        <div className="section-label">Phạm vi quét</div>
        <ul className="scope-list">
          {scopeItems.map((item, i) => (
            <li key={i} className="scope-item">
              <span className="scope-bullet" />
              {item}
            </li>
          ))}
        </ul>
      </div>

      <button
        className="btn-primary"
        onClick={performProjectScan}
        disabled={isLoading || !selectedFolder}
      >
        {isLoading ? 'Đang quét...' : 'Quét dự án'}
      </button>
    </>
  );
};
