import React from 'react';
import { useStore } from '../store/useStore';

export const ReportExportButton: React.FC = () => {
  const { exportReport, urlScanResult, projectScanResult, activeTab } = useStore();
  const scanResult = activeTab === 'url' ? urlScanResult : projectScanResult;
  if (!scanResult) return null;

  return (
    <div className="export-row">
      <button className="btn-secondary" onClick={() => exportReport('html')}>Export HTML</button>
      <button className="btn-secondary" onClick={() => exportReport('json')}>Export JSON</button>
    </div>
  );
};
