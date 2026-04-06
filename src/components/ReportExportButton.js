import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useStore } from '../store/useStore';
export const ReportExportButton = () => {
    const { exportReport, urlScanResult, projectScanResult, activeTab } = useStore();
    const scanResult = activeTab === 'url' ? urlScanResult : projectScanResult;
    if (!scanResult)
        return null;
    return (_jsxs("div", { className: "export-row", children: [_jsx("button", { className: "btn-secondary", onClick: () => exportReport('html'), children: "Export HTML" }), _jsx("button", { className: "btn-secondary", onClick: () => exportReport('json'), children: "Export JSON" })] }));
};
