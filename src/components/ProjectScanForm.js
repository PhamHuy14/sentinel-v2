import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useStore } from '../store/useStore';
export const ProjectScanForm = () => {
    const { selectedFolder, setSelectedFolder, performProjectScan, isLoading } = useStore();
    const handleBrowse = async () => {
        const result = await window.owaspWorkbench?.pickFolder?.();
        if (result?.ok && result.folderPath)
            setSelectedFolder(result.folderPath);
    };
    const scopeItems = [
        'npm/yarn dependencies (CVE lookup)',
        'Hardcoded secrets & API keys',
        'Config & environment files',
        'CI/CD pipeline security',
        'Logging & error handling',
    ];
    return (_jsxs(_Fragment, { children: [_jsxs("div", { className: "section", children: [_jsx("div", { className: "section-label", children: "Project Folder" }), _jsxs("div", { className: "field", children: [_jsx("label", { className: "field-label", children: "Source Directory" }), _jsxs("div", { style: { display: 'flex', gap: 10, width: '100%' }, children: [_jsxs("div", { className: "input-clear-row", children: [_jsx("input", { type: "text", value: selectedFolder || '', readOnly: true, placeholder: "No folder selected" }), selectedFolder && (_jsx("button", { type: "button", className: "btn-clear", title: "Clear folder", disabled: isLoading, onClick: () => setSelectedFolder(''), children: "\u2715" }))] }), _jsx("button", { className: "btn-secondary", onClick: handleBrowse, disabled: isLoading, style: { whiteSpace: 'nowrap' }, children: "Browse" })] })] })] }), _jsxs("div", { className: "section", children: [_jsx("div", { className: "section-label", children: "Scan Scope" }), _jsx("ul", { className: "scope-list", children: scopeItems.map((item, i) => (_jsxs("li", { className: "scope-item", children: [_jsx("span", { className: "scope-bullet" }), item] }, i))) })] }), _jsx("button", { className: "btn-primary", onClick: performProjectScan, disabled: isLoading || !selectedFolder, children: isLoading ? 'Scanning...' : 'Scan Project' })] }));
};
