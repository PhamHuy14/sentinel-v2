import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import React, { useEffect, useRef } from 'react';
import { useStore } from '../store/useStore';
const ICONS = {
    crawl: '🌐',
    probe: '🔬',
    analyze: '⚡',
    fuzz: '🎯',
    found: '⚠',
    done: '✓',
    error: '✗',
};
const STAGES = ['crawl', 'probe', 'analyze', 'fuzz', 'done'];
export const ScanProgress = () => {
    const { progressLog, stopScan, isLoading } = useStore();
    const bottomRef = useRef(null);
    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [progressLog.length]);
    const activeStage = progressLog.length > 0 ? progressLog[progressLog.length - 1].stage : '';
    const doneStages = new Set(progressLog.map((e) => e.stage));
    const logCount = progressLog.length;
    return (_jsxs("div", { className: "progress-panel", children: [_jsxs("div", { className: "progress-panel-hdr", children: [_jsx("div", { className: "spinner-sm" }), _jsx("span", { className: "progress-panel-title", children: "Scanning in progress\u2026" }), _jsx("div", { style: { flex: 1 } }), _jsxs("span", { className: "log-count-badge", children: [logCount, " events"] }), isLoading && (_jsx("button", { className: "btn-stop", onClick: stopScan, title: "Stop scan", children: "\u25A0 Stop" }))] }), _jsx("div", { className: "stage-pipeline", children: STAGES.map((s) => {
                    const stage = s;
                    return (_jsxs(React.Fragment, { children: [_jsxs("div", { className: `stage-node ${doneStages.has(stage) ? 'done' : ''} ${activeStage === stage ? 'active' : ''}`, children: [_jsx("div", { className: "stage-dot" }), _jsx("span", { children: s })] }), s !== 'done' && _jsx("div", { className: `stage-line ${doneStages.has(stage) ? 'done' : ''}` })] }, s));
                }) }), _jsxs("div", { className: "progress-log", children: [progressLog.length === 0 && (_jsx("div", { className: "log-line log-info", children: _jsx("span", { className: "log-msg", children: "Initialising\u2026" }) })), progressLog.map((ev, i) => (_jsxs("div", { className: `log-line log-${ev.level}`, children: [_jsx("span", { className: "log-icon", children: ICONS[ev.stage] || '·' }), _jsx("span", { className: "log-ts", children: new Date(ev.ts).toLocaleTimeString('en', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) }), _jsx("span", { className: "log-msg", children: ev.msg })] }, i))), _jsx("div", { ref: bottomRef })] })] }));
};
