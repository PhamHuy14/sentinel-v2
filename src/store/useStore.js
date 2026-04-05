import { create } from 'zustand';
const HISTORY_KEY = 'sentinel_v2_history';
const MAX_HISTORY = 10;
const MAX_LOG = 200; // limit progressLog to avoid memory growth
// ── LocalStorage helpers ──────────────────────────────────────────────────────
function loadHistoryFromStorage() {
    try {
        const raw = localStorage.getItem(HISTORY_KEY) || '[]';
        const entries = JSON.parse(raw);
        return entries;
    }
    catch (_e) {
        return [];
    }
}
function saveHistoryToStorage(h) {
    try {
        const slim = h.map(e => ({
            ...e,
            scanResult: {
                ...e.scanResult,
                findings: e.scanResult.findings.slice(0, 100),
            },
        }));
        localStorage.setItem(HISTORY_KEY, JSON.stringify(slim));
    }
    catch (_e) {
        try {
            const trimmed = h.slice(0, Math.max(1, Math.floor(h.length / 2)));
            localStorage.setItem(HISTORY_KEY, JSON.stringify(trimmed));
        }
        catch (_e2) {
            void 0;
        }
    }
}
function calcRiskScore(findings) {
    const SEV_W = { critical: 10, high: 7, medium: 4, low: 1 };
    return Math.min(100, findings.reduce((s, f) => s + (SEV_W[f.severity] || 0), 0));
}
const ipc = () => {
    if (typeof window !== 'undefined' && window.owaspWorkbench)
        return window.owaspWorkbench;
    throw new Error('Ứng dụng cần chạy trong Electron. Khởi động bằng npm run dev.');
};
export const useStore = create((set, get) => ({
    activeTab: 'url',
    setActiveTab: (tab) => set({ activeTab: tab }),
    isLoading: false,
    scanResult: null,
    error: null,
    urlInput: '',
    authConfig: { cookie: '', bearerToken: '', authorization: '', customHeaders: '' },
    setUrlInput: (url) => set({ urlInput: url }),
    setAuthConfig: (config) => set((s) => ({ authConfig: { ...s.authConfig, ...config } })),
    crawlDepth: 1,
    requestBudget: 30,
    setCrawlDepth: (n) => set({ crawlDepth: n }),
    setRequestBudget: (n) => set({ requestBudget: n }),
    selectedFolder: null,
    setSelectedFolder: (folder) => set({ selectedFolder: folder }),
    checklist: null,
    progressLog: [],
    appendProgress: (ev) => set((s) => ({
        progressLog: s.progressLog.length >= MAX_LOG
            ? [...s.progressLog.slice(-MAX_LOG + 1), ev] // rolling window
            : [...s.progressLog, ev],
    })),
    clearProgress: () => set({ progressLog: [] }),
    history: loadHistoryFromStorage(),
    loadHistory: () => set({ history: loadHistoryFromStorage() }),
    saveToHistory: (result) => {
        const riskScore = calcRiskScore(result.findings);
        const entry = {
            id: Date.now().toString(),
            ts: Date.now(),
            mode: result.mode,
            target: result.scannedUrl || result.target || '',
            riskScore,
            summary: { total: result.metadata.summary.total, bySeverity: result.metadata.summary.bySeverity },
            scanResult: result,
        };
        const updated = [entry, ...loadHistoryFromStorage()].slice(0, MAX_HISTORY);
        saveHistoryToStorage(updated);
        set({ history: updated });
    },
    restoreFromHistory: (id) => {
        const entry = get().history.find((e) => e.id === id);
        if (entry)
            set({ scanResult: entry.scanResult, error: null, showHistoryDropdown: false });
    },
    clearHistory: () => { saveHistoryToStorage([]); set({ history: [] }); },
    showHistoryDropdown: false,
    setShowHistoryDropdown: (show) => set({ showHistoryDropdown: show }),
    _progressListener: null,
    // ── Scan Actions ──────────────────────────────────────────
    performUrlScan: async () => {
        const { urlInput, authConfig, crawlDepth, requestBudget } = get();
        if (!urlInput.trim()) {
            set({ error: 'Vui lòng nhập URL mục tiêu', scanResult: null });
            return;
        }
        get().clearProgress();
        set({ isLoading: true, error: null, scanResult: null });
        // Register progress listener and keep ref for cleanup
        try {
            const cb = (ev) => get().appendProgress(ev);
            window.owaspWorkbench?.onScanProgress?.(cb);
            set({ _progressListener: cb });
        }
        catch (_e) {
            void 0;
        }
        try {
            const result = await ipc().scanUrl({ url: urlInput, auth: authConfig, maxDepth: crawlDepth, maxBudget: requestBudget });
            if (result.ok) {
                set({ scanResult: result, error: null });
                get().saveToHistory(result);
            }
            else
                set({ error: result.error || 'Scan thất bại', scanResult: null });
        }
        catch (err) {
            set({ error: (err instanceof Error ? err.message : String(err)) || 'Lỗi không xác định', scanResult: null });
        }
        finally {
            try {
                const listener = get()._progressListener;
                window.owaspWorkbench?.offScanProgress?.(listener ?? undefined);
            }
            catch (_e) {
                void 0;
            }
            set({ isLoading: false, _progressListener: null });
        }
    },
    performProjectScan: async () => {
        const { selectedFolder } = get();
        if (!selectedFolder) {
            set({ error: 'Vui lòng chọn thư mục project', scanResult: null });
            return;
        }
        get().clearProgress();
        set({ isLoading: true, error: null, scanResult: null });
        try {
            const cb = (ev) => get().appendProgress(ev);
            window.owaspWorkbench?.onScanProgress?.(cb);
            set({ _progressListener: cb });
        }
        catch (_e) {
            void 0;
        }
        try {
            const result = await ipc().scanProject(selectedFolder);
            if (result.ok) {
                set({ scanResult: result, error: null });
                get().saveToHistory(result);
            }
            else
                set({ error: result.error || 'Scan thất bại', scanResult: null });
        }
        catch (err) {
            set({ error: (err instanceof Error ? err.message : String(err)) || 'Lỗi không xác định', scanResult: null });
        }
        finally {
            try {
                const listener = get()._progressListener;
                window.owaspWorkbench?.offScanProgress?.(listener ?? undefined);
            }
            catch (_e) {
                void 0;
            }
            set({ isLoading: false, _progressListener: null });
        }
    },
    stopScan: async () => {
        try {
            await window.owaspWorkbench?.stopScan?.();
        }
        catch (_e) {
            void 0;
        }
        set({ isLoading: false, error: 'Scan đã bị hủy bởi người dùng.' });
        try {
            const listener = get()._progressListener;
            window.owaspWorkbench?.offScanProgress?.(listener ?? undefined);
        }
        catch (_e) {
            void 0;
        }
        set({ _progressListener: null });
    },
    loadChecklist: async () => {
        if (get().checklist)
            return;
        try {
            const r = await ipc().getChecklist();
            if (r.ok && r.data)
                set({ checklist: r.data });
        }
        catch (err) {
            console.warn('Checklist unavailable:', err.message);
        }
    },
    resetScan: () => set({ scanResult: null, error: null }),
    exportReport: async (format) => {
        const { scanResult } = get();
        if (!scanResult) {
            set({ error: 'Không có kết quả scan để xuất báo cáo' });
            return;
        }
        try {
            const r = await ipc().exportReport({ format, scanResult });
            if (!r.ok && !r.canceled)
                set({ error: r.error || 'Xuất báo cáo thất bại' });
        }
        catch (err) {
            set({ error: (err instanceof Error ? err.message : String(err)) || 'Xuất báo cáo thất bại' });
        }
    },
}));
