import { create } from 'zustand';
import { ScanResult, AuthConfig, ChecklistData, ScanProgressEvent, ScanHistoryEntry } from '../types';

const HISTORY_KEY  = 'sentinel_v2_history';
const MAX_HISTORY  = 10;
const MAX_LOG      = 200; // limit progressLog to avoid memory growth

// ── LocalStorage helpers ──────────────────────────────────────────────────────
function loadHistoryFromStorage(): ScanHistoryEntry[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY) || '[]';
    const entries: ScanHistoryEntry[] = JSON.parse(raw);
    return entries;
  } catch (_e) { return []; }
}

function saveHistoryToStorage(h: ScanHistoryEntry[]) {
  try {
    const slim = h.map(e => ({
      ...e,
      scanResult: {
        ...e.scanResult,
        findings: e.scanResult.findings.slice(0, 100),
      },
    }));
    localStorage.setItem(HISTORY_KEY, JSON.stringify(slim));
  } catch (_e) {
    try {
      const trimmed = h.slice(0, Math.max(1, Math.floor(h.length / 2)));
      localStorage.setItem(HISTORY_KEY, JSON.stringify(trimmed));
    } catch (_e2) { void 0; }
  }
}

function calcRiskScore(findings: ScanResult['findings']): number {
  const SEV_W: Record<string, number> = { critical: 10, high: 7, medium: 4, low: 1 };
  return Math.min(100, findings.reduce((s, f) => s + (SEV_W[f.severity] || 0), 0));
}

const ipc = () => {
  if (typeof window !== 'undefined' && window.owaspWorkbench) return window.owaspWorkbench;
  throw new Error('Ứng dụng cần chạy trong Electron. Khởi động bằng npm run dev.');
};

interface AppState {
  activeTab: 'url' | 'project' | 'checklist';
  setActiveTab: (tab: 'url' | 'project' | 'checklist') => void;
  isLoading: boolean;
  urlScanResult: ScanResult | null;
  projectScanResult: ScanResult | null;
  error: string | null;

  checkedChecklistItems: string[];
  toggleChecklistItem: (id: string) => void;

  urlInput: string;
  authConfig: AuthConfig;
  setUrlInput: (url: string) => void;
  setAuthConfig: (config: Partial<AuthConfig>) => void;

  crawlDepth: number;
  requestBudget: number;
  setCrawlDepth: (n: number) => void;
  setRequestBudget: (n: number) => void;

  selectedFolder: string | null;
  setSelectedFolder: (folder: string | null) => void;

  checklist: ChecklistData | null;

  progressLog: ScanProgressEvent[];
  appendProgress: (ev: ScanProgressEvent) => void;
  clearProgress: () => void;

  history: ScanHistoryEntry[];
  loadHistory: () => void;
  saveToHistory: (result: ScanResult) => void;
  restoreFromHistory: (id: string) => void;
  clearHistory: () => void;

  showHistoryDropdown: boolean;
  setShowHistoryDropdown: (show: boolean) => void;

  // ── Actions ────────────────────────────────────────────────
  performUrlScan: () => Promise<void>;
  performProjectScan: () => Promise<void>;
  stopScan: () => Promise<void>;
  loadChecklist: () => Promise<void>;
  resetScan: () => void;
  exportReport: (format: 'json' | 'html') => Promise<void>;

  // Track current listener ref for proper cleanup
  _progressListener: ((_e: ScanProgressEvent) => void) | null;
}

export const useStore = create<AppState>((set, get) => ({
  activeTab:  'url',
  setActiveTab: (tab) => set({ activeTab: tab }),

  isLoading: false,
  urlScanResult: null,
  projectScanResult: null,
  error: null,

  checkedChecklistItems: [],
  toggleChecklistItem: (id) => set((s) => ({
    checkedChecklistItems: s.checkedChecklistItems.includes(id) 
      ? s.checkedChecklistItems.filter(i => i !== id)
      : [...s.checkedChecklistItems, id]
  })),

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
      ? [...s.progressLog.slice(-MAX_LOG + 1), ev]  // rolling window
      : [...s.progressLog, ev],
  })),
  clearProgress: () => set({ progressLog: [] }),

  history: loadHistoryFromStorage(),
  loadHistory: () => set({ history: loadHistoryFromStorage() }),

  saveToHistory: (result) => {
    const riskScore = calcRiskScore(result.findings);
    const entry: ScanHistoryEntry = {
      id:       Date.now().toString(),
      ts:       Date.now(),
      mode:     result.mode,
      target:   result.scannedUrl || result.target || '',
      riskScore,
      summary:  { total: result.metadata.summary.total, bySeverity: result.metadata.summary.bySeverity },
      scanResult: result,
    };
    const updated = [entry, ...loadHistoryFromStorage()].slice(0, MAX_HISTORY);
    saveHistoryToStorage(updated);
    set({ history: updated });
  },

  restoreFromHistory: (id) => {
    const entry = get().history.find((e) => e.id === id);
    if (entry) {
      if (entry.mode === 'url-scan') {
        set({ urlScanResult: entry.scanResult, activeTab: 'url', error: null, showHistoryDropdown: false });
      } else {
        set({ projectScanResult: entry.scanResult, activeTab: 'project', error: null, showHistoryDropdown: false });
      }
    }
  },
  clearHistory: () => { saveHistoryToStorage([]); set({ history: [] }); },

  showHistoryDropdown: false,
  setShowHistoryDropdown: (show) => set({ showHistoryDropdown: show }),

  _progressListener: null,

  // ── Scan Actions ──────────────────────────────────────────
  performUrlScan: async () => {
    const { urlInput, authConfig, crawlDepth, requestBudget } = get();
    if (!urlInput.trim()) { set({ error: 'Vui lòng nhập URL mục tiêu' }); return; }
    get().clearProgress();
    set({ isLoading: true, error: null, urlScanResult: null });

    // Register progress listener and keep ref for cleanup
    try {
      const cb = (ev: ScanProgressEvent) => get().appendProgress(ev);
      window.owaspWorkbench?.onScanProgress?.(cb);
      set({ _progressListener: cb });
    } catch (_e) { void 0; }

    try {
      const result = await ipc().scanUrl({ url: urlInput, auth: authConfig, maxDepth: crawlDepth, maxBudget: requestBudget });
      if (result.ok) { set({ urlScanResult: result, error: null }); get().saveToHistory(result); }
      else set({ error: result.error || 'Scan thất bại' });
    } catch (err: Error | unknown) {
      set({ error: (err instanceof Error ? err.message : String(err)) || 'Lỗi không xác định' });
    } finally {
      try {
        const listener = get()._progressListener;
        window.owaspWorkbench?.offScanProgress?.(listener ?? undefined);
      } catch (_e) { void 0; }
      set({ isLoading: false, _progressListener: null });
    }
  },

  performProjectScan: async () => {
    const { selectedFolder } = get();
    if (!selectedFolder) { set({ error: 'Vui lòng chọn thư mục project' }); return; }
    get().clearProgress();
    set({ isLoading: true, error: null, projectScanResult: null });

    try {
      const cb = (ev: ScanProgressEvent) => get().appendProgress(ev);
      window.owaspWorkbench?.onScanProgress?.(cb);
      set({ _progressListener: cb });
    } catch (_e) { void 0; }

    try {
      const result = await ipc().scanProject(selectedFolder);
      if (result.ok) { set({ projectScanResult: result, error: null }); get().saveToHistory(result); }
      else set({ error: result.error || 'Scan thất bại' });
    } catch (err: Error | unknown) {
      set({ error: (err instanceof Error ? err.message : String(err)) || 'Lỗi không xác định' });
    } finally {
      try {
        const listener = get()._progressListener;
        window.owaspWorkbench?.offScanProgress?.(listener ?? undefined);
      } catch (_e) { void 0; }
      set({ isLoading: false, _progressListener: null });
    }
  },

  stopScan: async () => {
    try {
      await window.owaspWorkbench?.stopScan?.();
    } catch (_e) { void 0; }
    set({ isLoading: false, error: 'Scan đã bị hủy bởi người dùng.' });
    try {
      const listener = get()._progressListener;
      window.owaspWorkbench?.offScanProgress?.(listener ?? undefined);
    } catch (_e) { void 0; }
    set({ _progressListener: null });
  },

  loadChecklist: async () => {
    if (get().checklist) return;
    try {
      const r = await ipc().getChecklist();
      if (r.ok && r.data) set({ checklist: r.data });
    } catch (err: Error | unknown) { console.warn('Checklist unavailable:', err instanceof Error ? err.message : String(err)); }
  },

  resetScan: () => {
    if (get().activeTab === 'url') set({ urlScanResult: null, error: null });
    else set({ projectScanResult: null, checkedChecklistItems: [], error: null });
  },

  exportReport: async (format) => {
    const { urlScanResult, projectScanResult, activeTab } = get();
    const scanResult = activeTab === 'url' ? urlScanResult : projectScanResult;
    if (!scanResult) { set({ error: 'Không có kết quả scan để xuất báo cáo' }); return; }
    try {
      const r = await ipc().exportReport({ format, scanResult });
      if (!r.ok && !r.canceled) set({ error: r.error || 'Xuất báo cáo thất bại' });
    } catch (err: Error | unknown) {
      set({ error: (err instanceof Error ? err.message : String(err)) || 'Xuất báo cáo thất bại' });
    }
  },
}));
