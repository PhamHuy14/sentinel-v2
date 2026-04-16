/**
 * AI Chat Store — tách biệt với useStore chính để tránh bloat.
 * Dùng để truyền pending finding từ FindingCard → AIChatWidget
 * mà không cần prop drilling qua nhiều tầng component.
 */
import { create } from 'zustand';
import type { Finding } from '../types';

export type AIFabMode = 'normal' | 'dim' | 'hidden';

interface AIState {
  isOpen: boolean;
  pendingFinding: Finding | null;
  fabMode: AIFabMode;
  setAIChatOpen: (open: boolean) => void;
  toggleAIChat: () => void;
  setAIPendingFinding: (finding: Finding | null) => void;
  clearAIPendingFinding: () => void;
  setAIFabMode: (mode: AIFabMode) => void;
  cycleAIFabMode: () => void;
}

const FAB_MODE_KEY = 'sentinel_v2_ai_fab_mode';

function loadFabMode(): AIFabMode {
  try {
    const v = localStorage.getItem(FAB_MODE_KEY);
    if (v === 'normal' || v === 'dim' || v === 'hidden') return v;
  } catch { /* ignore */ }
  return 'normal';
}

function saveFabMode(mode: AIFabMode) {
  try { localStorage.setItem(FAB_MODE_KEY, mode); } catch { /* ignore */ }
}

export const useAIStore = create<AIState>((set, get) => ({
  isOpen: false,
  pendingFinding: null,
  fabMode: loadFabMode(),

  setAIChatOpen: (open) => set({ isOpen: open }),
  toggleAIChat: () => set({ isOpen: !get().isOpen }),
  setAIPendingFinding: (finding) => set({ pendingFinding: finding }),
  clearAIPendingFinding: () => set({ pendingFinding: null }),

  setAIFabMode: (mode) => {
    saveFabMode(mode);
    set({ fabMode: mode });
  },
  cycleAIFabMode: () => {
    const cur = get().fabMode;
    const next: AIFabMode = cur === 'normal' ? 'dim' : cur === 'dim' ? 'hidden' : 'normal';
    saveFabMode(next);
    set({ fabMode: next });
  },
}));
