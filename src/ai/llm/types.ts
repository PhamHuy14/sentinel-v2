/**
 * Giao dien nha cung cap LLM & Cac kieu du lieu dung chung
 *
 * Dinh nghia hop dong ma moi adapter cua nha cung cap phai trien khai,
 * cung voi doi tuong phan hoi chuan tra ve cho nguoi goi.
 */

// ── Trang thai suc khoe nha cung cap ───────────────────────────────────────────────────
export interface ProviderHealth {
  /** Diem so 0–1; 1 = hoan toan khoe manh */
  score: number;
  /** Uoc luong han muc con lai (don vi tuy y, tuy thuoc vao nha cung cap) */
  remainingQuota: number;
  /** Do tre trung binh tinh bang ms tu cac lenh goi gan day */
  avgLatencyMs: number;
  /** Ty le loi trong N lenh goi gan nhat (0–1) */
  recentErrorRate: number;
  /** Trang thai ngat mach (circuit-breaker) co dang mo hay khong */
  circuitOpen: boolean;
}

// ── Truu tuong hoa nha cung cap ───────────────────────────────────────────────────────
export interface LLMProvider {
  /** Dinh danh duy nhat, vi du: "groq", "together", "huggingface" */
  readonly id: string;
  /** Nhan hien thi cho nguoi dung doc */
  readonly label: string;
  /** Nha cung cap nay co ho tro dau ra dang JSON goc hay khong */
  readonly supportsJsonMode: boolean;

  /**
   * Tao phan hoi cho `prompt`.
   * @param prompt - Chuoi prompt da duoc lam sach.
   * @param options - Cac tuy chon ghi de (maxTokens, systemPrompt, jsonMode).
   * @returns Phan hoi dang van ban tho.
   * @throws {ProviderError} khi co loi cap API.
   */
  generate(prompt: string, options?: GenerateOptions): Promise<string>;

  /**
   * Kiem tra nhanh trang thai hoat dong / han muc.
   * Nen nhe nhang — ly tuong nhat la mot lenh goi sieu du lieu re hoac duoc cache.
   */
  health(): Promise<ProviderHealth>;

  /**
   * Tra ve uoc luong han muc con lai.
   * Co the tra ve Infinity khi han muc khong xac dinh hoac khong gioi han.
   */
  estimateCostOrQuota(): Promise<number>;
}

// ── Tuy chon tao phan hoi ───────────────────────────────────────────────────────────
export interface GenerateOptions {
  maxTokens?: number;
  systemPrompt?: string;
  jsonMode?: boolean;
  /** Ghi de thoi gian cho o cap do request tinh bang ms */
  timeoutMs?: number;
  /** AbortSignal de huy request dang chay */
  signal?: AbortSignal;
  /** Streaming token callback (neu nha cung cap ho tro) */
  onToken?: (token: string) => void;
  /** Bat streaming khi co onToken */
  stream?: boolean;
}

// ── Loi tu nha cung cap ───────────────────────────────────────────────────────────
export type ProviderErrorKind =
  | 'rate_limit'      // 429
  | 'server_error'    // 5xx
  | 'timeout'
  | 'auth_error'      // 401/403
  | 'bad_request'     // 400
  | 'unknown';

export class ProviderError extends Error {
  constructor(
    public readonly kind: ProviderErrorKind,
    public readonly providerId: string,
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = 'ProviderError';
  }
}

// ── Phan hoi AI chuan muc ─────────────────────────────────────────────────────
export interface AiResponse {
  /** Cau tra loi cuoi cung tra ve cho nguoi dung */
  answer: string;
  /** Diem do tin cay tu 0–1 */
  confidence: number;
  /** Tat ca cac nha cung cap da duoc thu */
  providersTried: string[];
  /** Nha cung cap co cau tra loi cuoi cung duoc su dung */
  providerUsed: string;
  /** Da thuc hien kiem tra cheo hay chua */
  crossChecked: boolean;
  /** Cac canh bao khong nghiem trong (vi du: "nha cung cap X qua han, dung du phong") */
  warnings: string[];
  /** Tong do tre thuc te tinh bang ms */
  latencyMs: number;
  /** Lop nguon cung cap: 'knowledge_base' | 'llm' | 'synthesized' */
  source: 'knowledge_base' | 'llm' | 'synthesized';
}

// ── Cau hinh bo dinh tuyen ─────────────────────────────────────────────────────────────
export interface RouterConfig {
  /**
   * ID cua cac nha cung cap theo thu tu uu tien.
   * Bo dinh tuyen se thu cac nha cung cap co muc uu tien cao hon truoc,
   * tuy thuoc vao diem suc khoe.
   */
  providerPriority: string[];

  /** Trong so dung trong diem lua chon nha cung cap (moi cai trong khoang 0–1) */
  selectionWeights: {
    health: number;
    quota: number;
    latency: number;
    errorRate: number;
  };

  /** Thoi gian toi da cho mot lenh goi nha cung cap, ms */
  timeoutMs: number;

  /** So lan thu lai mot lenh goi that bai truoc khi chuyen sang nha cung cap tiep theo */
  maxRetries: number;

  /** Do tre co so cho thuat toan back-off cap so nhan, ms */
  retryBaseDelayMs: number;

  /** Gioi han do tre back-off toi da, ms */
  retryMaxDelayMs: number;

  /**
   * So lan that bai lien tiep de ngat mach (circuit breaker).
   * Khi bi ngat, nha cung cap se bi bo qua trong `circuitResetMs`.
   */
  circuitBreakerThreshold: number;

  /** Thoi gian duy tri trang thai ngat mach truoc khi thu lai, ms */
  circuitResetMs: number;

  /** Thoi gian song (TTL) cho cac cau tra loi duoc cache, ms */
  cacheTtlMs: number;

  /** So luong muc toi da trong cache */
  cacheMaxSize: number;

  /**
   * Diem tin cay toi thieu tu mot nha cung cap de bo qua kiem tra cheo.
   * Duoi nguong nay, nha cung cap thu hai cung se duoc truy van.
   */
  crossCheckThreshold: number;

  /**
   * Cho phep hoac vo hieu hoa kiem tra cheo.
   * Co the duoc bat/tat theo moi truong thong qua bien moi truong.
   */
  crossCheckEnabled: boolean;

  /** So luong token toi da gui den nha cung cap (bao ve dau vao) */
  maxInputTokens: number;

  /** So luong token toi da yeu cau tu nha cung cap (bao ve dau ra) */
  maxOutputTokens: number;
}

// ── Cau hinh mac dinh ─────────────────────────────────────────────────────────────
// NANG CAP: maxOutputTokens tang tu 512 -> 2048 de co cau tra loi day du hon
// NANG CAP: maxInputTokens tang tu 1500 -> 2500 de gui nhieu ngu canh hon
// NANG CAP: timeoutMs tang tu 12s -> 20s de nha cung cap co du thoi gian tra loi
// NANG CAP: crossCheckThreshold giam tu 0.65 -> 0.55 de kich hoat cross-check it thuong xuyen hon (tiet kiem quota)
// NANG CAP: circuitBreakerThreshold tang tu 5 -> 6 de it bi ngat mach hon
export const DEFAULT_ROUTER_CONFIG: RouterConfig = {
  providerPriority: ['groq', 'gemini', 'openrouter', 'together', 'huggingface'],
  selectionWeights: { health: 0.35, quota: 0.25, latency: 0.25, errorRate: 0.15 },
  timeoutMs: 20_000,
  maxRetries: 2,
  retryBaseDelayMs: 400,
  retryMaxDelayMs: 5_000,
  circuitBreakerThreshold: 6,
  circuitResetMs: 90_000,
  cacheTtlMs: 10 * 60_000,
  cacheMaxSize: 300,
  crossCheckThreshold: 0.55,
  crossCheckEnabled: true,
  maxInputTokens: 2_500,
  maxOutputTokens: 2_048,
};
