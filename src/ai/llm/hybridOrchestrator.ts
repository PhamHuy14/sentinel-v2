/**
 * Hybrid AI Orchestrator (Dieu phoi AI lai)
 *
 * Trien khai kien truc 3 lop (3-layer architecture):
 *   Lop 1 -> Knowledge Base (FAQ ngoai tuyen, phan hoi ngay lap tuc, uu tien cao nhat)
 *   Lop 2 -> LLM Da nha cung cap (API ben ngoai, dung du phong)
 *   Lop 3 -> Trinh kiem tra cheo / tong hop (trinh xac minh duoc tich hop vao LLMRouter)
 *
 * NANG CAP v2:
 *  - KB_MIN_LENGTH tang tu 80 -> 200: KB can cau tra loi du dai moi khong can LLM
 *  - Them logic HYBRID: ket hop KB + LLM khi KB tra loi duoc nhung cau hoi phuc tap
 *  - Phat hien cau hoi "can giai thich sau" de luon goi LLM
 *  - OOS_MARKERS mo rong de bat chinh xac hon
 *  - Fallback graceful: khong hien thi loi tho voi user
 */

import { AiQueryPayload, routeQuery } from '../aiRouter.js';
import { LLMRouter } from './llmRouter.js';
import { AiResponse } from './types';

// ── Nguong cai tien ─────────────────────────────────────────────────────────────────

/**
 * NANG CAP: Tang tu 80 -> 200.
 * KB can co cau tra loi du chat luong (it nhat 200 ky tu) moi duoc xem la "tot".
 * Dieu nay khien cac cau hoi phuc tap duoc escalate sang LLM thuong xuyen hon.
 */
const KB_MIN_LENGTH = 200;

/**
 * Do dai KB toi thieu cho cau hoi don gian (chao hoi, liet ke topic, v.v.)
 * Cac cau tra loi nay khong can LLM.
 */
const KB_SHORT_ANSWER_MIN = 50;

/** Marker nhan biet cau tra loi nam ngoai pham vi KB hoac la fallback */
const OOS_MARKERS = [
  'Ngoai pham vi ho tro',
  'Chua co trong knowledge base',
  'Toi la AI assistant **chuyen ve bao mat web**',
  '⚠️ **AI service temporarily unavailable.**',
  'Cau hoi nay nam ngoai',
  'khong thuoc pham vi',
];

/** Marker nhan biet day la cau tra loi don gian tu KB (khong can LLM bo sung) */
const SIMPLE_KB_MARKERS = [
  '## Toi ho tro nhung chu de nao',
  '## Toi la SENTINEL AI Assistant',
  'Xin chao!',
  'Cam on ban',
  'Rat vui',
];

/** Tu khoa goi y cau hoi can giai thich sau -> luon dung LLM */
const DEEP_EXPLAIN_MARKERS = [
  'tai sao', 'why', 'co che', 'mechanism', 'hoat dong nhu the nao',
  'how does', 'chi tiet', 'phan tich sau', 'so sanh', 'compare',
  'khac nhau', 'difference', 'vi du thuc te', 'real example',
  'cach khai thac', 'how to exploit', 'demonstrate', 'giai thich ky',
];

function stripDiacritics(text: string): string {
  return text.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

function isOOSResponse(text: string): boolean {
  const norm = stripDiacritics(text);
  return OOS_MARKERS.some(m => norm.includes(stripDiacritics(m)));
}

function isSimpleKBResponse(text: string): boolean {
  const norm = stripDiacritics(text);
  return SIMPLE_KB_MARKERS.some(m => norm.includes(stripDiacritics(m)));
}

function needsDeepExplanation(question: string): boolean {
  const q = stripDiacritics(question);
  return DEEP_EXPLAIN_MARKERS.some(m => q.includes(stripDiacritics(m)));
}

// ── Orchestrator ───────────────────────────────────────────────────────────────────
export class HybridOrchestrator {
  private readonly llmRouter: LLMRouter | null;

  constructor(llmRouter: LLMRouter | null = null) {
    this.llmRouter = llmRouter;
  }

  /**
   * Diem truy cap chinh.
   *
   * Logic uu tien (v2):
   * 1. KB tra loi cau don gian (chao/list topics) -> tra ve ngay, khong can LLM.
   * 2. Cau hoi "can giai thich sau" -> bo qua KB, di thang LLM.
   * 3. KB co cau tra loi du dai (>200 ky tu) va khong phai OOS -> tra ve tu KB.
   *    (Tuy chon: neu co LLM va cau tra loi ngan-vua, them context tu LLM)
   * 4. KB OOS hoac qua ngan -> dung LLM lam nguon chinh.
   * 5. Neu LLM cung that bai -> tra ve KB du chat luong kem.
   */
  async orchestrate(payload: AiQueryPayload): Promise<AiResponse> {
    const start    = Date.now();
    const warnings: string[] = [];
    const question = payload.question ?? '';

    // ── Lop 1a: Cau tra loi KB ─────────────────────────────────────────────────
    const kbAnswer = routeQuery(payload);

    // Neu KB tra ve cau don gian (chao hoi, liet ke, v.v.) -> dung luon
    if (isSimpleKBResponse(kbAnswer) && kbAnswer.length >= KB_SHORT_ANSWER_MIN) {
      return {
        answer:         kbAnswer,
        confidence:     0.90,
        providersTried: ['knowledge_base'],
        providerUsed:   'knowledge_base',
        crossChecked:   false,
        warnings:       [],
        latencyMs:      Date.now() - start,
        source:         'knowledge_base',
      };
    }

    // ── Lop 1b: Bo qua KB neu can giai thich sau ─────────────────────────────
    const skipKB = needsDeepExplanation(question) || kbAnswer === '' || isOOSResponse(kbAnswer);

    // ── Lop 1c: KB du tot -> tra ve tu KB ─────────────────────────────────────
    if (!skipKB && kbAnswer.length >= KB_MIN_LENGTH) {
      // Neu LLM co san va cau tra loi KB vua phai (200-600 ky tu), bo sung them tu LLM
      const shouldEnrichWithLLM = this.llmRouter !== null && kbAnswer.length < 600;

      if (!shouldEnrichWithLLM) {
        return {
          answer:         kbAnswer,
          confidence:     0.90,
          providersTried: ['knowledge_base'],
          providerUsed:   'knowledge_base',
          crossChecked:   false,
          warnings:       [],
          latencyMs:      Date.now() - start,
          source:         'knowledge_base',
        };
      }

      try {
        const enrichPayload = { ...payload, onToken: undefined };
        const llmResponse = await this.llmRouter!.query(enrichPayload);
        if (llmResponse.confidence >= 0.50 && !llmResponse.answer.includes('temporarily unavailable')) {
          const enriched = `${kbAnswer}\n\n---\n**🤖 Bo sung tu AI:**\n\n${llmResponse.answer}`;
          return {
            ...llmResponse,
            answer:         enriched,
            confidence:     Math.max(0.85, llmResponse.confidence),
            providersTried: ['knowledge_base', ...llmResponse.providersTried],
            warnings:       [...llmResponse.warnings, ...warnings],
            latencyMs:      Date.now() - start,
            source:         'synthesized',
          };
        }
      } catch {
        // Neu LLM that bai khi enrich, van tra ve KB
      }

      return {
        answer:         kbAnswer,
        confidence:     0.88,
        providersTried: ['knowledge_base'],
        providerUsed:   'knowledge_base',
        crossChecked:   false,
        warnings,
        latencyMs:      Date.now() - start,
        source:         'knowledge_base',
      };
    }

    // ── Lop 2: LLM lam nguon chinh ──────────────────────────────────────────────
    if (!this.llmRouter) {
      // Khong co LLM -> dung KB bat ke chat luong
      return {
        answer:         isOOSResponse(kbAnswer) || kbAnswer.length < 20
          ? 'Cau hoi nay chua co trong knowledge base. Vui long thu cau hinh API key (Gemini/Groq/OpenRouter) de nhan cau tra loi tu AI.'
          : kbAnswer,
        confidence:     0.35,
        providersTried: ['knowledge_base'],
        providerUsed:   'knowledge_base',
        crossChecked:   false,
        warnings:       ['LLM tier not configured; using knowledge base only'],
        latencyMs:      Date.now() - start,
        source:         'knowledge_base',
      };
    }

    try {
      const llmResponse = await this.llmRouter.query(payload);

      // Neu LLM tra ve cau tra loi te nhung KB co noi dung huu ich -> ket hop
      if (
        llmResponse.confidence < 0.30 &&
        kbAnswer.length > 60 &&
        !isOOSResponse(kbAnswer)
      ) {
        warnings.push('LLM confidence low; supplementing with knowledge base');
        return {
          ...llmResponse,
          answer:   `${kbAnswer}\n\n---\n*Them tu AI (confidence thap):*\n\n${llmResponse.answer}`,
          warnings: [...llmResponse.warnings, ...warnings],
          latencyMs: Date.now() - start,
          source:   'synthesized',
        };
      }

      return {
        ...llmResponse,
        warnings:  [...llmResponse.warnings, ...warnings],
        latencyMs: Date.now() - start,
      };
    } catch (err) {
      warnings.push(`LLM tier error: ${(err as Error).message}`);

      // Graceful fallback ve KB
      const fallbackAnswer = isOOSResponse(kbAnswer) || kbAnswer.length < 20
        ? '⚠️ Dich vu AI tam thoi khong kha dung va cau hoi nay chua co trong knowledge base. Vui long thu lai sau hoac hoi cau khac.'
        : kbAnswer;

      return {
        answer:         fallbackAnswer,
        confidence:     isOOSResponse(kbAnswer) ? 0.10 : 0.45,
        providersTried: ['knowledge_base'],
        providerUsed:   'knowledge_base',
        crossChecked:   false,
        warnings,
        latencyMs:      Date.now() - start,
        source:         'knowledge_base',
      };
    }
  }
}

// ── Singleton factory ──────────────────────────────────────────────────────────
let _instance: HybridOrchestrator | null = null;

export function getOrchestrator(): HybridOrchestrator {
  if (!_instance) _instance = new HybridOrchestrator(null);
  return _instance;
}

/**
 * Goi ham nay mot lan khi khoi dong ung dung de dua LLM router (voi cac nha cung cap that) vao su dung.
 * Co the goi nhieu lan an toan — luon thay the instance cu.
 */
export function initOrchestrator(llmRouter: LLMRouter): void {
  _instance = new HybridOrchestrator(llmRouter);
}

/**
 * Trinh bao boc tuong thich nguoc: tra ve chuoi van ban thuan.
 */
export async function orchestrateToString(payload: AiQueryPayload): Promise<string> {
  return (await getOrchestrator().orchestrate(payload)).answer;
}
