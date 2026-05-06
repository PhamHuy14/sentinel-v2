/**
 * sentinelAI.ts — Tang goi LLM truc tiep (Direct LLM Caller)
 *
 * Day la tang du phong duoc goi khi LLMRouter (qua hybridOrchestrator) khong
 * kha dung, hoac khi can mot lenh goi don gian khong qua pipeline day du.
 *
 * NANG CAP v2:
 *  - SYSTEM_PROMPT mo rong va chi tiet hon
 *  - scoreAnswer() cai tien: nhan biet cau tra loi ne tranh, thieu noi dung
 *  - buildPrompt(): them huong dan output structure
 *  - targetScore(): nguong chat luong thuc te hon
 *  - max_tokens tang len 2048 mac dinh
 *  - callOpenAiCompatible: them temperature 0.3 (nhinh hon mot chut de phong phu hon)
 *  - Model list cap nhat: uu tien model moi hon va mien phi hon
 */

import { HISTORY_TURNS } from '../aiRouter.js';
import { sanitizePrompt } from './sanitizer.js';

type ChatRole = 'user' | 'assistant';

export interface SentinelHistoryItem {
  role: ChatRole;
  content: string;
}

export interface SentinelAskPayload {
  question: string;
  conversationHistory?: SentinelHistoryItem[];
  lastAssistantMessage?: string;
  findingContext?: Record<string, unknown>;
}

export interface SentinelAnswer {
  answer: string;
  confidence: number;
  providerUsed: string;
  modelUsed: string;
  providersTried: string[];
  warnings: string[];
  latencyMs: number;
  llmStatus: 'online' | 'offline';
  debug: SentinelDebugInfo;
}

export interface SentinelDebugInfo {
  providerUsed: string;
  modelUsed: string;
  latencyMs: number;
  confidence: number;
  providersTried: string[];
  warningCount: number;
  configuredProviderCount: number;
}

type ProviderId = 'groq' | 'gemini' | 'openrouter' | 'together' | 'huggingface';

interface ProviderProfile {
  id: ProviderId;
  apiKeyEnv: string;
  models: string[];
  endpoint: string;
  timeoutMs: number;
  openAiCompatible: boolean;
}

interface CandidateAnswer {
  answer: string;
  confidence: number;
  providerUsed: string;
  modelUsed: string;
}

function buildDebugInfo(
  answer: Pick<SentinelAnswer, 'providerUsed' | 'modelUsed' | 'latencyMs' | 'confidence'>,
  providersTried: string[],
  warnings: string[],
  configuredProviderCount: number,
): SentinelDebugInfo {
  return {
    providerUsed: answer.providerUsed,
    modelUsed: answer.modelUsed,
    latencyMs: answer.latencyMs,
    confidence: answer.confidence,
    providersTried,
    warningCount: warnings.length,
    configuredProviderCount,
  };
}

// NANG CAP: Groq dung dau (nhanh nhat + free), Gemini thu 2
const DEFAULT_PROVIDER_ORDER: ProviderId[] = ['groq', 'gemini', 'openrouter', 'together', 'huggingface'];

// NANG CAP: Cap nhat model list voi cac model moi hon, manh hon
const DEFAULT_MODELS: Record<ProviderId, string[]> = {
  groq: [
    'llama-3.3-70b-versatile',
    'llama-3.1-8b-instant',
    'llama3-8b-8192',
  ],
  gemini: [
    'gemini-2.0-flash',
    'gemini-1.5-flash',
    'gemini-2.0-flash-lite',
  ],
  openrouter: [
    'meta-llama/llama-3.3-70b-instruct:free',
    'meta-llama/llama-3.1-8b-instruct:free',
    'mistralai/mistral-7b-instruct:free',
  ],
  together: [
    'meta-llama/Llama-3.3-70B-Instruct-Turbo-Free',
    'Qwen/Qwen2.5-72B-Instruct-Turbo',
  ],
  huggingface: [
    'Qwen/Qwen2.5-72B-Instruct',
    'mistralai/Mistral-7B-Instruct-v0.3',
  ],
};

// NANG CAP: System prompt chi tiet hon, huong dan cu the hon
const SYSTEM_PROMPT = [
  'Ban la SENTINEL AI — chuyen gia bao mat web va OWASP cap cao, tich hop trong SENTINEL OWASP Security Workbench.',
  '',
  '**QUY TAC BAT BUOC:**',
  '1. Luon tra loi bang tieng Viet chuyen nghiep, tu nhien (tru khi duoc yeu cau khac).',
  '2. KHONG BAO GIO noi "Toi khong co du thong tin" hay "Cau hoi nay kha phuc tap" ma khong giai thich.',
  '3. KHONG viet cau tra loi qua ngan (duoi 150 tu) voi cau hoi ky thuat.',
  '4. Voi cau hoi ve lo hong: giai thich co che + vi du PoC minh hoa (khong phai exploit thuc te) + cach fix.',
  '5. Voi cau hoi so sanh: dung bang hoac danh sach co cau truc ro rang.',
  '6. Voi cau hoi "la gi": dinh nghia + vi du thuc te + tam quan trong.',
  '7. Voi cau hoi "cach fix": liet ke tung buoc, kem code snippet neu phu hop.',
  '',
  '**DINH DANG:**',
  '- Dung Markdown: ## tieu de, **in dam**, `code`, danh sach -.',
  '- Emoji vua phai: ⚠️ 🔴 ✅ 🛡️ de highlight y chinh.',
  '- Code snippet: dung ```language ... ``` khi co vi du code.',
  '',
  '**GIOI HAN AN TOAN:**',
  '- KHONG cung cap payload exploit co the chay ngay de tan cong thuc te.',
  '- Chi dung PoC minh hoa ngan gon de giao duc phong thu.',
].join('\n');



function readEnv(name: string): string {
  const env = (import.meta as unknown as { env?: Record<string, string> }).env ?? {};
  return (env[name] ?? '').trim();
}

function splitCsv(raw: string, fallback: string[]): string[] {
  const items = raw
    .split(',')
    .map(v => v.trim())
    .filter(Boolean);
  return items.length ? items : fallback;
}

function createProviderProfiles(): ProviderProfile[] {
  return [
    {
      id: 'groq',
      apiKeyEnv: 'VITE_GROQ_API_KEY',
      models: splitCsv(readEnv('VITE_GROQ_MODELS'), DEFAULT_MODELS.groq),
      endpoint: 'https://api.groq.com/openai/v1/chat/completions',
      timeoutMs: Number(readEnv('VITE_GROQ_TIMEOUT_MS') || '15000'),
      openAiCompatible: true,
    },
    {
      id: 'gemini',
      apiKeyEnv: 'VITE_GEMINI_API_KEY',
      models: splitCsv(readEnv('VITE_GEMINI_MODELS'), DEFAULT_MODELS.gemini),
      endpoint: 'https://generativelanguage.googleapis.com/v1beta/models',
      timeoutMs: Number(readEnv('VITE_GEMINI_TIMEOUT_MS') || '20000'),
      openAiCompatible: false,
    },
    {
      id: 'openrouter',
      apiKeyEnv: 'VITE_OPENROUTER_API_KEY',
      models: splitCsv(readEnv('VITE_OPENROUTER_MODELS'), DEFAULT_MODELS.openrouter),
      endpoint: 'https://openrouter.ai/api/v1/chat/completions',
      timeoutMs: Number(readEnv('VITE_OPENROUTER_TIMEOUT_MS') || '20000'),
      openAiCompatible: true,
    },
    {
      id: 'together',
      apiKeyEnv: 'VITE_TOGETHER_API_KEY',
      models: splitCsv(readEnv('VITE_TOGETHER_MODELS'), DEFAULT_MODELS.together),
      endpoint: 'https://api.together.xyz/v1/chat/completions',
      timeoutMs: Number(readEnv('VITE_TOGETHER_TIMEOUT_MS') || '20000'),
      openAiCompatible: true,
    },
    {
      id: 'huggingface',
      apiKeyEnv: 'VITE_HF_API_KEY',
      models: splitCsv(readEnv('VITE_HF_MODELS'), DEFAULT_MODELS.huggingface),
      endpoint: 'https://router.huggingface.co/novita/v3/openai/chat/completions',
      timeoutMs: Number(readEnv('VITE_HF_TIMEOUT_MS') || '30000'),
      openAiCompatible: true,
    },
  ];
}

function getProviderOrder(): ProviderId[] {
  const configured = splitCsv(readEnv('VITE_LLM_PROVIDER_PRIORITY'), DEFAULT_PROVIDER_ORDER);
  const valid = configured.filter((id): id is ProviderId =>
    id === 'groq' || id === 'gemini' || id === 'openrouter' || id === 'together' || id === 'huggingface',
  );
  return valid.length ? valid : DEFAULT_PROVIDER_ORDER;
}

// NANG CAP: buildPrompt them huong dan output structure dua tren loai cau hoi
function buildPrompt(payload: SentinelAskPayload): string {
  const sections: string[] = [];
  const q = payload.question.trim();

  sections.push(`User question:\n${q}`);

  if (payload.findingContext && Object.keys(payload.findingContext).length > 0) {
    sections.push(`Finding context (JSON):\n${JSON.stringify(payload.findingContext, null, 2)}`);
  }

  if (payload.lastAssistantMessage?.trim()) {
    sections.push(`Last assistant message:\n${payload.lastAssistantMessage.trim()}`);
  }

  if (payload.conversationHistory && payload.conversationHistory.length > 0) {
    const history = payload.conversationHistory
      .slice(-HISTORY_TURNS)
      .map(item => `${item.role.toUpperCase()}: ${item.content}`)
      .join('\n');
    sections.push(`Recent conversation:\n${history}`);
  }

  // Huong dan output theo loai cau hoi
  const qLower = q.toLowerCase();
  const instructions = ['Huong dan tra loi:'];

  if (qLower.includes('tai sao') || qLower.includes('why') || qLower.includes('co che')) {
    instructions.push(
      '- Giai thich NGUYEN NHAN va CO CHE ky thuat.',
      '- Bao gom vi du minh hoa thuc te.',
      '- Neu ro tac dong va hau qua.',
    );
  } else if (qLower.includes('so sanh') || qLower.includes('compare') || qLower.includes('khac nhau')) {
    instructions.push(
      '- Tao bang so sanh hoac danh sach ro rang.',
      '- Neu diem giong nhau va khac nhau cu the.',
      '- Cho vi du khi nao dung cai nao.',
    );
  } else if (qLower.includes('fix') || qLower.includes('khac phuc') || qLower.includes('phong')) {
    instructions.push(
      '- Liet ke cac buoc fix theo thu tu uu tien.',
      '- Kem code snippet minh hoa neu phu hop.',
      '- De cap ca server-side va client-side neu lien quan.',
    );
  } else if (qLower.includes('la gi') || qLower.includes('what is') || qLower.includes('dinh nghia')) {
    instructions.push(
      '- Dinh nghia ro rang, suc tich.',
      '- Vi du tan cong thuc te minh hoa.',
      '- Cach phat hien va phong chong.',
    );
  } else {
    instructions.push(
      '- Tra loi day du, chi tiet, co cau truc.',
      '- Khong ket thuc cau tra loi dot ngot.',
    );
  }

  instructions.push('- KHONG tra loi chung chung; phai co thong tin ky thuat cu the.');
  sections.push(instructions.join('\n'));

  return sections.join('\n\n');
}

function isUnsafeOffensiveRequest(question: string): boolean {
  const q = question.toLowerCase();
  const markers = [
    'reverse shell',
    'sqlmap command',
    'drop database',
    'hack website',
    'chi tiet tan cong',
    'executable exploit',
    'metasploit module',
    'create malware',
    'ransomware',
  ];
  return markers.some(m => q.includes(m));
}

function offensiveRefusal(): SentinelAnswer {
  const configuredProviderCount = createProviderProfiles()
    .filter(provider => Boolean(readEnv(provider.apiKeyEnv)))
    .length;

  return {
    answer:
      '🛡️ Minh khong the ho tro huong dan tan cong hoac cung cap payload khai thac thuc te.\n\n' +
      'Neu ban muon, minh co the giup theo huong **phong thu**:\n' +
      '- Cach phat hien lo hong trong code\n' +
      '- Harden cau hinh server/ung dung\n' +
      '- Checklist bao mat OWASP\n' +
      '- Review security best practices',
    confidence: 0.98,
    providerUsed: 'policy',
    modelUsed: 'policy',
    providersTried: ['policy'],
    warnings: ['Blocked offensive request'],
    latencyMs: 0,
    llmStatus: 'offline',
    debug: buildDebugInfo(
      { providerUsed: 'policy', modelUsed: 'policy', latencyMs: 0, confidence: 0.98 },
      ['policy'],
      ['Blocked offensive request'],
      configuredProviderCount,
    ),
  };
}

function normalizeWhitespace(text: string): string {
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
}

// NANG CAP: scoreAnswer cai tien dang ke
function scoreAnswer(question: string, answer: string): number {
  if (!answer.trim()) return 0;

  const text = answer.toLowerCase();
  const len  = answer.length;

  // Phat hien cau tra loi ne tranh -> diem rat thap
  const evasiveMarkers = [
    'toi khong co du thong tin',
    'cau hoi nay kha phuc tap',
    'i am an ai language model',
    'i cannot provide information',
    'as an ai, i',
    'i don\'t have',
    'khong the cung cap thong tin',
  ];
  if (evasiveMarkers.some(m => text.includes(m)) && len < 400) {
    return 0.10;
  }

  let score = 0.20;

  // Diem theo do dai
  if (len > 80)   score += 0.08;
  if (len > 200)  score += 0.10;
  if (len > 450)  score += 0.10;
  if (len > 800)  score += 0.08;
  if (len > 1200) score += 0.05;

  // Diem noi dung bao mat
  if (text.includes('owasp'))   score += 0.06;
  if (text.includes('cwe-'))    score += 0.05;
  if (text.includes('```'))     score += 0.08;
  if (text.includes('##'))      score += 0.04;
  if (text.includes('- '))      score += 0.03;
  if (
    text.includes('vi du') || text.includes('example') ||
    text.includes('minh hoa') || text.includes('chang han')
  ) score += 0.07;
  if (
    text.includes('buoc') || text.includes('step') ||
    text.includes('1.') || text.includes('1)')
  ) score += 0.05;
  if (
    text.includes('khac phuc') || text.includes('fix') ||
    text.includes('remediat') || text.includes('phong ngua') ||
    text.includes('ngan chan')
  ) score += 0.08;
  if (
    text.includes('co che') || text.includes('mechanism') ||
    text.includes('tai sao') || text.includes('nguyen nhan')
  ) score += 0.06;

  // Penalty
  if (text.includes('toi la ai') || text.includes('i am an ai language model')) score -= 0.15;
  if (text.includes('khong biet') && len < 120) score -= 0.10;
  if (question.trim().length < 15 && len > 800) score -= 0.05;
  if (text.includes('reverse shell') || text.includes('sqlmap')) score -= 0.25;

  return Math.max(0, Math.min(1, score));
}

// NANG CAP: Nguong chat luong thuc te hon
function targetScore(question: string): number {
  const q = question.toLowerCase();

  // Cau hoi phuc tap can cau tra loi chi tiet hon
  if (q.includes('tai sao') || q.includes('why') || q.includes('co che') || q.includes('so sanh')) {
    return 0.52;
  }
  if (q.includes('la gi') || q.includes('what is') || q.includes('dinh nghia')) {
    return 0.46;
  }
  if (q.includes('cach fix') || q.includes('khac phuc') || q.includes('how to fix')) {
    return 0.50;
  }
  // Cau hoi ngan/chao hoi
  if (question.trim().length < 20) {
    return 0.38;
  }
  return 0.48;
}

function buildHeaders(provider: ProviderProfile, apiKey: string): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${apiKey}`,
  };
  if (provider.id === 'openrouter') {
    headers['HTTP-Referer'] = 'https://sentinel.local';
    headers['X-Title'] = 'SENTINEL OWASP Assistant';
  }
  return headers;
}

interface OpenAiMessage {
  role: 'system' | 'user';
  content: string;
}

interface OpenAiLikeChoice {
  message?: {
    content?: string | Array<{ type?: string; text?: string }>;
  };
}

interface OpenAiLikeResponse {
  choices?: OpenAiLikeChoice[];
}

function extractOpenAiContent(data: OpenAiLikeResponse): string {
  const content = data.choices?.[0]?.message?.content;
  if (!content) return '';
  if (typeof content === 'string') return content;
  return content
    .map(item => (item.type === 'text' ? item.text ?? '' : ''))
    .join('')
    .trim();
}

async function callOpenAiCompatible(
  provider: ProviderProfile,
  apiKey: string,
  model: string,
  userPrompt: string,
): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), provider.timeoutMs);

  // NANG CAP: max_tokens tang len 2048 mac dinh
  const body = {
    model,
    temperature: 0.3,
    max_tokens: Number(readEnv('VITE_LLM_MAX_OUTPUT_TOKENS') || '2048'),
    messages: [
      { role: 'system', content: SYSTEM_PROMPT } satisfies OpenAiMessage,
      { role: 'user',   content: userPrompt    } satisfies OpenAiMessage,
    ],
  };

  try {
    const response = await fetch(provider.endpoint, {
      method: 'POST',
      headers: buildHeaders(provider, apiKey),
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`${provider.id}:${model} HTTP ${response.status}`);
    }

    const data = await response.json() as OpenAiLikeResponse;
    return normalizeWhitespace(extractOpenAiContent(data));
  } finally {
    clearTimeout(timer);
  }
}

interface GeminiApiResponse {
  candidates?: Array<{
    content?: {
      parts?: Array<{ text?: string }>;
    };
  }>;
  error?: { message?: string; code?: number };
}

async function callGemini(
  provider: ProviderProfile,
  apiKey: string,
  model: string,
  userPrompt: string,
): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), provider.timeoutMs);
  const url = `${provider.endpoint}/${model}:generateContent?key=${apiKey}`;

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        system_instruction: { parts: [{ text: SYSTEM_PROMPT }] },
        contents: [{ role: 'user', parts: [{ text: userPrompt }] }],
        generationConfig: {
          temperature: 0.3,
          maxOutputTokens: Number(readEnv('VITE_LLM_MAX_OUTPUT_TOKENS') || '2048'),
        },
      }),
      signal: controller.signal,
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => '');
      let detail = `HTTP ${response.status}`;
      try {
        const parsed = JSON.parse(errText) as GeminiApiResponse;
        if (parsed?.error?.message) detail = `HTTP ${response.status}: ${parsed.error.message}`;
      } catch { /* ignore */ }
      throw new Error(`gemini:${model} ${detail}`);
    }

    const data = await response.json() as GeminiApiResponse;
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text ?? '';
    return normalizeWhitespace(text);
  } finally {
    clearTimeout(timer);
  }
}

async function callProviderModel(
  provider: ProviderProfile,
  apiKey: string,
  model: string,
  userPrompt: string,
): Promise<string> {
  if (provider.id === 'gemini') {
    return callGemini(provider, apiKey, model, userPrompt);
  }
  // HuggingFace cung dung OpenAI-compatible endpoint moi
  return callOpenAiCompatible(provider, apiKey, model, userPrompt);
}

function fallbackAnswer(warnings: string[], latencyMs: number, tried: string[] = []): SentinelAnswer {
  const configuredProviderCount = createProviderProfiles()
    .filter(provider => Boolean(readEnv(provider.apiKeyEnv)))
    .length;

  return {
    answer:
      '⚠️ **Cac API AI hien khong kha dung hoac het quota.**\n\n' +
      'Ban van co the su dung knowledge base offline de hoi ve OWASP Top 10 va bao mat web co ban.\n\n' +
      '**De kich hoat AI day du**, hay kiem tra API key trong file `.env`:\n' +
      '- `VITE_GROQ_API_KEY` — Groq (nhanh nhat, mien phi tai console.groq.com)\n' +
      '- `VITE_GEMINI_API_KEY` — Google Gemini (aistudio.google.com)\n' +
      '- `VITE_OPENROUTER_API_KEY` — OpenRouter (openrouter.ai)\n' +
      '- `VITE_TOGETHER_API_KEY` — Together AI\n' +
      '- `VITE_HF_API_KEY` — HuggingFace',
    confidence: 0.20,
    providerUsed: 'fallback',
    modelUsed: 'fallback',
    providersTried: tried,
    warnings,
    latencyMs,
    llmStatus: 'offline',
    debug: buildDebugInfo(
      { providerUsed: 'fallback', modelUsed: 'fallback', latencyMs, confidence: 0.20 },
      tried,
      warnings,
      configuredProviderCount,
    ),
  };
}

export async function askSentinelAI(payload: SentinelAskPayload): Promise<SentinelAnswer> {
  const start    = Date.now();
  const question = payload.question.trim();
  const providerProfiles = createProviderProfiles();
  const configuredProviderCount = providerProfiles
    .filter(provider => Boolean(readEnv(provider.apiKeyEnv)))
    .length;

  if (!question) {
    const latencyMs = Date.now() - start;
    return {
      answer: 'Ban hay nhap cau hoi cu the hon de minh ho tro chinh xac nhe.',
      confidence: 0.20,
      providerUsed: 'validation',
      modelUsed: 'validation',
      providersTried: ['validation'],
      warnings: ['Empty question'],
      latencyMs,
      llmStatus: 'offline',
      debug: buildDebugInfo(
        { providerUsed: 'validation', modelUsed: 'validation', latencyMs, confidence: 0.20 },
        ['validation'],
        ['Empty question'],
        configuredProviderCount,
      ),
    };
  }

  if (isUnsafeOffensiveRequest(question)) {
    const blocked  = offensiveRefusal();
    const latencyMs = Date.now() - start;
    return {
      ...blocked,
      latencyMs,
      llmStatus: 'offline',
      debug: buildDebugInfo(
        { providerUsed: 'policy', modelUsed: 'policy', latencyMs, confidence: blocked.confidence },
        blocked.providersTried,
        blocked.warnings,
        configuredProviderCount,
      ),
    };
  }

  const warnings: string[] = [];
  const tried: string[]    = [];
  const providerOrder      = getProviderOrder();
  const profileById        = new Map(providerProfiles.map(p => [p.id, p]));
  const requestedMaxInputTokens = Number(readEnv('VITE_LLM_MAX_INPUT_TOKENS') || '2500');
  const enrichedPrompt     = buildPrompt(payload);
  const sanitized          = sanitizePrompt(enrichedPrompt, requestedMaxInputTokens);
  warnings.push(...sanitized.warnings);

  let best: CandidateAnswer | null = null;
  const minScore = targetScore(question);

  for (const providerId of providerOrder) {
    const provider = profileById.get(providerId);
    if (!provider) continue;

    const apiKey = readEnv(provider.apiKeyEnv);
    if (!apiKey) {
      warnings.push(`${provider.id} skipped (missing ${provider.apiKeyEnv})`);
      continue;
    }

    for (const model of provider.models) {
      const attemptId = `${provider.id}:${model}`;
      tried.push(attemptId);
      try {
        const answer     = await callProviderModel(provider, apiKey, model, sanitized.prompt);
        const confidence = scoreAnswer(question, answer);

        if (!best || confidence > best.confidence) {
          best = { answer, confidence, providerUsed: provider.id, modelUsed: model };
        }

        // Du tot -> tra ve ngay
        if (confidence >= minScore) {
          const latencyMs = Date.now() - start;
          return {
            answer,
            confidence,
            providerUsed: provider.id,
            modelUsed: model,
            providersTried: tried,
            warnings,
            latencyMs,
            llmStatus: 'online',
            debug: buildDebugInfo(
              { providerUsed: provider.id, modelUsed: model, latencyMs, confidence },
              tried,
              warnings,
              configuredProviderCount,
            ),
          };
        }
      } catch (error) {
        warnings.push(`${attemptId} failed: ${(error as Error).message}`);
      }
    }
  }

  // Tra ve best-effort neu co
  if (best) {
    warnings.push('Returned best-effort answer (below quality threshold)');
    const latencyMs = Date.now() - start;
    return {
      answer: best.answer,
      confidence: best.confidence,
      providerUsed: best.providerUsed,
      modelUsed: best.modelUsed,
      providersTried: tried,
      warnings,
      latencyMs,
      llmStatus: 'online',
      debug: buildDebugInfo(
        {
          providerUsed: best.providerUsed,
          modelUsed: best.modelUsed,
          latencyMs,
          confidence: best.confidence,
        },
        tried,
        warnings,
        configuredProviderCount,
      ),
    };
  }

  return fallbackAnswer(warnings, Date.now() - start, tried);
}
