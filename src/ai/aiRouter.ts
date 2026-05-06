/**
 * AI Router v4 — Nâng cấp toàn diện
 *
 * Cải tiến so với v3:
 * - Thêm fuzzy matching với Levenshtein distance để bắt lỗi chính tả
 * - Dedup: tránh trả cùng câu trả lời nhiều lần liên tiếp
 * - Conversation memory: hiểu ngữ cảnh 3 turn gần nhất
 * - Response variant pool: nhiều cách diễn đạt greeting/OOS để tránh lặp
 * - Compound intent: detect kết hợp ý định (what_is + how_to_fix)
 * - Sub-intent branching: cùng topic nhưng intent khác nhau → reply khác
 * - Confidence scoring chi tiết hơn với bonus ngữ cảnh
 * - New topics: GraphQL, WebSocket, HSTS preload, 2FA/MFA, OAuth, file upload
 * - Typo tolerance: xử lý "sqli", "xsss", "crsf", "srf", "idoor"
 * - Tối ưu hóa stop words tiếng Việt đầy đủ hơn
 */

import { INLINE_FAQ_DATA } from './faqData';

export interface AIChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  ts: number;
  providerUsed?: string;
  source?: 'knowledge_base' | 'llm' | 'synthesized';
  findingContext?: {
    ruleId: string;
    title: string;
    severity: string;
    owaspCategory: string;
  };
}

export const HISTORY_TURNS = Number(
  (import.meta as unknown as { env?: Record<string, string> }).env?.VITE_LLM_HISTORY_TURNS || '20'
);

interface FaqEntry {
  id: string;
  keywords: string[];
  question: string;
  answer: string;
  tags?: string[];
}

const FAQ: FaqEntry[] = INLINE_FAQ_DATA as FaqEntry[];

// ── Chuẩn hóa văn bản ─────────────────────────────────────────────────────────
export function normalize(text: string): string {
  return text
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^\w\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// ── Danh sách stop words mở rộng (Việt + Anh) ────────────────────────────────
const STOP_WORDS = new Set([
  // Vietnamese
  'la', 'gi', 'the', 'nao', 'nhu', 'co', 'khong', 'va', 'de', 'trong',
  'toi', 'ban', 'minh', 'hay', 'hoac', 'se', 'da', 'dang', 'can', 'biet',
  'hieu', 'lam', 'duoc', 'bao', 'nhieu', 'khi', 'tai', 'vi', 'mot', 'cac',
  'cho', 'voi', 'qua', 'len', 'xuong', 'sau', 'truoc', 'theo', 'tu', 'den',
  'tren', 'duoi', 'ngoai', 'day', 'kia', 'do', 'nay', 'thi', 'neu', 'ma',
  'nhung', 'cung', 'rat', 'qua', 'them', 'biet', 'hoi', 'tra', 'loi',
  // English
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'do', 'for', 'from',
  'has', 'he', 'in', 'is', 'it', 'its', 'of', 'on', 'or', 'that', 'the',
  'to', 'was', 'were', 'what', 'when', 'where', 'which', 'with', 'you',
  'this', 'they', 'them', 'their', 'there', 'then', 'than', 'also', 'but',
  'how', 'why', 'who', 'your', 'have', 'had', 'will', 'can', 'may', 'not',
]);

export function extractKeywords(norm: string): string[] {
  return norm.split(' ').filter(w => w.length > 2 && !STOP_WORDS.has(w));
}

// ── Khoảng cách Levenshtein (chịu lỗi chính tả) ───────────────────────────────
function levenshtein(a: string, b: string): number {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  if (Math.abs(a.length - b.length) > 3) return 99; // early exit
  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1,
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

// So khớp mờ: trả về true nếu độ tương đồng đủ cao
function fuzzyMatch(query: string, target: string): boolean {
  if (query === target) return true;
  if (target.length < 4) return query === target;
  const dist = levenshtein(query, target);
  const threshold = target.length <= 5 ? 1 : target.length <= 8 ? 2 : 3;
  return dist <= threshold;
}

// ── Bảng sửa lỗi chính tả thường gặp ──────────────────────────────────────────
const TYPO_MAP: Record<string, string> = {
  'sqli': 'sql injection',
  'sqlinjection': 'sql injection',
  'xsss': 'xss',
  'crsf': 'csrf',
  'srf': 'ssrf',
  'idoor': 'idor',
  'iddor': 'idor',
  'jwtt': 'jwt',
  'jot': 'jwt',
  'sssti': 'ssti',
  'corss': 'cors',
  'cors': 'cors',
  'clickjack': 'clickjacking',
  'traversal': 'path traversal',
  'pathtraversal': 'path traversal',
  'lfi': 'path traversal',
  'rfi': 'path traversal',
  'rce': 'command injection',
  'xxee': 'xxe',
  'xmlinjection': 'xxe',
  'bruteforce': 'brute force',
  'ratelimit': 'rate limiting',
  'ratelimiting': 'rate limiting',
  'hardcoded': 'hardcode',
  'hardcodesecret': 'hardcoded secrets',
  'opensource': 'dependency',
  'npm audit': 'dependency',
  'depen': 'dependency',
};

function applyTypoCorrections(norm: string): string {
  let result = norm;
  for (const [typo, correction] of Object.entries(TYPO_MAP)) {
    if (result.includes(typo)) {
      result = result.replace(new RegExp(`\\b${typo}\\b`, 'g'), correction);
    }
  }
  return result;
}

// ── Nhận diện ý định câu hỏi ──────────────────────────────────────────────────
type Intent =
  | 'greeting'
  | 'what_is'
  | 'how_to_fix'
  | 'how_to_use'
  | 'example'
  | 'explain_more'
  | 'impact'
  | 'prevent'
  | 'finding_query'
  | 'owasp_category'
  | 'compare'
  | 'personal_question'
  | 'thanks'
  | 'list_topics'
  | 'general';

// Ý định kép: khi người dùng hỏi nhiều mục đích cùng lúc
interface CompoundIntent {
  primary: Intent;
  secondary?: Intent;
}

const INTENT_PATTERNS: { intent: Intent; patterns: string[] }[] = [
  { intent: 'greeting',          patterns: ['xin chao', 'hello', 'hi', 'chao', 'hey', 'alo', 'good morning', 'good afternoon', 'chào buổi'] },
  { intent: 'thanks',            patterns: ['cam on', 'thank', 'cảm ơn', 'thanks', 'thank you', 'tks', 'ok tks', 'tuyet voi', 'hay qua'] },
  { intent: 'list_topics',       patterns: ['ban co the giup', 'can giup gi', 'ho tro gi', 'nhung gi', 'co nhung gi', 'tat ca cau hoi', 'danh sach', 'can biet gi', 'tu van gi', 'menu'] },
  { intent: 'personal_question', patterns: ['ban la ai', 'may la ai', 'ai day', 'ten ban', 'ban ten gi', 'who are you', 'what are you', 'ban duoc tao', 'ban sinh ra', 'ban la cai gi', 'trinh do', 'kha nang'] },
  { intent: 'how_to_fix',        patterns: ['cach fix', 'cach sua', 'khac phuc', 'fix nhu the nao', 'sua nhu the nao', 'cach ngan', 'giai phap', 'patch', 'remediat', 'phong ngua', 'bao ve', 'ngan chan', 'giai quyet', 'xu ly'] },
  { intent: 'how_to_use',        patterns: ['cach dung', 'cach su dung', 'huong dan', 'bat dau', 'buoc', 'lam the nao de', 'how to use', 'how do i', 'dung nhu the nao', 'su dung nhu the nao', 'thao tac'] },
  { intent: 'example',           patterns: ['vi du', 'example', 'cho xem', 'minh hoa', 'thi du', 'demo', 'sample', 'payload la gi', 'payload vi du', 'cho toi xem', 'thu cong', 'thu nghiem'] },
  { intent: 'explain_more',      patterns: ['giai thich them', 'noi them', 'ro hon', 'chi tiet hon', 'co the giai thich', 'mo ta', 'elaborate', 'detail', 'hieu hon', 'muon hieu', 'co the noi ro'] },
  { intent: 'impact',            patterns: ['hau qua', 'nguy hiem', 'impact', 'thiet hai', 'rui ro', 'nguy co', 'anh huong', 'dan den', 'de lam gi', 'khai thac duoc gi', 'gay ra'] },
  { intent: 'prevent',           patterns: ['phong tranh', 'ngan chan', 'tranh', 'prevent', 'avoid', 'mitigate', 'bao ve nhu the nao', 'lam sao de ngan', 'cach phong'] },
  { intent: 'compare',           patterns: ['khac nhau', 'so sanh', 'difference', 'compare', ' vs ', 'hay la', 'phan biet', 'giong nhau', 'khac gi'] },
  { intent: 'what_is',           patterns: ['la gi', 'nghia la gi', 'co nghia', 'dinh nghia', 'what is', 'giai thich', 'means', 'khai niem', 'kieu gi', 'loai gi', 'dang nao'] },
];

function detectIntent(norm: string): CompoundIntent {
  // Chào hỏi khớp chính xác
  if (['xin chao', 'hello', 'hi', 'chao', 'hey', 'alo'].some(g => norm === g || norm.startsWith(g + ' '))) {
    return { primary: 'greeting' };
  }
  // Lời cảm ơn
  if (['cam on', 'thank', 'tks', 'ok cam on', 'great', 'perfect'].some(p => norm === p || norm.startsWith(p))) {
    return { primary: 'thanks' };
  }
  // Câu hỏi về danh tính trợ lý
  if (['ban la ai', 'may la ai', 'ai day', 'ban ten gi', 'who are you', 'what are you'].some(p => norm.includes(p))) {
    return { primary: 'personal_question' };
  }
  // Rút gọn mã OWASP
  if (/\ba0?([1-9]|10)\b/.test(norm)) return { primary: 'owasp_category' };

  // Thu thập tất cả ý định khớp
  const matched: Intent[] = [];
  for (const { intent, patterns } of INTENT_PATTERNS) {
    if (patterns.some(p => {
      const pNorm = normalize(p);
      if (!pNorm) return false;
      return norm.includes(pNorm);
    })) matched.push(intent);
  }

  if (matched.length === 0) return { primary: 'general' };
  if (matched.length === 1) return { primary: matched[0] };

  // Nếu có nhiều ý định như what_is + how_to_fix thì trả về ý định kép
  const primary = matched[0];
  const secondary = matched.find(i => i !== primary);
  return { primary, secondary };
}

// ── Trích xuất chủ đề (bản nâng cao) ──────────────────────────────────────────
const TOPIC_MAP: { topic: string; variants: string[] }[] = [
  { topic: 'sql_injection',      variants: ['sql injection', 'sqli', 'sql inject', 'structured query', 'sql query', 'database inject'] },
  { topic: 'xss',                variants: ['xss', 'cross site scripting', 'cross-site scripting', 'script inject', 'stored xss', 'reflected xss', 'dom xss'] },
  { topic: 'csrf',               variants: ['csrf', 'cross site request forgery', 'request forgery', 'forged request'] },
  { topic: 'cors',               variants: ['cors', 'cross origin', 'cross-origin', 'access-control-allow-origin', 'cors policy', 'cors header'] },
  { topic: 'idor',               variants: ['idor', 'insecure direct object', 'object reference', 'insecure reference'] },
  { topic: 'bola',               variants: ['bola', 'broken object level', 'api idor', 'object level auth', 'bola api'] },
  { topic: 'ssti',               variants: ['ssti', 'server side template', 'template inject', 'jinja inject', 'twig inject'] },
  { topic: 'ssrf',               variants: ['ssrf', 'server side request forgery', 'server request forgery', 'internal request'] },
  { topic: 'jwt',                variants: ['jwt', 'json web token', 'bearer token', 'jot', 'jwt secret', 'jwt alg', 'jwt none'] },
  { topic: 'path_traversal',     variants: ['path traversal', 'directory traversal', 'lfi', 'local file inclusion', 'dot dot', '../', 'rfi', 'file inclusion'] },
  { topic: 'clickjacking',       variants: ['clickjacking', 'click jacking', 'ui redressing', 'iframe trap', 'x-frame'] },
  { topic: 'open_redirect',      variants: ['open redirect', 'url redirect', 'unvalidated redirect', 'redirect bypass'] },
  { topic: 'command_injection',  variants: ['command injection', 'os command', 'shell inject', 'rce', 'remote code execution', 'shell command', 'exec inject'] },
  { topic: 'xxe',                variants: ['xxe', 'xml external entity', 'xml inject', 'xml parser'] },
  { topic: 'headers',            variants: ['security header', 'csp', 'hsts', 'x-frame', 'x-content-type', 'referrer-policy', 'permissions-policy', 'nosniff'] },
  { topic: 'rate_limiting',      variants: ['rate limit', 'brute force', 'throttl', 'lockout', 'login attempt', 'account lockout', 'too many request'] },
  { topic: 'password',           variants: ['password', 'mat khau', 'bcrypt', 'argon', 'hash', 'salt', 'password hash', 'luu mat khau', 'password storage'] },
  { topic: 'session',            variants: ['session', 'phien lam viec', 'session fixation', 'session hijack', 'cookie', 'session token', 'session id'] },
  { topic: 'dependency',         variants: ['dependency', 'npm', 'package', 'cve', 'thu vien', 'vulnerable component', 'npm audit', 'outdated package', 'supply chain'] },
  { topic: 'secrets',            variants: ['hardcode', 'secret', 'api key', 'credentials', 'env', 'dotenv', 'environment variable', 'hardcoded secret', 'api token'] },
  { topic: 'docker',             variants: ['docker', 'container', 'kubernetes', 'dockerfile', 'k8s', 'docker compose', 'docker security', 'container security'] },
  { topic: 'api_security',       variants: ['api security', 'rest api', 'graphql', 'api bao mat', 'api endpoint', 'api design', 'api auth'] },
  { topic: 'sri',                variants: ['sri', 'subresource integrity', 'cdn script', 'integrity', 'integrity hash'] },
  { topic: 'sentinel',           variants: ['sentinel', 'cong cu', 'ung dung nay', 'phan mem', 'tool nay', 'sentinel v2', 'ung dung'] },
  { topic: 'url_scan',           variants: ['url scan', 'scan url', 'quet url', 'black-box', 'blackbox', 'kiem thu url'] },
  { topic: 'project_scan',       variants: ['project scan', 'scan project', 'quet code', 'source code', 'static analysis', 'sast', 'code scan'] },
  { topic: 'crawl_depth',        variants: ['crawl depth', 'do sau', 'crawl', 'depth', 'do sau crawl'] },
  { topic: 'request_budget',     variants: ['request budget', 'budget', 'so request', 'request limit', 'bao nhieu request'] },
  { topic: 'auth',               variants: ['authentication', 'xac thuc', 'dang nhap', 'login', 'auth', '2fa', 'mfa', 'multi factor', 'two factor'] },
  { topic: 'oauth',              variants: ['oauth', 'oauth2', 'openid', 'sso', 'social login', 'authorization code', 'implicit flow'] },
  { topic: 'export',             variants: ['export', 'bao cao', 'report', 'xuat', 'xuat bao cao', 'download report', 'pdf report'] },
  { topic: 'history',            variants: ['history', 'lich su', 'scan history', 'lich su scan', 'xem lai'] },
  { topic: 'findings',           variants: ['finding', 'ket qua', 'severity', 'critical', 'high', 'medium', 'low', 'false positive', 'collector'] },
  { topic: 'owasp',              variants: ['owasp', 'top 10', 'danh muc', 'owasp 2021', 'owasp top 10'] },
  { topic: 'pentest',            variants: ['pentest', 'penetration test', 'kiem thu xam nhap', 'vuln scan', 'vulnerability scan', 'pen test'] },
  { topic: 'sensitive_data',     variants: ['sensitive data', 'thong tin nhay cam', 'data exposure', 'information disclosure', 'data leak', 'ro ri du lieu'] },
  { topic: 'env_config',         variants: ['env config', 'environment', 'bien moi truong', '.env', 'config file', 'cau hinh', 'configuration'] },
  { topic: 'checklist',          variants: ['checklist', 'danh sach kiem tra', 'security checklist', 'tab checklist'] },
  { topic: 'how_to_use',         variants: ['cach dung', 'huong dan', 'bat dau', 'su dung nhu the nao', 'bước đầu', 'quy trinh'] },
];

export function extractTopic(norm: string): string | null {
  // Đầu tiên thử khớp chính xác / chuỗi con (exact / substring match)
  for (const { topic, variants } of TOPIC_MAP) {
    for (const v of variants) {
      const vNorm = normalize(v);
      // Tránh trường hợp `norm.includes('')` => luôn trả về true khi `normalize(v)` trở thành rỗng
      if (!vNorm) continue;
      if (norm.includes(vNorm)) return topic;
    }
  }
  // Dự phòng (Fallback): so khớp mờ (fuzzy match) trên các từ khóa
  const words = norm.split(' ').filter(w => w.length > 3);
  for (const { topic, variants } of TOPIC_MAP) {
    for (const v of variants) {
      const vNorm = normalize(v);
      if (vNorm.length < 4) continue;
      for (const w of words) {
        if (fuzzyMatch(w, vNorm)) return topic;
      }
    }
  }
  return null;
}

// ── Topic → FAQ ID mapping ────────────────────────────────────────────────────
const TOPIC_TO_FAQ: Record<string, string> = {
  sql_injection: 'faq_sql_injection', xss: 'faq_xss', csrf: 'faq_csrf',
  cors: 'faq_cors', idor: 'faq_idor', bola: 'faq_broken_object_auth',
  ssti: 'faq_ssti', ssrf: 'faq_ssrf', jwt: 'faq_jwt',
  path_traversal: 'faq_path_traversal', clickjacking: 'faq_clickjacking',
  open_redirect: 'faq_open_redirect', command_injection: 'faq_command_injection',
  xxe: 'faq_xml_xxe', headers: 'faq_headers', rate_limiting: 'faq_rate_limiting',
  password: 'faq_password_security', session: 'faq_session_management',
  dependency: 'faq_dependency', secrets: 'faq_hardcoded_secrets',
  docker: 'faq_docker_security', api_security: 'faq_api_security',
  sri: 'faq_subresource_integrity', sentinel: 'faq_what_is_sentinel',
  url_scan: 'faq_url_scan', project_scan: 'faq_project_scan',
  crawl_depth: 'faq_crawl_depth', request_budget: 'faq_request_budget',
  auth: 'faq_auth', export: 'faq_export', history: 'faq_history',
  findings: 'faq_findings_explain', owasp: 'faq_owasp',
  pentest: 'faq_pentest_vs_vuln_scan', sensitive_data: 'faq_sensitive_data_exposure',
  env_config: 'faq_env_config', checklist: 'faq_checklist',
  how_to_use: 'faq_how_to_use', oauth: 'faq_auth',
};

// ── Tính điểm các mục FAQ (nâng cao với so khớp mờ + điểm thưởng ngữ cảnh) ───────────────────
function scoreFaq(
  entry: FaqEntry,
  normQuery: string,
  keywords: string[],
  contextTopic?: string | null,
): number {
  let score = 0;

  for (const kw of entry.keywords) {
    const normKw = normalize(kw);
    if (normQuery.includes(normKw)) {
      score += normKw.split(' ').length * 4;
      continue;
    }
    const kwWords = normKw.split(' ').filter(w => w.length > 2);
    if (kwWords.length > 1 && kwWords.every(w => normQuery.includes(w))) {
      score += kwWords.length * 3;
      continue;
    }
    const hits = kwWords.filter(w => w.length > 2 && normQuery.includes(w)).length;
    if (hits > 0) score += hits * 1.5;

    // Thưởng điểm so khớp mờ cho các từ khóa đơn (single-word)
    if (kwWords.length === 1 && kwWords[0].length > 4) {
      for (const qw of keywords) {
        if (fuzzyMatch(qw, kwWords[0])) score += 1.2;
      }
    }
  }

  // Trùng lặp từ ngữ câu hỏi
  const normQ = normalize(entry.question);
  const qWords = normQ.split(' ').filter(w => w.length > 3 && !STOP_WORDS.has(w));
  for (const w of qWords) { if (keywords.includes(w)) score += 1.2; }

  // Khớp phần tiền tố (Prefix match)
  for (const kw of keywords) {
    for (const ekw of entry.keywords) {
      const normEkw = normalize(ekw);
      if (normEkw.startsWith(kw) || kw.startsWith(normEkw.slice(0, 5))) score += 0.8;
    }
  }

  // Thưởng điểm chủ đề ngữ cảnh: nếu mục khớp với chủ đề cuộc trò chuyện hiện tại
  if (contextTopic && TOPIC_TO_FAQ[contextTopic] === entry.id) {
    score += 2;
  }

  return score;
}

// ── Danh mục OWASP ──────────────────────────────────────────────────────────
const OWASP_QUICK: Record<string, string> = {
  'a01': `## A01 — Broken Access Control\n\nĐây là lỗ hổng phổ biến nhất theo OWASP 2021–2025. Xảy ra khi ứng dụng không kiểm tra đúng quyền truy cập.\n\n**Biểu hiện thường gặp:**\n- IDOR: thay ID trên URL để xem dữ liệu người khác\n- Bỏ qua kiểm tra xác thực ở API endpoint\n- Thiếu CSRF token trên form nhạy cảm\n- Privilege escalation: user thường truy cập tính năng admin\n\n**Hướng khắc phục:**\n- Luôn kiểm tra quyền ở phía server cho mọi request — không tin client\n- Dùng UUID thay sequential ID (1, 2, 3...)\n- Implement RBAC (Role-Based Access Control) nhất quán\n- Log và alert mọi access control failure\n\n*Hỏi tôi: "IDOR là gì?", "CSRF là gì?" để tìm hiểu từng lỗ hổng cụ thể.*`,
  'a02': `## A02 — Cryptographic Failures\n\nXảy ra khi dữ liệu nhạy cảm được truyền hoặc lưu mà không có mã hóa đúng cách.\n\n**Biểu hiện thường gặp:**\n- Thiếu cookie flags: \`HttpOnly\`, \`Secure\`, \`SameSite\`\n- Thiếu security headers: CSP, HSTS, X-Content-Type-Options\n- Lưu mật khẩu bằng MD5/SHA1 hoặc plain text\n- Dùng thuật toán mã hóa yếu: DES, RC4, MD5\n- Truyền dữ liệu nhạy cảm qua HTTP thay HTTPS\n\n**Hướng khắc phục:**\n- Bắt buộc HTTPS với HSTS header\n- Dùng bcrypt/Argon2 cho password hashing — không bao giờ MD5\n- Thiết lập đúng cookie flags cho session\n- Dùng TLS 1.2+ và cipher suite mạnh\n\n*Hỏi tôi: "Security Headers là gì?", "Cách lưu mật khẩu an toàn?"*`,
  'a03': `## A03 — Injection\n\nXảy ra khi dữ liệu người dùng được nhúng trực tiếp vào câu lệnh mà không qua xử lý an toàn.\n\n**Các loại phổ biến:**\n- **SQL Injection**: chèn SQL code vào query database\n- **XSS**: chèn JavaScript vào trang web người dùng khác\n- **Command Injection**: chèn lệnh hệ thống (RCE)\n- **SSTI**: chèn code vào template engine (Jinja2, Twig...)\n- **XXE**: XML External Entity qua XML parser\n- **LDAP Injection**: chèn query LDAP\n\n**Hướng khắc phục:**\n- Dùng Prepared Statements / Parameterized Queries\n- Encode output trước khi render HTML\n- Validate và sanitize toàn bộ user input\n- Content Security Policy (CSP) để giảm thiểu XSS impact\n\n*Hỏi tôi về bất kỳ loại injection cụ thể để xem ví dụ tấn công và cách fix.*`,
  'a04': `## A04 — Insecure Design\n\nLỗ hổng từ thiết kế kiến trúc và logic sai ngay từ đầu — không thể fix chỉ bằng patch code.\n\n**Biểu hiện:**\n- Thiếu threat modeling trong design phase\n- Thiếu rate limiting trên toàn hệ thống\n- Business logic dễ bypass (discount abuse, race condition)\n- Thiếu audit logging cho thao tác nhạy cảm\n\n**Hướng khắc phục:**\n- Áp dụng secure design patterns từ đầu dự án\n- Thực hiện threat modeling định kỳ\n- Defense in depth: nhiều lớp bảo vệ\n- Thiết kế với "fail secure" principle`,
  'a05': `## A05 — Security Misconfiguration\n\nCấu hình sai tạo điểm tấn công dễ khai thác.\n\n**Biểu hiện thường gặp:**\n- Debug endpoints công khai (/debug, /actuator, /swagger)\n- CORS cấu hình sai: \`Access-Control-Allow-Origin: *\`\n- Default credentials chưa đổi (admin/admin)\n- Error messages tiết lộ stack trace, tên DB, path server\n- Thiếu security headers\n\n**Hướng khắc phục:**\n- Tắt debug mode trên production\n- Cấu hình CORS whitelist cụ thể\n- Đổi tất cả default password\n- Thiết lập error handling tùy chỉnh — không expose stack trace`,
  'a06': `## A06 — Vulnerable & Outdated Components\n\nDùng thư viện/framework có CVE (lỗ hổng đã công bố) là rủi ro cao.\n\n**Nguy cơ:** Attacker có thể search CVE của thư viện bạn đang dùng và có exploit sẵn.\n\n**Hướng khắc phục:**\n- Chạy \`npm audit\` hoặc \`yarn audit\` thường xuyên\n- Dùng Dependabot hoặc Snyk trong CI/CD pipeline\n- Loại bỏ dependencies không dùng\n- Theo dõi security advisory của framework\n\n*SENTINEL Project Scan tự động kiểm tra CVE trong dependencies của bạn.*`,
  'a07': `## A07 — Auth & Session Management Failures\n\nLỗ hổng trong cơ chế xác thực hoặc quản lý phiên.\n\n**Biểu hiện:**\n- Không có rate limiting → brute force password\n- Account enumeration: thông báo "Email không tồn tại" vs "Sai mật khẩu"\n- JWT với secret yếu, \`alg: none\`, hoặc không verify signature\n- Session không invalidate sau logout\n- Session fixation: không tạo session ID mới sau login\n\n**Hướng khắc phục:**\n- Rate limit login endpoint (5 lần/phút)\n- Thông báo lỗi chung chung: "Email hoặc mật khẩu không đúng"\n- Dùng JWT secret đủ dài (>= 256-bit)\n- Invalidate session token sau logout và sau timeout\n- Multi-Factor Authentication (MFA/2FA)`,
  'a08': `## A08 — Software & Data Integrity Failures\n\nKhi ứng dụng không xác minh tính toàn vẹn của code hoặc data.\n\n**Biểu hiện:**\n- Script CDN không có SRI (Subresource Integrity) attribute\n- Update pipeline không có chữ ký số\n- Deserialization dữ liệu không tin cậy\n- Supply chain attack qua npm package bị compromise\n\n**Hướng khắc phục:**\n- Thêm \`integrity\` attribute cho script CDN\n- Dùng signature verification trong update pipeline\n- Lockfile (\`package-lock.json\`) trong version control\n- Kiểm tra npm package trước khi install`,
  'a09': `## A09 — Security Logging & Monitoring Failures\n\nThiếu logging làm chậm hoặc ngăn việc phát hiện tấn công, có thể kéo dài MTTR hàng tháng.\n\n**Cần log:**\n- Authentication events (login, logout, failed login)\n- Authorization failures (403, access denied)\n- Input validation failures\n- High-value transactions\n\n**Hướng khắc phục:**\n- Log đầy đủ với timestamp, user ID, IP, action\n- Centralize logs (ELK, Splunk, CloudWatch)\n- Thiết lập alerting cho pattern bất thường\n- Đảm bảo log không chứa dữ liệu nhạy cảm (password, card number)`,
  'a10': `## A10 — SSRF (Server-Side Request Forgery)\n\nKẻ tấn công lừa server gửi request đến URL tùy ý, thường là internal network hoặc cloud metadata.\n\n**Attack scenarios phổ biến:**\n- AWS metadata: \`http://169.254.169.254/latest/meta-data/\` → lấy IAM credentials\n- Internal service: \`http://192.168.1.1/admin\` → bypass firewall\n- Port scan internal network\n- Lợi dụng webhook để exfiltrate data\n\n**Hướng khắc phục:**\n- Validate và whitelist URL scheme/host\n- Block private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x)\n- Resolve hostname và verify IP trước khi request\n- Tắt HTTP redirect hoặc limit redirect\n- Dùng thư viện SSRF-safe\n\n*Hỏi tôi "SSRF là gì?" để xem ví dụ cụ thể.*`,
};

// ── Trả lời riêng cho từng loại Finding (Finding-specific answers) ──────────────────────────────────────────────────
interface FindingContext {
  ruleId?: string; title?: string; severity?: string;
  owaspCategory?: string; remediation?: string; evidence?: string[];
}

function buildFindingAnswer(finding: FindingContext): string {
  const cat = (finding.owaspCategory || '').toLowerCase();
  const owaspDetail = OWASP_QUICK[cat] || '';
  const severityText = severityLabel(finding.severity || '');
  const owaspUpper = (finding.owaspCategory || '').toUpperCase();
  const evidenceBlock = finding.evidence && finding.evidence.length > 0
    ? `\n\n**Bằng chứng phát hiện bởi SENTINEL**\n\`\`\`\n${finding.evidence.slice(0, 3).join('\n')}\n\`\`\`` : '';
  const remediationBlock = finding.remediation ? `\n\n**Hướng dẫn khắc phục**\n${finding.remediation}` : '';
  const owaspBlock = owaspDetail ? `\n\n---\n\n${owaspDetail}` : '';
  return `## Phân tích Finding: ${finding.title || 'Finding'}\n\n**Mức độ**: ${severityText} | **OWASP**: ${owaspUpper} | **Rule**: \`${finding.ruleId || 'N/A'}\`${evidenceBlock}${remediationBlock}${owaspBlock}\n\n---\n*Muốn tìm hiểu thêm? Gõ tên lỗ hổng (ví dụ: "${finding.title}") để nhận giải thích đầy đủ.*`;
}

function severityLabel(sev: string): string {
  return ({ critical: '🔴 Critical', high: '🟠 High', medium: '🟡 Medium', low: '🟢 Low' } as Record<string, string>)[sev] || sev;
}

// ── Trình kiểm tra lĩnh vực bảo mật (Security domain checker) ───────────────────────────────────────────────────
const SECURITY_MUST_TERMS = [
  'bao mat', 'lo hong', 'tan cong', 'khai thac', 'xac thuc', 'ma hoa',
  'quet', 'scan', 'finding', 'severity', 'owasp', 'pentest', 'kiem thu',
  'injection', 'xss', 'csrf', 'sqli', 'ssrf', 'ssti', 'idor', 'bola',
  'cors', 'jwt', 'session', 'cookie', 'token', 'auth', 'oauth',
  'vulnerability', 'exploit', 'payload', 'hash', 'encrypt', 'decrypt',
  'ssl', 'tls', 'https', 'certificate', 'firewall', 'waf', 'cve', 'cwe',
  'header', 'hsts', 'csp', 'x-frame', 'clickjack', 'sql',
  'traversal', 'redirect', 'bypass', 'brute force', 'rate limit',
  'sentinel', 'url scan', 'project scan', 'crawl', 'budget', 'export',
  'hardcode', 'secret', 'api key', 'dotenv', 'credential',
  'docker', 'container', 'dependency', 'npm', 'package',
  'rce', 'lfi', 'rfi', 'xxe', 'ssti', 'csrf', 'xss', 'sqli',
  'mfa', '2fa', 'two factor', 'multi factor',
  'subresource', 'integrity', 'sri',
  'false positive', 'collector', 'checklist', 'history',
];

function isSecurityRelated(norm: string): boolean {
  return SECURITY_MUST_TERMS.some(t => norm.includes(t));
}

// ── Trình phân loại các câu hỏi ngoài phạm vi (Out-of-scope classifier) ───────────────────────────────────────────────────
const OUT_OF_SCOPE_TOPICS = [
  'ban la ai', 'may la ai', 'ai day', 'ban ten gi', 'ten cua ban',
  'thoi tiet', 'weather', 'bong da', 'football', 'soccer', 'the thao',
  'nau an', 'cooking', 'recipe', 'am nhac', 'music', 'phim', 'movie',
  'tin tuc', 'news', 'chinh tri', 'politics',
  'toan hoc', 'vat ly', 'hoa hoc', 'sinh vat', 'y hoc', 'suc khoe',
  'machine learning', 'deep learning', 'gpt', 'chatgpt', 'openai',
  'blockchain', 'nft', 'bitcoin', 'tien ao',
  'game dev', 'unity', 'unreal',
  'gia ca', 'mua sam', 'shopping', 'du lich', 'travel',
  'nha hang', 'restaurant', 'mon an', 'food', 'nuoc',
];

function isOutOfScope(norm: string): boolean {
  return OUT_OF_SCOPE_TOPICS.some(t => norm.includes(t));
}

function isPersonNameQuery(norm: string): boolean {
  return /^[\w\s]{2,20}\s+la\s+ai[\s?]*$/.test(norm.trim());
}

// ── Gợi ý thông minh (nhận biết chủ đề) ──────────────────────────────────────────
const TOPIC_SUGGESTIONS: Record<string, string[]> = {
  sql_injection:    ['XSS là gì?', 'SSTI là gì và cách fix?', 'Command Injection là gì?'],
  xss:             ['CSRF là gì?', 'Security Headers là gì?', 'Content Security Policy là gì?'],
  csrf:            ['XSS là gì?', 'JWT là gì?', 'Session Management an toàn?'],
  cors:            ['Security Headers là gì?', 'CSRF là gì?', 'CORS fix như thế nào?'],
  idor:            ['BOLA/API IDOR là gì?', 'JWT là gì?', 'A01 Broken Access Control là gì?'],
  jwt:             ['Session Management an toàn?', 'Rate Limiting là gì?', 'OAuth là gì?'],
  ssrf:            ['Command Injection là gì?', 'Path Traversal là gì?', 'A10 SSRF là gì?'],
  sentinel:        ['URL Scan là gì?', 'Project Scan là gì?', 'Cách đọc kết quả scan?'],
  url_scan:        ['Request Budget là gì?', 'Crawl Depth là gì?', 'Cách thêm Authentication khi scan?'],
  findings:        ['Severity là gì?', 'Collector là gì?', 'Khi nào findings có thể là false positive?'],
  owasp:           ['A01 Broken Access Control là gì?', 'A03 Injection là gì?', 'A07 Auth Failures là gì?'],
  password:        ['Session Management an toàn?', 'Rate Limiting là gì?', '2FA/MFA là gì?'],
  dependency:      ['Docker Security là gì?', 'Hardcoded Secrets là gì?', 'Supply chain attack là gì?'],
  headers:         ['CSP là gì?', 'HSTS là gì?', 'Clickjacking là gì?'],
  command_injection: ['SSRF là gì?', 'Path Traversal là gì?', 'SSTI là gì?'],
};

function generateSmartSuggestions(norm: string, topic: string | null): string[] {
  if (topic && TOPIC_SUGGESTIONS[topic]) return TOPIC_SUGGESTIONS[topic];
  if (isSecurityRelated(norm)) return ['SQL Injection là gì?', 'XSS là gì?', 'Cách sử dụng SENTINEL?'];
  return ['OWASP Top 10 là gì?', 'URL Scan là gì?', 'Security Headers là gì?'];
}

// ── Response variant pools (tránh lặp lại câu trả lời cứng nhắc) ─────────────
const GREETING_VARIANTS = [
  `Xin chào! Tôi là **SENTINEL AI Assistant** — trợ lý bảo mật chạy hoàn toàn offline.\n\nTôi có thể giúp bạn về:\n\n- **Lỗ hổng bảo mật**: XSS, SQL Injection, CSRF, IDOR, SSTI, SSRF, JWT, Path Traversal...\n- **Công cụ SENTINEL**: cấu hình scan, đọc kết quả, xuất báo cáo, lịch sử\n- **OWASP Top 10**: giải thích chi tiết A01–A10 với ví dụ thực tế\n- **Phân tích Finding**: nhấn **"Hỏi AI"** trên bất kỳ finding để nhận phân tích tường tận\n\nHãy gõ câu hỏi hoặc nhấn 💡 để xem gợi ý!`,
  `Chào bạn! 👋 Tôi là **SENTINEL AI** — chuyên gia bảo mật web offline của bạn.\n\nBạn có thể hỏi tôi về:\n- Các lỗ hổng bảo mật theo chuẩn OWASP (XSS, SQLi, CSRF, SSRF...)\n- Cách sử dụng SENTINEL để scan URL hoặc Project\n- Phân tích chi tiết từng Finding trong kết quả scan\n\n💡 Nhấn nút bóng đèn để xem danh sách câu hỏi gợi ý!`,
];

const THANKS_RESPONSES = [
  '😊 Không có gì! Nếu có thêm câu hỏi về bảo mật, cứ hỏi nhé.\n\n*Nhấn 💡 để xem gợi ý câu hỏi tiếp theo.*',
  'Vui được giúp! 🛡️ Hỏi tiếp nếu bạn muốn tìm hiểu thêm về bảo mật web.\n\n*Nhấn 💡 để xem danh sách câu hỏi.*',
  '👍 Hy vọng thông tin hữu ích! Có câu hỏi nào khác về bảo mật không?',
];

// Theo dõi các biến thể đã dùng lần cuối để tránh lặp lại
let lastGreetingIdx = -1;
let lastThanksIdx = -1;

// ── Câu trả lời cho các nội dung ngoài phạm vi ────────────────────────────────────────────────────
function buildOOSResponse(norm: string, topic: string | null, isPersonQuery = false): string {
  const suggestions = generateSmartSuggestions(norm, topic);
  const suggestionText = suggestions.map(s => `- ${s}`).join('\n');

  if (isPersonQuery) {
    return `## Ngoài phạm vi hỗ trợ\n\nTôi là **SENTINEL AI Assistant** — chuyên về bảo mật web và OWASP. Câu hỏi về danh tính cá nhân không nằm trong lĩnh vực của tôi.\n\n**Thử hỏi tôi về bảo mật:**\n${suggestionText}\n\n*Nhấn 💡 để xem toàn bộ câu hỏi được hỗ trợ.*`;
  }
  if (isSecurityRelated(norm)) {
    return `## Chưa có trong knowledge base\n\nCâu hỏi này liên quan đến bảo mật nhưng chưa có câu trả lời cụ thể trong knowledge base hiện tại.\n\n**Tôi hỗ trợ tốt nhất:**\n- Lỗ hổng OWASP Top 10 (XSS, SQLi, CSRF, IDOR, SSRF...)\n- Cấu hình và sử dụng SENTINEL\n- Security best practices và hardening\n\n**Có thể bạn muốn hỏi:**\n${suggestionText}\n\n*Nhấn 💡 để xem toàn bộ danh sách câu hỏi được hỗ trợ.*`;
  }
  return `## Ngoài phạm vi hỗ trợ\n\nTôi là AI assistant **chuyên về bảo mật web** — câu hỏi này nằm ngoài lĩnh vực của tôi.\n\n**Tôi có thể giúp bạn về:**\n- Các lỗ hổng bảo mật web theo chuẩn OWASP\n- Hướng dẫn sử dụng SENTINEL để scan và phân tích\n- Cách khắc phục từng loại lỗ hổng cụ thể\n\n**Thử hỏi:**\n${suggestionText}\n\n*Nhấn 💡 để xem toàn bộ câu hỏi được hỗ trợ.*`;
}

// ── Phát hiện câu hỏi nối tiếp (Follow-up detection) ───────────────────────────────────────────────────────
const FOLLOWUP_CONTINUATION_WORDS = [
  'cach fix', 'vi du', 'example', 'cho xem vi du', 'chi tiet hon',
  'giai thich them', 'noi them', 'ro hon', 'lam sao', 'hau qua', 'impact',
  'phong tranh', 'prevent', 'them nua', 'tiep theo', 'con gi nua',
  'the con', 'va con', 'tai sao lai', 'vi sao lai', 'con cach nao',
  'co cach nao khac', 'ngoai ra', 'kem theo', 'nguy hiem hon',
];

function isLikelyFollowUp(norm: string, hasClearTopic: boolean, hasClearIntent: boolean): boolean {
  if (hasClearTopic || hasClearIntent) return false;
  const wordCount = norm.split(' ').filter(w => w.length > 1).length;
  if (wordCount <= 3 && !isSecurityRelated(norm)) return false;
  if (FOLLOWUP_CONTINUATION_WORDS.some(k => norm.includes(k))) return true;
  return wordCount <= 6 && isSecurityRelated(norm);
}

// ── Bản đồ tên các danh mục OWASP ──────────────────────────────────────────────────
const OWASP_NAME_MAP: Record<string, string> = {
  'broken access control': 'a01', 'broken access': 'a01', 'access control': 'a01',
  'cryptographic failures': 'a02', 'cryptographic': 'a02', 'ma hoa': 'a02',
  'injection': 'a03', 'insecure design': 'a04',
  'security misconfiguration': 'a05', 'misconfiguration': 'a05',
  'vulnerable components': 'a06', 'outdated components': 'a06',
  'auth failures': 'a07', 'authentication failures': 'a07',
  'software integrity': 'a08', 'data integrity': 'a08',
  'logging failures': 'a09', 'monitoring failures': 'a09',
  'server side request': 'a10',
};

// ── Phân nhánh theo ý định phụ: sửa đổi câu trả lời dựa trên ý định ─────────────────
function applyIntentModifier(answer: string, intent: Intent, topic: string | null): string {
  if (intent === 'impact') {
    return `${answer}\n\n---\n⚠️ *Muốn biết thêm hậu quả thực tế? Hỏi: "Tấn công ${topic?.replace(/_/g, ' ')} có thể gây ra gì?"*`;
  }
  if (intent === 'prevent') {
    return `${answer}\n\n---\n🛡️ *Để biết cách implement cụ thể cho stack của bạn (Node.js, Python, Java...), mô tả thêm nhé.*`;
  }
  if (intent === 'example') {
    return `${answer}\n\n---\n🔬 *Muốn xem payload tấn công cụ thể? Hỏi: "Ví dụ tấn công ${topic?.replace(/_/g, ' ')} là gì?"*`;
  }
  if (intent === 'how_to_fix') {
    return `${answer}\n\n---\n🔧 *Cần code mẫu cho framework cụ thể? Nêu stack của bạn (ví dụ: Express.js, Django, Laravel).*`;
  }
  return answer;
}

// ── Bảo vệ chống trùng lặp (Dedup guard): ngăn trả cùng một câu trả lời 2 lần liên tiếp ─────────────────────────
function isDuplicateAnswer(answer: string, lastAnswer?: string): boolean {
  if (!lastAnswer) return false;
  // So sánh 100 ký tự đầu tiên (tiêu đề + phần mở đầu)
  const sig1 = answer.slice(0, 100).replace(/\s+/g, ' ').trim();
  const sig2 = lastAnswer.slice(0, 100).replace(/\s+/g, ' ').trim();
  return sig1 === sig2;
}

// ── Router chính ───────────────────────────────────────────────────────────────
export interface AiQueryPayload {
  question: string;
  findingContext?: FindingContext;
  lastAssistantMessage?: string;
  conversationHistory?: { role: 'user' | 'assistant'; content: string }[];
  signal?: AbortSignal;
  onToken?: (token: string) => void;
}

export function routeQuery(payload: AiQueryPayload): string {
  const { question, findingContext, lastAssistantMessage, conversationHistory } = payload;

  // Áp dụng sửa lỗi chính tả trước khi chuẩn hóa
  const normRaw = normalize(question);
  const normQ = applyTypoCorrections(normRaw);

  const intentResult = detectIntent(normQ);
  const { primary: intent, secondary: secondaryIntent } = intentResult;
  const topic = extractTopic(normQ);
  const keywords = extractKeywords(normQ);

  // Trích xuất chủ đề ngữ cảnh từ lịch sử trò chuyện (2 tin nhắn gần nhất của trợ lý)
  let contextTopic: string | null = null;
  if (conversationHistory && conversationHistory.length > 0) {
    const recentAssistant = conversationHistory
      .filter(m => m.role === 'assistant')
      .slice(-2)
      .map(m => normalize(m.content.slice(0, 200)));
    for (const t of recentAssistant) {
      const ct = extractTopic(t);
      if (ct) { contextTopic = ct; break; }
    }
  }

  // BỎ QUA KNOWLEDGE BASE NẾU YÊU CẦU "CHI TIẾT"
  // Nếu người dùng yêu cầu giải thích chi tiết, ta trả về chuỗi rỗng
  // để HybridOrchestrator tự động chuyển câu hỏi sang LLM (trả lời đầy đủ, tự nhiên, bớt máy móc)
  if (intent === 'explain_more' || secondaryIntent === 'explain_more' || normQ.includes('chi tiet')) {
    return "";
  }

  // 1. Chào hỏi (Greeting)
  if (intent === 'greeting') {
    const idx = (lastGreetingIdx + 1) % GREETING_VARIANTS.length;
    lastGreetingIdx = idx;
    return GREETING_VARIANTS[idx];
  }

  // 2. Cảm ơn (Thanks)
  if (intent === 'thanks') {
    const idx = (lastThanksIdx + 1) % THANKS_RESPONSES.length;
    lastThanksIdx = idx;
    return THANKS_RESPONSES[idx];
  }

  // 3. Liệt kê các chủ đề (List topics)
  if (intent === 'list_topics') {
    return `## Tôi hỗ trợ những chủ đề nào?\n\n**🔴 Lỗ hổng bảo mật (OWASP Top 10)**\nSQL Injection, XSS, CSRF, IDOR, CORS, JWT, SSRF, SSTI, Path Traversal, Clickjacking, Open Redirect, Command Injection, XXE, BOLA, Rate Limiting, Password Security, API Security, Session Management, Subresource Integrity, Docker Security, Sensitive Data Exposure\n\n**🛡️ Công cụ SENTINEL**\nURL Scan, Project Scan, Crawl Depth, Request Budget, Authentication, Export Báo cáo, Lịch sử Scan, Checklist, Collector, False Positive, Risk Score\n\n**📋 OWASP A01–A10**\nGiải thích chi tiết từng category với ví dụ thực tế\n\n**✅ Best Practices**\nHardcoded Secrets, Env Config, Security Headers, Dependency Management\n\n*Nhấn 💡 để xem danh sách câu hỏi gợi ý hoặc gõ tên chủ đề bất kỳ.*`;
  }

  // 4. Định danh cá nhân (Personal identity)
  if (intent === 'personal_question') {
    return `## Tôi là SENTINEL AI Assistant\n\nTôi là trợ lý bảo mật tích hợp trong **SENTINEL v2**, hoạt động **hoàn toàn offline** và được xây dựng để:\n\n- Giải thích các lỗ hổng bảo mật theo chuẩn OWASP\n- Hướng dẫn sử dụng SENTINEL từng bước\n- Phân tích findings từ kết quả scan\n- Đề xuất cách khắc phục cụ thể\n\n**Tôi không phải con người và không kết nối internet.** Knowledge base của tôi được cập nhật theo OWASP Top 10 2021–2025.\n\nHỏi tôi về bảo mật web! 💡`;
  }

  // 5. Câu hỏi về tên người "[X] là ai?"
  if (isPersonNameQuery(normQ)) return buildOOSResponse(normQ, topic, true);

  // 6. Nằm ngoài phạm vi rõ ràng (Explicit out-of-scope)
  if (isOutOfScope(normQ)) return buildOOSResponse(normQ, topic, false);

  // 7. Ngữ cảnh Finding (Finding context)
  if (findingContext) {
    const isVagueOnFinding = normQ.split(' ').length <= 5 && (
      normQ.includes('nay') || normQ.includes('gi') || normQ.includes('sao') ||
      normQ.includes('giai thich') || normQ.includes('what') || normQ.includes('mean')
    );
    if (isVagueOnFinding || normQ.includes('finding')) return buildFindingAnswer(findingContext);
  }

  // 8. Danh mục OWASP A01..A10 (bằng số)
  if (intent === 'owasp_category') {
    const match = normQ.match(/\ba0?([1-9]|10)\b/);
    if (match) {
      const key = `a${match[1].padStart(2, '0')}`;
      if (OWASP_QUICK[key]) return `${OWASP_QUICK[key]}\n\n---\n*Hỏi về lỗ hổng cụ thể để nhận hướng dẫn chi tiết.*`;
    }
  }

  // 9. Danh mục OWASP theo tên
  for (const [phrase, key] of Object.entries(OWASP_NAME_MAP)) {
    if (normQ.includes(normalize(phrase)) && OWASP_QUICK[key]) {
      return `${OWASP_QUICK[key]}\n\n---\n*Hỏi về lỗ hổng cụ thể để nhận hướng dẫn chi tiết hơn.*`;
    }
  }

  // 10. Tra cứu trực tiếp theo chủ đề
  if (topic) {
    let directFaqId: string | undefined = TOPIC_TO_FAQ[topic];

    // Sửa các trường hợp "chủ đề quá rộng" thường gặp
    // - Chủ đề `findings` hiện đang khớp với nhiều câu hỏi (severity/false positive/collector),
    //   nhưng chúng ta phải chuyển hướng chúng đến mục FAQ cụ thể.
    if (topic === 'findings') {
      if (normQ.includes('false positive')) directFaqId = 'faq_false_positive';
      else if (normQ.includes('collector')) directFaqId = 'faq_collector';
      else if (normQ.includes('risk score')) directFaqId = 'faq_risk_score';
      else if (normQ.includes('severity') || /\b(critical|high|medium|low)\b/.test(normQ)) directFaqId = 'faq_severity';
    }

    // - Biến thể chủ đề `auth` bao gồm các từ khóa 2fa/mfa, nhưng TOPIC_TO_FAQ ánh xạ nó tới faq_auth.
    //   Ghi đè để trả về mục dành riêng cho 2FA/MFA.
    if (topic === 'auth' && /\b(2fa|mfa|two factor|multi factor|multi-factor|two-factor)\b/.test(normQ)) {
      directFaqId = 'faq_2fa_mfa';
    }

    if (directFaqId) {
      const directEntry = FAQ.find(e => e.id === directFaqId);
      if (directEntry) {
      let answer = directEntry.answer;

      // Dedup: nếu đã đưa ra cùng câu trả lời vào lần trước, hãy làm phong phú thêm nó
      if (isDuplicateAnswer(answer, lastAssistantMessage)) {
        const related = FAQ.find(e =>
          e.id !== directEntry.id &&
          TOPIC_SUGGESTIONS[topic]?.some(s => normalize(s).includes(normalize(e.question).slice(0, 10)))
        );
        if (related) {
          answer = `${answer}\n\n---\n## Thông tin thêm\n\n${related.answer.slice(0, 400)}...`;
        }
      }

      // Áp dụng bộ điều chỉnh ý định cho các ý định kép
      const effectiveIntent = secondaryIntent || intent;
      if (['how_to_fix', 'impact', 'prevent', 'example'].includes(effectiveIntent)) {
        answer = applyIntentModifier(answer, effectiveIntent, topic);
      } else if (intent === 'how_to_fix' && !answer.includes('Cách khắc phục')) {
        answer += '\n\n---\n*Cần ví dụ code cho stack cụ thể? Hãy mô tả thêm (Node.js, Python, Java...).*';
      }

      // Gợi ý liên quan (tránh trùng lặp)
      const suggestions = generateSmartSuggestions(normQ, topic);
      if (suggestions.length > 0) {
        const pick = suggestions[Math.floor(Math.random() * suggestions.length)];
        if (!isDuplicateAnswer(pick, lastAssistantMessage)) {
          answer += `\n\n---\n*Câu hỏi liên quan: **${pick}***`;
        }
      }
      return answer;
      }
    }
  }

  // 11. Kiểm tra mức độ liên quan đến bảo mật
  const hasClearTopic = topic !== null;
  const hasClearIntent = intent !== 'general';
  if (!isSecurityRelated(normQ) && !hasClearTopic && !hasClearIntent) {
    return buildOOSResponse(normQ, topic, isPersonNameQuery(normQ));
  }

  // 12. Xử lý câu hỏi nối tiếp (Follow-up) — kèm theo ngữ cảnh
  if (lastAssistantMessage && isLikelyFollowUp(normQ, hasClearTopic, hasClearIntent)) {
    const ctxNorm = normalize(lastAssistantMessage.slice(0, 800));
    const combinedKeywords = extractKeywords(`${normQ} ${ctxNorm.slice(0, 400)}`);
    const combined = `${normQ} ${ctxNorm.slice(0, 400)}`;
    const combinedScored = FAQ
      .map(e => ({ entry: e, score: scoreFaq(e, combined, combinedKeywords, contextTopic) }))
      .filter(x => x.score > 3)
      .sort((a, b) => b.score - a.score);
    if (combinedScored.length > 0) {
      const best = combinedScored[0].entry;
      if (!isDuplicateAnswer(best.answer, lastAssistantMessage)) {
        return best.answer + `\n\n---\n*Tiếp tục chủ đề: **${best.question}***`;
      }
      // Nếu trùng lặp, thử câu tiếp theo
      if (combinedScored.length > 1) {
        return combinedScored[1].entry.answer + `\n\n---\n*Chủ đề liên quan: **${combinedScored[1].entry.question}***`;
      }
    }
  }

  // 13. Tính điểm toàn bộ FAQ với điểm thưởng ngữ cảnh
  const scored = FAQ
    .map(entry => ({ entry, score: scoreFaq(entry, normQ, keywords, contextTopic) }))
    .filter(x => x.score > 0)
    .sort((a, b) => b.score - a.score);

  if (scored.length > 0 && scored[0].score >= 3) {
    let answer = scored[0].entry.answer;

    // Dedup: chọn câu tốt tiếp theo nếu câu đầu tiên bị trùng lặp
    if (isDuplicateAnswer(answer, lastAssistantMessage) && scored.length > 1 && scored[1].score >= 2) {
      answer = scored[1].entry.answer;
    }

    const related = scored.slice(1).find(x =>
      x.score >= scored[0].score * 0.6 &&
      x.entry.id !== scored[0].entry.id &&
      !isDuplicateAnswer(x.entry.answer, lastAssistantMessage)
    );
    if (related) answer += `\n\n---\n*Câu hỏi liên quan: **${related.entry.question}***`;
    return answer;
  }

  // 14. Dự phòng bằng ngữ cảnh Finding
  if (findingContext) return buildFindingAnswer(findingContext);

  // 15. Độ tin cậy thấp — chỉ hiển thị nếu liên quan đến bảo mật
  if (isSecurityRelated(normQ) && scored.length > 0 && scored[0].score >= 1.5) {
    if (!isDuplicateAnswer(scored[0].entry.answer, lastAssistantMessage)) {
      return `## Có thể bạn muốn hỏi về...\n\n${scored[0].entry.answer}\n\n---\n*Nếu đây không phải câu trả lời bạn cần, hãy thử diễn đạt lại hoặc nhấn 💡.*`;
    }
  }

  // 16. Dự phòng cuối cùng (Final fallback)
  return buildOOSResponse(normQ, topic, isPersonNameQuery(normQ));
}

// ── Tạo Message ID ───────────────────────────────────────────────────────
export function genMsgId(): string {
  return `msg_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
}

// ── Xoay vòng gợi ý trong ô nhập liệu (Rotating placeholder hints) ───────────────────────────────────────────────
export const INPUT_PLACEHOLDER_HINTS = [
  'SQL Injection là gì và cách fix?',
  'XSS là gì?',
  'CSRF là gì và cách phòng tránh?',
  'JWT các lỗi thường gặp?',
  'CORS misconfiguration là gì?',
  'Path Traversal là gì?',
  'SSRF là gì?',
  'Security Headers cần thiết lập gì?',
  'IDOR là gì?',
  'OWASP Top 10 là gì?',
  'Cách sử dụng SENTINEL?',
  'URL Scan là gì?',
  'Project Scan hoạt động như thế nào?',
  'Risk Score được tính như thế nào?',
  'Cách thêm Authentication khi scan?',
  'Command Injection là gì?',
  'SSTI là gì và cách fix?',
  'Cách lưu mật khẩu an toàn?',
  'Rate Limiting là gì?',
  'Docker security lỗi phổ biến?',
  'Clickjacking là gì?',
  'Open Redirect có nguy hiểm không?',
  'XXE Injection là gì?',
  'Hardcoded secrets là gì?',
  'A01 Broken Access Control là gì?',
  'BOLA / API IDOR là gì?',
  'False positive trong scan là gì?',
  'Session Management an toàn?',
  'Subresource Integrity là gì?',
  '2FA/MFA bảo vệ như thế nào?',
];