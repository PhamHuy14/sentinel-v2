import { INLINE_FAQ_DATA } from './faqData';
import type { AiQueryPayload } from './aiRouter';

interface FaqEntry {
  id: string;
  keywords: string[];
  question: string;
  answer: string;
}

export interface RetrievedContextItem {
  id: string;
  title: string;
  text: string;
  score: number;
  source: 'faq' | 'finding' | 'conversation';
}

export interface RetrievedContext {
  items: RetrievedContextItem[];
  sourceIds: string[];
  summary: string;
}

const FAQ = INLINE_FAQ_DATA as FaqEntry[];

const STOP_WORDS = new Set([
  'the', 'and', 'for', 'from', 'with', 'what', 'when', 'where', 'which', 'this',
  'that', 'are', 'you', 'your', 'how', 'why', 'can', 'may', 'not', 'hay', 'cho',
  'toi', 'ban', 'minh', 'cua', 'cac', 'mot', 'nhung', 'trong', 'ngoai', 'neu',
  'thi', 'la', 'gi', 'nao', 'sao', 'nay', 'kia', 'do', 'duoc', 'khong',
]);

function normalize(text: string): string {
  return text
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^\w\s./:-]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokens(text: string): string[] {
  return normalize(text)
    .split(' ')
    .filter(token => token.length > 2 && !STOP_WORDS.has(token));
}

function unique<T>(items: T[]): T[] {
  return Array.from(new Set(items));
}

function scoreText(queryTokens: string[], text: string): number {
  const haystack = normalize(text);
  let score = 0;
  for (const token of queryTokens) {
    if (haystack.includes(token)) score += token.length > 5 ? 2 : 1;
  }
  return score;
}

function compact(text: string, maxLength = 900): string {
  const clean = text.replace(/\s+/g, ' ').trim();
  return clean.length <= maxLength ? clean : `${clean.slice(0, maxLength).trim()}...`;
}

function buildFindingItem(payload: AiQueryPayload): RetrievedContextItem | null {
  const finding = payload.findingContext;
  if (!finding) return null;

  const evidence = finding.evidence?.length
    ? `Evidence: ${finding.evidence.slice(0, 4).join(' | ')}`
    : '';
  const remediation = finding.remediation ? `Remediation: ${finding.remediation}` : '';
  const location = finding.location ? `Location: ${finding.location}` : '';
  const target = finding.target ? `Target: ${finding.target}` : '';
  const references = finding.references?.length
    ? `References: ${finding.references.slice(0, 4).join(', ')}`
    : '';
  const remediationPlan = finding.remediationPlan
    ? `Structured remediation plan: ${JSON.stringify(finding.remediationPlan)}`
    : '';

  return {
    id: `finding:${finding.ruleId || 'current'}`,
    title: `Current finding: ${finding.title || finding.ruleId || 'Untitled'}`,
    source: 'finding',
    score: 100,
    text: compact([
      `Rule: ${finding.ruleId || 'N/A'}`,
      `Title: ${finding.title || 'N/A'}`,
      `Severity: ${finding.severity || 'N/A'}`,
      `OWASP: ${finding.owaspCategory || 'N/A'}`,
      `Confidence: ${finding.confidence || 'N/A'}`,
      target,
      location,
      evidence,
      remediation,
      remediationPlan,
      references,
    ].filter(Boolean).join('\n'), 1400),
  };
}

function buildConversationItems(payload: AiQueryPayload, queryTokens: string[]): RetrievedContextItem[] {
  const history = payload.conversationHistory ?? [];
  return history
    .slice(-6)
    .map((item, index) => ({
      id: `conversation:${index}`,
      title: `${item.role === 'user' ? 'User' : 'Assistant'} recent turn`,
      text: compact(item.content, 500),
      score: scoreText(queryTokens, item.content),
      source: 'conversation' as const,
    }))
    .filter(item => item.score >= 2)
    .sort((a, b) => b.score - a.score)
    .slice(0, 2);
}

function buildFaqItems(payload: AiQueryPayload, queryTokens: string[]): RetrievedContextItem[] {
  const finding = payload.findingContext;
  const expandedQuery = [
    payload.question,
    payload.lastAssistantMessage ?? '',
    finding?.title ?? '',
    finding?.ruleId ?? '',
    finding?.owaspCategory ?? '',
    finding?.remediation ?? '',
    ...(finding?.evidence ?? []),
  ].join(' ');
  const expandedTokens = unique([...queryTokens, ...tokens(expandedQuery)]);

  return FAQ
    .map(entry => {
      const searchable = [
        entry.id,
        entry.question,
        entry.answer,
        ...(entry.keywords ?? []),
      ].join(' ');
      const keywordBonus = (entry.keywords ?? []).reduce((sum, keyword) => {
        const normKeyword = normalize(keyword);
        return expandedTokens.some(token => normKeyword.includes(token) || token.includes(normKeyword))
          ? sum + 3
          : sum;
      }, 0);
      const categoryBonus = finding?.owaspCategory &&
        normalize(searchable).includes(normalize(finding.owaspCategory))
        ? 6
        : 0;

      return {
        id: entry.id,
        title: entry.question,
        text: compact(entry.answer, 1000),
        score: scoreText(expandedTokens, searchable) + keywordBonus + categoryBonus,
        source: 'faq' as const,
      };
    })
    .filter(item => item.score >= 3)
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);
}

export function retrieveKnowledgeContext(payload: AiQueryPayload): RetrievedContext {
  const queryTokens = unique(tokens([
    payload.question,
    payload.lastAssistantMessage ?? '',
    payload.findingContext?.title ?? '',
  ].join(' ')));

  const items: RetrievedContextItem[] = [];
  const findingItem = buildFindingItem(payload);
  if (findingItem) items.push(findingItem);
  items.push(...buildFaqItems(payload, queryTokens));
  items.push(...buildConversationItems(payload, queryTokens));

  const deduped = items.filter((item, index, all) =>
    all.findIndex(other => other.id === item.id) === index
  ).slice(0, 8);

  return {
    items: deduped,
    sourceIds: deduped.map(item => item.id),
    summary: deduped
      .map((item, index) => `[${index + 1}] ${item.title} (${item.source})\n${item.text}`)
      .join('\n\n'),
  };
}
