import type { AiQueryPayload } from '../aiRouter';
import type { RetrievedContext } from '../contextRetriever';

export interface QualityCheck {
  ok: boolean;
  score: number;
  warnings: string[];
}

function normalize(text: string): string {
  return text
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function includesAny(text: string, terms: string[]): boolean {
  const norm = normalize(text);
  return terms.some(term => term && norm.includes(normalize(term)));
}

function hasVietnameseDiacritics(text: string): boolean {
  return /[àáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩòóọỏõôồốộổỗơờớợởỡùúụủũưừứựửữỳýỵỷỹđ]/i.test(text);
}

export function assessAnswerQuality(
  answer: string,
  payload: AiQueryPayload,
  retrieved: RetrievedContext,
): QualityCheck {
  const warnings: string[] = [];
  let score = 0.45;
  const normAnswer = normalize(answer);

  if (answer.trim().length >= 250) score += 0.12;
  else warnings.push('answer is short');

  if (hasVietnameseDiacritics(answer)) {
    score += 0.10;
  } else {
    score -= 0.20;
    warnings.push('answer should be Vietnamese with diacritics');
  }

  if (includesAny(answer, ['khắc phục', 'fix', 'remediation', 'giải pháp', 'phòng tránh'])) {
    score += 0.12;
  } else {
    warnings.push('missing remediation guidance');
  }

  if (includesAny(answer, ['owasp', 'severity', 'mức độ', 'rủi ro', 'risk'])) score += 0.08;

  if (payload.findingContext) {
    const finding = payload.findingContext;
    const identityTerms = [
      finding.ruleId ?? '',
      finding.title ?? '',
      finding.owaspCategory ?? '',
      finding.severity ?? '',
    ].filter(Boolean);
    if (includesAny(answer, identityTerms)) {
      score += 0.15;
    } else {
      warnings.push('does not reference the current finding clearly');
    }

    if (finding.evidence?.length) {
      const evidenceTerms = finding.evidence
        .join(' ')
        .split(/\s+/)
        .filter(term => term.length >= 5)
        .slice(0, 12);
      if (includesAny(answer, evidenceTerms)) score += 0.08;
      else warnings.push('does not use finding evidence');
    }
  }

  if (retrieved.sourceIds.length > 0) {
    const sourceHits = retrieved.items.filter(item => {
      const titleTerms = item.title.split(/\s+/).filter(term => term.length >= 4).slice(0, 4);
      return titleTerms.length > 0 && includesAny(answer, titleTerms);
    }).length;
    if (sourceHits > 0 || normAnswer.includes('sentinel') || normAnswer.includes('finding')) {
      score += 0.08;
    } else {
      warnings.push('weak grounding in retrieved context');
    }
  }

  const evasive = [
    'toi khong co du thong tin',
    'as an ai',
    'i cannot',
    'khong the tra loi',
    'cau hoi nay qua phuc tap',
  ];
  if (evasive.some(marker => normAnswer.includes(marker))) {
    score -= 0.25;
    warnings.push('answer appears evasive');
  }

  const finalScore = Math.max(0, Math.min(1, score));
  return {
    ok: finalScore >= (payload.findingContext ? 0.68 : 0.58),
    score: finalScore,
    warnings,
  };
}
