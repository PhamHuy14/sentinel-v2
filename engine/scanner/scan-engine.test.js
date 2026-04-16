// engine/scanner/scan-engine.test.js
import { describe, expect, it } from 'vitest';
import { getChecklist, runProjectScan } from './scan-engine.js';

describe('Scanner Engine - Basic Validations', () => {
  it('getChecklist should return the correct OWASP category structure', () => {
    const checklist = getChecklist();
    expect(checklist.categories).toBeDefined();
    expect(checklist.categories.length).toBeGreaterThan(0);
    expect(checklist.categories[0].id).toBe('A01');
    expect(checklist.designQuestions).toBeDefined();
  });

  it('runProjectScan should reject when folderPath is invalid', async () => {
    try {
      await runProjectScan(null);
    } catch (e) {
      expect(e.message).toContain('Hãy chọn thư mục project');
    }
  });

  it('runProjectScan should abort immediately if abortSignal is true', async () => {
    const mockSignal = { aborted: true };
    const result = await runProjectScan('/fake/path', { abortSignal: mockSignal });
    expect(result.ok).toBe(false);
    expect(result.error).toContain('đã bị hủy');
  });
});
