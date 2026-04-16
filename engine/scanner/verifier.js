// engine/scanner/verifier.js

const { isSqlError } = require('./analyzer');
const { URL } = require('url');

/**
 * Module Verifier — Kiểm chứng mức độ tin cậy (confidence verification)
 *
 * Khi Analyzer/Fuzzer phát hiện dấu hiệu vulnerability, Verifier gửi thêm các
 * request có payload kiểm soát để xác nhận server thực sự bị ảnh hưởng —
 * không phải lỗi ngẫu nhiên hay false positive.
 *
 * Lưu ý sau fix BUG 2 (isSqlError):
 * isSqlError() hiện chỉ check SQL error pattern trong response body, KHÔNG check HTTP 500.
 * Logic verifier bên dưới dùng isSqlError() để phát hiện "vẫn rò rỉ SQL error với payload
 * boolean chuẩn" → hạ confidence xuống 'potential'. Logic này vẫn đúng sau fix:
 * nếu server trả SQL error pattern với cả payload boolean → server lỗi sẵn, không phải
 * ta đang điều khiển được — confidence thấp là hợp lý.
 */

/**
 * Kiểm chứng SQLi theo kiểu boolean-based.
 *
 * Chiến lược:
 *   1. Gửi "' AND 1=0--" (false condition, syntax chuẩn) → nếu SQL error pattern xuất hiện,
 *      server bị lỗi sẵn, không phải do ta inject → confidence = 'potential'
 *   2. Gửi "' AND 1=1--" (true condition) → nếu không có SQL error → boolean inference
 *      thành công → confidence = 'high'
 *   3. Còn lại → confidence = 'medium'
 *
 * @param {string} targetUrl   - URL đang test
 * @param {string} paramKey    - Tên param dính lỗi
 * @param {object} client      - ScannerHttpClient instance
 * @param {object} reqHeaders  - Request headers
 * @returns {Promise<'high'|'medium'|'potential'>}
 */
async function verifySqli(targetUrl, paramKey, client, reqHeaders) {
  try {
    const falseUrl = new URL(targetUrl);
    falseUrl.searchParams.set(paramKey, "' AND 1=0--");
    const falseRes = await client.request(falseUrl.toString(), { headers: reqHeaders }).catch(() => null);

    // Nếu payload boolean hợp lệ mà vẫn trigger SQL error pattern → server lỗi sẵn
    if (falseRes && isSqlError(falseRes)) {
      return 'potential';
    }

    const trueUrl = new URL(targetUrl);
    trueUrl.searchParams.set(paramKey, "' AND 1=1--");
    const trueRes = await client.request(trueUrl.toString(), { headers: reqHeaders }).catch(() => null);

    // False không lỗi + True không lỗi → boolean inference thiết lập thành công
    if (trueRes && !isSqlError(trueRes)) {
      return 'high';
    }

    return 'medium';
  } catch {
    return 'potential';
  }
}

/**
 * Kiểm chứng hiện tượng phản xạ XSS.
 *
 * Chiến lược: gửi chuỗi probe chứa ký tự điều khiển HTML (<, >).
 *   - Còn nguyên vẹn trong response → không có output encoding → 'high'
 *   - Bị encode thành &lt;&gt;            → có encoding, FP có thể xảy ra → 'low'
 *   - Không kết luận được                → 'medium'
 *
 * @param {string} targetUrl   - URL đang test
 * @param {string} paramKey    - Tên param nghi vấn
 * @param {object} client      - ScannerHttpClient instance
 * @param {object} reqHeaders  - Request headers
 * @returns {Promise<'high'|'medium'|'low'>}
 */
async function verifyXss(targetUrl, paramKey, client, reqHeaders) {
  try {
    const probeUrl = new URL(targetUrl);
    const probeString = '<SNTL_PROBE>';
    probeUrl.searchParams.set(paramKey, probeString);

    const res = await client.request(probeUrl.toString(), { headers: reqHeaders }).catch(() => null);
    if (res?.text) {
      if (res.text.includes(probeString))            return 'high';
      if (res.text.includes('&lt;SNTL_PROBE&gt;')) return 'low';
    }
    return 'medium';
  } catch {
    return 'medium';
  }
}

module.exports = { verifySqli, verifyXss };
