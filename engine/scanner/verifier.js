// engine/scanner/verifier.js

const { isSqlError } = require('./analyzer');
const { URL } = require('url');

/**
 * Module Verifier (Kiểm toán mức độ tin cậy)
 * Khi Analyzer báo động có lỗi, Verifier sẽ chặn lại không cho xuất Report ngay.
 * Nó sẽ bắn thêm các Request "Khởi tạo lại trạng thái" để chắc chắn rằng
 * server thực sự bị điều khiển bởi payload chứ không phải ngẫu nhiên sập.
 */

/**
 * Double Check lỗi SQL Injection (Boolean-based Verification)
 * Nếu server trả lỗi 500 do dấu nháy đơn ('), ta gửi một lệnh boolean nghịch đảo.
 * 
 * @param {string} targetUrl URL cần test
 * @param {string} paramKey Tên tham số dính lỗi
 * @param {Object} client ScannerHttpClient instance
 * @param {Object} reqHeaders Request headers
 * @returns {Promise<string>} Confidence level: 'high' | 'medium' | 'potential'
 */
async function verifySqli(targetUrl, paramKey, client, reqHeaders) {
    try {
        const falseUrl = new URL(targetUrl);
        // Payload cố tình làm Sai logic mệnh đề (Nếu bị SQLi thì trang web có biểu hiện biến mất Data hoặc trả 200 trống)
        // Nhưng quan trọng nó KHÔNG vướng lỗi Syntax Error như dấu (')
        falseUrl.searchParams.set(paramKey, "' AND 1=0--");
        const falseRes = await client.request(falseUrl.toString(), { headers: reqHeaders }).catch(() => null);
        
        // Cú pháp này rất chuẩn SQL. Nếu nó vẫn văng lỗi 500 hoặc rò rỉ Syntax Error...
        // ...thì có nghĩa là hệ thống web tự thân nó đã bị hỏng sẵn, chứ không phải ta đang thao túng được DB!
        if (falseRes && isSqlError(falseRes)) {
            return 'potential'; // Vẫn báo nhưng hạ cấp độ tin cậy xuống
        }

        // Nếu bắn False mà mượt mà (Không bị 500 Server error). Ta gửi luôn True.
        const trueUrl = new URL(targetUrl);
        trueUrl.searchParams.set(paramKey, "' AND 1=1--");
        const trueRes = await client.request(trueUrl.toString(), { headers: reqHeaders }).catch(() => null);
        
        // Nếu True cũng mượt mà nốt không lỗi 500 -> Ta đã thiết lập được Boolean Inference.
        if (trueRes && !isSqlError(trueRes)) {
            return 'high';
        }

        return 'medium';
    } catch {
        return 'potential';
    }
}

/**
 * Kiểm định XSS Reflection
 * 
 * @param {string} targetUrl URL cần test
 * @param {string} paramKey Tham số dính lỗi
 * @param {Object} client HttpClient instance
 * @param {Object} reqHeaders Request Headers
 * @returns {Promise<string>} Confidence level
 */
async function verifyXss(targetUrl, paramKey, client, reqHeaders) {
    try {
        const probeUrl = new URL(targetUrl);
        // Thử gửi kí tự HTML control (<, >, ") để xem có bị escape thành &lt; &gt; không.
        const probeString = "<SNTL_PROBE>";
        probeUrl.searchParams.set(paramKey, probeString);

        const res = await client.request(probeUrl.toString(), { headers: reqHeaders }).catch(() => null);
        if (res && res.text) {
            // Nếu dấu ngoặc nhọn CÒN NGUYÊN VẸN, chứng tỏ WAF/Filter bypass thành công hoàn toàn
            if (res.text.includes(probeString)) {
                return 'high';
            }
            // Nếu nó bị đổi (VD < biến thành &lt;), thì đợt báo động trước có thể là False Positive
            if (res.text.includes('&lt;SNTL_PROBE&gt;')) {
                return 'low';
            }
        }
        return 'medium';
    } catch {
        return 'medium';
    }
}

module.exports = {
    verifySqli,
    verifyXss
};
