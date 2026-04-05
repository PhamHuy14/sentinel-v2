function getDesignChecklist() {
  return [
    'Có threat model cho luồng đăng nhập, thanh toán và thao tác admin.',
    'Có abuse cases cho brute force, IDOR, privilege escalation, destructive action.',
    'Có xác định trust boundary giữa client, API, DB, bên thứ ba.',
    'Có thiết kế rate limiting / throttling cho luồng nhạy cảm.',
    'Có default deny / least privilege cho route và dữ liệu.',
    'Có fail-safe behavior khi lỗi timeout, parse lỗi, service phụ chết.',
    'Có data classification cho PII, credentials, tokens, secrets.',
    'Có review thiết kế bảo mật trước khi release.'
  ];
}

module.exports = { getDesignChecklist };
