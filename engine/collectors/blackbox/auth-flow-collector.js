function detectAuthHints(html, headers = {}) {
  const content = `${html || ''} ${JSON.stringify(headers || {})}`;
  return {
    hasLoginHint: /login|sign in|đăng nhập/i.test(content),
    hasForgotPasswordHint: /forgot password|reset password|quên mật khẩu/i.test(content),
    hasMfaHint: /otp|mfa|2fa|two-factor|xác thực hai lớp/i.test(content)
  };
}

module.exports = { detectAuthHints };
