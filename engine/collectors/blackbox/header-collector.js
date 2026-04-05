function collectCookieIssues(setCookies = []) {
  const issues = [];
  for (const cookie of setCookies) {
    const lower = cookie.toLowerCase();
    const name = cookie.split('=')[0];
    if (!lower.includes('httponly')) issues.push(`${name}: thiếu HttpOnly`);
    if (!lower.includes('secure')) issues.push(`${name}: thiếu Secure`);
    if (!lower.includes('samesite=')) issues.push(`${name}: thiếu SameSite`);
  }
  return issues;
}

module.exports = { collectCookieIssues };
