function responseFingerprint(text) {
  const body = (text || '').replace(/\s+/g, ' ').trim();
  return {
    length: body.length,
    hasSqlError: /sql|syntax error|database error|mysql|postgres|sqlserver|odbc/i.test(body),
    hasStack: /exception|stack trace|traceback|System\.\w+Exception/i.test(body),
    excerpt: body.slice(0, 180)
  };
}

module.exports = { responseFingerprint };
