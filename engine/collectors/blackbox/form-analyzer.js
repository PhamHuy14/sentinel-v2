function hasCsrfToken(html) {
  const patterns = [/__requestverificationtoken/i, /csrf/i, /xsrf/i, /authenticity_token/i, /_token/i];
  return patterns.some((p) => p.test(html || ''));
}

function detectPostForms(forms = []) {
  // FIX: Hỗ trợ cả format object mới {method, action, inputs} và format string cũ (backward-compat)
  return forms.filter((form) => {
    if (typeof form === 'string') {
      return /method\s*=\s*["']?post/i.test(form);
    }
    return (form.method || 'get').toLowerCase() === 'post';
  });
}

module.exports = { hasCsrfToken, detectPostForms };
