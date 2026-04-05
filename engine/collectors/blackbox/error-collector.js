function detectVerboseErrors(text = '') {
  return /exception|stack trace|traceback|System\.\w+Exception|ReferenceError|TypeError|SQL/i.test(text);
}

function detectFailOpenCandidate(baseStatus, variantStatus) {
  return baseStatus === 401 && variantStatus === 200;
}

module.exports = { detectVerboseErrors, detectFailOpenCandidate };
