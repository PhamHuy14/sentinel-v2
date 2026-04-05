/* global URL, module */
function extractForms(html) {
  const formMatches = [...(html || '').matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)];
  
  return formMatches.map(m => {
    const attrs = m[1];
    const body  = m[2];

    // Parse form attributes
    const actionMatch = attrs.match(/action=["']([^"']*)["']/i);
    const methodMatch = attrs.match(/method=["']([^"']*)["']/i);
    const action = actionMatch ? actionMatch[1] : '';
    const method = methodMatch ? methodMatch[1].toLowerCase() : 'get';

    // Parse all input / select / textarea fields
    const inputMatches = [...body.matchAll(/<(?:input|select|textarea)\b([^>]*)/gi)];
    const inputs = inputMatches.map(im => {
      const ia = im[1];
      const nameMatch = ia.match(/name=["']([^"']*)["']/i);
      const typeMatch = ia.match(/type=["']([^"']*)["']/i);
      const valueMatch = ia.match(/value=["']([^"']*)["']/i);
      return {
        name:  nameMatch  ? nameMatch[1]  : null,
        type:  typeMatch  ? typeMatch[1].toLowerCase()  : 'text',
        value: valueMatch ? valueMatch[1] : ''
      };
    }).filter(i => i.name); // Loại bỏ các field không có name

    return { action, method, inputs };
  });
}


function extractLinks(html, baseOrigin) {
  const links = new Set();
  
  // 1. Standard href
  const aMatches = [...(html || '').matchAll(/href=["']([^"'#>]+)["']/gi)];
  // 2. SRC endpoints (scripts, imgs)
  const srcMatches = [...(html || '').matchAll(/src=["']([^"'#>]+)["']/gi)];
  // 3. API/fetch like patterns
  const apiMatches = [...(html || '').matchAll(/(?:axios\.(?:get|post|put|delete)|fetch)\s*\(\s*['"]([^"'#>]+)['"]/gi)];
  // 4. Relative path patterns inside JS files or inline scripts
  const jsPathMatches = [...(html || '').matchAll(/['"](\/(?:api|v1|v2|users|admin|auth)[^"'#>]*|[^"'#>]+\.php|[^"'#>]+\.aspx)['"]/gi)];

  const allMatches = [...aMatches, ...srcMatches, ...apiMatches, ...jsPathMatches];

  for (const m of allMatches) {
    let href = m[1].trim();
    if (!href) continue;
    if (href.startsWith('javascript:')) continue;
    if (href.startsWith('mailto:')) continue;
    if (href.startsWith('tel:')) continue;
    if (href.startsWith('data:')) continue;

    if (href.startsWith('/')) {
      links.add(new URL(href, baseOrigin).toString());
    } else if (/^https?:\/\//i.test(href)) {
      links.add(href);
    }
  }

  return [...links].slice(0, 100);
}

module.exports = { extractForms, extractLinks };
