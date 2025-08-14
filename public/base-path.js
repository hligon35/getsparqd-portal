(function(){
  // Determine base path when reverse proxied under /portal
  const BASE = window.location.pathname.startsWith('/portal') ? '/portal' : '';
  window.__PORTAL_BASE__ = BASE;

  // Wrap fetch to automatically prefix BASE when URL starts with '/'
  const origFetch = window.fetch.bind(window);
  window.fetch = (input, init) => {
    try {
      if (typeof input === 'string' && input.startsWith('/')) {
        input = `${BASE}${input}`;
      } else if (input && input.url && input.url.startsWith('/')) {
        input = new Request(`${BASE}${input.url}`, input);
      }
    } catch (_) {}
    return origFetch(input, init);
  };

  // Helper for redirects that need BASE prefix
  window.__withBase__ = (path) => `${BASE}${path.startsWith('/') ? path : '/'+path}`;
})();
