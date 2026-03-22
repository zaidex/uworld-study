// _worker.js — Cloudflare Pages Worker
// Gates /app.html (and any path that isn't login.html or assets) behind auth.
// The session token is stored in a cookie called "zworld_token" set by login.html after sign-in.

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Always allow: login page, static assets, favicon
    const PUBLIC = ['/', '/login.html', '/favicon.ico'];
    const isPublic =
      PUBLIC.includes(path) ||
      path.startsWith('/_') ||          // Cloudflare internals
      path.match(/\.(css|js|png|svg|ico|woff2?|ttf)$/);

    if (isPublic) {
      return env.ASSETS.fetch(request);
    }

    // Everything else (including /app.html) requires a valid token cookie
    const cookie = request.headers.get('Cookie') || '';
    const tokenMatch = cookie.match(/zworld_token=([^;]+)/);
    const token = tokenMatch ? tokenMatch[1] : null;

    if (!token) {
      // No token — redirect to login
      return Response.redirect(new URL('/login.html', request.url).toString(), 302);
    }

    // Verify token is a real Supabase JWT (just check structure — full verify needs secret)
    // We do a lightweight check: must be 3 base64 parts and not expired
    try {
      const parts = token.split('.');
      if (parts.length !== 3) throw new Error('bad jwt');
      const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < now) throw new Error('expired');
    } catch (_) {
      // Invalid or expired token — redirect to login with expired flag
      const loginUrl = new URL('/login.html', request.url);
      loginUrl.searchParams.set('expired', '1');
      return Response.redirect(loginUrl.toString(), 302);
    }

    // Valid token — serve the requested file
    return env.ASSETS.fetch(request);
  }
};
