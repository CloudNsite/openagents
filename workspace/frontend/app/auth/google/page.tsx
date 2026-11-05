'use client';

import { useEffect, useState } from 'react';
import { googleLoginDest } from '@/lib/auth-redirects';
import { saveWorkspaceSession } from '@/lib/workspace-session';

/** Landing page for direct Google sign-in (see backend routers/google_login.py).
 * The backend puts the workspace session in the URL fragment so it never
 * reaches server logs; we store it and continue to the original page. */
export default function GoogleAuthLanding() {
  const [error, setError] = useState('');
  useEffect(() => {
    const p = new URLSearchParams(window.location.hash.slice(1));
    const s = p.get('s'); const e = p.get('e'); const x = Number(p.get('x'));
    history.replaceState(null, '', '/auth/google');
    if (!s || !e || !x) { setError('Sign-in failed. Please try again.'); return; }
    saveWorkspaceSession({ token: s, email: e, displayName: p.get('n') || null, expiresAt: x });
    window.location.replace(googleLoginDest(p.get('r') || '/'));
  }, []);
  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-8">
      {error ? <a href="/login" className="text-sm text-destructive">{error}</a>
             : <p className="text-sm text-muted-foreground">Signing in...</p>}
    </div>
  );
}
