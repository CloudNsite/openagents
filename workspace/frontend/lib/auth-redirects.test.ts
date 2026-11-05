import { afterEach, describe, expect, it, vi } from 'vitest';
import { goToCentralLogin, goToCentralLogout, googleLoginDest, redirectToLogin } from './auth-redirects';

afterEach(() => vi.unstubAllGlobals());
describe('desktop account boundaries', () => {
  it('uses desktop sign-in instead of navigating the embedded app to the account site', () => {
    const signIn = vi.fn();
    const location = { hostname:'workspace', href:'openagents://workspace/index.html#/team' };
    vi.stubGlobal('window', { location, __oaHost__:{ signIn } });
    goToCentralLogin();
    expect(signIn).toHaveBeenCalledOnce();
    expect(location.href).toBe('openagents://workspace/index.html#/team');
  });
  it('does not navigate to central logout after the host clears its session', async () => {
    const signOut = vi.fn().mockResolvedValue(undefined);
    const location = { hostname:'workspace', href:'openagents://workspace/index.html#/team' };
    vi.stubGlobal('window', { location, __oaHost__:{} });
    await goToCentralLogout(signOut);
    expect(signOut).toHaveBeenCalledOnce();
    expect(location.href).toBe('openagents://workspace/index.html#/team');
  });
  it('preserves the central login flow in the web app', () => {
    const location = { hostname:'workspace.openagents.org', href:'https://workspace.openagents.org/team' };
    vi.stubGlobal('window', { location });
    goToCentralLogin();
    expect(location.href).toBe('https://openagents.org/login?returnTo=https%3A%2F%2Fworkspace.openagents.org%2Fteam');
  });
});

it('redirects signed-out preview visitors to login with a return path', () => {
  const replace = vi.fn();
  vi.stubGlobal('window', { location: { hostname: 'workspace-preview.openagents.org', pathname: '/team/settings/members', search: '?x=1', hash: '', replace } });
  redirectToLogin();
  expect(replace).toHaveBeenCalledWith('/login?returnTo=%2Fteam%2Fsettings%2Fmembers%3Fx%3D1');
});


it('preserves the exact preview invitation when using central login', () => {
  const href = 'https://workspace-preview.openagents.org/invite/invite-token';
  const location = { hostname: 'workspace-preview.openagents.org', href };
  vi.stubGlobal('window', { location });
  const popup = vi.fn();
  goToCentralLogin(popup, { forceCentral: true });
  expect(popup).not.toHaveBeenCalled();
  const login = new URL(location.href);
  expect(login.origin + login.pathname).toBe('https://openagents.org/login');
  expect(login.searchParams.get('returnTo')).toBe(href);
});

it('can bypass inline login even on localhost', () => {
  const location = { hostname: 'localhost', href: 'http://localhost:3000/invite/test' };
  vi.stubGlobal('window', { location });
  const popup = vi.fn();
  goToCentralLogin(popup, { forceCentral: true });
  expect(popup).not.toHaveBeenCalled();
  expect(location.href).toContain('https://openagents.org/login?returnTo=');
});

describe('googleLoginDest', () => {
  const origin = 'https://agents.example.com';
  it('continues to pages on this origin', () => {
    expect(googleLoginDest('/team/threads?x=1#m', origin)).toBe('/team/threads?x=1#m');
  });
  it('allows the desktop landing page, with its handoff query', () => {
    const r = '/auth/desktop?port=54321&state=abc&retried=1';
    expect(googleLoginDest(r, origin)).toBe(r);
  });
  it.each(['/auth/google', '/auth/callback?x=1', '/auth/desktop/../callback', '/auth/desktopx'])(
    'refuses the other auth page %s', (r) => {
      expect(googleLoginDest(r, origin)).toBe('/');
    });
  it.each([
    'https://evil.example/',
    'https://evil.example/auth/desktop?port=54321&state=abc',
    '//evil.example/',
    '/\\evil.example/',
    '/\t/evil.example/',
    '/\n/evil.example/auth/desktop',
    'javascript:alert(1)',
    'https://user@evil.example/',
  ])('refuses the off-origin target %j', (r) => {
    expect(googleLoginDest(r, origin)).toBe('/');
  });
});
