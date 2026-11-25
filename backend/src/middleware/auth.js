import { Session } from '../models/index.js';
import { sha256, randomToken } from '../utils/crypto.js';
import { forbidden, unauthorized } from '../utils/errors.js';

export const SESSION_COOKIE = 'aerotrack_session';

// In-memory session cache (TTL 60s) to avoid redundant database round trips on parallel requests
const sessionCache = new Map();

export function invalidateSession(tokenHash) {
  if (tokenHash) sessionCache.delete(tokenHash);
}

export function clearSessionCache() {
  sessionCache.clear();
}

export function cookieOptions(env) {
  return {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: env.COOKIE_SAMESITE,
    path: '/',
    maxAge: env.SESSION_TTL_HOURS * 3600 * 1000,
  };
}

export async function startSession(env, req, res, user) {
  const token = randomToken(32);
  const tokenHash = sha256(token);
  invalidateSession(tokenHash);
  await Session.create({
    user: user._id,
    tokenHash,
    expiresAt: new Date(Date.now() + env.SESSION_TTL_HOURS * 3600 * 1000),
    userAgent: req.get('user-agent')?.slice(0, 300),
  });
  res.cookie(SESSION_COOKIE, token, cookieOptions(env));
}

/** Attaches req.user when a valid session cookie is present. Never throws for anonymous requests. */
export const loadSession = async (req, _res, next) => {
  const token = req.cookies?.[SESSION_COOKIE];
  if (typeof token !== 'string' || token.length < 20 || token.length > 100) return next();
  const tokenHash = sha256(token);
  const now = Date.now();

  const cached = sessionCache.get(tokenHash);
  if (cached && cached.cachedUntil > now) {
    req.user = cached.user;
    req.sessionId = cached.sessionId;
    req.sessionTokenHash = tokenHash;
    return next();
  }

  try {
    const session = await Session.findOne({ tokenHash, expiresAt: { $gt: new Date() } }).populate('user');
    if (!session || !session.user || session.user.disabled) {
      sessionCache.delete(tokenHash);
      return next();
    }
    req.user = session.user;
    req.sessionId = String(session._id);
    req.sessionTokenHash = tokenHash;

    sessionCache.set(tokenHash, {
      user: session.user,
      sessionId: req.sessionId,
      cachedUntil: now + 60_000,
    });
    if (sessionCache.size > 2000) {
      for (const [k, v] of sessionCache.entries()) {
        if (v.cachedUntil <= now) sessionCache.delete(k);
      }
    }
  } catch {
    req.user = null;
  }
  next();
};

export const requireAuth = (req, _res, next) => {
  if (!req.user) throw unauthorized();
  next();
};

export const requireVerified = (req, _res, next) => {
  if (!req.user) throw unauthorized();
  if (!req.user.emailVerified) throw forbidden('Please verify your email address first.');
  next();
};

export function requireRole(...roles) {
  return (req, _res, next) => {
    if (!req.user) throw unauthorized();
    if (!roles.includes(req.user.role)) throw forbidden();
    next();
  };
}

export const isStaff = (u) => u?.role === 'staff' || u?.role === 'admin';
