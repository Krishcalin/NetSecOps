/**
 * HTTP client for the NetSecOps API.
 *
 * Auth tokens live in HttpOnly cookies (FR-AUTH-02), so this client never touches a
 * token: it just sends credentials and echoes the CSRF cookie back in a header for the
 * double-submit check (SEC-03).
 *
 * A 401 on any call triggers a single refresh attempt, then a replay of the original
 * request. Concurrent 401s share one refresh so a page with several queries does not
 * fire a burst of rotations — which the reuse detection in FR-AUTH-02 would read as a
 * stolen token.
 */

const API_BASE = import.meta.env.VITE_API_BASE ?? '/api/v1';

const CSRF_COOKIE = 'netsecops_csrf';
const CSRF_HEADER = 'X-CSRF-Token';

/** RFC 7807 problem details, as returned by every error path in the API. */
export interface Problem {
  type: string;
  title: string;
  status: number;
  detail: string;
  instance?: string;
  correlation_id?: string;
  violations?: string[];
  errors?: { loc: (string | number)[]; msg: string; type: string }[];
}

export class ApiError extends Error {
  readonly status: number;
  readonly problem: Problem;

  constructor(problem: Problem) {
    super(problem.detail || problem.title);
    this.name = 'ApiError';
    this.status = problem.status;
    this.problem = problem;
  }

  /** True when the account is locked out (FR-AUTH-06), which the UI phrases differently. */
  get isLocked(): boolean {
    return this.status === 423;
  }

  get isRateLimited(): boolean {
    return this.status === 429;
  }
}

function readCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp(`(^|;\\s*)${name}=([^;]*)`));
  const value = match?.[2];
  return value === undefined ? null : decodeURIComponent(value);
}

type RequestOptions = Omit<RequestInit, 'body'> & { body?: unknown; skipRefresh?: boolean };

/** Shared in-flight refresh, so parallel 401s cause exactly one rotation. */
let refreshInFlight: Promise<boolean> | null = null;

async function refreshSession(): Promise<boolean> {
  refreshInFlight ??= (async () => {
    try {
      const response = await fetch(`${API_BASE}/auth/refresh`, {
        method: 'POST',
        credentials: 'include',
        headers: csrfHeaders(),
      });
      return response.ok;
    } catch {
      return false;
    } finally {
      // Cleared on the microtask after settling so callers awaiting this promise all
      // observe the same result before the next attempt can start.
      queueMicrotask(() => {
        refreshInFlight = null;
      });
    }
  })();

  return refreshInFlight;
}

function csrfHeaders(): Record<string, string> {
  const token = readCookie(CSRF_COOKIE);
  return token ? { [CSRF_HEADER]: token } : {};
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { body, skipRefresh, headers, ...rest } = options;

  const send = (): Promise<Response> =>
    fetch(`${API_BASE}${path}`, {
      ...rest,
      credentials: 'include',
      headers: {
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...csrfHeaders(),
        ...(headers as Record<string, string> | undefined),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

  let response = await send();

  if (response.status === 401 && !skipRefresh && !path.startsWith('/auth/')) {
    if (await refreshSession()) {
      response = await send();
    }
  }

  if (response.status === 204) {
    return undefined as T;
  }

  if (!response.ok) {
    throw new ApiError(await toProblem(response));
  }

  return (await response.json()) as T;
}

async function toProblem(response: Response): Promise<Problem> {
  try {
    const body = (await response.json()) as Partial<Problem>;
    return {
      type: body.type ?? 'about:blank',
      title: body.title ?? response.statusText,
      status: body.status ?? response.status,
      detail: body.detail ?? response.statusText,
      instance: body.instance,
      correlation_id: body.correlation_id,
      violations: body.violations,
      errors: body.errors,
    };
  } catch {
    // A proxy error or a network-level failure will not be problem+json.
    return {
      type: 'about:blank',
      title: response.statusText || 'Request failed',
      status: response.status,
      detail: 'The server returned an unexpected response.',
    };
  }
}

export const api = {
  get: <T>(path: string) => request<T>(path, { method: 'GET' }),
  post: <T>(path: string, body?: unknown) => request<T>(path, { method: 'POST', body }),
  patch: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PATCH', body }),
  put: <T>(path: string, body?: unknown) => request<T>(path, { method: 'PUT', body }),
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
};
