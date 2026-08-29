const DEFAULT_BASE_URL = 'http://127.0.0.1:8000';

export class ApiError extends Error {
  code: string;
  status?: number;

  constructor(message: string, code: string, status?: number) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
  }
}

export function getApiBaseUrl(): string {
  return (import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim() || DEFAULT_BASE_URL;
}

export async function getJson(path: string): Promise<unknown> {
  const url = new URL(path, getApiBaseUrl()).toString();

  let response: Response;
  try {
    response = await fetch(url, {
      headers: { Accept: 'application/json' },
    });
  } catch {
    throw new ApiError('Backend unavailable. Could not reach the AEGIS API.', 'network_failure');
  }

  let data: unknown = null;
  try {
    data = await response.json();
  } catch {
    throw new ApiError('The API returned an invalid JSON response.', 'invalid_json', response.status);
  }

  if (!response.ok) {
    const message = extractErrorMessage(data, response.status);
    const code = extractErrorCode(data, response.status);
    throw new ApiError(message, code, response.status);
  }

  return data;
}

function extractErrorMessage(data: unknown, status: number): string {
  if (typeof data === 'object' && data !== null && 'detail' in data) {
    const detail = (data as { detail: unknown }).detail;
    if (typeof detail === 'string') {
      return detail;
    }
    if (typeof detail === 'object' && detail !== null && 'message' in detail) {
      const message = (detail as { message?: unknown }).message;
      if (typeof message === 'string' && message.trim()) {
        return message;
      }
    }
  }

  if (status === 404) {
    return 'The selected security event could not be found.';
  }
  if (status === 422) {
    return 'The request parameters were invalid.';
  }
  if (status === 503) {
    return 'Backend storage is unavailable.';
  }
  return 'The AEGIS API returned an unexpected error.';
}

function extractErrorCode(data: unknown, status: number): string {
  if (typeof data === 'object' && data !== null && 'detail' in data) {
    const detail = (data as { detail: unknown }).detail;
    if (typeof detail === 'object' && detail !== null && 'code' in detail) {
      const code = (detail as { code?: unknown }).code;
      if (typeof code === 'string' && code.trim()) {
        return code;
      }
    }
  }
  return `http_${status}`;
}
