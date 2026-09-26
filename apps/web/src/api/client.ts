import axios, { AxiosError, type AxiosInstance, type AxiosRequestConfig } from 'axios';
import { message } from 'antd';
import { ERROR_CODES } from '@vuln/shared';

/**
 * 统一请求封装：
 *  - 自动注入 Authorization: Bearer <token>
 *  - 解包契约响应 { code, message, data }，code !== 0 时抛出带 code 的错误
 *  - 401 / 40100 时清理 token 并跳登录页
 */
const TOKEN_KEY = 'vuln_platform_token';

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

export interface ApiError extends Error {
  code: number;
  httpStatus?: number;
  data?: unknown;
  fieldErrors?: Array<{ field: string; message: string }>;
}

let redirecting = false;

export const http: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_BASE ?? '/api/v1',
  timeout: 30_000,
  headers: { 'Content-Type': 'application/json' },
});

http.interceptors.request.use((cfg) => {
  const token = getToken();
  if (token) cfg.headers.Authorization = `Bearer ${token}`;
  return cfg;
});

http.interceptors.response.use(
  (res) => res,
  (error: AxiosError<{ code?: number; message?: string; data?: unknown; traceId?: string }>) => {
    const status = error.response?.status;
    const body = error.response?.data;
    const code = body?.code ?? (status === 401 ? ERROR_CODES.UNAUTHORIZED : ERROR_CODES.INTERNAL_ERROR);

    const err = new Error(body?.message ?? error.message ?? '请求失败') as ApiError;
    err.code = code;
    err.httpStatus = status;
    err.data = body?.data;

    const errors = (body?.data as { errors?: Array<{ field: string; message: string }> } | undefined)?.errors;
    if (Array.isArray(errors)) err.fieldErrors = errors;

    if (code === ERROR_CODES.UNAUTHORIZED || code === ERROR_CODES.API_KEY_INVALID) {
      clearToken();
      if (!redirecting && !window.location.pathname.startsWith('/login')) {
        redirecting = true;
        message.warning('登录已过期，请重新登录');
        const next = encodeURIComponent(window.location.pathname + window.location.search);
        window.location.replace(`/login?next=${next}`);
        setTimeout(() => {
          redirecting = false;
        }, 1500);
      }
    }
    return Promise.reject(err);
  },
);

/** 解包 { code, message, data }，返回 data */
async function unwrap<T>(p: Promise<{ data: { code: number; message: string; data: T } }>): Promise<T> {
  const res = await p;
  const body = res.data;
  if (body && typeof body === 'object' && 'code' in body && body.code !== ERROR_CODES.OK) {
    const err = new Error(body.message || '请求失败') as ApiError;
    err.code = body.code;
    throw err;
  }
  return body?.data as T;
}

export const api = {
  get: <T>(url: string, params?: unknown, config?: AxiosRequestConfig) =>
    unwrap<T>(http.get(url, { params, ...config })),
  post: <T>(url: string, data?: unknown, config?: AxiosRequestConfig) =>
    unwrap<T>(http.post(url, data, config)),
  patch: <T>(url: string, data?: unknown) => unwrap<T>(http.patch(url, data)),
  delete: <T>(url: string) => unwrap<T>(http.delete(url)),
  /** 原始响应，用于导出 CSV 这类非 JSON 场景 */
  raw: (url: string, params?: unknown) => http.get(url, { params, responseType: 'blob' }),
};
