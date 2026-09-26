import { ERROR_CODES, ERROR_MESSAGES } from '@vuln/shared';

export interface FieldError {
  field: string;
  message: string;
}

/**
 * 业务异常基类：抛出后由 errorHandler 统一转成 { code, message, data } 响应。
 * `httpStatus` 与 `code` 都按 docs/02 第 10 章错误码全表取值。
 */
export class AppError extends Error {
  readonly httpStatus: number;
  readonly code: number;
  readonly data: unknown;

  constructor(code: number, message?: string, httpStatus?: number, data: unknown = null) {
    super(message ?? ERROR_MESSAGES[code] ?? '未知错误');
    this.name = 'AppError';
    this.code = code;
    this.httpStatus = httpStatus ?? defaultHttpStatus(code);
    this.data = data;
  }

  static badRequest(fieldErrors: FieldError[], message = ERROR_MESSAGES[ERROR_CODES.PARAM_INVALID]) {
    return new AppError(ERROR_CODES.PARAM_INVALID, message, 400, { errors: fieldErrors });
  }

  static invalid(message: string, field = 'request') {
    return AppError.badRequest([{ field, message }], '参数校验失败');
  }

  static unauthorized(code: number = ERROR_CODES.UNAUTHORIZED) {
    return new AppError(code, undefined, 401);
  }

  static forbidden(code: number = ERROR_CODES.FORBIDDEN) {
    return new AppError(code, undefined, 403);
  }

  static notFound(message?: string) {
    return new AppError(ERROR_CODES.NOT_FOUND, message, 404);
  }

  static conflict(message?: string) {
    return new AppError(ERROR_CODES.CONFLICT, message, 409);
  }

  static internal(message?: string) {
    return new AppError(ERROR_CODES.INTERNAL_ERROR, message, 500);
  }
}

export function defaultHttpStatus(code: number): number {
  switch (code) {
    case ERROR_CODES.OK:
      return 200;
    case ERROR_CODES.PARAM_INVALID:
    case ERROR_CODES.OLD_PASSWORD_WRONG:
    case ERROR_CODES.PASSWORD_TOO_WEAK:
    case ERROR_CODES.SCAN_STATE_NOT_ALLOWED:
      return 400;
    case ERROR_CODES.UNAUTHORIZED:
    case ERROR_CODES.API_KEY_INVALID:
    case ERROR_CODES.API_KEY_EXPIRED:
    case ERROR_CODES.API_KEY_REPO_DENIED:
      return 401;
    case ERROR_CODES.FORBIDDEN:
    case ERROR_CODES.ACCOUNT_DISABLED:
      return 403;
    case ERROR_CODES.NOT_FOUND:
      return 404;
    case ERROR_CODES.CONFLICT:
      return 409;
    case ERROR_CODES.PAYLOAD_TOO_LARGE:
      return 413;
    case ERROR_CODES.RATE_LIMITED:
    case ERROR_CODES.LOGIN_RATE_LIMITED:
      return 429;
    case ERROR_CODES.SERVICE_UNAVAILABLE:
      return 503;
    default:
      return 500;
  }
}
