import { api } from './client';
import type {
  ApiKeyCreated,
  ApiKeyItem,
  MlAnalyzeResponse,
  MlDetectResult,
  MlServiceStatus,
  Paged,
  Project,
  ProjectDetail,
  SampleListItem,
  SampleListResult,
  SampleStats,
  ScanTask,
  ScanTaskDetail,
  Severity,
  SeverityBucket,
  StatsOverview,
  TopProject,
  TopRule,
  TrendPoint,
  UserInfo,
  VulnListQuery,
  VulnListResult,
  VulnerabilityDetail,
} from '@vuln/shared';

/** 按模块拆分的接口封装，与 docs/02-API接口文档.md 一一对应 */
export const authApi = {
  me: () => api.get<UserInfo>('/auth/me'),
  changePassword: (oldPassword: string, newPassword: string) =>
    api.post<{ id: number; updatedAt: string }>('/auth/change-password', { oldPassword, newPassword }),
};

export const statsApi = {
  overview: (params?: { projectId?: number[]; days?: number }) =>
    api.get<StatsOverview>('/stats/overview', params),
  trend: (params?: { days?: number; projectId?: number[] }) =>
    api.get<{ list: TrendPoint[] }>('/stats/trend', params),
  severity: (params?: { projectId?: number[]; includeExcluded?: boolean }) =>
    api.get<{ list: SeverityBucket[] }>('/stats/severity', params),
  topRules: (params?: { limit?: number; projectId?: number[]; days?: number }) =>
    api.get<{ list: TopRule[] }>('/stats/top-rules', params),
  topProjects: (params?: { limit?: number; sortBy?: string }) =>
    api.get<{ list: TopProject[] }>('/stats/top-projects', params),
  statusDistribution: (params?: { projectId?: number[] }) =>
    api.get<{ list: Array<{ status: string; count: number }> }>('/stats/status', params),
  recentScans: (params?: { limit?: number }) =>
    api.get<{ list: ScanTask[] }>('/stats/recent-scans', params),
};

export const vulnApi = {
  list: (params?: VulnListQuery) => api.get<VulnListResult>('/vulnerabilities', params),
  detail: (id: number | string) => api.get<VulnerabilityDetail>(`/vulnerabilities/${id}`),
  updateStatus: (id: number | string, status: string, comment?: string) =>
    api.patch<{ id: number; status: string; fixedAt: string | null; updatedAt: string }>(
      `/vulnerabilities/${id}/status`,
      { status, comment },
    ),
  batchStatus: (ids: number[], status: string, comment?: string) =>
    api.post<{ requested: number; updated: number; failed: Array<{ id: number; reason: string }> }>(
      '/vulnerabilities/batch-status',
      { ids, status, comment },
    ),
  assign: (id: number | string, assignee: number | null, comment?: string) =>
    api.patch<{ id: number; assignee: number | null }>(`/vulnerabilities/${id}/assignee`, {
      assignee,
      comment,
    }),
  comment: (id: number | string, comment: string) =>
    api.post<{ id: number }>(`/vulnerabilities/${id}/comments`, { comment }),
  exportCsv: (params?: VulnListQuery) => api.raw('/vulnerabilities/export', params),
};

export const projectApi = {
  list: (params?: { page?: number; pageSize?: number; keyword?: string; repoType?: string }) =>
    api.get<Paged<Project>>('/projects', params),
  detail: (id: number | string) => api.get<ProjectDetail>(`/projects/${id}`),
  create: (body: Partial<Project>) => api.post<Project>('/projects', body),
  update: (id: number | string, body: Partial<Project>) => api.patch<Project>(`/projects/${id}`, body),
  options: () => api.get<{ list: Array<{ id: number; name: string; repoType: string }> }>('/projects/options/all'),
};

export const scanApi = {
  list: (params?: {
    page?: number;
    pageSize?: number;
    projectId?: number[];
    status?: string[];
    keyword?: string;
    sortBy?: string;
  }) => api.get<Paged<ScanTask> & { summary: Record<string, number> }>('/scans', params),
  detail: (scanNo: string) => api.get<ScanTaskDetail>(`/scans/${encodeURIComponent(scanNo)}`),
};

export const sampleApi = {
  list: (params?: {
    page?: number;
    pageSize?: number;
    projectId?: number[];
    label?: string[];
    ruleId?: string;
    language?: string;
    keyword?: string;
  }) => api.get<SampleListResult>('/samples', params),
  detail: (id: number | string) =>
    api.get<SampleListItem & { snippet: string | null; snippetHash: string; vuln: unknown }>(`/samples/${id}`),
  stats: (params?: { projectId?: number; startTime?: string; endTime?: string }) =>
    api.get<SampleStats>('/samples/stats', params),
};

export const apiKeyApi = {
  list: (params?: { page?: number; pageSize?: number; status?: number }) =>
    api.get<Paged<ApiKeyItem>>('/api-keys', params),
  create: (body: { name: string; scopes?: string[]; repoScope?: string[] | null; expiresAt?: string | null }) =>
    api.post<ApiKeyCreated>('/api-keys', body),
  revoke: (id: number) => api.delete<{ id: number; status: number }>(`/api-keys/${id}`),
  restore: (id: number) => api.post<{ id: number; status: number }>(`/api-keys/${id}/restore`),
};

export const userApi = {
  list: (params?: { page?: number; pageSize?: number; keyword?: string; role?: string; status?: number }) =>
    api.get<Paged<UserInfo>>('/users', params),
  create: (body: {
    username: string;
    password: string;
    displayName?: string | null;
    email?: string | null;
    role: string;
    status?: number;
  }) => api.post<UserInfo>('/users', body),
  update: (id: number, body: Partial<UserInfo> & { password?: string }) =>
    api.patch<UserInfo>(`/users/${id}`, body),
  options: () =>
    api.get<{ list: Array<{ id: number; username: string; displayName: string | null; role: string }> }>(
      '/users/options',
    ),
};

export const assigneeApi = {
  list: () =>
    api.get<{ list: Array<{ id: number; username: string; displayName: string | null; role: string }> }>(
      '/assignees',
    ),
};

export const mlApi = {
  status: () => api.get<MlServiceStatus>('/ml/status'),
  info: () => api.get<Record<string, unknown>>('/ml/info'),
  detect: (body: {
    code: string;
    mode?: 'auto' | 'detection' | 'classification';
    threshold?: number;
    filePath?: string;
    language?: string;
  }) => api.post<MlDetectResult>('/ml/detect', body),
  analyze: (body: {
    code: string;
    mode?: 'auto' | 'detection' | 'classification';
    threshold?: number;
    filePath?: string;
    language?: string;
    projectId?: number;
    title?: string;
  }) => api.post<MlAnalyzeResponse>('/ml/analyze', body),
};

export type { Severity };
