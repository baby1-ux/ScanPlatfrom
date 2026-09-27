import { create } from 'zustand';
import { api, clearToken, getToken, setToken } from '@/api/client';
import type { LoginResult, Permission, Role, UserInfo } from '@vuln/shared';

interface AuthState {
  user: UserInfo | null;
  loading: boolean;
  /** 已尝试过恢复会话（用于避免路由守卫闪烁） */
  initialized: boolean;
  login: (username: string, password: string) => Promise<UserInfo>;
  logout: () => Promise<void>;
  fetchMe: () => Promise<void>;
  hasPermission: (...perms: Permission[]) => boolean;
  hasRole: (...roles: Role[]) => boolean;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  loading: false,
  initialized: false,

  async login(username, password) {
    set({ loading: true });
    try {
      const data = await api.post<LoginResult>('/auth/login', { username, password });
      setToken(data.accessToken);
      set({ user: data.user, initialized: true });
      return data.user;
    } finally {
      set({ loading: false });
    }
  },

  async logout() {
    try {
      if (getToken()) await api.post('/auth/logout');
    } catch {
      /* 登出失败不阻塞前端清理 */
    }
    clearToken();
    set({ user: null });
  },

  async fetchMe() {
    if (!getToken()) {
      set({ user: null, initialized: true });
      return;
    }
    try {
      const me = await api.get<UserInfo>('/auth/me');
      set({ user: me, initialized: true });
    } catch {
      clearToken();
      set({ user: null, initialized: true });
    }
  },

  hasPermission(...perms) {
    const list = get().user?.permissions ?? [];
    return perms.every((p) => list.includes(p));
  },

  hasRole(...roles) {
    const role = get().user?.role;
    return role ? roles.includes(role) : false;
  },
}));
