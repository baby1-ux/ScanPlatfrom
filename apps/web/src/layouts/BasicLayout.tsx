import { useEffect, useMemo, useState } from 'react';
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { Avatar, Dropdown, Form, Input, Layout, Menu, Modal, Tag, Tooltip, Typography, App as AntdApp } from 'antd';
import {
  ApiOutlined,
  AppstoreOutlined,
  BugOutlined,
  DashboardOutlined,
  ExperimentOutlined,
  KeyOutlined,
  LogoutOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  ProjectOutlined,
  SettingOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { ROLE_META } from '@vuln/shared';
import { useAuthStore } from '@/store/auth';
import { authApi, mlApi } from '@/api';

const { Header, Sider, Content } = Layout;

const MENU_ITEMS = [
  { key: '/dashboard', icon: <DashboardOutlined />, label: <Link to="/dashboard">数据看板</Link> },
  { key: '/vulnerabilities', icon: <BugOutlined />, label: <Link to="/vulnerabilities">漏洞管理</Link> },
  { key: '/projects', icon: <ProjectOutlined />, label: <Link to="/projects">项目管理</Link> },
  { key: '/scans', icon: <AppstoreOutlined />, label: <Link to="/scans">扫描记录</Link> },
  { key: '/samples', icon: <ExperimentOutlined />, label: <Link to="/samples">样本库</Link> },
  { key: '/model', icon: <ApiOutlined />, label: <Link to="/model">模型检测</Link> },
  { key: '/settings', icon: <SettingOutlined />, label: <Link to="/settings">系统设置</Link> },
];

export default function BasicLayout() {
  const [collapsed, setCollapsed] = useState(false);
  const [pwdOpen, setPwdOpen] = useState(false);
  const [pwdForm] = Form.useForm();
  const [mlStatus, setMlStatus] = useState<{ online: boolean; detail: string | null } | null>(null);
  const { user, logout } = useAuthStore();
  const location = useLocation();
  const navigate = useNavigate();
  const { message, modal } = AntdApp.useApp();

  /** 菜单选中项：取路径首段，保证详情页也高亮父菜单 */
  const selectedKey = useMemo(() => {
    const seg = `/${location.pathname.split('/')[1] ?? ''}`;
    return MENU_ITEMS.some((m) => m.key === seg) ? seg : '/dashboard';
  }, [location.pathname]);

  /** 顶部探测一次模型服务状态，让使用者知道看板上的模型数据是否来自真实模型 */
  useEffect(() => {
    let alive = true;
    mlApi
      .status()
      .then((s) => {
        if (alive) setMlStatus({ online: s.online, detail: s.detail ?? null });
      })
      .catch(() => {
        if (alive) setMlStatus({ online: false, detail: '平台后端未响应' });
      });
    return () => {
      alive = false;
    };
  }, []);

  const onChangePassword = async () => {
    const values = await pwdForm.validateFields();
    try {
      await authApi.changePassword(values.oldPassword, values.newPassword);
      message.success('密码已修改，请重新登录');
      setPwdOpen(false);
      pwdForm.resetFields();
      await logout();
      navigate('/login');
    } catch (e) {
      message.error(e instanceof Error ? e.message : '修改失败');
    }
  };

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider
        collapsible
        collapsed={collapsed}
        onCollapse={setCollapsed}
        trigger={null}
        width={216}
        collapsedWidth={64}
        breakpoint="lg"
        style={{ position: 'sticky', top: 0, height: '100vh', overflow: 'auto' }}
      >
        <div className="sider-logo">
          <span className="dot" />
          {!collapsed && <span>漏洞管理平台</span>}
        </div>
        <Menu theme="dark" mode="inline" selectedKeys={[selectedKey]} items={MENU_ITEMS} />
      </Sider>

      <Layout>
        <Header
          style={{
            padding: '0 20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            borderBottom: '1px solid #f0f0f0',
            position: 'sticky',
            top: 0,
            zIndex: 10,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <span
              role="button"
              tabIndex={0}
              onClick={() => setCollapsed((c) => !c)}
              onKeyDown={(e) => e.key === 'Enter' && setCollapsed((c) => !c)}
              style={{ cursor: 'pointer', fontSize: 16 }}
            >
              {collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
            </span>
            <Typography.Text type="secondary" style={{ fontSize: 13 }}>
              ScanMan 扫描工具上报 · 漏洞与正负样本集中管理
            </Typography.Text>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            {mlStatus && (
              <Tooltip title={mlStatus.detail ?? (mlStatus.online ? 'ScanMan 模型服务在线' : '模型服务离线，检测将降级为启发式判定')}>
                <Tag color={mlStatus.online ? 'green' : 'orange'} style={{ marginInlineEnd: 0 }}>
                  模型服务 {mlStatus.online ? '在线' : '离线'}
                </Tag>
              </Tooltip>
            )}
            <Dropdown
              menu={{
                items: [
                  {
                    key: 'role',
                    label: `角色：${ROLE_META[user?.role ?? 'viewer']?.label ?? '-'}`,
                    disabled: true,
                  },
                  { type: 'divider' },
                  { key: 'password', icon: <KeyOutlined />, label: '修改密码' },
                  { key: 'logout', icon: <LogoutOutlined />, label: '退出登录', danger: true },
                ],
                onClick: async ({ key }) => {
                  if (key === 'password') setPwdOpen(true);
                  if (key === 'logout') {
                    modal.confirm({
                      title: '确认退出登录？',
                      onOk: async () => {
                        await logout();
                        navigate('/login');
                      },
                    });
                  }
                },
              }}
            >
              <span style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Avatar size={30} style={{ background: '#1677ff' }} icon={<UserOutlined />} />
                <span style={{ fontSize: 13 }}>{user?.displayName ?? user?.username}</span>
              </span>
            </Dropdown>
          </div>
        </Header>

        <Content style={{ padding: 24, minHeight: 'calc(100vh - 56px)' }}>
          <Outlet />
        </Content>
      </Layout>

      <Modal
        title="修改密码"
        open={pwdOpen}
        onCancel={() => setPwdOpen(false)}
        onOk={onChangePassword}
        okText="确认修改"
        destroyOnClose
      >
        <Form form={pwdForm} layout="vertical" style={{ marginTop: 12 }}>
          <Form.Item name="oldPassword" label="旧密码" rules={[{ required: true, message: '请输入旧密码' }]}>
            <Input.Password placeholder="当前密码" autoComplete="current-password" />
          </Form.Item>
          <Form.Item
            name="newPassword"
            label="新密码"
            rules={[
              { required: true, message: '请输入新密码' },
              { min: 8, message: '至少 8 位' },
            ]}
            extra="需至少包含大写字母、小写字母、数字、特殊字符中的 3 类"
          >
            <Input.Password placeholder="新密码" autoComplete="new-password" />
          </Form.Item>
        </Form>
      </Modal>
    </Layout>
  );
}
