import { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Alert, Button, Card, Checkbox, Form, Input, Space, Typography, App as AntdApp } from 'antd';
import { LockOutlined, SafetyCertificateOutlined, UserOutlined } from '@ant-design/icons';
import { useAuthStore } from '@/store/auth';

const REMEMBER_KEY = 'vuln_platform_remember';

export default function LoginPage() {
  const [form] = Form.useForm();
  const { login, loading, user } = useAuthStore();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { message } = AntdApp.useApp();

  const next = params.get('next') || '/dashboard';

  useEffect(() => {
    if (user) navigate(next, { replace: true });
  }, [user, navigate, next]);

  useEffect(() => {
    const saved = localStorage.getItem(REMEMBER_KEY);
    if (saved) {
      try {
        form.setFieldsValue(JSON.parse(saved));
      } catch {
        localStorage.removeItem(REMEMBER_KEY);
      }
    }
  }, [form]);

  const onFinish = async (values: { username: string; password: string; remember?: boolean }) => {
    try {
      const u = await login(values.username, values.password);
      if (values.remember) {
        localStorage.setItem(
          REMEMBER_KEY,
          JSON.stringify({ username: values.username, password: values.password, remember: true }),
        );
      } else {
        localStorage.removeItem(REMEMBER_KEY);
      }
      message.success(`欢迎回来，${u.displayName ?? u.username}`);
      navigate(next, { replace: true });
    } catch (e) {
      // 错误提示由拦截器/此处统一给出，不暴露账号是否存在
      message.error(e instanceof Error ? e.message : '登录失败，请检查账号密码');
    }
  };

  return (
    <div className="login-bg">
      <Card className="login-card" styles={{ body: { padding: '32px 32px 24px' } }}>
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <div className="login-logo">{`  ___  ___ __ _ _ __  __  __ __ _ _ __
 / __|/ __/ _\` | '_ \\|  \\/  |/ _\` | '_ \\
 \\__ \\ (_| (_| | | | | |\\/| | (_| | | | |
 |___/\\___\\__,_|_| |_|_|  |_|\\__,_|_| |_|`}</div>
          <Typography.Title level={4} style={{ margin: '8px 0 4px' }}>
            漏洞管理平台
          </Typography.Title>
          <Typography.Text type="secondary" style={{ fontSize: 13 }}>
            接收 ScanMan 上报的漏洞与正负样本 · 集中查看与处置
          </Typography.Text>
        </div>

        <Form form={form} layout="vertical" onFinish={onFinish} size="large" initialValues={{ remember: true }}>
          <Form.Item name="username" rules={[{ required: true, message: '请输入用户名' }]}>
            <Input prefix={<UserOutlined />} placeholder="用户名" autoComplete="username" autoFocus />
          </Form.Item>
          <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }]}>
            <Input.Password
              prefix={<LockOutlined />}
              placeholder="密码"
              autoComplete="current-password"
              onPressEnter={() => form.submit()}
            />
          </Form.Item>
          <Form.Item style={{ marginBottom: 12 }}>
            <Space style={{ width: '100%', justifyContent: 'space-between' }}>
              <Form.Item name="remember" valuePropName="checked" noStyle>
                <Checkbox>记住我</Checkbox>
              </Form.Item>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                <SafetyCertificateOutlined /> JWT 有效期 8 小时
              </Typography.Text>
            </Space>
          </Form.Item>
          <Form.Item style={{ marginBottom: 8 }}>
            <Button type="primary" htmlType="submit" block loading={loading} size="large">
              登 录
            </Button>
          </Form.Item>
        </Form>

        <Alert
          type="info"
          showIcon
          style={{ marginTop: 8 }}
          message="演示账号"
          description={
            <div style={{ fontSize: 12.5, lineHeight: 1.8 }}>
              <div>
                管理员 <span className="code-inline">admin / Admin@12345</span>
              </div>
              <div>
                审计员 <span className="code-inline">auditor / Admin@12345</span> · 只读{' '}
                <span className="code-inline">viewer / Admin@12345</span>
              </div>
              <div className="text-muted">首次部署后请立刻修改默认密码</div>
            </div>
          }
        />
      </Card>
    </div>
  );
}
