import { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Form,
  Input,
  Modal,
  Popconfirm,
  Row,
  Select,
  Space,
  Table,
  Tabs,
  Tag,
  Typography,
  App as AntdApp,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import {
  CopyOutlined,
  DeleteOutlined,
  KeyOutlined,
  PlusOutlined,
  ReloadOutlined,
  SafetyOutlined,
  UndoOutlined,
  UserOutlined,
} from '@ant-design/icons';
import {
  ROLES,
  ROLE_META,
  type ApiKeyCreated,
  type ApiKeyItem,
  type Role,
  type UserInfo,
} from '@vuln/shared';
import { apiKeyApi, userApi } from '@/api';
import { PageHeader, formatTime } from '@/components/common';
import { useAuthStore } from '@/store/auth';

// -------------------------------------------------------------- 用户管理
function UserPanel() {
  const { message } = AntdApp.useApp();
  const currentUser = useAuthStore((s) => s.user);
  const [loading, setLoading] = useState(false);
  const [list, setList] = useState<UserInfo[]>([]);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<UserInfo | null>(null);
  const [form] = Form.useForm();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await userApi.list({ page: 1, pageSize: 100 });
      setList(data.list);
    } catch (e) {
      message.error(e instanceof Error ? e.message : '加载用户失败');
    } finally {
      setLoading(false);
    }
  }, [message]);

  useEffect(() => {
    void load();
  }, [load]);

  const submit = async () => {
    const v = await form.validateFields();
    try {
      if (editing) {
        await userApi.update(editing.id, {
          displayName: v.displayName,
          email: v.email,
          role: v.role,
          status: v.status,
          password: v.password || undefined,
        });
        message.success('用户已更新');
      } else {
        await userApi.create(v);
        message.success('用户已创建');
      }
      setOpen(false);
      form.resetFields();
      void load();
    } catch (e) {
      message.error(e instanceof Error ? e.message : '保存失败');
    }
  };

  const columns: ColumnsType<UserInfo> = [
    {
      title: '用户',
      dataIndex: 'username',
      render: (v: string, r) => (
        <Space>
          <span style={{ fontWeight: 500 }}>{r.displayName ?? v}</span>
          <span className="mono text-muted" style={{ fontSize: 12 }}>{v}</span>
          {r.id === currentUser?.id ? <Tag color="blue">当前登录</Tag> : null}
        </Space>
      ),
    },
    {
      title: '角色',
      dataIndex: 'role',
      width: 140,
      render: (v: Role) => <Tag color={v === 'admin' ? 'red' : v === 'auditor' ? 'blue' : 'default'}>{ROLE_META[v]?.label ?? v}</Tag>,
    },
    { title: '邮箱', dataIndex: 'email', width: 200, render: (v: string | null) => v ?? '-' },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: number) => (v === 1 ? <Tag color="green">启用</Tag> : <Tag>禁用</Tag>),
    },
    {
      title: '最后登录',
      dataIndex: 'lastLoginAt',
      width: 160,
      render: (v: string | null) => (v ? formatTime(v) : <span className="text-muted">从未登录</span>),
    },
    {
      title: '操作',
      width: 100,
      render: (_: unknown, r) => (
        <Button
          type="link"
          size="small"
          onClick={() => {
            setEditing(r);
            form.setFieldsValue({
              username: r.username,
              displayName: r.displayName,
              email: r.email,
              role: r.role,
              status: r.status,
            });
            setOpen(true);
          }}
        >
          编辑
        </Button>
      ),
    },
  ];

  return (
    <>
      <Card
        className="stat-card"
        styles={{ body: { padding: 0 } }}
        title="平台用户"
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} size="small" onClick={() => load()} loading={loading}>
              刷新
            </Button>
            <Button
              type="primary"
              size="small"
              icon={<PlusOutlined />}
              onClick={() => {
                setEditing(null);
                form.resetFields();
                form.setFieldsValue({ role: 'auditor', status: 1 });
                setOpen(true);
              }}
            >
              新建用户
            </Button>
          </Space>
        }
      >
        <Table
          className="vuln-table"
          rowKey="id"
          loading={loading}
          columns={columns}
          dataSource={list}
          pagination={false}
          scroll={{ x: 900 }}
        />
      </Card>

      <Card className="stat-card" style={{ marginTop: 16 }} title="角色权限矩阵">
        <Table
          size="small"
          rowKey="perm"
          pagination={false}
          dataSource={[
            { perm: '查看漏洞列表 / 详情', admin: true, auditor: true, viewer: true },
            { perm: '修改漏洞状态 / 指派', admin: true, auditor: true, viewer: false },
            { perm: '导出报表', admin: true, auditor: true, viewer: true },
            { perm: '查看样本库', admin: true, auditor: true, viewer: true },
            { perm: '维护项目信息', admin: true, auditor: true, viewer: false },
            { perm: '调用模型检测', admin: true, auditor: true, viewer: false },
            { perm: '用户管理', admin: true, auditor: false, viewer: false },
            { perm: 'API Key 管理', admin: true, auditor: false, viewer: false },
          ]}
          columns={[
            { title: '功能', dataIndex: 'perm' },
            ...ROLES.map((r) => ({
              title: ROLE_META[r].label,
              dataIndex: r,
              width: 130,
              align: 'center' as const,
              render: (v: boolean) => (v ? <Tag color="green">✅</Tag> : <Tag>❌</Tag>),
            })),
          ]}
        />
        <Typography.Paragraph type="secondary" style={{ fontSize: 12.5, marginTop: 12, marginBottom: 0 }}>
          权限点来自 <span className="code-inline">@vuln/shared</span> 的{' '}
          <span className="code-inline">ROLE_PERMISSIONS</span>，前后端共用同一份定义，避免权限漂移。
          扫描工具（机器）只持 API Key，仅能调 <span className="code-inline">/ingest/**</span>，不能查询业务数据。
        </Typography.Paragraph>
      </Card>

      <Modal
        title={editing ? `编辑用户 · ${editing.username}` : '新建用户'}
        open={open}
        onCancel={() => setOpen(false)}
        onOk={submit}
        okText="保存"
        destroyOnClose
      >
        <Form form={form} layout="vertical" style={{ marginTop: 12 }}>
          <Form.Item
            name="username"
            label="用户名"
            rules={[{ required: !editing, message: '请输入用户名' }]}
          >
            <Input disabled={!!editing} placeholder="登录名，仅字母数字与 _ . -" maxLength={64} />
          </Form.Item>
          <Form.Item
            name="password"
            label={editing ? '重置密码（留空则不修改）' : '密码'}
            rules={editing ? [] : [{ required: true, message: '请输入密码' }, { min: 8, message: '至少 8 位' }]}
            extra="需至少包含大写字母、小写字母、数字、特殊字符中的 3 类"
          >
            <Input.Password placeholder={editing ? '不修改请留空' : '至少 8 位'} autoComplete="new-password" />
          </Form.Item>
          <Row gutter={12}>
            <Col span={12}>
              <Form.Item name="displayName" label="显示名">
                <Input placeholder="如 李四" maxLength={64} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="role" label="角色" rules={[{ required: true }]}>
                <Select options={ROLES.map((r) => ({ label: ROLE_META[r].label, value: r }))} />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={12}>
            <Col span={14}>
              <Form.Item name="email" label="邮箱" rules={[{ type: 'email', message: '邮箱格式不正确' }]}>
                <Input placeholder="user@example.com" maxLength={128} />
              </Form.Item>
            </Col>
            <Col span={10}>
              <Form.Item name="status" label="状态">
                <Select
                  options={[
                    { label: '启用', value: 1 },
                    { label: '禁用', value: 0 },
                  ]}
                />
              </Form.Item>
            </Col>
          </Row>
          {editing ? (
            <Alert
              type="info"
              showIcon
              message="为避免把自己锁在门外，不能修改自己的角色，也不能禁用当前登录账号。"
            />
          ) : null}
        </Form>
      </Modal>
    </>
  );
}

// ------------------------------------------------------------ API Key 管理
function ApiKeyPanel() {
  const { message, modal } = AntdApp.useApp();
  const [loading, setLoading] = useState(false);
  const [list, setList] = useState<ApiKeyItem[]>([]);
  const [open, setOpen] = useState(false);
  const [created, setCreated] = useState<ApiKeyCreated | null>(null);
  const [form] = Form.useForm();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await apiKeyApi.list({ page: 1, pageSize: 100 });
      setList(data.list);
    } catch (e) {
      message.error(e instanceof Error ? e.message : '加载 API Key 失败');
    } finally {
      setLoading(false);
    }
  }, [message]);

  useEffect(() => {
    void load();
  }, [load]);

  const submit = async () => {
    const v = await form.validateFields();
    try {
      const r = await apiKeyApi.create({
        name: v.name,
        scopes: v.scopes ?? ['ingest'],
        repoScope: v.repoScope ? v.repoScope.split('\n').map((s: string) => s.trim()).filter(Boolean) : null,
        expiresAt: v.expiresAt || null,
      });
      setCreated(r);
      setOpen(false);
      form.resetFields();
      void load();
    } catch (e) {
      message.error(e instanceof Error ? e.message : '创建失败');
    }
  };

  const columns: ColumnsType<ApiKeyItem> = [
    { title: '用途备注', dataIndex: 'name', render: (v: string) => <span style={{ fontWeight: 500 }}>{v}</span> },
    {
      title: 'Key（掩码）',
      dataIndex: 'maskedKey',
      width: 240,
      render: (v: string) => <span className="mono" style={{ fontSize: 12.5 }}>{v}</span>,
    },
    {
      title: '权限范围',
      dataIndex: 'scopes',
      width: 130,
      render: (v: string[]) => v.map((s) => <Tag key={s}>{s}</Tag>),
    },
    {
      title: '仓库白名单',
      dataIndex: 'repoScope',
      width: 200,
      ellipsis: true,
      render: (v: string[] | null) =>
        v && v.length ? (
          <Space direction="vertical" size={0}>
            {v.map((r) => (
              <span key={r} className="mono" style={{ fontSize: 12 }}>{r}</span>
            ))}
          </Space>
        ) : (
          <Tag color="orange">不限（全部仓库）</Tag>
        ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: number) => (v === 1 ? <Tag color="green">启用</Tag> : <Tag color="red">已吊销</Tag>),
    },
    {
      title: '最近使用',
      dataIndex: 'lastUsedAt',
      width: 160,
      render: (v: string | null) => (v ? formatTime(v) : <span className="text-muted">从未使用</span>),
    },
    { title: '创建时间', dataIndex: 'createdAt', width: 160, render: (v: string) => formatTime(v) },
    {
      title: '操作',
      width: 100,
      render: (_: unknown, r) =>
        r.status === 1 ? (
          <Popconfirm
            title="吊销该 API Key？"
            description="吊销后扫描工具再次上报将立即返回 40101，且不可恢复原 Key。"
            okText="确认吊销"
            okButtonProps={{ danger: true }}
            onConfirm={async () => {
              try {
                await apiKeyApi.revoke(r.id);
                message.success('已吊销');
                void load();
              } catch (e) {
                message.error(e instanceof Error ? e.message : '吊销失败');
              }
            }}
          >
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>
              吊销
            </Button>
          </Popconfirm>
        ) : (
          <Button
            type="link"
            size="small"
            icon={<UndoOutlined />}
            onClick={async () => {
              try {
                await apiKeyApi.restore(r.id);
                message.success('已恢复启用');
                void load();
              } catch (e) {
                message.error(e instanceof Error ? e.message : '恢复失败');
              }
            }}
          >
            恢复
          </Button>
        ),
    },
  ];

  return (
    <>
      <Card
        className="stat-card"
        styles={{ body: { padding: 0 } }}
        title="扫描工具凭证（API Key）"
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} size="small" onClick={() => load()} loading={loading}>
              刷新
            </Button>
            <Button
              type="primary"
              size="small"
              icon={<PlusOutlined />}
              onClick={() => {
                form.resetFields();
                setOpen(true);
              }}
            >
              创建 API Key
            </Button>
          </Space>
        }
      >
        <Table
          className="vuln-table"
          rowKey="id"
          loading={loading}
          columns={columns}
          dataSource={list}
          pagination={false}
          scroll={{ x: 1300 }}
          locale={{ emptyText: '还没有 API Key。创建后交给扫描侧配置到 CI 的 secrets 中。' }}
        />
      </Card>

      <Card className="stat-card" style={{ marginTop: 16 }} title="扫描侧接入示例">
        <Typography.Paragraph type="secondary" style={{ fontSize: 12.5 }}>
          上报使用 <span className="code-inline">X-API-Key</span> 请求头，调用链 4 步（scanNo 为幂等键）：
        </Typography.Paragraph>
        <div className="code-block">
          <pre style={{ padding: 16, fontSize: 12.5, lineHeight: 1.7, margin: 0 }}>{`# 0) 自检 Key 是否有效
curl -H "X-API-Key: $VULN_KEY" http://127.0.0.1:3000/api/v1/ingest/ping

# 1) 创建扫描批次（幂等）
curl -X POST http://127.0.0.1:3000/api/v1/ingest/scans \\
  -H "Content-Type: application/json" -H "X-API-Key: $VULN_KEY" \\
  -d '{"scanNo":"gh-org-demo-20250101-abc1234","scan":{"repoType":"github","repoUrl":"https://github.com/org/demo","projectName":"demo","branch":"main"}}'

# 2) 上报漏洞
curl -X POST http://127.0.0.1:3000/api/v1/ingest/scans/gh-org-demo-20250101-abc1234/vulnerabilities \\
  -H "Content-Type: application/json" -H "X-API-Key: $VULN_KEY" \\
  -d '{"vulnerabilities":[{"externalVulnId":"VULN-0001","ruleId":"sql-injection-java","title":"SQL注入","severity":"high","filePath":"src/UserDao.java","lineStart":42,"codeSnippet":"String sql = \\"...\\" + name;"}]}'

# 3) 上报正负样本（正样本用 externalVulnId 关联第 2 步的漏洞）
curl -X POST http://127.0.0.1:3000/api/v1/ingest/scans/gh-org-demo-20250101-abc1234/samples \\
  -H "Content-Type: application/json" -H "X-API-Key: $VULN_KEY" \\
  -d '{"samples":[{"label":"positive","filePath":"src/UserDao.java","externalVulnId":"VULN-0001","snippet":"..."},{"label":"negative","filePath":"src/UserService.java","snippet":"..."}]}'

# 4) 结束批次
curl -X POST http://127.0.0.1:3000/api/v1/ingest/scans/gh-org-demo-20250101-abc1234/complete \\
  -H "Content-Type: application/json" -H "X-API-Key: $VULN_KEY" \\
  -d '{"status":"success","scannedFiles":1275}'`}</pre>
        </div>
      </Card>

      {/* 创建弹窗 */}
      <Modal title="创建 API Key" open={open} onCancel={() => setOpen(false)} onOk={submit} okText="创建" destroyOnClose>
        <Form form={form} layout="vertical" style={{ marginTop: 12 }} initialValues={{ scopes: ['ingest'] }}>
          <Form.Item name="name" label="用途备注" rules={[{ required: true, message: '请输入用途备注' }]}>
            <Input placeholder="如 github-actions-prod" maxLength={64} />
          </Form.Item>
          <Form.Item name="scopes" label="权限范围">
            <Select mode="multiple" options={[{ label: 'ingest（上报）', value: 'ingest' }]} />
          </Form.Item>
          <Form.Item name="repoScope" label="允许上报的仓库白名单（每行一个，留空=不限）">
            <Input.TextArea rows={3} placeholder={'https://github.com/org/repo-a\nhttps://gitlab.acme.com/team/repo-b'} />
          </Form.Item>
          <Form.Item name="expiresAt" label="过期时间（留空=永不过期）" extra="ISO 8601，如 2026-01-01T00:00:00Z">
            <Input placeholder="2026-01-01T00:00:00Z" />
          </Form.Item>
        </Form>
      </Modal>

      {/* 明文只展示一次 */}
      <Modal
        title={
          <Space>
            <KeyOutlined style={{ color: '#faad14' }} />
            请立即保存：明文只显示这一次
          </Space>
        }
        open={!!created}
        onCancel={() => setCreated(null)}
        footer={[
          <Button
            key="copy"
            type="primary"
            icon={<CopyOutlined />}
            onClick={() => {
              if (created) {
                void navigator.clipboard.writeText(created.apiKey);
                message.success('已复制到剪贴板');
              }
            }}
          >
            复制 Key
          </Button>,
          <Button key="close" onClick={() => setCreated(null)}>
            我已保存
          </Button>,
        ]}
        width={620}
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message="平台只保存 sha256 哈希，关闭本窗口后无法再次查看明文"
          description="请立刻粘贴到扫描侧 CI 的 secrets / 环境变量中；如已丢失，请吊销后重新创建。"
        />
        <Descriptions column={1} size="small" bordered>
          <Descriptions.Item label="用途备注">{created?.name}</Descriptions.Item>
          <Descriptions.Item label="明文 Key">
            <Typography.Text className="mono" copyable style={{ wordBreak: 'break-all' }}>
              {created?.apiKey}
            </Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label="掩码">{created?.maskedKey}</Descriptions.Item>
          <Descriptions.Item label="权限">{created?.scopes.join(', ')}</Descriptions.Item>
          <Descriptions.Item label="仓库白名单">
            {created?.repoScope?.length ? created.repoScope.join(', ') : '不限'}
          </Descriptions.Item>
        </Descriptions>
      </Modal>
    </>
  );
}

// ------------------------------------------------------------------ 页面
export default function SettingsPage() {
  const user = useAuthStore((s) => s.user);
  const isAdmin = user?.role === 'admin';

  const systemPanel = (
    <Space direction="vertical" style={{ width: '100%' }} size={16}>
      <Card className="stat-card" title="技术栈与结构">
        <Descriptions column={{ xs: 1, md: 2 }} size="small" bordered>
          <Descriptions.Item label="前端">React 18 + Vite 5 + Ant Design 5 + @ant-design/plots</Descriptions.Item>
          <Descriptions.Item label="后端">Node.js 20+ / Express 4 + TypeScript + zod</Descriptions.Item>
          <Descriptions.Item label="数据库">SQLite（内置 node:sqlite，零原生依赖）</Descriptions.Item>
          <Descriptions.Item label="企业库">MySQL 8.0（适配层已预留，见 server/src/db）</Descriptions.Item>
          <Descriptions.Item label="鉴权">前端 JWT（8h） / 扫描工具 X-API-Key</Descriptions.Item>
          <Descriptions.Item label="模型">ScanMan CodeBERT（检测 + CWE 分类），独立 Python 推理服务</Descriptions.Item>
          <Descriptions.Item label="单仓结构" span={2}>
            <span className="mono" style={{ fontSize: 12 }}>
              apps/server · apps/web · packages/shared · model-service · docs
            </span>
          </Descriptions.Item>
        </Descriptions>
      </Card>

      <Card className="stat-card" title="契约与文档">
        <Space direction="vertical" size={6} style={{ fontSize: 13 }}>
          <div>
            · 接口契约：<span className="code-inline">docs/02-API接口文档.md</span> +{' '}
            <span className="code-inline">docs/openapi.yaml</span>
          </div>
          <div>
            · 需求与设计：<span className="code-inline">docs/01-需求与开发文档.md</span>
          </div>
          <div>
            · 统一响应：<span className="code-inline">{'{ code, message, data, traceId }'}</span>，code = 0 为成功
          </div>
          <div>
            · 幂等键：批次 <span className="code-inline">scanNo</span>；漏洞{' '}
            <span className="code-inline">fingerprint</span>；样本{' '}
            <span className="code-inline">(scanId, filePath, snippetHash)</span>
          </div>
          <div>
            · 兼容策略：只增字段，不删不改语义
          </div>
        </Space>
      </Card>

      <Card className="stat-card" title="安全提示">
        <Space direction="vertical" size={8} style={{ width: '100%' }}>
          <Alert
            type="warning"
            showIcon
            message="部署前必须处理"
            description={
              <ul style={{ margin: 0, paddingLeft: 20, fontSize: 12.5, lineHeight: 1.9 }}>
                <li>
                  修改 <span className="code-inline">JWT_SECRET</span>（默认值仅用于本地开发，生产环境启动会直接报错）
                </li>
                <li>修改默认管理员密码（admin / Admin@12345）</li>
                <li>
                  演示用 API Key <span className="code-inline">vuln_sk_demo...</span> 已写入演示库，生产请吊销并重建
                </li>
                <li>密码使用 bcrypt 存储；API Key 只存 sha256，明文不可找回</li>
              </ul>
            }
          />
        </Space>
      </Card>
    </Space>
  );

  if (!isAdmin) {
    return (
      <>
        <PageHeader
          title="系统设置"
          subtitle="当前角色非管理员，仅可查看系统信息；用户管理与 API Key 管理需要 admin 角色"
        />
        {systemPanel}
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="系统设置"
        subtitle={
          <Space size={8}>
            <SafetyOutlined />
            <span>用户管理、API Key 管理与系统信息（仅 admin 可见）</span>
          </Space>
        }
      />
      <Tabs
        items={[
          {
            key: 'users',
            label: (
              <span>
                <UserOutlined /> 用户管理
              </span>
            ),
            children: <UserPanel />,
          },
          {
            key: 'apikeys',
            label: (
              <span>
                <KeyOutlined /> API Key 管理
              </span>
            ),
            children: <ApiKeyPanel />,
          },
          {
            key: 'system',
            label: (
              <span>
                <SafetyOutlined /> 系统信息
              </span>
            ),
            children: systemPanel,
          },
        ]}
      />
    </>
  );
}
