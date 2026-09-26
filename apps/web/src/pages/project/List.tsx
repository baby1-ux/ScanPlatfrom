import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Button,
  Card,
  Col,
  Empty,
  Form,
  Input,
  Modal,
  Row,
  Select,
  Space,
  Statistic,
  Table,
  Tag,
  Tooltip,
  Typography,
  App as AntdApp,
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { PlusOutlined, ReloadOutlined, SearchOutlined } from '@ant-design/icons';
import { REPO_TYPES, REPO_TYPE_META, type Project, type RepoType } from '@vuln/shared';
import { projectApi } from '@/api';
import { PageHeader, RepoTypeTag, formatNumber, formatTime } from '@/components/common';
import { useAuthStore } from '@/store/auth';

export default function ProjectListPage() {
  const { message } = AntdApp.useApp();
  const canWrite = useAuthStore((s) => s.hasPermission('project:write'));
  const [loading, setLoading] = useState(false);
  const [list, setList] = useState<Project[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [keyword, setKeyword] = useState('');
  const [repoType, setRepoType] = useState<RepoType | undefined>();
  const [createOpen, setCreateOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<Project | null>(null);
  const [form] = Form.useForm();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await projectApi.list({ page, pageSize, keyword: keyword || undefined, repoType });
      setList(data.list);
      setTotal(data.pagination.total);
    } catch (e) {
      message.error(e instanceof Error ? e.message : '加载失败');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, keyword, repoType, message]);

  useEffect(() => {
    void load();
  }, [load]);

  const openCreate = () => {
    setEditTarget(null);
    form.resetFields();
    setCreateOpen(true);
  };

  const openEdit = (p: Project) => {
    setEditTarget(p);
    form.setFieldsValue({
      name: p.name,
      repoType: p.repoType,
      repoUrl: p.repoUrl,
      repoFullName: p.repoFullName,
      defaultBranch: p.defaultBranch,
      owner: p.owner,
      description: p.description,
      status: p.status,
    });
    setCreateOpen(true);
  };

  const submit = async () => {
    const v = await form.validateFields();
    try {
      if (editTarget) {
        await projectApi.update(editTarget.id, v);
        message.success('项目已更新');
      } else {
        await projectApi.create(v);
        message.success('项目已创建');
      }
      setCreateOpen(false);
      form.resetFields();
      void load();
    } catch (e) {
      message.error(e instanceof Error ? e.message : '保存失败');
    }
  };

  const columns: ColumnsType<Project> = [
    {
      title: '项目 / 仓库',
      dataIndex: 'name',
      width: 280,
      render: (v: string, r) => (
        <div style={{ lineHeight: 1.6 }}>
          <Link to={`/projects/${r.id}`} style={{ fontWeight: 500 }}>
            {v}
          </Link>
          <div>
            <RepoTypeTag repoType={r.repoType} />
            <Typography.Text className="mono" type="secondary" style={{ fontSize: 12 }} copyable={{ text: r.repoUrl }}>
              {r.repoFullName ?? r.repoUrl}
            </Typography.Text>
          </div>
        </div>
      ),
    },
    {
      title: '负责人',
      dataIndex: 'owner',
      width: 100,
      render: (v: string | null) => v ?? <span className="text-muted">未指定</span>,
    },
    {
      title: '扫描次数',
      width: 96,
      align: 'right',
      render: (_: unknown, r) => <span className="stat-value">{r.stats?.scanCount ?? 0}</span>,
    },
    {
      title: '漏洞总数',
      width: 96,
      align: 'right',
      render: (_: unknown, r) => <b className="stat-value">{r.stats?.vulnTotal ?? 0}</b>,
    },
    {
      title: '未处理',
      width: 90,
      align: 'right',
      render: (_: unknown, r) => (
        <span className="stat-value" style={{ color: (r.stats?.vulnOpen ?? 0) > 0 ? '#fa541c' : undefined }}>
          {r.stats?.vulnOpen ?? 0}
        </span>
      ),
    },
    {
      title: '严重 / 高危',
      width: 110,
      align: 'right',
      render: (_: unknown, r) => (
        <span className="stat-value">
          <span style={{ color: '#cf1322', fontWeight: 600 }}>{r.stats?.vulnCritical ?? 0}</span> /{' '}
          <span style={{ color: '#fa541c', fontWeight: 600 }}>{r.stats?.vulnHigh ?? 0}</span>
        </span>
      ),
    },
    {
      title: '最近扫描',
      dataIndex: 'lastScanAt',
      width: 150,
      render: (v: string | null | undefined) => (v ? formatTime(v) : <span className="text-muted">从未扫描</span>),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 80,
      render: (v: number) => (v === 1 ? <Tag color="green">启用</Tag> : <Tag>停用</Tag>),
    },
    {
      title: '操作',
      width: 130,
      fixed: 'right',
      render: (_: unknown, r) => (
        <Space size={4}>
          <Link to={`/projects/${r.id}`}>
            <Button type="link" size="small">
              详情
            </Button>
          </Link>
          <Link to={`/vulnerabilities?projectId=${r.id}`}>
            <Button type="link" size="small">
              漏洞
            </Button>
          </Link>
          {canWrite ? (
            <Button type="link" size="small" onClick={() => openEdit(r)}>
              编辑
            </Button>
          ) : null}
        </Space>
      ),
    },
  ];

  const totalVuln = list.reduce((a, b) => a + (b.stats?.vulnTotal ?? 0), 0);
  const totalOpen = list.reduce((a, b) => a + (b.stats?.vulnOpen ?? 0), 0);

  return (
    <>
      <PageHeader
        title="项目管理"
        subtitle="扫描工具上报时会按 (repoType, repoUrl) 自动创建项目；此页用于预先注册或补充负责人等信息"
        extra={
          <Space wrap>
            <Input
              allowClear
              placeholder="项目名 / 仓库地址 / 负责人"
              prefix={<SearchOutlined />}
              style={{ width: 240 }}
              value={keyword}
              onChange={(e) => setKeyword(e.target.value)}
              onPressEnter={() => {
                setPage(1);
                void load();
              }}
            />
            <Select
              allowClear
              placeholder="仓库类型"
              style={{ width: 140 }}
              value={repoType}
              onChange={(v) => {
                setRepoType(v);
                setPage(1);
              }}
              options={REPO_TYPES.map((t) => ({ label: REPO_TYPE_META[t].label, value: t }))}
            />
            <Button icon={<ReloadOutlined />} onClick={() => load()} loading={loading}>
              刷新
            </Button>
            {canWrite ? (
              <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
                新建项目
              </Button>
            ) : null}
          </Space>
        }
      />

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic title="项目数（当前页）" value={list.length} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic title="漏洞总数（当前页）" value={totalVuln} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic title="未处理（当前页）" value={totalOpen} valueStyle={{ color: '#fa541c' }} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic title="项目总数" value={total} />
          </Card>
        </Col>
      </Row>

      <Card className="stat-card" styles={{ body: { padding: 0 } }}>
        <Table
          className="vuln-table"
          rowKey="id"
          loading={loading}
          columns={columns}
          dataSource={list}
          scroll={{ x: 1200 }}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: true,
            showTotal: (t) => `共 ${formatNumber(t)} 个项目`,
            onChange: (p, ps) => {
              setPage(p);
              setPageSize(ps);
            },
          }}
          locale={{
            emptyText: <Empty description="还没有项目。等扫描工具第一次上报，或在此手动新建" />,
          }}
        />
      </Card>

      <Modal
        title={editTarget ? `编辑项目 · ${editTarget.name}` : '新建项目'}
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={submit}
        okText="保存"
        destroyOnClose
        width={560}
      >
        <Form form={form} layout="vertical" initialValues={{ repoType: 'github', status: 1 }} style={{ marginTop: 12 }}>
          <Form.Item name="name" label="项目名" rules={[{ required: true, message: '请输入项目名' }]}>
            <Input placeholder="如 order-service" maxLength={128} />
          </Form.Item>
          <Row gutter={12}>
            <Col span={10}>
              <Form.Item name="repoType" label="仓库类型" rules={[{ required: true }]}>
                <Select options={REPO_TYPES.map((t) => ({ label: REPO_TYPE_META[t].label, value: t }))} />
              </Form.Item>
            </Col>
            <Col span={14}>
              <Form.Item
                name="repoUrl"
                label="仓库地址"
                rules={[{ required: true, message: '请输入仓库地址' }]}
                extra="平台以仓库地址唯一标识项目"
              >
                <Input placeholder="https://github.com/org/repo" maxLength={512} />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={12}>
            <Col span={12}>
              <Form.Item name="repoFullName" label="org/repo">
                <Input placeholder="org/repo" maxLength={255} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="defaultBranch" label="默认分支">
                <Input placeholder="main" maxLength={128} />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={12}>
            <Col span={12}>
              <Form.Item name="owner" label="负责人">
                <Input placeholder="如 张三" maxLength={64} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="status" label="状态">
                <Select
                  options={[
                    { label: '启用', value: 1 },
                    { label: '停用', value: 0 },
                  ]}
                />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item name="description" label="描述">
            <Input.TextArea rows={2} maxLength={512} showCount />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}
