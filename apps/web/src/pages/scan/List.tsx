import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Button,
  Card,
  Col,
  Empty,
  Input,
  Progress,
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
import { ReloadOutlined, SearchOutlined } from '@ant-design/icons';
import {
  SCAN_STATUSES,
  SCAN_STATUS_META,
  TRIGGER_TYPES,
  TRIGGER_TYPE_META,
  type ScanStatus,
  type ScanTask,
  type TriggerType,
} from '@vuln/shared';
import { projectApi, scanApi } from '@/api';
import { PageHeader, ScanStatusTag, formatDuration, formatNumber, formatTime } from '@/components/common';

interface ScanListResult extends ScanTask {
  summary?: Record<string, number>;
}

export default function ScanListPage() {
  const { message } = AntdApp.useApp();
  const [loading, setLoading] = useState(false);
  const [list, setList] = useState<ScanTask[]>([]);
  const [summary, setSummary] = useState<Record<string, number> | null>(null);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [keyword, setKeyword] = useState('');
  const [status, setStatus] = useState<ScanStatus[]>([]);
  const [projectIds, setProjectIds] = useState<number[]>([]);
  const [projects, setProjects] = useState<Array<{ id: number; name: string }>>([]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await scanApi.list({
        page,
        pageSize,
        keyword: keyword || undefined,
        status: status.length ? status : undefined,
        projectId: projectIds.length ? projectIds : undefined,
      });
      setList(data.list);
      setTotal(data.pagination.total);
      setSummary((data as unknown as { summary: Record<string, number> }).summary ?? null);
    } catch (e) {
      message.error(e instanceof Error ? e.message : '加载失败');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, keyword, status, projectIds, message]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    projectApi.options().then((r) => setProjects(r.list)).catch(() => undefined);
  }, []);

  const columns: ColumnsType<ScanTask> = [
    {
      title: '批次号',
      dataIndex: 'scanNo',
      width: 260,
      render: (v: string) => (
        <Link to={`/scans/${encodeURIComponent(v)}`} className="mono">
          {v}
        </Link>
      ),
    },
    {
      title: '项目',
      width: 140,
      ellipsis: true,
      render: (_: unknown, r) =>
        r.project ? <Link to={`/projects/${r.project.id}`}>{r.project.name}</Link> : '-',
    },
    {
      title: '触发 / 分支',
      width: 150,
      render: (_: unknown, r) => (
        <Space size={4} wrap>
          <Tag>{TRIGGER_TYPE_META[r.triggerType as TriggerType]?.label ?? r.triggerType}</Tag>
          {r.branch ? <span className="mono" style={{ fontSize: 12.5 }}>{r.branch}</span> : null}
        </Space>
      ),
    },
    {
      title: '提交',
      ellipsis: true,
      render: (_: unknown, r) => (
        <div style={{ lineHeight: 1.5 }}>
          <div>
            <Tooltip title={r.commitMessage}>
              <span>{r.commitMessage ?? '-'}</span>
            </Tooltip>
          </div>
          <div className="text-muted" style={{ fontSize: 12 }}>
            {r.commitId ? <span className="mono">{r.commitId.slice(0, 8)}</span> : null}
            {r.commitAuthor ? ` · ${r.commitAuthor}` : ''}
            {r.commitTime ? ` · ${formatTime(r.commitTime)}` : ''}
          </div>
        </div>
      ),
    },
    {
      title: '文件覆盖',
      width: 150,
      render: (_: unknown, r) => {
        const pct = r.totalFiles > 0 ? Math.round((r.scannedFiles / r.totalFiles) * 100) : 0;
        return (
          <Tooltip title={`${r.scannedFiles} / ${r.totalFiles}`}>
            <Progress
              percent={pct}
              size="small"
              status={r.status === 'failed' ? 'exception' : pct === 100 ? 'success' : 'active'}
            />
          </Tooltip>
        );
      },
    },
    {
      title: '漏洞',
      dataIndex: 'vulnCount',
      width: 80,
      align: 'right',
      sorter: true,
      render: (v: number) => <b className="stat-value">{v}</b>,
    },
    {
      title: '样本（正/负）',
      width: 130,
      align: 'right',
      render: (_: unknown, r) => (
        <span className="stat-value" style={{ fontSize: 12.5 }}>
          <span style={{ color: '#cf1322' }}>{r.positiveCount}</span> /{' '}
          <span style={{ color: '#52c41a' }}>{formatNumber(r.negativeCount)}</span>
        </span>
      ),
    },
    {
      title: '耗时',
      dataIndex: 'durationMs',
      width: 90,
      align: 'right',
      sorter: true,
      render: (v: number | null) => formatDuration(v),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: ScanStatus) => <ScanStatusTag status={v} />,
    },
    {
      title: '开始时间',
      dataIndex: 'startedAt',
      width: 150,
      sorter: true,
      render: (v: string | null, r) => formatTime(v ?? r.createdAt),
    },
  ];

  return (
    <>
      <PageHeader
        title="扫描记录"
        subtitle="扫描工具每完成一次扫描会上报一个批次（scanNo 为幂等键，重复上报不会产生新记录）"
        extra={
          <Space wrap>
            <Input
              allowClear
              placeholder="批次号 / 提交信息 / 提交人 / 项目"
              prefix={<SearchOutlined />}
              style={{ width: 260 }}
              value={keyword}
              onChange={(e) => setKeyword(e.target.value)}
              onPressEnter={() => {
                setPage(1);
                void load();
              }}
            />
            <Select
              mode="multiple"
              allowClear
              placeholder="状态"
              style={{ width: 180 }}
              value={status}
              onChange={(v) => {
                setStatus(v);
                setPage(1);
              }}
              options={SCAN_STATUSES.map((s) => ({ label: SCAN_STATUS_META[s].label, value: s }))}
            />
            <Select
              mode="multiple"
              allowClear
              placeholder="项目"
              style={{ minWidth: 180 }}
              maxTagCount="responsive"
              value={projectIds}
              onChange={(v) => {
                setProjectIds(v);
                setPage(1);
              }}
              options={projects.map((p) => ({ label: p.name, value: p.id }))}
            />
            <Button icon={<ReloadOutlined />} onClick={() => load()} loading={loading}>
              刷新
            </Button>
          </Space>
        }
      />

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic title="批次总数（当前筛选）" value={summary?.total ?? total} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic title="成功" value={summary?.success ?? 0} valueStyle={{ color: '#52c41a' }} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic title="失败" value={summary?.failed ?? 0} valueStyle={{ color: '#cf1322' }} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic title="扫描中" value={summary?.running ?? 0} valueStyle={{ color: '#1677ff' }} />
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
          scroll={{ x: 1600 }}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: true,
            showTotal: (t) => `共 ${formatNumber(t)} 个批次`,
            onChange: (p, ps) => {
              setPage(p);
              setPageSize(ps);
            },
          }}
          locale={{
            emptyText: (
              <div style={{ padding: '40px 0' }}>
                <Empty description="还没有扫描记录。可在「模型检测」页跑一次检测，或等 ScanMan 在 CI 中上报。" />
                <Typography.Text type="secondary" style={{ fontSize: 12.5 }}>
                  上报入口：<span className="code-inline">POST /api/v1/ingest/scans</span>（需 X-API-Key）
                </Typography.Text>
              </div>
            ),
          }}
        />
      </Card>
    </>
  );
}

export type { ScanListResult };
