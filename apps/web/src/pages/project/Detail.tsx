import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Empty,
  Row,
  Skeleton,
  Space,
  Statistic,
  Table,
  Tag,
  Typography,
  App as AntdApp,
} from 'antd';
import { ArrowLeftOutlined, BugOutlined } from '@ant-design/icons';
import { Pie } from '@ant-design/plots';
import { SEVERITIES, SEVERITY_META, type ProjectDetail, type Severity } from '@vuln/shared';
import { projectApi } from '@/api';
import {
  PageHeader,
  RepoTypeTag,
  ScanStatusTag,
  SeverityTag,
  formatNumber,
  formatTime,
} from '@/components/common';

export default function ProjectDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { message } = AntdApp.useApp();
  const [data, setData] = useState<ProjectDetail | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    try {
      setData(await projectApi.detail(id));
    } catch (e) {
      message.error(e instanceof Error ? e.message : '加载失败');
    } finally {
      setLoading(false);
    }
  }, [id, message]);

  useEffect(() => {
    void load();
  }, [load]);

  const pieConfig = useMemo(() => {
    const dist = data?.severityDistribution ?? [];
    const items = SEVERITIES.map((s) => ({
      type: SEVERITY_META[s].label,
      value: dist.find((d) => d.severity === s)?.count ?? 0,
      severity: s,
    })).filter((d) => d.value > 0);
    return {
      data: items,
      angleField: 'value',
      colorField: 'type',
      radius: 0.9,
      innerRadius: 0.6,
      label: { text: 'value' },
      legend: { color: { position: 'bottom' } },
      scale: {
        color: {
          domain: items.map((i) => i.type),
          range: items.map((i) => SEVERITY_META[i.severity as Severity].color),
        },
      },
      tooltip: { title: 'type' },
      style: { stroke: '#fff', lineWidth: 2 },
    };
  }, [data]);

  if (loading && !data) {
    return (
      <>
        <PageHeader title="项目详情" subtitle="加载中…" />
        <Card>
          <Skeleton active paragraph={{ rows: 8 }} />
        </Card>
      </>
    );
  }

  if (!data) {
    return (
      <Card>
        <Empty description="项目不存在">
          <Button type="primary" onClick={() => navigate('/projects')}>
            返回项目列表
          </Button>
        </Empty>
      </Card>
    );
  }

  return (
    <>
      <PageHeader
        title={
          <Space size={12} wrap>
            <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/projects')} />
            <span>{data.name}</span>
            <RepoTypeTag repoType={data.repoType} />
          </Space>
        }
        subtitle={
          <Typography.Text className="mono" type="secondary" copyable={{ text: data.repoUrl }}>
            {data.repoUrl}
          </Typography.Text>
        }
        extra={
          <Link to={`/vulnerabilities?projectId=${data.id}`}>
            <Button type="primary" icon={<BugOutlined />}>
              查看该项目漏洞
            </Button>
          </Link>
        }
      />

      <Row gutter={[16, 16]}>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic title="扫描次数" value={data.stats?.scanCount ?? 0} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic title="漏洞总数" value={data.stats?.vulnTotal ?? 0} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic title="未处理" value={data.stats?.vulnOpen ?? 0} valueStyle={{ color: '#fa541c' }} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic
              title="严重 / 高危"
              value={data.stats?.vulnCritical ?? 0}
              suffix={<span style={{ fontSize: 14, color: '#fa541c' }}>/ {data.stats?.vulnHigh ?? 0}</span>}
              valueStyle={{ color: '#cf1322' }}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} xl={10}>
          <Card title="等级分布" className="stat-card">
            {(data.severityDistribution ?? []).length === 0 ? (
              <Empty description="暂无漏洞" style={{ padding: '40px 0' }} />
            ) : (
              <Pie {...pieConfig} height={250} />
            )}
          </Card>
        </Col>
        <Col xs={24} xl={14}>
          <Card title="项目信息" className="stat-card">
            <Descriptions column={{ xs: 1, sm: 2 }} size="small" bordered>
              <Descriptions.Item label="项目名">{data.name}</Descriptions.Item>
              <Descriptions.Item label="org/repo">{data.repoFullName ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="默认分支">{data.defaultBranch ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="负责人">{data.owner ?? '未指定'}</Descriptions.Item>
              <Descriptions.Item label="状态">
                {data.status === 1 ? <Tag color="green">启用</Tag> : <Tag>停用</Tag>}
              </Descriptions.Item>
              <Descriptions.Item label="最近扫描">
                {data.lastScanAt ? formatTime(data.lastScanAt) : '从未扫描'}
              </Descriptions.Item>
              <Descriptions.Item label="创建时间">{formatTime(data.createdAt)}</Descriptions.Item>
              <Descriptions.Item label="更新时间">{formatTime(data.updatedAt)}</Descriptions.Item>
              <Descriptions.Item label="描述" span={2}>
                {data.description || <span className="text-muted">无</span>}
              </Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
      </Row>

      <Card title="最近 5 次扫描" className="stat-card" style={{ marginTop: 16 }}>
        {(data.recentScans ?? []).length === 0 ? (
          <Alert type="info" showIcon message="该项目还没有扫描记录" />
        ) : (
          <Table
            className="vuln-table"
            size="middle"
            rowKey="id"
            pagination={false}
            dataSource={data.recentScans}
            columns={[
              {
                title: '批次号',
                dataIndex: 'scanNo',
                render: (v: string) => (
                  <Link to={`/scans/${encodeURIComponent(v)}`} className="mono">
                    {v}
                  </Link>
                ),
              },
              { title: '分支', dataIndex: 'branch', width: 110, render: (v: string | null) => v ?? '-' },
              {
                title: '提交',
                dataIndex: 'commitId',
                width: 110,
                render: (v: string | null) => <span className="mono">{v ? v.slice(0, 8) : '-'}</span>,
              },
              {
                title: '漏洞',
                dataIndex: 'vulnCount',
                width: 80,
                align: 'right',
                render: (v: number) => <b className="stat-value">{v}</b>,
              },
              {
                title: '样本',
                dataIndex: 'sampleCount',
                width: 100,
                align: 'right',
                render: (v: number) => <span className="stat-value">{formatNumber(v)}</span>,
              },
              {
                title: '状态',
                dataIndex: 'status',
                width: 100,
                render: (v: string) => <ScanStatusTag status={v as never} />,
              },
              {
                title: '时间',
                dataIndex: 'startedAt',
                width: 160,
                render: (v: string | null, r) => formatTime(v ?? (r.createdAt as string)),
              },
            ]}
          />
        )}
      </Card>

      <Space style={{ marginTop: 16 }} wrap>
        <span className="text-muted" style={{ fontSize: 12.5 }}>
          等级图例：
        </span>
        {SEVERITIES.map((s) => (
          <SeverityTag key={s} severity={s} />
        ))}
      </Space>
    </>
  );
}
