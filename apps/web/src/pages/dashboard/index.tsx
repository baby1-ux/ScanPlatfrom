import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Badge,
  Button,
  Card,
  Col,
  Empty,
  Progress,
  Row,
  Segmented,
  Select,
  Skeleton,
  Space,
  Statistic,
  Table,
  Tag,
  Tooltip,
  Typography,
  App as AntdApp,
} from 'antd';
import {
  ArrowDownOutlined,
  ArrowUpOutlined,
  BugOutlined,
  CheckCircleOutlined,
  FireOutlined,
  ReloadOutlined,
  RiseOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import { Area, Column, Pie } from '@ant-design/plots';import {
  SCAN_STATUS_META,
  SEVERITIES,
  SEVERITY_META,
  VULN_STATUS_META,
  VULN_STATUSES,
  type ScanStatus,
  type Severity,
  type SeverityBucket,
  type StatsOverview,
  type TopProject,
  type TopRule,
  type TrendPoint,
  type VulnStatus,
} from '@vuln/shared';
import { statsApi, projectApi } from '@/api';
import { PageHeader, ScanStatusTag, SeverityTag, formatNumber, formatDuration, formatTime } from '@/components/common';

interface RecentScan {
  id: number;
  scanNo: string;
  project: { name: string | null; repoType: string | null };
  status: ScanStatus;
  branch: string | null;
  commitMessage: string | null;
  commitAuthor: string | null;
  vulnCount: number;
  sampleCount: number;
  startedAt: string | null;
  finishedAt: string | null;
  createdAt: string;
  durationMs: number | null;
}

const DAY_OPTIONS = [
  { label: '近 7 天', value: 7 },
  { label: '近 30 天', value: 30 },
  { label: '近 90 天', value: 90 },
];

export default function DashboardPage() {
  const { message } = AntdApp.useApp();
  const [days, setDays] = useState(30);
  const [projectIds, setProjectIds] = useState<number[]>([]);
  const [loading, setLoading] = useState(true);
  const [overview, setOverview] = useState<StatsOverview | null>(null);
  const [trend, setTrend] = useState<TrendPoint[]>([]);
  const [severity, setSeverity] = useState<SeverityBucket[]>([]);
  const [statusDist, setStatusDist] = useState<Array<{ status: VulnStatus; count: number }>>([]);
  const [topRules, setTopRules] = useState<TopRule[]>([]);
  const [topProjects, setTopProjects] = useState<TopProject[]>([]);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [projects, setProjects] = useState<Array<{ id: number; name: string }>>([]);

  const load = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true);
      try {
        const params = { projectId: projectIds.length ? projectIds : undefined };
        const [ov, tr, sev, st, rules, projs, scans] = await Promise.all([
          statsApi.overview({ ...params, days }),
          statsApi.trend({ ...params, days }),
          statsApi.severity(params),
          statsApi.statusDistribution(params),
          statsApi.topRules({ ...params, limit: 8, days }),
          statsApi.topProjects({ limit: 8, sortBy: 'vulnOpen' }),
          statsApi.recentScans({ limit: 8 }),
        ]);
        setOverview(ov);
        setTrend(tr.list);
        setSeverity(sev.list);
        setStatusDist(st.list as Array<{ status: VulnStatus; count: number }>);
        setTopRules(rules.list);
        setTopProjects(projs.list);
        setRecentScans(scans.list as unknown as RecentScan[]);
      } catch (e) {
        message.error(e instanceof Error ? e.message : '看板数据加载失败');
      } finally {
        setLoading(false);
      }
    },
    [days, projectIds, message],
  );

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    projectApi
      .options()
      .then((r) => setProjects(r.list))
      .catch(() => setProjects([]));
  }, []);

  /** 趋势：新增 / 修复用面积图（G2 v5 语法） */
  const trendConfig = useMemo(
    () => ({
      data: trend.flatMap((d) => [
        { date: d.date, type: '新增', value: d.newCount },
        { date: d.date, type: '修复', value: d.fixedCount },
      ]),
      xField: 'date',
      yField: 'value',
      colorField: 'type',
      shapeField: 'smooth',
      style: { fillOpacity: 0.25, lineWidth: 2 },
      axis: {
        x: { labelAutoRotate: false, labelAutoHide: true, tickCount: 8 },
        y: { title: false },
      },
      legend: { color: { position: 'top', layout: { justifyContent: 'flex-end' } } },
      scale: { color: { range: ['#cf1322', '#52c41a'] } },
      tooltip: { title: (d: { date: string }) => d.date },
      animation: { appear: { duration: 400 } },
    }),
    [trend],
  );

  /** 等级分布：语义色饼图 */
  const severityConfig = useMemo(() => {
    const data = severity
      .filter((s) => s.count > 0)
      .map((s) => ({ type: SEVERITY_META[s.severity]?.label ?? s.severity, value: s.count, severity: s.severity }));
    return {
      data,
      angleField: 'value',
      colorField: 'type',
      radius: 0.9,
      innerRadius: 0.6,
      label: { text: 'value', style: { fontWeight: 600 } },
      legend: { color: { position: 'right', rowPadding: 6 } },
      scale: {
        color: {
          domain: data.map((d) => d.type),
          range: data.map((d) => SEVERITY_META[d.severity as Severity]?.color ?? '#8c8c8c'),
        },
      },
      tooltip: { title: 'type' },
      style: { stroke: '#fff', lineWidth: 2 },
      annotation: [
        {
          type: 'text',
          style: {
            text: `${data.reduce((a, b) => a + b.value, 0)}\n漏洞总数`,
            x: '50%',
            y: '50%',
            textAlign: 'center',
            fontSize: 18,
            fontWeight: 600,
          },
        },
      ],
    };
  }, [severity]);

  /** 状态分布：横向柱状 */
  const statusConfig = useMemo(() => {
    const data = VULN_STATUSES.map((s) => ({
      status: s,
      label: VULN_STATUS_META[s].label,
      value: statusDist.find((d) => d.status === s)?.count ?? 0,
    }));
    return {
      data,
      xField: 'label',
      yField: 'value',
      colorField: 'status',
      style: { radiusTopLeft: 6, radiusTopRight: 6, maxWidth: 44 },
      legend: false,
      axis: { x: { title: false }, y: { title: false } },
      scale: {
        color: {
          domain: data.map((d) => d.status),
          range: data.map((d) => {
            const c = VULN_STATUS_META[d.status as VulnStatus].color;
            return (
              { red: '#ff4d4f', orange: '#fa8c16', blue: '#1677ff', green: '#52c41a', default: '#8c8c8c', purple: '#722ed1' } as Record<string, string>
            )[c] ?? '#8c8c8c';
          }),
        },
      },
      label: { text: 'value', position: 'top' as const },
    };
  }, [statusDist]);

  const openStatusTotal = useMemo(
    () => statusDist.filter((s) => ['open', 'confirmed', 'fixing'].includes(s.status)).reduce((a, b) => a + b.count, 0),
    [statusDist],
  );
  const fixRate = useMemo(() => {
    const fixed = statusDist.find((s) => s.status === 'fixed')?.count ?? 0;
    const total = statusDist.reduce((a, b) => a + b.count, 0);
    return total > 0 ? Math.round((fixed / total) * 100) : 0;
  }, [statusDist]);

  if (loading && !overview) {
    return (
      <>
        <PageHeader title="数据看板" subtitle="正在加载统计…" />
        <Row gutter={[16, 16]}>
          {[0, 1, 2, 3].map((i) => (
            <Col xs={24} sm={12} xl={6} key={i}>
              <Card className="stat-card">
                <Skeleton active paragraph={{ rows: 2 }} />
              </Card>
            </Col>
          ))}
        </Row>
        <Card style={{ marginTop: 16 }}>
          <Skeleton active paragraph={{ rows: 8 }} />
        </Card>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="数据看板"
        subtitle={
          <Space size={8} wrap>
            <span>统计口径：不含误报与已忽略；未处理 = 待处理 + 已确认 + 修复中</span>
            <Tag color="blue">近 {days} 天</Tag>
          </Space>
        }
        extra={
          <Space wrap>
            <Select
              mode="multiple"
              allowClear
              placeholder="全部项目"
              style={{ minWidth: 200 }}
              value={projectIds}
              onChange={setProjectIds}
              options={projects.map((p) => ({ label: p.name, value: p.id }))}
              maxTagCount="responsive"
            />
            <Segmented options={DAY_OPTIONS} value={days} onChange={(v) => setDays(v as number)} />
            <Tooltip title="重新拉取看板数据">
              <Button icon={<ReloadOutlined />} onClick={() => load()} loading={loading}>
                刷新
              </Button>
            </Tooltip>
          </Space>
        }
      />

      {/* ---------------- 顶部统计卡片 ---------------- */}
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} xl={6}>
          <Card className="stat-card">
            <Statistic
              title={
                <Space size={6}>
                  <BugOutlined style={{ color: '#1677ff' }} />
                  漏洞总数
                </Space>
              }
              value={overview?.vulnTotal ?? 0}
              valueStyle={{ fontWeight: 600 }}
              suffix={<span style={{ fontSize: 13, color: '#8c8c8c' }}>条</span>}
            />
            <div style={{ marginTop: 8, fontSize: 12.5 }}>
              <span style={{ color: '#cf1322', fontWeight: 600 }}>{overview?.vulnCritical ?? 0}</span> 严重 ·{' '}
              <span style={{ color: '#fa541c', fontWeight: 600 }}>{overview?.vulnHigh ?? 0}</span> 高危
            </div>
          </Card>
        </Col>

        <Col xs={24} sm={12} xl={6}>
          <Card className="stat-card">
            <Statistic
              title={
                <Space size={6}>
                  <FireOutlined style={{ color: '#fa541c' }} />
                  待处理
                </Space>
              }
              value={overview?.vulnOpen ?? 0}
              valueStyle={{ fontWeight: 600, color: (overview?.vulnOpen ?? 0) > 0 ? '#fa541c' : undefined }}
              suffix={<span style={{ fontSize: 13, color: '#8c8c8c' }}>条</span>}
            />
            <div style={{ marginTop: 8, fontSize: 12.5, color: '#8c8c8c' }}>
              占全部 {overview?.vulnTotal ? Math.round(((overview.vulnOpen ?? 0) / overview.vulnTotal) * 100) : 0}%
            </div>
          </Card>
        </Col>

        <Col xs={24} sm={12} xl={6}>
          <Card className="stat-card">
            <Statistic
              title={
                <Space size={6}>
                  <RiseOutlined style={{ color: '#cf1322' }} />
                  近 {days} 天新增
                </Space>
              }
              value={overview?.newInPeriod ?? 0}
              valueStyle={{ fontWeight: 600 }}
              prefix={
                (overview?.newInPeriod ?? 0) > 0 ? <ArrowUpOutlined style={{ color: '#cf1322', fontSize: 16 }} /> : undefined
              }
            />
            <div style={{ marginTop: 8, fontSize: 12.5 }}>
              <CheckCircleOutlined style={{ color: '#52c41a' }} /> 同期修复{' '}
              <span style={{ color: '#52c41a', fontWeight: 600 }}>{overview?.fixedInPeriod ?? 0}</span> 条
              {(overview?.fixedInPeriod ?? 0) === 0 && (overview?.newInPeriod ?? 0) > 0 ? (
                <ArrowDownOutlined style={{ color: '#8c8c8c', marginLeft: 4 }} />
              ) : null}
            </div>
          </Card>
        </Col>

        <Col xs={24} sm={12} xl={6}>
          <Card className="stat-card">
            <Statistic
              title={
                <Space size={6}>
                  <ThunderboltOutlined style={{ color: '#52c41a' }} />
                  平均修复时长
                </Space>
              }
              value={overview?.avgFixHours ?? 0}
              precision={overview?.avgFixHours === null ? 0 : 1}
              suffix={<span style={{ fontSize: 13, color: '#8c8c8c' }}>小时</span>}
              valueStyle={{ fontWeight: 600 }}
            />
            <div style={{ marginTop: 8, fontSize: 12.5, color: '#8c8c8c' }}>
              {overview?.avgFixHours === null ? '暂无已修复数据' : `修复率 ${fixRate}% · 样本 ${formatNumber(overview?.sampleCount)}`}
            </div>
          </Card>
        </Col>
      </Row>

      {/* ---------------- 趋势 + 等级分布 ---------------- */}
      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} xl={16}>
          <Card
            title="漏洞趋势"
            className="stat-card"
            extra={
              <Space size={12} className="text-muted" style={{ fontSize: 12.5 }}>
                <span>
                  <Badge color="#cf1322" /> 新增
                </span>
                <span>
                  <Badge color="#52c41a" /> 修复
                </span>
              </Space>
            }
          >
            {trend.length === 0 ? (
              <Empty description="所选时间范围内暂无数据" style={{ padding: '48px 0' }} />
            ) : (
              <Area {...trendConfig} height={300} />
            )}
          </Card>
        </Col>

        <Col xs={24} xl={8}>
          <Card title="漏洞等级分布" className="stat-card">
            {severity.every((s) => s.count === 0) ? (
              <Empty description="暂无漏洞数据" style={{ padding: '48px 0' }} />
            ) : (
              <>
                <Pie {...severityConfig} height={230} />
                <Row gutter={[8, 8]} style={{ marginTop: 12 }}>
                  {SEVERITIES.map((sev) => {
                    const item = severity.find((s) => s.severity === sev);
                    return (
                      <Col span={12} key={sev}>
                        <div style={{ fontSize: 12.5, display: 'flex', justifyContent: 'space-between' }}>
                          <SeverityTag severity={sev} />
                          <span className="stat-value">
                            <b>{item?.count ?? 0}</b>
                            <span className="text-muted"> / 未处理 {item?.openCount ?? 0}</span>
                          </span>
                        </div>
                      </Col>
                    );
                  })}
                </Row>
              </>
            )}
          </Card>
        </Col>
      </Row>

      {/* ---------------- 状态 / Top 规则 / Top 项目 ---------------- */}
      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} xl={8}>
          <Card
            title="处置状态分布"
            className="stat-card"
            extra={<span className="text-muted" style={{ fontSize: 12.5 }}>未处理 {openStatusTotal}</span>}
          >
            {statusDist.length === 0 ? (
              <Empty description="暂无数据" style={{ padding: '40px 0' }} />
            ) : (
              <>
                <Column {...statusConfig} height={220} />
                <Progress
                  percent={fixRate}
                  size="small"
                  strokeColor="#52c41a"
                  format={(p) => `修复率 ${p}%`}
                  style={{ marginTop: 8 }}
                />
              </>
            )}
          </Card>
        </Col>

        <Col xs={24} xl={8}>
          <Card
            title="Top 漏洞规则"
            className="stat-card"
            extra={<Link to="/vulnerabilities">查看全部</Link>}
          >
            {topRules.length === 0 ? (
              <Empty description="暂无数据" style={{ padding: '40px 0' }} />
            ) : (
              <Table
                className="vuln-table"
                size="small"
                rowKey="ruleId"
                pagination={false}
                dataSource={topRules}
                columns={[
                  {
                    title: '规则',
                    dataIndex: 'ruleName',
                    ellipsis: true,
                    render: (v: string | null, r: TopRule) => (
                      <Tooltip title={r.ruleId}>
                        <span>{v ?? r.ruleId}</span>
                      </Tooltip>
                    ),
                  },
                  {
                    title: '数量',
                    dataIndex: 'count',
                    width: 96,
                    align: 'right',
                    render: (v: number, r: TopRule) => (
                      <Space size={4}>
                        <b className="stat-value">{v}</b>
                        {r.criticalCount > 0 && <Tag color="red">严重 {r.criticalCount}</Tag>}
                      </Space>
                    ),
                  },
                ]}
              />
            )}
          </Card>
        </Col>

        <Col xs={24} xl={8}>
          <Card title="风险 Top 项目" className="stat-card" extra={<Link to="/projects">查看全部</Link>}>
            {topProjects.length === 0 ? (
              <Empty description="暂无数据" style={{ padding: '40px 0' }} />
            ) : (
              <Table
                className="vuln-table"
                size="small"
                rowKey="projectId"
                pagination={false}
                dataSource={topProjects}
                columns={[
                  {
                    title: '项目',
                    dataIndex: 'name',
                    ellipsis: true,
                    render: (v: string, r: TopProject) => <Link to={`/projects/${r.projectId}`}>{v}</Link>,
                  },
                  {
                    title: '未处理',
                    dataIndex: 'vulnOpen',
                    width: 80,
                    align: 'right',
                    render: (v: number) => <b className="stat-value">{v}</b>,
                  },
                  {
                    title: '严重/高危',
                    width: 100,
                    align: 'right',
                    render: (_: unknown, r: TopProject) => (
                      <span className="stat-value">
                        <span style={{ color: '#cf1322' }}>{r.criticalCount}</span> /{' '}
                        <span style={{ color: '#fa541c' }}>{r.highCount}</span>
                      </span>
                    ),
                  },
                ]}
              />
            )}
          </Card>
        </Col>
      </Row>

      {/* ---------------- 最近扫描批次 ---------------- */}
      <Card
        title="最近扫描批次"
        className="stat-card"
        style={{ marginTop: 16 }}
        extra={<Link to="/scans">全部扫描记录</Link>}
      >
        {recentScans.length === 0 ? (
          <Empty description="暂无扫描记录，等扫描工具上报后这里会出现数据" style={{ padding: '32px 0' }} />
        ) : (
          <Table
            className="vuln-table"
            size="middle"
            rowKey="id"
            pagination={false}
            scroll={{ x: 900 }}
            dataSource={recentScans}
            columns={[
              {
                title: '批次号',
                dataIndex: 'scanNo',
                width: 250,
                render: (v: string) => (
                  <Link to={`/scans/${encodeURIComponent(v)}`} className="mono">
                    {v}
                  </Link>
                ),
              },
              {
                title: '项目',
                width: 150,
                render: (_: unknown, r: RecentScan) => r.project?.name ?? '-',
              },
              {
                title: '分支',
                dataIndex: 'branch',
                width: 100,
                render: (v: string | null) => <span className="mono">{v ?? '-'}</span>,
              },
              {
                title: '提交信息',
                dataIndex: 'commitMessage',
                ellipsis: true,
                render: (v: string | null, r: RecentScan) => (
                  <Tooltip title={v}>
                    <span>
                      {v ?? '-'}
                      {r.commitAuthor ? <span className="text-muted"> · {r.commitAuthor}</span> : null}
                    </span>
                  </Tooltip>
                ),
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
                width: 90,
                align: 'right',
                render: (v: number) => <span className="stat-value">{formatNumber(v)}</span>,
              },
              {
                title: '耗时',
                dataIndex: 'durationMs',
                width: 90,
                align: 'right',
                render: (v: number | null) => formatDuration(v),
              },
              {
                title: '状态',
                dataIndex: 'status',
                width: 100,
                render: (v: ScanStatus) => <ScanStatusTag status={v} />,
              },
              {
                title: '时间',
                dataIndex: 'createdAt',
                width: 150,
                render: (v: string) => formatTime(v),
              },
            ]}
          />
        )}
      </Card>

      <Typography.Paragraph type="secondary" style={{ marginTop: 16, fontSize: 12.5, textAlign: 'center' }}>
        {SCAN_STATUS_META.success.label} 批次 {overview?.scanCount ?? 0} 次 · 覆盖项目 {overview?.projectCount ?? 0} 个 ·
        样本累计 {formatNumber(overview?.sampleCount ?? 0)} 条
      </Typography.Paragraph>
    </>
  );
}
