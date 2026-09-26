import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Empty,
  Progress,
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
import { SEVERITIES, SEVERITY_META, TRIGGER_TYPE_META, type ScanTaskDetail, type TriggerType } from '@vuln/shared';
import { scanApi } from '@/api';
import {
  PageHeader,
  ScanStatusTag,
  SeverityTag,
  formatDuration,
  formatNumber,
  formatTime,
} from '@/components/common';

export default function ScanDetailPage() {
  const { scanNo } = useParams<{ scanNo: string }>();
  const navigate = useNavigate();
  const { message } = AntdApp.useApp();
  const [data, setData] = useState<ScanTaskDetail | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!scanNo) return;
    setLoading(true);
    try {
      setData(await scanApi.detail(scanNo));
    } catch (e) {
      message.error(e instanceof Error ? e.message : '加载失败');
    } finally {
      setLoading(false);
    }
  }, [scanNo, message]);

  useEffect(() => {
    void load();
  }, [load]);

  if (loading && !data) {
    return (
      <>
        <PageHeader title="扫描批次详情" subtitle="加载中…" />
        <Card>
          <Skeleton active paragraph={{ rows: 8 }} />
        </Card>
      </>
    );
  }

  if (!data) {
    return (
      <Card>
        <Empty description="批次不存在">
          <Button type="primary" onClick={() => navigate('/scans')}>
            返回扫描记录
          </Button>
        </Empty>
      </Card>
    );
  }

  const coverage = data.totalFiles > 0 ? Math.round((data.scannedFiles / data.totalFiles) * 100) : 0;

  return (
    <>
      <PageHeader
        title={
          <Space size={12} wrap>
            <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/scans')} />
            <span className="mono" style={{ fontSize: 17 }}>
              {data.scanNo}
            </span>
            <ScanStatusTag status={data.status} />
          </Space>
        }
        subtitle={
          <Space size={12} wrap>
            {data.project ? <Link to={`/projects/${data.project.id}`}>{data.project.name}</Link> : null}
            <span className="text-muted">·</span>
            <Tag>{TRIGGER_TYPE_META[data.triggerType as TriggerType]?.label ?? data.triggerType}</Tag>
            {data.branch ? <Tag>分支 {data.branch}</Tag> : null}
            <span>扫描器 {data.scanner.name ?? '-'} {data.scanner.version ?? ''}</span>
          </Space>
        }
        extra={
          data.project ? (
            <Link to={`/vulnerabilities?projectId=${data.project.id}`}>
              <Button type="primary" icon={<BugOutlined />}>
                查看项目漏洞
              </Button>
            </Link>
          ) : null
        }
      />

      {data.status === 'failed' && data.errorMessage ? (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 16 }}
          message="本次扫描失败"
          description={data.errorMessage}
        />
      ) : null}
      {data.status === 'running' ? (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="该批次仍在扫描中"
          description="超过 2 小时未结束的批次会被定时任务标记为 partial，不会永久挂起。"
        />
      ) : null}

      <Row gutter={[16, 16]}>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic title="本批次漏洞" value={data.vulnCount} valueStyle={{ color: '#fa541c' }} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic title="样本总数" value={data.sampleCount} formatter={(v) => formatNumber(Number(v))} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic
              title="正 / 负样本"
              value={data.positiveCount}
              suffix={<span style={{ fontSize: 14, color: '#52c41a' }}>/ {formatNumber(data.negativeCount)}</span>}
              valueStyle={{ color: '#cf1322' }}
            />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic title="扫描耗时" value={formatDuration(data.durationMs)} />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} xl={12}>
          <Card title="批次信息" className="stat-card">
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="批次号">
                <Typography.Text className="mono" copyable>
                  {data.scanNo}
                </Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="项目">{data.project?.name ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="扫描器">
                {data.scanner.name ?? '-'} {data.scanner.version ? `v${data.scanner.version}` : ''}
              </Descriptions.Item>
              <Descriptions.Item label="触发方式">
                {TRIGGER_TYPE_META[data.triggerType as TriggerType]?.label ?? data.triggerType}
              </Descriptions.Item>
              <Descriptions.Item label="分支">{data.branch ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="Commit">
                <span className="mono">{data.commitId ?? '-'}</span>
              </Descriptions.Item>
              <Descriptions.Item label="提交信息">{data.commitMessage ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="提交人">{data.commitAuthor ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="提交时间">{formatTime(data.commitTime)}</Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>

        <Col xs={24} xl={12}>
          <Card title="扫描进度与时间" className="stat-card">
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 13, marginBottom: 6 }}>
                文件覆盖率：{formatNumber(data.scannedFiles)} / {formatNumber(data.totalFiles)}
              </div>
              <Progress
                percent={coverage}
                status={data.status === 'failed' ? 'exception' : coverage === 100 ? 'success' : 'active'}
              />
            </div>
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="开始时间">{formatTime(data.startedAt, 'YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
              <Descriptions.Item label="结束时间">
                {data.finishedAt ? formatTime(data.finishedAt, 'YYYY-MM-DD HH:mm:ss') : <span className="text-muted">未结束</span>}
              </Descriptions.Item>
              <Descriptions.Item label="入库时间">{formatTime(data.createdAt, 'YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
              <Descriptions.Item label="状态">
                <ScanStatusTag status={data.status} />
              </Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} xl={10}>
          <Card title="本批次漏洞等级分布" className="stat-card">
            <Space direction="vertical" style={{ width: '100%' }} size={10}>
              {SEVERITIES.map((s) => {
                const count = data.vulnSummary?.[s] ?? 0;
                const totalV = SEVERITIES.reduce((a, k) => a + (data.vulnSummary?.[k] ?? 0), 0);
                const pct = totalV > 0 ? Math.round((count / totalV) * 100) : 0;
                return (
                  <div key={s}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <SeverityTag severity={s} />
                      <span className="stat-value">
                        <b>{count}</b> <span className="text-muted">({pct}%)</span>
                      </span>
                    </div>
                    <Progress
                      percent={pct}
                      showInfo={false}
                      strokeColor={SEVERITY_META[s].color}
                      size="small"
                    />
                  </div>
                );
              })}
            </Space>
          </Card>
        </Col>

        <Col xs={24} xl={14}>
          <Card title="本批次 Top 规则" className="stat-card">
            {(data.topRules ?? []).length === 0 ? (
              <Empty description="本批次未命中任何规则" />
            ) : (
              <Table
                className="vuln-table"
                size="small"
                rowKey="ruleId"
                pagination={false}
                dataSource={data.topRules}
                columns={[
                  {
                    title: '规则',
                    render: (_: unknown, r) => (
                      <Space direction="vertical" size={0}>
                        <span>{r.ruleName ?? r.ruleId}</span>
                        <span className="mono text-muted" style={{ fontSize: 12 }}>
                          {r.ruleId}
                        </span>
                      </Space>
                    ),
                  },
                  {
                    title: '命中数',
                    dataIndex: 'count',
                    width: 100,
                    align: 'right',
                    render: (v: number, r) => (
                      <Link to={`/vulnerabilities?ruleId=${encodeURIComponent(r.ruleId)}`} className="stat-value">
                        <b>{v}</b>
                      </Link>
                    ),
                  },
                  {
                    title: '操作',
                    width: 100,
                    render: (_: unknown, r) => (
                      <Link to={`/vulnerabilities?ruleId=${encodeURIComponent(r.ruleId)}`}>
                        <Button type="link" size="small">
                          查看漏洞
                        </Button>
                      </Link>
                    ),
                  },
                ]}
              />
            )}
          </Card>
        </Col>
      </Row>

      <Card style={{ marginTop: 16 }} className="stat-card">
        <Alert
          type="info"
          showIcon
          message="关于本批次的样本"
          description={
            <span style={{ fontSize: 12.5 }}>
              本批次共上报 {formatNumber(data.sampleCount)} 条样本，其中正样本（有漏洞）{data.positiveCount} 条、
              负样本（无漏洞）{formatNumber(data.negativeCount)} 条。
              <Link to={`/samples?scanNo=${encodeURIComponent(data.scanNo)}`}> 前往样本库查看 →</Link>
            </span>
          }
        />
      </Card>
    </>
  );
}
