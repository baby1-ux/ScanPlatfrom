import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Button,
  Card,
  Col,
  Drawer,
  Empty,
  Input,
  Row,
  Segmented,
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
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneLight } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { ReloadOutlined, SearchOutlined } from '@ant-design/icons';
import { SAMPLE_LABELS, SAMPLE_LABEL_META, type SampleLabel, type SampleListItem } from '@vuln/shared';
import { projectApi, sampleApi } from '@/api';
import { PageHeader, SampleLabelTag, formatNumber, formatTime } from '@/components/common';

type LabelFilter = 'all' | SampleLabel;

export default function SampleListPage() {
  const { message } = AntdApp.useApp();
  const [loading, setLoading] = useState(false);
  const [list, setList] = useState<SampleListItem[]>([]);
  const [summary, setSummary] = useState<{ positive: number; negative: number }>({ positive: 0, negative: 0 });
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [label, setLabel] = useState<LabelFilter>('all');
  const [keyword, setKeyword] = useState('');
  const [projectIds, setProjectIds] = useState<number[]>([]);
  const [projects, setProjects] = useState<Array<{ id: number; name: string }>>([]);
  const [detail, setDetail] = useState<(SampleListItem & { snippet: string | null; snippetHash: string }) | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await sampleApi.list({
        page,
        pageSize,
        label: label === 'all' ? undefined : [label],
        keyword: keyword || undefined,
        projectId: projectIds.length ? projectIds : undefined,
      });
      setList(data.list);
      setTotal(data.pagination.total);
      setSummary(data.summary);
    } catch (e) {
      message.error(e instanceof Error ? e.message : '加载失败');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, label, keyword, projectIds, message]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    projectApi.options().then((r) => setProjects(r.list)).catch(() => undefined);
  }, []);

  const openDetail = async (id: number) => {
    setDetailLoading(true);
    try {
      const d = await sampleApi.detail(id);
      setDetail(d as never);
    } catch (e) {
      message.error(e instanceof Error ? e.message : '加载样本失败');
    } finally {
      setDetailLoading(false);
    }
  };

  const columns: ColumnsType<SampleListItem> = [
    {
      title: '标签',
      dataIndex: 'label',
      width: 90,
      render: (v: SampleLabel) => <SampleLabelTag label={v} />,
    },
    {
      title: '文件路径',
      dataIndex: 'filePath',
      ellipsis: true,
      render: (v: string, r) => (
        <Space direction="vertical" size={0}>
          <span className="mono" style={{ fontSize: 12.5 }}>
            {v}
          </span>
          <span className="text-muted" style={{ fontSize: 12 }}>
            {r.language ?? '-'}
            {r.lineStart ? ` · L${r.lineStart}-${r.lineEnd ?? r.lineStart}` : ''}
          </span>
        </Space>
      ),
    },
    {
      title: '片段预览',
      dataIndex: 'snippetPreview',
      ellipsis: true,
      render: (v: string | null) =>
        v ? (
          <Tooltip title={<pre style={{ margin: 0, fontSize: 12, maxWidth: 520, whiteSpace: 'pre-wrap' }}>{v}</pre>}>
            <span className="mono text-muted" style={{ fontSize: 12 }}>
              {v.slice(0, 90)}
              {v.length > 90 ? '…' : ''}
            </span>
          </Tooltip>
        ) : (
          <span className="text-muted">无内容</span>
        ),
    },
    {
      title: '项目',
      dataIndex: 'projectName',
      width: 130,
      ellipsis: true,
      render: (v: string | null, r) => (v ? <Link to={`/projects/${r.projectId}`}>{v}</Link> : r.projectId),
    },
    {
      title: '关联漏洞',
      width: 130,
      render: (_: unknown, r) =>
        r.vulnId ? (
          <Link to={`/vulnerabilities/${r.vulnId}`} className="mono" style={{ fontSize: 12.5 }}>
            #{r.vulnId}
          </Link>
        ) : (
          <span className="text-muted">-</span>
        ),
    },
    {
      title: '规则',
      dataIndex: 'ruleId',
      width: 160,
      ellipsis: true,
      render: (v: string | null) => (v ? <Tag>{v}</Tag> : <span className="text-muted">-</span>),
    },
    {
      title: '大小',
      dataIndex: 'snippetSize',
      width: 90,
      align: 'right',
      render: (v: number) => <span className="stat-value">{v} B</span>,
    },
    {
      title: '批次',
      dataIndex: 'scanNo',
      width: 220,
      ellipsis: true,
      render: (v: string | null) =>
        v ? (
          <Link to={`/scans/${encodeURIComponent(v)}`} className="mono" style={{ fontSize: 12 }}>
            {v}
          </Link>
        ) : (
          '-'
        ),
    },
    {
      title: '入库时间',
      dataIndex: 'createdAt',
      width: 150,
      render: (v: string) => formatTime(v),
    },
    {
      title: '操作',
      width: 80,
      fixed: 'right',
      render: (_: unknown, r) => (
        <Button type="link" size="small" onClick={() => openDetail(r.id)}>
          预览
        </Button>
      ),
    },
  ];

  const totalSamples = summary.positive + summary.negative;

  return (
    <>
      <PageHeader
        title="样本库"
        subtitle="正样本 = 有漏洞的代码片段；负样本 = 扫描过的无漏洞文件。样本可用于后续扫描引擎的模型/规则调优"
        extra={
          <Space wrap>
            <Segmented
              value={label}
              onChange={(v) => {
                setLabel(v as LabelFilter);
                setPage(1);
              }}
              options={[
                { label: '全部', value: 'all' },
                ...SAMPLE_LABELS.map((l) => ({ label: SAMPLE_LABEL_META[l].label, value: l })),
              ]}
            />
            <Input
              allowClear
              placeholder="文件路径 / 片段内容"
              prefix={<SearchOutlined />}
              style={{ width: 230 }}
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
              placeholder="项目"
              style={{ minWidth: 170 }}
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
            <Statistic title="样本总数（当前筛选）" value={total} formatter={(v) => formatNumber(Number(v))} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic title="正样本" value={summary.positive} valueStyle={{ color: '#cf1322' }} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic title="负样本" value={summary.negative} valueStyle={{ color: '#52c41a' }} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="stat-card">
            <Statistic
              title="正样本占比"
              value={totalSamples > 0 ? (summary.positive / totalSamples) * 100 : 0}
              precision={3}
              suffix="%"
            />
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
          scroll={{ x: 1500 }}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: true,
            showTotal: (t, range) => `${range[0]}-${range[1]} / 共 ${formatNumber(t)} 条`,
            onChange: (p, ps) => {
              setPage(p);
              setPageSize(ps);
            },
          }}
          locale={{
            emptyText: <Empty description="暂无样本数据。扫描工具上报正负样本后即可在此查看" />,
          }}
        />
      </Card>

      <Drawer
        title="样本详情"
        open={!!detail}
        onClose={() => setDetail(null)}
        width={760}
        loading={detailLoading}
      >
        {detail ? (
          <Space direction="vertical" style={{ width: '100%' }} size={16}>
            <Card size="small" type="inner">
              <Row gutter={[12, 12]}>
                <Col span={12}>
                  <div className="text-muted" style={{ fontSize: 12 }}>标签</div>
                  <SampleLabelTag label={detail.label} />
                </Col>
                <Col span={12}>
                  <div className="text-muted" style={{ fontSize: 12 }}>语言 / 行号</div>
                  <div>
                    {detail.language ?? '-'}
                    {detail.lineStart ? ` · L${detail.lineStart}-${detail.lineEnd ?? detail.lineStart}` : ''}
                  </div>
                </Col>
                <Col span={24}>
                  <div className="text-muted" style={{ fontSize: 12 }}>文件路径</div>
                  <div className="mono" style={{ wordBreak: 'break-all' }}>{detail.filePath}</div>
                </Col>
                <Col span={24}>
                  <div className="text-muted" style={{ fontSize: 12 }}>片段哈希（sha256）</div>
                  <Typography.Text className="mono" copyable style={{ fontSize: 12 }}>
                    {detail.snippetHash}
                  </Typography.Text>
                </Col>
                {detail.ruleId ? (
                  <Col span={12}>
                    <div className="text-muted" style={{ fontSize: 12 }}>规则</div>
                    <Tag>{detail.ruleId}</Tag>
                  </Col>
                ) : null}
                {detail.vulnId ? (
                  <Col span={12}>
                    <div className="text-muted" style={{ fontSize: 12 }}>关联漏洞</div>
                    <Link to={`/vulnerabilities/${detail.vulnId}`}>#{detail.vulnId}</Link>
                  </Col>
                ) : null}
              </Row>
            </Card>

            <div>
              <Typography.Title level={5}>代码片段</Typography.Title>
              {detail.snippet ? (
                <div className="code-block" style={{ maxHeight: 520 }}>
                  <SyntaxHighlighter
                    language={detail.language?.toLowerCase() === 'js' ? 'javascript' : detail.language?.toLowerCase() ?? 'text'}
                    style={oneLight}
                    showLineNumbers
                    startingLineNumber={detail.lineStart ?? 1}
                    wrapLongLines
                  >
                    {detail.snippet}
                  </SyntaxHighlighter>
                </div>
              ) : (
                <Empty description="该样本没有片段内容" />
              )}
            </div>
          </Space>
        ) : null}
      </Drawer>
    </>
  );
}
