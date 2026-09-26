import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Alert,
  Badge,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  Empty,
  Form,
  Input,
  InputNumber,
  Progress,
  Row,
  Select,
  Slider,
  Space,
  Statistic,
  Table,
  Tag,
  Tooltip,
  Typography,
  App as AntdApp,
} from 'antd';
import {
  ApiOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  ExportOutlined,
  PlayCircleOutlined,
  ReloadOutlined,
  SaveOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneLight } from 'react-syntax-highlighter/dist/esm/styles/prism';
import type { MlAnalyzeResponse, MlDetectResult, MlServiceStatus } from '@vuln/shared';
import { mlApi, projectApi } from '@/api';
import { PageHeader, formatTime } from '@/components/common';

const SAMPLES: Array<{ key: string; label: string; language: string; filePath: string; code: string }> = [
  {
    key: 'sqli',
    label: 'SQL 注入（Java）',
    language: 'java',
    filePath: 'src/main/java/com/demo/dao/UserDao.java',
    code: `public List<User> find(String name) {
    String sql = "SELECT * FROM users WHERE name = '" + name + "'";
    return jdbc.query(sql);
}`,
  },
  {
    key: 'overflow',
    label: '缓冲区溢出（C）',
    language: 'c',
    filePath: 'src/core/string_util.c',
    code: `void copy_name(char *src) {
    char dst[32];
    strcpy(dst, src);
    printf("%s\\n", dst);
}`,
  },
  {
    key: 'xss',
    label: '反射型 XSS（JS）',
    language: 'javascript',
    filePath: 'src/web/pages/search.js',
    code: `const q = new URLSearchParams(location.search).get("q");
document.getElementById("result").innerHTML = "搜索结果: " + q;`,
  },
  {
    key: 'cmd',
    label: '命令注入（Python）',
    language: 'python',
    filePath: 'scripts/net_tools.py',
    code: `def ping(host):
    cmd = "ping -c 1 " + host
    return os.popen(cmd).read()`,
  },
  {
    key: 'safe',
    label: '安全代码（参数化查询）',
    language: 'java',
    filePath: 'src/main/java/com/demo/dao/SafeUserDao.java',
    code: `public List<User> find(String name) {
    String sql = "SELECT * FROM users WHERE name = ?";
    return jdbc.query(sql, new Object[]{name});
}`,
  },
];

export default function ModelDetectPage() {
  const { message } = AntdApp.useApp();
  const [form] = Form.useForm();
  const [status, setStatus] = useState<MlServiceStatus | null>(null);
  const [statusLoading, setStatusLoading] = useState(false);
  const [detecting, setDetecting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<MlDetectResult | null>(null);
  const [lastAnalyze, setLastAnalyze] = useState<MlAnalyzeResponse | null>(null);
  const [projects, setProjects] = useState<Array<{ id: number; name: string }>>([]);
  const [code, setCode] = useState(SAMPLES[0]!.code);
  const [threshold, setThreshold] = useState(0.5);

  const loadStatus = useCallback(async () => {
    setStatusLoading(true);
    try {
      setStatus(await mlApi.status());
    } catch (e) {
      setStatus({
        online: false,
        url: '-',
        fallbackMode: 'fallback',
        modelName: null,
        checkpoint: null,
        devices: null,
        detail: e instanceof Error ? e.message : '无法获取模型服务状态',
        checkedAt: new Date().toISOString(),
      });
    } finally {
      setStatusLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadStatus();
    projectApi.options().then((r) => setProjects(r.list)).catch(() => undefined);
  }, [loadStatus]);

  const fillSample = (key: string) => {
    const s = SAMPLES.find((x) => x.key === key);
    if (!s) return;
    setCode(s.code);
    form.setFieldsValue({ language: s.language, filePath: s.filePath });
    setResult(null);
    setLastAnalyze(null);
  };

  const onDetect = async () => {
    if (!code.trim()) {
      message.warning('请先输入要检测的代码');
      return;
    }
    setDetecting(true);
    try {
      const v = form.getFieldsValue();
      const r = await mlApi.detect({
        code,
        mode: v.mode ?? 'auto',
        threshold,
        filePath: v.filePath,
        language: v.language,
      });
      setResult(r);
      if (r.degraded) {
        message.warning('模型服务不可用，本次结果为降级启发式判定');
      } else {
        message.success('检测完成');
      }
      void loadStatus();
    } catch (e) {
      message.error(e instanceof Error ? e.message : '检测失败');
    } finally {
      setDetecting(false);
    }
  };

  const onAnalyze = async () => {
    if (!code.trim()) {
      message.warning('请先输入要检测的代码');
      return;
    }
    setSaving(true);
    try {
      const v = form.getFieldsValue();
      const r = await mlApi.analyze({
        code,
        mode: v.mode ?? 'auto',
        threshold,
        filePath: v.filePath,
        language: v.language,
        projectId: v.projectId,
        title: v.title,
      });
      setResult(r.result);
      setLastAnalyze(r);
      message.success(
        `已归档为扫描批次 ${r.scan.scanNo}（新增漏洞 ${r.scan.vulnCreated}，正样本 ${r.scan.positiveSamples}）`,
      );
    } catch (e) {
      message.error(e instanceof Error ? e.message : '归档失败');
    } finally {
      setSaving(false);
    }
  };

  const vulnerable = result?.verdict === 'vulnerable';
  const prob = result?.vulnerableProbability ?? 0;

  return (
    <>
      <PageHeader
        title="模型检测"
        subtitle="调用已训练好的 ScanMan 模型（BERT 漏洞检测 + CWE 分类）对单段代码做判定；可一键归档为扫描批次与样本"
        extra={
          <Space wrap>
            <Tooltip title={status?.detail ?? ''}>
              <Tag
                color={status?.online ? 'green' : 'orange'}
                icon={status?.online ? <CheckCircleOutlined /> : <WarningOutlined />}
              >
                模型服务{status?.online ? '在线' : '离线（将降级）'}
              </Tag>
            </Tooltip>
            <Button icon={<ReloadOutlined />} onClick={loadStatus} loading={statusLoading}>
              检测连通性
            </Button>
          </Space>
        }
      />

      {status && !status.online ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message="未连接到 ScanMan 推理服务，检测结果将降级为启发式判定（非模型输出）"
          description={
            <div style={{ fontSize: 12.5, lineHeight: 1.9 }}>
              <div>
                期望地址：<span className="code-inline">{status.url}</span>
              </div>
              <div>
                原因：{status.detail ?? '服务未响应'}
              </div>
              <div>
                启动方式：<span className="code-inline">cd model-service &amp;&amp; ./run.ps1</span>
                （或在 <span className="code-inline">.env</span> 中调整{' '}
                <span className="code-inline">ML_SERVICE_URL</span>）
              </div>
              <div className="text-muted">
                降级结果会在响应中标记 degraded=true，写入平台时也会在漏洞描述里注明，不会被当成模型结论。
              </div>
            </div>
          }
        />
      ) : null}

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={15}>
          <Card
            title={
              <Space>
                <ApiOutlined />
                待检测代码
              </Space>
            }
            className="stat-card"
            extra={
              <Space wrap>
                <Select
                  placeholder="载入示例"
                  style={{ width: 190 }}
                  onChange={fillSample}
                  options={SAMPLES.map((s) => ({ label: s.label, value: s.key }))}
                />
                <Button size="small" onClick={() => { setCode(''); setResult(null); setLastAnalyze(null); }}>
                  清空
                </Button>
              </Space>
            }
          >
            <Form form={form} layout="vertical" initialValues={{ mode: 'auto', language: 'java', filePath: SAMPLES[0]!.filePath }}>
              <Row gutter={12}>
                <Col xs={24} sm={8}>
                  <Form.Item name="mode" label="检测模式">
                    <Select
                      options={[
                        { label: '自动（检测 + 分类）', value: 'auto' },
                        { label: '仅漏洞检测', value: 'detection' },
                        { label: '仅 CWE 分类', value: 'classification' },
                      ]}
                    />
                  </Form.Item>
                </Col>
                <Col xs={24} sm={8}>
                  <Form.Item name="language" label="语言（可选）">
                    <Input placeholder="java / c / python" />
                  </Form.Item>
                </Col>
                <Col xs={24} sm={8}>
                  <Form.Item name="filePath" label="文件路径（可选）">
                    <Input placeholder="src/main/java/..." />
                  </Form.Item>
                </Col>
              </Row>

              <div className="code-block" style={{ maxHeight: 420, marginBottom: 12 }}>
                <Input.TextArea
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  autoSize={{ minRows: 12, maxRows: 22 }}
                  style={{
                    fontFamily: "'SFMono-Regular', Consolas, Menlo, monospace",
                    fontSize: 13,
                    background: 'transparent',
                    border: 'none',
                    boxShadow: 'none',
                    resize: 'vertical',
                  }}
                  placeholder="在此粘贴要检测的源码片段…"
                />
              </div>

              <Row gutter={12} align="middle">
                <Col xs={24} md={10}>
                  <Form.Item label={`判定阈值：${threshold.toFixed(2)}`} style={{ marginBottom: 0 }}>
                    <Slider min={0.05} max={0.95} step={0.05} value={threshold} onChange={setThreshold} />
                  </Form.Item>
                </Col>
                <Col xs={24} md={14}>
                  <Space wrap>
                    <Button type="primary" icon={<PlayCircleOutlined />} onClick={onDetect} loading={detecting}>
                      开始检测
                    </Button>
                    <Button icon={<SaveOutlined />} onClick={onAnalyze} loading={saving}>
                      检测并归档
                    </Button>
                  </Space>
                </Col>
              </Row>
            </Form>
          </Card>
        </Col>

        <Col xs={24} xl={9}>
          <Card title="检测结果" className="stat-card" style={{ marginBottom: 16 }}>
            {!result ? (
              <Empty description="尚未检测。点击「开始检测」查看结果" style={{ padding: '48px 0' }} />
            ) : (
              <Space direction="vertical" style={{ width: '100%' }} size={14}>
                {result.degraded ? (
                  <Alert
                    type="warning"
                    showIcon
                    message="部分结果来自降级启发式（非模型输出）"
                    description={
                      <div style={{ fontSize: 12.5 }}>
                        <div style={{ marginBottom: 6 }}>
                          详情：
                          {(['detection', 'classification'] as const).map((k) => {
                            const t = result.tasks?.[k];
                            if (!t) return null;
                            return (
                              <Tag key={k} color={t.degraded ? 'orange' : 'green'} style={{ marginLeft: 4 }}>
                                {k === 'detection' ? '漏洞检测' : 'CWE 分类'}：
                                {t.degraded ? '降级（启发式）' : '真实模型'}
                              </Tag>
                            );
                          })}
                        </div>
                        <div className="text-muted">{result.degradedReason}</div>
                      </div>
                    }
                  />
                ) : (
                  <Alert type="success" showIcon message="本次结果全部由 ScanMan 模型产出" />
                )}

                {/* 自动模式下：明确标出哪个任务是真模型、哪个是 mock，避免把真结论当 mock */}
                {result.degraded && result.tasks ? (
                  <Space size={6} wrap>
                    {(['detection', 'classification'] as const).map((k) => {
                      const t = result.tasks?.[k];
                      if (!t) return null;
                      return (
                        <Tooltip key={k} title={t.reason ?? `来源：${t.modelName}`}>
                          <Tag color={t.degraded ? 'orange' : 'blue'}>
                            {k === 'detection' ? '检测' : '分类'} · {t.degraded ? '启发式 mock' : t.modelName}
                          </Tag>
                        </Tooltip>
                      );
                    })}
                  </Space>
                ) : null}

                <div style={{ textAlign: 'center' }}>
                  <Tag
                    color={vulnerable ? 'red' : 'green'}
                    style={{ fontSize: 15, padding: '6px 18px', borderRadius: 20 }}
                    icon={vulnerable ? <CloseCircleOutlined /> : <CheckCircleOutlined />}
                  >
                    {vulnerable ? '判定为漏洞' : '判定为安全'}
                  </Tag>
                  <div className="text-muted" style={{ fontSize: 12.5, marginTop: 8 }}>
                    模型：{result.modelName} · 耗时 {result.latencyMs}ms
                  </div>
                </div>

                {result.vulnerableProbability !== null ? (
                  <>
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12.5 }}>
                        <span>漏洞概率</span>
                        <b className="stat-value">{(prob * 100).toFixed(2)}%</b>
                      </div>
                      <Progress
                        percent={Math.round(prob * 100)}
                        strokeColor={vulnerable ? '#cf1322' : '#52c41a'}
                        showInfo={false}
                      />
                    </div>
                    <Row gutter={8}>
                      <Col span={12}>
                        <Statistic
                          title="漏洞概率"
                          value={result.vulnerableProbability}
                          precision={4}
                          valueStyle={{ color: '#cf1322', fontSize: 18 }}
                        />
                      </Col>
                      <Col span={12}>
                        <Statistic
                          title="安全概率"
                          value={result.safeProbability ?? 0}
                          precision={4}
                          valueStyle={{ color: '#52c41a', fontSize: 18 }}
                        />
                      </Col>
                    </Row>
                    <div className="text-muted" style={{ fontSize: 12 }}>
                      判定阈值 {result.threshold}（概率 ≥ 阈值即判为漏洞）
                    </div>
                  </>
                ) : null}

                <Divider style={{ margin: '4px 0' }} />

                <div>
                  <div style={{ marginBottom: 6, fontSize: 13, fontWeight: 600 }}>CWE 分类</div>
                  {result.predictedCwe ? (
                    <Space direction="vertical" style={{ width: '100%' }} size={6}>
                      <Space>
                        <Tag color="geekblue" style={{ fontSize: 13 }}>
                          {result.predictedCwe}
                        </Tag>
                        <span>{result.predictedCweName}</span>
                        {result.cweConfidence !== null ? (
                          <span className="text-muted">({(result.cweConfidence * 100).toFixed(1)}%)</span>
                        ) : null}
                      </Space>
                      {result.topCwe.length > 0 ? (
                        <Table
                          size="small"
                          rowKey="cwe"
                          pagination={false}
                          dataSource={result.topCwe}
                          columns={[
                            { title: 'CWE', dataIndex: 'cwe', width: 100 },
                            { title: '名称', dataIndex: 'name', ellipsis: true },
                            {
                              title: '概率',
                              dataIndex: 'probability',
                              width: 90,
                              align: 'right',
                              render: (v: number) => `${(v * 100).toFixed(1)}%`,
                            },
                          ]}
                        />
                      ) : null}
                    </Space>
                  ) : (
                    <span className="text-muted">本次未执行分类（mode=detection）或模型未返回类别</span>
                  )}
                </div>
              </Space>
            )}
          </Card>

          <Card title="归档参数" className="stat-card">
            <Form form={form} layout="vertical">
              <Form.Item name="title" label="漏洞标题（可选，留空自动生成）">
                <Input placeholder="自动生成：[模型判定] CWE-xxx @ 文件路径" maxLength={512} />
              </Form.Item>
              <Form.Item name="projectId" label="归档到项目（可选）">
                <Select
                  allowClear
                  placeholder="默认：ScanMan 模型检测（自动创建）"
                  options={projects.map((p) => ({ label: p.name, value: p.id }))}
                />
              </Form.Item>
            </Form>
            <Typography.Paragraph type="secondary" style={{ fontSize: 12.5, marginBottom: 0 }}>
              「检测并归档」会把本次判定写成一次<strong>扫描批次</strong>：判定为漏洞时创建一条漏洞记录，并把被检测代码
              作为<strong>正样本</strong>沉淀；判定为安全时只沉淀为<strong>负样本</strong>。归档后可在扫描记录与样本库中看到。
            </Typography.Paragraph>
          </Card>
        </Col>
      </Row>

      {lastAnalyze ? (
        <Card className="stat-card" style={{ marginTop: 16 }} title="最近一次归档结果">
          <Row gutter={[16, 16]}>
            <Col xs={12} md={4}>
              <Statistic title="新增漏洞" value={lastAnalyze.scan.vulnCreated} valueStyle={{ color: '#cf1322' }} />
            </Col>
            <Col xs={12} md={4}>
              <Statistic title="更新漏洞" value={lastAnalyze.scan.vulnUpdated} />
            </Col>
            <Col xs={12} md={4}>
              <Statistic title="正样本" value={lastAnalyze.scan.positiveSamples} valueStyle={{ color: '#cf1322' }} />
            </Col>
            <Col xs={12} md={4}>
              <Statistic title="负样本" value={lastAnalyze.scan.negativeSamples} valueStyle={{ color: '#52c41a' }} />
            </Col>
            <Col xs={24} md={8}>
              <div className="text-muted" style={{ fontSize: 12 }}>扫描批次</div>
              <Link to={`/scans/${encodeURIComponent(lastAnalyze.scan.scanNo)}`} className="mono">
                {lastAnalyze.scan.scanNo}
              </Link>
              <div style={{ marginTop: 8 }}>
                <Link to={`/samples?scanNo=${encodeURIComponent(lastAnalyze.scan.scanNo)}`}>
                  <Button size="small" icon={<ExportOutlined />}>
                    查看本次样本
                  </Button>
                </Link>
              </div>
            </Col>
          </Row>
        </Card>
      ) : null}

      <Card className="stat-card" style={{ marginTop: 16 }} title="模型服务状态">
        <Row gutter={[16, 16]}>
          <Col xs={24} md={12}>
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="服务地址">
                <span className="mono">{status?.url ?? '-'}</span>
              </Descriptions.Item>
              <Descriptions.Item label="在线状态">
                {status?.online ? <Badge status="success" text="在线" /> : <Badge status="error" text="离线" />}
              </Descriptions.Item>
              <Descriptions.Item label="模型名">{status?.modelName ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="权重路径">
                <span className="mono" style={{ fontSize: 12 }}>{status?.checkpoint ?? '-'}</span>
              </Descriptions.Item>
              <Descriptions.Item label="运行设备">{status?.devices?.join(', ') ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="降级策略">
                <Tag color={status?.fallbackMode === 'strict' ? 'red' : 'orange'}>{status?.fallbackMode}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="探测时间">{formatTime(status?.checkedAt)}</Descriptions.Item>
            </Descriptions>
          </Col>
          <Col xs={24} md={12}>
            <Alert
              type="info"
              showIcon
              message="如何接入已训练好的 ScanMan 模型"
              description={
                <div style={{ fontSize: 12.5, lineHeight: 1.9 }}>
                  <div>1. 在 <span className="code-inline">model-service/</span> 下准备 Python 环境并安装依赖</div>
                  <div>
                    2. 通过 <span className="code-inline">DETECTION_CHECKPOINT</span> /{' '}
                    <span className="code-inline">CLASSIFICATION_CHECKPOINT</span> 指向训练产物{' '}
                    <span className="code-inline">outputs/&lt;run&gt;/best</span>
                  </div>
                  <div>3. 启动推理服务，本页顶部状态会变为「在线」</div>
                  <div>
                    4. 平台后端通过 <span className="code-inline">ML_SERVICE_URL</span> 代理调用，前端不直连模型
                  </div>
                  <div className="text-muted">
                    详见 <span className="code-inline">model-service/README.md</span>
                  </div>
                </div>
              }
            />
          </Col>
        </Row>
      </Card>

      <Card className="stat-card" style={{ marginTop: 16 }} title="代码片段预览（当前输入）">
        {code ? (
          <div className="code-block">
            <SyntaxHighlighter
              language={form.getFieldValue('language')?.toLowerCase() ?? 'text'}
              style={oneLight}
              showLineNumbers
              wrapLongLines
            >
              {code}
            </SyntaxHighlighter>
          </div>
        ) : (
          <Empty description="暂无代码" />
        )}
      </Card>
    </>
  );
}
