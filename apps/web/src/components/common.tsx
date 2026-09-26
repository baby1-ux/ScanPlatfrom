import React from 'react';
import { Tag, Tooltip } from 'antd';
import dayjs from 'dayjs';
import {
  SAMPLE_LABEL_META,
  SCAN_STATUS_META,
  SEVERITY_META,
  VULN_STATUS_META,
  REPO_TYPE_META,
  type RepoType,
  type SampleLabel,
  type ScanStatus,
  type Severity,
  type VulnStatus,
} from '@vuln/shared';

/** 等级标签：语义色 + 严重度圆点（docs/01 第 11.3 节色板） */
export function SeverityTag({ severity, showDot = true }: { severity: Severity; showDot?: boolean }) {
  const meta = SEVERITY_META[severity] ?? { label: severity, color: '#8c8c8c' };
  return (
    <Tag
      style={{
        color: meta.color,
        borderColor: `${meta.color}55`,
        background: `${meta.color}12`,
        fontWeight: 600,
      }}
    >
      {showDot ? <span className="severity-dot" style={{ background: meta.color }} /> : null}
      {meta.label}
    </Tag>
  );
}

export function StatusTag({ status }: { status: VulnStatus }) {
  const meta = VULN_STATUS_META[status];
  if (!meta) return <Tag>{status}</Tag>;
  return <Tag color={meta.color}>{meta.label}</Tag>;
}

export function ScanStatusTag({ status }: { status: ScanStatus }) {
  const meta = SCAN_STATUS_META[status];
  if (!meta) return <Tag>{status}</Tag>;
  return <Tag color={meta.color}>{meta.label}</Tag>;
}

export function SampleLabelTag({ label }: { label: SampleLabel }) {
  const meta = SAMPLE_LABEL_META[label];
  if (!meta) return <Tag>{label}</Tag>;
  return (
    <Tag color={label === 'positive' ? 'red' : 'green'}>
      {label === 'positive' ? '正样本' : '负样本'}
    </Tag>
  );
}

export function RepoTypeTag({ repoType }: { repoType: RepoType | string | null | undefined }) {
  if (!repoType) return <span className="text-muted">-</span>;
  const meta = REPO_TYPE_META[repoType as RepoType];
  return <Tag color={meta?.color ?? 'default'}>{meta?.label ?? repoType}</Tag>;
}

/** 时间统一按浏览器时区展示（存储为 UTC ISO8601） */
export function formatTime(value: string | null | undefined, fmt = 'YYYY-MM-DD HH:mm'): string {
  if (!value) return '-';
  const d = dayjs(value);
  return d.isValid() ? d.format(fmt) : String(value);
}

export function formatRelative(value: string | null | undefined): string {
  if (!value) return '-';
  const d = dayjs(value);
  return d.isValid() ? d.fromNow() : String(value);
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return '-';
  if (ms < 1000) return `${ms}ms`;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rest = s % 60;
  if (m < 60) return `${m}m ${rest}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

export function formatNumber(n: number | null | undefined): string {
  if (n === null || n === undefined) return '-';
  return n.toLocaleString('zh-CN');
}

/** 文件路径 + 行号 */
export function FileLocation({
  filePath,
  lineStart,
  lineEnd,
}: {
  filePath: string;
  lineStart?: number | null;
  lineEnd?: number | null;
}) {
  const range =
    lineStart && lineEnd
      ? lineStart === lineEnd
        ? `L${lineStart}`
        : `L${lineStart}-${lineEnd}`
      : lineStart
        ? `L${lineStart}`
        : '';
  return (
    <Tooltip title={filePath}>
      <span className="mono" style={{ wordBreak: 'break-all' }}>
        {filePath}
        {range ? <span style={{ color: '#8c8c8c' }}>:{range}</span> : null}
      </span>
    </Tooltip>
  );
}

export function PageHeader({
  title,
  subtitle,
  extra,
}: {
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  extra?: React.ReactNode;
}) {
  return (
    <div
      className="page-header"
      style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}
    >
      <div>
        <h2>{title}</h2>
        {subtitle ? <div className="sub">{subtitle}</div> : null}
      </div>
      {extra ? <div>{extra}</div> : null}
    </div>
  );
}
