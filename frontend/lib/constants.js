import {
  Shield, Activity, Terminal, AlertTriangle,
  CheckCircle, XCircle, Clock, WifiOff, ChevronRight,
  RefreshCw, Layers, Target, Zap,
  Eye, Lock, Globe, Cpu,
} from 'lucide-react'

export const SEVERITY_MAP = {
  critical: { label: 'CRITICAL', cls: 'severity-critical', dot: 'bg-red-400' },
  high:     { label: 'HIGH',     cls: 'severity-high',     dot: 'bg-orange-400' },
  medium:   { label: 'MEDIUM',   cls: 'severity-medium',   dot: 'bg-yellow-400' },
  low:      { label: 'LOW',      cls: 'severity-low',      dot: 'bg-blue-400' },
  info:     { label: 'INFO',     cls: 'severity-info',     dot: 'bg-zinc-500' },
}

export const EVENT_ICONS = {
  ENGAGEMENT_STARTED:   { icon: Zap,           color: 'text-emerald-400' },
  ENGAGEMENT_PLANNED:   { icon: Layers,        color: 'text-sky-400' },
  ENGAGEMENT_COMPLETED: { icon: CheckCircle,   color: 'text-emerald-400' },
  PHASE_STARTED:        { icon: ChevronRight,  color: 'text-sky-400' },
  PHASE_COMPLETED:      { icon: CheckCircle,   color: 'text-emerald-300' },
  AGENT_SPAWNED:        { icon: Cpu,           color: 'text-violet-400' },
  AGENT_RUNNING:        { icon: Activity,      color: 'text-sky-300' },
  AGENT_FINISHED:       { icon: CheckCircle,   color: 'text-emerald-400' },
  AGENT_FAILED:         { icon: XCircle,       color: 'text-red-400' },
  FINDING_CREATED:      { icon: AlertTriangle, color: 'text-orange-400' },
  FINDING_VERIFIED:     { icon: Eye,           color: 'text-sky-400' },
  FINDING_CLASSIFIED:   { icon: CheckCircle,   color: 'text-emerald-400' },
  GATE_CONFIRMATION_REQUIRED: { icon: Lock,   color: 'text-amber-400' },
  GATE_AUTO_APPROVED:   { icon: CheckCircle,   color: 'text-zinc-400' },
  OPERATOR_MESSAGE:     { icon: Terminal,      color: 'text-zinc-400' },
  KALI_UNREACHABLE:     { icon: WifiOff,       color: 'text-red-400' },
  TOOL_TIMEOUT:         { icon: Clock,         color: 'text-amber-400' },
  TOKEN_BUDGET_WARNING: { icon: AlertTriangle, color: 'text-amber-400' },
  LLM_FALLBACK:         { icon: RefreshCw,     color: 'text-amber-300' },
  SYSTEM_STARTED:       { icon: Shield,        color: 'text-emerald-400' },
  CVE_CORRELATED:       { icon: Globe,         color: 'text-sky-400' },
  ATTACK_MAPPED:        { icon: Target,        color: 'text-orange-400' },
}

export const REPORT_FORMATS_UI = [
  'executive', 'technical', 'remediation_roadmap',
  'developer_handoff', 'compliance_mapping', 'regression',
]
export const REPORT_FRAMEWORKS = ['NIST-CSF', 'PCI-DSS', 'GDPR', 'ISO27001', 'SOC2']
