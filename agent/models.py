from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

class TaskState(str, Enum):
    PENDING = "PENDING"
    PLANNING = "PLANNING"
    EXECUTING = "EXECUTING"
    REVIEWING = "REVIEWING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class ComponentKind(str, Enum):
    """Product-level component taxonomy; names describe behavior, not branding."""

    LLM_AGENT = "llm-agent"
    TOOL_SCANNER = "tool-scanner"
    GATE = "gate"

@dataclass
class ChangedLine:
    path: str
    line: int
    content: str


#这是代码审查的核心数据结构。它不仅记录了问题在哪里，还包含了 AI 或审查工具给出的解释、修复建议、测试建议以及置信度等丰富的上下文信息。
@dataclass
class Finding:
    rule_id: str # 触发此问题的规则ID
    severity: Severity # 问题的严重级别
    title: str  # 问题标题
    explanation: str  # 问题的详细解释
    path: str  # 出现问题的文件路径
    line: int  # 出现问题的行号
    evidence: str  # 证明该问题的代码证据
    fix: str  # 修复建议
    test: str   # 验证修复的测试用例建议
    confidence: float = 0.8  # AI 或工具对该发现的置信度（默认 0.8）
    evidence_refs: List[Dict[str, Any]] = field(default_factory=list)  # 证据引用的列表
    call_chain: List[Dict[str, Any]] = field(default_factory=list)  # 调用链信息
    source: str = "unknown"  # 发现的来源
    gate: Dict[str, Any] = field(default_factory=dict)   # 相关的门禁检查信息

    def to_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["severity"] = self.severity.value
        return value

#这是最终生成的审查报告结构。它汇总了仓库信息、整体风险、所有具体的 Finding 以及审查过程的元数据。
@dataclass
class ReviewReport:
    repository: str
    pull_request: Optional[int]
    summary: str
    risk: str
    findings: List[Finding] = field(default_factory=list)
    files_reviewed: List[str] = field(default_factory=list)
    reviewer: str = "local-rules"
    collaboration: Dict[str, Any] = field(default_factory=dict)
    run_mode: Dict[str, Any] = field(default_factory=dict)
    components: List[Dict[str, Any]] = field(default_factory=list)
    execution: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repository": self.repository,
            "pull_request": self.pull_request,
            "summary": self.summary,
            "risk": self.risk,
            "findings": [item.to_dict() for item in self.findings],
            "files_reviewed": self.files_reviewed,
            "reviewer": self.reviewer,
            "collaboration": self.collaboration,
            "run_mode": self.run_mode,
            "components": self.components,
            "execution": self.execution,
        }

@dataclass
class TraceEvent:
    step: int # 步骤序号
    state: TaskState  # 当前任务状态
    message: str  # 状态消息/日志
    created_at: str # 事件创建时间

    def to_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["state"] = self.state.value
        return value
