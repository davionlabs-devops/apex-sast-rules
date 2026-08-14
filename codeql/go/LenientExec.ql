import go

/**
 * @name Go 命令执行 (宽松, sink 即报)
 * @description 任意 os/exec Command/CommandContext 调用 (CWE-78)。
 * @kind problem
 * @id apex/l-go-exec-anyuse
 * @problem.severity warning
 * @security-severity 3.0
 * @tags security external/cwe/cwe-78 lenient
 */
from CallExpr ce
where
  ce.getTarget().getName().regexpMatch("^(Command|CommandContext)$") and
  ce.getTarget().getQualifiedName().regexpMatch("^os/exec\\..*")
select ce, "exec.Command 调用(宽松): " + ce.getEnclosingFunction().getName() +
  " — 确认命令及参数非用户可控"
