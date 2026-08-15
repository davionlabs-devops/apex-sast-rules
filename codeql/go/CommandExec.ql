/**
 * @name Go 命令执行 (os/exec)
 * @description exec.Command / exec.CommandContext 调用点 — 复核参数是否拼接远端输入
 *              (命令注入, CWE-78)。Go 侧先报调用点, 污点精度迭代再补。
 * @kind problem
 * @id apex/go-cmd-exec
 * @problem.severity warning
 * @tags security external/cwe/cwe-78
 */
import go

from CallExpr call
where call.getTarget().getQualifiedName().regexpMatch("^os/exec\\.(Command|CommandContext)$")
select call, "os/exec 命令执行调用点 — 复核参数是否拼接远端输入 (CWE-78)."
