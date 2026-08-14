import java

/**
 * @name Velocity 模板求值调用 (宽松, sink 即报)
 * @description 任意 Velocity evaluate/mergeTemplate 调用 (CWE-1336)。
 * @kind problem
 * @id apex/l-java-velocity-anyuse
 * @problem.severity warning
 * @security-severity 3.0
 * @tags security external/cwe/cwe-1336 lenient
 */
from MethodCall mc
where
  mc.getMethod().getName().regexpMatch("^(evaluate|mergeTemplate)$") and
  mc.getMethod().getDeclaringType().getASupertype*().getQualifiedName().regexpMatch(
    "org\\.apache\\.velocity\\..*")
select mc, "Velocity 求值调用(宽松): " + mc.getEnclosingCallable().getName() +
  " — 确认模板内容服务端固定"
