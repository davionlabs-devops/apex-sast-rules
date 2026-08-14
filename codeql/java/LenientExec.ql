import java

/**
 * @name Java 命令执行 (宽松, sink 即报)
 * @description 任意 Runtime.exec / ProcessBuilder 构造 (CWE-78)。
 * @kind problem
 * @id apex/l-java-exec-anyuse
 * @problem.severity warning
 * @security-severity 3.0
 * @tags security external/cwe/cwe-78 lenient
 */
from MethodCall mc
where
  mc.getMethod().hasName("exec") and
  mc.getMethod().getDeclaringType().getASupertype*().getQualifiedName() = "java.lang.Runtime"
select mc, "Runtime.exec 调用(宽松): " + mc.getEnclosingCallable().getName() +
  " — 确认命令及参数非用户可控"
