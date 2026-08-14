/**
 * @name JNDI lookup 调用 (宽松, sink 即报)
 * @description 任意 javax.naming / spring JndiTemplate lookup 调用 (CWE-50)。
 * @kind problem
 * @id apex/l-java-jndi-anyuse
 * @problem.severity warning
 * @security-severity 3.0
 * @tags security external/cwe/cwe-50 lenient
 */
import java

from MethodCall mc
where
  mc.getMethod().hasName("lookup") and
  mc.getMethod().getDeclaringType().getASupertype*().getQualifiedName().regexpMatch(
    "javax\\.naming\\..*|org\\.springframework\\.jndi\\..*")
select mc, "JNDI lookup 调用(宽松): " + mc.getEnclosingCallable().getName() +
  " — 确认 name 非用户可控(防 JNDI 注入)"
