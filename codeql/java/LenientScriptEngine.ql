import java

/**
 * @name 脚本引擎 eval 调用 (宽松, sink 即报)
 * @description 任意 javax.script ScriptEngine.eval 调用 (CWE-94)。
 * @kind problem
 * @id apex/l-java-scriptengine-anyuse
 * @problem.severity warning
 * @security-severity 3.0
 * @tags security external/cwe/cwe-94 lenient
 */
from MethodCall mc
where
  mc.getMethod().hasName("eval") and
  mc.getMethod().getDeclaringType().getASupertype*().getQualifiedName().regexpMatch(
    "javax\\.script\\..*")
select mc, "ScriptEngine.eval 调用(宽松): " + mc.getEnclosingCallable().getName() +
  " — 确认脚本内容非用户可控"
