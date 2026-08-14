import java

/**
 * @name Java 原生反序列化 readObject (宽松, sink 即报)
 * @description 任意 java.io.ObjectInput* readObject 调用 (CWE-502)。
 * @kind problem
 * @id apex/l-java-deser-anyuse
 * @problem.severity warning
 * @security-severity 3.0
 * @tags security external/cwe/cwe-502 lenient
 */
from MethodCall mc
where
  mc.getMethod().hasName("readObject") and
  mc.getMethod().getDeclaringType().getASupertype*().getQualifiedName().regexpMatch(
    "java\\.io\\.(ObjectInputStream|ObjectInput)")
select mc, "readObject 反序列化(宽松): " + mc.getEnclosingCallable().getName() +
  " — 确认输入流来源可信"
