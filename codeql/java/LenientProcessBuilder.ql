import java

/**
 * @name ProcessBuilder 构造 (宽松, sink 即报)
 * @description 任意 java.lang.ProcessBuilder 构造 (CWE-78)。
 * @kind problem
 * @id apex/l-java-processbuilder-anyuse
 * @problem.severity warning
 * @security-severity 3.0
 * @tags security external/cwe/cwe-78 lenient
 */
from ClassInstanceExpr cie
where
  cie.getConstructor().getDeclaringType().getQualifiedName() = "java.lang.ProcessBuilder"
select cie, "ProcessBuilder 构造(宽松): " + cie.getEnclosingCallable().getName() +
  " — 确认命令及参数非用户可控"
