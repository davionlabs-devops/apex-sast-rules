import java

/**
 * @name FreeMarker 模板构造 (宽松, sink 即报)
 * @description 任意 freemarker.template.Template 构造调用 (CWE-1336)。
 * @kind problem
 * @id apex/l-java-freemarker-anyuse
 * @problem.severity warning
 * @security-severity 3.0
 * @tags security external/cwe/cwe-1336 lenient
 */
from ClassInstanceExpr cie
where
  cie.getConstructor().getDeclaringType().getQualifiedName() = "freemarker.template.Template"
select cie, "FreeMarker 模板构造(宽松): " + cie.getEnclosingCallable().getName() +
  " — 确认模板来源非用户输入"
