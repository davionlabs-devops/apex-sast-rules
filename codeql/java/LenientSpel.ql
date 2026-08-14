/**
 * @name SpEL 表达式解析调用 (宽松, sink 即报)
 * @description 任意 SpelExpressionParser.parseExpression 调用, 不要求 taint。
 *              注解常量等静态场景为误报, 由人工二次筛查。
 * @kind problem
 * @id apex/l-java-spel-anyuse
 * @problem.severity warning
 * @security-severity 3.0
 * @tags security external/cwe/cwe-94 lenient
 */
import java

from MethodCall mc
where
  mc.getMethod().hasName("parseExpression") and
  mc.getMethod().getDeclaringType().getASupertype*().getQualifiedName().regexpMatch(
    "org\\.springframework\\.expression\\..*")
select mc, "SpEL 解析调用(宽松): " + mc.getEnclosingCallable().getName() +
  " — 确认表达式非用户可控且使用 SimpleEvaluationContext"
