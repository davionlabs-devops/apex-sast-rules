/**
 * @name SpEL 表达式注入
 * @description 远端输入流入 SpelExpressionParser.parseExpression → SpEL 注入 RCE (CWE-94)。
 * @kind path-problem
 * @id apex/java-spel-injection
 * @problem.severity error
 * @security-severity 9.8
 * @tags security external/cwe/cwe-94
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

module ApexSpelCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      mc.getMethod().hasName("parseExpression") and
      mc.getMethod().getDeclaringType().getASupertype*().getQualifiedName().regexpMatch(
        "org\\.springframework\\.expression\\..*") and
      sink.asExpr() = mc.getAnArgument()
    )
  }
}

module ApexSpelFlow = TaintTracking::Global<ApexSpelCfg>;

import ApexSpelFlow::PathGraph

from ApexSpelFlow::PathNode source, ApexSpelFlow::PathNode sink
where ApexSpelFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "SpEL 注入: 远端输入流入表达式解析 (CWE-94); 确认使用 SimpleEvaluationContext 或表达式不含用户输入."
