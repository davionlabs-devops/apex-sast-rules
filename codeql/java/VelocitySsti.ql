/**
 * @name Velocity SSTI
 * @description 远端输入流入 Velocity/VelocityEngine.evaluate 或 mergeTemplate →
 *              模板注入 RCE (CWE-1336)。
 * @kind path-problem
 * @id apex/java-velocity-ssti
 * @problem.severity error
 * @tags security external/cwe/cwe-1336
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

class ApexVelocitySstiFlow extends TaintTracking::Configuration {
  ApexVelocitySstiFlow() { this = "ApexVelocitySstiFlow" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      mc.getMethod().getName().regexpMatch("evaluate|mergeTemplate") and
      mc.getMethod().getDeclaringType().getASupertype*().getQualifiedName().regexpMatch(
        "org\\.apache\\.velocity(\\.app)?\\.(VelocityEngine|Velocity)") and
      sink.asExpr() = mc.getAnArgument()
    )
  }
}

from ApexVelocitySstiFlow cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Velocity SSTI: 远端输入流入模板求值 (CWE-1336)."
