/**
 * @name Velocity SSTI
 * @description 远端输入流入 Velocity/VelocityEngine.evaluate 或 mergeTemplate →
 *              模板注入 RCE (CWE-1336)。
 * @kind path-problem
 * @id apex/java-velocity-ssti
 * @problem.severity error
 * @security-severity 9.8
 * @tags security external/cwe/cwe-1336
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

module ApexVelocityCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      mc.getMethod().getName().regexpMatch("evaluate|mergeTemplate") and
      mc.getMethod().getDeclaringType().getASupertype*().getQualifiedName().regexpMatch(
        "org\\.apache\\.velocity(\\.app)?\\.(VelocityEngine|Velocity)") and
      sink.asExpr() = mc.getAnArgument()
    )
  }
}

module ApexVelocityFlow = TaintTracking::Global<ApexVelocityCfg>;

import ApexVelocityFlow::PathGraph

from ApexVelocityFlow::PathNode source, ApexVelocityFlow::PathNode sink
where ApexVelocityFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Velocity SSTI: 远端输入流入模板求值 (CWE-1336)."
