/**
 * @name 不安全反序列化(远端输入构造流)
 * @description 远端输入流入 new ObjectInputStream/HessianInput/Hessian2Input(...) →
 *              Java/Hessian 反序列化 RCE (CWE-502)。
 * @kind path-problem
 * @id apex/java-deser-tainted
 * @problem.severity error
 * @security-severity 9.8
 * @tags security external/cwe/cwe-502
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

module ApexDeserCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(NewClassExpr ne |
      ne.getConstructor().getDeclaringType().(RefType).getASupertype*().getName().regexpMatch(
        "ObjectInputStream|HessianInput|Hessian2Input") and
      sink.asExpr() = ne.getAnArgument()
    )
  }
}

module ApexDeserFlow = TaintTracking::Global<ApexDeserCfg>;

import ApexDeserFlow::PathGraph

from ApexDeserFlow::PathNode source, ApexDeserFlow::PathNode sink
where ApexDeserFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "不安全反序列化: 远端输入构造 ObjectInputStream/Hessian 流 (CWE-502); 须白名单 ObjectInputFilter."
