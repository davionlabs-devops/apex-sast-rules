/**
 * @name 不安全反序列化(远端输入构造流)
 * @description 远端输入流入 new ObjectInputStream/HessianInput/Hessian2Input(...) →
 *              Java/Hessian 反序列化 RCE (CWE-502)。
 * @kind path-problem
 * @id apex/java-deser-tainted
 * @problem.severity error
 * @tags security external/cwe/cwe-502
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

class ApexDeserFlow extends TaintTracking::Configuration {
  ApexDeserFlow() { this = "ApexDeserFlow" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(NewClassExpr ne |
      ne.getType().getASupertype*().getName().regexpMatch("ObjectInputStream|HessianInput|Hessian2Input") and
      sink.asExpr() = ne.getAnArgument()
    )
  }
}

from ApexDeserFlow cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "不安全反序列化: 远端输入构造 ObjectInputStream/Hessian 流 (CWE-502); 须白名单 ObjectInputFilter."
