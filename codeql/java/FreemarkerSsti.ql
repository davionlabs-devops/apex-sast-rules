/**
 * @name FreeMarker SSTI
 * @description 远端输入作为 FreeMarker 模板内容 (new Template(name, userInput, cfg)) →
 *              服务端模板注入 RCE (CWE-1336); fastjson gadget 链环节。
 * @kind path-problem
 * @id apex/java-freemarker-ssti
 * @problem.severity error
 * @security-severity 9.8
 * @tags security external/cwe/cwe-1336
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

module ApexFreemarkerCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(NewClassExpr ne |
      ne.getConstructor().getDeclaringType().(RefType).getASupertype*().getQualifiedName() = "freemarker.template.Template" and
      ne.getArgument(1) = sink.asExpr()
    )
  }
}

module ApexFreemarkerFlow = TaintTracking::Global<ApexFreemarkerCfg>;

import ApexFreemarkerFlow::PathGraph

from ApexFreemarkerFlow::PathNode source, ApexFreemarkerFlow::PathNode sink
where ApexFreemarkerFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "FreeMarker SSTI: 远端输入作为模板内容 (CWE-1336); 模板须服务端固定, 用户输入只做数据."
