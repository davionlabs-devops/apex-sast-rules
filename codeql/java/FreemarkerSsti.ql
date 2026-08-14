/**
 * @name FreeMarker SSTI
 * @description 远端输入作为 FreeMarker 模板内容 (new Template(name, userInput, cfg)) →
 *              服务端模板注入 RCE (CWE-1336); fastjson gadget 链环节。
 * @kind path-problem
 * @id apex/java-freemarker-ssti
 * @problem.severity error
 * @tags security external/cwe/cwe-1336
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

class ApexFreemarkerSstiFlow extends TaintTracking::Configuration {
  ApexFreemarkerSstiFlow() { this = "ApexFreemarkerSstiFlow" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(NewClassExpr ne |
      ne.getConstructor().getDeclaringType().getASupertype*().getQualifiedName() = "freemarker.template.Template" and
      ne.getArgument(1) = sink.asExpr()
    )
  }
}

from ApexFreemarkerSstiFlow cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "FreeMarker SSTI: 远端输入作为模板内容 (CWE-1336); 模板须服务端固定, 用户输入只做数据."
