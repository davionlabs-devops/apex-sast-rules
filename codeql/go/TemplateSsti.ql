/**
 * @name Go 模板注入(SSTI)
 * @description 远端输入作为 text/template / html/template 模板源(Parse) → 模板注入 (CWE-1336)。
 *              Go 模板可调用导出方法, 污染模板源即攻击面。
 * @kind path-problem
 * @id apex/go-template-ssti
 * @problem.severity warning
 * @tags security external/cwe/cwe-1336
 */
import go
import semmle.code.go.dataflow.TaintTracking
import semmle.code.go.dataflow.FlowSources

class ApexGoTplFlow extends TaintTracking::Configuration {
  ApexGoTplFlow() { this = "ApexGoTplFlow" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink = API::moduleImport("text/template").getMember("Template").getMember("Parse").getACall().getAnArgument()
    or
    sink = API::moduleImport("text/template").getFunction("ParseFiles").getACall().getAnArgument()
    or
    sink = API::moduleImport("text/template").getFunction("ParseGlob").getACall().getAnArgument()
    or
    sink = API::moduleImport("html/template").getMember("Template").getMember("Parse").getACall().getAnArgument()
    or
    sink = API::moduleImport("html/template").getFunction("ParseFiles").getACall().getAnArgument()
    or
    sink = API::moduleImport("html/template").getFunction("ParseGlob").getACall().getAnArgument()
  }
}

from ApexGoTplFlow cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Go SSTI: 远端输入作为模板源 (CWE-1336); 用户输入须作渲染数据, 模板须服务端固定."
