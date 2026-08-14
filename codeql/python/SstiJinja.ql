/**
 * @name Python SSTI (Jinja2/Flask)
 * @description 远端输入流入 render_template_string / Environment.from_string →
 *              模板注入 RCE (CWE-1336)。
 * @kind path-problem
 * @id apex/py-ssti-jinja
 * @problem.severity error
 * @tags security external/cwe/cwe-1336
 */
import python
import semmle.code.python.dataflow.TaintTracking
import semmle.code.python.dataflow.FlowSources

class ApexPySstiFlow extends TaintTracking::Configuration {
  ApexPySstiFlow() { this = "ApexPySstiFlow" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Function f, Call c |
      c = f.getACall() and
      sink.asExpr() = c.getArg(0) and
      f = API::moduleImport("flask").getFunction("render_template_string"))
    or
    exists(Call c |
      c.getFunc().(Name).getId() = "from_string" and
      sink.asExpr() = c.getArg(0))
  }
}

from ApexPySstiFlow cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Python SSTI: 远端输入作为模板字符串 (CWE-1336); 用户输入须作渲染数据而非模板."
