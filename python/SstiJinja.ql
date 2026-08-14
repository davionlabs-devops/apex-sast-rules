/**
 * @name Python SSTI (Jinja2/Flask)
 * @description 远端输入流入 flask.render_template_string / jinja2 Environment.from_string →
 *              模板注入 RCE (CWE-1336)。
 * @kind path-problem
 * @id apex/py-ssti-jinja
 * @problem.severity error
 * @security-severity 9.8
 * @tags security external/cwe/cwe-1336
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.ApiGraphs

module ApexPySstiCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink = API::moduleImport("flask").getMember("render_template_string").getACall().getArg(0)
    or
    sink = API::moduleImport("jinja2").getMember("Environment").getMember("from_string").getACall().getArg(0)
  }
}

module ApexPySstiFlow = TaintTracking::Global<ApexPySstiCfg>;

import ApexPySstiFlow::PathGraph

from ApexPySstiFlow::PathNode source, ApexPySstiFlow::PathNode sink
where ApexPySstiFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Python SSTI: 远端输入作为模板字符串 (CWE-1336); 用户输入须作渲染数据而非模板."
