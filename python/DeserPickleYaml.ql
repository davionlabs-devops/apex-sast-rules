/**
 * @name Python 不安全反序列化 (pickle/yaml)
 * @description 远端输入流入 pickle.loads/yaml.load → 反序列化 RCE
 *              (CWE-502; yaml 无 SafeLoader 时任意对象构造)。
 * @kind path-problem
 * @id apex/py-deser-pickle-yaml
 * @problem.severity error
 * @security-severity 9.8
 * @tags security external/cwe/cwe-502
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.ApiGraphs

module ApexPyDeserCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink = API::moduleImport("pickle").getMember("loads").getParameter(0).asSink()
    or
    sink = API::moduleImport("pickle").getMember("load").getParameter(0).asSink()
    or
    sink = API::moduleImport("_pickle").getMember("loads").getParameter(0).asSink()
    or
    sink = API::moduleImport("cPickle").getMember("loads").getParameter(0).asSink()
    or
    sink = API::moduleImport("yaml").getMember("load").getParameter(0).asSink()
  }
}

module ApexPyDeserFlow = TaintTracking::Global<ApexPyDeserCfg>;

import ApexPyDeserFlow::PathGraph

from ApexPyDeserFlow::PathNode source, ApexPyDeserFlow::PathNode sink
where ApexPyDeserFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Python 不安全反序列化: 远端输入流入 pickle/yaml.load (CWE-502); yaml 须 SafeLoader, pickle 禁用于不可信输入."
