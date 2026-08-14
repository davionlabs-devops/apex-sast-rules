/**
 * @name Python 不安全反序列化 (pickle/yaml)
 * @description 远端输入流入 pickle.loads/cPickle.loads/yaml.load → 反序列化 RCE
 *              (CWE-502; yaml 无 SafeLoader 时任意对象构造)。
 * @kind path-problem
 * @id apex/py-deser-pickle-yaml
 * @problem.severity error
 * @tags security external/cwe/cwe-502
 */
import python
import semmle.code.python.dataflow.TaintTracking
import semmle.code.python.dataflow.FlowSources

class ApexPyDeserFlow extends TaintTracking::Configuration {
  ApexPyDeserFlow() { this = "ApexPyDeserFlow" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Function f, Call c |
      c = f.getACall() and
      sink.asExpr() = c.getArg(0) and
      (
        f = API::moduleImport("pickle").getFunction("loads") or
        f = API::moduleImport("pickle").getFunction("load") or
        f = API::moduleImport("_pickle").getFunction("loads") or
        f = API::moduleImport("cPickle").getFunction("loads") or
        f = API::moduleImport("yaml").getFunction("load")
      ))
  }
}

from ApexPyDeserFlow cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Python 不安全反序列化: 远端输入流入 pickle/yaml.load (CWE-502); yaml 须 SafeLoader, pickle 禁用于不可信输入."
