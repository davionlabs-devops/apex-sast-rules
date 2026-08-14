/**
 * @name Python 命令注入
 * @description 远端输入流入 os.system/os.popen/subprocess.* → 命令执行 (CWE-78)。
 * @kind path-problem
 * @id apex/py-cmd-injection
 * @problem.severity error
 * @tags security external/cwe/cwe-78
 */
import python
import semmle.code.python.dataflow.TaintTracking
import semmle.code.python.dataflow.FlowSources

class ApexPyCmdFlow extends TaintTracking::Configuration {
  ApexPyCmdFlow() { this = "ApexPyCmdFlow" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Function f, Call c |
      c = f.getACall() and
      sink.asExpr() = c.getArg(_) and
      (
        f = API::moduleImport("os").getFunction("system") or
        f = API::moduleImport("os").getFunction("popen") or
        f = API::moduleImport("subprocess").getFunction("run") or
        f = API::moduleImport("subprocess").getFunction("call") or
        f = API::moduleImport("subprocess").getFunction("check_call") or
        f = API::moduleImport("subprocess").getFunction("check_output") or
        f = API::moduleImport("subprocess").getFunction("Popen") or
        f = API::moduleImport("subprocess").getFunction("getoutput") or
        f = API::moduleImport("subprocess").getFunction("getstatusoutput")
      ))
  }
}

from ApexPyCmdFlow cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Python 命令注入: 远端输入流入 os/subprocess 执行 (CWE-78)."
