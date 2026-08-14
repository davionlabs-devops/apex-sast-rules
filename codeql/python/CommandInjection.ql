/**
 * @name Python 命令注入
 * @description 远端输入流入 os.system/os.popen/subprocess.* (官方 SystemCommandExecution 概念) (CWE-78)。
 * @kind path-problem
 * @id apex/py-cmd-injection
 * @problem.severity error
 * @security-severity 9.8
 * @tags security external/cwe/cwe-78
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.Concepts

module ApexPyCmdCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof SystemCommandExecution
  }
}

module ApexPyCmdFlow = TaintTracking::Global<ApexPyCmdCfg>;

import ApexPyCmdFlow::PathGraph

from ApexPyCmdFlow::PathNode source, ApexPyCmdFlow::PathNode sink
where ApexPyCmdFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Python 命令注入: 远端输入流入 os/subprocess 执行 (CWE-78); 须列表传参+白名单."
