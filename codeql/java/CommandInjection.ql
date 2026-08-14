/**
 * @name 命令注入 (Runtime.exec / ProcessBuilder)
 * @description 远端输入未经净化流入进程执行 sink → 任意命令执行 (CWE-78)。
 * @kind path-problem
 * @id apex/java-cmd-injection
 * @problem.severity error
 * @security-severity 9.8
 * @tags security external/cwe/cwe-78
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

module ApexCmdCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      mc.getMethod().hasName("exec") and
      mc.getMethod().getDeclaringType().getASupertype*().getQualifiedName() = "java.lang.Runtime" and
      sink.asExpr() = mc.getAnArgument()
    )
    or
    exists(NewClassExpr ne |
      ne.getConstructor().getDeclaringType().(RefType).getASupertype*().getQualifiedName() = "java.lang.ProcessBuilder" and
      sink.asExpr() = ne.getAnArgument()
    )
  }
}

module ApexCmdFlow = TaintTracking::Global<ApexCmdCfg>;

import ApexCmdFlow::PathGraph

from ApexCmdFlow::PathNode source, ApexCmdFlow::PathNode sink
where ApexCmdFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "命令注入: 远端输入流入 Runtime.exec/ProcessBuilder (CWE-78)."
