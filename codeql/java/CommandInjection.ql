/**
 * @name 命令注入 (Runtime.exec / ProcessBuilder)
 * @description 远端输入未经净化流入进程执行 sink → 任意命令执行 (CWE-78)。
 * @kind path-problem
 * @id apex/java-cmd-injection
 * @problem.severity error
 * @tags security external/cwe/cwe-78
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

class ApexCmdInjectionFlow extends TaintTracking::Configuration {
  ApexCmdInjectionFlow() { this = "ApexCmdInjectionFlow" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      mc.getMethod().hasName("exec") and
      mc.getMethod().getDeclaringType().getASupertype*().getQualifiedName() = "java.lang.Runtime" and
      sink.asExpr() = mc.getAnArgument()
    )
    or
    exists(NewClassExpr ne |
      ne.getConstructor().getDeclaringType().getASupertype*().getQualifiedName() = "java.lang.ProcessBuilder" and
      sink.asExpr() = ne.getAnArgument()
    )
  }
}

from ApexCmdInjectionFlow cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "命令注入: 远端输入流入 Runtime.exec/ProcessBuilder (CWE-78)."
