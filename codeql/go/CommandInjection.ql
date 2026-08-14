/**
 * @name Go 命令注入(污点)
 * @description 远端输入(net/http)流入 os/exec.Command/CommandContext 参数 → 命令注入 (CWE-78)。
 *              与 CommandExec.ql(调用点清单)互补: 本规则只报有污点路径的。
 * @kind path-problem
 * @id apex/go-cmd-injection
 * @problem.severity error
 * @tags security external/cwe/cwe-78
 */
import go
import semmle.code.go.dataflow.TaintTracking
import semmle.code.go.dataflow.FlowSources

class ApexGoCmdFlow extends TaintTracking::Configuration {
  ApexGoCmdFlow() { this = "ApexGoCmdFlow" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink = API::moduleImport("os/exec").getFunction("Command").getACall().getAnArgument()
    or
    sink = API::moduleImport("os/exec").getFunction("CommandContext").getACall().getAnArgument()
  }
}

from ApexGoCmdFlow cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Go 命令注入: 远端输入流入 os/exec.Command (CWE-78); 参数须逐个传递且白名单子命令."
