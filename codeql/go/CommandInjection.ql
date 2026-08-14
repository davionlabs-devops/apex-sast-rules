/**
 * @name Go 命令注入
 * @description 远端输入流入命令执行(os/exec 及官方 SystemCommandExecution 概念覆盖面) (CWE-78)。
 * @kind path-problem
 * @id apex/go-cmd-injection
 * @problem.severity error
 * @security-severity 9.8
 * @tags security external/cwe/cwe-78
 */
import go

module ApexGoCmdCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof SystemCommandExecution
  }
}

module ApexGoCmdFlow = TaintTracking::Global<ApexGoCmdCfg>;

import ApexGoCmdFlow::PathGraph

from ApexGoCmdFlow::PathNode source, ApexGoCmdFlow::PathNode sink
where ApexGoCmdFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Go 命令注入: 远端输入流入命令执行 (CWE-78); 命令/参数须白名单, 勿拼接 shell."
