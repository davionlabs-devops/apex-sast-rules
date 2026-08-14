/**
 * @name Go 脚本引擎任意代码执行(yaegi 等)
 * @description 远端输入流入 Eval 脚本求值(yaegi interp.Eval 等) → 解释器 RCE (CWE-94)。
 * @kind path-problem
 * @id apex/go-script-eval-injection
 * @problem.severity error
 * @security-severity 9.8
 * @tags security external/cwe/cwe-94
 */
import go

module ApexGoEvalCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CallExpr ce |
      ce.getTarget().getName().regexpMatch("^(Eval|EvalScript|EvalString)$") and
      sink.asExpr() = ce.getAnArgument()
    )
  }
}

module ApexGoEvalFlow = TaintTracking::Global<ApexGoEvalCfg>;

import ApexGoEvalFlow::PathGraph

from ApexGoEvalFlow::PathNode source, ApexGoEvalFlow::PathNode sink
where ApexGoEvalFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Go 脚本引擎 RCE: 远端输入流入 Eval (CWE-94); 脚本内容须服务端固定."
