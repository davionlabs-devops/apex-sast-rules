/**
 * @name ScriptEngine 任意代码执行
 * @description 远端输入流入 javax.script ScriptEngine.eval → 脚本引擎任意代码执行 (CWE-94)。
 * @kind path-problem
 * @id apex/java-script-eval-injection
 * @problem.severity error
 * @security-severity 9.8
 * @tags security external/cwe/cwe-94
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

module ApexScriptEvalCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      mc.getMethod().hasName("eval") and
      mc.getMethod().getDeclaringType().getASupertype*().getQualifiedName() = "javax.script.ScriptEngine" and
      sink.asExpr() = mc.getAnArgument()
    )
  }
}

module ApexScriptEvalFlow = TaintTracking::Global<ApexScriptEvalCfg>;

import ApexScriptEvalFlow::PathGraph

from ApexScriptEvalFlow::PathNode source, ApexScriptEvalFlow::PathNode sink
where ApexScriptEvalFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "ScriptEngine 任意代码执行: 远端输入流入 eval (CWE-94); 脚本内容须固定/白名单."
