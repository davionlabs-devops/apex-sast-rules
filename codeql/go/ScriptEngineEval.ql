/**
 * @name Go 脚本引擎任意代码执行
 * @description 远端输入流入 otto / goja / yaegi 脚本引擎 → 任意代码执行 (CWE-94)。
 * @kind path-problem
 * @id apex/go-script-eval-injection
 * @problem.severity error
 * @tags security external/cwe/cwe-94
 */
import go
import semmle.code.go.dataflow.TaintTracking
import semmle.code.go.dataflow.FlowSources

class ApexGoScriptFlow extends TaintTracking::Configuration {
  ApexGoScriptFlow() { this = "ApexGoScriptFlow" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    // otto (JS)
    sink = API::moduleImport("github.com/robertkrimen/otto").getMember("Otto").getMember("Run").getACall().getAnArgument()
    or
    sink = API::moduleImport("github.com/robertkrimen/otto").getMember("Otto").getMember("RunScript").getACall().getAnArgument()
    or
    sink = API::moduleImport("github.com/robertkrimen/otto").getMember("Otto").getMember("RunString").getACall().getAnArgument()
    // goja (JS)
    or
    sink = API::moduleImport("github.com/dop251/goja").getMember("Runtime").getMember("RunString").getACall().getAnArgument()
    or
    sink = API::moduleImport("github.com/dop251/goja").getMember("Runtime").getMember("RunProgram").getACall().getAnArgument()
    // yaegi (Go 解释器)
    or
    sink = API::moduleImport("github.com/traefik/yaegi/interp").getMember("Interpreter").getMember("Eval").getACall().getAnArgument()
  }
}

from ApexGoScriptFlow cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Go 脚本引擎任意代码执行: 远端输入流入 otto/goja/yaegi (CWE-94); 脚本内容须服务端固定."
