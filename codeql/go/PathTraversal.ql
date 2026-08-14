/**
 * @name Go 路径穿越
 * @description 远端输入流入 os/io/ioutil 文件读写路径参数 → 任意文件读写 (CWE-22)。
 * @kind path-problem
 * @id apex/go-path-traversal
 * @problem.severity error
 * @tags security external/cwe/cwe-22
 */
import go
import semmle.code.go.dataflow.TaintTracking
import semmle.code.go.dataflow.FlowSources

class ApexGoPathFlow extends TaintTracking::Configuration {
  ApexGoPathFlow() { this = "ApexGoPathFlow" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink = API::moduleImport("os").getFunction("ReadFile").getACall().getAnArgument()
    or
    sink = API::moduleImport("os").getFunction("WriteFile").getACall().getAnArgument()
    or
    sink = API::moduleImport("os").getFunction("Create").getACall().getAnArgument()
    or
    sink = API::moduleImport("os").getFunction("Open").getACall().getAnArgument()
    or
    sink = API::moduleImport("os").getFunction("OpenFile").getACall().getAnArgument()
    or
    sink = API::moduleImport("io/ioutil").getFunction("ReadFile").getACall().getAnArgument()
    or
    sink = API::moduleImport("io/ioutil").getFunction("WriteFile").getACall().getAnArgument()
  }
}

from ApexGoPathFlow cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Go 路径穿越: 远端输入流入文件路径 (CWE-22); 须 filepath.Clean + 前缀白名单校验."
