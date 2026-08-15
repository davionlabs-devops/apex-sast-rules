/**
 * @name Go 路径穿越
 * @description 远端输入流入文件系统操作(os.Open/Create/OpenFile/ReadFile/WriteFile/Remove/Mkdir 等) (CWE-22)。
 * @kind path-problem
 * @id apex/go-path-traversal
 * @problem.severity warning
 * @security-severity 7.5
 * @tags security external/cwe/cwe-22
 */
import go

module ApexGoPathCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CallExpr ce |
      ce.getTarget().getQualifiedName().regexpMatch(
        "^(os|io/ioutil)\\.(Open|OpenFile|Create|CreateTemp|ReadFile|WriteFile|Remove|RemoveAll|Mkdir|MkdirAll)$") and
      sink.asExpr() = ce.getAnArgument()
    )
  }
}

module ApexGoPathFlow = TaintTracking::Global<ApexGoPathCfg>;

import ApexGoPathFlow::PathGraph

from ApexGoPathFlow::PathNode source, ApexGoPathFlow::PathNode sink
where ApexGoPathFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Go 路径穿越: 远端输入流入文件系统路径 (CWE-22); 须 filepath.Clean + 前缀白名单校验."
