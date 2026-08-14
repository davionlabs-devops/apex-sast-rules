/**
 * @name Go 不安全反序列化
 * @description 远端输入流入 Unmarshal/Decode 类调用(yaml/json/gob/toml 等, 按名匹配) (CWE-502)。
 * @kind path-problem
 * @id apex/go-deser-tainted
 * @problem.severity warning
 * @security-severity 7.5
 * @tags security external/cwe/cwe-502
 */
import go

module ApexGoDeserCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CallExpr ce |
      ce.getTarget().getName().regexpMatch("^(Unmarshal|UnmarshalStrict|UnmarshalYAML)$") and
      sink.asExpr() = ce.getAnArgument()
    )
  }
}

module ApexGoDeserFlow = TaintTracking::Global<ApexGoDeserCfg>;

import ApexGoDeserFlow::PathGraph

from ApexGoDeserFlow::PathNode source, ApexGoDeserFlow::PathNode sink
where ApexGoDeserFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Go 不安全反序列化: 远端输入流入 Unmarshal (CWE-502); 须校验来源与 schema."
