/**
 * @name Go 模板注入(text/template, html/template)
 * @description 远端输入流入模板内容构造(Parse/ParseFiles/ParseGlob) → SSTI (CWE-1336)。
 *              Go template 默认无函数逃逸, 主要风险是注入模板逻辑/数据泄露, 评 warning。
 * @kind path-problem
 * @id apex/go-template-ssti
 * @problem.severity warning
 * @security-severity 5.0
 * @tags security external/cwe/cwe-1336
 */
import go

module ApexGoTplCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(CallExpr ce |
      ce.getTarget().getName().regexpMatch("^(Parse|ParseFiles|ParseGlob|ParseFS)$") and
      sink.asExpr() = ce.getAnArgument()
    )
  }
}

module ApexGoTplFlow = TaintTracking::Global<ApexGoTplCfg>;

import ApexGoTplFlow::PathGraph

from ApexGoTplFlow::PathNode source, ApexGoTplFlow::PathNode sink
where ApexGoTplFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Go 模板注入: 远端输入流入模板内容 (CWE-1336); 模板须服务端固定, 用户输入只做数据."
