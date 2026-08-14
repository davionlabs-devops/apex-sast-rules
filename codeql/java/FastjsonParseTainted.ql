/**
 * @name fastjson 解析远端输入
 * @description 远端输入流入 com.alibaba.fastjson[2].JSON.parseObject/parse/parseArray —
 *              配合 autoType 即 RCE; 8-5 入侵链入口即此类调用。
 * @kind path-problem
 * @id apex/fastjson-parse-tainted
 * @problem.severity warning
 * @tags security external/cwe/cwe-502
 */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

class ApexFastjsonParseFlow extends TaintTracking::Configuration {
  ApexFastjsonParseFlow() { this = "ApexFastjsonParseFlow" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      mc.getMethod().getName().regexpMatch("parseObject|parse|parseArray") and
      mc.getMethod().getDeclaringType().getQualifiedName().regexpMatch("com\\.alibaba\\.fastjson2?\\.JSON") and
      sink.asExpr() = mc.getAnArgument()
    )
  }
}

from ApexFastjsonParseFlow cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "远端输入流入 fastjson 解析 — 若开启 autoType 即 RCE (CVE-2022-25845); 确认输入校验且 autoType 关闭."
