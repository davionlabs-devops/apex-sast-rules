/**
 * @name Go 不安全反序列化(yaml/gob)
 * @description 远端输入流入 yaml.Unmarshal / gob.NewDecoder → 非预期类型构造 (CWE-502)。
 *              Go json 安全, yaml 自定义 unmarshaler/gob 仍有类型混淆面。
 * @kind path-problem
 * @id apex/go-deser-tainted
 * @problem.severity warning
 * @tags security external/cwe/cwe-502
 */
import go
import semmle.code.go.dataflow.TaintTracking
import semmle.code.go.dataflow.FlowSources

class ApexGoDeserFlow extends TaintTracking::Configuration {
  ApexGoDeserFlow() { this = "ApexGoDeserFlow" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink = API::moduleImport("gopkg.in/yaml.v2").getFunction("Unmarshal").getACall().getAnArgument()
    or
    sink = API::moduleImport("gopkg.in/yaml.v3").getFunction("Unmarshal").getACall().getAnArgument()
    or
    sink = API::moduleImport("sigs.k8s.io/yaml").getFunction("Unmarshal").getACall().getAnArgument()
    or
    sink = API::moduleImport("encoding/gob").getFunction("NewDecoder").getACall().getAnArgument()
  }
}

from ApexGoDeserFlow cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Go 不安全反序列化: 远端输入流入 yaml/gob 解码 (CWE-502); 确认目标类型固定且数据来源可信."
