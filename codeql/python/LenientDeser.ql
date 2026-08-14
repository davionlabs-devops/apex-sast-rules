import python
import semmle.python.ApiGraphs

/**
 * @name Python 危险反序列化 (宽松, sink 即报)
 * @description 任意 pickle/cPickle/_pickle/marshal loads、yaml.load 调用 (CWE-502)。
 * @kind problem
 * @id apex/l-py-deser-anyuse
 * @problem.severity warning
 * @security-severity 3.0
 * @tags security external/cwe/cwe-502 lenient
 */
from API::CallNode c
where
  c = API::moduleImport("pickle").getMember("loads").getACall()
  or c = API::moduleImport("cPickle").getMember("loads").getACall()
  or c = API::moduleImport("_pickle").getMember("loads").getACall()
  or c = API::moduleImport("marshal").getMember("loads").getACall()
  or c = API::moduleImport("yaml").getMember("load").getACall()
select c, "危险反序列化调用(宽松) — 确认输入来源可信, yaml 须用 safe_load"
