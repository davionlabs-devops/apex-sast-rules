/**
 * @name Go 模板 Parse 调用 (宽松, sink 即报)
 * @description 任意 text/template / html/template 的 Parse* 调用 (CWE-1336)。
 * @kind problem
 * @id apex/l-go-template-anyuse
 * @problem.severity warning
 * @security-severity 3.0
 * @tags security external/cwe/cwe-1336 lenient
 */
import go

from CallExpr ce
where
  ce.getTarget().getName().regexpMatch("^(Parse|ParseFiles|ParseGlob|ParseFS)$") and
  ce.getTarget().getQualifiedName().regexpMatch("^(text|html)/template\\..*")
select ce, "Go 模板 Parse 调用(宽松): " + ce.getEnclosingFunction().getName() +
  " — 确认模板内容服务端固定, 用户输入只做数据"
