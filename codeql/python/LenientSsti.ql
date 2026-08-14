/**
 * @name Python SSTI 调用 (宽松, sink 即报)
 * @description 任意 flask render_template_string / jinja2 from_string 调用 (CWE-1336)。
 * @kind problem
 * @id apex/l-py-ssti-anyuse
 * @problem.severity warning
 * @security-severity 3.0
 * @tags security external/cwe/cwe-1336 lenient
 */
import python

from Call c
where
  (
    c.getFunc().(Attribute).getName() = "render_template_string" or
    c.getFunc().(Attribute).getName() = "from_string"
  )
select c, "SSTI 模板渲染调用(宽松) — 确认模板串非用户可控"
