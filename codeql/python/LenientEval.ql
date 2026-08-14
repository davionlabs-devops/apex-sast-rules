import python

/**
 * @name Python eval/exec 调用 (宽松, sink 即报)
 * @description 任意 eval / exec 内建调用 (CWE-94)。
 * @kind problem
 * @id apex/l-py-eval-anyuse
 * @problem.severity warning
 * @security-severity 3.0
 * @tags security external/cwe/cwe-94 lenient
 */
from Call c
where
  c.getFunc() instanceof Name and
  c.getFunc().(Name).getId() in ["eval", "exec"]
select c, "eval/exec 调用(宽松) — 确认参数非用户可控"
