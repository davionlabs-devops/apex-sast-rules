import go

/**
 * @name Go SQL 拼接执行 (宽松, fmt.Sprintf 进 SQL)
 * @description db Exec/Query* 参数含 fmt.Sprintf 拼接 (CWE-89)。
 * @kind problem
 * @id apex/l-go-sql-format-anyuse
 * @problem.severity warning
 * @security-severity 3.0
 * @tags security external/cwe/cwe-89 lenient
 */
from CallExpr ce, CallExpr fmtCall
where
  ce.getTarget().getName().regexpMatch(
    "^(Exec|Query|QueryRow|ExecContext|QueryContext|QueryRowContext)$") and
  fmtCall = ce.getAnArgument() and
  fmtCall.getTarget().getName().regexpMatch("^(Sprintf|Format)$") and
  fmtCall.getTarget().getQualifiedName().regexpMatch("^fmt\\..*")
select ce, "SQL 拼接执行(宽松): " + ce.getEnclosingFunction().getName() +
  " — fmt.Sprintf 结果直接进 SQL, 确认无用户输入参与拼接"
