import python
import semmle.python.ApiGraphs

/**
 * @name Python os.system/os.popen 调用 (宽松, sink 即报)
 * @description 任意 os.system / os.popen* 调用 (CWE-78)。
 * @kind problem
 * @id apex/l-py-system-anyuse
 * @problem.severity warning
 * @security-severity 3.0
 * @tags security external/cwe/cwe-78 lenient
 */
from API::CallNode c
where
  c = API::moduleImport("os").getMember("system").getACall()
  or c = API::moduleImport("os").getMember("popen").getACall()
  or c = API::moduleImport("os").getMember("popen2").getACall()
  or c = API::moduleImport("os").getMember("popen3").getACall()
select c, "os.system/popen 调用(宽松) — 确认命令非用户可控"
