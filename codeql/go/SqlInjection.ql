/**
 * @name Go SQL 注入
 * @description 远端输入流入 database/sql / sqlx / gorm 查询参数 → SQL 注入 (CWE-89)。
 *              覆盖 db.Query*/Exec*、sqlx Queryx/NamedExec、gorm Raw/Exec/Where。
 * @kind path-problem
 * @id apex/go-sql-injection
 * @problem.severity error
 * @tags security external/cwe/cwe-89
 */
import go
import semmle.code.go.dataflow.TaintTracking
import semmle.code.go.dataflow.FlowSources

class ApexGoSqlFlow extends TaintTracking::Configuration {
  ApexGoSqlFlow() { this = "ApexGoSqlFlow" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    // database/sql
    sink = API::moduleImport("database/sql").getMember("DB").getMember("Query").getACall().getAnArgument()
    or
    sink = API::moduleImport("database/sql").getMember("DB").getMember("QueryContext").getACall().getAnArgument()
    or
    sink = API::moduleImport("database/sql").getMember("DB").getMember("QueryRow").getACall().getAnArgument()
    or
    sink = API::moduleImport("database/sql").getMember("DB").getMember("QueryRowContext").getACall().getAnArgument()
    or
    sink = API::moduleImport("database/sql").getMember("DB").getMember("Exec").getACall().getAnArgument()
    or
    sink = API::moduleImport("database/sql").getMember("DB").getMember("ExecContext").getACall().getAnArgument()
    // sqlx
    or
    sink = API::moduleImport("github.com/jmoiron/sqlx").getMember("DB").getMember("Queryx").getACall().getAnArgument()
    or
    sink = API::moduleImport("github.com/jmoiron/sqlx").getMember("DB").getMember("QueryRowx").getACall().getAnArgument()
    or
    sink = API::moduleImport("github.com/jmoiron/sqlx").getMember("DB").getMember("NamedExec").getACall().getAnArgument()
    // gorm
    or
    sink = API::moduleImport("gorm.io/gorm").getMember("DB").getMember("Raw").getACall().getAnArgument()
    or
    sink = API::moduleImport("gorm.io/gorm").getMember("DB").getMember("Exec").getACall().getAnArgument()
    or
    sink = API::moduleImport("gorm.io/gorm").getMember("DB").getMember("Where").getACall().getAnArgument()
  }
}

from ApexGoSqlFlow cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Go SQL 注入: 远端输入流入查询构造 (CWE-89); 须参数化查询(?占位), 禁止拼接."
