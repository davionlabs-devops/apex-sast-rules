/**
 * @name Go SQL 注入
 * @description 远端输入流入 SQL 查询构造(官方 SQL::QueryString 概念, 覆盖 database/sql/gorm/sqlx/squirrel) (CWE-89)。
 * @kind path-problem
 * @id apex/go-sql-injection
 * @problem.severity error
 * @security-severity 9.8
 * @tags security external/cwe/cwe-89
 */
import go

module ApexGoSqlCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof SQL::QueryString
  }
}

module ApexGoSqlFlow = TaintTracking::Global<ApexGoSqlCfg>;

import ApexGoSqlFlow::PathGraph

from ApexGoSqlFlow::PathNode source, ApexGoSqlFlow::PathNode sink
where ApexGoSqlFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Go SQL 注入: 远端输入流入查询语句 (CWE-89); 须参数化查询(?占位), 禁止拼接."
