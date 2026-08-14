/**
 * @name JNDI 注入
 * @description 远端输入流入 javax.naming Context.lookup → JNDI/RMI/LDAP 注入,
 *              可触发远程类加载 (log4shell 同型, CWE-74)。
 * @kind path-problem
 * @id apex/java-jndi-injection
 * @problem.severity error
 * @security-severity 9.8
 * @tags security external/cwe/cwe-74
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

module ApexJndiCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      mc.getMethod().hasName("lookup") and
      mc.getMethod().getDeclaringType().getASupertype*().getQualifiedName() = "javax.naming.Context" and
      sink.asExpr() = mc.getAnArgument()
    )
  }
}

module ApexJndiFlow = TaintTracking::Global<ApexJndiCfg>;

import ApexJndiFlow::PathGraph

from ApexJndiFlow::PathNode source, ApexJndiFlow::PathNode sink
where ApexJndiFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "JNDI 注入: 远端输入流入 Context.lookup (CWE-74, log4shell 同型); lookup 目标须白名单."
