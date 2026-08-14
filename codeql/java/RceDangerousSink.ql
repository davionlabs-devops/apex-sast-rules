/**
 * @name RCE 危险 sink(无须污点即报)
 * @description 高危 gadget 出口, 出现即值得人工复核:
 *              ClassPathXmlApplicationContext(FileSystem...) 远程/不可信 XML → Spring bean RCE;
 *              XMLDecoder.readObject → 任意代码执行;
 *              SnakeYAML new Yaml().load/loadAll 无 SafeConstructor (CVE-2022-1471);
 *              XStream.fromXML 反序列化;
 *              MVEL.eval / Ognl.parseExpression 表达式引擎;
 *              FreeMarker Configuration.setSetting("new_builtin_class_resolver", ...) 解除类解析限制。
 * @kind problem
 * @id apex/java-rce-dangerous-sink
 * @problem.severity error
 * @tags security external/cwe/cwe-94 external/cwe/cwe-502
 */
import java

from Expr e
where
  exists(NewClassExpr ne |
    ne = e and
    ne.getType().getASupertype*().getName().regexpMatch("ClassPathXmlApplicationContext|FileSystemXmlApplicationContext|XMLDecoder"))
  or
  exists(MethodCall mc |
    mc = e and
    mc.getMethod().getName().regexpMatch("load|loadAll") and
    mc.getQualifier().getType().getASupertype*().getName() = "Yaml")
  or
  exists(MethodCall mc |
    mc = e and
    mc.getMethod().getName().regexpMatch("eval|parseExpression") and
    mc.getMethod().getDeclaringType().getName().regexpMatch("MVEL|Ognl"))
  or
  exists(MethodCall mc |
    mc = e and
    mc.getMethod().hasName("fromXML"))
  or
  exists(MethodCall mc |
    mc = e and
    mc.getMethod().hasName("setSetting") and
    exists(StringLiteral sl |
      sl = mc.getArgument(0) and
      sl.getValue().matches("%new_builtin_class_resolver%")))
select e, "RCE 危险 sink (gadget 出口) — 出现即需人工复核是否可达远端输入 (CWE-94/502)."
