/**
 * @name fastjson autoType/白名单开启(任意位置)
 * @description setAutoTypeSupport(true)/setAutoTypeSupportNotCheck(true)/addAccept() — 任意 ParserConfig
 *              实例级开启多态反序列化 → RCE (CVE-2022-25845)。与全局版(GlobalAutoType)互补, 覆盖非全局调用点。
 * @kind problem
 * @id apex/fastjson-autotype-enable
 * @problem.severity error
 * @tags security external/cwe/cwe-502
 */
import java

from MethodCall ma
where
  ma.getMethod().getName().regexpMatch("setAutoTypeSupport|setAutoTypeSupportNotCheck|addAccept")
select ma, "fastjson autoType/白名单开启 — 多态反序列化 RCE 面 (CVE-2022-25845, 8-5 l2dex-admin-server 失陷根因链)."
