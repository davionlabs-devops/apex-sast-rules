/**
 * @name Fastjson autoType 全局开启
 * @description ParserConfig.getGlobalInstance().setAutoTypeSupport(true) 在进程级开启多态反序列化,
 *              使所有 JSON 接口暴露于远程代码执行 (CVE-2022-25845)。
 *              2026-08-05 l2dex-admin-server 经此失陷: 全局单例开关 → 47 个 controller 的 JSON 端点全部 RCE。
 * @kind problem
 * @id apex/fastjson-global-autotype
 * @problem.severity error
 * @tags security external/cwe/cwe-502
 */
import java

from MethodCall ma
where
  ma.getMethod().hasName("setAutoTypeSupport") and
  ma.getQualifier().(MethodCall).getMethod().hasName("getGlobalInstance")
select ma, "Fastjson autoType 全局开启 — 所有 JSON 接口暴露于 RCE (8-5 l2dex-admin-server 失陷根因, CVE-2022-25845)."
