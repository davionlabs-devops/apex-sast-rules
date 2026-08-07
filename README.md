# apex-sast-rules — ApeX 外挂扫描规则仓

本仓是 ApeX 的**外挂扫描规则**中心，被 devops-tools 里的扫描 workflow 在**运行时 clone** 下来读取。
设计目的:**规则更新直接 push 本仓，不需要再为 devops-tools 提 PR + 审批**(devops-tools main 有 ruleset)。

## 目录结构

```
codeql/          # CodeQL 自定义查询(.ql + qlpack.yml)
  qlpack.yml     # pack: apex/codeql-java, 依赖 codeql/java
  java/          # Java 规则(8-5 入侵相关代码级 sink)
semgrep/         # semgrep 自定义规则(.yml, 阶段二)
  apex-fastjson.yml
  apex-deser-rce-ssti.yml
scan-config.yml  # codeql 扫描仓清单/语言(文档 + 预留:workflow 可读)
```

## 怎么加 / 改规则

1. 在 `codeql/java/` 下加 `*.ql`(或在 `semgrep/` 下加 `*.yml`)。
2. `git push origin main`(本仓**无分支保护**, 直接 push)。
3. 下次扫描自动拉到新规则。devops-tools 的 workflow 文件**不用动**。

## 与 8-5 入侵的关联

2026-08-05 `l2dex-admin-server` 经 fastjson autoType 全局开关(`ParserConfig.getGlobalInstance().setAutoTypeSupport(true)`,
CVE-2022-25845)失陷。本仓首批规则即针对该 sink + 反序列化/SSTI/SpEL/命令执行 gadget 链。
