# 2026-08-16 增补: github/codeql 精选差集规则 (11 条)

来源: github/codeql@codeql-cli/v2.26.2 (与 runner bundle 同版本, 免 API 漂移)。
均为 security-extended 套件**未收录**的高价值规则 (experimental/ 或 low precision 被套件选择器排除)。
挑选原则: 对症 ApeX 攻击面(鉴权绕过/SSRF/XSS/JWT/CORS), 排除 Android/LDAP/hardcoded-credentials 噪音类。

## javascript/ (5 条, 新建 pack)
| 规则 id | 检测 | 备注 |
|---|---|---|
| js/different-kinds-comparison-bypass | == 类型混淆绕过鉴权比较 | 直接打鉴权面 |
| javascript/ssrf-ipv6-transition-incomplete-guard | IPv6 转换绕过 SSRF IP 防护 | 7-28 SSRF 前科 |
| js/user-prompt-injection | 用户输入拼进 LLM prompt | AI 功能新增仓 |
| js/missing-x-frame-options | 缺 X-Frame-Options (clickjacking) | 4 个管理后台 |
| js/password-in-configuration-file | 配置文件明文密码 | |

## go/ (2 条)
| go/stored-xss | 存储型 XSS (模板渲染未净化) | lib: semmle.go.security.StoredXss (go-all 内置) |
| go/stored-command | 存储的命令字符串进 exec | lib 同上 |

## java/ (1 条)
| java/cleartext-storage-in-class | 敏感数据明文存类字段 | 与 fastjson 链互补 |

## python/ (3 条 + experimental lib 闭包)
| py/jwt-missing-verification | JWT 签名验证缺失 | 依赖 experimental/semmle/python/** (36 qll, 已随包) |
| py/jwt-empty-secret-or-algorithm | JWT 空 secret / alg:none | 同上 |
| py/cors-bypass | CORS 字符串比较绕过 | 同上 |

注意: python/experimental/semmle/** 是查询伴生库(.qll), run-queries 只执行 .ql, 不会重复告警。
