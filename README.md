# pac4j-check

**离线排查 CVE-2026-29000(CVSS 10.0)—— 包括官方 advisory 没有列出的那些包。**

[English](#english) | 中文

单个 jar,约 24KB,零运行时依赖,Java 8 起可用,完全离线,不外传任何数据。

---

## 这个漏洞是什么

`org.pac4j:pac4j-jwt` 的 `JwtAuthenticator` 在处理**加密 JWT(JWE)** 时未强制校验签名。
攻击者只要拿到服务器的 **RSA 公钥**(公钥本来就是公开的),
就能构造一个 JWE 包裹的 PlainJWT,把 subject 和 role 写成任意值,
**以任意用户身份登录,包括管理员**。无需任何凭据。

| 项 | 值 |
|---|---|
| CVE | **CVE-2026-29000** |
| GitHub advisory | `GHSA-pm7g-w2cf-q238` |
| CVSS | **10.0(满分)** |
| 公开日 | 2026-03-05 |

pac4j 被 Spring Security、**Apereo CAS**、JEE、Vert.x、Play、Dropwizard 等广泛集成。

## 🔴 v0.2.0 更正:v0.1.0 的核心主张是错的

**v0.1.0 声称「官方漏洞库只列了 1 个包,实际有 5 个」,并会因此对
`pac4j-oidc` / `javalin-pac4j` / `lagom-pac4j` / `ratpack-pac4j` 报危。
那是误报。官方 advisory 只列 `pac4j-jwt` 是对的。**

复核依据(两条独立证据,都可自行复现):

| 构件 | 它对 pac4j-jwt 的依赖 | 会传给使用者吗 |
|---|---|---|
| `pac4j-oidc` | `test` scope(3.0.0 / 4.0.0 / 4.5.0 / 5.0.0 / 5.7.0 / 6.0.0 / 6.3.0 逐版本核过) | ❌ |
| `javalin-pac4j` | `test` scope | ❌ |
| `lagom-pac4j-parent` | `provided` scope | ❌ |
| `ratpack-pac4j:1.4.6` | 那段依赖**整块被 XML 注释包着**,根本不存在 | ❌ |

1. **scope 不传递** —— Maven 里 `test` / `provided` 依赖**不会传递给下游**,
   使用者的 runtime classpath 上不会出现 pac4j-jwt。
2. **构件实物复验** —— `pac4j-oidc-6.0.0.jar` 共 78 个条目,全部在 `org/pac4j/oidc/` 下,
   **没有任何 shade 进来的 pac4j-jwt 类**。既不传递,也不携带。

**错在哪**:v0.1.0 逐个解析了 pom,但只看「谁写了 `pac4j-jwt` 这个坐标」,
**没看 `scope`** —— 把「pom 里写了」当成了「使用者会拿到」。

> **如果你因为 v0.1.0 的报告升级过 pac4j,那次升级不是必需的(升级本身无害)。
> 只有你的应用里真的存在受影响版本的 `pac4j-jwt` 时,才需要处置。**

## 为什么仍然需要一个专门的工具

判断某台机器上到底有没有受影响的 `pac4j-jwt`,`mvn dependency:tree` 在两种情况下会失效 ——
生产机上只有一个打好的 fat-jar(没有源码和 pom);或者它被 shade 进了某个 SDK 内部,
依赖树上根本不出现。本工具直接扫**构件本身**,不依赖构建环境。

| 构件 | 受影响版本数 | 官方 advisory |
|---|---|---|
| `org.pac4j:pac4j-jwt` | 114 | ✅ 唯一被列出的,**且这是对的** |

## 用法

```bash
java -jar pac4j-check.jar ./myapp.jar        # 扫一个 jar/war
java -jar pac4j-check.jar /opt/apps          # 扫一个目录(递归)
java -jar pac4j-check.jar /opt/apps --json   # JSON 输出,便于接管道
java -jar pac4j-check.jar ./app.jar --gbk    # Windows 控制台中文乱码时用
```

**退出码**:`0` = 未发现受影响 · `1` = 存疑/无法判定 · `2` = 发现受影响。可直接挂 CI。

### 输出示例

```
[CRITICAL] pac4j-jwt 5.4.3
  位置    :demo-app.jar!/BOOT-INF/lib/pac4j-jwt-5.4.3.jar
  版本来源:pom.properties(可靠)
  部署形态:Spring Boot fat-JAR
  结论    :命中 CVE-2026-29000 —— JWE 处理路径未强制校验签名,
            拿到服务器 RSA 公钥即可伪造任意身份(含管理员)登录
  处置    :升级 pac4j-jwt 至 5.7.9
```

> v0.1.0 在这里还会多报一条 `[CRITICAL] pac4j-oidc` —— **那是误报,v0.2.0 已删除**,
> 理由见开头的更正说明。

## 它做什么

- **递归展开 Spring Boot fat-JAR**(在内存里,不解压落地),溯源到具体嵌套路径
- **识别被 shade 进宿主 jar 的情况** —— 就是 `mvn dependency:tree` 查不到的那类
- **溯源引入链** —— 告诉你是哪个构件把 pac4j-jwt 拖进来的
- 按官方区间给出判定与**具体升级目标**

## 判定规则与边界(请读完再用)

判定**一律以官方 advisory `GHSA-pm7g-w2cf-q238` 为准**:

```
pac4j-jwt  < 4.5.9                      -> 升 4.5.9
pac4j-jwt  >= 5.0.0-RC1  且 < 5.7.9     -> 升 5.7.9
pac4j-jwt  >= 6.0.4.1    且 < 6.3.3     -> 升 6.3.3
```

**自校验**:本工具对 Maven Central 上 pac4j-jwt 全部 147 个版本跑判定,
命中数为 **114**,与官方 advisory 三段区间的版本数之和(13+33+68)**精确吻合**。
这条断言写在测试里(`OfficialRangeCrossCheckTest`),对不上就构建失败。

> ⚠️ **但要清楚它验证的是什么**:它验证**版本区间算法**正确,
> **验证不了「哪些构件该进判定表」** —— v0.1.0 的误报正是发生在后者,
> 而当时这条自校验是绿的。**校验通过的范围 ≠ 结论成立的范围。**

### 两条必须说明的局限

1. **只覆盖 `org.pac4j` 这一个 groupId。**
   有第三方研究称受影响构件共 19 个、1,020 个版本,但未公开完整清单。
   本工具独立重建的是 org.pac4j 范围内的部分,**不宣称已覆盖全部**。
   其他 groupId(如 Apereo CAS 的 `org.apereo.cas`)未纳入。

2. **`pac4j-jwt` 6.0.0 ~ 6.0.4 标为「存疑」而非「受影响」。**
   官方称 6.x 自 `6.0.4.1` 起受影响;而第三方研究称漏洞早在 `1.9.2` 就已引入 ——
   若属实,这 5 个版本也该算。**我们没有独立验证第三方结论**,
   因此单独标出并建议保守升级,而不是直接判危。

> 为什么这么保守:判定规则错了不是「误报」,是**让用户做错事**。
> 宁可标注存疑,也不把没验证过的范围写死成结论。

## 构建

```bash
mvn package        # 产物:target/pac4j-check.jar
mvn test           # 31 个测试
```

## 反馈

发现判定错误、漏报或误报,请提 [Issue](../../issues)。
如果你能提供可复现的构件坐标(groupId:artifactId:version),修起来会快很多。

## License

Apache License 2.0

---

<a name="english"></a>

# pac4j-check (English)

**Offline scanner for CVE-2026-29000 (CVSS 10.0) — including the packages the official advisory does not list.**

Single jar, ~24KB, zero runtime dependencies, Java 8+, fully offline, sends nothing anywhere.

## The vulnerability

`JwtAuthenticator` in `org.pac4j:pac4j-jwt` fails to enforce signature validation on certain
**encrypted JWT (JWE)** processing paths. An attacker holding the server's **RSA public key**
(which is public by design) can craft a JWE-wrapped PlainJWT with arbitrary `subject` and role
claims and **authenticate as any user, including administrators** — with no credentials.

| | |
|---|---|
| CVE | **CVE-2026-29000** |
| GitHub advisory | `GHSA-pm7g-w2cf-q238` |
| CVSS | **10.0** |
| Published | 2026-03-05 |

## 🔴 v0.2.0 correction: v0.1.0's central claim was wrong

**v0.1.0 claimed the official advisory "lists only one package while there are five", and
flagged `pac4j-oidc` / `javalin-pac4j` / `lagom-pac4j` / `ratpack-pac4j` as affected.
Those were false positives. The advisory listing only `pac4j-jwt` is correct.**

| Artifact | How it declares pac4j-jwt | Reaches consumers? |
|---|---|---|
| `pac4j-oidc` | `test` scope (verified on 3.0.0 / 4.0.0 / 4.5.0 / 5.0.0 / 5.7.0 / 6.0.0 / 6.3.0) | ❌ |
| `javalin-pac4j` | `test` scope | ❌ |
| `lagom-pac4j-parent` | `provided` scope | ❌ |
| `ratpack-pac4j:1.4.6` | the whole block is **inside an XML comment** — it does not exist | ❌ |

Two independent lines of evidence, both reproducible:

1. **Scope does not propagate** — Maven does not pass `test` / `provided` dependencies to
   downstream consumers, so pac4j-jwt never reaches their runtime classpath.
2. **Artifact inspection** — `pac4j-oidc-6.0.0.jar` has 78 entries, all under
   `org/pac4j/oidc/`, with **no shaded pac4j-jwt classes**.

**Root cause:** v0.1.0 did parse every pom, but only looked at *who names the coordinate*,
never at `scope` — mistaking "declared in a pom" for "reaches the consumer".

> **If you upgraded pac4j because of a v0.1.0 report, that upgrade was not required (though
> harmless). Action is only needed when an affected `pac4j-jwt` is actually present.**

## Why a dedicated tool

Deciding whether an affected `pac4j-jwt` is actually on a given machine defeats
`mvn dependency:tree` in two common cases: a production box with only a packaged fat-jar
(no sources, no pom), or a copy shaded inside some vendor SDK, invisible to the dependency
tree. This tool inspects the **artifacts themselves**.

| Artifact | Affected versions | In official advisory |
|---|---|---|
| `org.pac4j:pac4j-jwt` | 114 | ✅ the only one listed — **and that is correct** |

## Usage

```bash
java -jar pac4j-check.jar ./myapp.jar
java -jar pac4j-check.jar /opt/apps
java -jar pac4j-check.jar /opt/apps --json
```

Exit codes: `0` clean · `1` disputed/undetermined · `2` affected.

## What it does

- Recursively unpacks **Spring Boot fat-JARs** in memory (nothing written to disk)
- Detects pac4j-jwt **shaded into a host jar** — the case `mvn dependency:tree` cannot see
- **Traces the introduction chain**, so you know which artifact pulled it in
- Reports a concrete upgrade target

## Rules and limitations

Verdicts follow the official advisory `GHSA-pm7g-w2cf-q238` exactly:

```
pac4j-jwt  < 4.5.9                    -> 4.5.9
pac4j-jwt  >= 5.0.0-RC1  and < 5.7.9  -> 5.7.9
pac4j-jwt  >= 6.0.4.1    and < 6.3.3  -> 6.3.3
```

**Cross-check:** running the rules over all 147 published pac4j-jwt versions yields **114**
affected — exactly matching the advisory's three ranges (13+33+68). This is asserted in
`OfficialRangeCrossCheckTest`; a mismatch fails the build.

Two limitations, stated plainly:

1. **Only the `org.pac4j` groupId is covered.** Third-party research reports 19 affected
   packages across 1,020 versions but has not published the full list. This tool independently
   reconstructs the org.pac4j portion and **does not claim full coverage**.
2. **pac4j-jwt 6.0.0–6.0.4 are reported as DISPUTED, not AFFECTED.** The advisory starts the
   6.x range at `6.0.4.1`; third-party research states the flaw was introduced as early as
   `1.9.2`. We have not independently verified the latter, so these versions are flagged for
   human review with a conservative upgrade recommendation rather than asserted as vulnerable.

> A wrong verdict is not a "false positive" — it makes people take the wrong action.

## License

Apache License 2.0
