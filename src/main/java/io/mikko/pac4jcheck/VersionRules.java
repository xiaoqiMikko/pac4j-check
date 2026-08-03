package io.mikko.pac4jcheck;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * CVE-2026-29000 的版本判定规则。
 *
 * <p><b>判定一律以官方 advisory 为准</b>（GitHub {@code GHSA-pm7g-w2cf-q238}，CVSS 10.0）：
 * <pre>
 *   org.pac4j:pac4j-jwt   &lt; 4.5.9                        -&gt; 修复版 4.5.9
 *   org.pac4j:pac4j-jwt   &gt;= 5.0.0-RC1 且 &lt; 5.7.9      -&gt; 修复版 5.7.9
 *   org.pac4j:pac4j-jwt   &gt;= 6.0.4.1  且 &lt; 6.3.3       -&gt; 修复版 6.3.3
 * </pre>
 *
 * <p>为什么不采用「漏洞自 1.9.2 起就存在」那个更宽的说法：那是第三方（Sonatype）的结论，
 * 我们没有独立验证过。工具给出的是<b>行动建议</b>，宁可保守到可辩护，
 * 也不能把没验证的范围写死成判定 —— 判定错了不是误报，是让人做错事。
 * 官方与第三方口径不一致的那一段（6.0.0 ~ 6.0.4）单独标为「存疑」，见
 * {@link #isDisputedRange(String)}。
 */
public final class VersionRules {

    public static final String CVE = "CVE-2026-29000";
    public static final String GHSA = "GHSA-pm7g-w2cf-q238";
    public static final String CVSS = "10.0";

    /** 受影响的核心构件。官方 advisory 只列了这一个。 */
    public static final String CORE = "org.pac4j:pac4j-jwt";

    private static final Version V_4_5_9 = Version.parse("4.5.9");
    private static final Version V_5_0_0_RC1 = Version.parse("5.0.0-RC1");
    private static final Version V_5_7_9 = Version.parse("5.7.9");
    private static final Version V_6_0_4_1 = Version.parse("6.0.4.1");
    private static final Version V_6_3_3 = Version.parse("6.3.3");
    private static final Version V_6_0_0 = Version.parse("6.0.0");

    /**
     * 会把受影响的 pac4j-jwt 一并拖进来的「引入者」构件 —— <b>官方 advisory 一个都没列</b>。
     *
     * <p>其中 {@code pac4j-oidc} 最要命：它是 OIDC 单点登录的主力模块，
     * 与 pac4j-jwt 同属一个 Maven reactor，pom 里引用时不写 version、
     * 继承 pac4j-parent 的 {@code ${project.version}}，
     * 因此 <b>pac4j-oidc:X 必然拖进 pac4j-jwt:X</b>。
     * 用 OIDC 做登录的人通常根本不知道自己依赖了 pac4j-jwt。
     */
    public static final String INTRODUCER_OIDC = "org.pac4j:pac4j-oidc";

    /** pac4j-oidc 从这个版本起才开始依赖 pac4j-jwt；更早的版本不受影响。 */
    private static final Version OIDC_JWT_SINCE = Version.parse("3.0.0-RC1");

    /**
     * 另外三个引入者用 {@code ${pac4j.version}} 属性锁定 pac4j-jwt 版本，
     * 各版本对应关系不规则，只能逐版本实测得出（数据来自 Maven Central 逐个 pom 解析）。
     */
    private static final Map<String, String> JAVALIN;
    private static final Map<String, String> LAGOM;
    private static final Map<String, String> RATPACK;

    static {
        Map<String, String> javalin = new LinkedHashMap<String, String>();
        javalin.put("1.0.0.RC0", "3.0.0");
        javalin.put("2.0.0", "3.8.2");
        javalin.put("3.0.0", "4.0.1");
        javalin.put("4.0.0", "5.1.3");
        javalin.put("5.0.0", "5.4.3");
        javalin.put("5.0.1", "5.5.0");
        javalin.put("6.0.0", "5.7.0");
        javalin.put("7.0.0", "6.0.4.1");
        javalin.put("8.0.0", "6.3.3"); // 已含修复
        JAVALIN = Collections.unmodifiableMap(javalin);

        Map<String, String> lagom = new LinkedHashMap<String, String>();
        lagom.put("1.0.0", "3.4.0");
        lagom.put("1.1.0", "3.6.1");
        lagom.put("2.0.0", "3.6.1");
        lagom.put("2.1.0", "3.7.0");
        lagom.put("2.2.0", "3.7.0");
        lagom.put("2.2.1", "3.7.0");
        LAGOM = Collections.unmodifiableMap(lagom);

        Map<String, String> ratpack = new LinkedHashMap<String, String>();
        ratpack.put("1.4.6", "1.8.9");
        // ratpack-pac4j 2.0.0 起不再依赖 pac4j-jwt
        RATPACK = Collections.unmodifiableMap(ratpack);
    }

    private VersionRules() {
    }

    /** 判定结论。 */
    public enum Verdict {
        /** 命中官方受影响区间。 */
        AFFECTED,
        /** 落在官方与第三方口径不一致的区间（6.0.0 ~ 6.0.4），需人工确认。 */
        DISPUTED,
        /** 官方区间外，判定为不受影响。 */
        NOT_AFFECTED,
        /** 版本号无法解析。 */
        UNKNOWN
    }

    /** 判定一个 pac4j-jwt 版本。 */
    public static Verdict judgeJwt(String version) {
        Version v = Version.parse(version);
        if (v == null) {
            return Verdict.UNKNOWN;
        }
        if (v.lt(V_4_5_9)) {
            return Verdict.AFFECTED;
        }
        if (v.gte(V_5_0_0_RC1) && v.lt(V_5_7_9)) {
            return Verdict.AFFECTED;
        }
        if (v.gte(V_6_0_4_1) && v.lt(V_6_3_3)) {
            return Verdict.AFFECTED;
        }
        if (v.gte(V_6_0_0) && v.lt(V_6_0_4_1)) {
            return Verdict.DISPUTED;
        }
        return Verdict.NOT_AFFECTED;
    }

    /**
     * 官方 advisory 声称 6.x 的受影响区间从 {@code 6.0.4.1} 起，
     * 但第三方研究称漏洞早在 1.9.2 就已引入 —— 若属实，6.0.0~6.0.4 也应受影响。
     * 我们没有独立验证，因此单独标出而不并入 AFFECTED。
     */
    public static boolean isDisputedRange(String version) {
        return judgeJwt(version) == Verdict.DISPUTED;
    }

    /** 给出该 pac4j-jwt 版本对应的修复版本；不受影响则返回 null。 */
    public static String fixedVersionFor(String version) {
        Version v = Version.parse(version);
        if (v == null) {
            return null;
        }
        if (v.lt(V_4_5_9)) {
            return "4.5.9";
        }
        if (v.gte(V_5_0_0_RC1) && v.lt(V_5_7_9)) {
            return "5.7.9";
        }
        if (v.gte(V_6_0_0) && v.lt(V_6_3_3)) {
            return "6.3.3";
        }
        return null;
    }

    /**
     * 给定一个「引入者」构件及其版本，推断它拖进来的 pac4j-jwt 版本。
     *
     * @return pac4j-jwt 版本；该版本不引入 pac4j-jwt 时返回 null
     */
    public static String introducedJwtVersion(String artifactId, String version) {
        if (artifactId == null || version == null) {
            return null;
        }
        if ("pac4j-oidc".equals(artifactId)) {
            Version v = Version.parse(version);
            if (v == null || v.lt(OIDC_JWT_SINCE)) {
                return null; // 3.0.0-RC1 之前不依赖 pac4j-jwt
            }
            return version; // 同 reactor，版本恒等
        }
        if ("javalin-pac4j".equals(artifactId)) {
            return JAVALIN.get(version);
        }
        if ("lagom-pac4j".equals(artifactId) || "lagom-pac4j-parent".equals(artifactId)) {
            return LAGOM.get(version);
        }
        if ("ratpack-pac4j".equals(artifactId)) {
            return RATPACK.get(version);
        }
        return null;
    }

    /** 该 artifactId 是否属于我们已知的「引入者」。 */
    public static boolean isIntroducer(String artifactId) {
        return "pac4j-oidc".equals(artifactId)
                || "javalin-pac4j".equals(artifactId)
                || "lagom-pac4j".equals(artifactId)
                || "lagom-pac4j-parent".equals(artifactId)
                || "ratpack-pac4j".equals(artifactId);
    }
}
