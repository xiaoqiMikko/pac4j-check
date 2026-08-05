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
     * <b>「引入者」判定已于 2026-08-05 全部撤销 —— 它是错的。</b>
     *
     * <p>v0.1.0 曾判定 {@code pac4j-oidc} / {@code javalin-pac4j} /
     * {@code lagom-pac4j-parent} / {@code ratpack-pac4j} 四个构件会把受影响的
     * pac4j-jwt 一并拖进来，并称「官方 advisory 一个都没列」。
     * 复核后确认：<b>官方 advisory 只列 pac4j-jwt 是对的，这四个都不该判为受影响。</b>
     *
     * <p>撤销依据（两条独立证据，均可自行复现）：
     * <ol>
     *   <li><b>scope 不传递</b> —— 逐版本解析 Maven Central 上的 pom：
     *       {@code pac4j-oidc} 对 pac4j-jwt 是 {@code test}
     *       （3.0.0 / 4.0.0 / 4.5.0 / 5.0.0 / 5.7.0 / 6.0.0 / 6.3.0 无一例外），
     *       {@code javalin-pac4j} 是 {@code test}，
     *       {@code lagom-pac4j-parent} 是 {@code provided}，
     *       而 {@code ratpack-pac4j:1.4.6} 那段依赖<b>整块被 XML 注释包着</b>，
     *       根本不存在。Maven 语义下 {@code test} / {@code provided}
     *       <b>不传递给下游</b>，使用者的 runtime classpath 里不会出现 pac4j-jwt。</li>
     *   <li><b>构件实物复验</b> —— {@code pac4j-oidc-6.0.0.jar} 共 78 个条目，
     *       全部位于 {@code org/pac4j/oidc/} 下，<b>没有任何 shaded 进来的
     *       pac4j-jwt 类</b>。既不传递依赖，也不打包携带。</li>
     * </ol>
     *
     * <p>原判定的根因：只看了「谁在 pom 里写了这个坐标」，
     * 没看 {@code scope} —— 把「写了坐标」当成了「使用者会拿到它」。
     *
     * <p>注意：若使用者<b>自己显式依赖</b> pac4j-jwt，扫描器的第 1 步本就会扫到并判定，
     * 不依赖这套推断。<b>推断本身是纯粹的误报来源，故整个撤销。</b>
     */
    public static final String INTRODUCER_RETRACTED_NOTE =
            "引入者判定已撤销：pac4j-oidc 等对 pac4j-jwt 是 test/provided scope，不传递给使用者";

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
     * <b>恒返回 {@code null}</b> —— 「引入者会拖进 pac4j-jwt」这个推断已被证伪，
     * 详见 {@link #INTRODUCER_RETRACTED_NOTE} 处的完整依据。
     *
     * <p>方法与 JSON 字段 {@code introducedJwtVersion} 一并保留（值恒为 null），
     * 是为了不破坏 v0.1.0 已经发布出去的输出结构。
     *
     * @return 恒为 null
     */
    public static String introducedJwtVersion(String artifactId, String version) {
        return null;
    }

    /**
     * <b>恒返回 {@code false}</b> —— 判定已撤销，理由同上。
     *
     * <p>只有使用者<b>自己显式依赖</b> pac4j-jwt 才会被判定，那条路径走扫描器第 1 步。
     */
    public static boolean isIntroducer(String artifactId) {
        return false;
    }
}
