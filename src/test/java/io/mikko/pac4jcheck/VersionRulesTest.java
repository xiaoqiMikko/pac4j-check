package io.mikko.pac4jcheck;

import org.junit.Test;

import static io.mikko.pac4jcheck.VersionRules.Verdict;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * 判定规则测试。
 *
 * <p>重点在<b>区间边界</b>：第一注 fastjson-check 栽过的那个 bug 就是上界写死，
 * 结果把已修复版本报成高危，还建议用户去做代价高得多的大版本迁移 ——
 * 那不是误报，是给出了错误的行动建议。所以每个边界都要正反各测一次。
 */
public class VersionRulesTest {

    // ---------- 区间一：< 4.5.9 ----------

    @Test
    public void veryOldVersionsAreAffected() {
        assertEquals(Verdict.AFFECTED, VersionRules.judgeJwt("1.8.0"));
        assertEquals(Verdict.AFFECTED, VersionRules.judgeJwt("1.9.2"));
        assertEquals(Verdict.AFFECTED, VersionRules.judgeJwt("3.8.2"));
        assertEquals(Verdict.AFFECTED, VersionRules.judgeJwt("4.0.1"));
    }

    @Test
    public void boundary_4_5_9() {
        assertEquals(Verdict.AFFECTED, VersionRules.judgeJwt("4.5.8"));
        // 4.5.9 是修复版，必须判为不受影响
        assertEquals(Verdict.NOT_AFFECTED, VersionRules.judgeJwt("4.5.9"));
        assertEquals(Verdict.NOT_AFFECTED, VersionRules.judgeJwt("4.5.10"));
    }

    @Test
    public void gapBetween_4_and_5_isNotAffected() {
        // 4.5.9 之后、5.0.0-RC1 之前这一段不在任何受影响区间内
        assertEquals(Verdict.NOT_AFFECTED, VersionRules.judgeJwt("4.6.0"));
        assertEquals(Verdict.NOT_AFFECTED, VersionRules.judgeJwt("4.9.9"));
    }

    // ---------- 区间二：>= 5.0.0-RC1 且 < 5.7.9 ----------

    @Test
    public void boundary_5_0_0_RC1() {
        // 预发布版是区间下界本身，必须受影响
        assertEquals(Verdict.AFFECTED, VersionRules.judgeJwt("5.0.0-RC1"));
        assertEquals(Verdict.AFFECTED, VersionRules.judgeJwt("5.0.0"));
        assertEquals(Verdict.AFFECTED, VersionRules.judgeJwt("5.4.3"));
    }

    @Test
    public void boundary_5_7_9() {
        assertEquals(Verdict.AFFECTED, VersionRules.judgeJwt("5.7.8"));
        assertEquals(Verdict.NOT_AFFECTED, VersionRules.judgeJwt("5.7.9"));
        assertEquals(Verdict.NOT_AFFECTED, VersionRules.judgeJwt("5.7.10"));
    }

    // ---------- 区间三：>= 6.0.4.1 且 < 6.3.3 ----------

    @Test
    public void boundary_6_0_4_1_fourSegmentVersion() {
        // 官方 6.x 区间下界是罕见的四段版本号，解析错会整段判错
        assertEquals(Verdict.AFFECTED, VersionRules.judgeJwt("6.0.4.1"));
        assertEquals(Verdict.AFFECTED, VersionRules.judgeJwt("6.1.0"));
        assertEquals(Verdict.AFFECTED, VersionRules.judgeJwt("6.3.2"));
    }

    @Test
    public void boundary_6_3_3() {
        assertEquals(Verdict.NOT_AFFECTED, VersionRules.judgeJwt("6.3.3"));
        assertEquals(Verdict.NOT_AFFECTED, VersionRules.judgeJwt("6.5.5"));
    }

    // ---------- 官方与第三方口径冲突的一段 ----------

    @Test
    public void disputedRange_6_0_0_to_6_0_4() {
        // 官方称 6.x 自 6.0.4.1 起受影响；第三方称漏洞自 1.9.2 就存在。
        // 我们没独立验证，所以既不判 AFFECTED 也不判 NOT_AFFECTED。
        assertEquals(Verdict.DISPUTED, VersionRules.judgeJwt("6.0.0"));
        assertEquals(Verdict.DISPUTED, VersionRules.judgeJwt("6.0.4"));
        assertTrue(VersionRules.isDisputedRange("6.0.2"));
        assertTrue(!VersionRules.isDisputedRange("6.0.4.1"));
    }

    // ---------- 修复版本建议 ----------

    @Test
    public void fixedVersionSuggestions() {
        assertEquals("4.5.9", VersionRules.fixedVersionFor("4.0.1"));
        assertEquals("5.7.9", VersionRules.fixedVersionFor("5.4.3"));
        assertEquals("6.3.3", VersionRules.fixedVersionFor("6.0.4.1"));
        // 存疑区间也应给出升级目标，否则用户不知道往哪升
        assertEquals("6.3.3", VersionRules.fixedVersionFor("6.0.0"));
        assertNull(VersionRules.fixedVersionFor("6.3.3"));
        assertNull(VersionRules.fixedVersionFor("4.5.9"));
    }

    @Test
    public void unparsableVersionIsUnknown() {
        assertEquals(Verdict.UNKNOWN, VersionRules.judgeJwt(null));
        assertEquals(Verdict.UNKNOWN, VersionRules.judgeJwt(""));
        assertEquals(Verdict.UNKNOWN, VersionRules.judgeJwt("not-a-version"));
    }

    // ---------- 「引入者」判定已撤销（2026-08-05）----------
    //
    // 这一组测试原本断言 pac4j-oidc / javalin / lagom / ratpack 会拖进 pac4j-jwt。
    // 复核后确认那是**误报**，依据见 VersionRules.INTRODUCER_RETRACTED_NOTE：
    //   · pac4j-oidc → test scope（3.0.0 ~ 6.3.0 逐版本核过，无一例外）
    //   · javalin-pac4j → test scope；lagom-pac4j-parent → provided scope
    //   · ratpack-pac4j:1.4.6 那段依赖整块被 XML 注释包着，根本不存在
    //   · pac4j-oidc-6.0.0.jar 实物复验：78 个条目全在 org/pac4j/oidc/ 下，无 shaded jwt 类
    // test / provided 在 Maven 里不传递给下游 → 使用者拿不到 pac4j-jwt。
    //
    // 现在把它们**反过来断言不再误报** —— 留着这组测试就是为了防止判定被改回去。

    @Test
    public void oidcIsNotAffected_testScopeDoesNotPropagate() {
        assertNull(VersionRules.introducedJwtVersion("pac4j-oidc", "5.4.3"));
        assertNull(VersionRules.introducedJwtVersion("pac4j-oidc", "6.0.0"));
        assertNull(VersionRules.introducedJwtVersion("pac4j-oidc", "1.7.0"));
    }

    @Test
    public void javalinLagomRatpackAreNotAffected() {
        assertNull(VersionRules.introducedJwtVersion("javalin-pac4j", "7.0.0"));
        assertNull(VersionRules.introducedJwtVersion("javalin-pac4j", "1.0.0.RC0"));
        assertNull(VersionRules.introducedJwtVersion("lagom-pac4j-parent", "2.2.1"));
        // 1.4.6 曾是全工具唯一被判受影响的 ratpack 版本，实为注释掉的 test 依赖
        assertNull(VersionRules.introducedJwtVersion("ratpack-pac4j", "1.4.6"));
    }

    @Test
    public void nothingIsTreatedAsIntroducerAnymore() {
        assertTrue(!VersionRules.isIntroducer("pac4j-oidc"));
        assertTrue(!VersionRules.isIntroducer("javalin-pac4j"));
        assertTrue(!VersionRules.isIntroducer("lagom-pac4j-parent"));
        assertTrue(!VersionRules.isIntroducer("ratpack-pac4j"));
        assertTrue(!VersionRules.isIntroducer("pac4j-core"));
    }

    // ---------- 版本比较本身 ----------

    @Test
    public void preReleaseSortsBeforeRelease() {
        // 这条写反会让 5.0.0 正式版逃出受影响区间
        assertTrue(Version.parse("5.0.0-RC1").lt(Version.parse("5.0.0")));
        assertTrue(Version.parse("1.8.0-RC1").lt(Version.parse("1.8.0")));
    }

    @Test
    public void fourSegmentComparison() {
        assertTrue(Version.parse("6.0.4").lt(Version.parse("6.0.4.1")));
        assertTrue(Version.parse("6.0.4.1").lt(Version.parse("6.1.0")));
        // 缺失段按 0 补
        assertEquals(Version.parse("6.0.4"), Version.parse("6.0.4.0"));
    }
}
