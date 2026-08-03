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

    // ---------- 引入者映射（官方 advisory 完全没有的部分） ----------

    @Test
    public void oidcDragsInSameJwtVersion() {
        // pac4j-oidc 与 pac4j-jwt 同 reactor，版本恒等
        assertEquals("5.4.3", VersionRules.introducedJwtVersion("pac4j-oidc", "5.4.3"));
        assertEquals(Verdict.AFFECTED,
                VersionRules.judgeJwt(VersionRules.introducedJwtVersion("pac4j-oidc", "5.4.3")));
    }

    @Test
    public void oidcBefore_3_0_0_RC1_doesNotDependOnJwt() {
        // 实测：pac4j-oidc 早期 33 个版本根本不依赖 pac4j-jwt，不能一律报危
        assertNull(VersionRules.introducedJwtVersion("pac4j-oidc", "1.7.0"));
        assertNull(VersionRules.introducedJwtVersion("pac4j-oidc", "2.3.1"));
    }

    @Test
    public void javalinVersionMapping() {
        assertEquals("3.0.0", VersionRules.introducedJwtVersion("javalin-pac4j", "1.0.0.RC0"));
        assertEquals("6.0.4.1", VersionRules.introducedJwtVersion("javalin-pac4j", "7.0.0"));
        // javalin-pac4j 8.0.0 锁的是已修复的 6.3.3
        assertEquals("6.3.3", VersionRules.introducedJwtVersion("javalin-pac4j", "8.0.0"));
        assertEquals(Verdict.NOT_AFFECTED,
                VersionRules.judgeJwt(VersionRules.introducedJwtVersion("javalin-pac4j", "8.0.0")));
        assertEquals(Verdict.AFFECTED,
                VersionRules.judgeJwt(VersionRules.introducedJwtVersion("javalin-pac4j", "7.0.0")));
    }

    @Test
    public void lagomAndRatpackMapping() {
        assertEquals("3.7.0", VersionRules.introducedJwtVersion("lagom-pac4j-parent", "2.2.1"));
        assertEquals("1.8.9", VersionRules.introducedJwtVersion("ratpack-pac4j", "1.4.6"));
        // ratpack-pac4j 2.0.0 起不再依赖 pac4j-jwt
        assertNull(VersionRules.introducedJwtVersion("ratpack-pac4j", "2.0.0"));
        assertNull(VersionRules.introducedJwtVersion("ratpack-pac4j", "5.0.0"));
    }

    @Test
    public void introducerRecognition() {
        assertTrue(VersionRules.isIntroducer("pac4j-oidc"));
        assertTrue(VersionRules.isIntroducer("javalin-pac4j"));
        assertTrue(!VersionRules.isIntroducer("pac4j-core"));
        assertTrue(!VersionRules.isIntroducer("pac4j-saml"));
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
