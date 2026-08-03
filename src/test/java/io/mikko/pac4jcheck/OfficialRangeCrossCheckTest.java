package io.mikko.pac4jcheck;

import org.junit.Test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * <b>自校验：把本工具的判定结果与官方漏洞库对账。</b>
 *
 * <p>这个测试是整个工具可信度的地基。判定规则是 pac4j-check 的全部价值，
 * 而规则写错不是误报，是<b>让用户做错事</b>（第一注 fastjson-check 就栽在这里：
 * 上界写死导致把已修复版本报成高危，还建议做大版本迁移）。
 *
 * <p>做法：取 Maven Central 上 pac4j-jwt 的全部 147 个版本，逐个跑本工具的判定，
 * 统计命中官方受影响区间的数量，必须精确等于 OSV / GitHub advisory
 * {@code GHSA-pm7g-w2cf-q238} 声明的三段区间版本数之和：
 * <pre>
 *   &lt; 4.5.9                    68 个
 *   &gt;= 5.0.0-RC1, &lt; 5.7.9    33 个
 *   &gt;= 6.0.4.1,  &lt; 6.3.3     13 个
 *   ------------------------------
 *   合计                        114 个
 * </pre>
 *
 * <p>对上了，才有资格谈「官方漏掉了另外 4 个包」这个增量结论 ——
 * 否则连基准都算错，增量部分一文不值。
 */
public class OfficialRangeCrossCheckTest {

    /** OSV / GitHub advisory GHSA-pm7g-w2cf-q238 三段区间的版本数之和。 */
    private static final int OSV_AFFECTED_COUNT = 114;

    /** Maven Central 上 pac4j-jwt 的版本总数（2026-08-04 拉取）。 */
    private static final int TOTAL_VERSIONS = 147;

    private List<String> loadVersions() throws Exception {
        InputStream in = getClass().getClassLoader().getResourceAsStream("pac4j-jwt-versions.txt");
        assertNotNull("缺少测试资源 pac4j-jwt-versions.txt", in);
        List<String> out = new ArrayList<String>();
        BufferedReader r = new BufferedReader(new InputStreamReader(in, Charset.forName("UTF-8")));
        String line;
        while ((line = r.readLine()) != null) {
            line = line.trim();
            if (!line.isEmpty() && !line.startsWith("#")) {
                out.add(line);
            }
        }
        r.close();
        return out;
    }

    @Test
    public void versionListIsIntact() throws Exception {
        assertEquals("版本清单条数与拉取时不符，说明资源文件被改动过", TOTAL_VERSIONS, loadVersions().size());
    }

    @Test
    public void affectedCountMatchesOfficialAdvisory() throws Exception {
        List<String> versions = loadVersions();
        List<String> affected = new ArrayList<String>();
        List<String> unknown = new ArrayList<String>();
        for (String v : versions) {
            VersionRules.Verdict verdict = VersionRules.judgeJwt(v);
            if (verdict == VersionRules.Verdict.AFFECTED) {
                affected.add(v);
            } else if (verdict == VersionRules.Verdict.UNKNOWN) {
                unknown.add(v);
            }
        }
        assertTrue("有版本号解析不了，判定逻辑会漏判：" + unknown, unknown.isEmpty());
        assertEquals("与官方 advisory 对账失败 —— 判定逻辑有问题，不要发布",
                OSV_AFFECTED_COUNT, affected.size());
    }

    @Test
    public void disputedRangeIsExactlyTheFiveVersions() throws Exception {
        // 官方称 6.x 自 6.0.4.1 起受影响，第三方称漏洞自 1.9.2 就存在。
        // 差异恰好落在这 5 个版本上，把它们单独标出而不并入 AFFECTED。
        List<String> disputed = new ArrayList<String>();
        for (String v : loadVersions()) {
            if (VersionRules.judgeJwt(v) == VersionRules.Verdict.DISPUTED) {
                disputed.add(v);
            }
        }
        assertEquals(Arrays.asList("6.0.0", "6.0.1", "6.0.2", "6.0.3", "6.0.4"), disputed);
    }

    @Test
    public void everyAffectedVersionGetsAFixTarget() throws Exception {
        // 判定为受影响却给不出升级目标，等于告诉用户「你完蛋了但我不知道怎么办」
        for (String v : loadVersions()) {
            VersionRules.Verdict verdict = VersionRules.judgeJwt(v);
            if (verdict == VersionRules.Verdict.AFFECTED || verdict == VersionRules.Verdict.DISPUTED) {
                assertNotNull("受影响版本 " + v + " 没有对应的修复版本",
                        VersionRules.fixedVersionFor(v));
            }
        }
    }
}
