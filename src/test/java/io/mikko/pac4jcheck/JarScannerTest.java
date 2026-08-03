package io.mikko.pac4jcheck;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/** 扫描器端到端测试：覆盖 fat-JAR 递归、shade、引入者溯源这三个真实场景。 */
public class JarScannerTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private static final String JWT_MARKER =
            "org/pac4j/jwt/credentials/authenticator/JwtAuthenticator.class";

    /** 造一个普通依赖 jar：带 marker class + Maven 元数据。 */
    private static byte[] libJar(String artifactId, String version) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ZipOutputStream z = new ZipOutputStream(bos);
        if ("pac4j-jwt".equals(artifactId)) {
            put(z, JWT_MARKER, "class".getBytes("UTF-8"));
        } else {
            put(z, "org/pac4j/" + artifactId.replace("pac4j-", "") + "/Client.class",
                    "class".getBytes("UTF-8"));
        }
        String props = "groupId=org.pac4j\nartifactId=" + artifactId + "\nversion=" + version + "\n";
        put(z, "META-INF/maven/org.pac4j/" + artifactId + "/pom.properties",
                props.getBytes(Charset.forName("UTF-8")));
        z.close();
        return bos.toByteArray();
    }

    private static void put(ZipOutputStream z, String name, byte[] content) throws Exception {
        z.putNextEntry(new ZipEntry(name));
        z.write(content);
        z.closeEntry();
    }

    private File write(String fileName, byte[] content) throws Exception {
        File f = tmp.newFile(fileName);
        OutputStream out = new FileOutputStream(f);
        out.write(content);
        out.close();
        return f;
    }

    private static Detection find(List<Detection> ds, String artifactId, Detection.Kind kind) {
        for (Detection d : ds) {
            if (artifactId.equals(d.artifactId()) && d.kind() == kind) {
                return d;
            }
        }
        return null;
    }

    @Test
    public void plainAffectedJar() throws Exception {
        File f = write("pac4j-jwt-5.4.3.jar", libJar("pac4j-jwt", "5.4.3"));
        JarScanner s = new JarScanner();
        s.scan(f);
        Detection d = find(s.detections(), "pac4j-jwt", Detection.Kind.JWT_DIRECT);
        assertNotNull(d);
        assertEquals("5.4.3", d.version());
        assertEquals(VersionRules.Verdict.AFFECTED, d.verdict());
        assertEquals("5.7.9", d.fixedVersion());
        assertTrue(!d.shaded());
    }

    @Test
    public void fixedVersionIsNotFlagged() throws Exception {
        File f = write("pac4j-jwt-6.3.3.jar", libJar("pac4j-jwt", "6.3.3"));
        JarScanner s = new JarScanner();
        s.scan(f);
        Detection d = find(s.detections(), "pac4j-jwt", Detection.Kind.JWT_DIRECT);
        assertEquals(VersionRules.Verdict.NOT_AFFECTED, d.verdict());
        assertNull(d.fixedVersion());
    }

    /**
     * Spring Boot fat-JAR：依赖藏在 BOOT-INF/lib/ 下，必须递归展开才能看见。
     * 同时验证 fat-JAR 标记会向下继承 —— 内层依赖 jar 自身并没有 BOOT-INF 目录，
     * 不继承就会漏掉部署形态提示（fastjson-check 有过这个真 bug）。
     */
    @Test
    public void springBootFatJarIsUnpackedRecursively() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ZipOutputStream z = new ZipOutputStream(bos);
        put(z, "BOOT-INF/classes/com/example/App.class", "x".getBytes("UTF-8"));
        put(z, "BOOT-INF/lib/pac4j-jwt-5.4.3.jar", libJar("pac4j-jwt", "5.4.3"));
        z.close();
        File f = write("demo-app.jar", bos.toByteArray());

        JarScanner s = new JarScanner();
        s.scan(f);
        Detection d = find(s.detections(), "pac4j-jwt", Detection.Kind.JWT_DIRECT);
        assertNotNull("没能进入 BOOT-INF/lib 里的嵌套 jar", d);
        assertEquals(VersionRules.Verdict.AFFECTED, d.verdict());
        assertTrue("fat-JAR 标记没有向下继承到嵌套依赖", d.springBootFatJar());
        assertTrue("位置应能溯源到嵌套路径:" + d.location(),
                d.location().contains("!/BOOT-INF/lib/pac4j-jwt-5.4.3.jar"));
    }

    /**
     * 被 shade 进宿主 jar：有 class 但没有 Maven 元数据。
     * 这类最危险 —— mvn dependency:tree 根本看不见它。
     */
    @Test
    public void shadedIntoHostJarIsFlagged() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ZipOutputStream z = new ZipOutputStream(bos);
        put(z, "com/vendor/Sdk.class", "x".getBytes("UTF-8"));
        put(z, JWT_MARKER, "class".getBytes("UTF-8"));
        z.close();
        File f = write("vendor-sdk.jar", bos.toByteArray());

        JarScanner s = new JarScanner();
        s.scan(f);
        Detection d = find(s.detections(), "pac4j-jwt", Detection.Kind.JWT_DIRECT);
        assertNotNull(d);
        assertTrue("应标记为疑似 shade", d.shaded());
        assertEquals(VersionRules.Verdict.UNKNOWN, d.verdict());
    }

    /**
     * 引入者溯源 —— 本工具相对官方 advisory 的增量价值就在这里。
     * pac4j-oidc 与 pac4j-jwt 同 reactor，版本恒等。
     */
    @Test
    public void introducerIsTracedAndFlagged() throws Exception {
        File f = write("pac4j-oidc-5.4.3.jar", libJar("pac4j-oidc", "5.4.3"));
        JarScanner s = new JarScanner();
        s.scan(f);
        Detection d = find(s.detections(), "pac4j-oidc", Detection.Kind.INTRODUCER);
        assertNotNull("没识别出引入者 pac4j-oidc", d);
        assertEquals("5.4.3", d.introducedJwtVersion());
        assertEquals(VersionRules.Verdict.AFFECTED, d.verdict());
        assertEquals("5.7.9", d.fixedVersion());
    }

    @Test
    public void introducerOnFixedVersionIsNotFlagged() throws Exception {
        File f = write("pac4j-oidc-6.3.3.jar", libJar("pac4j-oidc", "6.3.3"));
        JarScanner s = new JarScanner();
        s.scan(f);
        Detection d = find(s.detections(), "pac4j-oidc", Detection.Kind.INTRODUCER);
        assertNotNull(d);
        assertEquals(VersionRules.Verdict.NOT_AFFECTED, d.verdict());
    }

    /** pac4j-oidc 早期版本根本不依赖 pac4j-jwt，不能一律报危。 */
    @Test
    public void earlyOidcIsNotReportedAsIntroducer() throws Exception {
        File f = write("pac4j-oidc-2.3.1.jar", libJar("pac4j-oidc", "2.3.1"));
        JarScanner s = new JarScanner();
        s.scan(f);
        assertNull(find(s.detections(), "pac4j-oidc", Detection.Kind.INTRODUCER));
    }

    /** 无关的 pac4j 模块不该被误报。 */
    @Test
    public void unrelatedPac4jModuleIsIgnored() throws Exception {
        File f = write("pac4j-saml-5.4.3.jar", libJar("pac4j-saml", "5.4.3"));
        JarScanner s = new JarScanner();
        s.scan(f);
        assertTrue("pac4j-saml 不引入 pac4j-jwt，不该有任何命中", s.detections().isEmpty());
    }

    @Test
    public void directoryScanFindsAll() throws Exception {
        write("a-pac4j-jwt-5.4.3.jar", libJar("pac4j-jwt", "5.4.3"));
        write("b-pac4j-jwt-6.3.3.jar", libJar("pac4j-jwt", "6.3.3"));
        JarScanner s = new JarScanner();
        s.scan(tmp.getRoot());
        assertEquals(2, s.detections().size());
    }

    @Test
    public void jarNameParsing() {
        String[] nv = JarScanner.artifactAndVersionFromJarName("pac4j-jwt-6.0.4.1.jar");
        assertNotNull(nv);
        assertEquals("pac4j-jwt", nv[0]);
        assertEquals("6.0.4.1", nv[1]);
        assertNull(JarScanner.artifactAndVersionFromJarName("no-version.jar"));
    }
}
