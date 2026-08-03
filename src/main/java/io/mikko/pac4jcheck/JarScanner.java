package io.mikko.pac4jcheck;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 扫描器：在 jar / war / 目录中寻找 pac4j-jwt，以及会把它拖进来的构件。
 *
 * <p>关键能力是<b>递归进入嵌套 jar</b>。Spring Boot fat-JAR 把依赖全打进
 * {@code BOOT-INF/lib/}，传统做法必须先解压；本扫描器直接在内存里逐层展开，不落地。
 *
 * <p>与 fastjson-check 的差别在于：这次不只找一个构件，还要找出<b>是谁把它拖进来的</b>。
 * 官方 advisory 只列了 {@code org.pac4j:pac4j-jwt} 一个包，
 * 而实测另有 {@code pac4j-oidc} 等 4 个构件会引入受影响版本 ——
 * 用 OIDC 做单点登录的人根本不知道自己依赖了 pac4j-jwt，Dependabot 也不会提醒他们。
 */
public class JarScanner {

    /** pac4j-jwt 的标志性 class —— 漏洞就在这个类的 JWE 处理路径上。 */
    private static final String MARKER_JWT =
            "org/pac4j/jwt/credentials/authenticator/JwtAuthenticator.class";

    /** 退一步的标志：jwt 包下任意 class（用于识别被 shade 且主类被裁剪的情况）。 */
    private static final String MARKER_JWT_PKG_PREFIX = "org/pac4j/jwt/";

    /** META-INF/maven/{groupId}/{artifactId}/pom.properties */
    private static final Pattern POM_PROPS =
            Pattern.compile("^META-INF/maven/([^/]+)/([^/]+)/pom\\.properties$");

    /** 从 jar 文件名提取构件名与版本，如 pac4j-jwt-5.4.3.jar、pac4j-oidc-6.0.4.1.jar。 */
    private static final Pattern JAR_NAME =
            Pattern.compile("^([a-zA-Z][a-zA-Z0-9._-]*?)-(\\d+(?:\\.\\d+)*(?:[._-][A-Za-z0-9]+)*)\\.jar$");

    private static final long MAX_NESTED_ENTRY_BYTES = 64L * 1024 * 1024;
    private static final int MAX_DEPTH = 8;

    private final List<Detection> detections = new ArrayList<Detection>();
    private final List<String> warnings = new ArrayList<String>();
    private int scannedArchives;

    public List<Detection> detections() {
        return detections;
    }

    public List<String> warnings() {
        return warnings;
    }

    public int scannedArchives() {
        return scannedArchives;
    }

    /** 扫描一个路径，可以是 jar/war 文件，也可以是目录（递归查找归档）。 */
    public void scan(File target) {
        if (!target.exists()) {
            warnings.add("路径不存在:" + target.getPath());
            return;
        }
        if (target.isDirectory()) {
            scanDirectory(target);
        } else if (isArchive(target.getName())) {
            scanArchiveFile(target);
        } else {
            warnings.add("跳过(不是 jar/war/ear):" + target.getPath());
        }
    }

    private void scanDirectory(File dir) {
        File[] children = dir.listFiles();
        if (children == null) {
            warnings.add("目录无法读取:" + dir.getPath());
            return;
        }
        for (File child : children) {
            if (child.isDirectory()) {
                scanDirectory(child);
            } else if (isArchive(child.getName())) {
                scanArchiveFile(child);
            }
        }
    }

    private void scanArchiveFile(File file) {
        InputStream in = null;
        try {
            in = new FileInputStream(file);
            scanArchiveStream(in, file.getPath(), file.getName(), 0, false);
        } catch (IOException e) {
            warnings.add("读取失败 " + file.getPath() + ":" + e.getMessage());
        } finally {
            closeQuietly(in);
        }
    }

    /**
     * @param inFatJar 外层是否为 Spring Boot fat-JAR。必须向下传递 ——
     *                 BOOT-INF/lib/ 里的依赖 jar 自身不含 BOOT-INF 目录，
     *                 不继承这个标记就会漏掉部署形态的提示。
     *                 （fastjson-check 曾因此有过一个真 bug）
     */
    private void scanArchiveStream(InputStream in, String location, String archiveName, int depth,
                                   boolean inFatJar) throws IOException {
        if (depth > MAX_DEPTH) {
            warnings.add("嵌套层级超过上限,已停止深入:" + location);
            return;
        }
        scannedArchives++;

        boolean hasJwtMarker = false;
        boolean hasJwtPackage = false;
        boolean springBootFatJar = false;
        // artifactId -> version，来自 pom.properties（仅取 org.pac4j 下的）
        Map<String, String> pac4jArtifacts = new LinkedHashMap<String, String>();
        List<NestedArchive> nested = new ArrayList<NestedArchive>();

        ZipInputStream zis = new ZipInputStream(in);
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            String name = entry.getName();

            if (name.startsWith("BOOT-INF/")) {
                springBootFatJar = true;
            }

            if (MARKER_JWT.equals(name)) {
                hasJwtMarker = true;
            } else if (name.startsWith(MARKER_JWT_PKG_PREFIX) && name.endsWith(".class")) {
                hasJwtPackage = true;
            }

            Matcher pm = POM_PROPS.matcher(name);
            if (pm.matches()) {
                String groupId = pm.group(1);
                String artifactId = pm.group(2);
                if (groupId.startsWith("org.pac4j")) {
                    String v = readVersionFromPomProperties(zis);
                    if (v != null) {
                        pac4jArtifacts.put(artifactId, v);
                    }
                }
            } else if (!entry.isDirectory() && isArchive(name)) {
                long size = entry.getSize();
                if (size > MAX_NESTED_ENTRY_BYTES) {
                    warnings.add("嵌套包过大已跳过(" + size + " 字节):" + location + "!/" + name);
                    continue;
                }
                byte[] bytes = readAllBytes(zis, MAX_NESTED_ENTRY_BYTES);
                if (bytes != null) {
                    nested.add(new NestedArchive(name, bytes));
                }
            }
        }

        boolean fatJarContext = springBootFatJar || inFatJar;

        // 1) pac4j-jwt 本体
        String jwtVersion = pac4jArtifacts.get("pac4j-jwt");
        if (hasJwtMarker || hasJwtPackage || jwtVersion != null) {
            recordJwt(location, archiveName, jwtVersion, fatJarContext);
        }

        // 2) 引入者 —— 官方 advisory 完全没覆盖的部分
        for (Map.Entry<String, String> e : pac4jArtifacts.entrySet()) {
            String artifactId = e.getKey();
            if (!VersionRules.isIntroducer(artifactId)) {
                continue;
            }
            String introduced = VersionRules.introducedJwtVersion(artifactId, e.getValue());
            if (introduced == null) {
                continue; // 该版本不引入 pac4j-jwt
            }
            detections.add(new Detection(location, artifactId, e.getValue(),
                    Detection.VersionSource.POM_PROPERTIES, Detection.Kind.INTRODUCER,
                    introduced, false, fatJarContext, VersionRules.judgeJwt(introduced)));
        }

        for (NestedArchive na : nested) {
            String childLocation = location + "!/" + na.entryName;
            String childName = na.entryName.substring(na.entryName.lastIndexOf('/') + 1);
            try {
                scanArchiveStream(new ByteArrayInputStream(na.content), childLocation, childName,
                        depth + 1, fatJarContext);
            } catch (IOException e) {
                warnings.add("嵌套包读取失败 " + childLocation + ":" + e.getMessage());
            }
        }
    }

    private void recordJwt(String location, String archiveName, String versionFromPom,
                           boolean springBootFatJar) {
        String version = versionFromPom;
        Detection.VersionSource source = Detection.VersionSource.POM_PROPERTIES;

        if (version == null) {
            String[] nv = artifactAndVersionFromJarName(archiveName);
            if (nv != null && "pac4j-jwt".equals(nv[0])) {
                version = nv[1];
                source = Detection.VersionSource.FILE_NAME;
            } else {
                source = Detection.VersionSource.UNKNOWN;
            }
        }

        // 有 class 却没有 Maven 元数据 —— 被 shade 进宿主 jar，mvn dependency:tree 看不见它
        boolean shaded = versionFromPom == null && !looksLikeJwtJar(archiveName);

        detections.add(new Detection(location, "pac4j-jwt", version, source,
                Detection.Kind.JWT_DIRECT, null, shaded, springBootFatJar,
                VersionRules.judgeJwt(version)));
    }

    private static String readVersionFromPomProperties(InputStream in) {
        byte[] bytes = readAllBytes(in, 64 * 1024);
        if (bytes == null) {
            return null;
        }
        Properties props = new Properties();
        try {
            props.load(new ByteArrayInputStream(bytes));
        } catch (IOException e) {
            return null;
        }
        String v = props.getProperty("version");
        return (v != null && !v.trim().isEmpty()) ? v.trim() : null;
    }

    /** 从 jar 文件名切出 {artifactId, version}；切不出返回 null。 */
    static String[] artifactAndVersionFromJarName(String jarName) {
        if (jarName == null) {
            return null;
        }
        Matcher m = JAR_NAME.matcher(jarName);
        return m.matches() ? new String[]{m.group(1), m.group(2)} : null;
    }

    private static boolean looksLikeJwtJar(String jarName) {
        return jarName != null && jarName.startsWith("pac4j-jwt") && jarName.endsWith(".jar");
    }

    static boolean isArchive(String name) {
        if (name == null) {
            return false;
        }
        String lower = name.toLowerCase();
        return lower.endsWith(".jar") || lower.endsWith(".war") || lower.endsWith(".ear");
    }

    private static byte[] readAllBytes(InputStream in, long limit) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            long total = 0;
            int n;
            while ((n = in.read(buf)) > 0) {
                total += n;
                if (total > limit) {
                    return null;
                }
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    private static void closeQuietly(InputStream in) {
        if (in != null) {
            try {
                in.close();
            } catch (IOException ignored) {
                // 关闭失败不影响结果
            }
        }
    }

    private static final class NestedArchive {
        final String entryName;
        final byte[] content;

        NestedArchive(String entryName, byte[] content) {
            this.entryName = entryName;
            this.content = content;
        }
    }
}
