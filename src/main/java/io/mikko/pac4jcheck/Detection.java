package io.mikko.pac4jcheck;

/** 一次命中：在某个位置发现了 pac4j-jwt，或发现了会把它拖进来的构件。 */
public class Detection {

    /** 版本号的来源，直接影响结论可信度。 */
    public enum VersionSource {
        /** 从 META-INF/maven/.../pom.properties 读到，最可靠。 */
        POM_PROPERTIES,
        /** 从 jar 文件名推断，jar 被重命名时会失准。 */
        FILE_NAME,
        /** 拿不到版本号。 */
        UNKNOWN
    }

    /** 命中类型。 */
    public enum Kind {
        /** 直接发现 pac4j-jwt 本体。 */
        JWT_DIRECT,
        /** 发现「引入者」构件，它会拖进受影响的 pac4j-jwt —— 官方 advisory 未覆盖这类。 */
        INTRODUCER
    }

    private final String location;
    private final String artifactId;
    private final String version;
    private final VersionSource versionSource;
    private final Kind kind;
    /** 仅 INTRODUCER 有值：推断出的被拖进来的 pac4j-jwt 版本。 */
    private final String introducedJwtVersion;
    /** 有 class 却没有 Maven 元数据 —— 典型的被 shade 进宿主 jar，依赖树查不到。 */
    private final boolean shaded;
    private final boolean springBootFatJar;
    private final VersionRules.Verdict verdict;

    public Detection(String location, String artifactId, String version, VersionSource versionSource,
                     Kind kind, String introducedJwtVersion, boolean shaded, boolean springBootFatJar,
                     VersionRules.Verdict verdict) {
        this.location = location;
        this.artifactId = artifactId;
        this.version = version;
        this.versionSource = versionSource;
        this.kind = kind;
        this.introducedJwtVersion = introducedJwtVersion;
        this.shaded = shaded;
        this.springBootFatJar = springBootFatJar;
        this.verdict = verdict;
    }

    public String location() {
        return location;
    }

    public String artifactId() {
        return artifactId;
    }

    public String version() {
        return version;
    }

    public VersionSource versionSource() {
        return versionSource;
    }

    public Kind kind() {
        return kind;
    }

    public String introducedJwtVersion() {
        return introducedJwtVersion;
    }

    public boolean shaded() {
        return shaded;
    }

    public boolean springBootFatJar() {
        return springBootFatJar;
    }

    public VersionRules.Verdict verdict() {
        return verdict;
    }

    /** 判定为受影响或存疑时的建议升级目标。 */
    public String fixedVersion() {
        String v = kind == Kind.INTRODUCER ? introducedJwtVersion : version;
        return VersionRules.fixedVersionFor(v);
    }

    public Severity severity() {
        switch (verdict) {
            case AFFECTED:
                return Severity.CRITICAL;
            case DISPUTED:
                return Severity.WARN;
            case UNKNOWN:
                return Severity.UNKNOWN;
            default:
                return Severity.OK;
        }
    }
}
