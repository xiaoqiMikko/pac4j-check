package io.mikko.pac4jcheck;

/** 结论等级。进程退出码按最高等级给，方便挂到 CI 上。 */
public enum Severity {

    /** 命中官方受影响区间。 */
    CRITICAL(2),
    /** 落在官方与第三方口径不一致的区间，需人工确认。 */
    WARN(1),
    /** 拿不到版本号，无法判定。 */
    UNKNOWN(1),
    /** 不受影响。 */
    OK(0);

    private final int exitCode;

    Severity(int exitCode) {
        this.exitCode = exitCode;
    }

    public int exitCode() {
        return exitCode;
    }

    /** 取更严重的那个。 */
    public Severity max(Severity other) {
        return this.exitCode >= other.exitCode ? this : other;
    }
}
