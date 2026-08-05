package io.mikko.pac4jcheck;

import java.io.File;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

/**
 * CLI 入口。
 *
 * <pre>
 *   java -jar pac4j-check.jar ./myapp.jar
 *   java -jar pac4j-check.jar /opt/apps
 *   java -jar pac4j-check.jar /opt/apps --json
 * </pre>
 *
 * <p>退出码：0 = 未发现受影响；1 = 有存疑/无法判定；2 = 发现受影响。方便挂 CI。
 */
public final class Main {

    static final String VERSION = "0.2.0";

    public static void main(String[] args) {
        List<String> targets = new ArrayList<String>();
        boolean json = false;
        String encoding = null;

        for (String a : args) {
            if ("--json".equals(a)) {
                json = true;
            } else if ("--utf8".equals(a)) {
                encoding = "UTF-8";
            } else if ("--gbk".equals(a)) {
                encoding = "GBK";
            } else if ("-h".equals(a) || "--help".equals(a)) {
                printUsage(System.out);
                return;
            } else if ("-v".equals(a) || "--version".equals(a)) {
                System.out.println("pac4j-check " + VERSION);
                return;
            } else if (a.startsWith("-")) {
                System.err.println("未知参数:" + a);
                printUsage(System.err);
                System.exit(64);
                return;
            } else {
                targets.add(a);
            }
        }

        // Windows 控制台默认 GBK，直接输出中文会乱码；JSON 恒为 UTF-8（机器读）
        PrintStream out = System.out;
        String enc = json ? "UTF-8" : encoding;
        if (enc != null) {
            try {
                out = new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out), true, enc);
            } catch (UnsupportedEncodingException e) {
                // 保持默认输出流
            }
        }

        if (targets.isEmpty()) {
            printUsage(out);
            System.exit(64);
            return;
        }

        JarScanner scanner = new JarScanner();
        for (String t : targets) {
            scanner.scan(new File(t));
        }

        Severity worst = Severity.OK;
        for (Detection d : scanner.detections()) {
            worst = worst.max(d.severity());
        }

        if (json) {
            printJson(out, scanner, worst);
        } else {
            printText(out, scanner, worst);
        }
        out.flush();
        System.exit(worst.exitCode());
    }

    private static void printUsage(PrintStream out) {
        out.println("pac4j-check " + VERSION + " —— " + VersionRules.CVE
                + " (CVSS " + VersionRules.CVSS + ") 离线排查工具");
        out.println();
        out.println("用法:java -jar pac4j-check.jar <jar|war|目录> [更多路径...] [选项]");
        out.println();
        out.println("选项:");
        out.println("  --json      输出 JSON(恒为 UTF-8)");
        out.println("  --utf8      文本输出用 UTF-8");
        out.println("  --gbk       文本输出用 GBK(Windows 控制台中文乱码时用)");
        out.println("  -v          显示版本");
        out.println();
        out.println("退出码:0=未发现受影响  1=存疑/无法判定  2=发现受影响");
    }

    private static void printText(PrintStream out, JarScanner scanner, Severity worst) {
        out.println("pac4j-check " + VERSION + "  |  " + VersionRules.CVE
                + "  CVSS " + VersionRules.CVSS + "  (" + VersionRules.GHSA + ")");
        out.println("扫描归档数:" + scanner.scannedArchives());
        out.println();

        if (scanner.detections().isEmpty()) {
            out.println("[OK] 未发现 pac4j-jwt。");
        }

        for (Detection d : scanner.detections()) {
            String label = d.kind() == Detection.Kind.JWT_DIRECT
                    ? "pac4j-jwt " + nvl(d.version())
                    : d.artifactId() + " " + nvl(d.version());
            out.println("[" + d.severity() + "] " + label);
            out.println("  位置    :" + d.location());
            out.println("  版本来源:" + describeSource(d.versionSource()));

            if (d.kind() == Detection.Kind.INTRODUCER) {
                out.println("  引入链  :" + d.artifactId() + ":" + d.version()
                        + "  ->  pac4j-jwt:" + d.introducedJwtVersion());
                out.println("  ⚠ 注意  :官方 advisory 未列出 " + d.artifactId()
                        + ",Dependabot 不会因此告警");
            }
            if (d.shaded()) {
                out.println("  ⚠ 注意  :未找到 Maven 元数据,疑似被 shade 进宿主 jar —— "
                        + "mvn dependency:tree 查不到这类");
            }
            if (d.springBootFatJar()) {
                out.println("  部署形态:Spring Boot fat-JAR");
            }

            switch (d.verdict()) {
                case AFFECTED:
                    out.println("  结论    :命中 " + VersionRules.CVE + " —— JWE 处理路径未强制校验签名,"
                            + "拿到服务器 RSA 公钥即可伪造任意身份(含管理员)登录");
                    out.println("  处置    :升级 pac4j-jwt 至 " + d.fixedVersion());
                    break;
                case DISPUTED:
                    out.println("  结论    :⚠ 存疑 —— 官方 advisory 称 6.x 自 6.0.4.1 起受影响,"
                            + "该版本不在其中;但第三方研究称漏洞早在 1.9.2 已引入");
                    out.println("  处置    :本工具未独立验证第三方结论,建议按保守处理升级至 "
                            + d.fixedVersion());
                    break;
                case UNKNOWN:
                    out.println("  结论    :拿不到版本号,无法判定,请人工确认");
                    break;
                default:
                    out.println("  结论    :不在官方受影响区间");
                    break;
            }
            out.println();
        }

        for (String w : scanner.warnings()) {
            out.println("[warn] " + w);
        }

        out.println("总体结论:" + worst);
    }

    private static void printJson(PrintStream out, JarScanner scanner, Severity worst) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"tool\": \"pac4j-check\",\n");
        sb.append("  \"toolVersion\": \"").append(VERSION).append("\",\n");
        sb.append("  \"cve\": \"").append(VersionRules.CVE).append("\",\n");
        sb.append("  \"ghsa\": \"").append(VersionRules.GHSA).append("\",\n");
        sb.append("  \"cvss\": \"").append(VersionRules.CVSS).append("\",\n");
        sb.append("  \"scannedArchives\": ").append(scanner.scannedArchives()).append(",\n");
        sb.append("  \"overall\": \"").append(worst).append("\",\n");
        sb.append("  \"detections\": [\n");
        List<Detection> ds = scanner.detections();
        for (int i = 0; i < ds.size(); i++) {
            Detection d = ds.get(i);
            sb.append("    {\n");
            sb.append("      \"kind\": \"").append(d.kind()).append("\",\n");
            sb.append("      \"artifactId\": \"").append(esc(d.artifactId())).append("\",\n");
            sb.append("      \"version\": ").append(quoteOrNull(d.version())).append(",\n");
            sb.append("      \"introducedJwtVersion\": ").append(quoteOrNull(d.introducedJwtVersion())).append(",\n");
            sb.append("      \"location\": \"").append(esc(d.location())).append("\",\n");
            sb.append("      \"versionSource\": \"").append(d.versionSource()).append("\",\n");
            sb.append("      \"shaded\": ").append(d.shaded()).append(",\n");
            sb.append("      \"springBootFatJar\": ").append(d.springBootFatJar()).append(",\n");
            sb.append("      \"verdict\": \"").append(d.verdict()).append("\",\n");
            sb.append("      \"severity\": \"").append(d.severity()).append("\",\n");
            sb.append("      \"fixedVersion\": ").append(quoteOrNull(d.fixedVersion())).append("\n");
            sb.append("    }").append(i < ds.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ],\n");
        sb.append("  \"warnings\": [\n");
        List<String> ws = scanner.warnings();
        for (int i = 0; i < ws.size(); i++) {
            sb.append("    \"").append(esc(ws.get(i))).append("\"")
              .append(i < ws.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ]\n");
        sb.append("}");
        out.println(sb);
    }

    private static String describeSource(Detection.VersionSource s) {
        switch (s) {
            case POM_PROPERTIES:
                return "pom.properties(可靠)";
            case FILE_NAME:
                return "jar 文件名(jar 被改名会失准)";
            default:
                return "未知";
        }
    }

    private static String nvl(String s) {
        return s == null ? "(版本未知)" : s;
    }

    private static String quoteOrNull(String s) {
        return s == null ? "null" : "\"" + esc(s) + "\"";
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    private Main() {
    }
}
