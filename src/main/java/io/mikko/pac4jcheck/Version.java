package io.mikko.pac4jcheck;

import java.util.ArrayList;
import java.util.List;

/**
 * Maven 版本号的可比较表示。
 *
 * <p>这里不用完整的 Maven 版本语义，只覆盖 pac4j 实际用到的形态，但必须覆盖对：
 * <ul>
 *   <li>四段版本 —— {@code 6.0.4.1}（官方 advisory 的 6.x 区间下界就是它）</li>
 *   <li>预发布 —— {@code 5.0.0-RC1}（官方 5.x 区间下界），{@code 1.8.0-RC1}</li>
 * </ul>
 *
 * <p>预发布排在同数字段的正式版之前：{@code 5.0.0-RC1 < 5.0.0}。
 * 这条直接决定区间边界判定，写反了会让 5.0.0 正式版逃出受影响区间。
 */
final class Version implements Comparable<Version> {

    private final String raw;
    private final int[] parts;
    /** 是否带预发布后缀（RC / M / alpha / beta / SNAPSHOT 等）。 */
    private final boolean preRelease;
    /** 预发布后缀原文，用于同为预发布时再比一次。 */
    private final String preTag;

    private Version(String raw, int[] parts, boolean preRelease, String preTag) {
        this.raw = raw;
        this.parts = parts;
        this.preRelease = preRelease;
        this.preTag = preTag;
    }

    static Version parse(String s) {
        if (s == null) {
            return null;
        }
        String v = s.trim();
        if (v.isEmpty()) {
            return null;
        }
        // 数字段与后缀的分界：第一个不是数字也不是点的字符
        int cut = -1;
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c != '.' && (c < '0' || c > '9')) {
                cut = i;
                break;
            }
        }
        String numeric = cut < 0 ? v : v.substring(0, cut);
        String suffix = cut < 0 ? "" : v.substring(cut);
        // 去掉数字段末尾可能残留的分隔符，如 "1.8.0-RC1" 切出来是 "1.8.0" + "-RC1"
        while (numeric.endsWith(".") || numeric.endsWith("-") || numeric.endsWith("_")) {
            numeric = numeric.substring(0, numeric.length() - 1);
        }
        if (numeric.isEmpty()) {
            return null;
        }

        String[] segs = numeric.split("\\.");
        List<Integer> nums = new ArrayList<Integer>();
        for (String seg : segs) {
            if (seg.isEmpty()) {
                continue;
            }
            try {
                nums.add(Integer.valueOf(Integer.parseInt(seg)));
            } catch (NumberFormatException e) {
                return null;
            }
        }
        if (nums.isEmpty()) {
            return null;
        }
        int[] arr = new int[nums.size()];
        for (int i = 0; i < nums.size(); i++) {
            arr[i] = nums.get(i).intValue();
        }

        String tag = suffix;
        while (tag.startsWith(".") || tag.startsWith("-") || tag.startsWith("_")) {
            tag = tag.substring(1);
        }
        boolean pre = !tag.isEmpty();
        return new Version(v, arr, pre, tag);
    }

    public String raw() {
        return raw;
    }

    @Override
    public int compareTo(Version other) {
        int n = Math.max(parts.length, other.parts.length);
        for (int i = 0; i < n; i++) {
            // 缺失的段按 0 补：6.0.4 与 6.0.4.0 视为相等
            int a = i < parts.length ? parts[i] : 0;
            int b = i < other.parts.length ? other.parts[i] : 0;
            if (a != b) {
                return a < b ? -1 : 1;
            }
        }
        if (preRelease != other.preRelease) {
            // 预发布小于同数字段的正式版
            return preRelease ? -1 : 1;
        }
        if (preRelease) {
            return preTag.compareToIgnoreCase(other.preTag);
        }
        return 0;
    }

    boolean lt(Version o) {
        return compareTo(o) < 0;
    }

    boolean gte(Version o) {
        return compareTo(o) >= 0;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Version && compareTo((Version) o) == 0;
    }

    @Override
    public int hashCode() {
        int h = 0;
        for (int p : parts) {
            h = h * 31 + p;
        }
        return h * 31 + (preRelease ? 1 : 0);
    }

    @Override
    public String toString() {
        return raw;
    }
}
