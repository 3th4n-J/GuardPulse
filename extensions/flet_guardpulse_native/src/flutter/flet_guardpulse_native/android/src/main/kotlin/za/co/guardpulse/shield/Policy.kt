package za.co.guardpulse.shield

import java.io.File
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject

enum class Decision { ALLOW, BLOCK, DEFAULT }

/** A scheduled app lock; mirrors guardpulse.guard.Schedule.active_at (bit 0 of ``days`` = Monday). */
class LockWindow(val days: Int, val startMin: Int, val endMin: Int, val packages: Set<String>) {
    fun activeAt(mondayIndex: Int, minute: Int): Boolean {
        if (startMin <= endMin) {
            return (days shr mondayIndex) and 1 == 1 && minute >= startMin && minute < endMin
        }
        // overnight: the evening part belongs to today, the morning part to yesterday
        if (minute >= startMin) return (days shr mondayIndex) and 1 == 1
        val yesterday = (mondayIndex + 6) % 7
        return (days shr yesterday) and 1 == 1 && minute < endMin
    }
}

/**
 * The rule set the Python side writes to policy.json (signed with policy.sig).
 * Matching mirrors guardpulse/domains.py: a rule covers the host and every
 * sub-domain, the most specific rule wins and an equal-length allow beats a block.
 */
class Policy(
    val block: List<String>,
    val allow: List<String>,
    val familyDns: Boolean,
    familyServers: List<String>,
    val apps: Set<String> = emptySet(),
    val schedules: List<LockWindow> = emptyList(),
    private val flags: Map<String, Boolean> = emptyMap(),
) {
    val upstream: List<String> = if (familyDns) familyServers else PLAIN_DNS

    /** Protective switches from Settings (browser_overlay, feed_youtube_shorts, ...); on unless set. */
    fun flag(key: String): Boolean = flags[key] ?: true

    /**
     * Always-blocked apps plus apps inside an active schedule window.
     * ``mondayIndex`` is 0 for Monday like Python's ``weekday()``.
     */
    fun appBlocked(pkg: String, mondayIndex: Int, minute: Int): Boolean =
        pkg in apps || schedules.any { pkg in it.packages && it.activeAt(mondayIndex, minute) }

    fun decide(rawHost: String): Decision {
        val host = rawHost.trimEnd('.').lowercase()
        val b = mostSpecific(host, block + BUILTIN_BLOCK)
        val a = mostSpecific(host, allow + BUILTIN_ALLOW)
        if (b == null && a == null) return Decision.DEFAULT
        if (a != null && (b == null || a.length >= b.length)) return Decision.ALLOW
        return Decision.BLOCK
    }

    companion object {
        val FAMILY_DNS = listOf("1.1.1.3", "1.0.0.3")
        val PLAIN_DNS = listOf("1.1.1.1", "1.0.0.1")

        /** Used before the first policy loads or when the signature is bad: filter, block nothing extra. */
        val SAFE_DEFAULT = Policy(emptyList(), emptyList(), true, FAMILY_DNS)

        /**
         * Encrypted-DNS endpoints that would let a browser skip this filter, plus
         * Firefox's canary domain (NXDOMAIN there switches Firefox's DoH off).
         */
        val BUILTIN_BLOCK = listOf(
            "use-application-dns.net",
            "dns.google",
            "dns.google.com",
            "cloudflare-dns.com",
            "doh.opendns.com",
            "dns.quad9.net",
            "dns.nextdns.io",
            "doh.cleanbrowsing.org",
            "dns.adguard-dns.com",
            "dns.adguard.com",
        )

        /** Cloudflare Family's own DoT/DoH name must keep resolving. */
        val BUILTIN_ALLOW = listOf("family.cloudflare-dns.com")

        fun mostSpecific(host: String, rules: List<String>): String? {
            var best: String? = null
            for (rule in rules) {
                if ((host == rule || host.endsWith(".$rule")) && (best == null || rule.length > best.length)) {
                    best = rule
                }
            }
            return best
        }

        /** Load and verify; returns null when the files are missing or the HMAC doesn't match. */
        fun load(folder: File): Policy? {
            val json = File(folder, "policy.json")
            val sig = File(folder, "policy.sig")
            val key = File(folder, "seal.key")
            if (!json.exists() || !sig.exists() || !key.exists()) return null
            val payload = json.readBytes()
            val expected = sig.readText().trim()
            val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key.readBytes(), "HmacSHA256")) }
            val actual = mac.doFinal(payload).joinToString("") { "%02x".format(it) }
            if (!MessageDigest.isEqual(actual.toByteArray(), expected.toByteArray())) return null

            val root = JSONObject(String(payload, Charsets.UTF_8))
            val settings = root.optJSONObject("settings") ?: JSONObject()
            val dns = root.optJSONObject("dns")?.optJSONArray("v4")
            val flags = mutableMapOf<String, Boolean>()
            for (key in settings.keys()) {
                val value = settings.opt(key)
                if (value is Boolean) flags[key] = value
            }
            val windows = root.optJSONArray("schedules")
            return Policy(
                block = root.optJSONArray("block").toStrings(),
                allow = root.optJSONArray("allow").toStrings(),
                familyDns = settings.optBoolean("family_dns", true),
                familyServers = dns.toStrings().ifEmpty { FAMILY_DNS },
                // package names are case-sensitive, so no lower-casing here
                apps = root.optJSONArray("apps").toStrings(lower = false).toSet(),
                schedules = if (windows == null) emptyList() else (0 until windows.length()).map {
                    val w = windows.getJSONObject(it)
                    LockWindow(
                        days = w.optInt("days"),
                        startMin = w.optInt("start_min"),
                        endMin = w.optInt("end_min"),
                        packages = w.optJSONArray("packages").toStrings(lower = false).toSet(),
                    )
                },
                flags = flags,
            )
        }

        private fun org.json.JSONArray?.toStrings(lower: Boolean = true): List<String> =
            if (this == null) emptyList()
            else (0 until length()).map { getString(it).let { s -> if (lower) s.lowercase() else s } }
    }
}
