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
    /** Partner alerts: ntfy server + topic ("" until a partner is set up). */
    val ntfyServer: String = "https://ntfy.sh",
    val ntfyTopic: String = "",
    /** Blocked search keywords, already normalised by Python ("free porn"). */
    val keywords: List<String> = emptyList(),
    /** Apps that app blocks and schedules never cover (Bible, banking, phone...). */
    val alwaysAllow: Set<String> = emptySet(),
) {
    val upstream: List<String> = if (familyDns) familyServers else PLAIN_DNS

    /** Protective switches from Settings (browser_overlay, feed_youtube_shorts, ...); on unless set. */
    fun flag(key: String): Boolean = flags[key] ?: true

    /**
     * Always-blocked apps plus apps inside an active schedule window.
     * ``mondayIndex`` is 0 for Monday like Python's ``weekday()``.
     */
    fun appBlocked(pkg: String, mondayIndex: Int, minute: Int): Boolean =
        pkg !in alwaysAllow &&
            (pkg in apps || schedules.any { pkg in it.packages && it.activeAt(mondayIndex, minute) })

    /** The first blocked keyword in ``text`` (punctuation counts as a space), mirrors guard.keyword_in. */
    fun keywordIn(text: String): String? {
        if (keywords.isEmpty()) return null
        val flat = " " + text.lowercase().replace(NOT_WORD, " ").trim() + " "
        return keywords.firstOrNull { flat.contains(it) }
    }

    fun decide(rawHost: String): Decision {
        val host = rawHost.trimEnd('.').lowercase()
        if (flag("dork_guard")) {
            // caches / archives / reader proxies that show other sites' pages
            if (mostSpecific(host, DORK_BLOCK) != null && mostSpecific(host, allow) == null) return Decision.BLOCK
            // Google Translate as a proxy: www-reddit-com.translate.goog serves reddit.com
            proxiedHost(host)?.let { inner -> if (decideRules(inner) == Decision.BLOCK) return Decision.BLOCK }
        }
        val ruled = decideRules(host)
        // a site whose name contains a blocked keyword (free-porn-site.com)
        if (ruled == Decision.DEFAULT && keywordIn(host) != null) return Decision.BLOCK
        return ruled
    }

    private fun decideRules(host: String): Decision {
        val b = mostSpecific(host, block + BUILTIN_BLOCK)
        val a = mostSpecific(host, allow + BUILTIN_ALLOW)
        if (b == null && a == null) return Decision.DEFAULT
        if (a != null && (b == null || a.length >= b.length)) return Decision.ALLOW
        return Decision.BLOCK
    }

    companion object {
        val FAMILY_DNS = listOf("1.1.1.3", "1.0.0.3")
        val PLAIN_DNS = listOf("1.1.1.1", "1.0.0.1")
        private val NOT_WORD = Regex("[^0-9a-z\u00c0-\uffff]+")

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

        /**
         * With dorking protection on: services that display another site's pages
         * under their own name (search-engine caches, web archives, paywall/reader
         * proxies), which would otherwise show blocked sites. A user's own
         * whitelist entry still wins.
         */
        val DORK_BLOCK = listOf(
            "webcache.googleusercontent.com",
            "cachedview.nl",
            "cachedview.com",
            "cachedviews.com",
            "web.archive.org",
            "wayback.archive.org",
            "archive.today",
            "archive.ph",
            "archive.is",
            "archive.li",
            "archive.vn",
            "archive.md",
            "archive.fo",
            "ghostarchive.org",
            "12ft.io",
            "removepaywall.com",
            "archive.ec",
            "proxysite.com",
            "croxyproxy.com",
            "hide.me",
            "hidester.com",
            "kproxy.com",
        )

        /**
         * Google Translate's proxy names: "www-reddit-com.translate.goog" serves
         * www.reddit.com ("-" stands for "." and "--" for a real "-"). Returns the
         * real host, or null for anything else.
         */
        fun proxiedHost(host: String): String? {
            val h = host.trimEnd('.').lowercase()
            if (!h.endsWith(".translate.goog")) return null
            val encoded = h.removeSuffix(".translate.goog").substringAfterLast('.')
            if (encoded.isEmpty()) return null
            val decoded = encoded.replace("--", "\u0000").replace('-', '.').replace('\u0000', '-')
            return decoded.takeIf { it.contains('.') && !it.startsWith('.') && !it.endsWith('.') }
        }

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
                ntfyServer = settings.optString("ntfy_server", "https://ntfy.sh").ifBlank { "https://ntfy.sh" },
                ntfyTopic = settings.optString("ntfy_topic", ""),
                keywords = root.optJSONArray("keywords").toStrings(),
                alwaysAllow = root.optJSONArray("always_allow").toStrings(lower = false).toSet(),
            )
        }

        private fun org.json.JSONArray?.toStrings(lower: Boolean = true): List<String> =
            if (this == null) emptyList()
            else (0 until length()).map { getString(it).let { s -> if (lower) s.lowercase() else s } }
    }
}
