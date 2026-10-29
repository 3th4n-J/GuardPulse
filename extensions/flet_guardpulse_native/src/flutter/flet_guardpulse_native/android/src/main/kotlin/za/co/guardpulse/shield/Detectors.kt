package za.co.guardpulse.shield

import java.net.URI

/**
 * What the security overlay looks for on screen. Kept free of Android types so
 * it can be unit-tested on the JVM. View ids are app-version specific: when a
 * browser or social app redesigns, add the new id here.
 */
object Detectors {

    /** Browser package -> view ids of its address bar (first match wins). */
    val BROWSER_URL_BARS: Map<String, List<String>> = mapOf(
        "com.android.chrome" to listOf("url_bar"),
        "com.chrome.beta" to listOf("url_bar"),
        "com.chrome.dev" to listOf("url_bar"),
        "com.brave.browser" to listOf("url_bar"),
        "com.microsoft.emmx" to listOf("url_bar"),
        "com.vivaldi.browser" to listOf("url_bar"),
        "com.kiwibrowser.browser" to listOf("url_bar"),
        "org.mozilla.firefox" to listOf("mozac_browser_toolbar_url_view", "url_bar_title"),
        "org.mozilla.firefox_beta" to listOf("mozac_browser_toolbar_url_view"),
        "org.mozilla.focus" to listOf("mozac_browser_toolbar_url_view", "display_url"),
        "com.sec.android.app.sbrowser" to listOf("location_bar_edit_text", "custom_tab_toolbar_url_bar_text"),
        "com.opera.browser" to listOf("url_field"),
        "com.opera.mini.native" to listOf("url_field"),
        "com.duckduckgo.mobile.android" to listOf("omnibarTextInput"),
        "com.mi.globalbrowser" to listOf("url"),
        "com.UCMobile.intl" to listOf("titlebar_text"),
    )

    /**
     * A short-video feed inside an otherwise allowed app. ``viewIds`` are
     * containers that only exist while the feed is open; ``selectedLabels``
     * catch apps with obfuscated ids (a selected tab whose text or content
     * description matches).
     */
    class Feed(
        val setting: String,
        val packageName: String,
        val label: String,
        val viewIds: List<String>,
        val selectedLabels: List<String> = emptyList(),
    )

    val FEEDS: List<Feed> = listOf(
        Feed(
            "feed_youtube_shorts",
            "com.google.android.youtube",
            "YouTube Shorts",
            listOf("reel_recycler", "reel_player_page_container", "reel_watch_player", "shorts_container"),
            listOf("Shorts"),
        ),
        Feed(
            "feed_instagram_reels",
            "com.instagram.android",
            "Instagram Reels",
            listOf("clips_viewer_view_pager", "clips_viewer_container", "clips_video_container"),
            listOf("Reels"),
        ),
        Feed(
            "feed_facebook_reels",
            "com.facebook.katana",
            "Facebook Reels",
            emptyList(),
            listOf("Reels", "Reels tab"),
        ),
        Feed(
            "feed_snapchat_spotlight",
            "com.snapchat.android",
            "Snapchat Spotlight",
            listOf("spotlight_container", "spotlight_feed"),
            listOf("Spotlight"),
        ),
    )

    fun feedFor(packageName: String): Feed? = FEEDS.firstOrNull { it.packageName == packageName }

    /** "Shorts" matches "Shorts" and "Shorts, tab 2 of 5" but not "No Shorts here". */
    fun labelMatches(text: CharSequence?, labels: List<String>): Boolean {
        val t = text?.toString()?.trim() ?: return false
        return labels.any { t.equals(it, ignoreCase = true) || t.startsWith("$it,", ignoreCase = true) || t.startsWith("$it tab", ignoreCase = true) }
    }

    /**
     * Address-bar text -> host, or null for search terms and empty bars.
     * Chrome shows "example.com/path"; others show the full URL.
     */
    fun hostFromAddressBar(raw: CharSequence?): String? {
        var text = raw?.toString()?.trim() ?: return null
        if (text.isEmpty() || text.contains(' ') || !text.contains('.')) return null
        if (!text.contains("://")) text = "http://$text"
        return try {
            URI(text).host?.trimEnd('.')?.lowercase()?.removePrefix("www.")?.takeIf { it.contains('.') }
        } catch (e: Exception) {
            null
        }
    }
}
