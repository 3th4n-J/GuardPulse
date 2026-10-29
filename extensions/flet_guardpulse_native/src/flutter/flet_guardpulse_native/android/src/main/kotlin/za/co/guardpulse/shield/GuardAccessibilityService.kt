package za.co.guardpulse.shield

import android.accessibilityservice.AccessibilityService
import android.content.ComponentName
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.FileObserver
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.Settings
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import java.util.ArrayDeque
import java.util.Calendar
import java.util.concurrent.atomic.AtomicLong

/**
 * The security overlay: watches the foreground app and covers it when it is a
 * blocked app (always or by schedule), a browser showing a blocked site, or a
 * short-video feed the partner has switched off.
 */
class GuardAccessibilityService : AccessibilityService() {

    companion object {
        @Volatile var instance: GuardAccessibilityService? = null
            private set
        val blockedApps = AtomicLong()
        val blockedSites = AtomicLong()
        val blockedFeeds = AtomicLong()

        private const val FEED_DEBOUNCE_MS = 1200L
        private const val ESCAPE_WINDOW_MS = 2500L
        private const val SETTINGS_GRANT_MS = 90_000L
        private const val MAX_NODES = 600
        private const val BLANK_PAGE = "about:blank"

        fun isEnabled(ctx: Context): Boolean {
            val enabled = Settings.Secure.getString(
                ctx.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
            ) ?: return false
            val me = ComponentName(ctx, GuardAccessibilityService::class.java)
            return enabled.split(':').any {
                ComponentName.unflattenFromString(it) == me
            }
        }
    }

    @Volatile private var policy: Policy = Policy.SAFE_DEFAULT
    private var observer: FileObserver? = null
    private lateinit var overlay: BlockOverlay
    private var stoppingByApp = false
    private var lastFeedBounce = 0L
    private var escapingUntil = 0L
    private val main = Handler(Looper.getMainLooper())
    private val pinGate = PinGate()
    private var settingsGrantedUntil = 0L

    override fun onServiceConnected() {
        super.onServiceConnected()
        instance = this
        overlay = BlockOverlay(this)
        Store.setOverlayWanted(this, true)
        loadPolicy()
        watchPolicy()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent) {
        val pkg = event.packageName?.toString() ?: return
        if (pkg == packageName) return // our own app and overlay windows

        // left the covered app (home gesture, recents): drop the cover
        val coveredApp = overlay.key?.removePrefix("app:")
        if (event.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED && overlay.showing &&
            overlay.key?.startsWith("app:") == true && coveredApp != pkg
        ) {
            overlay.hide()
        }

        if (checkSettings(pkg)) return

        val now = Calendar.getInstance()
        val mondayIndex = (now.get(Calendar.DAY_OF_WEEK) + 5) % 7
        val minute = now.get(Calendar.HOUR_OF_DAY) * 60 + now.get(Calendar.MINUTE)
        if (policy.appBlocked(pkg, mondayIndex, minute)) {
            coverApp(pkg)
            return
        }
        Detectors.BROWSER_URL_BARS[pkg]?.let { ids ->
            if (policy.flag("browser_overlay")) checkBrowser(pkg, ids)
            return
        }
        Detectors.feedFor(pkg)?.let { feed ->
            if (policy.flag(feed.setting)) checkFeed(feed)
        }
    }

    // --- settings guard ---------------------------------------------------------

    /**
     * On a Settings / installer screen that could switch GuardPulse off, ask for
     * the partner PIN before letting it through. Returns true when it handled the
     * screen (so other detectors are skipped).
     */
    private fun checkSettings(pkg: String): Boolean {
        if (!policy.flag("settings_guard")) return false
        val folder = Store.folder(this) ?: return false
        if (!NativeAuth.hasPin(folder)) return false
        if (SystemClock.elapsedRealtime() < settingsGrantedUntil) return false

        val root = rootInActiveWindow ?: return false
        val reason = SettingsTargets.guardedReason(pkg, appLabel(), collectTexts(root)) ?: run {
            if (overlay.key?.startsWith("settings:") == true) overlay.hide()
            return false
        }
        if (overlay.key == "settings:$reason") return true
        overlay.showPinPrompt(
            key = "settings:$reason",
            title = "Partner PIN needed",
            message = "Enter your accountability partner's PIN to $reason.",
            onPin = { entered ->
                val wait = pinGate.lockedForMs
                if (wait > 0) {
                    "Too many wrong tries. Wait ${wait / 1000 + 1}s."
                } else if (pinGate.attempt(NativeAuth.verify(folder, entered))) {
                    settingsGrantedUntil = SystemClock.elapsedRealtime() + SETTINGS_GRANT_MS
                    Store.event(this, "settings_unlocked", reason)
                    null
                } else {
                    Store.event(this, "settings_pin_failed", reason)
                    "Incorrect PIN."
                }
            },
            onBack = { performGlobalAction(GLOBAL_ACTION_BACK) },
        )
        return true
    }

    private fun appLabel(): String =
        try {
            applicationInfo.loadLabel(packageManager).toString()
        } catch (e: Exception) {
            "GuardPulse"
        }

    /** Bounded collection of visible text + content descriptions on screen. */
    private fun collectTexts(root: AccessibilityNodeInfo): List<String> {
        val texts = mutableListOf<String>()
        val queue = ArrayDeque<AccessibilityNodeInfo>()
        queue.add(root)
        var seen = 0
        while (queue.isNotEmpty() && seen < MAX_NODES && texts.size < 120) {
            val node = queue.removeFirst()
            seen++
            node.text?.let { if (it.isNotBlank()) texts.add(it.toString()) }
            node.contentDescription?.let { if (it.isNotBlank()) texts.add(it.toString()) }
            for (i in 0 until node.childCount) node.getChild(i)?.let(queue::add)
        }
        return texts
    }

    // --- detectors --------------------------------------------------------------

    private fun coverApp(pkg: String) {
        if (overlay.key == "app:$pkg") return
        blockedApps.incrementAndGet()
        val label = try {
            packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
        } catch (e: Exception) {
            pkg
        }
        overlay.show(
            "app:$pkg",
            "$label is blocked",
            "This app is blocked by GuardPulse right now. Your accountability partner can change this.",
            "Close",
        ) {
            performGlobalAction(GLOBAL_ACTION_HOME)
            overlay.hide()
        }
    }

    private fun checkBrowser(pkg: String, ids: List<String>) {
        if (SystemClock.elapsedRealtime() < escapingUntil) return // our own redirect in progress
        val root = rootInActiveWindow ?: return
        for (id in ids) {
            val bar = root.findAccessibilityNodeInfosByViewId("$pkg:id/$id").firstOrNull() ?: continue
            if (bar.isFocused) return // the user is typing, not viewing a page
            val host = Detectors.hostFromAddressBar(bar.text) ?: return
            if (policy.decide(host) == Decision.BLOCK) escapeSite(pkg, host, bar)
            return
        }
    }

    /**
     * Leave a blocked site for good. Android won't let us close another app's
     * tab, so we do the next best thing: cover the page, type about:blank into
     * the address bar and press Enter (the tab no longer holds the site, so
     * reopening the browser doesn't loop), then go to the home screen.
     */
    private fun escapeSite(pkg: String, host: String, bar: AccessibilityNodeInfo) {
        blockedSites.incrementAndGet()
        escapingUntil = SystemClock.elapsedRealtime() + ESCAPE_WINDOW_MS
        overlay.show(
            "site:$host",
            "Site blocked",
            "$host is on your blocklist. Closing it…",
            button = null,
            focusable = false, // the browser's address bar must keep input focus
        ) {}

        bar.performAction(AccessibilityNodeInfo.ACTION_FOCUS)
        bar.performAction(AccessibilityNodeInfo.ACTION_CLICK)
        main.postDelayed({
            // Firefox/Samsung swap the bar for an edit field once tapped - use whatever has input focus
            val edit = rootInActiveWindow?.findFocus(AccessibilityNodeInfo.FOCUS_INPUT)?.takeIf { it.isEditable } ?: bar
            val args = Bundle().apply {
                putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, BLANK_PAGE)
            }
            val typed = edit.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
            main.postDelayed({
                val entered = typed && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R &&
                    edit.performAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER.id)
                if (!entered) performGlobalAction(GLOBAL_ACTION_BACK) // older Android: at least leave the page
                main.postDelayed({
                    performGlobalAction(GLOBAL_ACTION_HOME)
                    overlay.hide()
                    overlay.flash("Blocked: $host - tab closed")
                }, 600)
            }, 200)
        }, 300)
    }

    private fun checkFeed(feed: Detectors.Feed) {
        if (SystemClock.elapsedRealtime() - lastFeedBounce < FEED_DEBOUNCE_MS) return
        val root = rootInActiveWindow ?: return
        val byId = feed.viewIds.any { id ->
            root.findAccessibilityNodeInfosByViewId("${feed.packageName}:id/$id").any { it.isVisibleToUser }
        }
        if (!byId && !hasSelectedTab(root, feed.selectedLabels)) return
        lastFeedBounce = SystemClock.elapsedRealtime()
        blockedFeeds.incrementAndGet()
        performGlobalAction(GLOBAL_ACTION_BACK)
        overlay.flash("${feed.label} are blocked")
    }

    /** A selected tab (or its child) labelled e.g. "Shorts". Bounded walk; ids are obfuscated in some apps. */
    private fun hasSelectedTab(root: AccessibilityNodeInfo, labels: List<String>): Boolean {
        if (labels.isEmpty()) return false
        val queue = ArrayDeque<AccessibilityNodeInfo>()
        queue.add(root)
        var seen = 0
        while (queue.isNotEmpty() && seen < MAX_NODES) {
            val node = queue.removeFirst()
            seen++
            if (node.isSelected) {
                if (Detectors.labelMatches(node.contentDescription, labels) || Detectors.labelMatches(node.text, labels)) {
                    return true
                }
                for (i in 0 until node.childCount) {
                    val child = node.getChild(i) ?: continue
                    if (Detectors.labelMatches(child.text, labels) || Detectors.labelMatches(child.contentDescription, labels)) {
                        return true
                    }
                }
            }
            for (i in 0 until node.childCount) node.getChild(i)?.let(queue::add)
        }
        return false
    }

    // --- policy -----------------------------------------------------------------

    /** Called by the plugin when the app (re)configures the data folder or rules change. */
    fun reload() {
        loadPolicy()
        watchPolicy()
    }

    private fun loadPolicy() {
        val folder = Store.folder(this) ?: return
        Policy.load(folder)?.let { policy = it }
    }

    @Suppress("DEPRECATION")
    private fun watchPolicy() {
        if (observer != null) return
        val folder = Store.folder(this) ?: return
        observer = object : FileObserver(folder.path, CLOSE_WRITE or MOVED_TO) {
            override fun onEvent(event: Int, path: String?) {
                if (path == "policy.sig") loadPolicy()
            }
        }.also { it.startWatching() }
    }

    // --- lifecycle --------------------------------------------------------------

    /** Partner-approved "turn off" from inside the app. */
    fun stopByApp() {
        stoppingByApp = true
        Store.setOverlayWanted(this, false)
        overlay.hideAll()
        disableSelf()
    }

    override fun onInterrupt() {}

    override fun onUnbind(intent: android.content.Intent?): Boolean {
        // switched off in Android's Accessibility settings
        if (!stoppingByApp && Store.overlayWanted(this)) {
            Store.event(this, "accessibility_disabled", "The security overlay was switched off outside GuardPulse")
        }
        cleanup()
        return super.onUnbind(intent)
    }

    override fun onDestroy() {
        cleanup()
        super.onDestroy()
    }

    private fun cleanup() {
        instance = null
        observer?.stopWatching()
        observer = null
        if (::overlay.isInitialized) overlay.hideAll()
    }
}
