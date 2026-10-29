package za.co.guardpulse.shield

/**
 * Decides whether the Settings / installer screen now on top is one that could
 * switch GuardPulse off, so the overlay should ask for the partner PIN first.
 *
 * Pure text matching (no Android types) so it can be unit-tested: the service
 * passes the foreground package, GuardPulse's own app label, and the visible
 * on-screen text. Screens and wording vary by OEM, so this stays heuristic and
 * errs toward guarding when GuardPulse's name sits next to a risky action.
 */
object SettingsTargets {

    private val SETTINGS = setOf(
        "com.android.settings",
        "com.samsung.android.settings",
    )
    private val INSTALLERS = setOf(
        "com.google.android.packageinstaller",
        "com.android.packageinstaller",
        "com.samsung.android.packageinstaller",
        "com.miui.packageinstaller",
    )

    // human reason -> words that identify it (any one, case-insensitive, substring)
    private val ACTIONS = linkedMapOf(
        "uninstall GuardPulse" to listOf("uninstall", "remove app"),
        "remove GuardPulse's device-admin protection" to
            listOf("deactivate", "device admin", "device administrator"),
        "clear GuardPulse's data" to listOf("clear storage", "clear data", "clear & reset"),
        "force stop GuardPulse" to listOf("force stop", "force close"),
        "disable GuardPulse" to listOf("disable", "turn off"),
    )

    /**
     * A short reason ("stop GuardPulse being uninstalled") when ``texts`` show a
     * screen acting on GuardPulse, otherwise null. ``appLabel`` is GuardPulse's
     * launcher label; ``pkg`` is the foreground package.
     */
    fun guardedReason(pkg: String, appLabel: String, texts: Collection<String>): String? {
        val relevant = pkg in SETTINGS || pkg in INSTALLERS
        if (!relevant) return null
        val haystack = texts.map { it.lowercase() }
        val label = appLabel.lowercase()
        // the screen must be about GuardPulse itself, not some other app
        val mentionsUs = haystack.any { it.contains(label) } || pkg in INSTALLERS
        if (!mentionsUs) return null
        for ((reason, words) in ACTIONS) {
            if (haystack.any { h -> words.any { h.contains(it) } }) return reason
        }
        return null
    }
}
