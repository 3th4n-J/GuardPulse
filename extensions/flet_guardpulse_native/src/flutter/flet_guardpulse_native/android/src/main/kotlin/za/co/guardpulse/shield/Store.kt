package za.co.guardpulse.shield

import android.content.Context
import java.io.File
import org.json.JSONObject

/** Small persistent state shared by the plugin, the VPN service and the boot receiver. */
object Store {
    private const val PREFS = "guardpulse_shield"

    fun folder(ctx: Context): File? =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("folder", null)?.let(::File)

    fun setFolder(ctx: Context, folder: String) =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString("folder", folder).apply()

    /** True while the user wants the filter on - drives restart after reboot or update. */
    fun enabled(ctx: Context): Boolean =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean("enabled", false)

    fun setEnabled(ctx: Context, on: Boolean) =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("enabled", on).apply()

    /**
     * Append an event for the Python side, which drains native_events.jsonl and
     * turns tamper events into partner alerts.
     */
    @Synchronized
    fun event(ctx: Context, event: String, detail: String = "") {
        val folder = folder(ctx) ?: return
        val line = JSONObject()
            .put("at", System.currentTimeMillis() / 1000.0)
            .put("event", event)
            .put("detail", detail)
            .toString()
        File(folder, "native_events.jsonl").appendText(line + "\n")
    }
}
