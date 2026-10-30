package za.co.guardpulse.shield

import android.content.Context
import android.util.Log
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

/**
 * Partner alerts sent straight from the Android layer over ntfy.
 *
 * Tamper events (VPN switched off, overlay disabled, uninstall protection
 * removed, wrong PIN at Settings) happen while the Flet app is usually closed,
 * and a determined user would never reopen it - so they're sent here, at the
 * moment they happen. Each alert is written to a pending file first and only
 * removed once ntfy accepts it, so being offline just delays it.
 *
 * The destination (server + topic) comes from the last policy that passed its
 * signature check (cached in Store), so tampering with policy.json can't stop
 * the tamper alert from going out.
 */
object Alerts {
    private const val TAG = "GuardPulse"
    private const val PENDING = "native_alerts.jsonl"

    /** Queue an alert and try to send it now (in the background). */
    fun notify(ctx: Context, title: String, message: String, tags: String = "rotating_light", priority: Int = 5) {
        val folder = Store.folder(ctx) ?: return
        val line = JSONObject()
            .put("at", System.currentTimeMillis() / 1000.0)
            .put("title", title)
            .put("message", message)
            .put("tags", tags)
            .put("priority", priority)
            .toString()
        synchronized(this) { File(folder, PENDING).appendText(line + "\n") }
        flushAsync(ctx)
    }

    fun flushAsync(ctx: Context) {
        val app = ctx.applicationContext
        Thread({ flush(app) }, "guardpulse-alerts").start()
    }

    /** Send queued alerts in order; stop at the first failure (probably offline). Returns how many remain. */
    @Synchronized
    fun flush(ctx: Context): Int {
        val folder = Store.folder(ctx) ?: return 0
        val file = File(folder, PENDING)
        if (!file.exists()) return 0
        val (server, topic) = Store.alertTarget(ctx) ?: return file.readLines().count { it.isNotBlank() }
        val lines = file.readLines().filter { it.isNotBlank() }
        var sent = 0
        for (line in lines) {
            val alert = try {
                JSONObject(line)
            } catch (e: Exception) {
                sent++ // unreadable line: drop it
                continue
            }
            if (!post(server, topic, alert)) break
            sent++
        }
        val remaining = lines.drop(sent)
        if (remaining.isEmpty()) file.delete() else file.writeText(remaining.joinToString("\n", postfix = "\n"))
        return remaining.size
    }

    private fun post(server: String, topic: String, alert: JSONObject): Boolean = try {
        val conn = URL("${server.trimEnd('/')}/$topic").openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.connectTimeout = 10_000
        conn.readTimeout = 15_000
        conn.setRequestProperty("Title", alert.optString("title", "GuardPulse"))
        conn.setRequestProperty("Tags", alert.optString("tags", "bell"))
        conn.setRequestProperty("Priority", alert.optInt("priority", 4).toString())
        conn.setRequestProperty("User-Agent", "GuardPulse")
        conn.outputStream.use { it.write(alert.optString("message").toByteArray(Charsets.UTF_8)) }
        val ok = conn.responseCode in 200..299
        conn.disconnect()
        ok
    } catch (e: Exception) {
        Log.w(TAG, "alert not sent yet: ${e.message}")
        false
    }
}
