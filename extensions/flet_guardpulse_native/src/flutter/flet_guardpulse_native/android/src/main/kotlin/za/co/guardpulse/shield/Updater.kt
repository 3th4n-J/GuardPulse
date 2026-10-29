package za.co.guardpulse.shield

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Self-update from a GitHub release, built so an update can never wipe data:
 * the APK is only handed to Android when it has the same package name, a
 * higher versionCode and the SAME signing certificate as the installed app,
 * i.e. when Android will update in place and keep every byte of app data.
 */
object Updater {
    private const val ACTION_RESULT = "za.co.guardpulse.shield.UPDATE_RESULT"

    fun apkFile(ctx: Context): File = File(File(ctx.cacheDir, "updates").apply { mkdirs() }, "update.apk")

    /** Follows GitHub's redirect to its asset host (https -> https). Returns bytes written. */
    fun download(ctx: Context, url: String): Long {
        val target = apkFile(ctx)
        val partial = File(target.parentFile, "update.apk.part")
        var location = URL(url)
        repeat(5) {
            val conn = location.openConnection() as HttpURLConnection
            conn.instanceFollowRedirects = false
            conn.connectTimeout = 15_000
            conn.readTimeout = 30_000
            conn.setRequestProperty("User-Agent", "GuardPulse-Updater")
            val code = conn.responseCode
            if (code in 300..399) {
                location = URL(location, conn.getHeaderField("Location"))
                conn.disconnect()
                return@repeat
            }
            if (code != 200) throw IllegalStateException("Download failed (HTTP $code)")
            conn.inputStream.use { input -> partial.outputStream().use { input.copyTo(it) } }
            conn.disconnect()
            if (!partial.renameTo(target)) {
                partial.copyTo(target, overwrite = true)
                partial.delete()
            }
            return target.length()
        }
        throw IllegalStateException("Too many redirects")
    }

    /** Checks that make an in-place (data-preserving) update certain. */
    fun verify(ctx: Context, file: File): Map<String, Any?> {
        val pm = ctx.packageManager
        val installed = packageInfo(pm, ctx.packageName)
        val candidate = archiveInfo(pm, file)
            ?: return mapOf("ok" to false, "reason" to "The download isn't a valid Android app.")
        val installedCode = versionCode(installed)
        val candidateCode = versionCode(candidate)
        val installedSigners = signerDigests(installed)
        val candidateSigners = signerDigests(candidate)
        val reason = when {
            candidate.packageName != ctx.packageName ->
                "That file is a different app (${candidate.packageName})."
            candidateSigners.isEmpty() || candidateSigners != installedSigners ->
                "That file isn't signed with GuardPulse's key. Android would make you uninstall first, " +
                    "which would erase your rules and partner settings - so it was not installed."
            candidateCode <= installedCode ->
                "That file isn't newer than the installed version."
            else -> null
        }
        return mapOf(
            "ok" to (reason == null),
            "reason" to reason,
            "version_name" to candidate.versionName,
            "version_code" to candidateCode,
            "installed_code" to installedCode,
        )
    }

    fun canInstall(ctx: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.O || ctx.packageManager.canRequestPackageInstalls()

    /** Hands the verified APK to PackageInstaller; Android then asks the user to confirm. */
    fun install(ctx: Context, file: File) {
        val installer = ctx.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(ctx.packageName)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_REQUIRED)
            }
        }
        val sessionId = installer.createSession(params)
        installer.openSession(sessionId).use { session ->
            file.inputStream().use { input ->
                session.openWrite("guardpulse.apk", 0, file.length()).use { out ->
                    input.copyTo(out)
                    session.fsync(out)
                }
            }
            val intent = Intent(ctx, UpdateReceiver::class.java).setAction(ACTION_RESULT)
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or
                (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0)
            session.commit(PendingIntent.getBroadcast(ctx, sessionId, intent, flags).intentSender)
        }
    }

    fun signerSha256(ctx: Context): List<String> =
        signerDigests(packageInfo(ctx.packageManager, ctx.packageName))

    // --- helpers -------------------------------------------------------------------

    @Suppress("DEPRECATION")
    private fun packageInfo(pm: PackageManager, name: String): PackageInfo =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pm.getPackageInfo(name, PackageManager.GET_SIGNING_CERTIFICATES)
        } else {
            pm.getPackageInfo(name, PackageManager.GET_SIGNATURES)
        }

    @Suppress("DEPRECATION")
    private fun archiveInfo(pm: PackageManager, file: File): PackageInfo? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pm.getPackageArchiveInfo(file.path, PackageManager.GET_SIGNING_CERTIFICATES)
        } else {
            pm.getPackageArchiveInfo(file.path, PackageManager.GET_SIGNATURES)
        }

    @Suppress("DEPRECATION")
    private fun versionCode(info: PackageInfo): Long =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) info.longVersionCode else info.versionCode.toLong()

    @Suppress("DEPRECATION")
    private fun signerDigests(info: PackageInfo): List<String> {
        val sigs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info.signingInfo?.let { s ->
                if (s.hasMultipleSigners()) s.apkContentsSigners else s.signingCertificateHistory
            }
        } else {
            info.signatures
        } ?: return emptyList()
        val sha = MessageDigest.getInstance("SHA-256")
        return sigs.map { sig -> sha.digest(sig.toByteArray()).joinToString("") { "%02x".format(it) } }.sorted()
    }
}

/** PackageInstaller reports back here: show Android's confirm screen, log failures. */
class UpdateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                @Suppress("DEPRECATION")
                val confirm = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                } else {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT)
                }
                confirm?.let { context.startActivity(it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
            }
            PackageInstaller.STATUS_SUCCESS -> Store.event(context, "update_installed")
            else -> Store.event(
                context,
                "update_failed",
                intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "status $status",
            )
        }
    }
}
