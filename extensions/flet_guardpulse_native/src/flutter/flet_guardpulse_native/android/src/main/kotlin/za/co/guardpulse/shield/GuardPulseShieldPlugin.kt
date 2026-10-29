package za.co.guardpulse.shield

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.PluginRegistry

/** ``guardpulse/shield`` channel used by the GuardNative Flet service. */
class GuardPulseShieldPlugin :
    FlutterPlugin,
    ActivityAware,
    MethodChannel.MethodCallHandler,
    PluginRegistry.ActivityResultListener {

    companion object {
        private const val REQUEST_VPN = 4210
        private const val REQUEST_NOTIFICATIONS = 4211
    }

    private lateinit var channel: MethodChannel
    private lateinit var context: Context
    private var binding: ActivityPluginBinding? = null
    private var pendingPrepare: MethodChannel.Result? = null

    override fun onAttachedToEngine(b: FlutterPlugin.FlutterPluginBinding) {
        context = b.applicationContext
        channel = MethodChannel(b.binaryMessenger, "guardpulse/shield")
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(b: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "status" -> result.success(status())
            "prepare_vpn" -> prepareVpn(result)
            "start_vpn" -> {
                val folder = call.argument<String>("folder")
                if (folder.isNullOrBlank()) {
                    result.error("bad_args", "folder is required", null)
                    return
                }
                if (VpnService.prepare(context) != null) {
                    result.success(false)
                    return
                }
                Store.setFolder(context, folder)
                askForNotifications()
                GuardVpnService.send(context, GuardVpnService.ACTION_START)
                result.success(true)
            }
            "stop_vpn" -> {
                GuardVpnService.send(context, GuardVpnService.ACTION_STOP)
                result.success(true)
            }
            "configure" -> {
                val folder = call.argument<String>("folder")
                if (!folder.isNullOrBlank()) Store.setFolder(context, folder)
                GuardAccessibilityService.instance?.reload()
                result.success(true)
            }
            "reload_policy" -> {
                if (GuardVpnService.running) GuardVpnService.send(context, GuardVpnService.ACTION_RELOAD)
                GuardAccessibilityService.instance?.reload()
                result.success(true)
            }
            "open_vpn_settings" -> {
                open(Intent(Settings.ACTION_VPN_SETTINGS))
                result.success(true)
            }
            "open_accessibility_settings" -> {
                open(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
                result.success(true)
            }
            "open_app_info" -> {
                // Android 13+ hides accessibility for sideloaded apps until
                // "Allow restricted settings" is tapped in App info's menu.
                open(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${context.packageName}")))
                result.success(true)
            }
            "stop_overlay" -> {
                val service = GuardAccessibilityService.instance
                if (service != null) service.stopByApp() else Store.setOverlayWanted(context, false)
                result.success(true)
            }
            "list_apps" -> listApps(result)
            "app_icons" -> {
                val packages = call.argument<List<String>>("packages") ?: emptyList()
                background(result) { packages.mapNotNull { p -> iconPng(p)?.let { p to it } }.toMap() }
            }
            "app_info" -> result.success(
                mapOf(
                    "version_name" to versionName(),
                    "signer_sha256" to Updater.signerSha256(context),
                    "can_install_updates" to Updater.canInstall(context),
                )
            )
            "update_download" -> {
                val url = call.argument<String>("url")
                if (url.isNullOrBlank() || !url.startsWith("https://")) {
                    result.error("bad_args", "an https url is required", null)
                    return
                }
                background(result) { mapOf("bytes" to Updater.download(context, url)) }
            }
            "update_verify" -> background(result) { Updater.verify(context, Updater.apkFile(context)) }
            "update_install" -> {
                if (!Updater.canInstall(context)) {
                    // one-time "Install unknown apps" switch for GuardPulse
                    open(
                        Intent(
                            Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                            Uri.parse("package:${context.packageName}"),
                        )
                    )
                    result.success("needs_permission")
                    return
                }
                // re-check right before installing: the file could have changed since verify
                val check = Updater.verify(context, Updater.apkFile(context))
                if (check["ok"] != true) {
                    result.success(check["reason"] ?: "verification failed")
                    return
                }
                background(result) {
                    Updater.install(context, Updater.apkFile(context))
                    "started"
                }
            }
            else -> result.notImplemented()
        }
    }

    /** Run off the main thread; reply on it (MethodChannel results must be main-thread). */
    private fun background(result: MethodChannel.Result, work: () -> Any?) {
        val main = Handler(Looper.getMainLooper())
        Thread {
            try {
                val value = work()
                main.post { result.success(value) }
            } catch (e: Exception) {
                main.post { result.error("failed", e.message ?: e.toString(), null) }
            }
        }.start()
    }

    @Suppress("DEPRECATION")
    private fun versionName(): String? = context.packageManager.getPackageInfo(context.packageName, 0).versionName

    /**
     * The app's own launcher icon from this phone, as a small base64 PNG.
     * Nothing is bundled with GuardPulse - icons only show for installed apps.
     */
    private fun iconPng(pkg: String, sizeDp: Int = 40): String? = try {
        val drawable = context.packageManager.getApplicationIcon(pkg)
        val px = (sizeDp * context.resources.displayMetrics.density).toInt().coerceAtLeast(48)
        val bitmap = android.graphics.Bitmap.createBitmap(px, px, android.graphics.Bitmap.Config.ARGB_8888)
        val canvas = android.graphics.Canvas(bitmap)
        drawable.setBounds(0, 0, px, px)
        drawable.draw(canvas)
        val out = java.io.ByteArrayOutputStream()
        bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, out)
        android.util.Base64.encodeToString(out.toByteArray(), android.util.Base64.NO_WRAP)
    } catch (e: PackageManager.NameNotFoundException) {
        null
    }

    private fun open(intent: Intent) {
        val activity = binding?.activity
        if (activity != null) activity.startActivity(intent)
        else context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    /** Launchable apps (label + package), off the main thread; labels can be slow to load. */
    private fun listApps(result: MethodChannel.Result) {
        val main = Handler(Looper.getMainLooper())
        Thread {
            val pm = context.packageManager
            val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            val infos = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.queryIntentActivities(launcher, PackageManager.ResolveInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.queryIntentActivities(launcher, 0)
            }
            val apps = infos
                .map { mapOf("package" to it.activityInfo.packageName, "label" to it.loadLabel(pm).toString()) }
                .filter { it["package"] != context.packageName }
                .distinctBy { it["package"] }
                .sortedBy { it["label"]!!.lowercase() }
                .map { it + ("icon" to iconPng(it["package"]!!, 32)) }
            main.post { result.success(apps) }
        }.start()
    }

    private fun status(): Map<String, Any?> {
        val resolver = context.contentResolver
        // Private DNS is readable by any app; "hostname" mode to anything but
        // Cloudflare Family sends DNS over TLS straight past the filter.
        val pdnsMode = Settings.Global.getString(resolver, "private_dns_mode")
        val pdnsHost = Settings.Global.getString(resolver, "private_dns_specifier")
        return mapOf(
            "available" to true,
            "sdk" to Build.VERSION.SDK_INT,
            "vpn_prepared" to (VpnService.prepare(context) == null),
            "vpn_enabled" to Store.enabled(context),
            "vpn_running" to GuardVpnService.running,
            "always_on" to GuardVpnService.alwaysOn,
            "lockdown" to GuardVpnService.lockdown,
            "policy_ok" to GuardVpnService.policyOk,
            "blocked" to GuardVpnService.blocked.get(),
            "forwarded" to GuardVpnService.forwarded.get(),
            "private_dns_mode" to pdnsMode,
            "private_dns_host" to pdnsHost,
            "overlay_enabled" to GuardAccessibilityService.isEnabled(context),
            "overlay_wanted" to Store.overlayWanted(context),
            "overlay_connected" to (GuardAccessibilityService.instance != null),
            "overlay_blocked_apps" to GuardAccessibilityService.blockedApps.get(),
            "overlay_blocked_sites" to GuardAccessibilityService.blockedSites.get(),
            "overlay_blocked_feeds" to GuardAccessibilityService.blockedFeeds.get(),
        )
    }

    private fun prepareVpn(result: MethodChannel.Result) {
        val consent = VpnService.prepare(context)
        if (consent == null) {
            result.success(true)
            return
        }
        val activity = binding?.activity
        if (activity == null) {
            result.error("no_activity", "GuardPulse must be in the foreground", null)
            return
        }
        pendingPrepare?.success(false)
        pendingPrepare = result
        activity.startActivityForResult(consent, REQUEST_VPN)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        if (requestCode != REQUEST_VPN) return false
        pendingPrepare?.success(resultCode == Activity.RESULT_OK)
        pendingPrepare = null
        return true
    }

    private fun askForNotifications() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val activity = binding?.activity ?: return
        if (activity.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            activity.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
        }
    }

    // --- ActivityAware -----------------------------------------------------------

    override fun onAttachedToActivity(b: ActivityPluginBinding) {
        binding = b
        b.addActivityResultListener(this)
    }

    override fun onDetachedFromActivityForConfigChanges() = onDetachedFromActivity()

    override fun onReattachedToActivityForConfigChanges(b: ActivityPluginBinding) = onAttachedToActivity(b)

    override fun onDetachedFromActivity() {
        binding?.removeActivityResultListener(this)
        binding = null
    }
}
