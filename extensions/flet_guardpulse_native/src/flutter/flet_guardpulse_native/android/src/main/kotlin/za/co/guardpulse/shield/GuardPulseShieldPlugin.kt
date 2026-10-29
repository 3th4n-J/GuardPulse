package za.co.guardpulse.shield

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
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
            "reload_policy" -> {
                if (GuardVpnService.running) GuardVpnService.send(context, GuardVpnService.ACTION_RELOAD)
                result.success(GuardVpnService.running)
            }
            "open_vpn_settings" -> {
                val activity = binding?.activity
                val intent = Intent(Settings.ACTION_VPN_SETTINGS)
                if (activity != null) activity.startActivity(intent)
                else context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                result.success(true)
            }
            else -> result.notImplemented()
        }
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
