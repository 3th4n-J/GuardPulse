package za.co.guardpulse.shield

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService

/** Bring the filter back after a reboot or an app update if it was on. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED && intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        Alerts.flushAsync(context) // alerts queued before the reboot
        if (!Store.enabled(context)) return
        if (VpnService.prepare(context) != null) {
            Store.event(context, "vpn_not_prepared", "VPN permission was removed")
            return
        }
        GuardVpnService.send(context, GuardVpnService.ACTION_START)
    }
}
