package za.co.guardpulse.shield

import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent

/**
 * Device admin for uninstall protection. While GuardPulse is an active device
 * admin, Android blocks uninstalling it until admin is deactivated - and the
 * accessibility settings-guard covers the deactivation screen with the partner
 * PIN. The two together are what stop a casual uninstall.
 *
 * Nothing here manages the device; it only holds admin status so uninstall is
 * blocked. The warning shown on the deactivation screen is set below.
 */
class GuardDeviceAdminReceiver : DeviceAdminReceiver() {
    override fun onDisableRequested(context: Context, intent: Intent): CharSequence =
        "Turning this off lets GuardPulse be uninstalled. Your accountability partner's " +
            "PIN is needed first, and they'll be told."

    override fun onDisabled(context: Context, intent: Intent) {
        // reached only after the settings-guard let it through (or admin was
        // removed via adb); either way, record it for the partner
        Store.setAdminWanted(context, false)
        Store.event(context, "device_admin_removed", "Uninstall protection was switched off")
    }
}
