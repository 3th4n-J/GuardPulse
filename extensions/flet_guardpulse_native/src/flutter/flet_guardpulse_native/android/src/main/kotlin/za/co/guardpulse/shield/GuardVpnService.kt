package za.co.guardpulse.shield

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.FileObserver
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

/**
 * DNS-only VPN. The tunnel claims a single virtual DNS server address, so the
 * only traffic it ever sees is DNS; everything else keeps using the normal
 * network. Blocked names get NXDOMAIN, the rest are forwarded (through a
 * protected socket) to Cloudflare Family, or plain Cloudflare when the
 * partner has switched Family DNS off.
 */
class GuardVpnService : VpnService() {

    companion object {
        private const val TAG = "GuardPulse"
        const val ACTION_START = "za.co.guardpulse.shield.START"
        const val ACTION_STOP = "za.co.guardpulse.shield.STOP"
        const val ACTION_RELOAD = "za.co.guardpulse.shield.RELOAD"

        private const val TUN_ADDRESS = "10.111.222.1"
        private const val TUN_DNS = "10.111.222.2"
        private const val CHANNEL = "guardpulse_protection"
        private const val NOTIFY_RUNNING = 4201
        private const val NOTIFY_OFF = 4202
        private const val UPSTREAM_TIMEOUT_MS = 2500

        @Volatile var running = false
            private set
        @Volatile var alwaysOn = false
            private set
        @Volatile var lockdown = false
            private set
        @Volatile var policyOk = false
            private set
        val blocked = AtomicLong()
        val forwarded = AtomicLong()

        fun intent(ctx: Context, action: String) =
            Intent(ctx, GuardVpnService::class.java).setAction(action)

        fun send(ctx: Context, action: String) {
            val i = intent(ctx, action)
            if (action == ACTION_START && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                ctx.startForegroundService(i)
            } else {
                ctx.startService(i)
            }
        }
    }

    private var tun: ParcelFileDescriptor? = null
    private var reader: Thread? = null
    private var pool: ExecutorService? = null
    private var observer: FileObserver? = null
    @Volatile private var policy: Policy = Policy.SAFE_DEFAULT
    @Volatile private var stopping = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopping = true
                Store.setEnabled(this, false)
                shutdown()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_RELOAD -> {
                if (tun != null) loadPolicy()
                return START_STICKY
            }
            else -> start() // ACTION_START, always-on VPN (null action) or a sticky restart
        }
        return START_STICKY
    }

    private fun start() {
        goForeground()
        loadPolicy()
        watchPolicy()
        if (tun != null) return

        val builder = Builder()
            .setSession("GuardPulse")
            .addAddress(TUN_ADDRESS, 32)
            .addDnsServer(TUN_DNS)
            .addRoute(TUN_DNS, 32)
            .setBlocking(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
        val fd = try {
            builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "establish failed", e)
            null
        }
        if (fd == null) {
            // consent missing or revoked: the app must call prepare_vpn again
            Store.event(this, "vpn_not_prepared", "VPN permission is missing")
            stopSelf()
            return
        }
        tun = fd
        stopping = false
        Store.setEnabled(this, true)
        running = true
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            alwaysOn = isAlwaysOn
            lockdown = isLockdownEnabled
        }
        pool = Executors.newFixedThreadPool(8)
        reader = Thread({ readLoop(fd) }, "guardpulse-dns").also { it.start() }
        Log.i(TAG, "DNS filter running (family=${policy.familyDns})")
    }

    private fun readLoop(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        while (!Thread.currentThread().isInterrupted) {
            val n = try {
                input.read(buf)
            } catch (e: IOException) {
                break // tunnel closed
            }
            if (n <= 0) continue
            val query = Packets.parse(buf, n) ?: continue
            pool?.execute { answer(query, output) }
        }
    }

    private fun answer(q: DnsQuery, output: FileOutputStream) {
        val host = Packets.qname(q.dns)
        val reply = if (host != null && policy.decide(host) == Decision.BLOCK) {
            blocked.incrementAndGet()
            Packets.nxdomain(q.dns)
        } else {
            forwarded.incrementAndGet()
            forward(q.dns) ?: Packets.servfail(q.dns)
        } ?: return
        val packet = Packets.reply(q, reply)
        try {
            synchronized(output) { output.write(packet) }
        } catch (e: IOException) {
            // tunnel went away mid-answer
        }
    }

    private fun forward(dns: ByteArray): ByteArray? {
        for (server in policy.upstream) {
            try {
                DatagramSocket().use { socket ->
                    if (!protect(socket)) return@use
                    socket.soTimeout = UPSTREAM_TIMEOUT_MS
                    socket.send(DatagramPacket(dns, dns.size, InetAddress.getByName(server), 53))
                    val buf = ByteArray(4096)
                    val packet = DatagramPacket(buf, buf.size)
                    socket.receive(packet)
                    return buf.copyOf(packet.length)
                }
            } catch (e: IOException) {
                // try the next resolver
            }
        }
        return null
    }

    private fun loadPolicy() {
        val folder = Store.folder(this) ?: return
        var loaded = Policy.load(folder)
        if (loaded == null) {
            // the app writes policy.json then policy.sig; give it a moment
            Thread.sleep(300)
            loaded = Policy.load(folder)
        }
        if (loaded == null) {
            policyOk = false
            if (File(folder, "policy.json").exists()) {
                Store.event(this, "policy_signature_invalid", "policy.json failed its signature check")
            }
            return // keep the last good policy (or the safe default)
        }
        policy = loaded
        policyOk = true
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

    override fun onRevoke() {
        // Another VPN took over, or the user disconnected us in Android settings.
        if (!stopping) {
            Store.event(this, "vpn_revoked", "The DNS filter was switched off outside GuardPulse")
            notifyOff()
        }
        shutdown()
        super.onRevoke()
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    private fun shutdown() {
        running = false
        observer?.stopWatching()
        observer = null
        reader?.interrupt()
        reader = null
        try {
            tun?.close()
        } catch (e: IOException) {
        }
        tun = null
        pool?.shutdownNow()
        pool = null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    // --- notifications ---------------------------------------------------------

    private fun goForeground() {
        val n = notification(
            "Protection is on",
            "Filtering sites with Cloudflare Family DNS",
            ongoing = true,
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFY_RUNNING, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFY_RUNNING, n)
        }
    }

    private fun notifyOff() {
        val n = notification(
            "Protection is OFF",
            "The DNS filter was switched off. Your partner has been alerted. Open GuardPulse to turn it back on.",
            ongoing = false,
        )
        (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIFY_OFF, n)
    }

    private fun notification(title: String, text: String, ongoing: Boolean): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, "Protection status", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val launch = packageManager.getLaunchIntentForPackage(packageName)
        val tap = launch?.let {
            PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        }
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setSmallIcon(applicationInfo.icon)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(tap)
            .setOngoing(ongoing)
            .build()
    }
}
