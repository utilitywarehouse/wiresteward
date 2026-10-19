package com.utilitywarehouse.wiresteward

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.util.Log
import mobile.Mobile
import mobile.TunProvider
import java.io.File
import java.util.concurrent.Executors

/**
 * Hosts the Go agent. The agent asks for the VPN interface through
 * [TunProvider.establish] every time it receives a new lease.
 */
class WirestewardVpnService : VpnService(), TunProvider {

    // Starting and stopping the agent run in request order on one thread, so
    // that a stop is never overtaken by the start that preceded it.
    private val agentExecutor = Executors.newSingleThreadExecutor()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopAgent()
            stopSelf()
            return START_NOT_STICKY
        }
        startForegroundNotification()
        startAgent()
        return START_STICKY
    }

    override fun onDestroy() {
        stopAgent()
        agentExecutor.shutdown()
        super.onDestroy()
    }

    override fun onRevoke() {
        // The user turned the VPN off from the system settings.
        stopAgent()
        stopSelf()
    }

    private fun startAgent() {
        // onStartCommand runs on every start request; only start the agent once.
        if (!starting.compareAndSet(false, true)) return
        val config = configFile(this)
        if (!config.exists()) {
            Log.e(TAG, "no config at $config, import one first")
            starting.set(false)
            stopSelf()
            return
        }
        // Mobile.start() returns once the agent is set up; the agent keeps
        // running in its own goroutines. Keep it off the main thread, it
        // opens files and may touch the network.
        agentExecutor.execute {
            try {
                Mobile.start(config.absolutePath, filesDir.absolutePath, "", "debug", userAgent(), this)
                running = true
            } catch (e: Exception) {
                Log.e(TAG, "cannot start agent", e)
                starting.set(false)
                stopSelf()
            }
        }
    }

    /** What the servers show as the client: the app version, the Android version and the CPU architecture. */
    @Suppress("DEPRECATION")
    private fun userAgent(): String {
        val version = packageManager.getPackageInfo(packageName, 0).versionName ?: "unknown"
        val abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown"
        return "wiresteward-android/$version (Android ${Build.VERSION.RELEASE}; $abi)"
    }

    private fun stopAgent() {
        starting.set(false)
        agentExecutor.execute {
            Mobile.stop()
            running = false
        }
    }

    /**
     * Called from a Go thread. The returned descriptor is detached, so
     * ownership moves to the agent which closes it with the device.
     */
    override fun establish(address: String, prefixLen: Long, routes: String, mtu: Long): Long {
        val builder = Builder()
            .setSession("Wiresteward")
            .setMtu(mtu.toInt())
            .addAddress(address, prefixLen.toInt())
        routes.lines().filter { it.isNotBlank() }.forEach {
            val (ip, prefix) = it.split("/")
            builder.addRoute(ip, prefix.toInt())
        }
        val pfd = builder.establish() ?: throw IllegalStateException("VPN permission revoked")
        return pfd.detachFd().toLong()
    }

    private fun startForegroundNotification() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        // The settings of a channel cannot be changed once it exists, so the
        // one that showed a launcher badge was replaced by this one.
        nm.deleteNotificationChannel(OLD_CHANNEL_ID)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW)
                .apply { setShowBadge(false) }
        )
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.notification_text))
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    companion object {
        private val starting = java.util.concurrent.atomic.AtomicBoolean(false)
        private const val TAG = "wiresteward"
        private const val OLD_CHANNEL_ID = "vpn"
        private const val CHANNEL_ID = "vpn_status"
        private const val NOTIFICATION_ID = 1
        const val ACTION_STOP = "com.utilitywarehouse.wiresteward.STOP"

        @Volatile
        var running = false
            private set

        fun configFile(context: Context) = File(context.filesDir, "config.json")
    }
}
