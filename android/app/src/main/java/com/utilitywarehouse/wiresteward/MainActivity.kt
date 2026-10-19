package com.utilitywarehouse.wiresteward

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import mobile.Mobile
import org.json.JSONObject
import java.text.DateFormat
import java.time.OffsetDateTime
import java.util.Date
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Control and status screen: import the agent config, start/stop the VPN
 * service, show the token and tunnel state and open the browser for login.
 */
class MainActivity : ComponentActivity() {

    private lateinit var tokenView: TextView
    private lateinit var devicesBox: LinearLayout
    private lateinit var toggleButton: Button
    private lateinit var loginButton: Button
    private var lastStatus = ""
    private var running = false

    private val importConfig =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
            if (uri == null) return@registerForActivityResult
            contentResolver.openInputStream(uri)?.use { input ->
                WirestewardVpnService.configFile(this).outputStream().use { input.copyTo(it) }
            }
            Toast.makeText(this, "Config imported, restart the VPN to apply", Toast.LENGTH_SHORT).show()
        }

    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) startVpnService()
            else Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
        }

    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    // The agent starts on a background thread, so poll its state while visible.
    // The status can wait for the network (token refresh), so it is read off
    // the main thread, one request at a time.
    private val handler = Handler(Looper.getMainLooper())
    private val statusExecutor = Executors.newSingleThreadExecutor()
    private val polling = AtomicBoolean(false)
    private val poll = object : Runnable {
        override fun run() {
            refreshAsync()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val pad = dp(20)
        tokenView = TextView(this).apply { textSize = 16f }
        devicesBox = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(12), 0, dp(12))
        }
        toggleButton = button("Start") { if (running) stop() else start() }
        loginButton = button("Login") { openLogin() }

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            addView(tokenView)
            addView(devicesBox)
            addView(toggleButton)
            addView(loginButton)
            addView(button("Import config") { importConfig.launch(arrayOf("application/json", "*/*")) })
        }
        val root = ScrollView(this).apply {
            addView(content)
            // Targeting SDK 35 draws edge to edge: keep clear of the system bars.
            ViewCompat.setOnApplyWindowInsetsListener(this) { v: View, insets ->
                val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
                v.setPadding(0, bars.top, 0, bars.bottom)
                insets
            }
        }
        setContentView(root)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    override fun onResume() {
        super.onResume()
        poll.run()
    }

    override fun onPause() {
        handler.removeCallbacks(poll)
        super.onPause()
    }

    override fun onDestroy() {
        statusExecutor.shutdown()
        super.onDestroy()
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun button(label: String, onClick: () -> Unit) =
        Button(this).apply {
            text = label
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
            setOnClickListener { onClick() }
        }

    private fun refreshAsync() {
        if (!polling.compareAndSet(false, true)) return
        statusExecutor.execute {
            val json = try {
                Mobile.status()
            } catch (e: Exception) {
                null
            }
            handler.post {
                polling.set(false)
                if (json != null && !isDestroyed) refresh(json)
            }
        }
    }

    private fun refresh(json: String) {
        if (json == lastStatus) return
        lastStatus = json
        val status = JSONObject(json)
        running = status.optBoolean("running")
        toggleButton.text = if (running) "Stop" else "Start"
        loginButton.isEnabled = running

        if (!running) {
            val config = if (WirestewardVpnService.configFile(this).exists()) "" else " (no config imported)"
            tokenView.text = "VPN stopped$config"
            tokenView.setTextColor(Color.DKGRAY)
            devicesBox.removeAllViews()
            return
        }

        val token = status.getJSONObject("token")
        when {
            !token.optBoolean("present") -> {
                tokenView.text = "Not logged in"
                tokenView.setTextColor(RED)
            }
            token.optBoolean("active") -> {
                tokenView.text = "Logged in until ${formatTime(token.optString("expiry"))}"
                tokenView.setTextColor(GREEN)
            }
            else -> {
                tokenView.text = "Login expired at ${formatTime(token.optString("expiry"))}"
                tokenView.setTextColor(RED)
            }
        }

        devicesBox.removeAllViews()
        val devices = status.optJSONArray("devices")
        for (i in 0 until (devices?.length() ?: 0)) {
            devicesBox.addView(deviceView(devices!!.getJSONObject(i)))
        }
    }

    private fun deviceView(d: JSONObject): View {
        val connected = d.optBoolean("connected")
        val (label, color) = when {
            !connected -> "waiting for lease" to Color.GRAY
            !d.optBoolean("healthChecked") -> "connected" to GREEN
            d.optBoolean("healthy") -> "healthy" to GREEN
            else -> "unhealthy" to RED
        }
        val routes = d.optJSONArray("routes")
        val routeList = (0 until (routes?.length() ?: 0)).joinToString(", ") { routes!!.getString(it) }
        val details = listOfNotNull(
            d.optString("address").takeIf { it.isNotEmpty() },
            d.optString("server").takeIf { it.isNotEmpty() }?.removePrefix("https://"),
            routeList.takeIf { it.isNotEmpty() },
        ).joinToString("\n")

        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(8), 0, dp(8))
            addView(TextView(context).apply {
                text = "● ${d.getString("name")}  $label"
                setTextColor(color)
                textSize = 16f
                setTypeface(typeface, Typeface.BOLD)
            })
            if (details.isNotEmpty()) {
                addView(TextView(context).apply {
                    text = details
                    setTextColor(Color.GRAY)
                    textSize = 12f
                })
            }
        }
    }

    private fun formatTime(rfc3339: String): String = try {
        val t = OffsetDateTime.parse(rfc3339)
        DateFormat.getTimeInstance(DateFormat.SHORT).format(Date.from(t.toInstant()))
    } catch (e: Exception) {
        rfc3339
    }

    private fun start() {
        if (!WirestewardVpnService.configFile(this).exists()) {
            Toast.makeText(this, "Import a config first", Toast.LENGTH_SHORT).show()
            return
        }
        // Shows the system consent dialog the first time, null afterwards.
        val intent = VpnService.prepare(this)
        if (intent != null) vpnPermission.launch(intent) else startVpnService()
    }

    private fun startVpnService() {
        startForegroundService(Intent(this, WirestewardVpnService::class.java))
    }

    private fun stop() {
        startService(Intent(this, WirestewardVpnService::class.java).setAction(WirestewardVpnService.ACTION_STOP))
    }

    /** Login is the only thing that needs the browser: the agent serves the
     * oauth2 flow on loopback and the redirect lands back on it. */
    private fun openLogin() {
        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("http://localhost:7773/renew")))
    }

    companion object {
        private val GREEN = Color.rgb(0x2E, 0x7D, 0x32)
        private val RED = Color.rgb(0xC6, 0x28, 0x28)
    }
}
