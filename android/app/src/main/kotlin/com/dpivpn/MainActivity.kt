// Ana ekran: profil/mod seçimi, BAŞLAT/DURDUR, durum ve istatistik gösterimi.
package com.dpivpn

import android.Manifest
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.AutoCompleteTextView
import android.widget.TextView
import android.widget.Toast
import com.google.android.material.button.MaterialButton
import com.google.android.material.materialswitch.MaterialSwitch

class MainActivity : Activity() {

    companion object {
        const val ACTION_STATE_UPDATE = "com.dpivpn.STATE_UPDATE"
        private const val VPN_REQUEST = 1001
        private const val NOTIF_REQUEST = 1002
        private const val PREFS = "dpi_prefs"
    }

    private lateinit var statusText: TextView
    private lateinit var statsText: TextView
    private lateinit var statusDot: android.view.View
    private lateinit var profileDropdown: AutoCompleteTextView
    private lateinit var modeDropdown: AutoCompleteTextView
    private lateinit var dnsSwitch: MaterialSwitch
    private lateinit var quicSwitch: MaterialSwitch
    private lateinit var profiles: Array<String>
    private lateinit var modes: Array<String>

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != ACTION_STATE_UPDATE) return
            val up = intent.getLongExtra("bytes_up", 0L)
            val down = intent.getLongExtra("bytes_down", 0L)
            val secs = intent.getLongExtra("duration_sec", 0L)
            val running = intent.getBooleanExtra("running", false)
            if (!running && intent.getStringExtra("error") == "vpn_denied") {
                statusText.text = getString(R.string.vpn_denied)
                statusDot.setBackgroundResource(R.drawable.dot_red)
                statsText.text = getString(R.string.stats_empty)
                return
            }
            statusText.text = if (running) getString(R.string.status_running) else getString(R.string.status_stopped)
            statusDot.setBackgroundResource(if (running) R.drawable.dot_green else R.drawable.dot_red)
            statsText.text = getString(R.string.stats_format, up, down, secs)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        statsText = findViewById(R.id.statsText)
        statusDot = findViewById(R.id.statusDot)
        profileDropdown = findViewById(R.id.profileDropdown)
        modeDropdown = findViewById(R.id.modeDropdown)
        dnsSwitch = findViewById(R.id.dnsSwitch)
        quicSwitch = findViewById(R.id.quicSwitch)
        val startButton: MaterialButton = findViewById(R.id.startButton)
        val stopButton: MaterialButton = findViewById(R.id.stopButton)
        val pickAppsButton: MaterialButton = findViewById(R.id.pickAppsButton)

        profiles = resources.getStringArray(R.array.profiles)
        modes = resources.getStringArray(R.array.modes)
        profileDropdown.setAdapter(ArrayAdapter(this, android.R.layout.simple_list_item_1, profiles))
        modeDropdown.setAdapter(ArrayAdapter(this, android.R.layout.simple_list_item_1, modes))

        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        profileDropdown.setText(profiles[prefs.getInt("profile", 0).coerceIn(profiles.indices)], false)
        modeDropdown.setText(modes[prefs.getInt("mode", 0).coerceIn(modes.indices)], false)
        dnsSwitch.isChecked = prefs.getBoolean("custom_dns", false)
        quicSwitch.isChecked = prefs.getBoolean("quic_block", true)

        startButton.setOnClickListener {
            prefs.edit()
                .putInt("profile", profiles.indexOf(profileDropdown.text.toString()).coerceAtLeast(0))
                .putInt("mode", modes.indexOf(modeDropdown.text.toString()).coerceAtLeast(0))
                .putBoolean("custom_dns", dnsSwitch.isChecked)
                .putBoolean("quic_block", quicSwitch.isChecked)
                .apply()
            askNotifPermission()
            val prepare = VpnService.prepare(this)
            if (prepare != null) {
                startActivityForResult(prepare, VPN_REQUEST)
            } else {
                startVpn()
            }
        }
        stopButton.setOnClickListener { stopVpn() }
        pickAppsButton.setOnClickListener {
            startActivity(Intent(this, AppPickerActivity::class.java))
        }

        registerReceiverCompat(stateReceiver, IntentFilter(ACTION_STATE_UPDATE))
    }

    // Android 13+ bildirim izni (canlı VPN bildirimi için).
    private fun askNotifPermission() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), NOTIF_REQUEST)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST) {
            if (resultCode == RESULT_OK) startVpn()
            else Toast.makeText(this, R.string.vpn_denied, Toast.LENGTH_SHORT).show()
        }
    }

    private fun startVpn() {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        val intent = Intent(this, DpiVpnService::class.java).apply {
            action = "CONNECT"
            putExtra("profile", prefs.getInt("profile", 0))
            putExtra("mode", prefs.getInt("mode", 0))
            putExtra("custom_dns", prefs.getBoolean("custom_dns", false))
            putExtra("quic_block", prefs.getBoolean("quic_block", true))
            putStringArrayListExtra("allowed_apps", ArrayList(
                prefs.getStringSet("allowed_apps", emptySet()) ?: emptySet()
            ))
        }
        startService(intent)
        statusText.text = getString(R.string.status_running)
        statusDot.setBackgroundResource(R.drawable.dot_green)
    }

    private fun stopVpn() {
        startService(Intent(this, DpiVpnService::class.java).apply { action = "DISCONNECT" })
        statusText.text = getString(R.string.status_stopped)
        statusDot.setBackgroundResource(R.drawable.dot_red)
    }

    private fun registerReceiverCompat(receiver: BroadcastReceiver, filter: IntentFilter) {
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION") registerReceiver(receiver, filter)
        }
    }

    override fun onDestroy() {
        try { unregisterReceiver(stateReceiver) } catch (_: Exception) {}
        super.onDestroy()
    }
}
