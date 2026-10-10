// SPDX-License-Identifier: GPL-3.0-or-later
// Ana ekran: profil/mod seçimi, BAŞLAT/DURDUR, durum ve istatistik gösterimi.
package com.dpivpn

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.Spinner
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast

class MainActivity : Activity() {

    companion object {
        const val ACTION_STATE_UPDATE = "com.dpivpn.STATE_UPDATE"
        private const val VPN_REQUEST = 1001
        private const val PREFS = "dpi_prefs"
    }

    private lateinit var statusText: TextView
    private lateinit var statsText: TextView
    private lateinit var profileSpinner: Spinner
    private lateinit var modeSpinner: Spinner
    private lateinit var dnsSwitch: Switch

    // Servisten gelen bayt/süre yayınını alıp istatistik satırını günceller.
    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != ACTION_STATE_UPDATE) return
            val up = intent.getLongExtra("bytes_up", 0L)
            val down = intent.getLongExtra("bytes_down", 0L)
            val secs = intent.getLongExtra("duration_sec", 0L)
            val running = intent.getBooleanExtra("running", false)
            statusText.text = if (running) getString(R.string.status_running) else getString(R.string.status_stopped)
            statsText.text = getString(R.string.stats_format, up, down, secs)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        statsText = findViewById(R.id.statsText)
        profileSpinner = findViewById(R.id.profileSpinner)
        modeSpinner = findViewById(R.id.modeSpinner)
        dnsSwitch = findViewById(R.id.dnsSwitch)
        val startButton: Button = findViewById(R.id.startButton)
        val stopButton: Button = findViewById(R.id.stopButton)
        val pickAppsButton: Button = findViewById(R.id.pickAppsButton)

        val profiles = resources.getStringArray(R.array.profiles)
        profileSpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, profiles).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }
        val modes = resources.getStringArray(R.array.modes)
        modeSpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, modes).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        profileSpinner.setSelection(prefs.getInt("profile", 0).coerceIn(profiles.indices))
        modeSpinner.setSelection(prefs.getInt("mode", 0).coerceIn(modes.indices))
        dnsSwitch.isChecked = prefs.getBoolean("custom_dns", false)

        startButton.setOnClickListener {
            prefs.edit()
                .putInt("profile", profileSpinner.selectedItemPosition)
                .putInt("mode", modeSpinner.selectedItemPosition)
                .putBoolean("custom_dns", dnsSwitch.isChecked)
                .apply()
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

        registerReceiver(stateReceiver, IntentFilter(ACTION_STATE_UPDATE))
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
            putExtra("profile", profileSpinner.selectedItemPosition)
            putExtra("mode", modeSpinner.selectedItemPosition)
            putExtra("custom_dns", prefs.getBoolean("custom_dns", false))
            putStringArrayListExtra("allowed_apps", ArrayList(
                prefs.getStringSet("allowed_apps", emptySet()) ?: emptySet()
            ))
        }
        startService(intent)
        statusText.text = getString(R.string.status_running)
    }

    private fun stopVpn() {
        startService(Intent(this, DpiVpnService::class.java).apply { action = "DISCONNECT" })
        statusText.text = getString(R.string.status_stopped)
    }

    override fun onDestroy() {
        try { unregisterReceiver(stateReceiver) } catch (_: Exception) {}
        super.onDestroy()
    }
}
