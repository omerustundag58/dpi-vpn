// SPDX-License-Identifier: GPL-3.0-or-later
// Uygulama seçim ekranı: sistem uygulamalarını gizleyip allowed_apps kümesini kaydeder.
package com.dpivpn

import android.app.Activity
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Button
import android.widget.ListView

class AppPickerActivity : Activity() {

    companion object {
        private const val PREFS = "dpi_prefs"
        private const val KEY = "allowed_apps"
    }

    data class AppEntry(val label: String, val packageName: String, var allowed: Boolean)

    private val apps = mutableListOf<AppEntry>()
    private lateinit var adapter: AppListAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_picker)

        val list: ListView = findViewById(R.id.appList)
        val saveButton: Button = findViewById(R.id.saveButton)

        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        val saved = prefs.getStringSet(KEY, emptySet()) ?: emptySet()

        loadApps(saved)
        adapter = AppListAdapter(this, apps)
        list.adapter = adapter

        saveButton.setOnClickListener {
            val selected = apps.filter { it.allowed }.map { it.packageName }.toSet()
            prefs.edit().putStringSet(KEY, selected).apply()
            finish()
        }
    }

    // Sadece başlatılabilir (launcher'lı) ve sistem-dışı uygulamaları listeler.
    private fun loadApps(saved: Set<String>) {
        val pm: PackageManager = packageManager
        val launchIntent = android.content.Intent(android.content.Intent.ACTION_MAIN, null).apply {
            addCategory(android.content.Intent.CATEGORY_LAUNCHER)
        }
        val resolve = pm.queryIntentActivities(launchIntent, 0)
        val seen = mutableSetOf<String>()
        for (ri in resolve) {
            val pkg = ri.activityInfo.packageName
            if (!seen.add(pkg)) continue
            val ai = try { pm.getApplicationInfo(pkg, 0) } catch (_: Exception) { continue }
            if (ai.flags and ApplicationInfo.FLAG_SYSTEM != 0) continue
            val label = pm.getApplicationLabel(ai).toString()
            apps.add(AppEntry(label, pkg, saved.contains(pkg)))
        }
        apps.sortBy { it.label.lowercase() }
    }
}
