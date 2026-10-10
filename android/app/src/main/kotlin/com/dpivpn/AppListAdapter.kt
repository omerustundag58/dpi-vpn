// SPDX-License-Identifier: GPL-3.0-or-later
// Uygulama listesi satır bağdaştırıcısı: ikon + ad + seçim kutusunu doldurur.
package com.dpivpn

import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.CheckBox
import android.widget.ImageView
import android.widget.TextView

class AppListAdapter(
    private val context: Context,
    private val items: List<AppPickerActivity.AppEntry>,
) : BaseAdapter() {

    override fun getCount(): Int = items.size
    override fun getItem(position: Int): Any = items[position]
    override fun getItemId(position: Int): Long = position.toLong()

    override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
        val view = convertView ?: LayoutInflater.from(context).inflate(R.layout.item_app, parent, false)
        val entry = items[position]
        val icon: ImageView = view.findViewById(R.id.appIcon)
        val name: TextView = view.findViewById(R.id.appName)
        val check: CheckBox = view.findViewById(R.id.appCheck)
        try {
            icon.setImageDrawable(context.packageManager.getApplicationIcon(entry.packageName))
        } catch (_: Exception) {
            icon.setImageDrawable(null)
        }
        name.text = entry.label
        check.setOnCheckedChangeListener(null)
        check.isChecked = entry.allowed
        check.setOnCheckedChangeListener { _, isChecked -> entry.allowed = isChecked }
        view.setOnClickListener { check.toggle() }
        return view
    }
}
