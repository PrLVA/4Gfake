package com.example.antenatalm.ui

import android.annotation.SuppressLint
import android.graphics.Color
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.example.antenatalm.databinding.ItemLogEntryBinding
import com.example.antenatalm.model.SecurityLogEntry
import com.example.antenatalm.model.ThreatLevel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class LogAdapter : ListAdapter<SecurityLogEntry, LogAdapter.ViewHolder>(DiffCallback) {

    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    class ViewHolder(val binding: ItemLogEntryBinding) : RecyclerView.ViewHolder(binding.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemLogEntryBinding.inflate(
            LayoutInflater.from(parent.context), parent, false
        )
        return ViewHolder(binding)
    }

    @SuppressLint("SetTextI18n")
    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)

        val (badgeText, badgeBg, textColor) = when (item.threatLevel) {
            ThreatLevel.SAFE -> Triple("OK", Color.parseColor("#00FF41"), Color.BLACK)
            ThreatLevel.SUSPICIOUS -> Triple("ALERTA", Color.parseColor("#FFD600"), Color.BLACK)
            ThreatLevel.HIGH_RISK -> Triple("CRITICO", Color.parseColor("#FF1744"), Color.WHITE)
        }

        holder.binding.tvLogBadge.text = badgeText
        holder.binding.tvLogBadge.setBackgroundColor(badgeBg)
        holder.binding.tvLogBadge.setTextColor(textColor)

        holder.binding.tvLogTime.text = timeFormat.format(Date(item.timestamp))
        holder.binding.tvLogCellId.text = if (item.cellId != -1L) "CID: ${item.cellId}" else "CID: N/D"
        holder.binding.tvLogMessage.text = item.message
    }

    object DiffCallback : DiffUtil.ItemCallback<SecurityLogEntry>() {
        override fun areItemsTheSame(oldItem: SecurityLogEntry, newItem: SecurityLogEntry): Boolean {
            return oldItem.id == newItem.id
        }

        override fun areContentsTheSame(oldItem: SecurityLogEntry, newItem: SecurityLogEntry): Boolean {
            return oldItem == newItem
        }
    }
}
