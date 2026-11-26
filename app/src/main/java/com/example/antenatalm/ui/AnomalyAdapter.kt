package com.example.antenatalm.ui

import android.content.res.ColorStateList
import android.graphics.Color
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.example.antenatalm.databinding.ItemAnomalyBinding
import com.example.antenatalm.model.AnomalySeverity
import com.example.antenatalm.model.SecurityAnomaly

class AnomalyAdapter : ListAdapter<SecurityAnomaly, AnomalyAdapter.ViewHolder>(DiffCallback) {

    class ViewHolder(val binding: ItemAnomalyBinding) : RecyclerView.ViewHolder(binding.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemAnomalyBinding.inflate(
            LayoutInflater.from(parent.context), parent, false
        )
        return ViewHolder(binding)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)
        holder.binding.tvTitle.text = item.title
        holder.binding.tvDescription.text = item.description

        val color = when (item.severity) {
            AnomalySeverity.HIGH -> Color.parseColor("#FF1744") // Matrix Red
            AnomalySeverity.MEDIUM -> Color.parseColor("#FFD600") // Matrix Cyber Gold
            AnomalySeverity.LOW -> Color.parseColor("#00FF41") // Matrix Green
        }

        holder.binding.chipSeverity.text = when (item.severity) {
            AnomalySeverity.HIGH -> "CRÍTICO"
            AnomalySeverity.MEDIUM -> "MEDIO"
            AnomalySeverity.LOW -> "INFO"
        }
        holder.binding.chipSeverity.chipBackgroundColor = ColorStateList.valueOf(color)
        holder.binding.viewIndicator.setBackgroundColor(color)
    }

    object DiffCallback : DiffUtil.ItemCallback<SecurityAnomaly>() {
        override fun areItemsTheSame(oldItem: SecurityAnomaly, newItem: SecurityAnomaly): Boolean {
            return oldItem.title == newItem.title
        }

        override fun areContentsTheSame(oldItem: SecurityAnomaly, newItem: SecurityAnomaly): Boolean {
            return oldItem == newItem
        }
    }
}
