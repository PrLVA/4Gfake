package com.example.antenatalm.ui

import android.annotation.SuppressLint
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.example.antenatalm.databinding.ItemNeighborCellBinding
import com.example.antenatalm.model.NeighborCellInfo

class NeighborAdapter : ListAdapter<NeighborCellInfo, NeighborAdapter.ViewHolder>(DiffCallback) {

    class ViewHolder(val binding: ItemNeighborCellBinding) : RecyclerView.ViewHolder(binding.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemNeighborCellBinding.inflate(
            LayoutInflater.from(parent.context), parent, false
        )
        return ViewHolder(binding)
    }

    @SuppressLint("SetTextI18n")
    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = getItem(position)
        holder.binding.tvNeighborType.text = item.type

        val pciStr = if (item.pci != -1) "PCI: ${item.pci}" else "PCI: N/D"
        val tacStr = if (item.tac != -1) "TAC: ${item.tac}" else "TAC: N/D"
        val cidStr = if (item.cellId != null && item.cellId != -1L) " | CID: ${item.cellId}" else ""

        holder.binding.tvNeighborDetails.text = "$pciStr | $tacStr$cidStr"
        holder.binding.tvNeighborSignal.text = "${item.signalDbm} dBm"
    }

    object DiffCallback : DiffUtil.ItemCallback<NeighborCellInfo>() {
        override fun areItemsTheSame(oldItem: NeighborCellInfo, newItem: NeighborCellInfo): Boolean {
            return oldItem.pci == newItem.pci && oldItem.cellId == newItem.cellId
        }

        override fun areContentsTheSame(oldItem: NeighborCellInfo, newItem: NeighborCellInfo): Boolean {
            return oldItem == newItem
        }
    }
}
