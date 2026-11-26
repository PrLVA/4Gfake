package com.example.antenatalm.model

/**
 * Represents information about a neighboring cell tower reported by the modem.
 */
data class NeighborCellInfo(
    val cellId: Long? = null,
    val type: String = "LTE",
    val pci: Int = -1,
    val signalDbm: Int = -140,
    val tac: Int = -1
)
