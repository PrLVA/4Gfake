package com.example.antenatalm.model

/**
 * Represents detailed parameters of the active connected cell tower.
 */
data class CellDetails(
    val cellId: Long = -1L,
    val networkType: String = "Desconocido",
    val is2G: Boolean = false,
    val mcc: String? = null,
    val mnc: String? = null,
    val operatorName: String? = "Desconocido",
    val simOperator: String? = null,
    val tac: Int = -1, // Tracking Area Code or Location Area Code (LAC)
    val pci: Int = -1, // Physical Cell ID
    val signalDbm: Int = -140, // dBm level
    val signalLevel: Int = 0, // 0 to 4
    val bandOrArfcn: Int? = null,
    val isRegistered: Boolean = true
)
