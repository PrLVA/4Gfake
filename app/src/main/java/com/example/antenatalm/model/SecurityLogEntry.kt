package com.example.antenatalm.model

/**
 * Historical log item for tracking cell re-selections, threat alerts, and network changes.
 */
data class SecurityLogEntry(
    val id: Long = System.nanoTime(),
    val timestamp: Long = System.currentTimeMillis(),
    val threatLevel: ThreatLevel,
    val cellId: Long,
    val networkType: String,
    val tac: Int,
    val message: String
)
