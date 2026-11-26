package com.example.antenatalm.model

/**
 * Complete security assessment result for the current cell connection.
 */
data class SecurityAssessment(
    val threatLevel: ThreatLevel = ThreatLevel.SAFE,
    val threatScore: Int = 0, // 0 (Safe) to 100 (Critical threat)
    val primaryCell: CellDetails = CellDetails(),
    val neighborCells: List<NeighborCellInfo> = emptyList(),
    val anomalies: List<SecurityAnomaly> = emptyList(),
    val recommendations: List<String> = emptyList(),
    val timestamp: Long = System.currentTimeMillis()
)
