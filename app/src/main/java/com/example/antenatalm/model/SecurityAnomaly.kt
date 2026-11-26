package com.example.antenatalm.model

enum class AnomalySeverity {
    HIGH,
    MEDIUM,
    LOW
}

enum class AnomalyType {
    FORCED_2G_DOWNGRADE,
    ISOLATED_CELL_NO_NEIGHBORS,
    UNUSUAL_SIGNAL_POWER,
    INVALID_TAC_LAC,
    MCC_MNC_MISMATCH,
    TAC_RAPID_CHANGE
}

/**
 * Represents a specific security indicator or anomaly detected in the current cell connection.
 */
data class SecurityAnomaly(
    val title: String,
    val description: String,
    val severity: AnomalySeverity,
    val type: AnomalyType
)
