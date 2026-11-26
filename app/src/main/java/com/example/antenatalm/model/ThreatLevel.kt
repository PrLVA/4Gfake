package com.example.antenatalm.model

/**
 * Threat level classifications for rogue cell tower detection.
 */
enum class ThreatLevel(
    val titleEs: String,
    val descriptionEs: String
) {
    SAFE(
        titleEs = "RED SEGURA",
        descriptionEs = "No se detectaron anomalías en la estación base de telefonía."
    ),
    SUSPICIOUS(
        titleEs = "RED SOSPECHOSA",
        descriptionEs = "Se detectaron indicadores inusuales en la celda conectada."
    ),
    HIGH_RISK(
        titleEs = "AMENAZA ALTA / POSIBLE CELDA FALSA",
        descriptionEs = "Se detectaron patrones típicos de un IMSI Catcher / Falsa antena base (Stingray)."
    )
}
