package com.example.antenatalm.analyzer

import com.example.antenatalm.model.AnomalySeverity
import com.example.antenatalm.model.AnomalyType
import com.example.antenatalm.model.CellDetails
import com.example.antenatalm.model.NeighborCellInfo
import com.example.antenatalm.model.SecurityAnomaly
import com.example.antenatalm.model.SecurityAssessment
import com.example.antenatalm.model.ThreatLevel

class CellularNetworkAnalyzer {

    private val recentTacs = mutableListOf<Pair<Long, Int>>() // Timestamp to TAC

    /**
     * Evaluates current connected cell tower details and neighbor info to produce a threat assessment.
     */
    fun analyze(
        cell: CellDetails,
        neighbors: List<NeighborCellInfo>
    ): SecurityAssessment {
        val anomalies = mutableListOf<SecurityAnomaly>()
        val recommendations = mutableListOf<String>()

        var score = 0

        // 1. Check for 2G / GSM Downgrade Attack
        if (cell.is2G) {
            score += 35
            anomalies.add(
                SecurityAnomaly(
                    title = "Conexión en Red 2G (GSM / EDGE)",
                    description = "Las redes 2G carecen de autenticación mutua obligatoria, lo que permite a las antenas falsas (IMSI Catchers) interceptar llamadas y SMS.",
                    severity = AnomalySeverity.HIGH,
                    type = AnomalyType.FORCED_2G_DOWNGRADE
                )
            )
            recommendations.add("Inhabilita la opción '2G' o 'Redes antiguas' en la configuración de tarjeta SIM de tu dispositivo Android.")
        }

        // 2. Check for Isolated Cell Tower (No Neighboring Cells)
        if (neighbors.isEmpty() && cell.cellId != -1L) {
            // If signal is very strong but no neighbors exist, rogue tower indicator
            if (cell.signalDbm > -85 || cell.is2G) {
                score += 35
                anomalies.add(
                    SecurityAnomaly(
                        title = "Torre Celular Aislada (Sin celdas vecinas)",
                        description = "La celda conectada no reporta ninguna antena vecina pese a tener buena cobertura. Esto es típico de un Stingray/falsa estación base portátil.",
                        severity = AnomalySeverity.HIGH,
                        type = AnomalyType.ISOLATED_CELL_NO_NEIGHBORS
                    )
                )
                recommendations.add("Mantén el tráfico de datos encriptado (VPN/HTTPS) y evita ingresar credenciales sensibles.")
            } else {
                score += 15
                anomalies.add(
                    SecurityAnomaly(
                        title = "Sin Celdas Vecinas Detectadas",
                        description = "No se observan antenas de respaldo cercanas en este escaneo.",
                        severity = AnomalySeverity.LOW,
                        type = AnomalyType.ISOLATED_CELL_NO_NEIGHBORS
                    )
                )
            }
        }

        // 3. Check for Suspicious/Invalid TAC (Tracking Area Code) or LAC
        if (isAnomalousTac(cell.tac)) {
            score += 30
            anomalies.add(
                SecurityAnomaly(
                    title = "Código de Área (TAC/LAC) Anómalo",
                    description = "El valor TAC/LAC (${cell.tac}) es inválido o genérico (0, 65535, etc.). Las celdas falsas usan TACs genéricos para forzar actualizaciones de ubicación.",
                    severity = AnomalySeverity.HIGH,
                    type = AnomalyType.INVALID_TAC_LAC
                )
            )
        }

        // 4. Check for Rapid TAC Switching
        val now = System.currentTimeMillis()
        if (cell.tac > 0) {
            recentTacs.add(Pair(now, cell.tac))
            // Remove TACs older than 5 minutes (300,000 ms)
            recentTacs.removeAll { now - it.first > 300_000 }

            val distinctTacsInWindow = recentTacs.map { it.second }.distinct().size
            if (distinctTacsInWindow >= 3) {
                score += 25
                anomalies.add(
                    SecurityAnomaly(
                        title = "Cambio Rápido de Código de Área (TAC)",
                        description = "Se detectaron $distinctTacsInWindow cambios de TAC en menos de 5 minutos sin desplazamiento significativo.",
                        severity = AnomalySeverity.MEDIUM,
                        type = AnomalyType.TAC_RAPID_CHANGE
                    )
                )
            }
        }

        // 5. Check for MCC/MNC Mismatch (SIM Operator vs Cellular Operator)
        if (!cell.simOperator.isNull_or_Empty() && !cell.mcc.isNull_or_Empty() && !cell.mnc.isNull_or_Empty()) {
            val networkOperator = "${cell.mcc}${cell.mnc}"
            if (cell.simOperator != networkOperator && networkOperator != "00000" && networkOperator != "99999") {
                score += 15
                anomalies.add(
                    SecurityAnomaly(
                        title = "Diferencia de Operador (MCC/MNC)",
                        description = "El código de red transmitido ($networkOperator) no coincide con el código de tu tarjeta SIM (${cell.simOperator}).",
                        severity = AnomalySeverity.MEDIUM,
                        type = AnomalyType.MCC_MNC_MISMATCH
                    )
                )
            }
        }

        // 6. Check for Abnormal Signal Power
        if (cell.signalDbm > -55 && cell.signalDbm != 0) {
            score += 20
            anomalies.add(
                SecurityAnomaly(
                    title = "Potencia de Señal Anormalmente Alta",
                    description = "La intensidad de la señal (${cell.signalDbm} dBm) es atípicamente fuerte. Los IMSI Catchers emiten alta potencia para forzar la conexión del móvil.",
                    severity = AnomalySeverity.MEDIUM,
                    type = AnomalyType.UNUSUAL_SIGNAL_POWER
                )
            )
        }

        // Final Threat Level determination
        val clampedScore = score.coerceIn(0, 100)
        val threatLevel = when {
            clampedScore >= 50 -> ThreatLevel.HIGH_RISK
            clampedScore >= 25 -> ThreatLevel.SUSPICIOUS
            else -> ThreatLevel.SAFE
        }

        if (recommendations.isEmpty()) {
            recommendations.add("Tu conexión a la red de telefonía celular parece estable y segura.")
            recommendations.add("Escanea periódicamente si te desplazas por zonas de alta concurrencia.")
        } else {
            recommendations.add("Nota sobre Android: Si el conteo de vecinos es 0, asegúrate de tener el **GPS (Ubicación)** activado. Android y muchos modems restringen la lectura de antenas vecinas si la ubicación está desactivada.")
        }

        return SecurityAssessment(
            threatLevel = threatLevel,
            threatScore = clampedScore,
            primaryCell = cell,
            neighborCells = neighbors,
            anomalies = anomalies,
            recommendations = recommendations,
            timestamp = System.currentTimeMillis()
        )
    }

    private fun isAnomalousTac(tac: Int): Boolean {
        return tac == 0 || tac == 65535 || tac == 65534 || tac == -1
    }

    private fun String?.isNull_or_Empty(): Boolean {
        return this.isNullOrEmpty()
    }
}
