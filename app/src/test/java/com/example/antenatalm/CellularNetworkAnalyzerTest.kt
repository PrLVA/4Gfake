package com.example.antenatalm

import com.example.antenatalm.analyzer.CellularNetworkAnalyzer
import com.example.antenatalm.model.AnomalyType
import com.example.antenatalm.model.CellDetails
import com.example.antenatalm.model.NeighborCellInfo
import com.example.antenatalm.model.ThreatLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class CellularNetworkAnalyzerTest {

    private lateinit var analyzer: CellularNetworkAnalyzer

    @Before
    fun setUp() {
        analyzer = CellularNetworkAnalyzer()
    }

    @Test
    fun analyze_normal4gNetwork_returnsSafe() {
        val cell = CellDetails(
            cellId = 20849102L,
            networkType = "LTE 4G",
            is2G = false,
            mcc = "214",
            mnc = "07",
            operatorName = "Movistar ES",
            simOperator = "21407",
            tac = 18400,
            pci = 230,
            signalDbm = -85
        )
        val neighbors = listOf(
            NeighborCellInfo(20849103L, "LTE 4G", 231, -90, 18400),
            NeighborCellInfo(20849105L, "LTE 4G", 235, -95, 18400)
        )

        val result = analyzer.analyze(cell, neighbors)

        assertEquals(ThreatLevel.SAFE, result.threatLevel)
        assertTrue(result.threatScore < 25)
        assertTrue(result.anomalies.isEmpty())
    }

    @Test
    fun analyze_forced2gConnection_detects2gDowngradeAnomaly() {
        val cell = CellDetails(
            cellId = 40291L,
            networkType = "GSM 2G",
            is2G = true,
            mcc = "214",
            mnc = "07",
            tac = 18400,
            signalDbm = -75
        )
        val neighbors = listOf(
            NeighborCellInfo(40292L, "GSM 2G", -1, -88, 18400)
        )

        val result = analyzer.analyze(cell, neighbors)

        assertTrue(result.anomalies.any { it.type == AnomalyType.FORCED_2G_DOWNGRADE })
        assertTrue(result.threatScore >= 35)
    }

    @Test
    fun analyze_isolatedCellWithNoNeighbors_detectsIsolatedCellAnomaly() {
        val cell = CellDetails(
            cellId = 102938L,
            networkType = "LTE 4G",
            is2G = false,
            tac = 12000,
            signalDbm = -70
        )
        val neighbors = emptyList<NeighborCellInfo>()

        val result = analyzer.analyze(cell, neighbors)

        assertTrue(result.anomalies.any { it.type == AnomalyType.ISOLATED_CELL_NO_NEIGHBORS })
    }

    @Test
    fun analyze_imsiCatcherStingrayScenario_returnsHighRisk() {
        val cell = CellDetails(
            cellId = 99999L,
            networkType = "GSM 2G (Forzado)",
            is2G = true,
            mcc = "214",
            mnc = "99",
            simOperator = "21407",
            tac = 0, // Invalid TAC
            signalDbm = -45 // Abnormally high signal
        )
        val neighbors = emptyList<NeighborCellInfo>()

        val result = analyzer.analyze(cell, neighbors)

        assertEquals(ThreatLevel.HIGH_RISK, result.threatLevel)
        assertTrue(result.threatScore >= 50)
        assertTrue(result.anomalies.any { it.type == AnomalyType.FORCED_2G_DOWNGRADE })
        assertTrue(result.anomalies.any { it.type == AnomalyType.INVALID_TAC_LAC })
        assertTrue(result.anomalies.any { it.type == AnomalyType.ISOLATED_CELL_NO_NEIGHBORS })
    }
}
