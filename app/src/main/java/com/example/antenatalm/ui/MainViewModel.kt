package com.example.antenatalm.ui

import android.app.Application
import android.content.Context
import android.location.LocationManager
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.antenatalm.model.SecurityAssessment
import com.example.antenatalm.model.SecurityLogEntry
import com.example.antenatalm.model.ThreatLevel
import com.example.antenatalm.telephony.CellularScanner
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class MainUiState(
    val hasPermissions: Boolean = false,
    val isLocationEnabled: Boolean = true,
    val isScanning: Boolean = false,
    val assessment: SecurityAssessment = SecurityAssessment(),
    val logs: List<SecurityLogEntry> = emptyList(),
    val isAutoScanActive: Boolean = true,
    val isScanningActive: Boolean = true
)

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val scanner = CellularScanner(application)

    private val _uiState = MutableStateFlow(MainUiState())
    val uiState: StateFlow<MainUiState> = _uiState.asStateFlow()

    private var autoScanJob: Job? = null

    init {
        checkPermissions()
        checkLocationEnabled()
        refreshScan()
        startAutoScan()
    }

    fun checkPermissions() {
        val hasPerms = scanner.hasRequiredPermissions()
        _uiState.update { it.copy(hasPermissions = hasPerms) }
    }

    fun checkLocationEnabled() {
        val context = getApplication<Application>()
        val locationManager = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
        val isGpsOn = locationManager?.isProviderEnabled(LocationManager.GPS_PROVIDER) == true ||
                      locationManager?.isProviderEnabled(LocationManager.NETWORK_PROVIDER) == true
        _uiState.update { it.copy(isLocationEnabled = isGpsOn) }
    }

    fun refreshScan() {
        checkLocationEnabled()
        viewModelScope.launch {
            _uiState.update { it.copy(isScanning = true) }

            // Brief delay for user feedback on scan animation
            delay(300)

            val newAssessment = scanner.scanNetwork()
            val currentLogs = _uiState.value.logs.toMutableList()

            // Create a log entry if network details or threat state changed
            val lastLog = currentLogs.firstOrNull()
            if (lastLog == null ||
                lastLog.threatLevel != newAssessment.threatLevel ||
                lastLog.cellId != newAssessment.primaryCell.cellId ||
                lastLog.tac != newAssessment.primaryCell.tac
            ) {
                val logMessage = when (newAssessment.threatLevel) {
                    ThreatLevel.HIGH_RISK -> "¡ALERTA! Posible celda falsa detectada (${newAssessment.primaryCell.networkType}, TAC ${newAssessment.primaryCell.tac})"
                    ThreatLevel.SUSPICIOUS -> "Conexión sospechosa detectada (${newAssessment.primaryCell.networkType})"
                    ThreatLevel.SAFE -> "Red verificada y segura (${newAssessment.primaryCell.networkType}, ${newAssessment.primaryCell.operatorName})"
                }

                currentLogs.add(
                    0,
                    SecurityLogEntry(
                        threatLevel = newAssessment.threatLevel,
                        cellId = newAssessment.primaryCell.cellId,
                        networkType = newAssessment.primaryCell.networkType,
                        tac = newAssessment.primaryCell.tac,
                        message = logMessage
                    )
                )
            }

            _uiState.update {
                it.copy(
                    isScanning = false,
                    assessment = newAssessment,
                    logs = currentLogs
                )
            }
        }
    }

    fun startScanning() {
        _uiState.update { it.copy(isScanningActive = true, isAutoScanActive = true) }
        refreshScan()
        startAutoScan()
    }

    fun stopScanning() {
        autoScanJob?.cancel()
        autoScanJob = null
        _uiState.update { it.copy(isScanningActive = false, isAutoScanActive = false, isScanning = false) }
    }

    fun toggleAutoScan(enabled: Boolean) {
        _uiState.update { it.copy(isAutoScanActive = enabled) }
        if (enabled) {
            startAutoScan()
        } else {
            autoScanJob?.cancel()
            autoScanJob = null
        }
    }

    fun clearLogs() {
        _uiState.update { it.copy(logs = emptyList()) }
    }

    private fun startAutoScan() {
        autoScanJob?.cancel()
        autoScanJob = viewModelScope.launch {
            while (true) {
                delay(8000) // Scan every 8 seconds
                if (_uiState.value.isAutoScanActive && _uiState.value.isScanningActive) {
                    refreshScan()
                }
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        autoScanJob?.cancel()
    }
}
