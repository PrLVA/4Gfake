package com.example.antenatalm

import android.Manifest
import android.annotation.SuppressLint
import android.content.res.ColorStateList
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import com.example.antenatalm.databinding.ActivityMainBinding
import com.example.antenatalm.databinding.DialogSecurityGuideBinding
import com.example.antenatalm.model.ThreatLevel
import com.example.antenatalm.ui.AnomalyAdapter
import com.example.antenatalm.ui.LogAdapter
import com.example.antenatalm.ui.MainViewModel
import com.example.antenatalm.ui.NeighborAdapter
import kotlinx.coroutines.launch

/**
 * MainActivity acts as the primary user interface controller for AntenaTalm Guard.
 * Manages runtime permissions, observes security assessment state from MainViewModel,
 * updates the Matrix Cyberpunk UI, handles scan controls, and supports CSV log exports.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val viewModel: MainViewModel by viewModels()

    // Adapters for anomalies, neighboring cells, and historical logs
    private val anomalyAdapter = AnomalyAdapter()
    private val neighborAdapter = NeighborAdapter()
    private val logAdapter = LogAdapter()

    // Animator for the Matrix radar scan pulse effect
    private var scanAnimator: android.animation.ObjectAnimator? = null

    // Runtime permission launcher for Location and Phone State
    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { _ ->
        viewModel.checkPermissions()
        viewModel.refreshScan()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.topAppBar)

        // Handle edge-to-edge window insets
        ViewCompat.setOnApplyWindowInsetsListener(binding.main) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        setupRecyclerViews()
        setupListeners()
        observeUiState()

        requestPermissionsIfNeeded()
    }

    private fun setupRecyclerViews() {
        binding.rvAnomalies.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = anomalyAdapter
        }

        binding.rvNeighbors.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = neighborAdapter
        }

        binding.rvLogs.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = logAdapter
        }
    }

    private fun setupListeners() {
        // Start live monitoring and scanning loop
        binding.btnStartScan.setOnClickListener {
            viewModel.startScanning()
        }

        // Stop live monitoring
        binding.btnStopScan.setOnClickListener {
            viewModel.stopScanning()
        }

        // Request runtime permissions again if denied
        binding.btnGrantPermissions.setOnClickListener {
            requestPermissionsIfNeeded()
        }

        // Open location settings to enable GPS
        binding.btnEnableGps.setOnClickListener {
            startActivity(android.content.Intent(android.provider.Settings.ACTION_LOCATION_SOURCE_SETTINGS))
        }

        // Clear historical audit logs
        binding.btnClearLogs.setOnClickListener {
            viewModel.clearLogs()
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.checkLocationEnabled()
        viewModel.checkPermissions()
    }

    private fun requestPermissionsIfNeeded() {
        val permissionsToRequest = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.READ_PHONE_STATE
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissionsToRequest.add(Manifest.permission.POST_NOTIFICATIONS)
        }

        permissionLauncher.launch(permissionsToRequest.toTypedArray())
    }

    private fun observeUiState() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.uiState.collect { state ->
                    updateUi(state)
                }
            }
        }
    }

    @SuppressLint("SetTextI18n")
    private fun updateUi(state: com.example.antenatalm.ui.MainUiState) {
        // Show/hide permission warning banner
        binding.cardPermissionWarning.visibility =
            if (!state.hasPermissions) View.VISIBLE else View.GONE

        // Show/hide GPS warning banner if location services are turned off
        binding.cardGpsWarning.visibility =
            if (!state.isLocationEnabled) View.VISIBLE else View.GONE

        // Show/hide progress indicator during network query
        binding.progressScan.visibility = if (state.isScanning) View.VISIBLE else View.INVISIBLE

        // Threat Status Banner styling based on threat level (Safe, Suspicious, High Risk)
        val assessment = state.assessment
        val (bgColor, strokeColor, iconTint, titleColor) = when (assessment.threatLevel) {
            ThreatLevel.SAFE -> Quadruple(
                Color.parseColor("#052B10"),
                Color.parseColor("#00FF41"),
                Color.parseColor("#00FF41"),
                Color.parseColor("#00FF41")
            )
            ThreatLevel.SUSPICIOUS -> Quadruple(
                Color.parseColor("#241C00"),
                Color.parseColor("#FFD600"),
                Color.parseColor("#FFD600"),
                Color.parseColor("#FFD600")
            )
            ThreatLevel.HIGH_RISK -> Quadruple(
                Color.parseColor("#2B0409"),
                Color.parseColor("#FF1744"),
                Color.parseColor("#FF1744"),
                Color.parseColor("#FF1744")
            )
        }

        binding.cardThreatStatus.setCardBackgroundColor(bgColor)
        binding.cardThreatStatus.strokeColor = strokeColor
        binding.ivThreatIcon.imageTintList = ColorStateList.valueOf(iconTint)

        // Update radar scanning animation state
        updateScanningAnimation(state.isScanningActive)

        if (state.isScanning) {
            binding.tvThreatTitle.text = ">_ ESCANEANDO RADIOFRECUENCIA..."
        } else {
            binding.tvThreatTitle.text = assessment.threatLevel.titleEs
        }
        binding.tvThreatTitle.setTextColor(titleColor)
        binding.tvThreatSubtitle.text = "THREAT_INDEX: ${assessment.threatScore} / 100"
        binding.tvThreatSubtitle.setTextColor(titleColor)
        binding.tvThreatDescription.text = assessment.threatLevel.descriptionEs
        binding.tvThreatDescription.setTextColor(titleColor)

        // Update Start/Stop button visual opacities based on scan activity state
        if (state.isScanningActive) {
            binding.btnStartScan.alpha = 1.0f
            binding.btnStopScan.alpha = 0.4f
        } else {
            binding.btnStartScan.alpha = 0.4f
            binding.btnStopScan.alpha = 1.0f
        }

        // Active Cell Details
        val primary = assessment.primaryCell
        binding.tvCellOperator.text = "${primary.operatorName} (${primary.mcc}-${primary.mnc})"
        binding.tvCellNetworkType.text = primary.networkType
        binding.tvCellId.text = if (primary.cellId != -1L) primary.cellId.toString() else "N/D"
        binding.tvCellTac.text = if (primary.tac != -1) primary.tac.toString() else "N/D"
        binding.tvCellSignalDbm.text = "${primary.signalDbm} dBm"

        // Adapters
        anomalyAdapter.submitList(assessment.anomalies)

        // Neighbors Section & Total Count
        val neighborCount = assessment.neighborCells.size
        val totalAntennasCount = if (primary.cellId != -1L) neighborCount + 1 else neighborCount

        binding.tvTotalAntennasCount.text = totalAntennasCount.toString()
        binding.tvNeighborsCountBadge.text = neighborCount.toString()

        binding.tvNeighborsHeader.text = "> CELDAS_VECINAS // DETECTADAS ($neighborCount VECINAS | TOTAL $totalAntennasCount EN RANGO)"
        binding.tvNeighborsEmpty.visibility = if (neighborCount == 0) View.VISIBLE else View.GONE

        neighborAdapter.submitList(assessment.neighborCells)
        logAdapter.submitList(state.logs)
    }

    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_refresh -> {
                viewModel.refreshScan()
                true
            }
            R.id.action_export -> {
                exportAuditLogs(viewModel.uiState.value.logs)
                true
            }
            R.id.action_guide -> {
                showSecurityGuideDialog()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    /**
     * Exports real-time monitoring audit logs as a CSV format via Android Share Intent.
     */
    private fun exportAuditLogs(logs: List<com.example.antenatalm.model.SecurityLogEntry>) {
        val sb = StringBuilder()
        sb.append("TIMESTAMP,THREAT_LEVEL,CELL_ID,NETWORK_TYPE,TAC,MESSAGE\n")
        val dateFormat = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.getDefault())
        for (log in logs) {
            val dateStr = dateFormat.format(java.util.Date(log.timestamp))
            sb.append("\"$dateStr\",\"${log.threatLevel}\",\"${log.cellId}\",\"${log.networkType}\",\"${log.tac}\",\"${log.message.replace("\"", "\"\"")}\"\n")
        }

        val sendIntent = android.content.Intent().apply {
            action = android.content.Intent.ACTION_SEND
            putExtra(android.content.Intent.EXTRA_SUBJECT, "AntenaTalm Guard - Security Audit Log")
            putExtra(android.content.Intent.EXTRA_TEXT, sb.toString())
            type = "text/plain"
        }
        startActivity(android.content.Intent.createChooser(sendIntent, "Exportar Auditoría CSV"))
    }

    private fun showSecurityGuideDialog() {
        val dialogBinding = DialogSecurityGuideBinding.inflate(layoutInflater)
        val dialog = AlertDialog.Builder(this)
            .setView(dialogBinding.root)
            .create()

        dialogBinding.btnCloseGuide.setOnClickListener {
            dialog.dismiss()
        }

        dialog.show()
    }

    /**
     * Controls the Matrix radar icon pulsing animation during active monitoring.
     */
    private fun updateScanningAnimation(isScanning: Boolean) {
        if (isScanning) {
            if (scanAnimator == null) {
                scanAnimator = android.animation.ObjectAnimator.ofFloat(binding.ivThreatIcon, "alpha", 1.0f, 0.2f, 1.0f).apply {
                    duration = 600
                    repeatCount = android.animation.ObjectAnimator.INFINITE
                    repeatMode = android.animation.ObjectAnimator.REVERSE
                    start()
                }
            }
        } else {
            scanAnimator?.cancel()
            scanAnimator = null
            binding.ivThreatIcon.alpha = 1.0f
        }
    }

    private data class Quadruple<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)
}
