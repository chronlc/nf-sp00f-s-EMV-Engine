package com.example.emvdemo

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

// Import nf-sp00f EMV Engine
import com.nf_sp00f.app.emv.*
import com.nf_sp00f.app.emv.nfc.*
import com.nf_sp00f.app.emv.data.*

/**
 * Quick Start Example - EMV Transaction Processing
 * 
 * This example shows how to integrate and use the nf-sp00f EMV Engine
 * in your Android application for processing EMV card transactions.
 */
class MainActivity : ComponentActivity() {
    
    private lateinit var emvEngine: EmvEngine
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Initialize EMV Engine
        initializeEmvEngine()
        
        setContent {
            EmvDemoApp()
        }
    }
    
    /**
     * Initialize the EMV Engine with Android Internal NFC
     */
    private fun initializeEmvEngine() {
        emvEngine = EmvEngine.builder()
            .nfcProvider(AndroidInternalNfcProvider(this))
            .enableRocaDetection(true)
            .enableDebugLogging(true)
            .setSecurityLevel(SecurityLevel.HIGH)
            .build()
    }
    
    @Composable
    fun EmvDemoApp() {
        var transactionResult by remember { mutableStateOf<TransactionResult?>(null) }
        var isProcessing by remember { mutableStateOf(false) }
        
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            
            Text(
                text = "nf-sp00f EMV Engine Demo",
                style = MaterialTheme.typography.headlineMedium
            )
            
            Spacer(modifier = Modifier.height(32.dp))
            
            // Transaction Amount Input
            var amount by remember { mutableStateOf("10.00") }
            OutlinedTextField(
                value = amount,
                onValueChange = { amount = it },
                label = { Text("Amount (USD)") },
                modifier = Modifier.fillMaxWidth()
            )
            
            Spacer(modifier = Modifier.height(16.dp))
            
            // Process Transaction Button
            Button(
                onClick = { 
                    processTransaction(amount.toDoubleOrNull() ?: 0.0) { result ->
                        transactionResult = result
                        isProcessing = false
                    }
                },
                enabled = !isProcessing,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (isProcessing) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                }
                Text(if (isProcessing) "Processing..." else "Process EMV Transaction")
            }
            
            Spacer(modifier = Modifier.height(24.dp))
            
            // Display Transaction Result
            transactionResult?.let { result ->
                TransactionResultCard(result)
            }
        }
    }
    
    /**
     * Process EMV transaction with the specified amount
     */
    private fun processTransaction(amount: Double, callback: (TransactionResult) -> Unit) {
        lifecycleScope.launch {
            try {
                val transactionData = TransactionData(
                    amount = (amount * 100).toLong(), // Convert to cents
                    currency = "USD",
                    transactionType = TransactionType.PURCHASE,
                    timestamp = System.currentTimeMillis()
                )
                
                val result = emvEngine.processTransaction(transactionData)
                callback(result)
                
            } catch (e: Exception) {
                callback(TransactionResult.Error("Transaction failed: ${e.message}"))
            }
        }
    }
    
    @Composable
    fun TransactionResultCard(result: TransactionResult) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = when (result) {
                    is TransactionResult.Success -> MaterialTheme.colorScheme.primaryContainer
                    is TransactionResult.Error -> MaterialTheme.colorScheme.errorContainer
                }
            )
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                when (result) {
                    is TransactionResult.Success -> {
                        Text(
                            text = "✅ Transaction Successful",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onPrimaryContainer
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        Text("Card: ${maskPan(result.cardData.pan ?: "Unknown")}")
                        Text("Amount: $${result.amount?.div(100.0) ?: "0.00"}")
                        Text("Auth: ${result.authenticationMethod?.name ?: "None"}")
                        result.cardData.expiry?.let { Text("Expires: $it") }
                        
                        // Security Information
                        if (result.securityAnalysis?.rocaVulnerable == true) {
                            Text(
                                text = "⚠️ ROCA Vulnerability Detected",
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                    
                    is TransactionResult.Error -> {
                        Text(
                            text = "❌ Transaction Failed",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        Text(
                            text = result.errorMessage,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                }
            }
        }
    }
    
    /**
     * Mask PAN for display (PCI DSS compliance)
     */
    private fun maskPan(pan: String): String {
        return if (pan.length >= 8) {
            "${pan.take(4)}****${pan.takeLast(4)}"
        } else {
            "****"
        }
    }
}

/**
 * Advanced EMV Operations Example
 */
class AdvancedEmvOperations(private val emvEngine: EmvEngine) {
    
    /**
     * Perform comprehensive card analysis
     */
    suspend fun analyzeCard(): CardAnalysisResult {
        return try {
            // Use command interface for advanced operations
            val commandInterface = EmvCommandInterface()
            val sessionId = commandInterface.createSession(emvEngine.nfcProvider)
            
            try {
                // Execute card detection
                val cardResult = commandInterface.executeCardDetection(
                    CommandContext(sessionId, emvEngine.nfcProvider)
                )
                
                if (cardResult is CommandResult.Success) {
                    // Execute security analysis
                    val securityResult = commandInterface.executeSecurityAnalysis(
                        CommandContext(sessionId, emvEngine.nfcProvider)
                    )
                    
                    CardAnalysisResult.Success(
                        cardInfo = cardResult.data,
                        securityAnalysis = (securityResult as? CommandResult.Success)?.data
                    )
                } else {
                    CardAnalysisResult.Failed("Card detection failed")
                }
                
            } finally {
                commandInterface.closeSession(sessionId)
            }
            
        } catch (e: Exception) {
            CardAnalysisResult.Failed("Analysis error: ${e.message}")
        }
    }
    
    /**
     * Export transaction data to JSON
     */
    suspend fun exportTransactionData(
        cardInfo: CardInfo,
        transactions: List<TransactionResult>
    ): String {
        val jsonProcessor = EmvJsonProcessor()
        
        return jsonProcessor.exportSessionToJson(
            sessionId = "export_${System.currentTimeMillis()}",
            cardInfo = cardInfo,
            tlvDatabase = TlvDatabase(), // Would contain actual card data
            transactionResults = transactions,
            authenticationResults = emptyList(),
            nfcProviderInfo = emvEngine.nfcProvider.getProviderInfo(),
            format = JsonExportFormat.PRETTY
        )
    }
    
    /**
     * Switch between NFC providers
     */
    suspend fun switchToPN532(bluetoothAddress: String): Boolean {
        return try {
            val pn532Provider = Pn532BluetoothNfcProvider().apply {
                setBluetoothDevice(bluetoothAddress, "PN532-HC06")
            }
            
            val config = NfcProviderConfig(
                type = NfcProviderType.PN532_BLUETOOTH,
                bluetoothAddress = bluetoothAddress
            )
            
            pn532Provider.initialize(config)
        } catch (e: Exception) {
            false
        }
    }
}

/**
 * Card analysis result sealed class
 */
sealed class CardAnalysisResult {
    data class Success(
        val cardInfo: CardInfo,
        val securityAnalysis: SecurityAnalysisResult?
    ) : CardAnalysisResult()
    
    data class Failed(val error: String) : CardAnalysisResult()
}

/**
 * Dependencies for build.gradle.kts:
 * 
 * dependencies {
 *     implementation(project(":emv-library"))
 *     
 *     // Required for EMV Engine
 *     implementation("androidx.core:core-ktx:1.12.0")
 *     implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
 *     implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.2")
 *     implementation("com.jakewharton.timber:timber:5.0.1")
 *     
 *     // UI (Compose)
 *     implementation("androidx.activity:activity-compose:1.8.2")
 *     implementation("androidx.compose.ui:ui:1.5.4")
 *     implementation("androidx.compose.material3:material3:1.1.2")
 *     implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
 * }
 */