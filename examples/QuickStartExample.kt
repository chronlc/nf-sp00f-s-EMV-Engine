/**
 * nf-sp00f EMV Engine - Enterprise Quick Start Example
 * 
 * Production-grade EMV transaction processing demonstration with comprehensive:
 * - Complete EMV transaction workflow implementation
 * - Enterprise audit logging and error handling
 * - Thread-safe operations with performance monitoring
 * - Advanced card analysis and security validation
 * - Zero defensive programming patterns with comprehensive validation
 * - Professional UI/UX with complete transaction lifecycle
 * 
 * @package com.example.emvdemo
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.example.emvdemo

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import java.math.BigDecimal
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.ConcurrentHashMap

// Import nf-sp00f EMV Engine
import com.nf_sp00f.app.emv.*
import com.nf_sp00f.app.emv.nfc.*
import com.nf_sp00f.app.emv.data.*
import com.nf_sp00f.app.emv.reader.*
import com.nf_sp00f.app.emv.security.*
import com.nf_sp00f.app.emv.config.*
import com.nf_sp00f.app.emv.audit.*
import com.nf_sp00f.app.emv.metrics.*

/**
 * Enterprise EMV Transaction Processing Demonstration
 * 
 * Complete implementation showcasing production-grade EMV processing capabilities
 * with comprehensive audit logging, security analysis, and performance monitoring.
 */
class MainActivity : ComponentActivity() {
    
    companion object {
        private const val DEFAULT_CURRENCY = "840" // USD
        private const val MIN_TRANSACTION_AMOUNT = 0.01
        private const val MAX_TRANSACTION_AMOUNT = 999999.99
        private val SUPPORTED_TRANSACTION_TYPES = listOf(
            EmvTransactionType.PURCHASE,
            EmvTransactionType.CASH_ADVANCE,
            EmvTransactionType.REFUND,
            EmvTransactionType.CASHBACK
        )
    }
    
    private lateinit var emvEngine: EmvEngine
    private lateinit var cardReader: EmvCardReader
    private lateinit var securityAnalyzer: SecurityAnalyzer
    private lateinit var auditLogger: EmvAuditLogger
    private lateinit var performanceMetrics: EmvPerformanceMetrics
    private val transactionCounter = AtomicLong(0)
    private val transactionHistory = ConcurrentHashMap<String, EmvTransactionRecord>()
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        initializeEmvComponents()
        
        setContent {
            EmvDemoTheme {
                EmvDemoApp()
            }
        }
    }
    
    /**
     * Initialize complete EMV processing infrastructure
     */
    private fun initializeEmvComponents() {
        try {
            // Initialize NFC provider factory
            val nfcProviderFactory = NfcProviderFactory()
            val nfcProvider = nfcProviderFactory.createAndroidInternalProvider(this)
            
            // Initialize configuration manager
            val configurationManager = EmvConfigurationManager().apply {
                loadDefaultConfiguration()
                setSecurityLevel(EmvSecurityLevel.MAXIMUM)
                enableRocaDetection(true)
                enableComprehensiveAuditLogging(true)
                setPerformanceMonitoring(true)
            }
            
            // Initialize security analyzer
            securityAnalyzer = SecurityAnalyzer(configurationManager)
            
            // Initialize audit logger
            auditLogger = EmvAuditLogger()
            
            // Initialize performance metrics
            performanceMetrics = EmvPerformanceMetrics()
            
            // Initialize card reader
            cardReader = EmvCardReader(
                nfcProviderFactory = nfcProviderFactory,
                configuration = EmvCardReaderConfiguration(
                    enableContactless = true,
                    enableContact = true,
                    maxRetryAttempts = 3,
                    operationTimeoutMs = 30000L,
                    enableAuditLogging = true,
                    enablePerformanceMonitoring = true,
                    enableStrictValidation = true,
                    enableDataAuthentication = true,
                    enableRiskManagement = true
                )
            )
            
            // Initialize EMV engine
            emvEngine = EmvEngine(
                nfcProvider = nfcProvider,
                configurationManager = configurationManager,
                securityAnalyzer = securityAnalyzer,
                auditLogger = auditLogger,
                performanceMetrics = performanceMetrics
            )
            
            auditLogger.logOperation("SYSTEM_INITIALIZATION", "EMV components initialized successfully")
            
        } catch (e: Exception) {
            auditLogger.logError("SYSTEM_INITIALIZATION_FAILED", "Failed to initialize EMV components: ${e.message}")
            throw EmvSystemInitializationException("EMV system initialization failed", e)
        }
    }
    
    @Composable
    fun EmvDemoApp() {
        var selectedTransactionType by remember { mutableStateOf(EmvTransactionType.PURCHASE) }
        var transactionAmount by remember { mutableStateOf("10.00") }
        var transactionResult by remember { mutableStateOf<EmvTransactionResult>(null) }
        var isProcessing by remember { mutableStateOf(false) }
        var showTransactionHistory by remember { mutableStateOf(false) }
        var cardAnalysisResult by remember { mutableStateOf<EmvCardAnalysisResult>(null) }
        
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            
            // Header Section
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = "nf-sp00f EMV Engine",
                        style = MaterialTheme.typography.headlineMedium,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                    Text(
                        text = "Enterprise Transaction Processing",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    Row {
                        Text(
                            text = "Transactions: ${transactionCounter.get()}",
                            style = MaterialTheme.typography.bodySmall
                        )
                        Spacer(modifier = Modifier.width(16.dp))
                        Text(
                            text = "Active Sessions: ${cardReader.getActiveSessions().size}",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(24.dp))
            
            // Transaction Configuration Section
            Card(
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp)
                ) {
                    Text(
                        text = "Transaction Configuration",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    // Transaction Type Selection
                    Text(
                        text = "Transaction Type",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium
                    )
                    
                    SUPPORTED_TRANSACTION_TYPES.forEach { type ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = selectedTransactionType == type,
                                onClick = { selectedTransactionType = type }
                            )
                            Text(
                                text = type.name,
                                modifier = Modifier.clickable { selectedTransactionType = type }
                            )
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    // Amount Input
                    OutlinedTextField(
                        value = transactionAmount,
                        onValueChange = { amount ->
                            validateAndSetAmount(amount) { validAmount ->
                                transactionAmount = validAmount
                            }
                        },
                        label = { Text("Amount (USD)") },
                        prefix = { Text("$") },
                        modifier = Modifier.fillMaxWidth(),
                        isError = !isValidAmount(transactionAmount)
                    )
                    
                    if (!isValidAmount(transactionAmount)) {
                        Text(
                            text = "Amount must be between $${MIN_TRANSACTION_AMOUNT} and $${MAX_TRANSACTION_AMOUNT}",
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(24.dp))
            
            // Action Buttons Section
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = { 
                        performCardAnalysis { result ->
                            cardAnalysisResult = result
                        }
                    },
                    enabled = !isProcessing,
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Analyze Card")
                }
                
                Button(
                    onClick = { 
                        executeEmvTransaction(
                            selectedTransactionType,
                            transactionAmount
                        ) { result ->
                            transactionResult = result
                            isProcessing = false
                        }
                    },
                    enabled = !isProcessing && isValidAmount(transactionAmount),
                    modifier = Modifier.weight(1f)
                ) {
                    if (isProcessing) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                    }
                    Text(if (isProcessing) "Processing..." else "Process Transaction")
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            // Transaction History Button
            Button(
                onClick = { showTransactionHistory = !showTransactionHistory },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(if (showTransactionHistory) "Hide History" else "Show Transaction History")
            }
            
            Spacer(modifier = Modifier.height(24.dp))
            
            // Results Section
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Display Transaction Result
                item {
                    transactionResult?.let { result ->
                        TransactionResultCard(result)
                    }
                }
                
                // Display Card Analysis Result
                item {
                    cardAnalysisResult?.let { result ->
                        CardAnalysisResultCard(result)
                    }
                }
                
                // Display Transaction History
                if (showTransactionHistory) {
                    items(transactionHistory.values.sortedByDescending { it.timestamp }) { transaction ->
                        TransactionHistoryCard(transaction)
                    }
                }
            }
        }
    }
    
    /**
     * Execute comprehensive EMV transaction with full workflow
     */
    private fun executeEmvTransaction(
        transactionType: EmvTransactionType,
        amountStr: String,
        callback: (EmvTransactionResult) -> Unit
    ) {
        lifecycleScope.launch {
            isProcessing = true
            val operationStart = System.currentTimeMillis()
            
            try {
                auditLogger.logOperation("TRANSACTION_INITIATION", 
                    "Starting EMV transaction: type=$transactionType amount=$amountStr")
                
                val amount = validateTransactionAmount(amountStr)
                val nfcProvider = emvEngine.getNfcProvider()
                
                val transactionResult = cardReader.readCard(
                    nfcProvider = nfcProvider,
                    transactionAmount = (amount * 100).toLong(), // Convert to cents
                    transactionCurrency = DEFAULT_CURRENCY,
                    transactionType = transactionType,
                    additionalOptions = mapOf(
                        "merchant_id" to "DEMO_MERCHANT_001",
                        "terminal_id" to "DEMO_TERMINAL_001",
                        "operation_id" to "EMV_DEMO_${System.currentTimeMillis()}"
                    )
                )
                
                val processingTime = System.currentTimeMillis() - operationStart
                val transactionId = "TXN_${transactionCounter.incrementAndGet()}_${System.currentTimeMillis()}"
                
                when (transactionResult) {
                    is EmvCardReadingResult.Success -> {
                        val successResult = EmvTransactionResult.Success(
                            transactionId = transactionId,
                            cardData = transactionResult.cardData,
                            transactionData = transactionResult.transactionData,
                            processingTime = processingTime,
                            operationsPerformed = transactionResult.operationsPerformed,
                            authenticationType = transactionResult.authenticationType,
                            securityLevel = transactionResult.securityLevel,
                            cardCapabilities = transactionResult.cardCapabilities,
                            terminalVerificationResults = transactionResult.terminalVerificationResults,
                            auditTrail = generateAuditTrail(transactionResult)
                        )
                        
                        // Store transaction record
                        transactionHistory[transactionId] = EmvTransactionRecord(
                            transactionId = transactionId,
                            timestamp = LocalDateTime.now(),
                            transactionType = transactionType,
                            amount = amount,
                            status = "SUCCESS",
                            processingTime = processingTime,
                            cardPan = maskPan(transactionResult.cardData.pan),
                            authenticationMethod = transactionResult.authenticationType.name,
                            securityLevel = transactionResult.securityLevel.name
                        )
                        
                        auditLogger.logOperation("TRANSACTION_SUCCESS", 
                            "EMV transaction completed successfully: id=$transactionId time=${processingTime}ms")
                        
                        callback(successResult)
                    }
                    
                    is EmvCardReadingResult.Failed -> {
                        val failedResult = EmvTransactionResult.Failed(
                            transactionId = transactionId,
                            error = transactionResult.error,
                            operation = transactionResult.operation,
                            cardState = transactionResult.cardState,
                            processingTime = processingTime,
                            partialData = transactionResult.partialData,
                            failureContext = transactionResult.failureContext,
                            recoveryGuidance = generateRecoveryGuidance(transactionResult.error)
                        )
                        
                        transactionHistory[transactionId] = EmvTransactionRecord(
                            transactionId = transactionId,
                            timestamp = LocalDateTime.now(),
                            transactionType = transactionType,
                            amount = amount,
                            status = "FAILED",
                            processingTime = processingTime,
                            cardPan = "****",
                            authenticationMethod = "NONE",
                            securityLevel = "NONE",
                            errorMessage = transactionResult.error.message
                        )
                        
                        auditLogger.logError("TRANSACTION_FAILED", 
                            "EMV transaction failed: id=$transactionId error=${transactionResult.error.message}")
                        
                        callback(failedResult)
                    }
                }
                
            } catch (e: Exception) {
                val processingTime = System.currentTimeMillis() - operationStart
                val transactionId = "TXN_ERR_${System.currentTimeMillis()}"
                
                val errorResult = EmvTransactionResult.Failed(
                    transactionId = transactionId,
                    error = EmvTransactionException("Transaction processing failed: ${e.message}", e),
                    operation = EmvCardOperation.CARD_DETECTION,
                    cardState = EmvCardState.ERROR_STATE,
                    processingTime = processingTime,
                    partialData = EmvPartialCardData(),
                    failureContext = mapOf("exception" to e.javaClass.simpleName),
                    recoveryGuidance = "Check card positioning and retry transaction"
                )
                
                auditLogger.logError("TRANSACTION_EXCEPTION", 
                    "EMV transaction exception: error=${e.message} time=${processingTime}ms")
                
                callback(errorResult)
            }
        }
    }
    
    /**
     * Perform comprehensive card analysis
     */
    private fun performCardAnalysis(callback: (EmvCardAnalysisResult) -> Unit) {
        lifecycleScope.launch {
            val analysisStart = System.currentTimeMillis()
            
            try {
                auditLogger.logOperation("CARD_ANALYSIS_START", "Starting comprehensive card analysis")
                
                val nfcProvider = emvEngine.getNfcProvider()
                val applications = cardReader.readCardApplications(nfcProvider)
                
                val securityAnalysis = securityAnalyzer.performComprehensiveAnalysis(
                    cardData = applications.selectedApplication.aid.toByteArray(),
                    analysisLevel = SecurityAnalysisLevel.COMPREHENSIVE
                )
                
                val analysisTime = System.currentTimeMillis() - analysisStart
                
                val result = EmvCardAnalysisResult.Success(
                    applicationSelectionResult = applications,
                    securityAnalysis = securityAnalysis,
                    analysisTime = analysisTime,
                    cardCapabilities = applications.cardCapabilities,
                    recommendedActions = generateSecurityRecommendations(securityAnalysis)
                )
                
                auditLogger.logOperation("CARD_ANALYSIS_SUCCESS", 
                    "Card analysis completed: time=${analysisTime}ms")
                
                callback(result)
                
            } catch (e: Exception) {
                val analysisTime = System.currentTimeMillis() - analysisStart
                
                val result = EmvCardAnalysisResult.Failed(
                    error = "Card analysis failed: ${e.message}",
                    analysisTime = analysisTime,
                    errorDetails = e.stackTraceToString()
                )
                
                auditLogger.logError("CARD_ANALYSIS_FAILED", 
                    "Card analysis failed: error=${e.message} time=${analysisTime}ms")
                
                callback(result)
            }
        }
    }
    
    @Composable
    fun TransactionResultCard(result: EmvTransactionResult) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = when (result) {
                    is EmvTransactionResult.Success -> MaterialTheme.colorScheme.primaryContainer
                    is EmvTransactionResult.Failed -> MaterialTheme.colorScheme.errorContainer
                }
            )
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                when (result) {
                    is EmvTransactionResult.Success -> {
                        Text(
                            text = "✅ Transaction Successful",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onPrimaryContainer
                        )
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        TransactionDetailRow("Transaction ID", result.transactionId)
                        TransactionDetailRow("Card", maskPan(result.cardData.pan))
                        TransactionDetailRow("Amount", formatAmount(result.transactionData.amount, result.transactionData.currency))
                        TransactionDetailRow("Authentication", result.authenticationType.name)
                        TransactionDetailRow("Security Level", result.securityLevel.name)
                        TransactionDetailRow("Processing Time", "${result.processingTime}ms")
                        TransactionDetailRow("Cardholder", result.cardData.cardholderName.ifEmpty { "Not Available" })
                        TransactionDetailRow("Expiry", result.cardData.expiryDate)
                        TransactionDetailRow("Issuer Country", result.cardData.issuerCountryCode)
                        
                        if (result.cardCapabilities.supportsDDA) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = "🔒 Dynamic Data Authentication Supported",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                        
                        if (result.securityLevel == EmvSecurityLevel.MAXIMUM) {
                            Text(
                                text = "🛡️ Maximum Security Level Achieved",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                    }
                    
                    is EmvTransactionResult.Failed -> {
                        Text(
                            text = "❌ Transaction Failed",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        TransactionDetailRow("Transaction ID", result.transactionId)
                        TransactionDetailRow("Error", result.error.message)
                        TransactionDetailRow("Operation", result.operation.name)
                        TransactionDetailRow("Card State", result.cardState.name)
                        TransactionDetailRow("Processing Time", "${result.processingTime}ms")
                        
                        if (result.recoveryGuidance.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = "💡 Recovery Guidance:",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium
                            )
                            Text(
                                text = result.recoveryGuidance,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onErrorContainer
                            )
                        }
                    }
                }
            }
        }
    }
    
    @Composable
    fun CardAnalysisResultCard(result: EmvCardAnalysisResult) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = when (result) {
                    is EmvCardAnalysisResult.Success -> MaterialTheme.colorScheme.secondaryContainer
                    is EmvCardAnalysisResult.Failed -> MaterialTheme.colorScheme.errorContainer
                }
            )
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                when (result) {
                    is EmvCardAnalysisResult.Success -> {
                        Text(
                            text = "🔍 Card Analysis Complete",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSecondaryContainer
                        )
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        TransactionDetailRow("Application", result.applicationSelectionResult.selectedApplication.label)
                        TransactionDetailRow("AID", result.applicationSelectionResult.selectedApplication.aid)
                        TransactionDetailRow("Analysis Time", "${result.analysisTime}ms")
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        Text(
                            text = "Card Capabilities:",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium
                        )
                        
                        val capabilities = result.cardCapabilities
                        if (capabilities.supportsSDA) Text("• Static Data Authentication")
                        if (capabilities.supportsDDA) Text("• Dynamic Data Authentication")
                        if (capabilities.supportsCDA) Text("• Combined Data Authentication")
                        if (capabilities.supportsContactless) Text("• Contactless Transactions")
                        if (capabilities.supportsOnlineProcessing) Text("• Online Processing")
                        if (capabilities.supportsOfflineProcessing) Text("• Offline Processing")
                        
                        if (result.recommendedActions.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = "Recommendations:",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium
                            )
                            result.recommendedActions.forEach { action ->
                                Text("• $action", style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                    
                    is EmvCardAnalysisResult.Failed -> {
                        Text(
                            text = "❌ Card Analysis Failed",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        Text(
                            text = result.error,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                        
                        TransactionDetailRow("Analysis Time", "${result.analysisTime}ms")
                    }
                }
            }
        }
    }
    
    @Composable
    fun TransactionHistoryCard(transaction: EmvTransactionRecord) {
        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(12.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = transaction.transactionId,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium
                    )
                    Text(
                        text = transaction.status,
                        style = MaterialTheme.typography.bodySmall,
                        color = if (transaction.status == "SUCCESS") 
                            MaterialTheme.colorScheme.primary 
                        else 
                            MaterialTheme.colorScheme.error
                    )
                }
                
                Spacer(modifier = Modifier.height(4.dp))
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "${transaction.transactionType.name} - ${formatAmount(transaction.amount.toLong() * 100, DEFAULT_CURRENCY)}",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Text(
                        text = transaction.timestamp.format(DateTimeFormatter.ofPattern("HH:mm:ss")),
                        style = MaterialTheme.typography.bodySmall
                    )
                }
                
                if (transaction.cardPan != "****") {
                    Text(
                        text = "Card: ${transaction.cardPan}",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
                
                if (transaction.errorMessage.isNotEmpty()) {
                    Text(
                        text = "Error: ${transaction.errorMessage}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
    }
    
    @Composable
    fun TransactionDetailRow(label: String, value: String) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = "$label:",
                style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.Medium
            )
            Text(
                text = value,
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
    
    // Utility Functions
    
    private fun validateTransactionAmount(amountStr: String): Double {
        val amount = amountStr.toDoubleOrNull()
        if (amount == null || amount < MIN_TRANSACTION_AMOUNT || amount > MAX_TRANSACTION_AMOUNT) {
            throw EmvTransactionException("Invalid transaction amount: $amountStr")
        }
        return amount
    }
    
    private fun isValidAmount(amountStr: String): Boolean {
        val amount = amountStr.toDoubleOrNull()
        return amount != null && amount >= MIN_TRANSACTION_AMOUNT && amount <= MAX_TRANSACTION_AMOUNT
    }
    
    private fun validateAndSetAmount(amount: String, callback: (String) -> Unit) {
        // Remove any non-numeric characters except decimal point
        val cleaned = amount.filter { it.isDigit() || it == '.' }
        
        // Ensure only one decimal point
        val parts = cleaned.split('.')
        val validAmount = if (parts.size <= 2) {
            if (parts.size == 2) {
                "${parts[0]}.${parts[1].take(2)}" // Limit to 2 decimal places
            } else {
                parts[0]
            }
        } else {
            parts[0] + "." + parts[1].take(2)
        }
        
        callback(validAmount)
    }
    
    private fun maskPan(pan: String): String {
        return if (pan.length >= 8) {
            "${pan.take(4)}****${pan.takeLast(4)}"
        } else {
            "****"
        }
    }
    
    private fun formatAmount(amountCents: Long, currencyCode: String): String {
        val amount = amountCents / 100.0
        return when (currencyCode) {
            "840" -> "$%.2f".format(amount) // USD
            "978" -> "€%.2f".format(amount) // EUR
            "826" -> "£%.2f".format(amount) // GBP
            else -> "%.2f %s".format(amount, currencyCode)
        }
    }
    
    private fun generateAuditTrail(result: EmvCardReadingResult.Success): List<String> {
        return listOf(
            "Card detected and validated",
            "Application selected: EMV",
            "Authentication completed: ${result.authenticationType}",
            "Security level achieved: ${result.securityLevel}",
            "Transaction processed successfully",
            "Audit trail generated"
        )
    }
    
    private fun generateRecoveryGuidance(error: EmvCardReaderException): String {
        return when (error.javaClass.simpleName) {
            "CardNotPresentException" -> "Position EMV card within 4cm of NFC antenna and retry"
            "CardLostException" -> "Maintain card position throughout transaction and restart"
            "ApduTransmissionException" -> "Check NFC connection quality and retry APDU transmission"
            "AuthenticationException" -> "Verify card authenticity and try different authentication method"
            "TransactionDeclinedException" -> "Check transaction amount, account status, and card validity"
            else -> "Check card positioning, ensure NFC is enabled, and retry transaction"
        }
    }
    
    private fun generateSecurityRecommendations(analysis: SecurityAnalysisResult): List<String> {
        val recommendations = mutableListOf<String>()
        
        if (analysis.rocaVulnerabilityDetected) {
            recommendations.add("Card uses RSA keys vulnerable to ROCA attack")
            recommendations.add("Consider upgrading to newer card with secure cryptographic implementation")
        }
        
        if (analysis.certificateChainValid) {
            recommendations.add("Certificate chain validation successful")
        } else {
            recommendations.add("Certificate chain validation failed - verify issuer certificates")
        }
        
        if (analysis.staticDataAuthenticationResult.isValid) {
            recommendations.add("Static Data Authentication successful")
        }
        
        return recommendations
    }
}

/**
 * EMV Transaction Result sealed class
 */
sealed class EmvTransactionResult {
    data class Success(
        val transactionId: String,
        val cardData: EmvCardData,
        val transactionData: EmvTransactionData,
        val processingTime: Long,
        val operationsPerformed: List<EmvCardOperation>,
        val authenticationType: EmvAuthenticationType,
        val securityLevel: EmvSecurityLevel,
        val cardCapabilities: EmvCardCapabilities,
        val terminalVerificationResults: ByteArray,
        val auditTrail: List<String>
    ) : EmvTransactionResult()
    
    data class Failed(
        val transactionId: String,
        val error: EmvCardReaderException,
        val operation: EmvCardOperation,
        val cardState: EmvCardState,
        val processingTime: Long,
        val partialData: EmvPartialCardData,
        val failureContext: Map<String, Any>,
        val recoveryGuidance: String
    ) : EmvTransactionResult()
}

/**
 * EMV Card Analysis Result sealed class
 */
sealed class EmvCardAnalysisResult {
    data class Success(
        val applicationSelectionResult: EmvApplicationSelectionResult,
        val securityAnalysis: SecurityAnalysisResult,
        val analysisTime: Long,
        val cardCapabilities: EmvCardCapabilities,
        val recommendedActions: List<String>
    ) : EmvCardAnalysisResult()
    
    data class Failed(
        val error: String,
        val analysisTime: Long,
        val errorDetails: String
    ) : EmvCardAnalysisResult()
}

/**
 * EMV Transaction Record for history tracking
 */
data class EmvTransactionRecord(
    val transactionId: String,
    val timestamp: LocalDateTime,
    val transactionType: EmvTransactionType,
    val amount: Double,
    val status: String,
    val processingTime: Long,
    val cardPan: String,
    val authenticationMethod: String,
    val securityLevel: String,
    val errorMessage: String = ""
)

/**
 * Custom theme for EMV demo application
 */
@Composable
fun EmvDemoTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = lightColorScheme(
            primary = androidx.compose.ui.graphics.Color(0xFF1976D2),
            primaryContainer = androidx.compose.ui.graphics.Color(0xFFE3F2FD),
            secondary = androidx.compose.ui.graphics.Color(0xFF388E3C),
            secondaryContainer = androidx.compose.ui.graphics.Color(0xFFE8F5E8),
            error = androidx.compose.ui.graphics.Color(0xFFD32F2F),
            errorContainer = androidx.compose.ui.graphics.Color(0xFFFFEBEE)
        ),
        content = content
    )
}

/**
 * EMV System Initialization Exception
 */
class EmvSystemInitializationException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)

/**
 * EMV Transaction Exception
 */
class EmvTransactionException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)

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
 *     
 *     // UI (Compose)
 *     implementation("androidx.activity:activity-compose:1.8.2")
 *     implementation("androidx.compose.ui:ui:1.5.4")
 *     implementation("androidx.compose.material3:material3:1.1.2")
 *     implementation("androidx.compose.ui:ui-tooling-preview:1.5.4")
 *     implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
 *     implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.7.0")
 * }
 */
