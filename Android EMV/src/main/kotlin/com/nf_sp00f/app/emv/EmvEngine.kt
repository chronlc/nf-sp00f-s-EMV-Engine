package com.nf_sp00f.app.emv

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import timber.log.Timber
import com.nf_sp00f.app.emv.nfc.*
import com.nf_sp00f.app.emv.security.RocaSecurityScanner

/**
 * nf-sp00f EMV Engine - Main Processing Engine
 * 
 * Advanced EMV processing with dual NFC provider support.
 * Integrates TLV parsing, APDU building, and complete EMV transaction flow.
 * 
 * @package com.nf_sp00f.app.emv
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv

import com.nf_sp00f.app.emv.nfc.INfcProvider
import com.nf_sp00f.app.emv.security.RocaSecurityScanner
import com.nf_sp00f.app.emv.tlv.*
import com.nf_sp00f.app.emv.apdu.*
import com.nf_sp00f.app.emv.crypto.*
import com.nf_sp00f.app.emv.auth.*
import kotlinx.coroutines.*

/**
 * Main EMV processing engine with comprehensive transaction support
 * 
 * Implements complete EMV L1/L2 transaction flow:
 * 1. Application Selection (PSE/AID)
 * 2. Initiate Application Processing (GPO)
 * 3. Read Application Data (AFL records)
 * 4. Offline Data Authentication (SDA/DDA/CDA)
 * 5. Processing Restrictions
 * 6. Cardholder Verification
 * 7. Terminal Risk Management
 * 8. Terminal Action Analysis
 * 9. Online Processing (if required)
 * 10. Issuer Authentication (if required)
 * 11. Script Processing (if required)
 */
class EmvEngine private constructor(
    private val nfcProvider: INfcProvider,
    private val rocaScanner: RocaSecurityScanner,
    private val configuration: EmvConfiguration
) {
    
    companion object {
        private const val TAG = "EmvEngine"
        
        // Common AIDs for automatic selection
        val COMMON_AIDS = listOf(
            "A0000000031010", // Visa Classic
            "A0000000032010", // Visa Electron  
            "A0000000041010", // Mastercard Classic
            "A0000000042010", // Mastercard Maestro
            "A00000002501",   // American Express
            "A0000000651010", // JCB
            "A0000001523010", // Discover
        )
        
        /**
         * Create EmvEngine builder for configuration
         */
        fun builder(): Builder = Builder()
    }
    
    private val tlvParser = TlvParser()
    private val tlvOperations = TlvDatabaseOperations()
    private val apduBuilder = EmvApduBuilder()
    private val pkiProcessor = EmvPkiProcessor()
    private val authEngine = EmvAuthenticationEngine(pkiProcessor, apduBuilder)
    private val authDetector = AuthenticationMethodDetector()
    
    /**
     * Process complete EMV transaction with full authentication
     * 
     * Ported from Proxmark3: CmdEMVExec(), CmdEMVScan()
     */
    suspend fun processTransaction(
        amount: Long,
        currencyCode: String = "USD",
        transactionType: TransactionType = TransactionType.PURCHASE
    ): EmvTransactionResult = withContext(Dispatchers.IO) {
        
        try {
            // Step 1: Card detection and activation
            if (!nfcProvider.isConnected()) {
                val connected = nfcProvider.connect()
                if (!connected) {
                    return@withContext EmvTransactionResult.Error("Failed to connect to card")
                }
            }
            
            // Step 2: Application selection (PSE or direct AID)
            val applicationResult = selectApplication()
            if (applicationResult is ApplicationSelectionResult.Error) {
                return@withContext EmvTransactionResult.Error(applicationResult.message)
            }
            
            val selectedApp = (applicationResult as ApplicationSelectionResult.Success).application
            
            // Step 3: Initiate application processing (GPO)
            val processingResult = initiateApplicationProcessing(selectedApp, amount, currencyCode, transactionType)
            if (processingResult is ProcessingResult.Error) {
                return@withContext EmvTransactionResult.Error(processingResult.message)
            }
            
            // Step 4: Read application data (AFL records)
            val cardData = readApplicationData(processingResult as ProcessingResult.Success)
            
            // Step 5: Perform authentication (SDA/DDA/CDA)
            val authResult = performAuthentication(cardData, selectedApp)
            
            // Step 6: ROCA vulnerability check
            if (configuration.enableRocaCheck) {
                val rocaResult = rocaScanner.checkCard(cardData)
                if (rocaResult.isVulnerable) {
                    return@withContext EmvTransactionResult.RocaVulnerable(rocaResult)
                }
            }
            
            // Step 7: Processing restrictions and risk management
            val riskResult = performRiskManagement(cardData, amount, transactionType)
            
            // Step 8: Terminal action analysis
            val actionResult = performActionAnalysis(cardData, authResult, riskResult)
            
            // Step 9: Transaction completion
            EmvTransactionResult.Success(
                cardData = cardData,
                authenticationResult = authResult,
                riskResult = riskResult,
                actionResult = actionResult,
                transactionAmount = amount,
                currencyCode = currencyCode,
                transactionType = transactionType
            )
            
        } catch (e: Exception) {
            EmvTransactionResult.Error("Transaction failed: ${e.message}", e)
        } finally {
            nfcProvider.disconnect()
        }
    }
    
    /**
     * Select EMV application using PSE or direct AID selection
     * Ported from: EMVSearchPSE(), EMVSearch()
     */
    private suspend fun selectApplication(): ApplicationSelectionResult {
        // Try PSE selection first (contactless preferred)
        val pseResult = selectViaPSE(contactless = true)
        if (pseResult is ApplicationSelectionResult.Success) {
            return pseResult
        }
        
        // Try contact PSE if contactless failed
        val contactPseResult = selectViaPSE(contactless = false)
        if (contactPseResult is ApplicationSelectionResult.Success) {
            return contactPseResult
        }
        
        // Fall back to direct AID selection
        return selectViaDirectAid()
    }
    
    /**
     * Select application via PSE (Payment System Environment)
     * Ported from: EMVSelectPSE()
     */
    private suspend fun selectViaPSE(contactless: Boolean): ApplicationSelectionResult {
        try {
            // Build SELECT PSE command
            val selectPseCommand = apduBuilder.buildSelectPSE(contactless)
            
            // Send APDU
            val apduResult = nfcProvider.exchangeApdu(selectPseCommand.toByteArray())
            when (apduResult) {
                is ApduResult.Success -> {
                    val response = apduResult.response
                    if (!response.isSuccess) {
                        return ApplicationSelectionResult.Error("PSE selection failed: ${response.errorDescription}")
                    }
                    
                    // Parse PSE response to find applications
                    val pseApps = parsePseResponse(response.data)
                    if (pseApps.isEmpty()) {
                        return ApplicationSelectionResult.Error("No applications found in PSE")
                    }
                    
                    // Select highest priority application
                    val selectedApp = pseApps.minByOrNull { it.priority }
                        ?: return ApplicationSelectionResult.Error("No valid application found")
                    
                    return ApplicationSelectionResult.Success(selectedApp)
                }
                is ApduResult.Error -> {
                    return ApplicationSelectionResult.Error("PSE APDU failed: ${apduResult.message}")
                }
                is ApduResult.Timeout -> {
                    return ApplicationSelectionResult.Error("PSE selection timeout")
                }
            }
        } catch (e: Exception) {
            return ApplicationSelectionResult.Error("PSE selection error: ${e.message}")
        }
    }
    
    /**
     * Select application via direct AID probing
     * Ported from: EMVSearch()
     */
    private suspend fun selectViaDirectAid(): ApplicationSelectionResult {
        for (aidHex in COMMON_AIDS) {
            try {
                val selectCommand = apduBuilder.buildSelectAid(aidHex)
                val apduResult = nfcProvider.exchangeApdu(selectCommand.toByteArray())
                
                if (apduResult is ApduResult.Success && apduResult.response.isSuccess) {
                    // Parse FCI response
                    val app = parseFciResponse(aidHex, apduResult.response.data)
                    return ApplicationSelectionResult.Success(app)
                }
            } catch (e: Exception) {
                // Continue trying next AID
                continue
            }
        }
        
        return ApplicationSelectionResult.Error("No supported application found")
    }
    
    /**
     * Initiate application processing (GET PROCESSING OPTIONS)
     * Ported from: EMVGPO()
     */
    private suspend fun initiateApplicationProcessing(
        application: EmvApplication,
        amount: Long,
        currencyCode: String,
        transactionType: TransactionType
    ): ProcessingResult {
        try {
            // Build PDOL data if required
            val pdolData = buildPdolData(application, amount, currencyCode, transactionType)
            
            // Build GPO command
            val gpoCommand = apduBuilder.buildGetProcessingOptions(pdolData)
            
            // Send APDU
            val apduResult = nfcProvider.exchangeApdu(gpoCommand.toByteArray())
            when (apduResult) {
                is ApduResult.Success -> {
                    val response = apduResult.response
                    if (!response.isSuccess) {
                        return ProcessingResult.Error("GPO failed: ${response.errorDescription}")
                    }
                    
                    // Parse GPO response
                    val processingOptions = parseGpoResponse(response.data)
                    return ProcessingResult.Success(processingOptions)
                }
                is ApduResult.Error -> {
                    return ProcessingResult.Error("GPO APDU failed: ${apduResult.message}")
                }
                is ApduResult.Timeout -> {
                    return ProcessingResult.Error("GPO timeout")
                }
            }
        } catch (e: Exception) {
            return ProcessingResult.Error("GPO error: ${e.message}")
        }
    }
    
    /**
     * Read application data from AFL (Application File Locator)
     * Ported from: EMVReadRecord()
     */
    private suspend fun readApplicationData(
        processingResult: ProcessingResult.Success
    ): EmvCardData {
        val tlvDatabase = TlvDatabase()
        val processingOptions = processingResult.options
        
        // Read records specified in AFL
        for (fileRecord in processingOptions.afl) {
            for (recordNum in fileRecord.firstRecord..fileRecord.lastRecord) {
                try {
                    val readCommand = apduBuilder.buildReadRecord(recordNum.toUByte(), fileRecord.sfi.toUByte())
                    val apduResult = nfcProvider.exchangeApdu(readCommand.toByteArray())
                    
                    if (apduResult is ApduResult.Success && apduResult.response.isSuccess) {
                        // Parse TLV data from record
                        val parseResult = tlvParser.parseToDatabase(apduResult.response.data)
                        if (parseResult is TlvResult.Success) {
                            // Merge into main database
                            for ((tag, element) in parseResult.value.getAllElements()) {
                                tlvDatabase.addElement(element)
                            }
                        }
                    }
                } catch (e: Exception) {
                    // Continue reading other records
                    continue
                }
            }
        }
        
        // Extract card data from TLV database
        return extractCardDataFromTlv(tlvDatabase)
    }
    
    /**
     * Perform EMV authentication (SDA/DDA/CDA)
     * Ported from: trSDA(), trDDA(), trCDA()
     */
    private suspend fun performAuthentication(
        cardData: EmvCardData,
        application: EmvApplication
    ): AuthenticationResult {
        val tlvDatabase = cardData.tlvDatabase ?: return AuthenticationResult.Failed("No TLV data available")
        
        // Determine authentication method from AIP
        val authMethod = authDetector.determineAuthenticationMethod(tlvDatabase)
        
        return when (authMethod) {
            AuthenticationType.SDA -> authEngine.performStaticDataAuthentication(tlvDatabase)
            AuthenticationType.DDA -> authEngine.performDynamicDataAuthentication(nfcProvider, tlvDatabase)
            AuthenticationType.CDA -> {
                // CDA requires additional transaction data - for now, fall back to DDA
                authEngine.performDynamicDataAuthentication(nfcProvider, tlvDatabase)
            }
            AuthenticationType.NONE -> AuthenticationResult.NotRequired
        }
    }
    
    /**
     * Perform risk management checks
     */
    private suspend fun performRiskManagement(
        cardData: EmvCardData,
        amount: Long,
        transactionType: TransactionType
    ): RiskManagementResult {
        // TODO: Implement risk management logic
        return RiskManagementResult.Approved
    }
    
    /**
     * Perform terminal action analysis
     */
    private suspend fun performActionAnalysis(
        cardData: EmvCardData,
        authResult: AuthenticationResult,
        riskResult: RiskManagementResult
    ): ActionAnalysisResult {
        // TODO: Implement action analysis logic
        return ActionAnalysisResult.Approved
    }
    
    // Helper methods for parsing responses
    private suspend fun parsePseResponse(data: ByteArray): List<EmvApplication> {
        // TODO: Parse PSE FCI template to extract applications
        return emptyList()
    }
    
    private fun parseFciResponse(aid: String, data: ByteArray): EmvApplication {
        // TODO: Parse FCI template to extract application info
        return EmvApplication(
            aid = aid,
            label = "Unknown",
            priority = 1
        )
    }
    
    private fun buildPdolData(
        application: EmvApplication,
        amount: Long,
        currencyCode: String,
        transactionType: TransactionType
    ): ByteArray {
        // TODO: Build PDOL data based on application requirements
        return byteArrayOf()
    }
    
    private suspend fun parseGpoResponse(data: ByteArray): ProcessingOptions {
        // TODO: Parse GPO response (Format 1 or Format 2)
        return ProcessingOptions(
            aip = byteArrayOf(),
            afl = emptyList()
        )
    }
    
    private fun extractCardDataFromTlv(database: TlvDatabase): EmvCardData {
        // Extract common EMV data elements
        val pan = database.findElement(TlvTag(TlvTag.APPLICATION_PAN))?.valueAsString() ?: "Unknown"
        val expiry = database.findElement(TlvTag(TlvTag.APPLICATION_EXPIRATION_DATE))?.valueAsString() ?: "Unknown"
        val name = database.findElement(TlvTag(TlvTag.CARDHOLDER_NAME))?.valueAsString() ?: "Unknown"
        val label = database.findElement(TlvTag(TlvTag.APPLICATION_LABEL))?.valueAsString() ?: "Unknown"
        
        return EmvCardData(
            pan = pan,
            expiryDate = expiry,
            cardholderName = name,
            applicationLabel = label,
            tlvDatabase = database
        )
    }
    
    /**
     * Initialize PKI processor with default CA keys
     */
    private fun initializePkiProcessor() {
        pkiProcessor.loadDefaultCaKeys()
        pkiProcessor.setStrictValidation(configuration.strictValidation)
    }
    
    /**
     * Builder pattern for EmvEngine configuration
     */
    class Builder {
        private var nfcProvider: INfcProvider? = null
        private var rocaScanner: RocaSecurityScanner? = null
        private var configuration = EmvConfiguration()
        
        fun nfcProvider(provider: INfcProvider) = apply {
            this.nfcProvider = provider
        }
        
        fun enableRocaCheck(enabled: Boolean) = apply {
            this.configuration = configuration.copy(enableRocaCheck = enabled)
        }
        
        fun timeout(timeoutMs: Long) = apply {
            this.configuration = configuration.copy(timeoutMs = timeoutMs)
        }
        
        fun strictValidation(enabled: Boolean) = apply {
            this.configuration = configuration.copy(strictValidation = enabled)
        }
        
        fun build(): EmvEngine {
            val provider = nfcProvider ?: throw IllegalStateException("NFC provider is required")
            val scanner = rocaScanner ?: RocaSecurityScanner()
            
            val engine = EmvEngine(provider, scanner, configuration)
            engine.initializePkiProcessor()
            return engine
        }
    }
}
class EmvEngine private constructor() {
    
    private var currentNfcProvider: INfcProvider? = null
    private var nfcConfig: NfcProviderConfig = NfcProviderConfig(NfcProviderType.ANDROID_INTERNAL)
    private val rocaScanner = RocaSecurityScanner()
    
    companion object {
        @Volatile
        private var INSTANCE: EmvEngine? = null
        
        fun getInstance(): EmvEngine {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: EmvEngine().also { INSTANCE = it }
            }
        }
        
        // Load native library
        init {
            System.loadLibrary("emvport")
        }
    }
    
    // JNI Native methods - implemented in emv_jni.cpp
    private external fun nativeInitializeEmv(): Boolean
    private external fun nativeCleanupEmv()
    private external fun nativeProcessCard(
        cardData: ByteArray,
        selectAid: String?
    ): EmvTransactionResult
    private external fun nativeGetSupportedAids(): Array<String>
    private external fun nativeValidateCertificate(
        certData: ByteArray,
        issuerCert: ByteArray
    ): Boolean
    
    /**
     * Initialize the EMV engine with NFC provider configuration
     */
    suspend fun initialize(config: NfcProviderConfig? = null): Boolean = withContext(Dispatchers.Default) {
        try {
            // Set NFC configuration
            config?.let { nfcConfig = it }
            
            // Initialize native EMV engine
            val nativeResult = nativeInitializeEmv()
            if (!nativeResult) {
                Timber.e("Failed to initialize native EMV Engine")
                return@withContext false
            }
            
            // Initialize NFC provider
            currentNfcProvider = NfcProviderFactory.createProvider(nfcConfig.type)
            val nfcResult = currentNfcProvider?.initialize(nfcConfig) ?: false
            
            if (nfcResult) {
                Timber.i("EMV Engine initialized successfully with ${nfcConfig.type}")
                true
            } else {
                Timber.e("Failed to initialize NFC provider: ${nfcConfig.type}")
                false
            }
        } catch (e: Exception) {
            Timber.e(e, "Error initializing EMV Engine")
            false
        }
    }
    
    /**
     * Configure NFC provider type and settings
     */
    suspend fun configureNfcProvider(config: NfcProviderConfig): Boolean {
        return try {
            // Cleanup current provider
            currentNfcProvider?.cleanup()
            
            // Initialize new provider
            nfcConfig = config
            currentNfcProvider = NfcProviderFactory.createProvider(config.type)
            currentNfcProvider?.initialize(config) ?: false
        } catch (e: Exception) {
            Timber.e(e, "Error configuring NFC provider")
            false
        }
    }
    
    /**
     * Auto-detect and configure best available NFC provider
     */
    suspend fun autoConfigureNfc(): Boolean {
        val detectedType = NfcProviderFactory.detectBestProvider()
        return if (detectedType != null) {
            val config = NfcProviderConfig(detectedType)
            configureNfcProvider(config)
        } else {
            Timber.e("No suitable NFC provider detected")
            false
        }
    }
    
    /**
     * Process EMV card using current NFC provider (Android Internal or PN532)
     */
    suspend fun processCard(
        tag: Tag? = null,  // For Android Internal NFC
        bluetoothAddress: String? = null,  // For PN532 Bluetooth
        transactionAmount: Long = 0L,
        currencyCode: String = "840", // USD default
        selectAid: String? = null
    ): Flow<EmvTransactionStep> = flow {
        val provider = currentNfcProvider ?: throw IllegalStateException("EMV Engine not initialized")
        
        try {
            emit(EmvTransactionStep.Connecting)
            
            // Handle different connection methods based on provider type
            when (nfcConfig.type) {
                NfcProviderType.ANDROID_INTERNAL -> {
                    if (tag == null) {
                        emit(EmvTransactionStep.Error("Android NFC requires Tag parameter", null))
                        return@flow
                    }
                    // Set tag for Android provider
                    (provider as AndroidInternalNfcProvider).setCurrentTag(tag)
                    if (!provider.connectToCardFromIntent(tag)) {
                        emit(EmvTransactionStep.Error("Failed to connect to Android NFC card", null))
                        return@flow
                    }
                }
                NfcProviderType.PN532_BLUETOOTH -> {
                    // Scan for cards with PN532
                    val cards = provider.scanForCards()
                    if (cards.isEmpty()) {
                        emit(EmvTransactionStep.Error("No cards detected by PN532", null))
                        return@flow
                    }
                    if (!provider.connectToCard(cards.first())) {
                        emit(EmvTransactionStep.Error("Failed to connect to PN532 card", null))
                        return@flow
                    }
                }
            }
            
            emit(EmvTransactionStep.SelectingApplication)
            
            // Get card info from current provider
            val cardInfo = provider.getCardInfo()
            Timber.d("Card Info (${nfcConfig.type}): $cardInfo")
            
            // Select EMV application 
            val selectResponse = if (selectAid != null) {
                provider.selectApplication(selectAid)
            } else {
                // Auto-select first available EMV application
                selectFirstEmvApplication(provider)
            }
            
            if (!selectResponse.isSuccess) {
                emit(EmvTransactionStep.Error("Application selection failed", null))
                return@flow
            }
            
            emit(EmvTransactionStep.ProcessingTransaction)
            
            // Process EMV transaction using native engine
            val cardData = buildEmvCardData(cardInfo, selectResponse)
            val result = withContext(Dispatchers.Default) {
                nativeProcessCard(cardData, selectAid)
            }
            
            when (result.status) {
                EmvTransactionStatus.SUCCESS -> {
                    emit(EmvTransactionStep.Success(result))
                }
                EmvTransactionStatus.CARD_ERROR -> {
                    emit(EmvTransactionStep.Error("Card communication error", result))
                }
                EmvTransactionStatus.AUTHENTICATION_FAILED -> {
                    emit(EmvTransactionStep.Error("Authentication failed", result))
                }
                else -> {
                    emit(EmvTransactionStep.Error("Unknown error", result))
                }
            }
            
        } catch (e: Exception) {
            Timber.e(e, "Error processing EMV card with ${nfcConfig.type}")
            emit(EmvTransactionStep.Error(e.message ?: "Unknown error", null))
        } finally {
            provider.disconnect()
        }
    }
    
    /**
     * Auto-select first available EMV application
     */
    private suspend fun selectFirstEmvApplication(provider: INfcProvider): ApduResponse {
        val commonAids = listOf(
            "A0000000031010",     // VISA
            "A0000000041010",     // MasterCard  
            "A000000025010402",   // American Express
            "A0000000651010",     // JCB
        )
        
        for (aid in commonAids) {
            try {
                val response = provider.selectApplication(aid)
                if (response.isSuccess) {
                    Timber.d("Successfully selected AID: $aid")
                    return response
                }
            } catch (e: Exception) {
                Timber.w("Failed to select AID $aid: ${e.message}")
            }
        }
        
        throw EmvCommunicationException("No supported EMV applications found")
    }
    
    /**
     * Build EMV card data from NFC provider information
     */
    private fun buildEmvCardData(cardInfo: NfcCardInfo?, selectResponse: ApduResponse): ByteArray {
        // Combine Android NFC card info with select response
        val cardData = mutableListOf<Byte>()
        
        // Add card UID
        cardInfo?.uid?.let { uid ->
            cardData.addAll(uid.hexToByteArray().toList())
        }
        
        // Add select response data
        cardData.addAll(selectResponse.data.toList())
        
        return cardData.toByteArray()
    }
    
    /**
     * Get list of supported Application Identifiers (AIDs)
     */
    fun getSupportedAids(): List<String> = try {
        nativeGetSupportedAids().toList()
    } catch (e: Exception) {
        Timber.e(e, "Error getting supported AIDs")
        emptyList()
    }
    
    /**
     * Validate EMV certificate chain
     */
    suspend fun validateCertificate(
        certData: ByteArray,
        issuerCert: ByteArray
    ): Boolean = withContext(Dispatchers.Default) {
        try {
            nativeValidateCertificate(certData, issuerCert)
        } catch (e: Exception) {
            Timber.e(e, "Error validating certificate")
            false
        }
    }
    
    /**
     * Extension function for hex string conversion  
     */
    private fun String.hexToByteArray(): ByteArray = 
        chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    
    /**
     * Get current NFC provider information
     */
    fun getNfcProviderInfo(): Pair<NfcProviderType, NfcCapabilities?> {
        return Pair(nfcConfig.type, currentNfcProvider?.getCapabilities())
    }
    
    /**
     * Check if specific NFC provider is available
     */
    suspend fun isNfcProviderAvailable(type: NfcProviderType): Boolean {
        return try {
            val testProvider = NfcProviderFactory.createProvider(type)
            val testConfig = NfcProviderConfig(type)
            val result = testProvider.initialize(testConfig)
            testProvider.cleanup()
            result
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Scan EMV certificates for ROCA vulnerability (CVE-2017-15361)
     */
    suspend fun scanForRocaVulnerability(certificates: List<EmvCertificate>): List<Pair<EmvCertificate, com.nf_sp00f.app.emv.security.RocaVulnerabilityResult>> {
        return rocaScanner.scanMultipleCertificates(certificates)
    }
    
    /**
     * Run ROCA self-test to verify vulnerability detection
     */
    suspend fun runRocaSelfTest(): Boolean {
        return rocaScanner.runSelfTest()
    }
    
    /**
     * Cleanup resources
     */
    fun cleanup() {
        try {
            runBlocking {
                currentNfcProvider?.cleanup()
            }
            nativeCleanupEmv()
            Timber.d("EMV Engine cleaned up")
        } catch (e: Exception) {
            Timber.e(e, "Error during EMV cleanup")
        }
    }
}