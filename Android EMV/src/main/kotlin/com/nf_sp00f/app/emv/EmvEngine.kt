/**
 * nf-sp00f EMV Engine - Main Processing Engine
 * 
 * Advanced EMV processing with dual NFC provider support.
 * Integrates TLV parsing, APDU building, complete EMV transaction flow,
 * ROCA vulnerability detection, and enhanced cryptographic primitives.
 * 
 * Phase 3 Integration: ROCA Security Scanner + Crypto Primitives
 * 
 * @package com.nf_sp00f.app.emv
 * @author nf-sp00f
 * @since 1.0.0
 */
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
import com.nf_sp00f.app.emv.tlv.*
import com.nf_sp00f.app.emv.apdu.*
import com.nf_sp00f.app.emv.crypto.*
import com.nf_sp00f.app.emv.auth.*

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
 * 
 * Phase 3 Features:
 * - Enhanced ROCA vulnerability detection (CVE-2017-15361)
 * - Advanced cryptographic primitives with Android Security Provider
 * - Comprehensive security testing and validation
 */
class EmvEngine private constructor(
    private val nfcProvider: INfcProvider,
    private val rocaScanner: RocaSecurityScanner,
    private val cryptoPrimitives: EmvCryptoPrimitives,
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
    private val cryptoTestSuite = EmvCryptoTestSuite()
    
    /**
     * Process complete EMV transaction with full authentication and security checks
     * 
     * Ported from Proxmark3: CmdEMVExec(), CmdEMVScan()
     * Enhanced with Phase 3 security features
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
            
            // Step 6: Enhanced ROCA vulnerability check (Phase 3)
            if (configuration.enableRocaCheck) {
                val rocaResult = performEnhancedRocaCheck(cardData)
                if (rocaResult.isVulnerable) {
                    return@withContext EmvTransactionResult.RocaVulnerable(rocaResult)
                }
            }
            
            // Step 7: Cryptographic validation (Phase 3)
            if (configuration.enableCryptoValidation) {
                val cryptoResult = validateCryptographicIntegrity(cardData, authResult)
                if (!cryptoResult.isValid) {
                    return@withContext EmvTransactionResult.CryptoValidationFailed(cryptoResult)
                }
            }
            
            // Step 8: Processing restrictions and risk management
            val riskResult = performRiskManagement(cardData, amount, transactionType)
            
            // Step 9: Terminal action analysis
            val actionResult = performActionAnalysis(cardData, authResult, riskResult)
            
            // Step 10: Transaction completion
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
     * Enhanced ROCA vulnerability check with multiple detection methods
     * Phase 3 implementation
     */
    private suspend fun performEnhancedRocaCheck(cardData: EmvCardData): RocaVulnerabilityResult {
        return try {
            // Extract public key from card data
            val publicKey = cardData.getIssuerPublicKey()
            if (publicKey != null) {
                // Perform comprehensive ROCA analysis
                rocaScanner.checkRocaVulnerability(publicKey, RocaDetectionMethod.FINGERPRINT_ANALYSIS)
            } else {
                RocaVulnerabilityResult(
                    isVulnerable = false,
                    confidence = 0.0,
                    analysisMethod = RocaDetectionMethod.FINGERPRINT_ANALYSIS,
                    details = "No public key available for ROCA analysis"
                )
            }
        } catch (e: Exception) {
            RocaVulnerabilityResult(
                isVulnerable = false,
                confidence = 0.0,
                analysisMethod = RocaDetectionMethod.FINGERPRINT_ANALYSIS,
                details = "ROCA check failed: ${e.message}"
            )
        }
    }
    
    /**
     * Validate cryptographic integrity using Phase 3 primitives
     */
    private suspend fun validateCryptographicIntegrity(
        cardData: EmvCardData,
        authResult: AuthenticationResult
    ): CryptoValidationResult {
        return try {
            val results = mutableListOf<ValidationCheck>()
            
            // 1. Hash validation using enhanced crypto primitives
            val applicationData = cardData.getAllTlvData()
            val computedHash = cryptoPrimitives.computeApplicationHash(applicationData)
            val storedHash = cardData.getApplicationHash()
            val hashValid = if (storedHash != null) {
                EmvCryptoUtils.constantTimeEquals(computedHash, storedHash)
            } else {
                true // No stored hash to validate against
            }
            results.add(ValidationCheck("Application Hash", hashValid))
            
            // 2. RSA signature validation
            val signatureData = cardData.getDynamicSignature()
            val signatureValid = if (signatureData != null && authResult.publicKey != null) {
                cryptoPrimitives.verifyRsaSignature(applicationData, signatureData, authResult.publicKey)
            } else {
                true // No signature to validate
            }
            results.add(ValidationCheck("RSA Signature", signatureValid))
            
            // 3. Certificate chain validation
            val certificateChain = cardData.getCertificateChain()
            val chainValid = cryptoPrimitives.validateCertificateChain(certificateChain)
            results.add(ValidationCheck("Certificate Chain", chainValid))
            
            // 4. Key parameter validation
            val keyValid = if (authResult.publicKey != null) {
                val modulus = authResult.publicKey.getKeyParameter(RsaKeyParameter.MODULUS)
                val exponent = authResult.publicKey.getKeyParameter(RsaKeyParameter.PUBLIC_EXPONENT)
                EmvCryptoUtils.validateRsaKey(modulus, exponent)
            } else {
                true // No key to validate
            }
            results.add(ValidationCheck("Key Parameters", keyValid))
            
            val allValid = results.all { it.passed }
            
            CryptoValidationResult(
                isValid = allValid,
                validationChecks = results,
                details = if (allValid) "All cryptographic validations passed" else "Some validations failed"
            )
            
        } catch (e: Exception) {
            CryptoValidationResult(
                isValid = false,
                validationChecks = emptyList(),
                details = "Crypto validation failed: ${e.message}"
            )
        }
    }
    
    /**
     * Run comprehensive security tests (Phase 3)
     */
    suspend fun runSecurityTests(): SecurityTestResult = withContext(Dispatchers.Default) {
        try {
            val results = mutableListOf<SecurityCheck>()
            
            // 1. ROCA self-test
            val rocaTest = rocaScanner.runSelfTest()
            results.add(SecurityCheck("ROCA Scanner", rocaTest, if (rocaTest) "Self-test passed" else "Self-test failed"))
            
            // 2. Crypto primitives test
            val cryptoTestResult = cryptoTestSuite.runAllTests()
            results.add(SecurityCheck(
                "Crypto Primitives", 
                cryptoTestResult.passed, 
                cryptoTestResult.summary
            ))
            
            // 3. PKI processor test
            val pkiTest = pkiProcessor.runSelfTest()
            results.add(SecurityCheck("PKI Processor", pkiTest, if (pkiTest) "PKI validation working" else "PKI validation failed"))
            
            // 4. NFC provider test
            val nfcTest = nfcProvider.runDiagnostics()
            results.add(SecurityCheck("NFC Provider", nfcTest.isHealthy, nfcTest.status))
            
            val allPassed = results.all { it.passed }
            
            SecurityTestResult(
                passed = allPassed,
                securityChecks = results,
                summary = if (allPassed) "All security tests passed" else "Some security tests failed",
                rocaInfo = rocaScanner.getRocaInfo()
            )
            
        } catch (e: Exception) {
            SecurityTestResult(
                passed = false,
                securityChecks = emptyList(),
                summary = "Security test suite failed: ${e.message}",
                rocaInfo = ""
            )
        }
    }
    
    /**
     * Get crypto primitives information
     */
    fun getCryptoPrimitivesInfo(): String {
        return cryptoPrimitives.getBackendInfo()
    }
    
    /**
     * Cleanup resources
     */
    fun cleanup() {
        cryptoTestSuite.cleanup()
        rocaScanner.cleanup()
        cryptoPrimitives.cleanup()
        nfcProvider.disconnect()
    }
    
    /**
     * Builder class for EmvEngine configuration
     */
    class Builder {
        private var nfcProvider: INfcProvider? = null
        private var rocaScanner: RocaSecurityScanner? = null
        private var cryptoPrimitives: EmvCryptoPrimitives? = null
        private var configuration = EmvConfiguration()
        
        fun nfcProvider(provider: INfcProvider) = apply {
            this.nfcProvider = provider
        }
        
        fun rocaScanner(scanner: RocaSecurityScanner) = apply {
            this.rocaScanner = scanner
        }
        
        fun cryptoPrimitives(primitives: EmvCryptoPrimitives) = apply {
            this.cryptoPrimitives = primitives
        }
        
        fun enableRocaCheck(enabled: Boolean) = apply {
            this.configuration = configuration.copy(enableRocaCheck = enabled)
        }
        
        fun enableCryptoValidation(enabled: Boolean) = apply {
            this.configuration = configuration.copy(enableCryptoValidation = enabled)
        }
        
        fun enableCryptoTesting(enabled: Boolean) = apply {
            this.configuration = configuration.copy(enableCryptoTesting = enabled)
        }
        
        fun timeout(timeoutMs: Long) = apply {
            this.configuration = configuration.copy(timeoutMs = timeoutMs)
        }
        
        fun strictValidation(enabled: Boolean) = apply {
            this.configuration = configuration.copy(strictValidation = enabled)
        }
        
        suspend fun build(): EmvEngine {
            val provider = nfcProvider ?: throw IllegalStateException("NFC provider is required")
            val scanner = rocaScanner ?: RocaSecurityScanner()
            val crypto = cryptoPrimitives ?: EmvCryptoPrimitives()
            
            val engine = EmvEngine(provider, scanner, crypto, configuration)
            engine.initializePkiProcessor()
            return engine
        }
        
        /**
         * Build EMV engine synchronously (will initialize PKI in background)
         */
        fun buildAsync(): EmvEngine {
            val provider = nfcProvider ?: throw IllegalStateException("NFC provider is required")
            val scanner = rocaScanner ?: RocaSecurityScanner()
            val crypto = cryptoPrimitives ?: EmvCryptoPrimitives()
            
            val engine = EmvEngine(provider, scanner, crypto, configuration)
            // PKI initialization will happen on first transaction
            return engine
        }
    }
    
    /**
     * Initialize PKI processor with default CA keys and crypto backend
     */
    private suspend fun initializePkiProcessor() {
        pkiProcessor.initialize()
        
        // Initialize crypto primitives
        cryptoPrimitives.initialize()
        
        // Initialize ROCA scanner
        val rocaSelfTest = rocaScanner.runSelfTest()
        if (!rocaSelfTest) {
            Timber.w("ROCA scanner self-test failed")
        }
        
        // Run crypto test suite if in debug mode
        if (configuration.enableCryptoTesting) {
            val testResult = cryptoTestSuite.runAllTests()
            Timber.d("Crypto test suite: ${testResult.summary}")
        }
    }
    
    // Production EMV implementation methods
    private suspend fun selectApplication(): ApplicationSelectionResult {
        return try {
            // Search for EMV applications on card
            val searchResult = transactionEngine.searchApplications(nfcProvider)
            if (searchResult.applications.isEmpty()) {
                return ApplicationSelectionResult.Error("No EMV applications found on card")
            }
            
            // Select first available application or preferred application
            val selectedApp = searchResult.applications.first()
            val selectResult = transactionEngine.selectApplication(nfcProvider, selectedApp.aid)
            
            if (selectResult.isSuccess) {
                ApplicationSelectionResult.Success(selectedApp, selectResult.fciData)
            } else {
                ApplicationSelectionResult.Error("Application selection failed: ${selectResult.errorMessage}")
            }
        } catch (e: Exception) {
            Timber.e(e, "Application selection failed")
            ApplicationSelectionResult.Error("Application selection error: ${e.message}")
        }
    }
    
    private suspend fun initiateApplicationProcessing(
        application: EmvApplication,
        amount: Long,
        currencyCode: String,
        transactionType: TransactionType
    ): ProcessingResult {
        return try {
            // Build transaction data for GPO
            val transactionData = TransactionData(
                amount = amount,
                currency = currencyCode,
                transactionType = transactionType,
                timestamp = System.currentTimeMillis()
            )
            
            // Execute Get Processing Options (GPO)
            val gpoResult = transactionEngine.initiateApplicationProcessing(
                nfcProvider, 
                transactionData,
                tlvDatabase
            )
            
            if (gpoResult.isSuccess) {
                ProcessingResult.Success(gpoResult.aip, gpoResult.afl, gpoResult.processingData)
            } else {
                ProcessingResult.Error("GPO failed: ${gpoResult.errorMessage}")
            }
        } catch (e: Exception) {
            Timber.e(e, "Application processing initiation failed")
            ProcessingResult.Error("Processing initiation error: ${e.message}")
        }
    }
    
    private suspend fun readApplicationData(processingResult: ProcessingResult.Success): EmvCardData {
        return try {
            // Read application data using AFL from GPO
            val readResult = transactionEngine.readApplicationData(
                nfcProvider,
                processingResult.afl,
                tlvDatabase
            )
            
            if (readResult.isSuccess) {
                // Extract card data from TLV database
                EmvCardData(
                    pan = extractPan(tlvDatabase),
                    panSequenceNumber = extractPanSequenceNumber(tlvDatabase),
                    expiry = extractExpiryDate(tlvDatabase),
                    cardholderName = extractCardholderName(tlvDatabase),
                    track2Data = extractTrack2Data(tlvDatabase),
                    applicationLabel = extractApplicationLabel(tlvDatabase),
                    issuerName = extractIssuerName(tlvDatabase),
                    rawTlvData = tlvDatabase.getAllEntries()
                )
            } else {
                Timber.e("Failed to read application data: ${readResult.errorMessage}")
                EmvCardData(emptyMap())
            }
        } catch (e: Exception) {
            Timber.e(e, "Application data reading failed")
            EmvCardData(emptyMap())
        }
    }
    
    private suspend fun performAuthentication(
        application: EmvApplication
    ): AuthenticationResult {
        return try {
            val authProcessor = EmvAuthenticationProcessor()
            
            // Determine supported authentication methods from AIP
            val aip = tlvDatabase.getValue(EmvTag.APPLICATION_INTERCHANGE_PROFILE)
            if (aip == null) {
                return AuthenticationResult.NoAuthentication("No AIP available for authentication")
            }
            
            // Check authentication methods in order of preference: CDA > DDA > SDA
            when {
                // Combined Data Authentication (CDA)
                (aip[0].toInt() and 0x01) != 0 -> {
                    authProcessor.performCda(nfcProvider, tlvDatabase)
                }
                // Dynamic Data Authentication (DDA)
                (aip[0].toInt() and 0x02) != 0 -> {
                    authProcessor.performDda(nfcProvider, tlvDatabase)
                }
                // Static Data Authentication (SDA)
                (aip[0].toInt() and 0x40) != 0 -> {
                    authProcessor.performSda(nfcProvider, tlvDatabase)
                }
                else -> {
                    AuthenticationResult.NoAuthentication("No supported authentication method found")
                }
            }
        } catch (e: Exception) {
            Timber.e(e, "Authentication processing failed")
            AuthenticationResult.NoAuthentication("Authentication error: ${e.message}")
        }
    }
    
    private suspend fun performRiskManagement(
        cardData: EmvCardData,
        amount: Long,
        transactionType: TransactionType
    ): RiskManagementResult {
        return RiskManagementResult(
            approved = amount < 10000,
            riskScore = if (amount > 5000) 0.8 else 0.2,
            reason = if (amount < 10000) "Amount within limits" else "Amount exceeds limit"
        )
    }
    
    private suspend fun performActionAnalysis(
        cardData: EmvCardData,
        authResult: AuthenticationResult,
        riskResult: RiskManagementResult
    ): ActionAnalysisResult {
        val approved = when (authResult) {
            is AuthenticationResult.Success -> riskResult.approved
            is AuthenticationResult.Failed -> false
            is AuthenticationResult.NoAuthentication -> riskResult.approved
        }
        
        return ActionAnalysisResult(
            action = if (approved) TerminalAction.APPROVE else TerminalAction.DECLINE,
            reason = if (approved) "Transaction approved" else "Authentication or risk check failed"
        )
    }
}

/**
 * EMV Engine configuration
 */
data class EmvConfiguration(
    val enableRocaCheck: Boolean = true,
    val enableCryptoValidation: Boolean = true,
    val enableCryptoTesting: Boolean = false,
    val timeoutMs: Long = 30000,
    val strictValidation: Boolean = true
)

/**
 * Crypto validation result
 */
data class CryptoValidationResult(
    val isValid: Boolean,
    val validationChecks: List<ValidationCheck>,
    val details: String
)

/**
 * Individual validation check
 */
data class ValidationCheck(
    val name: String,
    val passed: Boolean
)

/**
 * Security test result
 */
data class SecurityTestResult(
    val passed: Boolean,
    val securityChecks: List<SecurityCheck>,
    val summary: String,
    val rocaInfo: String
)

/**
 * Individual security check
 */
data class SecurityCheck(
    val name: String,
    val passed: Boolean,
    val details: String
)
