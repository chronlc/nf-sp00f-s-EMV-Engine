package com.nf_sp00f.app.emv.nfc

/**
 * Enterprise NFC Provider Interface Suite
 * 
 * Production-grade NFC abstraction layer providing unified access to multiple
 * NFC hardware sources with comprehensive validation and enterprise features.
 * Zero defensive programming patterns.
 * 
 * EMV Book Reference: EMV Contactless Specifications 
 * - EMV Contactless Book A: Architecture and General Requirements
 * - EMV Contactless Book B: Entry Point Specification  
 * - EMV Contactless Book C-2: Kernel 2 Specification (Mastercard)
 * - EMV Contactless Book C-3: Kernel 3 Specification (Visa)
 * 
 * Architecture:
 * - Complete hardware abstraction for Android NFC and PN532 Bluetooth
 * - Enterprise-grade validation and error handling
 * - Production-ready configuration management
 * - Comprehensive audit logging integration
 * - Zero defensive programming patterns (?:, ?., !!, .let)
 */

import kotlinx.coroutines.flow.Flow

/**
 * NFC Provider Type Enumeration
 * 
 * Comprehensive classification of supported NFC hardware interfaces
 * with enterprise-grade capability mapping
 */
enum class NfcProviderType(
    val displayName: String,
    val hardwareRequirements: Set<String>,
    val supportedProtocols: Set<NfcProtocol>,
    val enterpriseFeatures: Set<String>
) {
    ANDROID_INTERNAL(
        displayName = "Android Internal NFC",
        hardwareRequirements = setOf("ANDROID_NFC_HARDWARE", "NFC_PERMISSION"),
        supportedProtocols = setOf(
            NfcProtocol.ISO14443_TYPE_A,
            NfcProtocol.ISO14443_TYPE_B,
            NfcProtocol.ISO15693,
            NfcProtocol.FELICA
        ),
        enterpriseFeatures = setOf(
            "HOST_CARD_EMULATION",
            "BEAM_SUPPORT",
            "READER_MODE",
            "EXTENDED_LENGTH_APDU"
        )
    ),
    
    PN532_BLUETOOTH(
        displayName = "PN532 Bluetooth UART",
        hardwareRequirements = setOf("BLUETOOTH_CLASSIC", "UART_COMMUNICATION"),
        supportedProtocols = setOf(
            NfcProtocol.ISO14443_TYPE_A,
            NfcProtocol.ISO14443_TYPE_B,
            NfcProtocol.FELICA,
            NfcProtocol.MIFARE_CLASSIC,
            NfcProtocol.MIFARE_ULTRALIGHT
        ),
        enterpriseFeatures = setOf(
            "RF_FIELD_CONTROL",
            "LOW_LEVEL_FRAME_ACCESS",
            "CUSTOM_MODULATION",
            "HARDWARE_ENCRYPTION"
        )
    ),
    
    PN532_USB(
        displayName = "PN532 USB Interface",
        hardwareRequirements = setOf("USB_HOST", "USB_PERMISSION"),
        supportedProtocols = setOf(
            NfcProtocol.ISO14443_TYPE_A,
            NfcProtocol.ISO14443_TYPE_B,
            NfcProtocol.FELICA
        ),
        enterpriseFeatures = setOf(
            "HIGH_SPEED_COMMUNICATION",
            "BULK_TRANSFER",
            "HARDWARE_FLOW_CONTROL"
        )
    ),
    
    PN532_SPI(
        displayName = "PN532 SPI Interface", 
        hardwareRequirements = setOf("SPI_CONTROLLER", "GPIO_CONTROL"),
        supportedProtocols = setOf(
            NfcProtocol.ISO14443_TYPE_A,
            NfcProtocol.ISO14443_TYPE_B
        ),
        enterpriseFeatures = setOf(
            "DIRECT_HARDWARE_ACCESS",
            "INTERRUPT_DRIVEN",
            "HIGH_PERFORMANCE"
        )
    )
}

/**
 * NFC Protocol Support Enumeration
 */
enum class NfcProtocol(
    val technicalName: String,
    val maxFrameSize: Int,
    val supportsBinaryTransmission: Boolean
) {
    ISO14443_TYPE_A("ISO/IEC 14443 Type A", 256, true),
    ISO14443_TYPE_B("ISO/IEC 14443 Type B", 256, true),
    ISO15693("ISO/IEC 15693", 64, true),
    FELICA("FeliCa (JIS X 6319-4)", 254, true),
    MIFARE_CLASSIC("MIFARE Classic", 16, false),
    MIFARE_ULTRALIGHT("MIFARE Ultralight", 16, false),
    MIFARE_DESFIRE("MIFARE DESFire", 60, true)
}

/**
 * NFC Provider Configuration
 * 
 * Enterprise configuration management with comprehensive validation
 */
data class NfcProviderConfig(
    val providerType: NfcProviderType,
    val connectionParameters: ConnectionParameters,
    val operationalSettings: OperationalSettings,
    val securitySettings: SecuritySettings,
    val performanceSettings: PerformanceSettings,
    val auditSettings: AuditSettings
) {
    
    /**
     * Validate configuration completeness and correctness
     */
    fun validate() {
        if (providerType == NfcProviderType.PN532_BLUETOOTH) {
            if (connectionParameters.bluetoothAddress.isEmpty()) {
                throw NfcProviderConfigurationException(
                    "Bluetooth address is required for PN532 Bluetooth provider",
                    context = mapOf("provider_type" to providerType.name)
                )
            }
            
            if (!isValidBluetoothAddress(connectionParameters.bluetoothAddress)) {
                throw NfcProviderConfigurationException(
                    "Invalid Bluetooth address format",
                    context = mapOf("address" to connectionParameters.bluetoothAddress)
                )
            }
        }
        
        if (operationalSettings.transactionTimeout < 1000) {
            throw NfcProviderConfigurationException(
                "Transaction timeout must be at least 1000ms",
                context = mapOf("timeout" to operationalSettings.transactionTimeout)
            )
        }
        
        if (performanceSettings.maxConcurrentOperations < 1) {
            throw NfcProviderConfigurationException(
                "Maximum concurrent operations must be at least 1",
                context = mapOf("max_operations" to performanceSettings.maxConcurrentOperations)
            )
        }
    }
    
    private fun isValidBluetoothAddress(address: String): Boolean {
        return address.matches(Regex("([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"))
    }
}

/**
 * Connection Parameters
 */
data class ConnectionParameters(
    val bluetoothAddress: String = "",
    val usbVendorId: Int = 0,
    val usbProductId: Int = 0,
    val baudRate: Int = 115200,
    val dataBits: Int = 8,
    val stopBits: Int = 1,
    val parity: ParityType = ParityType.NONE,
    val flowControl: FlowControlType = FlowControlType.NONE
)

/**
 * Operational Settings  
 */
data class OperationalSettings(
    val transactionTimeout: Long = 30000L,
    val cardDetectionTimeout: Long = 5000L,
    val apduTimeout: Long = 10000L,
    val retryAttempts: Int = 3,
    val retryDelayMs: Long = 1000L,
    val autoReconnectOnError: Boolean = true,
    val enableCardPresenceMonitoring: Boolean = true,
    val cardPollingIntervalMs: Long = 500L
)

/**
 * Security Settings
 */
data class SecuritySettings(
    val enableSecureChannel: Boolean = false,
    val requireMutualAuthentication: Boolean = false,
    val encryptionAlgorithm: EncryptionAlgorithm = EncryptionAlgorithm.NONE,
    val keyDerivationMethod: KeyDerivationMethod = KeyDerivationMethod.PBKDF2,
    val validateCardCertificates: Boolean = true,
    val enforceMinimumSecurityLevel: Boolean = true,
    val allowWeakCiphers: Boolean = false
)

/**
 * Performance Settings
 */
data class PerformanceSettings(
    val maxConcurrentOperations: Int = 1,
    val operationQueueSize: Int = 100,
    val enableBulkOperations: Boolean = true,
    val cacheResponseData: Boolean = true,
    val optimizeForThroughput: Boolean = false,
    val enableParallelProcessing: Boolean = false
)

/**
 * Audit Settings
 */
data class AuditSettings(
    val enableFullAuditLogging: Boolean = true,
    val logApduExchanges: Boolean = true,
    val logPerformanceMetrics: Boolean = true,
    val auditLogLevel: AuditLogLevel = AuditLogLevel.DETAILED,
    val retainAuditLogs: Boolean = true,
    val maxAuditLogEntries: Int = 10000
)

/**
 * Supporting Enumerations
 */
enum class ParityType { NONE, ODD, EVEN, MARK, SPACE }
enum class FlowControlType { NONE, HARDWARE, SOFTWARE }
enum class EncryptionAlgorithm { NONE, AES128, AES256, DES, TDES }
enum class KeyDerivationMethod { NONE, PBKDF2, SCRYPT, BCRYPT }
enum class AuditLogLevel { MINIMAL, STANDARD, DETAILED, COMPREHENSIVE }

/**
 * Enterprise NFC Provider Interface
 * 
 * Production-grade interface defining complete contract for NFC operations
 * with comprehensive error handling and validation requirements
 */
interface INfcProvider {
    
    /**
     * Provider Information and Status
     */
    
    /**
     * Get provider type identifier
     */
    fun getProviderType(): NfcProviderType
    
    /**
     * Get provider display name
     */
    fun getProviderName(): String
    
    /**
     * Get provider version information
     */
    fun getProviderVersion(): String
    
    /**
     * Check if provider hardware is available
     */
    suspend fun isHardwareAvailable(): Boolean
    
    /**
     * Get provider capabilities and limitations
     */
    fun getCapabilities(): NfcProviderCapabilities
    
    /**
     * Initialization and Configuration
     */
    
    /**
     * Initialize provider with enterprise configuration
     * 
     * @param config Complete provider configuration
     * @return Initialization result with detailed status
     * @throws NfcProviderInitializationException if initialization fails
     */
    suspend fun initialize(config: NfcProviderConfig): NfcInitializationResult
    
    /**
     * Validate provider configuration without initializing
     * 
     * @param config Configuration to validate
     * @return Validation result with any issues
     */
    fun validateConfiguration(config: NfcProviderConfig): NfcConfigValidationResult
    
    /**
     * Check if provider is ready for operations
     */
    fun isReady(): Boolean
    
    /**
     * Get current provider status
     */
    fun getProviderStatus(): NfcProviderStatus
    
    /**
     * Card Detection and Management
     */
    
    /**
     * Start monitoring for card presence
     * 
     * @return Flow of card detection events
     */
    fun startCardMonitoring(): Flow<NfcCardEvent>
    
    /**
     * Stop card presence monitoring
     */
    suspend fun stopCardMonitoring()
    
    /**
     * Check if card is currently present
     */
    fun isCardPresent(): Boolean
    
    /**
     * Get information about currently present card
     * 
     * @return Complete card information or null if no card present
     * @throws NfcCardNotPresentException if no card is present
     */
    fun getCurrentCardInfo(): NfcCardInfo
    
    /**
     * Scan for all available cards in field
     * 
     * @param scanTimeout Maximum time to scan in milliseconds
     * @return List of detected cards with complete information
     * @throws NfcScanException if scan operation fails
     */
    suspend fun scanForCards(scanTimeout: Long = 5000L): List<NfcCardInfo>
    
    /**
     * Connect to specific card
     * 
     * @param cardInfo Card to connect to
     * @return Connection result with status and capabilities
     * @throws NfcConnectionException if connection fails
     */
    suspend fun connectToCard(cardInfo: NfcCardInfo): NfcConnectionResult
    
    /**
     * Disconnect from current card
     * 
     * @throws NfcDisconnectionException if disconnection fails
     */
    suspend fun disconnect()
    
    /**
     * EMV Transaction Operations
     */
    
    /**
     * Exchange APDU command with connected card
     * 
     * @param command Complete APDU command
     * @return APDU response with status and data
     * @throws NfcApduException if APDU exchange fails
     * @throws NfcCardNotConnectedException if no card is connected
     */
    suspend fun exchangeApdu(command: ApduCommand): ApduResponse
    
    /**
     * Select EMV application by AID
     * 
     * @param aid Application Identifier
     * @return Selection response with FCI data
     * @throws EmvApplicationSelectionException if selection fails
     */
    suspend fun selectApplication(aid: ByteArray): EmvApplicationSelectionResult
    
    /**
     * Get Processing Options (GPO) command
     * 
     * @param pdol Processing Options Data Object List
     * @return GPO response with AIP and AFL
     * @throws EmvProcessingOptionsException if GPO fails
     */
    suspend fun getProcessingOptions(pdol: ByteArray): EmvProcessingOptionsResult
    
    /**
     * Read record from EMV application
     * 
     * @param sfi Short File Identifier
     * @param recordNumber Record number to read
     * @return Record data
     * @throws EmvRecordReadException if read operation fails
     */
    suspend fun readRecord(sfi: Int, recordNumber: Int): EmvRecordData
    
    /**
     * Generate Application Cryptogram
     * 
     * @param cryptogramType Type of cryptogram (ARQC, TC, AAC)
     * @param cdol Card Data Object List
     * @return Cryptogram generation result
     * @throws EmvCryptogramException if generation fails
     */
    suspend fun generateApplicationCryptogram(
        cryptogramType: EmvCryptogramType,
        cdol: ByteArray
    ): EmvCryptogramResult
    
    /**
     * Perform cardholder verification
     * 
     * @param cvmList Cardholder Verification Method list
     * @param amount Transaction amount
     * @return Verification result
     * @throws EmvCardholderVerificationException if verification fails
     */
    suspend fun performCardholderVerification(
        cvmList: ByteArray,
        amount: Long
    ): EmvCardholderVerificationResult
    
    /**
     * Advanced Operations
     */
    
    /**
     * Execute batch of APDU commands atomically
     * 
     * @param commands List of APDU commands to execute
     * @return List of responses corresponding to each command
     * @throws NfcBatchOperationException if batch operation fails
     */
    suspend fun executeBatchApdu(commands: List<ApduCommand>): List<ApduResponse>
    
    /**
     * Control RF field power
     * 
     * @param enable True to enable RF field, false to disable
     * @throws NfcFieldControlException if field control fails
     */
    suspend fun controlRfField(enable: Boolean)
    
    /**
     * Set custom communication parameters
     * 
     * @param parameters Custom parameters for provider
     * @throws NfcParameterException if parameters are invalid
     */
    suspend fun setCustomParameters(parameters: Map<String, Any>)
    
    /**
     * Performance and Monitoring
     */
    
    /**
     * Get performance metrics
     */
    fun getPerformanceMetrics(): NfcPerformanceMetrics
    
    /**
     * Reset performance counters
     */
    fun resetPerformanceMetrics()
    
    /**
     * Get audit log entries
     */
    fun getAuditLog(maxEntries: Int = 100): List<NfcAuditLogEntry>
    
    /**
     * Resource Management
     */
    
    /**
     * Cleanup and release all resources
     * 
     * @throws NfcCleanupException if cleanup fails
     */
    suspend fun cleanup()
    
    /**
     * Reset provider to initial state
     * 
     * @throws NfcResetException if reset fails
     */
    suspend fun reset()
}

/**
 * NFC Card Information
 * 
 * Comprehensive card data structure with enterprise validation
 */
data class NfcCardInfo(
    val uid: ByteArray,
    val cardType: NfcCardType,
    val protocol: NfcProtocol,
    val atr: ByteArray,
    val historicalBytes: ByteArray,
    val applicationData: Map<String, ByteArray>,
    val capabilities: NfcCardCapabilities,
    val securityFeatures: Set<NfcSecurityFeature>,
    val detectionTimestamp: Long,
    val providerType: NfcProviderType
) {
    
    /**
     * Get card UID as hex string
     */
    fun getUidHex(): String {
        return uid.joinToString("") { "%02X".format(it) }
    }
    
    /**
     * Get ATR as hex string
     */
    fun getAtrHex(): String {
        return atr.joinToString("") { "%02X".format(it) }
    }
    
    /**
     * Validate card information completeness
     */
    fun validate() {
        if (uid.isEmpty()) {
            throw NfcCardValidationException(
                "Card UID cannot be empty",
                context = mapOf("card_type" to cardType.name)
            )
        }
        
        if (uid.size > 10) {
            throw NfcCardValidationException(
                "Card UID too long: ${uid.size} bytes (max 10)",
                context = mapOf("uid" to getUidHex())
            )
        }
        
        if (atr.isNotEmpty() && atr.size < 2) {
            throw NfcCardValidationException(
                "Invalid ATR length: ${atr.size} bytes (minimum 2)",
                context = mapOf("atr" to getAtrHex())
            )
        }
    }
}

/**
 * NFC Card Type Classification
 */
enum class NfcCardType(
    val technicalName: String,
    val emvCompliant: Boolean,
    val maxDataRate: Int
) {
    ISO14443_TYPE_A("ISO/IEC 14443 Type A", true, 847),
    ISO14443_TYPE_B("ISO/IEC 14443 Type B", true, 847),
    ISO15693("ISO/IEC 15693", false, 26),
    MIFARE_CLASSIC("MIFARE Classic", false, 106),
    MIFARE_ULTRALIGHT("MIFARE Ultralight", false, 106),
    MIFARE_DESFIRE("MIFARE DESFire", true, 847),
    FELICA("FeliCa", true, 424),
    UNKNOWN("Unknown Card Type", false, 0)
}

/**
 * NFC Card Capabilities
 */
data class NfcCardCapabilities(
    val maxApduLength: Int,
    val supportsExtendedLength: Boolean,
    val supportedCommands: Set<String>,
    val memorySize: Long,
    val processingPower: NfcProcessingPower,
    val securityLevel: NfcSecurityLevel
)

/**
 * NFC Security Features
 */
enum class NfcSecurityFeature {
    MUTUAL_AUTHENTICATION,
    DATA_ENCRYPTION,
    SECURE_MESSAGING,
    TAMPER_DETECTION,
    KEY_DIVERSIFICATION,
    SECURE_KEY_STORAGE
}

/**
 * NFC Processing Power Classification
 */
enum class NfcProcessingPower { LOW, MEDIUM, HIGH, ENTERPRISE }

/**
 * NFC Security Level Classification  
 */
enum class NfcSecurityLevel { BASIC, STANDARD, HIGH, GOVERNMENT }

/**
 * NFC Provider Capabilities
 */
data class NfcProviderCapabilities(
    val supportedCardTypes: Set<NfcCardType>,
    val supportedProtocols: Set<NfcProtocol>,
    val maxApduLength: Int,
    val supportsExtendedLength: Boolean,
    val canControlField: Boolean,
    val canSetTimeout: Boolean,
    val supportsBaudRateChange: Boolean,
    val supportsParallelOperations: Boolean,
    val enterpriseFeatures: Set<String>
)

/**
 * Result Data Classes
 */

/**
 * Initialization Result
 */
data class NfcInitializationResult(
    val success: Boolean,
    val providerVersion: String,
    val hardwareVersion: String,
    val firmwareVersion: String,
    val supportedFeatures: Set<String>,
    val initializationTime: Long,
    val errorDetails: String = ""
)

/**
 * Configuration Validation Result
 */
data class NfcConfigValidationResult(
    val isValid: Boolean,
    val validationErrors: List<String>,
    val warnings: List<String>,
    val recommendations: List<String>
)

/**
 * Provider Status
 */
data class NfcProviderStatus(
    val isInitialized: Boolean,
    val isConnected: Boolean,
    val cardPresent: Boolean,
    val operationInProgress: Boolean,
    val lastOperationTime: Long,
    val totalOperations: Long,
    val errorCount: Long,
    val currentConfig: NfcProviderConfig
)

/**
 * Card Event  
 */
sealed class NfcCardEvent(val timestamp: Long) {
    data class CardDetected(val cardInfo: NfcCardInfo, val eventTime: Long) : NfcCardEvent(eventTime)
    data class CardRemoved(val cardUid: ByteArray, val eventTime: Long) : NfcCardEvent(eventTime)
    data class CardError(val error: Exception, val eventTime: Long) : NfcCardEvent(eventTime)
}

/**
 * Connection Result
 */
data class NfcConnectionResult(
    val success: Boolean,
    val connectionTime: Long,
    val cardCapabilities: NfcCardCapabilities,
    val establishedProtocol: NfcProtocol,
    val errorDetails: String = ""
)

/**
 * EMV-Specific Result Classes
 */

/**
 * Application Selection Result
 */
data class EmvApplicationSelectionResult(
    val success: Boolean,
    val fciData: ByteArray,
    val applicationLabel: String,
    val preferredName: String,
    val selectionTime: Long,
    val errorDetails: String = ""
)

/**
 * Processing Options Result
 */
data class EmvProcessingOptionsResult(
    val success: Boolean,
    val aip: ByteArray,
    val afl: ByteArray,
    val processingTime: Long,
    val errorDetails: String = ""
)

/**
 * Record Data
 */
data class EmvRecordData(
    val sfi: Int,
    val recordNumber: Int,
    val data: ByteArray,
    val readTime: Long
)

/**
 * Cryptogram Type
 */
enum class EmvCryptogramType { ARQC, TC, AAC }

/**
 * Cryptogram Result
 */
data class EmvCryptogramResult(
    val success: Boolean,
    val cryptogramType: EmvCryptogramType,
    val cryptogramData: ByteArray,
    val issuerApplicationData: ByteArray,
    val generationTime: Long,
    val errorDetails: String = ""
)

/**
 * Cardholder Verification Result
 */
data class EmvCardholderVerificationResult(
    val success: Boolean,
    val cvmResults: ByteArray,
    val verificationMethod: String,
    val verificationTime: Long,
    val errorDetails: String = ""
)

/**
 * Performance Metrics
 */
data class NfcPerformanceMetrics(
    val totalOperations: Long,
    val successfulOperations: Long,
    val failedOperations: Long,
    val averageOperationTime: Long,
    val maxOperationTime: Long,
    val minOperationTime: Long,
    val throughputOperationsPerSecond: Double,
    val lastOperationTime: Long
)

/**
 * Audit Log Entry
 */
data class NfcAuditLogEntry(
    val timestamp: Long,
    val operation: String,
    val result: String,
    val details: Map<String, Any>,
    val performanceData: Map<String, Long>
)

/**
 * Exception Classes for Enterprise Error Handling
 */

/**
 * Base NFC Provider Exception
 */
open class NfcProviderException(
    message: String,
    cause: Throwable? = null,
    val context: Map<String, Any> = emptyMap()
) : Exception(message, cause)

/**
 * Specific NFC Exceptions
 */
class NfcProviderConfigurationException(message: String, context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, context = context)

class NfcProviderInitializationException(message: String, cause: Throwable? = null, context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, cause, context)

class NfcCardNotPresentException(message: String = "No NFC card present", context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, context = context)

class NfcCardValidationException(message: String, context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, context = context)

class NfcScanException(message: String, cause: Throwable? = null, context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, cause, context)

class NfcConnectionException(message: String, cause: Throwable? = null, context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, cause, context)

class NfcDisconnectionException(message: String, cause: Throwable? = null, context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, cause, context)

class NfcApduException(message: String, cause: Throwable? = null, context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, cause, context)

class NfcCardNotConnectedException(message: String = "No card connected", context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, context = context)

class EmvApplicationSelectionException(message: String, cause: Throwable? = null, context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, cause, context)

class EmvProcessingOptionsException(message: String, cause: Throwable? = null, context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, cause, context)

class EmvRecordReadException(message: String, cause: Throwable? = null, context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, cause, context)

class EmvCryptogramException(message: String, cause: Throwable? = null, context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, cause, context)

class EmvCardholderVerificationException(message: String, cause: Throwable? = null, context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, cause, context)

class NfcBatchOperationException(message: String, cause: Throwable? = null, context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, cause, context)

class NfcFieldControlException(message: String, cause: Throwable? = null, context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, cause, context)

class NfcParameterException(message: String, context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, context = context)

class NfcCleanupException(message: String, cause: Throwable? = null, context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, cause, context)

class NfcResetException(message: String, cause: Throwable? = null, context: Map<String, Any> = emptyMap()) 
    : NfcProviderException(message, cause, context)

/**
 * Enterprise NFC Provider Factory
 * 
 * Production-grade factory for creating and managing NFC providers
 */
object NfcProviderFactory {
    
    private val providerRegistry = mutableMapOf<NfcProviderType, () -> INfcProvider>()
    
    init {
        registerProvider(NfcProviderType.ANDROID_INTERNAL) { AndroidInternalNfcProvider() }
        registerProvider(NfcProviderType.PN532_BLUETOOTH) { Pn532BluetoothNfcProvider() }
        registerProvider(NfcProviderType.PN532_USB) { Pn532UsbNfcProvider() }
        registerProvider(NfcProviderType.PN532_SPI) { Pn532SpiNfcProvider() }
    }
    
    /**
     * Register custom provider implementation
     */
    fun registerProvider(type: NfcProviderType, factory: () -> INfcProvider) {
        providerRegistry[type] = factory
        NfcProviderAuditor.logProviderRegistration(type.name, "SUCCESS")
    }
    
    /**
     * Create provider instance
     */
    fun createProvider(type: NfcProviderType): INfcProvider {
        val factory = providerRegistry[type]
        if (factory == null) {
            throw NfcProviderException(
                "Unsupported provider type: ${type.name}",
                context = mapOf("available_types" to providerRegistry.keys.map { it.name })
            )
        }
        
        val provider = factory()
        NfcProviderAuditor.logProviderCreation(type.name, provider.getProviderVersion())
        return provider
    }
    
    /**
     * Detect best available provider with comprehensive testing
     */
    suspend fun detectBestProvider(): NfcProviderType {
        NfcProviderAuditor.logProviderDetection("DETECTION_START")
        
        val testResults = mutableMapOf<NfcProviderType, Boolean>()
        
        // Test Android internal NFC first (most common)
        try {
            val androidProvider = createProvider(NfcProviderType.ANDROID_INTERNAL)
            if (androidProvider.isHardwareAvailable()) {
                testResults[NfcProviderType.ANDROID_INTERNAL] = true
                androidProvider.cleanup()
                NfcProviderAuditor.logProviderDetection("ANDROID_DETECTED")
                return NfcProviderType.ANDROID_INTERNAL
            }
        } catch (e: Exception) {
            testResults[NfcProviderType.ANDROID_INTERNAL] = false
            NfcProviderAuditor.logProviderDetection("ANDROID_FAILED", e.message.orEmpty())
        }
        
        // Test PN532 Bluetooth
        try {
            val pn532Provider = createProvider(NfcProviderType.PN532_BLUETOOTH)
            if (pn532Provider.isHardwareAvailable()) {
                testResults[NfcProviderType.PN532_BLUETOOTH] = true
                pn532Provider.cleanup()
                NfcProviderAuditor.logProviderDetection("PN532_BLUETOOTH_DETECTED")
                return NfcProviderType.PN532_BLUETOOTH
            }
        } catch (e: Exception) {
            testResults[NfcProviderType.PN532_BLUETOOTH] = false
            NfcProviderAuditor.logProviderDetection("PN532_BLUETOOTH_FAILED", e.message.orEmpty())
        }
        
        // Test PN532 USB  
        try {
            val pn532UsbProvider = createProvider(NfcProviderType.PN532_USB)
            if (pn532UsbProvider.isHardwareAvailable()) {
                testResults[NfcProviderType.PN532_USB] = true
                pn532UsbProvider.cleanup()
                NfcProviderAuditor.logProviderDetection("PN532_USB_DETECTED")
                return NfcProviderType.PN532_USB
            }
        } catch (e: Exception) {
            testResults[NfcProviderType.PN532_USB] = false
            NfcProviderAuditor.logProviderDetection("PN532_USB_FAILED", e.message.orEmpty())
        }
        
        NfcProviderAuditor.logProviderDetection("NO_PROVIDER_AVAILABLE", testResults.toString())
        throw NfcProviderException(
            "No NFC provider available",
            context = mapOf("test_results" to testResults)
        )
    }
    
    /**
     * Get all available provider types
     */
    fun getAvailableProviderTypes(): Set<NfcProviderType> {
        return providerRegistry.keys
    }
}

/**
 * NFC Provider Auditor
 * 
 * Enterprise audit logging for NFC provider operations
 */
object NfcProviderAuditor {
    
    fun logProviderRegistration(providerType: String, status: String) {
        val timestamp = System.currentTimeMillis()
        println("NFC_PROVIDER_AUDIT: [$timestamp] PROVIDER_REGISTRATION - type=$providerType status=$status")
    }
    
    fun logProviderCreation(providerType: String, version: String) {
        val timestamp = System.currentTimeMillis()
        println("NFC_PROVIDER_AUDIT: [$timestamp] PROVIDER_CREATION - type=$providerType version=$version")
    }
    
    fun logProviderDetection(status: String, details: String = "") {
        val timestamp = System.currentTimeMillis()
        println("NFC_PROVIDER_AUDIT: [$timestamp] PROVIDER_DETECTION - status=$status details=$details")
    }
}
