package com.nf_sp00f.app.emv.nfc

/**
 * NFC Provider Types supported by the EMV engine
 */
enum class NfcProviderType {
    ANDROID_INTERNAL,    // Android built-in NFC adapter
    PN532_BLUETOOTH      // PN532 connected via Bluetooth UART (HC-06)
}

/**
 * NFC Provider Configuration
 */
data class NfcProviderConfig(
    val type: NfcProviderType,
    val bluetoothAddress: String? = null,  // For PN532_BLUETOOTH
    val baudRate: Int = 115200,            // UART baud rate for PN532
    val timeout: Long = 30000L,            // Operation timeout in milliseconds
    val autoConnect: Boolean = true        // Auto-connect on initialization
)

/**
 * Unified NFC Provider Interface
 * 
 * This interface abstracts different NFC sources (Android internal NFC, PN532, etc.)
 * providing a consistent API for EMV processing regardless of the underlying hardware.
 */
interface INfcProvider {
    
    /**
     * Initialize the NFC provider
     */
    suspend fun initialize(config: NfcProviderConfig): Boolean
    
    /**
     * Check if NFC provider is ready for operations
     */
    fun isReady(): Boolean
    
    /**
     * Scan for available cards
     */
    suspend fun scanForCards(): List<NfcCardInfo>
    
    /**
     * Connect to a specific card
     */
    suspend fun connectToCard(cardInfo: NfcCardInfo): Boolean
    
    /**
     * Exchange APDU with the connected card
     */
    suspend fun exchangeApdu(apdu: ByteArray): ApduResponse
    
    /**
     * Select application by AID
     */
    suspend fun selectApplication(aid: String): ApduResponse
    
    /**
     * Get Processing Options (GPO)
     */
    suspend fun getProcessingOptions(pdol: ByteArray): ApduResponse
    
    /**
     * Read record from card
     */
    suspend fun readRecord(sfi: Int, recordNumber: Int): ApduResponse
    
    /**
     * Generate Application Cryptogram
     */
    suspend fun generateAc(acType: Int, cdol: ByteArray): ApduResponse
    
    /**
     * Get current card information
     */
    fun getCardInfo(): NfcCardInfo?
    
    /**
     * Disconnect from card
     */
    suspend fun disconnect()
    
    /**
     * Cleanup and release resources
     */
    suspend fun cleanup()
    
    /**
     * Get provider-specific capabilities
     */
    fun getCapabilities(): NfcCapabilities
}

/**
 * Unified card information from any NFC provider
 */
data class NfcCardInfo(
    val uid: String,
    val atr: String? = null,              // Answer To Reset (PN532)
    val atqa: String? = null,             // Answer To Request A (Android NFC)
    val sak: String? = null,              // Select Acknowledge (Android NFC) 
    val historicalBytes: String? = null,  // Historical bytes (Android NFC)
    val hiLayerResponse: String? = null,  // Hi-layer response (Android NFC)
    val cardType: NfcCardType,
    val providerType: NfcProviderType,
    val maxTransceiveLength: Int = 256,
    val isExtendedLengthSupported: Boolean = false
)

/**
 * NFC Card types
 */
enum class NfcCardType {
    ISO14443_TYPE_A,
    ISO14443_TYPE_B,
    ISO15693,
    MIFARE_CLASSIC,
    MIFARE_ULTRALIGHT,
    FELICA,
    UNKNOWN
}

/**
 * NFC Provider capabilities
 */
data class NfcCapabilities(
    val supportedCardTypes: Set<NfcCardType>,
    val maxApduLength: Int,
    val supportsExtendedLength: Boolean,
    val canControlField: Boolean,
    val canSetTimeout: Boolean,
    val supportsBaudRateChange: Boolean,
    val providerSpecificFeatures: Map<String, Any> = emptyMap()
)

/**
 * NFC Provider factory for creating appropriate providers
 */
object NfcProviderFactory {
    
    fun createProvider(type: NfcProviderType): INfcProvider {
        return when (type) {
            NfcProviderType.ANDROID_INTERNAL -> AndroidInternalNfcProvider()
            NfcProviderType.PN532_BLUETOOTH -> Pn532BluetoothNfcProvider()
        }
    }
    
    /**
     * Auto-detect best available NFC provider
     */
    suspend fun detectBestProvider(): NfcProviderType? {
        // Try Android internal NFC first
        val androidProvider = createProvider(NfcProviderType.ANDROID_INTERNAL)
        if (androidProvider.initialize(NfcProviderConfig(NfcProviderType.ANDROID_INTERNAL))) {
            androidProvider.cleanup()
            return NfcProviderType.ANDROID_INTERNAL
        }
        
        // TODO: Add PN532 Bluetooth detection logic
        
        return null
    }
}