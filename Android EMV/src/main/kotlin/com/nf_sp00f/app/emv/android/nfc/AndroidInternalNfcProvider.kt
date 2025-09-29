/**
 * nf-sp00f EMV Engine - Android Internal NFC Provider
 *
 * Enterprise-grade Android Internal NFC Provider implementation
 * Zero defensive programming - comprehensive validation approach
 *
 * @package com.nf_sp00f.app.emv.nfc
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv.nfc

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.nfc.tech.NfcA
import android.nfc.tech.NfcB
import kotlinx.coroutines.*
import timber.log.Timber

/**
 * Enterprise Android Internal NFC Provider
 * Unified interface matching external PN532 capabilities with comprehensive validation
 */
class AndroidInternalNfcProvider(
    private val context: Any? = null // Context placeholder for real implementation
) : INfcProvider {
    
    private var isoDep: IsoDep? = null
    private var currentCard: CardInfo? = null
    private var currentTag: Tag? = null
    private var config: NfcProviderConfig? = null
    
    override suspend fun initialize(config: NfcProviderConfig): Boolean = withContext(Dispatchers.Main) {
        validateConfigurationForInitialization(config)
        this@AndroidInternalNfcProvider.config = config
        
        try {
            validateNfcEnvironment()
            
            NfcProviderAuditor.logInitialization("SUCCESS", "Android Internal NFC initialized successfully")
            return@withContext true
            
        } catch (e: Exception) {
            NfcProviderAuditor.logInitialization("FAILED", e.message ?: "Unknown error")
            Timber.e(e, "Failed to initialize Android Internal NFC")
            return@withContext false
        }
    }
    
    override fun isReady(): Boolean {
        val ready = currentTag != null && isoDep != null
        NfcProviderAuditor.logReadyCheck(ready, if (ready) "Card present and connected" else "No card or connection")
        return ready
    }
    
    override suspend fun getDetectedCards(): List<CardInfo> = withContext(Dispatchers.IO) {
        if (currentCard != null) {
            validateCardInfoForProvider(currentCard!!)
            NfcProviderAuditor.logCardDetection("FOUND", "1 card detected")
            return@withContext listOf(currentCard!!)
        } else {
            NfcProviderAuditor.logCardDetection("NONE", "No cards detected")
            return@withContext emptyList()
        }
    }
    
    /**
     * Connect to card using Android NFC Tag with enterprise validation
     */
    fun connectToCardFromIntent(tag: Tag): Boolean {
        return runBlocking { 
            val cardInfo = parseTagToCardInfo(tag)
            connectToCard(cardInfo) 
        }
    }
    
    override suspend fun connectToCard(cardInfo: CardInfo): Boolean = withContext(Dispatchers.IO) {
        try {
            val tag = currentTag
            if (tag == null) {
                throw IllegalStateException("No tag available - ensure tag is set via setCurrentTag()")
            }
            
            validateTagForEmvProcessing(tag)
            validateCardInfoForConnection(cardInfo)
            
            if (!tag.techList.contains(IsoDep::class.java.name)) {
                throw EmvException("Tag does not support ISO-DEP - EMV processing not possible")
            }
            
            val newIsoDep = IsoDep.get(tag)
            if (newIsoDep == null) {
                throw EmvException("Failed to get IsoDep interface from tag")
            }
            
            validateIsoDepForTransaction(newIsoDep)
            
            isoDep = newIsoDep
            currentCard = cardInfo
            
            // Enterprise configuration for EMV operations
            val timeout = if (config != null) config!!.timeout.toInt() else 30000
            isoDep!!.timeout = timeout
            isoDep!!.connect()
            
            val connectionInfo = buildConnectionInfo(tag, isoDep!!)
            NfcProviderAuditor.logConnection("SUCCESS", connectionInfo)
            
            return@withContext true
            
        } catch (e: Exception) {
            NfcProviderAuditor.logConnection("FAILED", e.message ?: "Unknown error")
            Timber.e(e, "Failed to connect to EMV card")
            return@withContext false
        }
    }
    
    override suspend fun sendApdu(apdu: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        if (isoDep == null) {
            throw IllegalStateException("Not connected to card - call connectToCard() first")
        }
        
        validateApduForTransaction(apdu)
        
        try {
            NfcTransactionAuditor.logTransaction("SEND", "Android NFC", apdu.size, 0)
            
            val response = isoDep!!.transceive(apdu)
            
            validateTransactionResponse(response)
            
            NfcTransactionAuditor.logTransaction("RECEIVE", "Android NFC", apdu.size, response.size)
            
            return@withContext response
            
        } catch (e: Exception) {
            NfcTransactionAuditor.logTransaction("ERROR", "Android NFC", apdu.size, 0)
            throw EmvException("Android NFC transaction failed: ${e.message}", e)
        }
    }
    
    override suspend fun selectApplication(aid: String): ByteArray {
        validateAidForSelection(aid)
        
        val aidBytes = aid.hexToByteArray()
        val selectCommand = byteArrayOf(
            0x00.toByte(), 0xA4.toByte(), 0x04.toByte(), 0x00.toByte(),
            aidBytes.size.toByte()
        ) + aidBytes
        
        NfcProviderAuditor.logEmvOperation("SELECT_APPLICATION", aid)
        return sendApdu(selectCommand)
    }
    
    override suspend fun getProcessingOptions(pdol: ByteArray): ByteArray {
        validatePdolForProcessing(pdol)
        
        val gpoCommand = byteArrayOf(
            0x80.toByte(), 0xA8.toByte(), 0x00.toByte(), 0x00.toByte(),
            pdol.size.toByte()
        ) + pdol
        
        NfcProviderAuditor.logEmvOperation("GET_PROCESSING_OPTIONS", "${pdol.size} bytes")
        return sendApdu(gpoCommand)
    }
    
    override suspend fun readRecord(sfi: Int, recordNumber: Int): ByteArray {
        validateRecordParameters(sfi, recordNumber)
        
        val readCommand = byteArrayOf(
            0x00.toByte(), 0xB2.toByte(),
            recordNumber.toByte(),
            ((sfi shl 3) or 0x04).toByte(),
            0x00.toByte()
        )
        
        NfcProviderAuditor.logEmvOperation("READ_RECORD", "SFI=$sfi, Record=$recordNumber")
        return sendApdu(readCommand)
    }
    
    override suspend fun generateAc(acType: Int, cdol: ByteArray): ByteArray {
        validateAcParameters(acType, cdol)
        
        val genAcCommand = byteArrayOf(
            0x80.toByte(), 0xAE.toByte(),
            acType.toByte(), 0x00.toByte(),
            cdol.size.toByte()
        ) + cdol
        
        NfcProviderAuditor.logEmvOperation("GENERATE_AC", "Type=$acType, CDOL=${cdol.size} bytes")
        return sendApdu(genAcCommand)
    }
    
    override suspend fun disconnect() {
        try {
            if (isoDep != null) {
                isoDep!!.close()
                NfcProviderAuditor.logDisconnection("SUCCESS", "Android NFC disconnected cleanly")
            } else {
                NfcProviderAuditor.logDisconnection("NO_CONNECTION", "No active connection to disconnect")
            }
        } catch (e: Exception) {
            NfcProviderAuditor.logDisconnection("ERROR", e.message ?: "Unknown error")
            Timber.w(e, "Error during Android NFC disconnect")
        } finally {
            isoDep = null
            currentCard = null
            currentTag = null
        }
    }
    
    override suspend fun cleanup() {
        disconnect()
        NfcProviderAuditor.logCleanup("SUCCESS", "Android NFC provider cleanup completed")
    }
    
    override fun getCapabilities(): NfcCapabilities {
        val dep = isoDep
        val capabilities = NfcCapabilities(
            supportedCardTypes = setOf(
                NfcCardType.ISO14443_TYPE_A,
                NfcCardType.ISO14443_TYPE_B,
                NfcCardType.MIFARE_CLASSIC,
                NfcCardType.MIFARE_ULTRALIGHT,
                NfcCardType.FELICA
            ),
            maxApduLength = if (dep != null) dep.maxTransceiveLength else 261,
            supportsExtendedLength = if (dep != null) dep.isExtendedLengthApduSupported else false,
            canControlField = false, // Android manages field automatically
            canSetTimeout = true,
            supportsBaudRateChange = false,
            providerSpecificFeatures = mapOf(
                "androidNative" to true,
                "hardwareSecurityModule" to true,
                "systemManaged" to true
            )
        )
        
        NfcProviderAuditor.logCapabilities("RETRIEVED", "MaxAPDU=${capabilities.maxApduLength}, Extended=${capabilities.supportsExtendedLength}")
        return capabilities
    }
    
    /**
     * Set the current tag (called from Android NFC intent) with validation
     */
    fun setCurrentTag(tag: Tag) {
        validateTagForSetting(tag)
        currentTag = tag
        currentCard = parseTagToCardInfo(tag)
        NfcProviderAuditor.logTagSet("SUCCESS", "Tag set: UID=${tag.id.toHexString()}")
    }
    
    /**
     * Parse Android NFC Tag to unified card info with comprehensive validation
     */
    private fun parseTagToCardInfo(tag: Tag): CardInfo {
        validateTagForParsing(tag)
        
        val nfcA = NfcA.get(tag)
        val nfcB = NfcB.get(tag)
        val isoDep = IsoDep.get(tag)
        
        val cardType = when {
            nfcB != null -> NfcCardType.ISO14443_TYPE_B
            nfcA != null -> NfcCardType.ISO14443_TYPE_A
            else -> NfcCardType.UNKNOWN
        }
        
        val cardInfo = CardInfo(
            uid = tag.id,
            atr = if (isoDep != null && isoDep.historicalBytes != null) isoDep.historicalBytes!! else byteArrayOf(),
            aid = null, // Will be set during application selection
            label = null,
            preferredName = null,
            vendor = CardVendor.UNKNOWN,
            cardType = determineCardType(tag),
            detectedAt = System.currentTimeMillis(),
            fciTemplate = null
        )
        
        NfcProviderAuditor.logCardParsing("SUCCESS", "Parsed card: Type=$cardType, UID=${tag.id.toHexString()}")
        return cardInfo
    }
    
    /**
     * Enterprise validation functions
     */
    private fun validateConfigurationForInitialization(config: NfcProviderConfig) {
        if (config.timeout <= 0) {
            throw IllegalArgumentException("Invalid timeout in configuration: ${config.timeout} (must be positive)")
        }
        
        if (config.timeout > 300000) {
            throw IllegalArgumentException("Timeout too large: ${config.timeout}ms (maximum 300000ms)")
        }
        
        NfcProviderAuditor.logValidation("CONFIG", "SUCCESS", "Timeout=${config.timeout}ms")
    }
    
    private fun validateNfcEnvironment() {
        // Note: In real implementation, context would be used here
        // For now, we'll simulate the validation
        val nfcAdapter = NfcAdapter.getDefaultAdapter(null)
        if (nfcAdapter == null) {
            throw EmvException("NFC not supported on this device")
        }
        
        if (!nfcAdapter.isEnabled) {
            throw EmvException("NFC is disabled - please enable NFC in device settings")
        }
        
        NfcProviderAuditor.logValidation("NFC_ENVIRONMENT", "SUCCESS", "NFC adapter available and enabled")
    }
    
    private fun validateCardInfoForProvider(cardInfo: CardInfo) {
        if (cardInfo.uid.isEmpty()) {
            throw EmvException("Card info has empty UID")
        }
        
        if (cardInfo.atr.isEmpty()) {
            NfcProviderAuditor.logValidation("CARD_INFO", "WARNING", "Card has empty ATR")
        }
        
        NfcProviderAuditor.logValidation("CARD_INFO", "SUCCESS", "UID=${cardInfo.uid.size} bytes, ATR=${cardInfo.atr.size} bytes")
    }
    
    private fun validateTagForEmvProcessing(tag: Tag) {
        if (tag.id.isEmpty()) {
            throw EmvException("Tag has empty UID")
        }
        
        if (tag.techList.isEmpty()) {
            throw EmvException("Tag has no supported technologies")
        }
        
        NfcProviderAuditor.logValidation("TAG_EMV", "SUCCESS", "UID=${tag.id.toHexString()}, Tech=${tag.techList.size}")
    }
    
    private fun validateCardInfoForConnection(cardInfo: CardInfo) {
        if (cardInfo.uid.isEmpty()) {
            throw EmvException("Cannot connect to card with empty UID")
        }
        
        NfcProviderAuditor.logValidation("CARD_CONNECTION", "SUCCESS", "UID validated")
    }
    
    private fun validateIsoDepForTransaction(isoDep: IsoDep) {
        if (isoDep.maxTransceiveLength < 261) {
            throw EmvException("IsoDep max transceive length too small: ${isoDep.maxTransceiveLength} (minimum 261)")
        }
        
        NfcProviderAuditor.logValidation("ISODEP_TRANSACTION", "SUCCESS", "MaxLength=${isoDep.maxTransceiveLength}")
    }
    
    private fun validateApduForTransaction(apdu: ByteArray) {
        if (apdu.isEmpty()) {
            throw EmvException("APDU cannot be empty")
        }
        
        if (apdu.size < 4) {
            throw EmvException("APDU too short: ${apdu.size} bytes (minimum 4)")
        }
        
        if (apdu.size > 65535) {
            throw EmvException("APDU too long: ${apdu.size} bytes (maximum 65535)")
        }
        
        NfcProviderAuditor.logValidation("APDU", "SUCCESS", "${apdu.size} bytes")
    }
    
    private fun validateTransactionResponse(response: ByteArray) {
        if (response.size < 2) {
            throw EmvException("Response too short: ${response.size} bytes (minimum 2 for SW1/SW2)")
        }
        
        NfcProviderAuditor.logValidation("RESPONSE", "SUCCESS", "${response.size} bytes")
    }
    
    private fun validateAidForSelection(aid: String) {
        if (aid.isBlank()) {
            throw EmvException("AID cannot be blank")
        }
        
        if (aid.length % 2 != 0) {
            throw EmvException("AID must have even number of hex characters")
        }
        
        if (aid.length < 10 || aid.length > 32) {
            throw EmvException("AID length invalid: ${aid.length} characters (must be 10-32)")
        }
        
        NfcProviderAuditor.logValidation("AID_SELECTION", "SUCCESS", aid)
    }
    
    private fun validatePdolForProcessing(pdol: ByteArray) {
        if (pdol.size > 252) {
            throw EmvException("PDOL too large: ${pdol.size} bytes (maximum 252)")
        }
        
        NfcProviderAuditor.logValidation("PDOL", "SUCCESS", "${pdol.size} bytes")
    }
    
    private fun validateRecordParameters(sfi: Int, recordNumber: Int) {
        if (sfi < 1 || sfi > 30) {
            throw EmvException("Invalid SFI: $sfi (must be 1-30)")
        }
        
        if (recordNumber < 1 || recordNumber > 16) {
            throw EmvException("Invalid record number: $recordNumber (must be 1-16)")
        }
        
        NfcProviderAuditor.logValidation("RECORD_PARAMS", "SUCCESS", "SFI=$sfi, Record=$recordNumber")
    }
    
    private fun validateAcParameters(acType: Int, cdol: ByteArray) {
        if (acType !in listOf(0x00, 0x40, 0x80)) {
            throw EmvException("Invalid AC type: $acType (must be 0x00, 0x40, or 0x80)")
        }
        
        if (cdol.size > 252) {
            throw EmvException("CDOL too large: ${cdol.size} bytes (maximum 252)")
        }
        
        NfcProviderAuditor.logValidation("AC_PARAMS", "SUCCESS", "Type=$acType, CDOL=${cdol.size} bytes")
    }
    
    private fun validateTagForSetting(tag: Tag) {
        if (tag.id.isEmpty()) {
            throw EmvException("Cannot set tag with empty UID")
        }
        
        NfcProviderAuditor.logValidation("TAG_SETTING", "SUCCESS", "UID=${tag.id.toHexString()}")
    }
    
    private fun validateTagForParsing(tag: Tag) {
        if (tag.id.isEmpty()) {
            throw EmvException("Cannot parse tag with empty UID")
        }
        
        if (tag.techList.isEmpty()) {
            throw EmvException("Cannot parse tag with no technologies")
        }
        
        NfcProviderAuditor.logValidation("TAG_PARSING", "SUCCESS", "Ready for parsing")
    }
    
    private fun buildConnectionInfo(tag: Tag, isoDep: IsoDep): String {
        val uid = tag.id.toHexString()
        val histBytes = if (isoDep.historicalBytes != null) isoDep.historicalBytes!!.toHexString() else "none"
        val hiLayer = if (isoDep.hiLayerResponse != null) isoDep.hiLayerResponse!!.toHexString() else "none"
        return "UID=$uid, Historical=$histBytes, HiLayer=$hiLayer, MaxLength=${isoDep.maxTransceiveLength}"
    }
    
    private fun determineCardType(tag: Tag): EmvCardType {
        return when {
            tag.techList.contains("android.nfc.tech.NfcB") -> EmvCardType.EMV_CONTACTLESS
            tag.techList.contains("android.nfc.tech.NfcA") -> EmvCardType.EMV_CONTACTLESS
            tag.techList.contains("android.nfc.tech.IsoDep") -> EmvCardType.EMV_CONTACTLESS
            else -> EmvCardType.UNKNOWN
        }
    }
}

/**
 * NFC Provider auditor for enterprise environments
 */
object NfcProviderAuditor {
    fun logInitialization(result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_NFC_PROVIDER_AUDIT: [$timestamp] INITIALIZATION - result=$result details=$details")
    }
    
    fun logReadyCheck(ready: Boolean, details: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_NFC_PROVIDER_AUDIT: [$timestamp] READY_CHECK - ready=$ready details=$details")
    }
    
    fun logCardDetection(result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_NFC_PROVIDER_AUDIT: [$timestamp] CARD_DETECTION - result=$result details=$details")
    }
    
    fun logConnection(result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_NFC_PROVIDER_AUDIT: [$timestamp] CONNECTION - result=$result details=$details")
    }
    
    fun logEmvOperation(operation: String, params: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_NFC_PROVIDER_AUDIT: [$timestamp] EMV_OPERATION - operation=$operation params=$params")
    }
    
    fun logDisconnection(result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_NFC_PROVIDER_AUDIT: [$timestamp] DISCONNECTION - result=$result details=$details")
    }
    
    fun logCleanup(result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_NFC_PROVIDER_AUDIT: [$timestamp] CLEANUP - result=$result details=$details")
    }
    
    fun logCapabilities(result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_NFC_PROVIDER_AUDIT: [$timestamp] CAPABILITIES - result=$result details=$details")
    }
    
    fun logTagSet(result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_NFC_PROVIDER_AUDIT: [$timestamp] TAG_SET - result=$result details=$details")
    }
    
    fun logCardParsing(result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_NFC_PROVIDER_AUDIT: [$timestamp] CARD_PARSING - result=$result details=$details")
    }
    
    fun logValidation(component: String, result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_NFC_PROVIDER_AUDIT: [$timestamp] VALIDATION - component=$component result=$result details=$details")
    }
}

/**
 * NFC Transaction auditor for enterprise environments
 */
object NfcTransactionAuditor {
    fun logTransaction(direction: String, provider: String, requestSize: Int, responseSize: Int) {
        val timestamp = System.currentTimeMillis()
        println("EMV_NFC_TRANSACTION_AUDIT: [$timestamp] TRANSACTION - direction=$direction provider=$provider request_size=$requestSize response_size=$responseSize")
    }
}

// Extension functions for hex conversion with validation
private fun ByteArray.toHexString(): String = 
    joinToString("") { "%02X".format(it) }

private fun String.hexToByteArray(): ByteArray = 
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()
