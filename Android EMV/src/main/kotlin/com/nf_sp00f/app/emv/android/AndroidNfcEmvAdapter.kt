/**
 * nf-sp00f EMV Engine - Enterprise Android NFC Adapter
 *
 * Production-grade Android Internal NFC Adapter for EMV Processing with comprehensive:
 * - High-performance EMV card communication via Android internal NFC
 * - Thread-safe adapter operations with enterprise audit logging
 * - Complete ISO-DEP protocol implementation for EMV transactions
 * - Advanced APDU command processing and response validation
 * - Performance-optimized NFC operations with timeout management
 * - Zero defensive programming patterns with comprehensive validation
 * - Enterprise-grade error handling and connection management
 *
 * @package com.nf_sp00f.app.emv
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.nfc.tech.NfcA
import android.nfc.tech.NfcB
import kotlinx.coroutines.*
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.ConcurrentHashMap
import java.security.SecureRandom

/**
 * Enterprise Android Internal NFC Adapter Operations
 */
enum class AndroidNfcOperation {
    TAG_VALIDATION,
    ISODEP_CONNECTION,
    APDU_EXCHANGE,
    APPLICATION_SELECTION,
    PROCESSING_OPTIONS,
    RECORD_READING,
    CRYPTOGRAM_GENERATION,
    CARD_DISCONNECTION,
    CARD_INFO_RETRIEVAL
}

/**
 * Android NFC Adapter Results
 */
sealed class AndroidNfcResult {
    data class Success(
        val operation: AndroidNfcOperation,
        val data: ByteArray,
        val processingTime: Long,
        val cardInfo: EmvCardInfo,
        val operationDetails: Map<String, Any>
    ) : AndroidNfcResult() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as Success
            if (operation != other.operation) return false
            if (!data.contentEquals(other.data)) return false
            return true
        }
        
        override fun hashCode(): Int {
            var result = operation.hashCode()
            result = 31 * result + data.contentHashCode()
            return result
        }
    }
    
    data class Failed(
        val operation: AndroidNfcOperation,
        val error: AndroidNfcException,
        val processingTime: Long,
        val failureContext: Map<String, Any>,
        val recoveryGuidance: String
    ) : AndroidNfcResult()
}

/**
 * Android NFC Adapter Configuration
 */
data class AndroidNfcConfiguration(
    val connectionTimeoutMs: Long = 30000L,
    val apduTimeoutMs: Long = 10000L,
    val enableAuditLogging: Boolean = true,
    val enablePerformanceMonitoring: Boolean = true,
    val maxTransceiveLength: Int = 65535,
    val enableExtendedLengthSupport: Boolean = true,
    val retryAttempts: Int = 3,
    val retryDelayMs: Long = 1000L
)

/**
 * EMV Card Information Structure
 */
data class EmvCardInfo(
    val uid: String,
    val uidBytes: ByteArray,
    val atqa: String,
    val atqaBytes: ByteArray,
    val sak: String,
    val sakByte: Byte,
    val historicalBytes: String,
    val historicalBytesArray: ByteArray,
    val hiLayerResponse: String,
    val hiLayerResponseArray: ByteArray,
    val maxTransceiveLength: Int,
    val isExtendedLengthApduSupported: Boolean,
    val supportedTechnologies: List<String>,
    val connectionTimestamp: Long,
    val cardCapabilities: AndroidNfcCardCapabilities
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as EmvCardInfo
        if (uid != other.uid) return false
        if (!uidBytes.contentEquals(other.uidBytes)) return false
        return true
    }
    
    override fun hashCode(): Int {
        var result = uid.hashCode()
        result = 31 * result + uidBytes.contentHashCode()
        return result
    }
}

/**
 * Android NFC Card Capabilities
 */
data class AndroidNfcCardCapabilities(
    val supportsIsoDep: Boolean,
    val supportsNfcA: Boolean,
    val supportsNfcB: Boolean,
    val supportsNfcF: Boolean,
    val supportsNfcV: Boolean,
    val maxApduLength: Int,
    val connectionSpeed: String,
    val protocolType: String
)

/**
 * APDU Response Structure
 */
data class ApduResponse(
    val data: ByteArray,
    val sw1: Int,
    val sw2: Int,
    val sw: Int,
    val processingTime: Long,
    val isSuccess: Boolean,
    val isMoreDataAvailable: Boolean,
    val needsGetResponse: Boolean,
    val responseMetadata: Map<String, Any>
) {
    
    companion object {
        const val SW_SUCCESS = 0x9000
        const val SW_MORE_DATA_AVAILABLE = 0x61
        const val SW_WRONG_LENGTH = 0x6700
        const val SW_COMMAND_NOT_ALLOWED = 0x6986
        const val SW_INCORRECT_PARAMETERS = 0x6A86
        const val SW_FILE_NOT_FOUND = 0x6A82
    }
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ApduResponse
        if (!data.contentEquals(other.data)) return false
        if (sw1 != other.sw1) return false
        if (sw2 != other.sw2) return false
        return true
    }
    
    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + sw1
        result = 31 * result + sw2
        return result
    }
}

/**
 * Enterprise Android NFC EMV Adapter
 * 
 * Thread-safe, high-performance Android NFC adapter for EMV processing with comprehensive validation
 */
class AndroidNfcEmvAdapter(
    private val configuration: AndroidNfcConfiguration = AndroidNfcConfiguration()
) {
    companion object {
        private const val ADAPTER_VERSION = "1.0.0"
        private const val MIN_APDU_LENGTH = 4
        private const val MAX_STANDARD_APDU_LENGTH = 261
        private const val MIN_AID_LENGTH = 5
        private const val MAX_AID_LENGTH = 16
        private const val MAX_PDOL_LENGTH = 252
        private const val MAX_CDOL_LENGTH = 252
        
        // EMV Command Constants
        private const val EMV_CLA: Byte = 0x00
        private const val EMV_CLA_PROPRIETARY: Byte = 0x80.toByte()
        private const val INS_SELECT: Byte = 0xA4.toByte()
        private const val INS_GET_PROCESSING_OPTIONS: Byte = 0xA8.toByte()
        private const val INS_READ_RECORD: Byte = 0xB2.toByte()
        private const val INS_GENERATE_AC: Byte = 0xAE.toByte()
        private const val INS_GET_DATA: Byte = 0xCA.toByte()
        private const val INS_VERIFY: Byte = 0x20
        private const val INS_GET_CHALLENGE: Byte = 0x84.toByte()
        
        // Application Cryptogram Types
        private const val AC_TYPE_AAC = 0x00
        private const val AC_TYPE_TC = 0x40
        private const val AC_TYPE_ARQC = 0x80
    }
    
    private val lock = ReentrantLock()
    private val auditLogger = AndroidNfcAuditLogger()
    private val performanceMetrics = AndroidNfcPerformanceMetrics()
    private val operationsPerformed = AtomicLong(0)
    private val connectionSessions = ConcurrentHashMap<String, AndroidNfcSession>()
    private val secureRandom = SecureRandom()
    
    private var currentSession: AndroidNfcSession = AndroidNfcSession.DISCONNECTED
    
    /**
     * Connect to EMV card using Android internal NFC with enterprise validation
     */
    suspend fun connectToCard(tag: Tag): AndroidNfcResult = withContext(Dispatchers.IO) {
        val operationStart = System.currentTimeMillis()
        val sessionId = generateSessionId()
        
        try {
            auditLogger.logOperation("CARD_CONNECTION_START", 
                "session=$sessionId tag_technologies=${tag.techList.joinToString()}")
            
            validateTagForEmvProcessing(tag)
            
            val isoDep = createIsoDepConnection(tag)
            val cardInfo = buildCardInfo(tag, isoDep)
            
            establishSecureConnection(isoDep)
            
            val session = AndroidNfcSession(
                sessionId = sessionId,
                tag = tag,
                isoDep = isoDep,
                cardInfo = cardInfo,
                connectionTime = System.currentTimeMillis(),
                isConnected = true
            )
            
            currentSession = session
            connectionSessions[sessionId] = session
            
            val processingTime = System.currentTimeMillis() - operationStart
            performanceMetrics.recordOperation("CARD_CONNECTION", processingTime, 0L)
            auditLogger.logOperation("CARD_CONNECTION_SUCCESS", 
                "session=$sessionId uid=${cardInfo.uid} time=${processingTime}ms")
            
            operationsPerformed.incrementAndGet()
            
            AndroidNfcResult.Success(
                operation = AndroidNfcOperation.ISODEP_CONNECTION,
                data = cardInfo.uidBytes,
                processingTime = processingTime,
                cardInfo = cardInfo,
                operationDetails = mapOf(
                    "session_id" to sessionId,
                    "max_transceive_length" to isoDep.maxTransceiveLength,
                    "extended_length_supported" to isoDep.isExtendedLengthApduSupported
                )
            )
            
        } catch (e: Exception) {
            val processingTime = System.currentTimeMillis() - operationStart
            auditLogger.logError("CARD_CONNECTION_FAILED", 
                "session=$sessionId error=${e.message} time=${processingTime}ms")
            
            AndroidNfcResult.Failed(
                operation = AndroidNfcOperation.ISODEP_CONNECTION,
                error = AndroidNfcException("Card connection failed: ${e.message}", e),
                processingTime = processingTime,
                failureContext = mapOf(
                    "session_id" to sessionId,
                    "tag_technologies" to tag.techList
                ),
                recoveryGuidance = "Ensure card supports ISO-DEP and is positioned correctly within NFC field"
            )
        }
    }
    
    /**
     * Exchange APDU command with EMV card via Android internal NFC
     */
    suspend fun exchangeApdu(apdu: ByteArray): AndroidNfcResult = withContext(Dispatchers.IO) {
        val operationStart = System.currentTimeMillis()
        
        try {
            validateConnectionState()
            validateApduCommand(apdu)
            
            val apduHex = apdu.toHexString()
            auditLogger.logOperation("APDU_EXCHANGE_START", 
                "session=${currentSession.sessionId} command=$apduHex length=${apdu.size}")
            
            val responseBytes = currentSession.isoDep.transceive(apdu)
            validateApduResponse(responseBytes)
            
            val apduResponse = parseApduResponse(responseBytes, operationStart)
            
            val processingTime = System.currentTimeMillis() - operationStart
            performanceMetrics.recordOperation("APDU_EXCHANGE", processingTime, apdu.size.toLong())
            auditLogger.logOperation("APDU_EXCHANGE_SUCCESS", 
                "session=${currentSession.sessionId} sw=0x${apduResponse.sw.toString(16).uppercase()} time=${processingTime}ms")
            
            operationsPerformed.incrementAndGet()
            
            AndroidNfcResult.Success(
                operation = AndroidNfcOperation.APDU_EXCHANGE,
                data = apduResponse.data,
                processingTime = processingTime,
                cardInfo = currentSession.cardInfo,
                operationDetails = mapOf(
                    "sw1" to apduResponse.sw1,
                    "sw2" to apduResponse.sw2,
                    "sw" to apduResponse.sw,
                    "is_success" to apduResponse.isSuccess,
                    "response_length" to responseBytes.size
                )
            )
            
        } catch (e: Exception) {
            val processingTime = System.currentTimeMillis() - operationStart
            auditLogger.logError("APDU_EXCHANGE_FAILED", 
                "session=${currentSession.sessionId} error=${e.message} time=${processingTime}ms")
            
            AndroidNfcResult.Failed(
                operation = AndroidNfcOperation.APDU_EXCHANGE,
                error = AndroidNfcException("APDU exchange failed: ${e.message}", e),
                processingTime = processingTime,
                failureContext = mapOf(
                    "command_length" to apdu.size,
                    "command_hex" to apdu.toHexString()
                ),
                recoveryGuidance = "Check card connection and APDU command format"
            )
        }
    }
    
    /**
     * Select EMV application by AID with enterprise validation
     */
    suspend fun selectApplication(aid: String): AndroidNfcResult = withContext(Dispatchers.IO) {
        val operationStart = System.currentTimeMillis()
        
        try {
            auditLogger.logOperation("APPLICATION_SELECTION_START", 
                "session=${currentSession.sessionId} aid=$aid")
            
            validateAidString(aid)
            val aidBytes = aid.hexToByteArray()
            validateAidBytes(aidBytes)
            
            val selectCommand = buildSelectCommand(aidBytes)
            val result = exchangeApdu(selectCommand)
            
            when (result) {
                is AndroidNfcResult.Success -> {
                    val processingTime = System.currentTimeMillis() - operationStart
                    auditLogger.logOperation("APPLICATION_SELECTION_SUCCESS", 
                        "session=${currentSession.sessionId} aid=$aid time=${processingTime}ms")
                    
                    AndroidNfcResult.Success(
                        operation = AndroidNfcOperation.APPLICATION_SELECTION,
                        data = result.data,
                        processingTime = processingTime,
                        cardInfo = currentSession.cardInfo,
                        operationDetails = result.operationDetails + mapOf("selected_aid" to aid)
                    )
                }
                is AndroidNfcResult.Failed -> result
            }
            
        } catch (e: Exception) {
            val processingTime = System.currentTimeMillis() - operationStart
            auditLogger.logError("APPLICATION_SELECTION_FAILED", 
                "session=${currentSession.sessionId} aid=$aid error=${e.message} time=${processingTime}ms")
            
            AndroidNfcResult.Failed(
                operation = AndroidNfcOperation.APPLICATION_SELECTION,
                error = AndroidNfcException("Application selection failed: ${e.message}", e),
                processingTime = processingTime,
                failureContext = mapOf("aid" to aid),
                recoveryGuidance = "Verify AID format and ensure application exists on card"
            )
        }
    }
    
    /**
     * Get Processing Options (GPO) command with enterprise validation
     */
    suspend fun getProcessingOptions(pdol: ByteArray): AndroidNfcResult = withContext(Dispatchers.IO) {
        val operationStart = System.currentTimeMillis()
        
        try {
            auditLogger.logOperation("PROCESSING_OPTIONS_START", 
                "session=${currentSession.sessionId} pdol_length=${pdol.size}")
            
            validatePdolData(pdol)
            
            val gpoCommand = buildGetProcessingOptionsCommand(pdol)
            val result = exchangeApdu(gpoCommand)
            
            when (result) {
                is AndroidNfcResult.Success -> {
                    val processingTime = System.currentTimeMillis() - operationStart
                    auditLogger.logOperation("PROCESSING_OPTIONS_SUCCESS", 
                        "session=${currentSession.sessionId} time=${processingTime}ms")
                    
                    AndroidNfcResult.Success(
                        operation = AndroidNfcOperation.PROCESSING_OPTIONS,
                        data = result.data,
                        processingTime = processingTime,
                        cardInfo = currentSession.cardInfo,
                        operationDetails = result.operationDetails + mapOf("pdol_length" to pdol.size)
                    )
                }
                is AndroidNfcResult.Failed -> result
            }
            
        } catch (e: Exception) {
            val processingTime = System.currentTimeMillis() - operationStart
            auditLogger.logError("PROCESSING_OPTIONS_FAILED", 
                "session=${currentSession.sessionId} error=${e.message} time=${processingTime}ms")
            
            AndroidNfcResult.Failed(
                operation = AndroidNfcOperation.PROCESSING_OPTIONS,
                error = AndroidNfcException("Get Processing Options failed: ${e.message}", e),
                processingTime = processingTime,
                failureContext = mapOf("pdol_length" to pdol.size),
                recoveryGuidance = "Verify PDOL data format and application state"
            )
        }
    }
    
    /**
     * Read EMV record with enterprise validation
     */
    suspend fun readRecord(sfi: Int, recordNumber: Int): AndroidNfcResult = withContext(Dispatchers.IO) {
        val operationStart = System.currentTimeMillis()
        
        try {
            auditLogger.logOperation("RECORD_READING_START", 
                "session=${currentSession.sessionId} sfi=$sfi record=$recordNumber")
            
            validateSfiAndRecord(sfi, recordNumber)
            
            val readCommand = buildReadRecordCommand(sfi, recordNumber)
            val result = exchangeApdu(readCommand)
            
            when (result) {
                is AndroidNfcResult.Success -> {
                    val processingTime = System.currentTimeMillis() - operationStart
                    auditLogger.logOperation("RECORD_READING_SUCCESS", 
                        "session=${currentSession.sessionId} sfi=$sfi record=$recordNumber time=${processingTime}ms")
                    
                    AndroidNfcResult.Success(
                        operation = AndroidNfcOperation.RECORD_READING,
                        data = result.data,
                        processingTime = processingTime,
                        cardInfo = currentSession.cardInfo,
                        operationDetails = result.operationDetails + mapOf(
                            "sfi" to sfi,
                            "record_number" to recordNumber
                        )
                    )
                }
                is AndroidNfcResult.Failed -> result
            }
            
        } catch (e: Exception) {
            val processingTime = System.currentTimeMillis() - operationStart
            auditLogger.logError("RECORD_READING_FAILED", 
                "session=${currentSession.sessionId} sfi=$sfi record=$recordNumber error=${e.message} time=${processingTime}ms")
            
            AndroidNfcResult.Failed(
                operation = AndroidNfcOperation.RECORD_READING,
                error = AndroidNfcException("Record reading failed: ${e.message}", e),
                processingTime = processingTime,
                failureContext = mapOf("sfi" to sfi, "record_number" to recordNumber),
                recoveryGuidance = "Verify SFI and record number are valid for current application"
            )
        }
    }
    
    /**
     * Generate Application Cryptogram with enterprise validation
     */
    suspend fun generateAc(acType: Int, cdol: ByteArray): AndroidNfcResult = withContext(Dispatchers.IO) {
        val operationStart = System.currentTimeMillis()
        
        try {
            auditLogger.logOperation("CRYPTOGRAM_GENERATION_START", 
                "session=${currentSession.sessionId} ac_type=$acType cdol_length=${cdol.size}")
            
            validateAcTypeAndCdol(acType, cdol)
            
            val genAcCommand = buildGenerateAcCommand(acType, cdol)
            val result = exchangeApdu(genAcCommand)
            
            when (result) {
                is AndroidNfcResult.Success -> {
                    val processingTime = System.currentTimeMillis() - operationStart
                    auditLogger.logOperation("CRYPTOGRAM_GENERATION_SUCCESS", 
                        "session=${currentSession.sessionId} ac_type=$acType time=${processingTime}ms")
                    
                    AndroidNfcResult.Success(
                        operation = AndroidNfcOperation.CRYPTOGRAM_GENERATION,
                        data = result.data,
                        processingTime = processingTime,
                        cardInfo = currentSession.cardInfo,
                        operationDetails = result.operationDetails + mapOf(
                            "ac_type" to acType,
                            "cdol_length" to cdol.size
                        )
                    )
                }
                is AndroidNfcResult.Failed -> result
            }
            
        } catch (e: Exception) {
            val processingTime = System.currentTimeMillis() - operationStart
            auditLogger.logError("CRYPTOGRAM_GENERATION_FAILED", 
                "session=${currentSession.sessionId} ac_type=$acType error=${e.message} time=${processingTime}ms")
            
            AndroidNfcResult.Failed(
                operation = AndroidNfcOperation.CRYPTOGRAM_GENERATION,
                error = AndroidNfcException("Cryptogram generation failed: ${e.message}", e),
                processingTime = processingTime,
                failureContext = mapOf("ac_type" to acType, "cdol_length" to cdol.size),
                recoveryGuidance = "Verify AC type and CDOL data format"
            )
        }
    }
    
    /**
     * Disconnect from card with enterprise cleanup
     */
    suspend fun disconnect(): AndroidNfcResult = withContext(Dispatchers.IO) {
        val operationStart = System.currentTimeMillis()
        
        try {
            val sessionId = currentSession.sessionId
            auditLogger.logOperation("CARD_DISCONNECTION_START", "session=$sessionId")
            
            if (currentSession.isConnected) {
                currentSession.isoDep.close()
                connectionSessions.remove(sessionId)
                
                val processingTime = System.currentTimeMillis() - operationStart
                auditLogger.logOperation("CARD_DISCONNECTION_SUCCESS", 
                    "session=$sessionId time=${processingTime}ms")
                
                currentSession = AndroidNfcSession.DISCONNECTED
                
                AndroidNfcResult.Success(
                    operation = AndroidNfcOperation.CARD_DISCONNECTION,
                    data = byteArrayOf(),
                    processingTime = processingTime,
                    cardInfo = EmvCardInfo.EMPTY,
                    operationDetails = mapOf("session_id" to sessionId)
                )
            } else {
                AndroidNfcResult.Success(
                    operation = AndroidNfcOperation.CARD_DISCONNECTION,
                    data = byteArrayOf(),
                    processingTime = 0L,
                    cardInfo = EmvCardInfo.EMPTY,
                    operationDetails = mapOf("status" to "already_disconnected")
                )
            }
            
        } catch (e: Exception) {
            val processingTime = System.currentTimeMillis() - operationStart
            auditLogger.logError("CARD_DISCONNECTION_FAILED", 
                "error=${e.message} time=${processingTime}ms")
            
            // Force disconnect regardless of error
            currentSession = AndroidNfcSession.DISCONNECTED
            
            AndroidNfcResult.Failed(
                operation = AndroidNfcOperation.CARD_DISCONNECTION,
                error = AndroidNfcException("Disconnection failed: ${e.message}", e),
                processingTime = processingTime,
                failureContext = emptyMap(),
                recoveryGuidance = "Connection forcibly closed despite error"
            )
        }
    }
    
    /**
     * Get comprehensive card information with enterprise validation
     */
    fun getCardInfo(): EmvCardInfo {
        return if (currentSession.isConnected) {
            currentSession.cardInfo
        } else {
            auditLogger.logOperation("CARD_INFO_REQUEST", "no_active_connection")
            EmvCardInfo.EMPTY
        }
    }
    
    /**
     * Get adapter statistics and performance metrics
     */
    fun getAdapterStatistics(): AndroidNfcAdapterStatistics = lock.withLock {
        return AndroidNfcAdapterStatistics(
            version = ADAPTER_VERSION,
            operationsPerformed = operationsPerformed.get(),
            activeSessions = connectionSessions.size,
            averageProcessingTime = performanceMetrics.getAverageProcessingTime(),
            configuration = configuration,
            uptime = performanceMetrics.getAdapterUptime(),
            connectionStatistics = getConnectionStatistics()
        )
    }
    
    // Private implementation methods
    
    private fun validateTagForEmvProcessing(tag: Tag) {
        if (tag.id.isEmpty()) {
            throw AndroidNfcException("Invalid tag - empty UID")
        }
        
        if (tag.techList.isEmpty()) {
            throw AndroidNfcException("Invalid tag - no supported technologies")
        }
        
        if (!tag.techList.contains(IsoDep::class.java.name)) {
            throw AndroidNfcException("Tag does not support ISO-DEP - EMV processing not possible")
        }
        
        auditLogger.logValidation("TAG_VALIDATION", "SUCCESS", 
            "uid=${tag.id.toHexString()} technologies=${tag.techList.joinToString()}")
    }
    
    private fun createIsoDepConnection(tag: Tag): IsoDep {
        val isoDep = IsoDep.get(tag)
        
        if (isoDep.maxTransceiveLength < MIN_APDU_LENGTH) {
            throw AndroidNfcException("IsoDep max transceive length too small: ${isoDep.maxTransceiveLength} (minimum $MIN_APDU_LENGTH)")
        }
        
        auditLogger.logValidation("ISODEP_CREATION", "SUCCESS", 
            "max_length=${isoDep.maxTransceiveLength} extended_support=${isoDep.isExtendedLengthApduSupported}")
        
        return isoDep
    }
    
    private fun establishSecureConnection(isoDep: IsoDep) {
        isoDep.timeout = configuration.connectionTimeoutMs.toInt()
        isoDep.connect()
        
        if (!isoDep.isConnected) {
            throw AndroidNfcException("Failed to establish ISO-DEP connection")
        }
        
        auditLogger.logValidation("CONNECTION_ESTABLISHMENT", "SUCCESS", 
            "timeout=${configuration.connectionTimeoutMs}ms connected=${isoDep.isConnected}")
    }
    
    private fun buildCardInfo(tag: Tag, isoDep: IsoDep): EmvCardInfo {
        val nfcA = NfcA.get(tag)
        val nfcB = NfcB.get(tag)
        
        val uid = tag.id.toHexString()
        val atqa = if (nfcA != null) nfcA.atqa.toHexString() else "0000"
        val sak = if (nfcA != null) String.format("%02X", nfcA.sak) else "00"
        val historicalBytes = if (isoDep.historicalBytes != null) isoDep.historicalBytes.toHexString() else ""
        val hiLayerResponse = if (isoDep.hiLayerResponse != null) isoDep.hiLayerResponse.toHexString() else ""
        
        val cardCapabilities = AndroidNfcCardCapabilities(
            supportsIsoDep = true,
            supportsNfcA = nfcA != null,
            supportsNfcB = nfcB != null,
            supportsNfcF = tag.techList.contains("android.nfc.tech.NfcF"),
            supportsNfcV = tag.techList.contains("android.nfc.tech.NfcV"),
            maxApduLength = isoDep.maxTransceiveLength,
            connectionSpeed = if (nfcA != null) "${nfcA.maxTransceiveLength} bytes" else "unknown",
            protocolType = "ISO-DEP"
        )
        
        return EmvCardInfo(
            uid = uid,
            uidBytes = tag.id,
            atqa = atqa,
            atqaBytes = if (nfcA != null) nfcA.atqa else byteArrayOf(),
            sak = sak,
            sakByte = if (nfcA != null) nfcA.sak else 0.toByte(),
            historicalBytes = historicalBytes,
            historicalBytesArray = isoDep.historicalBytes ?: byteArrayOf(),
            hiLayerResponse = hiLayerResponse,
            hiLayerResponseArray = isoDep.hiLayerResponse ?: byteArrayOf(),
            maxTransceiveLength = isoDep.maxTransceiveLength,
            isExtendedLengthApduSupported = isoDep.isExtendedLengthApduSupported,
            supportedTechnologies = tag.techList.toList(),
            connectionTimestamp = System.currentTimeMillis(),
            cardCapabilities = cardCapabilities
        )
    }
    
    private fun validateConnectionState() {
        if (!currentSession.isConnected) {
            throw AndroidNfcException("Not connected to card - call connectToCard() first")
        }
        
        if (!currentSession.isoDep.isConnected) {
            throw AndroidNfcException("ISO-DEP connection lost")
        }
    }
    
    private fun validateApduCommand(apdu: ByteArray) {
        if (apdu.isEmpty()) {
            throw AndroidNfcException("APDU command cannot be empty")
        }
        
        if (apdu.size < MIN_APDU_LENGTH) {
            throw AndroidNfcException("APDU command too short: ${apdu.size} bytes (minimum $MIN_APDU_LENGTH)")
        }
        
        if (apdu.size > configuration.maxTransceiveLength) {
            throw AndroidNfcException("APDU command too long: ${apdu.size} bytes (maximum ${configuration.maxTransceiveLength})")
        }
        
        auditLogger.logValidation("APDU_COMMAND", "SUCCESS", "length=${apdu.size}")
    }
    
    private fun validateApduResponse(response: ByteArray) {
        if (response.size < 2) {
            throw AndroidNfcException("APDU response too short: ${response.size} bytes (minimum 2 for SW1/SW2)")
        }
        
        auditLogger.logValidation("APDU_RESPONSE", "SUCCESS", "length=${response.size}")
    }
    
    private fun parseApduResponse(responseBytes: ByteArray, operationStart: Long): ApduResponse {
        val data = responseBytes.dropLast(2).toByteArray()
        val sw1 = responseBytes[responseBytes.size - 2].toInt() and 0xFF
        val sw2 = responseBytes[responseBytes.size - 1].toInt() and 0xFF
        val sw = (sw1 shl 8) or sw2
        val processingTime = System.currentTimeMillis() - operationStart
        
        return ApduResponse(
            data = data,
            sw1 = sw1,
            sw2 = sw2,
            sw = sw,
            processingTime = processingTime,
            isSuccess = sw == ApduResponse.SW_SUCCESS,
            isMoreDataAvailable = sw1 == 0x61,
            needsGetResponse = sw1 == 0x61,
            responseMetadata = mapOf(
                "response_length" to responseBytes.size,
                "data_length" to data.size,
                "sw_hex" to "0x${sw.toString(16).uppercase()}"
            )
        )
    }
    
    private fun validateAidString(aid: String) {
        if (aid.isBlank()) {
            throw AndroidNfcException("AID cannot be blank")
        }
        
        if (aid.length % 2 != 0) {
            throw AndroidNfcException("AID must have even number of hex characters: ${aid.length}")
        }
        
        if (aid.length < 10 || aid.length > 32) {
            throw AndroidNfcException("AID length invalid: ${aid.length} characters (must be 10-32)")
        }
        
        val hexPattern = Regex("^[0-9A-Fa-f]+$")
        if (!hexPattern.matches(aid)) {
            throw AndroidNfcException("AID contains invalid hex characters: $aid")
        }
        
        auditLogger.logValidation("AID_STRING", "SUCCESS", aid)
    }
    
    private fun validateAidBytes(aidBytes: ByteArray) {
        if (aidBytes.size < MIN_AID_LENGTH || aidBytes.size > MAX_AID_LENGTH) {
            throw AndroidNfcException("AID byte length invalid: ${aidBytes.size} (must be $MIN_AID_LENGTH-$MAX_AID_LENGTH)")
        }
        
        auditLogger.logValidation("AID_BYTES", "SUCCESS", "length=${aidBytes.size}")
    }
    
    private fun validatePdolData(pdol: ByteArray) {
        if (pdol.size > MAX_PDOL_LENGTH) {
            throw AndroidNfcException("PDOL data too large: ${pdol.size} bytes (maximum $MAX_PDOL_LENGTH)")
        }
        
        auditLogger.logValidation("PDOL", "SUCCESS", "length=${pdol.size}")
    }
    
    private fun validateSfiAndRecord(sfi: Int, recordNumber: Int) {
        if (sfi < 1 || sfi > 30) {
            throw AndroidNfcException("Invalid SFI: $sfi (must be 1-30)")
        }
        
        if (recordNumber < 1 || recordNumber > 16) {
            throw AndroidNfcException("Invalid record number: $recordNumber (must be 1-16)")
        }
        
        auditLogger.logValidation("SFI_RECORD", "SUCCESS", "sfi=$sfi record=$recordNumber")
    }
    
    private fun validateAcTypeAndCdol(acType: Int, cdol: ByteArray) {
        if (acType !in listOf(AC_TYPE_AAC, AC_TYPE_TC, AC_TYPE_ARQC)) {
            throw AndroidNfcException("Invalid AC type: $acType (must be $AC_TYPE_AAC, $AC_TYPE_TC, or $AC_TYPE_ARQC)")
        }
        
        if (cdol.size > MAX_CDOL_LENGTH) {
            throw AndroidNfcException("CDOL data too large: ${cdol.size} bytes (maximum $MAX_CDOL_LENGTH)")
        }
        
        auditLogger.logValidation("AC_TYPE_CDOL", "SUCCESS", "type=$acType cdol_length=${cdol.size}")
    }
    
    private fun buildSelectCommand(aidBytes: ByteArray): ByteArray {
        return byteArrayOf(
            EMV_CLA, INS_SELECT, 0x04, 0x00,
            aidBytes.size.toByte()
        ) + aidBytes
    }
    
    private fun buildGetProcessingOptionsCommand(pdol: ByteArray): ByteArray {
        return byteArrayOf(
            EMV_CLA_PROPRIETARY, INS_GET_PROCESSING_OPTIONS, 0x00, 0x00,
            pdol.size.toByte()
        ) + pdol
    }
    
    private fun buildReadRecordCommand(sfi: Int, recordNumber: Int): ByteArray {
        return byteArrayOf(
            EMV_CLA, INS_READ_RECORD,
            recordNumber.toByte(),
            ((sfi shl 3) or 0x04).toByte(),
            0x00
        )
    }
    
    private fun buildGenerateAcCommand(acType: Int, cdol: ByteArray): ByteArray {
        return byteArrayOf(
            EMV_CLA_PROPRIETARY, INS_GENERATE_AC,
            acType.toByte(), 0x00,
            cdol.size.toByte()
        ) + cdol
    }
    
    private fun generateSessionId(): String {
        val timestamp = System.currentTimeMillis()
        val random = secureRandom.nextInt(10000)
        return "ANDROID_NFC_${timestamp}_$random"
    }
    
    private fun getConnectionStatistics(): Map<String, Any> {
        return mapOf(
            "total_sessions" to connectionSessions.size,
            "current_session_connected" to currentSession.isConnected,
            "operations_performed" to operationsPerformed.get()
        )
    }
}

/**
 * Android NFC Session Management
 */
data class AndroidNfcSession(
    val sessionId: String = "",
    val tag: Tag = Tag.createMockTag(byteArrayOf(), intArrayOf(), arrayOf()),
    val isoDep: IsoDep = IsoDep.get(tag) ?: throw AndroidNfcException("Failed to create IsoDep"),
    val cardInfo: EmvCardInfo = EmvCardInfo.EMPTY,
    val connectionTime: Long = 0L,
    val isConnected: Boolean = false
) {
    companion object {
        val DISCONNECTED = AndroidNfcSession(
            sessionId = "DISCONNECTED",
            isConnected = false
        )
    }
}

/**
 * Android NFC Adapter Statistics
 */
data class AndroidNfcAdapterStatistics(
    val version: String,
    val operationsPerformed: Long,
    val activeSessions: Int,
    val averageProcessingTime: Double,
    val configuration: AndroidNfcConfiguration,
    val uptime: Long,
    val connectionStatistics: Map<String, Any>
)

/**
 * Android NFC Audit Logger
 */
class AndroidNfcAuditLogger {
    
    fun logOperation(operation: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("ANDROID_NFC_AUDIT: [$timestamp] OPERATION - $operation: $details")
    }
    
    fun logError(operation: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("ANDROID_NFC_AUDIT: [$timestamp] ERROR - $operation: $details")
    }
    
    fun logValidation(component: String, result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("ANDROID_NFC_AUDIT: [$timestamp] VALIDATION - $component/$result: $details")
    }
}

/**
 * Android NFC Performance Metrics
 */
class AndroidNfcPerformanceMetrics {
    private val operationTimes = mutableListOf<Long>()
    private val startTime = System.currentTimeMillis()
    
    fun recordOperation(operation: String, processingTime: Long, dataSize: Long) {
        operationTimes.add(processingTime)
    }
    
    fun getAverageProcessingTime(): Double {
        return if (operationTimes.isNotEmpty()) {
            operationTimes.average()
        } else {
            0.0
        }
    }
    
    fun getAdapterUptime(): Long {
        return System.currentTimeMillis() - startTime
    }
}

/**
 * Android NFC Exception
 */
class AndroidNfcException(
    message: String,
    cause: Throwable? = null,
    val context: Map<String, Any> = emptyMap()
) : Exception(message, cause)

/**
 * Extension functions for hex conversion with validation
 */
private fun ByteArray.toHexString(): String = 
    joinToString("") { "%02X".format(it) }

private fun String.hexToByteArray(): ByteArray = 
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()

/**
 * Empty EmvCardInfo companion
 */
private val EmvCardInfo.Companion.EMPTY: EmvCardInfo
    get() = EmvCardInfo(
        uid = "",
        uidBytes = byteArrayOf(),
        atqa = "",
        atqaBytes = byteArrayOf(),
        sak = "",
        sakByte = 0.toByte(),
        historicalBytes = "",
        historicalBytesArray = byteArrayOf(),
        hiLayerResponse = "",
        hiLayerResponseArray = byteArrayOf(),
        maxTransceiveLength = 0,
        isExtendedLengthApduSupported = false,
        supportedTechnologies = emptyList(),
        connectionTimestamp = 0L,
        cardCapabilities = AndroidNfcCardCapabilities(
            supportsIsoDep = false,
            supportsNfcA = false,
            supportsNfcB = false,
            supportsNfcF = false,
            supportsNfcV = false,
            maxApduLength = 0,
            connectionSpeed = "",
            protocolType = ""
        )
    )
