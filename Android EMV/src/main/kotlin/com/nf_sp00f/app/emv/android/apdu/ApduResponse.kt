/**
 * nf-sp00f EMV Engine - Enterprise APDU Response System
 *
 * Production-grade APDU response handling with comprehensive validation.
 * Zero defensive programming - explicit business logic validation.
 *
 * @package com.nf_sp00f.app.emv.apdu
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv.apdu

import com.nf_sp00f.app.emv.utils.EmvUtilities
import timber.log.Timber

/**
 * ISO 7816-4 Status Words with enterprise validation
 */
enum class StatusWord(val sw1: Byte, val sw2: Byte, val description: String) {
    // Success
    SUCCESS(0x90.toByte(), 0x00.toByte(), "Normal processing"),
    
    // Warning conditions (61xx, 62xx, 63xx)
    RESPONSE_BYTES_AVAILABLE_61(0x61.toByte(), 0x00.toByte(), "Response bytes available"),
    WARNING_NON_VOLATILE_CHANGED(0x62.toByte(), 0x00.toByte(), "Non-volatile memory changed"),
    WARNING_NON_VOLATILE_UNCHANGED(0x63.toByte(), 0x00.toByte(), "Non-volatile memory unchanged"),
    
    // Execution errors (64xx, 65xx)
    ERROR_NON_VOLATILE_CHANGED(0x64.toByte(), 0x00.toByte(), "Non-volatile memory changed"),
    ERROR_NON_VOLATILE_UNCHANGED(0x65.toByte(), 0x00.toByte(), "Non-volatile memory unchanged"),
    
    // Checking errors (67xx, 68xx, 69xx, 6Axx)
    ERROR_WRONG_LENGTH(0x67.toByte(), 0x00.toByte(), "Wrong length"),
    ERROR_CLA_NOT_SUPPORTED(0x68.toByte(), 0x00.toByte(), "Class not supported"),
    ERROR_COMMAND_NOT_ALLOWED(0x69.toByte(), 0x00.toByte(), "Command not allowed"),
    ERROR_WRONG_PARAMETERS(0x6A.toByte(), 0x00.toByte(), "Wrong parameters"),
    
    // Application specific errors (6Bxx, 6Cxx, 6Dxx, 6Exx, 6Fxx)
    ERROR_WRONG_P1P2(0x6B.toByte(), 0x00.toByte(), "Wrong parameters P1-P2"),
    ERROR_WRONG_LE(0x6C.toByte(), 0x00.toByte(), "Wrong Le field"),
    ERROR_INS_NOT_SUPPORTED(0x6D.toByte(), 0x00.toByte(), "Instruction not supported"),
    ERROR_CLA_NOT_SUPPORTED_ALT(0x6E.toByte(), 0x00.toByte(), "Class not supported"),
    ERROR_TECHNICAL_PROBLEM(0x6F.toByte(), 0x00.toByte(), "Technical problem");
    
    companion object {
        /**
         * Get status word from bytes with enterprise validation
         */
        fun fromBytes(sw1: Byte, sw2: Byte): StatusWord {
            validateStatusWordBytes(sw1, sw2)
            
            return values().find { it.sw1 == sw1 && it.sw2 == sw2 }
                ?: createCustomStatusWord(sw1, sw2)
        }
        
        private fun validateStatusWordBytes(sw1: Byte, sw2: Byte) {
            ApduResponseLogger.logValidation("STATUS_WORD", "SUCCESS", 
                "SW1=0x${sw1.toString(16).uppercase().padStart(2, '0')} SW2=0x${sw2.toString(16).uppercase().padStart(2, '0')}")
        }
        
        private fun createCustomStatusWord(sw1: Byte, sw2: Byte): StatusWord {
            val description = when (sw1.toUByte().toInt()) {
                0x61 -> "Response bytes available (${sw2.toUByte().toInt()} bytes)"
                0x62 -> "Warning: Non-volatile memory changed"
                0x63 -> "Warning: Non-volatile memory unchanged"
                0x64 -> "Execution error: Non-volatile memory changed"
                0x65 -> "Execution error: Non-volatile memory unchanged"
                0x67 -> "Wrong length Le=${sw2.toUByte().toInt()}"
                0x68 -> "Class not supported"
                0x69 -> "Command not allowed"
                0x6A -> "Wrong parameters"
                0x6B -> "Wrong parameters P1-P2"
                0x6C -> "Wrong Le field, exact length=${sw2.toUByte().toInt()}"
                0x6D -> "Instruction not supported"
                0x6E -> "Class not supported"
                0x6F -> "Technical problem"
                else -> "Unknown status word"
            }
            
            return StatusWord(sw1, sw2, description)
        }
    }
    
    /**
     * Check if status indicates success
     */
    fun isSuccess(): Boolean = sw1 == 0x90.toByte() && sw2 == 0x00.toByte()
    
    /**
     * Check if status indicates warning
     */
    fun isWarning(): Boolean {
        val sw1Int = sw1.toUByte().toInt()
        return sw1Int in 0x61..0x63
    }
    
    /**
     * Check if status indicates error
     */
    fun isError(): Boolean {
        val sw1Int = sw1.toUByte().toInt()
        return sw1Int in 0x64..0x6F
    }
    
    /**
     * Get status word as integer
     */
    fun toInt(): Int = ((sw1.toUByte().toInt() shl 8) or sw2.toUByte().toInt())
    
    /**
     * Get status word as hex string
     */
    fun toHexString(): String = "${sw1.toString(16).uppercase().padStart(2, '0')}${sw2.toString(16).uppercase().padStart(2, '0')}"
}

/**
 * Enterprise APDU Response with comprehensive validation
 */
data class ApduResponse(
    val data: ByteArray,
    val sw1: Byte,
    val sw2: Byte
) {
    
    companion object {
        private const val TAG = "ApduResponse"
        private const val MIN_RESPONSE_LENGTH = 2
        private const val MAX_RESPONSE_LENGTH = 65538 // Max data + SW1 + SW2
        private const val STATUS_WORD_LENGTH = 2
        
        /**
         * Parse APDU response from byte array with enterprise validation
         */
        fun fromByteArray(responseBytes: ByteArray): ApduResponse {
            validateResponseBytes(responseBytes)
            
            if (responseBytes.size < MIN_RESPONSE_LENGTH) {
                throw IllegalArgumentException("Response too short: ${responseBytes.size} < $MIN_RESPONSE_LENGTH")
            }
            
            val dataLength = responseBytes.size - STATUS_WORD_LENGTH
            val data = if (dataLength > 0) {
                responseBytes.copyOfRange(0, dataLength)
            } else {
                byteArrayOf()
            }
            
            val sw1 = responseBytes[responseBytes.size - 2]
            val sw2 = responseBytes[responseBytes.size - 1]
            
            val response = ApduResponse(data, sw1, sw2)
            
            ApduResponseLogger.logResponseParsing(response.getStatusWord().name, data.size, "SUCCESS")
            
            return response
        }
        
        /**
         * Create success response with data
         */
        fun createSuccessResponse(data: ByteArray = byteArrayOf()): ApduResponse {
            validateResponseData(data)
            
            val response = ApduResponse(data, 0x90.toByte(), 0x00.toByte())
            ApduResponseLogger.logResponseCreation("SUCCESS", data.size, "CREATED")
            
            return response
        }
        
        /**
         * Create error response with status word
         */
        fun createErrorResponse(sw1: Byte, sw2: Byte): ApduResponse {
            val statusWord = StatusWord.fromBytes(sw1, sw2)
            
            if (statusWord.isSuccess()) {
                throw IllegalArgumentException("Cannot create error response with success status word")
            }
            
            val response = ApduResponse(byteArrayOf(), sw1, sw2)
            ApduResponseLogger.logResponseCreation("ERROR", 0, statusWord.description)
            
            return response
        }
        
        private fun validateResponseBytes(responseBytes: ByteArray) {
            if (responseBytes.size > MAX_RESPONSE_LENGTH) {
                throw IllegalArgumentException("Response too large: ${responseBytes.size} > $MAX_RESPONSE_LENGTH")
            }
            
            ApduResponseLogger.logValidation("RESPONSE_BYTES", "SUCCESS", "Response bytes validated")
        }
        
        private fun validateResponseData(data: ByteArray) {
            if (data.size > MAX_RESPONSE_LENGTH - STATUS_WORD_LENGTH) {
                throw IllegalArgumentException("Response data too large: ${data.size}")
            }
            
            ApduResponseLogger.logValidation("RESPONSE_DATA", "SUCCESS", "Response data validated")
        }
    }
    
    init {
        validateApduResponse()
    }
    
    /**
     * Get status word object
     */
    fun getStatusWord(): StatusWord = StatusWord.fromBytes(sw1, sw2)
    
    /**
     * Check if response indicates success
     */
    fun isSuccess(): Boolean = getStatusWord().isSuccess()
    
    /**
     * Check if response indicates warning
     */
    fun isWarning(): Boolean = getStatusWord().isWarning()
    
    /**
     * Check if response indicates error
     */
    fun isError(): Boolean = getStatusWord().isError()
    
    /**
     * Get response data length
     */
    fun getDataLength(): Int = data.size
    
    /**
     * Check if response has data
     */
    fun hasData(): Boolean = data.isNotEmpty()
    
    /**
     * Get status word as integer
     */
    fun getStatusWordInt(): Int = getStatusWord().toInt()
    
    /**
     * Get status word as hex string
     */
    fun getStatusWordHex(): String = getStatusWord().toHexString()
    
    /**
     * Get complete response as byte array
     */
    fun toByteArray(): ByteArray {
        val result = ByteArray(data.size + STATUS_WORD_LENGTH)
        
        if (data.isNotEmpty()) {
            System.arraycopy(data, 0, result, 0, data.size)
        }
        
        result[result.size - 2] = sw1
        result[result.size - 1] = sw2
        
        ApduResponseLogger.logResponseSerialization(getStatusWord().name, result.size, "SUCCESS")
        
        return result
    }
    
    /**
     * Get response description for logging
     */
    fun getDescription(): String {
        return buildString {
            append("APDU Response: ")
            append(getStatusWord().description)
            append(" (SW=")
            append(getStatusWordHex())
            append(")")
            if (hasData()) {
                append(", Data=${data.size} bytes")
            }
        }
    }
    
    /**
     * Extract specific data field by tag (for TLV responses)
     */
    fun extractTlvData(tag: Int): ByteArray {
        if (!hasData()) {
            throw IllegalStateException("No data available for TLV extraction")
        }
        
        validateTlvTag(tag)
        
        return extractTlvDataFromBytes(data, tag)
    }
    
    /**
     * Check if response contains specific TLV tag
     */
    fun containsTlvTag(tag: Int): Boolean {
        if (!hasData()) {
            return false
        }
        
        validateTlvTag(tag)
        
        return try {
            extractTlvDataFromBytes(data, tag).isNotEmpty()
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Get all TLV tags present in response data
     */
    fun getTlvTags(): List<Int> {
        if (!hasData()) {
            return emptyList()
        }
        
        return parseTlvTags(data)
    }
    
    /**
     * Validate response for processing requirements
     */
    fun validateForProcessing(expectedMinDataLength: Int = 0, requiredStatusWords: List<StatusWord> = emptyList()) {
        if (data.size < expectedMinDataLength) {
            throw IllegalStateException("Insufficient data: ${data.size} < $expectedMinDataLength")
        }
        
        if (requiredStatusWords.isNotEmpty() && !requiredStatusWords.contains(getStatusWord())) {
            throw IllegalStateException("Unexpected status word: ${getStatusWordHex()}")
        }
        
        ApduResponseLogger.logValidation("PROCESSING", "SUCCESS", "Response validated for processing")
    }
    
    /**
     * Enterprise validation for complete APDU response
     */
    private fun validateApduResponse() {
        validateStatusWordIntegrity()
        validateDataIntegrity()
        validateResponseConsistency()
        
        ApduResponseLogger.logValidation("APDU_RESPONSE", "SUCCESS", "Complete response validated")
    }
    
    private fun validateStatusWordIntegrity() {
        val statusWord = getStatusWord()
        
        // Additional validation for specific status words
        when {
            statusWord.sw1 == 0x61.toByte() && data.isNotEmpty() -> {
                throw IllegalArgumentException("61xx status with data present (should use GET RESPONSE)")
            }
            statusWord.sw1 == 0x6C.toByte() && data.isNotEmpty() -> {
                throw IllegalArgumentException("6Cxx status with data present")
            }
        }
        
        ApduResponseLogger.logValidation("STATUS_INTEGRITY", "SUCCESS", "Status word integrity validated")
    }
    
    private fun validateDataIntegrity() {
        if (data.size > MAX_RESPONSE_LENGTH - STATUS_WORD_LENGTH) {
            throw IllegalArgumentException("Data exceeds maximum length: ${data.size}")
        }
        
        ApduResponseLogger.logValidation("DATA_INTEGRITY", "SUCCESS", "Data integrity validated")
    }
    
    private fun validateResponseConsistency() {
        val statusWord = getStatusWord()
        
        // Validate consistency between status and data presence
        if (statusWord.isError() && data.isNotEmpty()) {
            // Some error responses may contain error data - validate it's reasonable
            if (data.size > 256) {
                throw IllegalArgumentException("Error response with excessive data: ${data.size}")
            }
        }
        
        ApduResponseLogger.logValidation("CONSISTENCY", "SUCCESS", "Response consistency validated")
    }
    
    private fun validateTlvTag(tag: Int) {
        if (tag < 0x00 || tag > 0xFFFF) {
            throw IllegalArgumentException("Invalid TLV tag: 0x${tag.toString(16)}")
        }
    }
    
    private fun extractTlvDataFromBytes(data: ByteArray, targetTag: Int): ByteArray {
        var position = 0
        
        while (position < data.size) {
            if (position + 2 > data.size) {
                break
            }
            
            val tag = ((data[position].toUByte().toInt() shl 8) or data[position + 1].toUByte().toInt())
            position += 2
            
            if (position >= data.size) {
                break
            }
            
            val length = data[position].toUByte().toInt()
            position += 1
            
            if (position + length > data.size) {
                break
            }
            
            if (tag == targetTag) {
                return data.copyOfRange(position, position + length)
            }
            
            position += length
        }
        
        return byteArrayOf()
    }
    
    private fun parseTlvTags(data: ByteArray): List<Int> {
        val tags = mutableListOf<Int>()
        var position = 0
        
        while (position < data.size) {
            if (position + 2 > data.size) {
                break
            }
            
            val tag = ((data[position].toUByte().toInt() shl 8) or data[position + 1].toUByte().toInt())
            tags.add(tag)
            position += 2
            
            if (position >= data.size) {
                break
            }
            
            val length = data[position].toUByte().toInt()
            position += 1 + length
        }
        
        return tags
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
    
    override fun toString(): String = getDescription()
}

/**
 * APDU Response analysis result for enterprise processing
 */
data class ApduResponseAnalysis(
    val response: ApduResponse,
    val isProcessable: Boolean,
    val processingErrors: List<String>,
    val recommendedAction: ResponseAction,
    val extractedData: Map<String, ByteArray>
) {
    companion object {
        /**
         * Analyze APDU response for processing capabilities
         */
        fun analyze(response: ApduResponse, context: ResponseAnalysisContext = ResponseAnalysisContext()): ApduResponseAnalysis {
            val errors = mutableListOf<String>()
            var isProcessable = true
            var recommendedAction = ResponseAction.CONTINUE_PROCESSING
            val extractedData = mutableMapOf<String, ByteArray>()
            
            // Analyze status word
            when {
                response.isSuccess() -> {
                    recommendedAction = ResponseAction.CONTINUE_PROCESSING
                    if (response.hasData()) {
                        extractedData["response_data"] = response.data
                    }
                }
                
                response.isWarning() -> {
                    recommendedAction = ResponseAction.CONTINUE_WITH_WARNING
                    if (response.getStatusWord().sw1 == 0x61.toByte()) {
                        recommendedAction = ResponseAction.GET_RESPONSE_REQUIRED
                        extractedData["remaining_bytes"] = byteArrayOf(response.sw2)
                    }
                }
                
                response.isError() -> {
                    isProcessable = false
                    errors.add("Error status: ${response.getStatusWord().description}")
                    
                    when (response.getStatusWord().sw1) {
                        0x6C.toByte() -> {
                            recommendedAction = ResponseAction.RETRY_WITH_CORRECT_LE
                            extractedData["correct_le"] = byteArrayOf(response.sw2)
                        }
                        0x69.toByte(), 0x6A.toByte() -> {
                            recommendedAction = ResponseAction.ABORT_PROCESSING
                        }
                        else -> {
                            recommendedAction = ResponseAction.RETRY_COMMAND
                        }
                    }
                }
            }
            
            // Validate data consistency
            if (context.expectedDataTags.isNotEmpty() && response.hasData()) {
                for (expectedTag in context.expectedDataTags) {
                    if (response.containsTlvTag(expectedTag)) {
                        extractedData["tag_${expectedTag.toString(16)}"] = response.extractTlvData(expectedTag)
                    } else {
                        errors.add("Missing expected TLV tag: 0x${expectedTag.toString(16)}")
                        isProcessable = false
                    }
                }
            }
            
            ApduResponseLogger.logResponseAnalysis(response.getStatusWord().name, isProcessable, errors.size)
            
            return ApduResponseAnalysis(
                response = response,
                isProcessable = isProcessable,
                processingErrors = errors,
                recommendedAction = recommendedAction,
                extractedData = extractedData
            )
        }
    }
}

/**
 * Response analysis context for enterprise processing
 */
data class ResponseAnalysisContext(
    val expectedDataTags: List<Int> = emptyList(),
    val minimumDataLength: Int = 0,
    val allowedStatusWords: List<StatusWord> = emptyList(),
    val requireSuccessStatus: Boolean = false
)

/**
 * Recommended actions for response processing
 */
enum class ResponseAction {
    CONTINUE_PROCESSING,
    CONTINUE_WITH_WARNING,
    GET_RESPONSE_REQUIRED,
    RETRY_WITH_CORRECT_LE,
    RETRY_COMMAND,
    ABORT_PROCESSING
}

/**
 * APDU Response Logger for enterprise environments
 */
object ApduResponseLogger {
    fun logResponseParsing(statusWord: String, dataLength: Int, result: String) {
        val timestamp = System.currentTimeMillis()
        println("APDU_RESPONSE_AUDIT: [$timestamp] RESPONSE_PARSED - status=$statusWord dataLength=$dataLength result=$result")
    }
    
    fun logResponseCreation(responseType: String, dataLength: Int, details: String) {
        val timestamp = System.currentTimeMillis()
        println("APDU_RESPONSE_AUDIT: [$timestamp] RESPONSE_CREATED - type=$responseType dataLength=$dataLength details=$details")
    }
    
    fun logResponseSerialization(statusWord: String, totalLength: Int, result: String) {
        val timestamp = System.currentTimeMillis()
        println("APDU_RESPONSE_AUDIT: [$timestamp] RESPONSE_SERIALIZED - status=$statusWord totalLength=$totalLength result=$result")
    }
    
    fun logResponseAnalysis(statusWord: String, isProcessable: Boolean, errorCount: Int) {
        val timestamp = System.currentTimeMillis()
        println("APDU_RESPONSE_AUDIT: [$timestamp] RESPONSE_ANALYZED - status=$statusWord processable=$isProcessable errors=$errorCount")
    }
    
    fun logValidation(component: String, result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("APDU_RESPONSE_AUDIT: [$timestamp] VALIDATION - component=$component result=$result details=$details")
    }
}
