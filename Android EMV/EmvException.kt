package com.nf_sp00f.app.emv

/**
 * Enterprise EMV Exception Hierarchy
 * 
 * Comprehensive exception system for EMV processing with detailed error classification,
 * audit logging, and recovery guidance. Zero defensive programming patterns.
 * 
 * EMV Book Reference: Section 11 - Error Handling and Recovery
 * 
 * Architecture:
 * - Hierarchical exception structure based on EMV specification
 * - Comprehensive error context preservation  
 * - Audit trail integration for all exceptions
 * - Recovery guidance for each error category
 * - Zero defensive programming patterns (?:, ?., !!, .let)
 */

import java.lang.Exception

/**
 * Base EMV Exception Class
 * 
 * Foundation for all EMV-related exceptions with comprehensive context preservation
 * and audit logging integration. All EMV exceptions extend this base class.
 */
sealed class EmvException(
    message: String,
    cause: Throwable? = null,
    val errorCode: String,
    val errorCategory: ErrorCategory,
    val context: Map<String, Any> = emptyMap(),
    val recoveryGuidance: String = ""
) : Exception(message, cause) {
    
    /**
     * EMV Error Categories based on EMV Book specifications
     */
    enum class ErrorCategory {
        CARD_COMMUNICATION,
        AUTHENTICATION_FAILURE, 
        TRANSACTION_DECLINED,
        DATA_VALIDATION_ERROR,
        CRYPTOGRAPHIC_ERROR,
        PROTOCOL_VIOLATION,
        HARDWARE_FAILURE,
        CONFIGURATION_ERROR,
        SECURITY_VIOLATION,
        TIMEOUT_ERROR
    }
    
    init {
        // Log exception creation for audit trail
        EmvExceptionLogger.logException(this)
    }
    
    /**
     * Get complete error details for logging and debugging
     */
    fun getFullErrorDetails(): String {
        return buildString {
            appendLine("EMV Exception Details:")
            appendLine("Error Code: $errorCode")
            appendLine("Category: ${errorCategory.name}")
            appendLine("Message: $message")
            appendLine("Recovery Guidance: $recoveryGuidance")
            if (context.isNotEmpty()) {
                appendLine("Context:")
                context.forEach { (key, value) ->
                    appendLine("  $key: $value")
                }
            }
            if (cause != null) {
                appendLine("Underlying Cause: ${cause!!.message}")
            }
        }
    }
}

/**
 * Card Communication Exceptions
 * 
 * Exceptions related to NFC communication, APDU transmission, and card presence
 */
sealed class CardCommunicationException(
    message: String,
    cause: Throwable? = null,
    errorCode: String,
    context: Map<String, Any> = emptyMap(),
    recoveryGuidance: String = ""
) : EmvException(
    message = message,
    cause = cause,
    errorCode = errorCode,
    errorCategory = ErrorCategory.CARD_COMMUNICATION,
    context = context,
    recoveryGuidance = recoveryGuidance
)

class CardNotPresentException(
    message: String = "EMV card not present in NFC field",
    context: Map<String, Any> = emptyMap()
) : CardCommunicationException(
    message = message,
    errorCode = "EMV_CARD_NOT_PRESENT",
    context = context,
    recoveryGuidance = "Position EMV card within 4cm of NFC antenna and retry"
)

class CardLostException(
    message: String = "EMV card lost during transaction processing",
    context: Map<String, Any> = emptyMap()
) : CardCommunicationException(
    message = message,
    errorCode = "EMV_CARD_LOST",
    context = context,
    recoveryGuidance = "Maintain card position throughout transaction and restart"
)

class ApduTransmissionException(
    message: String,
    cause: Throwable? = null,
    val apduCommand: String = "",
    context: Map<String, Any> = emptyMap()
) : CardCommunicationException(
    message = message,
    cause = cause,
    errorCode = "EMV_APDU_TRANSMISSION_FAILED",
    context = context + mapOf("apdu_command" to apduCommand),
    recoveryGuidance = "Check NFC connection quality and retry APDU transmission"
)

class InvalidResponseException(
    message: String,
    val expectedFormat: String = "",
    val actualResponse: String = "",
    context: Map<String, Any> = emptyMap()
) : CardCommunicationException(
    message = message,
    errorCode = "EMV_INVALID_RESPONSE",
    context = context + mapOf(
        "expected_format" to expectedFormat,
        "actual_response" to actualResponse
    ),
    recoveryGuidance = "Verify card EMV compliance and retry communication"
)

/**
 * Authentication Failure Exceptions
 * 
 * Exceptions related to EMV authentication processes including SDA, DDA, and CDA
 */
sealed class AuthenticationException(
    message: String,
    cause: Throwable? = null,
    errorCode: String,
    context: Map<String, Any> = emptyMap(),
    recoveryGuidance: String = ""
) : EmvException(
    message = message,
    cause = cause,
    errorCode = errorCode,
    errorCategory = ErrorCategory.AUTHENTICATION_FAILURE,
    context = context,
    recoveryGuidance = recoveryGuidance
)

class SdaVerificationException(
    message: String = "Static Data Authentication (SDA) verification failed",
    val certificateData: String = "",
    context: Map<String, Any> = emptyMap()
) : AuthenticationException(
    message = message,
    errorCode = "EMV_SDA_VERIFICATION_FAILED",
    context = context + mapOf("certificate_data" to certificateData),
    recoveryGuidance = "Verify issuer certificate chain and card authenticity"
)

class DdaVerificationException(
    message: String = "Dynamic Data Authentication (DDA) verification failed", 
    val signedData: String = "",
    context: Map<String, Any> = emptyMap()
) : AuthenticationException(
    message = message,
    errorCode = "EMV_DDA_VERIFICATION_FAILED",
    context = context + mapOf("signed_data" to signedData),
    recoveryGuidance = "Verify dynamic signature and card cryptographic capabilities"
)

class CdaVerificationException(
    message: String = "Combined Data Authentication (CDA) verification failed",
    val applicationCryptogram: String = "",
    context: Map<String, Any> = emptyMap()
) : AuthenticationException(
    message = message,
    errorCode = "EMV_CDA_VERIFICATION_FAILED", 
    context = context + mapOf("application_cryptogram" to applicationCryptogram),
    recoveryGuidance = "Verify application cryptogram and transaction data integrity"
)

/**
 * Transaction Processing Exceptions
 * 
 * Exceptions related to EMV transaction processing, terminal verification, and issuer responses
 */
sealed class TransactionException(
    message: String,
    cause: Throwable? = null,
    errorCode: String,
    context: Map<String, Any> = emptyMap(),
    recoveryGuidance: String = ""
) : EmvException(
    message = message,
    cause = cause,
    errorCode = errorCode,
    errorCategory = ErrorCategory.TRANSACTION_DECLINED,
    context = context,
    recoveryGuidance = recoveryGuidance
)

class TransactionDeclinedException(
    message: String,
    val declineReason: String = "",
    val issuerResponse: String = "",
    context: Map<String, Any> = emptyMap()
) : TransactionException(
    message = message,
    errorCode = "EMV_TRANSACTION_DECLINED",
    context = context + mapOf(
        "decline_reason" to declineReason,
        "issuer_response" to issuerResponse
    ),
    recoveryGuidance = "Check transaction amount, account status, and card validity"
)

class TerminalVerificationException(
    message: String = "Terminal verification failed during EMV processing",
    val verificationResults: String = "",
    context: Map<String, Any> = emptyMap()
) : TransactionException(
    message = message,
    errorCode = "EMV_TERMINAL_VERIFICATION_FAILED",
    context = context + mapOf("verification_results" to verificationResults),
    recoveryGuidance = "Review terminal configuration and EMV parameters"
)

class ApplicationSelectionException(
    message: String = "EMV application selection failed",
    val availableApplications: List<String> = emptyList(),
    context: Map<String, Any> = emptyMap()
) : TransactionException(
    message = message,
    errorCode = "EMV_APPLICATION_SELECTION_FAILED",
    context = context + mapOf("available_applications" to availableApplications),
    recoveryGuidance = "Select supported EMV application or update terminal configuration"
)

/**
 * Data Validation Exceptions
 * 
 * Exceptions related to EMV data validation, TLV parsing, and format verification
 */
sealed class DataValidationException(
    message: String,
    cause: Throwable? = null,
    errorCode: String,
    context: Map<String, Any> = emptyMap(),
    recoveryGuidance: String = ""
) : EmvException(
    message = message,
    cause = cause,
    errorCode = errorCode,
    errorCategory = ErrorCategory.DATA_VALIDATION_ERROR,
    context = context,
    recoveryGuidance = recoveryGuidance
)

class TlvParsingException(
    message: String,
    val tlvData: String = "",
    val parsePosition: Int = 0,
    context: Map<String, Any> = emptyMap()
) : DataValidationException(
    message = message,
    errorCode = "EMV_TLV_PARSING_ERROR",
    context = context + mapOf(
        "tlv_data" to tlvData,
        "parse_position" to parsePosition
    ),
    recoveryGuidance = "Verify TLV data format and encoding compliance with EMV specifications"
)

class InvalidTagException(
    message: String,
    val tag: String = "",
    val expectedFormat: String = "",
    context: Map<String, Any> = emptyMap()
) : DataValidationException(
    message = message,
    errorCode = "EMV_INVALID_TAG",
    context = context + mapOf(
        "invalid_tag" to tag,
        "expected_format" to expectedFormat
    ),
    recoveryGuidance = "Verify EMV tag definition and value format compliance"
)

class DataFormatException(
    message: String,
    val fieldName: String = "",
    val invalidValue: String = "",
    context: Map<String, Any> = emptyMap()
) : DataValidationException(
    message = message,
    errorCode = "EMV_DATA_FORMAT_ERROR",
    context = context + mapOf(
        "field_name" to fieldName,
        "invalid_value" to invalidValue
    ),
    recoveryGuidance = "Ensure data format matches EMV specification requirements"
)

/**
 * Cryptographic Exceptions
 * 
 * Exceptions related to EMV cryptographic operations, key management, and security
 */
sealed class CryptographicException(
    message: String,
    cause: Throwable? = null,
    errorCode: String,
    context: Map<String, Any> = emptyMap(),
    recoveryGuidance: String = ""
) : EmvException(
    message = message,
    cause = cause,
    errorCode = errorCode,
    errorCategory = ErrorCategory.CRYPTOGRAPHIC_ERROR,
    context = context,
    recoveryGuidance = recoveryGuidance
)

class KeyManagementException(
    message: String,
    val keyType: String = "",
    cause: Throwable? = null,
    context: Map<String, Any> = emptyMap()
) : CryptographicException(
    message = message,
    cause = cause,
    errorCode = "EMV_KEY_MANAGEMENT_ERROR",
    context = context + mapOf("key_type" to keyType),
    recoveryGuidance = "Verify cryptographic key availability and certificate chain"
)

class SignatureVerificationException(
    message: String = "Digital signature verification failed",
    val signatureData: String = "",
    context: Map<String, Any> = emptyMap()
) : CryptographicException(
    message = message,
    errorCode = "EMV_SIGNATURE_VERIFICATION_FAILED",
    context = context + mapOf("signature_data" to signatureData),
    recoveryGuidance = "Verify signature algorithm, key parameters, and data integrity"
)

class RocaVulnerabilityException(
    message: String = "ROCA vulnerability detected in cryptographic key",
    val keyModulus: String = "",
    context: Map<String, Any> = emptyMap()
) : CryptographicException(
    message = message,
    errorCode = "EMV_ROCA_VULNERABILITY_DETECTED",
    context = context + mapOf("key_modulus" to keyModulus),
    recoveryGuidance = "Replace vulnerable key with ROCA-safe cryptographic implementation"
)

/**
 * Hardware Failure Exceptions
 * 
 * Exceptions related to NFC hardware, Bluetooth connectivity, and device communication
 */
sealed class HardwareException(
    message: String,
    cause: Throwable? = null,
    errorCode: String,
    context: Map<String, Any> = emptyMap(),
    recoveryGuidance: String = ""
) : EmvException(
    message = message,
    cause = cause,
    errorCode = errorCode,
    errorCategory = ErrorCategory.HARDWARE_FAILURE,
    context = context,
    recoveryGuidance = recoveryGuidance
)

class NfcHardwareException(
    message: String,
    cause: Throwable? = null,
    context: Map<String, Any> = emptyMap()
) : HardwareException(
    message = message,
    cause = cause,
    errorCode = "EMV_NFC_HARDWARE_ERROR",
    context = context,
    recoveryGuidance = "Check NFC hardware status and enable NFC in device settings"
)

class BluetoothConnectionException(
    message: String,
    val deviceAddress: String = "",
    cause: Throwable? = null,
    context: Map<String, Any> = emptyMap()
) : HardwareException(
    message = message,
    cause = cause,
    errorCode = "EMV_BLUETOOTH_CONNECTION_ERROR",
    context = context + mapOf("device_address" to deviceAddress),
    recoveryGuidance = "Verify Bluetooth pairing and PN532 device connectivity"
)

/**
 * Timeout Exceptions
 * 
 * Exceptions related to EMV processing timeouts and response delays
 */
sealed class TimeoutException(
    message: String,
    cause: Throwable? = null,
    errorCode: String,
    val timeoutDuration: Long = 0,
    context: Map<String, Any> = emptyMap(),
    recoveryGuidance: String = ""
) : EmvException(
    message = message,
    cause = cause,
    errorCode = errorCode,
    errorCategory = ErrorCategory.TIMEOUT_ERROR,
    context = context + mapOf("timeout_duration_ms" to timeoutDuration),
    recoveryGuidance = recoveryGuidance
)

class CardResponseTimeoutException(
    message: String = "EMV card response timeout exceeded",
    timeoutDuration: Long = 0,
    context: Map<String, Any> = emptyMap()
) : TimeoutException(
    message = message,
    errorCode = "EMV_CARD_RESPONSE_TIMEOUT",
    timeoutDuration = timeoutDuration,
    context = context,
    recoveryGuidance = "Improve card positioning and retry with extended timeout"
)

class TransactionTimeoutException(
    message: String = "EMV transaction processing timeout exceeded",
    timeoutDuration: Long = 0,
    context: Map<String, Any> = emptyMap()
) : TimeoutException(
    message = message,
    errorCode = "EMV_TRANSACTION_TIMEOUT", 
    timeoutDuration = timeoutDuration,
    context = context,
    recoveryGuidance = "Restart transaction processing with optimized parameters"
)

/**
 * EMV Exception Logger
 * 
 * Centralized logging system for all EMV exceptions with audit trail preservation
 */
object EmvExceptionLogger {
    
    private val exceptionHistory = mutableListOf<ExceptionLogEntry>()
    
    data class ExceptionLogEntry(
        val timestamp: Long,
        val exceptionClass: String,
        val errorCode: String,
        val errorCategory: String,
        val message: String,
        val context: Map<String, Any>,
        val stackTrace: String
    )
    
    /**
     * Log exception occurrence for audit and debugging
     */
    fun logException(exception: EmvException) {
        val logEntry = ExceptionLogEntry(
            timestamp = System.currentTimeMillis(),
            exceptionClass = exception::class.java.simpleName,
            errorCode = exception.errorCode,
            errorCategory = exception.errorCategory.name,
            message = exception.message.orEmpty(),
            context = exception.context,
            stackTrace = exception.stackTraceToString()
        )
        
        exceptionHistory.add(logEntry)
        
        // Maintain reasonable history size
        if (exceptionHistory.size > 1000) {
            exceptionHistory.removeAt(0)
        }
        
        // Log to system for debugging
        println("EMV Exception Logged: ${logEntry.errorCode} - ${logEntry.message}")
    }
    
    /**
     * Get exception statistics for monitoring
     */
    fun getExceptionStatistics(): Map<String, Int> {
        return exceptionHistory.groupingBy { it.errorCode }.eachCount()
    }
    
    /**
     * Get recent exceptions for debugging
     */
    fun getRecentExceptions(count: Int = 10): List<ExceptionLogEntry> {
        return exceptionHistory.takeLast(count)
    }
    
    /**
     * Clear exception history
     */
    fun clearHistory() {
        exceptionHistory.clear()
    }
}

/**
 * EMV Exception Factory
 * 
 * Factory for creating appropriate EMV exceptions based on error conditions
 */
object EmvExceptionFactory {
    
    /**
     * Create exception from APDU status word
     */
    fun createFromStatusWord(statusWord: String, context: Map<String, Any> = emptyMap()): EmvException {
        return when (statusWord) {
            "6A82" -> ApplicationSelectionException(
                "Application not found",
                context = context
            )
            "6A81" -> DataValidationException(
                "Function not supported",
                errorCode = "EMV_FUNCTION_NOT_SUPPORTED",
                context = context,
                recoveryGuidance = "Use supported EMV command set"
            )
            "6983" -> AuthenticationException(
                "Authentication method blocked",
                errorCode = "EMV_AUTH_METHOD_BLOCKED", 
                context = context,
                recoveryGuidance = "Use alternative authentication method"
            )
            "6985" -> TransactionDeclinedException(
                "Conditions not satisfied",
                declineReason = "Transaction conditions not met",
                context = context
            )
            else -> CardCommunicationException(
                "Unexpected status word: $statusWord",
                errorCode = "EMV_UNEXPECTED_STATUS",
                context = context + mapOf("status_word" to statusWord),
                recoveryGuidance = "Check EMV specification for status word meaning"
            )
        }
    }
    
    /**
     * Create timeout exception with appropriate duration
     */
    fun createTimeoutException(operation: String, duration: Long): TimeoutException {
        return when (operation) {
            "CARD_RESPONSE" -> CardResponseTimeoutException(
                timeoutDuration = duration
            )
            "TRANSACTION" -> TransactionTimeoutException(
                timeoutDuration = duration
            )
            else -> TimeoutException(
                "Operation timeout: $operation",
                errorCode = "EMV_OPERATION_TIMEOUT",
                timeoutDuration = duration,
                recoveryGuidance = "Retry operation with extended timeout"
            )
        }
    }
}
