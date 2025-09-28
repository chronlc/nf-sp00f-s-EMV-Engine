package com.nf_sp00f.app.emv

/**
 * EMV Transaction processing steps
 */
sealed class EmvTransactionStep {
    object Connecting : EmvTransactionStep()
    object SelectingApplication : EmvTransactionStep()
    object ProcessingTransaction : EmvTransactionStep()
    object AuthenticatingCard : EmvTransactionStep()
    object ValidatingCertificates : EmvTransactionStep()
    
    data class Success(val result: EmvTransactionResult) : EmvTransactionStep()
    data class Error(val message: String, val result: EmvTransactionResult?) : EmvTransactionStep()
}

/**
 * EMV Transaction status codes
 */
enum class EmvTransactionStatus {
    SUCCESS,
    CARD_ERROR,
    AUTHENTICATION_FAILED,
    CERTIFICATE_INVALID,
    UNSUPPORTED_CARD,
    COMMUNICATION_ERROR,
    TIMEOUT,
    UNKNOWN_ERROR
}

/**
 * EMV Transaction types
 */
enum class EmvTransactionType {
    MSD,        // Magnetic Stripe Data
    VSDC,       // Visa Smart Debit/Credit
    QVSDC,      // qVSDC (contactless)
    CDA         // Combined Data Authentication
}

/**
 * EMV Card vendor identification
 */
enum class EmvCardVendor {
    UNKNOWN,
    VISA,
    MASTERCARD,
    AMERICAN_EXPRESS,
    JCB,
    CB,
    SWITCH,
    DINERS,
    OTHER
}

/**
 * Complete EMV transaction result
 */
/**
 * EMV transaction processing results
 */
sealed class EmvTransactionResult {
    data class Success(
        val cardData: EmvCardData,
        val authenticationResult: AuthenticationResult,
        val riskResult: RiskManagementResult,
        val actionResult: ActionAnalysisResult,
        val transactionAmount: Long,
        val currencyCode: String,
        val transactionType: TransactionType
    ) : EmvTransactionResult()
    
    data class Error(
        val message: String,
        val exception: Throwable? = null
    ) : EmvTransactionResult()
    
    data class RocaVulnerable(
        val rocaResult: RocaVulnerabilityResult
    ) : EmvTransactionResult()
}

/**
 * EMV Certificate information
 */
data class EmvCertificate(
    val type: CertificateType,
    val data: ByteArray,
    val isValid: Boolean,
    val issuer: String?,
    val subject: String?,
    val keyUsage: List<String>
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as EmvCertificate

        if (type != other.type) return false
        if (!data.contentEquals(other.data)) return false
        if (isValid != other.isValid) return false
        if (issuer != other.issuer) return false
        if (subject != other.subject) return false
        if (keyUsage != other.keyUsage) return false

        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + data.contentHashCode()
        result = 31 * result + isValid.hashCode()
        result = 31 * result + (issuer?.hashCode() ?: 0)
        result = 31 * result + (subject?.hashCode() ?: 0)
        result = 31 * result + keyUsage.hashCode()
        return result
    }
}

/**
 * EMV Certificate types
 */
enum class CertificateType {
    CA_CERTIFICATE,
    ISSUER_CERTIFICATE,
    ICC_CERTIFICATE
}

/**
 * EMV Application Information
 */
data class EmvApplication(
    val aid: String,
    val label: String?,
    val preferredName: String? = null,
    val priority: Int,
    val vendor: EmvCardVendor = EmvCardVendor.UNKNOWN,
    val isSupported: Boolean = true
)

/**
 * EMV card data extracted from transaction
 */
data class EmvCardData(
    val pan: String,
    val expiryDate: String,
    val cardholderName: String,
    val applicationLabel: String,
    val track2Data: String? = null,
    val issuerCountryCode: String? = null,
    val applicationInterchangeProfile: ByteArray? = null,
    val tlvDatabase: com.nf_sp00f.app.emv.tlv.TlvDatabase? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EmvCardData) return false
        
        return pan == other.pan &&
               expiryDate == other.expiryDate &&
               cardholderName == other.cardholderName &&
               applicationLabel == other.applicationLabel &&
               track2Data == other.track2Data &&
               issuerCountryCode == other.issuerCountryCode &&
               applicationInterchangeProfile?.contentEquals(other.applicationInterchangeProfile) == true
    }
    
    override fun hashCode(): Int {
        var result = pan.hashCode()
        result = 31 * result + expiryDate.hashCode()
        result = 31 * result + cardholderName.hashCode()
        result = 31 * result + applicationLabel.hashCode()
        result = 31 * result + (track2Data?.hashCode() ?: 0)
        result = 31 * result + (issuerCountryCode?.hashCode() ?: 0)
        result = 31 * result + (applicationInterchangeProfile?.contentHashCode() ?: 0)
        return result
    }
}

/**
 * EMV Processing Options from GPO response
 */
data class ProcessingOptions(
    val aip: ByteArray, // Application Interchange Profile
    val afl: List<FileRecord>  // Application File Locator parsed
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ProcessingOptions) return false
        return aip.contentEquals(other.aip) && afl == other.afl
    }
    
    override fun hashCode(): Int {
        var result = aip.contentHashCode()
        result = 31 * result + afl.hashCode()
        return result
    }
}

/**
 * File record information from AFL
 */
data class FileRecord(
    val sfi: Int,        // Short File Identifier
    val firstRecord: Int, // First record number
    val lastRecord: Int,  // Last record number
    val offlineRecords: Int // Number of records for offline authentication
)

/**
 * Transaction types
 */
enum class TransactionType(val code: UByte) {
    PURCHASE(0x00u),
    CASH_ADVANCE(0x01u),
    REFUND(0x20u),
    BALANCE_INQUIRY(0x31u),
    PAYMENT(0x50u)
}

/**
 * Authentication types
 */
enum class AuthenticationType {
    NONE,
    SDA,  // Static Data Authentication
    DDA,  // Dynamic Data Authentication
    CDA   // Combined Data Authentication
}

/**
 * Authentication results
 */
sealed class AuthenticationResult {
    data class Success(val type: AuthenticationType) : AuthenticationResult()
    data class Failed(val reason: String) : AuthenticationResult()
    object NotRequired : AuthenticationResult()
}

/**
 * Application selection results
 */
sealed class ApplicationSelectionResult {
    data class Success(val application: EmvApplication) : ApplicationSelectionResult()
    data class Error(val message: String) : ApplicationSelectionResult()
}

/**
 * Processing results
 */
sealed class ProcessingResult {
    data class Success(val options: ProcessingOptions) : ProcessingResult()
    data class Error(val message: String) : ProcessingResult()
}

/**
 * Risk management result
 */
sealed class RiskManagementResult {
    object Approved : RiskManagementResult()
    object Declined : RiskManagementResult()
    data class Refer(val reason: String) : RiskManagementResult()
}

/**
 * Action analysis result
 */
sealed class ActionAnalysisResult {
    object Approved : ActionAnalysisResult()
    object Declined : ActionAnalysisResult()
    data class OnlineRequired(val reason: String) : ActionAnalysisResult()
}

/**
 * ROCA vulnerability result
 */
data class RocaVulnerabilityResult(
    val isVulnerable: Boolean,
    val keyModulus: String?,
    val confidence: Double,
    val details: String
)

/**
 * EMV engine configuration
 */
data class EmvConfiguration(
    val enableRocaCheck: Boolean = true,
    val timeoutMs: Long = 30000,
    val maxRetries: Int = 3,
    val strictValidation: Boolean = false,
    val enableLogging: Boolean = false
)

/**
 * Empty processing options for compatibility
 */
class EmptyProcessingOptions : ProcessingOptions(byteArrayOf(), emptyList())