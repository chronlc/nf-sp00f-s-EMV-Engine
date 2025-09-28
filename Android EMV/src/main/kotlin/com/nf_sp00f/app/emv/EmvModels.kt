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
data class EmvTransactionResult(
    val status: EmvTransactionStatus,
    val transactionType: EmvTransactionType?,
    val cardVendor: EmvCardVendor,
    val applicationId: String?,
    val cardholderName: String?,
    val pan: String?,
    val expiryDate: String?,
    val applicationLabel: String?,
    val issuerCountryCode: String?,
    val currencyCode: String?,
    val amount: Long?,
    val authenticationMethods: List<String>,
    val certificates: List<EmvCertificate>,
    val tlvData: Map<String, ByteArray>,
    val errorMessage: String?
)

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
    val preferredName: String?,
    val priority: Int,
    val vendor: EmvCardVendor,
    val isSupported: Boolean
)