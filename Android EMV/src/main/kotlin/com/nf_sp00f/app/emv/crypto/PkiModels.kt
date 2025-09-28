/**
 * nf-sp00f EMV Engine - PKI Models
 * 
 * Public Key Infrastructure data models for EMV certificate processing.
 * Implements EMV certificate chain validation and key recovery.
 * 
 * @package com.nf_sp00f.app.emv.crypto
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv.crypto

import java.math.BigInteger
import java.security.PublicKey
import java.security.interfaces.RSAPublicKey

/**
 * EMV Public Key representation
 * Ported from: struct emv_pk
 */
data class EmvPublicKey(
    val rid: ByteArray,                    // Registered Application Provider Identifier (5 bytes)
    val index: UByte,                      // CA Public Key Index
    val hashAlgorithm: HashAlgorithm,      // Hash algorithm indicator
    val algorithm: PublicKeyAlgorithm,     // Public key algorithm
    val modulus: ByteArray,                // RSA modulus (N)
    val exponent: ByteArray,               // RSA public exponent (e)
    val expiryDate: String? = null,        // Expiration date (MMDDYYYY)
    val checksum: ByteArray? = null        // SHA-1 hash of modulus and exponent
) {
    
    companion object {
        const val RID_LENGTH = 5
        const val DEFAULT_EXPONENT = 65537 // 0x010001
        
        /**
         * Create EMV public key from RSA components
         */
        fun fromRsaComponents(
            rid: ByteArray,
            index: UByte,
            modulus: ByteArray,
            exponent: ByteArray = byteArrayOf(0x01, 0x00, 0x01) // Default F4
        ): EmvPublicKey {
            require(rid.size == RID_LENGTH) { "RID must be exactly $RID_LENGTH bytes" }
            
            return EmvPublicKey(
                rid = rid,
                index = index,
                hashAlgorithm = HashAlgorithm.SHA1,
                algorithm = PublicKeyAlgorithm.RSA,
                modulus = modulus,
                exponent = exponent
            )
        }
        
        /**
         * Create EMV public key from Java RSAPublicKey
         */
        fun fromJavaRsaKey(
            rid: ByteArray,
            index: UByte,
            rsaKey: RSAPublicKey
        ): EmvPublicKey {
            val modulus = rsaKey.modulus.toByteArray().removeLeadingZeros()
            val exponent = rsaKey.publicExponent.toByteArray().removeLeadingZeros()
            
            return fromRsaComponents(rid, index, modulus, exponent)
        }
        
        private fun ByteArray.removeLeadingZeros(): ByteArray {
            val firstNonZero = indexOfFirst { it != 0.toByte() }
            return if (firstNonZero > 0) sliceArray(firstNonZero until size) else this
        }
    }
    
    /**
     * Get modulus as BigInteger
     */
    val modulusBigInt: BigInteger
        get() = BigInteger(1, modulus)
    
    /**
     * Get exponent as BigInteger
     */
    val exponentBigInt: BigInteger
        get() = BigInteger(1, exponent)
    
    /**
     * Get key length in bits
     */
    val keyLengthBits: Int
        get() = modulus.size * 8
    
    /**
     * Get key length in bytes
     */
    val keyLengthBytes: Int
        get() = modulus.size
    
    /**
     * Convert to Java RSAPublicKey
     */
    fun toJavaRsaKey(): RSAPublicKey {
        val keySpec = java.security.spec.RSAPublicKeySpec(modulusBigInt, exponentBigInt)
        val keyFactory = java.security.KeyFactory.getInstance("RSA")
        return keyFactory.generatePublic(keySpec) as RSAPublicKey
    }
    
    /**
     * Verify key integrity using checksum
     */
    fun verifyChecksum(): Boolean {
        if (checksum == null) return true // No checksum to verify
        
        val calculatedChecksum = calculateChecksum()
        return checksum.contentEquals(calculatedChecksum)
    }
    
    /**
     * Calculate SHA-1 checksum of modulus and exponent
     */
    private fun calculateChecksum(): ByteArray {
        val digest = java.security.MessageDigest.getInstance("SHA-1")
        digest.update(modulus)
        digest.update(exponent)
        return digest.digest()
    }
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EmvPublicKey) return false
        
        return rid.contentEquals(other.rid) &&
               index == other.index &&
               hashAlgorithm == other.hashAlgorithm &&
               algorithm == other.algorithm &&
               modulus.contentEquals(other.modulus) &&
               exponent.contentEquals(other.exponent)
    }
    
    override fun hashCode(): Int {
        var result = rid.contentHashCode()
        result = 31 * result + index.hashCode()
        result = 31 * result + hashAlgorithm.hashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + modulus.contentHashCode()
        result = 31 * result + exponent.contentHashCode()
        return result
    }
    
    override fun toString(): String {
        return "EmvPublicKey(RID=${rid.joinToString("") { "%02X".format(it) }}, " +
               "Index=$index, Algorithm=$algorithm, KeyLength=${keyLengthBits}bits)"
    }
}

/**
 * EMV Certificate types
 */
enum class EmvCertificateType(val code: UByte) {
    CA_CERTIFICATE(0x02u),           // Certification Authority
    ISSUER_CERTIFICATE(0x02u),       // Issuer Certificate  
    ICC_CERTIFICATE(0x04u),          // Integrated Circuit Card Certificate
    ICC_PIN_ENCIPHERMENT(0x04u)      // ICC PIN Encipherment Certificate
}

/**
 * EMV Certificate representation
 * Ported from certificate processing functions
 */
data class EmvCertificate(
    val type: EmvCertificateType,
    val format: CertificateFormat,
    val data: ByteArray,
    val remainder: ByteArray? = null,
    val exponent: ByteArray? = null,
    val recoveredData: CertificateData? = null
) {
    
    /**
     * Check if certificate is valid format
     */
    val isValidFormat: Boolean
        get() = data.isNotEmpty() && 
                data[0] == 0x6A.toByte() && 
                data[data.size - 1] == 0xBC.toByte()
    
    /**
     * Get certificate serial number
     */
    val serialNumber: ByteArray?
        get() = recoveredData?.serialNumber
    
    /**
     * Get certificate expiry date
     */
    val expiryDate: String?
        get() = recoveredData?.expiryDate
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EmvCertificate) return false
        
        return type == other.type &&
               format == other.format &&
               data.contentEquals(other.data)
    }
    
    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + format.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }
}

/**
 * Certificate formats
 */
enum class CertificateFormat {
    RSA_STANDARD,      // Standard RSA certificate
    RSA_WITH_REMAINDER // RSA certificate with remainder
}

/**
 * Recovered certificate data
 */
data class CertificateData(
    val certificateFormat: UByte,
    val applicationPan: ByteArray?,
    val certificateExpirationDate: String?,
    val certificateSerialNumber: ByteArray?,
    val hashAlgorithmIndicator: UByte,
    val issuerPublicKeyAlgorithm: UByte,
    val issuerPublicKeyLength: UByte,
    val issuerPublicKeyOrLeftmostDigits: ByteArray,
    val pad: ByteArray?
) {
    val serialNumber: ByteArray?
        get() = certificateSerialNumber
    
    val expiryDate: String?
        get() = certificateExpirationDate
}

/**
 * Supported hash algorithms
 */
enum class HashAlgorithm(val indicator: UByte) {
    SHA1(0x01u),
    SHA224(0x02u),
    SHA256(0x03u),
    SHA384(0x04u),
    SHA512(0x05u);
    
    companion object {
        fun fromIndicator(indicator: UByte): HashAlgorithm {
            return values().find { it.indicator == indicator } ?: SHA1
        }
    }
    
    val algorithmName: String
        get() = when (this) {
            SHA1 -> "SHA-1"
            SHA224 -> "SHA-224"
            SHA256 -> "SHA-256"
            SHA384 -> "SHA-384"
            SHA512 -> "SHA-512"
        }
}

/**
 * Supported public key algorithms  
 */
enum class PublicKeyAlgorithm(val indicator: UByte) {
    RSA(0x01u),
    DSA(0x02u),
    ECDSA(0x03u);
    
    companion object {
        fun fromIndicator(indicator: UByte): PublicKeyAlgorithm {
            return values().find { it.indicator == indicator } ?: RSA
        }
    }
}

/**
 * Certificate recovery results
 */
sealed class CertificateRecoveryResult {
    data class Success(
        val certificate: EmvCertificate,
        val publicKey: EmvPublicKey
    ) : CertificateRecoveryResult()
    
    data class Failed(
        val reason: String,
        val details: String? = null
    ) : CertificateRecoveryResult()
}

/**
 * PKI validation results
 */
sealed class PkiValidationResult {
    object Valid : PkiValidationResult()
    
    data class Invalid(
        val reason: String,
        val failedChecks: List<String> = emptyList()
    ) : PkiValidationResult()
    
    data class Warning(
        val message: String,
        val warnings: List<String> = emptyList()
    ) : PkiValidationResult()
}

/**
 * CA (Certification Authority) Public Key Database Entry
 */
data class CaPublicKey(
    val rid: ByteArray,
    val index: UByte,
    val publicKey: EmvPublicKey,
    val description: String? = null,
    val isActive: Boolean = true
) {
    
    /**
     * Get unique identifier for this CA key
     */
    val identifier: String
        get() = "${rid.joinToString("") { "%02X".format(it) }}_${index.toString(16).padStart(2, '0').uppercase()}"
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CaPublicKey) return false
        
        return rid.contentEquals(other.rid) && index == other.index
    }
    
    override fun hashCode(): Int {
        var result = rid.contentHashCode()
        result = 31 * result + index.hashCode()
        return result
    }
}

/**
 * SDA (Static Data Authentication) Tag List
 */
data class SdaTagList(
    val tags: List<UInt>,
    val data: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SdaTagList) return false
        
        return tags == other.tags && data.contentEquals(other.data)
    }
    
    override fun hashCode(): Int {
        var result = tags.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }
}