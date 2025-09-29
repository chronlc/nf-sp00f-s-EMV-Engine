/**
 * nf-sp00f EMV Engine - PKI Models
 * 
 * Data models for Public Key Infrastructure operations.
 * Includes CA keys, public keys, and certificate structures.
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
 * EMV Certificate Authority Public Key
 */
data class EmvCaPublicKey(
    val rid: String,
    val index: Int,
    val modulus: String,
    val exponent: String,
    val hashAlgorithm: String
)

/**
 * EMV Public Key representation
 */
data class EmvPublicKey(
    val modulus: ByteArray,
    val exponent: ByteArray,
    val keyLength: Int
) {
    
    /**
     * Convert to Java RSA PublicKey
     */
    fun toJavaPublicKey(): RSAPublicKey {
        val modulusBigInt = BigInteger(1, modulus)
        val exponentBigInt = BigInteger(1, exponent)
        
        val keySpec = java.security.spec.RSAPublicKeySpec(modulusBigInt, exponentBigInt)
        val keyFactory = java.security.KeyFactory.getInstance("RSA")
        
        return keyFactory.generatePublic(keySpec) as RSAPublicKey
    }
    
    /**
     * Get key size in bits
     */
    fun getKeySize(): Int {
        return BigInteger(1, modulus).bitLength()
    }
    
    /**
     * Get key parameter
     */
    fun getKeyParameter(parameter: RsaKeyParameter): ByteArray {
        return when (parameter) {
            RsaKeyParameter.MODULUS -> modulus
            RsaKeyParameter.PUBLIC_EXPONENT -> exponent
        }
    }
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        
        other as EmvPublicKey
        
        if (!modulus.contentEquals(other.modulus)) return false
        if (!exponent.contentEquals(other.exponent)) return false
        if (keyLength != other.keyLength) return false
        
        return true
    }
    
    override fun hashCode(): Int {
        var result = modulus.contentHashCode()
        result = 31 * result + exponent.contentHashCode()
        result = 31 * result + keyLength
        return result
    }
}

/**
 * RSA key parameter enumeration
 */
enum class RsaKeyParameter {
    MODULUS,
    PUBLIC_EXPONENT
}
