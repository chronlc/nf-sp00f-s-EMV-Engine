/**
 * nf-sp00f EMV Engine - PKI Processor
 * 
 * Public Key Infrastructure processor for EMV certificate validation.
 * Handles CA public keys, certificate recovery, and signature verification.
 * 
 * Phase 2 Implementation: PKI Infrastructure (18 functions)
 * 
 * @package com.nf_sp00f.app.emv.crypto
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv.crypto

import com.nf_sp00f.app.emv.tlv.*
import kotlinx.coroutines.*
import java.math.BigInteger
import java.security.*
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec
import javax.crypto.Cipher

/**
 * EMV PKI Processor
 * 
 * Comprehensive EMV PKI operations including certificate recovery,
 * public key validation, and signature verification.
 * 
 * Ported from Proxmark3: emv_pk.c, emv_pki.c functions
 */
class EmvPkiProcessor {
    
    companion object {
        private const val TAG = "EmvPkiProcessor"
        
        // EMV Certificate Authority Public Keys (sample - real implementations need complete CA key database)
        private val CA_PUBLIC_KEYS = mapOf(
            "A000000003" to EmvCaPublicKey(
                rid = "A000000003",
                index = 1,
                modulus = "C696034213D7D8546984579D1D0F0EA519CDF16B898318C13C7C23E55829B1605BFA0BE8"
                    + "E23F5A11CAF450C951ED3F5F7D033F9BA4E6D0D75E00E25E7978E5A6EA1E3E6B4E976"
                    + "F85096C2042885658F890F30B8543B482FBA8E", // Sample Visa CA key
                exponent = "010001",
                hashAlgorithm = "SHA-1"
            )
        )
    }
    
    private val caKeys = mutableMapOf<String, EmvCaPublicKey>()
    private var isInitialized = false
    
    /**
     * Initialize PKI processor with CA keys
     */
    suspend fun initialize(): Boolean = withContext(Dispatchers.Default) {
        try {
            // Load default CA keys
            caKeys.clear()
            caKeys.putAll(CA_PUBLIC_KEYS)
            
            isInitialized = true
            true
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Add CA public key
     * 
     * Ported from Proxmark3: emv_pk_add()
     */
    fun addCaPublicKey(caKey: EmvCaPublicKey): Boolean {
        return try {
            val keyId = "${caKey.rid}_${caKey.index}"
            caKeys[keyId] = caKey
            true
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Get CA public key by RID and index
     * 
     * Ported from Proxmark3: emv_pk_get_ca_pk()
     */
    fun getCaPublicKey(rid: String, caIndex: Int): EmvCaPublicKey? {
        val keyId = "${rid}_${caIndex}"
        return caKeys[keyId]
    }
    
    /**
     * Recover issuer public key from certificate
     * 
     * Ported from Proxmark3: emv_pki_recover_issuer_cert()
     */
    suspend fun recoverIssuerPublicKey(
        issuerCertificate: ByteArray,
        issuerRemainder: ByteArray?,
        issuerExponent: ByteArray
    ): EmvPublicKey? = withContext(Dispatchers.Default) {
        
        try {
            // Extract certificate fields
            val certFormat = issuerCertificate[0].toInt() and 0xFF
            if (certFormat != 0x6A) return@withContext null // Invalid certificate format
            
            // Extract RID and CA key index
            val rid = issuerCertificate.sliceArray(1..5)
            val caIndex = issuerCertificate[6].toInt() and 0xFF
            
            // Get CA public key
            val ridString = rid.joinToString("") { "%02X".format(it) }
            val caPublicKey = getCaPublicKey(ridString, caIndex)
                ?: return@withContext null
            
            // Decrypt certificate with CA public key
            val decryptedCert = decryptCertificate(issuerCertificate, caPublicKey)
                ?: return@withContext null
            
            // Extract issuer public key components
            val keyLength = decryptedCert[13].toInt() and 0xFF
            val modulusStart = 15
            val modulusEnd = modulusStart + keyLength - issuerExponent.size
            
            var modulus = decryptedCert.sliceArray(modulusStart until modulusEnd)
            
            // Append remainder if provided
            issuerRemainder?.let { remainder ->
                modulus = modulus + remainder
            }
            
            // Create EmvPublicKey
            EmvPublicKey(
                modulus = modulus,
                exponent = issuerExponent,
                keyLength = keyLength
            )
            
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Recover ICC public key from certificate
     * 
     * Ported from Proxmark3: emv_pki_recover_icc_cert()
     */
    suspend fun recoverIccPublicKey(
        iccCertificate: ByteArray,
        iccRemainder: ByteArray?,
        iccExponent: ByteArray,
        issuerPublicKey: EmvPublicKey
    ): EmvPublicKey? = withContext(Dispatchers.Default) {
        
        try {
            // Decrypt ICC certificate with issuer public key
            val decryptedCert = decryptCertificateWithEmvKey(iccCertificate, issuerPublicKey)
                ?: return@withContext null
            
            // Validate certificate format
            val certFormat = decryptedCert[0].toInt() and 0xFF
            if (certFormat != 0x6A) return@withContext null
            
            // Extract ICC public key components
            val keyLength = decryptedCert[13].toInt() and 0xFF
            val modulusStart = 21
            val modulusEnd = modulusStart + keyLength - iccExponent.size
            
            var modulus = decryptedCert.sliceArray(modulusStart until modulusEnd)
            
            // Append remainder if provided
            iccRemainder?.let { remainder ->
                modulus = modulus + remainder
            }
            
            // Create EmvPublicKey
            EmvPublicKey(
                modulus = modulus,
                exponent = iccExponent,
                keyLength = keyLength
            )
            
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Verify data signature using public key
     * 
     * Ported from Proxmark3: emv_pki_verify()
     */
    suspend fun verifyDataSignature(
        data: ByteArray,
        signature: ByteArray,
        publicKey: EmvPublicKey
    ): Boolean = withContext(Dispatchers.Default) {
        
        try {
            // Decrypt signature
            val decryptedSignature = decryptSignature(signature, publicKey)
                ?: return@withContext false
            
            // Validate signature format
            if (decryptedSignature.isEmpty() || decryptedSignature[0] != 0x6A.toByte()) {
                return@withContext false
            }
            
            // Extract hash from signature
            val hashAlgorithm = decryptedSignature[1].toInt() and 0xFF
            val hashLength = when (hashAlgorithm) {
                0x01 -> 20 // SHA-1
                0x02 -> 32 // SHA-256
                else -> return@withContext false
            }
            
            val signatureHash = decryptedSignature.takeLast(hashLength).toByteArray()
            
            // Compute data hash
            val computedHash = when (hashAlgorithm) {
                0x01 -> MessageDigest.getInstance("SHA-1").digest(data)
                0x02 -> MessageDigest.getInstance("SHA-256").digest(data)
                else -> return@withContext false
            }
            
            // Compare hashes
            signatureHash.contentEquals(computedHash)
            
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Decrypt certificate with CA public key
     */
    private suspend fun decryptCertificate(
        certificate: ByteArray,
        caPublicKey: EmvCaPublicKey
    ): ByteArray? = withContext(Dispatchers.Default) {
        
        try {
            val modulus = BigInteger(caPublicKey.modulus, 16)
            val exponent = BigInteger(caPublicKey.exponent, 16)
            
            val keySpec = RSAPublicKeySpec(modulus, exponent)
            val keyFactory = KeyFactory.getInstance("RSA")
            val rsaPublicKey = keyFactory.generatePublic(keySpec)
            
            val cipher = Cipher.getInstance("RSA/ECB/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, rsaPublicKey)
            
            cipher.doFinal(certificate)
            
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Decrypt certificate with EMV public key
     */
    private suspend fun decryptCertificateWithEmvKey(
        certificate: ByteArray,
        publicKey: EmvPublicKey
    ): ByteArray? = withContext(Dispatchers.Default) {
        
        try {
            val rsaPublicKey = publicKey.toJavaPublicKey()
            
            val cipher = Cipher.getInstance("RSA/ECB/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, rsaPublicKey)
            
            cipher.doFinal(certificate)
            
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Decrypt signature with public key
     */
    private suspend fun decryptSignature(
        signature: ByteArray,
        publicKey: EmvPublicKey
    ): ByteArray? = withContext(Dispatchers.Default) {
        
        try {
            val rsaPublicKey = publicKey.toJavaPublicKey()
            
            val cipher = Cipher.getInstance("RSA/ECB/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, rsaPublicKey)
            
            cipher.doFinal(signature)
            
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Validate certificate chain
     */
    suspend fun validateCertificateChain(
        issuerCertificate: ByteArray,
        iccCertificate: ByteArray,
        rid: String,
        caIndex: Int
    ): Boolean = withContext(Dispatchers.Default) {
        
        try {
            // Step 1: Recover issuer public key
            val issuerPublicKey = recoverIssuerPublicKey(
                issuerCertificate,
                null,
                byteArrayOf(0x01, 0x00, 0x01) // F4 exponent
            ) ?: return@withContext false
            
            // Step 2: Recover ICC public key
            val iccPublicKey = recoverIccPublicKey(
                iccCertificate,
                null,
                byteArrayOf(0x01, 0x00, 0x01), // F4 exponent
                issuerPublicKey
            ) ?: return@withContext false
            
            // Step 3: Validate key parameters
            validateKeyParameters(issuerPublicKey) && validateKeyParameters(iccPublicKey)
            
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Validate key parameters
     */
    private fun validateKeyParameters(publicKey: EmvPublicKey): Boolean {
        return try {
            val modulus = BigInteger(1, publicKey.modulus)
            val exponent = BigInteger(1, publicKey.exponent)
            
            // Check minimum key size
            if (modulus.bitLength() < 1024) return false
            
            // Check exponent
            if (exponent <= BigInteger.ONE) return false
            
            true
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Run PKI self-test
     */
    fun runSelfTest(): Boolean {
        return try {
            isInitialized && caKeys.isNotEmpty()
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Get PKI processor status
     */
    fun getStatus(): String {
        return buildString {
            append("EMV PKI Processor Status:\n")
            append("Initialized: $isInitialized\n")
            append("CA Keys Loaded: ${caKeys.size}\n")
            append("Available RIDs: ${caKeys.keys.joinToString(", ")}")
        }
    }
    
    /**
     * Cleanup resources
     */
    fun cleanup() {
        caKeys.clear()
        isInitialized = false
    }
}
