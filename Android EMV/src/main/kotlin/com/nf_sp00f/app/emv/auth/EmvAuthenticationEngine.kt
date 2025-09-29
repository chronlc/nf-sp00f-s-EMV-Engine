/**
 * nf-sp00f EMV Engine - Authentication Engine
 * 
 * Comprehensive EMV authentication implementation supporting SDA, DDA, and CDA.
 * Ported from Proxmark3 Iceman Fork EMV authentication functions.
 * 
 * Phase 2 Implementation: Authentication Suite (5 functions)
 * 
 * @package com.nf_sp00f.app.emv.auth
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv.auth

import com.nf_sp00f.app.emv.crypto.*
import com.nf_sp00f.app.emv.tlv.*
import com.nf_sp00f.app.emv.apdu.*
import com.nf_sp00f.app.emv.nfc.INfcProvider
import kotlinx.coroutines.*
import java.security.MessageDigest

/**
 * EMV Authentication Engine
 * 
 * Implements offline data authentication methods:
 * - SDA (Static Data Authentication)
 * - DDA (Dynamic Data Authentication) 
 * - CDA (Combined Data Authentication)
 * 
 * Ported from Proxmark3: EMVSDA(), EMVDDA(), EMVCDA()
 */
class EmvAuthenticationEngine(
    private val pkiProcessor: EmvPkiProcessor,
    private val apduBuilder: EmvApduBuilder
) {
    
    companion object {
        private const val TAG = "EmvAuthenticationEngine"
    }
    
    /**
     * Perform Static Data Authentication (SDA)
     * 
     * Ported from Proxmark3: EMVSDA()
     */
    suspend fun performSDA(cardData: EmvCardData): AuthenticationResult = withContext(Dispatchers.Default) {
        try {
            // Step 1: Extract Issuer Public Key Certificate
            val issuerCertificate = cardData.getByteArrayValue(EmvTags.ISSUER_PUBLIC_KEY_CERTIFICATE)
                ?: return@withContext AuthenticationResult.Failed("No issuer public key certificate found")
            
            // Step 2: Recover Issuer Public Key
            val issuerPublicKey = pkiProcessor.recoverIssuerPublicKey(
                issuerCertificate,
                cardData.getByteArrayValue(EmvTags.ISSUER_PUBLIC_KEY_REMAINDER),
                cardData.getByteArrayValue(EmvTags.ISSUER_PUBLIC_KEY_EXPONENT) ?: byteArrayOf(0x01, 0x00, 0x01)
            )
            
            if (issuerPublicKey == null) {
                return@withContext AuthenticationResult.Failed("Failed to recover issuer public key")
            }
            
            // Step 3: Extract Signed Static Application Data (SSAD)
            val ssad = cardData.getByteArrayValue(EmvTags.SIGNED_STATIC_APPLICATION_DATA)
                ?: return@withContext AuthenticationResult.Failed("No signed static application data found")
            
            // Step 4: Verify SSAD signature
            val staticDataToVerify = buildStaticDataForSDA(cardData)
            val verificationResult = pkiProcessor.verifyDataSignature(
                staticDataToVerify,
                ssad,
                issuerPublicKey
            )
            
            if (verificationResult) {
                AuthenticationResult.Success(
                    method = AuthenticationMethod.SDA,
                    publicKey = issuerPublicKey,
                    details = "SDA verification successful"
                )
            } else {
                AuthenticationResult.Failed("SDA signature verification failed")
            }
            
        } catch (e: Exception) {
            AuthenticationResult.Failed("SDA authentication error: ${e.message}", e)
        }
    }
    
    /**
     * Perform Dynamic Data Authentication (DDA)
     * 
     * Ported from Proxmark3: EMVDDA()
     */
    suspend fun performDDA(cardData: EmvCardData): AuthenticationResult = withContext(Dispatchers.Default) {
        try {
            // Step 1: Perform SDA first (DDA builds on SDA)
            val sdaResult = performSDA(cardData)
            if (sdaResult !is AuthenticationResult.Success) {
                return@withContext AuthenticationResult.Failed("SDA verification failed, cannot perform DDA")
            }
            
            // Step 2: Extract ICC Public Key Certificate
            val iccCertificate = cardData.getByteArrayValue(EmvTags.ICC_PUBLIC_KEY_CERTIFICATE)
                ?: return@withContext AuthenticationResult.Failed("No ICC public key certificate found")
            
            // Step 3: Recover ICC Public Key
            val iccPublicKey = pkiProcessor.recoverIccPublicKey(
                iccCertificate,
                cardData.getByteArrayValue(EmvTags.ICC_PUBLIC_KEY_REMAINDER),
                cardData.getByteArrayValue(EmvTags.ICC_PUBLIC_KEY_EXPONENT) ?: byteArrayOf(0x01, 0x00, 0x01),
                sdaResult.publicKey
            )
            
            if (iccPublicKey == null) {
                return@withContext AuthenticationResult.Failed("Failed to recover ICC public key")
            }
            
            // Step 4: Generate Internal Authenticate command
            val unpredictableNumber = EmvCryptoUtils.generateRandomBytes(4)
            val internalAuthCommand = apduBuilder.buildInternalAuthenticate(unpredictableNumber)
            
            // Step 5: This would normally be sent to the card, but for now we'll simulate
            // In real implementation: val response = nfcProvider.sendCommand(internalAuthCommand)
            val dynamicSignature = cardData.getByteArrayValue(EmvTags.SIGNED_DYNAMIC_APPLICATION_DATA)
                ?: return@withContext AuthenticationResult.Failed("No signed dynamic application data found")
            
            // Step 6: Verify dynamic signature
            val dynamicDataToVerify = buildDynamicDataForDDA(cardData, unpredictableNumber)
            val verificationResult = pkiProcessor.verifyDataSignature(
                dynamicDataToVerify,
                dynamicSignature,
                iccPublicKey
            )
            
            if (verificationResult) {
                AuthenticationResult.Success(
                    method = AuthenticationMethod.DDA,
                    publicKey = iccPublicKey,
                    details = "DDA verification successful"
                )
            } else {
                AuthenticationResult.Failed("DDA signature verification failed")
            }
            
        } catch (e: Exception) {
            AuthenticationResult.Failed("DDA authentication error: ${e.message}", e)
        }
    }
    
    /**
     * Perform Combined Data Authentication (CDA)
     * 
     * Ported from Proxmark3: EMVCDA()
     */
    suspend fun performCDA(cardData: EmvCardData): AuthenticationResult = withContext(Dispatchers.Default) {
        try {
            // Step 1: Perform DDA first (CDA builds on DDA)
            val ddaResult = performDDA(cardData)
            if (ddaResult !is AuthenticationResult.Success) {
                return@withContext AuthenticationResult.Failed("DDA verification failed, cannot perform CDA")
            }
            
            // Step 2: Extract Application Cryptogram (AC)
            val applicationCryptogram = cardData.getByteArrayValue(EmvTags.APPLICATION_CRYPTOGRAM)
                ?: return@withContext AuthenticationResult.Failed("No application cryptogram found")
            
            // Step 3: Extract Transaction Data Hash Code
            val transactionDataHashCode = cardData.getByteArrayValue(EmvTags.TRANSACTION_DATA_HASH_CODE)
                ?: return@withContext AuthenticationResult.Failed("No transaction data hash code found")
            
            // Step 4: Verify CDA signature (includes AC and transaction data)
            val cdaDataToVerify = buildCombinedDataForCDA(
                cardData, 
                applicationCryptogram, 
                transactionDataHashCode
            )
            
            val cdaSignature = cardData.getByteArrayValue(EmvTags.SIGNED_DYNAMIC_APPLICATION_DATA)
                ?: return@withContext AuthenticationResult.Failed("No CDA signature found")
            
            val verificationResult = pkiProcessor.verifyDataSignature(
                cdaDataToVerify,
                cdaSignature,
                ddaResult.publicKey
            )
            
            if (verificationResult) {
                AuthenticationResult.Success(
                    method = AuthenticationMethod.CDA,
                    publicKey = ddaResult.publicKey,
                    details = "CDA verification successful - transaction data integrity confirmed"
                )
            } else {
                AuthenticationResult.Failed("CDA signature verification failed")
            }
            
        } catch (e: Exception) {
            AuthenticationResult.Failed("CDA authentication error: ${e.message}", e)
        }
    }
    
    /**
     * Build static data for SDA verification
     */
    private fun buildStaticDataForSDA(cardData: EmvCardData): ByteArray {
        val dataBuilder = mutableListOf<Byte>()
        
        // Add AFL records used for authentication
        val aflRecords = cardData.getAuthenticationRecords()
        for (record in aflRecords) {
            dataBuilder.addAll(record.toList())
        }
        
        return dataBuilder.toByteArray()
    }
    
    /**
     * Build dynamic data for DDA verification
     */
    private fun buildDynamicDataForDDA(cardData: EmvCardData, unpredictableNumber: ByteArray): ByteArray {
        val staticData = buildStaticDataForSDA(cardData)
        val dataBuilder = mutableListOf<Byte>()
        
        // Add static data
        dataBuilder.addAll(staticData.toList())
        
        // Add unpredictable number
        dataBuilder.addAll(unpredictableNumber.toList())
        
        return dataBuilder.toByteArray()
    }
    
    /**
     * Build combined data for CDA verification
     */
    private fun buildCombinedDataForCDA(
        cardData: EmvCardData,
        applicationCryptogram: ByteArray,
        transactionDataHashCode: ByteArray
    ): ByteArray {
        val staticData = buildStaticDataForSDA(cardData)
        val dataBuilder = mutableListOf<Byte>()
        
        // Add static data
        dataBuilder.addAll(staticData.toList())
        
        // Add application cryptogram
        dataBuilder.addAll(applicationCryptogram.toList())
        
        // Add transaction data hash code
        dataBuilder.addAll(transactionDataHashCode.toList())
        
        return dataBuilder.toByteArray()
    }
}

/**
 * Authentication Method Detector
 * 
 * Determines which authentication method to use based on card capabilities
 */
class AuthenticationMethodDetector {
    
    /**
     * Detect supported authentication method from AIP and card data
     */
    fun detectAuthenticationMethod(aip: ByteArray, cardData: EmvCardData): AuthenticationMethod {
        if (aip.isEmpty()) return AuthenticationMethod.NONE
        
        val aipByte1 = aip[0].toInt() and 0xFF
        
        return when {
            // Check for CDA support (bit 1 of AIP byte 1)
            (aipByte1 and 0x01) != 0 -> {
                if (cardData.hasTag(EmvTags.ICC_PUBLIC_KEY_CERTIFICATE)) {
                    AuthenticationMethod.CDA
                } else {
                    AuthenticationMethod.DDA
                }
            }
            // Check for DDA support (bit 2 of AIP byte 1)  
            (aipByte1 and 0x02) != 0 -> {
                if (cardData.hasTag(EmvTags.ICC_PUBLIC_KEY_CERTIFICATE)) {
                    AuthenticationMethod.DDA
                } else {
                    AuthenticationMethod.SDA
                }
            }
            // Check for SDA support (bit 6 of AIP byte 1)
            (aipByte1 and 0x40) != 0 -> AuthenticationMethod.SDA
            // No authentication supported
            else -> AuthenticationMethod.NONE
        }
    }
}

/**
 * Authentication method enumeration
 */
enum class AuthenticationMethod {
    NONE,
    SDA,    // Static Data Authentication
    DDA,    // Dynamic Data Authentication  
    CDA     // Combined Data Authentication
}

/**
 * Authentication result sealed class
 */
sealed class AuthenticationResult {
    data class Success(
        val method: AuthenticationMethod,
        val publicKey: EmvPublicKey,
        val details: String
    ) : AuthenticationResult()
    
    data class Failed(
        val reason: String,
        val exception: Throwable? = null
    ) : AuthenticationResult()
    
    data class NoAuthentication(
        val reason: String
    ) : AuthenticationResult()
}
