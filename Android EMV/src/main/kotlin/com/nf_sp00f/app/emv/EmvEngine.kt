package com.nf_sp00f.app.emv

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import timber.log.Timber
import com.nf_sp00f.app.emv.nfc.*
import com.nf_sp00f.app.emv.security.RocaSecurityScanner

/**
 * Main EMV Processing Engine for Android
 * 
 * Provides high-level EMV transaction processing capabilities supporting
 * both Android Internal NFC and external PN532 via Bluetooth UART.
 * Bridges Kotlin/Android APIs with the ported Proxmark EMV C library.
 */
class EmvEngine private constructor() {
    
    private var currentNfcProvider: INfcProvider? = null
    private var nfcConfig: NfcProviderConfig = NfcProviderConfig(NfcProviderType.ANDROID_INTERNAL)
    private val rocaScanner = RocaSecurityScanner()
    
    companion object {
        @Volatile
        private var INSTANCE: EmvEngine? = null
        
        fun getInstance(): EmvEngine {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: EmvEngine().also { INSTANCE = it }
            }
        }
        
        // Load native library
        init {
            System.loadLibrary("emvport")
        }
    }
    
    // JNI Native methods - implemented in emv_jni.cpp
    private external fun nativeInitializeEmv(): Boolean
    private external fun nativeCleanupEmv()
    private external fun nativeProcessCard(
        cardData: ByteArray,
        selectAid: String?
    ): EmvTransactionResult
    private external fun nativeGetSupportedAids(): Array<String>
    private external fun nativeValidateCertificate(
        certData: ByteArray,
        issuerCert: ByteArray
    ): Boolean
    
    /**
     * Initialize the EMV engine with NFC provider configuration
     */
    suspend fun initialize(config: NfcProviderConfig? = null): Boolean = withContext(Dispatchers.Default) {
        try {
            // Set NFC configuration
            config?.let { nfcConfig = it }
            
            // Initialize native EMV engine
            val nativeResult = nativeInitializeEmv()
            if (!nativeResult) {
                Timber.e("Failed to initialize native EMV Engine")
                return@withContext false
            }
            
            // Initialize NFC provider
            currentNfcProvider = NfcProviderFactory.createProvider(nfcConfig.type)
            val nfcResult = currentNfcProvider?.initialize(nfcConfig) ?: false
            
            if (nfcResult) {
                Timber.i("EMV Engine initialized successfully with ${nfcConfig.type}")
                true
            } else {
                Timber.e("Failed to initialize NFC provider: ${nfcConfig.type}")
                false
            }
        } catch (e: Exception) {
            Timber.e(e, "Error initializing EMV Engine")
            false
        }
    }
    
    /**
     * Configure NFC provider type and settings
     */
    suspend fun configureNfcProvider(config: NfcProviderConfig): Boolean {
        return try {
            // Cleanup current provider
            currentNfcProvider?.cleanup()
            
            // Initialize new provider
            nfcConfig = config
            currentNfcProvider = NfcProviderFactory.createProvider(config.type)
            currentNfcProvider?.initialize(config) ?: false
        } catch (e: Exception) {
            Timber.e(e, "Error configuring NFC provider")
            false
        }
    }
    
    /**
     * Auto-detect and configure best available NFC provider
     */
    suspend fun autoConfigureNfc(): Boolean {
        val detectedType = NfcProviderFactory.detectBestProvider()
        return if (detectedType != null) {
            val config = NfcProviderConfig(detectedType)
            configureNfcProvider(config)
        } else {
            Timber.e("No suitable NFC provider detected")
            false
        }
    }
    
    /**
     * Process EMV card using current NFC provider (Android Internal or PN532)
     */
    suspend fun processCard(
        tag: Tag? = null,  // For Android Internal NFC
        bluetoothAddress: String? = null,  // For PN532 Bluetooth
        transactionAmount: Long = 0L,
        currencyCode: String = "840", // USD default
        selectAid: String? = null
    ): Flow<EmvTransactionStep> = flow {
        val provider = currentNfcProvider ?: throw IllegalStateException("EMV Engine not initialized")
        
        try {
            emit(EmvTransactionStep.Connecting)
            
            // Handle different connection methods based on provider type
            when (nfcConfig.type) {
                NfcProviderType.ANDROID_INTERNAL -> {
                    if (tag == null) {
                        emit(EmvTransactionStep.Error("Android NFC requires Tag parameter", null))
                        return@flow
                    }
                    // Set tag for Android provider
                    (provider as AndroidInternalNfcProvider).setCurrentTag(tag)
                    if (!provider.connectToCardFromIntent(tag)) {
                        emit(EmvTransactionStep.Error("Failed to connect to Android NFC card", null))
                        return@flow
                    }
                }
                NfcProviderType.PN532_BLUETOOTH -> {
                    // Scan for cards with PN532
                    val cards = provider.scanForCards()
                    if (cards.isEmpty()) {
                        emit(EmvTransactionStep.Error("No cards detected by PN532", null))
                        return@flow
                    }
                    if (!provider.connectToCard(cards.first())) {
                        emit(EmvTransactionStep.Error("Failed to connect to PN532 card", null))
                        return@flow
                    }
                }
            }
            
            emit(EmvTransactionStep.SelectingApplication)
            
            // Get card info from current provider
            val cardInfo = provider.getCardInfo()
            Timber.d("Card Info (${nfcConfig.type}): $cardInfo")
            
            // Select EMV application 
            val selectResponse = if (selectAid != null) {
                provider.selectApplication(selectAid)
            } else {
                // Auto-select first available EMV application
                selectFirstEmvApplication(provider)
            }
            
            if (!selectResponse.isSuccess) {
                emit(EmvTransactionStep.Error("Application selection failed", null))
                return@flow
            }
            
            emit(EmvTransactionStep.ProcessingTransaction)
            
            // Process EMV transaction using native engine
            val cardData = buildEmvCardData(cardInfo, selectResponse)
            val result = withContext(Dispatchers.Default) {
                nativeProcessCard(cardData, selectAid)
            }
            
            when (result.status) {
                EmvTransactionStatus.SUCCESS -> {
                    emit(EmvTransactionStep.Success(result))
                }
                EmvTransactionStatus.CARD_ERROR -> {
                    emit(EmvTransactionStep.Error("Card communication error", result))
                }
                EmvTransactionStatus.AUTHENTICATION_FAILED -> {
                    emit(EmvTransactionStep.Error("Authentication failed", result))
                }
                else -> {
                    emit(EmvTransactionStep.Error("Unknown error", result))
                }
            }
            
        } catch (e: Exception) {
            Timber.e(e, "Error processing EMV card with ${nfcConfig.type}")
            emit(EmvTransactionStep.Error(e.message ?: "Unknown error", null))
        } finally {
            provider.disconnect()
        }
    }
    
    /**
     * Auto-select first available EMV application
     */
    private suspend fun selectFirstEmvApplication(provider: INfcProvider): ApduResponse {
        val commonAids = listOf(
            "A0000000031010",     // VISA
            "A0000000041010",     // MasterCard  
            "A000000025010402",   // American Express
            "A0000000651010",     // JCB
        )
        
        for (aid in commonAids) {
            try {
                val response = provider.selectApplication(aid)
                if (response.isSuccess) {
                    Timber.d("Successfully selected AID: $aid")
                    return response
                }
            } catch (e: Exception) {
                Timber.w("Failed to select AID $aid: ${e.message}")
            }
        }
        
        throw EmvCommunicationException("No supported EMV applications found")
    }
    
    /**
     * Build EMV card data from NFC provider information
     */
    private fun buildEmvCardData(cardInfo: NfcCardInfo?, selectResponse: ApduResponse): ByteArray {
        // Combine Android NFC card info with select response
        val cardData = mutableListOf<Byte>()
        
        // Add card UID
        cardInfo?.uid?.let { uid ->
            cardData.addAll(uid.hexToByteArray().toList())
        }
        
        // Add select response data
        cardData.addAll(selectResponse.data.toList())
        
        return cardData.toByteArray()
    }
    
    /**
     * Get list of supported Application Identifiers (AIDs)
     */
    fun getSupportedAids(): List<String> = try {
        nativeGetSupportedAids().toList()
    } catch (e: Exception) {
        Timber.e(e, "Error getting supported AIDs")
        emptyList()
    }
    
    /**
     * Validate EMV certificate chain
     */
    suspend fun validateCertificate(
        certData: ByteArray,
        issuerCert: ByteArray
    ): Boolean = withContext(Dispatchers.Default) {
        try {
            nativeValidateCertificate(certData, issuerCert)
        } catch (e: Exception) {
            Timber.e(e, "Error validating certificate")
            false
        }
    }
    
    /**
     * Extension function for hex string conversion  
     */
    private fun String.hexToByteArray(): ByteArray = 
        chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    
    /**
     * Get current NFC provider information
     */
    fun getNfcProviderInfo(): Pair<NfcProviderType, NfcCapabilities?> {
        return Pair(nfcConfig.type, currentNfcProvider?.getCapabilities())
    }
    
    /**
     * Check if specific NFC provider is available
     */
    suspend fun isNfcProviderAvailable(type: NfcProviderType): Boolean {
        return try {
            val testProvider = NfcProviderFactory.createProvider(type)
            val testConfig = NfcProviderConfig(type)
            val result = testProvider.initialize(testConfig)
            testProvider.cleanup()
            result
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Scan EMV certificates for ROCA vulnerability (CVE-2017-15361)
     */
    suspend fun scanForRocaVulnerability(certificates: List<EmvCertificate>): List<Pair<EmvCertificate, com.nf_sp00f.app.emv.security.RocaVulnerabilityResult>> {
        return rocaScanner.scanMultipleCertificates(certificates)
    }
    
    /**
     * Run ROCA self-test to verify vulnerability detection
     */
    suspend fun runRocaSelfTest(): Boolean {
        return rocaScanner.runSelfTest()
    }
    
    /**
     * Cleanup resources
     */
    fun cleanup() {
        try {
            runBlocking {
                currentNfcProvider?.cleanup()
            }
            nativeCleanupEmv()
            Timber.d("EMV Engine cleaned up")
        } catch (e: Exception) {
            Timber.e(e, "Error during EMV cleanup")
        }
    }
}