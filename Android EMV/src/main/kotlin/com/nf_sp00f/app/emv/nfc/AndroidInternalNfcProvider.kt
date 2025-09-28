package com.nf_sp00f.app.emv.nfc

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.nfc.tech.NfcA
import android.nfc.tech.NfcB
import kotlinx.coroutines.*
import timber.log.Timber

/**
 * Android Internal NFC Provider
 * 
 * This class implements NFC operations using Android's built-in NFC adapter.
 * It provides a unified interface that matches external PN532 capabilities.
 */
class AndroidInternalNfcProvider : INfcProvider {
    
    private var isoDep: IsoDep? = null
    private var currentCard: NfcCardInfo? = null
    private var currentTag: Tag? = null
    private var config: NfcProviderConfig? = null
    
    override suspend fun initialize(config: NfcProviderConfig): Boolean = withContext(Dispatchers.Main) {
        this@AndroidInternalNfcProvider.config = config
        
        try {
            // Check if NFC is available
            val nfcAdapter = NfcAdapter.getDefaultAdapter(null) // Context needed in real implementation
            if (nfcAdapter == null) {
                Timber.e("NFC not supported on this device")
                return@withContext false
            }
            
            if (!nfcAdapter.isEnabled) {
                Timber.e("NFC is disabled")
                return@withContext false
            }
            
            Timber.i("Android Internal NFC initialized successfully")
            return@withContext true
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to initialize Android Internal NFC")
            return@withContext false
        }
    }
    
    override fun isReady(): Boolean {
        // For Android NFC, we're ready when a card is present
        return currentTag != null
    }
    
    override suspend fun scanForCards(): List<NfcCardInfo> {
        // Android NFC doesn't actively scan - cards are detected via intent system
        // This method is mainly for compatibility with PN532 interface
        return currentCard?.let { listOf(it) } ?: emptyList()
    }
    
    /**
     * Connect to card using Android NFC Tag
     */
    fun connectToCardFromIntent(tag: Tag): Boolean {
        return runBlocking { connectToCard(parseTagToCardInfo(tag)) }
    }
    
    override suspend fun connectToCard(cardInfo: NfcCardInfo): Boolean = withContext(Dispatchers.IO) {
        try {
            val tag = currentTag ?: throw IllegalStateException("No tag available")
            
            // Check if tag supports ISO-DEP (required for EMV)
            if (!tag.techList.contains(IsoDep::class.java.name)) {
                Timber.w("Tag does not support ISO-DEP, EMV not possible")
                return@withContext false
            }
            
            isoDep = IsoDep.get(tag)
            currentCard = cardInfo
            
            // Configure for EMV operations
            isoDep?.let { dep ->
                dep.timeout = config?.timeout?.toInt() ?: 30000
                dep.connect()
                
                Timber.d("Connected to EMV card: ${tag.id.toHexString()}")
                Timber.d("Historical bytes: ${dep.historicalBytes?.toHexString()}")
                Timber.d("Hi-layer response: ${dep.hiLayerResponse?.toHexString()}")
                
                true
            } ?: false
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to connect to EMV card")
            false
        }
    }
    
    override suspend fun exchangeApdu(apdu: ByteArray): ApduResponse = withContext(Dispatchers.IO) {
        val dep = isoDep ?: throw IllegalStateException("Not connected to card")
        
        try {
            Timber.d("Android NFC APDU Exchange: ${apdu.toHexString()}")
            
            val response = dep.transceive(apdu)
            
            Timber.d("Android NFC APDU Response: ${response.toHexString()}")
            
            // Parse SW1 SW2 (last 2 bytes)
            if (response.size < 2) {
                throw IllegalArgumentException("Invalid APDU response length")
            }
            
            val data = response.dropLast(2).toByteArray()
            val sw1 = response[response.size - 2].toInt() and 0xFF
            val sw2 = response[response.size - 1].toInt() and 0xFF
            val sw = (sw1 shl 8) or sw2
            
            ApduResponse(data, sw1, sw2, sw)
            
        } catch (e: Exception) {
            Timber.e(e, "Android NFC APDU exchange failed")
            throw EmvCommunicationException("Android NFC APDU exchange failed: ${e.message}", e)
        }
    }
    
    override suspend fun selectApplication(aid: String): ApduResponse {
        val aidBytes = aid.hexToByteArray()
        val selectCommand = byteArrayOf(
            0x00.toByte(), 0xA4.toByte(), 0x04.toByte(), 0x00.toByte(),
            aidBytes.size.toByte()
        ) + aidBytes
        
        return exchangeApdu(selectCommand)
    }
    
    override suspend fun getProcessingOptions(pdol: ByteArray): ApduResponse {
        val gpoCommand = byteArrayOf(
            0x80.toByte(), 0xA8.toByte(), 0x00.toByte(), 0x00.toByte(),
            pdol.size.toByte()
        ) + pdol
        
        return exchangeApdu(gpoCommand)
    }
    
    override suspend fun readRecord(sfi: Int, recordNumber: Int): ApduResponse {
        val readCommand = byteArrayOf(
            0x00.toByte(), 0xB2.toByte(),
            recordNumber.toByte(),
            ((sfi shl 3) or 0x04).toByte(),
            0x00.toByte()
        )
        
        return exchangeApdu(readCommand)
    }
    
    override suspend fun generateAc(acType: Int, cdol: ByteArray): ApduResponse {
        val genAcCommand = byteArrayOf(
            0x80.toByte(), 0xAE.toByte(),
            acType.toByte(), 0x00.toByte(),
            cdol.size.toByte()
        ) + cdol
        
        return exchangeApdu(genAcCommand)
    }
    
    override fun getCardInfo(): NfcCardInfo? = currentCard
    
    override suspend fun disconnect() {
        try {
            isoDep?.close()
            Timber.d("Disconnected from Android NFC card")
        } catch (e: Exception) {
            Timber.w(e, "Error during Android NFC disconnect")
        } finally {
            isoDep = null
            currentCard = null
            currentTag = null
        }
    }
    
    override suspend fun cleanup() {
        disconnect()
    }
    
    override fun getCapabilities(): NfcCapabilities {
        val dep = isoDep
        return NfcCapabilities(
            supportedCardTypes = setOf(
                NfcCardType.ISO14443_TYPE_A,
                NfcCardType.ISO14443_TYPE_B,
                NfcCardType.MIFARE_CLASSIC,
                NfcCardType.MIFARE_ULTRALIGHT,
                NfcCardType.FELICA
            ),
            maxApduLength = dep?.maxTransceiveLength ?: 261,
            supportsExtendedLength = dep?.isExtendedLengthApduSupported ?: false,
            canControlField = false, // Android manages field automatically
            canSetTimeout = true,
            supportsBaudRateChange = false,
            providerSpecificFeatures = mapOf(
                "androidNative" to true,
                "hardwareSecurityModule" to true,
                "systemManaged" to true
            )
        )
    }
    
    /**
     * Set the current tag (called from Android NFC intent)
     */
    fun setCurrentTag(tag: Tag) {
        currentTag = tag
        currentCard = parseTagToCardInfo(tag)
    }
    
    /**
     * Parse Android NFC Tag to unified card info
     */
    private fun parseTagToCardInfo(tag: Tag): NfcCardInfo {
        val nfcA = NfcA.get(tag)
        val nfcB = NfcB.get(tag)
        val isoDep = IsoDep.get(tag)
        
        val cardType = when {
            nfcB != null -> NfcCardType.ISO14443_TYPE_B
            nfcA != null -> NfcCardType.ISO14443_TYPE_A
            else -> NfcCardType.UNKNOWN
        }
        
        return NfcCardInfo(
            uid = tag.id.toHexString(),
            atqa = nfcA?.atqa?.toHexString(),
            sak = nfcA?.sak?.toString(16),
            historicalBytes = isoDep?.historicalBytes?.toHexString(),
            hiLayerResponse = isoDep?.hiLayerResponse?.toHexString(),
            cardType = cardType,
            providerType = NfcProviderType.ANDROID_INTERNAL,
            maxTransceiveLength = isoDep?.maxTransceiveLength ?: 261,
            isExtendedLengthSupported = isoDep?.isExtendedLengthApduSupported ?: false
        )
    }
}

// Extension functions
private fun ByteArray.toHexString(): String = joinToString("") { "%02X".format(it) }
private fun String.hexToByteArray(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()