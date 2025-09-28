package com.nf_sp00f.app.emv

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.nfc.tech.NfcA
import android.nfc.tech.NfcB
import kotlinx.coroutines.*
import timber.log.Timber

/**
 * Android Internal NFC Adapter Wrapper for EMV Processing
 * 
 * This class provides optimized EMV transaction processing specifically 
 * designed for Android's built-in NFC adapter, replacing Proxmark3 hardware calls.
 */
class AndroidNfcEmvAdapter {
    
    private var isoDep: IsoDep? = null
    private var currentTag: Tag? = null
    
    /**
     * Connect to EMV card using Android internal NFC
     */
    suspend fun connectToCard(tag: Tag): Boolean = withContext(Dispatchers.IO) {
        try {
            // Check if tag supports ISO-DEP (required for EMV)
            if (!tag.techList.contains(IsoDep::class.java.name)) {
                Timber.w("Tag does not support ISO-DEP, EMV not possible")
                return@withContext false
            }
            
            isoDep = IsoDep.get(tag)
            currentTag = tag
            
            // Configure for EMV operations
            isoDep?.let { dep ->
                dep.timeout = 30000  // 30 second timeout for EMV operations
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
    
    /**
     * Send APDU command to EMV card via Android internal NFC
     * This replaces Proxmark3's EMVExchange function
     */
    suspend fun exchangeApdu(apdu: ByteArray): ApduResponse = withContext(Dispatchers.IO) {
        val dep = isoDep ?: throw IllegalStateException("Not connected to card")
        
        try {
            Timber.d("Sending APDU: ${apdu.toHexString()}")
            
            val response = dep.transceive(apdu)
            
            Timber.d("Received response: ${response.toHexString()}")
            
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
            Timber.e(e, "APDU exchange failed")
            throw EmvCommunicationException("APDU exchange failed: ${e.message}", e)
        }
    }
    
    /**
     * Select EMV application by AID
     */
    suspend fun selectApplication(aid: String): ApduResponse {
        val aidBytes = aid.hexToByteArray()
        val selectCommand = byteArrayOf(
            0x00.toByte(), 0xA4.toByte(), 0x04.toByte(), 0x00.toByte(),
            aidBytes.size.toByte()
        ) + aidBytes
        
        return exchangeApdu(selectCommand)
    }
    
    /**
     * Get Processing Options (GPO) command
     */
    suspend fun getProcessingOptions(pdol: ByteArray): ApduResponse {
        val gpoCommand = byteArrayOf(
            0x80.toByte(), 0xA8.toByte(), 0x00.toByte(), 0x00.toByte(),
            pdol.size.toByte()
        ) + pdol
        
        return exchangeApdu(gpoCommand)
    }
    
    /**
     * Read EMV record
     */
    suspend fun readRecord(sfi: Int, recordNumber: Int): ApduResponse {
        val readCommand = byteArrayOf(
            0x00.toByte(), 0xB2.toByte(), 
            recordNumber.toByte(), 
            ((sfi shl 3) or 0x04).toByte(),
            0x00.toByte()
        )
        
        return exchangeApdu(readCommand)
    }
    
    /**
     * Generate Application Cryptogram (for authentication)
     */
    suspend fun generateAc(
        acType: Int, 
        cdol: ByteArray
    ): ApduResponse {
        val genAcCommand = byteArrayOf(
            0x80.toByte(), 0xAE.toByte(),
            acType.toByte(), 0x00.toByte(),
            cdol.size.toByte()
        ) + cdol
        
        return exchangeApdu(genAcCommand)
    }
    
    /**
     * Disconnect from card
     */
    suspend fun disconnect() = withContext(Dispatchers.IO) {
        try {
            isoDep?.close()
            Timber.d("Disconnected from EMV card")
        } catch (e: Exception) {
            Timber.w(e, "Error during disconnect")
        } finally {
            isoDep = null
            currentTag = null
        }
    }
    
    /**
     * Get card information
     */
    fun getCardInfo(): EmvCardInfo? {
        val tag = currentTag ?: return null
        val dep = isoDep ?: return null
        
        return EmvCardInfo(
            uid = tag.id.toHexString(),
            atqa = if (NfcA.get(tag) != null) NfcA.get(tag).atqa.toHexString() else null,
            sak = if (NfcA.get(tag) != null) NfcA.get(tag).sak.toString() else null,
            historicalBytes = dep.historicalBytes?.toHexString(),
            hiLayerResponse = dep.hiLayerResponse?.toHexString(),
            maxTransceiveLength = dep.maxTransceiveLength,
            isExtendedLengthApduSupported = dep.isExtendedLengthApduSupported
        )
    }
}

/**
 * APDU Response data class
 */
data class ApduResponse(
    val data: ByteArray,
    val sw1: Int,
    val sw2: Int, 
    val sw: Int
) {
    val isSuccess: Boolean get() = sw == 0x9000
    val isMoreDataAvailable: Boolean get() = sw1 == 0x61
    val needsGetResponse: Boolean get() = isMoreDataAvailable
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as ApduResponse
        return data.contentEquals(other.data) && sw1 == other.sw1 && sw2 == other.sw2
    }
    
    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + sw1
        result = 31 * result + sw2
        return result
    }
}

/**
 * EMV Card information from Android NFC
 */
data class EmvCardInfo(
    val uid: String,
    val atqa: String?,
    val sak: String?, 
    val historicalBytes: String?,
    val hiLayerResponse: String?,
    val maxTransceiveLength: Int,
    val isExtendedLengthApduSupported: Boolean
)

/**
 * EMV Communication Exception
 */
class EmvCommunicationException(message: String, cause: Throwable? = null) : Exception(message, cause)

// Extension functions for hex conversion
private fun ByteArray.toHexString(): String = 
    joinToString("") { "%02X".format(it) }

private fun String.hexToByteArray(): ByteArray = 
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()