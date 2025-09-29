/**
 * nf-sp00f EMV Engine - Android Internal NFC Adapter Wrapper
 * 
 * Optimized EMV transaction processing specifically designed for Android's 
 * built-in NFC adapter, replacing Proxmark3 hardware calls.
 * 
 * @package com.nf_sp00f.app.emv
 * @author nf-sp00f
 * @since 1.0.0
 */
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
            
            currentTag = tag
            isoDep = IsoDep.get(tag)
            
            // Set timeout for EMV operations (typically 1 second)
            isoDep?.timeout = 1000
            
            // Connect to the card
            isoDep?.connect()
            
            Timber.d("Successfully connected to EMV card")
            true
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to connect to EMV card")
            false
        }
    }
    
    /**
     * Disconnect from EMV card
     */
    fun disconnect() {
        try {
            isoDep?.close()
            isoDep = null
            currentTag = null
            Timber.d("Disconnected from EMV card")
        } catch (e: Exception) {
            Timber.w(e, "Error during EMV card disconnect")
        }
    }
    
    /**
     * Send APDU command to EMV card
     */
    suspend fun sendApdu(command: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        val isoDepConnection = isoDep ?: throw IllegalStateException("Not connected to EMV card")
        
        try {
            Timber.d("Sending APDU: ${command.joinToString("") { "%02X".format(it) }}")
            
            val response = isoDepConnection.transceive(command)
            
            Timber.d("Received response: ${response.joinToString("") { "%02X".format(it) }}")
            
            response
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to send APDU command")
            throw e
        }
    }
    
    /**
     * Get card UID (for logging/tracking purposes)
     */
    fun getCardUid(): String? {
        return currentTag?.id?.joinToString("") { "%02X".format(it) }
    }
    
    /**
     * Check if currently connected to a card
     */
    fun isConnected(): Boolean {
        return isoDep?.isConnected == true
    }
    
    /**
     * Get available NFC technologies for current tag
     */
    fun getAvailableTechnologies(): List<String> {
        return currentTag?.techList?.toList() ?: emptyList()
    }
    
    /**
     * Check if tag supports EMV processing
     */
    fun supportsEmv(): Boolean {
        val techList = currentTag?.techList ?: return false
        return techList.contains(IsoDep::class.java.name)
    }
    
    /**
     * Get tag type information
     */
    fun getTagType(): String {
        val tag = currentTag ?: return "Unknown"
        
        return when {
            tag.techList.contains(NfcA::class.java.name) -> "Type A"
            tag.techList.contains(NfcB::class.java.name) -> "Type B"
            else -> "Unknown"
        }
    }
    
    /**
     * Get maximum transceive length
     */
    fun getMaxTransceiveLength(): Int {
        return isoDep?.maxTransceiveLength ?: 0
    }
    
    /**
     * Set extended length APDU support
     */
    fun setExtendedLengthApduSupported(enabled: Boolean) {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
            isoDep?.isExtendedLengthApduSupported = enabled
        }
    }
}
