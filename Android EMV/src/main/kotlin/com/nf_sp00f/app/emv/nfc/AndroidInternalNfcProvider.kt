/**
 * nf-sp00f EMV Engine - Android Internal NFC Provider
 * 
 * Implementation of NFC provider using Android's built-in NFC capabilities.
 * Optimized for IsoDep (ISO14443-4) EMV card communication.
 * 
 * @package com.nf_sp00f.app.emv.nfc
 * @author nf-sp00f
 * @since 1.0.0
 */
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
 * Provides EMV NFC communication using Android's native NFC stack.
 * Supports both Type A and Type B cards through IsoDep interface.
 */
class AndroidInternalNfcProvider : INfcProvider {
    
    companion object {
        private const val TAG = "AndroidInternalNfcProvider"
        private const val DEFAULT_TIMEOUT_MS = 5000
        private const val MAX_TRANSCEIVE_LENGTH = 253 // Standard IsoDep limit
    }
    
    private var isoDep: IsoDep? = null
    private var currentTag: Tag? = null
    private var isConnected = false
    private var demoTag: Tag? = null // For demo purposes
    
    override suspend fun initialize(config: NfcProviderConfig): Boolean = withContext(Dispatchers.IO) {
        try {
            Timber.d("Initializing Android Internal NFC Provider")
            
            // Verify configuration
            if (config.type != NfcProviderType.ANDROID_INTERNAL) {
                Timber.e("Invalid config type for Android NFC provider: ${config.type}")
                return@withContext false
            }
            
            // Check if device supports NFC
            val nfcAdapter = NfcAdapter.getDefaultAdapter(null) // Context would be injected in real app
            if (nfcAdapter == null) {
                Timber.e("NFC not supported on this device")
                return@withContext false
            }
            
            if (!nfcAdapter.isEnabled) {
                Timber.w("NFC is disabled on this device")
                return@withContext false
            }
            
            Timber.i("Android Internal NFC Provider initialized successfully")
            true
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to initialize Android NFC provider")
            false
        }
    }
    
    override suspend fun connect(): Boolean = withContext(Dispatchers.IO) {
        try {
            val tag = demoTag ?: currentTag
            if (tag == null) {
                Timber.e("No NFC tag available for connection")
                return@withContext false
            }
            
            // Check if tag supports IsoDep (required for EMV)
            if (!tag.techList.contains(IsoDep::class.java.name)) {
                Timber.e("Tag does not support IsoDep (ISO14443-4) - EMV not possible")
                return@withContext false
            }
            
            // Get IsoDep instance
            isoDep = IsoDep.get(tag)
            if (isoDep == null) {
                Timber.e("Failed to get IsoDep instance from tag")
                return@withContext false
            }
            
            // Configure timeouts and parameters
            isoDep!!.timeout = DEFAULT_TIMEOUT_MS
            
            // Enable extended length APDUs if supported
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
                isoDep!!.isExtendedLengthApduSupported = true
            }
            
            // Connect to the tag
            isoDep!!.connect()
            isConnected = true
            
            val uid = tag.id.joinToString("") { "%02X".format(it) }
            Timber.i("Successfully connected to EMV card (UID: $uid)")
            
            true
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to connect to NFC tag")
            isConnected = false
            false
        }
    }
    
    override suspend fun sendCommand(command: ByteArray): NfcResponse = withContext(Dispatchers.IO) {
        try {
            if (!isConnected || isoDep == null) {
                return@withContext NfcResponse.Error("Not connected to NFC tag")
            }
            
            if (command.size > MAX_TRANSCEIVE_LENGTH) {
                return@withContext NfcResponse.Error("Command exceeds maximum length: ${command.size} > $MAX_TRANSCEIVE_LENGTH")
            }
            
            Timber.d("Sending APDU: ${command.joinToString("") { "%02X".format(it) }}")
            
            // Send command via IsoDep
            val startTime = System.currentTimeMillis()
            val response = isoDep!!.transceive(command)
            val duration = System.currentTimeMillis() - startTime
            
            Timber.d("Received response (${duration}ms): ${response.joinToString("") { "%02X".format(it) }}")
            
            if (response.size < 2) {
                return@withContext NfcResponse.Error("Response too short: ${response.size} bytes")
            }
            
            // Extract status word (last 2 bytes)
            val data = response.sliceArray(0 until response.size - 2)
            val sw1 = response[response.size - 2].toInt() and 0xFF
            val sw2 = response[response.size - 1].toInt() and 0xFF
            val statusWord = (sw1 shl 8) or sw2
            
            NfcResponse.Success(data, statusWord, duration)
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to send NFC command")
            NfcResponse.Error("Command failed: ${e.message}")
        }
    }
    
    override fun isConnected(): Boolean = isConnected && isoDep?.isConnected == true
    
    override suspend fun disconnect(): Boolean = withContext(Dispatchers.IO) {
        try {
            isoDep?.close()
            isoDep = null
            isConnected = false
            currentTag = null
            
            Timber.d("Disconnected from NFC tag")
            true
            
        } catch (e: Exception) {
            Timber.w(e, "Error during NFC disconnect")
            false
        }
    }
    
    override suspend fun runDiagnostics(): NfcDiagnostics = withContext(Dispatchers.Default) {
        val diagnostics = mutableMapOf<String, String>()
        
        try {
            // Check NFC adapter status
            val nfcAdapter = NfcAdapter.getDefaultAdapter(null)
            diagnostics["NFC Adapter"] = if (nfcAdapter != null) "Available" else "Not Available"
            diagnostics["NFC Enabled"] = if (nfcAdapter?.isEnabled == true) "Yes" else "No"
            
            // Check current connection
            diagnostics["Connection Status"] = if (isConnected) "Connected" else "Disconnected"
            diagnostics["IsoDep Available"] = if (isoDep != null) "Yes" else "No"
            
            // Check tag information
            currentTag?.let { tag ->
                diagnostics["Tag UID"] = tag.id.joinToString("") { "%02X".format(it) }
                diagnostics["Tag Technologies"] = tag.techList.joinToString(", ")
                diagnostics["Tag Type"] = getTagType(tag)
                
                isoDep?.let { iso ->
                    diagnostics["Max Transceive Length"] = iso.maxTransceiveLength.toString()
                    diagnostics["Timeout"] = "${iso.timeout}ms"
                    
                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
                        diagnostics["Extended Length APDU"] = if (iso.isExtendedLengthApduSupported) "Supported" else "Not Supported"
                    }
                }
            }
            
            // Performance metrics
            diagnostics["Provider Type"] = "Android Internal NFC"
            diagnostics["API Level"] = android.os.Build.VERSION.SDK_INT.toString()
            
            NfcDiagnostics(
                isHealthy = isConnected && isoDep != null,
                status = if (isConnected) "Operational" else "Standby",
                details = diagnostics,
                lastCheck = System.currentTimeMillis()
            )
            
        } catch (e: Exception) {
            Timber.e(e, "NFC diagnostics failed")
            NfcDiagnostics(
                isHealthy = false,
                status = "Error: ${e.message}",
                details = diagnostics,
                lastCheck = System.currentTimeMillis()
            )
        }
    }
    
    override fun getProviderInfo(): NfcProviderInfo {
        return NfcProviderInfo(
            type = NfcProviderType.ANDROID_INTERNAL,
            name = "Android Internal NFC",
            version = "Android API ${android.os.Build.VERSION.SDK_INT}",
            capabilities = listOf(
                "IsoDep (ISO14443-4)",
                "NFC-A (ISO14443 Type A)",
                "NFC-B (ISO14443 Type B)",
                "Extended Length APDUs",
                "Hardware Acceleration"
            ),
            maxDataLength = MAX_TRANSCEIVE_LENGTH,
            supportsBackground = false // Android NFC requires foreground
        )
    }
    
    /**
     * Set demo tag for testing purposes
     */
    fun setDemoTag(tag: Tag) {
        this.demoTag = tag
        this.currentTag = tag
        Timber.d("Demo tag set: ${tag.id.joinToString("") { "%02X".format(it) }}")
    }
    
    /**
     * Set current NFC tag from discovery
     */
    fun setCurrentTag(tag: Tag) {
        this.currentTag = tag
        Timber.d("Current tag set: ${tag.id.joinToString("") { "%02X".format(it) }}")
    }
    
    /**
     * Get detailed tag type information
     */
    private fun getTagType(tag: Tag): String {
        return when {
            tag.techList.contains(NfcA::class.java.name) -> {
                val nfcA = NfcA.get(tag)
                "Type A (ATQA: ${nfcA?.atqa?.joinToString("") { "%02X".format(it) } ?: "Unknown"})"
            }
            tag.techList.contains(NfcB::class.java.name) -> {
                val nfcB = NfcB.get(tag)
                "Type B (Application Data: ${nfcB?.applicationData?.joinToString("") { "%02X".format(it) } ?: "Unknown"})"
            }
            else -> "Unknown"
        }
    }
    
    /**
     * Get current tag information
     */
    fun getCurrentTagInfo(): Map<String, String> {
        val info = mutableMapOf<String, String>()
        
        currentTag?.let { tag ->
            info["UID"] = tag.id.joinToString("") { "%02X".format(it) }
            info["Type"] = getTagType(tag)
            info["Technologies"] = tag.techList.joinToString(", ") { it.substringAfterLast('.') }
            
            // Add IsoDep specific information
            if (tag.techList.contains(IsoDep::class.java.name)) {
                val iso = IsoDep.get(tag)
                iso?.let {
                    info["Historical Bytes"] = it.historicalBytes?.joinToString("") { byte -> "%02X".format(byte) } ?: "None"
                    info["Hi-Layer Response"] = it.hiLayerResponse?.joinToString("") { byte -> "%02X".format(byte) } ?: "None"
                }
            }
        }
        
        return info
    }
    
    /**
     * Check if current tag supports EMV
     */
    fun isEmvCompatible(): Boolean {
        return currentTag?.techList?.contains(IsoDep::class.java.name) == true
    }
    
    /**
     * Get NFC adapter state
     */
    fun getNfcAdapterState(): String {
        val adapter = NfcAdapter.getDefaultAdapter(null)
        return when {
            adapter == null -> "Not Available"
            !adapter.isEnabled -> "Disabled"
            else -> "Enabled"
        }
    }
}
