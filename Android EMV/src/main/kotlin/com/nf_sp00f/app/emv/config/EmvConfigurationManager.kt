package com.nf_sp00f.app.emv.config

import com.nf_sp00f.app.emv.nfc.NfcProviderConfig
import com.nf_sp00f.app.emv.nfc.NfcProviderType
import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber

/**
 * EMV Configuration Manager
 * 
 * Manages EMV engine configuration including NFC provider settings,
 * Bluetooth device pairing, and user preferences.
 */
class EmvConfigurationManager(private val context: Context) {
    
    companion object {
        private const val PREFS_NAME = "emv_config"
        private const val KEY_NFC_PROVIDER_TYPE = "nfc_provider_type"
        private const val KEY_BLUETOOTH_ADDRESS = "bluetooth_address" 
        private const val KEY_BLUETOOTH_DEVICE_NAME = "bluetooth_device_name"
        private const val KEY_UART_BAUD_RATE = "uart_baud_rate"
        private const val KEY_CONNECTION_TIMEOUT = "connection_timeout"
        private const val KEY_AUTO_CONNECT = "auto_connect"
        private const val KEY_PREFERRED_AIDS = "preferred_aids"
        
        // Default values
        private const val DEFAULT_BAUD_RATE = 115200
        private const val DEFAULT_TIMEOUT = 30000L
        private const val DEFAULT_AUTO_CONNECT = true
    }
    
    private val sharedPrefs: SharedPreferences = 
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    
    /**
     * Get current NFC provider configuration
     */
    fun getNfcProviderConfig(): NfcProviderConfig {
        val typeString = sharedPrefs.getString(KEY_NFC_PROVIDER_TYPE, 
            NfcProviderType.ANDROID_INTERNAL.name) ?: NfcProviderType.ANDROID_INTERNAL.name
        
        val type = try {
            NfcProviderType.valueOf(typeString)
        } catch (e: IllegalArgumentException) {
            Timber.w("Invalid NFC provider type: $typeString, using default")
            NfcProviderType.ANDROID_INTERNAL
        }
        
        return NfcProviderConfig(
            type = type,
            bluetoothAddress = sharedPrefs.getString(KEY_BLUETOOTH_ADDRESS, null),
            baudRate = sharedPrefs.getInt(KEY_UART_BAUD_RATE, DEFAULT_BAUD_RATE),
            timeout = sharedPrefs.getLong(KEY_CONNECTION_TIMEOUT, DEFAULT_TIMEOUT),
            autoConnect = sharedPrefs.getBoolean(KEY_AUTO_CONNECT, DEFAULT_AUTO_CONNECT)
        )
    }
    
    /**
     * Save NFC provider configuration
     */
    fun saveNfcProviderConfig(config: NfcProviderConfig) {
        sharedPrefs.edit().apply {
            putString(KEY_NFC_PROVIDER_TYPE, config.type.name)
            putString(KEY_BLUETOOTH_ADDRESS, config.bluetoothAddress)
            putInt(KEY_UART_BAUD_RATE, config.baudRate)
            putLong(KEY_CONNECTION_TIMEOUT, config.timeout)
            putBoolean(KEY_AUTO_CONNECT, config.autoConnect)
        }.apply()
        
        Timber.d("Saved NFC provider config: ${config.type}")
    }
    
    /**
     * Configure for Android Internal NFC
     */
    fun configureAndroidNfc(timeout: Long = DEFAULT_TIMEOUT) {
        val config = NfcProviderConfig(
            type = NfcProviderType.ANDROID_INTERNAL,
            timeout = timeout
        )
        saveNfcProviderConfig(config)
    }
    
    /**
     * Configure for PN532 via Bluetooth UART
     */
    fun configurePn532Bluetooth(
        bluetoothAddress: String,
        deviceName: String? = null,
        baudRate: Int = DEFAULT_BAUD_RATE,
        timeout: Long = DEFAULT_TIMEOUT
    ) {
        val config = NfcProviderConfig(
            type = NfcProviderType.PN532_BLUETOOTH,
            bluetoothAddress = bluetoothAddress,
            baudRate = baudRate,
            timeout = timeout
        )
        saveNfcProviderConfig(config)
        
        // Save device name separately for UI purposes
        if (deviceName != null) {
            sharedPrefs.edit()
                .putString(KEY_BLUETOOTH_DEVICE_NAME, deviceName)
                .apply()
        }
        
        Timber.i("Configured PN532 Bluetooth: $bluetoothAddress ($deviceName)")
    }
    
    /**
     * Get saved Bluetooth device info
     */
    fun getSavedBluetoothDevice(): Pair<String?, String?> {
        val address = sharedPrefs.getString(KEY_BLUETOOTH_ADDRESS, null)
        val name = sharedPrefs.getString(KEY_BLUETOOTH_DEVICE_NAME, null)
        return Pair(address, name)
    }
    
    /**
     * Get preferred EMV Application IDs
     */
    fun getPreferredAids(): List<String> {
        val aidsString = sharedPrefs.getString(KEY_PREFERRED_AIDS, null)
        return if (aidsString != null) {
            aidsString.split(",").filter { it.isNotBlank() }
        } else {
            // Default EMV AIDs
            listOf(
                "A0000000031010",     // VISA
                "A0000000041010",     // MasterCard
                "A000000025010402",   // American Express
                "A0000000651010",     // JCB
            )
        }
    }
    
    /**
     * Save preferred EMV Application IDs
     */
    fun savePreferredAids(aids: List<String>) {
        val aidsString = aids.joinToString(",")
        sharedPrefs.edit()
            .putString(KEY_PREFERRED_AIDS, aidsString)
            .apply()
        
        Timber.d("Saved preferred AIDs: ${aids.size} entries")
    }
    
    /**
     * Reset configuration to defaults
     */
    fun resetToDefaults() {
        sharedPrefs.edit().clear().apply()
        Timber.i("EMV configuration reset to defaults")
    }
    
    /**
     * Check if PN532 Bluetooth is configured
     */
    fun isPn532BluetoothConfigured(): Boolean {
        val config = getNfcProviderConfig()
        return config.type == NfcProviderType.PN532_BLUETOOTH && 
               config.bluetoothAddress != null
    }
    
    /**
     * Get configuration summary for debugging
     */
    fun getConfigSummary(): String {
        val config = getNfcProviderConfig()
        val (btAddress, btName) = getSavedBluetoothDevice()
        val aids = getPreferredAids()
        
        return buildString {
            appendLine("EMV Configuration Summary:")
            appendLine("  NFC Provider: ${config.type}")
            if (config.type == NfcProviderType.PN532_BLUETOOTH) {
                appendLine("  Bluetooth Address: ${btAddress ?: "Not set"}")
                appendLine("  Bluetooth Name: ${btName ?: "Unknown"}")
                appendLine("  UART Baud Rate: ${config.baudRate}")
            }
            appendLine("  Connection Timeout: ${config.timeout}ms")
            appendLine("  Auto Connect: ${config.autoConnect}")
            appendLine("  Preferred AIDs: ${aids.size} configured")
        }
    }
}