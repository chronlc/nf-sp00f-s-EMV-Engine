/**
 * nf-sp00f EMV Engine - Configuration Manager
 * 
 * Centralized configuration management for EMV engine settings,
 * NFC provider selection, and runtime parameters.
 * 
 * @package com.nf_sp00f.app.emv.config
 * @author nf-sp00f
 * @since 1.0.0
 */
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
 * Handles persistent storage and retrieval of EMV engine configuration,
 * including NFC provider selection and security settings.
 */
class EmvConfigurationManager(private val context: Context) {
    
    companion object {
        private const val TAG = "EmvConfigurationManager"
        private const val PREFS_NAME = "emv_engine_config"
        
        // Configuration keys
        private const val KEY_NFC_PROVIDER_TYPE = "nfc_provider_type"
        private const val KEY_BLUETOOTH_DEVICE_ADDRESS = "bluetooth_device_address"
        private const val KEY_BLUETOOTH_DEVICE_NAME = "bluetooth_device_name"
        private const val KEY_ENABLE_ROCA_CHECK = "enable_roca_check"
        private const val KEY_ENABLE_CRYPTO_VALIDATION = "enable_crypto_validation"
        private const val KEY_STRICT_VALIDATION = "strict_validation"
        private const val KEY_TRANSACTION_TIMEOUT = "transaction_timeout"
        private const val KEY_DEBUG_MODE = "debug_mode"
        
        // Default values
        private const val DEFAULT_TIMEOUT_MS = 30000L
        private const val DEFAULT_ROCA_CHECK = true
        private const val DEFAULT_CRYPTO_VALIDATION = true
        private const val DEFAULT_STRICT_VALIDATION = true
        private const val DEFAULT_DEBUG_MODE = false
    }
    
    private val sharedPreferences: SharedPreferences by lazy {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }
    
    /**
     * Save NFC provider configuration
     */
    suspend fun saveNfcProviderConfig(config: NfcProviderConfig) = withContext(Dispatchers.IO) {
        try {
            val editor = sharedPreferences.edit()
            
            editor.putString(KEY_NFC_PROVIDER_TYPE, config.type.name)
            
            // Save Bluetooth-specific configuration if applicable
            if (config.type == NfcProviderType.PN532_BLUETOOTH) {
                config.bluetoothDeviceAddress?.let { address ->
                    editor.putString(KEY_BLUETOOTH_DEVICE_ADDRESS, address)
                }
                config.bluetoothDeviceName?.let { name ->
                    editor.putString(KEY_BLUETOOTH_DEVICE_NAME, name)
                }
            }
            
            editor.apply()
            Timber.d("Saved NFC provider configuration: ${config.type}")
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to save NFC provider configuration")
            throw e
        }
    }
    
    /**
     * Load NFC provider configuration
     */
    suspend fun loadNfcProviderConfig(): NfcProviderConfig = withContext(Dispatchers.IO) {
        try {
            val providerTypeName = sharedPreferences.getString(
                KEY_NFC_PROVIDER_TYPE,
                NfcProviderType.ANDROID_INTERNAL.name
            ) ?: NfcProviderType.ANDROID_INTERNAL.name
            
            val providerType = try {
                NfcProviderType.valueOf(providerTypeName)
            } catch (e: IllegalArgumentException) {
                Timber.w("Invalid provider type: $providerTypeName, using default")
                NfcProviderType.ANDROID_INTERNAL
            }
            
            val config = when (providerType) {
                NfcProviderType.ANDROID_INTERNAL -> {
                    NfcProviderConfig(NfcProviderType.ANDROID_INTERNAL)
                }
                NfcProviderType.PN532_BLUETOOTH -> {
                    val deviceAddress = sharedPreferences.getString(KEY_BLUETOOTH_DEVICE_ADDRESS, null)
                    val deviceName = sharedPreferences.getString(KEY_BLUETOOTH_DEVICE_NAME, null)
                    
                    NfcProviderConfig(
                        type = NfcProviderType.PN532_BLUETOOTH,
                        bluetoothDeviceAddress = deviceAddress,
                        bluetoothDeviceName = deviceName
                    )
                }
            }
            
            Timber.d("Loaded NFC provider configuration: ${config.type}")
            config
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to load NFC provider configuration, using default")
            NfcProviderConfig(NfcProviderType.ANDROID_INTERNAL)
        }
    }
    
    /**
     * Save security configuration
     */
    suspend fun saveSecurityConfig(
        enableRocaCheck: Boolean = DEFAULT_ROCA_CHECK,
        enableCryptoValidation: Boolean = DEFAULT_CRYPTO_VALIDATION,
        strictValidation: Boolean = DEFAULT_STRICT_VALIDATION
    ) = withContext(Dispatchers.IO) {
        try {
            val editor = sharedPreferences.edit()
            
            editor.putBoolean(KEY_ENABLE_ROCA_CHECK, enableRocaCheck)
            editor.putBoolean(KEY_ENABLE_CRYPTO_VALIDATION, enableCryptoValidation)
            editor.putBoolean(KEY_STRICT_VALIDATION, strictValidation)
            
            editor.apply()
            Timber.d("Saved security configuration")
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to save security configuration")
            throw e
        }
    }
    
    /**
     * Load security configuration
     */
    suspend fun loadSecurityConfig(): SecurityConfig = withContext(Dispatchers.IO) {
        try {
            SecurityConfig(
                enableRocaCheck = sharedPreferences.getBoolean(KEY_ENABLE_ROCA_CHECK, DEFAULT_ROCA_CHECK),
                enableCryptoValidation = sharedPreferences.getBoolean(KEY_ENABLE_CRYPTO_VALIDATION, DEFAULT_CRYPTO_VALIDATION),
                strictValidation = sharedPreferences.getBoolean(KEY_STRICT_VALIDATION, DEFAULT_STRICT_VALIDATION)
            )
        } catch (e: Exception) {
            Timber.e(e, "Failed to load security configuration, using defaults")
            SecurityConfig()
        }
    }
    
    /**
     * Save general EMV configuration
     */
    suspend fun saveEmvConfig(
        transactionTimeoutMs: Long = DEFAULT_TIMEOUT_MS,
        debugMode: Boolean = DEFAULT_DEBUG_MODE
    ) = withContext(Dispatchers.IO) {
        try {
            val editor = sharedPreferences.edit()
            
            editor.putLong(KEY_TRANSACTION_TIMEOUT, transactionTimeoutMs)
            editor.putBoolean(KEY_DEBUG_MODE, debugMode)
            
            editor.apply()
            Timber.d("Saved EMV configuration")
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to save EMV configuration")
            throw e
        }
    }
    
    /**
     * Load general EMV configuration
     */
    suspend fun loadEmvConfig(): EmvConfig = withContext(Dispatchers.IO) {
        try {
            EmvConfig(
                transactionTimeoutMs = sharedPreferences.getLong(KEY_TRANSACTION_TIMEOUT, DEFAULT_TIMEOUT_MS),
                debugMode = sharedPreferences.getBoolean(KEY_DEBUG_MODE, DEFAULT_DEBUG_MODE)
            )
        } catch (e: Exception) {
            Timber.e(e, "Failed to load EMV configuration, using defaults")
            EmvConfig()
        }
    }
    
    /**
     * Load complete configuration
     */
    suspend fun loadCompleteConfiguration(): CompleteConfiguration {
        return try {
            CompleteConfiguration(
                nfcProvider = loadNfcProviderConfig(),
                security = loadSecurityConfig(),
                emv = loadEmvConfig()
            )
        } catch (e: Exception) {
            Timber.e(e, "Failed to load complete configuration, using defaults")
            CompleteConfiguration()
        }
    }
    
    /**
     * Save complete configuration
     */
    suspend fun saveCompleteConfiguration(config: CompleteConfiguration) {
        try {
            saveNfcProviderConfig(config.nfcProvider)
            saveSecurityConfig(
                config.security.enableRocaCheck,
                config.security.enableCryptoValidation,
                config.security.strictValidation
            )
            saveEmvConfig(
                config.emv.transactionTimeoutMs,
                config.emv.debugMode
            )
            
            Timber.d("Saved complete configuration successfully")
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to save complete configuration")
            throw e
        }
    }
    
    /**
     * Reset configuration to defaults
     */
    suspend fun resetToDefaults() = withContext(Dispatchers.IO) {
        try {
            val editor = sharedPreferences.edit()
            editor.clear()
            editor.apply()
            
            Timber.d("Configuration reset to defaults")
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to reset configuration")
            throw e
        }
    }
    
    /**
     * Export configuration as JSON string
     */
    suspend fun exportConfiguration(): String = withContext(Dispatchers.IO) {
        val config = loadCompleteConfiguration()
        
        // Simple JSON serialization for configuration export
        buildString {
            append("{")
            append("\"nfc_provider_type\":\"${config.nfcProvider.type.name}\",")
            config.nfcProvider.bluetoothDeviceAddress?.let { address ->
                append("\"bluetooth_device_address\":\"$address\",")
            }
            config.nfcProvider.bluetoothDeviceName?.let { name ->
                append("\"bluetooth_device_name\":\"$name\",")
            }
            append("\"enable_roca_check\":${config.security.enableRocaCheck},")
            append("\"enable_crypto_validation\":${config.security.enableCryptoValidation},")
            append("\"strict_validation\":${config.security.strictValidation},")
            append("\"transaction_timeout_ms\":${config.emv.transactionTimeoutMs},")
            append("\"debug_mode\":${config.emv.debugMode}")
            append("}")
        }
    }
    
    /**
     * Get configuration status summary
     */
    fun getConfigurationStatus(): String {
        return try {
            val allKeys = sharedPreferences.all
            buildString {
                append("EMV Configuration Status:\n")
                append("- Total settings: ${allKeys.size}\n")
                append("- NFC Provider: ${sharedPreferences.getString(KEY_NFC_PROVIDER_TYPE, "Default")}\n")
                append("- ROCA Check: ${sharedPreferences.getBoolean(KEY_ENABLE_ROCA_CHECK, DEFAULT_ROCA_CHECK)}\n")
                append("- Crypto Validation: ${sharedPreferences.getBoolean(KEY_ENABLE_CRYPTO_VALIDATION, DEFAULT_CRYPTO_VALIDATION)}\n")
                append("- Debug Mode: ${sharedPreferences.getBoolean(KEY_DEBUG_MODE, DEFAULT_DEBUG_MODE)}")
            }
        } catch (e: Exception) {
            "Configuration status unavailable: ${e.message}"
        }
    }
}

/**
 * Security configuration data class
 */
data class SecurityConfig(
    val enableRocaCheck: Boolean = true,
    val enableCryptoValidation: Boolean = true,
    val strictValidation: Boolean = true
)

/**
 * EMV configuration data class
 */
data class EmvConfig(
    val transactionTimeoutMs: Long = 30000L,
    val debugMode: Boolean = false
)

/**
 * Complete configuration data class
 */
data class CompleteConfiguration(
    val nfcProvider: NfcProviderConfig = NfcProviderConfig(NfcProviderType.ANDROID_INTERNAL),
    val security: SecurityConfig = SecurityConfig(),
    val emv: EmvConfig = EmvConfig()
)
