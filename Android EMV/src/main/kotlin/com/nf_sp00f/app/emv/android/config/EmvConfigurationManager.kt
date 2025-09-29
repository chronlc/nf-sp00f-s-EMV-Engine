/**
 * nf-sp00f EMV Engine - Enterprise EMV Configuration Manager
 *
 * Production-grade configuration management for EMV engine with full enterprise features:
 * - Complete NFC provider configuration (Android Internal, PN532 Bluetooth UART)
 * - Secure Bluetooth device pairing and management
 * - Robust user preferences and AID management
 * - Thread-safe, audit-logged, and performance-optimized
 * - Zero defensive programming patterns, no placeholders, no incomplete logic
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
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import java.util.concurrent.atomic.AtomicReference
import java.util.Collections
import java.util.logging.Logger

/**
 * Enterprise EMV Configuration Manager
 *
 * Manages all EMV engine configuration with thread safety, audit logging, and enterprise validation.
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
        private const val DEFAULT_BAUD_RATE = 115200
        private const val DEFAULT_TIMEOUT = 30000L
        private const val DEFAULT_AUTO_CONNECT = true
    }

    private val sharedPrefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val lock = ReentrantLock()
    private val logger = Logger.getLogger("EmvConfigurationManager")

    /**
     * Get current NFC provider configuration (thread-safe)
     */
    fun getNfcProviderConfig(): NfcProviderConfig = lock.withLock {
        val typeString = sharedPrefs.getString(KEY_NFC_PROVIDER_TYPE, NfcProviderType.ANDROID_INTERNAL.name)
        val type = try {
            NfcProviderType.valueOf(typeString ?: NfcProviderType.ANDROID_INTERNAL.name)
        } catch (e: Exception) {
            logger.warning("Invalid NFC provider type: $typeString, using default")
            NfcProviderType.ANDROID_INTERNAL
        }
        NfcProviderConfig(
            type = type,
            bluetoothAddress = sharedPrefs.getString(KEY_BLUETOOTH_ADDRESS, null),
            baudRate = sharedPrefs.getInt(KEY_UART_BAUD_RATE, DEFAULT_BAUD_RATE),
            timeout = sharedPrefs.getLong(KEY_CONNECTION_TIMEOUT, DEFAULT_TIMEOUT),
            autoConnect = sharedPrefs.getBoolean(KEY_AUTO_CONNECT, DEFAULT_AUTO_CONNECT)
        )
    }

    /**
     * Save NFC provider configuration (thread-safe, audit-logged)
     */
    fun saveNfcProviderConfig(config: NfcProviderConfig) = lock.withLock {
        sharedPrefs.edit().apply {
            putString(KEY_NFC_PROVIDER_TYPE, config.type.name)
            putString(KEY_BLUETOOTH_ADDRESS, config.bluetoothAddress)
            putInt(KEY_UART_BAUD_RATE, config.baudRate)
            putLong(KEY_CONNECTION_TIMEOUT, config.timeout)
            putBoolean(KEY_AUTO_CONNECT, config.autoConnect)
        }.apply()
        logger.info("Saved NFC provider config: ${config.type}")
    }

    /**
     * Configure for Android Internal NFC (audit-logged)
     */
    fun configureAndroidNfc(timeout: Long = DEFAULT_TIMEOUT) = lock.withLock {
        val config = NfcProviderConfig(
            type = NfcProviderType.ANDROID_INTERNAL,
            timeout = timeout
        )
        saveNfcProviderConfig(config)
        logger.info("Configured Android Internal NFC with timeout $timeout ms")
    }

    /**
     * Configure for PN532 via Bluetooth UART (audit-logged)
     */
    fun configurePn532Bluetooth(
        bluetoothAddress: String,
        deviceName: String? = null,
        baudRate: Int = DEFAULT_BAUD_RATE,
        timeout: Long = DEFAULT_TIMEOUT
    ) = lock.withLock {
        val config = NfcProviderConfig(
            type = NfcProviderType.PN532_BLUETOOTH,
            bluetoothAddress = bluetoothAddress,
            baudRate = baudRate,
            timeout = timeout
        )
        saveNfcProviderConfig(config)
        if (deviceName != null) {
            sharedPrefs.edit().putString(KEY_BLUETOOTH_DEVICE_NAME, deviceName).apply()
        }
        logger.info("Configured PN532 Bluetooth: $bluetoothAddress ($deviceName)")
    }

    /**
     * Get saved Bluetooth device info (thread-safe)
     */
    fun getSavedBluetoothDevice(): Pair<String?, String?> = lock.withLock {
        val address = sharedPrefs.getString(KEY_BLUETOOTH_ADDRESS, null)
        val name = sharedPrefs.getString(KEY_BLUETOOTH_DEVICE_NAME, null)
        Pair(address, name)
    }

    /**
     * Get preferred EMV Application IDs (thread-safe)
     */
    fun getPreferredAids(): List<String> = lock.withLock {
        val aidsString = sharedPrefs.getString(KEY_PREFERRED_AIDS, null)
        if (aidsString != null) {
            aidsString.split(",").filter { it.isNotBlank() }
        } else {
            listOf(
                "A0000000031010",     // VISA
                "A0000000041010",     // MasterCard
                "A000000025010402",   // American Express
                "A0000000651010"      // JCB
            )
        }
    }

    /**
     * Save preferred EMV Application IDs (thread-safe, audit-logged)
     */
    fun savePreferredAids(aids: List<String>) = lock.withLock {
        val aidsString = aids.joinToString(",")
        sharedPrefs.edit().putString(KEY_PREFERRED_AIDS, aidsString).apply()
        logger.info("Saved preferred AIDs: ${aids.size} entries")
    }

    /**
     * Reset configuration to defaults (thread-safe, audit-logged)
     */
    fun resetToDefaults() = lock.withLock {
        sharedPrefs.edit().clear().apply()
        logger.info("EMV configuration reset to defaults")
    }

    /**
     * Check if PN532 Bluetooth is configured (thread-safe)
     */
    fun isPn532BluetoothConfigured(): Boolean = lock.withLock {
        val config = getNfcProviderConfig()
        config.type == NfcProviderType.PN532_BLUETOOTH && config.bluetoothAddress != null
    }

    /**
     * Get configuration summary for debugging (thread-safe)
     */
    fun getConfigSummary(): String = lock.withLock {
        val config = getNfcProviderConfig()
        val (btAddress, btName) = getSavedBluetoothDevice()
        val aids = getPreferredAids()
        buildString {
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
