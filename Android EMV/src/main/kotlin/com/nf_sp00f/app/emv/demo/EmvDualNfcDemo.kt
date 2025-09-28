package com.nf_sp00f.app.emv.demo

import android.nfc.Tag
import com.nf_sp00f.app.emv.EmvEngine
import com.nf_sp00f.app.emv.config.EmvConfigurationManager
import com.nf_sp00f.app.emv.nfc.NfcProviderConfig
import com.nf_sp00f.app.emv.nfc.NfcProviderType
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.collect
import timber.log.Timber

/**
 * EMV Dual NFC Demo
 * 
 * Demonstrates usage of the EMV library with both Android Internal NFC
 * and PN532 connected via Bluetooth UART (HC-06).
 */
class EmvDualNfcDemo(private val configManager: EmvConfigurationManager) {
    
    private val emvEngine = EmvEngine.getInstance()
    
    /**
     * Demo: Process EMV card with Android Internal NFC
     */
    suspend fun processCardWithAndroidNfc(tag: Tag): String = withContext(Dispatchers.Main) {
        try {
            Timber.i("=== EMV Processing with Android Internal NFC ===")
            
            // Configure for Android Internal NFC
            val config = NfcProviderConfig(NfcProviderType.ANDROID_INTERNAL)
            
            // Initialize EMV engine
            if (!emvEngine.initialize(config)) {
                return@withContext "❌ Failed to initialize EMV engine for Android NFC"
            }
            
            val results = mutableListOf<String>()
            results.add("✅ EMV Engine initialized with Android Internal NFC")
            
            // Process the card
            emvEngine.processCard(tag = tag).collect { step ->
                when (step) {
                    is com.nf_sp00f.app.emv.EmvTransactionStep.Connecting -> {
                        results.add("🔗 Connecting to card...")
                    }
                    is com.nf_sp00f.app.emv.EmvTransactionStep.SelectingApplication -> {
                        results.add("🎯 Selecting EMV application...")
                    }
                    is com.nf_sp00f.app.emv.EmvTransactionStep.ProcessingTransaction -> {
                        results.add("⚡ Processing EMV transaction...")
                    }
                    is com.nf_sp00f.app.emv.EmvTransactionStep.Success -> {
                        results.add("✅ EMV Transaction completed successfully!")
                        results.add("   Card Vendor: ${step.result.cardVendor}")
                        results.add("   Application: ${step.result.applicationLabel}")
                        results.add("   PAN: ${step.result.pan}")
                    }
                    is com.nf_sp00f.app.emv.EmvTransactionStep.Error -> {
                        results.add("❌ EMV Error: ${step.message}")
                    }
                }
            }
            
            results.joinToString("\n")
            
        } catch (e: Exception) {
            Timber.e(e, "Error in Android NFC demo")
            "❌ Android NFC Demo Error: ${e.message}"
        }
    }
    
    /**
     * Demo: Process EMV card with PN532 via Bluetooth
     */
    suspend fun processCardWithPn532Bluetooth(bluetoothAddress: String): String = withContext(Dispatchers.Main) {
        try {
            Timber.i("=== EMV Processing with PN532 Bluetooth ===")
            
            // Configure for PN532 Bluetooth
            val config = NfcProviderConfig(
                type = NfcProviderType.PN532_BLUETOOTH,
                bluetoothAddress = bluetoothAddress,
                baudRate = 115200,
                timeout = 30000L
            )
            
            // Initialize EMV engine
            if (!emvEngine.initialize(config)) {
                return@withContext "❌ Failed to initialize EMV engine for PN532 Bluetooth"
            }
            
            val results = mutableListOf<String>()
            results.add("✅ EMV Engine initialized with PN532 Bluetooth")
            results.add("   Bluetooth Address: $bluetoothAddress")
            
            // Process the card (no tag parameter needed for PN532)
            emvEngine.processCard().collect { step ->
                when (step) {
                    is com.nf_sp00f.app.emv.EmvTransactionStep.Connecting -> {
                        results.add("🔗 Connecting to PN532 via Bluetooth...")
                    }
                    is com.nf_sp00f.app.emv.EmvTransactionStep.SelectingApplication -> {
                        results.add("🎯 Selecting EMV application with PN532...")
                    }
                    is com.nf_sp00f.app.emv.EmvTransactionStep.ProcessingTransaction -> {
                        results.add("⚡ Processing EMV transaction via PN532...")
                    }
                    is com.nf_sp00f.app.emv.EmvTransactionStep.Success -> {
                        results.add("✅ PN532 EMV Transaction completed successfully!")
                        results.add("   Card Vendor: ${step.result.cardVendor}")
                        results.add("   Application: ${step.result.applicationLabel}")
                        results.add("   PAN: ${step.result.pan}")
                    }
                    is com.nf_sp00f.app.emv.EmvTransactionStep.Error -> {
                        results.add("❌ PN532 EMV Error: ${step.message}")
                    }
                }
            }
            
            results.joinToString("\n")
            
        } catch (e: Exception) {
            Timber.e(e, "Error in PN532 Bluetooth demo")
            "❌ PN532 Bluetooth Demo Error: ${e.message}"
        }
    }
    
    /**
     * Demo: Auto-detect and configure best NFC provider
     */
    suspend fun autoDetectAndConfigure(): String = withContext(Dispatchers.Default) {
        try {
            Timber.i("=== Auto-detecting NFC Providers ===")
            
            val results = mutableListOf<String>()
            results.add("🔍 Auto-detecting available NFC providers...")
            
            // Check Android Internal NFC
            val androidNfcAvailable = emvEngine.isNfcProviderAvailable(NfcProviderType.ANDROID_INTERNAL)
            results.add("   Android Internal NFC: ${if (androidNfcAvailable) "✅ Available" else "❌ Not Available"}")
            
            // Check PN532 Bluetooth (need configured address)
            val (btAddress, btName) = configManager.getSavedBluetoothDevice()
            val pn532Available = if (btAddress != null) {
                emvEngine.isNfcProviderAvailable(NfcProviderType.PN532_BLUETOOTH)
            } else {
                false
            }
            results.add("   PN532 Bluetooth: ${if (pn532Available) "✅ Available ($btName)" else "❌ Not Available"}")
            
            // Auto-configure best option
            when {
                androidNfcAvailable -> {
                    configManager.configureAndroidNfc()
                    results.add("🎯 Configured for Android Internal NFC")
                }
                pn532Available -> {
                    results.add("🎯 Configured for PN532 Bluetooth ($btAddress)")
                }
                else -> {
                    results.add("❌ No NFC providers available")
                }
            }
            
            results.joinToString("\n")
            
        } catch (e: Exception) {
            Timber.e(e, "Error in auto-detection")
            "❌ Auto-detection Error: ${e.message}"
        }
    }
    
    /**
     * Demo: Configure PN532 Bluetooth device
     */
    fun configurePn532Device(bluetoothAddress: String, deviceName: String = "HC-06"): String {
        try {
            Timber.i("=== Configuring PN532 Bluetooth Device ===")
            
            configManager.configurePn532Bluetooth(
                bluetoothAddress = bluetoothAddress,
                deviceName = deviceName,
                baudRate = 115200,
                timeout = 30000L
            )
            
            return buildString {
                appendLine("✅ PN532 Bluetooth Configuration Saved")
                appendLine("   Device: $deviceName")
                appendLine("   Address: $bluetoothAddress")
                appendLine("   Baud Rate: 115200")
                appendLine("   Timeout: 30 seconds")
                appendLine("")
                appendLine("💡 You can now use PN532 for EMV processing!")
            }
            
        } catch (e: Exception) {
            Timber.e(e, "Error configuring PN532")
            return "❌ PN532 Configuration Error: ${e.message}"
        }
    }
    
    /**
     * Get current configuration status
     */
    fun getConfigurationStatus(): String {
        return try {
            buildString {
                appendLine("📋 EMV Configuration Status")
                appendLine("=" * 40)
                appendLine()
                append(configManager.getConfigSummary())
                appendLine()
                
                val (providerType, capabilities) = emvEngine.getNfcProviderInfo()
                appendLine("Current NFC Provider: $providerType")
                
                capabilities?.let { caps ->
                    appendLine("Provider Capabilities:")
                    appendLine("  - Supported Cards: ${caps.supportedCardTypes.joinToString(", ")}")
                    appendLine("  - Max APDU Length: ${caps.maxApduLength}")
                    appendLine("  - Extended Length: ${caps.supportsExtendedLength}")
                    appendLine("  - Field Control: ${caps.canControlField}")
                }
            }
        } catch (e: Exception) {
            "❌ Error getting configuration status: ${e.message}"
        }
    }
}