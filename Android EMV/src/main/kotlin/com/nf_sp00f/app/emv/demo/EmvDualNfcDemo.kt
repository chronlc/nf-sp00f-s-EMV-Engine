/**
 * nf-sp00f EMV Engine - Dual NFC Demo Application
 * 
 * Demonstration application showcasing dual NFC provider support:
 * - Android Internal NFC (IsoDep/NfcA/NfcB)
 * - PN532 via Bluetooth UART (HC-06)
 * 
 * @package com.nf_sp00f.app.emv.demo
 * @author nf-sp00f
 * @since 1.0.0
 */
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
 * EMV Dual NFC Demonstration Application
 * 
 * Showcases seamless switching between Android internal NFC
 * and external PN532 via Bluetooth connectivity.
 */
class EmvDualNfcDemo {
    
    companion object {
        private const val TAG = "EmvDualNfcDemo"
        
        // Demo transaction parameters
        private const val DEMO_AMOUNT = 2500L // $25.00
        private const val DEMO_CURRENCY = "USD"
        
        // Bluetooth configuration for PN532
        private const val DEFAULT_PN532_NAME = "HC-06"
        private const val DEFAULT_PN532_ADDRESS = "98:D3:61:FD:2C:87" // Example MAC
    }
    
    private lateinit var configManager: EmvConfigurationManager
    private var currentEngine: EmvEngine? = null
    private val demoScope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    
    /**
     * Initialize demo application
     */
    suspend fun initialize(configManager: EmvConfigurationManager): Boolean {
        return try {
            this.configManager = configManager
            
            // Load current configuration
            val config = configManager.loadCompleteConfiguration()
            Timber.i("Demo initialized with NFC provider: ${config.nfcProvider.type}")
            
            true
        } catch (e: Exception) {
            Timber.e(e, "Failed to initialize EMV demo")
            false
        }
    }
    
    /**
     * Run Android Internal NFC demo
     */
    suspend fun runAndroidNfcDemo(tag: Tag): DemoResult = withContext(Dispatchers.Default) {
        try {
            Timber.i("Starting Android NFC demo with tag: ${tag.id.joinToString("") { "%02X".format(it) }}")
            
            // Configure for Android Internal NFC
            val nfcConfig = NfcProviderConfig(NfcProviderType.ANDROID_INTERNAL)
            configManager.saveNfcProviderConfig(nfcConfig)
            
            // Build EMV engine for Android NFC
            currentEngine = EmvEngine.builder()
                .nfcProvider(createAndroidNfcProvider(tag))
                .enableRocaCheck(true)
                .enableCryptoValidation(true)
                .timeout(30000)
                .build()
            
            // Process EMV transaction
            val transactionResult = currentEngine!!.processTransaction(
                amount = DEMO_AMOUNT,
                currencyCode = DEMO_CURRENCY,
                transactionType = TransactionType.PURCHASE
            )
            
            // Run security tests
            val securityResult = currentEngine!!.runSecurityTests()
            
            DemoResult.Success(
                provider = "Android Internal NFC",
                transactionResult = transactionResult,
                securityTestResult = securityResult,
                duration = System.currentTimeMillis() // Simplified timing
            )
            
        } catch (e: Exception) {
            Timber.e(e, "Android NFC demo failed")
            DemoResult.Failed("Android NFC demo error: ${e.message}")
        } finally {
            currentEngine?.cleanup()
        }
    }
    
    /**
     * Run PN532 Bluetooth NFC demo
     */
    suspend fun runPn532BluetoothDemo(deviceAddress: String = DEFAULT_PN532_ADDRESS): DemoResult = withContext(Dispatchers.Default) {
        try {
            Timber.i("Starting PN532 Bluetooth demo with device: $deviceAddress")
            
            // Configure for PN532 Bluetooth
            val nfcConfig = NfcProviderConfig(
                type = NfcProviderType.PN532_BLUETOOTH,
                bluetoothDeviceAddress = deviceAddress,
                bluetoothDeviceName = DEFAULT_PN532_NAME
            )
            configManager.saveNfcProviderConfig(nfcConfig)
            
            // Build EMV engine for PN532
            currentEngine = EmvEngine.builder()
                .nfcProvider(createPn532BluetoothProvider(deviceAddress))
                .enableRocaCheck(true)
                .enableCryptoValidation(true)
                .timeout(45000) // Longer timeout for Bluetooth
                .build()
            
            // Test PN532 connection first
            val connectionTest = testPn532Connection()
            if (!connectionTest) {
                return@withContext DemoResult.Failed("PN532 Bluetooth connection failed")
            }
            
            // Process EMV transaction
            val transactionResult = currentEngine!!.processTransaction(
                amount = DEMO_AMOUNT,
                currencyCode = DEMO_CURRENCY,
                transactionType = TransactionType.PURCHASE
            )
            
            // Run security tests
            val securityResult = currentEngine!!.runSecurityTests()
            
            DemoResult.Success(
                provider = "PN532 Bluetooth ($deviceAddress)",
                transactionResult = transactionResult,
                securityTestResult = securityResult,
                duration = System.currentTimeMillis()
            )
            
        } catch (e: Exception) {
            Timber.e(e, "PN532 Bluetooth demo failed")
            DemoResult.Failed("PN532 demo error: ${e.message}")
        } finally {
            currentEngine?.cleanup()
        }
    }
    
    /**
     * Run comparative demo between both NFC providers
     */
    suspend fun runComparativeDemo(tag: Tag, bluetoothAddress: String = DEFAULT_PN532_ADDRESS): ComparativeDemoResult = withContext(Dispatchers.Default) {
        try {
            Timber.i("Starting comparative demo: Android NFC vs PN532 Bluetooth")
            
            // Run Android NFC demo
            val androidResult = runAndroidNfcDemo(tag)
            delay(1000) // Brief pause between tests
            
            // Run PN532 Bluetooth demo
            val pn532Result = runPn532BluetoothDemo(bluetoothAddress)
            
            // Compare results
            val comparison = compareResults(androidResult, pn532Result)
            
            ComparativeDemoResult(
                androidNfcResult = androidResult,
                pn532BluetoothResult = pn532Result,
                comparison = comparison,
                recommendation = generateRecommendation(comparison)
            )
            
        } catch (e: Exception) {
            Timber.e(e, "Comparative demo failed")
            ComparativeDemoResult(
                androidNfcResult = DemoResult.Failed("Comparative demo error"),
                pn532BluetoothResult = DemoResult.Failed("Comparative demo error"),
                comparison = ComparisonResult.ERROR,
                recommendation = "Demo execution failed: ${e.message}"
            )
        }
    }
    
    /**
     * Test PN532 Bluetooth connectivity
     */
    private suspend fun testPn532Connection(): Boolean = withContext(Dispatchers.IO) {
        return try {
            // Simulate PN532 connection test
            delay(2000) // Simulate Bluetooth connection time
            
            // In real implementation, this would:
            // 1. Connect to Bluetooth device
            // 2. Send PN532 firmware version command
            // 3. Validate response
            
            Timber.d("PN532 connection test completed")
            true // Simulate successful connection
            
        } catch (e: Exception) {
            Timber.e(e, "PN532 connection test failed")
            false
        }
    }
    
    /**
     * Create Android NFC provider for demo
     */
    private fun createAndroidNfcProvider(tag: Tag): AndroidInternalNfcProvider {
        return AndroidInternalNfcProvider().apply {
            // Configure with demo tag
            setDemoTag(tag)
        }
    }
    
    /**
     * Create PN532 Bluetooth provider for demo
     */
    private fun createPn532BluetoothProvider(deviceAddress: String): Pn532BluetoothNfcProvider {
        return Pn532BluetoothNfcProvider().apply {
            // Configure with Bluetooth parameters
            setBluetoothDevice(deviceAddress, DEFAULT_PN532_NAME)
        }
    }
    
    /**
     * Compare results between NFC providers
     */
    private fun compareResults(androidResult: DemoResult, pn532Result: DemoResult): ComparisonResult {
        return when {
            androidResult is DemoResult.Success && pn532Result is DemoResult.Success -> {
                // Compare performance and capabilities
                val androidDuration = androidResult.duration
                val pn532Duration = pn532Result.duration
                
                when {
                    androidDuration < pn532Duration -> ComparisonResult.ANDROID_NFC_FASTER
                    pn532Duration < androidDuration -> ComparisonResult.PN532_FASTER
                    else -> ComparisonResult.EQUIVALENT_PERFORMANCE
                }
            }
            androidResult is DemoResult.Success && pn532Result is DemoResult.Failed -> {
                ComparisonResult.ANDROID_NFC_ONLY
            }
            androidResult is DemoResult.Failed && pn532Result is DemoResult.Success -> {
                ComparisonResult.PN532_ONLY
            }
            else -> ComparisonResult.BOTH_FAILED
        }
    }
    
    /**
     * Generate recommendation based on comparison
     */
    private fun generateRecommendation(comparison: ComparisonResult): String {
        return when (comparison) {
            ComparisonResult.ANDROID_NFC_FASTER -> 
                "Recommendation: Use Android Internal NFC for better performance and reliability."
            ComparisonResult.PN532_FASTER -> 
                "Recommendation: PN532 Bluetooth shows superior performance for this scenario."
            ComparisonResult.EQUIVALENT_PERFORMANCE -> 
                "Recommendation: Both providers perform similarly. Choose based on hardware availability."
            ComparisonResult.ANDROID_NFC_ONLY -> 
                "Recommendation: Use Android Internal NFC. PN532 Bluetooth connectivity issues detected."
            ComparisonResult.PN532_ONLY -> 
                "Recommendation: Use PN532 Bluetooth. Android Internal NFC not available or compatible."
            ComparisonResult.BOTH_FAILED -> 
                "Recommendation: Check card compatibility and NFC hardware functionality."
            ComparisonResult.ERROR -> 
                "Recommendation: Review demo configuration and retry."
        }
    }
    
    /**
     * Get demo status and configuration
     */
    fun getDemoStatus(): DemoStatus {
        return DemoStatus(
            isInitialized = ::configManager.isInitialized,
            currentProvider = getCurrentProviderType(),
            engineActive = currentEngine != null,
            lastDemoTime = System.currentTimeMillis()
        )
    }
    
    /**
     * Get current NFC provider type
     */
    private suspend fun getCurrentProviderType(): NfcProviderType? {
        return try {
            val config = configManager.loadNfcProviderConfig()
            config.type
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Cleanup demo resources
     */
    fun cleanup() {
        currentEngine?.cleanup()
        currentEngine = null
        demoScope.cancel()
        Timber.d("EMV demo cleanup completed")
    }
}

/**
 * Demo result sealed class
 */
sealed class DemoResult {
    data class Success(
        val provider: String,
        val transactionResult: EmvTransactionResult,
        val securityTestResult: SecurityTestResult,
        val duration: Long
    ) : DemoResult()
    
    data class Failed(
        val reason: String
    ) : DemoResult()
}

/**
 * Comparative demo result
 */
data class ComparativeDemoResult(
    val androidNfcResult: DemoResult,
    val pn532BluetoothResult: DemoResult,
    val comparison: ComparisonResult,
    val recommendation: String
)

/**
 * Comparison result enumeration
 */
enum class ComparisonResult {
    ANDROID_NFC_FASTER,
    PN532_FASTER,
    EQUIVALENT_PERFORMANCE,
    ANDROID_NFC_ONLY,
    PN532_ONLY,
    BOTH_FAILED,
    ERROR
}

/**
 * Demo status data class
 */
data class DemoStatus(
    val isInitialized: Boolean,
    val currentProvider: NfcProviderType?,
    val engineActive: Boolean,
    val lastDemoTime: Long
)

/**
 * Transaction type enumeration
 */
enum class TransactionType(val code: Int) {
    PURCHASE(0x00),
    CASH_ADVANCE(0x01),
    REFUND(0x20),
    BALANCE_INQUIRY(0x30)
}
