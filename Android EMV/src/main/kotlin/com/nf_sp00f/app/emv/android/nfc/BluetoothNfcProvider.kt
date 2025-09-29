/**
 * nf-sp00f EMV Engine - Enterprise Bluetooth NFC Provider
 *
 * Production-grade Bluetooth NFC provider implementation with comprehensive validation.
 * Zero defensive programming - explicit business logic validation.
 *
 * @package com.nf_sp00f.app.emv.nfc
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv.nfc

import android.content.Context
import com.nf_sp00f.app.emv.apdu.ApduCommand
import com.nf_sp00f.app.emv.apdu.ApduResponse
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import timber.log.Timber
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Bluetooth NFC Provider state management
 */
enum class BluetoothProviderState {
    UNINITIALIZED,
    INITIALIZED,
    CONNECTING,
    CONNECTED,
    READY,
    DISCONNECTED,
    ERROR,
    TIMEOUT
}

/**
 * Target management for Bluetooth NFC operations
 */
data class BluetoothTarget(
    val targetId: Byte,
    val cardInfo: CardInfo,
    val isSelected: Boolean = false,
    val lastActivity: Long = System.currentTimeMillis()
) {
    
    /**
     * Check if target is still active
     */
    fun isActive(maxIdleTime: Long = 30000L): Boolean {
        return System.currentTimeMillis() - lastActivity < maxIdleTime
    }
    
    /**
     * Update last activity timestamp
     */
    fun updateActivity(): BluetoothTarget {
        return copy(lastActivity = System.currentTimeMillis())
    }
}

/**
 * Enterprise Bluetooth NFC Provider Implementation
 */
class BluetoothNfcProvider(
    private val context: Context,
    private val deviceAddress: String
) : INfcProvider {
    
    companion object {
        private const val TAG = "BluetoothNfcProvider"
        private const val PROVIDER_NAME = "Bluetooth PN532"
        private const val PROVIDER_VERSION = "1.0.0"
        private const val MAX_TARGETS = 2
        private const val TARGET_TIMEOUT = 30000L
        private const val DETECTION_TIMEOUT = 10000L
    }
    
    private val bluetoothAdapter = BluetoothNfcAdapter(context, deviceAddress)
    private val providerState = AtomicBoolean(false)
    private val initializationState = AtomicBoolean(false)
    private val connectionCounter = AtomicLong(0)
    
    private val activeTargets = ConcurrentHashMap<Byte, BluetoothTarget>()
    private var selectedTarget: BluetoothTarget? = null
    
    private val providerScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    /**
     * Initialize provider with enterprise validation
     */
    override suspend fun initialize(): Boolean {
        if (initializationState.get()) {
            BluetoothProviderLogger.logInitialization("PROVIDER", "ALREADY_INITIALIZED")
            return true
        }
        
        BluetoothProviderLogger.logInitialization("PROVIDER", "INITIALIZING")
        
        return try {
            validateInitializationEnvironment()
            
            // Connect to Bluetooth adapter
            val connected = bluetoothAdapter.connect()
            if (!connected) {
                throw IllegalStateException("Failed to connect to Bluetooth adapter")
            }
            
            // Verify adapter capabilities
            validateAdapterCapabilities()
            
            initializationState.set(true)
            providerState.set(true)
            
            BluetoothProviderLogger.logInitialization("PROVIDER", "SUCCESS")
            true
        } catch (e: Exception) {
            cleanup()
            BluetoothProviderLogger.logInitialization("PROVIDER", "FAILED: ${e.message}")
            false
        }
    }
    
    /**
     * Check if provider is ready for operations
     */
    override fun isReady(): Boolean = initializationState.get() && providerState.get() && bluetoothAdapter.isReady()
    
    /**
     * Check if provider is initialized
     */
    override fun isInitialized(): Boolean = initializationState.get()
    
    /**
     * Get provider information
     */
    override fun getProviderInfo(): NfcProviderInfo {
        return NfcProviderInfo(
            name = PROVIDER_NAME,
            version = PROVIDER_VERSION,
            type = NfcProviderType.BLUETOOTH,
            capabilities = getCapabilities(),
            deviceInfo = getDeviceInfo()
        )
    }
    
    /**
     * Get provider capabilities
     */
    override fun getCapabilities(): NfcCapabilities = bluetoothAdapter.getCapabilities()
    
    /**
     * Detect available cards
     */
    override suspend fun getDetectedCards(): List<CardInfo> {
        validateProviderState()
        
        BluetoothProviderLogger.logCardDetection("STARTING", 0)
        
        val detectedCards = mutableListOf<CardInfo>()
        
        try {
            // Clear previous targets
            clearActiveTargets()
            
            // Detect Type A cards
            val typeACards = bluetoothAdapter.detectTypeACards(MAX_TARGETS)
            detectedCards.addAll(typeACards)
            
            // Detect Type B cards if no Type A found
            if (typeACards.isEmpty()) {
                val typeBCards = bluetoothAdapter.detectTypeBCards(MAX_TARGETS)
                detectedCards.addAll(typeBCards)
            }
            
            // Register detected targets
            registerDetectedTargets(detectedCards)
            
            BluetoothProviderLogger.logCardDetection("SUCCESS", detectedCards.size)
            
            return detectedCards
        } catch (e: Exception) {
            BluetoothProviderLogger.logCardDetection("FAILED", 0)
            throw EmvException("Card detection failed: ${e.message}", e)
        }
    }
    
    /**
     * Select application on card
     */
    override suspend fun selectApplication(aidHex: String): ByteArray {
        validateProviderState()
        validateApplicationAid(aidHex)
        
        val target = getSelectedTarget()
        val aid = hexToByteArray(aidHex)
        
        BluetoothProviderLogger.logApplicationSelection(aidHex, "STARTING")
        
        try {
            val selectCommand = ApduCommand.createSelectCommand(aid)
            val commandBytes = selectCommand.toByteArray()
            
            val responseBytes = bluetoothAdapter.exchangeData(target.targetId, commandBytes)
            val response = ApduResponse.fromByteArray(responseBytes)
            
            if (response.isSuccess()) {
                BluetoothProviderLogger.logApplicationSelection(aidHex, "SUCCESS")
                return response.data
            } else {
                BluetoothProviderLogger.logApplicationSelection(aidHex, "FAILED: ${response.getStatusWordHex()}")
                throw EmvException("Application selection failed: ${response.getDescription()}")
            }
        } catch (e: Exception) {
            BluetoothProviderLogger.logApplicationSelection(aidHex, "ERROR: ${e.message}")
            throw EmvException("Application selection error: ${e.message}", e)
        }
    }
    
    /**
     * Send APDU command to card
     */
    override suspend fun sendApduCommand(apduCommand: ApduCommand): ApduResponse {
        validateProviderState()
        validateApduCommand(apduCommand)
        
        val target = getSelectedTarget()
        
        BluetoothProviderLogger.logApduCommand(apduCommand.getCommandName(), "SENDING")
        
        return try {
            val commandBytes = apduCommand.toByteArray()
            val responseBytes = bluetoothAdapter.exchangeData(target.targetId, commandBytes)
            
            val response = ApduResponse.fromByteArray(responseBytes)
            
            BluetoothProviderLogger.logApduCommand(apduCommand.getCommandName(), 
                if (response.isSuccess()) "SUCCESS" else "FAILED")
            
            response
        } catch (e: Exception) {
            BluetoothProviderLogger.logApduCommand(apduCommand.getCommandName(), "ERROR: ${e.message}")
            throw EmvException("APDU command failed: ${e.message}", e)
        }
    }
    
    /**
     * Connect to card (select target)
     */
    override suspend fun connect(): Boolean {
        validateProviderState()
        
        if (activeTargets.isEmpty()) {
            throw IllegalStateException("No detected cards available for connection")
        }
        
        // Select first available target
        val firstTarget = activeTargets.values.first()
        
        return try {
            val selected = bluetoothAdapter.selectTarget(firstTarget.targetId)
            
            if (selected) {
                selectedTarget = firstTarget.copy(isSelected = true).updateActivity()
                activeTargets[firstTarget.targetId] = selectedTarget!!
                
                BluetoothProviderLogger.logTargetSelection(firstTarget.targetId.toString(), "SUCCESS")
                true
            } else {
                BluetoothProviderLogger.logTargetSelection(firstTarget.targetId.toString(), "FAILED")
                false
            }
        } catch (e: Exception) {
            BluetoothProviderLogger.logTargetSelection(firstTarget.targetId.toString(), "ERROR: ${e.message}")
            false
        }
    }
    
    /**
     * Disconnect from card
     */
    override suspend fun disconnect(): Boolean {
        return try {
            selectedTarget?.let { target ->
                val deselected = bluetoothAdapter.deselectTarget(target.targetId)
                
                if (deselected) {
                    selectedTarget = null
                    BluetoothProviderLogger.logTargetSelection(target.targetId.toString(), "DISCONNECTED")
                } else {
                    BluetoothProviderLogger.logTargetSelection(target.targetId.toString(), "DISCONNECT_FAILED")
                }
                
                deselected
            } ?: true // Already disconnected
        } catch (e: Exception) {
            BluetoothProviderLogger.logTargetSelection("UNKNOWN", "DISCONNECT_ERROR: ${e.message}")
            false
        }
    }
    
    /**
     * Cleanup provider resources
     */
    override suspend fun cleanup(): Boolean {
        BluetoothProviderLogger.logCleanup("STARTING")
        
        return try {
            // Disconnect from current target
            disconnect()
            
            // Clear active targets
            clearActiveTargets()
            
            // Disconnect Bluetooth adapter
            bluetoothAdapter.disconnect()
            
            // Reset state
            providerState.set(false)
            initializationState.set(false)
            selectedTarget = null
            
            BluetoothProviderLogger.logCleanup("SUCCESS")
            true
        } catch (e: Exception) {
            BluetoothProviderLogger.logCleanup("ERROR: ${e.message}")
            false
        }
    }
    
    /**
     * Get device-specific information
     */
    fun getDeviceInfo(): Map<String, String> {
        return mapOf(
            "deviceAddress" to deviceAddress,
            "adapterType" to "PN532",
            "connectionType" to "Bluetooth",
            "activeTargets" to activeTargets.size.toString(),
            "hasSelectedTarget" to (selectedTarget != null).toString()
        )
    }
    
    /**
     * Get selected target with validation
     */
    private fun getSelectedTarget(): BluetoothTarget {
        val target = selectedTarget
        if (target == null || !target.isSelected) {
            throw IllegalStateException("No target selected for communication")
        }
        
        if (!target.isActive(TARGET_TIMEOUT)) {
            throw IllegalStateException("Selected target has timed out")
        }
        
        return target
    }
    
    /**
     * Register detected targets for management
     */
    private fun registerDetectedTargets(cards: List<CardInfo>) {
        clearActiveTargets()
        
        cards.forEachIndexed { index, cardInfo ->
            val targetId = (index + 1).toByte()
            val target = BluetoothTarget(targetId, cardInfo)
            activeTargets[targetId] = target
            
            BluetoothProviderLogger.logTargetRegistration(targetId.toString(), cardInfo.cardType.name)
        }
    }
    
    /**
     * Clear all active targets
     */
    private fun clearActiveTargets() {
        activeTargets.clear()
        selectedTarget = null
    }
    
    /**
     * Convert hex string to byte array
     */
    private fun hexToByteArray(hex: String): ByteArray {
        val cleanHex = hex.replace(" ", "").replace(":", "")
        
        if (cleanHex.length % 2 != 0) {
            throw IllegalArgumentException("Invalid hex string length: ${cleanHex.length}")
        }
        
        return cleanHex.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
    
    /**
     * Enterprise validation functions
     */
    private fun validateInitializationEnvironment() {
        if (deviceAddress.isBlank()) {
            throw IllegalArgumentException("Device address cannot be blank")
        }
        
        BluetoothProviderLogger.logValidation("INIT_ENV", "SUCCESS", "Initialization environment validated")
    }
    
    private fun validateAdapterCapabilities() {
        val capabilities = bluetoothAdapter.getCapabilities()
        
        if (!capabilities.supportsTypeA && !capabilities.supportsTypeB) {
            throw IllegalStateException("Adapter doesn't support required card types")
        }
        
        if (capabilities.maxApduLength < 261) {
            throw IllegalStateException("Adapter APDU buffer too small: ${capabilities.maxApduLength}")
        }
        
        BluetoothProviderLogger.logValidation("CAPABILITIES", "SUCCESS", "Adapter capabilities validated")
    }
    
    private fun validateProviderState() {
        if (!isReady()) {
            throw IllegalStateException("Provider not ready for operations")
        }
    }
    
    private fun validateApplicationAid(aidHex: String) {
        if (aidHex.isBlank()) {
            throw IllegalArgumentException("AID cannot be blank")
        }
        
        val cleanHex = aidHex.replace(" ", "").replace(":", "")
        if (cleanHex.length < 10 || cleanHex.length > 32) {
            throw IllegalArgumentException("Invalid AID length: ${cleanHex.length} (expected 10-32)")
        }
        
        if (!cleanHex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
            throw IllegalArgumentException("Invalid AID format: contains non-hex characters")
        }
        
        BluetoothProviderLogger.logValidation("AID", "SUCCESS", "AID validated")
    }
    
    private fun validateApduCommand(apduCommand: ApduCommand) {
        if (apduCommand.getTotalLength() > getCapabilities().maxApduLength) {
            throw IllegalArgumentException("APDU command exceeds maximum length: ${apduCommand.getTotalLength()}")
        }
        
        BluetoothProviderLogger.logValidation("APDU_COMMAND", "SUCCESS", "APDU command validated")
    }
}

/**
 * Bluetooth Provider Logger for enterprise environments
 */
object BluetoothProviderLogger {
    fun logInitialization(component: String, result: String) {
        val timestamp = System.currentTimeMillis()
        println("BLUETOOTH_PROVIDER_AUDIT: [$timestamp] INITIALIZATION - component=$component result=$result")
    }
    
    fun logCardDetection(status: String, count: Int) {
        val timestamp = System.currentTimeMillis()
        println("BLUETOOTH_PROVIDER_AUDIT: [$timestamp] CARD_DETECTION - status=$status count=$count")
    }
    
    fun logApplicationSelection(aid: String, result: String) {
        val timestamp = System.currentTimeMillis()
        println("BLUETOOTH_PROVIDER_AUDIT: [$timestamp] APP_SELECTION - aid=$aid result=$result")
    }
    
    fun logApduCommand(command: String, result: String) {
        val timestamp = System.currentTimeMillis()
        println("BLUETOOTH_PROVIDER_AUDIT: [$timestamp] APDU_COMMAND - command=$command result=$result")
    }
    
    fun logTargetSelection(targetId: String, result: String) {
        val timestamp = System.currentTimeMillis()
        println("BLUETOOTH_PROVIDER_AUDIT: [$timestamp] TARGET_SELECTION - targetId=$targetId result=$result")
    }
    
    fun logTargetRegistration(targetId: String, cardType: String) {
        val timestamp = System.currentTimeMillis()
        println("BLUETOOTH_PROVIDER_AUDIT: [$timestamp] TARGET_REGISTERED - targetId=$targetId cardType=$cardType")
    }
    
    fun logCleanup(result: String) {
        val timestamp = System.currentTimeMillis()
        println("BLUETOOTH_PROVIDER_AUDIT: [$timestamp] CLEANUP - result=$result")
    }
    
    fun logValidation(component: String, result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("BLUETOOTH_PROVIDER_AUDIT: [$timestamp] VALIDATION - component=$component result=$result details=$details")
    }
}
