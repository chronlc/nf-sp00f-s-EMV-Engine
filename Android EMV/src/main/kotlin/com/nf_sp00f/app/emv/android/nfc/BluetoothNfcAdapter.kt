/**
 * nf-sp00f EMV Engine - Enterprise Bluetooth NFC Adapter
 *
 * Production-grade PN532 Bluetooth NFC adapter with comprehensive validation.
 * Zero defensive programming - explicit business logic validation.
 *
 * @package com.nf_sp00f.app.emv.nfc
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv.nfc

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothSocket
import android.content.Context
import kotlinx.coroutines.*
import timber.log.Timber
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * PN532 Command set for enterprise NFC operations
 */
enum class Pn532Command(val code: Byte, val description: String) {
    // System commands
    GET_FIRMWARE_VERSION(0x02, "Get firmware version"),
    GET_GENERAL_STATUS(0x04, "Get general status"),
    READ_REGISTER(0x06, "Read register"),
    WRITE_REGISTER(0x08, "Write register"),
    
    // RF Configuration
    RF_CONFIGURATION(0x32, "RF configuration"),
    RF_REGULATION_TEST(0x58, "RF regulation test"),
    
    // Card operations
    IN_LIST_PASSIVE_TARGET(0x4A, "List passive targets"),
    IN_ATR(0x50, "ATR command"),
    IN_PSL(0x4E, "Parameter selection"),
    IN_DATA_EXCHANGE(0x40, "Data exchange"),
    IN_COMMUNICATE_THRU(0x42, "Communicate through"),
    IN_DESELECT(0x44, "Deselect target"),
    IN_RELEASE(0x52, "Release target"),
    IN_SELECT(0x54, "Select target"),
    
    // Mifare operations  
    IN_AUTHENTICATE(0x60, "Mifare authenticate"),
    IN_READ(0x30, "Mifare read"),
    IN_WRITE(0xA0, "Mifare write"),
    
    // Power management
    POWER_DOWN(0x16, "Power down"),
    WAKE_UP(0x55, "Wake up")
}

/**
 * PN532 Frame structure for enterprise communication
 */
data class Pn532Frame(
    val command: Pn532Command,
    val data: ByteArray = byteArrayOf(),
    val timeout: Long = 5000L
) {
    
    companion object {
        private const val PREAMBLE = 0x00.toByte()
        private const val START_CODE_1 = 0x00.toByte()
        private const val START_CODE_2 = 0xFF.toByte()
        private const val DIRECTION_HOST_TO_PN532 = 0xD4.toByte()
        private const val DIRECTION_PN532_TO_HOST = 0xD5.toByte()
        private const val POSTAMBLE = 0x00.toByte()
        
        /**
         * Create PN532 command frame with enterprise validation
         */
        fun createCommandFrame(command: Pn532Command, data: ByteArray = byteArrayOf()): ByteArray {
            validateCommandData(command, data)
            
            val payload = byteArrayOf(DIRECTION_HOST_TO_PN532, command.code) + data
            val length = payload.size.toByte()
            val lengthChecksum = (0x100 - length.toInt()).toByte()
            val dataChecksum = calculateChecksum(payload)
            
            val frame = byteArrayOf(
                PREAMBLE,
                START_CODE_1,
                START_CODE_2,
                length,
                lengthChecksum
            ) + payload + byteArrayOf(dataChecksum, POSTAMBLE)
            
            BluetoothNfcLogger.logFrameCreation(command.name, frame.size, "SUCCESS")
            return frame
        }
        
        /**
         * Parse PN532 response frame with enterprise validation
         */
        fun parseResponseFrame(frameData: ByteArray): Pn532Response {
            validateFrameStructure(frameData)
            
            if (frameData.size < 7) {
                throw IllegalArgumentException("Frame too short: ${frameData.size}")
            }
            
            // Validate frame structure
            if (frameData[0] != PREAMBLE || 
                frameData[1] != START_CODE_1 || 
                frameData[2] != START_CODE_2) {
                throw IllegalArgumentException("Invalid frame preamble")
            }
            
            val length = frameData[3].toUByte().toInt()
            val lengthChecksum = frameData[4].toUByte().toInt()
            
            if ((length + lengthChecksum) and 0xFF != 0) {
                throw IllegalArgumentException("Invalid length checksum")
            }
            
            val payload = frameData.copyOfRange(5, 5 + length)
            val receivedChecksum = frameData[5 + length]
            val calculatedChecksum = calculateChecksum(payload)
            
            if (receivedChecksum != calculatedChecksum) {
                throw IllegalArgumentException("Invalid data checksum")
            }
            
            if (payload[0] != DIRECTION_PN532_TO_HOST) {
                throw IllegalArgumentException("Invalid response direction")
            }
            
            val responseCode = payload[1]
            val responseData = if (payload.size > 2) {
                payload.copyOfRange(2, payload.size)
            } else {
                byteArrayOf()
            }
            
            val response = Pn532Response(responseCode, responseData)
            BluetoothNfcLogger.logFrameParsing(responseCode.toString(), responseData.size, "SUCCESS")
            
            return response
        }
        
        private fun validateCommandData(command: Pn532Command, data: ByteArray) {
            if (data.size > 262) { // PN532 max payload - 2 bytes for direction and command
                throw IllegalArgumentException("Command data too large: ${data.size}")
            }
            
            BluetoothNfcLogger.logValidation("COMMAND_DATA", "SUCCESS", "${command.name} validated")
        }
        
        private fun validateFrameStructure(frameData: ByteArray) {
            if (frameData.size > 1024) { // Reasonable max frame size
                throw IllegalArgumentException("Frame too large: ${frameData.size}")
            }
            
            BluetoothNfcLogger.logValidation("FRAME_STRUCTURE", "SUCCESS", "Frame structure validated")
        }
        
        private fun calculateChecksum(data: ByteArray): Byte {
            var sum = 0
            for (byte in data) {
                sum += byte.toUByte().toInt()
            }
            return (0x100 - (sum and 0xFF)).toByte()
        }
    }
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        
        other as Pn532Frame
        
        if (command != other.command) return false
        if (!data.contentEquals(other.data)) return false
        if (timeout != other.timeout) return false
        
        return true
    }
    
    override fun hashCode(): Int {
        var result = command.hashCode()
        result = 31 * result + data.contentHashCode()
        result = 31 * result + timeout.hashCode()
        return result
    }
}

/**
 * PN532 Response structure
 */
data class Pn532Response(
    val responseCode: Byte,
    val data: ByteArray
) {
    
    /**
     * Check if response indicates success
     */
    fun isSuccess(): Boolean = responseCode >= 0
    
    /**
     * Check if response indicates error
     */
    fun isError(): Boolean = responseCode < 0
    
    /**
     * Get response description
     */
    fun getDescription(): String = "PN532 Response: code=0x${responseCode.toString(16).uppercase().padStart(2, '0')}, data=${data.size} bytes"
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        
        other as Pn532Response
        
        if (responseCode != other.responseCode) return false
        if (!data.contentEquals(other.data)) return false
        
        return true
    }
    
    override fun hashCode(): Int {
        var result = responseCode.toInt()
        result = 31 * result + data.contentHashCode()
        return result
    }
    
    override fun toString(): String = getDescription()
}

/**
 * Bluetooth connection state for enterprise monitoring
 */
enum class BluetoothConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    AUTHENTICATING,
    READY,
    ERROR,
    TIMEOUT
}

/**
 * Enterprise Bluetooth NFC Adapter for PN532 devices
 */
class BluetoothNfcAdapter(
    private val context: Context,
    private val deviceAddress: String
) {
    
    companion object {
        private const val TAG = "BluetoothNfcAdapter"
        private val UUID_SPP = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB")
        private const val CONNECTION_TIMEOUT = 30000L
        private const val COMMAND_TIMEOUT = 10000L
        private const val MAX_RETRIES = 3
        private const val RESPONSE_BUFFER_SIZE = 1024
    }
    
    private val bluetoothAdapter: BluetoothAdapter = BluetoothAdapter.getDefaultAdapter()
    private var bluetoothSocket: BluetoothSocket? = null
    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null
    
    private val connectionState = AtomicBoolean(false)
    private val deviceReady = AtomicBoolean(false)
    private val commandCounter = AtomicLong(0)
    private val responseCache = ConcurrentHashMap<String, Pn532Response>()
    
    private val adapterScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    init {
        validateBluetoothEnvironment()
        validateDeviceAddress()
    }
    
    /**
     * Connect to PN532 device with enterprise validation
     */
    suspend fun connect(): Boolean = withContext(Dispatchers.IO) {
        if (connectionState.get()) {
            BluetoothNfcLogger.logConnection(deviceAddress, "ALREADY_CONNECTED")
            return@withContext true
        }
        
        BluetoothNfcLogger.logConnection(deviceAddress, "CONNECTING")
        
        return@withContext try {
            val device = bluetoothAdapter.getRemoteDevice(deviceAddress)
            validateBluetoothDevice(device)
            
            bluetoothSocket = device.createRfcommSocketToServiceRecord(UUID_SPP)
            
            withTimeout(CONNECTION_TIMEOUT) {
                bluetoothSocket!!.connect()
            }
            
            inputStream = bluetoothSocket!!.inputStream
            outputStream = bluetoothSocket!!.outputStream
            
            validateStreams()
            
            connectionState.set(true)
            
            // Initialize PN532 device
            if (initializePN532()) {
                deviceReady.set(true)
                BluetoothNfcLogger.logConnection(deviceAddress, "CONNECTED_AND_READY")
                true
            } else {
                disconnect()
                BluetoothNfcLogger.logConnection(deviceAddress, "INITIALIZATION_FAILED")
                false
            }
        } catch (e: Exception) {
            cleanup()
            BluetoothNfcLogger.logConnection(deviceAddress, "CONNECTION_FAILED: ${e.message}")
            false
        }
    }
    
    /**
     * Disconnect from PN532 device with cleanup
     */
    suspend fun disconnect(): Boolean = withContext(Dispatchers.IO) {
        BluetoothNfcLogger.logConnection(deviceAddress, "DISCONNECTING")
        
        return@withContext try {
            cleanup()
            BluetoothNfcLogger.logConnection(deviceAddress, "DISCONNECTED")
            true
        } catch (e: Exception) {
            BluetoothNfcLogger.logConnection(deviceAddress, "DISCONNECT_ERROR: ${e.message}")
            false
        }
    }
    
    /**
     * Check if adapter is connected and ready
     */
    fun isReady(): Boolean = connectionState.get() && deviceReady.get()
    
    /**
     * Get firmware version from PN532
     */
    suspend fun getFirmwareVersion(): String {
        validateConnectionState()
        
        val response = executeCommand(Pn532Command.GET_FIRMWARE_VERSION)
        
        if (response.data.size >= 4) {
            val ic = response.data[0].toUByte().toInt()
            val ver = response.data[1].toUByte().toInt()
            val rev = response.data[2].toUByte().toInt()
            val support = response.data[3].toUByte().toInt()
            
            return "PN532 v$ver.$rev (IC: 0x${ic.toString(16).uppercase()}, Support: 0x${support.toString(16).uppercase()})"
        } else {
            throw IOException("Invalid firmware version response")
        }
    }
    
    /**
     * Detect ISO14443 Type A cards
     */
    suspend fun detectTypeACards(maxTargets: Int = 1): List<CardInfo> {
        validateConnectionState()
        validateMaxTargets(maxTargets)
        
        val commandData = byteArrayOf(maxTargets.toByte(), 0x00) // Type A, 106 kbps
        val response = executeCommand(Pn532Command.IN_LIST_PASSIVE_TARGET, commandData)
        
        return parseTypeATargets(response.data)
    }
    
    /**
     * Detect ISO14443 Type B cards  
     */
    suspend fun detectTypeBCards(maxTargets: Int = 1): List<CardInfo> {
        validateConnectionState()
        validateMaxTargets(maxTargets)
        
        val commandData = byteArrayOf(maxTargets.toByte(), 0x03) // Type B, 106 kbps
        val response = executeCommand(Pn532Command.IN_LIST_PASSIVE_TARGET, commandData)
        
        return parseTypeBTargets(response.data)
    }
    
    /**
     * Exchange data with selected target
     */
    suspend fun exchangeData(targetId: Byte, data: ByteArray): ByteArray {
        validateConnectionState()
        validateExchangeData(targetId, data)
        
        val commandData = byteArrayOf(targetId) + data
        val response = executeCommand(Pn532Command.IN_DATA_EXCHANGE, commandData, COMMAND_TIMEOUT)
        
        if (response.data.isEmpty()) {
            throw IOException("Empty response from target")
        }
        
        val status = response.data[0]
        if (status != 0x00.toByte()) {
            throw IOException("Target error status: 0x${status.toString(16).uppercase()}")
        }
        
        return if (response.data.size > 1) {
            response.data.copyOfRange(1, response.data.size)
        } else {
            byteArrayOf()
        }
    }
    
    /**
     * Select target for communication
     */
    suspend fun selectTarget(targetId: Byte): Boolean {
        validateConnectionState()
        
        val commandData = byteArrayOf(targetId)
        val response = executeCommand(Pn532Command.IN_SELECT, commandData)
        
        return response.data.isNotEmpty() && response.data[0] == 0x00.toByte()
    }
    
    /**
     * Deselect current target
     */
    suspend fun deselectTarget(targetId: Byte): Boolean {
        validateConnectionState()
        
        val commandData = byteArrayOf(targetId)
        val response = executeCommand(Pn532Command.IN_DESELECT, commandData)
        
        return response.data.isNotEmpty() && response.data[0] == 0x00.toByte()
    }
    
    /**
     * Configure RF settings for optimal EMV performance
     */
    suspend fun configureRfForEmv(): Boolean {
        validateConnectionState()
        
        return try {
            // Configure RF field timeout
            configureRfField(0x02, byteArrayOf(0x00, 0x0B, 0x0A))
            
            // Configure retry timeout  
            configureRfField(0x03, byteArrayOf(0x00, 0x08))
            
            // Configure ATR timeout
            configureRfField(0x04, byteArrayOf(0x00, 0x02, 0x05))
            
            BluetoothNfcLogger.logConfiguration("RF_EMV", "SUCCESS", "RF configured for EMV")
            true
        } catch (e: Exception) {
            BluetoothNfcLogger.logConfiguration("RF_EMV", "FAILED", e.message ?: "Unknown error")
            false
        }
    }
    
    /**
     * Get adapter capabilities
     */
    fun getCapabilities(): NfcCapabilities {
        return NfcCapabilities(
            supportsTypeA = true,
            supportsTypeB = true,
            supportsTypeF = false,
            supportsTypeV = false,
            maxApduLength = 262,
            supportsBaudRates = listOf(106, 212, 424),
            supportsAntiCollision = true,
            supportsMultipleTargets = true,
            requiresExternalPower = false
        )
    }
    
    /**
     * Execute PN532 command with enterprise error handling
     */
    private suspend fun executeCommand(
        command: Pn532Command, 
        data: ByteArray = byteArrayOf(),
        timeout: Long = COMMAND_TIMEOUT
    ): Pn532Response {
        validateCommandExecution(command, data)
        
        val commandId = commandCounter.incrementAndGet()
        BluetoothNfcLogger.logCommandStart(commandId.toString(), command.name)
        
        var lastException: Exception? = null
        
        repeat(MAX_RETRIES) { attempt ->
            try {
                val frame = Pn532Frame.createCommandFrame(command, data)
                
                // Send command
                outputStream!!.write(frame)
                outputStream!!.flush()
                
                // Wait for response
                val response = withTimeout(timeout) {
                    readResponse()
                }
                
                BluetoothNfcLogger.logCommandComplete(commandId.toString(), command.name, "SUCCESS")
                return response
                
            } catch (e: Exception) {
                lastException = e
                BluetoothNfcLogger.logCommandRetry(commandId.toString(), command.name, attempt + 1, e.message ?: "Unknown error")
                
                if (attempt < MAX_RETRIES - 1) {
                    delay(1000L * (attempt + 1)) // Progressive delay
                }
            }
        }
        
        BluetoothNfcLogger.logCommandComplete(commandId.toString(), command.name, "FAILED")
        throw lastException ?: IOException("Command execution failed after $MAX_RETRIES attempts")
    }
    
    /**
     * Read response from PN532 with timeout
     */
    private suspend fun readResponse(): Pn532Response {
        val buffer = ByteArray(RESPONSE_BUFFER_SIZE)
        var totalBytes = 0
        var attempts = 0
        val maxAttempts = 50
        
        while (totalBytes < 6 && attempts < maxAttempts) { // Minimum frame size
            if (inputStream!!.available() > 0) {
                val bytesRead = inputStream!!.read(buffer, totalBytes, buffer.size - totalBytes)
                if (bytesRead > 0) {
                    totalBytes += bytesRead
                } else {
                    break
                }
            } else {
                delay(100L)
                attempts++
            }
        }
        
        if (totalBytes < 6) {
            throw IOException("Insufficient response data: $totalBytes bytes")
        }
        
        // Find complete frame
        val frameData = findCompleteFrame(buffer, totalBytes)
        return Pn532Frame.parseResponseFrame(frameData)
    }
    
    /**
     * Initialize PN532 device for EMV operations
     */
    private suspend fun initializePN532(): Boolean {
        return try {
            // Get firmware version to verify communication
            val version = getFirmwareVersion()
            BluetoothNfcLogger.logInitialization("FIRMWARE", "SUCCESS", version)
            
            // Configure SAM (Secure Access Module)
            configureSAM()
            
            // Configure RF for EMV
            configureRfForEmv()
            
            BluetoothNfcLogger.logInitialization("PN532", "SUCCESS", "Device ready for EMV operations")
            true
        } catch (e: Exception) {
            BluetoothNfcLogger.logInitialization("PN532", "FAILED", e.message ?: "Unknown error")
            false
        }
    }
    
    /**
     * Configure SAM for normal mode
     */
    private suspend fun configureSAM() {
        val samConfig = byteArrayOf(0x01, 0x14, 0x01) // Normal mode, timeout, use IRQ
        executeCommand(Pn532Command.RF_CONFIGURATION, samConfig)
    }
    
    /**
     * Configure RF field settings
     */
    private suspend fun configureRfField(configItem: Byte, configData: ByteArray) {
        val commandData = byteArrayOf(configItem) + configData
        executeCommand(Pn532Command.RF_CONFIGURATION, commandData)
    }
    
    /**
     * Parse Type A target responses
     */
    private fun parseTypeATargets(responseData: ByteArray): List<CardInfo> {
        if (responseData.isEmpty()) {
            return emptyList()
        }
        
        val targetCount = responseData[0].toUByte().toInt()
        if (targetCount == 0) {
            return emptyList()
        }
        
        val targets = mutableListOf<CardInfo>()
        var offset = 1
        
        repeat(targetCount) {
            if (offset + 6 <= responseData.size) {
                val targetNumber = responseData[offset]
                val sens_res = responseData.copyOfRange(offset + 1, offset + 3)
                val sel_res = responseData[offset + 3]
                val nfcidLength = responseData[offset + 4].toUByte().toInt()
                
                if (offset + 5 + nfcidLength <= responseData.size) {
                    val nfcid = responseData.copyOfRange(offset + 5, offset + 5 + nfcidLength)
                    
                    val cardInfo = CardInfo(
                        uid = nfcid,
                        atr = byteArrayOf(), // Type A doesn't have ATR
                        cardType = CardType.ISO14443_TYPE_A,
                        protocol = NfcProtocol.ISO_DEP,
                        targetNumber = targetNumber
                    )
                    
                    targets.add(cardInfo)
                    offset += 5 + nfcidLength
                } else {
                    break
                }
            } else {
                break
            }
        }
        
        return targets
    }
    
    /**
     * Parse Type B target responses
     */
    private fun parseTypeBTargets(responseData: ByteArray): List<CardInfo> {
        if (responseData.isEmpty()) {
            return emptyList()
        }
        
        val targetCount = responseData[0].toUByte().toInt()
        if (targetCount == 0) {
            return emptyList()
        }
        
        val targets = mutableListOf<CardInfo>()
        var offset = 1
        
        repeat(targetCount) {
            if (offset + 1 <= responseData.size) {
                val targetNumber = responseData[offset]
                val atqbLength = if (offset + 1 < responseData.size) {
                    responseData[offset + 1].toUByte().toInt()
                } else {
                    0
                }
                
                if (offset + 2 + atqbLength <= responseData.size) {
                    val atqb = responseData.copyOfRange(offset + 2, offset + 2 + atqbLength)
                    
                    // Extract PUPI (4 bytes) from ATQB
                    val pupi = if (atqb.size >= 4) {
                        atqb.copyOfRange(0, 4)
                    } else {
                        byteArrayOf()
                    }
                    
                    val cardInfo = CardInfo(
                        uid = pupi,
                        atr = atqb, // Full ATQB as ATR equivalent
                        cardType = CardType.ISO14443_TYPE_B,
                        protocol = NfcProtocol.ISO_DEP,
                        targetNumber = targetNumber
                    )
                    
                    targets.add(cardInfo)
                    offset += 2 + atqbLength
                } else {
                    break
                }
            } else {
                break
            }
        }
        
        return targets
    }
    
    /**
     * Find complete frame in response buffer
     */
    private fun findCompleteFrame(buffer: ByteArray, totalBytes: Int): ByteArray {
        // Look for frame start sequence: 00 00 FF
        for (i in 0..totalBytes - 6) {
            if (buffer[i] == 0x00.toByte() && 
                buffer[i + 1] == 0x00.toByte() && 
                buffer[i + 2] == 0xFF.toByte()) {
                
                if (i + 5 < totalBytes) {
                    val length = buffer[i + 3].toUByte().toInt()
                    val frameLength = 6 + length + 1 // Preamble + header + payload + checksum + postamble
                    
                    if (i + frameLength <= totalBytes) {
                        return buffer.copyOfRange(i, i + frameLength)
                    }
                }
            }
        }
        
        throw IOException("Complete frame not found in response")
    }
    
    /**
     * Enterprise validation functions
     */
    private fun validateBluetoothEnvironment() {
        if (!bluetoothAdapter.isEnabled) {
            throw IllegalStateException("Bluetooth adapter not enabled")
        }
        
        BluetoothNfcLogger.logValidation("BLUETOOTH_ENV", "SUCCESS", "Bluetooth environment validated")
    }
    
    private fun validateDeviceAddress() {
        if (!BluetoothAdapter.checkBluetoothAddress(deviceAddress)) {
            throw IllegalArgumentException("Invalid Bluetooth device address: $deviceAddress")
        }
        
        BluetoothNfcLogger.logValidation("DEVICE_ADDRESS", "SUCCESS", "Device address validated")
    }
    
    private fun validateBluetoothDevice(device: BluetoothDevice) {
        if (device.bondState != BluetoothDevice.BOND_BONDED) {
            throw IllegalStateException("Device not paired: ${device.address}")
        }
        
        BluetoothNfcLogger.logValidation("DEVICE_BOND", "SUCCESS", "Device bonding validated")
    }
    
    private fun validateStreams() {
        if (inputStream == null || outputStream == null) {
            throw IllegalStateException("Failed to obtain Bluetooth streams")
        }
        
        BluetoothNfcLogger.logValidation("STREAMS", "SUCCESS", "Bluetooth streams validated")
    }
    
    private fun validateConnectionState() {
        if (!connectionState.get() || !deviceReady.get()) {
            throw IllegalStateException("Adapter not connected or ready")
        }
    }
    
    private fun validateMaxTargets(maxTargets: Int) {
        if (maxTargets < 1 || maxTargets > 2) {
            throw IllegalArgumentException("Invalid max targets: $maxTargets (1-2)")
        }
    }
    
    private fun validateExchangeData(targetId: Byte, data: ByteArray) {
        if (data.isEmpty()) {
            throw IllegalArgumentException("Exchange data cannot be empty")
        }
        
        if (data.size > 262) {
            throw IllegalArgumentException("Exchange data too large: ${data.size}")
        }
        
        BluetoothNfcLogger.logValidation("EXCHANGE_DATA", "SUCCESS", "Exchange data validated")
    }
    
    private fun validateCommandExecution(command: Pn532Command, data: ByteArray) {
        if (data.size > 262) {
            throw IllegalArgumentException("Command data exceeds maximum: ${data.size}")
        }
        
        BluetoothNfcLogger.logValidation("COMMAND_EXEC", "SUCCESS", "${command.name} execution validated")
    }
    
    /**
     * Cleanup resources
     */
    private fun cleanup() {
        connectionState.set(false)
        deviceReady.set(false)
        
        try {
            inputStream?.close()
        } catch (e: Exception) {
            // Ignore cleanup errors
        }
        
        try {
            outputStream?.close()
        } catch (e: Exception) {
            // Ignore cleanup errors
        }
        
        try {
            bluetoothSocket?.close()
        } catch (e: Exception) {
            // Ignore cleanup errors
        }
        
        inputStream = null
        outputStream = null
        bluetoothSocket = null
        
        responseCache.clear()
    }
}

/**
 * Bluetooth NFC Logger for enterprise environments
 */
object BluetoothNfcLogger {
    fun logConnection(deviceAddress: String, status: String) {
        val timestamp = System.currentTimeMillis()
        println("BLUETOOTH_NFC_AUDIT: [$timestamp] CONNECTION - device=$deviceAddress status=$status")
    }
    
    fun logFrameCreation(command: String, frameSize: Int, result: String) {
        val timestamp = System.currentTimeMillis()
        println("BLUETOOTH_NFC_AUDIT: [$timestamp] FRAME_CREATED - command=$command size=$frameSize result=$result")
    }
    
    fun logFrameParsing(responseCode: String, dataSize: Int, result: String) {
        val timestamp = System.currentTimeMillis()
        println("BLUETOOTH_NFC_AUDIT: [$timestamp] FRAME_PARSED - code=$responseCode dataSize=$dataSize result=$result")
    }
    
    fun logCommandStart(commandId: String, command: String) {
        val timestamp = System.currentTimeMillis()
        println("BLUETOOTH_NFC_AUDIT: [$timestamp] COMMAND_START - id=$commandId command=$command")
    }
    
    fun logCommandComplete(commandId: String, command: String, result: String) {
        val timestamp = System.currentTimeMillis()
        println("BLUETOOTH_NFC_AUDIT: [$timestamp] COMMAND_COMPLETE - id=$commandId command=$command result=$result")
    }
    
    fun logCommandRetry(commandId: String, command: String, attempt: Int, error: String) {
        val timestamp = System.currentTimeMillis()
        println("BLUETOOTH_NFC_AUDIT: [$timestamp] COMMAND_RETRY - id=$commandId command=$command attempt=$attempt error=$error")
    }
    
    fun logInitialization(component: String, result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("BLUETOOTH_NFC_AUDIT: [$timestamp] INITIALIZATION - component=$component result=$result details=$details")
    }
    
    fun logConfiguration(component: String, result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("BLUETOOTH_NFC_AUDIT: [$timestamp] CONFIGURATION - component=$component result=$result details=$details")
    }
    
    fun logValidation(component: String, result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("BLUETOOTH_NFC_AUDIT: [$timestamp] VALIDATION - component=$component result=$result details=$details")
    }
}
