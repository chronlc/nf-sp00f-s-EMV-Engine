/**
 * nf-sp00f EMV Engine - PN532 Bluetooth NFC Provider
 * 
 * Implementation of NFC provider using PN532 chipset via Bluetooth UART.
 * Enables EMV processing with external PN532 hardware connected via HC-06.
 * 
 * @package com.nf_sp00f.app.emv.nfc
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv.nfc

import android.bluetooth.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import timber.log.Timber
import java.io.InputStream
import java.io.OutputStream
import java.util.*

/**
 * PN532 Bluetooth NFC Provider
 * 
 * Communicates with PN532 NFC controller via Bluetooth UART adapter (HC-06).
 * Provides enhanced NFC capabilities and external antenna options.
 */
class Pn532BluetoothNfcProvider : INfcProvider {
    
    companion object {
        private const val TAG = "Pn532BluetoothNfcProvider"
        
        // Bluetooth UART UUID for HC-06
        private val UART_UUID: UUID = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB")
        
        // PN532 command timeouts
        private const val COMMAND_TIMEOUT_MS = 10000L
        private const val CONNECTION_TIMEOUT_MS = 15000L
        
        // PN532 frame constants
        private const val PN532_PREAMBLE: Byte = 0x00
        private const val PN532_START_CODE1: Byte = 0x00.toByte()
        private const val PN532_START_CODE2: Byte = 0xFF.toByte()
        private const val PN532_ACK: Byte = 0x01
        
        // PN532 commands
        private const val PN532_COMMAND_GETFIRMWAREVERSION: Byte = 0x02
        private const val PN532_COMMAND_SAMCONFIGURATION: Byte = 0x14
        private const val PN532_COMMAND_INLISTPASSIVETARGETS: Byte = 0x4A
        private const val PN532_COMMAND_INDATAEXCHANGE: Byte = 0x40
    }
    
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var bluetoothSocket: BluetoothSocket? = null
    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null
    
    private var deviceAddress: String? = null
    private var deviceName: String? = null
    private var isConnected = false
    private var currentTargetId: Byte = 0
    
    override suspend fun initialize(config: NfcProviderConfig): Boolean = withContext(Dispatchers.IO) {
        try {
            Timber.d("Initializing PN532 Bluetooth NFC Provider")
            
            // Verify configuration
            if (config.type != NfcProviderType.PN532_BLUETOOTH) {
                Timber.e("Invalid config type for PN532 provider: ${config.type}")
                return@withContext false
            }
            
            deviceAddress = config.bluetoothDeviceAddress
            deviceName = config.bluetoothDeviceName
            
            if (deviceAddress.isNullOrEmpty()) {
                Timber.e("Bluetooth device address not provided")
                return@withContext false
            }
            
            // Initialize Bluetooth adapter
            bluetoothAdapter = BluetoothAdapter.getDefaultAdapter()
            if (bluetoothAdapter == null) {
                Timber.e("Bluetooth not supported on this device")
                return@withContext false
            }
            
            if (!bluetoothAdapter!!.isEnabled) {
                Timber.e("Bluetooth is disabled")
                return@withContext false
            }
            
            Timber.i("PN532 Bluetooth NFC Provider initialized for device: $deviceAddress")
            true
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to initialize PN532 Bluetooth provider")
            false
        }
    }
    
    override suspend fun connect(): Boolean = withContext(Dispatchers.IO) {
        try {
            if (deviceAddress == null) {
                Timber.e("No Bluetooth device address configured")
                return@withContext false
            }
            
            // Get Bluetooth device
            val device = bluetoothAdapter!!.getRemoteDevice(deviceAddress)
            if (device == null) {
                Timber.e("Failed to get Bluetooth device: $deviceAddress")
                return@withContext false
            }
            
            Timber.d("Connecting to PN532 via Bluetooth: ${device.name ?: deviceAddress}")
            
            // Create and connect socket
            bluetoothSocket = device.createRfcommSocketToServiceRecord(UART_UUID)
            bluetoothSocket!!.connect()
            
            // Get I/O streams
            inputStream = bluetoothSocket!!.inputStream
            outputStream = bluetoothSocket!!.outputStream
            
            // Verify PN532 connection
            val firmwareVersion = getPn532FirmwareVersion()
            if (firmwareVersion == null) {
                Timber.e("Failed to communicate with PN532")
                disconnect()
                return@withContext false
            }
            
            Timber.i("PN532 connected successfully. Firmware: $firmwareVersion")
            
            // Configure PN532
            if (!configurePn532()) {
                Timber.e("Failed to configure PN532")
                disconnect()
                return@withContext false
            }
            
            isConnected = true
            true
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to connect to PN532 via Bluetooth")
            disconnect()
            false
        }
    }
    
    override suspend fun sendCommand(command: ByteArray): NfcResponse = withContext(Dispatchers.IO) {
        try {
            if (!isConnected || outputStream == null || inputStream == null) {
                return@withContext NfcResponse.Error("PN532 not connected")
            }
            
            Timber.d("Sending command via PN532: ${command.joinToString("") { "%02X".format(it) }}")
            
            // Wait for card if not present
            val targetFound = waitForCard()
            if (!targetFound) {
                return@withContext NfcResponse.Error("No NFC card detected by PN532")
            }
            
            // Send data exchange command to PN532
            val pn532Command = buildDataExchangeCommand(command)
            val startTime = System.currentTimeMillis()
            
            // Send command
            sendPn532Frame(pn532Command)
            
            // Read response
            val response = readPn532Response()
            val duration = System.currentTimeMillis() - startTime
            
            if (response == null) {
                return@withContext NfcResponse.Error("No response from PN532")
            }
            
            // Parse PN532 response
            val apduResponse = parsePn532DataExchangeResponse(response)
            if (apduResponse == null) {
                return@withContext NfcResponse.Error("Invalid PN532 response format")
            }
            
            Timber.d("Received response via PN532 (${duration}ms): ${apduResponse.joinToString("") { "%02X".format(it) }}")
            
            // Extract status word and data
            if (apduResponse.size < 2) {
                return@withContext NfcResponse.Error("Response too short")
            }
            
            val data = apduResponse.sliceArray(0 until apduResponse.size - 2)
            val sw1 = apduResponse[apduResponse.size - 2].toInt() and 0xFF
            val sw2 = apduResponse[apduResponse.size - 1].toInt() and 0xFF
            val statusWord = (sw1 shl 8) or sw2
            
            NfcResponse.Success(data, statusWord, duration)
            
        } catch (e: Exception) {
            Timber.e(e, "PN532 command failed")
            NfcResponse.Error("PN532 error: ${e.message}")
        }
    }
    
    override fun isConnected(): Boolean = isConnected && bluetoothSocket?.isConnected == true
    
    override suspend fun disconnect(): Boolean = withContext(Dispatchers.IO) {
        try {
            inputStream?.close()
            outputStream?.close()
            bluetoothSocket?.close()
            
            inputStream = null
            outputStream = null
            bluetoothSocket = null
            isConnected = false
            
            Timber.d("Disconnected from PN532 Bluetooth")
            true
            
        } catch (e: Exception) {
            Timber.w(e, "Error during PN532 disconnect")
            false
        }
    }
    
    override suspend fun runDiagnostics(): NfcDiagnostics = withContext(Dispatchers.Default) {
        val diagnostics = mutableMapOf<String, String>()
        
        try {
            // Bluetooth status
            diagnostics["Bluetooth Adapter"] = if (bluetoothAdapter != null) "Available" else "Not Available"
            diagnostics["Bluetooth Enabled"] = if (bluetoothAdapter?.isEnabled == true) "Yes" else "No"
            diagnostics["Device Address"] = deviceAddress ?: "Not Set"
            diagnostics["Device Name"] = deviceName ?: "Unknown"
            
            // Connection status
            diagnostics["Connection Status"] = if (isConnected) "Connected" else "Disconnected"
            diagnostics["Socket Status"] = if (bluetoothSocket?.isConnected == true) "Open" else "Closed"
            
            // PN532 specific diagnostics
            if (isConnected) {
                val firmwareVersion = getPn532FirmwareVersion()
                diagnostics["PN532 Firmware"] = firmwareVersion ?: "Unknown"
                diagnostics["Target ID"] = currentTargetId.toString()
                
                // Test communication
                val commTest = testPn532Communication()
                diagnostics["Communication Test"] = if (commTest) "Pass" else "Fail"
            }
            
            diagnostics["Provider Type"] = "PN532 Bluetooth UART"
            diagnostics["Max Command Length"] = "254 bytes"
            
            NfcDiagnostics(
                isHealthy = isConnected && bluetoothSocket?.isConnected == true,
                status = if (isConnected) "Operational" else "Disconnected",
                details = diagnostics,
                lastCheck = System.currentTimeMillis()
            )
            
        } catch (e: Exception) {
            Timber.e(e, "PN532 diagnostics failed")
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
            type = NfcProviderType.PN532_BLUETOOTH,
            name = "PN532 Bluetooth UART",
            version = "PN532 v1.6 + HC-06",
            capabilities = listOf(
                "ISO14443 Type A/B",
                "FeliCa",
                "Mifare Classic/Ultralight",
                "External Antenna Support",
                "Adjustable RF Settings",
                "Background Operation"
            ),
            maxDataLength = 254,
            supportsBackground = true
        )
    }
    
    /**
     * Set Bluetooth device parameters
     */
    fun setBluetoothDevice(address: String, name: String?) {
        this.deviceAddress = address
        this.deviceName = name
        Timber.d("PN532 Bluetooth device set: $name ($address)")
    }
    
    /**
     * Get PN532 firmware version
     */
    private suspend fun getPn532FirmwareVersion(): String? = withContext(Dispatchers.IO) {
        try {
            val command = byteArrayOf(PN532_COMMAND_GETFIRMWAREVERSION)
            sendPn532Frame(command)
            
            val response = readPn532Response()
            if (response != null && response.size >= 4) {
                val ic = response[0]
                val ver = response[1]
                val rev = response[2]
                val support = response[3]
                
                "IC: 0x%02X, Ver: %d.%d, Support: 0x%02X".format(ic, ver, rev, support)
            } else {
                null
            }
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to get PN532 firmware version")
            null
        }
    }
    
    /**
     * Configure PN532 for EMV operation
     */
    private suspend fun configurePn532(): Boolean = withContext(Dispatchers.IO) {
        try {
            // SAM Configuration - Normal mode, timeout 50ms
            val samConfig = byteArrayOf(
                PN532_COMMAND_SAMCONFIGURATION,
                0x01, // Normal mode
                0x14, // Timeout 50ms * 20 = 1s
                0x01  // Use IRQ pin
            )
            
            sendPn532Frame(samConfig)
            val response = readPn532Response()
            
            response != null // SAM config should return empty success response
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to configure PN532")
            false
        }
    }
    
    /**
     * Wait for NFC card detection
     */
    private suspend fun waitForCard(timeoutMs: Long = 5000): Boolean = withContext(Dispatchers.IO) {
        try {
            val listTargetsCommand = byteArrayOf(
                PN532_COMMAND_INLISTPASSIVETARGETS,
                0x01, // Max targets
                0x00  // 106 kbps Type A (ISO14443 Type A)
            )
            
            val startTime = System.currentTimeMillis()
            
            while (System.currentTimeMillis() - startTime < timeoutMs) {
                sendPn532Frame(listTargetsCommand)
                val response = readPn532Response()
                
                if (response != null && response.isNotEmpty() && response[0] > 0) {
                    // Found target(s)
                    currentTargetId = 1 // Use first target
                    Timber.d("PN532 detected NFC card")
                    return@withContext true
                }
                
                delay(100) // Brief pause before retry
            }
            
            false
            
        } catch (e: Exception) {
            Timber.e(e, "Error waiting for NFC card")
            false
        }
    }
    
    /**
     * Build PN532 data exchange command
     */
    private fun buildDataExchangeCommand(apduCommand: ByteArray): ByteArray {
        return byteArrayOf(PN532_COMMAND_INDATAEXCHANGE, currentTargetId) + apduCommand
    }
    
    /**
     * Send PN532 frame
     */
    private fun sendPn532Frame(command: ByteArray) {
        val frame = buildPn532Frame(command)
        outputStream!!.write(frame)
        outputStream!!.flush()
    }
    
    /**
     * Build PN532 frame with headers and checksum
     */
    private fun buildPn532Frame(command: ByteArray): ByteArray {
        val length = command.size + 1 // +1 for direction byte
        val lengthChecksum = (0x100 - length) and 0xFF
        
        val frame = mutableListOf<Byte>()
        
        // Frame format: [PREAMBLE] [START1] [START2] [LENGTH] [LENGTH_CHECKSUM] [DIRECTION] [COMMAND...] [DATA_CHECKSUM]
        frame.add(PN532_PREAMBLE)
        frame.add(PN532_START_CODE1)
        frame.add(PN532_START_CODE2)
        frame.add(length.toByte())
        frame.add(lengthChecksum.toByte())
        frame.add(0xD4.toByte()) // Direction: Host to PN532
        frame.addAll(command.toList())
        
        // Calculate data checksum
        var checksum = 0xD4 // Start with direction
        for (byte in command) {
            checksum += byte.toInt() and 0xFF
        }
        checksum = (0x100 - checksum) and 0xFF
        frame.add(checksum.toByte())
        
        return frame.toByteArray()
    }
    
    /**
     * Read PN532 response
     */
    private fun readPn532Response(): ByteArray? {
        try {
            val buffer = ByteArray(256)
            val bytesRead = inputStream!!.read(buffer)
            
            if (bytesRead < 6) return null // Minimum frame size
            
            // Validate frame format
            if (buffer[0] != PN532_PREAMBLE || 
                buffer[1] != PN532_START_CODE1 || 
                buffer[2] != PN532_START_CODE2) {
                return null
            }
            
            val length = buffer[3].toInt() and 0xFF
            if (bytesRead < length + 5) return null // Not enough data
            
            // Extract command response (skip headers and direction byte)
            val responseStart = 6 // After headers and direction
            val responseLength = length - 2 // Subtract direction and checksum
            
            return buffer.sliceArray(responseStart until responseStart + responseLength)
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to read PN532 response")
            return null
        }
    }
    
    /**
     * Parse PN532 data exchange response
     */
    private fun parsePn532DataExchangeResponse(response: ByteArray): ByteArray? {
        if (response.isEmpty()) return null
        
        // Check status byte
        val status = response[0]
        if (status.toInt() != 0x00) {
            Timber.w("PN532 data exchange error: 0x%02X".format(status))
            return null
        }
        
        // Return APDU response (skip status byte)
        return if (response.size > 1) {
            response.sliceArray(1 until response.size)
        } else {
            byteArrayOf() // Empty response
        }
    }
    
    /**
     * Test PN532 communication
     */
    private suspend fun testPn532Communication(): Boolean = withContext(Dispatchers.IO) {
        return try {
            getPn532FirmwareVersion() != null
        } catch (e: Exception) {
            false
        }
    }
}
