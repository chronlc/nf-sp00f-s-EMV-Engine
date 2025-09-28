package com.nf_sp00f.app.emv.nfc

import android.bluetooth.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import timber.log.Timber
import java.io.InputStream
import java.io.OutputStream
import java.util.*

/**
 * PN532 NFC Provider with Bluetooth UART Communication (HC-06)
 * 
 * This class implements NFC operations using an external PN532 module
 * connected via Bluetooth UART bridge (HC-06). It provides more control
 * and flexibility compared to Android's internal NFC.
 */
class Pn532BluetoothNfcProvider : INfcProvider {
    
    private var bluetoothSocket: BluetoothSocket? = null
    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null
    private var currentCard: NfcCardInfo? = null
    private var config: NfcProviderConfig? = null
    
    // PN532 Command constants
    companion object {
        private val SPP_UUID = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB")
        
        // PN532 Commands
        private const val PN532_PREAMBLE = 0x00.toByte()
        private const val PN532_STARTCODE1 = 0x00.toByte() 
        private const val PN532_STARTCODE2 = 0xFF.toByte()
        private const val PN532_POSTAMBLE = 0x00.toByte()
        
        // Command codes
        private const val PN532_COMMAND_GETFIRMWAREVERSION = 0x02.toByte()
        private const val PN532_COMMAND_SAMCONFIGURATION = 0x14.toByte()
        private const val PN532_COMMAND_INLISTPASSIVETARGETS = 0x4A.toByte()
        private const val PN532_COMMAND_INDATAEXCHANGE = 0x40.toByte()
        private const val PN532_COMMAND_INDESELECT = 0x44.toByte()
        private const val PN532_COMMAND_INRELEASE = 0x52.toByte()
        
        // Card types
        private const val PN532_MIFARE_ISO14443A = 0x00.toByte()
        private const val PN532_ISO14443B = 0x03.toByte()
    }
    
    override suspend fun initialize(config: NfcProviderConfig): Boolean = withContext(Dispatchers.IO) {
        this@Pn532BluetoothNfcProvider.config = config
        
        try {
            Timber.d("Initializing PN532 Bluetooth connection to ${config.bluetoothAddress}")
            
            if (config.bluetoothAddress == null) {
                Timber.e("Bluetooth address not provided")
                return@withContext false
            }
            
            // Get Bluetooth adapter
            val bluetoothAdapter = BluetoothAdapter.getDefaultAdapter()
            if (bluetoothAdapter == null || !bluetoothAdapter.isEnabled) {
                Timber.e("Bluetooth not available or not enabled")
                return@withContext false
            }
            
            // Connect to HC-06 device
            val device = bluetoothAdapter.getRemoteDevice(config.bluetoothAddress)
            bluetoothSocket = device.createRfcommSocketToServiceRecord(SPP_UUID)
            
            bluetoothSocket?.connect()
            
            inputStream = bluetoothSocket?.inputStream
            outputStream = bluetoothSocket?.outputStream
            
            // Wait for connection to stabilize
            delay(1000)
            
            // Initialize PN532
            if (!initializePn532()) {
                Timber.e("Failed to initialize PN532")
                cleanup()
                return@withContext false
            }
            
            Timber.i("PN532 Bluetooth connection initialized successfully")
            true
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to initialize PN532 Bluetooth connection")
            cleanup()
            false
        }
    }
    
    /**
     * Initialize PN532 chip
     */
    private suspend fun initializePn532(): Boolean {
        try {
            // Get firmware version
            val firmwareResponse = sendPn532Command(byteArrayOf(PN532_COMMAND_GETFIRMWAREVERSION))
            if (firmwareResponse.isEmpty()) {
                Timber.e("No response from PN532")
                return false
            }
            
            Timber.d("PN532 Firmware: ${firmwareResponse.toHexString()}")
            
            // Configure SAM (Secure Access Module)
            val samConfig = byteArrayOf(
                PN532_COMMAND_SAMCONFIGURATION,
                0x01, // Normal mode
                0x14, // Timeout 50ms * 20 = 1 second
                0x01  // Use IRQ pin
            )
            
            val samResponse = sendPn532Command(samConfig)
            if (samResponse.isEmpty()) {
                Timber.e("Failed to configure PN532 SAM")
                return false
            }
            
            Timber.d("PN532 SAM configured successfully")
            return true
            
        } catch (e: Exception) {
            Timber.e(e, "Error initializing PN532")
            return false
        }
    }
    
    override fun isReady(): Boolean = bluetoothSocket?.isConnected == true
    
    override suspend fun scanForCards(): List<NfcCardInfo> = withContext(Dispatchers.IO) {
        try {
            Timber.d("Scanning for cards with PN532")
            
            // Scan for ISO14443A cards (most EMV cards)
            val scanCommand = byteArrayOf(
                PN532_COMMAND_INLISTPASSIVETARGETS,
                0x01, // Max 1 target
                PN532_MIFARE_ISO14443A
            )
            
            val response = sendPn532Command(scanCommand)
            if (response.isEmpty() || response[0] == 0x00.toByte()) {
                return@withContext emptyList()
            }
            
            // Parse response to extract card information
            val cardInfo = parsePn532CardResponse(response)
            if (cardInfo != null) {
                listOf(cardInfo)
            } else {
                emptyList()
            }
            
        } catch (e: Exception) {
            Timber.e(e, "Error scanning for cards")
            emptyList()
        }
    }
    
    override suspend fun connectToCard(cardInfo: NfcCardInfo): Boolean {
        currentCard = cardInfo
        return true // PN532 maintains connection from scan
    }
    
    override suspend fun exchangeApdu(apdu: ByteArray): ApduResponse = withContext(Dispatchers.IO) {
        try {
            Timber.d("PN532 APDU Exchange: ${apdu.toHexString()}")
            
            val exchangeCommand = byteArrayOf(PN532_COMMAND_INDATAEXCHANGE, 0x01) + apdu
            val response = sendPn532Command(exchangeCommand)
            
            if (response.isEmpty() || response[0] != 0x00.toByte()) {
                throw Exception("PN532 data exchange failed")
            }
            
            // Remove PN532 status byte and extract APDU response
            val apduResponse = response.drop(1).toByteArray()
            
            if (apduResponse.size < 2) {
                throw Exception("Invalid APDU response length")
            }
            
            val data = apduResponse.dropLast(2).toByteArray()
            val sw1 = apduResponse[apduResponse.size - 2].toInt() and 0xFF
            val sw2 = apduResponse[apduResponse.size - 1].toInt() and 0xFF
            val sw = (sw1 shl 8) or sw2
            
            Timber.d("PN532 APDU Response: ${apduResponse.toHexString()}")
            
            ApduResponse(data, sw1, sw2, sw)
            
        } catch (e: Exception) {
            Timber.e(e, "PN532 APDU exchange failed")
            throw EmvCommunicationException("PN532 APDU exchange failed: ${e.message}", e)
        }
    }
    
    override suspend fun selectApplication(aid: String): ApduResponse {
        val aidBytes = aid.hexToByteArray()
        val selectCommand = byteArrayOf(
            0x00.toByte(), 0xA4.toByte(), 0x04.toByte(), 0x00.toByte(),
            aidBytes.size.toByte()
        ) + aidBytes
        
        return exchangeApdu(selectCommand)
    }
    
    override suspend fun getProcessingOptions(pdol: ByteArray): ApduResponse {
        val gpoCommand = byteArrayOf(
            0x80.toByte(), 0xA8.toByte(), 0x00.toByte(), 0x00.toByte(),
            pdol.size.toByte()
        ) + pdol
        
        return exchangeApdu(gpoCommand)
    }
    
    override suspend fun readRecord(sfi: Int, recordNumber: Int): ApduResponse {
        val readCommand = byteArrayOf(
            0x00.toByte(), 0xB2.toByte(),
            recordNumber.toByte(),
            ((sfi shl 3) or 0x04).toByte(),
            0x00.toByte()
        )
        
        return exchangeApdu(readCommand)
    }
    
    override suspend fun generateAc(acType: Int, cdol: ByteArray): ApduResponse {
        val genAcCommand = byteArrayOf(
            0x80.toByte(), 0xAE.toByte(),
            acType.toByte(), 0x00.toByte(),
            cdol.size.toByte()
        ) + cdol
        
        return exchangeApdu(genAcCommand)
    }
    
    override fun getCardInfo(): NfcCardInfo? = currentCard
    
    override suspend fun disconnect() {
        try {
            if (currentCard != null) {
                // Release the card
                val releaseCommand = byteArrayOf(PN532_COMMAND_INRELEASE, 0x01)
                sendPn532Command(releaseCommand)
                currentCard = null
            }
        } catch (e: Exception) {
            Timber.w(e, "Error releasing PN532 card")
        }
    }
    
    override suspend fun cleanup() {
        try {
            disconnect()
            inputStream?.close()
            outputStream?.close()
            bluetoothSocket?.close()
            Timber.d("PN532 Bluetooth connection cleaned up")
        } catch (e: Exception) {
            Timber.w(e, "Error during PN532 cleanup")
        } finally {
            inputStream = null
            outputStream = null
            bluetoothSocket = null
            currentCard = null
        }
    }
    
    override fun getCapabilities(): NfcCapabilities = NfcCapabilities(
        supportedCardTypes = setOf(
            NfcCardType.ISO14443_TYPE_A,
            NfcCardType.ISO14443_TYPE_B,
            NfcCardType.MIFARE_CLASSIC,
            NfcCardType.MIFARE_ULTRALIGHT,
            NfcCardType.FELICA
        ),
        maxApduLength = 255,
        supportsExtendedLength = false,
        canControlField = true,
        canSetTimeout = true,
        supportsBaudRateChange = false,
        providerSpecificFeatures = mapOf(
            "firmwareControl" to true,
            "samConfiguration" to true,
            "multipleCardSupport" to true
        )
    )
    
    /**
     * Send command to PN532 and receive response
     */
    private suspend fun sendPn532Command(command: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        val output = outputStream ?: throw Exception("PN532 not connected")
        val input = inputStream ?: throw Exception("PN532 not connected")
        
        // Build PN532 frame
        val frame = buildPn532Frame(command)
        
        // Send command
        output.write(frame)
        output.flush()
        
        // Read response with timeout
        val response = withTimeoutOrNull(config?.timeout ?: 30000L) {
            readPn532Response(input)
        } ?: throw Exception("PN532 command timeout")
        
        response
    }
    
    /**
     * Build PN532 frame with checksum
     */
    private fun buildPn532Frame(command: ByteArray): ByteArray {
        val len = command.size + 1
        val lenChecksum = (0x100 - len) and 0xFF
        
        val frame = mutableListOf<Byte>()
        frame.add(PN532_PREAMBLE)
        frame.add(PN532_STARTCODE1)
        frame.add(PN532_STARTCODE2)
        frame.add(len.toByte())
        frame.add(lenChecksum.toByte())
        frame.add(0xD4.toByte()) // TFI (host to PN532)
        frame.addAll(command.toList())
        
        // Calculate data checksum
        val dataSum = (0xD4.toInt() + command.sum()) and 0xFF
        val dataChecksum = (0x100 - dataSum) and 0xFF
        frame.add(dataChecksum.toByte())
        frame.add(PN532_POSTAMBLE)
        
        return frame.toByteArray()
    }
    
    /**
     * Read PN532 response frame
     */
    private suspend fun readPn532Response(input: InputStream): ByteArray {
        // Read response frame
        val buffer = ByteArray(1024)
        var bytesRead = 0
        
        // Wait for response
        while (bytesRead == 0 && input.available() == 0) {
            delay(10)
        }
        
        bytesRead = input.read(buffer)
        if (bytesRead < 6) {
            throw Exception("Invalid PN532 response frame")
        }
        
        // Parse frame and extract data
        val dataLength = buffer[3].toInt() and 0xFF
        val dataStart = 6 // After preamble, start codes, length, checksum, TFI
        
        return buffer.sliceArray(dataStart until dataStart + dataLength - 1)
    }
    
    /**
     * Parse PN532 card scan response
     */
    private fun parsePn532CardResponse(response: ByteArray): NfcCardInfo? {
        if (response.size < 4) return null
        
        val numTargets = response[0].toInt() and 0xFF
        if (numTargets == 0) return null
        
        val targetNumber = response[1].toInt() and 0xFF
        val sens_res = response.sliceArray(2..3)
        val sel_res = response[4]
        val uidLength = response[5].toInt() and 0xFF
        val uid = response.sliceArray(6 until 6 + uidLength)
        
        return NfcCardInfo(
            uid = uid.toHexString(),
            atqa = sens_res.toHexString(),
            sak = sel_res.toString(16),
            cardType = NfcCardType.ISO14443_TYPE_A,
            providerType = NfcProviderType.PN532_BLUETOOTH,
            maxTransceiveLength = 255
        )
    }
}

// Extension functions
private fun ByteArray.toHexString(): String = joinToString("") { "%02X".format(it) }
private fun String.hexToByteArray(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
private fun ByteArray.sum(): Int = sumOf { it.toInt() and 0xFF }