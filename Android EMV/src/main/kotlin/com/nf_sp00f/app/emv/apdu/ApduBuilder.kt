/**
 * nf-sp00f EMV Engine - APDU Builder
 * 
 * EMV APDU (Application Protocol Data Unit) construction and processing.
 * Implements core EMV commands ported from Proxmark3 with Android optimization.
 * 
 * @package com.nf_sp00f.app.emv.apdu
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv.apdu

/**
 * APDU Command structure
 */
data class ApduCommand(
    val cla: UByte,          // Class byte
    val ins: UByte,          // Instruction byte  
    val p1: UByte,           // Parameter 1
    val p2: UByte,           // Parameter 2
    val data: ByteArray = byteArrayOf(), // Command data
    val le: UByte? = null    // Expected response length
) {
    
    /**
     * Convert APDU command to byte array for transmission
     */
    fun toByteArray(): ByteArray {
        val lc = if (data.isNotEmpty()) data.size.toUByte() else null
        
        return buildList<Byte> {
            add(cla.toByte())
            add(ins.toByte())
            add(p1.toByte())
            add(p2.toByte())
            
            // Add Lc (data length) if data present
            lc?.let {
                add(it.toByte())
                addAll(data.toList())
            }
            
            // Add Le (expected length) if specified
            le?.let { add(it.toByte()) }
            
        }.toByteArray()
    }
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ApduCommand) return false
        
        return cla == other.cla &&
               ins == other.ins &&
               p1 == other.p1 &&
               p2 == other.p2 &&
               data.contentEquals(other.data) &&
               le == other.le
    }
    
    override fun hashCode(): Int {
        var result = cla.hashCode()
        result = 31 * result + ins.hashCode()
        result = 31 * result + p1.hashCode()
        result = 31 * result + p2.hashCode()
        result = 31 * result + data.contentHashCode()
        result = 31 * result + (le?.hashCode() ?: 0)
        return result
    }
    
    override fun toString(): String {
        return "APDU(CLA=%02X INS=%02X P1=%02X P2=%02X Lc=%02X Le=%s)".format(
            cla.toInt(), ins.toInt(), p1.toInt(), p2.toInt(), 
            data.size, le?.let { "%02X".format(it.toInt()) } ?: "none"
        )
    }
}

/**
 * APDU Response structure  
 */
data class ApduResponse(
    val data: ByteArray,
    val sw1: UByte,
    val sw2: UByte
) {
    
    companion object {
        fun fromByteArray(response: ByteArray): ApduResponse {
            require(response.size >= 2) { "APDU response must be at least 2 bytes (SW1+SW2)" }
            
            val dataLength = response.size - 2
            val data = if (dataLength > 0) response.sliceArray(0 until dataLength) else byteArrayOf()
            val sw1 = response[response.size - 2].toUByte()
            val sw2 = response[response.size - 1].toUByte()
            
            return ApduResponse(data, sw1, sw2)
        }
    }
    
    /**
     * Get status word as 16-bit value
     */
    val statusWord: UShort
        get() = ((sw1.toUInt() shl 8) or sw2.toUInt()).toUShort()
    
    /**
     * Check if command was successful
     */
    val isSuccess: Boolean
        get() = statusWord == 0x9000u.toUShort()
    
    /**
     * Check for warning conditions
     */
    val isWarning: Boolean
        get() = (statusWord and 0xFF00u) == 0x6200u ||
                (statusWord and 0xFF00u) == 0x6300u
    
    /**
     * Check for error conditions
     */
    val isError: Boolean
        get() = !isSuccess && !isWarning
    
    /**
     * Get error description
     */
    val errorDescription: String
        get() = when (statusWord.toUInt()) {
            0x9000u -> "Success"
            0x6100u -> "Response available (${sw2.toInt()} bytes)"
            0x6282u -> "End of file reached"
            0x6283u -> "Selected file deactivated"  
            0x6284u -> "File control information not formatted"
            0x6300u -> "Authentication failed"
            0x6381u -> "File filled up by last write"
            0x6400u -> "Execution error"
            0x6581u -> "Memory failure"
            0x6700u -> "Wrong length (Lc)"
            0x6800u -> "Functions in CLA not supported"
            0x6881u -> "Logical channel not supported"
            0x6882u -> "Secure messaging not supported"
            0x6900u -> "Command not allowed"
            0x6981u -> "Command incompatible with file structure"
            0x6982u -> "Security status not satisfied"
            0x6983u -> "Authentication method blocked"
            0x6984u -> "Referenced data invalidated"
            0x6985u -> "Conditions of use not satisfied"
            0x6986u -> "Command not allowed (no current EF)"
            0x6A00u -> "Wrong parameter(s) P1-P2"
            0x6A80u -> "Incorrect parameters in data field"
            0x6A81u -> "Function not supported"
            0x6A82u -> "File not found"
            0x6A83u -> "Record not found"
            0x6A84u -> "Not enough memory space in the file"
            0x6A86u -> "Incorrect parameters P1-P2"
            0x6A88u -> "Referenced data not found"
            0x6B00u -> "Wrong parameter(s) P1-P2"
            0x6D00u -> "Instruction code not supported or invalid"
            0x6E00u -> "Class not supported"
            0x6F00u -> "No precise diagnosis"
            else -> "Unknown error (${statusWord.toString(16)})"
        }
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ApduResponse) return false
        
        return data.contentEquals(other.data) &&
               sw1 == other.sw1 &&
               sw2 == other.sw2
    }
    
    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + sw1.hashCode()
        result = 31 * result + sw2.hashCode()
        return result
    }
    
    override fun toString(): String {
        return "Response(${data.size} bytes, SW=%04X: ${errorDescription})".format(statusWord.toInt())
    }
}

/**
 * EMV APDU Builder - Core EMV Commands
 * 
 * Ported from Proxmark3 EMV functions:
 * - EMVSelect() -> buildSelect()
 * - EMVSelectPSE() -> buildSelectPSE()
 * - EMVGPO() -> buildGetProcessingOptions()
 * - EMVReadRecord() -> buildReadRecord()
 * - EMVAC() -> buildGenerateApplicationCryptogram()
 * - EMVGenerateChallenge() -> buildGenerateChallenge()
 * - EMVInternalAuthenticate() -> buildInternalAuthenticate()
 * - EMVGetData() -> buildGetData()
 */
class EmvApduBuilder {
    
    companion object {
        // EMV Class bytes
        const val CLA_ISO7816 = 0x00.toUByte()
        const val CLA_PROPRIETARY = 0x80.toUByte()
        
        // EMV Instructions
        const val INS_SELECT = 0xA4.toUByte()
        const val INS_GET_PROCESSING_OPTIONS = 0xA8.toUByte()
        const val INS_READ_RECORD = 0xB2.toUByte()
        const val INS_GET_DATA = 0xCA.toUByte()
        const val INS_GENERATE_AC = 0xAE.toUByte()
        const val INS_EXTERNAL_AUTHENTICATE = 0x82.toUByte()
        const val INS_INTERNAL_AUTHENTICATE = 0x88.toUByte()
        const val INS_GET_CHALLENGE = 0x84.toUByte()
        const val INS_COMPUTE_CRYPTOGRAPHIC_CHECKSUM = 0x2A.toUByte()
        
        // P1 Parameters
        const val P1_SELECT_BY_NAME = 0x04.toUByte()
        const val P1_SELECT_BY_AID = 0x04.toUByte()
        
        // P2 Parameters  
        const val P2_FIRST_OCCURRENCE = 0x00.toUByte()
        const val P2_NEXT_OCCURRENCE = 0x02.toUByte()
        const val P2_RETURN_FCI = 0x00.toUByte()
        
        // AC Types
        const val AC_AAC = 0x00.toUByte() // Application Authentication Cryptogram
        const val AC_TC = 0x40.toUByte()  // Transaction Certificate
        const val AC_ARQC = 0x80.toUByte() // Authorization Request Cryptogram
        const val AC_CDA = 0x10.toUByte()  // Combined Data Authentication
        
        // PSE Names
        const val PSE_1PAY_SYS_DDF01 = "1PAY.SYS.DDF01"
        const val PSE_2PAY_SYS_DDF01 = "2PAY.SYS.DDF01"
    }
    
    /**
     * Build SELECT command for application/file selection
     * Ported from: EMVSelect()
     */
    fun buildSelect(
        aid: ByteArray,
        firstOccurrence: Boolean = true,
        returnFci: Boolean = true
    ): ApduCommand {
        val p1 = P1_SELECT_BY_AID
        val p2 = if (firstOccurrence) P2_FIRST_OCCURRENCE else P2_NEXT_OCCURRENCE
        
        return ApduCommand(
            cla = CLA_ISO7816,
            ins = INS_SELECT, 
            p1 = p1,
            p2 = p2,
            data = aid,
            le = if (returnFci) 0x00.toUByte() else null
        )
    }
    
    /**
     * Build SELECT PSE (Payment System Environment) command
     * Ported from: EMVSelectPSE()
     */
    fun buildSelectPSE(contactless: Boolean = true): ApduCommand {
        val pseName = if (contactless) PSE_2PAY_SYS_DDF01 else PSE_1PAY_SYS_DDF01
        return buildSelect(pseName.toByteArray(Charsets.US_ASCII))
    }
    
    /**
     * Build GET PROCESSING OPTIONS command  
     * Ported from: EMVGPO()
     */
    fun buildGetProcessingOptions(pdol: ByteArray = byteArrayOf()): ApduCommand {
        // PDOL data is wrapped in tag 0x83
        val commandData = if (pdol.isEmpty()) {
            byteArrayOf(0x83.toByte(), 0x00.toByte()) // Empty PDOL
        } else {
            byteArrayOf(0x83.toByte(), pdol.size.toByte()) + pdol
        }
        
        return ApduCommand(
            cla = CLA_ISO7816,
            ins = INS_GET_PROCESSING_OPTIONS,
            p1 = 0x00.toUByte(),
            p2 = 0x00.toUByte(),
            data = commandData,
            le = 0x00.toUByte()
        )
    }
    
    /**
     * Build READ RECORD command
     * Ported from: EMVReadRecord()
     */
    fun buildReadRecord(recordNumber: UByte, sfi: UByte): ApduCommand {
        val p2 = ((sfi.toUInt() shl 3) or 0x04u).toUByte() // SFI in upper 5 bits + 0x04
        
        return ApduCommand(
            cla = CLA_ISO7816,
            ins = INS_READ_RECORD,
            p1 = recordNumber,
            p2 = p2,
            le = 0x00.toUByte()
        )
    }
    
    /**
     * Build GENERATE APPLICATION CRYPTOGRAM command
     * Ported from: EMVAC()
     */
    fun buildGenerateApplicationCryptogram(
        acType: UByte,
        cdol: ByteArray = byteArrayOf()
    ): ApduCommand {
        return ApduCommand(
            cla = CLA_PROPRIETARY,
            ins = INS_GENERATE_AC,
            p1 = acType,
            p2 = 0x00.toUByte(),
            data = cdol,
            le = 0x00.toUByte()
        )
    }
    
    /**
     * Build GENERATE CHALLENGE command
     * Ported from: EMVGenerateChallenge()
     */
    fun buildGenerateChallenge(challengeLength: UByte = 0x08.toUByte()): ApduCommand {
        return ApduCommand(
            cla = CLA_ISO7816,
            ins = INS_GET_CHALLENGE,
            p1 = 0x00.toUByte(),
            p2 = 0x00.toUByte(),
            le = challengeLength
        )
    }
    
    /**
     * Build INTERNAL AUTHENTICATE command
     * Ported from: EMVInternalAuthenticate() 
     */
    fun buildInternalAuthenticate(ddol: ByteArray): ApduCommand {
        return ApduCommand(
            cla = CLA_ISO7816,
            ins = INS_INTERNAL_AUTHENTICATE,
            p1 = 0x00.toUByte(),
            p2 = 0x00.toUByte(),
            data = ddol,
            le = 0x00.toUByte()
        )
    }
    
    /**
     * Build GET DATA command
     * Ported from: EMVGetData()
     */
    fun buildGetData(tag: UShort): ApduCommand {
        val p1 = ((tag.toUInt() shr 8) and 0xFFu).toUByte()
        val p2 = (tag.toUInt() and 0xFFu).toUByte()
        
        return ApduCommand(
            cla = CLA_ISO7816,
            ins = INS_GET_DATA,
            p1 = p1,
            p2 = p2,
            le = 0x00.toUByte()
        )
    }
    
    /**
     * Build EXTERNAL AUTHENTICATE command
     */
    fun buildExternalAuthenticate(authData: ByteArray): ApduCommand {
        return ApduCommand(
            cla = CLA_ISO7816,
            ins = INS_EXTERNAL_AUTHENTICATE,
            p1 = 0x00.toUByte(),
            p2 = 0x00.toUByte(),
            data = authData
        )
    }
    
    /**
     * Build COMPUTE CRYPTOGRAPHIC CHECKSUM command (Mastercard specific)
     * Ported from: MSCComputeCryptoChecksum()
     */
    fun buildComputeCryptographicChecksum(udol: ByteArray): ApduCommand {
        return ApduCommand(
            cla = CLA_PROPRIETARY,
            ins = INS_COMPUTE_CRYPTOGRAPHIC_CHECKSUM,
            p1 = 0x8E.toUByte(),
            p2 = 0x80.toUByte(),
            data = udol,
            le = 0x00.toUByte()
        )
    }
    
    /**
     * Build SELECT command with AID string
     */
    fun buildSelectAid(aidHex: String, firstOccurrence: Boolean = true): ApduCommand {
        val aid = aidHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        return buildSelect(aid, firstOccurrence)
    }
    
    /**
     * Build common EMV test commands
     */
    fun buildTestCommands(): List<ApduCommand> {
        return listOf(
            buildSelectPSE(contactless = true),   // SELECT 2PAY.SYS.DDF01
            buildSelectPSE(contactless = false),  // SELECT 1PAY.SYS.DDF01
            buildGetProcessingOptions(),          // GPO with empty PDOL
            buildGenerateChallenge(),             // GET CHALLENGE
        )
    }
}

/**
 * APDU Exchange Result
 */
sealed class ApduResult {
    data class Success(val response: ApduResponse) : ApduResult()
    data class Error(val message: String, val exception: Throwable? = null) : ApduResult()
    data class Timeout(val timeoutMs: Long) : ApduResult()
    
    fun isSuccess(): Boolean = this is Success
    fun isError(): Boolean = this is Error || this is Timeout
    
    inline fun onSuccess(action: (ApduResponse) -> Unit): ApduResult {
        if (this is Success) action(response)
        return this
    }
    
    inline fun onError(action: (String, Throwable?) -> Unit): ApduResult {
        when (this) {
            is Error -> action(message, exception)
            is Timeout -> action("Command timeout (${timeoutMs}ms)", null)
            else -> {}
        }
        return this
    }
}