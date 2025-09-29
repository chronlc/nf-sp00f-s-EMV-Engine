/**
 * nf-sp00f EMV Engine - Enterprise APDU Command System
 *
 * Production-grade APDU command representation with comprehensive validation.
 * Zero defensive programming - explicit business logic validation.
 *
 * @package com.nf_sp00f.app.emv.apdu
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv.apdu

import com.nf_sp00f.app.emv.utils.EmvUtilities
import timber.log.Timber

/**
 * APDU instruction classes following ISO/IEC 7816-4
 */
enum class ApduClass(val value: Byte) {
    ISO_7816_INTERINDUSTRY(0x00.toByte()),
    ISO_7816_RESERVED_FUTURE_USE(0x10.toByte()),
    EMV_PROPRIETARY(0x80.toByte()),
    VENDOR_SPECIFIC(0x90.toByte()),
    APPLICATION_SPECIFIC(0xA0.toByte())
}

/**
 * Common EMV APDU instructions
 */
enum class ApduInstruction(val value: Byte) {
    SELECT(0xA4.toByte()),
    READ_RECORD(0xB2.toByte()),
    GET_PROCESSING_OPTIONS(0xA8.toByte()),
    GET_DATA(0xCA.toByte()),
    VERIFY(0x20.toByte()),
    INTERNAL_AUTHENTICATE(0x88.toByte()),
    EXTERNAL_AUTHENTICATE(0x82.toByte()),
    GENERATE_AC(0xAE.toByte()),
    GET_CHALLENGE(0x84.toByte()),
    PUT_DATA(0xDA.toByte())
}

/**
 * Enterprise APDU Command with comprehensive validation
 */
data class ApduCommand(
    val cla: Byte,
    val ins: Byte,
    val p1: Byte,
    val p2: Byte,
    val data: ByteArray = byteArrayOf(),
    val le: Int? = null
) {
    
    companion object {
        private const val TAG = "ApduCommand"
        private const val MAX_APDU_LENGTH = 65535
        private const val MAX_DATA_LENGTH = 65535
        private const val MAX_LE_VALUE = 65536
        
        /**
         * Create SELECT command with enterprise validation
         */
        fun createSelectCommand(
            aid: ByteArray,
            selectType: SelectType = SelectType.SELECT_BY_DF_NAME
        ): ApduCommand {
            validateAidForSelection(aid)
            
            val command = ApduCommand(
                cla = ApduClass.ISO_7816_INTERINDUSTRY.value,
                ins = ApduInstruction.SELECT.value,
                p1 = selectType.p1Value,
                p2 = 0x00,
                data = aid,
                le = 0x00
            )
            
            ApduCommandLogger.logCommandCreation("SELECT", aid.size, "SUCCESS")
            return command
        }
        
        /**
         * Create READ RECORD command with enterprise validation
         */
        fun createReadRecordCommand(
            recordNumber: Int,
            sfi: Int,
            readType: ReadRecordType = ReadRecordType.READ_RECORD_ABSOLUTE
        ): ApduCommand {
            validateRecordNumber(recordNumber)
            validateSfi(sfi)
            
            val p1 = recordNumber.toByte()
            val p2 = ((sfi shl 3) or readType.value).toByte()
            
            val command = ApduCommand(
                cla = ApduClass.ISO_7816_INTERINDUSTRY.value,
                ins = ApduInstruction.READ_RECORD.value,
                p1 = p1,
                p2 = p2,
                le = 0x00
            )
            
            ApduCommandLogger.logCommandCreation("READ_RECORD", 0, "SUCCESS")
            return command
        }
        
        /**
         * Create GET PROCESSING OPTIONS command with enterprise validation
         */
        fun createGetProcessingOptionsCommand(pdol: ByteArray): ApduCommand {
            validatePdolData(pdol)
            
            val command = ApduCommand(
                cla = ApduClass.ISO_7816_INTERINDUSTRY.value,
                ins = ApduInstruction.GET_PROCESSING_OPTIONS.value,
                p1 = 0x00,
                p2 = 0x00,
                data = pdol,
                le = 0x00
            )
            
            ApduCommandLogger.logCommandCreation("GET_PROCESSING_OPTIONS", pdol.size, "SUCCESS")
            return command
        }
        
        /**
         * Create GENERATE AC command with enterprise validation
         */
        fun createGenerateAcCommand(
            acType: AcType,
            cdol: ByteArray
        ): ApduCommand {
            validateCdolData(cdol)
            
            val command = ApduCommand(
                cla = ApduClass.ISO_7816_INTERINDUSTRY.value,
                ins = ApduInstruction.GENERATE_AC.value,
                p1 = acType.p1Value,
                p2 = 0x00,
                data = cdol,
                le = 0x00
            )
            
            ApduCommandLogger.logCommandCreation("GENERATE_AC", cdol.size, "SUCCESS")
            return command
        }
        
        /**
         * Create GET DATA command with enterprise validation
         */
        fun createGetDataCommand(tag: Int): ApduCommand {
            validateDataObjectTag(tag)
            
            val p1 = ((tag shr 8) and 0xFF).toByte()
            val p2 = (tag and 0xFF).toByte()
            
            val command = ApduCommand(
                cla = ApduClass.ISO_7816_INTERINDUSTRY.value,
                ins = ApduInstruction.GET_DATA.value,
                p1 = p1,
                p2 = p2,
                le = 0x00
            )
            
            ApduCommandLogger.logCommandCreation("GET_DATA", 0, "SUCCESS")
            return command
        }
        
        /**
         * Create INTERNAL AUTHENTICATE command with enterprise validation
         */
        fun createInternalAuthenticateCommand(authData: ByteArray): ApduCommand {
            validateAuthenticationData(authData)
            
            val command = ApduCommand(
                cla = ApduClass.ISO_7816_INTERINDUSTRY.value,
                ins = ApduInstruction.INTERNAL_AUTHENTICATE.value,
                p1 = 0x00,
                p2 = 0x00,
                data = authData,
                le = 0x00
            )
            
            ApduCommandLogger.logCommandCreation("INTERNAL_AUTHENTICATE", authData.size, "SUCCESS")
            return command
        }
        
        /**
         * Enterprise validation functions
         */
        private fun validateAidForSelection(aid: ByteArray) {
            if (aid.isEmpty()) {
                throw IllegalArgumentException("AID cannot be empty for SELECT command")
            }
            
            if (aid.size > 16) {
                throw IllegalArgumentException("AID length exceeds maximum: ${aid.size} > 16")
            }
            
            ApduCommandLogger.logValidation("AID", "SUCCESS", "AID validated for SELECT")
        }
        
        private fun validateRecordNumber(recordNumber: Int) {
            if (recordNumber < 1 || recordNumber > 255) {
                throw IllegalArgumentException("Record number out of range: $recordNumber (1-255)")
            }
            
            ApduCommandLogger.logValidation("RECORD_NUMBER", "SUCCESS", "Record number validated")
        }
        
        private fun validateSfi(sfi: Int) {
            if (sfi < 1 || sfi > 30) {
                throw IllegalArgumentException("SFI out of range: $sfi (1-30)")
            }
            
            ApduCommandLogger.logValidation("SFI", "SUCCESS", "SFI validated")
        }
        
        private fun validatePdolData(pdol: ByteArray) {
            if (pdol.size > 255) {
                throw IllegalArgumentException("PDOL data exceeds maximum length: ${pdol.size}")
            }
            
            ApduCommandLogger.logValidation("PDOL", "SUCCESS", "PDOL data validated")
        }
        
        private fun validateCdolData(cdol: ByteArray) {
            if (cdol.size > 255) {
                throw IllegalArgumentException("CDOL data exceeds maximum length: ${cdol.size}")
            }
            
            ApduCommandLogger.logValidation("CDOL", "SUCCESS", "CDOL data validated")
        }
        
        private fun validateDataObjectTag(tag: Int) {
            if (tag < 0x0000 || tag > 0xFFFF) {
                throw IllegalArgumentException("Data object tag out of range: 0x${tag.toString(16)}")
            }
            
            ApduCommandLogger.logValidation("DATA_TAG", "SUCCESS", "Data object tag validated")
        }
        
        private fun validateAuthenticationData(authData: ByteArray) {
            if (authData.isEmpty()) {
                throw IllegalArgumentException("Authentication data cannot be empty")
            }
            
            if (authData.size > 255) {
                throw IllegalArgumentException("Authentication data exceeds maximum: ${authData.size}")
            }
            
            ApduCommandLogger.logValidation("AUTH_DATA", "SUCCESS", "Authentication data validated")
        }
    }
    
    init {
        validateApduCommand()
    }
    
    /**
     * Convert APDU command to byte array representation
     */
    fun toByteArray(): ByteArray {
        validateCommandForTransmission()
        
        val result = mutableListOf<Byte>()
        
        // Add header (CLA, INS, P1, P2)
        result.add(cla)
        result.add(ins)
        result.add(p1)
        result.add(p2)
        
        // Add Lc and data if present
        if (data.isNotEmpty()) {
            if (data.size <= 255) {
                result.add(data.size.toByte())
            } else {
                result.add(0x00)
                result.add(((data.size shr 8) and 0xFF).toByte())
                result.add((data.size and 0xFF).toByte())
            }
            result.addAll(data.toList())
        }
        
        // Add Le if present
        if (le != null) {
            when {
                le == 0x00 -> result.add(0x00)
                le <= 255 -> result.add(le.toByte())
                else -> {
                    result.add(0x00)
                    result.add(((le shr 8) and 0xFF).toByte())
                    result.add((le and 0xFF).toByte())
                }
            }
        }
        
        val byteArray = result.toByteArray()
        ApduCommandLogger.logCommandSerialization(getCommandName(), byteArray.size, "SUCCESS")
        
        return byteArray
    }
    
    /**
     * Get human-readable command name
     */
    fun getCommandName(): String {
        return when (ins) {
            ApduInstruction.SELECT.value -> "SELECT"
            ApduInstruction.READ_RECORD.value -> "READ_RECORD"
            ApduInstruction.GET_PROCESSING_OPTIONS.value -> "GET_PROCESSING_OPTIONS"
            ApduInstruction.GENERATE_AC.value -> "GENERATE_AC"
            ApduInstruction.GET_DATA.value -> "GET_DATA"
            ApduInstruction.INTERNAL_AUTHENTICATE.value -> "INTERNAL_AUTHENTICATE"
            ApduInstruction.EXTERNAL_AUTHENTICATE.value -> "EXTERNAL_AUTHENTICATE"
            ApduInstruction.VERIFY.value -> "VERIFY"
            ApduInstruction.GET_CHALLENGE.value -> "GET_CHALLENGE"
            ApduInstruction.PUT_DATA.value -> "PUT_DATA"
            else -> "UNKNOWN_0x${ins.toString(16).uppercase().padStart(2, '0')}"
        }
    }
    
    /**
     * Get command description for logging
     */
    fun getDescription(): String {
        return buildString {
            append("APDU Command: ${getCommandName()}")
            append(" (CLA=0x${cla.toString(16).uppercase().padStart(2, '0')}")
            append(", INS=0x${ins.toString(16).uppercase().padStart(2, '0')}")
            append(", P1=0x${p1.toString(16).uppercase().padStart(2, '0')}")
            append(", P2=0x${p2.toString(16).uppercase().padStart(2, '0')}")
            if (data.isNotEmpty()) {
                append(", Lc=${data.size}")
            }
            if (le != null) {
                append(", Le=$le")
            }
            append(")")
        }
    }
    
    /**
     * Check if command expects response data
     */
    fun expectsResponseData(): Boolean = le != null
    
    /**
     * Check if command has data field
     */
    fun hasDataField(): Boolean = data.isNotEmpty()
    
    /**
     * Get total command length including all fields
     */
    fun getTotalLength(): Int {
        var length = 4 // CLA + INS + P1 + P2
        
        if (data.isNotEmpty()) {
            length += if (data.size <= 255) 1 else 3 // Lc field
            length += data.size // Data
        }
        
        if (le != null) {
            length += if (le <= 255) 1 else 3 // Le field
        }
        
        return length
    }
    
    /**
     * Enterprise validation for complete APDU command
     */
    private fun validateApduCommand() {
        validateApduLength()
        validateDataLength()
        validateLeValue()
        validateCommandStructure()
        
        ApduCommandLogger.logValidation("APDU_COMMAND", "SUCCESS", "Complete APDU validated")
    }
    
    private fun validateApduLength() {
        val totalLength = getTotalLength()
        if (totalLength > MAX_APDU_LENGTH) {
            throw IllegalArgumentException("APDU length exceeds maximum: $totalLength > $MAX_APDU_LENGTH")
        }
    }
    
    private fun validateDataLength() {
        if (data.size > MAX_DATA_LENGTH) {
            throw IllegalArgumentException("Data length exceeds maximum: ${data.size} > $MAX_DATA_LENGTH")
        }
    }
    
    private fun validateLeValue() {
        if (le != null && le > MAX_LE_VALUE) {
            throw IllegalArgumentException("Le value exceeds maximum: $le > $MAX_LE_VALUE")
        }
    }
    
    private fun validateCommandStructure() {
        // Validate that extended length encoding is used consistently
        val hasExtendedLc = data.isNotEmpty() && data.size > 255
        val hasExtendedLe = le != null && le > 255
        
        if (hasExtendedLc && le != null && le <= 255) {
            throw IllegalArgumentException("Inconsistent length encoding: extended Lc with short Le")
        }
        
        if (hasExtendedLe && data.size <= 255 && data.isNotEmpty()) {
            throw IllegalArgumentException("Inconsistent length encoding: short Lc with extended Le")
        }
    }
    
    private fun validateCommandForTransmission() {
        if (getTotalLength() > MAX_APDU_LENGTH) {
            throw IllegalStateException("Command too large for transmission: ${getTotalLength()}")
        }
        
        ApduCommandLogger.logValidation("TRANSMISSION", "SUCCESS", "Command ready for transmission")
    }
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        
        other as ApduCommand
        
        if (cla != other.cla) return false
        if (ins != other.ins) return false
        if (p1 != other.p1) return false
        if (p2 != other.p2) return false
        if (!data.contentEquals(other.data)) return false
        if (le != other.le) return false
        
        return true
    }
    
    override fun hashCode(): Int {
        var result = cla.toInt()
        result = 31 * result + ins.toInt()
        result = 31 * result + p1.toInt()
        result = 31 * result + p2.toInt()
        result = 31 * result + data.contentHashCode()
        result = 31 * result + (le ?: 0)
        return result
    }
    
    override fun toString(): String = getDescription()
}

/**
 * SELECT command types
 */
enum class SelectType(val p1Value: Byte) {
    SELECT_BY_DF_NAME(0x04),
    SELECT_BY_PATH(0x08),
    SELECT_BY_FILE_IDENTIFIER(0x00),
    SELECT_PARENT_DF(0x03),
    SELECT_BY_AID(0x04)
}

/**
 * READ RECORD command types
 */
enum class ReadRecordType(val value: Int) {
    READ_RECORD_ABSOLUTE(0x04),
    READ_RECORD_CURRENT(0x00),
    READ_ALL_RECORDS(0x05)
}

/**
 * Application Cryptogram types for GENERATE AC
 */
enum class AcType(val p1Value: Byte) {
    AAC(0x00), // Application Authentication Cryptogram (decline)
    TC(0x40),  // Transaction Certificate (approve)
    ARQC(0x80), // Authorization Request Cryptogram (online)
    CDA(0x10)  // Combined DDA/Application Cryptogram
}

/**
 * APDU Command Logger for enterprise environments
 */
object ApduCommandLogger {
    fun logCommandCreation(commandType: String, dataLength: Int, result: String) {
        val timestamp = System.currentTimeMillis()
        println("APDU_COMMAND_AUDIT: [$timestamp] COMMAND_CREATED - type=$commandType dataLength=$dataLength result=$result")
    }
    
    fun logCommandSerialization(commandType: String, totalLength: Int, result: String) {
        val timestamp = System.currentTimeMillis()
        println("APDU_COMMAND_AUDIT: [$timestamp] COMMAND_SERIALIZED - type=$commandType totalLength=$totalLength result=$result")
    }
    
    fun logValidation(component: String, result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("APDU_COMMAND_AUDIT: [$timestamp] VALIDATION - component=$component result=$result details=$details")
    }
}
