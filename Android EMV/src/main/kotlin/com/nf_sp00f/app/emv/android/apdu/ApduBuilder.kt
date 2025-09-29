/**
 * nf-sp00f EMV Engine - APDU Builder
 *
 * Enterprise-grade APDU command builder for EMV transactions
 * Zero defensive programming - comprehensive validation approach
 *
 * @package com.nf_sp00f.app.emv.apdu
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv.apdu

/**
 * Enterprise APDU Command Builder
 * Constructs EMV-compliant APDU commands with comprehensive validation
 */
class ApduBuilder {
    
    private val command = mutableListOf<Byte>()
    
    /**
     * Build APDU command with enterprise validation
     */
    fun build(
        cla: Int,
        ins: Int, 
        p1: Int,
        p2: Int,
        data: ByteArray = byteArrayOf(),
        lc: Int? = null,
        le: Int? = null
    ): ByteArray {
        validateApduParameters(cla, ins, p1, p2, data, lc, le)
        
        command.clear()
        
        // Add header
        command.add(cla.toByte())
        command.add(ins.toByte())
        command.add(p1.toByte())
        command.add(p2.toByte())
        
        // Add Lc and data if present
        if (data.isNotEmpty()) {
            val lcValue = if (lc != null) {
                validateLcValue(lc, data.size)
                lc
            } else {
                data.size
            }
            
            command.add(lcValue.toByte())
            command.addAll(data.toList())
        }
        
        // Add Le if present
        if (le != null) {
            validateLeValue(le)
            command.add(le.toByte())
        }
        
        val apdu = command.toByteArray()
        validateBuiltApdu(apdu)
        
        ApduAuditor.logApduBuild(
            "SUCCESS",
            "CLA=0x${String.format("%02X", cla)} INS=0x${String.format("%02X", ins)} " +
            "P1=0x${String.format("%02X", p1)} P2=0x${String.format("%02X", p2)} " +
            "DataLen=${data.size} Lc=${lc ?: "auto"} Le=${le ?: "none"}"
        )
        
        return apdu
    }
    
    /**
     * Build SELECT command with comprehensive validation
     */
    fun buildSelect(aid: String): ByteArray {
        validateAidForSelect(aid)
        
        val aidBytes = aid.hexToByteArray()
        
        ApduAuditor.logSelectCommand("AID", aid)
        return build(
            cla = 0x00,
            ins = 0xA4,
            p1 = 0x04,
            p2 = 0x00,
            data = aidBytes
        )
    }
    
    /**
     * Build GET PROCESSING OPTIONS command with validation
     */
    fun buildGetProcessingOptions(pdol: ByteArray): ByteArray {
        validatePdolForGpo(pdol)
        
        ApduAuditor.logGpoCommand("PDOL", "${pdol.size} bytes")
        return build(
            cla = 0x80,
            ins = 0xA8,
            p1 = 0x00,
            p2 = 0x00,
            data = pdol
        )
    }
    
    /**
     * Build READ RECORD command with validation
     */
    fun buildReadRecord(recordNumber: Int, sfi: Int): ByteArray {
        validateReadRecordParameters(recordNumber, sfi)
        
        ApduAuditor.logReadRecordCommand("PARAMS", "Record=$recordNumber, SFI=$sfi")
        return build(
            cla = 0x00,
            ins = 0xB2,
            p1 = recordNumber,
            p2 = (sfi shl 3) or 0x04,
            le = 0x00
        )
    }
    
    /**
     * Build GENERATE AC command with validation
     */
    fun buildGenerateAc(acType: Int, cdol: ByteArray): ByteArray {
        validateGenerateAcParameters(acType, cdol)
        
        ApduAuditor.logGenerateAcCommand("PARAMS", "Type=0x${String.format("%02X", acType)}, CDOL=${cdol.size} bytes")
        return build(
            cla = 0x80,
            ins = 0xAE,
            p1 = acType,
            p2 = 0x00,
            data = cdol
        )
    }
    
    /**
     * Build VERIFY command with validation
     */
    fun buildVerify(p2: Int, data: ByteArray): ByteArray {
        validateVerifyParameters(p2, data)
        
        ApduAuditor.logVerifyCommand("PARAMS", "P2=0x${String.format("%02X", p2)}, Data=${data.size} bytes")
        return build(
            cla = 0x00,
            ins = 0x20,
            p1 = 0x00,
            p2 = p2,
            data = data
        )
    }
    
    /**
     * Build GET DATA command with validation
     */
    fun buildGetData(tag: Int): ByteArray {
        validateGetDataTag(tag)
        
        val p1 = (tag shr 8) and 0xFF
        val p2 = tag and 0xFF
        
        ApduAuditor.logGetDataCommand("TAG", "0x${String.format("%04X", tag)}")
        return build(
            cla = 0x00,
            ins = 0xCA,
            p1 = p1,
            p2 = p2,
            le = 0x00
        )
    }
    
    /**
     * Enterprise validation functions
     */
    private fun validateApduParameters(
        cla: Int, ins: Int, p1: Int, p2: Int, 
        data: ByteArray, lc: Int?, le: Int?
    ) {
        if (cla !in 0x00..0xFF) {
            throw IllegalArgumentException("Invalid CLA: $cla (must be 0x00-0xFF)")
        }
        
        if (ins !in 0x00..0xFF) {
            throw IllegalArgumentException("Invalid INS: $ins (must be 0x00-0xFF)")
        }
        
        if (p1 !in 0x00..0xFF) {
            throw IllegalArgumentException("Invalid P1: $p1 (must be 0x00-0xFF)")
        }
        
        if (p2 !in 0x00..0xFF) {
            throw IllegalArgumentException("Invalid P2: $p2 (must be 0x00-0xFF)")
        }
        
        if (data.size > 255) {
            throw IllegalArgumentException("Data too large: ${data.size} bytes (maximum 255 for standard APDU)")
        }
        
        if (lc != null && (lc < 0 || lc > 255)) {
            throw IllegalArgumentException("Invalid Lc: $lc (must be 0-255)")
        }
        
        if (le != null && (le < 0 || le > 256)) {
            throw IllegalArgumentException("Invalid Le: $le (must be 0-256, where 0 means 256)")
        }
        
        ApduAuditor.logValidation("APDU_PARAMS", "SUCCESS", "All parameters validated")
    }
    
    private fun validateLcValue(lc: Int, dataSize: Int) {
        if (lc != dataSize) {
            throw IllegalArgumentException("Lc mismatch: specified $lc but data size is $dataSize")
        }
        
        ApduAuditor.logValidation("LC_VALUE", "SUCCESS", "Lc=$lc matches data size")
    }
    
    private fun validateLeValue(le: Int) {
        if (le < 0 || le > 256) {
            throw IllegalArgumentException("Invalid Le: $le (must be 0-256)")
        }
        
        ApduAuditor.logValidation("LE_VALUE", "SUCCESS", "Le=$le")
    }
    
    private fun validateBuiltApdu(apdu: ByteArray) {
        if (apdu.size < 4) {
            throw IllegalStateException("Built APDU too short: ${apdu.size} bytes (minimum 4)")
        }
        
        if (apdu.size > 261) {
            throw IllegalStateException("Built APDU too long: ${apdu.size} bytes (maximum 261)")
        }
        
        ApduAuditor.logValidation("BUILT_APDU", "SUCCESS", "${apdu.size} bytes")
    }
    
    private fun validateAidForSelect(aid: String) {
        if (aid.isBlank()) {
            throw IllegalArgumentException("AID cannot be blank")
        }
        
        if (aid.length % 2 != 0) {
            throw IllegalArgumentException("AID must have even number of hex characters: ${aid.length}")
        }
        
        if (aid.length < 10 || aid.length > 32) {
            throw IllegalArgumentException("AID length invalid: ${aid.length} characters (must be 10-32)")
        }
        
        val hexPattern = Regex("^[0-9A-Fa-f]+$")
        if (!hexPattern.matches(aid)) {
            throw IllegalArgumentException("AID contains invalid hex characters: $aid")
        }
        
        ApduAuditor.logValidation("AID_SELECT", "SUCCESS", aid)
    }
    
    private fun validatePdolForGpo(pdol: ByteArray) {
        if (pdol.size > 252) {
            throw IllegalArgumentException("PDOL too large: ${pdol.size} bytes (maximum 252)")
        }
        
        ApduAuditor.logValidation("PDOL_GPO", "SUCCESS", "${pdol.size} bytes")
    }
    
    private fun validateReadRecordParameters(recordNumber: Int, sfi: Int) {
        if (recordNumber < 1 || recordNumber > 16) {
            throw IllegalArgumentException("Invalid record number: $recordNumber (must be 1-16)")
        }
        
        if (sfi < 1 || sfi > 30) {
            throw IllegalArgumentException("Invalid SFI: $sfi (must be 1-30)")
        }
        
        ApduAuditor.logValidation("READ_RECORD_PARAMS", "SUCCESS", "Record=$recordNumber, SFI=$sfi")
    }
    
    private fun validateGenerateAcParameters(acType: Int, cdol: ByteArray) {
        val validAcTypes = setOf(0x00, 0x40, 0x80)
        if (acType !in validAcTypes) {
            throw IllegalArgumentException("Invalid AC type: 0x${String.format("%02X", acType)} (must be 0x00, 0x40, or 0x80)")
        }
        
        if (cdol.size > 252) {
            throw IllegalArgumentException("CDOL too large: ${cdol.size} bytes (maximum 252)")
        }
        
        ApduAuditor.logValidation("GENERATE_AC_PARAMS", "SUCCESS", "Type=0x${String.format("%02X", acType)}, CDOL=${cdol.size} bytes")
    }
    
    private fun validateVerifyParameters(p2: Int, data: ByteArray) {
        if (p2 !in 0x00..0xFF) {
            throw IllegalArgumentException("Invalid P2 for VERIFY: $p2 (must be 0x00-0xFF)")
        }
        
        if (data.isEmpty()) {
            throw IllegalArgumentException("VERIFY data cannot be empty")
        }
        
        if (data.size > 8) {
            throw IllegalArgumentException("VERIFY data too large: ${data.size} bytes (maximum 8)")
        }
        
        ApduAuditor.logValidation("VERIFY_PARAMS", "SUCCESS", "P2=0x${String.format("%02X", p2)}, Data=${data.size} bytes")
    }
    
    private fun validateGetDataTag(tag: Int) {
        if (tag < 0 || tag > 0xFFFF) {
            throw IllegalArgumentException("Invalid tag for GET DATA: 0x${String.format("%04X", tag)} (must be 0x0000-0xFFFF)")
        }
        
        ApduAuditor.logValidation("GET_DATA_TAG", "SUCCESS", "0x${String.format("%04X", tag)}")
    }
}

/**
 * APDU auditor for enterprise environments
 */
object ApduAuditor {
    fun logApduBuild(result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_APDU_AUDIT: [$timestamp] BUILD - result=$result details=$details")
    }
    
    fun logSelectCommand(type: String, value: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_APDU_AUDIT: [$timestamp] SELECT_COMMAND - type=$type value=$value")
    }
    
    fun logGpoCommand(type: String, value: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_APDU_AUDIT: [$timestamp] GPO_COMMAND - type=$type value=$value")
    }
    
    fun logReadRecordCommand(type: String, value: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_APDU_AUDIT: [$timestamp] READ_RECORD_COMMAND - type=$type value=$value")
    }
    
    fun logGenerateAcCommand(type: String, value: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_APDU_AUDIT: [$timestamp] GENERATE_AC_COMMAND - type=$type value=$value")
    }
    
    fun logVerifyCommand(type: String, value: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_APDU_AUDIT: [$timestamp] VERIFY_COMMAND - type=$type value=$value")
    }
    
    fun logGetDataCommand(type: String, value: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_APDU_AUDIT: [$timestamp] GET_DATA_COMMAND - type=$type value=$value")
    }
    
    fun logValidation(component: String, result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_APDU_AUDIT: [$timestamp] VALIDATION - component=$component result=$result details=$details")
    }
}

// Extension function for hex conversion
private fun String.hexToByteArray(): ByteArray = 
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()
