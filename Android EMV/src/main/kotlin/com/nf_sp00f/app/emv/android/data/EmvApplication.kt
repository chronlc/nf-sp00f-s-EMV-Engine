/**
 * nf-sp00f EMV Engine - Enterprise EMV Application Data Structure
 *
 * Production-grade EMV application representation with comprehensive validation.
 * Zero defensive programming - explicit business logic validation.
 *
 * @package com.nf_sp00f.app.emv.data
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv.data

import com.nf_sp00f.app.emv.utils.EmvUtilities
import timber.log.Timber

/**
 * EMV Application Selection Indicator values per EMV Book 1
 */
enum class ApplicationSelectionIndicator(val value: Byte, val description: String) {
    PARTIAL_AID_MATCH(0x00, "Partial AID selection supported"),
    EXACT_AID_MATCH(0x01, "Exact AID match required");
    
    companion object {
        fun fromByte(value: Byte): ApplicationSelectionIndicator {
            return values().find { it.value == value } ?: PARTIAL_AID_MATCH
        }
    }
}

/**
 * EMV Application Priority levels per EMV Book 1
 */
enum class ApplicationPriority(val level: Int, val description: String) {
    HIGHEST(1, "Highest priority"),
    HIGH(2, "High priority"),
    NORMAL(3, "Normal priority"),
    LOW(4, "Low priority"),
    LOWEST(15, "Lowest priority");
    
    companion object {
        fun fromInt(level: Int): ApplicationPriority {
            return values().find { it.level == level } ?: NORMAL
        }
        
        fun fromByte(value: Byte): ApplicationPriority {
            return fromInt(value.toInt() and 0x0F)
        }
    }
}

/**
 * EMV Application Type classification
 */
enum class EmvApplicationType(val code: String, val description: String) {
    CREDIT("CREDIT", "Credit application"),
    DEBIT("DEBIT", "Debit application"),
    PREPAID("PREPAID", "Prepaid application"),
    LOYALTY("LOYALTY", "Loyalty application"),
    TRANSIT("TRANSIT", "Transit application"),
    ELECTRONIC_CASH("E_CASH", "Electronic cash application"),
    UNKNOWN("UNKNOWN", "Unknown application type");
    
    companion object {
        fun fromLabel(label: String): EmvApplicationType {
            return when {
                label.contains("CREDIT", ignoreCase = true) -> CREDIT
                label.contains("DEBIT", ignoreCase = true) -> DEBIT
                label.contains("PREPAID", ignoreCase = true) -> PREPAID
                label.contains("LOYALTY", ignoreCase = true) -> LOYALTY
                label.contains("TRANSIT", ignoreCase = true) -> TRANSIT
                label.contains("CASH", ignoreCase = true) -> ELECTRONIC_CASH
                else -> UNKNOWN
            }
        }
    }
}

/**
 * Enterprise EMV Application data structure with comprehensive validation
 */
data class EmvApplication(
    val aid: ByteArray,
    val label: String,
    val preferredName: String? = null,
    val priority: Int = ApplicationPriority.NORMAL.level,
    val languagePreference: String? = null,
    val issuerCodeTableIndex: Int? = null,
    val applicationSelectionIndicator: Boolean = false,
    val pdol: ByteArray? = null,
    val fci: ByteArray? = null,
    val dedicatedFileName: ByteArray? = null
) {
    
    companion object {
        private const val TAG = "EmvApplication"
        private const val MIN_AID_LENGTH = 5
        private const val MAX_AID_LENGTH = 16
        private const val MAX_LABEL_LENGTH = 16
        private const val MAX_PREFERRED_NAME_LENGTH = 16
        private const val MAX_LANGUAGE_PREFERENCE_LENGTH = 8
        
        /**
         * Create EMV application from FCI template with enterprise validation
         */
        fun fromFciTemplate(aid: ByteArray, fciTemplate: ByteArray): EmvApplication {
            validateAidForApplication(aid)
            validateFciTemplate(fciTemplate)
            
            val tlvParser = TlvParser()
            val fciData = tlvParser.parseTemplate(fciTemplate)
            
            // Extract application data from FCI
            val label = extractApplicationLabel(fciData)
            val preferredName = extractPreferredName(fciData)
            val priority = extractApplicationPriority(fciData)
            val languagePreference = extractLanguagePreference(fciData)
            val issuerCodeTableIndex = extractIssuerCodeTableIndex(fciData)
            val asi = extractApplicationSelectionIndicator(fciData)
            val pdol = extractPdol(fciData)
            val dedicatedFileName = extractDedicatedFileName(fciData)
            
            val application = EmvApplication(
                aid = aid,
                label = label,
                preferredName = preferredName,
                priority = priority,
                languagePreference = languagePreference,
                issuerCodeTableIndex = issuerCodeTableIndex,
                applicationSelectionIndicator = asi,
                pdol = pdol,
                fci = fciTemplate,
                dedicatedFileName = dedicatedFileName
            )
            
            EmvApplicationLogger.logApplicationCreation(application.getDisplayName(), aid.size, "SUCCESS")
            
            return application
        }
        
        /**
         * Create application from PSE entry with enterprise validation
         */
        fun fromPseEntry(pseRecord: ByteArray): EmvApplication {
            validatePseRecord(pseRecord)
            
            val tlvParser = TlvParser()
            val pseData = tlvParser.parseTemplate(pseRecord)
            
            // Extract required data from PSE record
            val aid = extractAidFromPse(pseData)
            val label = extractApplicationLabel(pseData)
            val priority = extractApplicationPriority(pseData)
            val preferredName = extractPreferredName(pseData)
            val languagePreference = extractLanguagePreference(pseData)
            
            val application = EmvApplication(
                aid = aid,
                label = label,
                preferredName = preferredName,
                priority = priority,
                languagePreference = languagePreference
            )
            
            EmvApplicationLogger.logApplicationCreation(application.getDisplayName(), aid.size, "PSE_SUCCESS")
            
            return application
        }
        
        /**
         * Create application with known AID for testing/fallback
         */
        fun createKnownApplication(aidHex: String, label: String): EmvApplication {
            validateKnownAid(aidHex)
            validateApplicationLabel(label)
            
            val aid = EmvUtilities.hexToByteArray(aidHex)
            val priority = determineKnownApplicationPriority(aidHex)
            val applicationType = EmvApplicationType.fromLabel(label)
            
            val application = EmvApplication(
                aid = aid,
                label = label,
                priority = priority
            )
            
            EmvApplicationLogger.logApplicationCreation(label, aid.size, "KNOWN_APP")
            
            return application
        }
        
        private fun validateAidForApplication(aid: ByteArray) {
            if (aid.size < MIN_AID_LENGTH || aid.size > MAX_AID_LENGTH) {
                throw IllegalArgumentException("Invalid AID length: ${aid.size} (expected $MIN_AID_LENGTH-$MAX_AID_LENGTH)")
            }
            
            EmvApplicationLogger.logValidation("AID", "SUCCESS", "AID length validated")
        }
        
        private fun validateFciTemplate(fciTemplate: ByteArray) {
            if (fciTemplate.isEmpty()) {
                throw IllegalArgumentException("FCI template cannot be empty")
            }
            
            if (fciTemplate.size > 255) {
                throw IllegalArgumentException("FCI template too large: ${fciTemplate.size}")
            }
            
            EmvApplicationLogger.logValidation("FCI_TEMPLATE", "SUCCESS", "FCI template validated")
        }
        
        private fun validatePseRecord(pseRecord: ByteArray) {
            if (pseRecord.isEmpty()) {
                throw IllegalArgumentException("PSE record cannot be empty")
            }
            
            if (pseRecord.size > 255) {
                throw IllegalArgumentException("PSE record too large: ${pseRecord.size}")
            }
            
            EmvApplicationLogger.logValidation("PSE_RECORD", "SUCCESS", "PSE record validated")
        }
        
        private fun validateKnownAid(aidHex: String) {
            if (aidHex.isBlank()) {
                throw IllegalArgumentException("Known AID cannot be blank")
            }
            
            val cleanHex = aidHex.replace(" ", "").replace(":", "")
            if (cleanHex.length < MIN_AID_LENGTH * 2 || cleanHex.length > MAX_AID_LENGTH * 2) {
                throw IllegalArgumentException("Invalid known AID hex length: ${cleanHex.length}")
            }
            
            EmvApplicationLogger.logValidation("KNOWN_AID", "SUCCESS", "Known AID validated")
        }
        
        private fun validateApplicationLabel(label: String) {
            if (label.isBlank()) {
                throw IllegalArgumentException("Application label cannot be blank")
            }
            
            if (label.length > MAX_LABEL_LENGTH) {
                throw IllegalArgumentException("Application label too long: ${label.length}")
            }
            
            EmvApplicationLogger.logValidation("APP_LABEL", "SUCCESS", "Application label validated")
        }
        
        private fun extractApplicationLabel(tlvData: Map<String, ByteArray>): String {
            // Try Application Label (tag 50) first
            tlvData["50"]?.let { labelBytes ->
                return String(labelBytes, Charsets.UTF_8).trim()
            }
            
            // Fallback to Application Preferred Name (tag 9F12)
            tlvData["9F12"]?.let { nameBytes ->
                return String(nameBytes, Charsets.UTF_8).trim()
            }
            
            return "EMV APPLICATION"
        }
        
        private fun extractPreferredName(tlvData: Map<String, ByteArray>): String? {
            return tlvData["9F12"]?.let { nameBytes ->
                val name = String(nameBytes, Charsets.UTF_8).trim()
                if (name.isNotBlank() && name.length <= MAX_PREFERRED_NAME_LENGTH) name else null
            }
        }
        
        private fun extractApplicationPriority(tlvData: Map<String, ByteArray>): Int {
            return tlvData["87"]?.let { priorityBytes ->
                if (priorityBytes.isNotEmpty()) {
                    ApplicationPriority.fromByte(priorityBytes[0]).level
                } else {
                    ApplicationPriority.NORMAL.level
                }
            } ?: ApplicationPriority.NORMAL.level
        }
        
        private fun extractLanguagePreference(tlvData: Map<String, ByteArray>): String? {
            return tlvData["5F2D"]?.let { langBytes ->
                val lang = String(langBytes, Charsets.UTF_8).trim()
                if (lang.isNotBlank() && lang.length <= MAX_LANGUAGE_PREFERENCE_LENGTH) lang else null
            }
        }
        
        private fun extractIssuerCodeTableIndex(tlvData: Map<String, ByteArray>): Int? {
            return tlvData["9F11"]?.let { indexBytes ->
                if (indexBytes.isNotEmpty()) {
                    indexBytes[0].toUByte().toInt()
                } else {
                    null
                }
            }
        }
        
        private fun extractApplicationSelectionIndicator(tlvData: Map<String, ByteArray>): Boolean {
            return tlvData["9F29"]?.let { asiBytes ->
                if (asiBytes.isNotEmpty()) {
                    ApplicationSelectionIndicator.fromByte(asiBytes[0]) == ApplicationSelectionIndicator.EXACT_AID_MATCH
                } else {
                    false
                }
            } ?: false
        }
        
        private fun extractPdol(tlvData: Map<String, ByteArray>): ByteArray? {
            return tlvData["9F38"]
        }
        
        private fun extractDedicatedFileName(tlvData: Map<String, ByteArray>): ByteArray? {
            return tlvData["84"]
        }
        
        private fun extractAidFromPse(tlvData: Map<String, ByteArray>): ByteArray {
            return tlvData["4F"] ?: throw IllegalArgumentException("No AID found in PSE record")
        }
        
        private fun determineKnownApplicationPriority(aidHex: String): Int {
            return when {
                aidHex.startsWith("A0000000031010") -> ApplicationPriority.HIGH.level // Visa
                aidHex.startsWith("A0000000041010") -> ApplicationPriority.HIGH.level // Mastercard
                aidHex.startsWith("A000000025") -> ApplicationPriority.NORMAL.level // American Express
                aidHex.startsWith("A0000000651010") -> ApplicationPriority.NORMAL.level // JCB
                else -> ApplicationPriority.LOW.level
            }
        }
    }
    
    init {
        validateEmvApplication()
    }
    
    /**
     * Get display name for application
     */
    fun getDisplayName(): String {
        return preferredName ?: label
    }
    
    /**
     * Get AID as hex string
     */
    fun getAidHex(): String {
        return EmvUtilities.byteArrayToHex(aid)
    }
    
    /**
     * Get application type classification
     */
    fun getApplicationType(): EmvApplicationType {
        return EmvApplicationType.fromLabel(label)
    }
    
    /**
     * Get application priority enum
     */
    fun getApplicationPriority(): ApplicationPriority {
        return ApplicationPriority.fromInt(priority)
    }
    
    /**
     * Check if application supports partial AID matching
     */
    fun supportsPartialAidMatching(): Boolean {
        return !applicationSelectionIndicator
    }
    
    /**
     * Check if application has PDOL
     */
    fun hasPdol(): Boolean {
        return pdol != null && pdol.isNotEmpty()
    }
    
    /**
     * Get PDOL length
     */
    fun getPdolLength(): Int {
        return pdol?.size ?: 0
    }
    
    /**
     * Check if application has FCI template
     */
    fun hasFci(): Boolean {
        return fci != null && fci.isNotEmpty()
    }
    
    /**
     * Check if application has dedicated file name
     */
    fun hasDedicatedFileName(): Boolean {
        return dedicatedFileName != null && dedicatedFileName.isNotEmpty()
    }
    
    /**
     * Get comprehensive application description
     */
    fun getDescription(): String {
        return buildString {
            append("EMV Application: ${getDisplayName()}")
            append(" (AID: ${getAidHex()})")
            append(", Type: ${getApplicationType().description}")
            append(", Priority: ${getApplicationPriority().description}")
            
            if (languagePreference != null) {
                append(", Language: $languagePreference")
            }
            
            if (hasPdol()) {
                append(", PDOL: ${getPdolLength()} bytes")
            }
            
            if (supportsPartialAidMatching()) {
                append(", Supports partial AID matching")
            }
        }
    }
    
    /**
     * Validate application for selection
     */
    fun validateForSelection() {
        if (aid.isEmpty()) {
            throw IllegalStateException("Cannot select application with empty AID")
        }
        
        if (label.isBlank()) {
            throw IllegalStateException("Cannot select application with blank label")
        }
        
        EmvApplicationLogger.logValidation("SELECTION", "SUCCESS", "Application validated for selection")
    }
    
    /**
     * Validate application for transaction processing
     */
    fun validateForTransaction() {
        validateForSelection()
        
        if (getApplicationType() == EmvApplicationType.UNKNOWN) {
            throw IllegalStateException("Cannot process transaction with unknown application type")
        }
        
        EmvApplicationLogger.logValidation("TRANSACTION", "SUCCESS", "Application validated for transaction")
    }
    
    /**
     * Check if application matches AID
     */
    fun matchesAid(targetAid: ByteArray): Boolean {
        if (applicationSelectionIndicator) {
            // Exact match required
            return aid.contentEquals(targetAid)
        } else {
            // Partial match supported
            if (targetAid.size < aid.size) {
                return false
            }
            
            return aid.contentEquals(targetAid.copyOfRange(0, aid.size))
        }
    }
    
    /**
     * Check if application matches AID hex string
     */
    fun matchesAidHex(targetAidHex: String): Boolean {
        return try {
            val targetAid = EmvUtilities.hexToByteArray(targetAidHex)
            matchesAid(targetAid)
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Get application selection data for logging
     */
    fun getSelectionData(): Map<String, Any> {
        return mapOf(
            "aid" to getAidHex(),
            "label" to label,
            "preferredName" to (preferredName ?: ""),
            "priority" to priority,
            "type" to getApplicationType().code,
            "languagePreference" to (languagePreference ?: ""),
            "hasPdol" to hasPdol(),
            "pdolLength" to getPdolLength(),
            "supportsPartialMatching" to supportsPartialAidMatching(),
            "hasFci" to hasFci(),
            "hasDedicatedFileName" to hasDedicatedFileName()
        )
    }
    
    /**
     * Enterprise validation for complete EMV application
     */
    private fun validateEmvApplication() {
        validateApplicationAid()
        validateApplicationLabel()
        validateApplicationPriority()
        validateOptionalFields()
        
        EmvApplicationLogger.logValidation("EMV_APPLICATION", "SUCCESS", "Complete application validated")
    }
    
    private fun validateApplicationAid() {
        if (aid.size < MIN_AID_LENGTH || aid.size > MAX_AID_LENGTH) {
            throw IllegalArgumentException("Invalid AID length: ${aid.size}")
        }
        
        // Validate AID format (first bytes should indicate registered application identifier)
        if (aid.isEmpty() || aid[0] == 0x00.toByte()) {
            throw IllegalArgumentException("Invalid AID format")
        }
    }
    
    private fun validateApplicationLabel() {
        if (label.isBlank()) {
            throw IllegalArgumentException("Application label cannot be blank")
        }
        
        if (label.length > MAX_LABEL_LENGTH) {
            throw IllegalArgumentException("Application label too long: ${label.length}")
        }
    }
    
    private fun validateApplicationPriority() {
        if (priority < 1 || priority > 15) {
            throw IllegalArgumentException("Invalid application priority: $priority (1-15)")
        }
    }
    
    private fun validateOptionalFields() {
        preferredName?.let { name ->
            if (name.length > MAX_PREFERRED_NAME_LENGTH) {
                throw IllegalArgumentException("Preferred name too long: ${name.length}")
            }
        }
        
        languagePreference?.let { lang ->
            if (lang.length > MAX_LANGUAGE_PREFERENCE_LENGTH) {
                throw IllegalArgumentException("Language preference too long: ${lang.length}")
            }
        }
        
        issuerCodeTableIndex?.let { index ->
            if (index < 0 || index > 255) {
                throw IllegalArgumentException("Invalid issuer code table index: $index")
            }
        }
        
        pdol?.let { pdolData ->
            if (pdolData.size > 255) {
                throw IllegalArgumentException("PDOL too large: ${pdolData.size}")
            }
        }
    }
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        
        other as EmvApplication
        
        if (!aid.contentEquals(other.aid)) return false
        if (label != other.label) return false
        if (preferredName != other.preferredName) return false
        if (priority != other.priority) return false
        if (languagePreference != other.languagePreference) return false
        if (issuerCodeTableIndex != other.issuerCodeTableIndex) return false
        if (applicationSelectionIndicator != other.applicationSelectionIndicator) return false
        if (pdol != null) {
            if (other.pdol == null) return false
            if (!pdol.contentEquals(other.pdol)) return false
        } else if (other.pdol != null) return false
        
        return true
    }
    
    override fun hashCode(): Int {
        var result = aid.contentHashCode()
        result = 31 * result + label.hashCode()
        result = 31 * result + (preferredName?.hashCode() ?: 0)
        result = 31 * result + priority
        result = 31 * result + (languagePreference?.hashCode() ?: 0)
        result = 31 * result + (issuerCodeTableIndex ?: 0)
        result = 31 * result + applicationSelectionIndicator.hashCode()
        result = 31 * result + (pdol?.contentHashCode() ?: 0)
        return result
    }
    
    override fun toString(): String = getDescription()
}

/**
 * EMV Application comparison for selection priority
 */
class EmvApplicationComparator : Comparator<EmvApplication> {
    override fun compare(app1: EmvApplication, app2: EmvApplication): Int {
        // Compare by priority first (lower number = higher priority)
        val priorityComparison = app1.priority.compareTo(app2.priority)
        if (priorityComparison != 0) {
            return priorityComparison
        }
        
        // If same priority, compare by label
        return app1.label.compareTo(app2.label)
    }
}

/**
 * EMV Application Logger for enterprise environments
 */
object EmvApplicationLogger {
    fun logApplicationCreation(appName: String, aidLength: Int, result: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_APPLICATION_AUDIT: [$timestamp] APP_CREATED - name=$appName aidLength=$aidLength result=$result")
    }
    
    fun logApplicationSelection(appName: String, aidHex: String, result: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_APPLICATION_AUDIT: [$timestamp] APP_SELECTED - name=$appName aid=$aidHex result=$result")
    }
    
    fun logValidation(component: String, result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_APPLICATION_AUDIT: [$timestamp] VALIDATION - component=$component result=$result details=$details")
    }
}
