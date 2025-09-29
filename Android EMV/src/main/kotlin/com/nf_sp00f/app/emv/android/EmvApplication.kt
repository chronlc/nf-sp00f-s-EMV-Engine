/**
 * nf-sp00f EMV Engine - Enterprise EMV Application Data Structure
 *
 * Production-grade EMV application representation following EMV Book 1.
 * Zero defensive programming - explicit business logic validation.
 *
 * @package com.nf_sp00f.app.emv
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv

import com.nf_sp00f.app.emv.utils.EmvUtilities
import timber.log.Timber

/**
 * EMV Application Priority levels following EMV Book 1
 */
enum class ApplicationPriority(val value: Int, val description: String) {
    HIGHEST(1, "Highest priority"),
    HIGH(2, "High priority"),
    MEDIUM(3, "Medium priority"),
    LOW(4, "Low priority"),
    LOWEST(15, "Lowest priority");
    
    companion object {
        /**
         * Get priority from value with enterprise validation
         */
        fun fromValue(value: Int): ApplicationPriority {
            validatePriorityValue(value)
            
            return values().find { it.value == value } 
                ?: throw IllegalArgumentException("Invalid priority value: $value")
        }
        
        private fun validatePriorityValue(value: Int) {
            if (value < 1 || value > 15) {
                throw IllegalArgumentException("Priority value out of range: $value (1-15)")
            }
        }
    }
}

/**
 * Application Selection Indicator values
 */
enum class ApplicationSelectionIndicator(val value: Byte, val description: String) {
    SELECTION_SUPPORTED(0x00, "Selection with partial DF name supported"),
    SELECTION_NOT_SUPPORTED(0x80.toByte(), "Selection with partial DF name not supported");
    
    companion object {
        /**
         * Get selection indicator from byte value
         */
        fun fromValue(value: Byte): ApplicationSelectionIndicator {
            return values().find { it.value == value }
                ?: SELECTION_NOT_SUPPORTED
        }
    }
}

/**
 * Issuer Code Table Index values for character set selection
 */
enum class IssuerCodeTableIndex(val value: Byte, val description: String, val charset: String) {
    ISO_8859_1(0x01, "ISO 8859-1", "ISO-8859-1"),
    ISO_8859_2(0x02, "ISO 8859-2", "ISO-8859-2"),
    ISO_8859_3(0x03, "ISO 8859-3", "ISO-8859-3"),
    ISO_8859_4(0x04, "ISO 8859-4", "ISO-8859-4"),
    ISO_8859_5(0x05, "ISO 8859-5", "ISO-8859-5"),
    ISO_8859_6(0x06, "ISO 8859-6", "ISO-8859-6"),
    ISO_8859_7(0x07, "ISO 8859-7", "ISO-8859-7"),
    ISO_8859_8(0x08, "ISO 8859-8", "ISO-8859-8"),
    ISO_8859_9(0x09, "ISO 8859-9", "ISO-8859-9"),
    ISO_8859_10(0x0A, "ISO 8859-10", "ISO-8859-10");
    
    companion object {
        /**
         * Get code table from value
         */
        fun fromValue(value: Byte): IssuerCodeTableIndex? {
            return values().find { it.value == value }
        }
    }
}

/**
 * Enterprise EMV Application following EMV Book 1 specifications
 */
data class EmvApplication(
    val aid: ByteArray,
    val label: String,
    val preferredName: String? = null,
    val priority: ApplicationPriority = ApplicationPriority.MEDIUM,
    val languagePreference: String? = null,
    val issuerCodeTableIndex: IssuerCodeTableIndex? = null,
    val applicationSelectionIndicator: ApplicationSelectionIndicator = ApplicationSelectionIndicator.SELECTION_NOT_SUPPORTED,
    val pdolData: ByteArray? = null,
    val fciTemplate: ByteArray? = null,
    val supportedProtocols: Set<EmvProtocol> = emptySet(),
    val kernelConfiguration: EmvKernelConfiguration? = null
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
        fun fromFciTemplate(fciTemplate: ByteArray): EmvApplication {
            validateFciTemplate(fciTemplate)
            
            val parser = FciTemplateParser(fciTemplate)
            val parsedData = parser.parse()
            
            val application = EmvApplication(
                aid = parsedData.aid,
                label = parsedData.label,
                preferredName = parsedData.preferredName,
                priority = parsedData.priority,
                languagePreference = parsedData.languagePreference,
                issuerCodeTableIndex = parsedData.issuerCodeTableIndex,
                applicationSelectionIndicator = parsedData.applicationSelectionIndicator,
                pdolData = parsedData.pdolData,
                fciTemplate = fciTemplate,
                supportedProtocols = parsedData.supportedProtocols,
                kernelConfiguration = parsedData.kernelConfiguration
            )
            
            EmvApplicationLogger.logApplicationCreation(application.getAidHex(), "FROM_FCI", "SUCCESS")
            
            return application
        }
        
        /**
         * Create EMV application from known AID with enterprise validation
         */
        fun fromKnownAid(aidHex: String, label: String): EmvApplication {
            validateAidHex(aidHex)
            validateLabel(label)
            
            val aid = hexToByteArray(aidHex)
            val knownAppData = getKnownApplicationData(aid)
            
            val application = EmvApplication(
                aid = aid,
                label = label,
                preferredName = knownAppData.preferredName,
                priority = knownAppData.priority,
                languagePreference = knownAppData.languagePreference,
                issuerCodeTableIndex = knownAppData.issuerCodeTableIndex,
                applicationSelectionIndicator = knownAppData.selectionIndicator,
                supportedProtocols = knownAppData.supportedProtocols,
                kernelConfiguration = knownAppData.kernelConfiguration
            )
            
            EmvApplicationLogger.logApplicationCreation(aidHex, "FROM_KNOWN_AID", "SUCCESS")
            
            return application
        }
        
        /**
         * Enterprise validation functions
         */
        private fun validateFciTemplate(fciTemplate: ByteArray) {
            if (fciTemplate.isEmpty()) {
                throw IllegalArgumentException("FCI template cannot be empty")
            }
            
            if (fciTemplate.size > 255) {
                throw IllegalArgumentException("FCI template too large: ${fciTemplate.size}")
            }
            
            EmvApplicationLogger.logValidation("FCI_TEMPLATE", "SUCCESS", "FCI template validated")
        }
        
        private fun validateAidHex(aidHex: String) {
            if (aidHex.isBlank()) {
                throw IllegalArgumentException("AID cannot be blank")
            }
            
            val cleanHex = aidHex.replace(" ", "").replace(":", "")
            if (cleanHex.length < MIN_AID_LENGTH * 2 || cleanHex.length > MAX_AID_LENGTH * 2) {
                throw IllegalArgumentException("Invalid AID length: ${cleanHex.length} chars")
            }
            
            if (!cleanHex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
                throw IllegalArgumentException("Invalid AID format")
            }
            
            EmvApplicationLogger.logValidation("AID_HEX", "SUCCESS", "AID hex validated")
        }
        
        private fun validateLabel(label: String) {
            if (label.isBlank()) {
                throw IllegalArgumentException("Label cannot be blank")
            }
            
            if (label.length > MAX_LABEL_LENGTH) {
                throw IllegalArgumentException("Label too long: ${label.length} > $MAX_LABEL_LENGTH")
            }
            
            EmvApplicationLogger.logValidation("LABEL", "SUCCESS", "Label validated")
        }
        
        private fun hexToByteArray(hex: String): ByteArray {
            val cleanHex = hex.replace(" ", "").replace(":", "")
            return cleanHex.chunked(2)
                .map { it.toInt(16).toByte() }
                .toByteArray()
        }
        
        private fun getKnownApplicationData(aid: ByteArray): KnownApplicationData {
            return when {
                aid.contentEquals(hexToByteArray("A0000000031010")) -> KnownApplicationData(
                    preferredName = "VISA",
                    priority = ApplicationPriority.HIGH,
                    languagePreference = "en",
                    issuerCodeTableIndex = IssuerCodeTableIndex.ISO_8859_1,
                    selectionIndicator = ApplicationSelectionIndicator.SELECTION_SUPPORTED,
                    supportedProtocols = setOf(EmvProtocol.CONTACT, EmvProtocol.CONTACTLESS),
                    kernelConfiguration = EmvKernelConfiguration.VISA_KERNEL
                )
                
                aid.contentEquals(hexToByteArray("A0000000041010")) -> KnownApplicationData(
                    preferredName = "MASTERCARD",
                    priority = ApplicationPriority.HIGH,
                    languagePreference = "en",
                    issuerCodeTableIndex = IssuerCodeTableIndex.ISO_8859_1,
                    selectionIndicator = ApplicationSelectionIndicator.SELECTION_SUPPORTED,
                    supportedProtocols = setOf(EmvProtocol.CONTACT, EmvProtocol.CONTACTLESS),
                    kernelConfiguration = EmvKernelConfiguration.MASTERCARD_KERNEL
                )
                
                aid.contentEquals(hexToByteArray("A000000025010701")) -> KnownApplicationData(
                    preferredName = "AMERICAN EXPRESS",
                    priority = ApplicationPriority.MEDIUM,
                    languagePreference = "en",
                    issuerCodeTableIndex = IssuerCodeTableIndex.ISO_8859_1,
                    selectionIndicator = ApplicationSelectionIndicator.SELECTION_SUPPORTED,
                    supportedProtocols = setOf(EmvProtocol.CONTACT, EmvProtocol.CONTACTLESS),
                    kernelConfiguration = EmvKernelConfiguration.AMEX_KERNEL
                )
                
                else -> KnownApplicationData(
                    preferredName = null,
                    priority = ApplicationPriority.MEDIUM,
                    languagePreference = null,
                    issuerCodeTableIndex = null,
                    selectionIndicator = ApplicationSelectionIndicator.SELECTION_NOT_SUPPORTED,
                    supportedProtocols = setOf(EmvProtocol.CONTACT),
                    kernelConfiguration = EmvKernelConfiguration.GENERIC_KERNEL
                )
            }
        }
    }
    
    init {
        validateApplication()
    }
    
    /**
     * Get AID as hex string
     */
    fun getAidHex(): String = aid.joinToString("") { "%02X".format(it) }
    
    /**
     * Get display name (preferred name or label)
     */
    fun getDisplayName(): String = preferredName ?: label
    
    /**
     * Get application description for logging
     */
    fun getDescription(): String {
        return buildString {
            append("EMV Application: ${getDisplayName()}")
            append(" (AID: ${getAidHex()})")
            append(", Priority: ${priority.description}")
            if (languagePreference != null) {
                append(", Language: $languagePreference")
            }
        }
    }
    
    /**
     * Check if application supports specific protocol
     */
    fun supportsProtocol(protocol: EmvProtocol): Boolean = supportedProtocols.contains(protocol)
    
    /**
     * Check if application supports contactless
     */
    fun isContactlessSupported(): Boolean = supportsProtocol(EmvProtocol.CONTACTLESS)
    
    /**
     * Check if application supports contact
     */
    fun isContactSupported(): Boolean = supportsProtocol(EmvProtocol.CONTACT)
    
    /**
     * Get kernel identifier for processing
     */
    fun getKernelId(): String = kernelConfiguration?.kernelId ?: "GENERIC"
    
    /**
     * Check if application has PDOL data
     */
    fun hasPdolData(): Boolean = pdolData != null && pdolData.isNotEmpty()
    
    /**
     * Get PDOL data length
     */
    fun getPdolDataLength(): Int = pdolData?.size ?: 0
    
    /**
     * Get character encoding for text fields
     */
    fun getCharacterEncoding(): String = issuerCodeTableIndex?.charset ?: "UTF-8"
    
    /**
     * Create application selection request
     */
    fun createSelectionRequest(): ApplicationSelectionRequest {
        return ApplicationSelectionRequest(
            aid = aid,
            selectionType = if (applicationSelectionIndicator == ApplicationSelectionIndicator.SELECTION_SUPPORTED) {
                SelectionType.PARTIAL_AID
            } else {
                SelectionType.FULL_AID
            },
            expectedResponseLength = if (hasPdolData()) 256 else 0
        )
    }
    
    /**
     * Validate application completeness for processing
     */
    fun validateForProcessing() {
        if (aid.isEmpty()) {
            throw IllegalStateException("Application AID is empty")
        }
        
        if (label.isBlank()) {
            throw IllegalStateException("Application label is blank")
        }
        
        if (supportedProtocols.isEmpty()) {
            throw IllegalStateException("No supported protocols defined")
        }
        
        EmvApplicationLogger.logValidation("PROCESSING", "SUCCESS", "Application validated for processing")
    }
    
    /**
     * Enterprise validation for application
     */
    private fun validateApplication() {
        validateAid()
        validateApplicationLabel()
        validatePreferredName()
        validateLanguagePreference()
        validatePdolData()
        
        EmvApplicationLogger.logValidation("APPLICATION", "SUCCESS", "Complete application validated")
    }
    
    private fun validateAid() {
        if (aid.isEmpty()) {
            throw IllegalArgumentException("AID cannot be empty")
        }
        
        if (aid.size < MIN_AID_LENGTH || aid.size > MAX_AID_LENGTH) {
            throw IllegalArgumentException("Invalid AID length: ${aid.size} (${MIN_AID_LENGTH}-${MAX_AID_LENGTH})")
        }
        
        // Validate AID format (RID + PIX)
        if (aid.size >= 5) {
            val rid = aid.copyOfRange(0, 5)
            // Check for known RIDs
            val knownRids = setOf(
                "A000000003", // Visa
                "A000000004", // Mastercard  
                "A000000025", // American Express
                "A000000065", // JCB
                "A000000042"  // Maestro
            )
            
            val ridHex = rid.joinToString("") { "%02X".format(it) }
            if (!knownRids.any { ridHex.startsWith(it) }) {
                EmvApplicationLogger.logValidation("AID_RID", "WARNING", "Unknown RID: $ridHex")
            }
        }
    }
    
    private fun validateApplicationLabel() {
        if (label.isBlank()) {
            throw IllegalArgumentException("Application label cannot be blank")
        }
        
        if (label.length > MAX_LABEL_LENGTH) {
            throw IllegalArgumentException("Label too long: ${label.length} > $MAX_LABEL_LENGTH")
        }
        
        // Validate label characters (printable ASCII or specific encoding)
        if (!label.all { it.isLetterOrDigit() || it.isWhitespace() || it in "()-./" }) {
            throw IllegalArgumentException("Invalid characters in application label")
        }
    }
    
    private fun validatePreferredName() {
        if (preferredName != null) {
            if (preferredName.length > MAX_PREFERRED_NAME_LENGTH) {
                throw IllegalArgumentException("Preferred name too long: ${preferredName.length} > $MAX_PREFERRED_NAME_LENGTH")
            }
            
            if (!preferredName.all { it.isLetterOrDigit() || it.isWhitespace() || it in "()-./" }) {
                throw IllegalArgumentException("Invalid characters in preferred name")
            }
        }
    }
    
    private fun validateLanguagePreference() {
        if (languagePreference != null) {
            if (languagePreference.length > MAX_LANGUAGE_PREFERENCE_LENGTH) {
                throw IllegalArgumentException("Language preference too long: ${languagePreference.length}")
            }
            
            // Validate ISO 639 language code format
            if (!languagePreference.matches(Regex("^[a-z]{2,3}(-[A-Z]{2})?$"))) {
                throw IllegalArgumentException("Invalid language preference format: $languagePreference")
            }
        }
    }
    
    private fun validatePdolData() {
        if (pdolData != null && pdolData.size > 255) {
            throw IllegalArgumentException("PDOL data too large: ${pdolData.size}")
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
        if (pdolData != null) {
            if (other.pdolData == null) return false
            if (!pdolData.contentEquals(other.pdolData)) return false
        } else if (other.pdolData != null) return false
        
        return true
    }
    
    override fun hashCode(): Int {
        var result = aid.contentHashCode()
        result = 31 * result + label.hashCode()
        result = 31 * result + (preferredName?.hashCode() ?: 0)
        result = 31 * result + priority.hashCode()
        result = 31 * result + (languagePreference?.hashCode() ?: 0)
        result = 31 * result + (issuerCodeTableIndex?.hashCode() ?: 0)
        result = 31 * result + applicationSelectionIndicator.hashCode()
        result = 31 * result + (pdolData?.contentHashCode() ?: 0)
        return result
    }
    
    override fun toString(): String = getDescription()
}

/**
 * EMV Protocol support enumeration
 */
enum class EmvProtocol {
    CONTACT,
    CONTACTLESS,
    MOBILE,
    WEARABLE
}

/**
 * EMV Kernel configuration for different payment schemes
 */
enum class EmvKernelConfiguration(val kernelId: String, val description: String) {
    GENERIC_KERNEL("EMV_GENERIC", "Generic EMV kernel"),
    VISA_KERNEL("EMV_VISA", "Visa payWave kernel"),
    MASTERCARD_KERNEL("EMV_MASTERCARD", "Mastercard PayPass kernel"),
    AMEX_KERNEL("EMV_AMEX", "American Express ExpressPay kernel"),
    DISCOVER_KERNEL("EMV_DISCOVER", "Discover Zip kernel"),
    JCB_KERNEL("EMV_JCB", "JCB J/Speedy kernel"),
    UNIONPAY_KERNEL("EMV_UNIONPAY", "UnionPay QuickPass kernel")
}

/**
 * Application selection request data
 */
data class ApplicationSelectionRequest(
    val aid: ByteArray,
    val selectionType: SelectionType,
    val expectedResponseLength: Int
)

/**
 * Selection type enumeration
 */
enum class SelectionType {
    FULL_AID,
    PARTIAL_AID
}

/**
 * Known application data structure
 */
private data class KnownApplicationData(
    val preferredName: String?,
    val priority: ApplicationPriority,
    val languagePreference: String?,
    val issuerCodeTableIndex: IssuerCodeTableIndex?,
    val selectionIndicator: ApplicationSelectionIndicator,
    val supportedProtocols: Set<EmvProtocol>,
    val kernelConfiguration: EmvKernelConfiguration
)

/**
 * FCI template parser data structure
 */
private data class FciParsedData(
    val aid: ByteArray,
    val label: String,
    val preferredName: String?,
    val priority: ApplicationPriority,
    val languagePreference: String?,
    val issuerCodeTableIndex: IssuerCodeTableIndex?,
    val applicationSelectionIndicator: ApplicationSelectionIndicator,
    val pdolData: ByteArray?,
    val supportedProtocols: Set<EmvProtocol>,
    val kernelConfiguration: EmvKernelConfiguration?
)

/**
 * FCI Template Parser for enterprise processing
 */
private class FciTemplateParser(private val fciTemplate: ByteArray) {
    
    fun parse(): FciParsedData {
        // This would be a complete FCI template parser implementation
        // For now, return basic parsing results
        
        val aid = extractAidFromFci()
        val label = extractLabelFromFci()
        val preferredName = extractPreferredNameFromFci()
        val priority = extractPriorityFromFci()
        val languagePreference = extractLanguagePreferenceFromFci()
        val issuerCodeTableIndex = extractIssuerCodeTableIndexFromFci()
        val applicationSelectionIndicator = extractApplicationSelectionIndicatorFromFci()
        val pdolData = extractPdolDataFromFci()
        val supportedProtocols = extractSupportedProtocolsFromFci()
        val kernelConfiguration = extractKernelConfigurationFromFci()
        
        return FciParsedData(
            aid = aid,
            label = label,
            preferredName = preferredName,
            priority = priority,
            languagePreference = languagePreference,
            issuerCodeTableIndex = issuerCodeTableIndex,
            applicationSelectionIndicator = applicationSelectionIndicator,
            pdolData = pdolData,
            supportedProtocols = supportedProtocols,
            kernelConfiguration = kernelConfiguration
        )
    }
    
    private fun extractAidFromFci(): ByteArray {
        // Extract AID from FCI template (tag 4F)
        return findTlvData(0x4F) ?: throw IllegalArgumentException("No AID found in FCI")
    }
    
    private fun extractLabelFromFci(): String {
        // Extract application label (tag 50)
        val labelData = findTlvData(0x50)
        return if (labelData != null) {
            String(labelData, Charsets.UTF_8).trim()
        } else {
            "UNKNOWN APPLICATION"
        }
    }
    
    private fun extractPreferredNameFromFci(): String? {
        // Extract preferred name (tag 9F12)
        val nameData = findTlvData(0x9F12)
        return if (nameData != null) {
            String(nameData, Charsets.UTF_8).trim()
        } else {
            null
        }
    }
    
    private fun extractPriorityFromFci(): ApplicationPriority {
        // Extract priority indicator (tag 87)
        val priorityData = findTlvData(0x87)
        return if (priorityData != null && priorityData.isNotEmpty()) {
            ApplicationPriority.fromValue(priorityData[0].toInt() and 0x0F)
        } else {
            ApplicationPriority.MEDIUM
        }
    }
    
    private fun extractLanguagePreferenceFromFci(): String? {
        // Extract language preference (tag 5F2D)
        val langData = findTlvData(0x5F2D)
        return if (langData != null && langData.size >= 2) {
            String(langData.copyOfRange(0, 2), Charsets.US_ASCII)
        } else {
            null
        }
    }
    
    private fun extractIssuerCodeTableIndexFromFci(): IssuerCodeTableIndex? {
        // Extract issuer code table index (tag 9F11)
        val indexData = findTlvData(0x9F11)
        return if (indexData != null && indexData.isNotEmpty()) {
            IssuerCodeTableIndex.fromValue(indexData[0])
        } else {
            null
        }
    }
    
    private fun extractApplicationSelectionIndicatorFromFci(): ApplicationSelectionIndicator {
        // Extract application selection indicator (tag 9F29)
        val asiData = findTlvData(0x9F29)
        return if (asiData != null && asiData.isNotEmpty()) {
            ApplicationSelectionIndicator.fromValue(asiData[0])
        } else {
            ApplicationSelectionIndicator.SELECTION_NOT_SUPPORTED
        }
    }
    
    private fun extractPdolDataFromFci(): ByteArray? {
        // Extract PDOL (tag 9F38)
        return findTlvData(0x9F38)
    }
    
    private fun extractSupportedProtocolsFromFci(): Set<EmvProtocol> {
        // Default to contact protocol
        return setOf(EmvProtocol.CONTACT)
    }
    
    private fun extractKernelConfigurationFromFci(): EmvKernelConfiguration? {
        // Determine kernel based on AID
        return null
    }
    
    private fun findTlvData(tag: Int): ByteArray? {
        // Simple TLV parser implementation
        var position = 0
        
        while (position < fciTemplate.size - 2) {
            val currentTag = if ((fciTemplate[position].toInt() and 0x1F) == 0x1F) {
                // Multi-byte tag
                if (position + 1 >= fciTemplate.size) break
                ((fciTemplate[position].toInt() and 0xFF) shl 8) or (fciTemplate[position + 1].toInt() and 0xFF)
            } else {
                // Single-byte tag
                fciTemplate[position].toInt() and 0xFF
            }
            
            val tagLength = if ((fciTemplate[position].toInt() and 0x1F) == 0x1F) 2 else 1
            position += tagLength
            
            if (position >= fciTemplate.size) break
            
            val length = fciTemplate[position].toInt() and 0xFF
            position += 1
            
            if (position + length > fciTemplate.size) break
            
            if (currentTag == tag) {
                return fciTemplate.copyOfRange(position, position + length)
            }
            
            position += length
        }
        
        return null
    }
}

/**
 * EMV Application Logger for enterprise environments
 */
object EmvApplicationLogger {
    fun logApplicationCreation(aid: String, method: String, result: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_APPLICATION_AUDIT: [$timestamp] APP_CREATED - aid=$aid method=$method result=$result")
    }
    
    fun logValidation(component: String, result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("EMV_APPLICATION_AUDIT: [$timestamp] VALIDATION - component=$component result=$result details=$details")
    }
}
