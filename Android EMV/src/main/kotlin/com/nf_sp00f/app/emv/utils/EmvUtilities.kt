/**
 * nf-sp00f EMV Engine - EMV Utilities
 *
 * Comprehensive utility functions for EMV processing, card detection,
 * data parsing, validation, and helper operations.
 *
 * @package com.nf_sp00f.app.emv.utils
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv.utils

import com.nf_sp00f.app.emv.data.*
import com.nf_sp00f.app.emv.tlv.*
import com.nf_sp00f.app.emv.security.*
import timber.log.Timber
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Currency
import java.util.Locale
import kotlin.experimental.and

/**
 * EMV Card Vendor enumeration
 */
enum class CardVendor(val displayName: String, val supportedFeatures: Set<EmvFeature>) {
    VISA("Visa", setOf(EmvFeature.SDA, EmvFeature.DDA, EmvFeature.CDA, EmvFeature.CONTACTLESS)),
    MASTERCARD("Mastercard", setOf(EmvFeature.SDA, EmvFeature.DDA, EmvFeature.CDA, EmvFeature.MSC, EmvFeature.CONTACTLESS)),
    AMERICAN_EXPRESS("American Express", setOf(EmvFeature.SDA, EmvFeature.DDA, EmvFeature.CONTACTLESS)),
    JCB("JCB", setOf(EmvFeature.SDA, EmvFeature.DDA, EmvFeature.CONTACTLESS)),
    DINERS("Diners Club", setOf(EmvFeature.SDA, EmvFeature.DDA)),
    DISCOVER("Discover", setOf(EmvFeature.SDA, EmvFeature.DDA, EmvFeature.CONTACTLESS)),
    SWITCH("Switch", setOf(EmvFeature.SDA, EmvFeature.DDA)),
    CB("CB", setOf(EmvFeature.SDA, EmvFeature.DDA, EmvFeature.CONTACTLESS)),
    OTHER("Other", setOf(EmvFeature.SDA)),
    UNKNOWN("Unknown", emptySet())
}

/**
 * EMV Features supported by cards
 */
enum class EmvFeature {
    SDA,           // Static Data Authentication
    DDA,           // Dynamic Data Authentication
    CDA,           // Combined Data Authentication
    MSC,           // Mastercard Specific Commands
    CONTACTLESS,   // Contactless support
    MOBILE_PAYMENT // Mobile payment support
}

/**
 * Card Type classification
 */
enum class CardType {
    CONTACT,
    CONTACTLESS,
    DUAL_INTERFACE,
    UNKNOWN
}

/**
 * Currency information
 */
data class CurrencyInfo(
    val code: String,
    val numericCode: String,
    val displayName: String,
    val symbol: String
)

/**
 * Country information
 */
data class CountryInfo(
    val code: String,
    val numericCode: String,
    val displayName: String
)

/**
 * EMV Utilities class providing comprehensive helper functions
 */
class EmvUtilities {
    
    companion object {
        private const val TAG = "EmvUtilities"
        
        // AID prefixes for vendor detection
        private val VISA_AIDS = listOf(
            "A0000000031010",    // Visa Debit/Credit
            "A0000000032010",    // Visa Electron
            "A0000000033010",    // Visa Interlink
            "A0000000038010"     // Visa Plus
        )
        
        private val MASTERCARD_AIDS = listOf(
            "A0000000041010",    // Mastercard
            "A0000000042203",    // Mastercard Specific
            "A0000000043060",    // Mastercard Maestro
            "A00000000410101213", // Mastercard PayPass
            "A00000000410101215"  // Mastercard PayPass Mag Stripe
        )
        
        private val AMEX_AIDS = listOf(
            "A000000025010701",  // American Express
            "A000000025010801"   // American Express
        )
        
        private val JCB_AIDS = listOf(
            "A0000000651010",    // JCB
            "A0000000651011"     // JCB J Smart
        )
        
        private val DINERS_AIDS = listOf(
            "A0000001523010"     // Diners Club
        )
        
        private val DISCOVER_AIDS = listOf(
            "A0000001524010"     // Discover
        )
        
        // Currency code mappings (ISO 4217)
        private val CURRENCY_MAP = mapOf(
            "840" to CurrencyInfo("USD", "840", "US Dollar", "$"),
            "978" to CurrencyInfo("EUR", "978", "Euro", "€"),
            "826" to CurrencyInfo("GBP", "826", "British Pound", "£"),
            "392" to CurrencyInfo("JPY", "392", "Japanese Yen", "¥"),
            "756" to CurrencyInfo("CHF", "756", "Swiss Franc", "CHF"),
            "124" to CurrencyInfo("CAD", "124", "Canadian Dollar", "C$"),
            "036" to CurrencyInfo("AUD", "036", "Australian Dollar", "A$"),
            "156" to CurrencyInfo("CNY", "156", "Chinese Yuan", "¥"),
            "344" to CurrencyInfo("HKD", "344", "Hong Kong Dollar", "HK$"),
            "702" to CurrencyInfo("SGD", "702", "Singapore Dollar", "S$")
        )
        
        // Country code mappings (ISO 3166)
        private val COUNTRY_MAP = mapOf(
            "840" to CountryInfo("US", "840", "United States"),
            "276" to CountryInfo("DE", "276", "Germany"),
            "826" to CountryInfo("GB", "826", "United Kingdom"),
            "250" to CountryInfo("FR", "250", "France"),
            "392" to CountryInfo("JP", "392", "Japan"),
            "756" to CountryInfo("CH", "756", "Switzerland"),
            "124" to CountryInfo("CA", "124", "Canada"),
            "036" to CountryInfo("AU", "036", "Australia"),
            "156" to CountryInfo("CN", "156", "China"),
            "344" to CountryInfo("HK", "344", "Hong Kong")
        )
    }
    
    /**
     * Detect card vendor from AID
     */
    fun detectCardVendor(aid: String): CardVendor {
        val aidUpper = aid.uppercase()
        
        return when {
            VISA_AIDS.any { aidUpper.startsWith(it) } -> CardVendor.VISA
            MASTERCARD_AIDS.any { aidUpper.startsWith(it) } -> CardVendor.MASTERCARD
            AMEX_AIDS.any { aidUpper.startsWith(it) } -> CardVendor.AMERICAN_EXPRESS
            JCB_AIDS.any { aidUpper.startsWith(it) } -> CardVendor.JCB
            DINERS_AIDS.any { aidUpper.startsWith(it) } -> CardVendor.DINERS
            DISCOVER_AIDS.any { aidUpper.startsWith(it) } -> CardVendor.DISCOVER
            else -> {
                Timber.d("Unknown AID vendor: $aid")
                CardVendor.UNKNOWN
            }
        }
    }
    
    /**
     * Get card vendor from AID byte array
     */
    fun getCardVendorFromAid(aid: ByteArray): CardVendor {
        val aidString = aid.joinToString("") { "%02X".format(it) }
        return detectCardVendor(aidString)
    }
    
    /**
     * Identify card type from ATR or card capabilities
     */
    fun identifyCardType(atr: ByteArray): CardType {
        // Analyze ATR to determine interface capabilities
        if (atr.isEmpty()) return CardType.UNKNOWN
        
        // Basic ATR analysis - this is simplified
        // Real implementation would parse ATR structure
        return when {
            atr.size > 4 && atr[1] == 0x80.toByte() -> CardType.CONTACTLESS
            atr.size > 2 -> CardType.CONTACT
            else -> CardType.UNKNOWN
        }
    }
    
    /**
     * Get supported applications from card info
     */
    fun getSupportedApplications(cardInfo: CardInfo): List<EmvApplication> {
        val applications = mutableListOf<EmvApplication>()
        
        // Extract applications from FCI template or directory
        cardInfo.fciTemplate?.let { fci ->
            // Parse Application Directory if present
            // This is a simplified version - real implementation would parse full directory
            applications.add(
                EmvApplication(
                    aid = cardInfo.aid ?: byteArrayOf(),
                    label = cardInfo.label ?: "Unknown Application",
                    preferredName = cardInfo.preferredName,
                    priority = 1,
                    languagePreference = null,
                    issuerCodeTableIndex = null,
                    applicationSelectionIndicator = false
                )
            )
        }
        
        return applications
    }
    
    /**
     * Analyze card capabilities from TLV data
     */
    fun analyzeCardCapabilities(tlvData: TlvDatabase): CardCapabilities {
        val capabilities = mutableSetOf<EmvFeature>()
        
        // Check for authentication methods
        tlvData.getValue(EmvTag.CARD_RISK_MANAGEMENT_DATA_OBJECT_LIST_1)?.let {
            capabilities.add(EmvFeature.SDA)
        }
        
        tlvData.getValue(EmvTag.CARD_RISK_MANAGEMENT_DATA_OBJECT_LIST_2)?.let {
            capabilities.add(EmvFeature.DDA)
        }
        
        tlvData.getValue(EmvTag.SIGNED_DYNAMIC_APPLICATION_DATA)?.let {
            capabilities.add(EmvFeature.CDA)
        }
        
        // Check for contactless support
        tlvData.getValue(EmvTag.KERNEL_IDENTIFIER)?.let {
            capabilities.add(EmvFeature.CONTACTLESS)
        }
        
        return CardCapabilities(
            supportedFeatures = capabilities,
            maxTransactionAmount = extractMaxTransactionAmount(tlvData),
            contactlessTransactionLimit = extractContactlessLimit(tlvData),
            cvmMethods = extractCvmMethods(tlvData),
            applicationCurrencyCode = tlvData.getValue(EmvTag.APPLICATION_CURRENCY_CODE),
            applicationCountryCode = tlvData.getValue(EmvTag.ISSUER_COUNTRY_CODE)
        )
    }
    
    /**
     * Extract PAN from Track 2 data
     */
    fun getPanFromTrack2(track2: ByteArray): String? {
        try {
            val track2Hex = track2.joinToString("") { "%02X".format(it) }
            val separatorIndex = track2Hex.indexOf('D')
            
            if (separatorIndex == -1) return null
            
            val pan = track2Hex.substring(0, separatorIndex)
            return if (pan.length in 13..19 && pan.all { it.isDigit() }) pan else null
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to extract PAN from Track 2")
            return null
        }
    }
    
    /**
     * Extract expiry date from Track 2 data
     */
    fun getExpiryFromTrack2(track2: ByteArray): String? {
        try {
            val track2Hex = track2.joinToString("") { "%02X".format(it) }
            val separatorIndex = track2Hex.indexOf('D')
            
            if (separatorIndex == -1 || track2Hex.length < separatorIndex + 5) return null
            
            val expiry = track2Hex.substring(separatorIndex + 1, separatorIndex + 5)
            return if (expiry.length == 4 && expiry.all { it.isDigit() }) expiry else null
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to extract expiry from Track 2")
            return null
        }
    }
    
    /**
     * Extract dCVV from Track 2 data
     */
    fun getDcvvFromTrack2(track2: ByteArray): ByteArray? {
        try {
            val track2Hex = track2.joinToString("") { "%02X".format(it) }
            val separatorIndex = track2Hex.indexOf('D')
            
            if (separatorIndex == -1 || track2Hex.length < separatorIndex + 9) return null
            
            // dCVV is typically in positions after expiry date
            val dcvvHex = track2Hex.substring(separatorIndex + 5, separatorIndex + 9)
            return dcvvHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to extract dCVV from Track 2")
            return null
        }
    }
    
    /**
     * Get currency name from code
     */
    fun getCurrencyName(currencyCode: String): String {
        return CURRENCY_MAP[currencyCode]?.displayName ?: "Unknown Currency"
    }
    
    /**
     * Get currency symbol from code
     */
    fun getCurrencySymbol(currencyCode: String): String {
        return CURRENCY_MAP[currencyCode]?.symbol ?: currencyCode
    }
    
    /**
     * Get country name from code
     */
    fun getCountryName(countryCode: String): String {
        return COUNTRY_MAP[countryCode]?.displayName ?: "Unknown Country"
    }
    
    /**
     * Validate EMV compliance of card data
     */
    fun validateEmvCompliance(tlvData: TlvDatabase): EmvComplianceResult {
        val errors = mutableListOf<String>()
        val warnings = mutableListOf<String>()
        
        // Check mandatory tags
        val mandatoryTags = listOf(
            EmvTag.DEDICATED_FILE_NAME,
            EmvTag.APPLICATION_INTERCHANGE_PROFILE,
            EmvTag.APPLICATION_VERSION_NUMBER
        )
        
        mandatoryTags.forEach { tag ->
            if (!tlvData.hasTag(tag)) {
                errors.add("Missing mandatory tag: ${getEmvTagName(tag.value)}")
            }
        }
        
        // Check data format compliance
        tlvData.getValue(EmvTag.APPLICATION_PRIMARY_ACCOUNT_NUMBER)?.let { pan ->
            if (pan.size < 8 || pan.size > 10) {
                warnings.add("PAN length outside typical range")
            }
        }
        
        return EmvComplianceResult(
            isCompliant = errors.isEmpty(),
            errors = errors,
            warnings = warnings,
            checkedTags = mandatoryTags.size,
            complianceLevel = if (errors.isEmpty()) {
                if (warnings.isEmpty()) ComplianceLevel.FULL else ComplianceLevel.PARTIAL
            } else {
                ComplianceLevel.NON_COMPLIANT
            }
        )
    }
    
    /**
     * Check mandatory EMV tags
     */
    fun checkMandatoryTags(tlvData: TlvDatabase): List<EmvTag> {
        val mandatoryTags = listOf(
            EmvTag.DEDICATED_FILE_NAME,
            EmvTag.APPLICATION_INTERCHANGE_PROFILE,
            EmvTag.APPLICATION_VERSION_NUMBER,
            EmvTag.CERTIFICATION_AUTHORITY_PUBLIC_KEY_INDEX,
            EmvTag.ISSUER_PUBLIC_KEY_CERTIFICATE
        )
        
        return mandatoryTags.filter { !tlvData.hasTag(it) }
    }
    
    /**
     * Get EMV tag name for display
     */
    fun getEmvTagName(tag: Int): String {
        return EmvTagRegistry.getTagName(tag) ?: "Unknown Tag (${String.format("0x%X", tag)})"
    }
    
    /**
     * Calculate SHA-1 hash
     */
    fun calculateSha1Hash(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-1").digest(data)
    }
    
    /**
     * Calculate SHA-256 hash
     */
    fun calculateSha256Hash(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }
    
    /**
     * Convert hex string to byte array
     */
    fun hexToByteArray(hex: String): ByteArray {
        val cleanHex = hex.replace(" ", "").replace("-", "")
        return cleanHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
    
    /**
     * Convert byte array to hex string
     */
    fun byteArrayToHex(bytes: ByteArray, separator: String = ""): String {
        return bytes.joinToString(separator) { "%02X".format(it) }
    }
    
    /**
     * Parse BCD (Binary Coded Decimal) to string
     */
    fun parseBcd(bcd: ByteArray): String {
        return bcd.joinToString("") { byte ->
            val high = (byte.toInt() and 0xF0) shr 4
            val low = byte.toInt() and 0x0F
            "$high$low"
        }
    }
    
    /**
     * Encode string to BCD
     */
    fun encodeToBcd(input: String): ByteArray {
        val paddedInput = if (input.length % 2 == 1) "${input}F" else input
        return paddedInput.chunked(2).map { pair ->
            val high = pair[0].digitToInt()
            val low = pair[1].digitToIntOrNull() ?: 15 // F for padding
            ((high shl 4) or low).toByte()
        }.toByteArray()
    }
    
    /**
     * Validate card number using Luhn algorithm
     */
    fun validateCardNumber(cardNumber: String): Boolean {
        if (cardNumber.length < 13 || cardNumber.length > 19) return false
        if (!cardNumber.all { it.isDigit() }) return false
        
        var sum = 0
        var alternate = false
        
        for (i in cardNumber.length - 1 downTo 0) {
            var digit = cardNumber[i].digitToInt()
            
            if (alternate) {
                digit *= 2
                if (digit > 9) digit = digit / 10 + digit % 10
            }
            
            sum += digit
            alternate = !alternate
        }
        
        return sum % 10 == 0
    }
    
    // Private helper functions
    
    private fun extractMaxTransactionAmount(tlvData: TlvDatabase): Long? {
        return tlvData.getValue(EmvTag.TERMINAL_FLOOR_LIMIT)?.let { bytes ->
            if (bytes.size == 4) {
                ByteBuffer.wrap(bytes).int.toLong()
            } else null
        }
    }
    
    private fun extractContactlessLimit(tlvData: TlvDatabase): Long? {
        return tlvData.getValue(EmvTag.READER_CONTACTLESS_FLOOR_LIMIT)?.let { bytes ->
            if (bytes.size <= 6) {
                var amount = 0L
                for (byte in bytes) {
                    amount = (amount shl 8) or (byte.toLong() and 0xFF)
                }
                amount
            } else null
        }
    }
    
    private fun extractCvmMethods(tlvData: TlvDatabase): List<CvmMethod> {
        return tlvData.getValue(EmvTag.CARDHOLDER_VERIFICATION_METHOD_LIST)?.let { bytes ->
            parseCvmList(bytes)
        } ?: emptyList()
    }
    
    private fun parseCvmList(cvmListData: ByteArray): List<CvmMethod> {
        val methods = mutableListOf<CvmMethod>()
        
        if (cvmListData.size < 10) return methods // Minimum CVM list size
        
        // Skip X and Y amounts (first 8 bytes) and parse methods
        var offset = 8
        while (offset + 1 < cvmListData.size) {
            val method = cvmListData[offset]
            val condition = cvmListData[offset + 1]
            
            methods.add(CvmMethod(method, condition))
            offset += 2
        }
        
        return methods
    }
}

/**
 * Card capabilities data class
 */
data class CardCapabilities(
    val supportedFeatures: Set<EmvFeature>,
    val maxTransactionAmount: Long?,
    val contactlessTransactionLimit: Long?,
    val cvmMethods: List<CvmMethod>,
    val applicationCurrencyCode: ByteArray?,
    val applicationCountryCode: ByteArray?
)

/**
 * CVM Method data class
 */
data class CvmMethod(
    val method: Byte,
    val condition: Byte
)

/**
 * EMV Compliance result
 */
data class EmvComplianceResult(
    val isCompliant: Boolean,
    val errors: List<String>,
    val warnings: List<String>,
    val checkedTags: Int,
    val complianceLevel: ComplianceLevel
)

/**
 * Compliance levels
 */
enum class ComplianceLevel {
    FULL,
    PARTIAL,
    NON_COMPLIANT
}