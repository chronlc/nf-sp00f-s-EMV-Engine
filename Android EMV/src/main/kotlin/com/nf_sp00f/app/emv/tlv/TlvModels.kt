/**
 * nf-sp00f EMV Engine - TLV Data Models
 * 
 * Core TLV (Tag-Length-Value) data structures for EMV processing.
 * Ported from Proxmark3 EMV Engine with Kotlin optimization.
 * 
 * @package com.nf_sp00f.app.emv.tlv
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv.tlv

/**
 * TLV Tag representation
 * Handles both single-byte and multi-byte EMV tags
 */
@JvmInline
value class TlvTag(val value: UInt) {
    
    companion object {
        const val INVALID_TAG = 0x00u
        
        // Common EMV tags
        const val APPLICATION_IDENTIFIER = 0x4F_u
        const val APPLICATION_LABEL = 0x50_u
        const val TRACK_2_EQUIVALENT_DATA = 0x57_u
        const val APPLICATION_PAN = 0x5A_u
        const val CARDHOLDER_NAME = 0x5F20_u
        const val APPLICATION_EXPIRATION_DATE = 0x5F24_u
        const val APPLICATION_EFFECTIVE_DATE = 0x5F25_u
        const val ISSUER_COUNTRY_CODE = 0x5F28_u
        const val TRANSACTION_CURRENCY_CODE = 0x5F2A_u
        const val LANGUAGE_PREFERENCE = 0x5F2D_u
        const val SERVICE_CODE = 0x5F30_u
        const val APPLICATION_PRIMARY_ACCOUNT_NUMBER_SEQUENCE_NUMBER = 0x5F34_u
        const val TRANSACTION_CURRENCY_EXPONENT = 0x5F36_u
        const val IBAN = 0x5F53_u
        const val BANK_IDENTIFIER_CODE = 0x5F54_u
        const val APPLICATION_TEMPLATE = 0x61_u
        const val FCI_TEMPLATE = 0x6F_u
        const val READ_RECORD_RESPONSE_MESSAGE_TEMPLATE = 0x70_u
        const val RESPONSE_MESSAGE_TEMPLATE_2 = 0x77_u
        const val RESPONSE_MESSAGE_TEMPLATE_1 = 0x80_u
        const val AMOUNT_AUTHORIZED_BINARY = 0x81_u
        const val APPLICATION_INTERCHANGE_PROFILE = 0x82_u
        const val COMMAND_TEMPLATE = 0x83_u
        const val DEDICATED_FILE_NAME = 0x84_u
        const val ISSUER_SCRIPT_COMMAND = 0x86_u
        const val APPLICATION_PRIORITY_INDICATOR = 0x87_u
        const val SHORT_FILE_IDENTIFIER = 0x88_u
        const val AUTHORIZATION_CODE = 0x89_u
        const val AUTHORIZATION_RESPONSE_CODE = 0x8A_u
        const val CARD_RISK_MANAGEMENT_DATA_OBJECT_LIST_1 = 0x8C_u
        const val CARD_RISK_MANAGEMENT_DATA_OBJECT_LIST_2 = 0x8D_u
        const val CARDHOLDER_VERIFICATION_METHOD_LIST = 0x8E_u
        const val CERTIFICATION_AUTHORITY_PUBLIC_KEY_INDEX = 0x8F_u
        const val ISSUER_PUBLIC_KEY_CERTIFICATE = 0x90_u
        const val ISSUER_AUTHENTICATION_DATA = 0x91_u
        const val ISSUER_PUBLIC_KEY_REMAINDER = 0x92_u
        const val SIGNED_STATIC_APPLICATION_DATA = 0x93_u
        const val APPLICATION_FILE_LOCATOR = 0x94_u
        const val TERMINAL_VERIFICATION_RESULTS = 0x95_u
        const val TRANSACTION_CERTIFICATE_DATA_OBJECT_LIST = 0x97_u
        const val TRANSACTION_CERTIFICATE_HASH_VALUE = 0x98_u
                const val TRANSACTION_PERSONAL_IDENTIFICATION_NUMBER_DATA = 0x99_u\n        const val TRANSACTION_DATE = 0x9A_u\n        const val TRANSACTION_STATUS_INFORMATION = 0x9B_u\n        const val TRANSACTION_TYPE = 0x9C_u\n        const val DIRECTORY_DEFINITION_FILE_NAME = 0x9D_u\n        \n        // Additional EMV tags for authentication\n        const val APPLICATION_USAGE_CONTROL = 0x9F07_u\n        const val APPLICATION_VERSION_NUMBER = 0x9F08_u\n        const val ISSUER_ACTION_CODE_DEFAULT = 0x9F0D_u\n        const val ISSUER_ACTION_CODE_DENIAL = 0x9F0E_u\n        const val ISSUER_ACTION_CODE_ONLINE = 0x9F0F_u\n        const val ICC_PUBLIC_KEY_CERTIFICATE = 0x9F46_u\n        const val ICC_PUBLIC_KEY_EXPONENT = 0x9F47_u\n        const val ICC_PUBLIC_KEY_REMAINDER = 0x9F48_u\n        const val DYNAMIC_DATA_AUTHENTICATION_DATA_OBJECT_LIST = 0x9F49_u\n        const val STATIC_DATA_AUTHENTICATION_TAG_LIST = 0x9F4A_u"
        
        fun fromBytes(data: ByteArray, offset: Int = 0): Pair<TlvTag, Int> {
            if (offset >= data.size) return TlvTag(INVALID_TAG) to 0
            
            val firstByte = data[offset].toUByte()
            
            // Single byte tag (bits 1-5 not all set)
            if ((firstByte and 0x1Fu) != 0x1Fu) {
                return TlvTag(firstByte.toUInt()) to 1
            }
            
            // Multi-byte tag
            var tagValue = firstByte.toUInt()
            var bytesConsumed = 1
            
            while (offset + bytesConsumed < data.size) {
                val nextByte = data[offset + bytesConsumed].toUByte()
                tagValue = (tagValue shl 8) or nextByte.toUInt()
                bytesConsumed++
                
                // Check if more bytes follow (bit 8 clear)
                if ((nextByte and 0x80u) == 0u) break
            }
            
            return TlvTag(tagValue) to bytesConsumed
        }
    }
    
    /**
     * Check if this is a constructed tag (can contain other TLV elements)
     */
    fun isConstructed(): Boolean {
        val firstByte = (value shr ((tagLength() - 1) * 8)) and 0xFFu
        return (firstByte and 0x20u) != 0u
    }
    
    /**
     * Get the length of this tag in bytes
     */
    fun tagLength(): Int {
        return when {
            value <= 0xFFu -> 1
            value <= 0xFFFFu -> 2
            value <= 0xFFFFFFu -> 3
            else -> 4
        }
    }
    
    /**
     * Convert tag to byte array
     */
    fun toByteArray(): ByteArray {
        val length = tagLength()
        val result = ByteArray(length)
        
        for (i in 0 until length) {
            result[length - 1 - i] = ((value shr (i * 8)) and 0xFFu).toByte()
        }
        
        return result
    }
    
    override fun toString(): String = "0x${value.toString(16).uppercase().padStart(tagLength() * 2, '0')}"
}

/**
 * TLV Length representation
 * Handles both short form (<=127 bytes) and long form (>127 bytes) encoding
 */
@JvmInline
value class TlvLength(val value: UInt) {
    
    companion object {
        const val MAX_SHORT_FORM = 0x7Fu
        
        fun fromBytes(data: ByteArray, offset: Int = 0): Pair<TlvLength, Int> {
            if (offset >= data.size) return TlvLength(0u) to 0
            
            val firstByte = data[offset].toUByte()
            
            // Short form: 0xxxxxxx
            if ((firstByte and 0x80u) == 0u) {
                return TlvLength(firstByte.toUInt()) to 1
            }
            
            // Long form: 1xxxxxxx indicates number of subsequent length bytes
            val lengthBytes = (firstByte and 0x7Fu).toInt()
            if (lengthBytes == 0 || offset + lengthBytes >= data.size) {
                return TlvLength(0u) to 0 // Invalid length encoding
            }
            
            var length = 0u
            for (i in 1..lengthBytes) {
                length = (length shl 8) or data[offset + i].toUByte().toUInt()
            }
            
            return TlvLength(length) to (1 + lengthBytes)
        }
    }
    
    /**
     * Get the number of bytes needed to encode this length
     */
    fun encodedLength(): Int {
        return when {
            value <= MAX_SHORT_FORM -> 1
            value <= 0xFFu -> 2
            value <= 0xFFFFu -> 3
            value <= 0xFFFFFFu -> 4
            else -> 5
        }
    }
    
    /**
     * Convert length to byte array
     */
    fun toByteArray(): ByteArray {
        if (value <= MAX_SHORT_FORM) {
            return byteArrayOf(value.toByte())
        }
        
        // Long form encoding
        val valueBytes = when {
            value <= 0xFFu -> 1
            value <= 0xFFFFu -> 2
            value <= 0xFFFFFFu -> 3
            else -> 4
        }
        
        val result = ByteArray(1 + valueBytes)
        result[0] = (0x80u or valueBytes.toUInt()).toByte()
        
        for (i in 0 until valueBytes) {
            result[1 + valueBytes - 1 - i] = ((value shr (i * 8)) and 0xFFu).toByte()
        }
        
        return result
    }
}

/**
 * Core TLV element containing tag, length, and value
 */
data class TlvElement(
    val tag: TlvTag,
    val length: TlvLength,
    val value: ByteArray
) {
    
    init {
        require(value.size.toUInt() == length.value) { 
            "Value size (${value.size}) must match length (${length.value})" 
        }
    }
    
    /**
     * Check if this TLV element is constructed (can contain child elements)
     */
    fun isConstructed(): Boolean = tag.isConstructed()
    
    /**
     * Get total encoded size (tag + length + value)
     */
    fun encodedSize(): Int = tag.tagLength() + length.encodedLength() + value.size
    
    /**
     * Convert TLV element to byte array
     */
    fun toByteArray(): ByteArray {
        val tagBytes = tag.toByteArray()
        val lengthBytes = length.toByteArray()
        
        return tagBytes + lengthBytes + value
    }
    
    /**
     * Get value as string (assuming ASCII/UTF-8 encoding)
     */
    fun valueAsString(): String = value.decodeToString()
    
    /**
     * Get value as hex string
     */
    fun valueAsHex(): String = value.joinToString("") { "%02X".format(it) }
    
    /**
     * Get value as unsigned integer (up to 4 bytes)
     */
    fun valueAsUInt(): UInt {
        require(value.size <= 4) { "Value too large for UInt conversion" }
        
        var result = 0u
        for (byte in value) {
            result = (result shl 8) or byte.toUByte().toUInt()
        }
        return result
    }
    
    /**
     * Get value as unsigned byte
     */
    fun valueAsUByte(): UByte {
        require(value.size == 1) { "Value must be exactly 1 byte" }
        return value[0].toUByte()
    }
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TlvElement) return false
        
        return tag == other.tag && 
               length == other.length && 
               value.contentEquals(other.value)
    }
    
    override fun hashCode(): Int {
        var result = tag.hashCode()
        result = 31 * result + length.hashCode()
        result = 31 * result + value.contentHashCode()
        return result
    }
    
    override fun toString(): String {
        return "TLV(${tag}, len=${length.value}, value=${valueAsHex()})"
    }
}

/**
 * TLV Database for managing collections of TLV elements
 */
class TlvDatabase {
    private val elements = mutableMapOf<TlvTag, TlvElement>()
    private val children = mutableMapOf<TlvTag, TlvDatabase>()
    
    /**
     * Add a TLV element to the database
     */
    fun addElement(element: TlvElement) {
        elements[element.tag] = element
        
        // If constructed, parse children
        if (element.isConstructed()) {
            children[element.tag] = parseChildren(element.value)
        }
    }
    
    /**
     * Find TLV element by tag
     */
    fun findElement(tag: TlvTag): TlvElement? = elements[tag]
    
    /**
     * Find TLV element by tag path (for nested structures)
     */
    fun findElementByPath(tagPath: List<TlvTag>): TlvElement? {
        if (tagPath.isEmpty()) return null
        if (tagPath.size == 1) return findElement(tagPath[0])
        
        val firstTag = tagPath[0]
        val childDb = children[firstTag] ?: return null
        
        return childDb.findElementByPath(tagPath.drop(1))
    }
    
    /**
     * Get all elements with a specific tag (including children)
     */
    fun findAllElements(tag: TlvTag): List<TlvElement> {
        val result = mutableListOf<TlvElement>()
        
        elements[tag]?.let { result.add(it) }
        
        // Search in children
        children.values.forEach { childDb ->
            result.addAll(childDb.findAllElements(tag))
        }
        
        return result
    }
    
    /**
     * Check if database contains a specific tag
     */
    fun contains(tag: TlvTag): Boolean = elements.containsKey(tag)
    
    /**
     * Get all top-level elements
     */
    fun getAllElements(): Map<TlvTag, TlvElement> = elements.toMap()
    
    /**
     * Get child database for a constructed element
     */
    fun getChildDatabase(tag: TlvTag): TlvDatabase? = children[tag]
    
    /**
     * Remove element by tag
     */
    fun removeElement(tag: TlvTag): TlvElement? {
        children.remove(tag)
        return elements.remove(tag)
    }
    
    /**
     * Clear all elements
     */
    fun clear() {
        elements.clear()
        children.clear()
    }
    
    /**
     * Get total number of elements (including children)
     */
    fun size(): Int {
        return elements.size + children.values.sumOf { it.size() }
    }
    
    /**
     * Check if database is empty
     */
    fun isEmpty(): Boolean = elements.isEmpty() && children.isEmpty()
    
    private fun parseChildren(data: ByteArray): TlvDatabase {
        // This will be implemented in TlvParser
        return TlvDatabase()
    }
    
    override fun toString(): String {
        return "TlvDatabase(elements=${elements.size}, children=${children.size})"
    }
}

/**
 * Result wrapper for TLV parsing operations
 */
sealed class TlvResult<out T> {
    data class Success<T>(val value: T) : TlvResult<T>()
    data class Error(val message: String, val offset: Int = -1) : TlvResult<Nothing>()
    
    inline fun <R> map(transform: (T) -> R): TlvResult<R> {
        return when (this) {
            is Success -> Success(transform(value))
            is Error -> this
        }
    }
    
    inline fun onSuccess(action: (T) -> Unit): TlvResult<T> {
        if (this is Success) action(value)
        return this
    }
    
    inline fun onError(action: (String, Int) -> Unit): TlvResult<T> {
        if (this is Error) action(message, offset)
        return this
    }
}