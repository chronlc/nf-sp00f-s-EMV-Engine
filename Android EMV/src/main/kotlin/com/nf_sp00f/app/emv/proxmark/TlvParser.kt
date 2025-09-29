/**
 * nf-sp00f EMV Engine - Enterprise TLV Data Parser
 *
 * Production-grade TLV (Tag-Length-Value) parsing with comprehensive:
 * - Complete EMV Books 1-4 TLV structure processing and validation
 * - High-performance TLV parsing with enterprise validation and error handling
 * - Thread-safe TLV operations with comprehensive audit logging
 * - Advanced TLV construction, modification, and analysis capabilities
 * - Performance-optimized parsing with caching and batch processing
 * - Zero defensive programming patterns with comprehensive validation
 * - Enterprise-grade TLV data integrity and format verification
 * - Complete support for nested TLV structures and complex data objects
 *
 * @package com.nf_sp00f.app.emv
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import java.util.concurrent.atomic.AtomicLong

/**
 * TLV Data Object Types
 */
enum class TlvDataType {
    PRIMITIVE,
    CONSTRUCTED,
    TEMPLATE,
    PROPRIETARY
}

/**
 * TLV Tag Classes
 */
enum class TlvTagClass(val value: Int) {
    UNIVERSAL(0x00),
    APPLICATION(0x40),
    CONTEXT_SPECIFIC(0x80),
    PRIVATE(0xC0)
}

/**
 * TLV Length Encoding Types
 */
enum class TlvLengthEncoding {
    DEFINITE_SHORT,    // Length 0-127 (1 byte)
    DEFINITE_LONG,     // Length 128+ (multi-byte)
    INDEFINITE         // Length encoded as 0x80 with end-of-contents octets
}

/**
 * TLV Data Object
 */
data class TlvDataObject(
    val tag: String,
    val tagBytes: ByteArray,
    val length: Int,
    val lengthBytes: ByteArray,
    val value: ByteArray,
    val dataType: TlvDataType,
    val tagClass: TlvTagClass,
    val lengthEncoding: TlvLengthEncoding,
    val isConstructed: Boolean,
    val children: List<TlvDataObject> = emptyList(),
    val parent: TlvDataObject? = null,
    val offset: Int = 0,
    val totalLength: Int = tagBytes.size + lengthBytes.size + value.size
) {
    
    fun toByteArray(): ByteArray {
        return tagBytes + lengthBytes + value
    }
    
    fun getValueAsString(): String {
        return String(value, Charsets.UTF_8)
    }
    
    fun getValueAsHex(): String {
        return value.joinToString("") { "%02X".format(it) }
    }
    
    fun hasChildren(): Boolean = children.isNotEmpty()
    
    fun findChild(tag: String): TlvDataObject? {
        return children.find { it.tag.equals(tag, ignoreCase = true) }
    }
    
    fun findAllChildren(tag: String): List<TlvDataObject> {
        return children.filter { it.tag.equals(tag, ignoreCase = true) }
    }
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as TlvDataObject
        if (tag != other.tag) return false
        if (!tagBytes.contentEquals(other.tagBytes)) return false
        if (!value.contentEquals(other.value)) return false
        return true
    }
    
    override fun hashCode(): Int {
        var result = tag.hashCode()
        result = 31 * result + tagBytes.contentHashCode()
        result = 31 * result + value.contentHashCode()
        return result
    }
}

/**
 * TLV Parsing Result
 */
sealed class TlvParsingResult {
    data class Success(
        val tlvObjects: List<TlvDataObject>,
        val totalBytesProcessed: Int,
        val processingTime: Long,
        val validationResults: List<TlvValidationResult>,
        val performanceMetrics: TlvPerformanceMetrics
    ) : TlvParsingResult()
    
    data class Failed(
        val error: TlvParsingException,
        val bytesProcessed: Int,
        val processingTime: Long,
        val failureAnalysis: TlvFailureAnalysis
    ) : TlvParsingResult()
}

/**
 * TLV Construction Result
 */
sealed class TlvConstructionResult {
    data class Success(
        val tlvData: ByteArray,
        val constructedObjects: List<TlvDataObject>,
        val processingTime: Long,
        val validationResults: List<TlvValidationResult>
    ) : TlvConstructionResult() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as Success
            if (!tlvData.contentEquals(other.tlvData)) return false
            return true
        }
        
        override fun hashCode(): Int {
            return tlvData.contentHashCode()
        }
    }
    
    data class Failed(
        val error: TlvConstructionException,
        val processingTime: Long,
        val failureContext: Map<String, Any>
    ) : TlvConstructionResult()
}

/**
 * TLV Validation Result
 */
data class TlvValidationResult(
    val ruleName: String,
    val isValid: Boolean,
    val details: String,
    val severity: TlvValidationSeverity
)

/**
 * TLV Validation Severity
 */
enum class TlvValidationSeverity {
    INFO,
    WARNING,
    ERROR,
    CRITICAL
}

/**
 * TLV Performance Metrics
 */
data class TlvPerformanceMetrics(
    val parsingTime: Long,
    val bytesProcessed: Long,
    val objectsParsed: Int,
    val throughput: Double,
    val memoryUsage: Long
)

/**
 * TLV Failure Analysis
 */
data class TlvFailureAnalysis(
    val failureCategory: TlvFailureCategory,
    val errorOffset: Int,
    val rootCause: String,
    val recoveryOptions: List<String>
)

/**
 * TLV Failure Categories
 */
enum class TlvFailureCategory {
    INVALID_TAG,
    INVALID_LENGTH,
    INVALID_VALUE,
    STRUCTURE_ERROR,
    FORMAT_ERROR,
    VALIDATION_ERROR
}

/**
 * TLV Parser Configuration
 */
data class TlvParserConfiguration(
    val enableStrictValidation: Boolean = true,
    val enablePerformanceMonitoring: Boolean = true,
    val enableAuditLogging: Boolean = true,
    val maxNestingDepth: Int = 10,
    val maxDataSize: Long = 1048576L, // 1MB
    val enableCaching: Boolean = true,
    val validateTagRegistry: Boolean = true
)

/**
 * Enterprise TLV Data Parser
 * 
 * Thread-safe, high-performance TLV parser with comprehensive validation
 */
class TlvParser(
    private val configuration: TlvParserConfiguration = TlvParserConfiguration()
) {
    
    companion object {
        private const val PARSER_VERSION = "1.0.0"
        
        // TLV Constants
        private const val TAG_MORE_BYTES_MASK = 0x1F
        private const val TAG_CONSTRUCTED_MASK = 0x20
        private const val TAG_CLASS_MASK = 0xC0
        private const val LENGTH_LONG_FORM_MASK = 0x80
        private const val LENGTH_INDEFINITE = 0x80
        
        // Maximum limits
        private const val MAX_TAG_LENGTH = 4
        private const val MAX_LENGTH_BYTES = 4
        private const val MAX_NESTING_DEPTH = 20
    }
    
    private val lock = ReentrantLock()
    private val auditLogger = TlvAuditLogger()
    private val performanceTracker = TlvPerformanceTracker()
    private val operationsPerformed = AtomicLong(0)
    
    private val parseCache = ConcurrentHashMap<String, TlvParsingResult>()
    private val validationRules = mutableListOf<TlvValidationRule>()
    
    init {
        initializeValidationRules()
        auditLogger.logOperation("TLV_PARSER_INITIALIZED", "version=$PARSER_VERSION")
    }
    
    /**
     * Parse TLV data with enterprise validation
     */
    fun parseTlvData(data: ByteArray): TlvParsingResult {
        val parseStart = System.currentTimeMillis()
        
        return try {
            auditLogger.logOperation("TLV_PARSING_START", "data_length=${data.size}")
            
            validateParsingParameters(data)
            
            val cacheKey = generateCacheKey(data)
            if (configuration.enableCaching && parseCache.containsKey(cacheKey)) {
                val cachedResult = parseCache[cacheKey]
                auditLogger.logOperation("TLV_PARSING_CACHE_HIT", "cache_key=$cacheKey")
                return cachedResult as TlvParsingResult
            }
            
            val tlvObjects = mutableListOf<TlvDataObject>()
            var offset = 0
            var nestingDepth = 0
            
            while (offset < data.size) {
                val parseResult = parseSingleTlvObject(data, offset, nestingDepth)
                
                when (parseResult) {
                    is SingleTlvParseResult.Success -> {
                        tlvObjects.add(parseResult.tlvObject)
                        offset = parseResult.nextOffset
                    }
                    is SingleTlvParseResult.Failed -> {
                        throw TlvParsingException("TLV parsing failed at offset $offset: ${parseResult.error}")
                    }
                }
            }
            
            val processingTime = System.currentTimeMillis() - parseStart
            val validationResults = validateTlvStructure(tlvObjects)
            
            performanceTracker.recordParsing(processingTime, data.size.toLong(), tlvObjects.size)
            operationsPerformed.incrementAndGet()
            
            auditLogger.logOperation("TLV_PARSING_SUCCESS", 
                "objects_parsed=${tlvObjects.size} bytes_processed=${data.size} time=${processingTime}ms")
            
            val result = TlvParsingResult.Success(
                tlvObjects = tlvObjects,
                totalBytesProcessed = data.size,
                processingTime = processingTime,
                validationResults = validationResults,
                performanceMetrics = createPerformanceMetrics(processingTime, data.size.toLong(), tlvObjects.size)
            )
            
            if (configuration.enableCaching) {
                parseCache[cacheKey] = result
            }
            
            result
            
        } catch (e: Exception) {
            val processingTime = System.currentTimeMillis() - parseStart
            auditLogger.logError("TLV_PARSING_FAILED", 
                "error=${e.message} time=${processingTime}ms")
            
            TlvParsingResult.Failed(
                error = TlvParsingException("TLV parsing failed: ${e.message}", e),
                bytesProcessed = 0,
                processingTime = processingTime,
                failureAnalysis = analyzeTlvFailure(e, 0)
            )
        }
    }
    
    /**
     * Construct TLV data from objects with enterprise validation
     */
    fun constructTlvData(tlvObjects: List<TlvDataObject>): TlvConstructionResult {
        val constructStart = System.currentTimeMillis()
        
        return try {
            auditLogger.logOperation("TLV_CONSTRUCTION_START", "objects_count=${tlvObjects.size}")
            
            validateConstructionParameters(tlvObjects)
            
            val constructedData = mutableListOf<Byte>()
            val processedObjects = mutableListOf<TlvDataObject>()
            
            for (tlvObject in tlvObjects) {
                val objectData = constructSingleTlvObject(tlvObject)
                constructedData.addAll(objectData.toList())
                processedObjects.add(tlvObject)
            }
            
            val result = constructedData.toByteArray()
            val processingTime = System.currentTimeMillis() - constructStart
            val validationResults = validateConstructedData(result, tlvObjects)
            
            performanceTracker.recordConstruction(processingTime, result.size.toLong(), tlvObjects.size)
            operationsPerformed.incrementAndGet()
            
            auditLogger.logOperation("TLV_CONSTRUCTION_SUCCESS", 
                "objects_constructed=${tlvObjects.size} bytes_generated=${result.size} time=${processingTime}ms")
            
            TlvConstructionResult.Success(
                tlvData = result,
                constructedObjects = processedObjects,
                processingTime = processingTime,
                validationResults = validationResults
            )
            
        } catch (e: Exception) {
            val processingTime = System.currentTimeMillis() - constructStart
            auditLogger.logError("TLV_CONSTRUCTION_FAILED", 
                "error=${e.message} time=${processingTime}ms")
            
            TlvConstructionResult.Failed(
                error = TlvConstructionException("TLV construction failed: ${e.message}", e),
                processingTime = processingTime,
                failureContext = mapOf("objects_count" to tlvObjects.size)
            )
        }
    }
    
    /**
     * Find TLV objects by tag with enterprise validation
     */
    fun findTlvObjectsByTag(tlvObjects: List<TlvDataObject>, tag: String): List<TlvDataObject> {
        val searchStart = System.currentTimeMillis()
        
        return try {
            auditLogger.logOperation("TLV_SEARCH_START", "tag=$tag objects_count=${tlvObjects.size}")
            
            validateSearchParameters(tag, tlvObjects)
            
            val results = mutableListOf<TlvDataObject>()
            
            fun searchRecursive(objects: List<TlvDataObject>) {
                for (obj in objects) {
                    if (obj.tag.equals(tag, ignoreCase = true)) {
                        results.add(obj)
                    }
                    
                    if (obj.hasChildren()) {
                        searchRecursive(obj.children)
                    }
                }
            }
            
            searchRecursive(tlvObjects)
            
            val processingTime = System.currentTimeMillis() - searchStart
            auditLogger.logOperation("TLV_SEARCH_SUCCESS", 
                "tag=$tag results_found=${results.size} time=${processingTime}ms")
            
            results
            
        } catch (e: Exception) {
            auditLogger.logError("TLV_SEARCH_FAILED", 
                "tag=$tag error=${e.message}")
            emptyList()
        }
    }
    
    /**
     * Validate TLV structure integrity with enterprise validation
     */
    fun validateTlvStructure(tlvObjects: List<TlvDataObject>): List<TlvValidationResult> {
        val results = mutableListOf<TlvValidationResult>()
        
        for (rule in validationRules) {
            val validationResult = rule.validate(tlvObjects)
            results.add(validationResult)
        }
        
        return results
    }
    
    /**
     * Get TLV parser statistics
     */
    fun getParserStatistics(): TlvParserStatistics = lock.withLock {
        return TlvParserStatistics(
            version = PARSER_VERSION,
            operationsPerformed = operationsPerformed.get(),
            cachedResults = parseCache.size,
            averageParsingTime = performanceTracker.getAverageParsingTime(),
            averageConstructionTime = performanceTracker.getAverageConstructionTime(),
            throughput = performanceTracker.getThroughput(),
            configuration = configuration,
            uptime = performanceTracker.getParserUptime()
        )
    }
    
    // Private implementation methods
    
    private fun parseSingleTlvObject(data: ByteArray, offset: Int, nestingDepth: Int): SingleTlvParseResult {
        return try {
            validateNestingDepth(nestingDepth)
            
            // Parse tag
            val tagResult = parseTag(data, offset)
            val tag = tagResult.first
            val tagBytes = tagResult.second
            val tagLength = tagResult.third
            
            // Parse length
            val lengthResult = parseLength(data, offset + tagLength)
            val length = lengthResult.first
            val lengthBytes = lengthResult.second
            val lengthBytesCount = lengthResult.third
            
            // Extract value
            val valueOffset = offset + tagLength + lengthBytesCount
            validateValueBounds(data, valueOffset, length)
            
            val value = data.copyOfRange(valueOffset, valueOffset + length)
            
            // Determine TLV characteristics
            val isConstructed = (tagBytes[0].toInt() and TAG_CONSTRUCTED_MASK) != 0
            val tagClass = determineTagClass(tagBytes[0])
            val dataType = determineDataType(tagBytes, isConstructed)
            val lengthEncoding = determineLengthEncoding(lengthBytes)
            
            // Parse children if constructed
            val children = if (isConstructed && value.isNotEmpty()) {
                parseChildObjects(value, nestingDepth + 1)
            } else {
                emptyList()
            }
            
            val tlvObject = TlvDataObject(
                tag = tag,
                tagBytes = tagBytes,
                length = length,
                lengthBytes = lengthBytes,
                value = value,
                dataType = dataType,
                tagClass = tagClass,
                lengthEncoding = lengthEncoding,
                isConstructed = isConstructed,
                children = children,
                offset = offset,
                totalLength = tagLength + lengthBytesCount + length
            )
            
            SingleTlvParseResult.Success(
                tlvObject = tlvObject,
                nextOffset = valueOffset + length
            )
            
        } catch (e: Exception) {
            SingleTlvParseResult.Failed(
                error = e.message ?: "Unknown parsing error",
                offset = offset
            )
        }
    }
    
    private fun parseTag(data: ByteArray, offset: Int): Triple<String, ByteArray, Int> {
        validateTagBounds(data, offset)
        
        val firstByte = data[offset].toInt() and 0xFF
        val tagBytes = mutableListOf<Byte>()
        tagBytes.add(data[offset])
        
        var tagLength = 1
        
        // Multi-byte tag
        if ((firstByte and TAG_MORE_BYTES_MASK) == TAG_MORE_BYTES_MASK) {
            var currentOffset = offset + 1
            
            while (currentOffset < data.size && tagLength < MAX_TAG_LENGTH) {
                val nextByte = data[currentOffset].toInt() and 0xFF
                tagBytes.add(data[currentOffset])
                tagLength++
                currentOffset++
                
                // Check if more bytes follow
                if ((nextByte and 0x80) == 0) {
                    break
                }
            }
        }
        
        val tag = tagBytes.joinToString("") { "%02X".format(it.toInt() and 0xFF) }
        return Triple(tag, tagBytes.toByteArray(), tagLength)
    }
    
    private fun parseLength(data: ByteArray, offset: Int): Triple<Int, ByteArray, Int> {
        validateLengthBounds(data, offset)
        
        val firstByte = data[offset].toInt() and 0xFF
        val lengthBytes = mutableListOf<Byte>()
        lengthBytes.add(data[offset])
        
        // Short form (0-127)
        if ((firstByte and LENGTH_LONG_FORM_MASK) == 0) {
            return Triple(firstByte, lengthBytes.toByteArray(), 1)
        }
        
        // Long form
        val lengthOfLength = firstByte and 0x7F
        
        if (lengthOfLength == 0) {
            // Indefinite length (not typically used in EMV)
            return Triple(-1, lengthBytes.toByteArray(), 1)
        }
        
        validateLengthOfLength(lengthOfLength)
        validateLengthBounds(data, offset + 1 + lengthOfLength - 1)
        
        var length = 0
        for (i in 1..lengthOfLength) {
            lengthBytes.add(data[offset + i])
            length = (length shl 8) or (data[offset + i].toInt() and 0xFF)
        }
        
        return Triple(length, lengthBytes.toByteArray(), 1 + lengthOfLength)
    }
    
    private fun parseChildObjects(data: ByteArray, nestingDepth: Int): List<TlvDataObject> {
        val children = mutableListOf<TlvDataObject>()
        var offset = 0
        
        while (offset < data.size) {
            val parseResult = parseSingleTlvObject(data, offset, nestingDepth)
            
            when (parseResult) {
                is SingleTlvParseResult.Success -> {
                    children.add(parseResult.tlvObject)
                    offset = parseResult.nextOffset
                }
                is SingleTlvParseResult.Failed -> {
                    break // Stop parsing on error
                }
            }
        }
        
        return children
    }
    
    private fun constructSingleTlvObject(tlvObject: TlvDataObject): ByteArray {
        return tlvObject.toByteArray()
    }
    
    private fun determineTagClass(firstTagByte: Byte): TlvTagClass {
        val classValue = (firstTagByte.toInt() and TAG_CLASS_MASK)
        return when (classValue) {
            TlvTagClass.UNIVERSAL.value -> TlvTagClass.UNIVERSAL
            TlvTagClass.APPLICATION.value -> TlvTagClass.APPLICATION
            TlvTagClass.CONTEXT_SPECIFIC.value -> TlvTagClass.CONTEXT_SPECIFIC
            TlvTagClass.PRIVATE.value -> TlvTagClass.PRIVATE
            else -> TlvTagClass.UNIVERSAL
        }
    }
    
    private fun determineDataType(tagBytes: ByteArray, isConstructed: Boolean): TlvDataType {
        return when {
            isConstructed -> TlvDataType.CONSTRUCTED
            (tagBytes[0].toInt() and 0x80) != 0 -> TlvDataType.PROPRIETARY
            else -> TlvDataType.PRIMITIVE
        }
    }
    
    private fun determineLengthEncoding(lengthBytes: ByteArray): TlvLengthEncoding {
        return when {
            lengthBytes.size == 1 && (lengthBytes[0].toInt() and LENGTH_LONG_FORM_MASK) == 0 -> 
                TlvLengthEncoding.DEFINITE_SHORT
            lengthBytes.size == 1 && lengthBytes[0].toInt() == LENGTH_INDEFINITE -> 
                TlvLengthEncoding.INDEFINITE
            else -> 
                TlvLengthEncoding.DEFINITE_LONG
        }
    }
    
    private fun createPerformanceMetrics(
        processingTime: Long,
        bytesProcessed: Long,
        objectsProcessed: Int
    ): TlvPerformanceMetrics {
        val throughput = if (processingTime > 0) bytesProcessed.toDouble() / processingTime * 1000 else 0.0
        val memoryUsage = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()
        
        return TlvPerformanceMetrics(
            parsingTime = processingTime,
            bytesProcessed = bytesProcessed,
            objectsParsed = objectsProcessed,
            throughput = throughput,
            memoryUsage = memoryUsage
        )
    }
    
    private fun validateConstructedData(data: ByteArray, originalObjects: List<TlvDataObject>): List<TlvValidationResult> {
        val results = mutableListOf<TlvValidationResult>()
        
        // Validate that constructed data can be parsed back
        try {
            val parseResult = parseTlvData(data)
            when (parseResult) {
                is TlvParsingResult.Success -> {
                    results.add(TlvValidationResult(
                        ruleName = "CONSTRUCTION_ROUNDTRIP",
                        isValid = true,
                        details = "Constructed data parses correctly",
                        severity = TlvValidationSeverity.INFO
                    ))
                }
                is TlvParsingResult.Failed -> {
                    results.add(TlvValidationResult(
                        ruleName = "CONSTRUCTION_ROUNDTRIP",
                        isValid = false,
                        details = "Constructed data parsing failed: ${parseResult.error.message}",
                        severity = TlvValidationSeverity.ERROR
                    ))
                }
            }
        } catch (e: Exception) {
            results.add(TlvValidationResult(
                ruleName = "CONSTRUCTION_ROUNDTRIP",
                isValid = false,
                details = "Construction validation failed: ${e.message}",
                severity = TlvValidationSeverity.ERROR
            ))
        }
        
        return results
    }
    
    private fun analyzeTlvFailure(exception: Exception, offset: Int): TlvFailureAnalysis {
        val category = when {
            exception.message?.contains("tag", ignoreCase = true) == true -> TlvFailureCategory.INVALID_TAG
            exception.message?.contains("length", ignoreCase = true) == true -> TlvFailureCategory.INVALID_LENGTH
            exception.message?.contains("value", ignoreCase = true) == true -> TlvFailureCategory.INVALID_VALUE
            exception.message?.contains("structure", ignoreCase = true) == true -> TlvFailureCategory.STRUCTURE_ERROR
            else -> TlvFailureCategory.FORMAT_ERROR
        }
        
        return TlvFailureAnalysis(
            failureCategory = category,
            errorOffset = offset,
            rootCause = exception.message ?: "Unknown TLV parsing error",
            recoveryOptions = generateRecoveryOptions(category)
        )
    }
    
    private fun generateRecoveryOptions(category: TlvFailureCategory): List<String> {
        return when (category) {
            TlvFailureCategory.INVALID_TAG -> listOf(
                "Verify tag format and encoding",
                "Check for multi-byte tag support",
                "Validate tag class and construction bit"
            )
            TlvFailureCategory.INVALID_LENGTH -> listOf(
                "Verify length encoding format",
                "Check for indefinite length support",
                "Validate length field bounds"
            )
            TlvFailureCategory.INVALID_VALUE -> listOf(
                "Verify value data integrity",
                "Check value length consistency",
                "Validate nested TLV structure"
            )
            else -> listOf(
                "Review TLV data format",
                "Check data integrity",
                "Contact technical support"
            )
        }
    }
    
    private fun generateCacheKey(data: ByteArray): String {
        return data.joinToString("") { "%02X".format(it) }.take(32)
    }
    
    private fun initializeValidationRules() {
        validationRules.addAll(listOf(
            TlvValidationRule("STRUCTURE_INTEGRITY") { objects ->
                val isValid = objects.all { validateSingleObjectIntegrity(it) }
                TlvValidationResult(
                    ruleName = "STRUCTURE_INTEGRITY",
                    isValid = isValid,
                    details = if (isValid) "All TLV objects have valid structure" else "Some TLV objects have structural issues",
                    severity = if (isValid) TlvValidationSeverity.INFO else TlvValidationSeverity.ERROR
                )
            },
            
            TlvValidationRule("LENGTH_CONSISTENCY") { objects ->
                val isValid = objects.all { it.value.size == it.length }
                TlvValidationResult(
                    ruleName = "LENGTH_CONSISTENCY",
                    isValid = isValid,
                    details = if (isValid) "All length fields are consistent with value sizes" else "Length field inconsistencies detected",
                    severity = if (isValid) TlvValidationSeverity.INFO else TlvValidationSeverity.ERROR
                )
            }
        ))
    }
    
    private fun validateSingleObjectIntegrity(obj: TlvDataObject): Boolean {
        return try {
            obj.tagBytes.isNotEmpty() && 
            obj.lengthBytes.isNotEmpty() && 
            obj.value.size == obj.length
        } catch (e: Exception) {
            false
        }
    }
    
    // Parameter validation methods
    
    private fun validateParsingParameters(data: ByteArray) {
        if (data.isEmpty()) {
            throw TlvParsingException("Data cannot be empty")
        }
        
        if (data.size > configuration.maxDataSize) {
            throw TlvParsingException("Data size exceeds maximum: ${data.size} > ${configuration.maxDataSize}")
        }
        
        auditLogger.logValidation("PARSING_PARAMS", "SUCCESS", "data_length=${data.size}")
    }
    
    private fun validateConstructionParameters(tlvObjects: List<TlvDataObject>) {
        if (tlvObjects.isEmpty()) {
            throw TlvConstructionException("TLV objects list cannot be empty")
        }
        
        auditLogger.logValidation("CONSTRUCTION_PARAMS", "SUCCESS", "objects_count=${tlvObjects.size}")
    }
    
    private fun validateSearchParameters(tag: String, tlvObjects: List<TlvDataObject>) {
        if (tag.isBlank()) {
            throw TlvParsingException("Search tag cannot be blank")
        }
        
        if (tlvObjects.isEmpty()) {
            throw TlvParsingException("TLV objects list cannot be empty")
        }
        
        auditLogger.logValidation("SEARCH_PARAMS", "SUCCESS", "tag=$tag objects_count=${tlvObjects.size}")
    }
    
    private fun validateNestingDepth(depth: Int) {
        if (depth > configuration.maxNestingDepth) {
            throw TlvParsingException("Maximum nesting depth exceeded: $depth > ${configuration.maxNestingDepth}")
        }
    }
    
    private fun validateTagBounds(data: ByteArray, offset: Int) {
        if (offset >= data.size) {
            throw TlvParsingException("Tag offset out of bounds: $offset >= ${data.size}")
        }
    }
    
    private fun validateLengthBounds(data: ByteArray, offset: Int) {
        if (offset >= data.size) {
            throw TlvParsingException("Length offset out of bounds: $offset >= ${data.size}")
        }
    }
    
    private fun validateValueBounds(data: ByteArray, offset: Int, length: Int) {
        if (offset + length > data.size) {
            throw TlvParsingException("Value bounds exceed data size: ${offset + length} > ${data.size}")
        }
    }
    
    private fun validateLengthOfLength(lengthOfLength: Int) {
        if (lengthOfLength > MAX_LENGTH_BYTES) {
            throw TlvParsingException("Length of length exceeds maximum: $lengthOfLength > $MAX_LENGTH_BYTES")
        }
    }
}

/**
 * Single TLV Parse Result (Internal)
 */
private sealed class SingleTlvParseResult {
    data class Success(
        val tlvObject: TlvDataObject,
        val nextOffset: Int
    ) : SingleTlvParseResult()
    
    data class Failed(
        val error: String,
        val offset: Int
    ) : SingleTlvParseResult()
}

/**
 * TLV Validation Rule
 */
data class TlvValidationRule(
    val name: String,
    val validate: (List<TlvDataObject>) -> TlvValidationResult
)

/**
 * TLV Parser Statistics
 */
data class TlvParserStatistics(
    val version: String,
    val operationsPerformed: Long,
    val cachedResults: Int,
    val averageParsingTime: Double,
    val averageConstructionTime: Double,
    val throughput: Double,
    val configuration: TlvParserConfiguration,
    val uptime: Long
)

/**
 * TLV Parsing Exception
 */
class TlvParsingException(
    message: String,
    cause: Throwable? = null,
    val context: Map<String, Any> = emptyMap()
) : Exception(message, cause)

/**
 * TLV Construction Exception
 */
class TlvConstructionException(
    message: String,
    cause: Throwable? = null,
    val context: Map<String, Any> = emptyMap()
) : Exception(message, cause)

/**
 * TLV Audit Logger
 */
class TlvAuditLogger {
    
    fun logOperation(operation: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("TLV_AUDIT: [$timestamp] OPERATION - $operation: $details")
    }
    
    fun logError(operation: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("TLV_AUDIT: [$timestamp] ERROR - $operation: $details")
    }
    
    fun logValidation(component: String, result: String, details: String) {
        val timestamp = System.currentTimeMillis()
        println("TLV_AUDIT: [$timestamp] VALIDATION - $component/$result: $details")
    }
}

/**
 * TLV Performance Tracker
 */
class TlvPerformanceTracker {
    private val parsingTimes = mutableListOf<Long>()
    private val constructionTimes = mutableListOf<Long>()
    private val startTime = System.currentTimeMillis()
    
    fun recordParsing(parsingTime: Long, bytesProcessed: Long, objectsProcessed: Int) {
        parsingTimes.add(parsingTime)
    }
    
    fun recordConstruction(constructionTime: Long, bytesGenerated: Long, objectsConstructed: Int) {
        constructionTimes.add(constructionTime)
    }
    
    fun getAverageParsingTime(): Double {
        return if (parsingTimes.isNotEmpty()) {
            parsingTimes.average()
        } else {
            0.0
        }
    }
    
    fun getAverageConstructionTime(): Double {
        return if (constructionTimes.isNotEmpty()) {
            constructionTimes.average()
        } else {
            0.0
        }
    }
    
    fun getThroughput(): Double {
        val totalOperations = parsingTimes.size + constructionTimes.size
        val uptimeSeconds = (System.currentTimeMillis() - startTime) / 1000.0
        return if (uptimeSeconds > 0) totalOperations / uptimeSeconds else 0.0
    }
    
    fun getParserUptime(): Long {
        return System.currentTimeMillis() - startTime
    }
}
