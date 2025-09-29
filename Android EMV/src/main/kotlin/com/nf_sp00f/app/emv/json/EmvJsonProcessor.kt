/**
 * nf-sp00f EMV Engine - JSON Data Exchange
 *
 * Comprehensive JSON serialization and deserialization for EMV data structures,
 * transaction logging, and data export/import functionality.
 *
 * @package com.nf_sp00f.app.emv.json
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv.json

import com.nf_sp00f.app.emv.data.*
import com.nf_sp00f.app.emv.tlv.*
import com.nf_sp00f.app.emv.security.*
import com.nf_sp00f.app.emv.utils.*
import kotlinx.serialization.*
import kotlinx.serialization.json.*
import kotlinx.serialization.modules.*
import timber.log.Timber
import java.text.SimpleDateFormat
import java.util.*

/**
 * JSON Export format types
 */
enum class JsonExportFormat {
    COMPACT,        // Minimal JSON
    PRETTY,         // Human-readable format
    DETAILED,       // Include all metadata
    DEBUG          // Include debug information
}

/**
 * JSON Export scope
 */
enum class JsonExportScope {
    CARD_DATA_ONLY,
    TRANSACTION_DATA_ONLY,
    SESSION_DATA_ONLY,
    COMPLETE_EXPORT
}

/**
 * Serializable TLV entry for JSON export
 */
@Serializable
data class JsonTlvEntry(
    val tag: String,
    val tagName: String,
    val value: String,
    val length: Int,
    val description: String? = null
)

/**
 * Serializable card information for JSON export
 */
@Serializable
data class JsonCardInfo(
    val uid: String,
    val atr: String,
    val aid: String?,
    val label: String?,
    val preferredName: String?,
    val vendor: String,
    val cardType: String,
    val detectedAt: String,
    val capabilities: JsonCardCapabilities?
)

/**
 * Serializable card capabilities for JSON export
 */
@Serializable
data class JsonCardCapabilities(
    val supportedFeatures: List<String>,
    val maxTransactionAmount: Long?,
    val contactlessTransactionLimit: Long?,
    val cvmMethods: List<JsonCvmMethod>,
    val applicationCurrencyCode: String?,
    val applicationCountryCode: String?
)

/**
 * Serializable CVM method for JSON export
 */
@Serializable
data class JsonCvmMethod(
    val method: String,
    val condition: String,
    val methodDescription: String,
    val conditionDescription: String
)

/**
 * Serializable transaction result for JSON export
 */
@Serializable
data class JsonTransactionResult(
    val success: Boolean,
    val transactionType: String,
    val amount: Long?,
    val currency: String?,
    val authenticationMethod: String?,
    val cardData: JsonCardData,
    val terminalData: JsonTerminalData,
    val processingTime: Long,
    val timestamp: String,
    val errorMessage: String? = null
)

/**
 * Serializable card data for JSON export
 */
@Serializable
data class JsonCardData(
    val pan: String?,
    val panSequenceNumber: String?,
    val expiryDate: String?,
    val cardholderName: String?,
    val track2: String?,
    val applicationLabel: String?,
    val issuer: String?
)

/**
 * Serializable terminal data for JSON export
 */
@Serializable
data class JsonTerminalData(
    val terminalType: String,
    val terminalCapabilities: String,
    val additionalTerminalCapabilities: String?,
    val terminalCountryCode: String?,
    val terminalId: String?,
    val merchantId: String?
)

/**
 * Serializable authentication result for JSON export
 */
@Serializable
data class JsonAuthenticationResult(
    val authenticationType: String,
    val success: Boolean,
    val certificateValidation: Boolean,
    val signatureValidation: Boolean,
    val keyStrength: String?,
    val rocaVulnerability: Boolean?,
    val processingTime: Long,
    val errorMessage: String? = null
)

/**
 * Serializable session export containing all EMV data
 */
@Serializable
data class JsonSessionExport(
    val sessionId: String,
    val exportFormat: String,
    val exportScope: String,
    val exportTimestamp: String,
    val engineVersion: String,
    val nfcProvider: JsonNfcProviderInfo,
    val cardInfo: JsonCardInfo?,
    val tlvData: List<JsonTlvEntry>,
    val transactionResults: List<JsonTransactionResult>,
    val authenticationResults: List<JsonAuthenticationResult>,
    val securityAnalysis: JsonSecurityAnalysis?,
    val sessionMetrics: JsonSessionMetrics
)

/**
 * Serializable NFC provider info for JSON export
 */
@Serializable
data class JsonNfcProviderInfo(
    val type: String,
    val name: String,
    val version: String,
    val capabilities: List<String>
)

/**
 * Serializable security analysis for JSON export
 */
@Serializable
data class JsonSecurityAnalysis(
    val rocaVulnerabilityDetected: Boolean,
    val certificateChainValid: Boolean,
    val keyStrengthAnalysis: String,
    val emvComplianceLevel: String,
    val securityRecommendations: List<String>
)

/**
 * Serializable session metrics for JSON export
 */
@Serializable
data class JsonSessionMetrics(
    val sessionDuration: Long,
    val commandsExecuted: Int,
    val averageCommandTime: Long,
    val successRate: Double,
    val dataTransferred: Long,
    val performanceRating: String
)

/**
 * EMV JSON processor for data exchange operations
 */
class EmvJsonProcessor {
    
    companion object {
        private const val TAG = "EmvJsonProcessor"
        private const val ENGINE_VERSION = "nf-sp00f EMV Engine v1.0.0"
        
        private val dateFormatter = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
    }
    
    private val json = Json {
        prettyPrint = true
        ignoreUnknownKeys = true
        encodeDefaults = true
    }
    
    private val compactJson = Json {
        prettyPrint = false
        ignoreUnknownKeys = true
        encodeDefaults = false
    }
    
    private val emvUtilities = EmvUtilities()
    
    /**
     * Export complete EMV session to JSON
     */
    fun exportSessionToJson(
        sessionId: String,
        cardInfo: CardInfo?,
        tlvDatabase: TlvDatabase,
        transactionResults: List<TransactionResult>,
        authenticationResults: List<AuthenticationResult>,
        nfcProviderInfo: NfcProviderInfo,
        format: JsonExportFormat = JsonExportFormat.PRETTY,
        scope: JsonExportScope = JsonExportScope.COMPLETE_EXPORT
    ): String {
        try {
            Timber.d("Exporting EMV session $sessionId to JSON (format: $format, scope: $scope)")
            
            val export = JsonSessionExport(
                sessionId = sessionId,
                exportFormat = format.name,
                exportScope = scope.name,
                exportTimestamp = dateFormatter.format(Date()),
                engineVersion = ENGINE_VERSION,
                nfcProvider = convertNfcProviderInfo(nfcProviderInfo),
                cardInfo = cardInfo?.let { convertCardInfo(it) },
                tlvData = if (shouldIncludeTlvData(scope)) convertTlvDatabase(tlvDatabase) else emptyList(),
                transactionResults = if (shouldIncludeTransactionData(scope)) {
                    transactionResults.map { convertTransactionResult(it) }
                } else emptyList(),
                authenticationResults = if (shouldIncludeSessionData(scope)) {
                    authenticationResults.map { convertAuthenticationResult(it) }
                } else emptyList(),
                securityAnalysis = if (shouldIncludeSessionData(scope)) {
                    generateSecurityAnalysis(tlvDatabase, authenticationResults)
                } else null,
                sessionMetrics = generateSessionMetrics(transactionResults, authenticationResults)
            )
            
            val jsonString = when (format) {
                JsonExportFormat.COMPACT -> compactJson.encodeToString(export)
                else -> json.encodeToString(export)
            }
            
            Timber.i("Successfully exported EMV session to JSON (${jsonString.length} characters)")
            return jsonString
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to export EMV session to JSON")
            throw EmvException("JSON export failed: ${e.message}", e)
        }
    }
    
    /**
     * Import EMV session from JSON
     */
    fun importSessionFromJson(jsonString: String): JsonSessionExport {
        try {
            Timber.d("Importing EMV session from JSON")
            
            val sessionExport = json.decodeFromString<JsonSessionExport>(jsonString)
            
            Timber.i("Successfully imported EMV session: ${sessionExport.sessionId}")
            return sessionExport
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to import EMV session from JSON")
            throw EmvException("JSON import failed: ${e.message}", e)
        }
    }
    
    /**
     * Export TLV database to JSON
     */
    fun exportTlvDatabaseToJson(
        tlvDatabase: TlvDatabase,
        format: JsonExportFormat = JsonExportFormat.PRETTY
    ): String {
        try {
            val tlvEntries = convertTlvDatabase(tlvDatabase)
            
            return when (format) {
                JsonExportFormat.COMPACT -> compactJson.encodeToString(tlvEntries)
                else -> json.encodeToString(tlvEntries)
            }
        } catch (e: Exception) {
            Timber.e(e, "Failed to export TLV database to JSON")
            throw EmvException("TLV JSON export failed: ${e.message}", e)
        }
    }
    
    /**
     * Import TLV database from JSON
     */
    fun importTlvDatabaseFromJson(jsonString: String): TlvDatabase {
        try {
            val tlvEntries = json.decodeFromString<List<JsonTlvEntry>>(jsonString)
            val tlvDatabase = TlvDatabase()
            
            tlvEntries.forEach { entry ->
                val tag = EmvTag.fromInt(entry.tag.removePrefix("0x").toInt(16))
                val value = emvUtilities.hexToByteArray(entry.value)
                tlvDatabase.addEntry(tag, value)
            }
            
            return tlvDatabase
        } catch (e: Exception) {
            Timber.e(e, "Failed to import TLV database from JSON")
            throw EmvException("TLV JSON import failed: ${e.message}", e)
        }
    }
    
    /**
     * Export transaction result to JSON
     */
    fun exportTransactionResultToJson(
        result: TransactionResult,
        format: JsonExportFormat = JsonExportFormat.PRETTY
    ): String {
        try {
            val jsonResult = convertTransactionResult(result)
            
            return when (format) {
                JsonExportFormat.COMPACT -> compactJson.encodeToString(jsonResult)
                else -> json.encodeToString(jsonResult)
            }
        } catch (e: Exception) {
            Timber.e(e, "Failed to export transaction result to JSON")
            throw EmvException("Transaction JSON export failed: ${e.message}", e)
        }
    }
    
    /**
     * Import transaction result from JSON
     */
    fun importTransactionResultFromJson(jsonString: String): JsonTransactionResult {
        try {
            return json.decodeFromString<JsonTransactionResult>(jsonString)
        } catch (e: Exception) {
            Timber.e(e, "Failed to import transaction result from JSON")
            throw EmvException("Transaction JSON import failed: ${e.message}", e)
        }
    }
    
    /**
     * Export authentication result to JSON
     */
    fun exportAuthenticationResultToJson(
        result: AuthenticationResult,
        format: JsonExportFormat = JsonExportFormat.PRETTY
    ): String {
        try {
            val jsonResult = convertAuthenticationResult(result)
            
            return when (format) {
                JsonExportFormat.COMPACT -> compactJson.encodeToString(jsonResult)
                else -> json.encodeToString(jsonResult)
            }
        } catch (e: Exception) {
            Timber.e(e, "Failed to export authentication result to JSON")
            throw EmvException("Authentication JSON export failed: ${e.message}", e)
        }
    }
    
    /**
     * Create EMV report in JSON format
     */
    fun generateEmvReport(
        sessionId: String,
        cardInfo: CardInfo?,
        tlvDatabase: TlvDatabase,
        transactionResults: List<TransactionResult>,
        authenticationResults: List<AuthenticationResult>,
        securityAnalysis: SecurityAnalysisResult?,
        format: JsonExportFormat = JsonExportFormat.DETAILED
    ): String {
        try {
            val report = mapOf(
                "reportHeader" to mapOf(
                    "reportType" to "EMV Analysis Report",
                    "sessionId" to sessionId,
                    "generatedAt" to dateFormatter.format(Date()),
                    "engineVersion" to ENGINE_VERSION
                ),
                "cardInformation" to (cardInfo?.let { convertCardInfo(it) } ?: "No card detected"),
                "tlvAnalysis" to mapOf(
                    "totalTags" to tlvDatabase.size(),
                    "mandatoryTagsPresent" to checkMandatoryTags(tlvDatabase),
                    "tagBreakdown" to convertTlvDatabase(tlvDatabase)
                ),
                "transactionSummary" to mapOf(
                    "totalTransactions" to transactionResults.size,
                    "successfulTransactions" to transactionResults.count { it is TransactionResult.Success },
                    "failedTransactions" to transactionResults.count { it is TransactionResult.Error },
                    "transactions" to transactionResults.map { convertTransactionResult(it) }
                ),
                "authenticationSummary" to mapOf(
                    "totalAuthentications" to authenticationResults.size,
                    "successfulAuthentications" to authenticationResults.count { it.isSuccess },
                    "authentications" to authenticationResults.map { convertAuthenticationResult(it) }
                ),
                "securityAnalysis" to (securityAnalysis?.let { 
                    convertSecurityAnalysis(it) 
                } ?: "No security analysis performed"),
                "recommendations" to generateRecommendations(tlvDatabase, transactionResults, authenticationResults)
            )
            
            return when (format) {
                JsonExportFormat.COMPACT -> compactJson.encodeToString(report)
                else -> json.encodeToString(report)
            }
            
        } catch (e: Exception) {
            Timber.e(e, "Failed to generate EMV report")
            throw EmvException("EMV report generation failed: ${e.message}", e)
        }
    }
    
    // Private conversion functions
    
    private fun convertCardInfo(cardInfo: CardInfo): JsonCardInfo {
        return JsonCardInfo(
            uid = emvUtilities.byteArrayToHex(cardInfo.uid),
            atr = emvUtilities.byteArrayToHex(cardInfo.atr),
            aid = cardInfo.aid?.let { emvUtilities.byteArrayToHex(it) },
            label = cardInfo.label,
            preferredName = cardInfo.preferredName,
            vendor = cardInfo.vendor.displayName,
            cardType = cardInfo.cardType.name,
            detectedAt = dateFormatter.format(Date(cardInfo.detectedAt)),
            capabilities = null // Would convert if CardCapabilities were available
        )
    }
    
    private fun convertTlvDatabase(tlvDatabase: TlvDatabase): List<JsonTlvEntry> {
        return tlvDatabase.getAllEntries().map { (tag, value) ->
            JsonTlvEntry(
                tag = "0x${String.format("%X", tag.value)}",
                tagName = emvUtilities.getEmvTagName(tag.value),
                value = emvUtilities.byteArrayToHex(value),
                length = value.size,
                description = EmvTagRegistry.getTagDescription(tag.value)
            )
        }
    }
    
    private fun convertTransactionResult(result: TransactionResult): JsonTransactionResult {
        return when (result) {
            is TransactionResult.Success -> JsonTransactionResult(
                success = true,
                transactionType = result.transactionType.name,
                amount = result.amount,
                currency = result.currency,
                authenticationMethod = result.authenticationMethod?.name,
                cardData = convertCardDataFromResult(result),
                terminalData = convertTerminalDataFromResult(result),
                processingTime = result.processingTime,
                timestamp = dateFormatter.format(Date(result.timestamp))
            )
            is TransactionResult.Error -> JsonTransactionResult(
                success = false,
                transactionType = "UNKNOWN",
                amount = null,
                currency = null,
                authenticationMethod = null,
                cardData = JsonCardData(null, null, null, null, null, null, null),
                terminalData = JsonTerminalData("UNKNOWN", "UNKNOWN", null, null, null, null),
                processingTime = 0L,
                timestamp = dateFormatter.format(Date()),
                errorMessage = result.errorMessage
            )
        }
    }
    
    private fun convertAuthenticationResult(result: AuthenticationResult): JsonAuthenticationResult {
        return JsonAuthenticationResult(
            authenticationType = result.authenticationType.name,
            success = result.isSuccess,
            certificateValidation = result.certificateValidationResult?.isValid == true,
            signatureValidation = result.signatureVerificationResult?.isValid == true,
            keyStrength = result.keyStrengthAnalysis?.strength?.name,
            rocaVulnerability = result.rocaVulnerabilityResult?.isVulnerable,
            processingTime = result.processingTime,
            errorMessage = if (!result.isSuccess) result.errorMessage else null
        )
    }
    
    private fun convertNfcProviderInfo(info: NfcProviderInfo): JsonNfcProviderInfo {
        return JsonNfcProviderInfo(
            type = info.type.name,
            name = info.name,
            version = info.version,
            capabilities = info.capabilities
        )
    }
    
    private fun convertCardDataFromResult(result: TransactionResult.Success): JsonCardData {
        return JsonCardData(
            pan = result.cardData.pan,
            panSequenceNumber = result.cardData.panSequenceNumber?.toString(),
            expiryDate = result.cardData.expiry,
            cardholderName = result.cardData.cardholderName,
            track2 = result.cardData.track2Data?.let { emvUtilities.byteArrayToHex(it) },
            applicationLabel = result.cardData.applicationLabel,
            issuer = result.cardData.issuerName
        )
    }
    
    private fun convertTerminalDataFromResult(result: TransactionResult.Success): JsonTerminalData {
        return JsonTerminalData(
            terminalType = "ANDROID_NFC", // Default for our implementation
            terminalCapabilities = "CONTACTLESS_EMV",
            additionalTerminalCapabilities = null,
            terminalCountryCode = null,
            terminalId = null,
            merchantId = null
        )
    }
    
    private fun generateSecurityAnalysis(
        tlvDatabase: TlvDatabase,
        authenticationResults: List<AuthenticationResult>
    ): JsonSecurityAnalysis {
        val rocaDetected = authenticationResults.any { 
            it.rocaVulnerabilityResult?.isVulnerable == true 
        }
        val certificateValid = authenticationResults.any { 
            it.certificateValidationResult?.isValid == true 
        }
        
        return JsonSecurityAnalysis(
            rocaVulnerabilityDetected = rocaDetected,
            certificateChainValid = certificateValid,
            keyStrengthAnalysis = "Analysis performed on ${authenticationResults.size} authentications",
            emvComplianceLevel = emvUtilities.validateEmvCompliance(tlvDatabase).complianceLevel.name,
            securityRecommendations = generateSecurityRecommendations(rocaDetected, certificateValid)
        )
    }
    
    private fun generateSessionMetrics(
        transactionResults: List<TransactionResult>,
        authenticationResults: List<AuthenticationResult>
    ): JsonSessionMetrics {
        val totalOperations = transactionResults.size + authenticationResults.size
        val successfulOperations = transactionResults.count { it is TransactionResult.Success } +
                authenticationResults.count { it.isSuccess }
        
        val avgTime = if (totalOperations > 0) {
            (transactionResults.sumOf { 
                when (it) {
                    is TransactionResult.Success -> it.processingTime
                    is TransactionResult.Error -> 0L
                }
            } + authenticationResults.sumOf { it.processingTime }) / totalOperations
        } else 0L
        
        return JsonSessionMetrics(
            sessionDuration = 0L, // Would be calculated from actual session
            commandsExecuted = totalOperations,
            averageCommandTime = avgTime,
            successRate = if (totalOperations > 0) (successfulOperations.toDouble() / totalOperations) * 100 else 0.0,
            dataTransferred = 0L, // Would track actual bytes
            performanceRating = when {
                avgTime < 500 -> "EXCELLENT"
                avgTime < 1000 -> "GOOD"
                avgTime < 2000 -> "AVERAGE"
                else -> "SLOW"
            }
        )
    }
    
    private fun convertSecurityAnalysis(analysis: SecurityAnalysisResult): JsonSecurityAnalysis {
        return JsonSecurityAnalysis(
            rocaVulnerabilityDetected = analysis.rocaVulnerabilityCheck.isVulnerable,
            certificateChainValid = analysis.certificateValidation.isValid,
            keyStrengthAnalysis = analysis.keyStrengthAnalysis.analysis,
            emvComplianceLevel = analysis.complianceCheck.complianceLevel.name,
            securityRecommendations = generateSecurityRecommendations(
                analysis.rocaVulnerabilityCheck.isVulnerable,
                analysis.certificateValidation.isValid
            )
        )
    }
    
    private fun generateSecurityRecommendations(rocaDetected: Boolean, certificateValid: Boolean): List<String> {
        val recommendations = mutableListOf<String>()
        
        if (rocaDetected) {
            recommendations.add("CRITICAL: ROCA vulnerability detected - Replace card immediately")
        }
        
        if (!certificateValid) {
            recommendations.add("WARNING: Certificate validation failed - Verify card authenticity")
        }
        
        recommendations.add("Always verify transaction details before approval")
        recommendations.add("Keep EMV processing software updated")
        
        return recommendations
    }
    
    private fun generateRecommendations(
        tlvDatabase: TlvDatabase,
        transactionResults: List<TransactionResult>,
        authenticationResults: List<AuthenticationResult>
    ): List<String> {
        val recommendations = mutableListOf<String>()
        
        val compliance = emvUtilities.validateEmvCompliance(tlvDatabase)
        if (!compliance.isCompliant) {
            recommendations.add("Card does not meet full EMV compliance requirements")
        }
        
        val failedTransactions = transactionResults.count { it is TransactionResult.Error }
        if (failedTransactions > 0) {
            recommendations.add("$failedTransactions transaction(s) failed - Review error messages")
        }
        
        val failedAuth = authenticationResults.count { !it.isSuccess }
        if (failedAuth > 0) {
            recommendations.add("$failedAuth authentication(s) failed - Card may be compromised")
        }
        
        return recommendations
    }
    
    private fun checkMandatoryTags(tlvDatabase: TlvDatabase): Int {
        return emvUtilities.checkMandatoryTags(tlvDatabase).size
    }
    
    private fun shouldIncludeTlvData(scope: JsonExportScope): Boolean {
        return scope in listOf(JsonExportScope.CARD_DATA_ONLY, JsonExportScope.COMPLETE_EXPORT)
    }
    
    private fun shouldIncludeTransactionData(scope: JsonExportScope): Boolean {
        return scope in listOf(JsonExportScope.TRANSACTION_DATA_ONLY, JsonExportScope.COMPLETE_EXPORT)
    }
    
    private fun shouldIncludeSessionData(scope: JsonExportScope): Boolean {
        return scope in listOf(JsonExportScope.SESSION_DATA_ONLY, JsonExportScope.COMPLETE_EXPORT)
    }
}