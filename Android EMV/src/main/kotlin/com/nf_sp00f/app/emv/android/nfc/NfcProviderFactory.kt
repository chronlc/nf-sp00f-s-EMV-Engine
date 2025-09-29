package com.nf_sp00f.app.emv.nfc

/**
 * Enterprise NFC Provider Factory
 * 
 * Production-grade factory for creating and managing NFC providers with
 * comprehensive selection logic, provider registration, and enterprise features.
 * Zero defensive programming patterns.
 * 
 * EMV Book Reference: EMV Contactless Specifications
 * - EMV Contactless Book A: Architecture and General Requirements
 * - EMV Contactless Book B: Entry Point Specification
 * - ISO/IEC 14443: Proximity cards - contactless integrated circuit cards
 * 
 * Architecture:
 * - Enterprise-grade provider creation and management
 * - Comprehensive provider selection algorithms
 * - Production-ready capability detection and validation
 * - Complete audit logging integration
 * - Zero defensive programming patterns (?:, ?., !!, .let)
 */

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Provider Selection Strategy Enumeration
 * 
 * Comprehensive strategies for selecting optimal NFC providers
 * based on different enterprise requirements
 */
enum class ProviderSelectionStrategy(
    val displayName: String,
    val description: String,
    val priority: Int
) {
    PERFORMANCE_OPTIMIZED(
        displayName = "Performance Optimized",
        description = "Select provider with highest throughput and lowest latency",
        priority = 1
    ),
    
    RELIABILITY_FIRST(
        displayName = "Reliability First", 
        description = "Select provider with highest success rate and stability",
        priority = 2
    ),
    
    FEATURE_COMPLETE(
        displayName = "Feature Complete",
        description = "Select provider with most comprehensive EMV feature support",
        priority = 3
    ),
    
    SECURITY_FOCUSED(
        displayName = "Security Focused",
        description = "Select provider with strongest security capabilities",
        priority = 4
    ),
    
    COST_EFFECTIVE(
        displayName = "Cost Effective",
        description = "Select provider with lowest resource usage",
        priority = 5
    ),
    
    COMPATIBILITY_FIRST(
        displayName = "Compatibility First",
        description = "Select provider with broadest card type support",
        priority = 6
    )
}

/**
 * Provider Detection Result
 * 
 * Comprehensive result of provider detection and capability analysis
 */
data class ProviderDetectionResult(
    val providerType: NfcProviderType,
    val isAvailable: Boolean,
    val capabilities: NfcProviderCapabilities,
    val performanceScore: Double,
    val reliabilityScore: Double,
    val featureScore: Double,
    val securityScore: Double,
    val compatibilityScore: Double,
    val detectionTime: Long,
    val hardwareVersion: String = "",
    val firmwareVersion: String = "",
    val detectionError: Throwable? = null
)

/**
 * Provider Selection Criteria
 * 
 * Enterprise criteria for provider selection with weighted scoring
 */
data class ProviderSelectionCriteria(
    val strategy: ProviderSelectionStrategy,
    val requiredFeatures: Set<String> = emptySet(),
    val requiredCardTypes: Set<NfcCardType> = emptySet(),
    val minimumPerformanceScore: Double = 0.0,
    val minimumReliabilityScore: Double = 0.0,
    val minimumSecurityLevel: NfcSecurityLevel = NfcSecurityLevel.BASIC,
    val excludedProviders: Set<NfcProviderType> = emptySet(),
    val weightings: ProviderScoringWeights = ProviderScoringWeights()
)

/**
 * Provider Scoring Weights
 * 
 * Configurable weights for different aspects of provider evaluation
 */
data class ProviderScoringWeights(
    val performanceWeight: Double = 0.25,
    val reliabilityWeight: Double = 0.25,
    val featureWeight: Double = 0.20,
    val securityWeight: Double = 0.15,
    val compatibilityWeight: Double = 0.15
) {
    
    init {
        val totalWeight = performanceWeight + reliabilityWeight + featureWeight + securityWeight + compatibilityWeight
        if (totalWeight < 0.99 || totalWeight > 1.01) {
            throw NfcProviderFactoryException(
                "Scoring weights must sum to 1.0",
                context = mapOf("total_weight" to totalWeight)
            )
        }
    }
}

/**
 * Provider Factory Configuration
 * 
 * Enterprise configuration for factory behavior and provider management
 */
data class NfcProviderFactoryConfiguration(
    val enableAutoDetection: Boolean = true,
    val detectionTimeout: Long = 10000L,
    val enableParallelDetection: Boolean = true,
    val cacheDetectionResults: Boolean = true,
    val cacheExpiryTime: Long = 300000L, // 5 minutes
    val enableHealthMonitoring: Boolean = true,
    val healthCheckInterval: Long = 60000L, // 1 minute
    val maxProviderInstances: Int = 10,
    val enableProviderPooling: Boolean = true,
    val auditAllOperations: Boolean = true
) {
    
    /**
     * Validate configuration parameters
     */
    fun validate() {
        if (detectionTimeout < 1000L) {
            throw NfcProviderFactoryException(
                "Detection timeout must be at least 1000ms",
                context = mapOf("timeout" to detectionTimeout)
            )
        }
        
        if (maxProviderInstances < 1 || maxProviderInstances > 100) {
            throw NfcProviderFactoryException(
                "Max provider instances must be between 1 and 100",
                context = mapOf("max_instances" to maxProviderInstances)
            )
        }
        
        if (cacheExpiryTime < 60000L) {
            throw NfcProviderFactoryException(
                "Cache expiry time must be at least 60 seconds",
                context = mapOf("cache_expiry" to cacheExpiryTime)
            )
        }
    }
}

/**
 * Enterprise NFC Provider Factory
 * 
 * Production-grade factory providing comprehensive provider creation,
 * management, and selection with enterprise features
 */
class NfcProviderFactory(
    private val configuration: NfcProviderFactoryConfiguration = NfcProviderFactoryConfiguration()
) {
    
    companion object {
        private const val VERSION = "1.0.0"
        private val DEFAULT_PROVIDER_FACTORIES = mapOf(
            NfcProviderType.ANDROID_INTERNAL to { AndroidInternalNfcProvider() },
            NfcProviderType.PN532_BLUETOOTH to { Pn532BluetoothNfcProvider() },
            NfcProviderType.PN532_USB to { Pn532UsbNfcProvider() },
            NfcProviderType.PN532_SPI to { Pn532SpiNfcProvider() }
        )
    }
    
    // Provider Management
    private val providerFactories = ConcurrentHashMap<NfcProviderType, () -> INfcProvider>()
    private val providerInstances = ConcurrentHashMap<String, INfcProvider>()
    private val detectionCache = ConcurrentHashMap<NfcProviderType, CachedDetectionResult>()
    
    // Metrics and Statistics
    private val createdProviders = AtomicLong(0)
    private val detectionAttempts = AtomicLong(0)
    private val selectionRequests = AtomicLong(0)
    private val lastHealthCheck = AtomicReference(0L)
    
    init {
        configuration.validate()
        
        // Register default provider factories
        DEFAULT_PROVIDER_FACTORIES.forEach { (type, factory) ->
            registerProviderFactory(type, factory)
        }
        
        NfcProviderFactoryAuditor.logFactoryInitialization(VERSION, providerFactories.size)
    }
    
    /**
     * Factory Information and Status
     */
    
    /**
     * Get factory version
     */
    fun getVersion(): String = VERSION
    
    /**
     * Get factory configuration
     */
    fun getConfiguration(): NfcProviderFactoryConfiguration = configuration
    
    /**
     * Get registered provider types
     */
    fun getRegisteredProviderTypes(): Set<NfcProviderType> = providerFactories.keys.toSet()
    
    /**
     * Get factory statistics
     */
    fun getFactoryStatistics(): NfcProviderFactoryStatistics {
        return NfcProviderFactoryStatistics(
            registeredProviders = providerFactories.size,
            createdProviders = createdProviders.get(),
            activeInstances = providerInstances.size,
            detectionAttempts = detectionAttempts.get(),
            selectionRequests = selectionRequests.get(),
            cachedResults = detectionCache.size,
            lastHealthCheck = lastHealthCheck.get()
        )
    }
    
    /**
     * Provider Factory Registration
     */
    
    /**
     * Register custom provider factory
     */
    fun registerProviderFactory(
        providerType: NfcProviderType,
        factory: () -> INfcProvider
    ) {
        providerFactories[providerType] = factory
        
        NfcProviderFactoryAuditor.logProviderRegistration(
            providerType.displayName,
            "SUCCESS",
            "Total registered: ${providerFactories.size}"
        )
    }
    
    /**
     * Unregister provider factory
     */
    fun unregisterProviderFactory(providerType: NfcProviderType): Boolean {
        val removed = providerFactories.remove(providerType) != null
        
        if (removed) {
            // Clear related cache entries
            detectionCache.remove(providerType)
            
            // Remove provider instances of this type
            val instancesToRemove = providerInstances.filter { (_, provider) ->
                provider.getProviderType() == providerType
            }
            
            instancesToRemove.forEach { (key, provider) ->
                runBlocking { provider.cleanup() }
                providerInstances.remove(key)
            }
            
            NfcProviderFactoryAuditor.logProviderUnregistration(
                providerType.displayName,
                "SUCCESS",
                "Removed ${instancesToRemove.size} instances"
            )
        }
        
        return removed
    }
    
    /**
     * Provider Creation
     */
    
    /**
     * Create provider instance by type
     */
    fun createProvider(providerType: NfcProviderType): INfcProvider {
        val factory = providerFactories[providerType]
        if (factory == null) {
            throw NfcProviderFactoryException(
                "No factory registered for provider type: ${providerType.displayName}",
                context = mapOf(
                    "requested_type" to providerType.name,
                    "available_types" to providerFactories.keys.map { it.name }
                )
            )
        }
        
        val provider = factory()
        createdProviders.incrementAndGet()
        
        NfcProviderFactoryAuditor.logProviderCreation(
            providerType.displayName,
            provider.getProviderVersion(),
            "Total created: ${createdProviders.get()}"
        )
        
        return provider
    }
    
    /**
     * Create managed provider instance with pooling
     */
    fun createManagedProvider(providerType: NfcProviderType): INfcProvider {
        if (!configuration.enableProviderPooling) {
            return createProvider(providerType)
        }
        
        val instanceKey = generateInstanceKey(providerType)
        
        return providerInstances.computeIfAbsent(instanceKey) {
            val provider = createProvider(providerType)
            
            NfcProviderFactoryAuditor.logManagedProviderCreation(
                providerType.displayName,
                instanceKey,
                "Pool size: ${providerInstances.size}"
            )
            
            provider
        }
    }
    
    /**
     * Provider Detection and Selection
     */
    
    /**
     * Detect all available providers
     */
    suspend fun detectAvailableProviders(): List<ProviderDetectionResult> {
        detectionAttempts.incrementAndGet()
        
        NfcProviderFactoryAuditor.logProviderDetection(
            "DETECTION_START",
            providerFactories.size,
            "Parallel: ${configuration.enableParallelDetection}"
        )
        
        val startTime = System.currentTimeMillis()
        
        return try {
            if (configuration.enableParallelDetection) {
                detectProvidersParallel()
            } else {
                detectProvidersSequential()
            }
        } finally {
            val detectionTime = System.currentTimeMillis() - startTime
            NfcProviderFactoryAuditor.logProviderDetection(
                "DETECTION_COMPLETE",
                providerFactories.size,
                "Duration: ${detectionTime}ms"
            )
        }
    }
    
    /**
     * Select optimal provider based on criteria
     */
    suspend fun selectOptimalProvider(
        criteria: ProviderSelectionCriteria = ProviderSelectionCriteria(ProviderSelectionStrategy.PERFORMANCE_OPTIMIZED)
    ): NfcProviderSelectionResult {
        selectionRequests.incrementAndGet()
        
        NfcProviderFactoryAuditor.logProviderSelection(
            "SELECTION_START",
            criteria.strategy.displayName,
            "Excluded: ${criteria.excludedProviders.size}"
        )
        
        val startTime = System.currentTimeMillis()
        
        try {
            // Get available providers
            val availableProviders = detectAvailableProviders()
                .filter { it.isAvailable }
                .filter { !criteria.excludedProviders.contains(it.providerType) }
            
            if (availableProviders.isEmpty()) {
                return NfcProviderSelectionResult(
                    success = false,
                    selectionTime = System.currentTimeMillis() - startTime,
                    error = NfcProviderFactoryException(
                        "No available providers found",
                        context = mapOf("excluded_providers" to criteria.excludedProviders.size)
                    )
                )
            }
            
            // Filter by required features and capabilities
            val compatibleProviders = filterCompatibleProviders(availableProviders, criteria)
            
            if (compatibleProviders.isEmpty()) {
                return NfcProviderSelectionResult(
                    success = false,
                    selectionTime = System.currentTimeMillis() - startTime,
                    availableProviders = availableProviders,
                    error = NfcProviderFactoryException(
                        "No providers meet the specified criteria",
                        context = mapOf(
                            "available_providers" to availableProviders.size,
                            "required_features" to criteria.requiredFeatures.size
                        )
                    )
                )
            }
            
            // Score and rank providers
            val scoredProviders = scoreProviders(compatibleProviders, criteria)
            val selectedProvider = scoredProviders.first()
            
            val selectionTime = System.currentTimeMillis() - startTime
            
            NfcProviderFactoryAuditor.logProviderSelection(
                "SELECTION_SUCCESS",
                selectedProvider.detectionResult.providerType.displayName,
                "Score: ${selectedProvider.totalScore}, Duration: ${selectionTime}ms"
            )
            
            return NfcProviderSelectionResult(
                success = true,
                selectedProvider = selectedProvider.detectionResult,
                totalScore = selectedProvider.totalScore,
                selectionTime = selectionTime,
                availableProviders = availableProviders,
                rankedProviders = scoredProviders.map { it.detectionResult }
            )
            
        } catch (e: Exception) {
            val selectionTime = System.currentTimeMillis() - startTime
            
            NfcProviderFactoryAuditor.logProviderSelection(
                "SELECTION_FAILED",
                criteria.strategy.displayName,
                "Error: ${e.message}"
            )
            
            return NfcProviderSelectionResult(
                success = false,
                selectionTime = selectionTime,
                error = e
            )
        }
    }
    
    /**
     * Create optimal provider based on criteria
     */
    suspend fun createOptimalProvider(
        criteria: ProviderSelectionCriteria = ProviderSelectionCriteria(ProviderSelectionStrategy.PERFORMANCE_OPTIMIZED)
    ): INfcProvider {
        val selectionResult = selectOptimalProvider(criteria)
        
        if (!selectionResult.success || selectionResult.selectedProvider == null) {
            throw NfcProviderFactoryException(
                "Failed to select optimal provider",
                selectionResult.error,
                mapOf("selection_criteria" to criteria.strategy.displayName)
            )
        }
        
        return createManagedProvider(selectionResult.selectedProvider.providerType)
    }
    
    /**
     * Provider Health and Monitoring
     */
    
    /**
     * Perform health check on all managed providers
     */
    suspend fun performHealthCheck(): NfcProviderFactoryHealthResult {
        val startTime = System.currentTimeMillis()
        val healthResults = mutableMapOf<String, Boolean>()
        val issues = mutableListOf<String>()
        
        try {
            // Check factory configuration
            configuration.validate()
            
            // Check managed provider instances
            val healthChecks = providerInstances.map { (key, provider) ->
                async {
                    try {
                        val status = provider.getProviderStatus()
                        val isHealthy = status.isInitialized && status.errorCount < 10
                        healthResults[key] = isHealthy
                        
                        if (!isHealthy) {
                            issues.add("Provider $key unhealthy: errors=${status.errorCount}")
                        }
                        
                        isHealthy
                    } catch (e: Exception) {
                        healthResults[key] = false
                        issues.add("Provider $key health check failed: ${e.message}")
                        false
                    }
                }
            }
            
            val results = healthChecks.awaitAll()
            val healthyProviders = results.count { it }
            
            // Update health check timestamp
            lastHealthCheck.set(System.currentTimeMillis())
            
            val checkDuration = System.currentTimeMillis() - startTime
            val isHealthy = issues.isEmpty()
            
            NfcProviderFactoryAuditor.logHealthCheck(
                if (isHealthy) "HEALTHY" else "UNHEALTHY",
                healthyProviders,
                providerInstances.size,
                "Duration: ${checkDuration}ms, Issues: ${issues.size}"
            )
            
            return NfcProviderFactoryHealthResult(
                isHealthy = isHealthy,
                checkDuration = checkDuration,
                totalProviders = providerInstances.size,
                healthyProviders = healthyProviders,
                issues = issues,
                providerHealth = healthResults,
                timestamp = lastHealthCheck.get()
            )
            
        } catch (e: Exception) {
            val checkDuration = System.currentTimeMillis() - startTime
            
            NfcProviderFactoryAuditor.logHealthCheck(
                "HEALTH_CHECK_FAILED",
                0,
                providerInstances.size,
                "Error: ${e.message}"
            )
            
            return NfcProviderFactoryHealthResult(
                isHealthy = false,
                checkDuration = checkDuration,
                totalProviders = providerInstances.size,
                healthyProviders = 0,
                issues = listOf("Health check failed: ${e.message}"),
                timestamp = System.currentTimeMillis(),
                error = e
            )
        }
    }
    
    /**
     * Resource Management
     */
    
    /**
     * Cleanup all managed providers
     */
    suspend fun cleanup() {
        NfcProviderFactoryAuditor.logFactoryOperation(
            "CLEANUP_START",
            providerInstances.size,
            "Cleaning up all managed providers"
        )
        
        val startTime = System.currentTimeMillis()
        var cleanedProviders = 0
        
        try {
            // Cleanup all managed provider instances
            val cleanupTasks = providerInstances.map { (key, provider) ->
                async {
                    try {
                        provider.cleanup()
                        cleanedProviders++
                        NfcProviderFactoryAuditor.logProviderCleanup(key, "SUCCESS")
                    } catch (e: Exception) {
                        NfcProviderFactoryAuditor.logProviderCleanup(key, "FAILED", e.message.orEmpty())
                    }
                }
            }
            
            cleanupTasks.awaitAll()
            providerInstances.clear()
            
            // Clear detection cache
            detectionCache.clear()
            
            val cleanupTime = System.currentTimeMillis() - startTime
            
            NfcProviderFactoryAuditor.logFactoryOperation(
                "CLEANUP_COMPLETE",
                cleanedProviders,
                "Duration: ${cleanupTime}ms"
            )
            
        } catch (e: Exception) {
            val cleanupTime = System.currentTimeMillis() - startTime
            
            NfcProviderFactoryAuditor.logFactoryOperation(
                "CLEANUP_FAILED",
                cleanedProviders,
                "Error: ${e.message}, Duration: ${cleanupTime}ms"
            )
            
            throw NfcProviderFactoryException(
                "Factory cleanup failed",
                e,
                mapOf("cleaned_providers" to cleanedProviders)
            )
        }
    }
    
    /**
     * Reset factory to initial state
     */
    suspend fun reset() {
        NfcProviderFactoryAuditor.logFactoryOperation(
            "RESET_START",
            providerFactories.size,
            "Resetting factory state"
        )
        
        try {
            // Cleanup existing resources
            cleanup()
            
            // Reset metrics
            createdProviders.set(0)
            detectionAttempts.set(0)
            selectionRequests.set(0)
            lastHealthCheck.set(0)
            
            NfcProviderFactoryAuditor.logFactoryOperation(
                "RESET_COMPLETE",
                providerFactories.size,
                "Factory reset successfully"
            )
            
        } catch (e: Exception) {
            NfcProviderFactoryAuditor.logFactoryOperation(
                "RESET_FAILED",
                providerFactories.size,
                "Error: ${e.message}"
            )
            
            throw NfcProviderFactoryException(
                "Factory reset failed",
                e
            )
        }
    }
    
    // Private helper methods
    
    private suspend fun detectProvidersParallel(): List<ProviderDetectionResult> {
        return withContext(Dispatchers.IO) {
            val detectionTasks = providerFactories.map { (providerType, factory) ->
                async {
                    detectSingleProvider(providerType, factory)
                }
            }
            
            detectionTasks.awaitAll()
        }
    }
    
    private suspend fun detectProvidersSequential(): List<ProviderDetectionResult> {
        return providerFactories.map { (providerType, factory) ->
            detectSingleProvider(providerType, factory)
        }
    }
    
    private suspend fun detectSingleProvider(
        providerType: NfcProviderType,
        factory: () -> INfcProvider
    ): ProviderDetectionResult {
        // Check cache first
        if (configuration.cacheDetectionResults) {
            val cached = detectionCache[providerType]
            if (cached != null && !cached.isExpired()) {
                return cached.result
            }
        }
        
        val startTime = System.currentTimeMillis()
        
        return try {
            val provider = factory()
            val isAvailable = provider.isHardwareAvailable()
            
            val result = if (isAvailable) {
                val capabilities = provider.getCapabilities()
                
                ProviderDetectionResult(
                    providerType = providerType,
                    isAvailable = true,
                    capabilities = capabilities,
                    performanceScore = calculatePerformanceScore(providerType, capabilities),
                    reliabilityScore = calculateReliabilityScore(providerType, capabilities),
                    featureScore = calculateFeatureScore(capabilities),
                    securityScore = calculateSecurityScore(capabilities),
                    compatibilityScore = calculateCompatibilityScore(capabilities),
                    detectionTime = System.currentTimeMillis() - startTime,
                    hardwareVersion = "1.0.0", // Would be retrieved from provider
                    firmwareVersion = "1.0.0"  // Would be retrieved from provider
                )
            } else {
                ProviderDetectionResult(
                    providerType = providerType,
                    isAvailable = false,
                    capabilities = NfcProviderCapabilities(
                        supportedCardTypes = emptySet(),
                        supportedProtocols = emptySet(),
                        maxApduLength = 0,
                        supportsExtendedLength = false,
                        canControlField = false,
                        canSetTimeout = false,
                        supportsBaudRateChange = false,
                        supportsParallelOperations = false,
                        enterpriseFeatures = emptySet()
                    ),
                    performanceScore = 0.0,
                    reliabilityScore = 0.0,
                    featureScore = 0.0,
                    securityScore = 0.0,
                    compatibilityScore = 0.0,
                    detectionTime = System.currentTimeMillis() - startTime
                )
            }
            
            // Cache the result
            if (configuration.cacheDetectionResults) {
                detectionCache[providerType] = CachedDetectionResult(
                    result = result,
                    cacheTime = System.currentTimeMillis(),
                    expiryTime = System.currentTimeMillis() + configuration.cacheExpiryTime
                )
            }
            
            // Cleanup provider after detection
            provider.cleanup()
            
            result
            
        } catch (e: Exception) {
            val detectionTime = System.currentTimeMillis() - startTime
            
            ProviderDetectionResult(
                providerType = providerType,
                isAvailable = false,
                capabilities = NfcProviderCapabilities(
                    supportedCardTypes = emptySet(),
                    supportedProtocols = emptySet(),
                    maxApduLength = 0,
                    supportsExtendedLength = false,
                    canControlField = false,
                    canSetTimeout = false,
                    supportsBaudRateChange = false,
                    supportsParallelOperations = false,
                    enterpriseFeatures = emptySet()
                ),
                performanceScore = 0.0,
                reliabilityScore = 0.0,
                featureScore = 0.0,
                securityScore = 0.0,
                compatibilityScore = 0.0,
                detectionTime = detectionTime,
                detectionError = e
            )
        }
    }
    
    private fun filterCompatibleProviders(
        providers: List<ProviderDetectionResult>,
        criteria: ProviderSelectionCriteria
    ): List<ProviderDetectionResult> {
        return providers.filter { provider ->
            // Check required features
            if (criteria.requiredFeatures.isNotEmpty()) {
                val hasAllFeatures = criteria.requiredFeatures.all { feature ->
                    provider.capabilities.enterpriseFeatures.contains(feature)
                }
                if (!hasAllFeatures) return@filter false
            }
            
            // Check required card types
            if (criteria.requiredCardTypes.isNotEmpty()) {
                val hasAllCardTypes = criteria.requiredCardTypes.all { cardType ->
                    provider.capabilities.supportedCardTypes.contains(cardType)
                }
                if (!hasAllCardTypes) return@filter false
            }
            
            // Check minimum scores
            if (provider.performanceScore < criteria.minimumPerformanceScore) return@filter false
            if (provider.reliabilityScore < criteria.minimumReliabilityScore) return@filter false
            
            true
        }
    }
    
    private fun scoreProviders(
        providers: List<ProviderDetectionResult>,
        criteria: ProviderSelectionCriteria
    ): List<ScoredProvider> {
        val weights = criteria.weightings
        
        return providers.map { provider ->
            val totalScore = (provider.performanceScore * weights.performanceWeight) +
                           (provider.reliabilityScore * weights.reliabilityWeight) +
                           (provider.featureScore * weights.featureWeight) +
                           (provider.securityScore * weights.securityWeight) +
                           (provider.compatibilityScore * weights.compatibilityWeight)
            
            ScoredProvider(provider, totalScore)
        }.sortedByDescending { it.totalScore }
    }
    
    private fun calculatePerformanceScore(
        providerType: NfcProviderType,
        capabilities: NfcProviderCapabilities
    ): Double {
        var score = 0.0
        
        // Base score by provider type (Android internal typically fastest)
        score += when (providerType) {
            NfcProviderType.ANDROID_INTERNAL -> 0.4
            NfcProviderType.PN532_USB -> 0.3
            NfcProviderType.PN532_SPI -> 0.25
            NfcProviderType.PN532_BLUETOOTH -> 0.2
        }
        
        // APDU length score
        score += if (capabilities.maxApduLength >= 256) 0.2 else 0.1
        
        // Extended length support
        score += if (capabilities.supportsExtendedLength) 0.2 else 0.0
        
        // Parallel operations support
        score += if (capabilities.supportsParallelOperations) 0.2 else 0.0
        
        return minOf(1.0, score)
    }
    
    private fun calculateReliabilityScore(
        providerType: NfcProviderType,
        capabilities: NfcProviderCapabilities
    ): Double {
        var score = 0.0
        
        // Base reliability by provider type
        score += when (providerType) {
            NfcProviderType.ANDROID_INTERNAL -> 0.4
            NfcProviderType.PN532_USB -> 0.35
            NfcProviderType.PN532_SPI -> 0.3
            NfcProviderType.PN532_BLUETOOTH -> 0.25
        }
        
        // Field control capability (important for reliability)
        score += if (capabilities.canControlField) 0.3 else 0.0
        
        // Timeout control
        score += if (capabilities.canSetTimeout) 0.2 else 0.0
        
        // Baud rate change support
        score += if (capabilities.supportsBaudRateChange) 0.1 else 0.0
        
        return minOf(1.0, score)
    }
    
    private fun calculateFeatureScore(capabilities: NfcProviderCapabilities): Double {
        var score = 0.0
        
        // Card type support
        score += capabilities.supportedCardTypes.size * 0.1
        
        // Protocol support  
        score += capabilities.supportedProtocols.size * 0.1
        
        // Enterprise features
        score += capabilities.enterpriseFeatures.size * 0.05
        
        return minOf(1.0, score)
    }
    
    private fun calculateSecurityScore(capabilities: NfcProviderCapabilities): Double {
        var score = 0.0
        
        // Base security features
        if (capabilities.enterpriseFeatures.contains("HARDWARE_ENCRYPTION")) score += 0.3
        if (capabilities.enterpriseFeatures.contains("SECURE_MESSAGING")) score += 0.2
        if (capabilities.enterpriseFeatures.contains("TAMPER_DETECTION")) score += 0.2
        if (capabilities.enterpriseFeatures.contains("KEY_DIVERSIFICATION")) score += 0.15
        if (capabilities.enterpriseFeatures.contains("MUTUAL_AUTHENTICATION")) score += 0.15
        
        return minOf(1.0, score)
    }
    
    private fun calculateCompatibilityScore(capabilities: NfcProviderCapabilities): Double {
        val totalPossibleCardTypes = NfcCardType.values().size
        val totalPossibleProtocols = NfcProtocol.values().size
        
        val cardTypeScore = capabilities.supportedCardTypes.size.toDouble() / totalPossibleCardTypes
        val protocolScore = capabilities.supportedProtocols.size.toDouble() / totalPossibleProtocols
        
        return (cardTypeScore + protocolScore) / 2.0
    }
    
    private fun generateInstanceKey(providerType: NfcProviderType): String {
        return "${providerType.name}_${System.currentTimeMillis()}"
    }
    
    // Supporting data classes
    
    private data class CachedDetectionResult(
        val result: ProviderDetectionResult,
        val cacheTime: Long,
        val expiryTime: Long
    ) {
        fun isExpired(): Boolean = System.currentTimeMillis() > expiryTime
    }
    
    private data class ScoredProvider(
        val detectionResult: ProviderDetectionResult,
        val totalScore: Double
    )
}

/**
 * Result Data Classes
 */

/**
 * Provider Selection Result
 */
data class NfcProviderSelectionResult(
    val success: Boolean,
    val selectedProvider: ProviderDetectionResult? = null,
    val totalScore: Double = 0.0,
    val selectionTime: Long,
    val availableProviders: List<ProviderDetectionResult> = emptyList(),
    val rankedProviders: List<ProviderDetectionResult> = emptyList(),
    val error: Throwable? = null
)

/**
 * Factory Statistics
 */
data class NfcProviderFactoryStatistics(
    val registeredProviders: Int,
    val createdProviders: Long,
    val activeInstances: Int,
    val detectionAttempts: Long,
    val selectionRequests: Long,
    val cachedResults: Int,
    val lastHealthCheck: Long
)

/**
 * Factory Health Result
 */
data class NfcProviderFactoryHealthResult(
    val isHealthy: Boolean,
    val checkDuration: Long,
    val totalProviders: Int,
    val healthyProviders: Int,
    val issues: List<String> = emptyList(),
    val providerHealth: Map<String, Boolean> = emptyMap(),
    val timestamp: Long,
    val error: Throwable? = null
)

/**
 * Exception Classes
 */

/**
 * NFC Provider Factory Exception
 */
class NfcProviderFactoryException(
    message: String,
    cause: Throwable? = null,
    val context: Map<String, Any> = emptyMap()
) : Exception(message, cause)

/**
 * Provider Factory Auditor
 * 
 * Enterprise audit logging for NFC provider factory operations
 */
object NfcProviderFactoryAuditor {
    
    fun logFactoryInitialization(version: String, registeredProviders: Int) {
        val timestamp = System.currentTimeMillis()
        println("NFC_PROVIDER_FACTORY_AUDIT: [$timestamp] FACTORY_INIT - version=$version providers=$registeredProviders")
    }
    
    fun logProviderRegistration(providerName: String, status: String, details: String = "") {
        val timestamp = System.currentTimeMillis()
        println("NFC_PROVIDER_FACTORY_AUDIT: [$timestamp] PROVIDER_REGISTRATION - provider=$providerName status=$status details=$details")
    }
    
    fun logProviderUnregistration(providerName: String, status: String, details: String = "") {
        val timestamp = System.currentTimeMillis()
        println("NFC_PROVIDER_FACTORY_AUDIT: [$timestamp] PROVIDER_UNREGISTRATION - provider=$providerName status=$status details=$details")
    }
    
    fun logProviderCreation(providerName: String, version: String, details: String = "") {
        val timestamp = System.currentTimeMillis()
        println("NFC_PROVIDER_FACTORY_AUDIT: [$timestamp] PROVIDER_CREATION - provider=$providerName version=$version details=$details")
    }
    
    fun logManagedProviderCreation(providerName: String, instanceKey: String, details: String = "") {
        val timestamp = System.currentTimeMillis()
        println("NFC_PROVIDER_FACTORY_AUDIT: [$timestamp] MANAGED_PROVIDER_CREATION - provider=$providerName key=$instanceKey details=$details")
    }
    
    fun logProviderDetection(status: String, providerCount: Int, details: String = "") {
        val timestamp = System.currentTimeMillis()
        println("NFC_PROVIDER_FACTORY_AUDIT: [$timestamp] PROVIDER_DETECTION - status=$status count=$providerCount details=$details")
    }
    
    fun logProviderSelection(status: String, strategy: String, details: String = "") {
        val timestamp = System.currentTimeMillis()
        println("NFC_PROVIDER_FACTORY_AUDIT: [$timestamp] PROVIDER_SELECTION - status=$status strategy=$strategy details=$details")
    }
    
    fun logHealthCheck(status: String, healthyCount: Int, totalCount: Int, details: String = "") {
        val timestamp = System.currentTimeMillis()
        println("NFC_PROVIDER_FACTORY_AUDIT: [$timestamp] HEALTH_CHECK - status=$status healthy=$healthyCount total=$totalCount details=$details")
    }
    
    fun logProviderCleanup(instanceKey: String, status: String, details: String = "") {
        val timestamp = System.currentTimeMillis()
        println("NFC_PROVIDER_FACTORY_AUDIT: [$timestamp] PROVIDER_CLEANUP - key=$instanceKey status=$status details=$details")
    }
    
    fun logFactoryOperation(operation: String, count: Int, details: String = "") {
        val timestamp = System.currentTimeMillis()
        println("NFC_PROVIDER_FACTORY_AUDIT: [$timestamp] FACTORY_OPERATION - operation=$operation count=$count details=$details")
    }
}
