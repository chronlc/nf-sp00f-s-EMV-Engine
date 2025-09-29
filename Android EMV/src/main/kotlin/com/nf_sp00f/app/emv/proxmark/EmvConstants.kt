/**
 * nf-sp00f EMV Engine - Enterprise EMV Constants and Definitions
 *
 * Comprehensive EMV constants library with enterprise-grade definitions for:
 * - Complete EMV Books 1-4 compliance constants
 * - ISO 7816 and ISO 14443 protocol definitions
 * - Application Identifiers (AID) and tag definitions
 * - Transaction processing constants and status codes
 * - Cryptographic algorithm identifiers and parameters
 * - Card authentication methods and validation rules
 * - Terminal capabilities and configuration parameters
 * - Risk management thresholds and decision criteria
 *
 * @package com.nf_sp00f.app.emv
 * @author nf-sp00f
 * @since 1.0.0
 */
package com.nf_sp00f.app.emv

/**
 * EMV Application Identifiers (AIDs) - Complete Registry
 */
object EmvAids {
    // Payment System AIDs
    const val VISA = "A0000000031010"
    const val VISA_DEBIT = "A0000000032010"
    const val VISA_ELECTRON = "A0000000032020"
    const val VISA_VPAY = "A0000000032030"
    const val VISA_PLUS = "A0000000038002"
    
    const val MASTERCARD = "A0000000041010"
    const val MASTERCARD_MAESTRO = "A0000000043060"
    const val MASTERCARD_CIRRUS = "A0000000046000"
    const val MASTERCARD_WORLD = "A0000000049999"
    
    const val AMERICAN_EXPRESS = "A000000025010402"
    const val AMERICAN_EXPRESS_CORPORATE = "A000000025010701"
    
    const val DISCOVER = "A0000001523010"
    const val DINERS_CLUB = "A0000001544442"
    const val JCB = "A0000000651010"
    const val UNION_PAY = "A000000333010101"
    
    // Test AIDs
    const val TEST_AID_1 = "315041592E5359532E4444463031"
    const val TEST_AID_2 = "A0000000999999"
    
    val ALL_PAYMENT_AIDS = arrayOf(
        VISA, VISA_DEBIT, VISA_ELECTRON, VISA_VPAY, VISA_PLUS,
        MASTERCARD, MASTERCARD_MAESTRO, MASTERCARD_CIRRUS, MASTERCARD_WORLD,
        AMERICAN_EXPRESS, AMERICAN_EXPRESS_CORPORATE,
        DISCOVER, DINERS_CLUB, JCB, UNION_PAY
    )
}

/**
 * EMV Data Element Tags - Complete EMV Books 1-4 Registry
 */
object EmvTags {
    // Application Selection Tags
    const val AID = "4F"
    const val APPLICATION_LABEL = "50"
    const val TRACK_2_EQUIVALENT_DATA = "57"
    const val APPLICATION_PAN = "5A"
    const val CARDHOLDER_NAME = "5F20"
    const val APPLICATION_EXPIRATION_DATE = "5F24"
    const val APPLICATION_EFFECTIVE_DATE = "5F25"
    const val ISSUER_COUNTRY_CODE = "5F28"
    const val TRANSACTION_CURRENCY_CODE = "5F2A"
    const val LANGUAGE_PREFERENCE = "5F2D"
    const val SERVICE_CODE = "5F30"
    const val APPLICATION_PAN_SEQUENCE_NUMBER = "5F34"
    const val TRANSACTION_CURRENCY_EXPONENT = "5F36"
    
    // Processing Options Tags
    const val PROCESSING_OPTIONS_DATA_OBJECT_LIST = "83"
    const val APPLICATION_INTERCHANGE_PROFILE = "82"
    const val APPLICATION_FILE_LOCATOR = "94"
    
    // Read Application Data Tags
    const val ISSUER_APPLICATION_DATA = "9F10"
    const val APPLICATION_USAGE_CONTROL = "9F07"
    const val APPLICATION_VERSION_NUMBER = "9F08"
    const val CARDHOLDER_VERIFICATION_METHOD_LIST = "8E"
    const val TERMINAL_CAPABILITIES = "9F33"
    const val ADDITIONAL_TERMINAL_CAPABILITIES = "9F40"
    
    // Transaction Processing Tags
    const val AMOUNT_AUTHORIZED = "9F02"
    const val AMOUNT_OTHER = "9F03"
    const val APPLICATION_CRYPTOGRAM = "9F26"
    const val APPLICATION_TRANSACTION_COUNTER = "9F36"
    const val CRYPTOGRAM_INFORMATION_DATA = "9F27"
    const val ISSUER_APPLICATION_DATA_IAD = "9F10"
    const val TERMINAL_VERIFICATION_RESULTS = "95"
    const val TRANSACTION_DATE = "9A"
    const val TRANSACTION_TIME = "9F21"
    const val TRANSACTION_TYPE = "9C"
    const val UNPREDICTABLE_NUMBER = "9F37"
    
    // Authentication Tags
    const val SIGNED_DYNAMIC_APPLICATION_DATA = "9F4B"
    const val INTEGRATED_CIRCUIT_CARD_PIN_ENCIPHERMENT_PUBLIC_KEY_CERTIFICATE = "9F2D"
    const val INTEGRATED_CIRCUIT_CARD_PIN_ENCIPHERMENT_PUBLIC_KEY_EXPONENT = "9F2E"
    const val INTEGRATED_CIRCUIT_CARD_PIN_ENCIPHERMENT_PUBLIC_KEY_REMAINDER = "9F2F"
    const val ISSUER_PUBLIC_KEY_CERTIFICATE = "90"
    const val ISSUER_PUBLIC_KEY_EXPONENT = "9F32"
    const val ISSUER_PUBLIC_KEY_REMAINDER = "92"
    
    // Certificate Authority Tags
    const val CERTIFICATION_AUTHORITY_PUBLIC_KEY_INDEX = "8F"
    const val INTEGRATED_CIRCUIT_CARD_PUBLIC_KEY_CERTIFICATE = "9F46"
    const val INTEGRATED_CIRCUIT_CARD_PUBLIC_KEY_EXPONENT = "9F47"
    const val INTEGRATED_CIRCUIT_CARD_PUBLIC_KEY_REMAINDER = "9F48"
    
    // Terminal Tags
    const val TERMINAL_COUNTRY_CODE = "9F1A"
    const val TERMINAL_IDENTIFICATION = "9F1C"
    const val TERMINAL_TYPE = "9F35"
    const val INTERFACE_DEVICE_SERIAL_NUMBER = "9F1E"
    
    // Online Processing Tags
    const val AUTHORISATION_RESPONSE_CODE = "8A"
    const val AUTHORISATION_CODE = "89"
    const val ISSUER_AUTHENTICATION_DATA = "91"
    const val ISSUER_SCRIPT_TEMPLATE_1 = "71"
    const val ISSUER_SCRIPT_TEMPLATE_2 = "72"
    
    val MANDATORY_DATA_OBJECTS = arrayOf(
        AID, APPLICATION_LABEL, TRACK_2_EQUIVALENT_DATA, APPLICATION_PAN,
        APPLICATION_EXPIRATION_DATE, APPLICATION_INTERCHANGE_PROFILE
    )
    
    val OPTIONAL_DATA_OBJECTS = arrayOf(
        CARDHOLDER_NAME, APPLICATION_EFFECTIVE_DATE, ISSUER_COUNTRY_CODE,
        TRANSACTION_CURRENCY_CODE, LANGUAGE_PREFERENCE, SERVICE_CODE
    )
}

/**
 * EMV Status Words (SW1 SW2) - Complete ISO 7816 Registry
 */
object EmvStatusWords {
    // Success
    const val SW_SUCCESS = 0x9000
    const val SW_SUCCESS_WITH_INFO = 0x9100
    
    // Warning Conditions
    const val SW_MORE_DATA_AVAILABLE = 0x6100
    const val SW_FILE_FILLED_UP = 0x6281
    const val SW_END_OF_FILE = 0x6282
    const val SW_SELECTED_FILE_DEACTIVATED = 0x6283
    const val SW_FILE_CONTROL_INFO_FORMAT_ERROR = 0x6284
    const val SW_SELECTED_FILE_IN_TERMINATION_STATE = 0x6285
    
    // Execution Errors
    const val SW_MEMORY_FAILURE = 0x6581
    
    // Checking Errors - Wrong Length
    const val SW_WRONG_LENGTH = 0x6700
    
    // Checking Errors - Functions in CLA Not Supported
    const val SW_LOGICAL_CHANNEL_NOT_SUPPORTED = 0x6881
    const val SW_SECURE_MESSAGING_NOT_SUPPORTED = 0x6882
    const val SW_LAST_COMMAND_EXPECTED = 0x6883
    const val SW_COMMAND_CHAINING_NOT_SUPPORTED = 0x6884
    
    // Checking Errors - Command Not Allowed
    const val SW_COMMAND_NOT_ALLOWED = 0x6986
    const val SW_EXPECTED_SM_DATA_OBJECTS_MISSING = 0x6987
    const val SW_SM_DATA_OBJECTS_INCORRECT = 0x6988
    
    // Checking Errors - Wrong Parameters
    const val SW_INCORRECT_PARAMETERS_P1_P2 = 0x6A86
    const val SW_LC_INCONSISTENT_WITH_P1_P2 = 0x6A87
    const val SW_REFERENCED_DATA_NOT_FOUND = 0x6A88
    const val SW_FILE_ALREADY_EXISTS = 0x6A89
    const val SW_DF_NAME_ALREADY_EXISTS = 0x6A8A
    
    // Checking Errors - Wrong Parameters P1-P2
    const val SW_WRONG_PARAMETERS_P1_P2 = 0x6B00
    
    // Checking Errors - Wrong Le Field
    const val SW_WRONG_LE_FIELD = 0x6C00
    
    // Checking Errors - Instruction Code Not Supported
    const val SW_INS_NOT_SUPPORTED = 0x6D00
    
    // Checking Errors - Class Not Supported
    const val SW_CLA_NOT_SUPPORTED = 0x6E00
    
    // Checking Errors - No Precise Diagnosis
    const val SW_NO_PRECISE_DIAGNOSIS = 0x6F00
    
    // Application Errors
    const val SW_PIN_VERIFICATION_REQUIRED = 0x6982
    const val SW_PIN_BLOCKED = 0x6983
    const val SW_DATA_INVALID = 0x6984
    const val SW_CONDITIONS_NOT_SATISFIED = 0x6985
    const val SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982
    const val SW_AUTHENTICATION_METHOD_BLOCKED = 0x6983
    const val SW_DATA_OBJECT_NOT_FOUND = 0x6A82
    const val SW_FILE_NOT_FOUND = 0x6A82
    
    val SUCCESS_STATUS_WORDS = arrayOf(SW_SUCCESS, SW_SUCCESS_WITH_INFO)
    val WARNING_STATUS_WORDS = arrayOf(SW_MORE_DATA_AVAILABLE, SW_FILE_FILLED_UP, SW_END_OF_FILE)
    val ERROR_STATUS_WORDS = arrayOf(SW_WRONG_LENGTH, SW_COMMAND_NOT_ALLOWED, SW_INCORRECT_PARAMETERS_P1_P2)
}

/**
 * EMV Command Instructions - Complete ISO 7816-4 Registry
 */
object EmvInstructions {
    // Application and File Management
    const val INS_SELECT = 0xA4.toByte()
    const val INS_READ_BINARY = 0xB0.toByte()
    const val INS_UPDATE_BINARY = 0xD6.toByte()
    const val INS_READ_RECORD = 0xB2.toByte()
    const val INS_UPDATE_RECORD = 0xDC.toByte()
    const val INS_APPEND_RECORD = 0xE2.toByte()
    
    // Basic Security Commands
    const val INS_VERIFY = 0x20.toByte()
    const val INS_MANAGE_CHANNEL = 0x70.toByte()
    const val INS_EXTERNAL_AUTHENTICATE = 0x82.toByte()
    const val INS_GET_CHALLENGE = 0x84.toByte()
    const val INS_INTERNAL_AUTHENTICATE = 0x88.toByte()
    
    // EMV Specific Commands
    const val INS_GET_PROCESSING_OPTIONS = 0xA8.toByte()
    const val INS_GENERATE_AC = 0xAE.toByte()
    const val INS_GET_DATA = 0xCA.toByte()
    const val INS_PUT_DATA = 0xDA.toByte()
    
    // Proprietary Commands
    const val INS_PIN_CHANGE_UNBLOCK = 0x24.toByte()
    const val INS_APPLICATION_BLOCK = 0x1E.toByte()
    const val INS_APPLICATION_UNBLOCK = 0x18.toByte()
    const val INS_CARD_BLOCK = 0x16.toByte()
    
    val MANDATORY_INSTRUCTIONS = arrayOf(INS_SELECT, INS_READ_RECORD, INS_GET_PROCESSING_OPTIONS, INS_GENERATE_AC)
    val OPTIONAL_INSTRUCTIONS = arrayOf(INS_VERIFY, INS_GET_DATA, INS_GET_CHALLENGE, INS_INTERNAL_AUTHENTICATE)
}

/**
 * EMV Class Bytes (CLA) - Complete ISO 7816-4 Registry
 */
object EmvClassBytes {
    const val CLA_ISO7816 = 0x00.toByte()
    const val CLA_PROPRIETARY_1X = 0x80.toByte()
    const val CLA_PROPRIETARY_2X = 0x90.toByte()
    const val CLA_PROPRIETARY_3X = 0xA0.toByte()
    const val CLA_PROPRIETARY_4X = 0xB0.toByte()
    
    // EMV Specific Class Bytes
    const val CLA_EMV_PROPRIETARY = 0x80.toByte()
    const val CLA_EMV_INTERINDUSTRY = 0x00.toByte()
    
    // Secure Messaging Indicators
    const val CLA_SM_PROPRIETARY = 0x84.toByte()
    const val CLA_SM_INTERINDUSTRY = 0x04.toByte()
    
    val STANDARD_CLASS_BYTES = arrayOf(CLA_ISO7816, CLA_EMV_PROPRIETARY, CLA_EMV_INTERINDUSTRY)
}

/**
 * EMV Transaction Types - Complete EMV Books Registry
 */
object EmvTransactionTypes {
    const val TRANSACTION_TYPE_PURCHASE = 0x00.toByte()
    const val TRANSACTION_TYPE_CASH_ADVANCE = 0x01.toByte()
    const val TRANSACTION_TYPE_CASHBACK = 0x09.toByte()
    const val TRANSACTION_TYPE_PAYMENT = 0x20.toByte()
    const val TRANSACTION_TYPE_INQUIRY = 0x30.toByte()
    const val TRANSACTION_TYPE_TRANSFER = 0x40.toByte()
    const val TRANSACTION_TYPE_ADMINISTRATIVE = 0x60.toByte()
    const val TRANSACTION_TYPE_CASH_DEPOSIT = 0x21.toByte()
    const val TRANSACTION_TYPE_REFUND = 0x20.toByte()
    
    val SUPPORTED_TRANSACTION_TYPES = arrayOf(
        TRANSACTION_TYPE_PURCHASE, TRANSACTION_TYPE_CASH_ADVANCE, 
        TRANSACTION_TYPE_CASHBACK, TRANSACTION_TYPE_REFUND,
        TRANSACTION_TYPE_INQUIRY
    )
}

/**
 * EMV Cryptogram Types - Application Cryptogram Processing
 */
object EmvCryptogramTypes {
    const val AC_AAC = 0x00  // Application Authentication Cryptogram (Decline)
    const val AC_TC = 0x40   // Transaction Certificate (Approve Offline)
    const val AC_ARQC = 0x80 // Authorization Request Cryptogram (Go Online)
    const val AC_RFU = 0xC0  // Reserved for Future Use
    
    val VALID_CRYPTOGRAM_TYPES = arrayOf(AC_AAC, AC_TC, AC_ARQC)
}

/**
 * EMV Cardholder Verification Methods (CVM) - Complete Registry
 */
object EmvCardholderVerificationMethods {
    // CVM Codes
    const val CVM_FAIL = 0x00
    const val CVM_PLAINTEXT_PIN_VERIFICATION_BY_ICC = 0x01
    const val CVM_ENCIPHERED_PIN_VERIFICATION_ONLINE = 0x02
    const val CVM_PLAINTEXT_PIN_VERIFICATION_BY_ICC_AND_SIGNATURE = 0x03
    const val CVM_ENCIPHERED_PIN_VERIFICATION_BY_ICC = 0x04
    const val CVM_ENCIPHERED_PIN_VERIFICATION_BY_ICC_AND_SIGNATURE = 0x05
    const val CVM_SIGNATURE = 0x1E
    const val CVM_NO_CVM_REQUIRED = 0x1F
    
    // CVM Conditions
    const val CVM_CONDITION_ALWAYS = 0x00
    const val CVM_CONDITION_IF_UNATTENDED_CASH = 0x01
    const val CVM_CONDITION_IF_NOT_UNATTENDED_CASH_AND_NOT_MANUAL_CASH_AND_NOT_PURCHASE_WITH_CASHBACK = 0x02
    const val CVM_CONDITION_IF_TERMINAL_SUPPORTS_CVM = 0x03
    const val CVM_CONDITION_IF_MANUAL_CASH = 0x04
    const val CVM_CONDITION_IF_PURCHASE_WITH_CASHBACK = 0x05
    const val CVM_CONDITION_IF_TRANSACTION_CURRENCY_AND_UNDER_X = 0x06
    const val CVM_CONDITION_IF_TRANSACTION_CURRENCY_AND_OVER_X = 0x07
    const val CVM_CONDITION_IF_TRANSACTION_CURRENCY_AND_UNDER_Y = 0x08
    const val CVM_CONDITION_IF_TRANSACTION_CURRENCY_AND_OVER_Y = 0x09
    
    val SUPPORTED_CVM_METHODS = arrayOf(
        CVM_PLAINTEXT_PIN_VERIFICATION_BY_ICC,
        CVM_ENCIPHERED_PIN_VERIFICATION_ONLINE,
        CVM_SIGNATURE,
        CVM_NO_CVM_REQUIRED
    )
}

/**
 * EMV Terminal Capabilities - Comprehensive Terminal Configuration
 */
object EmvTerminalCapabilities {
    // Terminal Type
    const val TERMINAL_TYPE_OFFLINE_ONLY = 0x11
    const val TERMINAL_TYPE_ONLINE_ONLY = 0x12
    const val TERMINAL_TYPE_OFFLINE_WITH_ONLINE_CAPABILITY = 0x21
    const val TERMINAL_TYPE_ONLINE_WITH_OFFLINE_CAPABILITY = 0x22
    
    // Data Input Capability
    const val DATA_INPUT_MANUAL_KEY_ENTRY = 0x80
    const val DATA_INPUT_MAGNETIC_STRIPE = 0x40
    const val DATA_INPUT_IC_WITH_CONTACTS = 0x20
    
    // CVM Capability
    const val CVM_CAPABILITY_PLAINTEXT_PIN_ICC = 0x80
    const val CVM_CAPABILITY_ENCIPHERED_PIN_ONLINE = 0x40
    const val CVM_CAPABILITY_SIGNATURE = 0x20
    const val CVM_CAPABILITY_ENCIPHERED_PIN_OFFLINE = 0x10
    const val CVM_CAPABILITY_NO_CVM_REQUIRED = 0x08
    
    // Security Capability
    const val SECURITY_CAPABILITY_SDA = 0x80
    const val SECURITY_CAPABILITY_DDA = 0x40
    const val SECURITY_CAPABILITY_CARD_CAPTURE = 0x20
    const val SECURITY_CAPABILITY_CDA = 0x08
    
    val DEFAULT_TERMINAL_CAPABILITIES = byteArrayOf(
        (DATA_INPUT_IC_WITH_CONTACTS or DATA_INPUT_MAGNETIC_STRIPE).toByte(),
        (CVM_CAPABILITY_PLAINTEXT_PIN_ICC or CVM_CAPABILITY_SIGNATURE).toByte(),
        (SECURITY_CAPABILITY_SDA or SECURITY_CAPABILITY_DDA or SECURITY_CAPABILITY_CDA).toByte()
    )
}

/**
 * EMV Application Interchange Profile (AIP) - Card Capabilities
 */
object EmvApplicationInterchangeProfile {
    // Byte 1
    const val AIP_SDA_SUPPORTED = 0x40
    const val AIP_DDA_SUPPORTED = 0x20
    const val AIP_CARDHOLDER_VERIFICATION_SUPPORTED = 0x10
    const val AIP_TERMINAL_RISK_MANAGEMENT_PERFORMED = 0x08
    const val AIP_ISSUER_AUTHENTICATION_SUPPORTED = 0x04
    const val AIP_ON_DEVICE_CARDHOLDER_VERIFICATION_SUPPORTED = 0x02
    const val AIP_CDA_SUPPORTED = 0x01
    
    // Byte 2
    const val AIP_MOBILE_FUNCTIONALITY_SUPPORTED = 0x80
    
    val MINIMUM_REQUIRED_AIP = (AIP_SDA_SUPPORTED or AIP_CARDHOLDER_VERIFICATION_SUPPORTED).toByte()
}

/**
 * EMV Currency Codes - ISO 4217 Numeric Codes
 */
object EmvCurrencyCodes {
    const val USD = 840 // US Dollar
    const val EUR = 978 // Euro
    const val GBP = 826 // British Pound Sterling
    const val JPY = 392 // Japanese Yen
    const val CAD = 124 // Canadian Dollar
    const val AUD = 36  // Australian Dollar
    const val CHF = 756 // Swiss Franc
    const val CNY = 156 // Chinese Yuan
    const val SEK = 752 // Swedish Krona
    const val NOK = 578 // Norwegian Krone
    const val DKK = 208 // Danish Krone
    
    val MAJOR_CURRENCY_CODES = arrayOf(USD, EUR, GBP, JPY, CAD, AUD)
}

/**
 * EMV Country Codes - ISO 3166-1 Numeric Codes
 */
object EmvCountryCodes {
    const val UNITED_STATES = 840
    const val CANADA = 124
    const val UNITED_KINGDOM = 826
    const val GERMANY = 276
    const val FRANCE = 250
    const val ITALY = 380
    const val SPAIN = 724
    const val JAPAN = 392
    const val AUSTRALIA = 36
    const val BRAZIL = 76
    const val CHINA = 156
    
    val SUPPORTED_COUNTRY_CODES = arrayOf(
        UNITED_STATES, CANADA, UNITED_KINGDOM, GERMANY, 
        FRANCE, JAPAN, AUSTRALIA
    )
}

/**
 * EMV Risk Management Thresholds - Enterprise Risk Configuration
 */
object EmvRiskManagement {
    // Floor Limits
    const val DEFAULT_FLOOR_LIMIT = 5000L // $50.00
    const val HIGH_VALUE_THRESHOLD = 25000L // $250.00
    const val MAXIMUM_OFFLINE_LIMIT = 100000L // $1000.00
    
    // Velocity Checking
    const val MAXIMUM_CONSECUTIVE_OFFLINE_TRANSACTIONS = 5
    const val MAXIMUM_OFFLINE_AMOUNT_ACCUMULATED = 50000L // $500.00
    
    // Random Transaction Selection
    const val RANDOM_SELECTION_PERCENTAGE = 10 // 10%
    const val RANDOM_SELECTION_THRESHOLD = 1000L // $10.00
    
    // Authentication Failure Limits
    const val MAXIMUM_PIN_TRIES = 3
    const val MAXIMUM_OFFLINE_PIN_TRIES = 3
    const val CARD_AUTHENTICATION_FAILURE_THRESHOLD = 2
    
    val DEFAULT_RISK_PARAMETERS = mapOf(
        "floor_limit" to DEFAULT_FLOOR_LIMIT,
        "max_consecutive_offline" to MAXIMUM_CONSECUTIVE_OFFLINE_TRANSACTIONS,
        "random_selection_percentage" to RANDOM_SELECTION_PERCENTAGE,
        "max_pin_tries" to MAXIMUM_PIN_TRIES
    )
}

/**
 * EMV Cryptographic Algorithm Identifiers
 */
object EmvCryptographicAlgorithms {
    // RSA Key Lengths
    const val RSA_KEY_LENGTH_1024 = 1024
    const val RSA_KEY_LENGTH_1152 = 1152
    const val RSA_KEY_LENGTH_1408 = 1408
    const val RSA_KEY_LENGTH_1536 = 1536
    const val RSA_KEY_LENGTH_1984 = 1984
    const val RSA_KEY_LENGTH_2048 = 2048
    
    // Hash Algorithms
    const val HASH_ALGORITHM_SHA1 = 0x01
    const val HASH_ALGORITHM_SHA224 = 0x02
    const val HASH_ALGORITHM_SHA256 = 0x03
    const val HASH_ALGORITHM_SHA384 = 0x04
    const val HASH_ALGORITHM_SHA512 = 0x05
    
    // Padding Schemes
    const val PADDING_SCHEME_ISO9796_2 = 0x01
    const val PADDING_SCHEME_PKCS1_V1_5 = 0x02
    const val PADDING_SCHEME_PSS = 0x03
    
    val SUPPORTED_RSA_KEY_LENGTHS = arrayOf(
        RSA_KEY_LENGTH_1024, RSA_KEY_LENGTH_1152, RSA_KEY_LENGTH_1408,
        RSA_KEY_LENGTH_1536, RSA_KEY_LENGTH_1984, RSA_KEY_LENGTH_2048
    )
    
    val SUPPORTED_HASH_ALGORITHMS = arrayOf(
        HASH_ALGORITHM_SHA1, HASH_ALGORITHM_SHA256, HASH_ALGORITHM_SHA512
    )
}

/**
 * EMV Processing Timeouts - Enterprise Performance Configuration
 */
object EmvProcessingTimeouts {
    const val CARD_CONNECTION_TIMEOUT_MS = 10000L
    const val APDU_RESPONSE_TIMEOUT_MS = 30000L
    const val AUTHENTICATION_TIMEOUT_MS = 60000L
    const val ONLINE_AUTHORIZATION_TIMEOUT_MS = 120000L
    const val TRANSACTION_COMPLETION_TIMEOUT_MS = 180000L
    
    // Retry Configuration
    const val MAXIMUM_RETRY_ATTEMPTS = 3
    const val RETRY_DELAY_MS = 1000L
    const val EXPONENTIAL_BACKOFF_MULTIPLIER = 2.0
    
    val DEFAULT_TIMEOUT_CONFIGURATION = mapOf(
        "card_connection" to CARD_CONNECTION_TIMEOUT_MS,
        "apdu_response" to APDU_RESPONSE_TIMEOUT_MS,
        "authentication" to AUTHENTICATION_TIMEOUT_MS,
        "online_authorization" to ONLINE_AUTHORIZATION_TIMEOUT_MS,
        "transaction_completion" to TRANSACTION_COMPLETION_TIMEOUT_MS
    )
}

/**
 * EMV Error Codes - Comprehensive Error Classification
 */
object EmvErrorCodes {
    // Application Selection Errors
    const val ERROR_APPLICATION_NOT_FOUND = "EMV_E001"
    const val ERROR_APPLICATION_BLOCKED = "EMV_E002"
    const val ERROR_APPLICATION_NOT_SUPPORTED = "EMV_E003"
    
    // Transaction Processing Errors
    const val ERROR_TRANSACTION_DECLINED = "EMV_E100"
    const val ERROR_INSUFFICIENT_FUNDS = "EMV_E101"
    const val ERROR_TRANSACTION_NOT_PERMITTED = "EMV_E102"
    const val ERROR_AMOUNT_LIMIT_EXCEEDED = "EMV_E103"
    
    // Authentication Errors
    const val ERROR_CARD_AUTHENTICATION_FAILED = "EMV_E200"
    const val ERROR_CARDHOLDER_VERIFICATION_FAILED = "EMV_E201"
    const val ERROR_PIN_VERIFICATION_FAILED = "EMV_E202"
    const val ERROR_PIN_BLOCKED = "EMV_E203"
    
    // Communication Errors
    const val ERROR_CARD_NOT_PRESENT = "EMV_E300"
    const val ERROR_CARD_COMMUNICATION_FAILURE = "EMV_E301"
    const val ERROR_CARD_MUTE = "EMV_E302"
    const val ERROR_APDU_TRANSMISSION_FAILED = "EMV_E303"
    
    // Configuration Errors
    const val ERROR_TERMINAL_NOT_CONFIGURED = "EMV_E400"
    const val ERROR_INVALID_TERMINAL_CAPABILITIES = "EMV_E401"
    const val ERROR_MISSING_MANDATORY_DATA = "EMV_E402"
    
    val CRITICAL_ERROR_CODES = arrayOf(
        ERROR_CARD_COMMUNICATION_FAILURE, ERROR_CARD_MUTE,
        ERROR_TERMINAL_NOT_CONFIGURED, ERROR_MISSING_MANDATORY_DATA
    )
}

/**
 * EMV Data Object Lengths - Validation Parameters
 */
object EmvDataObjectLengths {
    // Fixed Length Objects
    const val AID_MIN_LENGTH = 5
    const val AID_MAX_LENGTH = 16
    const val PAN_MIN_LENGTH = 12
    const val PAN_MAX_LENGTH = 19
    const val TRACK2_MIN_LENGTH = 13
    const val TRACK2_MAX_LENGTH = 37
    
    // Variable Length Objects
    const val APPLICATION_LABEL_MAX_LENGTH = 16
    const val CARDHOLDER_NAME_MAX_LENGTH = 26
    const val ISSUER_APPLICATION_DATA_MAX_LENGTH = 32
    
    // Cryptographic Object Lengths
    const val UNPREDICTABLE_NUMBER_LENGTH = 4
    const val APPLICATION_CRYPTOGRAM_LENGTH = 8
    const val AUTHORIZATION_CODE_LENGTH = 6
    
    val VALIDATION_RULES = mapOf(
        EmvTags.AID to (AID_MIN_LENGTH to AID_MAX_LENGTH),
        EmvTags.APPLICATION_PAN to (PAN_MIN_LENGTH to PAN_MAX_LENGTH),
        EmvTags.TRACK_2_EQUIVALENT_DATA to (TRACK2_MIN_LENGTH to TRACK2_MAX_LENGTH),
        EmvTags.APPLICATION_LABEL to (1 to APPLICATION_LABEL_MAX_LENGTH),
        EmvTags.CARDHOLDER_NAME to (1 to CARDHOLDER_NAME_MAX_LENGTH)
    )
}

/**
 * EMV Version Information - Compliance and Compatibility
 */
object EmvVersionInformation {
    const val EMV_SPECIFICATION_VERSION = "4.3"
    const val SUPPORTED_EMV_BOOKS = arrayOf("Book 1", "Book 2", "Book 3", "Book 4")
    const val MINIMUM_EMV_VERSION = "4.0"
    const val MAXIMUM_EMV_VERSION = "4.3"
    
    // Application Version Numbers
    const val APPLICATION_VERSION_1_0 = byteArrayOf(0x00, 0x10)
    const val APPLICATION_VERSION_1_4 = byteArrayOf(0x00, 0x14)
    const val APPLICATION_VERSION_2_0 = byteArrayOf(0x00, 0x20)
    
    val SUPPORTED_APPLICATION_VERSIONS = arrayOf(
        APPLICATION_VERSION_1_0, APPLICATION_VERSION_1_4, APPLICATION_VERSION_2_0
    )
}

/**
 * EMV Engine Configuration - Enterprise Default Parameters
 */
object EmvEngineConfiguration {
    const val ENGINE_VERSION = "1.0.0"
    const val ENGINE_NAME = "nf-sp00f EMV Engine"
    const val ENGINE_VENDOR = "nf-sp00f"
    
    // Performance Configuration
    const val DEFAULT_THREAD_POOL_SIZE = 4
    const val MAXIMUM_CONCURRENT_TRANSACTIONS = 10
    const val MEMORY_CACHE_SIZE_MB = 64
    const val AUDIT_LOG_RETENTION_DAYS = 90
    
    // Security Configuration
    const val ENABLE_ROCA_VULNERABILITY_CHECK = true
    const val ENABLE_COMPREHENSIVE_LOGGING = true
    const val ENABLE_PERFORMANCE_MONITORING = true
    const val ENABLE_ENTERPRISE_VALIDATION = true
    
    val DEFAULT_ENGINE_PARAMETERS = mapOf(
        "thread_pool_size" to DEFAULT_THREAD_POOL_SIZE,
        "max_concurrent_transactions" to MAXIMUM_CONCURRENT_TRANSACTIONS,
        "memory_cache_size_mb" to MEMORY_CACHE_SIZE_MB,
        "audit_retention_days" to AUDIT_LOG_RETENTION_DAYS,
        "enable_roca_check" to ENABLE_ROCA_VULNERABILITY_CHECK,
        "enable_logging" to ENABLE_COMPREHENSIVE_LOGGING,
        "enable_monitoring" to ENABLE_PERFORMANCE_MONITORING,
        "enable_validation" to ENABLE_ENTERPRISE_VALIDATION
    )
}
