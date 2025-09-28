# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.kts.

# Keep EMV native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep EMV data classes
-keep class com.nf_sp00f.app.emv.** { *; }

# Keep enum classes for JNI
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Prevent obfuscation of EMV-critical classes
-keep class com.nf_sp00f.app.emv.EmvEngine {
    public <methods>;
}

-keep class com.nf_sp00f.app.emv.EmvTransactionResult {
    public <methods>;
    <init>(...);
}

-keep class com.nf_sp00f.app.emv.EmvTransactionStatus {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

-keep class com.nf_sp00f.app.emv.EmvTransactionType {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

-keep class com.nf_sp00f.app.emv.EmvCardVendor {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}