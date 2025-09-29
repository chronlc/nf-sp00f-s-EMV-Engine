// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    id("com.android.library") version "8.2.0" apply false
    id("org.jetbrains.kotlin.android") version "1.9.20" apply false
    id("kotlinx-serialization") version "1.9.20" apply false
    kotlin("kapt") version "1.9.20" apply false
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}