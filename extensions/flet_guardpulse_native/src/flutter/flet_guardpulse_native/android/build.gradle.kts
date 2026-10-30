// Built as a sub-project of Flet's Android host app, which pins the plugin
// versions (Flet 1.0.5 template: AGP 8.11.1, Kotlin 2.2.20). AGP 8 has no
// built-in Kotlin for libraries, so the Kotlin plugin is applied here.
group = "za.co.guardpulse.shield"
version = "0.8.0"

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "za.co.guardpulse.shield"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/kotlin")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

dependencies {
    // Phase 6: "Sign in with Google" (Credential Manager) + the pairing-QR scanner
    implementation("androidx.credentials:credentials:1.3.0")
    implementation("androidx.credentials:credentials-play-services-auth:1.3.0")
    implementation("com.google.android.libraries.identity.googleid:googleid:1.1.1")
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")
}
