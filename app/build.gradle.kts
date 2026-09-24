import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

// Endpoints come from local.properties so a LAN backend can be used for
// testing without editing source, e.g.
//   copyyt.apiUrl=http://192.168.0.121:8000
//   copyyt.socketUrl=http://192.168.0.121:8001
val localProperties = Properties().apply {
    val file = rootProject.file("local.properties")
    if (file.exists()) file.inputStream().use { load(it) }
}
fun endpoint(key: String, fallback: String): String =
    (localProperties.getProperty(key) ?: fallback).trimEnd('/')

android {
    namespace = "com.copyyt.android"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "com.copyyt.android"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        buildConfigField(
            "String",
            "API_URL",
            "\"${endpoint("copyyt.apiUrl", "https://api.copyyt.com")}\"",
        )
        // The OAuth *web* client ID the backend accepts as the ID-token audience
        // (GOOGLE_WEB_CLIENT_ID). Empty hides "Continue with Google".
        buildConfigField(
            "String",
            "GOOGLE_SERVER_CLIENT_ID",
            "\"${localProperties.getProperty("copyyt.googleServerClientId", "").trim()}\"",
        )
        buildConfigField(
            "String",
            "SOCKET_URL",
            "\"${endpoint("copyyt.socketUrl", "https://api.copyyt.com")}\"",
        )
    }

    buildTypes {
        debug {
            // Allows a plain-HTTP LAN backend while testing.
            manifestPlaceholders["usesCleartextTraffic"] = "true"
        }
        release {
            manifestPlaceholders["usesCleartextTraffic"] = "false"
            optimization {
                enable = false
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.okhttp)
    implementation(libs.socket.io.client) {
        exclude(group = "org.json", module = "json")
    }
    implementation(libs.tink.android)
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.credentials.play.services)
    implementation(libs.googleid)
    // Credential Manager drags in an old fragment; activity-result APIs need 1.3+.
    implementation(libs.androidx.fragment)
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.test.runner)
}
