plugins {
  alias(libs.plugins.android.library)
  alias(libs.plugins.jetbrains.kotlin.android)
}

android {
  namespace = "com.siriuslee.geist"
  compileSdk = 36
  ndkVersion = "28.2.13676358"

  defaultConfig {
    minSdk = 26
    // The instrumented tests are the point of this module: everything in
    // GeistKeystore.kt touches the real AndroidKeyStore, and a unit test
    // on the JVM would only prove that a mock agrees with itself.
    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    ndk {
      abiFilters += listOf("arm64-v8a", "x86_64")
    }
    externalNativeBuild {
      cmake {
        arguments += "-DANDROID_STL=none"
      }
    }
  }

  externalNativeBuild {
    cmake {
      path = file("src/main/cpp/CMakeLists.txt")
      version = "4.1.2"
    }
  }

  sourceSets {
    getByName("main") {
      kotlin.srcDirs("src/main/kotlin")
    }
    getByName("androidTest") {
      kotlin.srcDirs("src/androidTest/kotlin")
    }
  }

  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
  }

  kotlin {
    compilerOptions {
      jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
  }
}

dependencies {
  implementation(libs.androidx.core.ktx)
  androidTestImplementation(libs.androidx.test.ext.junit)
  androidTestImplementation(libs.androidx.test.runner)
  androidTestImplementation(libs.junit)
}
