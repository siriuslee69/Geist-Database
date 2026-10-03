// geistvault <- keyrings (src/geist/keyring.nim) for Android apps.
//
//   src/main/nim/geist_vault_bridge.nim  --nim, per ABI-->  build/nimLibs/<abi>/libgeist_vault_nim.so
//   src/main/kotlin/.../GeistVault.kt    --kotlinc------->  the API an app calls
//
// The Nim library exports its JNI functions itself, so there is no C file
// and no CMake step. `nim` must be on PATH (or set -PgeistNim=/path/to/nim).
import java.io.File

plugins {
  alias(libs.plugins.android.library)
  alias(libs.plugins.jetbrains.kotlin.android)
}

val geistNdkVersion = "28.2.13676358"
val geistRoot: File = projectDir.parentFile.parentFile
val nimLibs = layout.buildDirectory.dir("nimLibs")
// ABI -> (NDK clang prefix, Nim cpu name)
val geistAbis = mapOf(
  "arm64-v8a" to ("aarch64-linux-android26" to "arm64"),
  "x86_64" to ("x86_64-linux-android26" to "amd64"),
)

android {
  namespace = "com.siriuslee.geist.vault"
  compileSdk = 36
  ndkVersion = geistNdkVersion

  defaultConfig {
    minSdk = 26
    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    ndk { abiFilters += geistAbis.keys }
  }

  sourceSets {
    getByName("main") {
      kotlin.srcDirs("src/main/kotlin")
      jniLibs.srcDir(nimLibs)
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

// {.role: configurator.}
fun ndkClang(prefix: String): File {
  val sdk = androidComponents.sdkComponents.sdkDirectory.get().asFile
  val host = if (System.getProperty("os.name").startsWith("Windows")) "windows-x86_64" else "linux-x86_64"
  val exe = if (host.startsWith("windows")) "$prefix-clang.cmd" else "$prefix-clang"
  return File(sdk, "ndk/$geistNdkVersion/toolchains/llvm/prebuilt/$host/bin/$exe")
}

// One compile per ABI. Each runs from the Geist root so its config.nims puts
// Tyr, Rune-Pragmas and the other dependencies on the path, exactly as for a
// desktop build. -d:useMalloc: JVM threads never set up Nim's per-thread
// allocator.
val nimTasks = geistAbis.map { (abi, target) ->
  tasks.register<Exec>("buildGeistVaultNim_${abi.replace('-', '_')}") {
    description = "Compile the Nim keyring bridge for $abi"
    val out = nimLibs.map { it.file("$abi/libgeist_vault_nim.so") }
    inputs.dir(File(geistRoot, "src"))
    inputs.dir("src/main/nim")
    outputs.file(out)
    workingDir = geistRoot
    doFirst {
      val clang = ndkClang(target.first)
      if (!clang.exists()) throw GradleException("Android NDK clang not found at ${clang.path}")
      out.get().asFile.parentFile.mkdirs()
      commandLine(
        (findProperty("geistNim") as String?) ?: "nim", "c", "--hints:off",
        "--app:lib", "--os:android", "--cpu:${target.second}", "--cc:clang",
        "--clang.exe:${clang.path}", "--clang.linkerexe:${clang.path}",
        "-d:useMalloc", "-d:release",
        "--nimcache:${layout.buildDirectory.get().asFile.path}/nimcache-$abi",
        "--passL:-Wl,-soname,libgeist_vault_nim.so",
        "--out:${out.get().asFile.path}",
        "android/geistvault/src/main/nim/geist_vault_bridge.nim",
      )
    }
  }
}

tasks.named("preBuild") { dependsOn(nimTasks) }

dependencies {
  androidTestImplementation(libs.androidx.test.ext.junit)
  androidTestImplementation(libs.androidx.test.runner)
  androidTestImplementation(libs.junit)
}
