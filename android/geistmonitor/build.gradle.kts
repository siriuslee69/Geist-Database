// Standalone device monitor; all networking lives in the shared Nim Geist client.
import java.io.File
plugins {
  id("com.android.application")
  alias(libs.plugins.jetbrains.kotlin.android)
}
val geistRoot = projectDir.parentFile.parentFile
val nimLibs = layout.buildDirectory.dir("nimLibs")
val ndkRelease = "28.2.13676358"
android {
  namespace = "com.siriuslee.geist.monitor"
  compileSdk = 36
  ndkVersion = ndkRelease
  defaultConfig {
    applicationId = "com.siriuslee.geist.monitor"
    minSdk = 26
    targetSdk = 35
    versionCode = 1
    versionName = "1.0"
    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    ndk { abiFilters += "arm64-v8a" }
  }
  sourceSets.getByName("main").jniLibs.srcDir(nimLibs)
  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
  }
  kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
}
val buildNim by tasks.registering(Exec::class) {
  inputs.dir(File(geistRoot, "src"))
  inputs.dir(File(geistRoot, "assets/monitor"))
  inputs.dir("src/main/nim")
  inputs.dir(File(geistRoot, "submodules/Bifrost-ExchangeProtocols/src"))
  inputs.dir(File(geistRoot, "submodules/Tyr-Crypto/src"))
  val output = nimLibs.map { it.file("arm64-v8a/libgeist_monitor.so") }
  outputs.file(output)
  workingDir = geistRoot
  doFirst {
    val sdk = androidComponents.sdkComponents.sdkDirectory.get().asFile
    val clang = File(sdk, "ndk/$ndkRelease/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang")
    output.get().asFile.parentFile.mkdirs()
    commandLine("nim", "c", "--hints:off", "--app:lib", "--os:android", "--cpu:arm64",
      "--cc:clang", "--clang.exe:${clang.path}", "--clang.linkerexe:${clang.path}",
      "-d:preset=android", "-d:useMalloc", "-d:release", "-d:bifrostHandshakes=am1ps", "-d:bifrostCarriers=dac",
      "--nimcache:${layout.buildDirectory.get().asFile}/nimcache-arm64",
      "--passL:-Wl,-soname,libgeist_monitor.so", "--out:${output.get().asFile}",
      "android/geistmonitor/src/main/nim/geist_monitor_bridge.nim")
  }
}
tasks.named("preBuild") { dependsOn(buildNim) }
dependencies {
  implementation(project(":geistkeystore"))
  androidTestImplementation(libs.androidx.test.ext.junit)
  androidTestImplementation(libs.androidx.test.runner)
  androidTestImplementation(libs.junit)
}
