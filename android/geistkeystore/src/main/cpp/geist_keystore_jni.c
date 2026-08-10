/*
 * geist_keystore_jni.c <- the five symbols geist/keystore.nim imports
 *
 *   Nim (kpAndroid)          this file           Kotlin
 *   ---------------          ---------           ------
 *   geistAndroidPut     ->   JNI call       ->   GeistKeystore.put
 *   geistAndroidGet     ->                  ->   GeistKeystore.get
 *   geistAndroidDrop    ->                  ->   GeistKeystore.drop
 *   geistAndroidStatus  ->                  ->   GeistKeystore.statusOf
 *   geistAndroidAvail.  ->                  ->   GeistKeystore.available
 *
 * WHY THERE IS A C LAYER AT ALL. Nim's `importc` binds to C symbols, and
 * Kotlin's are not C symbols. This is the whole translation and it does
 * nothing else: no policy, no caching, no error interpretation beyond
 * turning "no value" into the negative-status convention.
 *
 * THE NEGATIVE RETURN ON get IS THE POINT. A get that fails has to say
 * WHY, and the one answer that matters is `ksInvalidated` -- the case
 * where retrying is pointless because the platform destroyed the key.
 * Returning -status carries that back in the same int as the byte count,
 * so the Nim side needs no second call and no out-parameter.
 *
 *   >= 0   bytes written into the caller's buffer
 *   -1     ksPresent    (there, but this read failed)
 *   -2     ksInvalidated
 *   -3     ksUnavailable
 *
 * THREADING. `JavaVM` is cached at JNI_OnLoad, which is the only moment
 * the runtime guarantees to call us on a thread that has one. Every entry
 * point attaches the calling thread if it is not already attached, which
 * matters because Nim may call from a thread the JVM has never seen.
 */

#include <jni.h>
#include <string.h>

#define GEIST_KS_CLASS "com/siriuslee/geist/GeistKeystore"

static JavaVM *geistVm = NULL;
static jclass geistClass = NULL;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  JNIEnv *env = NULL;
  jclass local = NULL;
  (void)reserved;
  geistVm = vm;
  if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
    return JNI_ERR;
  }
  /* A local reference dies with this frame, and the class has to outlive
   * it: every later call looks the object up on this cached reference. */
  local = (*env)->FindClass(env, GEIST_KS_CLASS);
  if (local == NULL) {
    return JNI_ERR;
  }
  geistClass = (jclass)(*env)->NewGlobalRef(env, local);
  (*env)->DeleteLocalRef(env, local);
  return JNI_VERSION_1_6;
}

/* Attach if needed. `detach` tells the caller whether it must detach
 * again -- detaching a thread the JVM owns would tear down its stack. */
static JNIEnv *geistEnv(int *detach) {
  JNIEnv *env = NULL;
  *detach = 0;
  if (geistVm == NULL) {
    return NULL;
  }
  if ((*geistVm)->GetEnv(geistVm, (void **)&env, JNI_VERSION_1_6) == JNI_OK) {
    return env;
  }
  if ((*geistVm)->AttachCurrentThread(geistVm, &env, NULL) != JNI_OK) {
    return NULL;
  }
  *detach = 1;
  return env;
}

static void geistRelease(int detach) {
  if (detach && geistVm != NULL) {
    (*geistVm)->DetachCurrentThread(geistVm);
  }
}

/* An exception left pending would be thrown into the next JNI call, which
 * is a crash somewhere unrelated. Every path clears it and reports a
 * failure the ordinary way. */
static int geistFailed(JNIEnv *env) {
  if ((*env)->ExceptionCheck(env)) {
    (*env)->ExceptionDescribe(env);
    (*env)->ExceptionClear(env);
    return 1;
  }
  return 0;
}

int geist_android_ks_available(void) {
  JNIEnv *env = NULL;
  jmethodID m = NULL;
  jboolean r = JNI_FALSE;
  int detach = 0;
  env = geistEnv(&detach);
  if (env == NULL || geistClass == NULL) {
    return 0;
  }
  m = (*env)->GetStaticMethodID(env, geistClass, "available", "()Z");
  if (m == NULL || geistFailed(env)) {
    geistRelease(detach);
    return 0;
  }
  r = (*env)->CallStaticBooleanMethod(env, geistClass, m);
  if (geistFailed(env)) {
    geistRelease(detach);
    return 0;
  }
  geistRelease(detach);
  return r == JNI_TRUE ? 1 : 0;
}

int geist_android_ks_put(const char *name, const unsigned char *data,
                         int len) {
  JNIEnv *env = NULL;
  jmethodID m = NULL;
  jstring jname = NULL;
  jbyteArray jdata = NULL;
  jint r = -1;
  int detach = 0;
  if (name == NULL || data == NULL || len <= 0) {
    return -1;
  }
  env = geistEnv(&detach);
  if (env == NULL || geistClass == NULL) {
    return -1;
  }
  m = (*env)->GetStaticMethodID(env, geistClass, "put",
                                "(Ljava/lang/String;[B)I");
  if (m == NULL || geistFailed(env)) {
    geistRelease(detach);
    return -1;
  }
  jname = (*env)->NewStringUTF(env, name);
  jdata = (*env)->NewByteArray(env, (jsize)len);
  if (jname == NULL || jdata == NULL || geistFailed(env)) {
    geistRelease(detach);
    return -1;
  }
  (*env)->SetByteArrayRegion(env, jdata, 0, (jsize)len, (const jbyte *)data);
  r = (*env)->CallStaticIntMethod(env, geistClass, m, jname, jdata);
  if (geistFailed(env)) {
    r = -1;
  }
  /* The plaintext was copied into a Java array; clear it before the GC
   * can move it somewhere this code can no longer reach. */
  if (jdata != NULL) {
    jbyte *zero = (*env)->GetByteArrayElements(env, jdata, NULL);
    if (zero != NULL) {
      memset(zero, 0, (size_t)len);
      (*env)->ReleaseByteArrayElements(env, jdata, zero, 0);
    }
    (*env)->DeleteLocalRef(env, jdata);
  }
  if (jname != NULL) {
    (*env)->DeleteLocalRef(env, jname);
  }
  geistRelease(detach);
  return (int)r;
}

int geist_android_ks_get(const char *name, unsigned char *out, int cap) {
  JNIEnv *env = NULL;
  jmethodID m = NULL;
  jmethodID s = NULL;
  jstring jname = NULL;
  jbyteArray jout = NULL;
  jsize n = 0;
  jint status = 3;
  int detach = 0;
  int written = 0;
  if (name == NULL || out == NULL || cap <= 0) {
    return -3;
  }
  env = geistEnv(&detach);
  if (env == NULL || geistClass == NULL) {
    return -3;
  }
  m = (*env)->GetStaticMethodID(env, geistClass, "get",
                                "(Ljava/lang/String;)[B");
  s = (*env)->GetStaticMethodID(env, geistClass, "getLastStatus", "()I");
  if (m == NULL || s == NULL || geistFailed(env)) {
    geistRelease(detach);
    return -3;
  }
  jname = (*env)->NewStringUTF(env, name);
  if (jname == NULL || geistFailed(env)) {
    geistRelease(detach);
    return -3;
  }
  jout = (jbyteArray)(*env)->CallStaticObjectMethod(env, geistClass, m, jname);
  if (geistFailed(env)) {
    (*env)->DeleteLocalRef(env, jname);
    geistRelease(detach);
    return -3;
  }
  if (jout == NULL) {
    status = (*env)->CallStaticIntMethod(env, geistClass, s);
    if (geistFailed(env)) {
      status = 3;
    }
    (*env)->DeleteLocalRef(env, jname);
    geistRelease(detach);
    /* 0 (absent) has no negative form that the Nim side reads as absent,
     * and an absent key is not an error worth a status of its own here --
     * it comes back as -1 "present but unreadable" only when the platform
     * said so. Absent maps to -1 as well; the Nim side reports it from
     * the status call, which is the cheap path it uses anyway. */
    return status == 0 ? -1 : -(int)status;
  }
  n = (*env)->GetArrayLength(env, jout);
  if (n > (jsize)cap) {
    (*env)->DeleteLocalRef(env, jout);
    (*env)->DeleteLocalRef(env, jname);
    geistRelease(detach);
    return -3;
  }
  (*env)->GetByteArrayRegion(env, jout, 0, n, (jbyte *)out);
  written = (int)n;
  /* Same reasoning as put: the plaintext is in a Java array now. */
  {
    jbyte *zero = (*env)->GetByteArrayElements(env, jout, NULL);
    if (zero != NULL) {
      memset(zero, 0, (size_t)n);
      (*env)->ReleaseByteArrayElements(env, jout, zero, 0);
    }
  }
  (*env)->DeleteLocalRef(env, jout);
  (*env)->DeleteLocalRef(env, jname);
  geistRelease(detach);
  return written;
}

int geist_android_ks_drop(const char *name) {
  JNIEnv *env = NULL;
  jmethodID m = NULL;
  jstring jname = NULL;
  jint r = -1;
  int detach = 0;
  if (name == NULL) {
    return -1;
  }
  env = geistEnv(&detach);
  if (env == NULL || geistClass == NULL) {
    return -1;
  }
  m = (*env)->GetStaticMethodID(env, geistClass, "drop",
                                "(Ljava/lang/String;)I");
  if (m == NULL || geistFailed(env)) {
    geistRelease(detach);
    return -1;
  }
  jname = (*env)->NewStringUTF(env, name);
  if (jname == NULL || geistFailed(env)) {
    geistRelease(detach);
    return -1;
  }
  r = (*env)->CallStaticIntMethod(env, geistClass, m, jname);
  if (geistFailed(env)) {
    r = -1;
  }
  (*env)->DeleteLocalRef(env, jname);
  geistRelease(detach);
  return (int)r;
}

int geist_android_ks_status(const char *name) {
  JNIEnv *env = NULL;
  jmethodID m = NULL;
  jstring jname = NULL;
  jint r = 3;
  int detach = 0;
  if (name == NULL) {
    return 0;
  }
  env = geistEnv(&detach);
  if (env == NULL || geistClass == NULL) {
    return 3;
  }
  m = (*env)->GetStaticMethodID(env, geistClass, "statusOf",
                                "(Ljava/lang/String;)I");
  if (m == NULL || geistFailed(env)) {
    geistRelease(detach);
    return 3;
  }
  jname = (*env)->NewStringUTF(env, name);
  if (jname == NULL || geistFailed(env)) {
    geistRelease(detach);
    return 3;
  }
  r = (*env)->CallStaticIntMethod(env, geistClass, m, jname);
  if (geistFailed(env)) {
    r = 3;
  }
  (*env)->DeleteLocalRef(env, jname);
  geistRelease(detach);
  return (int)r;
}
