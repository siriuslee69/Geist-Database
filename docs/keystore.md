# The keystore: where a key actually lives

A desktop can seal a master key in a file and be done. A phone cannot:
the app is backgrounded, killed and restarted constantly, and the only
place on Android where a key is genuinely protected is the Keystore —
which never hands the key material back at all. It wraps and unwraps on
your behalf, inside hardware you cannot read.

So `geist/keystore.nim` is not "a file, but on Android". The two
providers have genuinely different shapes, and the API is the
**intersection of what both can honestly do**.

```
   openKeystore(dir, password, want)
        |
        +-- want available?  --yes-->  use it
        |                    --no -->  fall back to kpFile,
        |                              and RECORD that it happened
        v
   put / get / drop / status / names
```

| provider | where the bytes are | needs a password |
|---|---|---|
| `kpFile` | an Argon2id-sealed file, one per entry | yes |
| `kpAndroid` | the platform keystore; the raw key never leaves hardware | no |
| `kpMemory` | this process only; nothing is written | no |

---

## The four statuses, and why there are four

```
  ksAbsent        never stored, or dropped
  ksPresent       there, and retrievable
  ksInvalidated   there, and PERMANENTLY unreadable
  ksUnavailable   the provider cannot answer right now
```

`ksInvalidated` is the whole reason this is an enum and not a bool.

When a phone's owner adds a fingerprint or changes the screen lock,
Android **destroys** every key bound to biometrics. The bytes are gone.
No password recovers them, and re-enrolling the same fingerprint does not
bring them back.

Without a distinct status, that surfaces as a decrypt failure — and a
password manager that says *wrong password* to someone whose password is
right will have them typing it for an hour before they give up. The
message the module returns says so in as many words:

> permanently unreadable: the device destroyed the key that protected it,
> usually because the screen lock or fingerprints changed. It has to be
> set up again.

`ksUnavailable` is the opposite: the device is locked, the hardware is
busy, there is no runtime. **Try again** is a reasonable response, and
that is exactly what separates it from `ksInvalidated`.

---

## A downgrade is a value, not a silent decision

```nim
var k = openKeystore(dir, password, kpAndroid)
if k.downgraded():
  warn("Your keys are stored as " & describeProvider(k.provider) &
       " rather than in hardware.")
```

`openKeystore` never fails. A request for `kpAndroid` on a device that
cannot provide it comes back as `kpFile` with `note` explaining why,
because the alternative — refusing to open — turns *your keys are less
protected than you asked for* into *the app does not start*.

But it is **recorded**. `requested` and `provider` are both fields, and
`downgraded()` is the single comparison, so no application has to reason
about platform availability to know whether to warn.

---

## What is actually in hardware

AndroidKeyStore stores **keys**, not arbitrary blobs. So one entry is two
pieces:

```
   AndroidKeyStore                    app-private files
   ---------------                    -----------------
   alias "geist:master"        --->   master.blob = iv | ciphertext
   AES-256-GCM, non-exportable,              sealed with that key
   hardware-backed where available
```

The **wrapping key** never leaves hardware and cannot be read by this
process or any other — `KeyStore.getKey(...).encoded` is `null`, which
the on-device test asserts. The blob beside it is worthless without that
key, and is destroyed with it.

That last sentence is the whole `ksInvalidated` story: a blob whose key
the platform has destroyed is exactly what a fingerprint enrolment leaves
behind, and `statusOf` reports it as invalidated rather than as a failed
decrypt.

---

## What is implemented, and what is a seam

Stated plainly, because the difference matters:

| part | state |
|---|---|
| `kpFile` | complete, tested (`tests/test_keystore.nim`) |
| `kpMemory` | complete, tested |
| the fallback and downgrade reporting | complete, tested |
| the status vocabulary and its messages | complete, tested |
| `GeistKeystore.kt` — the companion | complete, `android/geistkeystore/` |
| `geist_keystore_jni.c` — the shim | complete; the arm64 `.so` exports all five symbols |
| the 15 on-device tests | **run on hardware, 15 passed, 0 failed** |
| `kpAndroid` end to end | **verified on a device** — see below |

On a build with no Android runtime, `kpAndroid` **refuses** rather than
pretending: `put` returns `this build has no Android Keystore` and `get`
returns `ksUnavailable`.

### The on-device run

```
Starting 15 tests on M2007J20CG - 12
Finished 15 tests on M2007J20CG - 12
tests="15" failures="0" errors="0" skipped="0"
```

Handset: Redmi 9 Power (`surya`), **Android 12, arm64-v8a**, MIUI.

The wrapping key reports **`SECURITY_LEVEL_TRUSTED_ENVIRONMENT`** on this
device, which is the claim that actually matters and the one that could
not be made from the desktop. *Non-exportable* and *in hardware* are two
different things — a software-backed AndroidKeyStore also returns `null`
from `getKey(...).encoded`, so `theKeyIsHardwareBackedAndNotExportable`
alone cannot separate them. `theWrappingKeyLivesInSecureHardware` asks
`KeyInfo.securityLevel` outright, and on this handset the answer is the
TEE, not the OS. (Not StrongBox: this device has no dedicated secure
element, and the test accepts either.)

To repeat the run:

```sh
cd android
gradle :geistkeystore:connectedDebugAndroidTest    # or: nimble androidTest
```

The report lands in
`android/geistkeystore/build/reports/androidTests/connected/debug/`.

**Two device-side toggles gate the install**, and neither is a code
problem:

```
INSTALL_FAILED_USER_RESTRICTED        MIUI "Install via USB"
INSTALL_FAILED_VERIFICATION_FAILURE   "Verify apps over USB"
```

The first must be enabled on the handset itself — *Developer options →
Install via USB*; Xiaomi gates it behind a signed-in account and it
cannot be set over adb. The second is
`adb shell settings put global verifier_verify_adb_installs 0`; **put it
back to `1` afterwards**, since it is a real protection on a phone that
is used as a phone.

### What the 15 tests check

| test | why it is there |
|---|---|
| the keystore is reachable | `available()` consults the provider rather than returning a constant |
| stores and reads back | the round trip, on real hardware |
| the key is hardware-backed and not exportable | `getKey(...).encoded == null` |
| **the wrapping key lives in secure hardware** | `KeyInfo.securityLevel` is the TEE or StrongBox, not software — the claim `encoded == null` cannot make |
| the blob on disk is not the plaintext | and is ≥ plaintext + 12-byte IV + 16-byte tag |
| an absent name is absent | `ksAbsent`, not a failure |
| dropping forgets | and removes the alias, not just the file |
| dropping what is not there succeeds | the caller asked for it gone; it is gone |
| a replacement replaces | |
| two entries have two keys | dropping one must not disturb the other — the reason there is one wrapping key per entry |
| **a blob whose key is gone reads as invalidated** | the fingerprint-enrolment state, produced by deleting the alias directly |
| a name that would escape is refused | `../../etc/passwd`, `a/b`, empty |
| an empty or oversized secret is refused | |
| a large secret round-trips | 32 KiB |

---

## The companion contract

`kpAndroid` binds to five C symbols. An Android app provides them as a
small JNI shim over `androidBridgeClass`
(`com/siriuslee/geist/GeistKeystore`):

```c
int  geist_android_ks_available(void);
int  geist_android_ks_put(const char *name, const uint8_t *data, int len);
int  geist_android_ks_get(const char *name, uint8_t *out, int cap);
int  geist_android_ks_drop(const char *name);
int  geist_android_ks_status(const char *name);
```

| symbol | returns |
|---|---|
| `available` | non-zero when the Keystore is reachable from this process |
| `put` | 0 on success, non-zero as an opaque platform code |
| `get` | bytes written on success; **negative** is `-status`, so `-3` is `ksInvalidated` |
| `drop` | 0 on success |
| `status` | the `KeyStatus` ordinal: 0 absent, 1 present, 2 invalidated, 3 unavailable |

The negative-return convention on `get` is what carries `ksInvalidated`
back across the boundary without a second call — the one case where the
caller must not retry, and therefore the one case that must not look like
a generic failure.

The Kotlin side should use `KeyGenParameterSpec` with
`setUserAuthenticationRequired` as the app's policy requires, and must
catch `KeyPermanentlyInvalidatedException` and map it to status **2**.
That single mapping is the reason this contract exists.

---

## Why this lives in Geist

Geist already owns key material: `secret.nim` holds it, `keys.nim` seals
it, `identity.nim` writes signing identities. A sixth place that also
knows how to protect a key is how one of them ends up wrong.

The file provider therefore **invents no cryptography**. It seals with
the same Argon2id-derived key file the database uses, one `KeySet` per
entry, so dropping one key cannot require rewriting the others and a
corrupt entry cannot take the rest with it.

---

## Names are path segments

```nim
checkName("../../.ssh/id_ed25519")   # refused
checkName("a/b")                     # refused
checkName("account-3.vault")         # fine
```

The file provider turns a name into a filename. Nothing else in the
module would stop a caller from naming a key `../../.ssh/id_ed25519`, so
the check is at the top of every entry point rather than in the provider
that happens to need it.
