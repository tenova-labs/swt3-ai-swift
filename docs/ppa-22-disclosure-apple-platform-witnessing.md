# PPA #22: On-Device AI Witnessing and Hardware-Bound Attestation for Consumer Computing Platforms

## PROVISIONAL PATENT APPLICATION DISCLOSURE

**Title:** On-Device AI Witnessing and Hardware-Bound Attestation for Consumer Computing Platforms

**Inventor:** Alvin Tondereau

**Assignee:** Tenable Nova LLC

**Filing Date:** [PENDING]

**Filing Strategy:** Standalone PPA #22
**Claim Count:** 27 claims across 5 claim areas
**Relationship:** Extends PPA #1 (Core Fingerprint), PPA #2 (SDKs + Clearing Engine), PPA #5 (Identity Binding), PPA #14 (Network Trust Protocol)
**New Capability:** Platform-native AI witnessing that activates hardware security, on-device model integrity, and spatial provenance capabilities via compile-time detection

---

## CORE THESIS

AI inference is rapidly migrating from cloud to edge. On-device models (compiled neural networks, quantized transformers, federated learning participants) execute billions of inferences daily on consumer hardware without any accountability trail. No existing system provides cryptographic attestation for on-device AI predictions that:

1. Operates entirely on the device with no cloud round-trip
2. Uses hardware security modules for tamper-evident signing
3. Verifies model integrity at load time before permitting inference
4. Records the physical-world location of spatial AI decisions
5. Activates platform-specific capabilities automatically without developer configuration

The SWT3 protocol's deterministic fingerprint formula is platform-agnostic by design. This disclosure extends the protocol with platform-native convenience methods that map on-device AI events to the existing witness anchor format, leveraging hardware capabilities that exist only on specific consumer computing platforms. The core protocol remains unchanged; the platform layer provides frictionless integration that would be impossible with a platform-agnostic-only approach.

---

## PRIOR ART ANALYSIS

### Closest Prior Art

1. **Apple DeviceCheck / App Attest** -- Proves an app is running on genuine hardware but does not attest the behavior or output of AI models running within the app. No fingerprint of inference inputs/outputs. No clearing levels. No model integrity verification.

2. **Google Play Integrity API** -- Device attestation focused on app authenticity and tamper detection. Does not address AI model behavior, inference provenance, or compliance witnessing.

3. **NVIDIA Confidential Computing** -- Protects model weights in GPU TEEs but does not produce portable compliance attestation anchors. Focused on weight secrecy, not behavioral accountability.

4. **ARM TrustZone** -- Hardware isolation for secure execution but no framework for AI inference witnessing. Provides the isolation primitive, not the attestation protocol.

5. **Federated Learning Privacy** -- Differential privacy and secure aggregation protect training data but do not produce per-inference attestation records. Privacy-preserving, not accountability-producing.

6. **Core ML model encryption** -- Protects model weights at rest via encryption but does not produce cryptographic evidence that a specific model (identified by hash) was used for a specific inference at a specific time.

7. **W3C Web Authentication (FIDO2)** -- Uses hardware-bound keys for user authentication but does not apply the same mechanism to AI inference attestation. Key binding is to user identity, not to compliance anchors.

### Novelty Argument

No prior art describes: (a) a system that mints compliance attestation anchors for on-device AI inference using the same deterministic formula as cloud-based witnessing; (b) binding attestation signatures to hardware security modules on consumer devices such that the private key provably never existed in software; (c) deterministic hashing of compiled model archives for load-time integrity verification integrated into the attestation pipeline; (d) recording the physical-world coordinates of spatial AI decisions as hashed metadata in compliance anchors; (e) a single-package SDK that activates platform-specific witnessing capabilities via compile-time framework detection without developer configuration. The combination of these elements into a unified on-device witnessing architecture is novel and non-obvious.

---

## CLAIM AREA 1: On-Device Inference Witnessing (Claims 1-6)

### Core Concept

A method for producing cryptographic compliance attestation for AI model predictions executed entirely on a consumer device, without requiring network connectivity, cloud services, or centralized adjudication.

**Claim 1.** A computer-implemented method for on-device AI inference witnessing, comprising:
- receiving an AI model prediction executed on a consumer computing device by a compiled machine learning model;
- extracting model metadata from the model's public description interface, comprising one or more of: model identifier, author, version, input feature schema, and output feature schema;
- computing a cryptographic hash of the input feature description and a separate cryptographic hash of the output feature description, such that the raw inference data is never transmitted, stored outside the device, or recoverable from the hashes;
- computing a deterministic fingerprint from a canonical formula applied to the tenant identifier, procedure identifier, numeric factors, and millisecond timestamp, wherein the formula uses only SHA-256 and string concatenation with no machine learning inference at any step;
- assembling a witness payload comprising the fingerprint, the model metadata (or a hash thereof at elevated clearing levels), the input hash, the output hash, and the inference latency;
- wherein the entire computation occurs on-device with zero network round-trips, and the resulting witness payload is compatible with the same ledger format used for cloud-based AI witnessing.

**Claim 2.** The method of Claim 1, wherein the model identifier is subjected to clearing level redaction comprising:
- at clearing levels 0 through 2, recording the model identifier in plaintext in the witness payload;
- at clearing level 3, replacing the model identifier with a truncated SHA-256 hash of the identifier;
- thereby enabling on-device witnesses to comply with the same privacy-preserving clearing hierarchy as cloud-based witnesses.

**Claim 3.** The method of Claim 1, wherein the input and output hashes are computed from a canonical serialization of the feature schema comprising:
- sorting the feature names lexicographically;
- for each feature, concatenating the feature name with its type identifier separated by a colon;
- joining all feature strings with a comma separator;
- computing a truncated SHA-256 hash of the joined string;
- thereby producing a deterministic schema fingerprint that identifies the model's interface without revealing the inference data.

**Claim 4.** The method of Claim 1, further comprising offline witness buffering wherein:
- witness payloads generated on-device are stored in a local buffer;
- when network connectivity is available, buffered payloads are transmitted to a witness endpoint in batch;
- the witness endpoint validates the fingerprints and records the anchors with their original on-device timestamps;
- thereby enabling continuous AI accountability even during periods of network unavailability.

**Claim 5.** The method of Claim 1, further comprising on-device witness chaining wherein:
- each subsequent witness payload includes a reference to the previous payload's fingerprint;
- the chain of fingerprints creates a tamper-evident sequence of on-device inferences;
- any modification to a historical payload invalidates all subsequent fingerprints in the chain;
- thereby providing offline verifiability of inference sequence integrity without ledger access.

**Claim 6.** The method of Claim 1, wherein the method is implemented as an extension on a namespace type (uninhabitable enumeration) in a compiled language, such that:
- the method is available as a static function requiring no object instantiation;
- the method accepts the AI model, input features, output features, latency, and tenant as parameters;
- the method returns a fully populated witness payload struct that is immediately serializable to JSON via protocol conformance;
- thereby providing a zero-configuration, single-function-call integration path for on-device AI witnessing.

---

## CLAIM AREA 2: Hardware Security Module Signing for AI Attestation (Claims 7-14)

### Core Concept

A method for signing AI witness anchors using cryptographic keys that are generated within and never leave a hardware security module on a consumer computing device, providing tamper-evident non-repudiation that is physically impossible to achieve with software-only signing.

**Claim 7.** A computer-implemented method for hardware-bound AI attestation signing, comprising:
- generating an asymmetric key pair within a hardware security module of a consumer computing device, wherein the private key is created inside the hardware module and is architecturally prevented from being exported, copied, or read by any software process including the operating system kernel;
- associating the key pair with a persistent identifier (tag) that enables subsequent retrieval of the key reference without exposing the key material;
- receiving an AI witness anchor fingerprint to be signed;
- constructing a signing message comprising the fingerprint and optionally an agent identity string;
- submitting the signing message to the hardware security module for signature computation;
- receiving the resulting digital signature from the hardware security module;
- encoding the signature as a hexadecimal string for inclusion in a witness payload;
- wherein the signing algorithm is constrained to those supported by the hardware module (ECDSA P-256), and the witness payload records both the signature and the signing algorithm identifier.

**Claim 8.** The method of Claim 7, wherein the hardware security module key is subject to access control policies comprising:
- the key is accessible only when the device is unlocked by the device owner;
- the key is bound to the specific physical device and cannot be restored from backup to a different device;
- thereby ensuring that a witness signature proves not only the fingerprint integrity but also the specific physical device on which the attestation was created.

**Claim 9.** The method of Claim 7, further comprising dual-algorithm signing wherein:
- the witness payload includes both an HMAC-SHA256 signature (computed in software using a symmetric key) and an ECDSA P-256 signature (computed in the hardware security module);
- the HMAC signature provides cross-language verification compatibility with existing SWT3 implementations;
- the hardware signature provides device-binding and tamper-evidence;
- verifiers may check either or both signatures depending on their trust requirements.

**Claim 10.** The method of Claim 7, further comprising key lifecycle management wherein:
- when a hardware-bound key is created, an initial witness anchor is minted recording the key's public component, creation timestamp, and device identifier;
- when a key is rotated, the new key signs a statement referencing the old key's last anchor, creating key lineage;
- when a key is deleted, a revocation anchor is minted recording the deletion;
- thereby creating an auditable lifecycle of all hardware-bound signing keys.

**Claim 11.** The method of Claim 7, wherein the hardware-bound signature serves as a device attestation proof comprising:
- the signature proves the private key exists in a hardware security module;
- the hardware security module provides attestation that the key was generated within the secure boundary;
- a verifier receiving the signature and the device attestation can confirm both the fingerprint integrity AND the hardware provenance;
- thereby establishing a chain of trust from the hardware silicon through the witness anchor to the ledger.

**Claim 12.** The method of Claim 7, further comprising error recovery wherein:
- if the hardware security module is unavailable (device locked, biometric required, hardware failure), the signing method throws a typed error indicating the specific failure mode;
- the calling application may fall back to software-based HMAC-SHA256 signing;
- the witness payload records which signing method was actually used;
- thereby maintaining attestation continuity even when hardware signing is temporarily unavailable.

**Claim 13.** The method of Claim 7, wherein the key tag follows a reverse-domain naming convention comprising:
- the tag includes the organization domain, the protocol identifier, and the key purpose (e.g., "io.tenova.swt3.signing");
- multiple keys for different purposes (signing, delegation) may coexist in the hardware module;
- the tag is used for key lookup without exposing the key reference to the application layer.

**Claim 14.** The method of Claim 7, further comprising fleet-level hardware attestation wherein:
- multiple devices in an organization each generate their own hardware-bound key;
- each device's public key is registered with the tenant's key registry;
- a fleet-level attestation anchor records the count of active hardware-bound keys and the hash of the sorted public key list;
- additions and removals from the fleet are recorded as anchor observations;
- thereby providing organizational visibility into the hardware attestation posture across all devices.

---

## CLAIM AREA 3: Compiled Model Archive Integrity Verification (Claims 15-19)

### Core Concept

A method for computing a deterministic integrity hash of a compiled machine learning model archive (a directory-based artifact containing model weights, configuration files, and metadata) for use in AI accountability attestation.

**Claim 15.** A computer-implemented method for compiled model archive integrity verification, comprising:
- receiving a URL pointing to a directory-based compiled model archive on the local filesystem;
- enumerating all regular files within the directory recursively, excluding hidden files;
- sorting the enumerated file paths lexicographically by their relative path within the archive;
- for each file in sorted order, updating a running SHA-256 hash with the file's relative path (as UTF-8 bytes) followed by the file's contents;
- finalizing the hash to produce a deterministic integrity digest;
- wherein the digest changes if any file is added, removed, modified, or renamed within the archive;
- and wherein the digest is independent of filesystem metadata (timestamps, permissions, ownership), ensuring reproducibility across devices.

**Claim 16.** The method of Claim 15, further comprising model integrity attestation wherein:
- the computed archive digest is recorded in a witness payload as the response hash field;
- a model description hash (derived from the model's public metadata) is recorded as the prompt hash field;
- the witness payload is minted with a model integrity procedure identifier (AI-MDL.1 or AI-MDL.5);
- thereby producing a compliance anchor that proves a specific model binary was verified at a specific time.

**Claim 17.** The method of Claim 15, further comprising load-time integrity gating wherein:
- the archive digest is computed immediately after the model archive is loaded into memory but before any inference is permitted;
- the computed digest is compared against a previously recorded digest stored in a local manifest;
- if the digests do not match, the model is flagged as potentially tampered and a FAIL verdict witness anchor is minted;
- if the digests match, a PASS verdict witness anchor is minted and inference proceeds;
- thereby creating a cryptographic proof that the model was verified as unmodified before every inference session.

**Claim 18.** The method of Claim 15, further comprising individual file integrity verification wherein:
- a separate method computes a truncated SHA-256 hash of a single file's contents;
- this method is used for verifying individual model weight files, adapter files, or configuration files;
- the per-file hash uses a consistent truncation length (16 hex characters by default) matching the protocol's prompt and response hash format;
- thereby enabling granular integrity verification of model components in addition to whole-archive verification.

**Claim 19.** The method of Claim 15, wherein the deterministic ordering uses relative paths comprising:
- absolute paths are converted to relative paths by removing the archive root prefix;
- relative paths are sorted using lexicographic string comparison;
- the relative path bytes are included in the hash computation before the file contents;
- thereby ensuring the hash captures both the archive structure and the file contents, and preventing an attacker from swapping two files' contents without detection.

---

## CLAIM AREA 4: Spatial Inference Provenance (Claims 20-24)

### Core Concept

A method for recording the physical-world spatial context of an AI decision as cryptographic metadata in a compliance attestation anchor, proving WHERE an AI system made a decision in addition to WHAT it decided and WHEN.

**Claim 20.** A computer-implemented method for spatial inference provenance attestation, comprising:
- receiving a 4x4 transformation matrix representing the world-space position and orientation at which an AI inference was executed, the matrix comprising 16 floating-point values encoding translation, rotation, and scale in a three-dimensional coordinate system;
- serializing the transformation matrix in column-major order with fixed decimal precision (6 decimal places per element), producing a deterministic string representation;
- computing a truncated SHA-256 hash of the serialized matrix;
- recording the spatial hash in a witness payload's metadata field;
- minting a fingerprint using the standard canonical formula with the spatial hash as contextual metadata;
- wherein the spatial coordinates are irreversibly hashed, preventing reconstruction of the exact location from the witness payload, while still enabling verification that a specific spatial context was attested.

**Claim 21.** The method of Claim 20, wherein the fixed-precision serialization ensures deterministic hashing comprising:
- each floating-point element is formatted to exactly 6 decimal places, regardless of the element's actual precision;
- elements are separated by commas with no whitespace;
- columns are serialized in order (column 0, column 1, column 2, column 3), and within each column, elements are serialized in order (x, y, z, w);
- thereby producing identical hash output regardless of the floating-point representation used by the source framework.

**Claim 22.** The method of Claim 20, further comprising spatial drift detection wherein:
- sequential spatial witnesses from the same agent are compared by computing the Euclidean distance between the translation components of their transformation matrices;
- if the distance exceeds a configurable threshold, a spatial drift event is recorded;
- the drift event may trigger re-verification of the agent's spatial authorization;
- thereby detecting when an AI system operating in a physical environment has moved outside its authorized operational boundary.

**Claim 23.** The method of Claim 20, further comprising spatial zone attestation wherein:
- the transformation matrix is classified into predefined spatial zones based on the translation component;
- each zone has an associated compliance policy (e.g., restricted zones requiring elevated clearing levels);
- the witness payload records the zone classification alongside the spatial hash;
- thereby enabling location-aware compliance enforcement for AI systems operating in physical environments.

**Claim 24.** The method of Claim 20, wherein the spatial provenance is combined with on-device inference witnessing (Claim 1) comprising:
- the spatial hash replaces or augments the input hash in the witness payload;
- the resulting anchor proves simultaneously: which model produced the inference, what the model's inputs and outputs were (as hashes), when the inference occurred, and where in physical space the inference was executed;
- thereby producing a four-dimensional accountability record (what, who, when, where) for spatial AI systems.

---

## CLAIM AREA 5: Conditional Platform Activation (Claims 25-27)

### Core Concept

A method for distributing a single software package that automatically activates platform-specific AI witnessing capabilities at compile time based on the availability of platform frameworks, without requiring developer configuration, conditional dependency management, or separate package installation.

**Claim 25.** A computer-implemented method for conditional platform activation of AI witnessing capabilities, comprising:
- distributing a single software package containing both platform-agnostic core primitives and platform-specific witnessing extensions;
- the platform-agnostic primitives (fingerprint minting, payload signing, SHA-256 hashing, type definitions) compile and execute on all supported platforms including server-side environments;
- the platform-specific extensions are enclosed in compile-time conditional blocks that test for the availability of platform frameworks;
- when a platform framework is available, the conditional block compiles and the platform-specific methods become available to the developer;
- when a platform framework is unavailable, the conditional block is excluded from compilation entirely, adding zero binary size and zero runtime overhead;
- wherein no configuration file, feature flag, build setting, or developer action is required to activate or deactivate platform-specific features.

**Claim 26.** The method of Claim 25, wherein the platform-specific extensions are implemented as extensions on the same namespace type as the core primitives, comprising:
- the core primitives are defined as static methods on an uninhabitable enumeration type (a type with no cases that cannot be instantiated);
- platform-specific methods are added via extension declarations within conditional compilation blocks;
- from the developer's perspective, all methods (core and platform-specific) appear on the same namespace with identical calling conventions;
- the developer calls platform-specific methods without awareness of or reference to the conditional compilation;
- thereby providing a unified API surface where platform capabilities appear and disappear transparently based on the compilation target.

**Claim 27.** The method of Claim 25, further comprising cryptographic dependency resolution wherein:
- on platforms with native cryptographic framework support, the package uses the platform's built-in cryptographic library with zero external dependencies;
- on platforms without native cryptographic support (server-side Linux environments), the package conditionally includes an open-source cryptographic library as a build-time dependency;
- both paths produce identical cryptographic output (verified by shared test vectors across all supported platforms);
- the conditional dependency is declared in the package manifest with a platform condition, not in the source code;
- thereby maintaining zero-dependency operation on consumer platforms while supporting server-side deployment.

---

## IMPLEMENTATION REFERENCE

The claims described in this disclosure are implemented in the SWT3 AI Witness SDK for Swift, version 0.5.7, at `packages/swt3-ai-swift/` in the Axiom Sovereign Engine repository. The implementation comprises:

- `Fingerprint.swift` -- Claims 1-6 (on-device fingerprint minting)
- `Signing.swift` -- Claims 7-14 (hardware security module signing)
- `ModelIntegrity.swift` -- Claims 15-19 (compiled model archive hashing)
- `SpatialWitness.swift` -- Claims 20-24 (spatial inference provenance)
- `Package.swift` -- Claims 25-27 (conditional platform activation)

74 automated tests verify cross-language parity with the Python, TypeScript, Rust, C#, and Ruby implementations.

---

## CLAIM DEPENDENCY MAP

```
Claim 1 (On-Device Inference) <-- Claims 2, 3, 4, 5, 6
Claim 7 (Hardware Signing)    <-- Claims 8, 9, 10, 11, 12, 13, 14
Claim 15 (Model Archive Hash) <-- Claims 16, 17, 18, 19
Claim 20 (Spatial Provenance)  <-- Claims 21, 22, 23, 24
Claim 25 (Platform Activation) <-- Claims 26, 27
```

5 independent claims (1, 7, 15, 20, 25) with 22 dependent claims.

---

*This disclosure is confidential and intended solely for patent filing purposes. Do not publish, deploy to web-accessible directories, or include in any public repository.*
