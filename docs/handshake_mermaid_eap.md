# EAP-EDHOC Handshake Diagrams (Primary Authentication)

> **Scope:** dokumen ini menggambarkan **primary authentication** —
> EAP-EDHOC dipakai untuk network access (link-layer) dengan FreeRADIUS sebagai
> backend AAA operator. Output kunci: `MSK` / `EMSK`.
>
> Untuk **secondary authentication** (EAP-EDHOC ke service / DN-AAA setelah
> device sudah ter-attach, dengan opsi *channel-binding* via EMSK primary,
> dan output Application Key untuk OSCORE) lihat file terpisah:
> [handshake_mermaid_eap_secondary_authentication.md](handshake_mermaid_eap_secondary_authentication.md).

Sequence diagrams for all 5 EDHOC variants wrapped in **EAP-EDHOC** framing
per [draft-ietf-emu-eap-edhoc].

- **EAP Method Type:** `0xFE` (Experimental)
- **Transport:** TCP with 2-byte length prefix
- **EAP MTU:** 1000 bytes/fragment (L/M/S flags for fragmentation)
- **MSK/EMSK:** Derived from EDHOC `PRK_out` after successful handshake

---

## Benchmark Results (loopback, 100 iterations)

| Rank | Variant | Total (µs) | Processing (µs) | Tx/Rx (µs) |
|------|---------|-----------|----------------|------------|
| 1 | Type 0 Classic | 258.92 | 83.56 | 87.41 |
| 2 | Type 3 Classic | 277.88 | 93.02 | 103.56 |
| 3 | Type 3 Hybrid | 800.12 | 268.16 | 330.38 |
| 4 | Type 3 PQ | 1369.88 | 510.19 | 707.03 |
| 5 | Type 0 PQ | 4326.39 | 1937.36 | 1870.48 |

---

## Legend

```
I = EAP Peer   (Initiator, EAP Supplicant side)
R = EAP Server (Responder, EAP Authenticator side)
[frag 1/N] = EAP fragment (M-bit set if more fragments follow)
MSK/EMSK   = derived from PRK_out via HKDF (64 bytes each)
```

---

## 1. Type 0 Classic — Ed25519 Sig-Sig (fastest in EAP context)

Cipher suite: EDHOC Method 0, Ed25519 static keys for authentication.
All messages fit in a single EAP fragment (≤ 1000 bytes).

```mermaid
sequenceDiagram
    participant I as EAP Peer (Initiator)
    participant R as EAP Server (Responder)

    Note over I,R: Pre-session: Exchange static Ed25519 public keys (raw TCP)
    I->>R: [raw TCP] PK_I (Ed25519, 32 B)
    R->>I: [raw TCP] PK_R (Ed25519, 32 B)

    Note over I,R: EAP-EDHOC Handshake begins
    R->>I: EAP-Request / Start (Code=1, S-flag, id=1)

    I->>R: EAP-Response / MSG1 (Code=2, 35 B, 1 fragment)
    Note right of I: SUITES_I, G_X (ephemeral X25519 PK), C_I

    R->>I: EAP-Request / MSG2 (Code=1, 98 B, 1 fragment)
    Note right of R: G_Y (eph X25519 PK), C_R, CIPHERTEXT_2<br/>(contains ENC_PLAINTEXT_2 + MAC_2 using PRK_2e)

    I->>R: EAP-Response / MSG3 (Code=2, 97 B, 1 fragment)
    Note right of I: CIPHERTEXT_3<br/>(contains ENC_PLAINTEXT_3 + MAC_3 + Signature_I using PRK_3e2m)

    R->>I: EAP-Success + MSK/EMSK
    Note right of R: MSK = HKDF-Expand(PRK_out, "EAP-EDHOC MSK", 64)<br/>EMSK = HKDF-Expand(PRK_out, "EAP-EDHOC EMSK", 64)
```

**EAP Round Trips:** 3 (Start → MSG1 → MSG2 → MSG3 → Success)

---

## 2. Type 3 Classic — X25519 MAC-MAC

Cipher suite: EDHOC Method 3, X25519 static keys, MAC-only authentication (no signatures).
All messages fit in a single EAP fragment.

```mermaid
sequenceDiagram
    participant I as EAP Peer (Initiator)
    participant R as EAP Server (Responder)

    Note over I,R: Pre-session: Exchange static X25519 public keys (raw TCP)
    I->>R: [raw TCP] PK_I_static (X25519, 32 B)
    R->>I: [raw TCP] PK_R_static (X25519, 32 B)

    Note over I,R: EAP-EDHOC Handshake begins
    R->>I: EAP-Request / Start (Code=1, S-flag, id=1)

    I->>R: EAP-Response / MSG1 (Code=2, 35 B, 1 fragment)
    Note right of I: SUITES_I, G_X (eph X25519 PK), C_I

    R->>I: EAP-Request / MSG2 (Code=1, 66 B, 1 fragment)
    Note right of R: G_Y (eph X25519 PK), C_R, CIPHERTEXT_2<br/>PRK_2e = HKDF(G_XY_eph || G_RX_static)<br/>MAC_2 = EDHOC-KDF(PRK_2e, ...)

    I->>R: EAP-Response / MSG3 (Code=2, 65 B, 1 fragment)
    Note right of I: CIPHERTEXT_3<br/>PRK_3e2m = HKDF(PRK_2e, G_IY_static)<br/>MAC_3 = EDHOC-KDF(PRK_3e2m, ...)

    R->>I: EAP-Success + MSK/EMSK
    Note right of R: PRK_out derived from PRK_3e2m<br/>MSK/EMSK = HKDF-Expand(PRK_out, ...)
```

**EAP Round Trips:** 3 | **Key Exchange:** 2× X25519 ECDH (eph+static) | **Auth:** HMAC-SHA256 MAC

---

## 3. Type 3 Hybrid — X25519 + ML-KEM-768 (Hybrid PQ)

Cipher suite: EDHOC Method 3 hybrid variant. Combines X25519 ECDHE with ML-KEM-768 encapsulation for post-quantum forward secrecy. Large messages require multiple EAP fragments.

```mermaid
sequenceDiagram
    participant I as EAP Peer (Initiator)
    participant R as EAP Server (Responder)

    Note over I,R: Pre-session: Exchange static X25519 public keys (raw TCP)
    I->>R: [raw TCP] PK_I_x25519 (32 B)
    R->>I: [raw TCP] PK_R_x25519 (32 B)

    Note over I,R: EAP-EDHOC Handshake begins
    R->>I: EAP-Request / Start (Code=1, S-flag)

    I->>R: EAP-Response / MSG1 frag 1/2 (Code=2, L+M flags, 1000 B)
    Note right of I: G_X_eph (X25519 32B) + KEM_PK (ML-KEM-768 1184B)<br/>Total MSG1 ≈ 1216 B → 2 fragments
    R->>I: EAP-Request / ACK (fragment ACK, empty body)
    I->>R: EAP-Response / MSG1 frag 2/2 (Code=2, 216 B)

    R->>I: EAP-Request / MSG2 frag 1/2 (Code=1, L+M flags, 1000 B)
    Note right of R: G_Y_eph (X25519 32B) + KEM_CT (ML-KEM-768 1088B)<br/>+ CIPHERTEXT_2 (MAC_2)<br/>Total MSG2 ≈ 1168 B → 2 fragments<br/>PRK_2 = HMAC(shared_xy || k_kem, TH_2)
    I->>R: EAP-Response / ACK (fragment ACK, empty body)
    R->>I: EAP-Request / MSG2 frag 2/2 (Code=1, 168 B)

    I->>R: EAP-Response / MSG3 (Code=2, ~48 B, 1 fragment)
    Note right of I: CIPHERTEXT_3 (MAC_3)<br/>PRK_3e2m = HMAC(PRK_2, X^b_static)<br/>PRK_4e3m = HMAC(PRK_3e2m, Y^a_static)

    R->>I: EAP-Success + MSK/EMSK
    Note right of R: MSK/EMSK = HKDF-Expand(PRK_out, ...)
```

**EAP Round Trips:** 5 (3 msg + 2 fragment ACKs) | **Key Exchange:** X25519 + ML-KEM-768 | **Auth:** HMAC-SHA256 MAC

---

## 4. Type 3 PQ — ML-KEM-768 Encrypted MSG1 (4-message)

Cipher suite: EDHOC Method 3 PQ variant. MSG1 is encrypted using Responder's long-term KEM public key, providing forward secrecy and identity protection. Uses 4 EDHOC messages requiring an extra EAP round trip.

```mermaid
sequenceDiagram
    participant I as EAP Peer (Initiator)
    participant R as EAP Server (Responder)

    Note over I,R: Pre-session: Exchange long-term ML-KEM-768 public keys (raw TCP)
    I->>R: [raw TCP] PK_I_kem (ML-KEM-768, 1184 B)
    R->>I: [raw TCP] PK_R_kem (ML-KEM-768, 1184 B)

    Note over I,R: EAP-EDHOC Handshake begins
    R->>I: EAP-Request / Start (Code=1, S-flag)

    I->>R: EAP-Response / MSG1 frag 1/3 (Code=2, L+M flags, 1000 B)
    Note right of I: KEM_CT_I (1088B, encaps to PK_R) + ENC_MSG1<br/>Total MSG1 ≈ 2295 B → 3 fragments
    R->>I: EAP-Request / ACK (fragment ACK)
    I->>R: EAP-Response / MSG1 frag 2/3 (Code=2, M flag, 1000 B)
    R->>I: EAP-Request / ACK (fragment ACK)
    I->>R: EAP-Response / MSG1 frag 3/3 (Code=2, 295 B)

    R->>I: EAP-Request / MSG2 frag 1/3 (Code=1, L+M flags, 1000 B)
    Note right of R: KEM_CT_R (1088B, encaps to PK_I) + CIPHERTEXT_2<br/>Total MSG2 ≈ 2214 B → 3 fragments<br/>PRK_1e = HKDF(ss_I)<br/>PRK_2m = HKDF(PRK_1e, ss_R)
    I->>R: EAP-Response / ACK (fragment ACK)
    R->>I: EAP-Request / MSG2 frag 2/3 (Code=1, M flag, 1000 B)
    I->>R: EAP-Response / ACK (fragment ACK)
    R->>I: EAP-Request / MSG2 frag 3/3 (Code=1, 214 B)

    I->>R: EAP-Response / MSG3 (Code=2, ~33 B, 1 fragment)
    Note right of I: CIPHERTEXT_3 (MAC_3)<br/>PRK_2e3e3m = HKDF(PRK_2m, ...)

    R->>I: EAP-Request / MSG4 (Code=1, ~17 B, 1 fragment)
    Note right of R: CIPHERTEXT_4 (MAC_4)<br/>4th message required by PQ variant

    I->>R: EAP-Response / ACK (Code=2, empty body — acknowledges MSG4)

    R->>I: EAP-Success + MSK/EMSK
    Note right of R: MSK/EMSK = HKDF-Expand(PRK_out, ...)
```

**EAP Round Trips:** 10 (4 EDHOC msgs + 4 fragment ACKs + MSG4-ACK + Success) | **Auth:** ML-KEM-768 (PQ-secure)

---

## 5. Type 0 PQ — ML-DSA-65 Sig-Sig (slowest)

Cipher suite: EDHOC Method 0 with ML-DSA-65 (Dilithium3) post-quantum signatures for mutual authentication. Large public keys and signatures require many EAP fragments.

```mermaid
sequenceDiagram
    participant I as EAP Peer (Initiator)
    participant R as EAP Server (Responder)

    Note over I,R: Pre-session: Exchange static ML-DSA-65 public keys (raw TCP)
    I->>R: [raw TCP] PK_I_dsa (ML-DSA-65, 1952 B)
    R->>I: [raw TCP] PK_R_dsa (ML-DSA-65, 1952 B)

    Note over I,R: EAP-EDHOC Handshake begins
    R->>I: EAP-Request / Start (Code=1, S-flag)

    I->>R: EAP-Response / MSG1 frag 1/2 (Code=2, L+M flags, 1000 B)
    Note right of I: SUITES_I + G_X (eph X25519 32B) + C_I<br/>+ ID_CRED_I + PK_I_dsa (1952B)<br/>Total MSG1 ≈ 1187 B → 2 fragments
    R->>I: EAP-Request / ACK (fragment ACK)
    I->>R: EAP-Response / MSG1 frag 2/2 (Code=2, 187 B)

    R->>I: EAP-Request / MSG2 frag 1/5 (Code=1, L+M flags, 1000 B)
    Note right of R: G_Y (eph X25519 32B) + CIPHERTEXT_2<br/>contains: PK_R_dsa (1952B) + MAC_2 + Signature_R (ML-DSA-65 ~3293B)<br/>Total MSG2 ≈ 4400 B → 5 fragments
    I->>R: EAP-Response / ACK
    R->>I: EAP-Request / MSG2 frag 2/5 (M flag, 1000 B)
    I->>R: EAP-Response / ACK
    R->>I: EAP-Request / MSG2 frag 3/5 (M flag, 1000 B)
    I->>R: EAP-Response / ACK
    R->>I: EAP-Request / MSG2 frag 4/5 (M flag, 1000 B)
    I->>R: EAP-Response / ACK
    R->>I: EAP-Request / MSG2 frag 5/5 (400 B)

    I->>R: EAP-Response / MSG3 frag 1/4 (Code=2, L+M flags, 1000 B)
    Note right of I: CIPHERTEXT_3<br/>contains: MAC_3 + Signature_I (ML-DSA-65 ~3293B)<br/>Total MSG3 ≈ 3326 B → 4 fragments
    R->>I: EAP-Request / ACK
    I->>R: EAP-Response / MSG3 frag 2/4 (M flag, 1000 B)
    R->>I: EAP-Request / ACK
    I->>R: EAP-Response / MSG3 frag 3/4 (M flag, 1000 B)
    R->>I: EAP-Request / ACK
    I->>R: EAP-Response / MSG3 frag 4/4 (326 B)

    R->>I: EAP-Success + MSK/EMSK
    Note right of R: MSK/EMSK = HKDF-Expand(PRK_out, ...)
```

**EAP Round Trips:** 14 (3 EDHOC msgs + 11 fragment ACKs) | **Auth:** ML-DSA-65 (PQ signatures)

---

## EAP Packet Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Code      |  Identifier   |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Flags     |   Total-Length (if L-bit)     |
|  (0xFE/254)   | L|M|S|0|0|0|0|         (4 bytes)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         EAP-EDHOC Data                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Code:  1=Request, 2=Response, 3=Success, 4=Failure
Flags: L=Length-included, M=More-fragments, S=EAP-Start
TCP:   each EAP packet prefixed with 2-byte big-endian length
```

## MSK/EMSK Derivation

After a successful EDHOC handshake, the EAP server exports keying material:

```
MSK  (64B) = EDHOC-Expand(PRK_out, "EAP-EDHOC MSK",  13, 64)
EMSK (64B) = EDHOC-Expand(PRK_out, "EAP-EDHOC EMSK", 14, 64)
```

where `EDHOC-Expand` is `HKDF-Expand(PRK_out, context_string || length, outlen)`.

---

## Secondary Authentication via FreeRADIUS AAA

The diagram below shows the **complete secondary-authentication flow** as
implemented in [src/benchmark_eap_responder_aaa.c](../src/benchmark_eap_responder_aaa.c)
and [src/benchmark_eap_initiator.c](../src/benchmark_eap_initiator.c). The IoT
device (EAP Peer / Initiator) performs an EAP-EDHOC handshake with the EAP
Authenticator (Responder), which then validates the device's identity against a
back-end FreeRADIUS server using the standard RADIUS Access-Request/Accept
exchange before granting network access.

```mermaid
sequenceDiagram
    autonumber
    participant DEV as IoT Device<br/>(EAP Peer / Initiator)
    participant AUTH as EAP Authenticator<br/>(eap_aaa_responder)
    participant AAA as AAA Server<br/>(FreeRADIUS)

    Note over DEV,AUTH: 1) EAP-EDHOC primary key establishment (one of 5 variants)
    AUTH->>DEV: EAP-Request / EAP-EDHOC Start (Type=0xFE, S-flag)
    DEV->>AUTH: EAP-Response / EDHOC MSG1 (fragmented if > MTU)
    AUTH->>DEV: EAP-Request / EDHOC MSG2 (fragmented if > MTU)
    DEV->>AUTH: EAP-Response / EDHOC MSG3
    opt Type 3 PQ (4-message variant)
        AUTH->>DEV: EAP-Request / EDHOC MSG4
        DEV->>AUTH: EAP-Response / ACK
    end
    Note over DEV,AUTH: PRK_out established → MSK / EMSK derived

    Note over AUTH,AAA: 2) Secondary authentication via RADIUS (post-EDHOC)
    AUTH->>AAA: RADIUS Access-Request<br/>User-Name = "edhoc_<Variant>"<br/>User-Password = shared secret<br/>NAS-IP-Address, Message-Authenticator
    AAA->>AAA: Lookup user in mods-config/files/authorize<br/>Verify Cleartext-Password
    AAA-->>AUTH: RADIUS Access-Accept<br/>(or Access-Reject on failure)

    alt AAA accepted
        AUTH->>DEV: EAP-Success<br/>+ MSK (64 B) / EMSK (64 B)
        Note over DEV,AUTH: Device authorized — keys ready for OSCORE / link-layer encryption
    else AAA rejected
        AUTH->>DEV: EAP-Failure
        Note over DEV,AUTH: Session terminated, keys discarded
    end
```

### Mapping ke Code

| Komponen | File | Fungsi utama |
|---|---|---|
| EAP Peer (IoT device) | [src/benchmark_eap_initiator.c](../src/benchmark_eap_initiator.c) | `run_handshake_benchmarks()`, `eap_send_response()` |
| EAP Authenticator | [src/benchmark_eap_responder_aaa.c](../src/benchmark_eap_responder_aaa.c) | `wait_for_client()`, `aaa_authenticate_variant()` |
| EAP layer & fragmentation | [src/eap_layer.c](../src/eap_layer.c) | `eap_send()`, `eap_recv()`, `eap_derive_msk_emsk()` |
| Per-variant EDHOC handshake | [src/eap_variant_type0_classic.c](../src/eap_variant_type0_classic.c) … `_type3_hybrid.c` | `run_eap_<variant>_initiator/_responder()` |
| AAA prepare script | [scripts/freeradius_aaa/prepare.sh](../scripts/freeradius_aaa/prepare.sh) | Setup FreeRADIUS raddb dengan port 3812 + EDHOC users |
| AAA run script | [scripts/freeradius_aaa/run_debug.sh](../scripts/freeradius_aaa/run_debug.sh) | Jalankan `freeradius -X` (debug mode) |
| AAA smoke test | [scripts/freeradius_aaa/smoke_test.sh](../scripts/freeradius_aaa/smoke_test.sh) | `radclient` Access-Request manual |

### Compliance dengan draft-ietf-emu-eap-edhoc

| Aspek draft | Implementasi |
|---|---|
| EAP Method Type | `0xFE` (Experimental, sesuai §3.1 draft) |
| EAP Header Flags | `L` (Length), `M` (More), `S` (Start) — `eap_layer.c` |
| Fragmentation MTU | Default `EAP_EDHOC_MTU = 1000 B` (§3.2) |
| EDHOC message flow | MSG1/MSG2/MSG3 (+MSG4 untuk method 3 PQ) |
| MSK derivation | `MSK  = EDHOC-Expand(PRK_out, "EAP-EDHOC MSK", 13, 64)` (§4) |
| EMSK derivation | `EMSK = EDHOC-Expand(PRK_out, "EAP-EDHOC EMSK", 14, 64)` (§4) |
| AAA back-end | FreeRADIUS via `radclient` (RFC 2865 Access-Request/Accept) |
