# EAP-EDHOC **Secondary Authentication** Handshake Diagrams

> Dokumen ini melengkapi [handshake_mermaid_eap.md](handshake_mermaid_eap.md)
> yang berisi **primary authentication** (network access). File ini fokus pada
> **secondary authentication**: setelah device sudah ter-attach ke jaringan,
> ia harus membuktikan identitasnya lagi ke server/service tertentu sebelum
> diizinkan mengakses application data.

---

## 1. Definisi & Perbedaan dengan Primary

| Aspek | Primary Authentication | Secondary Authentication |
|---|---|---|
| Tujuan | Boleh **konek ke jaringan** (link-layer / NAS) | Boleh **konek ke server / service tertentu** (app-layer) |
| Pemicu | Device join jaringan (Wi-Fi assoc, 5G registration) | Device buka sesi PDU / akses Data Network (DN) tertentu |
| AAA backend | Home AAA (operator) | DN-AAA (service provider, mis. enterprise/IoT cloud) |
| Output kunci | `MSK` → PMK / K_NAS (link-layer) | `MSK_2` → kunci sesi service + Application Key (OSCORE) |
| Identitas | NAI level operator (mis. `device@operator.id`) | NAI level service (mis. `dev123@iot-cloud.example`) |
| Standar | RFC 3748, IEEE 802.1X | 3GPP TS 33.501 §11, draft-ietf-emu-eap-edhoc §6 |
| Posisi EDHOC | EAP method `0xFE` di EAPOL / RADIUS | EAP method `0xFE` di-tunnel via PDU session |

**Inti perbedaan:** primary memvalidasi *"boleh akses jaringan?"*, secondary
memvalidasi *"boleh akses service ini?"*. Keduanya bisa pakai EAP-EDHOC tetapi
terhadap AAA server yang berbeda dan dengan kunci yang berbeda.

---

## 2. Hubungan & Key Continuity

Primary dan secondary **bisa independen** atau **terikat (cryptographic
binding)** lewat material kunci yang diturunkan dari primary.

```
Primary EAP-EDHOC                  Secondary EAP-EDHOC
─────────────────                  ───────────────────
PRK_out_primary                    PRK_out_secondary
  ├─ MSK_p  (link-layer)             ├─ MSK_s  (service session)
  └─ EMSK_p ──┐               ┌──── └─ Application Key (OSCORE MS)
              │               │
              └──► PSK_input ──┘  (opsional channel-binding)
                   atau "ext" field di EDHOC MSG1
```

- **Tanpa binding** → secondary jalan murni dengan static keys baru (PK_DN,
  PK_DEV_service). Aman, tapi server tidak tahu sesi ini berasal dari device
  yang sama yang sudah primary-auth.
- **Dengan binding** → `EMSK_primary` di-feed sebagai `PSK` atau `ext` field di
  EDHOC MSG1 secondary (`G1` = G_X || H(EMSK_primary)). DN-AAA bisa minta
  primary AAA untuk verifikasi → mencegah service-stealing attack.

> **Application Key** sendiri **tidak dipakai** di secondary handshake;
> Application Key justru *output* dari secondary (untuk OSCORE app data).
> Yang dipakai sebagai *input* binding adalah **EMSK** dari primary.

---

## 3. Sequence Diagram: Full Two-Phase Flow

```mermaid
sequenceDiagram
    autonumber
    participant DEV as IoT Device
    participant AP  as Access Point<br/>(EAP Authenticator #1)
    participant AAA1 as Operator AAA<br/>(FreeRADIUS:3812)
    participant SRV as Application Server<br/>(EAP Authenticator #2)
    participant AAA2 as DN-AAA<br/>(FreeRADIUS:3812 / realm svc)

    rect rgb(235, 245, 255)
    Note over DEV,AAA1: PHASE A — PRIMARY AUTH (network access)
    AP->>DEV: EAP-Request / EAP-EDHOC Start
    DEV->>AP: EAP-Response / EDHOC MSG1 (variant X)
    AP->>DEV: EAP-Request / EDHOC MSG2
    DEV->>AP: EAP-Response / EDHOC MSG3
    AP->>AAA1: RADIUS Access-Request (User-Name = "edhoc_<Variant>@operator")
    AAA1-->>AP: RADIUS Access-Accept
    AP->>DEV: EAP-Success
    Note over DEV,AP: Derive MSK_p, EMSK_p<br/>Link-layer encryption ON (Wi-Fi/5G)
    end

    Note over DEV,SRV: Device sekarang punya konektivitas IP.<br/>Buka sesi ke service ⇒ trigger secondary auth.

    rect rgb(245, 235, 255)
    Note over DEV,AAA2: PHASE B — SECONDARY AUTH (service access via EAP-EDHOC)
    DEV->>SRV: TCP/TLS connect (port 19600)
    SRV->>DEV: EAP-Request / EAP-EDHOC Start (S-flag, Type=0xFE)
    DEV->>SRV: EAP-Response / EDHOC MSG1<br/>SUITES_I, G_X, C_I,<br/>ext = H(EMSK_p)  ← channel binding
    SRV->>DEV: EAP-Request / EDHOC MSG2<br/>(G_Y, C_R, CIPHERTEXT_2)
    DEV->>SRV: EAP-Response / EDHOC MSG3<br/>(CIPHERTEXT_3)
    opt Type 3 PQ (4-message)
        SRV->>DEV: EAP-Request / EDHOC MSG4
        DEV->>SRV: EAP-Response / ACK
    end

    SRV->>AAA2: RADIUS Access-Request<br/>User-Name = "edhoc_<Variant>@svc"<br/>State = H(EMSK_p)  (binding evidence)
    opt Cross-AAA verification (if binding aktif)
        AAA2->>AAA1: Verify EMSK_p binding for device
        AAA1-->>AAA2: OK / NotFound
    end
    AAA2-->>SRV: RADIUS Access-Accept
    SRV->>DEV: EAP-Success
    Note over DEV,SRV: Derive MSK_s, EMSK_s, Application Key<br/>App Key → OSCORE Master Secret
    end

    rect rgb(235, 255, 235)
    Note over DEV,SRV: PHASE C — APPLICATION DATA (protected by OSCORE)
    DEV->>SRV: CoAP/HTTP request (encrypted with App Key)
    SRV->>DEV: CoAP/HTTP response (encrypted with App Key)
    end
```

---

## 4. Sequence Diagram: Secondary Auth Saja (zoom-in)

Asumsi primary auth sudah sukses; device punya `EMSK_p` di memory.

```mermaid
sequenceDiagram
    autonumber
    participant DEV as IoT Device<br/>(EAP Peer)
    participant SRV as Application Server<br/>(EAP Authenticator)
    participant AAA as DN-AAA<br/>(FreeRADIUS)

    Note over DEV: Punya EMSK_primary (64B) dari Phase A
    Note over DEV,SRV: Pre-session: pertukaran static keys khusus service<br/>(PK_DEV_svc, PK_SRV_svc) — beda dari kunci primary

    DEV->>SRV: TCP connect
    SRV->>DEV: EAP-Request / Start (Type=0xFE, S-flag, id=1)

    DEV->>SRV: EAP-Response / MSG1 (Type=0xFE, Code=2)
    Note right of DEV: SUITES_I, G_X (eph), C_I,<br/>EAD_1 = ["binding", H(EMSK_p) ]

    SRV->>AAA: RADIUS Access-Request (probe binding)
    Note right of SRV: User-Name = "edhoc_<Variant>@svc"<br/>State  = H(EMSK_p)<br/>Message-Authenticator
    AAA-->>SRV: RADIUS Access-Challenge<br/>(boleh lanjut handshake)

    SRV->>DEV: EAP-Request / MSG2
    Note right of SRV: G_Y, C_R, CIPHERTEXT_2<br/>(berisi MAC_R atas TH_2 || EAD_1)

    DEV->>SRV: EAP-Response / MSG3
    Note right of DEV: CIPHERTEXT_3<br/>(berisi MAC_I atas TH_3)

    opt Variant Type 3 PQ
        SRV->>DEV: EAP-Request / MSG4
        DEV->>SRV: EAP-Response / ACK
    end

    Note over DEV,SRV: PRK_out_secondary established

    SRV->>AAA: RADIUS Access-Request (final)
    Note right of SRV: User-Name = "edhoc_<Variant>@svc"<br/>User-Password = service shared secret<br/>Class = MSK_s context id
    AAA-->>SRV: RADIUS Access-Accept

    SRV->>DEV: EAP-Success

    Note over DEV,SRV: Derive:<br/>MSK_s         = EDHOC-Expand(PRK_out_s, "EAP-EDHOC MSK", 13, 64)<br/>EMSK_s        = EDHOC-Expand(PRK_out_s, "EAP-EDHOC EMSK", 14, 64)<br/>App Key (OSCORE MS) = EDHOC-Exporter("OSCORE_Master_Secret", 16)

    DEV->>SRV: Application data (OSCORE-protected)
```

---

## 5. Mapping ke Code (kondisi saat ini & gap)

| Komponen | Status | File / catatan |
|---|---|---|
| EAP-EDHOC handshake (5 variant) | ✅ Terimplementasi | [src/eap_variant_*.c](../src/) |
| EAP framing & MSK/EMSK derivation | ✅ Terimplementasi | [src/eap_layer.c](../src/eap_layer.c) — `eap_derive_msk_emsk()` |
| Authenticator + AAA (RADIUS) | ✅ Terimplementasi (primary mode) | [src/benchmark_eap_responder_aaa.c](../src/benchmark_eap_responder_aaa.c) |
| Two-phase (primary + secondary) split | ❌ Belum — saat ini hanya 1 phase | Perlu binary `eap_secondary_initiator` & `eap_secondary_responder` terpisah |
| Channel binding via `EAD_1 = H(EMSK_p)` | ❌ Belum | Tambah `EAD_1` di `run_eap_<variant>_initiator()` ambil `EMSK_p` dari ENV / file |
| Application Key (OSCORE MS) export | ❌ Belum | Panggil `edhoc_exporter("OSCORE_Master_Secret", 16, ...)` setelah handshake |
| DN-AAA realm terpisah dari Operator AAA | ❌ Belum | Tambah realm `@svc` di FreeRADIUS proxy.conf |
| Cross-AAA verification (binding lookup) | ❌ Belum | Custom RADIUS module / Perl unlang policy |

---

## 6. Compliance dengan Standar

| Aspek | Standar | Status diagram ini |
|---|---|---|
| EAP method type 0xFE | draft-ietf-emu-eap-edhoc §3.1 | ✅ |
| Secondary auth dalam PDU session | 3GPP TS 33.501 §11 (Annex U) | ✅ alur sesuai |
| EAP-EDHOC channel binding via EAD | RFC 9528 §3.8 (EAD_1) | ✅ |
| Application Key export | RFC 9528 §4.2 (`EDHOC-Exporter`) | ✅ |
| RADIUS Access-Request/Accept | RFC 2865 / RFC 3579 (EAP over RADIUS) | ✅ |

---

## 7. Ringkasan Jawaban Pertanyaan

> **Q1: Mermaid yang ada itu primary atau secondary?**
> A: Yang sudah ada = **primary authentication** (EAP-EDHOC untuk network
> access dengan FreeRADIUS sebagai backend AAA). Section "Secondary
> Authentication via FreeRADIUS AAA" di file lama itu sebenarnya juga primary
> — penamaan kurang tepat.

> **Q2: Apa primary dan secondary punya hubungan?**
> A: Ya. Hubungan utama lewat **EMSK** dari primary yang di-feed sebagai
> *channel-binding input* (mis. `H(EMSK_p)` di field `EAD_1`) pada secondary
> EDHOC MSG1. Tujuannya supaya server service tahu device ini sudah lulus
> primary auth.

> **Q3: Apakah Application Key primary dipakai di secondary?**
> A: **Tidak.** Application Key justru **output dari secondary** (jadi OSCORE
> master secret untuk app data). Yang menjadi *input binding* dari primary
> adalah **EMSK_primary**, bukan Application Key.
