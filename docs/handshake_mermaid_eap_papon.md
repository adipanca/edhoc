# EAP Standalone Handshake Mermaid (PAPOn)

Dokumen ini menjelaskan flow benchmark EAP-standalone yang membungkus alur EDHOC existing untuk Section2, Section32, Section33, Section34, dan Section35.

Implementasi kode terkait:
- src/p2p_eap_initiator.c
- src/p2p_eap_responder.c
- src/eap_wrap.c

Catatan implementasi benchmark:
- Flow kriptografi EDHOC per section tetap sama dengan varian non-EAP.
- Pembungkus EAP dilakukan untuk pesan benchmark (credential exchange + Message1/2/3/4) dengan EAP Request/Response semantics.
- Ada fase EAP Identity, EAP-Request/EDHOC-Start, dan EAP-Success.
- Fragmentasi EAP aktif berbasis MTU (`mtu` CLI), dengan reassembly di sisi penerima.
- EAP Method Type dapat dikonfigurasi via CLI (default suggested draft `57`).
- Setelah tiap section selesai, benchmark menurunkan MSK/EMSK dari key schedule final dan menulis CSV output.
- Profil benchmark ini mempertahankan pola Message4 sesuai varian code saat ini: Section33/34/35 mengirim Message4, Section2/32 tidak.

## Section2 (IKR: Sign-KEM)

```mermaid
sequenceDiagram
    autonumber
    participant I as Initiator
    participant A as Authenticator (logical)
    participant R as Responder

    rect rgba(100, 150, 200, 0.1)
    R->>A: EAP-Request/Identity
    A->>I: EAP-Request/Identity
    I->>A: EAP-Response/Identity
    A->>R: EAP-Response/Identity
    R->>A: EAP-Request/EDHOC-Start
    A->>I: EAP-Request/EDHOC-Start
    end

    I->>A: EAP-Response/EDHOC(Message1 = pk_eph_i || ct_r)
    A->>R: Message1 fragments

    R->>R: Decaps ct_r, Encaps pk_eph_i, TH2, PRK2e, PRK3e2m
    R->>R: MAC2 from PRK3e2m
    R->>A: EAP-Request/EDHOC(Message2 = ct_eph || CIPHERTEXT2)
    A->>I: Message2 fragments

    I->>I: Decaps ct_eph, verify MAC2, derive TH3/MAC3/SIGNATURE3
    I->>A: EAP-Response/EDHOC(Message3)
    A->>R: Message3 fragments

    R->>R: Verify SIGNATURE3, derive final key context
    R->>A: EAP-Success
    A->>I: EAP-Success
```

## Section32 (Sign-(KEM+Sign))

```mermaid
sequenceDiagram
    autonumber
    participant I as Initiator
    participant A as Authenticator (logical)
    participant R as Responder

    R->>A: EAP-Request/Identity
    A->>I: EAP-Request/Identity
    I->>A: EAP-Response/Identity
    A->>R: EAP-Response/Identity
    R->>A: EAP-Request/EDHOC-Start
    A->>I: EAP-Request/EDHOC-Start

    I->>A: Message1 (pk_eph_i) via EAP Response fragments
    A->>R: Message1 fragments
    R->>R: Build PLAINTEXT2 + SIGNATURE2
    R->>A: Message2 (ct_eph || CIPHERTEXT2) via EAP Request fragments
    A->>I: Message2 fragments

    I->>I: Verify SIGNATURE2, Encaps static KEM_R -> ct_r2
    I->>A: Message3 (ct_r2 || CIPHERTEXT3) via EAP Response fragments
    A->>R: Message3 fragments

    R->>R: Decaps ct_r2, verify SIGNATURE3
    R->>A: EAP-Success
    A->>I: EAP-Success
```

## Section33 ((KEM+Sign)-Sign)

```mermaid
sequenceDiagram
    autonumber
    participant I as Initiator
    participant A as Authenticator (logical)
    participant R as Responder

    R->>A: EAP-Request/Identity
    A->>I: EAP-Request/Identity
    I->>A: EAP-Response/Identity
    A->>R: EAP-Response/Identity
    R->>A: EAP-Request/EDHOC-Start
    A->>I: EAP-Request/EDHOC-Start

    I->>A: Message1 via EAP Response
    A->>R: Message1 fragments
    R->>R: Build PLAINTEXT2 (includes MAC2 from PRK2e) + SIGNATURE2
    R->>A: Message2 via EAP Request
    A->>I: Message2 fragments

    I->>I: Verify MAC2 + SIGNATURE2, set PRK3e2m=PRK2e
    I->>A: Message3 via EAP Response
    A->>R: Message3 fragments

    R->>R: Verify SIGNATURE3, derive TH4/PRK4e3m
    R->>A: Message4 (ct_i || CIPHERTEXT4) via EAP Request
    A->>I: Message4 fragments

    I->>I: Decaps ct_i, derive PRK4e3m, decrypt Message4
    I->>A: EAP-Response/EDHOC (empty ack)
    A->>R: EAP-Response/EDHOC (empty ack)

    R->>A: EAP-Success
    A->>I: EAP-Success
```

## Section34 ((KEM+Sign)-KEM)

```mermaid
sequenceDiagram
    autonumber
    participant I as Initiator
    participant A as Authenticator (logical)
    participant R as Responder

    R->>A: EAP-Request/Identity
    A->>I: EAP-Request/Identity
    I->>A: EAP-Response/Identity
    A->>R: EAP-Response/Identity
    R->>A: EAP-Request/EDHOC-Start
    A->>I: EAP-Request/EDHOC-Start

    I->>A: Message1 via EAP Response
    A->>R: Message1 fragments
    R->>A: Message2 via EAP Request (tanpa SIGNATURE2)
    A->>I: Message2 fragments

    I->>I: Encaps static KEM_R -> ct_r2, derive PRK3e2m
    I->>A: Message3 (ct_r2 || CIPHERTEXT3) via EAP Response
    A->>R: Message3 fragments

    R->>R: Verify SIGNATURE3, encaps to I -> ct_i
    R->>R: Derive PRK4e3m dan MAC2 deferred di Message4
    R->>A: Message4 (ct_i || CIPHERTEXT4 with MAC2) via EAP Request
    A->>I: Message4 fragments

    I->>I: Verify MAC2 dari PRK4e3m
    I->>A: EAP-Response/EDHOC (empty ack)
    A->>R: EAP-Response/EDHOC (empty ack)

    R->>A: EAP-Success
    A->>I: EAP-Success
```

## Section35 ((KEM+Sign)-(KEM+Sign))

```mermaid
sequenceDiagram
    autonumber
    participant I as Initiator
    participant A as Authenticator (logical)
    participant R as Responder

    R->>A: EAP-Request/Identity
    A->>I: EAP-Request/Identity
    I->>A: EAP-Response/Identity
    A->>R: EAP-Response/Identity
    R->>A: EAP-Request/EDHOC-Start
    A->>I: EAP-Request/EDHOC-Start

    I->>A: Message1 via EAP Response
    A->>R: Message1 fragments
    R->>A: Message2 via EAP Request (SIGNED PLAINTEXT2)
    A->>I: Message2 fragments

    I->>I: Verify SIGNATURE2, Encaps static KEM_R -> ct_r2
    I->>A: Message3 (ct_r2 || CIPHERTEXT3) via EAP Response
    A->>R: Message3 fragments

    R->>R: Verify SIGNATURE3, encaps to I -> ct_i, derive PRK4e3m
    R->>A: Message4 via EAP Request
    A->>I: Message4 fragments

    I->>I: Decaps ct_i, derive PRK4e3m, decrypt Message4
    I->>A: EAP-Response/EDHOC (empty ack)
    A->>R: EAP-Response/EDHOC (empty ack)

    R->>A: EAP-Success
    A->>I: EAP-Success
```

## Fragmentasi EAP (MTU)

Aturan di implementasi wrapper:
- Payload EDHOC dipecah menjadi beberapa EAP packet jika melebihi `mtu`.
- Tiap fragmen membawa `flags` bitfield `R|S|M|L` dan `edhoc_type` (Message1..4 atau credential exchange).
- `L` bits dipakai pada fragmen pertama untuk mengindikasikan panjang field EDHOC-message-length (saat terfragmentasi).
- Penerima melakukan reassembly berdasarkan `identifier` EAP dan `edhoc_type`.

## Method Type dan Keluaran Kunci

- Method Type EAP dapat dipilih lewat argumen CLI.
- Nilai default memakai Method Type `57` (suggested value di draft).
- Setelah tiap section selesai, key schedule final dipakai untuk turunkan:
  - `MSK` (64 byte)
  - `EMSK` (64 byte)
- Output ditulis ke CSV:
  - output/benchmark_eap_keymat_initiator.csv
  - output/benchmark_eap_keymat_responder.csv
