# Real Code Mermaid Flow (Section2, Section32, Section33, Section34, Section35)

Dokumen ini sudah disinkronkan dengan implementasi terbaru di:
- src/p2p_initiator.c
- src/p2p_responder.c
- src/edhoc_plaintext.c

## Canonical Format yang Dibekukan di Kode

### PLAINTEXT_2
Urutan field (canonical internal):
1. `c_r` (1 byte)
2. `id_cred_r` (32 byte)
3. `th2` (32 byte)
4. `mac2` (32 byte)
5. `ead_len` (u16, big-endian)
6. `ead` (0..65535 byte)

### PLAINTEXT_2A
`PLAINTEXT_2 || SIGNATURE_2 || sig2_len(u16)`

### PLAINTEXT_3
1. `id_cred_i` (32 byte)
2. `sig3_len` (u16)
3. `sig3`
4. `ead_len` (u16)
5. `ead`

### PLAINTEXT_4
1. `has_mac2` (1 byte)
2. `mac2` (32 byte)
3. `ead_len` (u16)
4. `ead`

Catatan implementasi:
- Pada section tanpa MAC_2 di pesan tertentu, field `mac2` tetap ada (diisi nol) agar format tetap canonical.
- `ead` saat ini dikirim kosong (`ead_len = 0`) di semua section.
- `ID_CRED_R` dipilih sesuai mode autentikasi responder: hash `kem_pk_R` untuk Section2/34, hash `sign_pk_R` untuk Section32/33/35.

## Konvensi KDF / Transcript (Sesuai Kode)
- `ID_CRED_I = SHA-256(sign_pk_I)`
- `ID_CRED_R = SHA-256(kem_pk_R)` untuk Section2/34, dan `SHA-256(sign_pk_R)` untuk Section32/33/35
- `TH_2 = H(kem.ct_eph || H(MSG1))`
- `KEYSTREAM_2 = KDF(PRK_2e, label=0, context=TH_2, len=|PLAINTEXT_2A|)`
- `SALT_3e2m = KDF(PRK_2e, label=1, context=TH_2, len=32)`
- `PRK_3e2m = Extract(SALT_3e2m, ss_R)` untuk Section2/32/34/35
- `PRK_3e2m = PRK_2e` untuk Section33
- `TH_3 = H(TH_2 || PLAINTEXT_2 || ID_CRED_R)`
- `MAC_3 = KDF(PRK_3e2m, label=6, context=(ID_CRED_I || TH_3), len=32)`
- `TH_4 = H(TH_3 || PLAINTEXT_3 || ID_CRED_I)`
- `SALT_4e3m = KDF(PRK_3e2m, label=5, context=TH_4, len=32)`
- `PRK_4e3m = Extract(SALT_4e3m, ss_I)`
- `K_3/IV_3` dan `K_4/IV_4` dari label `8/9`

## Section2 (Sign-KEM)

```mermaid
sequenceDiagram
    participant I as Initiator
    participant R as Responder

    I->>I: Generate eph KEM (pk_eph_i, sk_eph_i)
    I->>I: Encaps to static KEM_R -> (ct_r, ss_r)
    I->>R: MSG1 = pk_eph_i || ct_r

    R->>R: ss_r = Decaps(ct_r)
    R->>R: (ct_eph, ss_eph) = Encaps(pk_eph_i)
    R->>R: TH2, PRK2e
    R->>R: PRK3e2m = Extract(KDF(PRK2e,label1,TH2), ss_r)
    R->>R: MAC2 = KDF(PRK3e2m,label2,(c_r,id_cred_r,TH2))
    R->>R: PLAINTEXT2 (canonical), SIGNATURE2 kosong
    R->>R: CIPHERTEXT2 = PLAINTEXT2A XOR KEYSTREAM2
    R->>I: MSG2 = ct_eph || CIPHERTEXT2

    I->>I: Recover PLAINTEXT2A, decode canonical
    I->>I: Verify id_cred_r, th2, MAC2
    I->>I: PRK3e2m = Extract(KDF(PRK2e,label1,TH2), ss_r)
    I->>I: TH3, MAC3, SIGNATURE3
    I->>R: MSG3 = AEAD(K3,IV3,AAD=TH3,PLAINTEXT3)

    R->>R: Decrypt MSG3, decode PLAINTEXT3 canonical
    R->>R: Verify SIGNATURE3 over (ID_CRED_I,TH3,MAC3,EAD3)
```

## Section32 (Sign-(KEM+Sign))

```mermaid
sequenceDiagram
    participant I as Initiator
    participant R as Responder

    I->>I: Generate eph KEM
    I->>R: MSG1 = pk_eph_i

    R->>R: (ct_eph, ss_eph), TH2, PRK2e
    R->>R: Build PLAINTEXT2 canonical (mac2 zeroed)
    R->>R: SIGNATURE2 = Sign(PLAINTEXT2)
    R->>R: PLAINTEXT2A = PLAINTEXT2 || SIGNATURE2 || sig2_len
    R->>I: MSG2 = ct_eph || (PLAINTEXT2A XOR KEYSTREAM2)

    I->>I: Decode PLAINTEXT2A, verify SIGNATURE2(PLAINTEXT2)
    I->>I: Encaps static KEM_R -> (ct_r2, ss_r2)
    I->>I: PRK3e2m from ss_r2, derive TH3/MAC3/SIGNATURE3
    I->>R: MSG3 = ct_r2 || AEAD(K3,IV3,AAD=TH3,PLAINTEXT3)

    R->>R: Decaps ct_r2, derive PRK3e2m
    R->>R: Decrypt MSG3, verify SIGNATURE3
```

## Section33 ((KEM+Sign)-Sign)

```mermaid
sequenceDiagram
    participant I as Initiator
    participant R as Responder

    I->>R: MSG1 = pk_eph_i

    R->>R: Build PLAINTEXT2 canonical (mac2 = KDF(PRK2e,label2,(c_r,id_cred_r,TH2)))
    R->>R: SIGNATURE2 = Sign(PLAINTEXT2)
    R->>I: MSG2 = ct_eph || (PLAINTEXT2A XOR KEYSTREAM2)

    I->>I: Decode+verify SIGNATURE2, verify MAC2 dari PRK2e
    I->>I: PRK3e2m = PRK2e
    I->>R: MSG3 = AEAD(K3,IV3,AAD=TH3,PLAINTEXT3)

    R->>R: Verify SIGNATURE3 over (ID_CRED_I,TH3,MAC3,EAD3)
    R->>R: TH4, PRK4e3m from ss_I
    R->>R: PLAINTEXT4 canonical with has_mac2=0
    R->>I: MSG4 = ct_i || AEAD(K4,IV4,AAD=TH4,PLAINTEXT4)

    I->>I: Decaps ct_i, derive PRK4e3m
    I->>I: Decrypt+decode PLAINTEXT4 (has_mac2 must be 0)
```

## Section34 ((KEM+Sign)-KEM)

```mermaid
sequenceDiagram
    participant I as Initiator
    participant R as Responder

    I->>R: MSG1 = pk_eph_i

    R->>R: Build PLAINTEXT2 canonical (mac2 zeroed, tanpa SIGNATURE2)
    R->>I: MSG2 = ct_eph || (PLAINTEXT2A XOR KEYSTREAM2)

    I->>I: Decode PLAINTEXT2A (sig2_len = 0)
    I->>I: Encaps static KEM_R -> (ct_r2, ss_r2)
    I->>R: MSG3 = ct_r2 || AEAD(K3,IV3,AAD=TH3,PLAINTEXT3)

    R->>R: Verify SIGNATURE3 over (ID_CRED_I,TH3,MAC3,EAD3)
    R->>R: TH4, PRK4e3m from ss_I
    R->>R: MAC2 = KDF(PRK4e3m,label2,(c_r,id_cred_r,TH4))
    R->>R: PLAINTEXT4 canonical with has_mac2=1
    R->>I: MSG4 = ct_i || AEAD(K4,IV4,AAD=TH4,PLAINTEXT4)

    I->>I: Decode PLAINTEXT4, verify has_mac2=1
    I->>I: Verify MAC2
```

## Section35 ((KEM+Sign)-(KEM+Sign))

```mermaid
sequenceDiagram
    participant I as Initiator
    participant R as Responder

    I->>R: MSG1 = pk_eph_i

    R->>R: Build PLAINTEXT2 canonical (mac2 zeroed)
    R->>R: SIGNATURE2 = Sign(PLAINTEXT2)
    R->>I: MSG2 = ct_eph || (PLAINTEXT2A XOR KEYSTREAM2)

    I->>I: Verify SIGNATURE2
    I->>I: Encaps static KEM_R -> (ct_r2, ss_r2)
    I->>R: MSG3 = ct_r2 || AEAD(K3,IV3,AAD=TH3,PLAINTEXT3)

    R->>R: Verify SIGNATURE3 over (ID_CRED_I,TH3,MAC3,EAD3)
    R->>R: TH4, PRK4e3m from ss_I
    R->>R: PLAINTEXT4 canonical with has_mac2=0
    R->>I: MSG4 = ct_i || AEAD(K4,IV4,AAD=TH4,PLAINTEXT4)

    I->>I: Decode PLAINTEXT4 (has_mac2=0)
```
