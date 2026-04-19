# Handshake Mermaid (Implemented Flow)

These diagrams describe the EDHOC handshake protocol flows as implemented in the P2P benchmark,
following RFC 9528.

## 1) Type 0 Classic

```mermaid
sequenceDiagram
    autonumber
    participant I as Initiator (Sig Key)
    participant R as Responder (Sig Key)
 
    Note over I: Generate ephemeral ECDH key pair (X, G_X)
    Note over I: Select cipher suite, choose C_I
 
    I->>R: message_1: METHOD=0, SUITES_I, G_X, C_I, ?EAD_1
 
    Note over R: Verify METHOD & cipher suite negotiation
    Note over R: Generate ephemeral ECDH key pair (Y, G_Y)
    Note over R: Choose C_R
    Note over R: TH_2 = H( G_Y, H(message_1) )
    Note over R: G_XY = ECDH(Y, G_X)
    Note over R: PRK_2e = EDHOC_Extract( TH_2, G_XY )
    Note over R: PRK_3e2m = PRK_2e (no static DH for R in method 0)
    Note over R: context_2 = << C_R, ID_CRED_R, TH_2, CRED_R, ?EAD_2 >>
    Note over R: MAC_2 = EDHOC_KDF( PRK_3e2m, 2, context_2, hash_length )
    Note over R: Signature_or_MAC_2 = Sign( R; protected=<<ID_CRED_R>>,<br/>external_aad=<<TH_2,CRED_R,?EAD_2>>, payload=MAC_2 )
    Note over R: PLAINTEXT_2 = ( C_R, ID_CRED_R, Signature_or_MAC_2, ?EAD_2 )
    Note over R: KEYSTREAM_2 = EDHOC_KDF( PRK_2e, 0, TH_2, length(PLAINTEXT_2) )
    Note over R: CIPHERTEXT_2 = PLAINTEXT_2 XOR KEYSTREAM_2
 
    R->>I: message_2: G_Y || CIPHERTEXT_2
 
    Note over I: G_XY = ECDH(X, G_Y)
    Note over I: TH_2 = H( G_Y, H(message_1) )
    Note over I: PRK_2e = EDHOC_Extract( TH_2, G_XY )
    Note over I: Decrypt CIPHERTEXT_2 → PLAINTEXT_2
    Note over I: Retrieve CRED_R via ID_CRED_R
    Note over I: PRK_3e2m = PRK_2e
    Note over I: Recompute MAC_2 and verify Signature_or_MAC_2
    Note over I: TH_3 = H( TH_2, PLAINTEXT_2, CRED_R )
    Note over I: PRK_4e3m = PRK_3e2m (no static DH for I in method 0)
    Note over I: context_3 = << ID_CRED_I, TH_3, CRED_I, ?EAD_3 >>
    Note over I: MAC_3 = EDHOC_KDF( PRK_4e3m, 6, context_3, hash_length )
    Note over I: Signature_or_MAC_3 = Sign( I; protected=<<ID_CRED_I>>,<br/>external_aad=<<TH_3,CRED_I,?EAD_3>>, payload=MAC_3 )
    Note over I: PLAINTEXT_3 = ( ID_CRED_I, Signature_or_MAC_3, ?EAD_3 )
    Note over I: K_3 = EDHOC_KDF( PRK_3e2m, 3, TH_3, key_length )
    Note over I: IV_3 = EDHOC_KDF( PRK_3e2m, 4, TH_3, iv_length )
    Note over I: CIPHERTEXT_3 = AEAD-Encrypt( K_3, IV_3, TH_3, PLAINTEXT_3 )
 
    I->>R: message_3: CIPHERTEXT_3
 
    Note over R: Decrypt CIPHERTEXT_3 with K_3, IV_3, AAD=TH_3
    Note over R: Retrieve CRED_I via ID_CRED_I
    Note over R: Recompute MAC_3 and verify Signature_or_MAC_3
    Note over R: TH_4 = H( TH_3, PLAINTEXT_3, CRED_I )
    Note over R: PRK_4e3m = PRK_3e2m
    Note over R: PRK_out = EDHOC_KDF( PRK_4e3m, 7, TH_4, hash_length )
 
    Note over I: TH_4 = H( TH_3, PLAINTEXT_3, CRED_I )
    Note over I: PRK_out = EDHOC_KDF( PRK_4e3m, 7, TH_4, hash_length )
 
    Note over I,R: Session complete — derive app keys via EDHOC_Exporter(PRK_out)
 
    rect rgb(240, 248, 255)
        Note over R,I: [Optional] message_4: AEAD( K_4, IV_4, TH_4, ?EAD_4 )<br/>Provides key confirmation to Initiator
    end
```

## 2) Type 0 PQ (5-message KEM-only, no signatures)

```mermaid
sequenceDiagram
    autonumber
    participant I as EDHOC INITIATOR<br/>(Long-term static PQ key pair: pk_I, sk_I)
    participant R as EDHOC RESPONDER<br/>(Long-term static PQ key pair: pk_R, sk_R)
 
    Note over I: ── (1) Ephemeral PQ Key Generation ──
    Note over I: pk_eph, sk_eph = kemKeyGen()
 
    I->>R: Message 1: METHOD, SUITES_I, pk_eph, C_I, EAD_1
 
    Note over R: ── (2) PQ Encapsulate ──
    Note over R: ss_eph, ct_eph = kemEncaps(pk_eph)
    Note over R: ss_eph → PRK_2e
    Note over R: TH_2 = H( H(Message_1), ct_eph )
    Note over R: KEYSTREAM_2 = Expand(PRK_2e, TH_2, ...)
    Note over R: PLAINTEXT_2 = (C_R, ID_CRED_R, EAD_2)
    Note over R: CIPHERTEXT_2 = PLAINTEXT_2 XOR KEYSTREAM_2
 
    R->>I: Message 2: ct_eph, Enc(C_R, ID_CRED_R, EAD_2)
 
    Note over I: ── (3) PQ Decapsulate & KEM-based auth of R ──
    Note over I: ss_eph = kemDecaps(ct_eph, sk_eph)
    Note over I: ss_eph → PRK_2e → KEYSTREAM_2
    Note over I: Decrypt CIPHERTEXT_2 → PLAINTEXT_2
    Note over I: ID_CRED_R → X509_R
    Note over I: Verify(pk_CA, X509_R) → pk_R
    Note over I: ── PQ Encapsulate (auth of R) ──
    Note over I: ss_R, ct_R = kemEncaps(pk_R)
    Note over I: ss_R → PRK_3e2m
    Note over I: TH_3 = H( TH_2, PLAINTEXT_2, CRED_R, ct_R )
    Note over I: KEYSTREAM_3 = Expand(PRK_3e2m, TH_3, ...)
    Note over I: K_3 = Expand(PRK_3e2m, TH_3, key_length)
    Note over I: PLAINTEXT_3 = (ID_CRED_I, EAD_3)
    Note over I: CIPHERTEXT_3 = AEAD(K_3, PLAINTEXT_3)
    Note over I: ss_R → PRK_3e2m → K2m
 
    I->>R: Message 3: ct_R, AEAD(ID_CRED_I, EAD_3)
 
    Note over R: ── (4) PQ Decapsulate & KEM-based auth of I ──
    Note over R: ss_R = kemDecaps(ct_R, sk_R)
    Note over R: ss_R → PRK_3e2m
    Note over R: TH_3 = H( TH_2, PLAINTEXT_2, CRED_R, ct_R )
    Note over R: KEYSTREAM_3 = Expand(PRK_3e2m, TH_3, ...)
    Note over R: Decrypt CIPHERTEXT_3 → PLAINTEXT_3
    Note over R: MAC_2 = KDF(PRK_3e2m, ID_CRED_R, TH_4, CRED_R, EAD_4)
    Note over R: ID_CRED_I → X509_I
    Note over R: Verify(pk_CA, X509_I) → pk_I
    Note over R: ── PQ Encapsulate (auth of I) ──
    Note over R: ss_I, ct_I = kemEncaps(pk_I)
    Note over R: ss_I → PRK_4e3m → K_4
    Note over R: TH_4 = H( TH_3, PLAINTEXT_3, CRED_I, ct_I )
    Note over R: ss_I → PRK_4e3m → K3m
    Note over R: PLAINTEXT_4 = (EAD_4, MAC_2)
    Note over R: CIPHERTEXT_4 = AEAD(K_4, PLAINTEXT_4)
 
    R->>I: Message 4: ct_I, AEAD(EAD_4, MAC_2)
 
    Note over I: ── (5) PQ Decapsulate & Finalize ──
    Note over I: ss_I = kemDecaps(ct_I, sk_I)
    Note over I: ss_I → PRK_4e3m
    Note over I: TH_4 = H( TH_3, PLAINTEXT_3, CRED_I, ct_I )
    Note over I: K_4 = Expand(PRK_4e3m, TH_4, key_length)
    Note over I: Decrypt CIPHERTEXT_4 → (EAD_4, MAC_2)
    Note over I: MAC_3 = KDF(PRK_4e3m, ID_CRED_I, TH_5, CRED_I, EAD_5)
    Note over I: Verify(K_3e2m, MAC_2)
    Note over I: PRK_4e3m → PRK_out → Application Key
    Note over I: TH_5 = H( TH_4, PLAINTEXT_4 )
    Note over I: PLAINTEXT_5 = (EAD_5, MAC_3)
    Note over I: CIPHERTEXT_5 = AEAD(K_4, PLAINTEXT_5)
 
    I->>R: Message 5: AEAD(EAD_5, MAC_3)
 
    Note over R: ── (6) Final Verification ──
    Note over R: Decrypt CIPHERTEXT_5 → (EAD_5, MAC_3)
    Note over R: Verify(K_4e3m, MAC_3)
    Note over R: PRK_4e3m → PRK_out → Application Key
 
    Note over I,R: Session complete — derive app keys via PRK_out → PRK_exporter → Expand
```

## 3) Type 3 Classic

```mermaid
sequenceDiagram
    autonumber
    participant I as Initiator (Static DH Key)
    participant R as Responder (Static DH Key)
 
    Note over I: Generate ephemeral ECDH key pair (X, G_X)
    Note over I: Select cipher suite, choose C_I
 
    I->>R: message_1: METHOD=3, SUITES_I, G_X, C_I, ?EAD_1
 
    Note over R: Verify METHOD & cipher suite negotiation
    Note over R: Generate ephemeral ECDH key pair (Y, G_Y)
    Note over R: Choose C_R
    Note over R: TH_2 = H( G_Y, H(message_1) )
    Note over R: G_XY = ECDH(Y, G_X) — ephemeral-ephemeral
    Note over R: PRK_2e = EDHOC_Extract( TH_2, G_XY )
    Note over R: SALT_3e2m = EDHOC_KDF( PRK_2e, 1, TH_2, hash_length )
    Note over R: G_RX = ECDH(R, G_X) — static(R)-ephemeral(I)
    Note over R: PRK_3e2m = EDHOC_Extract( SALT_3e2m, G_RX )
    Note over R: context_2 = << C_R, ID_CRED_R, TH_2, CRED_R, ?EAD_2 >>
    Note over R: MAC_2 = EDHOC_KDF( PRK_3e2m, 2, context_2, mac_length_2 )
    Note over R: Signature_or_MAC_2 = MAC_2 (no signature for static DH)
    Note over R: PLAINTEXT_2 = ( C_R, ID_CRED_R, MAC_2, ?EAD_2 )
    Note over R: KEYSTREAM_2 = EDHOC_KDF( PRK_2e, 0, TH_2, length(PLAINTEXT_2) )
    Note over R: CIPHERTEXT_2 = PLAINTEXT_2 XOR KEYSTREAM_2
 
    R->>I: message_2: G_Y || CIPHERTEXT_2
 
    Note over I: G_XY = ECDH(X, G_Y)
    Note over I: TH_2 = H( G_Y, H(message_1) )
    Note over I: PRK_2e = EDHOC_Extract( TH_2, G_XY )
    Note over I: Decrypt CIPHERTEXT_2 → PLAINTEXT_2
    Note over I: Retrieve CRED_R via ID_CRED_R
    Note over I: SALT_3e2m = EDHOC_KDF( PRK_2e, 1, TH_2, hash_length )
    Note over I: G_RX = ECDH(X, G_R) — ephemeral(I)-static(R)
    Note over I: PRK_3e2m = EDHOC_Extract( SALT_3e2m, G_RX )
    Note over I: Recompute MAC_2 and verify
    Note over I: TH_3 = H( TH_2, PLAINTEXT_2, CRED_R )
    Note over I: SALT_4e3m = EDHOC_KDF( PRK_3e2m, 5, TH_3, hash_length )
    Note over I: G_IY = ECDH(I, G_Y) — static(I)-ephemeral(R)
    Note over I: PRK_4e3m = EDHOC_Extract( SALT_4e3m, G_IY )
    Note over I: context_3 = << ID_CRED_I, TH_3, CRED_I, ?EAD_3 >>
    Note over I: MAC_3 = EDHOC_KDF( PRK_4e3m, 6, context_3, mac_length_3 )
    Note over I: Signature_or_MAC_3 = MAC_3 (no signature for static DH)
    Note over I: PLAINTEXT_3 = ( ID_CRED_I, MAC_3, ?EAD_3 )
    Note over I: K_3 = EDHOC_KDF( PRK_3e2m, 3, TH_3, key_length )
    Note over I: IV_3 = EDHOC_KDF( PRK_3e2m, 4, TH_3, iv_length )
    Note over I: CIPHERTEXT_3 = AEAD-Encrypt( K_3, IV_3, TH_3, PLAINTEXT_3 )
 
    I->>R: message_3: CIPHERTEXT_3
 
    Note over R: Decrypt CIPHERTEXT_3 with K_3, IV_3, AAD=TH_3
    Note over R: Retrieve CRED_I via ID_CRED_I
    Note over R: TH_3 = H( TH_2, PLAINTEXT_2, CRED_R )
    Note over R: SALT_4e3m = EDHOC_KDF( PRK_3e2m, 5, TH_3, hash_length )
    Note over R: G_IY = ECDH(Y, G_I) — ephemeral(R)-static(I)
    Note over R: PRK_4e3m = EDHOC_Extract( SALT_4e3m, G_IY )
    Note over R: Recompute MAC_3 and verify
    Note over R: TH_4 = H( TH_3, PLAINTEXT_3, CRED_I )
    Note over R: PRK_out = EDHOC_KDF( PRK_4e3m, 7, TH_4, hash_length )
 
    Note over I: TH_4 = H( TH_3, PLAINTEXT_3, CRED_I )
    Note over I: PRK_out = EDHOC_KDF( PRK_4e3m, 7, TH_4, hash_length )
 
    Note over I,R: Session complete — derive app keys via EDHOC_Exporter(PRK_out)
 
    rect rgb(240, 248, 255)
        Note over R,I: [Optional] message_4: AEAD( K_4, IV_4, TH_4, ?EAD_4 )<br/>Provides key confirmation to Initiator
    end
```

## 4) Type 3 PQ (4-message encrypted MSG1, 3 KEM ops)

```mermaid
sequenceDiagram
    autonumber
    participant I as EDHOC INITIATOR<br/>(Long-term static PQ key pair: pk_I, sk_I)
    participant R as EDHOC RESPONDER<br/>(Long-term static PQ key pair: pk_R, sk_R)
 
    Note over I: ══════ (1) Initiator Setup ══════
    Note over I: Ephemeral PQ Key Generation
    Note over I: pk_eph, sk_eph = kemKeyGen()
    Note over I: ── PQ Encapsulate (to R's static key) ──
    Note over I: ss_R, ct_R = kemEncaps(pk_R)
    Note over I: ss_R → PRK_1e → K_1
    Note over I: TH_1 = H(pk_eph, ct_R)
    Note over I: PLAINTEXT_1 = (METHOD, SUITES_I, ID_CRED_I, C_I, EAD_1)
    Note over I: CIPHERTEXT_1 = AEAD(K_1, PLAINTEXT_1)
 
    I->>R: Message 1: ct_R, pk_eph, AEAD(METHOD, SUITES_I, ID_CRED_I, C_I, EAD_1)
 
    Note over R: ══════ (2) Responder Processing ══════
    Note over R: ── PQ Decapsulate (auth of I→R) ──
    Note over R: ss_R = kemDecaps(ct_R, sk_R)
    Note over R: ss_R → PRK_1e → K_1
    Note over R: Decrypt CIPHERTEXT_1 → PLAINTEXT_1
    Note over R: ── PQ Encapsulate (ephemeral) ──
    Note over R: ss_eph, ct_eph = kemEncaps(pk_eph)
    Note over R: ss_eph → PRK_2m → K2m
    Note over R: MAC_2 = KDF(PRK_2m, ID_CRED_R, TH_2, CRED_R, EAD_2)
    Note over R: ── Verify I's certificate ──
    Note over R: ID_CRED_I → X509_I
    Note over R: Verify(pk_CA, X509_I) → pk_I
    Note over R: ── PQ Encapsulate (auth of I) ──
    Note over R: ss_I, ct_I = kemEncaps(pk_I)
    Note over R: ss_I → PRK_2e3e3m → K_2
    Note over R: ss_I → PRK_2e3e3m → K3m
    Note over R: ss_I → PRK_2e3e3m → K_3
    Note over R: TH_2 = H(H(Message_1), ct_eph, ct_I)
    Note over R: PLAINTEXT_2 = (C_R, ID_CRED_R, EAD_2, MAC_2)
    Note over R: CIPHERTEXT_2 = AEAD(K_2, PLAINTEXT_2)
 
    R->>I: Message 2: ct_eph, ct_I, AEAD(C_R, ID_CRED_R, EAD_2, MAC_2)
 
    Note over I: ══════ (3) Initiator Verification ══════
    Note over I: ── PQ Decapsulate (ephemeral) ──
    Note over I: ss_eph = kemDecaps(ct_eph, sk_eph)
    Note over I: ss_eph → PRK_2m → K2m
    Note over I: ── PQ Decapsulate (auth of I) ──
    Note over I: ss_I = kemDecaps(ct_I, sk_I)
    Note over I: ss_I → PRK_2e3e3m → K_2
    Note over I: Decrypt CIPHERTEXT_2 → PLAINTEXT_2
    Note over I: ── Verify MAC_2 ──
    Note over I: Verify(K_2m, MAC_2)
    Note over I: MAC_3 = KDF(PRK_2e3e3m, ID_CRED_I, TH_3, CRED_I, EAD_3)
    Note over I: ss_I → PRK_2e3e3m → K_3
    Note over I: TH_3 = H(TH_2, PLAINTEXT_2, CRED_R)
    Note over I: PLAINTEXT_3 = (ID_CRED_I, EAD_3, MAC_3)
    Note over I: CIPHERTEXT_3 = AEAD(K_3, PLAINTEXT_3)
 
    I->>R: Message 3: AEAD(EAD_3, MAC_3)
 
    Note over R: ══════ (4) Responder Final Verification ══════
    Note over R: Decrypt CIPHERTEXT_3 → (EAD_3, MAC_3)
    Note over R: Verify(K_2e3e3m, MAC_3)
    Note over R: PRK_2e3e3m → PRK_out → Application Key
 
    Note over R: TH_4 = H(TH_3, PLAINTEXT_3, CRED_I)
    Note over R: K_4 = Expand(PRK_2e3e3m, TH_4, ...)
    Note over R: PLAINTEXT_4 = (EAD_4)
    Note over R: CIPHERTEXT_4 = AEAD(K_4, PLAINTEXT_4)
 
    R->>I: Message 4: AEAD(EAD_4)
 
    Note over I: Decrypt Message 4
    Note over I: PRK_2e3e3m → PRK_out → Application Key
 
    Note over I,R: Session complete — derive app keys via PRK_out → PRK_exporter → Expand
```

## 5) Type 3 Hybrid

```mermaid
sequenceDiagram
    autonumber
    participant I as Initiator I<br/>((a, A ≡ gᵃ), (R, B))
    participant R as Responder R<br/>((b, B ≡ gᵇ), (I, A))

    Note over I: ══════ Setup ══════
    Note over I: Generate PQ-KEM key pair
    Note over I: (sk_KEM, PK_KEM) = PQ-KEM.KeyGen(PRKEM)
    Note over I: Generate ephemeral ECDH key pair
    Note over I: (x, X = gˣ)

    I->>R: M1 = (METHOD, SUITES_I, X, PK_KEM, C_I, EAD_1)

    Note over R: ══════ Responder Processing ══════
    Note over R: ── PQ-KEM Encapsulate ──
    Note over R: (k_KEM, C_KEM) = PQ-KEM.Encaps(PK_KEM)
    Note over R: Generate ephemeral ECDH key pair (y, Y)
    Note over R: ── Key Schedule ──
    Note over R: TH_2 = H(Y, M1, C_KEM)
    Note over R: PRK_2 = Extract(Xʸ, k_KEM, TH_2)
    Note over R: EK_2 = Expand(PRK_2, TH_2)
    Note over R: ── Static DH: ephemeral(I)-static(R) ──
    Note over R: PRK_3e2m = Extract(Xᵇ, PRK_2)
    Note over R: MK_2 = Expand(PRK_3e2m, TH_2)
    Note over R: MAC_2 = KDF(MK_2, C_R, X, TH_2, B, EAD_2, len_2)
    Note over R: msg_2 = (C_R, R, MAC_2, EAD_2)
    Note over R: CIPHERTEXT_2 = Enc(EK_2, msg_2)

    R->>I: M2 = (Y, C_KEM, Enc_EK₂(msg_2))

    Note over I: ══════ Initiator Verification & Response ══════
    Note over I: ── PQ-KEM Decapsulate ──
    Note over I: k_KEM = PQ-KEM.Decaps(sk_KEM, C_KEM)
    Note over I: ── Key Schedule ──
    Note over I: TH_2 = H(Y, M1, C_KEM)
    Note over I: PRK_2 = Extract(Yˣ, k_KEM, TH_2)
    Note over I: EK_2 = Expand(PRK_2, TH_2)
    Note over I: msg_2 = Dec(EK_2, CIPHERTEXT_2)
    Note over I: (C_R, R, MAC_2, EAD_2) = msg_2
    Note over I: ── Static DH: ephemeral(I)-static(R) ──
    Note over I: PRK_3e2m = Extract(Bˣ, PRK_2)
    Note over I: MK_2 = Expand(PRK_3e2m, TH_2)
    Note over I: ── Verify MAC_2 ──
    Note over I: Verify MAC_2
    Note over I: ── Prepare Message 3 ──
    Note over I: TH_3 = H(TH_2, msg_2, B)
    Note over I: (EK_3, IV_3) = Expand(PRK_3e2m, TH_3)
    Note over I: ── Static DH: static(I)-ephemeral(R) ──
    Note over I: PRK_4e3m = Extract(Yᵃ, PRK_3e2m)
    Note over I: MK_3 = Expand(PRK_4e3m, TH_3)
    Note over I: MAC_3 = KDF(MK_3, I, TH_3, A, EAD_3, len_3)
    Note over I: msg_3 = (I, MAC_3, EAD_3)
    Note over I: CIPHERTEXT_3 = Enc(EK_3, IV_3, msg_3)
    Note over I: ── Derive session keys ──
    Note over I: TH_4 = H(TH_3, msg_3, A)
    Note over I: PRK_out = Expand(PRK_4e3m, TH_4)
    Note over I: AK = Expand(Expand(PRK_out))

    I->>R: M3 = Enc_EK₃(msg_3)

    Note over R: ══════ Responder Final Verification ══════
    Note over R: TH_3 = H(TH_2, msg_2, B)
    Note over R: (EK_3, IV_3) = Expand(PRK_3e2m, TH_3)
    Note over R: msg_3 = Dec(EK_3, IV_3, CIPHERTEXT_3)
    Note over R: (I, MAC_3, EAD_3) = msg_3
    Note over R: ── Static DH: static(I)-ephemeral(R) ──
    Note over R: PRK_4e3m = Extract(Aʸ, PRK_3e2m)
    Note over R: MK_3 = Expand(PRK_4e3m, TH_3)
    Note over R: ── Verify MAC_3 ──
    Note over R: Verify MAC_3
    Note over R: ── Derive session keys ──
    Note over R: TH_4 = H(TH_3, msg_3, A)
    Note over R: PRK_out = Expand(PRK_4e3m, TH_4)
    Note over R: AK = Expand(Expand(PRK_out))

    Note over I,R: Session complete — Application Key (AK) established
```

## Notes

- Type 0 Classic and Type 3 Classic diagrams follow RFC 9528 key schedule.
- Type 0 PQ, Type 3 PQ, and Type 3 Hybrid use post-quantum KEM-based key exchange.
- EDHOC_KDF labels: 0=KEYSTREAM_2, 1=SALT_3e2m, 2=MAC_2, 3=K_3, 4=IV_3, 5=SALT_4e3m, 6=MAC_3, 7=PRK_out.
