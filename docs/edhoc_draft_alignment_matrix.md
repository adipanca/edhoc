# EDHOC Draft Alignment Matrix (Current Code)

Dokumen ini mencocokkan implementasi saat ini terhadap draft EDHOC model Papon yang kita pakai pada audit sebelumnya, satu per satu per item kritis.

## Referensi Implementasi
- [src/p2p_initiator.c](src/p2p_initiator.c)
- [src/p2p_responder.c](src/p2p_responder.c)
- [src/edhoc_plaintext.h](src/edhoc_plaintext.h)
- [src/edhoc_plaintext.c](src/edhoc_plaintext.c)
- [output/internal_test_vectors_sections.csv](output/internal_test_vectors_sections.csv)

## Status Ringkas
- Canonical encoding PLAINTEXT_2/3/4: implemented (frozen in one codec module)
- Internal vectors TH_2/TH_3/TH_4, MAC_2/3, PRK_4e3m: implemented
- Formula transcript/kdf labels sesuai model audit: implemented

## Detail Kecocokan

1. TH_2
- Target: TH_2 = H(kem.ct_eph || H(MSG1))
- Status: Match
- Bukti code: inisiator dan responder menghitung `hm1 = H(MSG1)` lalu `TH2 = H(ct_eph || hm1)`.

2. PLAINTEXT_2 canonical
- Target: field tetap dan parser deterministik
- Status: Match (custom-canonical internal)
- Format dibekukan di codec:
  - c_r: 1 byte
  - id_cred_r: 32 bytes
  - th2: 32 bytes
  - mac2: 32 bytes
  - ead_len: u16 big-endian
  - ead bytes

3. PLAINTEXT_2A + CIPHERTEXT_2
- Target: PLAINTEXT_2A dienkripsi dengan keystream
- Status: Match
- `PLAINTEXT_2A = PLAINTEXT_2 || SIGNATURE2 || sig2_len(u16)`
- `CIPHERTEXT_2 = PLAINTEXT_2A XOR KEYSTREAM_2`

4. TH_3
- Target: TH_3 = H(TH_2 || PLAINTEXT_2 || ID_CRED_R)
- Status: Match
- Keduanya memakai plaintext2 hasil decode (bukan ciphertext).

5. MAC_3 / SIGNATURE_3 context
- Target: SIGNATURE_3 mengikat identitas + transcript + MAC_3
- Status: Match
- `MAC_3 = KDF(PRK_3e2m, label 6, ID_CRED_I||TH_3)`
- `SIGNATURE_3 = Sign(ID_CRED_I||TH_3||MAC_3)`

6. TH_4 dan PRK_4e3m (Section33/34/35)
- Target: TH_4 dan PRK_4e3m eksplisit
- Status: Match
- `TH_4 = H(TH_3 || PLAINTEXT_3 || ID_CRED_I)`
- `SALT_4e3m = KDF(PRK_3e2m, label 5, TH_4)`
- `PRK_4e3m = Extract(SALT_4e3m, ss_I)`

7. Section34 MAC_2 di MSG4
- Target: MAC_2 harus ada di PLAINTEXT_4
- Status: Match
- `MAC_2 = KDF(PRK_4e3m, label 2, (C_R,ID_CRED_R,TH_4))`
- Diverifikasi oleh Initiator setelah decrypt MSG4.

8. PLAINTEXT_3 canonical
- Status: Match (custom-canonical internal)
- Format:
  - id_cred_i: 32 bytes
  - sig3_len: u16
  - sig3 bytes
  - ead_len: u16
  - ead bytes

9. PLAINTEXT_4 canonical
- Status: Match (custom-canonical internal)
- Format:
  - has_mac2: 1 byte
  - mac2: 32 bytes
  - ead_len: u16
  - ead bytes

## Internal Test Vectors
File: [output/internal_test_vectors_sections.csv](output/internal_test_vectors_sections.csv)

Per section berisi:
- `th2`
- `th3`
- `th4` (kosong untuk Section2/32)
- `mac2` (terisi pada Section2 dan Section34)
- `mac3`
- `prk4e3m` (terisi pada Section33/34/35)

## Batasan yang Perlu Dicatat
- Encoding ini canonical internal proyek, belum CBOR canonical wire-format EDHOC IETF final.
- Label KDF sudah dipindahkan ke integer, tetapi konstruk info KDF masih custom internal (tetap konsisten antar sisi).
- Untuk interoperabilitas lintas implementasi EDHOC standar, tahap berikutnya perlu migrasi penuh ke struktur/encoding wire-format draft final yang dipilih.
