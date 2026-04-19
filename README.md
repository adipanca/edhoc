# EDHOC-Hybrid P2P Benchmark

Repository ini berisi implementasi benchmark EDHOC untuk skenario P2P:
- Initiator dijalankan di Raspberry Pi
- Responder dijalankan di server
- Komunikasi antar node menggunakan TCP socket

Benchmark dijalankan untuk 5 varian:
1. Type 0 Classic (sig-sig) — X25519 + Ed25519 sign/verify + certificate
2. Type 0 PQ (sig-sig) — ML-KEM-768 + ML-DSA-65 sign/verify + certificate
3. Type 3 Classic (mac-mac) — X25519 static DH + MAC
4. Type 3 PQ (mac-mac) — ML-KEM-768 + MAC
5. Type 3 Hybrid (mac-mac) — X25519 + ML-KEM-768 + MAC

Status implementasi terbaru:
- Setiap varian dipisah ke 1 file source tersendiri (inisiator + responder dalam file yang sama).
- **Type 0 Classic**: 3-message sig-sig, Ed25519 signature over MAC, certificate exchange (Ed25519 public key).
- **Type 0 PQ**: 3-message sig-sig, ML-DSA-65 signature over MAC, certificate exchange (ML-DSA-65 public key), ephemeral key exchange via ML-KEM-768.
- **Type 3 Classic**: 3-message mac-mac, autentikasi via static X25519 DH + MAC.
- **Type 3 PQ**: 4-message mac-mac, 3 operasi ML-KEM-768 + MAC, Message 1 terenkripsi.
- **Type 3 Hybrid**: 3-message mac-mac, X25519 ECDHE + ML-KEM-768 + HMAC-SHA256.
- Diagram flow terbaru tersedia di `docs/handshake_mermaid.md`.

## Ringkasan Fitur

- Benchmark pure crypto (micro-benchmark) di kedua sisi: initiator dan responder
- Benchmark full handshake per varian dengan pemisahan metrik:
  - per-operation time
  - processing vs tx/rx
  - CPU dan memory overhead
- Output otomatis ke 8 file CSV di direktori output
- Build khusus benchmark P2P memakai Makefile terpisah
- PQClean dipaksa compile dengan `-O0` agar sesuai requirement

## Mapping Algoritma ke Library

Tabel berikut merangkum pemetaan algoritma yang dipakai pada benchmark P2P:

| Algoritma | Library | Keterangan |
|---|---|---|
| X25519 (keygen/scalarmult) | libsodium | Untuk jalur classic dan hybrid |
| Ed25519 (sign/verify) | libsodium | Untuk Type 0 Classic (sig-sig, certificate) |
| ML-KEM-768 (keygen/encaps/decaps) | PQClean | Untuk jalur PQ dan hybrid |
| ML-DSA-65 (sign/verify) | PQClean | Untuk Type 0 PQ (sig-sig, certificate) |
| SHA-256 | libsodium | Untuk hash pada benchmark P2P |
| HKDF (HMAC-SHA256) | libsodium | Untuk derivasi key material |
| AEAD (AES-GCM) | mbedTLS | Dipakai pada benchmark crypto dan jalur classic/hybrid |

Catatan implementasi:
- Build P2P mengompilasi source PQClean dari `lib/PQClean`.
- Flag compile PQClean di `Makefile.p2p_bench` menggunakan `-O0`.
- **Type 0 (sig-sig)**: Kedua varian (Classic & PQ) menggunakan certificate (public key exchange) dan signature over MAC untuk autentikasi. Type 0 Classic memakai Ed25519, Type 0 PQ memakai ML-DSA-65.
- **Type 3 (mac-mac)**: Tidak menggunakan certificate/signature. Autentikasi via MAC yang diderivasi dari shared secret (static DH atau KEM).
- Type 3 PQ handshake menggunakan 3 operasi KEM (ct_R, ct_eph, ct_I) dengan Message 1 terenkripsi.

## Dependensi

Install dependensi sistem berikut:

```bash
sudo apt update
sudo apt install -y build-essential libsodium-dev
```

Submodule yang dibutuhkan:

```bash
git submodule update --init --recursive
```

Komponen yang digunakan:
- uoscore-uedhoc: base EDHOC + external mbedTLS
- PQClean: ML-KEM-768 dan ML-DSA-65
- libsodium: X25519, Ed25519, SHA-256, HKDF
- mbedTLS: AES-GCM dan fungsi kripto pendukung

## Build

Build benchmark P2P:

```bash
make -f Makefile.p2p_bench
```

Target lain:

```bash
make -f Makefile.p2p_bench initiator
make -f Makefile.p2p_bench responder
make -f Makefile.p2p_bench clean
```

Output binary:
- `build/p2p_initiator`
- `build/p2p_responder`

## Cara Pakai (P2P)

Jalankan responder dulu di server:

```bash
./build/p2p_responder [port]
```

Contoh:

```bash
./build/p2p_responder 19500
```

Lalu jalankan initiator di Raspberry Pi:

```bash
./build/p2p_initiator <server_ip> [port]
```

Contoh:

```bash
./build/p2p_initiator 10.0.0.2 19500
```

Flow eksekusi:
1. Kedua sisi menjalankan benchmark pure crypto
2. Initiator connect ke responder
3. Kedua sisi menjalankan 5 varian handshake
4. CSV ditulis otomatis ke direktori `output`

Contoh run lokal (satu mesin):

```bash
./build/p2p_responder 19501 &
sleep 1
./build/p2p_initiator 127.0.0.1 19501
```

Hasil validasi terakhir (ringkas):
- Semua 5 varian berhasil dijalankan end-to-end (initiator & responder)
- CSV berhasil ditulis lengkap (8 file)

## Output CSV

Berikut 8 file output yang dihasilkan:

1. `output/benchmark_crypto_initiator.csv`
2. `output/benchmark_crypto_responder.csv`
3. `output/benchmark_fullhandshake_operation_p2p_initiator.csv`
4. `output/benchmark_fullhandshake_operation_p2p_responder.csv`
5. `output/benchmark_fullhandshake_overhead_p2p_initiator.csv`
6. `output/benchmark_fullhandshake_overhead_p2p_responder.csv`
7. `output/benchmark_fullhandshake_processing_p2p_initiator.csv`
8. `output/benchmark_fullhandshake_processing_p2p_responder.csv`

Format utama:
- `benchmark_crypto_*`: statistik operasi kripto (`avg_us`, `stddev_us`, `min_us`, `max_us`, `median_us`)
- `benchmark_fullhandshake_operation_*`: rata-rata waktu per operasi per handshake
- `benchmark_fullhandshake_overhead_*`: CPU usage dan memory usage
- `benchmark_fullhandshake_processing_*`: breakdown `processing_us`, `txrx_us`, `precomputation_us`, `total_us`

## Struktur Direktori

Struktur inti project:

```text
edhoc/
├── Makefile
├── Makefile.crypto_bench
├── Makefile.p2p_bench
├── README.md
├── note.txt
├── include/
│   ├── edhoc_benchmark_p2p.h
│   ├── edhoc_pq_kem.h
│   ├── edhoc_common.h
│   ├── edhoc_type0_classic.h
│   ├── edhoc_type0_pq.h
│   ├── edhoc_type3_classic.h
│   ├── edhoc_type3_pq.h
│   ├── edhoc_type3_hybrid.h
│   └── edhoc_type3_x25519_testvec.h
├── src/
│   ├── benchmark_p2p_common.c
│   ├── benchmark_p2p_initiator.c
│   ├── benchmark_p2p_responder.c
│   ├── edhoc_pq_kem.c
│   ├── edhoc_common.c
│   ├── variant_type0_classic.c
│   ├── variant_type0_pq.c
│   ├── variant_type3_classic.c
│   ├── variant_type3_pq.c
│   ├── variant_type3_hybrid.c
│   ├── pqclean_kem.c
│   ├── pqclean_sig.c
│   ├── crypto_libsodium.c
│   └── main.c
├── lib/
│   ├── PQClean/
│   ├── uoscore-uedhoc/
│   └── freeradius-server/
├── build/
└── output/
```

## Catatan Tambahan

- Default port benchmark P2P: `19500`
- Iterasi default benchmark:
  - Crypto: `1000`
  - Handshake: `100`
- Konfigurasi ada di `include/edhoc_benchmark_p2p.h`
- Jika ingin membandingkan hasil antar perangkat, gunakan konfigurasi iterasi yang sama dan minimalkan background load pada kedua mesin

## Referensi Flow Handshake

- Diagram Mermaid terbaru untuk semua varian ada di `docs/handshake_mermaid.md`
- Section yang sudah diupdate sesuai implementasi terbaru:
  - Type 0 Classic (3-message sig-sig, Ed25519 + X25519)
  - Type 0 PQ (3-message sig-sig, ML-DSA-65 + ML-KEM-768)
  - Type 3 PQ (4-message mac-mac, encrypted MSG1)

## Perbandingan Autentikasi Varian

| Varian | Method | Key Exchange | Signature | Certificate | Messages |
|---|---|---|---|---|---|
| Type 0 Classic | sig-sig | X25519 ECDHE | Ed25519 | Ed25519 public key | 3 |
| Type 0 PQ | sig-sig | ML-KEM-768 | ML-DSA-65 | ML-DSA-65 public key | 3 |
| Type 3 Classic | mac-mac | X25519 static DH | — | — | 3 |
| Type 3 PQ | mac-mac | ML-KEM-768 (×3) | — | — | 4 |
| Type 3 Hybrid | mac-mac | X25519 + ML-KEM-768 | — | — | 3 |
