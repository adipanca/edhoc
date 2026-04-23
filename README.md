# EDHOC PQ Benchmark Workspace

Benchmark handshake EDHOC pasca-kuantum (PQ) untuk lima varian draft
**PAPOn** (Section 2, 3.2, 3.3, 3.4, 3.5) dengan tiga skenario
benchmark yang sebanding section-by-section:

1. **Non-EAP (baseline)** - EDHOC murni di atas UDP loopback.
2. **EAP standalone** - EDHOC dibungkus EAP-Request/Response, NAS
   menerbitkan `EAP-Success` sendiri.
3. **EAP + AAA hop** - sama seperti (2), ditambah satu round-trip
   RADIUS Access-Request/Access-Accept ke server FreeRADIUS lokal
   sehingga kita bisa memisahkan biaya AAA dari biaya kripto/EAP.

Lima varian PAPOn yang ditangani:

| Section   | Mode kriptografi yang diuji            | Catatan |
| --------- | -------------------------------------- | ------- |
| Section2  | I = Sign, R = Sign-KEM                 | 3 message |
| Section32 | I = Sign, R = Sign-(KEM+Sign)          | 3 message |
| Section33 | I = KEM,  R = (KEM+Sign)               | 4 message + ack |
| Section34 | I = KEM,  R = Sign                     | 4 message + ack |
| Section35 | I = KEM,  R = KEM                      | 4 message + ack |

Algoritma yang dipakai untuk operasi kripto (lewat PQClean dan
mbedTLS/libsodium):

- **KEM**: ML-KEM-768 (PQClean clean reference).
- **Signature**: ML-DSA-65 (PQClean clean reference).
- **Hash / KDF**: SHA-256 + HKDF (mbedTLS).
- **AEAD**: ChaCha20-Poly1305 (libsodium) untuk pesan EDHOC yang
  membutuhkan AEAD; SHAKE/SHA-2 dipakai oleh PQClean common.
- **MD5 / HMAC-MD5**: hanya untuk encoding RADIUS PAP +
  Message-Authenticator (RFC 2865 / RFC 3579), bukan untuk EDHOC.

Hasil benchmark per-mode ditulis ke `output/detail/*.csv`, lalu skrip
`scripts/merge_benchmarks.py` menggabungkan menjadi file ber-`;` di
`output/result/*.csv` agar mudah dibaca di spreadsheet.

## 1. Struktur repository

```
edhoc/
  Makefile                     <- build seluruh binary (dijalankan dari root)
  include/                     <- public headers (-Iinclude saat compile)
    eap_wrap.h
    edhoc_plaintext.h
    aaa_radius.h
    pqclean_adapter.h
    benchmark.h
  src/                         <- source EDHOC + EAP + AAA
    p2p_initiator.c            (mode 1: Non-EAP)
    p2p_responder.c
    p2p_eap_initiator.c        (mode 2: EAP standalone)
    p2p_eap_responder.c
    p2p_eap_aaa_initiator.c    (mode 3: wrapper -DBENCH_AAA / BENCH_TAG="_aaa")
    p2p_eap_aaa_responder.c
    eap_wrap.c                 (EAP framing + fragmentasi)
    edhoc_plaintext.c          (lima varian PAPOn EDHOC)
    aaa_radius.c               (klien RADIUS PAP + Message-Authenticator)
    pqclean_adapter.c          (jembatan PQClean untuk KEM/Sign)
    benchmark.c                (pengukuran waktu, RSS, fragmentasi)
  build/                       <- artefak hasil build (auto-generated)
    initiator, responder       (wrapper bash 1-perintah)
    p2p_*                      (binary per mode)
  scripts/
    run_all_initiator.sh       (jalankan 3 mode lalu merge)
    run_all_responder.sh
    merge_benchmarks.py        (gabungkan CSV per-mode)
    freeradius_aaa/
      prepare.sh               (siapkan tree raddb v3 di output/)
      run_server.sh            (jalankan FreeRADIUS foreground)
      smoke_test.sh            (radclient PAP test)
  lib/
    PQClean/                   (ML-KEM-768, ML-DSA-65 - submodule)
    uoscore-uedhoc/            (header mbedTLS, helper - submodule)
    freeradius-server/         (referensi v4 - submodule, opsional)
  output/
    detail/                    <- CSV per-mode/per-role (mentah)
    result/                    <- CSV gabungan ber-';' (final)
    freeradius_aaa/            <- raddb v3 hasil prepare.sh
  docs/
    handshake_mermaid_eap_papon.md
    handshake_mermaid_aaa_papon.md          (3 aktor: Sup-NAS-AAA)
    edhoc_draft_alignment_matrix.md
    p2p_realcode_mermaid_section2_35.md
  README.md
```

## 2. Arsitektur tiga mode benchmark

```mermaid
flowchart LR
  subgraph M1[Mode 1 - Non-EAP]
    I1[p2p_initiator] -- EDHOC msg1/2/3/(4) --> R1[p2p_responder]
  end
  subgraph M2[Mode 2 - EAP standalone]
    I2[p2p_eap_initiator] -- EAP-encapsulated EDHOC --> R2[p2p_eap_responder]
    R2 -- EAP-Success --> I2
  end
  subgraph M3[Mode 3 - EAP + AAA hop]
    I3[p2p_eap_aaa_initiator] -- EAP-encapsulated EDHOC --> R3[p2p_eap_aaa_responder]
    R3 -- RADIUS PAP --> AAA[FreeRADIUS<br/>127.0.0.1:3812]
    AAA -- Access-Accept --> R3
    R3 -- EAP-Success --> I3
  end
```

Detil sequence diagram per section/varian ada di
[docs/handshake_mermaid_eap_papon.md](docs/handshake_mermaid_eap_papon.md)
dan [docs/handshake_mermaid_aaa_papon.md](docs/handshake_mermaid_aaa_papon.md).

## 3. Clone & install dependency

Workspace ini memakai submodule `lib/PQClean`,
`lib/uoscore-uedhoc`, dan `lib/freeradius-server` (opsional).

```bash
git clone <repo-url> edhoc
cd edhoc
git submodule update --init --recursive lib/PQClean lib/uoscore-uedhoc
# Submodule FreeRADIUS hanya dibutuhkan kalau ingin pakai source-tree v4
# (mode AAA juga jalan dengan FreeRADIUS sistem v3, lihat bagian 6).
git submodule update --init lib/freeradius-server || true
```

Dependency sistem (Ubuntu/Debian/Raspberry Pi OS):

```bash
sudo apt update
sudo apt install -y \
    build-essential pkg-config python3 \
    libsodium-dev libmbedtls-dev \
    freeradius freeradius-utils    # untuk mode AAA
```

Pada Raspberry Pi (arm64/armhf) cukup paket yang sama; build dilakukan
native di Pi. PQClean dan uoscore-uedhoc dibawa lewat submodule jadi
tidak perlu paket tambahan.

## 4. Build

```bash
make -j"$(nproc)"
```

(Dijalankan dari root repo - `Makefile` ada di root.)

Binary yang dihasilkan di `build/`:

| Binary                    | Mode                |
| ------------------------- | ------------------- |
| `p2p_initiator`           | Non-EAP, sisi I     |
| `p2p_responder`           | Non-EAP, sisi R     |
| `p2p_eap_initiator`       | EAP standalone, I   |
| `p2p_eap_responder`       | EAP standalone, R   |
| `p2p_eap_aaa_initiator`   | EAP + AAA hop, I    |
| `p2p_eap_aaa_responder`   | EAP + AAA hop, R    |

Wrapper `p2p_eap_aaa_*` adalah file 3-baris yang
`#define BENCH_AAA + BENCH_TAG "_aaa"` lalu `#include` source EAP yang
sama, sehingga tidak ada duplikasi logic.

Bersihkan artefak: `make clean`.

## 5. Quickstart - jalankan 3 mode dalam 1 perintah

Satu perintah `./build/responder` di sisi server dan satu perintah
`./build/initiator` di sisi klien menjalankan **ketiga mode**
(Non-EAP, EAP standalone, EAP+AAA) berurutan, lalu otomatis
menggabungkan semua CSV ke `output/result/`.

### Loopback (satu host)

Terminal A (server):

```bash
./build/responder 15000
```

Terminal B (client):

```bash
./build/initiator 127.0.0.1 15000
```

Wrapper otomatis memakai port:
- `15000` -> Non-EAP (`p2p_{initiator,responder}`)
- `15001` -> EAP standalone (`p2p_eap_*`)
- `15002` -> EAP + AAA (`p2p_eap_aaa_*`)

Dan otomatis:
- menjalankan `scripts/freeradius_aaa/prepare.sh` saat pertama kali
  (kalau `output/freeradius_aaa/raddb` belum ada),
- start FreeRADIUS di UDP/3812 untuk durasi mode 3 lalu mematikannya,
- panggil `scripts/merge_benchmarks.py --result-dir output/result`
  setelah ketiga mode selesai.

Tunable lewat env var (sama di kedua sisi):

```bash
ITER=10 CRYPTO_ITER=10 MTU=512 EAP_METHOD=57 ./build/responder 15000
ITER=10 CRYPTO_ITER=10 MTU=512 EAP_METHOD=57 ./build/initiator 127.0.0.1 15000
```

Flag opsional:
- `SKIP_FREERADIUS=1` (responder) - jangan start FreeRADIUS, gunakan
  yang sudah jalan.
- `START_DELAY=2` (initiator) - jeda antar mode, naikkan kalau
  responder lambat siap.
- `AAA_PORT=3812` (responder) - port UDP FreeRADIUS.

Hasil akhir:
- Per-mode CSV mentah di `output/detail/*.csv`.
- File gabungan ber-`;` di `output/result/*.csv` (lihat bagian 9).

## 6. Run manual per mode (opsional)

Kalau ingin menjalankan satu mode saja, gunakan binary aslinya.

### Mode 1 - Non-EAP

```bash
./build/p2p_responder 9090 5 5
./build/p2p_initiator 127.0.0.1 9090 5 5
```

### Mode 2 - EAP standalone

```bash
./build/p2p_eap_responder 9095 5 5 256 57
./build/p2p_eap_initiator 127.0.0.1 9095 5 5 256 57
```

### Mode 3 - EAP + AAA hop

Lihat bagian 7 untuk setup FreeRADIUS, kemudian:

```bash
./build/p2p_eap_aaa_responder 9097 5 5 256 57
./build/p2p_eap_aaa_initiator 127.0.0.1 9097 5 5 256 57
```

Argumen umum: `<port|ip+port> <iter> <crypto_iter> [<mtu> <eap_method>]`.

Output per-mode (sebelum merge) ditulis ke `output/detail/`:
- `output/detail/benchmark_crypto_{initiator,responder}.csv`
- `output/detail/benchmark_fullhandshake_{operation,overhead,processing}_p2p[_eap[_aaa]]_{initiator,responder}.csv`
- `output/detail/benchmark_fragmentation[_eap[_aaa]]_{initiator,responder}.csv` (mode 2 & 3)
- `output/detail/benchmark_eap_keymat[_eap[_aaa]]_{initiator,responder}.csv` (mode 2 & 3)
- `output/detail/internal_test_vectors_sections[_eap[_aaa]].csv`
- `output/detail/benchmark_aaa_auth_p2p_eap_aaa_responder.csv` (mode 3)

## 7. Setup FreeRADIUS untuk mode AAA

`./build/responder` mengurus ini secara otomatis. Bagian ini hanya
relevan kalau Anda menjalankan binary mode 3 secara manual atau ingin
mengontrol FreeRADIUS sendiri.

### 7.1 Siapkan FreeRADIUS sekali per workspace

```bash
sudo systemctl stop freeradius || true       # bebaskan port 1812
./scripts/freeradius_aaa/prepare.sh           # build raddb v3 di output/
```

`prepare.sh` akan:
- meniru `/etc/freeradius/3.0` ke `output/freeradius_aaa/raddb`
  (atau pakai submodule `lib/freeradius-server` kalau v3),
- mendengarkan UDP **3812** (auth) / **3813** (acct),
- mematikan modul EAP (kita bench hanya hop RADIUS, bukan EAP-in-RADIUS),
- menambahkan user PAP per section dan client `127.0.0.1` dengan
  shared secret `testing123`.

### 7.2 Jalankan FreeRADIUS

Terminal A (biarkan terbuka):

```bash
./scripts/freeradius_aaa/run_server.sh
```

Smoke test (opsional):

```bash
./scripts/freeradius_aaa/smoke_test.sh 127.0.0.1 3812 testing123 \
    edhoc_Section2 edhoc-pass
# Harus melihat 'Received Access-Accept'.
```

### 7.3 Jalankan benchmark manual

Lihat bagian 6 ("Mode 3"). User PAP per section yang dibikin oleh
`prepare.sh`:

| Section   | User-Name        | Password    |
| --------- | ---------------- | ----------- |
| Section2  | `edhoc_Section2` | `edhoc-pass` |
| Section32 | `edhoc_Section32`| `edhoc-pass` |
| Section33 | `edhoc_Section33`| `edhoc-pass` |
| Section34 | `edhoc_Section34`| `edhoc-pass` |
| Section35 | `edhoc_Section35`| `edhoc-pass` |

## 8. Run terdistribusi (Initiator di Raspberry Pi, Responder di server)

Sama persis dengan quickstart di bagian 5, hanya saja initiator memakai
IP server (bukan `127.0.0.1`).

```
+-------------------+        EDHOC / EAP / RADIUS         +---------------+
| Raspberry Pi      |  <----------------------------->    |  Server       |
| ./build/initiator |                                     | ./build/      |
|   <server-ip>     |                                     |   responder   |
|   <base_port>     |                                     |   <base_port> |
+-------------------+                                     |  + freeradius |
                                                          +---------------+
```

Langkah:

1. **Build di kedua sisi** (clone + `make -j` di repo masing-masing).
   Pastikan versi PQClean/mbedTLS sama.
2. **Buka firewall** di server untuk tiga port UDP berurutan
   (`<base_port>`, `<base_port>+1`, `<base_port>+2`).
3. **Server** (jalankan dari root repo):

   ```bash
   ITER=10 CRYPTO_ITER=10 ./build/responder 15000
   ```

4. **Raspberry Pi**:

   ```bash
   ITER=10 CRYPTO_ITER=10 ./build/initiator 192.168.1.10 15000
   ```

5. **Kumpulkan CSV** untuk merge gabungan dua-sisi:

   ```bash
   # Di server, salin CSV initiator dari Pi
   scp pi@raspberrypi:edhoc/output/detail/*_initiator.csv server:edhoc/output/detail/
   scp pi@raspberrypi:edhoc/output/detail/internal_test_vectors_sections*.csv server:edhoc/output/detail/
   # Lalu re-merge
   python3 scripts/merge_benchmarks.py --output-dir output/detail --result-dir output/result
   ```

   (Wrapper sudah memanggil merger di tiap sisi, jadi `output/result/`
   lokal sudah valid - tapi kolom `Initiator` di sisi server akan kosong
   sampai Anda salin CSV initiator dari Pi.)

6. **Catatan timing**: kolom `txrx_us` / `io_wait_us` akan ikut
   mengukur RTT jaringan riil (bukan loopback), jadi jangan
   bandingkan langsung dengan run loopback.

## 9. Gabungkan CSV per-mode menjadi satu file

Wrapper `./build/responder` dan `./build/initiator` sudah memanggil ini
secara otomatis dan menyimpan hasilnya di `output/result/`.
Untuk run manual:

```bash
python3 scripts/merge_benchmarks.py --result-dir output/result
# atau dengan direktori berbeda:
python3 scripts/merge_benchmarks.py --output-dir /path/to/output \
                                    --result-dir /path/to/output/result
```

Akan menghasilkan (semuanya pakai delimiter `;`):

| File | Isi |
| ---- | --- |
| `benchmark_fullhandshake_processing_p2p_.csv` | processing/txrx/precomp/total per section, mode, role |
| `benchmark_fullhandshake_overhead_p2p_.csv`   | cpu/wall/crypto/io/residual per section, mode, role |
| `benchmark_fullhandshake_operation_p2p_.csv`  | breakdown per operasi (KeyGen/Encaps/Decaps/HKDF/HASH/AEAD/Sign/Verify) |
| `benchmark_fullhandshake_fragmentation_p2p_.csv` | byte/wire/fragments per pesan (hanya EAP & AAA) |
| `benchmark_crypto_.csv`                       | benchmark crypto-only |
| `benchmark_eap_keymat_.csv`                   | MSK/EMSK per mode (hanya EAP & AAA) |
| `internal_test_vectors_sections_.csv`         | test vector internal per mode |
| `benchmark_aaa_auth_p2p_.csv`                 | RTT RADIUS PAP per section (hanya AAA) |

Setiap baris diberi kolom **`status EAP`** dengan nilai
`Non-EAP`, `Standalone`, atau `AAA`.

## 10. Semantik metrik overhead

File `benchmark_fullhandshake_overhead_*.csv` memakai kolom:
- `cpu_time_us` - CPU time proses (CLOCK_PROCESS_CPUTIME_ID).
- `wall_time_us` - end-to-end lokal (CLOCK_MONOTONIC).
- `cpu_to_wall_ratio` - rasio keduanya.
- `protocol_state_est_bytes` - estimasi working-set state protokol.
- `rss_peak_bytes` - peak RSS proses (termasuk runtime + library).
- `crypto_time_est_us` - total operasi kripto terinstrumentasi.
- `io_wait_us` - waktu blocking di socket (di mode AAA termasuk RTT
  ke FreeRADIUS).
- `residual_overhead_us` = `wall - crypto - io` (parse/serialize/copy).

Catatan:
- `io_wait_us` dapat memuat waktu komputasi peer karena read blocking.
- `rss_peak_bytes` biasanya datar antar section; gunakan
  `protocol_state_est_bytes` untuk membandingkan section.
- Untuk publikasi disarankan menjalankan multi-run (20-30 run) dan
  melaporkan median + sebaran.

## 11. Implementasi singkat per komponen

- **EAP wrapper** (`src/eap_wrap.c`): server-initiated, fase
  `Identity` -> `EDHOC-Start` -> Message1..3(/4 + ack) -> `EAP-Success`.
  Fragmentasi MTU dengan reassembly. Section33/34/35 mengirim Message4
  + ACK, Section2/32 tidak.
- **AAA hop** (`src/aaa_radius.c`): satu Access-Request PAP per
  iterasi handshake, dengan **Message-Authenticator HMAC-MD5**
  (RFC 3579 §3.2) supaya tidak diblok BlastRADIUS check FreeRADIUS
  modern. Hasil RTT diakumulasi per section dan dipublish ke
  `benchmark_aaa_auth_p2p_eap_aaa_responder.csv`.
- **PQClean adapter** (`src/pqclean_adapter.c`): tipis, hanya
  forward ke ML-KEM-768 / ML-DSA-65 PQClean clean.
- **Benchmark runtime** (`src/benchmark.c`): wallclock + CPU-time +
  RSS sampling, plus akumulator per-operasi.

## 12. Dokumentasi tambahan

- [docs/handshake_mermaid_eap_papon.md](docs/handshake_mermaid_eap_papon.md) -
  sequence diagram per section untuk mode EAP standalone.
- [docs/handshake_mermaid_aaa_papon.md](docs/handshake_mermaid_aaa_papon.md) -
  sequence diagram 3 aktor (Supplicant - NAS - FreeRADIUS) per section.
- [docs/edhoc_draft_alignment_matrix.md](docs/edhoc_draft_alignment_matrix.md) -
  pemetaan implementasi ke draft PAPOn.
- [docs/p2p_realcode_mermaid_section2_35.md](docs/p2p_realcode_mermaid_section2_35.md) -
  diagram code-level Section2..Section35.
