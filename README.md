# EDHOC PQ Benchmark Workspace

Workspace ini berisi benchmark handshake EDHOC PQ dengan dua mode:
- Non-EAP baseline (existing)
- EAP standalone wrapper (baru), untuk komparasi section-by-section

## Build

```bash
cd src
make -j2
```

Binary yang dihasilkan:
- `build/p2p_initiator`
- `build/p2p_responder`
- `build/p2p_eap_initiator`
- `build/p2p_eap_responder`

## Run Non-EAP (baseline)

Terminal 1:

```bash
./build/p2p_responder 9090 2 5
```

Terminal 2:

```bash
./build/p2p_initiator 127.0.0.1 9090 2 5
```

Output baseline utama:
- `output/benchmark_crypto_initiator.csv`
- `output/benchmark_crypto_responder.csv`
- `output/benchmark_fullhandshake_operation_p2p_initiator.csv`
- `output/benchmark_fullhandshake_operation_p2p_responder.csv`
- `output/benchmark_fullhandshake_overhead_p2p_initiator.csv`
- `output/benchmark_fullhandshake_overhead_p2p_responder.csv`
- `output/benchmark_fullhandshake_processing_p2p_initiator.csv`
- `output/benchmark_fullhandshake_processing_p2p_responder.csv`
- `output/internal_test_vectors_sections.csv`

## Run EAP Standalone

Argumen tambahan EAP:
- `mtu`: batas ukuran EAP packet untuk fragmentasi
- `method_type`: EAP Method Type (default `57`, suggested di draft EAP-EDHOC)

Terminal 1:

```bash
./build/p2p_eap_responder 9095 2 5 256 57
```

Terminal 2:

```bash
./build/p2p_eap_initiator 127.0.0.1 9095 2 5 256 57
```

Output EAP utama:
- `output/benchmark_crypto_eap_initiator.csv`
- `output/benchmark_crypto_eap_responder.csv`
- `output/benchmark_fullhandshake_operation_p2p_eap_initiator.csv`
- `output/benchmark_fullhandshake_operation_p2p_eap_responder.csv`
- `output/benchmark_fullhandshake_overhead_p2p_eap_initiator.csv`
- `output/benchmark_fullhandshake_overhead_p2p_eap_responder.csv`
- `output/benchmark_fullhandshake_processing_p2p_eap_initiator.csv`
- `output/benchmark_fullhandshake_processing_p2p_eap_responder.csv`
- `output/internal_test_vectors_sections_eap.csv`
- `output/benchmark_eap_keymat_initiator.csv` (MSK/EMSK)
- `output/benchmark_eap_keymat_responder.csv` (MSK/EMSK)

## Overhead Metric Semantics

File overhead (`benchmark_fullhandshake_overhead_*.csv`) memakai kolom berikut:
- `cpu_time_us`: CPU time proses lokal (CLOCK_PROCESS_CPUTIME_ID), tidak termasuk waktu idle scheduler.
- `wall_time_us`: waktu end-to-end lokal per section (CLOCK_MONOTONIC).
- `cpu_to_wall_ratio`: rasio `cpu_time_us / wall_time_us`.
- `protocol_state_est_bytes`: estimasi working-set state protokol per section (berbasis operasi kripto yang benar-benar dipanggil).
- `rss_peak_bytes`: peak RSS proses (termasuk baseline library/runtime), bukan memory state protokol murni.
- `crypto_time_est_us`: total waktu operasi kripto yang diinstrumentasi (`KeyGen/Encaps/Decaps/HKDF/HASH/AEAD/Sign/Verify`).
- `io_wait_us`: waktu blocking di socket send/recv lokal.
- `residual_overhead_us`: `wall_time_us - crypto_time_est_us - io_wait_us` (parse/serialize/copy/misc framework overhead).

Catatan interpretasi:
- `io_wait_us` dapat memuat waktu tunggu komputasi endpoint lawan karena read blocking menunggu peer mengirim data.
- `rss_peak_bytes` biasanya flat antar section; gunakan `protocol_state_est_bytes` untuk komparasi section-level.
- Untuk analisis akademik, disarankan jalankan multi-run (mis. 20-30 run) dan laporkan median + sebaran.

## Implementasi EAP Wrapper

- Flow kriptografi per section tetap sama dengan baseline non-EAP.
- EAP identity mengikuti server-initiated semantics: Request/Identity dulu dari responder.
- Pesan benchmark dibungkus dalam EAP Request/Response packet.
- Fase tambahan: `Identity`, `EDHOC-Start`, `EAP-Success`.
- Untuk section yang memakai Message4 (Section33/34/35), initiator mengirim EAP-Response kosong sebagai ACK sebelum EAP-Success.
- Fragmentasi/reassembly EAP ditangani berdasarkan MTU.

Dokumentasi handshake EAP tersedia di:
- `docs/handshake_mermaid_eap_papon.md`
