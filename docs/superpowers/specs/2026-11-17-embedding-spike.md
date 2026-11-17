# Embedding runtime and model spike (v1.2, Task 19)

Status: findings for the controller's ruling. Measurement only; nothing in `src/` changed.

## Method

- Dev machine: Intel Core i5-11300H @ 3.10 GHz (Tiger Lake, AVX2 + AVX-512 + AVX512-VNNI), 8 logical CPUs. The benchmark was pinned to one core (`taskset -c 2`) with ONNX Runtime `intra_threads=1, inter_threads=1`.
- Benchmark: throwaway `examples/embed_bench.rs` (not committed). Rust, release build. Two runtimes: plain `ort 2.0.0-rc.15` + `tokenizers` (own mean pooling and L2 norm) and `fastembed 7.7.1` (`UserDefinedEmbeddingModel`, mean pooling).
- Latency: one text truncated to exactly 300 tokens, batch size 1, 3 warm-ups, median of 15 runs. Cold load = process start to session ready (tokenizer + ONNX session, model file in the OS page cache). Peak RSS = `VmHWM` of a fresh process per configuration.
- Retrieval: 12 synthetic documents (German contracts, insurance, tax, medical-like, invoices, warranty, English counterparts) and 12 queries (4 DE-DE or EN-EN, 8 cross-language), cosine over normalised mean-pooled vectors. E5 uses the `query: ` / `passage: ` prefixes. Top-1 and top-3 are out of 12. With only 12 documents, top-3 is lenient (25% of the corpus) and one query is 8 percentage points: read the numbers as a smoke test, not a benchmark.
- "Padded" retrieval: the same 12 documents with about 250 tokens of unrelated boilerplate appended so each chunk is about 300 tokens, the size the spec will actually embed.
- N150 numbers are **estimates**: single-thread ratio from published benchmarks (below), not measured.

## Results

| Model (revision pinned below) | Runtime | File(s) size | Cold load | Peak RSS | ms / 300-token chunk, dev (measured) | ms / chunk, N150 (estimate) | Top-1 / Top-3 (short docs) | Top-1 / Top-3 (padded to 300 tok) | License |
|---|---|---|---|---|---|---|---|---|---|
| multilingual-e5-small, int8 (`model_qint8_avx512_vnni.onnx`) | ort + tokenizers | 118.3 MB + tokenizer 17.1 MB = 135.4 MB | 0.63 s | 513 MB | 75.9 | 110-190 | 8/12, 12/12 | 9/12, 11/12 | MIT |
| multilingual-e5-small, int8 | fastembed | same | 1.3 s | 775 MB | 75.3 | 110-190 | 8/12, 12/12 | not run | MIT |
| paraphrase-multilingual-MiniLM-L12-v2, int8 (`model_qint8_avx512_vnni.onnx`) | ort + tokenizers | 118.4 MB + tokenizer 9.1 MB = 127.5 MB | 0.64 s | 513 MB | 78.7 | 115-195 | 12/12, 12/12 | **6/12, 8/12** | Apache-2.0 |
| MiniLM, uint8 AVX2 variant (`model_quint8_avx2.onnx`) | ort + tokenizers | 118.5 MB + 9.1 MB | 0.64 s | 513 MB | 110.1 | 160-270 | 12/12, 12/12 | not run | Apache-2.0 |
| multilingual-e5-small fp32 (reference only, over budget) | ort | 470 MB + 17 MB | 1.1 s | 1123 MB | 140.8 | - | 8/12, 11/12 | - | MIT |

Notes on the table:

- The fastembed MiniLM rows were disturbed by other load on the machine (121 ms instead of about 78 ms) and are omitted. fastembed and ort run the same ONNX Runtime and gave the same latency where the runs were clean (E5: 75.3 vs 75.9 ms).
- The first "ort e5" run printed 157 ms because an earlier stray benchmark process shared the core. All numbers in the table are from clean re-runs. Running the same binary inside `debian:trixie-slim` (built in `rust:1.98-trixie`) gave 73.8 ms and 512 MB peak RSS for E5 int8, so the Docker build target behaves as measured.
- E5 int8 matches fp32 on top-1 (8/12 both), so the 8/12 is the model's behaviour on this test set, not quantization damage. The 4 misses were all cross-language queries where the right document was still in the top 3 (E5 puts every score in the 0.8-0.9 band, so ranking margins are small).
- MiniLM was trained with a 128-token limit (sentence-transformers config). It is excellent on short documents (12/12) but dropped to 6/12 on 300-token chunks, which is exactly what the spec embeds. E5-small is trained for 512 tokens and degraded much less (9/12). Both models support 300 tokens technically; only E5 handles it well here.
- Fixed costs: peak RSS is about 513 MB even for a 118 MB model (the 250k-token embedding matrix and ONNX Runtime allocations). It fits the planned `mem_limit: 1536m` with margin, and the model unloads after 10 minutes idle. fastembed adds about 260 MB because it reads the whole model into a `Vec<u8>` and ORT then copies it (`commit_from_memory`); `ort` loading from a file does not.

### N150 estimate (basis)

- Dev CPU: Intel Core i5-11300H. PassMark single-thread about 2,765; Intel N150 about 1,900 (cpubenchmark.net pages, 2026). Ratio 1.46. Geekbench 6 single-core as listed by cpu-monkey: 1,896 vs 1,125, ratio 1.69.
- E5 int8: 75.9 ms x 1.46 to 1.69 = 111-128 ms. The N150 has no AVX-512, and the model file I measured is quantized for AVX-512 VNNI hosts. The AVX2-variant files ran 1.4x slower on the dev machine (110 vs 79 ms), so I widened the range upward to 110-190 ms. **Planning figure: about 150 ms per 300-token chunk per thread.** A 20-page document (about 40 chunks) is then about 6 s of embedding. Treat this as an estimate to be confirmed on the ZimaBoard (`embed_bench` takes minutes to rebuild if wanted).

## Pinned downloads

Hugging Face revision-pinned URLs (`resolve/<commit>/...`), SHA-256 computed on the downloaded files and cross-checked with the LFS hashes the Hub API reports.

### Recommended: intfloat/multilingual-e5-small, revision `614241f622f53c4eeff9890bdc4f31cfecc418b3` (MIT)

| File | Size (bytes) | SHA-256 |
|---|---|---|
| `onnx/model_qint8_avx512_vnni.onnx` | 118,346,824 | `dd476dd0c2514e9b9be83aeb3853fac0763e0bdf4a71645407587d77c48a2d88` |
| `tokenizer.json` | 17,082,730 | `0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39` |

URLs:

- `https://huggingface.co/intfloat/multilingual-e5-small/resolve/614241f622f53c4eeff9890bdc4f31cfecc418b3/onnx/model_qint8_avx512_vnni.onnx`
- `https://huggingface.co/intfloat/multilingual-e5-small/resolve/614241f622f53c4eeff9890bdc4f31cfecc418b3/tokenizer.json`

Only these two files are needed by the plain `ort` path (the tokenizer's truncation and padding are set in code). Total 135.4 MB. Output dimension 384, mean pooling over `last_hidden_state`, L2-normalise, prefixes `query: ` and `passage: `. The ONNX file is the Hub's dynamic-int8 export; despite the `avx512_vnni` name it runs on any x86-64 CPU through ONNX Runtime's generic kernels.

### Alternative: sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2, revision `e8f8c211226b894fcb81acc59f3b34ba3efd5f42` (Apache-2.0)

| File | Size (bytes) | SHA-256 |
|---|---|---|
| `onnx/model_qint8_avx512_vnni.onnx` | 118,412,398 | `783fea82d71a58179b830a4dbd2d58447e640609e98eedf9ffa12622d375a672` |
| `tokenizer.json` | 9,081,518 | `2c3387be76557bd40970cec13153b3bbf80407865484b209e655e5e4729076b8` |

(Same pattern: `https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2/resolve/e8f8c211226b894fcb81acc59f3b34ba3efd5f42/<path>`.) Not recommended, see below.

## ONNX Runtime shipping notes

- Versions: `ort 2.0.0-rc.15` (still a release candidate; the crate has no stable 2.0 yet) with ONNX Runtime **1.31.0**. `fastembed 7.7.1` pins `ort =2.0.0-rc.15`.
- **Default `download-binaries` does not produce a `.so` at all.** The `ort-sys` build script downloads a prebuilt static `libonnxruntime.a` (111.7 MB on disk, from `https://cdn.pyke.io/0/pyke:ort-rs/ms@1.31.0/x86_64-unknown-linux-gnu.tar.lzma2`, SHA-256 `02aac0d3b4927026292088986d7a377c657c88761b1c068be217a67b35447678`, verified by the build script) and links it into the binary. Nothing extra is copied into the runtime image.
- Binary growth: the stripped example (whole app + ort + tokenizers) is 29.7 MB, against 17.0 MB for today's `personal-media` binary, so about +13 MB.
- Dynamic dependencies of the resulting binary: `libstdc++.so.6`, `libgcc_s.so.1`, `libm`, `libc`. Required symbol versions: **GLIBC_2.38** and **GLIBCXX_3.4.31**. `debian:trixie-slim` has glibc 2.41 and `libstdc++.so.6.0.33`, so no `apt install` is needed. Verified: the binary built in `rust:1.98-trixie` ran correctly in `debian:trixie-slim` with no added packages.
- Build-time requirement: the Docker build stage needs network access to `cdn.pyke.io` (pyke's CDN, the only non-Hugging-Face host). The download is hash-checked by `ort-sys`, but it is a third-party host and the first build is not offline-reproducible. Mitigation: vendor the tarball in a cached layer, or set `ORT_LIB_LOCATION` to a copy you host.
- Alternative `load-dynamic`: `ort/load-dynamic` with Microsoft's own release `https://github.com/microsoft/onnxruntime/releases/download/v1.31.0/onnxruntime-linux-x64-1.31.0.tgz` (11,408,003 bytes, SHA-256 `cc5c72baf5ae5c8238a6841f0897227be2d02826b9cf98eaf02fdefaeeb03a57`) and `ORT_DYLIB_PATH`. It avoids the pyke CDN but adds a native library to ship and verify, plus a runtime failure mode if the file is missing. Not needed; static linking is simpler. (Not built or run in this spike.)
- Do not enable `copy-dylibs`/execution-provider features; CPU only.
- Licenses: ONNX Runtime MIT; `ort` MIT OR Apache-2.0; `fastembed` Apache-2.0; `tokenizers` Apache-2.0. No copyleft in the chain. Models: E5 MIT, MiniLM Apache-2.0. Both allow redistribution/downloading as planned.

## Recommendation

**multilingual-e5-small, int8 ONNX (`model_qint8_avx512_vnni.onnx`), on plain `ort` + `tokenizers`, one intra-op thread.**

Reasons:

1. **It holds up at the chunk size the spec uses.** On realistic 300-token chunks E5 kept 9/12 top-1 and 11/12 top-3, while MiniLM fell to 6/12 and 8/12. MiniLM's 12/12 on short text would only carry over if chunks were cut to about 128 tokens, which would triple the vector count and change the spec's chunking.
2. **Size fits:** 135.4 MB total (limit about 150 MB). Quantization costs no measurable quality (int8 equals fp32 on top-1).
3. **Cost:** about 76 ms per chunk on this dev core, estimated 110-190 ms (plan on about 150 ms) on the N150; cold load 0.6 s; peak RSS 513 MB.
4. **Plain `ort` over `fastembed`:** same latency, but 260 MB less peak RSS, half the load time, no `hf-hub`/`image`/`candle`-adjacent dependency surface, and full control over file loading (we already hash-verify the files and load them from `/data/models`, which fastembed's cache logic would not help with). The cost is about 60 lines of our own code for tokenizing, mean pooling and normalising; the benchmark contains a working version.
5. **Licenses are clean** (MIT model, MIT/Apache runtime, static link, no extra shared library to ship).

Concerns and follow-ups for the implementer:

- E5 needs the `query: ` / `passage: ` prefixes (count them in the token budget) and gives compressed cosine scores (0.8-0.9 typical). Rank by score but do not expose a raw absolute threshold as meaningful; any score cutoff needs calibrating.
- The test set is tiny and synthetic. E5's 8/12 top-1 on short documents is below MiniLM's 12/12; cross-language top-1 is the weak spot, top-3 is perfect. If the controller prefers better cross-language precision on short items, consider an extra measurement with the 512-token E5 (`multilingual-e5-base`, about 280 MB int8, over the budget) or hybrid ranking with FTS, which spec §17a already anticipates.
- `ort` is a release candidate (`2.0.0-rc.15`): pin it exactly with `=`. Its API changed from earlier rc versions (`Session::builder` needs an `Environment`).
- Estimate on the N150 should be confirmed on real hardware before the indexing-throughput promises are made. The int8 kernel path on a CPU without AVX-512 is the main uncertainty.
- Truncation must be set explicitly to 300 tokens in our own tokenizer setup: MiniLM's `tokenizer.json` ships with a built-in 128-token truncation, and E5's does not carry one we should rely on.
- The build stage needs access to `cdn.pyke.io` (see above).
