A reference built by reading the actual `Cisco-Talos/clamav` source (libclamav core + Rust modules). File paths are relative to the repo root so you can jump straight to the implementation. Everything is GPLv2 — fine to study, just respect the license if you copy code.

---

## 1. Engine architecture (the skeleton you'd replicate first)

The whole thing is the `libclamav` library; the CLI tools (`clamscan`, `clamd`, `freshclam`, `sigtool`…) are thin wrappers around it. Public API is in **`libclamav/clamav.h`**.

Three concepts hold the design together:

- **`struct cl_engine`** — the loaded, compiled signature database plus settings. Built once (`cl_engine_new` → load DBs → `cl_engine_compile`), then reused read-only across many scans/threads.
- **`fmap`** (**`libclamav/fmap.c`**, plus `libclamav_rust/src/fmap.rs`) — a memory-mapped *view* over the thing being scanned. Critical idea: every scanned object (the original file, **and** anything unpacked out of it) is wrapped in an fmap. Decompressed data is a new fmap layered on the old one. This is what lets recursive scanning work without writing temp files everywhere.
- **Recursion stack** — in `scanners.c`, `cli_recursion_stack_push/pop`. Each layer records its file type and attributes (`LAYER_ATTRIBUTES_NORMALIZED`, `_EMBEDDED`, etc.). A max-recursion limit prevents zip-bomb / quine attacks. **If you build your own scanner, copy this pattern**: treat "scan" as "identify → maybe unpack → recurse on each child → match signatures at every layer."

The main scan entry points: `cl_scanfile` / `cl_scanmap_callback` → `cli_magic_scan` (the big type-dispatch switch in **`scanners.c`**).

---

## 2. Signature-matching engines (the core value)

ClamAV doesn't use one matcher; it runs several specialized ones in parallel against each buffer. A `struct cli_matcher` (the "root") holds all of them. See **`matcher.c`** (`cli_scan_buff` / `cli_scan_fmap`) for the dispatcher.

### 2a. Aho-Corasick multi-pattern matcher — `matcher-ac.c`
The workhorse. Matches thousands of byte-patterns in a single pass over the data.

- Build a trie of all patterns, then add **failure links** via BFS (`ac_maketrans`, `bfs_enqueue`/`bfs_dequeue`) so a mismatch jumps to the longest proper suffix already matched — classic Aho-Corasick.
- Scan is one loop: `current = current->trans[buffer[i]]` and on a final node walk the pattern list (`cli_ac_scanbuff`, ~line 1819).
- Supports **wildcards** inside patterns (`CLI_MATCH_WILDCARD`, `_NIBBLE_HIGH/_LOW`, `_NOCASE`, alternates `(aa|bb)`, fixed/range gaps `{n}`, `{n-m}`, `*`). The fancy bits are handled by `ac_forward_match_branch` / `ac_backward_match_branch` after the trie gets you to an anchor.
- **Prefiltering**: `filtering.c` builds a fast Boyer-Moore-style filter so the expensive AC walk is skipped on buffers that can't possibly match.

This is the single most important file if you want to replicate ClamAV's detection model.

### 2b. Boyer-Moore matcher — `matcher-bm.c`
Used for simpler/anchored single patterns where BM's skip tables beat AC. `cli_bm_scanbuff`.

### 2c. Hash matchers — `matcher-hash.c` + `matcher-hash-types.h`
Whole-file and section hashing (MD5/SHA1/SHA256). Loaded from `.hdb/.hsb` (whole file), `.mdb/.msb` (PE section), `.imp` (PE import table hash), `.fp/.sfp` (false-positive allowlist). Implementation is just hash → hashtable lookup keyed by `(size, digest)`. `HASH_PURPOSE_*` enum selects what's being hashed.

### 2d. Byte-comparison matcher — `matcher-byte-comp.c`
Lets a signature read an integer at an offset (relative to another subsignature match) and compare it (`>`, `<`, `=`, ranges), with endianness/format options. Used in logical sigs as the `byte_compare` subsig type.

### 2e. PCRE matcher — `matcher-pcre.c`
Regular-expression subsignatures (compiled against libpcre2). Gated/triggered by a preceding AC anchor so you don't run regex over everything. Loaded as a subsig type inside `.ldb`.

### 2f. Image fuzzy hashing — `libclamav_rust/src/fuzzy_hash.rs`
Perceptual hash for detecting visually-similar images (e.g. phishing logos). It's a **DCT-based pHash** (uses `rustdct::DctPlanner`), producing a 64-bit (8-byte) hash; matching is hashmap lookup. Enabled by `CL_SCAN_PARSE_IMAGE_FUZZY_HASH`.

### 2g. Logical signatures (LDB) — the composition layer
The expressiveness most clones miss. A logical sig (`.ldb`) defines N subsignatures (any of the above types) and a **boolean/arithmetic expression** combining them, e.g. `(0&1)|(2&3)`, with count thresholds and target-type/file-size/engine constraints (`struct cli_lsig_tdb` in `matcher.h`). The expression evaluator is `cli_ac_chklsig` (`matcher-ac.c`), fed by per-subsig match counts tracked in `cli_ac_data`. **This is how you get "match only if these 3 things co-occur" without false positives.**

### 2h. Bytecode engine — `bytecode*.c` (`bytecode_vm.c`, `bytecode.c`, `bytecode_api.c`)
A sandboxed VM running compiled `.cbc` programs (a restricted LLVM-IR-like ISA). Signature authors write detection logic in C, compile with the ClamAV bytecode compiler, and the engine executes it with an interpreter (`bytecode_vm.c`) or, historically, a JIT. Used for unpackers and detections too complex for declarative sigs. Has its own API surface (`bytecode_api.c`) exposing safe scan primitives. This is heavy to replicate — most clones skip it.

---

## 3. Signature database types (the dispatch table)

From the extension switch in **`readdb.c`** (`cli_load`, ~line 4740). This *is* the feature list of "what kinds of detection exist":

| Ext | Loader | What it is |
|-----|--------|-----------|
| `.ndb`/`.ndu` | `cli_loadndb` | Basic hex-pattern sigs (AC/BM), with target type & offset |
| `.ldb`/`.ldu` | `cli_loadldb` | **Logical** signatures (multi-subsig boolean) |
| `.hdb/.hsb` (`.hdu/.hsu`) | `cli_loadhash` | Whole-file MD5/SHA hash |
| `.mdb/.msb` (`.mdu/.msu`) | `cli_loadhash` | PE section hash |
| `.imp` | `cli_loadhash` | PE import-table hash |
| `.fp/.sfp` | `cli_loadhash` | Hash **allowlist** (false-positive suppression) |
| `.cbc` | `cli_loadcbc` | Bytecode program |
| `.cdb` | `cli_loadcdb` | Container metadata sigs (archive contents: name/size/CRC) |
| `.idb` | `cli_loadidb` | PE icon signatures (`pe_icons.c`) |
| `.ftm` | `cli_loadftm` | File-type magic definitions |
| `.pdb/.gdb/.wdb` | `cli_loadpdb`/`cli_loadwdb` | Phishing: domain lists, allow lists |
| `.ign/.ign2` | `cli_loadign` | Disable specific sigs by name |
| `.crb` | `cli_loadcrt` | Trusted/revoked **Authenticode cert** rules |
| `.cat` | `cli_loadmscat` | MS security catalog |
| `.pwdb` | `cli_loadpwdb` | Archive **passwords** to try |
| `.sdb` | `cli_loadndb` | Same engine as ndb, mail-target |
| `.zmd/.rmd` | `cli_loadmd` | (legacy) zip/rar metadata |
| `.yar/.yara` | `cli_loadyara` | **YARA rules** (full compiler embedded) |
| `.ioc` | `cli_loadopenioc` | OpenIOC → converted to sigs |

YARA support is a whole sub-engine: `yara_grammar.c`, `yara_lexer.c`, `yara_exec.c`, `yara_compiler.c`, `yara_arena.c` — a ported YARA implementation.

---

## 4. File-type identification — `filetypes.c`, `textdet.c`

Before unpacking, the engine identifies type by (a) **magic bytes** loaded from `.ftm` rules (`cli_ftcalc`/`cli_filetype2`) and (b) text/binary classification (`textdet.c`, character-distribution based). Returns a `cli_file_t` (`CL_TYPE_*` enum in `filetypes.h`). The type drives the big switch in `scanners.c`. Note ClamAV does **not** trust file extensions — it sniffs content.

---

## 5. Embedded format parsers / unpackers (the "decode everything" feature)

Each of these turns a container/packed file into one or more child fmaps that get recursively scanned. This breadth is a major part of ClamAV's value. By category, with the file that implements it:

**Archives & compression:** ZIP (`unzip.c`), RAR (`libclamunrar/`, `unrar_iface`), 7-Zip (`7z_iface.c` + `7z/`), CAB (`libmspack`, `libmspack.c`), ARJ (`unarj.c`), LZH/LHA, ALZ (`libclamav_rust/src/alz.rs`), EGG (`egg.c`), GZIP/BZIP2/XZ (`xz_iface.c`)/inflate64 (`inflate64.c`), ZSTD, CPIO (`cpio.c`), TAR (`untar.c`/`is_tar.c`), XAR (`xar.c`), ISO9660 (`iso9660.c`), UDF (`udf.c`), DMG (`dmg.c`), HFS+ (`hfsplus.c`), GPT/MBR/APM partition tables (`gpt.c`/`mbr.c`/`apm.c`), MS SZDD/`explode.c`, `msexpand.c`.

**Executables (PE/ELF/Mach-O) + runtime unpackers:** core parsing in `pe.c`, `elf.c`, `macho.c`, `execs.c`, `rebuildpe.c`. Built-in unpackers for common packers: UPX (`upx.c`), FSG (`fsg.c`), Petite (`petite.c`), PeSpin (`spin.c`), NsPack (`unsp.c`), MEW (`mew.c`), Upack (`upack.c`), wwpack (`wwunpack.c`), aspack (`aspack.c`), yC (`yc.c`). Authenticode verification via `asn1.c` + `crtmgr.c`.

**Documents:** OLE2 / legacy Office (`ole2_extract.c`), OOXML (`ooxml.c` + `msxml.c`/`msxml_parser.c`), VBA macro extraction (`vba_extract.c`), Excel 4.0 macros (`xlm_extract.c`), RTF (`rtf.c`), PDF (`pdf.c`, `pdfng.c`, `pdfdecode.c`), HWP Korean docs (`hwp.c`), OneNote (`libclamav_rust/src/onenote.rs`).

**Mail & web:** MBOX/email (`mbox.c`, `message.c`, `text.c`), TNEF (`tnef.c`), MHTML, uuencode (`uuencode.c`), BinHex (`binhex.c`), base64 (`sf_base64decode.c`), HTML normalization (`htmlnorm.c`), entity decoding (`entconv.c`), XDP (`xdp.c`).

**Media/other:** SWF Flash (`swf.c`), images GIF/PNG/JPEG/TIFF (`gif.c`/`png.c`/`jpeg.c`/`tiff.c` — parsed for exploits + fuzzy hash), AutoIt scripts (`autoit.c`), InstallShield (`ishield.c`), SIS (`sis.c`), CryptFF (`cryptff`).

**Pattern to copy:** every parser has the same shape — validate header, iterate entries, for each entry create a child fmap and call back into `cli_magic_scan`. Implement a generic "extractor returns a list of (name, fmap)" interface and you can add formats incrementally.

---

## 6. Signature distribution: CVD format + updates

- **CVD/CLD/CUD files** (`cvd.c`, `libclamav_rust/src/cvd.rs`): a 512-byte ASCII header (`ClamAV-VDB:` magic, version, sig count, MD5, **RSA digital signature**, builder) followed by a gzipped tarball of the individual `.ndb/.ldb/...` files. `cl_cvdverify`/`cvd_verify` checks the signature so you can't load tampered DBs; `.cld` is an uncompressed/diff-applied variant, `.cud` is unsigned.
- **Incremental updates (cdiff)**: `libclamav_rust/src/cdiff.rs` applies signed diff patches so updates download KB not MB.
- **freshclam** (`freshclam/`, `libfreshclam/`): the updater daemon/CLI — checks DNS TXT / HTTP for the latest version, downloads CVD or cdiffs, verifies signatures, atomically swaps the DB.
- **sigtool** (`sigtool/`): build/unpack/inspect CVDs, generate hashes and sigs.

If you build a clone, you need *some* signed, versioned, incrementally-updatable container format — this is non-optional for a real-world AV.

---

## 7. Heuristic / non-signature detections

Toggled by `CL_SCAN_HEURISTIC_*` flags (see `clamav.h`). These raise alerts on *structure*, not known patterns:

- Encrypted archive / encrypted document detection.
- Broken executable / broken media (malformed PE, exploit-style PNG/JPEG/TIFF).
- Macro presence in Office docs.
- Partition table intersections / overlapping sectors (disk-image trickery).
- "Exceeds max" (file/scan limits hit → possible bomb).
- **Phishing** (`phishcheck.c`, `phish_domaincheck_db.c`, `phish_allow_list.c`): compares displayed URL vs. real href, SSL/cloak mismatches, against domain DBs.
- **DLP / structured data** (`dlp.c`): finds credit-card (Luhn-checked) and SSN patterns — `CL_SCAN_HEURISTIC_STRUCTURED_CC/_SSN_*`.

---

## 8. Daemon, clients & integration

- **clamd** (`clamd/`): multithreaded scanning daemon, listens on TCP/unix socket, command protocol (`SCAN`, `INSTREAM`, `MULTISCAN`, `CONTSCAN`…). Keeps the compiled engine resident.
- **clamdscan / clamonacc** (`clamdscan/`, `clamonacc/`): client + on-access (fanotify/inotify) real-time scanning.
- **clamav-milter** (`clamav-milter/`): Sendmail/Postfix mail filter.
- **clamdtop** (`clamdtop/`): live monitoring TUI.
- **Callbacks** (`CL_SCAN_CALLBACK_PRE_SCAN/POST_SCAN/ALERT/FILE_TYPE/PRE_HASH`): hook points so embedders can inspect/override every layer.
- **All-match mode** (`CL_SCAN_GENERAL_ALLMATCHES`): report every detection instead of stopping at first.

---

## 9. A pragmatic build-your-own roadmap

If the goal is "something similar," build in this order — each stage is independently useful:

1. **fmap abstraction + recursion stack** (§1). Without this, nothing else composes.
2. **File-type identification** from magic bytes (§4). Cheap, high value.
3. **Hash matcher** (§2c). Trivial to implement, immediately catches known files; gives you a working "AV" in a day.
4. **Aho-Corasick multi-pattern matcher** (§2a) with a prefilter. This is the real engine — budget the most time here.
5. **A couple of unpackers** (ZIP + gzip + PE) using the generic extractor interface (§5), recursing through the stack.
6. **Logical signatures** (§2g) once the basic matchers work — huge precision win for low effort.
7. **A signed, versioned DB container + updater** (§6) when you go beyond a toy.
8. (Optional, advanced) Embed **YARA** rather than reinventing it (§3), and add **fuzzy/perceptual hashing** (§2f) for near-duplicate detection.

Things to deliberately *skip* early: the bytecode VM (§2h) and the exotic runtime packers (§5) — high cost, low marginal benefit until you have real malware samples that need them.

---

*Source: Cisco-Talos/clamav, libclamav core + libclamav_rust. Paths point at the current main branch. GPLv2 — study freely, attribute/license appropriately if reusing code.*
