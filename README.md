# strlist-space-log

space kecil untuk poin **"String dan List: Mengubah Teks Mentah Menjadi Data"**.
Log mentah (teks `auth.log` dan JSON dari beberapa produk keamanan) diubah menjadi data seragam,
disimpan di **SQLite**, lalu diuji dengan aturan deteksi sederhana. Cocok dijalankan di **VS Code**
tanpa server database dan tanpa pustaka pihak ketiga (hanya pustaka standar Python).

> Semua angka ambang (misalnya 3 kegagalan) adalah **angka buatan sendiri untuk latihan**, bukan standar baku.
> Hasil aturan hanyalah petunjuk untuk ditinjau manusia, bukan bukti serangan.

## Struktur proyek

```
strlist-lab/
├── README.md
├── pyproject.toml            # paket, pytest, ruff
├── .gitignore                # data/external dan *.db tidak ikut commit
├── .github/workflows/ci.yml  # GitHub Actions: lint + uji + uji dataset publik
├── .vscode/                  # settings, launch (debug), tasks, ekstensi rekomendasi
├── src/strlist_lab/
│   ├── parsers.py            # string -> list -> dict (syslog/sshd)
│   ├── loaders.py            # JSON: array, objek berisi list, NDJSON
│   ├── normalize.py          # Okta / Azure AD / Wazuh / auth.log -> Event seragam
│   ├── rules.py              # brute_force, success_after_failures
│   ├── db.py                 # skema + simpan/baca SQLite (query berparameter)
│   ├── pipeline.py           # berkas -> Event -> aturan -> database (idempoten via SHA-256)
│   └── cli.py                # perintah: init-db, ingest, report
├── tests/
│   ├── fixtures/             # data sintetis buatan sendiri (offline)
│   └── test_*.py             # unit + integrasi (integrasi otomatis dilewati bila data tak ada)
└── data/                     # strlab.db dibuat di sini; data/external untuk dataset publik
```

## Mulai cepat (VS Code)

1. Buka folder ini di VS Code, lalu terima rekomendasi ekstensi (Python, Ruff, SQLite Viewer).
2. Buat lingkungan virtual dan pasang paket:

   ```bash
   python -m venv .venv
   # Windows PowerShell:  .venv\Scripts\Activate.ps1      macOS/Linux:  source .venv/bin/activate
   python -m pip install -e ".[dev]"
   ```
3. Pilih interpreter `.venv` (Ctrl+Shift+P > *Python: Select Interpreter*).
4. Jalankan uji: `pytest -q` (atau ikon Testing di VS Code). Uji unit memakai fixture sendiri, tanpa internet.
5. Coba alurnya:

   ```bash
   strlab init-db
   strlab ingest tests/fixtures/okta_bad.json --label malicious
   strlab ingest tests/fixtures/okta_ok.json  --label benign
   strlab report
   ```
6. Buka `data/strlab.db` dengan **SQLite Viewer** untuk melihat tabel `sources`, `events`, `findings`.

Tekan **F5** untuk men-debug (konfigurasi di `.vscode/launch.json`), atau **Terminal > Run Task** untuk tugas siap pakai.

## Dataset yang direkomendasikan (JSON, rapi, berpasangan berbahaya/normal)

Sumber: [`logtriage-cyber/security-log-samples`](https://github.com/logtriage-cyber/security-log-samples)
(sintetis, IP memakai rentang dokumentasi RFC 5737, ada `manifest.json` dengan SHA-256 tiap berkas).

```bash
git clone --depth 1 https://github.com/logtriage-cyber/security-log-samples data/external/security-log-samples
```

| Sampel | Bentuk JSON | Mengapa cocok untuk "string dan list" | Hasil uji (v0.1.0) |
|---|---|---|---|
| `okta/malicious/okta_credential_stuffing.json` dan `okta/benign/okta_normal_logins.json` | array berisi objek | Paling rapi; ambil `actor`, `client.ipAddress`, `outcome.result` | berbahaya: 12 event, 2 temuan; normal: 7 event, 0 temuan |
| `azure-ad-signin/malicious/azure_brute_force.json` dan `.../benign/azure_normal_corporate.json` | objek `{"value": [...]}` | Latihan membuka objek bersarang; `status.errorCode` sebagai pembeda | berbahaya: 8 event, 2 temuan; normal: 4 event, 0 temuan |
| `wazuh/malicious/wazuh_brute_force.json` dan `wazuh/benign/wazuh_normal.json` | NDJSON (satu objek per baris) | Paling kaya: **string** `full_log` untuk dipecah dan **list** `rule.groups` | berbahaya: 6 event, 2 temuan; normal: 3 event, 0 temuan |
| `auth-log/malicious/authlog_brute_force.log` dan `.../benign/authlog_normal.log` | teks syslog | Contoh dasar `split()` dan `strip()` | berbahaya: 27 event, 3 temuan; normal: 20 event, 0 temuan |

Atribusi wajib (**CC BY 4.0**): cantumkan "Security log samples by LogTriage (https://logtriage.app)" bila hasil ditampilkan di artikel.

**Catatan data lain:**
- `elastic/examples` (folder `Common Data Formats/apache_logs`) memuat **IP publik asli**; samarkan sebelum dipublikasikan.
- `istec-iuc/AuthInfo-Dataset` berisi pasangan nama pengguna (hash) dan **kata sandi teks biasa** dari kebocoran data. Tidak disarankan untuk artikel; jangan menampilkan isinya.

## Skema database

| Tabel | Kolom utama |
|---|---|
| `sources` | `id`, `name`, `label` (malicious/benign/unknown), `sha256` (UNIK), `ingested_at` |
| `events` | `source_id`, `seq`, `ts`, `user`, `ip`, `outcome` (failure/success/other), `tags` |
| `findings` | `source_id`, `rule`, `ip`, `failures`, `detail` |

Contoh query di SQLite Viewer:

```sql
SELECT s.name, f.rule, f.ip, f.failures
FROM findings f JOIN sources s ON s.id = f.source_id
ORDER BY f.failures DESC;
```

## GitHub Actions

`.github/workflows/ci.yml` memiliki dua job:

1. **test**: Python 3.10, 3.11, 3.12 menjalankan `ruff check .` lalu `pytest -q` (offline, memakai fixture).
2. **integration**: mengunduh dataset publik ke `data/external/` lalu `pytest -m integration -q`
   (aturan harus menyala pada sampel berbahaya, diam pada sampel normal, dan semua SHA-256 di manifest cocok).

## Memakai hasil untuk artikel content writer

- Jalankan `strlab report` dan salin tabelnya sebagai bukti ("diuji pada 8 sampel publik: 4 berbahaya menghasilkan temuan, 4 normal tidak").
- Tulis jujur: ambang buatan sendiri, data sintetis, dan hasil hanya petunjuk.
- Sebutkan bahwa baris rusak dilewati dan dihitung (lihat kolom `dilewati` pada keluaran `ingest`).
- Jangan memasukkan data pribadi atau IP asli ke artikel.

## Batasan

- Hanya mengenali empat bentuk sumber (Okta, Azure AD sign-in, Wazuh, auth.log). Bentuk lain dihitung sebagai `dilewati`.
- Aturan sederhana: mudah lolos bila penyerang memvariasikan alamat atau jeda waktu.
- Urutan `success_after_failures` mengikuti urutan baris berkas, bukan pengurutan waktu.

## Lisensi

Kode proyek ini: tentukan lisensi sendiri (mis. MIT) sebelum dipublikasikan. Dataset publik tetap mengikuti lisensinya masing-masing.
