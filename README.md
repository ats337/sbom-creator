# SBOM Creator (CLI)

OS環境（macOS, Linux, Windows）および各種プログラミング言語（C, C++, C#, Java, Python, TypeScript, Go）のプロジェクトを自動スキャンし、業界標準形式（CycloneDX, SPDX）やJSON/CSV形式でSBOM（Software Bill of Materials: ソフトウェア部品構成表）を出力するPython製CLIツールです。

Python 3の標準ライブラリのみで動作するため、追加の外部パッケージインストールなしで直ちに利用可能です。

---

## 🚀 主な機能・対応範囲

### 1. スキャン対象

| 対象カテゴリ | 言語 / 種別 | 対応マニフェスト・収集対象 |
| :--- | :--- | :--- |
| **OS** | **macOS** | OS詳細（`sw_vers`, ハードウェアモデル）、Homebrew（Formulae & Casks）、インストール済みアプリ（`/Applications`） |
| **OS** | **Linux** | OSバージョン（`/etc/os-release`）、dpkg（Debian/Ubuntu）、rpm（RHEL/CentOS/Fedora） |
| **OS** | **Windows** | OSバージョン、winget（パッケージ） |
| **言語** | **Python** | `requirements.txt`, `pyproject.toml` |
| **言語** | **TypeScript / JavaScript** | `package.json` (`dependencies`, `devDependencies`) |
| **言語** | **Go** | `go.mod` |
| **言語** | **Java** | `pom.xml` (Maven), `build.gradle` (Gradle) |
| **言語** | **C / C++** | ① マニフェスト: `CMakeLists.txt`, `conanfile.txt`, `vcpkg.json`<br>② ビルド設定: `Makefile`, `makefile`, `GNUmakefile` (`-l<lib>`, `pkg-config`), `meson.build`, `configure.ac`<br>③ 静的解析: ソース・ヘッダ（`.c`, `.cpp`, `.h` 等）内の `#include <...>` から外部OSSライブラリ自動推定 |
| **言語** | **C#** | `*.csproj` (NuGet `PackageReference`) |

### 2. 出力形式 (`--format` / `-f`)

- `cyclonedx` / `cyclonedx-json` : **CycloneDX v1.5 JSON**（標準フォーマット、`hashes`・`cpe`・`dependencies` 対応）
- `spdx` / `spdx-json` : **SPDX v2.3 JSON**（国際標準規格 ISO/IEC 5962:2021、`checksums`・NVD照合用 `cpe23Type`・`relationships` 対応）
- `json` : 人間が読みやすいシンプルなカスタムJSON
- `csv` : スプレッドシートやExcelで確認できるCSV表形式

---

## 📁 ディレクトリ構成

```text
sbom-creator/
├── main.py                     # CLI実行エントリポイント
├── sbom_creator/
│   ├── cli.py                  # コマンドライン引数パーサー (argparse)
│   ├── core.py                 # スキャン・出力の統括ロジック
│   ├── models.py               # Component, SBOMDocument などのデータモデル
│   ├── scanners/
│   │   ├── base.py             # スキャナ抽象基底クラス
│   │   ├── os_scanner.py       # OSおよびOSパッケージスキャナ
│   │   └── project_scanner.py  # 言語別マニフェスト走査・解析スキャナ
│   └── formats/
│       ├── base.py             # フォーマッタ基底クラス
│       ├── cyclonedx.py        # CycloneDX v1.5 JSON 出力
│       ├── spdx.py             # SPDX v2.3 JSON 出力
│       └── simple.py           # 簡易JSON / CSV 出力
├── examples/                   # テスト・サンプルプロジェクト
└── tests/                      # 単体テスト (unittest)
```

---

## 💻 使い方 (CLI)

### 設定ファイルによる設定と優先順位 (`-c / --config`)

設定ファイル（JSONまたはTOML）を指定することで、SBOMメタデータや出力オプションを一括指定できます。

**値の優先順位**:
1. **設定ファイルの値**（最優先）
2. **コマンドライン引数（CLI）の値**（設定ファイルに未指定の場合）
3. **デフォルト値**（どちらにも指定がない場合）

```bash
# 設定ファイルを指定して実行
python3 main.py -c config.json

# 設定ファイルにない項目のみCLIで指定
python3 main.py -c config.json -f spdx -o sbom.json
```

**設定ファイル例 (`config.json`)**:
```json
{
  "target": "/path/to/project",
  "format": "spdx-json",
  "output": "sbom.spdx.json",
  "name": "my-service",
  "version": "1.0.0",
  "description": "OCR Backend API Service",
  "license": "Apache-2.0",
  "copyright": "Copyright 2026 Example Corp.",
  "creator": "Organization: Example Security Team",
  "supplier": "Organization: Example Corp.",
  "download_location": "https://example.com/downloads/v1.0.0.tar.gz",
  "homepage": "https://example.com/project",
  "namespace_prefix": "https://example.com/spdxdocs",
  "include_os": false,
  "component_overrides": {
    "libz": {
      "version": "1.3.1",
      "license": "Zlib"
    }
  }
}
```

#### バージョンおよびライセンスの自動補完機能
マニフェストファイルにバージョンやライセンスが明記されていない場合でも、以下の機能により自動補完を試みます：
1. **`pkg-config` 連携 (C/C++)**: ローカル環境の `pkg-config --modversion` を自動照会し、実インストールバージョンを取得。
2. **システムヘッダ解析 (C/C++)**: `/usr/include` 等のヘッダファイルから `ZLIB_VERSION`, `OPENSSL_VERSION` 等のマクロを抽出。
3. **実行環境解析 (Python)**: `importlib.metadata` を参照して実インストールバージョンとライセンスを補完。
4. **SPDX公式ライセンス辞書**: 主要な既知OSSライブラリ（curl, OpenSSL, zlib, SQLite, leptonica 等）のライセンスを自動付与。
5. **設定ファイルによる上書き**: 設定ファイル内の `component_overrides` で手動での確実なバージョン・ライセンス上書きが可能。

### 基本的な実行

```bash
# 1. カレントディレクトリをスキャンして CycloneDX 形式で標準出力
python3 main.py

# 2. 対象ディレクトリを指定して実行
python3 main.py -t /path/to/project

# 3. ファイルへ保存
python3 main.py -t /path/to/project -o sbom.cdx.json
```

### 出力フォーマットの指定 (`-f`)

```bash
# SPDX v2.3 JSON 形式で出力
python3 main.py -t /path/to/project -f spdx -o sbom.spdx.json

# 簡易JSON形式で出力
python3 main.py -t /path/to/project -f json

# CSV形式で出力
python3 main.py -t /path/to/project -f csv -o sbom.csv
```

### OS情報の収集オプション

```bash
# プロジェクト依存関係に加えて、ホストOS情報およびインストール済みパッケージも含める
python3 main.py -t /path/to/project --include-os -o full-sbom.json

# OS情報のみを収集（プロジェクトコードは走査しない）
python3 main.py --os-only -f json

# OSのパッケージ走査はスキップし、OSの基本情報（OS名・カーネルバージョン・CPUアーキテクチャ）のみ含める
python3 main.py --include-os --no-os-packages
```

### ヘルプの表示

```bash
python3 main.py --help
```

---

## 🧪 テストの実行

```bash
python3 -m unittest discover tests
```
