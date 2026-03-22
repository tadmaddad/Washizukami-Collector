# Washizukami (鷲掴)

> **Windows 向けフォレンジック証拠収集ツール**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20x64-blue.svg)]()

---

## 概要

**Washizukami（鷲掴）** は、Rust で実装された Windows 向けのファストフォレンジック証拠収集ツールです。

OS がファイルをロックしている状況下でも、NTFS の Master File Table (MFT) を直接解析することで、レジストリハイブやイベントログなどのアーティファクトを取得できます。収集した証拠は SHA-256 ハッシュ付きの監査ログとともに保存されるため、そのまま各種解析ツールへの入力として利用できます。

このツールは、[CDIR-C](https://github.com/CyberDefenseInstitute/CDIR)（サイバーディフェンス研究所）に着想を得て開発しました。CDIR-C が切り拓いたライブシステムからのアーティファクト収集という手法を、Rust による実装でポータブルな単一バイナリとして提供することを目指しています。

**想定する解析ツールの例:**
- [Hayabusa](https://github.com/Yamato-Security/hayabusa) — Windows イベントログの脅威ハンティング
- [Velociraptor](https://github.com/Velocidex/velociraptor) / [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) などのフォレンジックフレームワーク
- ELK Stack / Splunk などの SIEM への取り込み

---

## 機能

| 機能 | 説明 |
|------|------|
| **NTFS Raw Read** | MFT を直接解析し、OS のファイルロックをバイパスして収集 |
| **SHA-256 整合性検証** | 収集したファイルをすべてハッシュ化し、改ざん検知を可能に |
| **監査ログ** | タイムスタンプ・収集方法・SHA-256 を含む構造化ログ (`collection.log`) |
| **単一バイナリ** | アーティファクト定義をコンパイル時に内蔵 — 実行時に外部ファイル不要 |
| **柔軟なフィルタリング** | CLI フラグまたは `config.yaml` で収集対象を名前・カテゴリ単位で制御 |
| **ZIP 出力** | 収集完了後にすべての成果物を単一 ZIP に圧縮して搬出を容易に |
| **メモリ取得連携** | `--mem` オプションで [WinPmem](https://github.com/Velocidex/WinPmem) と連携してメモリダンプを取得 |
| **Dry-Run モード** | ファイルシステムに触れずに収集対象パスのみを確認 |

---

## 動作環境

| 項目 | 要件 |
|------|------|
| **OS** | Windows 10 / Windows 11（x64） |
| **権限** | **管理者権限**（Administrator）で実行すること |
| **ランタイム** | 不要（静的ビルド済み — VC++ 再頒布可能パッケージ・MinGW DLL は不要） |
| **ディスク空き容量** | 収集するアーティファクトの合計サイズ以上 |
| **メモリ取得オプション** | `--mem` 使用時は `tools\` フォルダに `winpmem*.exe` を配置すること |

> **注意:** NTFS Raw Read を使用するため、対象ボリュームが NTFS フォーマットであることが前提です。FAT32/exFAT ボリューム上のファイルは通常の File コレクタで収集されます。

---

## 使い方

```
washi.exe [OPTIONS]

Options:
  -o, --output <DIR>               出力先ディレクトリ
                                   [デフォルト: <実行ファイルのフォルダ>\output\<COMPUTERNAME>]
  -a, --artifact <NAME>            収集対象を名前で指定（大文字小文字不問、複数指定可）
  -x, --exclude-category <CAT>     除外するカテゴリ（複数指定可）
      --dry-run                    パス解決結果のみ表示（ファイルは収集しない）
      --zip                        収集完了後に ZIP アーカイブを生成
      --mem                        tools\winpmem*.exe でメモリダンプを取得（収集前に実行）
      --volume <LETTER>            NTFS Raw Read のドライブレターを上書き
  -h, --help
  -V, --version
```

### 実行例

```powershell
# 全アーティファクトを収集（監査ログ付き）
washi.exe

# 収集後に ZIP アーカイブを生成
washi.exe --zip

# メモリダンプ取得 → 全アーティファクト収集 → ZIP 生成
washi.exe --mem --zip

# レジストリのみ収集（EventLogs と FileSystem を除外）
washi.exe --exclude-category EventLogs --exclude-category FileSystem

# 特定アーティファクトを名前で指定して収集
washi.exe --artifact "SAM Registry Hive" --artifact "Security Event Log"

# 収集対象の確認（ファイルは書き込まない）
washi.exe --dry-run

# 出力先を指定
washi.exe --output D:\evidence\case001 --zip
```

---

## 出力構造

```
<実行フォルダ>\
├── output\
│   └── HOSTNAME\
│       ├── collection.log      ← 監査ログ（タイムスタンプ・SHA-256・収集方法）
│       ├── memory.dmp          ← メモリダンプ（--mem 指定時のみ）
│       ├── EventLogs\
│       │   ├── Security.evtx
│       │   └── ...
│       ├── Registry\
│       │   ├── SAM
│       │   └── ...
│       └── FileSystem\
│           └── ...
└── output\HOSTNAME.zip         ← ZIP アーカイブ（--zip 指定時のみ）
```

### 監査ログ形式

```
[2026-03-21T10:30:00+0900] [OK   ] [NTFS        ] C:\Windows\System32\config\SAM -> output\HOSTNAME\Registry\SAM (262144 bytes, SHA256: abcd1234...)
[2026-03-21T10:30:01+0900] [SKIP ] [-           ] C:\path\missing — file not found
[2026-03-21T10:30:02+0900] [FAIL ] [-           ] C:\path\locked — <error>
[2026-03-21T10:30:03+0900] [TOOL ] [winpmem_x64 ] Starting: tools\winpmem_x64.exe -> output\HOSTNAME\memory.dmp
[2026-03-21T10:30:10+0900] [INFO ] [-           ] Complete — OK: 141  Skipped: 1  Failed: 0
```

---

## アーティファクト定義のカスタマイズ

内蔵定義は Windows イベントログ・レジストリハイブ・一般的なファイルシステムアーティファクトをカバーしています。収集対象を絞り込みたい場合は、`washi.exe` と同じフォルダに `config.yaml` を配置してください。

```yaml
# config.yaml — washi.exe と同じフォルダに配置
enabled:
  - "SAM Registry Hive"
  - "Security Event Log"
  - "System Event Log"

disabled_categories:
  - FileSystem
```

**優先順位:** CLI フラグ > `config.yaml` > 内蔵デフォルト

---

## メモリ取得（winpmem 連携）

`--mem` オプションを使用すると、アーティファクト収集の前に [WinPmem](https://github.com/Velocidex/WinPmem) でメモリダンプを取得できます。

1. [WinPmem リリースページ](https://github.com/Velocidex/WinPmem/releases) から `winpmem_x64.exe` をダウンロード
2. `washi.exe` と同じフォルダの `tools\` に配置
3. `--mem` を付けて実行

```
（配置例）
washi.exe
tools\
└── winpmem_x64.exe
```

> `tools\winpmem*.exe` が見つからない場合は警告をログに記録し、アーティファクト収集のみ続行します。

---

## ソースからのビルド

**必要なもの:**
- Rust stable ツールチェーン（`x86_64-pc-windows-gnu`）
- MSYS2 + MinGW-w64（GNU リンカ）

```powershell
git clone https://github.com/YourUsername/Washizukami.git
cd Washizukami
cargo build --release
```


---

## ライセンス

Copyright (C) 2026 tadmaddad - Jawfish Lab

本ソフトウェアは、GNU Affero General Public License v3.0（AGPL-3.0）に基づき、オープンソースとして公開されています。

---

## 利用ライブラリ・ツール

- [ntfs](https://github.com/ColinFinck/ntfs) by Colin Finck — MFT 直接アクセスを可能にする Pure Rust NTFS パーサ
- [WinPmem](https://github.com/Velocidex/WinPmem) by Velocidex — Windows メモリ取得ツール
