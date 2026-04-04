<div align="center">
 <p>
    <img alt="Washizukami Logo" src="Logo.png" width="60%">
 </p>
  [<a href="README.md">English</a>] | [<b>日本語</b>]
</div>

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
| **柔軟なフィルタリング** | `--category` でカテゴリ単位のインクルード/エクスクルード（`!` プレフィックスで除外）、詳細は `config.yaml` で制御 |
| **ZIP 出力** | 収集完了後にすべての成果物を単一 ZIP に圧縮して搬出を容易に |
| **メモリ取得連携** | `--mem` オプションで [WinPmem](https://github.com/Velocidex/WinPmem) と連携してメモリダンプを取得 |
| **Dry-Run モード** | ファイルシステムに触れずに収集対象パスのみを確認 |
| **YARA スキャン** | `scan` サブコマンドで永続化メカニズムを YARA-X でスキャン、検知ファイルを `infected.zip` に収集 |
| **確認プロンプト** | 収集・スキャン開始前に `[y/N]` で確認を求め、誤操作による意図しない収集を防止 |

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

### アーティファクト収集モード（デフォルト）

```
washi.exe [OPTIONS]

Options:
  -o, --output <DIR>               出力先ディレクトリ
                                   [デフォルト: <実行ファイルのフォルダ>\output\<COMPUTERNAME>]
  -c, --category <CATEGORY>        カテゴリでフィルタリング（複数指定可、大文字小文字不問）
                                   プレフィックスなし: 指定カテゴリのみ収集
                                   '!' プレフィックス: 指定カテゴリを除外
                                   指定可能値: EventLogs, Registry, NTFS, Filesystem, WMI, SRUM, Web
      --dry-run                    パス解決結果のみ表示（ファイルは収集しない）
      --zip                        収集完了後に ZIP アーカイブを生成
      --mem                        tools\winpmem*.exe でメモリダンプを取得（収集前に実行）
      --volume <LETTER>            NTFS Raw Read のドライブレターを上書き
  -v, --verbose                    カテゴリ単位の集計ではなく収集ファイルを1件ずつ表示
  -h, --help
  -V, --version
```

### YARA スキャンモード

```
washi.exe scan [OPTIONS] --rules <FILE> --output <DIR>

Options:
      --yara-path <PATH>           YARA-X エンジン（yr.exe）のパス [デフォルト: ./tools/yr.exe]
      --rules <FILE>               YARA ルールファイルのパス（必須）
      --output <DIR>               スキャン結果の出力先（必須）
  -h, --help
```

スキャン対象は以下の永続化メカニズムから自動収集されます：

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `C:\Windows\System32\Tasks`（タスクスケジューラ XML）

### 確認プロンプト

収集モード・スキャンモードともに、処理開始前に確認を求めます。

```
[?] Start collection? [y/N]:
```

`y` または `yes`（大文字小文字不問）を入力すると処理を開始します。それ以外の入力・Enter のみ・Ctrl+C はすべてアボートとして扱われます。`--dry-run` では確認は不要です。

### 実行例

```powershell
# 全アーティファクトを収集（監査ログ付き）
washi.exe

# 収集後に ZIP アーカイブを生成
washi.exe --zip

# メモリダンプ取得 → 全アーティファクト収集 → ZIP 生成
washi.exe --mem --zip

# Registry と EventLogs のみ収集
washi.exe --category Registry --category EventLogs

# EventLogs と WMI を除外してすべて収集
washi.exe --category '!EventLogs' --category '!WMI'

# 収集ファイルを1件ずつ表示（詳細モード）
washi.exe --verbose

# 収集対象の確認（ファイルは書き込まない）
washi.exe --dry-run

# 出力先を指定
washi.exe --output D:\evidence\case001 --zip

# YARA スキャン（永続化パスをスキャンし、検知ファイルを infected.zip に収集）
washi.exe scan --rules C:\rules\malware.yar --output C:\scan_out
```

---

## 収集対象アーティファクト

内蔵定義でカバーしているアーティファクトの一覧です。`config.yaml` でカスタム定義を追加することも可能です（詳細は「アーティファクト定義のカスタマイズ」を参照）。

| カテゴリ | アーティファクト | 収集方式 |
|---------|----------------|---------|
| **EventLogs** | Security / System / Application Event Log | NTFS |
| **Registry** | SAM / SECURITY / SOFTWARE / SYSTEM ハイブ | NTFS |
| **Registry** | Amcache.hve | NTFS |
| **Registry** | NTUSER.DAT / UsrClass.dat（全ユーザー） | NTFS |
| **NTFS** | `$MFT`（Master File Table） | NTFS |
| **NTFS** | `$SECURE:$SDS`（セキュリティ記述子ストリーム） | NTFS + ADS |
| **NTFS** | `$UsnJrnl:$J`（USN ジャーナル） | NTFS + ADS |
| **Filesystem** | プリフェッチファイル（`Prefetch\*.pf`） | File |
| **Filesystem** | 最近使ったファイル（`Recent\*.lnk`） | File |
| **WMI** | WMI リポジトリ（OBJECTS.DATA / INDEX.BTR / MAPPING*.MAP） | NTFS |
| **SRUM** | SRUM データベース（SRUDB.dat） | NTFS |
| **Web** | Chrome 履歴 | File |
| **Web** | Firefox 履歴・Cookie（places.sqlite / cookies.sqlite） | File |
| **Web** | IE / Edge WebCache（WebCacheV01.dat） | File |
| **Web** | Edge 履歴 | File |

> **NTFS + ADS:** Alternate Data Stream を MFT 直接読み取りで取得します。通常の API では読み出せないストリームにもアクセス可能です。

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
│       ├── NTFS\
│       │   ├── $MFT
│       │   ├── $Secure_SDS     ← $SECURE:$SDS ストリーム
│       │   └── $UsnJrnl_J      ← $UsnJrnl:$J ストリーム
│       ├── Filesystem\
│       │   └── ...
│       ├── WMI\
│       │   └── ...
│       ├── SRUM\
│       │   └── SRUDB.dat
│       └── Web\
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

# washi.exe scan 実行時
[2026-03-23T11:00:00+0900] [SCAN ] [yr          ] Starting scan — engine: ./tools/yr.exe  rules: malware.yar  targets: 59
[2026-03-23T11:00:02+0900] [MATCH] [yara        ] C:\Windows\System32\notepad.exe — test_notepad
[2026-03-23T11:00:02+0900] [SCAN ] [-           ] Complete — matched: 1  archive: scan_out\infected.zip
```

---

## アーティファクト定義のカスタマイズ

内蔵定義は Windows イベントログ・レジストリハイブ・一般的なファイルシステムアーティファクトをカバーしています。`washi.exe` と同じフォルダに `config.yaml` を配置することで、収集対象の絞り込みや独自アーティファクトの追加ができます。

**優先順位:** CLI フラグ > `config.yaml` > 内蔵デフォルト

### フィルタ

#### `enabled_artifacts`

収集するアーティファクト名のホワイトリストです。空または省略した場合はすべて収集されます。大文字小文字は区別しません。

<details>
<summary>内蔵アーティファクト名一覧</summary>

| カテゴリ | 名前 |
|---------|------|
| EventLogs | `Security Event Log` |
| EventLogs | `System Event Log` |
| EventLogs | `Application Event Log` |
| Registry | `SAM Registry Hive` |
| Registry | `SECURITY Registry Hive` |
| Registry | `SOFTWARE Registry Hive` |
| Registry | `SYSTEM Registry Hive` |
| Registry | `Amcache.hve` |
| Registry | `User NTUSER.DAT` |
| Registry | `User UsrClass.dat` |
| NTFS | `$MFT` |
| NTFS | `$SECURE:$SDS` |
| NTFS | `$UsnJrnl:$J` |
| Filesystem | `Prefetch Files` |
| Filesystem | `Recent LNK Files` |
| WMI | `WMI Repository OBJECTS.DATA` |
| WMI | `WMI Repository INDEX.BTR` |
| WMI | `WMI Repository MAPPING Files` |
| SRUM | `SRUM Database` |
| Web | `Chrome History` |
| Web | `Firefox places.sqlite` |
| Web | `Firefox cookies.sqlite` |
| Web | `IE/Edge WebCacheV01.dat` |
| Web | `Edge History` |

</details>

#### `disabled_categories`

カテゴリ単位で除外します。有効な値: `EventLogs` / `Registry` / `NTFS` / `Filesystem` / `WMI` / `SRUM` / `Web`（大文字小文字不問）。

> **注意:** `disabled_categories` は `enabled_artifacts` より**後に**評価されます。ホワイトリストに明示したアーティファクトでも、カテゴリが無効化されていれば除外されます。

### カスタムアーティファクト定義

`artifacts` キーで内蔵定義にないアーティファクトを追加できます。内蔵定義と同じ `name` を指定した場合はカスタム定義が優先されます。

必須フィールド:

| フィールド | 説明 |
|-----------|------|
| `name` | 一意な表示名。`config.yaml` の `enabled_artifacts` から参照されます。 |
| `category` | グループ名。出力サブフォルダ名にも使用されます。 |
| `target_path` | 収集対象パス。`%VAR%` 形式の環境変数とグロブワイルドカード（`*`・`?`）が使用可能。 |
| `method` | `File`（通常の OS コピー）または `NTFS`（MFT 直接読み取り、ファイルロック回避）。 |

### `config.yaml` の記述例

```yaml
# ── フィルタ ──────────────────────────────────────────────────────────────────
# 以下のアーティファクトのみ収集（コメントアウトすると全件収集）
enabled_artifacts:
  - "SAM Registry Hive"
  - "Security Event Log"
  - "System Event Log"

# カテゴリ単位で除外
disabled_categories:
  - Filesystem
  - Web

# ── カスタムアーティファクト定義 ──────────────────────────────────────────────
artifacts:
  - name: "My Application Log"
    category: "Custom"
    target_path: "C:\\MyApp\\logs\\app.log"
    method: File

  - name: "My Locked DB"
    category: "Custom"
    target_path: "%SystemDrive%\\MyApp\\data\\app.db"
    method: NTFS

  - name: "All XML Configs"
    category: "Custom"
    target_path: "C:\\MyApp\\config\\*.xml"
    method: File
```

### 応用例: Outlook .pst ファイルの収集

Classic 版 Outlook（新しい Outlook アプリではなく旧来の Outlook）の `.pst` ファイルは、環境によって保存場所が異なります。**日本語 Windows かつ OneDrive 連携が有効な場合**、既定の保存先は以下のパスになります。

```
C:\Users\<ユーザー名>\OneDrive\ドキュメント\Outlook ファイル\*.pst
```

全ユーザー分をまとめて収集するには、`config.yaml` に以下を追加します。

```yaml
artifacts:
  - name: "Outlook PST Files"
    category: "Mail"
    target_path: "C:\\Users\\*\\OneDrive\\ドキュメント\\Outlook ファイル\\*.pst"
    method: NTFS
```

> **`method: NTFS` を使う理由:** Classic 版 Outlook は起動中に `.pst` ファイルを排他ロックします。NTFS Raw Read を使うことでロックをバイパスし、Outlook を終了させることなく収集できます。
>
> **サイズに注意:** `.pst` ファイルは数 GB になる場合があります。収集前に `--dry-run` でファイルサイズを確認することをお勧めします。

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
git clone https://github.com/tadmaddad/Washizukami-Collector.git
cd Washizukami-Collector
cargo build --release
```


---

## ロードマップ

現在計画中・検討中の機能拡張です。実装順は未定です。

### YARA スキャンの拡張

`scan` サブコマンドは v0.4.0 で実装済みです。今後の拡張として以下を検討しています。

- `--target` オプションによる任意ディレクトリの追加スキャン
- `infected.zip` へのパスワード保護（AES-256）— 現在はビルド環境の制約により未実装
- スキャン対象の拡張（スタートアップフォルダ、サービス登録パスなど）

### メールクライアントアーティファクト

#### Microsoft Outlook `.pst` — config.yaml で今すぐ対応可能

Classic 版 Outlook の `.pst` 収集は、カスタムアーティファクト定義を使って現在のバージョンでも対応できます。設定方法は「[応用例: Outlook .pst ファイルの収集](#応用例-outlook-pst-ファイルの収集)」を参照してください。

#### 内蔵定義への追加（予定）

以下は今後の内蔵定義追加として検討中です。

| クライアント | 対象ファイル |
|-------------|------------|
| **Microsoft Outlook** | `.ost` ファイル、添付ファイルキャッシュ |
| **Mozilla Thunderbird** | メールボックス（`*.msf` / `INBOX`）、アドレス帳、設定ファイル |

メールデータはサイズが大きくなりがちなため、収集対象期間の絞り込みや差分収集などの最適化も合わせて検討しています。

---

## 名前の由来：なぜ「鷲掴（Washizukami）」なのか？

本ツールの名称は、Windows ログ解析のデファクトスタンダードであり、多くのセキュリティエンジニアが愛用する **[Hayabusa](https://github.com/Yamato-Security/hayabusa)** への深いリスペクトから命名されました。

空の王者であるハヤブサが鋭い眼光で獲物を見つけ出すなら、このツールはその獲物（アーティファクト）を物理的に「鷲掴み」にして、OS の制限（ファイルロック）さえもねじ伏せて持ち帰る。そんな力強い証拠収集へのこだわりを込めています。

…と、ここまでが公式の（真面目な）説明です。

たまに「作者の個人的な嗜好が反映されているのでは？」という邪推をいただくことがありますが、断じて違います。私はただ、NTFS の MFT とレジストリハイブを、法的に正しい手続きで、優しく、かつ力強くホールドしたいだけなのです。

---

## AI-Assisted Development（AI による開発支援）

本プロジェクトは、**Claude Code** および **Google Gemini** という 2 つの強力な AI アシスタントの支援を受けて開発されました。

- **Claude Code**: 主に Rust のコード構造の設計、リファクタリング、および Windows 特有のシステムプログラミングの実装支援。
- **Google Gemini**: プロジェクトの全体的なロードマップ策定、ドキュメントの整備、およびトラブルシューティングの壁打ち相手。

---

## ライセンス

Copyright (C) 2026 tadmaddad - Jawfish Lab

本ソフトウェアは、GNU Affero General Public License v3.0（AGPL-3.0）に基づき、オープンソースとして公開されています。

---

## 利用ライブラリ・ツール

- [ntfs](https://github.com/ColinFinck/ntfs) by Colin Finck — MFT 直接アクセスを可能にする Pure Rust NTFS パーサ
- [WinPmem](https://github.com/Velocidex/WinPmem) by Velocidex — Windows メモリ取得ツール
