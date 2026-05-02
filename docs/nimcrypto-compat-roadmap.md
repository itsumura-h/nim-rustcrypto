# nimcrypto 互換ロードマップと進捗管理

この文書を、このリポジトリにおける nimcrypto 互換計画の単一の参照先にします。

## 1. 更新ルール

- 互換対象、差分、未対応範囲、危殆化対象を変更したら、この文書を先に更新します。
- 新しい実装タスクは、必ず `Feature` か `Task` のどちらかに分解してから着手します。
- 状態は次の語彙に統一します。
  - `未着手`
  - `調査中`
  - `設計済み`
  - `実装待ち`
  - `実装中`
  - `検証中`
  - `完了`
  - `保留`
  - `対象外`
- 1 つの issue に複数の状態を混在させず、最も進んでいない段階を状態にします。

## 2. 互換表

| モジュール | 互換対象 | 主な確認観点 | 状態 | 差分・未対応範囲 | 危殆化・意図的非互換 |
|---|---|---|---|---|---|
| `hash` | 汎用 hash API | API 名、入力型、出力型、streaming 可否 | 設計済み | 現在は実装未着手。one-shot を先行し、streaming は後続で評価する | なし |
| `sha` | SHA-1 | digest 長、one-shot / streaming、hex 表現 | 設計済み | 現在は実装未着手。SHA-1 は互換目的で扱う前提を確認する | SHA-1 は衝突耐性の観点で警告対象 |
| `sha2` | SHA-2 family | SHA-224 / 256 / 384 / 512 などの対象範囲 | 設計済み | 現在は実装未着手。family ごとの公開 API を整理する | なし |
| `ripemd` | RIPEMD family | 対応 variant、digest 長、hex 表現 | 設計済み | 現在は実装未着手。RIPEMD-160 を中心に互換性を確認する | RIPEMD-160 の利用注意を記録する |
| `keccak` | Keccak / SHA-3 系 | Keccak と SHA-3 の差異、出力長 | 設計済み | 現在は実装未着手。nimcrypto の公開名に合わせた差分確認が必要 | 意図的差分がある場合は別記する |
| `blake2` | BLAKE2 family | BLAKE2b / BLAKE2s、keyed hashing | 設計済み | 現在は実装未着手。keyed hashing の扱いを確認する | なし |
| `hmac` | HMAC | 対応 hash、key / input / output 形式 | 設計済み | 現在は実装未着手。対応 hash の組み合わせを先に確定する | 弱い hash との組み合わせは警告対象 |
| `rijndael` | Rijndael / AES | 鍵長、block size、AES との差分 | 設計済み | 現在は実装未着手。AES と広義 Rijndael の境界を明確化する | AES 以外の Rijndael 互換範囲は要判断 |
| `twofish` | Twofish | 鍵長、block size、context API | 設計済み | 現在は実装未着手。context API を nimcrypto に寄せる | 採用理由と互換目的を記録する |
| `blowfish` | Blowfish | 鍵長、block size、context API | 設計済み | 現在は実装未着手。警告文と代替案を併記する | 64 bit block size に起因する制約を警告対象とする |
| `bcmode` | ブロック暗号モード | ECB / CBC / CFB / OFB / CTR / GCM、padding、IV / nonce | 設計済み | 現在は実装未着手。モードごとの優先順位を分けて評価する | ECB など安全でない利用形態は警告対象 |
| `utils` | 補助関数 | hex / base 変換、比較、出力表現 option | 設計済み | 現在は実装未着手。大文字小文字と `0x` 接頭辞を確認する | 定数時間比較の要否を確認する |
| `sysrand` | OS 乱数 | 失敗時挙動、blocking 可否、platform 差分 | 設計済み | 現在は実装未着手。疑似乱数 fallback は採用しない前提で確認する | 疑似乱数 fallback は意図的非互換候補 |

## 3. 進捗更新方針

- この文書が、ロードマップ、互換表、issue 分解、危殆化記録の共通ソースです。
- 既存 issue の状態更新は、実装の進行に合わせて `設計済み -> 実装待ち -> 実装中 -> 検証中 -> 完了` の順で進めます。
- 調査結果が変わった場合は、該当モジュールの `差分・未対応範囲` と `危殆化・意図的非互換` を先に更新します。
- Feature / Task の ID は、後続の GitHub issue 化を想定して固定します。

## 4. 初期マイルストーン issue 分解

### M1: ビルド基盤

| ID | 種別 | 対象 | 状態 | 完了条件 | 依存 issue | 互換性影響 | セキュリティ注記 |
|---|---|---|---|---|---|---|---|
| F-BUILD-001 | Feature | `build` | 設計済み | Rust staticlib 生成方針、Nim 静的リンク方針、最小 FFI 呼び出し検証の条件を README とロードマップで追える | なし | 対象外 | なし |
| T-BUILD-001 | Task | `build` | 設計済み | Cargo.toml の `crate-type = ["staticlib"]` 要件をチェックリスト化する | F-BUILD-001 | 対象外 | なし |
| T-BUILD-002 | Task | `build` | 設計済み | Nim からの静的リンク手順を `passL` 前提で記述する | F-BUILD-001 | 対象外 | なし |
| T-BUILD-003 | Task | `build` | 設計済み | 最小 FFI 呼び出しの成功条件を機械的に判定できる文言にする | F-BUILD-001 | 対象外 | なし |

### M2: FFI 契約

| ID | 種別 | 対象 | 状態 | 完了条件 | 依存 issue | 互換性影響 | セキュリティ注記 |
|---|---|---|---|---|---|---|---|
| F-FFI-001 | Feature | `ffi` | 設計済み | 入出力バッファ、エラーコード、opaque handle、解放責務の規約が一箇所に集約されている | F-BUILD-001 | 部分互換 | panic 非伝播と所有権分離を明記する |
| T-FFI-001 | Task | `ffi` | 設計済み | `data + len` / `out + out_len` の規約と null / zero length の扱いを定義する | F-FFI-001 | 部分互換 | バッファ境界を明示する |
| T-FFI-002 | Task | `ffi` | 設計済み | 戻り値を `int32` 相当で統一し、成功 / 失敗の符号規約を定義する | F-FFI-001 | 部分互換 | エラーコードで失敗を表現する |
| T-FFI-003 | Task | `ffi` | 設計済み | opaque handle の create / update / finish / free の規約を定義する | F-FFI-001 | 部分互換 | 二重解放と再利用可否を明示する |
| T-FFI-004 | Task | `ffi` | 設計済み | Rust 側確保メモリの解放関数を必須とする前提を定義する | F-FFI-001 | 部分互換 | Rust / Nim 混在解放を禁止する |

### M3: ハッシュ API

| ID | 種別 | 対象 | 状態 | 完了条件 | 依存 issue | 互換性影響 | セキュリティ注記 |
|---|---|---|---|---|---|---|---|
| F-HASH-001 | Feature | `hash` / `sha` / `sha2` | 設計済み | 対象アルゴリズム、one-shot 優先順位、streaming 後続化の方針を明記する | F-FFI-001 | 部分互換 | SHA-1 の警告を含める |
| F-HASH-002 | Feature | `ripemd` | 設計済み | 対応 variant と digest 長を整理する | F-FFI-001 | 部分互換 | RIPEMD-160 の利用注意を記録する |
| F-HASH-003 | Feature | `keccak` | 設計済み | Keccak と SHA-3 の差異と公開名の整合を整理する | F-FFI-001 | 部分互換 | 意図的差分がある場合は明記する |
| F-HASH-004 | Feature | `blake2` | 設計済み | BLAKE2b / BLAKE2s と keyed hashing の対象範囲を整理する | F-FFI-001 | 部分互換 | なし |
| T-HASH-001 | Task | `hash` | 設計済み | one-shot API と streaming API の採用順を決める | F-HASH-001 | 部分互換 | 実装順の明確化のみ |
| T-HASH-002 | Task | `hash` | 設計済み | 標準化文書、既知テストベクタ、nimcrypto 既存テストの参照先を整理する | F-HASH-001 | 部分互換 | テストベクタ漏れを防ぐ |

### M4: HMAC API

| ID | 種別 | 対象 | 状態 | 完了条件 | 依存 issue | 互換性影響 | セキュリティ注記 |
|---|---|---|---|---|---|---|---|
| F-HMAC-001 | Feature | `hmac` | 設計済み | nimcrypto 互換の入力 / 出力形式と対応 hash の範囲を明記する | F-HASH-001 | 部分互換 | 弱い hash との組み合わせは警告対象 |
| T-HMAC-001 | Task | `hmac` | 設計済み | 対応 hash アルゴリズムの組み合わせを一覧化する | F-HMAC-001 | 部分互換 | なし |
| T-HMAC-002 | Task | `hmac` | 設計済み | 出力形式、例外 / エラー挙動、ゼロ長入力の扱いを整理する | F-HMAC-001 | 部分互換 | 未定義動作を避ける |

### M5: ブロック暗号 API

| ID | 種別 | 対象 | 状態 | 完了条件 | 依存 issue | 互換性影響 | セキュリティ注記 |
|---|---|---|---|---|---|---|---|
| F-CIPHER-001 | Feature | `rijndael` / AES | 設計済み | 鍵長、block size、AES と広義 Rijndael の差分を整理する | F-FFI-001 | 部分互換 | 互換範囲を誤認させない |
| F-CIPHER-002 | Feature | `twofish` | 設計済み | Twofish の鍵設定と暗号化 / 復号 API を整理する | F-FFI-001 | 部分互換 | 互換目的と採用理由を記録する |
| F-CIPHER-003 | Feature | `blowfish` | 設計済み | Blowfish の鍵設定と暗号化 / 復号 API を整理する | F-FFI-001 | 部分互換 | 64 bit block size の制約を警告する |
| T-CIPHER-001 | Task | `rijndael` / `twofish` / `blowfish` | 設計済み | 鍵長、block size、初期化、暗号化 / 復号差分を一覧化する | F-CIPHER-001, F-CIPHER-002, F-CIPHER-003 | 部分互換 | なし |
| T-CIPHER-002 | Task | `blowfish` | 設計済み | 危殆化・非推奨扱いが必要な記載を追記する | F-CIPHER-003 | 部分互換 | 推奨代替を併記する |

### M6: ブロック暗号モード

| ID | 種別 | 対象 | 状態 | 完了条件 | 依存 issue | 互換性影響 | セキュリティ注記 |
|---|---|---|---|---|---|---|---|
| F-MODE-001 | Feature | `bcmode` | 設計済み | ECB / CBC / CFB / OFB / CTR / GCM の対応優先度を明記する | F-CIPHER-001 | 部分互換 | 安全でないモードの警告を含める |
| T-MODE-001 | Task | `bcmode` | 設計済み | ECB / CBC / CFB / OFB / CTR / GCM の対応優先度を整理する | F-MODE-001 | 部分互換 | なし |
| T-MODE-002 | Task | `bcmode` | 設計済み | 認証タグ、IV / nonce、padding、エラー挙動の差分を整理する | F-MODE-001 | 部分互換 | タグ失敗を panic にしない |
| T-MODE-003 | Task | `bcmode` | 設計済み | ECB など危険な利用形態の警告方針を記録する | F-MODE-001 | 部分互換 | 安全でない利用を明示する |

### M7: 乱数 API

| ID | 種別 | 対象 | 状態 | 完了条件 | 依存 issue | 互換性影響 | セキュリティ注記 |
|---|---|---|---|---|---|---|---|
| F-RNG-001 | Feature | `sysrand` | 設計済み | OS 乱数取得の前提と失敗時挙動を整理する | F-FFI-001 | 部分互換 | 疑似乱数 fallback を採用しない前提を明記する |
| T-RNG-001 | Task | `sysrand` | 設計済み | OS 乱数取得 API の前提と platform 差分を整理する | F-RNG-001 | 部分互換 | 失敗時の明示的エラーを使う |
| T-RNG-002 | Task | `sysrand` | 設計済み | テストで決定論的乱数を扱う場合の方針を整理する | F-RNG-001 | 部分互換 | 実運用の乱数と切り離す |

### M8: utilities と互換性評価

| ID | 種別 | 対象 | 状態 | 完了条件 | 依存 issue | 互換性影響 | セキュリティ注記 |
|---|---|---|---|---|---|---|---|
| F-UTIL-001 | Feature | `utils` | 設計済み | hex / base 変換、比較、出力表現 option の差分を整理する | F-FFI-001 | 部分互換 | 定数時間比較の要否を確認する |
| T-UTIL-001 | Task | `utils` | 設計済み | 16 進文字列の大文字小文字、`0x` 接頭辞、エンコード補助の差分を整理する | F-UTIL-001 | 部分互換 | 表現差分を明記する |
| T-UTIL-002 | Task | `docs` | 設計済み | nimcrypto のテスト、例、ドキュメントを基準に互換性評価表を更新する | F-UTIL-001 | 部分互換 | 評価基準を固定する |

## 5. 状態管理ルール

- `Feature` は公開 API やモジュール単位の互換方針を表します。
- `Task` は Feature を完了させるための小粒度の確認項目です。
- 1 つの Feature には、対応する Task をできるだけ `3` 件以上持たせます。
- Feature が `完了` になる条件は、紐づく Task がすべて `完了` か `対象外` になることです。
- `保留` は、依存 issue か仕様未確定で止まっている場合だけ使います。

## 6. 危殆化アルゴリズム・意図的非互換の記録欄

| 対象 | 分類 | 記録理由 | 方針 | 関連 issue |
|---|---|---|---|---|
| SHA-1 | 危殆化 | 衝突耐性が現代用途に不十分 | 互換目的で提供する場合は警告を明記する | F-HASH-001 |
| Blowfish | 注意対象 | 64 bit block size に起因する利用上の制約がある | 互換目的・制約・推奨代替を記録する | F-CIPHER-003, T-CIPHER-002 |
| ECB mode | 安全でない利用形態 | パターン漏洩により一般用途で非推奨 | 実装対象にする場合も警告と用途制限を記録する | F-MODE-001, T-MODE-003 |
| OS 乱数 fallback | 意図的非互換候補 | 安全でない疑似乱数 fallback を避ける | `sysrand` 互換調査後も fallback は採用しない前提で記録する | F-RNG-001, T-RNG-001 |

## 7. 参考資料

- Rust を Nim から呼び出す: https://zenn.dev/dumblepy/articles/3db2134ff88763
- nimcrypto: https://github.com/cheatfate/nimcrypto
- Rust Reference / Linkage: https://doc.rust-lang.org/reference/linkage.html
- Rustonomicon / Foreign Function Interface: https://doc.rust-lang.org/nomicon/ffi.html
- Rust 2024 Edition Guide / Unsafe attributes: https://doc.rust-lang.org/edition-guide/rust-2024/unsafe-attributes.html
- Nim Manual / Foreign function interface: https://nim-lang.org/docs/manual.html
