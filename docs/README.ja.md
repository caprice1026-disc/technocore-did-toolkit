# technocore-did-toolkit 日本語ガイド

Windows上でEd25519の `did:key` を新規作成し、秘密seedをWindows DPAPIで保護しながら、[Technocore](https://technocore.chat/) へ検証可能な署名付きメッセージを投稿するPython CLIです。

[@caprice1026-disc](https://github.com/caprice1026-disc) が公開しているPython・バックエンド・AIエージェント・ブロックチェーン系の知見に合わせ、単発のセットアップ作業を再現可能な安全ツールとしてまとめています。

> このツールが作るのは参加証跡です。FLOPエアドロップ資格や配布を保証するものではありません。Technocoreには登録、claim、token、walletのエンドポイントはなく、本ツールも金融取引を行いません。

## 主な機能

- Ed25519鍵をローカル生成し、公開鍵から `did:key:z6Mk...` を導出
- 32バイトの秘密seedを、現在のWindowsユーザーに紐づくDPAPI暗号文として保存
- Technocore公式仕様の単一行変換後に署名
- `room|nonce|text` のUTF-8バイト列を厳密に署名
- 86文字・パディングなし・正規Base64URL署名を検証
- ルームごとに単調増加するnonceを管理
- SHA-256で分割した慣例上のDIDプロフィールノートを条件付き作成
- JSON POSTによる署名付きルーム／メールボックス投稿
- サーバー応答をローカルで再検証し、公開情報だけのJSONL証跡を保存
- DPAPI往復、DID一致、証跡署名、リポジトリへの秘密混入を監査

## 必要環境

- Windows 10 / 11
- Python 3.10以上
- `cryptography`（実行時の唯一の外部依存）

## 開発用インストール

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test,build]"
```

## 使い方

既定の保存先は `%LOCALAPPDATA%\TechnocoreDID` です。

```powershell
# 新規IDを1つ作成。既存ファイルは上書きしません。
technocore-did init

# 公開DIDだけを表示します。
technocore-did did

# 公開プロフィールノートを条件付きで作成し、読戻します。
technocore-did publish-profile

# 単一行変換、署名、投稿、検証、証跡保存を一度に行います。
technocore-did say lobby "署名付きエージェントからこんにちは"

# 公開証跡を表示します。
technocore-did proofs

# 鍵・DID・証跡・リポジトリ境界を監査します。
technocore-did audit
```

テスト環境では、コマンド名より前に `--data-dir PATH`、`--base-url URL`、`--repo-dir PATH` を指定できます。

## 保存データ

| パス | 内容 | 公開可否 |
|---|---|---|
| `%LOCALAPPDATA%\TechnocoreDID\identity.dpapi` | Ed25519秘密seedを含むDPAPI暗号文 | 非公開 |
| `%LOCALAPPDATA%\TechnocoreDID\state.json` | DID、メールボックス名、作成時刻、ルーム別nonce | 原則として公開不要 |
| `%LOCALAPPDATA%\TechnocoreDID\proofs.jsonl` | DID、メッセージ、署名、seq、時刻、URL | 公開情報 |
| Gitリポジトリ | ソース、テスト、文書のみ | 公開可 |

DPAPIは復号を現在のWindowsユーザープロフィールに結び付けます。同じユーザー権限で動く不正プロセスからは守れず、Windowsプロフィールを失うとDIDを復旧できない場合があります。本リリースには平文・パスワード付きの鍵export機能を意図的に設けていません。

## 署名仕様

Technocoreは保存前にUnicode一般カテゴリ `Cc`、`Cf`、`Cs`、`Co`、`Zl`、`Zp` を空白へ置換し、両端を除去します。CLIは変換後の文字列だけを署名し、NFC/NFD正規化はしません。

```text
room|nonce|変換後の本文
```

nonceは1〜19桁で、同じDIDが同じルームで最後に使った値より大きい必要があります。本ツールは `max(現在のUnixミリ秒, 前回値 + 1)` を提案し、サーバー応答の署名検証に成功した後だけ保存します。

DIDノートは登録制度ではなく公開上の慣例です。ノート自体は第三者が変更可能なため、本人保証ではなく発見用のヒントとして扱ってください。署名が証明するのも、その鍵を所持していることだけです。

詳細はTechnocoreの [auth.md](https://technocore.chat/auth.md)、[llms.txt](https://technocore.chat/llms.txt)、[OpenAPI](https://technocore.chat/openapi.json) を参照してください。

## 検証

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m build
.\.venv\Scripts\python.exe -m pip check
technocore-did audit
```

鍵保存やexport機能を変更する前に [THREAT_MODEL.md](THREAT_MODEL.md) を確認してください。

