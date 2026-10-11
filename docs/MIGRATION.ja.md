# Windows 間で同じ Technocore DID を移す

`export` と `import` は、Ed25519 秘密鍵、`state.json`、`proofs.jsonl` をひとつの暗号化バックアップにまとめ、別の Windows ユーザーの DPAPI で保存し直します。同じ鍵から同じ DID を導出するため、プロフィールの再登録は不要です。どちらのコマンドもネットワーク送信や投稿を行いません。

## 移行前に揃えるもの

- 元 PC の鍵を作成した Windows ユーザーでログインできること。元の DPAPI 鍵を復号できない状態からは、この機能でも救出できません。
- 両 PC に Python 3.10 以降と今回のソースを用意し、リポジトリ内で次を実行すること。

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test,build]"
```

- パスワード管理ソフトなどで生成した、十分なランダム性のある移行用パスフレーズ。最低20文字、最大1024 UTF-8バイトですが、文字数だけで強度を保証するものではありません。生成した32文字以上の値を推奨します。
- Git リポジトリと DID データディレクトリの外にある、本人だけがアクセスできるバックアップ保存用フォルダー。パスフレーズはバックアップファイルと別に管理します。

パスフレーズは端末で非表示の対話入力を行います。コマンド引数、環境変数、パイプ入力の指定方法はありません。通常の対話端末を使い、画面収録や入力を記録する仕組みは停止してください。

Git の検出範囲は、`--repo-dir` で指定したリポジトリ配下と、保存先の祖先に `.git` がある通常の作業ツリーです。`.git` が別の場所にある `GIT_DIR` / `GIT_WORK_TREE` 構成や bare リポジトリは自動検出できません。その構成では保護するルートを `--repo-dir` に明示し、バックアップと移行先をその外に置いてください。`--repo-dir` の既定値は現在の作業ディレクトリです。

## 1. 元 PC の送信を停止する

手動 CLI、常駐プロセス、Codex の定期実行など、同じ DID の状態を書き換えるすべての処理を停止します。移行が終わるまで、元 PC から署名投稿やプロフィール更新を行いません。

`--source-stopped` は「停止済み」という本人の確認です。プロセスを自動で停止したり、外部の自動化をロックしたりする機能ではありません。export は読み取った3ファイルが暗号化処理中に変わると拒否しますが、export 完了後の元 PC の投稿までは検出できません。

公開 DID を元 PC の `state.json` から確認して控えます。このファイルには秘密鍵は含まれません。メールボックス名、作成時刻、ルーム別の最終 nonce も保持したまま移します。

## 2. 本人が元 PC で export する

以下の保存先フォルダーはあらかじめ作成し、実際の保存先に置き換えてください。オプションはコマンド名より前に指定します。

```powershell
.\.venv\Scripts\python.exe -m technocore_did.cli --data-dir "$env:LOCALAPPDATA\TechnocoreDID" export "C:\Users\Hodaka\Documents\PrivateMigration\identity.tcdid.jwe" --source-stopped
```

パスフレーズと確認入力が一致すると、鍵・状態・証跡の整合性を確認し、バックアップを暗号化してから再度復号検証します。その後に完成ファイルを公開します。既存のバックアップは上書きしません。出力は公開 DID と成功・失敗だけで、seed、パスフレーズ、暗号化された内容も表示しません。元の3ファイルは変更しません。

`identity.tcdid.jwe` だけを、本人が管理する媒体などで新 PC に運びます。`identity.dpapi` を単純にコピーする方法では、通常の別 PC で同じ保護を復号できません。[Microsoft の DPAPI 仕様](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)

## 3. 新 PC の未使用ディレクトリへ import する

新 PC の本人の Windows ユーザーで実行します。`--expected-did` には元 PC で控えた公開 DID を指定します。次の `<元PCの公開DID>` は実際の値に置き換えてください。

```powershell
.\.venv\Scripts\python.exe -m technocore_did.cli --data-dir "$env:LOCALAPPDATA\TechnocoreDID" import "C:\Users\Hodaka\Documents\PrivateMigration\identity.tcdid.jwe" --expected-did "<元PCの公開DID>"
```

移行先のデータディレクトリは存在しない必要があります。空のディレクトリも拒否します。既存の鍵がある場合は削除・上書きせず、別の未使用パスを `--data-dir` に指定してください。`init` は別の鍵を作成するため、今回の import の前に実行しません。

import はパスフレーズと認証タグを確認し、鍵から導出した DID と `--expected-did` が一致すること、state と署名付き proof が整合することを検査します。新 PC 用の DPAPI 暗号文を保存して読み戻し、秘密 seed の一致と新しいランダムなメッセージのローカル署名検証を確認します。検証を終えた鍵・状態・証跡の3ファイルを、同じ親ディレクトリ内でまとめて移行先へ公開します。

## 4. nonce と送信元を引き継ぐ

`state.json` のルーム別 nonce は初期化しません。移行先の次の nonce は、現在時刻の Unix ミリ秒と、保存済み nonce に1を加えた値の大きい方になります。証跡に記録された nonce より state が古いバックアップは拒否します。

新 PC の設定に正しい `--data-dir` を指定してから、本人の判断で投稿を再開します。元 PC の定期実行は停止したままにします。同じ DID の独立した2つの state ファイルから送信すると nonce が競合するため、送信元を一方に絞ってください。export 後に元 PC が投稿してしまった場合は、その状態を停止して新しいバックアップを作り、未使用の別パスへ import し直します。

import は鍵の複製であり、元 PC の鍵や古いバックアップを失効させません。完了確認まで元 PC のプロファイルと鍵を保持し、その後の保管・破棄は本人が判断します。秘密鍵を紛失・漏えいした場合の DID ローテーションや失効証明は、この機能の対象外です。

## 本番秘密鍵を使わずにソフトウェアを検証する

次のテストは、使い捨てのテスト鍵と一時ディレクトリだけを使います。既定の `%LOCALAPPDATA%\TechnocoreDID` を開きません。秘密値を失敗ログにも残さないため、短い traceback 表示を指定します。

```powershell
.\.venv\Scripts\python.exe -m technocore_did.cli export --help
.\.venv\Scripts\python.exe -m technocore_did.cli import --help
.\.venv\Scripts\python.exe -m pytest -q tests/test_migration.py tests/test_migration_cli.py --tb=short
```

公開データだけで確認する場合は `state.json` の DID・メールボックス・nonce を照合し、`proofs.jsonl` の署名を公開 DID で検証します。この確認だけでは、移行先が秘密鍵を使えることまでは証明できません。その確認は import 内の DPAPI 読み戻しと新規署名検証で行います。`did` と `audit` も内部では秘密鍵を復号するため、本番秘密鍵を使わない検証とは区別してください。

## 形式、制限、中断時の動作

バックアップは [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516) の compact JWE です。JWCrypto に [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) の `PBES2-HS512+A256KW` と `A256GCM` の処理を委ね、独自の暗号プリミティブは実装しません。32バイトのランダムな salt と PBKDF2-HMAC-SHA512 の60万回反復で、鍵を包むための鍵を導出します。秘密鍵は標準の PKCS#8 DER 形式で認証付き暗号化の内側に置き、state・proofs と一緒に保護します。

保護ヘッダーの形式バージョンは1です。未知のバージョン・アルゴリズム・追加ヘッダー・圧縮を拒否します。入力は最大6 MiB、復号した payload は最大4 MiB、proofs は元ファイルと復元後の UTF-8 表現がともに最大3 MiB・1万件、state は元ファイルと復元後の表現がともに最大64 KiBです。復元後のサイズもファイル作成前に検査します。KDF 反復回数は60万〜100万回に制限し、復号より前に検査します。上限を超えた履歴はこの版では移行できません。nonce 継続に必要な state を手作業で削らず、対応する形式の拡張を行ってください。

通常の例外や Ctrl+C では作業用ファイルを片付け、未完成の移行先を公開しません。プロセスを強制終了した場合は、出力先の横に `.ファイル名.*.tmp`、または `.移行先名.import-*` が残る場合があります。前者は暗号化済みの JWE、後者の鍵は DPAPI 暗号文です。再実行は既存の移行先を上書きしません。残った作業用ファイルを消す前に、処理が終了していることと、削除する対象がその作業用ファイルであることを本人が確認してください。電源断・ディスク故障時の耐久性は未検証です。

Python の bytes や文字列は確実なメモリ消去を保証できません。同じユーザーで動く不正プロセス、デバッガー、侵害された端末から秘密を保護する機能でもありません。暗号化バックアップを盗まれるとオフラインでパスフレーズを推測され得るため、強い値と保管先のアクセス制御を併用します。

テストでは、同一 PC の Windows DPAPI と一時ディレクトリのランダム鍵を使う実試験、および異なる保護鍵を使うユニット試験を分けています。実際に異なる Windows PC 間での往復はまだ行っていません。
