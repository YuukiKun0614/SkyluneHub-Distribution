# SkyluneHub Distribution

配布用 Public リポジトリです。元ソースは Private の `SkyluneHub-Source` で管理します。

- `loader/SkyluneHubLoader.lua` — Public 配布用 Loader。**SkyluneHub-Distribution** に接続します。
- `channels/beta.json` — 検証済み難読化版 V118 を指すテストチャンネル（有効）。
- `channels/stable.json` — Stable はまだ無効。動作確認後に公開します。
- `releases/v1.0.1/SkyluneHub.lua` — 難読化した V118 のみ収録。

## ベータ版起動（Potassium）

```lua
getgenv().SkyluneHubLoaderChannel = "beta"
getgenv().SkyluneHubLoaderDryRun = false
loadstring(game:HttpGet("https://raw.githubusercontent.com/YuukiKun0614/SkyluneHub-Distribution/main/loader/SkyluneHubLoader.lua"))()
```

## 注意

1. ZIPを解凍し、**フォルダ構成を保ったまま中身**を新規Publicリポジトリのルートへアップロードしてください。ZIPそのものをアップロードしないでください。
2. 新規リポジトリ名は **`SkyluneHub-Distribution`**、ブランチは `main` にしてください。
3. 配信ZIPには元のLuaソースを含めていません。ただし難読化は可逆なのでソースの絶対的な秘匿ではありません。
4. 旧 `SkyluneHub-Scripts` は**更新していません**。V117平文ソースは引き続き公開されており、履歴にも残っています。新リポジトリの検証が終わった後、旧リポジトリのPrivate化/削除を検討してください（公開済みコピーは回収できません）。
5. 繰り返しテストする前はRoblox / Potassiumを再起動するか、LoaderStatusとチャネルの前回状態に注意してください。
6. 配信ManifestのSHA-256は転送破損の検出を目的とし、リポジトリ改ざんを防ぐ電子署名ではありません。
