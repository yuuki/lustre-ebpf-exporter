# Lima Lustre 2.14.0 E2E 環境

このディレクトリは、Lima 上に Lustre 2.14.0 の最小 E2E 環境を立てるためのテンプレートと構築スクリプトをまとめたものです。

重要な前提:

- Lustre 2.14.0 の公開 RPM は `el8.3` 系で提供されています。
- そのため、以前の設計メモにあった `Rocky Linux 9.6 + Lustre 2.14.0` はそのままでは非対応です。
- この初期 E2E では、Lima 上の `Rocky 8 / x86_64` を実行対象にして Lustre 2.14.0 を検証します。
- Apple Silicon 上では `qemu + x86_64 エミュレーション` になるため、VM 起動や DKMS ビルドは遅めです。
- reverse-sshfs を使ってホストのワークスペースを guest へ見せるため、template の system provision で `fuse-sshfs` を入れます。

## 構成

- `lustre-e2e-server`
  - Rocky 8 / x86_64
  - MGS + MDT + OSS + OST を 1 ノードに集約
  - `mdt` と `ost` の Lima 追加ディスクを guest 側で `/dev/vdb`, `/dev/vdc` として ext4 フォーマットし、`/mnt/lima-mdt`, `/mnt/lima-ost` にマウントした上で loopback イメージを作って `mkfs.lustre` を実行
- `lustre-e2e-client`
  - Rocky 8 / x86_64
  - Lustre client をインストールして `lustrefs` を `/mnt/lustre` に mount
- ネットワーク
  - Lima `user-v2`
  - VM 間疎通ができるので、client から server の `@tcp` NID へ接続可能

## 使い方

```bash
./e2e/lima/scripts/up.sh
./e2e/lima/scripts/verify-cluster.sh
./e2e/lima/scripts/destroy.sh
```

`up.sh` は次を順に実行します。

1. Lima テンプレートの検証
2. `mdt` / `ost` 追加ディスクの作成
3. server VM 起動
4. client VM 起動
5. server 側 Lustre 構築
6. client 側 Lustre mount
7. smoke verify

## 注意点

- 本構成は `Lustre 2.14.0 をまず Lima 上で再現する` ことを優先した最小 E2E です。
- server 側は Lustre 付属 kernel へ切り替え、さらに `SELinux=disabled` にして host 側 restart を 2 回まで要求します。これは Whamcloud の walk-thru に合わせた前提です。
- server/client とも DKMS ではなく prebuilt `kmod-*` パッケージを優先します。
- 9.6 系の検証が必要なら、Lustre 側を 2.16 系へ上げる構成を別プロファイルとして分離するのが安全です。
