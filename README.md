# lustre-client-observer

`lustre-client-observer` は Lustre client 上で `llite` を主観測面、`PtlRPC` を補助観測面として扱い、uid・process 単位のアクセス頻度と遅延を常時計測する MVP です。

## アーキテクチャ

- `bpftrace` が `ll_lookup_nd`, `ll_file_open`, `ll_file_read_iter`, `ll_file_write_iter`, `ll_fsync`, `ptlrpc_send_new_req`, `ptlrpc_queue_wait`, `__ptlrpc_free_req` に attach して raw event を出力します。
- Python エージェントが 10 秒窓で集約し、`metadata` と `data` の分類、`user|worker|daemon` の actor 分類、uid/process 単位の集約を行います。
- 常時計測の主シグナルは `OpenTelemetry Metrics` です。`OTLP` exporter を使って Collector へ送ります。Collector が無い環境では `--dry-run` で JSON 集約結果を標準出力へ出せます。
- 現在の MVP は `llite/PTLRPC` 側で mount 単位フィルタをまだ持たないため、`/proc/mounts` 上で Lustre mount が 1 つだけの client を前提に動作させます。複数 mount がある場合は誤ラベル化を避けるため起動を拒否します。

## Metrics

- `lustre.client.access.operations`
- `lustre.client.access.duration`
- `lustre.client.data.bytes`
- `lustre.client.rpc.wait.operations`
- `lustre.client.rpc.wait.duration`
- `lustre.client.inflight.requests`

共通属性は `user.id`, `process.name`, `lustre.access.class`, `lustre.access.op`, `lustre.actor.type` です。resource 属性は `service.name=lustre-client-observer`, `lustre.fs.name`, `lustre.client.mount` などを付与します。

## 使い方

Collector に送る場合:

```bash
tools/lustre_client_trace.sh \
  --mount /mnt/lustre \
  --collector-endpoint http://127.0.0.1:4318/v1/metrics
```

ローカル確認だけ行う場合:

```bash
tools/lustre_client_trace.sh \
  --mount /mnt/lustre \
  --window-seconds 5 \
  --duration 30 \
  --dry-run
```

Lima ベースの疎通確認は [e2e/lima/README.md](/Users/y-tsubouchi/src/github.com/yuuki/otel-lustre-tracer/e2e/lima/README.md) と [verify-observer.sh](/Users/y-tsubouchi/src/github.com/yuuki/otel-lustre-tracer/e2e/lima/scripts/verify-observer.sh) を参照してください。
