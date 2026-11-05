# 証拠不足と比較拒否

## Case 02: コード変更を評価できない

実際の A/B → A/C 実行では `retired.js` の過去の Finding が現在報告されず、現在の経路は `PATH_REPORTED_SCANNED` と報告された。評価契約 `finding-disappearance-evaluation/v1` の全体状態は `UNDETERMINED`、コード変更仮説は `UNDETERMINED` だった。`source_snapshot_not_collected` と2種類の規則 identity 未検証が限界として返された。

| 分類 | 内容 | 根拠・限界・次の確認 |
| --- | --- | --- |
| DERIVED | 同じ Finding ID が現在報告されなかった | 2つの実 ScanResponse の集合差。応答に含まれない事実だけを表す |
| OBSERVED | 現在の対象経路が処理経路として報告された | Semgrep の範囲観察。全規則適用を保証しない |
| UNAVAILABLE | 一般ソース snapshot、ロードされた規則全体の identity | 分析器は diff を収集しない。分析家は履歴と規則を別途確認する |
| HYPOTHESIS | コードやマッチ条件の変化 | 実験者は変更したが評価器は原因を証明していない |
| NOT_SUPPORTED | 脆弱性解決・悪用可能性の自動判定 | 独立した手動検証が必要 |

Skip が未収集なら除外がなかった証拠にはならない。今回 B の実測では経路が scanned と報告されたため、`SKIP_EVIDENCE_NOT_COLLECTED` をこの Finding の実測結果としては記載しない。

## Case 03: 同じ Run を2回指定

同じ実 Run Handle を baseline と current に渡す実 API 操作は HTTP `409 binding_rejected` だった。独立した2回の検査を要求する境界であり、空の正常評価には変換されない。実験者は2つの異なる実行を取り直して評価する。

作成済み Session の Release 後の再評価は HTTP `404 evidence_unavailable` だった。Handle の値は公開しない。期限切れ・不在・解放済みの区別を外部へ詳細に開示しない設計である。これらは実 Semgrep 結果を登録した in-process FastAPI TestClient の観察で、外部サーバへのネットワーク送信ではない。

部分・失敗・省略や他 target の境界は既存の独立テストで検証する。Fake Clock や fake adapter を使うケースは実 Semgrep の観察と混同しない。正常 0 Finding は安全性証明ではなく、失敗検査とは scan status で区別する。
