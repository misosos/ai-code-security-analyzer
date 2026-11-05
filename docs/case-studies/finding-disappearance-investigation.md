# 再検査で消えた Finding を調べる

## ケースと環境

基準版 `f5f1452d4bb3c6bebb9e5d23d7f36ffed17a131c`、Python 3.12.7、Semgrep 1.182.1、ローカル `baseline` 規則を使用した。隔離した合成 JavaScript プロジェクトを実際の ScanService と API 経由で検査した。これは実在する脆弱性の診断ではない。

実験者は初回に `stable.js` と `retired.js` の動的実行パターンを用意し、再検査前に `retired.js` のパターンを取り除き `added.js` に別のパターンを作った。この変更は**実験者が知る操作**であり、分析器がコード差分として観測した事実ではない。

2回の正常完了結果を同じ登録対象・プロファイルで結び、Registry の Session を介して評価した。評価契約 `finding-disappearance-evaluation/v1` は `COMPARABLE`、全体評価は `UNDETERMINED` を返した。`COMPARABLE` は観察結果を比較できることを表し、ソースや実際にロードされた規則が同一であるという意味ではない。

## Evidence Matrix

| Finding | 基準 | 現在 | 評価された経路観察 | 可能な説明と未確認事項 | 次に行う確認 |
| --- | --- | --- | --- | --- | --- |
| A `stable.js` | 報告 | 報告 | 評価項目なし（null） | 同一 ID でもコード・影響の同一性は未確認 | コードと実行経路を再確認 |
| B `retired.js` | 報告 | 同じ ID を報告せず | `PATH_REPORTED_SCANNED` | コード・規則・マッチ条件の変化などは仮説。コードスナップショットとロードされた規則は未検証 | Git diff、現在のファイル、規則と除外設定を別途確認 |
| C `added.js` | 報告なし | 報告 | 評価項目なし（null） | 現在のみの報告は新たな脆弱性発生の証明ではない | 現在のコード、入力と実行経路を確認 |

B の除外仮説は `CONTRADICTED`、コード変更と規則同一性の仮説はそれぞれ `UNDETERMINED` だった。これは Semgrep が同じパスを処理経路として報告した観察に基づく。すべての規則がそのファイルに適用・完了した証明ではない。

## 観察と限界

- **OBSERVED**: 両 scan は completed。Semgrep の報告と同じ実行の Manifest が Registry に結び付いた。
- **DERIVED**: Finding ID の厳密な集合差から A/B/C を三範疇に分類した。Finding ID は意味的同一性やコード同一性を保証しない。
- **OBSERVED**: B の現在パスは `PATH_REPORTED_SCANNED`。`paths.scanned` は Semgrep の報告であり、全ファイル・全規則の完了証明ではない。
- **UNAVAILABLE**: `source_snapshot_not_collected`、`rule_bytes_unverified`、`loaded_rule_identity_unverified`、`scope_completeness_unverified` が返った。一般ソースのスナップショットはこの実装では収集せず、実行中の変更競合も解消していない。
- **HYPOTHESIS**: コード変更によるマッチ変化は可能な説明。実験者の操作を評価器が証明したとはしない。
- **NOT_SUPPORTED**: 脆弱性の修正・解決、実際の悪用可能性、コードの安全性の自動判定。

## 分析家の手順

1. 登録対象、Rule Profile、各検査の終了状態と結果の生略を確認する。
2. Finding ID の三範疇を確認し、基準側の B を選ぶ。
3. サーバ評価の経路観察と除外仮説を読み、未収集・未検証の限界を確認する。画面には内部 Manifest 全体を表示しない。
4. Git diff、コード移動や削除、規則ファイルと Semgrep 設定・ignore を別途調べる。必要なら同じ条件で再検査する。
5. 実際の影響と入力経路は手動で検証し、根拠が不足すれば判断を保留する。
6. 調査終了時に Session と Run の Release を要求する。画面終了時の伝達は保証されず、最大15分の TTL が最終的な保管上限となる。

再現コマンドと実行結果の範囲は [再現記録](../er-d1-reproducibility-record.md)、不足・比較拒否の事例は [証拠の境界](investigation-evidence-boundaries.md)を参照。
