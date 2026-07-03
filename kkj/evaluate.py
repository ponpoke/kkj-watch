"""紐付け・意味づけの品質評価ハーネス

  python -m kkj.evaluate            # 全CORRECTION_LINKEDをCSV出力+機械監査
出力: data/link_eval.csv (人間の○△×採点用列つき)
機械監査: タイトル核類似度の再計算、機関一致、公告日順序(訂正は元より後のはず)
"""
import csv
import json

from . import linker, store, config


def main():
    conn = store.connect()
    rows = conn.execute(
        """SELECT e.detail_json, e.detected_at,
                  (SELECT a.analysis_json FROM change_analyses a
                   WHERE a.case_key = json_extract(e.detail_json,'$.original_key')
                     AND a.kind='correction_notice'
                   ORDER BY a.id DESC LIMIT 1) AS analysis
           FROM events e WHERE e.event_type='CORRECTION_LINKED'
           ORDER BY e.id""").fetchall()
    out = config.DATA_DIR / "link_eval.csv"
    suspicious = 0
    with open(out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["訂正公告タイトル", "元公告タイトル", "機関一致", "タイトル核類似度",
                    "日付順OK", "summary", "impact例", "confidence", "根拠引用あり",
                    "機械監査", "人間採点(○△×)", "メモ"])
        for r in rows:
            d = json.loads(r["detail_json"])
            corr = conn.execute("SELECT latest_json FROM cases WHERE key=?",
                                (d["correction_key"],)).fetchone()
            orig = conn.execute("SELECT latest_json FROM cases WHERE key=?",
                                (d["original_key"],)).fetchone()
            if not (corr and orig):
                continue
            crec, orec = json.loads(corr["latest_json"]), json.loads(orig["latest_json"])
            org_match = crec.get("organization_name") == orec.get("organization_name")
            import difflib
            c_core = linker.title_core(crec.get("project_name", ""))
            o_core = linker.title_core(orec.get("project_name", ""))
            sim = 1.0 if (c_core in o_core or o_core in c_core) else \
                difflib.SequenceMatcher(None, c_core, o_core).ratio()
            date_ok = (crec.get("cft_issue_date") or "") >= (orec.get("cft_issue_date") or "")
            a = json.loads(r["analysis"]) if r["analysis"] else {}
            ch = (a.get("changes") or [{}])[0]
            audit = []
            if not org_match:
                audit.append("機関不一致!")
            if sim < 0.85:
                audit.append(f"類似度低({sim:.2f})")
            if not date_ok:
                audit.append("日付逆転")
            if audit:
                suspicious += 1
            w.writerow([
                crec.get("project_name", "")[:60], orec.get("project_name", "")[:60],
                "OK" if org_match else "NG", f"{sim:.2f}",
                "OK" if date_ok else "NG",
                a.get("summary", "")[:80], ch.get("impact", "")[:80],
                ch.get("confidence", ""), "あり" if ch.get("source_quote") else "なし",
                " / ".join(audit) or "問題なし", "", "",
            ])
    total = len(rows)
    print(f"紐付け総数: {total}")
    print(f"機械監査で要確認: {suspicious} ({100 * suspicious // max(total, 1)}%)")
    print(f"採点シート: {out}")
    conn.close()


if __name__ == "__main__":
    main()
