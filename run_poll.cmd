@echo off
rem kkj-watch 定期巡回: 案件メタデータ + 原典文書
set PYTHONIOENCODING=utf-8
cd /d C:\Users\ponzu\Desktop\fable_pj
python -m kkj.pipeline poll >> data\poll.log 2>&1
python -m kkj.pipeline poll-docs >> data\poll.log 2>&1
rem APIキーが環境変数にあれば新着案件を自動で構造化(無ければno-op)
python -m kkj.pipeline extract 20 >> data\poll.log 2>&1
rem 変更履歴DB(資産)のバックアップ、14世代保持
python -m kkj.pipeline backup >> data\poll.log 2>&1
