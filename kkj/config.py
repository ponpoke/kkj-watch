"""フェーズ0設定: 対象縦領域=IT・役務系(国の機関中心)"""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "kkj.db"

API_URL = "https://www.kkj.go.jp/api/"

# 官公需ポータルAPIは Query / Project_Name / Organization_Name / LG_Code のいずれか必須。
# IT・役務系のキーワードで領域を絞る(フェーズ0: 月数百件規模に収める)
QUERIES = [
    "システム開発",
    "システム保守",
    "ソフトウェア",
    "データ入力",
    "クラウド",
    "ネットワーク構築",
    "情報システム",
    "アプリケーション",
    # 変更検知の在庫を直接取り込む(官公需の訂正は別公告として出ることが多い)
    "訂正公告",
    "変更公告",
]

# 1クエリあたりの取得件数(APIのCountパラメータ)
FETCH_COUNT = 100

# 原典ドキュメント巡回の設定(robots/利用規約順守: 各リクエスト3秒間隔)
# 240件/回 × 3時間おき = 全周約9時間。締切14日以内の案件は毎回優先再取得
DOC_FETCH_DELAY_SEC = 3.0
DOC_FETCH_MAX_PER_RUN = 240
DOC_FETCH_TIMEOUT = 30
USER_AGENT = "kkj-watch/0.1 (tender change-detection research; contact: ponzuzuzuzuzu@gmail.com)"

# 抽出用LLM(プラン指定: Haiku級)。ANTHROPIC_API_KEY があるときのみ有効。
EXTRACT_MODEL = "claude-haiku-4-5"
EXTRACT_MAX_TOKENS = 2048
