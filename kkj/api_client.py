"""官公需情報ポータルサイト検索APIクライアント(標準ライブラリのみ)"""
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET

from . import config

# レスポンスXMLの SearchResult 直下フィールド → 内部キー
FIELDS = {
    "Key": "key",
    "ExternalDocumentURI": "document_uri",
    "ProjectName": "project_name",
    "ProjectDescription": "project_description",
    "Date": "fetched_by_portal_at",
    "CftIssueDate": "cft_issue_date",
    "PeriodStartTime": "period_start",
    "PeriodEndTime": "period_end",
    "OrganizationName": "organization_name",
    "PrefectureName": "prefecture_name",
    "CityName": "city_name",
    "LgCode": "lg_code",
    "CityCode": "city_code",
    "FileType": "file_type",
    "FileSize": "file_size",
    "Category": "category",
    "CftKind": "cft_kind",
    "Certification": "certification",
}


def search(query=None, count=None, cft_issue_date=None, extra=None):
    """検索APIを叩き、案件dictのリストと総ヒット数を返す"""
    params = {}
    if query is not None:
        params["Query"] = query
    if count is not None:
        params["Count"] = str(count)
    if cft_issue_date is not None:
        params["CFT_Issue_Date"] = cft_issue_date
    if extra:
        params.update(extra)

    url = config.API_URL + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": config.USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read()

    root = ET.fromstring(raw)
    hits_el = root.find(".//SearchHits")
    hits = int(hits_el.text) if hits_el is not None and hits_el.text else 0

    records = []
    for sr in root.iter("SearchResult"):
        rec = {}
        for xml_name, key in FIELDS.items():
            el = sr.find(xml_name)
            if el is not None and el.text is not None:
                rec[key] = el.text.strip()
        if rec.get("key"):
            records.append(rec)
    return records, hits
