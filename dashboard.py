import base64
import html
import importlib.util
import os
import re
import sqlite3
from datetime import datetime
from zoneinfo import ZoneInfo

import pandas as pd
import plotly.express as px
import pycountry
import streamlit as st
from geoip2fast import GeoIP2Fast

from status_check import evaluate_system_status

VARSAYILAN_SAAT_DILIMI = ZoneInfo("Europe/Istanbul")

# ---------- Sayfa ayarları ----------
# Logo yolu çalışma dizinine değil dashboard.py'nin konumuna göre çözülür.
LOGO_YOLU = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "logo.png")


def _sayfa_ikonu():
    # Sekme ikonu olarak logoyu kullanır; logo okunamazsa ikon koymaz.
    try:
        from PIL import Image

        with Image.open(LOGO_YOLU) as resim:
            resim.load()
            return resim.copy()
    except Exception:
        return None


st.set_page_config(
    page_title="Honeypot Tehdit Paneli",
    layout="wide",
    page_icon=_sayfa_ikonu(),
    initial_sidebar_state="collapsed",
)

# ---------- Renk paleti (dark) ----------
SURFACE = "#1a1a19"
INK_PRIMARY = "#ffffff"
INK_SECONDARY = "#c3c2b7"
INK_MUTED = "#898781"
GRIDLINE = "#2c2c2a"
BASELINE = "#383835"
BLUE = "#3987e5"
CATEGORICAL = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"]
MAVI_OLCEK = [
    "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b",
]

# Risk seviyesi renkleri (durum paleti - sabit, başka hiçbir seri için kullanılmaz)
RISK_RENKLERI = {"İyi": "#0ca30c", "Uyarı": "#fab219", "Ciddi": "#ec835a", "Kritik": "#d03b3b"}
RISK_SIRASI = ["İyi", "Uyarı", "Ciddi", "Kritik"]

# Canlı sistem durumu: status_check.evaluate_system_status()'ın İngilizce
# anahtarlarını (Live/Degraded/Down/Unknown) panelin Türkçe gösterimine eşler
# (renk, kutunun sol kenarı ve yazı rengiyle verilir). "Unknown" = Docker/ES'e
# ulaşılamadı (durum bilinmiyor); bu "Down"dan ayrı tutulur çünkü ulaşamamak
# ile sistemin gerçekten çöktüğünü doğrulamak aynı şey değildir.
SISTEM_DURUM_RENKLERI = {"Live": "#0ca30c", "Degraded": "#fab219", "Down": "#d03b3b", "Unknown": "#898781"}
SISTEM_DURUM_ETIKETLERI = {
    "Live": "Canlı",
    "Degraded": "Kısmi",
    "Down": "Çevrimdışı",
    "Unknown": "Durum Bilinmiyor",
}

# ---------- Görsel ince ayarlar ----------
st.markdown(
    """
    <style>
        /* Başlık satırındaki üç kutu (başlık / sistem durumu / saat) aynı sabit
           yükseklikte ve içerikleri dikeyde ortalı - tek bir hizalı satır. */
        .hp-header, .hp-durum, .hp-clock {
            box-sizing: border-box;
            height: 120px;
            padding: 0.9rem 1.2rem;
            margin-bottom: 1.2rem;
            border: 1px solid rgba(255,255,255,0.10);
            border-radius: 14px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            overflow: hidden;
        }
        .hp-header {
            background: linear-gradient(135deg, rgba(57,135,229,0.25), rgba(13,13,13,0));
            padding-left: 1.6rem;
        }
        /* Streamlit, markdown içindeki h1'e kendi üst/alt boşluğunu ekliyor;
           sıfırlanmazsa başlık kutusu diğerlerinden uzun kalıyordu. */
        .hp-header h1 { margin: 0; padding: 0; font-size: 1.8rem; line-height: 1.2; color: #ffffff; }
        .hp-header p { margin: 0.35rem 0 0 0; color: #c3c2b7; font-size: 0.92rem; }
        .hp-clock { background-color: #1a1a19; text-align: center; }
        .hp-clock p { margin: 0; }
        .hp-clock .hp-clock-label { color: #898781; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em; }
        .hp-clock .hp-clock-time { color: #ffffff; font-size: 1.5rem; font-weight: 600; font-variant-numeric: tabular-nums; }
        .hp-clock .hp-clock-date { color: #c3c2b7; font-size: 0.78rem; margin-top: 0.15rem; }
        .hp-durum { background-color: #1a1a19; }
        .hp-durum p { margin: 0; }
        .hp-durum .hp-durum-label { color: #898781; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em; }
        .hp-durum .hp-durum-value { font-size: 1.15rem; font-weight: 600; }
        /* Uzun durum/hata metni kutuyu taşırmasın: tek satır, sığmazsa "...",
           tam metin üzerine gelince (title) görünür. */
        .hp-durum .hp-durum-detay {
            color: #c3c2b7;
            font-size: 0.78rem;
            margin-top: 0.15rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        div[data-testid="stMetric"] {
            background-color: #1a1a19;
            border: 1px solid rgba(255,255,255,0.10);
            border-radius: 12px;
            padding: 1rem 1rem 0.7rem 1rem;
        }
        div[data-testid="stMetricLabel"] { color: #898781; }
        .stTabs [data-baseweb="tab-list"] { gap: 4px; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------- Maskeli IP önekinden ülke tespiti (KVKK: sadece görünen iki oktet kullanılır) ----------
def _ulkeleri_coz(maskeli_ipler):
    geo = GeoIP2Fast(verbose=False)
    esleme = {}
    for maskeli_ip in maskeli_ipler:
        parcalar = str(maskeli_ip).split(".")
        if len(parcalar) != 4:
            continue
        arama_ip = f"{parcalar[0]}.{parcalar[1]}.0.0"
        sonuc = geo.lookup(arama_ip)
        if sonuc.is_private or not sonuc.country_code or sonuc.country_code == "--":
            continue
        ulke = pycountry.countries.get(alpha_2=sonuc.country_code)
        if ulke is None:
            continue
        esleme[maskeli_ip] = (sonuc.country_name, ulke.alpha_3)
    return esleme


# ---------- Veriyi oku (bir kez okuyup bellekte tut - performans için) ----------
@st.cache_data(show_spinner=False)
def veri_yukle():
    df = pd.read_parquet("FINAL_tpot_30days_kvkk_compliant.parquet")
    df["timestamp"] = pd.to_datetime(df["@timestamp"])

    esleme = _ulkeleri_coz(df["src_ip"].dropna().unique())
    df["ulke_adi"] = df["src_ip"].map(lambda ip: esleme.get(ip, (None, None))[0])
    df["ulke_iso3"] = df["src_ip"].map(lambda ip: esleme.get(ip, (None, None))[1])
    return df


# ---------- 10_risk_scoring.py çıktısını oku (gerçek IP -> maskeli IP) ----------
# 10_risk_scoring.py maskesiz src_ip ile çalışır; panel ise KVKK uyumlu maskeli
# veriyi gösterir. Aynı maskeleme kuralını (07_kvkk_compliance.py) burada da
# uygulayıp maskeli /16 bloğuna indiriyoruz. Birden fazla gerçek IP aynı bloğa
# düşebileceğinden, o blok için en kötü senaryoyu (en yüksek riski) gösteriyoruz.
MASKELI_IP_GECERSIZ = "***.***.***.***"  # src_ip 4 oktete ayrışmadığında (boş/bozuk veri)


def _ip_maskele(ip):
    parcalar = str(ip).split(".")
    if len(parcalar) == 4:
        return f"{parcalar[0]}.{parcalar[1]}.***.***"
    return MASKELI_IP_GECERSIZ


@st.cache_data(show_spinner=False)
def risk_skorlarini_yukle():
    dosya_yolu = "10_ip_risk_scores.parquet"
    if not os.path.exists(dosya_yolu):
        return None

    risk_df = pd.read_parquet(dosya_yolu)
    risk_df["src_ip"] = risk_df["src_ip"].apply(_ip_maskele)
    return (
        risk_df.groupby("src_ip")
        .agg(
            Risk_Score=("Risk_Score", "max"),
            abuse_score=("abuse_score", "max"),
            virustotal_score=("virustotal_score", "max"),
            is_ml_anomaly=("is_ml_anomaly", "any"),
        )
        .reset_index()
    )


def risk_seviyesi(skor):
    if skor >= 75:
        return "Kritik"
    if skor >= 50:
        return "Ciddi"
    if skor >= 25:
        return "Uyarı"
    return "İyi"


# ---------- Seçili IP için talep üzerine yapay zeka tehdit raporu ----------
# KVKK: 10_risk_scoring.py'nin çıktısı gerçek IP'yle anahtarlanır - bu gerçek
# IP sadece DAHİLİ aramalar (satır/olay bulma) için kullanılır. UI'da her
# zaman maskeli IP gösterilir, ve LLM'in ÜRETTİĞİ rapor metni de ekrana
# veya DB'ye yazılmadan önce 07_kvkk_compliance.py'deki ile aynı mantıkla
# maskelenir - girdiyi maskelemek yetmez, model çıktısında IP'yi tekrar
# etmesi ihtimaline karşı çıktı da taranmalı.
_IP_RAPOR_TABLO_OLUSTUR = """
    CREATE TABLE IF NOT EXISTS ip_risk_reports (
        masked_ip TEXT PRIMARY KEY,
        risk_score REAL,
        report_content TEXT,
        creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
"""


def _metni_maskele(metin):
    # Metindeki tüm IP adreslerini maskeler (07 ile aynı mantık).
    # LLM'in yazdığı raporu ekrana basmadan önce kullanılır.
    # Maskedeki * işaretleri "\*" olarak yazılır, yoksa markdown bunları
    # kalın/italik yazı sanıp görüntüyü bozar.
    ipv4_deseni = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def _degistir(eslesme):
        return _ip_maskele(eslesme.group(0)).replace("*", "\\*")

    return ipv4_deseni.sub(_degistir, str(metin))


@st.cache_data
def ip_rapor_lookup_yukle():
    # Her maskeli IP için, o bloktaki en riskli gerçek IP'nin skorunu bulur.
    dosya_yolu = "10_ip_risk_scores.parquet"
    if not os.path.exists(dosya_yolu):
        return None
    skor_df = pd.read_parquet(dosya_yolu)
    skor_df["maskeli_ip"] = skor_df["src_ip"].apply(_ip_maskele)
    return (
        skor_df.sort_values("Risk_Score", ascending=False)
        .groupby("maskeli_ip")
        .first()
    )


@st.cache_data
def gercek_olaylari_yukle():
    # 04 dosyasını sadece gereken kolonlarla bir kez yükler.
    return pd.read_parquet(
        "04_tpot_30days_final_labeled.parquet",
        columns=["src_ip", "@timestamp", "dest_port", "type", "payload"],
    )


def gercek_ip_ornek_olay(gercek_ip):
    # Bu IP'nin en uzun payload'lu olayını döndürür.
    gercek_df = gercek_olaylari_yukle()
    ip_olaylari = gercek_df[gercek_df["src_ip"] == gercek_ip]
    if ip_olaylari.empty:
        return None
    uzunluklar = ip_olaylari["payload"].apply(lambda x: len(str(x)) if pd.notnull(x) else 0)
    return ip_olaylari.loc[uzunluklar.idxmax()]


def _skor_metni(deger):
    return f"{deger:.1f}" if pd.notna(deger) else "bilinmiyor"


def rapor_baglami_olustur(gercek_ip, skor_satiri, olay_satiri):
    # LLM'e gönderilecek metni hazırlar.
    # Gerçek IP sadece buraya girer, ekrana veya DB'ye yazılmaz.
    if olay_satiri is not None:
        olay_metni = f"""- Timestamp: {olay_satiri['@timestamp']}
    - Source IP: {gercek_ip}
    - Target Port: {olay_satiri['dest_port']}
    - Sensor Type: {olay_satiri['type']}
    - Payload Length: {len(str(olay_satiri['payload']))} characters
    - Raw Payload: {olay_satiri['payload']}"""
    else:
        olay_metni = f"- Source IP: {gercek_ip}\n    - (No individual event log found for this IP.)"

    return f"""
    Please analyze the following attacker IP using both its logged activity and its
    pre-computed risk assessment from an internal scoring pipeline:
    {olay_metni}

    Pre-computed Risk Assessment:
    - Overall Risk Score: {_skor_metni(skor_satiri['Risk_Score'])}/100
    - AbuseIPDB Confidence Score: {_skor_metni(skor_satiri['abuse_score'])}
    - VirusTotal Detection Score: {_skor_metni(skor_satiri['virustotal_score'])}
    - Flagged by ML Anomaly Detection: {bool(skor_satiri['is_ml_anomaly'])}
    """


@st.cache_resource
def _ai_agent_modulunu_yukle():
    # 05_ai_agent.py'yi yükler (adı rakamla başladığı için normal import olmaz).
    # Bir kez yüklenir ve önbellekte tutulur.
    spec = importlib.util.spec_from_file_location("ai_agent_mod", "05_ai_agent.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ip_rapor_db_oku(maskeli_ip):
    conn = None
    try:
        conn = sqlite3.connect("threat_intel.db")
        conn.execute(_IP_RAPOR_TABLO_OLUSTUR)
        satir = conn.execute(
            "SELECT report_content FROM ip_risk_reports WHERE masked_ip = ?", (maskeli_ip,)
        ).fetchone()
        return satir[0] if satir else None
    except Exception:
        return None
    finally:
        if conn is not None:
            conn.close()


def _ip_rapor_db_yaz(maskeli_ip, risk_skoru, rapor_metni):
    conn = None
    try:
        conn = sqlite3.connect("threat_intel.db")
        conn.execute(_IP_RAPOR_TABLO_OLUSTUR)
        conn.execute(
            "INSERT OR REPLACE INTO ip_risk_reports (masked_ip, risk_score, report_content) VALUES (?, ?, ?)",
            (maskeli_ip, risk_skoru, rapor_metni),
        )
        conn.commit()
    except Exception:
        pass
    finally:
        if conn is not None:
            conn.close()


# Yeni bir yapay zeka raporu Groq anahtarı gerektirir. Anahtar yoksa (ör. demo
# verisiyle çalışırken) önbellekteki hazır raporlar yine gösterilir; yalnızca
# yeni üretim engellenir ve hata yerine açık bir uyarı verilir.
GROQ_ANAHTARI_YOK_MESAJI = (
    "Yeni yapay zeka raporu üretmek için .env dosyasında GROQ_API_KEY tanımlı olmalı. "
    "Anahtar olmadan yalnızca önceden hazırlanmış (önbellekteki) raporlar görüntülenebilir."
)


def _groq_anahtari_var_mi():
    return bool((os.environ.get("GROQ_API_KEY") or "").strip())


def ip_raporu_getir(maskeli_ip, gercek_ip, skor_satiri):
    # Raporu önce oturum belleğinde, sonra veritabanında arar.
    # İkisinde de yoksa LLM'den yeni rapor ister.
    # Her yerde sadece maskeli IP saklanır. Döner: (rapor, hata).
    if "ip_raporlari" not in st.session_state:
        st.session_state["ip_raporlari"] = {}

    if maskeli_ip in st.session_state["ip_raporlari"]:
        return st.session_state["ip_raporlari"][maskeli_ip], None

    db_rapor = _ip_rapor_db_oku(maskeli_ip)
    if db_rapor is not None:
        st.session_state["ip_raporlari"][maskeli_ip] = db_rapor
        return db_rapor, None

    if not _groq_anahtari_var_mi():
        return None, GROQ_ANAHTARI_YOK_MESAJI

    try:
        ai_agent = _ai_agent_modulunu_yukle()
        olay_satiri = gercek_ip_ornek_olay(gercek_ip)
        baglam = rapor_baglami_olustur(gercek_ip, skor_satiri, olay_satiri)
        ham_rapor = ai_agent.generate_threat_report(baglam)
    except Exception:
        return None, "Rapor üretilemedi: yapay zeka servisine erişilemedi. Lütfen daha sonra tekrar deneyin."

    maskeli_rapor = _metni_maskele(ham_rapor)  # ham_rapor bir daha asla kullanılmaz

    st.session_state["ip_raporlari"][maskeli_ip] = maskeli_rapor
    _ip_rapor_db_yaz(maskeli_ip, float(skor_satiri["Risk_Score"]), maskeli_rapor)

    return maskeli_rapor, None


# ---------- Aylık yönetici (CISO) raporu ----------
# Kalıcı kayıt 08_export_to_db.py'nin ai_intelligence_reports tablosudur (ekleme
# tabanlı; en güncel rapor = en son eklenen satır). 06'nın ürettiği ham rapor
# maskeli DEĞİLDİR - ekrana veya DB'ye gitmeden önce _metni_maskele'den geçer.
YONETICI_RAPOR_TURU = "Executive CISO Report"

_AI_RAPOR_TABLO_OLUSTUR = """
    CREATE TABLE IF NOT EXISTS ai_intelligence_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_type TEXT,
        report_content TEXT,
        creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
"""


@st.cache_resource
def _yonetici_modulunu_yukle():
    # 06_executive_reporter.py'yi yükler (adı rakamla başladığı için normal import olmaz).
    spec = importlib.util.spec_from_file_location("yonetici_mod", "06_executive_reporter.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@st.cache_data
def _yonetici_rapor_verisi_yukle():
    # Yönetici raporu için gereken kolonları yükler (rapora IP gitmez).
    return pd.read_parquet(
        "04_tpot_30days_final_labeled.parquet", columns=["Attack_Type", "dest_port", "type"]
    )


def son_yonetici_raporunu_oku():
    # En son yönetici raporunu okur. Döner: (rapor, tarih, hata).
    conn = None
    try:
        conn = sqlite3.connect("threat_intel.db")
        conn.execute(_AI_RAPOR_TABLO_OLUSTUR)
        satir = conn.execute(
            """
            SELECT report_content, creation_date FROM ai_intelligence_reports
            WHERE report_type = ?
            ORDER BY creation_date DESC, id DESC
            LIMIT 1
            """,
            (YONETICI_RAPOR_TURU,),
        ).fetchone()
    except Exception:
        return None, None, "Yönetici raporu veritabanından okunamadı. Lütfen daha sonra tekrar deneyin."
    finally:
        if conn is not None:
            conn.close()

    if satir is None:
        return None, None, None
    # DB'deki satırların 07 ile maskelenmiş olması beklenir; 08, 07'den önce
    # çalıştırılmışsa maskesiz metin girmiş olabilir. Maskeli metinde etkisizdir.
    return _metni_maskele(satir[0]), satir[1], None


def _yonetici_raporu_db_yaz(maskeli_rapor):
    conn = None
    try:
        conn = sqlite3.connect("threat_intel.db")
        conn.execute(_AI_RAPOR_TABLO_OLUSTUR)
        conn.execute(
            "INSERT INTO ai_intelligence_reports (report_type, report_content) VALUES (?, ?)",
            (YONETICI_RAPOR_TURU, maskeli_rapor),
        )
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        if conn is not None:
            conn.close()


def yonetici_raporu_uret():
    # Yeni yönetici raporu üretir ve maskeli halini döndürür.
    # Döner: (maskeli_rapor, hata, kesik_mi).
    # kesik_mi True ise rapor token sınırına takılıp yarım kalmıştır.
    try:
        yonetici = _yonetici_modulunu_yukle()
        baglam = yonetici.build_stats_context(_yonetici_rapor_verisi_yukle())
        ham_rapor, bitis_nedeni = yonetici.generate_executive_report_with_finish_reason(baglam)
    except Exception:
        return None, "Rapor üretilemedi: yapay zeka servisine erişilemedi. Lütfen daha sonra tekrar deneyin.", False

    return _metni_maskele(ham_rapor), None, bitis_nedeni == "length"  # ham_rapor bir daha asla kullanılmaz


# ---------- Yönetici raporunun PDF çıktısı ----------
# Rapor markdown olarak geliyor (başlıklar, tablolar, kalın yazı); PDF'te bu
# işaretleri temizleyip başlık/paragraf/madde yapısını koruyoruz. Türkçe
# karakterler için matplotlib ile birlikte gelen DejaVu Sans fontu kullanılıyor
# (fpdf2'nin yerleşik fontları ğ/ş/ı'yı desteklemez; ayrı font dosyası taşımaya
# da gerek kalmaz, Windows/Linux'ta aynı çalışır).
_MD_BASLIK = re.compile(r"^(#{1,6})\s+(.*)$")
_MD_KALIN_SATIR = re.compile(r"^\*\*(.+?)\*\*:?$")
_MD_YATAY_CIZGI = re.compile(r"^(-{3,}|\*{3,}|_{3,})$")
_MD_TABLO_AYRAC = re.compile(r"^\|?\s*:?-{3,}")
_MD_MADDE = re.compile(r"^\s*[-*+]\s+(.*)$")


def _md_isaretlerini_temizle(metin):
    # _metni_maskele maske yıldızlarını markdown için "\*" olarak kaçışlıyor;
    # vurgu işaretlerini silerken bunları korumak için önce yer tutucuya alıyoruz.
    metin = metin.replace("\\*", "\x00")
    metin = re.sub(r"\*\*|__|\*|`", "", metin)
    return metin.replace("\x00", "*")


@st.cache_data
def yonetici_raporu_pdf_olustur(rapor, tarih, kesik_mi):
    # Maskeli raporu PDF'e çevirir. Diske dosya yazmaz.
    import matplotlib
    from fpdf import FPDF

    font_klasoru = os.path.join(matplotlib.get_data_path(), "fonts", "ttf")

    # Sıkı ama okunaklı düzen: gövde 9.5pt, satır yüksekliği ~1.3x (4.4mm).
    # Kenar boşlukları fpdf2 varsayılanı olan 1cm'de bırakıldı; alt boşluk
    # 1.5cm'den 1.2cm'ye indirildi.
    GOVDE_PUNTO, GOVDE_SATIR = 9.5, 4.4
    TABLO_PUNTO, TABLO_SATIR = 8.5, 4.0
    MADDE_GIRINTI = 3
    BASLIK_PUNTO = {1: 12, 2: 11}  # ### ve daha derinleri: 10
    BOS_SATIR_ARALIK = 1
    YATAY_CIZGI_ARALIK = 1.5

    class _RaporPDF(FPDF):
        def footer(self):
            self.set_y(-10)
            self.set_font("DejaVu", size=7.5)
            self.set_text_color(137, 135, 129)
            self.cell(0, 5, f"Sayfa {self.page_no()}", align="C")

    pdf = _RaporPDF(format="A4")
    pdf.set_margins(left=10, top=10, right=10)
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.add_font("DejaVu", "", os.path.join(font_klasoru, "DejaVuSans.ttf"))
    pdf.add_font("DejaVu", "B", os.path.join(font_klasoru, "DejaVuSans-Bold.ttf"))
    pdf.add_page()

    pdf.set_font("DejaVu", "B", 15)
    pdf.multi_cell(0, 7.5, "Aylık Yönetici Tehdit Raporu", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("DejaVu", size=8)
    pdf.set_text_color(82, 81, 78)
    pdf.multi_cell(
        0,
        4,
        f"Oluşturulma tarihi: {tarih}   ·   IP adresleri KVKK uyarınca maskelenmiştir.",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    if kesik_mi:
        pdf.set_text_color(208, 59, 59)
        pdf.multi_cell(
            0, 4, "Uyarı: Rapor token sınırına takıldığı için eksik olabilir.", new_x="LMARGIN", new_y="NEXT"
        )
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)

    for ham_satir in rapor.splitlines():
        satir = ham_satir.strip()

        if not satir:
            pdf.ln(BOS_SATIR_ARALIK)
            continue
        if _MD_YATAY_CIZGI.match(satir):
            pdf.ln(YATAY_CIZGI_ARALIK)
            continue

        baslik = _MD_BASLIK.match(satir)
        kalin_satir = _MD_KALIN_SATIR.match(satir)
        madde = _MD_MADDE.match(ham_satir)

        if baslik:
            pdf.ln(1.5)
            pdf.set_font("DejaVu", "B", BASLIK_PUNTO.get(len(baslik.group(1)), 10))
            pdf.multi_cell(0, 5.5, _md_isaretlerini_temizle(baslik.group(2)), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(0.5)
        elif satir.startswith("|"):
            if _MD_TABLO_AYRAC.match(satir):
                continue
            hucreler = [_md_isaretlerini_temizle(h.strip()) for h in satir.strip("|").split("|")]
            pdf.set_font("DejaVu", size=TABLO_PUNTO)
            pdf.multi_cell(0, TABLO_SATIR, "  |  ".join(hucreler), new_x="LMARGIN", new_y="NEXT")
        elif kalin_satir:
            pdf.ln(0.5)
            pdf.set_font("DejaVu", "B", GOVDE_PUNTO)
            pdf.multi_cell(
                0, GOVDE_SATIR, _md_isaretlerini_temizle(kalin_satir.group(1)), new_x="LMARGIN", new_y="NEXT"
            )
        elif madde:
            pdf.set_font("DejaVu", size=GOVDE_PUNTO)
            pdf.set_x(pdf.l_margin + MADDE_GIRINTI)
            pdf.multi_cell(
                pdf.epw - MADDE_GIRINTI,
                GOVDE_SATIR,
                "• " + _md_isaretlerini_temizle(madde.group(1)),
                new_x="LMARGIN",
                new_y="NEXT",
            )
        else:
            pdf.set_font("DejaVu", size=GOVDE_PUNTO)
            pdf.multi_cell(0, GOVDE_SATIR, _md_isaretlerini_temizle(satir), new_x="LMARGIN", new_y="NEXT")

    return bytes(pdf.output())


# ---------- Yükleme ekranı ----------
@st.cache_resource
def _ilk_yukleme_durumu():
    # Veriler bir kez yüklendiyse yükleme ekranı tekrar gösterilmez.
    return {"tamam": False}


@st.cache_data(show_spinner=False)
def _logo_base64(yol, degisim_zamani):
    # Logoyu kontrol edip base64'e çevirir. Logo değişirse önbellek yenilenir.
    from PIL import Image

    with Image.open(yol) as resim:
        resim.verify()
    with open(yol, "rb") as dosya:
        return base64.b64encode(dosya.read()).decode("ascii")


def _yukleme_ekrani_html():
    # Yükleme ekranının HTML'ini döndürür: logo + spinner + "Yükleniyor..." yazısı.
    # st.image ve st.spinner yerine düz HTML kullanılır, çünkü onlar
    # gereksiz bir tam ekran düğmesi ekliyor ve yanlış yerde çıkıyordu.
    try:
        logo = _logo_base64(LOGO_YOLU, os.path.getmtime(LOGO_YOLU)) if os.path.exists(LOGO_YOLU) else None
    except Exception:
        logo = None  # bozuk/okunamayan dosya: aşağıdaki yedeğe düş

    if logo:
        gorsel = (
            f'<img class="hp-yukleme-logo" src="data:image/png;base64,{logo}" alt="">'
        )
    else:
        gorsel = '<p class="hp-yukleme-yedek-baslik">Honeypot Tehdit İstihbaratı Paneli</p>'

    return f"""
    <style>
        .hp-yukleme {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            padding-top: 10vh;
            gap: 0.9rem;
        }}
        .hp-yukleme-logo {{
            width: min(420px, 85vw);
            pointer-events: none;
            user-select: none;
        }}
        .hp-yukleme-yedek-baslik {{ color: {INK_PRIMARY}; font-size: 1.6rem; font-weight: 600; margin: 0; }}
        .hp-yukleme-spinner {{
            width: 2rem;
            height: 2rem;
            border: 3px solid rgba(255, 255, 255, 0.12);
            border-top-color: {BLUE};
            border-radius: 50%;
            animation: hp-don 0.9s linear infinite;
        }}
        .hp-yukleme-yazi {{ color: {INK_SECONDARY}; font-size: 0.95rem; margin: 0; }}
        @keyframes hp-don {{ to {{ transform: rotate(360deg); }} }}
        @media (prefers-reduced-motion: reduce) {{
            .hp-yukleme-spinner {{ animation-duration: 2.4s; }}
        }}
    </style>
    <div class="hp-yukleme" role="status" aria-live="polite">
        {gorsel}
        <div class="hp-yukleme-spinner"></div>
        <p class="hp-yukleme-yazi">Yükleniyor...</p>
    </div>
    """


yukleme_durumu = _ilk_yukleme_durumu()
if yukleme_durumu["tamam"]:
    df = veri_yukle()
    risk_df = risk_skorlarini_yukle()
else:
    yukleme_ekrani = st.empty()
    try:
        yukleme_ekrani.markdown(_yukleme_ekrani_html(), unsafe_allow_html=True)
        df = veri_yukle()
        risk_df = risk_skorlarini_yukle()
        yukleme_durumu["tamam"] = True
    finally:
        yukleme_ekrani.empty()

# ---------- Canlı saat widget'ı ----------
# st.context.timezone, tarayıcının Intl API'sinden gelen IANA saat dilimini
# sunucuya bildirir; ziyaretçi İstanbul dışında biriyse doğru yerel saati
# göstermek için bunu kullanıyoruz, tespit edilemezse İstanbul'a düşüyoruz.
@st.fragment(run_every="1s")
def canli_saat():
    dilim_adi = st.context.timezone
    try:
        dilim = ZoneInfo(dilim_adi) if dilim_adi else VARSAYILAN_SAAT_DILIMI
    except Exception:
        dilim_adi, dilim = None, VARSAYILAN_SAAT_DILIMI

    simdi = datetime.now(dilim)
    etiket = dilim_adi or "İstanbul (varsayılan)"
    st.markdown(
        f"""
        <div class="hp-clock">
            <p class="hp-clock-label">Yerel Saat · {etiket}</p>
            <p class="hp-clock-time">{simdi.strftime('%H:%M:%S')}</p>
            <p class="hp-clock-date">{simdi.strftime('%d.%m.%Y')}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------- Canlı sistem durumu widget'ı ----------
# status_check.py Docker konteyner sayısını (subprocess + docker CLI) ve
# Elasticsearch'teki en son olayın ne kadar önce geldiğini kontrol eder.
# Docker/ES'e her saniye istek atmamak için saat widget'ından daha seyrek yeniliyoruz.
# status_check.py kendi içinde Docker/ES hatalarını zaten yutuyor, ama panel
# hiçbir durumda çökmemeli: beklenmeyen bir durum/anahtar gelirse de
# "Durum Bilinmiyor" göster, hata fırlatma.
@st.fragment(run_every="10s")
def canli_sistem_durumu():
    try:
        sonuc = evaluate_system_status()
        durum = sonuc["overall_status"]
        konteyner_detay = sonuc["container_detail"]
        tazelik_detay = sonuc["freshness_detail"]
    except Exception:
        durum = "Unknown"
        konteyner_detay = "Durum bilinmiyor"
        tazelik_detay = "Durum bilinmiyor"

    renk = SISTEM_DURUM_RENKLERI.get(durum, SISTEM_DURUM_RENKLERI["Unknown"])
    etiket = SISTEM_DURUM_ETIKETLERI.get(durum, SISTEM_DURUM_ETIKETLERI["Unknown"])
    konteyner_detay = html.escape(str(konteyner_detay))
    tazelik_detay = html.escape(str(tazelik_detay))
    st.markdown(
        f"""
        <div class="hp-durum" style="border-left: 4px solid {renk};">
            <p class="hp-durum-label">Honeypot Sistemi</p>
            <p class="hp-durum-value" style="color: {renk};">{etiket}</p>
            <p class="hp-durum-detay" title="{konteyner_detay}">{konteyner_detay}</p>
            <p class="hp-durum-detay" title="{tazelik_detay}">{tazelik_detay}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------- Başlık ----------
baslik_kolonu, durum_kolonu, saat_kolonu = st.columns([3, 2.2, 1.1])
with baslik_kolonu:
    st.markdown(
        """
        <div class="hp-header">
            <h1>Honeypot Tehdit İstihbaratı Paneli</h1>
            <p>Çok vektörlü honeypot sensörlerinden toplanan saldırı verilerinin analizi</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
with saat_kolonu:
    canli_saat()


# Durum rozeti başlıktaki yerine (durum_kolonu) yazılır ama betiğin SONUNDA
# çağrılır: Docker/ES kontrolü erişilemeyen bir host'ta saniyeler sürebiliyor
# (Windows'ta reddedilen localhost bağlantısı ~4sn), en başta çağrılırsa tüm
# gövde onu bekliyordu. Streamlit önceden oluşturulmuş bir kolona sonradan
# yazmaya izin verdiği için rozet aynı yerde, içerik çizildikten sonra belirir.
def _durum_rozetini_ciz():
    with durum_kolonu:
        canli_sistem_durumu()

# ---------- Kenar çubuğu filtreleri ----------
st.sidebar.header("Filtreler")

sensorler = sorted(df["type"].dropna().unique())
saldirilar = sorted(df["Attack_Type"].dropna().unique())
min_tarih, max_tarih = df["timestamp"].min().date(), df["timestamp"].max().date()

secili_sensorler = st.sidebar.multiselect("Honeypot Sensörü", sensorler, default=[])
secili_saldirilar = st.sidebar.multiselect("Saldırı Türü", saldirilar, default=[])
tarih_araligi = st.sidebar.date_input(
    "Tarih Aralığı", value=(min_tarih, max_tarih), min_value=min_tarih, max_value=max_tarih
)

sensor_filtresi = secili_sensorler if secili_sensorler else sensorler
saldiri_filtresi = secili_saldirilar if secili_saldirilar else saldirilar
if isinstance(tarih_araligi, tuple) and len(tarih_araligi) == 2:
    baslangic, bitis = tarih_araligi
else:
    baslangic, bitis = min_tarih, max_tarih

df_filtreli = df[
    df["type"].isin(sensor_filtresi)
    & df["Attack_Type"].isin(saldiri_filtresi)
    & (df["timestamp"].dt.date >= baslangic)
    & (df["timestamp"].dt.date <= bitis)
]

if df_filtreli.empty:
    st.warning("Seçili filtrelerle eşleşen kayıt bulunamadı.")
    _durum_rozetini_ciz()
    st.stop()


# ---------- Ortak grafik stili ----------
def stilendir(fig, height=420):
    fig.update_layout(
        paper_bgcolor=SURFACE,
        plot_bgcolor=SURFACE,
        font=dict(color=INK_SECONDARY, family="system-ui, -apple-system, 'Segoe UI', sans-serif"),
        title_font=dict(color=INK_PRIMARY, size=16),
        margin=dict(t=60, l=10, r=10, b=10),
        height=height,
        showlegend=False,
    )
    fig.update_xaxes(gridcolor=GRIDLINE, zerolinecolor=BASELINE, linecolor=BASELINE, color=INK_MUTED)
    fig.update_yaxes(gridcolor=GRIDLINE, zerolinecolor=BASELINE, linecolor=BASELINE, color=INK_MUTED)
    return fig


# ---------- Özet metrikler ----------
kolon1, kolon2, kolon3, kolon4 = st.columns(4)
kolon1.metric("Toplam Saldırı", f"{len(df_filtreli):,}")
kolon2.metric("Benzersiz Saldırgan IP", f"{df_filtreli['src_ip'].nunique():,}")
kolon3.metric("Saldırı Türü Sayısı", df_filtreli["Attack_Type"].nunique())
kolon4.metric("Aktif Sensör Sayısı", df_filtreli["type"].nunique())

st.write("")

# ---------- Bölüm gezinmesi ----------
# st.tabs seçili sekmeyi yeniden çalıştırmalar arasında korumuyor (sekme içindeki
# bir düğme ilk sekmeye geri atıyordu) ve tüm sekme panellerini gizli olarak
# DOM'a çizdiği için etiket ile içerik zaman zaman uyuşmuyordu. Bunun yerine
# seçim session_state'te (widget key) tutuluyor ve yalnızca aktif bölüm çiziliyor.
# Yalnızca aktif bölüm çizildiği için diğer bölümlerdeki widget'lar o çalışmada
# yok; Streamlit, çizilmeyen widget'ın değerini atar. Anahtarı widget oluşturulmadan
# önce kendine yeniden atamak değeri "kullanıcı ayarlı" yapar: bölüm gizliyken
# korunur, geri dönülünce geri yüklenir (st.tabs'taki davranışla aynı).
for _kalici_anahtar in ("risk_min_skor", "ip_rapor_secimi"):
    if _kalici_anahtar in st.session_state:
        st.session_state[_kalici_anahtar] = st.session_state[_kalici_anahtar]

BOLUMLER = [
    "Genel Bakış",
    "Bölgesel Dağılım",
    "Risk Skorları",
    "Portlar & Sensörler",
    "Yönetici Raporu",
    "Ham Veri",
]
aktif_bolum = st.segmented_control(
    "Bölüm",
    BOLUMLER,
    default=BOLUMLER[0],
    required=True,
    key="aktif_bolum",
    label_visibility="collapsed",
)
st.write("")

if aktif_bolum == "Genel Bakış":
    gunluk = df_filtreli.set_index("timestamp").resample("D").size().reset_index(name="Sayi")
    fig_zaman = px.area(gunluk, x="timestamp", y="Sayi", title="Günlük Saldırı Hacmi")
    fig_zaman.update_traces(line=dict(color=BLUE, width=2), fillcolor="rgba(57,135,229,0.15)")
    fig_zaman.update_layout(xaxis_title=None, yaxis_title="Saldırı Sayısı")
    st.plotly_chart(stilendir(fig_zaman), width='stretch')

    saldiri_sayilari = df_filtreli["Attack_Type"].value_counts().reset_index()
    saldiri_sayilari.columns = ["Attack_Type", "Sayi"]
    fig_saldiri = px.bar(
        saldiri_sayilari.sort_values("Sayi"),
        x="Sayi",
        y="Attack_Type",
        orientation="h",
        text="Sayi",
        title="En Çok Görülen Saldırı Türleri",
        color="Attack_Type",
        color_discrete_sequence=CATEGORICAL,
    )
    fig_saldiri.update_traces(textposition="outside", marker_line_width=0)
    fig_saldiri.update_layout(xaxis_title="Saldırı Sayısı", yaxis_title=None)
    st.plotly_chart(stilendir(fig_saldiri), width='stretch')

if aktif_bolum == "Bölgesel Dağılım":
    ulke_sayilari = (
        df_filtreli.dropna(subset=["ulke_iso3"])
        .groupby(["ulke_iso3", "ulke_adi"])
        .size()
        .reset_index(name="Sayi")
    )
    bilinmeyen_sayisi = len(df_filtreli) - int(ulke_sayilari["Sayi"].sum())

    fig_harita = px.choropleth(
        ulke_sayilari,
        locations="ulke_iso3",
        color="Sayi",
        hover_name="ulke_adi",
        color_continuous_scale=MAVI_OLCEK,
        title="Saldırganların Coğrafi Dağılımı (Maskeli IP Önekinden Ülke Tespiti)",
    )
    fig_harita.update_geos(
        bgcolor=SURFACE,
        landcolor="#242422",
        oceancolor="#0d0d0d",
        showocean=True,
        countrycolor=BASELINE,
        coastlinecolor=BASELINE,
        showframe=False,
        projection_type="natural earth",
    )
    fig_harita.update_layout(
        coloraxis_colorbar=dict(
            title="Saldırı Sayısı", tickfont=dict(color=INK_MUTED), title_font=dict(color=INK_SECONDARY)
        )
    )
    st.plotly_chart(stilendir(fig_harita, height=480), width='stretch')

    ulke_top = ulke_sayilari.sort_values("Sayi", ascending=False).head(10)
    fig_ulke_bar = px.bar(
        ulke_top.sort_values("Sayi"),
        x="Sayi",
        y="ulke_adi",
        orientation="h",
        text="Sayi",
        title="En Çok Saldırı Gönderen Ülkeler (Top 10)",
    )
    fig_ulke_bar.update_traces(marker_color=BLUE, textposition="outside")
    fig_ulke_bar.update_layout(xaxis_title="Saldırı Sayısı", yaxis_title=None)
    st.plotly_chart(stilendir(fig_ulke_bar), width='stretch')

    if bilinmeyen_sayisi > 0:
        st.caption(
            f"Not: {bilinmeyen_sayisi:,} kayıt özel/iç ağ IP'lerinden geldiği veya konumu "
            "maskeli önekten tespit edilemediği için haritaya dahil edilmedi."
        )

if aktif_bolum == "Risk Skorları":
    if risk_df is None:
        st.info(
            "Risk skorları henüz hesaplanmamış. Bu sekmeyi doldurmak için proje kök dizininde "
            "`python 10_risk_scoring.py` komutunu çalıştırın (AbuseIPDB + VirusTotal sorguları içerir, "
            "~500 benzersiz IP için birkaç dakika sürer)."
        )
    else:
        risk_filtreli = risk_df[risk_df["src_ip"].isin(df_filtreli["src_ip"].unique())].copy()

        if risk_filtreli.empty:
            st.info("Seçili filtrelerle eşleşen risk skoru bulunamadı.")
        else:
            risk_filtreli["Risk_Seviyesi"] = risk_filtreli["Risk_Score"].apply(risk_seviyesi)

            # ---------- Risk sekmesi içi filtre ----------
            min_risk_skoru = st.slider(
                "Minimum Risk Skoru", min_value=0, max_value=100, key="risk_min_skor"
            )
            risk_filtreli = risk_filtreli[risk_filtreli["Risk_Score"] >= min_risk_skoru]

            if risk_filtreli.empty:
                st.info("Seçili filtre kriterlerine uyan IP bulunamadı.")
            else:
                # ---------- Rapor için IP seçimi: yazmak yerine görüp tıklama ----------
                # "***.***.***.***" = kaynak IP alanı ayrıştırılamayan bozuk kayıtların
                # düştüğü ortak kova (ör. boş değer) - gerçek bir IP temsil etmediği
                # için rapor seçiminde göstermiyoruz.
                ip_secenekleri = [
                    ip
                    for ip in risk_filtreli.sort_values("Risk_Score", ascending=False)["src_ip"].tolist()
                    if ip != MASKELI_IP_GECERSIZ
                ]
                risk_skoru_haritasi = risk_filtreli.set_index("src_ip")["Risk_Score"]

                if not ip_secenekleri:
                    st.info("Rapor üretilebilecek geçerli bir IP bulunamadı.")
                    secili_maskeli_ip = None
                else:
                    secili_maskeli_ip = st.selectbox(
                        "IP Seçin (Risk Skoruna Göre Sıralı)",
                        ip_secenekleri,
                        format_func=lambda ip: f"{ip} — Risk: {risk_skoru_haritasi[ip]:.0f}",
                        key="ip_rapor_secimi",
                    )

                # Seçili IP'nin yapay zeka raporu, seçimin hemen altında. Geçerli IP
                # yoksa yukarıdaki bilgi mesajı zaten gösteriliyor.
                if secili_maskeli_ip is not None:
                    st.subheader("Seçili IP için Yapay Zeka Tehdit Raporu")
                    if st.button("Rapor Üret", key="ip_rapor_uret_buton"):
                        lookup_df = ip_rapor_lookup_yukle()
                        if lookup_df is None or secili_maskeli_ip not in lookup_df.index:
                            st.warning("Bu IP için önceden hesaplanmış risk verisi bulunamadı.")
                        else:
                            skor_satiri = lookup_df.loc[secili_maskeli_ip]
                            with st.spinner("Rapor üretiliyor..."):
                                rapor, hata = ip_raporu_getir(
                                    secili_maskeli_ip, skor_satiri["src_ip"], skor_satiri
                                )
                            if hata == GROQ_ANAHTARI_YOK_MESAJI:
                                st.warning(hata)
                            elif hata:
                                st.error(hata)
                            else:
                                st.markdown(rapor)

                st.write("")

                k1, k2, k3 = st.columns(3)
                k1.metric("Skorlanan IP Sayısı", f"{len(risk_filtreli):,}")
                k2.metric("Ortalama Risk Skoru", f"{risk_filtreli['Risk_Score'].mean():.1f}")
                k3.metric("Kritik Riskli IP Sayısı", int((risk_filtreli["Risk_Seviyesi"] == "Kritik").sum()))

                st.write("")

                risk_top = risk_filtreli.sort_values("Risk_Score", ascending=False).head(15)
                fig_risk = px.bar(
                    risk_top.sort_values("Risk_Score"),
                    x="Risk_Score",
                    y="src_ip",
                    orientation="h",
                    text="Risk_Score",
                    color="Risk_Seviyesi",
                    category_orders={"Risk_Seviyesi": RISK_SIRASI},
                    color_discrete_map=RISK_RENKLERI,
                    title="En Yüksek Risk Skorlu IP'ler (Top 15)",
                )
                fig_risk.update_traces(textposition="outside", marker_line_width=0)
                fig_risk.update_layout(xaxis_title="Risk Skoru (0-100)", yaxis_title=None, xaxis_range=[0, 108])
                stilendir(fig_risk)
                fig_risk.update_layout(
                    showlegend=True,
                    legend_title_text="Risk Seviyesi",
                    legend=dict(bgcolor=SURFACE, bordercolor=BASELINE, borderwidth=1),
                )
                st.plotly_chart(fig_risk, width='stretch')

                st.subheader("Risk Skoru Detayları")
                goster_df = risk_filtreli.sort_values("Risk_Score", ascending=False).copy()
                goster_df["is_ml_anomaly"] = goster_df["is_ml_anomaly"].map({True: "Evet", False: "Hayır"})
                goster_df = goster_df[
                    ["src_ip", "Risk_Score", "Risk_Seviyesi", "abuse_score", "virustotal_score", "is_ml_anomaly"]
                ]
                goster_df.columns = ["IP (Maskeli)", "Risk Skoru", "Seviye", "AbuseIPDB", "VirusTotal", "ML Anomali"]
                st.dataframe(goster_df, width='stretch', height=400, hide_index=True)

if aktif_bolum == "Portlar & Sensörler":
    sol, sag = st.columns(2)

    with sol:
        port_sayilari = (
            df_filtreli["dest_port"].dropna().astype(int).astype(str).value_counts().head(10).reset_index()
        )
        port_sayilari.columns = ["Port", "Sayi"]
        fig_port = px.bar(
            port_sayilari.sort_values("Sayi"),
            x="Sayi",
            y="Port",
            orientation="h",
            text="Sayi",
            title="En Çok Hedeflenen Portlar (Top 10)",
        )
        fig_port.update_traces(marker_color=BLUE, textposition="outside")
        fig_port.update_layout(xaxis_title="İstek Sayısı", yaxis_title=None, yaxis=dict(type="category"))
        st.plotly_chart(stilendir(fig_port), width='stretch')

    with sag:
        tip_sayilari = df_filtreli["type"].value_counts()
        top8 = tip_sayilari.head(8).copy()
        diger_toplam = tip_sayilari.iloc[8:].sum()
        if diger_toplam > 0:
            top8["Diğer"] = diger_toplam
        tip_df = top8.reset_index()
        tip_df.columns = ["Sensör", "Sayi"]
        fig_tip = px.bar(
            tip_df.sort_values("Sayi"),
            x="Sayi",
            y="Sensör",
            orientation="h",
            text="Sayi",
            title="Honeypot Sensör Dağılımı",
            color="Sensör",
            color_discrete_sequence=CATEGORICAL,
        )
        fig_tip.update_traces(textposition="outside", marker_line_width=0)
        fig_tip.update_layout(xaxis_title="Olay Sayısı", yaxis_title=None)
        st.plotly_chart(stilendir(fig_tip), width='stretch')

if aktif_bolum == "Yönetici Raporu":
    st.subheader("Aylık Yönetici (CISO) Tehdit Raporu")
    st.caption(
        "Son 30 günün toplu istatistiklerinden yapay zeka ile üretilir. "
        "Rapor, ekranda gösterilmeden ve kaydedilmeden önce KVKK uyarınca maskelenir."
    )

    gosterilecek_rapor, gosterilecek_tarih = None, None

    # finish_reason DB'de saklanmıyor (şema 08'e ait); bu yüzden kesik üretilen
    # raporları bu oturumda metinleriyle hatırlıyoruz ki uyarı sonraki
    # yeniden çizimlerde de aynı raporun üstünde kalsın.
    if "yonetici_kesik_raporlar" not in st.session_state:
        st.session_state["yonetici_kesik_raporlar"] = set()

    yeniden_uret = st.button("Yeniden Üret", key="yonetici_rapor_uret_buton")
    if yeniden_uret and not _groq_anahtari_var_mi():
        st.warning(GROQ_ANAHTARI_YOK_MESAJI)
    elif yeniden_uret:
        with st.spinner("Rapor üretiliyor..."):
            yeni_rapor, hata, kesik_mi = yonetici_raporu_uret()
        if not hata and kesik_mi:
            st.session_state["yonetici_kesik_raporlar"].add(yeni_rapor)
        if hata:
            st.error(hata)
        elif _yonetici_raporu_db_yaz(yeni_rapor):
            st.success("Yeni rapor üretildi ve kaydedildi.")
        else:
            # Kayıt başarısızsa DB'deki eski rapor "en güncel" görünmesin diye
            # yeni (maskeli) raporu doğrudan gösteriyoruz.
            st.warning("Rapor üretildi ancak veritabanına kaydedilemedi; aşağıda yalnızca bu oturum için gösteriliyor.")
            gosterilecek_rapor, gosterilecek_tarih = yeni_rapor, "şimdi (kaydedilmedi)"

    if gosterilecek_rapor is None:
        db_rapor, db_tarih, hata = son_yonetici_raporunu_oku()
        if hata:
            st.error(hata)
        elif db_rapor is None:
            st.info(
                "Henüz bir yönetici raporu üretilmemiş. İlk raporu oluşturmak için "
                "\"Yeniden Üret\" düğmesine basın."
            )
        else:
            gosterilecek_rapor, gosterilecek_tarih = db_rapor, f"{db_tarih} (UTC)"

    if gosterilecek_rapor is not None:
        st.caption(f"Oluşturulma tarihi: {gosterilecek_tarih}")
        rapor_kesik_mi = gosterilecek_rapor in st.session_state["yonetici_kesik_raporlar"]
        if rapor_kesik_mi:
            st.warning("Rapor token sınırına takıldığı için eksik olabilir.")

        try:
            pdf_bayt = yonetici_raporu_pdf_olustur(gosterilecek_rapor, gosterilecek_tarih, rapor_kesik_mi)
        except Exception:
            st.error("PDF oluşturulamadı. Rapor aşağıda görüntülenmeye devam ediyor.")
        else:
            tarih_eslesme = re.match(r"\d{4}-\d{2}-\d{2}", gosterilecek_tarih)
            dosya_adi = f"yonetici_raporu_{tarih_eslesme.group(0)}.pdf" if tarih_eslesme else "yonetici_raporu.pdf"
            st.download_button(
                "PDF Olarak İndir",
                data=pdf_bayt,
                file_name=dosya_adi,
                mime="application/pdf",
                key="yonetici_pdf_indir",
            )

        with st.container(border=True):
            st.markdown(gosterilecek_rapor)

if aktif_bolum == "Ham Veri":
    st.subheader("Son Kayıtlar")
    st.dataframe(
        df_filtreli.drop(columns=["timestamp"]).head(200),
        width='stretch',
        height=600,
        hide_index=True,
    )

# En son: yavaş olabilen canlı durum kontrolü, sayfa içeriği çizildikten sonra.
_durum_rozetini_ciz()
