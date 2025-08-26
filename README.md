# Cyber-Threat-Intelligence-Parser

🖥️ Kullanım --------------------------------------------------------------
Sözdizimi
python cti_parser.py INPUT [INPUT ...] [-o OUT] [--out-format {jsonl,csv,stix}] [--source SOURCE] [--tlp TLP]

Parametreler -------------------------------------------------------

INPUT → Girdi dosyaları (stix/misp/csv/xml/txt)

-o, --output → Çıktı dosyası (varsayılan stdout)

--out-format → jsonl | csv | stix

--source → Varsayılan kaynak adı

--tlp → Varsayılan TLP (CLEAR, GREEN, AMBER, AMBER+STRICT, RED)

Örnekler -------------------------------------------------------------
# JSON feed'ten JSONL çıktı
python cti_parser.py feed.json -o out.jsonl

# CSV'den CSV çıktı
python cti_parser.py feed.csv --out-format csv -o out.csv

# Düz metinden STIX çıktı
python cti_parser.py feed.txt --out-format stix -o indicators.json --source "OSINT Feed" --tlp AMBER

🧪 Test Senaryoları ----------------------------------------------

TXT Girdi: 8.8.8.8, malicious.com → ip ve domain olarak çıkar.

CSV Girdi: 1.1.1.1 (ip), malware.com (domain) → tarih ve tipler işlenir.

JSON Listesi: test@example.com (email), 32 karakter hex (md5) → doğru tür.

STIX Bundle: [domain-name:value = 'evil.org'] → domain çıkar.

MISP JSON: ip-dst: 9.9.9.9 → ip olarak çıkar.

python cti_parser.py samples/ioc.txt samples/ioc.csv samples/ioc.json \
  --out-format jsonl -o test_out.jsonl --source "Local Test" --tlp GREEN

⚠️ Kısıtlamalar ----------------------------------

Regex tabanlı IOC tespitinde false positive/negative olasılığı vardır.

OpenIOC desteği sınırlıdır.

STIX pattern parser yalnızca yaygın kalıpları destekler (karmaşık boolean ifadeler tam işlenmez).

Çok büyük dosyalar belleğe yüklenir; stream işleme yapılmaz.

Saat dilimi olmayan tarih alanları UTC kabul edilir.

🔗 Entegrasyon ------------------------------------

SOAR/SIEM: JSONL çıktı → Logstash/Fluentd ile ingest edilebilir.

STIX: TAXII sunucularına yüklemek için --out-format stix kullanılabilir.

Python modülü: parse_files() fonksiyonu doğrudan kullanılabilir.

📄 Lisans  -------------------------------------------------

İç kullanım için örnek betiktir; telif ve dağıtım koşulları kurum politikalarınıza göre belirlenmelidir.

