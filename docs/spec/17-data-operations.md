## 17. Veri, HA, Denetim Log'u, Gözlemlenebilirlik, Dağıtım ve Operasyon

**Bu bölümün kuralları.**
- Alt bölümler 17.1–17.10 operasyon konularıdır. §17.11 karar kaydı ve reconsider eşikleri, §17.12 açık sorulardır.
- Depo tablosu, CDDL zarfı, commit yolu, failure matrisi, SLO'lar ve sinyal tablosu burada normatiftir. Tablolardaki bileşen kimlikleri CMP-*n*'dir (§16.3.3).
- Operasyon kararları OP-9–OP-59'dur (OP-1–OP-8 §16.4'te, OP-60 §16.6.1'dedir). Her OP satırı şu alanları taşır: statü (FROZEN / PD / EA / HYPOTHESIS / WATCH), garanti sınıfı, gerekçe.
- **Düzlem ayrımı (bütün bölüm boyunca).** *Authority plane* kuralları (domain log, sequencer, ValidityContract) semantiktir. *Identity plane* kuralları (oturum, token, hesap, identity denetim log'u) mekanizmadır. Bir identity plane mekanizması authority kararına yalnız Claim girdisi olarak etki eder (TI-15, MD-7).
- Ölçülmüş sayılar tek ortamdadır (Apple M4, Rust 1.98.1, PG 18.6, Docker). Mutlak değerler kapasite planlamasına doğrudan girmez; oranlar ve yöntemler girer. ENGINEERING ASSUMPTION (EA) sayıları ölçülmemiştir (OQ-1).

---

### 17.1 Yazma yolu ve kanonik depo

#### 17.1.1 Authority plane: tek yazar, head CAS, atomik batch

Authority plane'in yazma yolu §16.1 A1–A3, §16.5 ve T6/T7'dedir ve değişmez. AuthorityDomain başına tek sequencer (CMP-3) vardır. Değerlendirme paraleldir, serileşme yalnız kısa kritik bölümdedir. Her batch tek transaction'dır: kayıtlar ∪ sync-derived ∪ outbox ∪ head CAS. Head CAS `WHERE pos = q_first−1 AND epoch = e` koşuluyla yapılır. Bölünmüş beyinde bile ikinci yazarı DB'de durdurur (TI-2; BS, FA-2 altında).

15 adımlı commit yolu normatiftir:

```text
1  CMP-1  TLS 1.3 sonlandırma; PEP transport kimliği (mTLS / OAuth client / DPoP / WIMSE WPT) → audience bağlamı
2  CMP-2  limitler (SI-20): aşım = protocol rejection (kayıt yok, nonce tüketilmez)
3  CMP-2  AIS ön-doğrulama (exact bayt üzerinde imza; domain/nonce/intent digest/PEP audience/mode eşleşmesi;
           eşleşmezse protocol hatası). KeyBinding'in GÜNCEL olduğu (rekey/terminate yok)
           otoriter olarak adım 8'de StateView'den okunur ve instance@(I) key'iyle read-set'e girer
4  CMP-2  IntentEnvelope'u pin'li SPP digest'iyle tiple → deterministic CBOR → intent digest (caller'ınki değil)
5  CMP-1  placement directory (CMP-26) → domain'in cell'i ve güncel leader'ı (OPERATIONAL; yanlışsa leader reddeder)
6  CMP-3  nonce tablosu: varsa → idempotent dönüş (aynı digest + actor) / terminal DENY / REQUIRE_ACTION ise
           aynı nonce ile yeniden değerlendirme; farklı digest → protocol hatası
7  CMP-3  inline proof'lar (Claim, assertion) → bu commit'in batch'ine Claim record olarak eklenecek (kararın önünde,
           ayrı pozisyonlarda; `domain.handover` / `domain.recover` batch'lerinde bu pozisyonlar HO/FR adımlarında
           açıkça sayılır [§16.6])
8  CMP-4  StateView(p) üzerinde değerlendirme (p = leader'ın uygulanmış head'i): outcome, read-set R,
           consumption planı K, zaman sınırı τ (bağımlılıkların en erken zaman sınırı)
9  CMP-3  SERIAL VALIDATION: ∀(key,ver)∈R: ver = head'deki ver; ∀u∈K: kalan ≥ draw;
           t = max(son recorded_at, now()); t < τ   — biri bozulursa (8)'e dön, head'de yeniden değerlendir
           (sınırlı deneme; tükenirse "retry" protocol rejection — outcome değil)
10  CMP-3  in-memory version/sayaç güncelle; kayıt pos = q; basis = q−1; batch'e ekle
11  CMP-5  BATCH TX: INSERT zarflar + body'ler; UPDATE sync-derived; INSERT outbox;
           UPDATE head SET pos=q_last, … WHERE domain=D AND pos=q_first−1 AND epoch=e   → COMMIT (sync quorum)
12  CMP-3  tx veya CAS başarısız → leader step-down, in-memory durum atılır, hiçbir ack yok (TI-2, TI-9)
13  CMP-7  ALLOW'da: receipt / artefakt payload'ları (digest'leri zaten kayıtta) → CMP-22a signer sürecinde
           operasyonel anahtarla imza
14  CMP-6  kayıt witness/replica-before-ack sınıfındaysa (SEC23): kapsayan checkpoint'e kadar önek replica'ya durable
           (CMP-21; TI-13) → out-of-cycle checkpoint → ≥1 bağımsız witness cosign
15  CMP-1  Decision Response (basis_ref = (D, q−1, version vector digest))
```

**Neden bu tasarım:** Değerlendirme paralel ve okuma ağırlıklıdır. Serileşme yalnız (9)–(11)'deki kısa kritik bölümdedir. SpiceDB'de token okuma tazeliğini sağlar; Access'te **yazma** (consumption) da aynı serileşme noktasından geçmek zorundadır (INV-21). Bu yüzden commit kararları hiçbir zaman token'lı bir replica'dan verilmez (TI-5).

Atomik birimler tablosu ve at-most-once senaryoları OP-S1–OP-S12 aşağıdadır:

| Geçiş | Tek tx'teki içerik | Not |
|---|---|---|
| ALLOW + consumption (draw, single-use, nonce) | DecisionRecord + budget sayaçları + single-use bayrakları + nonce satırı | INV-21 |
| Her meta-Exercise ALLOW + state change | DecisionRecord + güncel authority-state satırları + version key'leri | INV-2 |
| `instance.create` + ilk `mandate.bind` | Core meta-schema tek Exercise olarak ifade ediyorsa tek DecisionRecord'un iki effect'i; iki ayrı Exercise olarak gelirse ara durum fail-closed'dur: Mandate'siz Instance hiçbir şey exercise edemez (Exercisable = Holding ∩ Mandate, INV-11) | Her iki biçim güvenli taşınır |
| `instance.recover` (eski terminal + successor + recovery slot) | Tek DecisionRecord'un üç effect'i | INV-13 |
| `anchor.transfer` + disposition | Tek DecisionRecord'un effect'leri | E14 |
| Holder değişikliği (yeni issue + eski revoke) | Tek meta-Exercise ise tek tx; iki Exercise ise her biri kendi yetkisiyle geçerlidir ve ara durum authority içi kalır | INV-4 |
| `projection.issue` + offline slice draw | DecisionRecord + sayaçlar + `artifacts[]` digest'leri | P27, PI-20 |
| Quorum contribution'larının hedef exercise'ta tüketimi | Hedef ALLOW'un DecisionRecord'u + contribution single-use bayrakları | INV-20 |
| Inline Claim proof + karar | Claim record(lar)ı + DecisionRecord aynı batch'te, Claim'ler önce | Commit yolu adım 7 |

**Kural (TI-7):** Bir DecisionRecord'un bütün effect'leri ya birlikte görünür ya hiç; bir batch ya bütünüyle commit edilir ya hiçbiri. Batch'leme bir **performans** aracıdır, semantik atomiklik değil. Cross-product veya cross-domain atomiklik **yoktur** (E29, EI-23).

| # | Senaryo | Ne olur | Neden ikinci consumption yok |
|---|---|---|---|
| OP-S1 | Aynı budget'tan iki eşzamanlı commit, toplam > kalan | İkinci `budget@` key'inin version'ı değişmiş bulunur → head'de yeniden değerlendirilir → DENY `budget-exhausted` | Validation serial (adım 9) |
| OP-S2 | Client timeout, aynı nonce ile retry; ilk istek commit olmuştu | Aynı DecisionRecord döner | `(domain, nonce)` unique (TI-8) |
| OP-S3 | Client timeout; ilk istek commit OLMAMIŞTI | Yeniden değerlendirme | Önceki deneme hiçbir şey yazmadı (TI-7) |
| OP-S4 | Leader tx commit'ten sonra, ack'ten önce çöker | Yeni leader log'dan kurar; retry nonce'u bulur | Kayıt durable; nonce unique |
| OP-S5 | Leader tx commit'ten önce çöker | Retry yeniden değerlendirilir | Atomik tx |
| OP-S6 | Ağ bölünmesi: eski leader lease'inin bittiğini bilmiyor | Eski leader'ın batch'i `epoch = e` CAS'ında başarısız → step-down; hiçbir ack | Safety DB CAS'tan gelir, saatten değil (TI-2) |
| OP-S7 | DB primary failover (aynı cluster, sync standby promote) | Ack edilmiş her tx standby'dadır (FA-1); ack edilmemişler kaybolabilir → retry (OP-S3/OP-S5) | Sync quorum replication |
| OP-S8 | Aynı nonce, farklı intent digest | Protocol hatası | Commit yolu adım 6 |
| OP-S9 | Offline slice + online kullanım aynı budget'tan | Slice `projection.issue` commit'inde önceden draw edildi | PI-20, G3 |
| OP-S10 | Forced recovery sonrası eski provider'ın C_N ötesi draw'ları | Devam eden lineage'da authoritative değil; R4 ile daraltılır | Merkezde at-most-once yeni lineage için korunur; kayıp suffix'teki effect'ler NG (N-25 sınıfı) |
| OP-S11 | İki farklı domain'de home/target | Home'da tek draw; target yalnız ek daraltma | PI-24 |
| OP-S12 | Cross-cell / cross-region failover; hedefte async kopya geride | Async kopya promote edilmez. Planlıda HANDOFF/ACCEPTANCE; plansızda yalnız kanıtlı fence + eski son head kapsamı; aksi fail-closed, yol `domain.recover` | FA-13; pozisyon yeniden kullanılmaz (EI-20, SEC22) |

#### 17.1.2 OP-9 Group commit zorunludur

| Alan | Değer |
|---|---|
| Karar | Sequencer, birden çok bağımsız commit'i tek DB transaction'ında birleştirir (batch) ve tek WAL flush + tek sync-quorum turu ile commit eder. ≥ 2.000 commit/s/domain EA hedefi (OP-32) için bu zorunludur. Batch boyutu ve en uzun bekleme süresi PD'dir; ölçümle ayarlanır |
| Statü | FROZEN TECHNICAL (zorunluluk), EA (sayılar) |
| Garanti | Batch'leme semantiği değiştirmez: her commit kendi validation'ından geçer (PI-23, TI-7), BS |
| Gerekçe | Batch'siz AZ-sync yazma tavanı kabaca 0,5–1k tx/s civarındadır (**hesap, ölçüm değil**). Sync replikasyonun maliyeti yük arttıkça düşer, çünkü WAL flush'ları gruplanır (EDB kaynağı). Crosby–Wallach tipi batch, denetim log'unda imza payını da düşürür. Hash zinciri ve Merkle sequencer belleğinde batch içinde hesaplanır; satır içi serileşme olmaz |
| Kaynak | T7; commit yolu adım 11 (BATCH TX) |

#### 17.1.3 OP-10 Identity plane yazma yolu ve atomik denetim outbox'ı

| Alan | Değer |
|---|---|
| Karar | Identity plane'de tek yazar realm'in hücresindeki PG primary'sidir. Uygulama süreçleri durumsuzdur. Uçucu durum (kimlik doğrulama oturumu, authorization code, refresh ailesi, kaba kuvvet sayacı, PAR `request_uri`) DB'dedir. Her güvenlik-anlamlı iş değişikliği, kendi denetim olayının **minimal outbox satırını** aynı transaction'da yazar (olay türü, aktör, hedef, zaman, korelasyon). Zenginleştirme, imza ve dışa yayın sonra gelir (CMP-27) |
| Statü | FROZEN TECHNICAL |
| Garanti | "Kabul edilen bir güvenlik değişikliğinin denetim olayı kaybolmaz": sync-quorum commit altında UDC (OP-24). Outbox'ın tüketilip dışarı çıkması NG (teslim) |
| Gerekçe | Denetimin işten ayrı yazılması "değişiklik oldu, denetim yok" penceresi açar. Bu, authority plane'deki records ∪ outbox atomikliğinin (T7) identity plane karşılığıdır |

#### 17.1.4 Depo envanteri ve etiketler

Etiket ayrımı (CANONICAL / SYNC-DERIVED / DERIVED / PROJECTION / OPERATIONAL) §16.3 ve TI-16'dadır. Fiziksel depo tablosu identity plane satırlarını da içerir:

| Depo | İçerik | Etiket | Fiziksel yer | Yeniden kurulabilir mi |
|---|---|---|---|---|
| **Domain log** | Domain başına sıralı kayıt zarfları (Genesis, Exercise opening, DecisionRecord, Claim); her biri pozisyon, recordedAt, header alanları + salt'ları, body commitment'ları, proof commitment'ları, `prev` hash, leaf hash | **CANONICAL** | Canonical PostgreSQL cluster (cell başına) | Hayır — kaynak budur |
| **Body store** | Redakte edilebilir body'ler, her biri kendi DEK'i ve salt'ı ile şifreli; content-addressed | **CANONICAL** (redaksiyon INV-30'a tabi) | Aynı cluster (küçük) + S3-uyumlu şifreli object storage (büyük) | Hayır |
| **Proof store** | Zarfın dışındaki imzalı proof bayt'ları (AIS, AAS, WebAuthn assertion) AYNEN; leaf'e yalnız `proof_commit` digest'iyle bağlı | **CANONICAL** (SI-1; digest'i süresiz, G23) | Aynı cluster | Hayır |
| **Raw carrier evidence** | Ingest edilen Claim'in orijinal imzalı bayt'ları — minimize açıklama ile | **CANONICAL** | Body store | Hayır |
| **Sync-derived state** | Nonce tablosu, version key'leri, budget sayaçları, single-use bayrakları, episode tablosu, rolling aggregate'ler, güncel authority-state satırları, per-verifier contract/report durumu (SEC14), issuer kota sayaçları | **SYNC-DERIVED** | Canonical cluster, log ile aynı tx | Evet — log replay |
| **Outbox** (authority) | Commit edilmiş kayıtlardan türeyen event zarfları; imleç (domain, pos) | SYNC-DERIVED (teslim kuyruğu) | Canonical cluster | Evet |
| **Derived store** | Graph index, search (FTS), eligible set, impact, compromise impact, status list girdisi (`applied_pos`'lu), offline reconciliation görünümü, explain cache | **DERIVED** | Derived PostgreSQL cluster | Evet |
| **Checkpoint/witness arşivi** | Checkpoint'ler, witness cosign'ları, gossip gözlemleri | CANONICAL (log'a ingest edilen kısım) / DERIVED (karşılaştırma) | Canonical + derived | Kısmen |
| **Replica** | Domain log'unun CBOR sequence kopyası + checkpoint'ler | **PROJECTION** | Domain-controlled object storage veya archival witness | Kaynaktan |
| **Identity store** | Realm'ler, kullanıcı/credential, authenticator ve ceremony kayıtları, issue edilen Claim'ler, regime key-event history, oturum ve uçucu auth durumu, refresh aileleri, kaba kuvvet sayaçları, client'lar | **CANONICAL (identity plane kapsamı)** | Ayrı cluster, ayrı KMS | Hayır |
| **Identity outbox** | Minimal denetim satırları, epoch değişimleri, CAEP/SSF olay kaynakları | SYNC-DERIVED (aynı tx) | Identity cluster | Evet (iş tablolarından değil, kendi satırlarından; silinmeden önce tüketilir) |
| **Identity denetim log'u** | Zenginleştirilmiş olaylar, periyodik Merkle checkpoint'leri | CANONICAL (identity) + PROJECTION (export) | Identity cluster (sıcak) + S3 Parquet (soğuk, OP-40) | Hayır (sıcak), kaynaktan (soğuk) |
| **PII vault** | Party/kullanıcı başına DEK ile alan şifrelemesi | CANONICAL (identity) | Identity cluster + KMS | Hayır |
| **İmza anahtar deposu** | Authority operasyonel anahtarları; realm JOSE anahtarları | OPERATIONAL (anahtar materyali) | HSM/KMS (CMP-13); DB dışında, bağımsız yedekli (OP-58) | Hayır |
| **Hub cache** | Party başına bilinen domain'ler ve viewer-scoped okuma snapshot'ları | **DERIVED** | Client-local veya Experience backend (şifreli) | Evet |
| **Telemetri / analytics** | Metrik, trace, log; envelope-level analitik | **OPERATIONAL** / ClickHouse analitik **DERIVED** (OP-47) | OTel pipeline, ClickHouse | Önemsiz |
| **Placement directory** (CMP-26) | DomainID / realm / tenant → cell | **OPERATIONAL** | Global, küçük, replike | Evet |

Claim corpus ayrı bir veritabanı değildir: Claim record'ları aynı domain log'unda, aynı total order'da durur. Bunun nedeni şudur: HoldingRef `since` bir ingest pozisyonudur, ingest-time cutoff ingest zamanına göre işler ve StateBasis Claim'leri pozisyonla cite eder. Identity store, authority deposuyla hiçbir tablo, DB rolü, KMS anahtarı veya operatör rolü paylaşmaz (SEC19, TI-15).

---

### 17.2 Veri şeması ve PostgreSQL kuralları

#### 17.2.1 OP-11 Birincil anahtarlar ve dış kimlikler

| Alan | Değer |
|---|---|
| Karar | (a) Authority log'unda fiziksel PK `(domain_id, pos)`'tur. Kayıt kimliği = commitment (leaf hash) ikincil `UNIQUE`'tir (TI-RT11). (b) Identity plane ve authority sync-derived/derived tablolarında iç kimlik **UUIDv7**'dir (PG18 `uuidv7()`). PK, kapsam sütunuyla bileşiktir (OP-12). (c) Dışarıya verilen kimlikler opaktır: zaman veya sıra bilgisi sızdırmaz. Authority plane'de HMAC/opaque token (TI-RT10, RT21), identity plane'de UUIDv7'nin dışarıya açılmadığı opak tanımlayıcılar kullanılır (`sub` pairwise veya opak; `client_id` üretilir, §10) |
| Statü | FROZEN TECHNICAL |
| Garanti | Dış kimlikten zaman ve sıra çıkarılamaması BS (TI-RT10); iç sıralama özelliği garanti değil, performans |
| Gerekçe | UUIDv7, v4'e göre insert'te 1,67× hızlı, PK indeksi %26 küçük (M4 ortamı). v4 (`gen_random_uuid()`) yerine v7 seçilir (MD-18). v7 oluşturma zamanını sızdırır, bu yüzden dışarıya açılmaz |
| Kaynak | MD-18 |

#### 17.2.2 OP-12 Kiracılık izolasyonu: bileşik anahtar, RLS FORCE, tipte kapsam

| Alan | Değer |
|---|---|
| Karar | 1. Her tabloda kapsam sütunları PK'nin önekidir: authority tablolarında `domain_id`; identity tablolarında `tenant_id` + `realm_id`; ticari tablolarda `tenant_id` (MD-5). Bu, MD-5'in daraltılmış PK kuralıdır: `tenant_id` + RLS FORCE identity plane, derived, PII vault ve operasyon tablolarında zorunludur; authority canonical log ve kayıtları (ve aynı tx'teki SYNC-DERIVED tablolar; çıkarım) `domain_id` ile anahtarlanır. Domain tek tenant'a aittir; tenant ↔ domain eşlemesi placement directory'de (CMP-26) ve ticari tablolarda tutulur ve değişebilir. Gerekçe: append-only log (OP-17) ticari hesap değişince yeniden anahtarlanamaz. 2. Kapsam taşıyan her FK bileşiktir: `(tenant_id, realm_id, x_id)` → `(tenant_id, realm_id, id)`; authority'de `(domain_id, …)`. Böylece çapraz kiracı/domain referansı şema düzeyinde kurulamaz. 3. Her `UNIQUE` kısıt kapsam önekli olur. Örnek: `UNIQUE(realm_id, lower(email))`, global `UNIQUE(email)` değil. E-posta hiçbir zaman anahtar değildir (MD-5). Gerekçe: önceksiz `UNIQUE`, RLS'i atlatan bir varlık kanalıdır. 4. RLS **`ENABLE` + `FORCE`**; politikalar `AS RESTRICTIVE`; koşul tek indeksli eşitliktir (`tenant_id = current_setting('app.tenant_id', true)::uuid` vb.). Ayar yoksa `current_setting(…, true)` NULL döner ve eşitlik hiçbir satırı geçirmez (fail-closed). Alt sorgu/`EXISTS` içeren politika yazılmaz. 5. Uygulama rolleri `NOBYPASSRLS`'tir ve tablo sahibi değildir. Tablo sahibi ayrı bir göç rolüdür (OP-55). Superuser uygulama yolunda kullanılmaz. 6. Kapsam bağlamı yalnız transaction içinde `SET LOCAL` / `set_config(…, true)` ile kurulur (OP-18). 7. `access-store` kapsamsız sorgu tipini derlemez (OP-3) |
| Statü | FROZEN (MD-5) |
| Garanti | RLS ve bileşik FK **ikincil katmandır**. Birincil sınır uygulama ve tip düzeyindeki kapsam ile domain'in ayrı KEK'idir. Bir kapsam hatasının çapraz kiracı okumaya dönüşmemesi UNDER DECLARED CAPABILITY/POLICY'dir (RLS'in doğru yapılandırılması ve uygulama rolünün `NOBYPASSRLS` olması). Superuser/`BYPASSRLS`/sahip rolü bu katmanı atlatır: NG (HL-33). Authority plane'de karar doğruluğu RLS'e dayanmaz (INV-29, T27) |
| Maliyet | RLS tek indeksli eşitlikle yaklaşık %4,4 ek maliyet; `EXISTS` tabanlı politika yaklaşık %18,6 (M4 ortamı) |
| Reddedilen | Şema-per-tenant ve DB-per-tenant: 1.200 şemada katalog taraması 383 ms, 20k şemalık `pg_dump` 24 saati aşar (doğrulanmadı). Büyük müşteri için yol dedicated cell'dir (OP-54) |
| Kaynak | MD-5 |

RLS ile ilgili yayımlanmış CVE'ler gerekçe kanıtıdır. Numaraları doğrulanmadı (§17.15).

#### 17.2.3 OP-13 Partitioning

| Alan | Değer |
|---|---|
| Karar | (a) Authority domain log'u `(domain_id, pos)` aralığına göre bölümlenir; zamana göre bölümlenmez. Header'lar süresizdir (INV-30), `DROP PARTITION` ile silme yolu yoktur. Body tablosu redaksiyon için DEK silmeye dayanır, bölüm silmeye değil. (b) Identity denetim log'u ve yüksek hacimli olay tabloları (oturum geçmişi, DPoP `jti` tablosu) zamana göre bölümlenir. Saklama süresi dolunca bölüm önce `DETACH PARTITION … CONCURRENTLY` ile ayrılır, soğuk katmana aktarılır, sonra düşürülür (OP-40). (c) Bölüm sayısı lock budget'ı içinde tutulur. PG18 fast-path kilit düzeltmesi gerekçedir (OP-7) |
| Statü | PD (bölüm boyutları) |
| Garanti | Performans ve saklama mekanizmasıdır; güvenlik garantisi taşımaz |

#### 17.2.4 OP-14 Sıcak satırlar

- Sık güncellenen sayaç sütunları (SYNC-DERIVED budget, `released@`, kaba kuvvet `tat`) **indekslenmez**, böylece HOT update korunur. Bu tablolar düşük `fillfactor` ile (başlangıç 70, PD) oluşturulur.
- `last_seen`, `last_used_at` gibi gözlem sütunları 10–30 s aralıkla batch'lenerek yazılır. OPERATIONAL'dır, karar girdisi değildir.
- **SYNC-DERIVED sayaçlar batch'lenmez ve geciktirilmez.** Commit transaction'ında yazılırlar (TI-7). Gözlem sütunu kuralı onlara uygulanamaz.
- Statü: FROZEN TECHNICAL (kural), PD (değerler). Garanti: performans; SYNC-DERIVED kuralı BS (T9).

#### 17.2.5 OP-15 İndeks kuralları

- Büyük/küçük harf duyarsız login tanımlayıcısı: `lower(identifier)` fonksiyonel indeksi realm önekiyle, `UNIQUE(realm_id, lower(identifier))` (MD-5).
- Sıcak okuma yollarında covering indeks (`INCLUDE`) kullanılır.
- Her indeks kapsam sütunuyla başlar (OP-12).
- Statü: PD.

#### 17.2.6 OP-16 UNLOGGED tablolar

- `UNLOGGED` tablo CANONICAL, SYNC-DERIVED ve identity CANONICAL veri için **kesinlikle yasaktır**. Bu veriler çökme sonrası kesilir ve replike edilmez.
- Yalnız atılabilir OPERATIONAL veri için serbesttir.
- Kaba kuvvet ve OTP sayaçları (Katman B, OP-35) **logged** tablodadır, çünkü kayıpları kilidi sıfırlar. Katman A (IP/endpoint) sayaçları süreç içi bellektedir (governor) ve DB'ye yazılmaz.
- Statü: FROZEN TECHNICAL. Garanti: UDC (göç incelemesi + şema testi).

#### 17.2.7 OP-17 DB'de append-only savunması

| Alan | Değer |
|---|---|
| Karar | Domain log, proof store ve identity denetim log tabloları üç katmanla append-only tutulur: (1) **GRANT:** uygulama rolüne yalnız `INSERT, SELECT` verilir; `UPDATE/DELETE/TRUNCATE` verilmez. Authority log'a yalnız sequencer rolü yazar; sequencer dışındaki DB rolleri yalnız okur (CMP-5). (2) **Satır trigger'ı:** `BEFORE UPDATE OR DELETE` hata fırlatır. (3) **Statement trigger'ı:** `BEFORE TRUNCATE` hata fırlatır. `pgaudit` ikincil iz olarak açılır. Redaksiyon body store'da DEK ve body silme yoluyla yapılır, header satırına dokunmaz (T39) |
| Statü | FROZEN TECHNICAL |
| Garanti | DB içi önleme UDC'dir (rol ayrımı, superuser'ın uygulama yolunda olmaması). Superuser değişikliği önlenemez (HL-33). Log içeriğinin değişmesinin **tespiti** zincir, Merkle, witness ve replica ile BS'dir (G34). Identity log'unda tespit Merkle checkpoint'i yayınlandıktan sonra geçerlidir |
| Kaynak | CMP-5 |

#### 17.2.8 OP-18 Bağlantı havuzu ve `SET LOCAL`

- Havuz modu transaction-mode'dur (uygulama içi havuz veya pgcat/PgBouncer). Session düzeyinde `SET` **yasaktır**, çünkü havuzlanan bağlantıda bir sonraki isteğe sızar ve RLS'i yanlış kapsamla çalıştırır. Kapsam bağlamı yalnız `SET LOCAL` / `set_config(…, true)` ile kurulur.
- PgBouncer kullanılırsa sürüm ≥ 1.21 olmalıdır (isimli prepared statement desteği). Bu desteğin Access sürücüsüyle çalıştığı doğrulanmadı. Doğrulanana kadar sıcak yolda uygulama içi havuz kullanılır.
- `LISTEN/NOTIFY` her iki plane'de yasaktır (OP-19).
- Statü: FROZEN TECHNICAL (SET LOCAL kuralı), PD (araç).

---

#### 17.2.9 OP-66 Veri katmanı kod kuralları

**Statü: FROZEN TECHNICAL (ORM yok, SQL yalnız `store`'da, şema güvenlik testleri, gerçek Postgres ile test, üretim verisi yasağı); PD (araç ayrıntıları). Garanti: UDC.** OP-11–OP-18 ve OP-55 aynen geçerlidir.

1. **SQL yazımı.** ORM kullanılmaz. Sorgular derleme zamanında şemaya karşı denetlenen düz SQL'dir (`sqlx::query!`); sorgu meta verisi depoya commitlenir (offline mod), CI veritabanı olmadan derler. Gerekçe: RLS, `SET LOCAL`, bileşik anahtarlar ve append-only tablolar SQL'in tam kontrolünü ister.
2. **SQL'in yeri.** SQL yalnız `store` crate'indedir; iş mantığı veritabanını yalnız portlar üzerinden görür (OP-63). Başka crate'te SQL bulunması CI'da reddedilir.
3. **Göç dosyaları.** Zaman damgalı ve açıklayıcı ad (ör. `20261008120000_add_grant_index.sql`). Commitlenmiş göç değiştirilmez; düzeltme yeni göçtür. Her göç PR'ında kontrol listesi: genişletme mi daraltma mı (OP-55), kilit süresi, büyük tabloya etkisi, yeni tabloda RLS ve kapsam sütunları.
4. **Şema güvenlik testleri (CI).** Her tabloda RLS açık ve FORCE; kapsam sütunu (`domain_id` veya `tenant_id` + `realm_id`) PK önekinde (OP-12); append-only tablolarda UPDATE/DELETE yetkisi kapalı (OP-17); uygulama rolü tablo sahibi değil (OP-55). İhlal birleştirmeyi durdurur.
5. **Test verisi.** Testler gerçek PostgreSQL ile çalışır (testcontainers); taklit veritabanı kullanılmaz. Şema bir kez kurulur, her test template veritabanından kendi temiz kopyasını alır; testler paralel ve bağımsızdır. Test verisi kodla üretilir (builder/factory). Yerel geliştirme sentetik tohum verisiyle yapılır; gerçek müşteri verisi test veya geliştirme ortamına girmez.
6. **Küçük kurallar.** Durum alanları Postgres `ENUM` değil, `CHECK` kısıtlı `text`'tir (expand/contract uyumu). JSONB yalnız gerçekten şemasız veri içindir; sorgulanan veya kısıt gereken alan normal sütundur. Sık çalışan sorguların planı CI'da `EXPLAIN` ile denetlenir (OP-15).

### 17.3 Olay dağıtımı ve iptal yayılımı

#### 17.3.1 Authority plane olayları

Olay dağıtım tablosu normatiftir:

| Adım | Karar | Dayanak |
|---|---|---|
| Üretim | Event'ler commit tx'inde **outbox**'a yazılır; içerik commit edilmiş kayıtlardan deterministik türetilir. Event id domain başına anahtarlı HMAC'tir (TI-RT10, T26) → doğal dedup | E30, PI-9 |
| Durability fence | Hiçbir event, imza, artefakt veya dış istek, kaydı durable commit edilmeden çıkmaz | TI-6 |
| Backbone | Outbox relay → **NATS JetStream** (iç doorbell; az sayıda bölümlü stream; domain başına stream yok). NATS kaybı yalnız gecikmedir; kaynak outbox tablosu ve log'dur | T26 |
| SSF transmitter | SET'leri operasyonel anahtarla imzalar (CMP-22a); push (RFC 8935) / poll (RFC 8936); receiver başına stream; disclosure scope receiver'ın yetkisi kadar | P33 |
| Sıra | Garanti yok; her event `basis` pozisyonu taşır; receiver karşılaştırır ve re-query yapar | — |
| SI-21 | "Expansion about you" event'leri derived üretimde zorunlu event türleridir; teslim NG | SI-21 |
| Relay entegrasyonu | Relay SSF receiver veya webhook alıcısıdır; delivery ack Access'e gelmez, gelirse yalnız telemetri; authority-state ack ayrı bir Claim'dir | E30, EI-9 |
| Event ≠ commit | Event'in varlığı, sırası veya kaybı hiçbir commit'i, kararı veya status'u değiştirmez; status list ve re-query safety kanalıdır | PI-9, INV-24 |
| Realtime UI | SSE/WebSocket gateway NATS'tan beslenir; client sinyal alınca `at_least` ile yeniden okur (XI-3). Güvenlik yükü taşımaz | XI-3 |

#### 17.3.2 OP-19 Yasaklı taşıyıcılar

| Yasak | Kapsam | Gerekçe |
|---|---|---|
| PostgreSQL `LISTEN/NOTIFY` | Her iki plane | Transaction-mode havuzla çalışmaz; bildirim kuyruğu dolarsa `NOTIFY` yapan commit hata alır. Bu, yazma yolunun kullanılabilirliğini dış bir kuyruğa bağlar |
| Redis pub/sub (veya at-most-once bir kanal) iptal taşıyıcısı olarak | Her iki plane | At-most-once teslim; kaçırılan mesaj kalıcı olarak kaybolur |
| Redis/Infinispan doğruluk kaynağı olarak | Her iki plane | — |
| Bloom/cuckoo filtresi tabanlı iptal listesi | Identity plane | Epoch aynı işi hatasız yapar |

Statü: FROZEN TECHNICAL. Garanti: güvenlik hiçbir taşıyıcının teslimatına dayanmaz (FA-12, INV-24): BS.

#### 17.3.3 OP-20 Identity plane outbox'ı

| Alan | Değer |
|---|---|
| Karar | Identity plane olayları (epoch değişimi, denetim satırı, CAEP olay kaynağı) OP-10'daki aynı-tx outbox satırına yazılır. Tüketiciler polling ile okur (varsayılan aralık 100 ms, PD). `NOTIFY` hızlandırması kullanılmaz. **Kısıt:** `bigserial`/sequence imleci tek başına güvenli değildir. Sequence değerleri commit sırasıyla görünür olmaz; daha küçük numaralı uzun bir transaction daha sonra commit edilirse, imleci geçmiş bir tüketici o satırı hiç görmez (gap tuzağı). **Teslim algoritması açıktır: OQ-MD3** (xid8 watermark ↔ logical decoding) |
| Değişmez | Hangi algoritma seçilirse seçilsin, **tüketici ilerlemesi ile yeniden kurulabilir durum arasında boşluk olmaz** (OPI-1). Algoritma 6 senaryoluk testi (uzun tx, failover, replica slot kaybı vb.) geçmeden seçilmez |
| Authority plane | Etkilenmez. İmleç `(domain_id, pos)`'tur, çünkü sequencer pozisyonu boşluksuz ve commit sırasıyla aynıdır (T26). Cell genelinde `bigserial` imleç kullanılmaz |
| Statü | FROZEN (değişmez ve kısıt), açık (algoritma, OQ-MD3) |
| Garanti | Olay kaybı yokluğu, OQ-MD3 kapanana kadar **iddia edilmez**. Güvenlik olaya dayanmadığı için (cache-miss DB'ye sorar, OPI-3) bir kayıp yalnız gecikmedir: UDC |

#### 17.3.4 OP-21 Identity plane iptal yayılımı: `session_epoch` ve node cache

| Alan | Değer |
|---|---|
| Karar | Identity plane oturum ve token'larının hızlı iptali için Instance/Party başına monoton `session_epoch` sayacı tutulur. Token `rev` claim'i taşır; doğrulama sayaç üzerinden yapılır, zaman damgası yalnız gözlemlenebilirlik içindir. Üç katman vardır: (1) node-yerel epoch cache (pozitif değerler); (2) outbox polling ile güncelleme (100–250 ms); (3) PG primary doğruluk kaynağıdır. **Cache-miss her durumda primary'ye sorar; primary'ye ulaşılamazsa istek reddedilir.** Önbellekte olmayan kullanıcı için "epoch = 0" varsayılmaz (OPI-3; MD-7 "Cache bu kullanıcıyı hiç görmedi durumu fail-closed'dur"). Node başlarken son pencerenin iptal kümesini tek sorguyla yükler, sonra outbox'a takılır |
| Düzlem sınırı | `session_epoch` yalnız identity plane oturum/token'larını iptal eder. Bir authority kararını geçersiz kılmaz. Yalnız sonraki kararın `authentication` Claim girdisini değiştirir (TI-15). `authz_epoch` authority plane'de yoktur. Yerini AuthorityStateBasis ve `applied_pos` alır. `key_epoch` anahtar penceresidir (MD-7). Authority artefaktlarının iptali ValidityContract + status list + witness-before-ack ile yapılır (§13.3) |
| Statü | FROZEN (MD-7) |
| Garanti | Access'in kendi yüzeylerinde (login, refresh, introspection) cache-hit ile iptal yayılımı polling aralığıyla sınırlıdır: UDC (polling'in çalışması; primary erişilebilirken — primary'ye ulaşılamıyorsa introspection `active=false`, OP-45). Cache-miss doğruluğu BS (OPI-3). Introspection yapmayan RS: token ömrü (HL-22), NG |
| Gecikme bütçesi | OP-32 tablosu (EA) |
| Kaynak | MD-7 |

#### 17.3.5 OP-22 Olay kimliği ve sıralama

- Authority event'lerinin sıra garantisi yoktur. Her event `basis` pozisyonu (viewer'a göre opak) ve monoton bir sürüm alanı taşır. Alıcı kuralı şudur: "olay yetki değildir; kayıp yetkiyi genişletemez; şüphede yeniden sorgula" (§9 SSF alıcı kuralları).
- SSF'nin per-subject sıralamasına güvenen alıcı tasarımı önerilmez. Alıcı monoton sürüm alanını karşılaştırır.
- Identity plane CAEP olayları aynı kuralı izler.
- Statü: FROZEN. Garanti: BS (event safety kanalı değildir, INV-24).

#### 17.3.6 OP-23 NATS'in rolü ve self-host

- NATS JetStream yalnız doorbell'dir. Kaybı gecikmedir; polling her zaman çalışır ve yedektir.
- Küçük self-host formunda (OP-48) NATS **opsiyoneldir**. Relay ve SSF transmitter doğrudan outbox polling ile çalışır.
- Statü: FROZEN. Garanti: BS (event safety değil).
- Reconsider: receiver hacmi NATS stream modelini aşarsa Kafka bölümlemesine geçilir; o durumda da derived kalır (T26, §17.11).

---

### 17.4 HA, failover, çok bölge ve veri yerleşimi

Authority plane'in HA kuralları §16.2 (FA-1, FA-2, FA-3, FA-13), §16.6 (HO/FR) ve T8, T28'dedir ve değişmez. Topoloji ve failure modları aşağıda normatiftir. Identity plane kuralları OP-24–OP-30'dadır.

#### 17.4.1 Topoloji

- **Cell:** bir bölgede, ≥ 3 availability zone'a yayılmış Kubernetes cluster + canonical PostgreSQL (primary + sync quorum standby'ler farklı AZ'lerde; **≥ 2 sync standby**, OP-24) + derived cluster + NATS (opsiyonel self-host'ta, OP-23) + HSM erişimi. Domain'ler cell'lere yerleşir (CMP-26, OPERATIONAL).
- **Bölge ve residency:** Domain'in residency beyanı (Genesis'te veya provider sözleşmesinde) cell bölgesini belirler. **Active-active canonical yazma yoktur:** bir domain'in aynı anda tek yetkili cell/epoch'u vardır.
- **DR:** İki sınıf (residency'ye göre beyan edilir): (a) **regional** — yalnız AZ-seviyesi dayanıklılık; cross-region async kopya tutulabilir ama yalnız yedek/arşivdir ve **promote edilerek lineage'a devam edilmez**; (b) **multi-region sync** — cross-region sync WAL quorum (RPO = 0, commit latency artar); tek linearizable depo olduğundan bölge failover'ı bu depo içinde standby promote + epoch CAS'tır. Her iki sınıfta revocation/CT3 ack'leri ek olarak provider dışında witness (kök) ve replica (önek) ile korunur (SEC23).
- **Cell / bölge değişimi (HANDOFF/ACCEPTANCE + epoch CAS).** İki ayrı cluster'daki iki `domain_head` satırı arasında CAS yoktur (FA-2); bu yüzden:
  1. **Planlı:** kaynak cell'de head epoch e ile **mühürlenir** (CAS ile `sealed_at = q`; sonraki her append reddedilir) → hedef cell kaynağın log'unu q'ya kadar alır, replay ile doğrular, aynı kökü üretir ve kendi `domain_head`'ini (q, e+1) ile **kabul eder** → placement ancak bundan sonra değişir. Pozisyon asla yeniden kullanılmaz.
  2. **Plansız (bölge kaybı, kontrol düzlemi bölünmesi):** aynı lineage'da devam ancak (i) eski cell'in canonical deposu **kanıtlanmış biçimde fenced** ise (kaynak mühürü okunabiliyor veya kapsam dışı STONITH) **ve** (ii) eski deponun son commit'li head'i (pos, leaf hash) biliniyor ve devam log'u onu — dolayısıyla en az en yüksek witness'lı checkpoint'i — tam kapsıyor, kökü yeniden üretiliyorsa mümkündür. (i) veya (ii) sağlanamıyorsa **promote yok**: domain fail-closed durur ve yol root'un `domain.recover`'ıdır (SEC21–SEC22). Otomasyonun varsayılanı promote etmemektir (FA-13).
  3. Sonuç: hiçbir failover, DR restore veya cell taşıması aynı domain için ikinci yazar, pozisyon yeniden kullanımı veya root Exercise'ı dışında lineage değişikliği üretemez (INV-21, EI-20, SEC22, U10). Aynı lineage'da devam eden dürüst failover witness'ta çatallanma üretmez. Bu iddia `domain.recover` kol (ii) / çatallanma için geçerli değildir: orada witness beyanlı bir **recovery re-anchor** yapar (§16.6 FR, U24).

#### 17.4.2 Failure modları

| Arıza | Davranış | Guarantee |
|---|---|---|
| Leader process çökmesi | Lease süresi sonunda yeni leader; ara süre commit yok (fail closed); retry'ler idempotent. Planlı kapanışta graceful step-down (OP-31) | BY SEMANTICS (yanlış ALLOW yok); availability UDC |
| AZ kaybı | Sync standby promote (aynı cluster, aynı `domain_head` satırı); ack edilmiş tx'ler korunur (FA-1) | UDC |
| Bölge kaybı (regional sınıf) | Async kopya **promote edilmez**. Fence kanıtı + eski son head kapsamı varsa aynı lineage'da devam; aksi domain fail-closed, yol `domain.recover` (N = R\*) | UDC (FA-13, U10); availability kaybı ve beyanlı kayıp suffix NG (N-14) |
| Bölge kaybı (multi-region sync sınıfı) | Tek linearizable depo içinde standby promote + epoch CAS; RPO = 0 | UDC |
| Ağ bölünmesi (cell içi) | Azınlık tarafı commit edemez (DB quorum + epoch) | BY SEMANTICS (çift yazar yok) |
| Kontrol düzlemi bölünmesi (cell'ler arası) | Fence kanıtı yoksa promote yok | UDC (FA-13) |
| HSM erişilemez | Kayıtlar commit olur, artefakt imzası gecikir; checkpoint gecikir → witness-before-ack ack'leri bekler | Fail closed |
| Witness'ların tümü erişilemez | Revocation/CT3 ack'leri bekler; diğer commit'ler sürer | UDC |
| NATS kesintisi | Event gecikmesi; outbox birikir; polling sürer | BY SEMANTICS (event safety değil) |
| Derived cluster kesintisi | `check`/search/explain/hub UNKNOWN veya eski `as_of`; status list yayıncısı eski içeriği taze `iat` ile imzalamaz; introspection `at_least` bütçesi aşılınca `active=false`; commit etkilenmez | BY SEMANTICS |
| Saat sapması > beyan | Leader kendini sağlıksız işaretler | Fail closed |
| Provider tamamen yok | `domain.recover`; replica'sız / geride replica'da kol (ii) | UDC (FA-10, U24); replica'sız kayıpsızlık NG (N-14) |
| **Identity PG primary failover** | 503 + `Retry-After`, asla `invalid_grant` (OP-26) | Ack edilmiş yazma korunur UDC; kesinti NG |
| **Identity bölge kaybı** | Hücre modelinde yalnız o hücre etkilenir; async DR profilinde beyanlı RPO>0 promote + toptan epoch artırımı (OP-29) | HL-31 |
| **Identity DB tamamen erişilemez** | Bozulmuş mod (OP-45) | §16.7.1 |

#### 17.4.3 OP-24 Senkron replikasyon ayarı

| Alan | Değer |
|---|---|
| Karar | Her iki plane'in canonical cluster'ında (small-provider profili hariç; OP-48 beyanlı profil, HL-40) `synchronous_commit = on` ve `synchronous_standby_names = 'ANY 1 (sb_a, sb_b)'`, farklı AZ'lerde **en az iki sync standby** bulunur. Tek standby ile `on` yasaktır: o standby düşerse primary bütün yazmalarda asılır. `remote_apply` yalnız oturum düzeyinde, replikadan okumanın kaçınılmaz olduğu dar yollarda kullanılabilir. Varsayılan yol buna ihtiyaç duymaz, çünkü güvenlik okumaları primary'dendir (OP-27) |
| `local` kullanımı | **Authority kayıtları ve identity plane güvenlik olayları** (login sonucu, parola/MFA değişimi, iptal, kilit, yetki ve rol değişimi, refresh rotasyonu, kaba kuvvet sayacı) **`on`** ile yazılır. Yalnız OPERATIONAL telemetri ayrı bağlantıda `local` olabilir. Denetim yazmalarının ve güvenlik sayaçlarının `local` ile yazılması **reddedilir** |
| Statü | FROZEN TECHNICAL |
| Garanti | Ack edilmiş yazmanın AZ kaybında korunması: UDC (FA-1; dürüst fsync, ≥2 standby, orkestratör fencing'i) |
| Gerekçe | Failover'da kaybolabilecek bir denetim kaydı denetim garantisi taşıyamaz. Sayaç kaybı kilidi sıfırlar, refresh rotasyon kaybı reuse tespitini kırar. Sync maliyeti yük arttıkça düşer: 3 ms gecikmede 120+ istemcide `local` ile %1 içinde (EDB, üçüncü taraf ölçümü) |
| Kaynak | FA-1, T8, §17.4.1 |

#### 17.4.4 OP-25 Failover orkestratörü ve fence şartı

- Cell içi PG HA, CloudNativePG (CNPG) veya Patroni ile yapılır. Seçim PD'dir. Kubernetes'te CNPG varsayılandır, K8s dışı self-host'ta Patroni (DCS failsafe modu açık; etcd kaybı salt okunurluğa düşürür, tam kesintiye değil).
- Etcd/DCS ve PG düğümleri ≥ 3 AZ'ye yayılır.
- **Şart (FA-13):** Orkestratör yalnız **aynı cluster içinde** sync standby promote eder. Cluster'lar arası otomatik failover yapılmaz. CNPG'de zaten yoktur. Patroni'de bu kapalı tutulur. Cross-cell geçiş HANDOFF/ACCEPTANCE veya `domain.recover` ile yapılır (§17.4.1).
- Fence kanıtı olmayan promote girişimi sev-1 alarmdır (§17.8 sinyal tablosu).
- Statü: PD (araç), FROZEN (şart). Garanti: UDC (FA-13).

#### 17.4.5 OP-26 Failover'da istemci davranışı

| Plane | Davranış |
|---|---|
| Authority | Leader yok veya lease geçişte: "retry" protocol rejection (outcome değil). Client aynı nonce ile yeniden dener. Sonuç idempotenttir (OP-S2–OP-S5). UI "Not confirmed — checking" der (RT23). Bu davranış §16.7 failure contract'larındadır |
| Identity | Yazma gerektiren uç noktalar (token, refresh, login, kayıt) **HTTP 503 + `Retry-After`** döner. **`invalid_grant` asla dönmez**, çünkü SDK'ların çoğu bu hatada kullanıcıyı çıkış yaptırır. JWT doğrulaması ve JWKS bellekte sürer |
| Havuz | Ölü bağlantılar sağlık kontrolüyle hızla tahliye edilir, üstel geri çekilmeyle yeniden kurulur. libpq çok host + `target_session_attrs=read-write` kullanılır. Aksi halde 25 s'lik kesinti havuz doygunluğuyla 2–3 dk'ya uzar (Rust sürücüsünün bu semantiği desteklediği doğrulanmadı) |
| Zaman çizelgesi | Patroni TTL 20 / loop_wait 5 / retry_timeout 5 ile yaklaşık 25 s (kaynak tahmini, Access'te ölçülmedi) |

Statü: FROZEN (503 eşlemesi), PD (zamanlar). Garanti: kullanıcının yanlışlıkla çıkış yaptırılmaması UDC (istemcinin RFC'ye uygun 503 işlemesi); kesinti süresi NG.

#### 17.4.6 OP-27 Read replica kuralı

- **Authority:** commit kararları replica'dan verilmez (TI-5). `check`, search ve explain derived/replica'dan gelebilir; bunlar advisory'dir ve `as_of`/`at_least` taşır.
- **Identity:** Sonucu bir güvenlik kararını etkileyen her sorgu primary'den okunur. Kapsam: iptal/epoch, oturum aktifliği, refresh rotasyonu, kimlik bilgisi doğrulaması, kaba kuvvet sayacı, onay (consent), grup/rol üyeliği. Replica'ya yalnız şunlar gider: admin arama/listeleme, raporlar, denetim izi görüntüleme. Kullanıcının kendi profil ekranı replica'dan okunabilir, ancak LSN tabanlı read-your-writes ile: yazmadan sonra `pg_current_wal_lsn()`, replica'da `pg_last_wal_replay_lsn()` karşılaştırması, gerideyse primary. Gecikme eşiğini aşan replica devre dışı bırakılır.
- Değişmez **OPI-2**: iki plane'de de asenkron replica'dan güvenlik okuması yapılmaz.
- Statü: FROZEN. Garanti: UDC (sorgu yönlendirmesi kuralının uygulanması). Güvenlik okumasının replica'dan **karar üretmemesi** authority'de TI-5 olarak BS kalır.

#### 17.4.7 OP-28 Çok bölge ve LWW yasağı

- Karar (T28): cell modeli, active-active canonical yazma yok, async kopya promote edilmez.
- Kanıt: bölgeler arası sync yazmanın gecikmesi p99 47/84/130 ms'dir (üçüncü taraf). Önerilen eşik <5 ms, zorunlu tavan <10 ms'dir. Bir login 5–7 yazma yapar, bu yüzden kıtalar arası sync yazma identity plane'de çalışmaz. Keycloak 26.3'te 20 ms RTT ile p99 1.076 ms'ye çıkmıştır.
- **Last-writer-wins çakışma çözümü güvenlik durumunda her iki plane'de yasaktır** (OPI-5). Bu, PG mantıksal replikasyonla active-active ve Kanidm tarzı quorum'suz çok-primary yapıları kapsar.
- Reddedilen alternatif: CockroachDB/Spanner sınıfı dağıtık SQL. Gerekçeler: Ory CRDB 230 ms vakası, follower read ≥ 4,2 s bayatlık, T8 gerekçesi. Ayrıca global tablolar veri yerleşimini bozar.
- Statü: FROZEN. Garanti: çift yazar yokluğu UDC (FA-13).

#### 17.4.8 OP-29 Bölge kaybında plane'e göre davranış

| Plane | Kural |
|---|---|
| Authority | §17.4.1 madde 2. Fence'siz promote yasaktır. Kurtarma domain bazında ve seçicidir (FR-0–FR-6). Identity plane'in "bütün epoch'ları artır" yaklaşımı burada uygulanmaz. Domain log'unda çatallanma geri alınamaz; toptan epoch artırımı fence'siz promote'u meşrulaştırmaz |
| Identity (hücre modeli) | Kayıp hücredeki realm'ler etkilenir, diğer hücreler etkilenmez |
| Identity (async DR profili) | Yalnız **beyan edilmiş RPO>0 profiliyle** promote yapılır. Promote'tan hemen sonra bütün `session_epoch` ve refresh aileleri toptan artırılır, herkes yeniden login olur. Kayıp penceresindeki parola/MFA değişiklikleri kaybolabilir (HL-31). Bu profil identity realm'in residency/DR beyanında açıkça yazılır |
| Gerekçe | Identity oturumlarında yeniden login ucuzdur, authority log'unda çatallanma değildir |

Statü: FROZEN. Garanti: authority UDC (FA-13); identity async profilde kayıp NG (HL-31).

#### 17.4.9 OP-30 Veri yerleşimi

- Residency birimi cell'dir. Domain'in residency beyanı (T28) ve realm'in residency beyanı (MD-5) cell bölgesini belirler. Placement Directory (CMP-26) domain, realm ve tenant'ı cell'e eşler. Hücreler arası veri replikasyonu yoktur.
- Global tablo kullanan dağıtık SQL (CockroachDB global tables) veri yerleşimini bozar, bu yüzden reddedilir.
- Bir kullanıcının birden çok hücrede olması realm'ler arası açık IdentityBinding ile çözülür; global kullanıcı tablosu yoktur (MD-5).
- Statü: FROZEN. Garanti: UDC (operatör yerleşim beyanına uyar).

#### 17.4.10 OP-31 Sequencer graceful step-down

- Planlı kapanışta (rolling upgrade, node drain) sequencer şu sırayı izler: yeni batch almayı durdurur → uçuştaki batch'i commit eder veya bırakır → lease'i açıkça bırakır (lease satırında `released_at`) → in-memory durumu atar. Yeni leader lease süresini beklemeden devralır. Epoch CAS kuralı değişmez (TI-2).
- Graceful step-down yalnız availability iyileştirmesidir. Step-down yapılmadan ölen leader'da kural lease süresidir (FA-7).
- Lider seçimi sürüm kümesiyle kapılanır (OP-56).
- Statü: FROZEN TECHNICAL. Garanti: safety BS (epoch CAS); availability UDC.

#### 17.4.11 Saat kaynakları

FA-3 (provider saat belirsizliği ≤ beyan; hedef ≤ 250 ms, EA) ve RT4/TI-RT2 (iki bağımsız zaman kaynağı + sınırlı ilerleme + witness çapraz kontrolü) aynen geçerlidir (§16.2, §16.11). Identity plane token `iat`/`exp` değerleri aynı provider saatinden gelir. DPoP replay cache TTL'i kanıt ömrü + 2× saat kaymasıdır (MD-18). Değerler ölçülmemiştir (OQ-1).

---

### 17.5 Kapasite, SLO ve rate limiting

#### 17.5.1 OP-32 SLO ve kapasite hedefleri — ENGINEERING ASSUMPTION

**Bu tablodaki her sayı ENGINEERING ASSUMPTION'dır, ölçülmemiştir (OQ-1) ve satış dilinde garanti olarak kullanılamaz (B15).** Sayılar MD-19.6 gereği spec'te yer alır.

| Plane | Metrik | Hedef (EA) | Not / kaynak |
|---|---|---|---|
| Authority | Online `commit` p99, intra-cell | ≤ 30 ms (witness-before-ack hariç) | Batch tx + sync quorum |
| Authority | Witness-before-ack commit p99 | ≤ 750 ms | Out-of-cycle checkpoint + en yakın bağımsız witness RTT |
| Authority | `check` p99 | ≤ 10 ms | Replica / derived |
| Authority | Domain başına sürekli commit | ≥ 2.000/s | Tek sequencer + group commit (OP-9); üstü §17.11 T6/T8 |
| Authority | Cell başına domain sayısı | 10⁴–10⁵ | Çoğu domain düşük hacimli |
| Identity | İptal yayılımı, aynı node | 0 ms (senkron) | — |
| Identity | İptal yayılımı, aynı cluster diğer node'lar | p99 < 250 ms | Outbox polling 100 ms (hedef, ölçülmedi) |
| Identity | İptal yayılımı, diğer cluster/bölge | p99 < 500 ms | Hedef |
| Identity | İptal, introspection yapmayan RS | Access token ömrü | HL-22; "hızlı" ve "katı" (introspection zorunlu) profiller |
| Identity | Hash dışı CPU oranı (login) | toplam CPU / Argon2 CPU < 1,10 | Oran metriği, OP-33 |
| Identity | Login ve refresh kapasitesi | Ölçülecek | Keycloak kıyası yalnız rekabet bağlamıdır (§17.5.4) |

Uzak PEP'ler için latency, ALLOW'u replica'dan vermekle değil, beyan edilmiş projection profilleriyle çözülür (exact-intent token, bounds token, PAP).

**Ölçüm yöntemi.** Kapasite Little yasasıyla planlanır (L = λ·W). Havuz ve worker sayıları kuyruk derinliği metriğiyle doğrulanır. Ölçümler "ölçüm ortamı ≠ üretim" uyarısıyla tekrarlanır.

Statü: EA (bütün sayılar). Garanti: NOT GUARANTEED (hedeftir). Kaynak: MD-19.6.

#### 17.5.2 OP-33 Argon2 parametreleri ve planlama

| Alan | Değer |
|---|---|
| Karar | Argon2id, m = 7.168 KiB (7 MiB), t = 5, p = 1 (OWASP eşdeğer profili). Kanonik değer §15.14 CR-36'dır (ölçülmüş). Tek hash yaklaşık 8,95 ms (M4 ortamı). Hesaplama `spawn_blocking` üzerinde, çekirdek sayısına eşit izinli bir **semafor** arkasında yapılır. Bu düzen p99'u yaklaşık 25× iyileştirir. 10 thread'de kazanç 4,02×'te kalır (bellek bant genişliği). Parametreler realm başına yükseltilebilir, düşürülemez (PD). Var olmayan kullanıcı için dummy Argon2 çalıştırılmaz. Yerine adaptif gecikme ve varlıktan bağımsız semafor kullanılır (MD-18) |
| Yük atma | Semafor kuyruğu doluysa istek **503 + `Retry-After`** alır (kapasite shedding). Hesap veya istemci başına limit aşımı **429** alır (OP-35). Gerekçe: 429 istemci davranışını cezalandırır, kapasite sorunu ise 503'tür |
| Statü | PD (parametreler), FROZEN TECHNICAL (izolasyon) |
| Garanti | Argon2 maliyetinin tokio reaktörünü bloke etmemesi UDC (`spawn_blocking` + semafor kuralının uygulanması); kapasite NG |

#### 17.5.3 OP-34 İmza kapasitesi

- Ölçülmüş imza maliyetleri (aws-lc-rs; M4 ortamı): Ed25519 imza 4,10 µs / doğrulama 18,32 µs; ES256 11,05 / 27,30 µs; RSA-2048 imza 710 µs; DPoP doğrulama ≈ 21 µs. `jsonwebtoken` anahtar ayrıştırma yolu 1,91× kayıp getirir (OP-5).
- Bu fark kapasite açısından küçüktür; algoritma seçimi MD-3'tedir.
- RSA imzası identity plane'de yalnız opt-in'dir (RS256, MD-3), çünkü imza maliyeti ES256'ya göre yaklaşık 64×, Ed25519'a göre yaklaşık 173× yüksektir (oranlar yukarıdaki sayılardan hesaplandı).
- HSM/KMS kapasitesi ayrıca ölçülür; yukarıdaki sayılar yazılım anahtarı içindir.
- Authority plane'de imza commit sonrasıdır (CMP-7 → CMP-22a). Bu, Crosby–Wallach'ın "imza payı ekleme maliyetinin %83,3'ü" darboğazını zaten çözer.
- Statü: EA (kapasite).

#### 17.5.4 Keycloak kıyası (bilgi amaçlı)

Keycloak'ın yayımladığı sizing vCPU başına 15 login/s ve 120 refresh/s'dir. Buna göre 2.000 login/s + 10.000 refresh/s ≈ 286 vCPU eder ve hash payı yaklaşık %15'tir. Bu sayılar **vendor belgesine dayanır, Access ölçümü değildir**. Yalnız rekabet bağlamı olarak kalır, kapasite planına girmez. "Aynı donanımda daha yüksek login/s" hedefi identity plane'in EA'sıdır ve satış dilinde garanti olarak kullanılamaz (B15).

#### 17.5.5 OP-35 İki katmanlı rate limiting

| Katman | Authority plane (T33) | Identity plane |
|---|---|---|
| A — yerel, yaklaşık | Gateway'de (CMP-1) protocol-rejection limitleri; cell-yerel token bucket/GCRA; belirsizlikte **reddetme** yönünde | `governor` (GCRA, süreç içi); IP, endpoint, global QPS. Yaklaşıktır: N node = N× gerçek sınır, kabul edilebilir |
| B — kesin | Decision path'te SYNC-DERIVED sayaçlardan deterministik (requester throttling, policy sınırları; replay edilebilir) | PostgreSQL'de atomik `UPDATE login_throttle SET tat = GREATEST(tat, now()) + …` (GCRA benzeri, kilitsiz); hesap başına parola, OTP, MFA challenge, refresh reuse, hesap kilidi. Sync replike, logged (OP-16) |

- Kural: güvenlik sınırları (hesap başına deneme) **hiçbir zaman** node-yerel sayaçla uygulanmaz. Uygulanırsa yatay ölçekleme bir zafiyete dönüşür: 10 node'da 5 deneme fiilen 50 olur.
- Rate limiter arızası ALLOW'a dönmez (MD-8).
- Ürün limit değerleri POLICY DEFAULT'tur ve §13.7.4'tedir (commit 20/s sürekli, 100 burst; check 60/dk; istek ≤ 256 KB …). Identity API'leri için realm/tenant başına `rate_limit_rps` alanı eklenir (noisy neighbor).
- Statü: FROZEN TECHNICAL (yapı), POLICY DEFAULT (değerler). Garanti: Katman B kesinliği BS (sync replike tek satır); Katman A NG (yaklaşık).

#### 17.5.6 OP-36 Load shedding eşlemesi

| Durum | Authority | Identity |
|---|---|---|
| Sıcak domain / sequencer doygun | "Busy — retry" protocol rejection, outcome değil (§16.7) | — |
| Kapasite (Argon2 semaforu, havuz kuyruğu, DB failover) | — | 503 + `Retry-After` |
| İstemci/hesap limiti | Protocol rejection (SI-20) | 429 (+ `Retry-After`) |
| Kuyruk derinliği | Metrik ve geri basınç noktası uygulamadadır, DB'de değil | Aynı |

Statü: FROZEN. Garanti: shedding hiçbir zaman ALLOW üretmez: BS (MD-8).

---

### 17.6 Denetim log'u

İki denetim log'u vardır. **(1) Authority domain log'u** CANONICAL'dır, semantiktir ve Access kurallarına tabidir (T3, T16–T21, T39). **(2) Identity denetim log'u** identity plane'in CANONICAL olay kaydıdır ve OP-37–OP-44 kurallarına tabidir. Bu log authority kararı taşımaz. İki log aynı şemayı veya aynı saklama kuralını paylaşmaz.

#### 17.6.1 Kayıt zarfı ve hash formatı (normatif)

Kayıt zarfı kayıt modelinin alanlarının fiziksel temsilidir; yeni alan anlamı eklemez. Biçim deterministic CBOR (RFC 8949 §4.2) + CDDL (RFC 8610) şemasıdır. Aşağıdaki gösterim bilgilendiricidir; normatif CDDL open spec'te yayınlanır (P1 L2).

```text
RecordEnvelope = {
; --- leaf çekirdeği: her inclusion proof'ta açık (adres + sıra; içerik yok) ---
  domain:        DomainID; genesis digest'i (P3)
  pos:           uint; domain içi pozisyon; 0 = Genesis
  kind:          "genesis" / "opening" / "decision" / "claim"
  recorded_at:   TrustedTime; domain trusted time, pos ile monoton (TI-19)
  prev:          Digest; önceki zarfın leaf hash'i (hash chain)
; --- alanlar: her biri leaf'e yalnız salt'lı alan commitment'ıyla bağlı ---
  fields: {
    header…:     KindHeader alanları; redakte EDİLEMEZ alanlar (existence, attribution, lineage,
;   basis + dependency set, outcome, consumption effects,
;   artifacts[] digest'leri, ingest disposition…) — alan başına bir giriş
    body_commit: [* BodyCommitment]; H(salt ‖ body) — redakte edilebilir body'lerin taahhüdü
    proof_commit:[* Digest]; H(AIS / AAS / authentication assertion bayt'ları); bayt'lar AYNEN proof store'da
    versions:    VersionVector; core spec / meta-schema / schema digest / profile (PI-21)
  }
  field_salt:    { * name => bstr }; alan başına salt (redakte edilmez; kaba kuvvet engeli)
}
FieldCommit(name) = H(0x01 ‖ field_salt[name] ‖ det-CBOR([name, fields[name]]))
field_root        = MerkleRoot(FieldCommit'ler, name'e göre sıralı)
leaf_hash         = H(0x00 ‖ det-CBOR({domain, pos, kind, recorded_at, prev, field_root})); Merkle yaprağı
```

Kurallar:
1. **Redaksiyon ve seçici açıklama leaf hash'i bozmaz.** Body'ler salt'lı commitment'la bağlıdır. Redaksiyon body'yi, salt'ı ve DEK'i siler (crypto-shredding); commitment ve leaf hash kalır (INV-30, C34). Leaf yalnız leaf çekirdeğine ve alan commitment'larının köküne bağlıdır. Bir alanı açmadan yalnız `FieldCommit`'ini vermek leaf'i, `prev` zincirini ve Merkle kökünü yeniden hesaplamaya yeter. Salt, düşük entropili değerlerin commitment'tan kaba kuvvetle çıkarılmasını engeller.
2. **İmzalı bayt'lar yeniden kodlanmaz.** AIS, AAS, WebAuthn assertion, ID token, SET alındığı bayt'larla saklanır; doğrulama o bayt'lar üzerindedir (TI-11). Deterministic CBOR yalnız Access'in kendisinin hesapladığı digest'ler için kanoniktir.
3. **AIS her commit/continue kaydında** proof store'dadır ve digest'i `proof_commit`'tedir. Redakte export'ta yalnız digest'i kalır.
4. **Claim record'u** Claim alan kümesini taşır; `ingest_time = recorded_at`; ingest disposition header alanıdır; `quarantine:quota` yalnız qualifying etkiyi düşürür, narrowing etkisini değil.
5. **DecisionRecord header'ı** ayrıca `basis`, `artifacts[]` ve `consumption` alanlarını ayrı alan commitment'larıyla taşır. Inclusion proof yalnız `artifacts`'ı açar; lineage, dependency set ve consumption kapalı kalır (T19; SI-14, E26).

Domain separation: yaprak `0x00`, alan commitment'ı `0x01` önekiyle hash'lenir. Merkle iç düğümü RFC 9162 tipi `0x01` önekini kullanır. Bu ayrım ikinci ön-görüntü direnci için zorunludur. Identity denetim log'unun Merkle ağacı da aynı ayrımı kullanır. **CBOR golden-vector'leri CI kapısıdır** (OP-56).

#### 17.6.2 OP-37 Identity denetim log'unun bütünlük modeli

| Alan | Değer |
|---|---|
| Authority log'u (değişmez) | `prev` hash chain + Merkle (T3). Zincir sequencer belleğinde, batch içinde hesaplanır; DB'de satır içi serileşme yoktur. İmza commit sonrasıdır |
| Identity denetim log'u | **Olay başına hash zinciri yoktur.** Düz append-only tablo (OP-17) kullanılır. Periyodik Merkle checkpoint'i (OP-38) ayrı bir arka plan görevinde birleştirilir ve imzalanır. Ekleme yolu imza beklemez. Sıralama ile bütünleştirme ayrıdır (Tessera modeli). Checkpoint'ler dışarı yayımlanır: witness, müşteri hook'u, nesne kilitli S3. Yayımlanmayan bütünlük iddiası boştur |
| Uzun ömür | Tiled log + **yıllık shard** (C2SP tlog-tiles / static-ct deseni). Eski shard dondurulur, statik tile olarak arşivlenir. Authority log'unda header'lar süresiz olduğu için shard'lama yalnız Merkle ağacının ve kanıt maliyetinin sınırlanması içindir: domain log'u silinmez (çıkarım: authority Merkle ağacına yıllık shard uygulanması checkpoint formatını değiştireceği için **yalnız identity log'u** için kararlaştırılır; authority için WATCH) |
| Yönetilen defter yok | QLDB 31 Temmuz 2025'te destek dışı kaldı (doğrulanmadı). Bütünlük mevcut DB'de bir özelliktir |
| Statü | FROZEN TECHNICAL (identity), WATCH (authority shard) |
| Garanti | Identity log'unda yayımlanmış checkpoint'ten önceki değişikliğin tespiti: UDC (≥1 bağımsız yayın hedefi). Checkpoint öncesi pencere: NG (HL-33). Authority log'u: G34 BS |

"Hash-chained 5.898 tps ↔ zincirsiz 22.441 tps" ölçümü yapısal tavan değildir; ölçüm henüz yeniden üretilmedi. Zayıf kanıttır, karar gerekçesi yalnız mimaridir (seri bağımlılık).

#### 17.6.3 OP-38 Checkpoint aralığı beyanı ve coalescing

- Checkpoint aralığı her log için **ayrı yayımlanan bir parametredir** ve "en uzun birleştirme gecikmesi" (MMD) olarak dışarıya beyan edilir.
- Authority: 60 s veya 1.000 kayıt (POLICY DEFAULT, T16). Değişiklik yoksa heartbeat (60 s). Witness-before-ack sınıfında out-of-cycle (T18). Kritik authority olaylarında pencere witness-before-ack ile zaten kapanır (SEC23).
- Identity: hedef **≤ 1 s** (EA, ölçülecek). Yüksek değerli olaylarda (admin, kimlik bilgisi değişimi) daha kısa olabilir.
- **Coalescing:** revocation fırtınasında (çok sayıda witness-before-ack commit'i) out-of-cycle checkpoint'ler birleştirilir. Bekleyen bütün batch'leri kapsayan tek bir checkpoint üretilir ve witness'a tek gönderim yapılır. Her bekleyen ack o checkpoint'in cosign'ıyla döner. Bu, witness ve HSM yükünü batch sayısından bağımsız kılar. Semantik değişmez: ack yine kapsayan checkpoint + bağımsız cosign'dan sonradır (TI-6, TI-13).
- Statü: POLICY DEFAULT (authority), EA (identity), FROZEN TECHNICAL (coalescing). Garanti: coalescing BS (ack sırası korunur).

#### 17.6.4 Replica / mirror

T21 ve TI-13 aynen geçerlidir: domain'in beyan ettiği provider-dışı replica'ya sürekli CBOR sequence aktarılır; **mirror-before-witness**. Identity denetim log'unun dış yayın hedefleri (OP-37) bunun zayıf karşılığıdır: kaydın kendisini değil checkpoint'i taşır.

#### 17.6.5 İmza ve anahtar hiyerarşisi

T20, CMP-7 ve CMP-13 aynen geçerlidir; imza commit sonrasıdır, signer ayrı süreçtir (CMP-22a). Identity denetim checkpoint'leri CMP-22b'de realm'den bağımsız, cell başına bir denetim anahtarıyla imzalanır (çıkarım: cell başına anahtar realm anahtar rotasyonundan bağımsızlık için seçilmiştir, PD).

#### 17.6.6 OP-39 DENY ve başarısız girişim kaydı

| Alan | Değer |
|---|---|
| Authority | Commit-mode DENY/REQUIRE_ACTION, ilgili Exercise'ın DecisionRecord'u olarak **canonical'dır** (nonce'lu evaluation kaydı). Protocol rejection (limit, bozuk istek, AIS eşleşmezliği) kayıt üretmez. Bunlar kanonik olmayan **operasyonel denetim akışına zorunlu** olarak yazılır: CMP-1/CMP-2 olayı, OPERATIONAL, örneklemesiz (OP-44). |
| Identity | Başarısız login, başarısız MFA ve reddedilen token isteği identity denetim log'una **örneklemesiz** yazılır. Kabul noktası şudur: başarısız denemenin olay satırı, Katman B sayaç güncellemesi (OP-35) ile **aynı transaction**'da yazılır. Böylece "sayaç arttı, olay yok" durumu oluşmaz (çıkarım: Katman B'nin zaten bir yazma olması onu doğal atomik bağlama noktası yapar). Kalıcı iş değişikliği ve sayaç yazması olmayan bir başarısızlık (örneğin bozuk istek) operasyonel akışa gider |
| Statü | FROZEN TECHNICAL |
| Garanti | Authority DENY kaydı BS (commit-mode). Identity başarısız deneme kaydı UDC (sync commit) |

#### 17.6.7 OP-40 Saklama ve katmanlama

Authority plane retention tablosu normatiftir:

| Veri | Varsayılan | Mekanizma | Dayanak |
|---|---|---|---|
| Zarf header alanları + alan salt'ları, alan/body/proof commitment'ları, digest'ler, leaf/Merkle yapısı, AIS digest'leri | **Süresiz** | Silinmez | INV-30, G23 |
| Exercise body'leri (intent değerleri) | Canlı derivation'a gerekmiyorsa **400 gün** sonra redaksiyon uygunluğu (POLICY DEFAULT) | Redaksiyon = body + salt + DEK silme + derived index temizliği; redaksiyon Exercise'ı kayıtlıdır | SEC32, C34 |
| Claim değerleri | Kullanan canlı episode/decision yoksa aynı kural | Aynı | E26 |
| "Canlı derivation" tespiti | Açık episode, açık ValidityContract, açık REQUIRE_ACTION nonce'u, devam eden Exercise | Derived sorgu; **belirsizse redakte etme** | INV-30 |
| Raw carrier evidence | Claim değeriyle aynı | Aynı | P19 kural 5 |
| Identity PII | Identity plane politikası; silme talebi → DEK crypto-shredding | Authority log'da PartyRef kalır | — |
| Advisory/explain telemetrisi | 90 gün (EA), pseudonymous Instance ref | OPERATIONAL | SEC31 |
| Derived store, cache | Kaynağın redaksiyonunu izler; her hassas derived okuma canonical redaksiyon durumuna karşı yeniden kontrol edilir | — | SI-15 |
| Replica / export kopyaları | Redaksiyon kopyalara **yayılmaz** (NG, N-11); redaksiyon kaydı replica'ya ulaşır, replica operatörü uygulayabilir (U22) | — | U22, N-11 |

Identity denetim log'u:
- **Sıcak katman** PG'dedir: 30–90 gün, realm/tenant başına ayarlanabilir. **Soğuk katman** S3'te OCSF + Parquet biçimindedir, süresiz veya kiracı kararıdır. Analitik katman ClickHouse'tur, opsiyonel ve DERIVED'dir (OP-47).
- Saklama bölüm ayırma/düşürme ile yapılır, asla toplu `DELETE` ile yapılmaz.
- Olay iskeleti uzun, PII kısa yaşar. İskelet (takma adlı özne kimliği, olay tipi, sonuç, zaman) 12 ay veya daha uzun tutulur. IP, user-agent ve e-posta özne başına anahtarla şifreli ayrı tabloda tutulur ve kısa sürede (örnek 6 ay) crypto-shred edilir.
- Her alan "PII mi" ve "saklama sınıfı" etiketiyle işaretlenir.

**Sınır:** Kiracının "saklamayı 30 güne indir" ayarı yalnız identity denetim olaylarına ve authority body'lerine (400 gün POLICY DEFAULT, domain hukuki süreye göre ayarlar) uygulanır. **Authority log header'larına ve commitment'lara uygulanamaz**; bunlar süresizdir (INV-30). Bu sınır kiracı arayüzünde açıkça yazılır.

Statü: POLICY DEFAULT (süreler), FROZEN (header süresizliği). Garanti: header kalıcılığı BS (G23); body silme UDC (crypto-shredding, HL-9).

Uyum eşlemesi (bilgi): PCI DSS 4 Req. 10 olay izinde 12 ay ve 3 ay sıcak erişim ister. NIST SP 800-53 AU ailesinde AU-9/AU-10 kriptografik bütünlük ve inkâr edilemezlik içindir. Hiçbir büyük IdP 12 ayı kendi içinde karşılamaz, akışlı export'a devreder. Ayrıntı → §14 (uyum).

#### 17.6.8 OP-41 Dış formatlar ve export adaptörleri

| Alan | Değer |
|---|---|
| Kanonik | Authority: deterministik CBOR kayıt zarfı (T4; §17.6.1). Identity: Access'in sürümlediği iç olay şeması. Kimlik olay alanları OCSF IAM sınıflarının (3001–3008, OCSF 1.9.0; doğrulanmadı) alan adlarıyla **hizalanır**, ama kanonik şema OCSF **değildir** |
| Export adaptörleri | OCSF + Parquet (S3/Security Lake), SET (RFC 8417; push/poll), CAEP/SSF, OTLP log, HTTP olay toplayıcı, syslog/CEF/LEEF. Her adaptör ince tutulur (< 500 satır hedefi). RFC 9967 (SCIM olay profili) WATCH'tır, statüsü doğrulanmadı |
| İki yayın kanalı | Aksiyon odaklı CAEP akışı (8 tip) ve tam taksonomili denetim akışı. İkisi aynı olay yolunu ve ortak `txn` tanımlayıcısını kullanır. Üç zaman damgası birinci sınıftır: gerçekleşme, kayıt, checkpoint |
| Kural | SIEM'e giden her şey "copy — not the record"'dur (X22). Audit sorusu kayıttan cevaplanır |
| Gerekçe | Commitment'ların sabit kalması için kanonik şemanın sürümlenmesi Access'in kontrolünde olmalıdır; OCSF sürümleri dışarıdan değişir. "OCSF kanonik iç şema" yaklaşımı authority log'u için reddedilir, identity için alan hizalaması olarak alınır |
| Statü | FROZEN (kanonik), PD (adaptör seti) |

#### 17.6.9 OP-42 Silme, crypto-shred ve restore sonrası yeniden shred

- Teknik mekanizma (T39): salt'lı body commitment, body başına DEK, crypto-shredding, leaf süresiz. Identity PII'da kullanıcı başına DEK uygulanır. Silme şu adımlarla yapılır: anahtar materyali sıfırlanır, anahtar referansı tombstone olarak kalır, tek bir değişmez "silme olgusu" satırı eklenir, deftere dokunulmaz. Hash ciphertext üzerinden alınır.
- **Hukuki çerçeve (EDPB):** EDPB'nin 16 Ocak 2025 pseudonymisation kılavuzuna göre takma adlı veri ancak anonimlik koşulları sağlanıyorsa anonim sayılır. Crypto-shred "GDPR silmesi" olarak pazarlanmaz (tarih doğrulanmadı). Bu, HL-9 ile tutarlıdır: redaksiyon ≠ erase.
- **Restore sonrası yeniden shred:** Bir yedekten (PITR) geri dönüldüğünde, yedek anından sonra shred edilmiş anahtarlar yedekte hâlâ vardır. Restore prosedürü, kayıtlı silme olgularını (tombstone satırları ve redaksiyon Exercise'ları) geri yüklenen veriye **yeniden uygular**. Bu yapılmadan ortam trafiğe açılmaz (OP-57 tatbikat maddesi 7).
- KMS anahtar yedekleri de shred listesine tabidir: yedeklenmiş DEK, silme olgusundan sonra yedekte kalmamalıdır. Kalıyorsa saklama süresi beyan edilir (çıkarım).
- Statü: FROZEN TECHNICAL. Garanti: silmenin dağıtılmış kopyalara yayılması NG (HL-9, N-11); yeniden shred UDC (prosedür).

#### 17.6.10 OP-43 Kullanıcıya görünen denetim

- Identity plane kullanıcıya aksiyon odaklı bir güvenlik geçmişi gösterir: login, MFA, anahtar, oturum, OAuth onayı. Süre 30–90 gündür, IP maskelidir, risk skoru veya risk sinyali gösterilmez. Gerekçe: hesabı ele geçirmiş saldırgana kurbanın hareketleri ve risk modelinin ipuçları gösterilmemelidir.
- Taşınabilirlik (GDPR Art. 15/20) export'unda gözlenen veri (giriş geçmişi) dahildir, türetilmiş veri (risk skoru, profil) hariçtir. Bu ayrım şemada bir bayrakla kodlanır.
- Authority tarafının kullanıcı görünümü §8 yüzeyleridir (S-*), çapraz referans → §8.
- Statü: PD (süre).

#### 17.6.11 OP-44 Örnekleme yasağı ve denetime erişimin denetimi

- Denetim yolunda örnekleme yapılmaz; yalnız gerekçelendirilmiş olay tipi seçimi yapılır. Telemetri yolunda örnekleme serbesttir. İki yol aynı boru hattına konmaz.
- Denetim log'una erişim de bir denetim olayı üretir (sorgu başına bir kayıt). Üst denetim ayrı bir zincirde birleştirilir. Authority plane'de bu zaten `access.audit.export` Exercise'ıdır (PI-4).
- `pgaudit` ikincil DB düzeyi kontroldür, birincil denetim kaynağı değildir. Transactional değildir ve `TRUNCATE`'i kapsamaz.
- Statü: FROZEN TECHNICAL. Garanti: UDC.

#### 17.6.12 Sessiz bozulma tespiti

FA-14 (kayıt kimliği = commitment) ve rebuild-diff farkının sev-1 olması (TI-16, RT9) sürekli tespiti sağlar. Restore sonrası doğrulama maddeleri (checksum, depo bütünlüğü) restore tatbikatına eklenir (OP-57). Tespit öncesi NG (N-29), tespit sonrası UDC (U30).

#### 17.6.13 Explain, audit export ve replay (normatif)

- **Explain (geçmiş karar):** Explain builder DecisionRecord'un pozisyonu q'dan state'i **q−1'de** kurar (snapshot + replay) ve aynı normatif değerlendirmeyi (Kernel, CMP-24) explain modunda çalıştırır. Sonuç kaydedilen outcome'la eşleşmek zorundadır. Eşleşmezse bu bir determinism olayıdır ve açıklama verilmez (X25).
- **Explain (varsayımsal):** `check` ile aynı yol; `advisory` etiketli.
- **Disclosure filtresi her okuma yolunun son aşamasıdır** (TI-20).
- **Audit export:** `access.audit.export` Exercise'ı (PI-4); Record Export Package streaming CBOR sequence + checkpoint'ler + SPP'ler + Claim'ler (veya digest'leri).
- **Replay:** open Replay CLI (Kernel + Reference Verifier) export'u Suiss'siz doğrular: zincir, Merkle, witness cosign'ları, her kararın q−1 yeniden değerlendirmesi. Redakte export'ta zincir + Merkle + witness doğrulaması aynen geçer; yeniden değerlendirme açılan alanlar kadardır ve "replay coverage" beyan edilir.
- **Sampling replay:** replay agent replica'yı veya export stream'ini sürekli izler; CT3 %100, CT2 %1 (POLICY DEFAULT). Uyuşmazlık imzalı kanıt olarak raporlanır. Not: bu, *denetim* örneklemesi değil yeniden değerlendirme örneklemesidir; OP-44 ile çelişmez.
- **SIEM:** export'un projection'ı; OCSF eşlemesi (OP-41); "copy — not the record" (X22).

---

### 17.7 Bozulmuş mod ve break-glass

#### 17.7.1 Authority plane: bozulmuş mod yoktur

TI-9 (fail-open yok), SEC27 (continuity zarfları fail-open değildir), DL-8 ve SI-22 (Exercise dışında acil yol yok) aynen geçerlidir. Authority failure tablosu normatiftir:

| Arıza | Sonuç | Outcome mu? | Dayanak |
|---|---|---|---|
| Limit aşımı, bozuk istek, AIS eşleşmezliği | Protocol rejection | Hayır; kayıt yok, nonce açık | P8, SI-20 |
| Bilinmeyen sürüm/extension/must-understand | DENY (evaluation kaydı) veya protocol rejection (bilinmeyen profil) | DENY ise evet | PI-12 |
| Leader yok / lease geçişte | "retry" protocol rejection | Hayır | TI-9 |
| DB tx hatası, CAS hatası | Ack yok; client aynı nonce ile yeniden dener | Hayır | TI-2, TI-8 |
| Validation tekrar tekrar çakışıyor | Sınırlı denemeden sonra "retry" rejection | Hayır | — |
| Restriction politikası çalışma hatası | DENY `restricted/policy-error` | Evet (DENY) | INV-26, T13 |
| HSM/signer'a ulaşılamıyor (imza) | Kayıt commit edildi, artefakt henüz imzasız → client aynı nonce ile yeniden ister; imza gelince teslim | Outcome kayıtlıdır; artefakt gecikir | TI-12 |
| Witness'a ulaşılamıyor (witness-before-ack sınıfı) | Ack bekletilir; client aynı nonce ile yeniden dener | Outcome kayıtlı ve etkili; yalnız ack gecikir | SEC23, T18 |
| Derived store gecikmesi | Commit etkilenmez; advisory/search `as_of` eski; status list `iat` eskir (Δ tükenir), introspection `at_least` bekler veya `active=false` | — | TI-5, SI-7 |
| Cell/bölge kaybı veya cell'ler arası bölünme, fence kanıtı yok | Promote yok; domain commit kabul etmez; yol `domain.recover` | Hayır | FA-13, TI-2 |
| Identity plane kesintisi | Yeni `authentication` Claim yok → ilgili RequirementTerm karşılanmaz → REQUIRE_ACTION/DENY; mevcut KeyBinding'li Instance'lar AIS imzalamaya devam eder | Evet | E25, INV-26 |
| Saat belirsizliği beyanı aşıldı (FA-3) | Leader kendini sağlıksız işaretler, commit kabul etmez | Hayır | TI-19 |

**Fail-open konfigürasyonu yoktur:** "degraded allow", "timeout ⇒ allow", "bypass policy" bayrakları kodda tanımlı değildir; conformance suite bunu negatif testle doğrular (SI-22, X21). Authority artefaktlarının offline/kesinti davranışı yalnız ValidityContract'ın beyan ettiği sınır içindedir. Bu sınırın dışında hiçbir pencere yoktur.

#### 17.7.2 OP-45 Identity plane bozulmuş modu

| Alan | Değer |
|---|---|
| Karar | Identity DB'ye ulaşılamadığında ne olacağı tasarım kararıdır, varsayılan davranış değildir. Kurallar: (1) **Önceden imzalı, ömrü beyan edilmiş** access token'ların Access yüzeylerinde ve RS'lerde yerel doğrulaması sürer. Bunun için JWKS ve epoch cache bellektedir. Ömür, ilgili ValidityContract'ın beyan ettiği horizon'dur (MD-7). (2) **Cache-miss her durumda primary'ye sorar.** Primary yoksa doğrulama **reddedilir** (OPI-3). Pencereler cache-miss'i kabul ettirmez. (3) **Introspection**: Primary'ye veya tazelik kaynağına ulaşılamıyorsa introspection her token için `active=false` döner; cache-hit dahildir; 503 dönmez. Token türü (authority taşıyan / identity amaçlı) bu kuralı değiştirmez. RS 5xx'i ve `active=false`'ı DENY sayar (MD-8; §13.11 EP-3, U37; §14.8). Node bölünmesinde primary ve diğer node'lar iptal kabul etmeye devam eder; bu yüzden node cache'i "iptal edilmemiş" kanıtı değildir (OPI-3 genişletilmiş). "Identity amaçlı token'da cache-hit ve Δ içinde sınırlı cevap; Δ aşılınca `active=false` veya 503" seçeneği reddedilir. (4) Yeni login, refresh, kayıt, admin yazmaları ve revocation kabul edilmez; yanıt 503 + `Retry-After`'dır. (5) 60–300 s'lik bozulmuş mod pencereleri bütün plane'lerde ve Access'in kendi yüzeylerinde (introspection, userinfo, oturum kontrolü) **reddedilir** (MD-8). "`active:true` + düşük güven işareti" (`X-Access-Degraded`) fail-open'dır, çünkü işareti RS yok sayabilir. Süreye bağlı kalan tek kural operasyoneldir: 0–60 s `degraded_mode` alarmı, > 300 s sev-1 (PD). RS'lerin yerel JWT doğrulaması pencereyle değil beyanlı token ömrüyle sınırlıdır (U39, HL-22) |
| Statü | FROZEN (kurallar 1–5), PD (alarm eşikleri) |
| Garanti | Fail-open yok: BS. Kesinti sırasında yapılan iptalin uygulanamaması: RS'lerde ≤ token ömrü, NG (HL-22). Access'in kendi yüzeylerinde pencere yoktur. Bozulmuş modun gerçek güvenlik sınırı kısa access token ömrüdür |
| Gerekçe | Garanti sınıfı dürüstlüğü: pencere bir beyan olmalıdır, örtük bir genişleme olamaz. Introspection epoch önbelleğinden cevaplanmaz; cache-miss DB'ye sorar kuralı geçerlidir |
| Kaynak | MD-7, MD-8 |

Kademeli bozulma tablosu, OP-45 kurallarıyla birlikte normatiftir:

| Senaryo | Login | Refresh | JWT doğrulama | Introspection | Admin API | Kayıt |
|---|---|---|---|---|---|---|
| Normal | Çalışır | Çalışır | Çalışır | Çalışır | Çalışır | Çalışır |
| DB primary failover (0–30 s) | 503 | 503 + Retry-After (asla `invalid_grant`) | Çalışır | `active=false` (primary yok; cache-hit dahil) | Durur | Durur |
| DB tamamen erişilemez (dakikalar) | Durur | Durur | Bozulmuş modda çalışır (OP-45) | `active=false` (503 yok) | Durur | Durur |
| DCS kaybı, PG salt okunur | Durur | Durur | Çalışır | Çalışır (okuma) | Salt okunur | Durur |
| Read replica kaybı | Çalışır | Çalışır | Çalışır | Çalışır | Yavaşlar, primary'ye düşer | Çalışır |
| Redis/Valkey kaybı (varsa) | Çalışır | Çalışır | Çalışır | Çalışır | Çalışır | Çalışır (Redis kritik yolda değil) |
| 3 AZ'den biri kaybı | Çalışır | Çalışır | Çalışır | Çalışır | Çalışır | Çalışır |
| 2 AZ kaybı (quorum kaybı) | Durur | Durur | Çalışır | `active=false` | Durur | Durur |
| Bölge kaybı | Hücre modelinde diğer hücreler etkilenmez (OP-29) | | | | | |

#### 17.7.3 OP-46 Operatör break-glass yolu (CMP-25)

| Alan | Değer |
|---|---|
| Kapsam | Cell operatörünün **altyapı** erişimi içindir. Örnekler: yapılandırma okuma, sağlık kontrolü, özellik bayrağı, identity `session_epoch` toptan artırımı, leader'ı sağlıksız işaretleme. **Authority kararı üretemez ve authority state'e yazamaz** (SI-22). Authority'deki acil durumlar Exercise yoluyla, örneğin Security Party'nin narrowing `policy.set`'i ile yürür (RT3, RT9). Kullanıcı verisi okuyamaz ve değiştiremez |
| İlkeler (10 ilke) | 1. Normal yoldan bağımsız kod yolu; rate limiter, risk motoru ve MFA orkestratörü çağrılmaz. 2. Asgari bağımlılık: yerel diskten veya ortamdan okunan açık anahtar ve saat; DB'ye, Redis'e veya dış IdP'ye bağımlılık yok. 3. Kimlik donanım anahtarıyla ve çevrimdışı doğrulanabilir; önceden dağıtılmış FIDO2 açık anahtarları veya M-of-N çevrimdışı imzalı kısa ömürlü belge. 4. Ağ çağrısız yerel doğrulama. 5. Kısıtlı yetki (yukarıda). 6. Zorunlu ve silinemez iz: yerel dosya, sistem günlüğü ve erişilebilirse dış SIEM. Kendi denetim tablosuna güvenilmez, DB düşmüş olabilir. 7. Kullanımda bütün nöbetçilere otomatik alarm. 8. 15 dakika geçerli, tek kullanımlık; kullanımdan sonra rotasyon zorunlu. 9. Çeyrekte bir tatbikat. 10. Hücre başına ayrı kimlik bilgisi |
| Anti-desen | DB'de duran, parolası kasada olan acil durum admin hesabı yasaktır |
| Statü | FROZEN (kapsam sınırı), PD (süreler) |
| Garanti | Break-glass'in authority kararı üretmemesi: BS (kod yolu ayrı; SI-22). Operatörün altyapı düzeyinde zarar vermemesi: NG (HL-2) |
| Kaynak | SI-22 |

---

### 17.8 Gözlemlenebilirlik

#### 17.8.1 OP-47 Telemetri kuralları

| Alan | Değer |
|---|---|
| İlke | Telemetri minimize ve pseudonymous'tur, **karar girdisi değildir** (TI-18, INV-24). Audit sorusu telemetriden değil kayıttan cevaplanır (X22). Telemetri body/PII taşımaz (E26) |
| Yığın | OpenTelemetry (log ve metrik kararlı, trace beta) + `tracing`. Kütüphane kod tabanına yayılmaz, ince bir cephe arkasında tutulur. Metrikte OTel metrics kullanılır. Arka uç: VictoriaMetrics, Grafana; log/trace için ClickHouse (T37, PD) |
| Kardinalite | Metriklerde **`tenant_id`, `realm_id`, `domain_id` etiketi yoktur.** Kiracı ve domain kırılımı analitik katmanın özet tablolarından gelir. Exemplar ile trace kimliği iliştirilir; native histogram kullanılır. 1M aktif seri yalnız baş blok için 4–6 GB bellek demektir |
| PII ve sır | Sır ve PII taşıyan hiçbir tipte türetilmiş `Debug` yoktur; CI'da zorlanır. `secrecy`/`zeroize` kullanılır. Telemetride takma kullanıcı kimliği, denetimde gerçek kimlik kullanılır. Redaksiyon takibi telemetriye de uygulanır: redakte edilmiş body'den türetilmiş bir değer telemetride kalmaz |
| Semantik konvansiyon | OTel semconv'da (1.44) kimlik/kimlik doğrulama konvansiyonu yoktur. Kendi olay taksonomisi kurulur ve OCSF/CAEP'e statik eşlenir. Semconv'a sabit bağımlılık kurulmaz, eşleme katmanı konur |
| Örnekleme | Telemetride serbesttir; denetimde yasaktır (OP-44) |
| Search / analytics [T40] | Search derived'dır ve viewer-rechecked'dır; global search index yoktur (T40). ClickHouse analitik katmanı **DERIVED** etiketiyle kabul edilir. Envelope-level ve pseudonymous'tur, karar girdisi değildir (SI-8) |
| Statü | FROZEN (ilke ve etiket yasağı), PD (araçlar) |
| Garanti | Telemetrinin karar girdisi olmaması: BS (TI-18) |

#### 17.8.2 Operasyon sinyalleri (normatif)

| Sinyal | Neden | Not |
|---|---|---|
| Commit latency (p50/p99), validation retry oranı, batch boyutu | Decision path sağlığı (OP-32) | Domain başına (metrik etiketi değil; analitik kırılım) |
| Leader epoch değişimleri, CAS hataları, cell mühür/kabul ve fence olayları | Fencing olayları (TI-2, FA-13) | Alarm; fence kanıtsız promote girişimi = **sev-1** |
| Witness-before-ack bekleme süresi, witness erişilebilirliği, cosign uyuşmazlığı | SEC23, equivocation (U9) | Uyuşmazlık = güvenlik olayı |
| Replica gecikmesi (mirror lag) | FA-10 | Witness gönderimi bekletilir (TI-13) |
| Derived `applied_pos` gecikmesi; rebuild-diff farkları | TI-16 | Fark = **sev-1** |
| Ingest kuyruk yaşı (narrowing sınıfı ayrı), quarantine oranı, issuer kotası | Ingest yaş tavanları | Tavan aşımı domain'e beyan; karar girdisi değil (TI-18) |
| Status list `iat` yaşı, introspection `at_least` bekleme süresi | SI-7 | Δ'ya yaklaşırsa alarm |
| Rejection oranları (protocol), DENY/REQUIRE_ACTION oranları | RR-8 kalibrasyonu | Telemetri, canonical değil |
| Advisory `check` / explain hacmi per Instance | SEC31 oracle tespiti | Security tooling'e export |
| Replay agent uyuşmazlıkları | Sampling replay | İmzalı kanıt |
| Operatör erişim log'ları (DB okuma, HSM kullanımı) | SEC19 | Operatör authority state'e yazamaz; log yine tutulur |
| Identity: `degraded_mode` durumu ve süresi; epoch cache hit/miss oranı; outbox tüketici gecikmesi | OP-45, OP-21, OP-20 | Bozulmuş mod = alarm |
| Identity: Argon2 semafor kuyruk derinliği, 503/429 oranları, hash dışı CPU oranı | OP-33, OP-35 | Oran > 1,10 → alarm (EA) |
| Sync standby sayısı ve gecikmesi (her iki plane) | OP-24 | Sağlıklı sync standby < 2 → alarm |
| Identity denetim checkpoint gecikmesi (MMD) | OP-38 | Beyan aşımı = güvenlik olayı |
| Break-glass kullanımı | OP-46 | Her kullanım = alarm |
| Havuz kuyruk derinliği (kritik/admin/replica havuzları) | OP-53 | Geri basınç noktası |

Kurallar: telemetri body/PII taşımaz; telemetri hiçbir karar girdisi değildir; audit sorusu telemetriden değil kayıttan cevaplanır.

#### 17.8.3 OP-67 Gözlemlenebilirlik kod kuralları

**Statü: FROZEN TECHNICAL (korelasyon, kalıcı olay adları, sağlık uçlarının iç ağda olması, alarm-runbook bağı); PD (alan listesi, araçlar). Garanti: UDC.** OP-47 ve §17.8.2 aynen geçerlidir.

1. **Korelasyon.** Her istek W3C `traceparent` izleme kimliği taşır; istemci gönderdiyse o kullanılır, yoksa üretilir. Kimlik HTTP, iç RPC, outbox ve signer boyunca taşınır; `Request-Id` (OP-65) bu kimliğe bağlıdır.
2. **Ortak log alanları.** Her log satırında `trace_id`, `span_id`, `service`, `version`, `event` (kalıcı olay adı, ör. `grant.issued`, `login.failed`), `outcome` ve gerekiyorsa takma adlı aktör kimliği bulunur. Yayımlanmış olay adı değiştirilmez; alarmlar ve panolar bu adlara dayanır.
3. **Sağlık uçları.** Her süreçte `/livez` (süreç ayakta mı), `/readyz` (trafiğe hazır mı: veritabanı, signer ve bağımlı bileşenler) ve metrik çıkışı. Hazır olmayan süreç trafik almaz (MD-8). Sağlık uçları iç ağdadır.
4. **Yerel gözlemlenebilirlik.** Yerel geliştirme ortamı hafif bir izleme yığınıyla (Grafana ve bir trace arka ucu) gelir ve üretimle aynı OpenTelemetry çıktısını kullanır.
5. **Alarm ve runbook.** §17.8.2'deki her alarm, ne yapılacağını anlatan bir runbook'a bağlanır.

---

### 17.9 Dağıtım ve operatör deneyimi

#### 17.9.1 OP-48 Dağıtım formları, tek binary ve tek mod

Dağıtım biçimleri normatiftir:

| Biçim | Ne | Protocol'e etkisi |
|---|---|---|
| Suiss-hosted, paylaşılan cell | Çok domain/realm, bir cell | Yok |
| Suiss-hosted, dedicated cell | Tek büyük domain/organizasyon | Yok |
| Self-hosted (Suiss binary'leri) | Organizasyon kendi provider'ını işletir: tek node "small provider" profili (tek binary + PostgreSQL + HSM/soft-HSM) veya cell | Yok |
| Third-party provider | Access Kernel'i (CMP-24) gömen veya open spec'ten bağımsız yazılmış implementasyon | Yok — conformance suite + test vektörleri |

**Provider-neutrality kontrolü (TI-17):** Protocol yolundaki her işlev yalnız açık spec, açık Kernel / Reference Verifier ve standart altyapıyla gerçeklenebilir. Standart altyapı: PostgreSQL veya eşdeğeri ACID store, HSM/KMS PKCS#11, standart TLS/JOSE/COSE kütüphaneleri. Suiss'e özgü bileşenler (Experience backend, hub aggregator, analytics, placement directory) protocol yolunda değildir. Şart tek-head CAS ve atomik birimlerdir, teknoloji değil.

Ek kurallar:
- **Tek binary, tek mod.** Derleme adımı ve "dev/prod" kod yolu ayrımı yoktur. Geliştirme ile üretim arasındaki fark yalnız yapılandırma değerleridir. Signer ve gateway süreçleri (OP-2) aynı dağıtımın ayrı binary hedefleridir. Small-provider profilinde bunlar tek bir süreç yöneticisi altında yan yana çalışır, ama süreç sınırları korunur (çıkarım: OP-2 izolasyonu profil küçülünce kaldırılmaz).
- **SQLite yalnız tek node.** SQLite yalnız identity plane'in tek node ve küçük kurulumlarında (≈ 1.000 kullanıcı altı) desteklenir. HA topolojisinde SQLite ile başlatma reddedilir. Authority plane Suiss binary'lerinde PostgreSQL ≥ 18'dir (T8, OP-7); Suiss binary'si authority plane'i SQLite ile başlatmaz. SQLite'ın authority için kullanılması third-party provider kararıdır (TI-17). Tek-head CAS ve atomik birim şartının (TI-17) SQLite'ın tek yazar modelinde karşılandığı Suiss binary'leri için varsayılmaz; bunun açılması T8'in açıkça değiştirilmesini ve doğrulamayı (OQ-1) ön koşul yapar. Witness/replica beyanları small-provider'da da zorunludur (T21).
- **Small-provider dayanıklılık profili (beyanlı)**. Tek node profili beyanlı bir dağıtım biçimidir. Bu profilde FA-1 karşılanmaz: ack edilmiş yazma node/disk kaybında kaybolabilir (NG, HL-40). OP-24'ün ≥ 2 sync standby şartı bu profilde kalkar. Authority plane'de witness/replica-before-ack sınıfı (SEC23, T18, T21) yine zorunludur; kayıp suffix `domain.recover` ile ele alınır (FA-10, U24). Identity plane'de OPI-4 bu profilde geçerli değildir. Profil Domain Metadata ve realm DR beyanında `durability: single-node` olarak yayımlanır; garanti satırları UDC yerine HL-40 ile beyan edilir. OP-52 fail-fast kontrolü bu profilde sync standby sayısı yerine bu beyanın varlığını ve witness/replica yapılandırmasını doğrular. Çok node'lu cell'de tek standby ile başlatma reddedilmeye devam eder.
- NATS opsiyoneldir (OP-23).

Statü: FROZEN (formlar, tek mod), PD (SQLite eşiği). Garanti: TI-17 BS; small-provider dayanıklılığı NG (HL-40).

#### 17.9.2 OP-49 Container imajı ve build

- İmaj distroless tabanlıdır (`static` veya `base`; CA ve tz verisi gerekiyorsa `base`). Non-root çalışır.
- **musl varsayılan allocator'ı ile çok iş parçacıklı üretim binary'si yayımlanmaz.** Çok iş parçacıklı yükte ciddi yavaşlama raporu vardır (2020 kaynağı, doğrulanmadı). glibc tabanı veya musl + jemalloc/mimalloc benchmark ile seçilir.
- Build `cargo-chef` ile katmanlanır. Depo tek bir Cargo workspace'tir; workspace dışında path bağımlılığı yoktur.
- İmaj ve Helm chart kendi OCI kayıt defterinde yayımlanır, imaj referansları sabitlenir (digest pin). Üçüncü taraf imaj kataloglarına bağımlılık yoktur (Bitnami 28 Ağustos 2025 olayı; tarih doğrulanmadı).
- Sürüm imzalama cosign ile (keyless) yapılır, hedef SLSA L2'dir. Yeniden üretilebilir build taahhüt edilmez. Tedarik zinciri ayrıntısı → §14.
- Statü: PD.

#### 17.9.3 OP-50 Kubernetes yaşam döngüsü

| Ayar | Değer (PD) | Gerekçe |
|---|---|---|
| preStop bekleme | 5 s | Endpoint kaldırma ile SIGTERM sıralı değildir; yayılım yoğun cluster'da ≥ 1 s sürer |
| Drain gecikmesi | 2 s | Yeni istek almayı bırakma |
| Shutdown timeout (uçuştaki istekler) | 15 s | — |
| `terminationGracePeriodSeconds` | 45 s | Üçünü kapsar |
| Uçuştaki OAuth akışları | Grace süresiyle korunmaya çalışılmaz; auth oturumu DB'dedir (OP-10) | — |
| Probe'lar | Startup, liveness, readiness ayrı uç noktalarda ve ayrı yönetim portunda. **Şema göçü sırasında liveness "up" döner**, readiness "down"; uzun göç restart döngüsüne girmez. Readiness, cache ısınması bitene kadar başarısız döner (OP-53) | — |
| PDB | `maxUnavailable: 1` | Yalnız gönüllü kesintiyi korur |
| Topology spread | Zone'da **sert** (`DoNotSchedule`, `minDomains: 3`), host'ta yumuşak; `matchLabelKeys: [pod-template-hash]` | — |
| Sequencer | Planlı kapanışta graceful step-down (OP-31) önce gelir, sonra drain. Sequencer pod'larının preStop'u lease bırakmayı bekler | — |

Statü: PD (değerler), FROZEN TECHNICAL (göç sırasında liveness, sequencer step-down sırası).

#### 17.9.4 OP-51 Helm, operator ve GitOps

- **Hosted (Suiss):** T36 aynen. Kubernetes per cell, OpenTofu, Argo CD, Cilium + Envoy Gateway, SPIFFE/SPIRE servis kimliği. Servis kimliği transport kimliğidir, actor değildir.
- **Self-host:** Birinci sınıf dağıtım artefaktı **Helm chart**'tır. Operator Helm'in yanında opsiyonel olarak sunulur ve yalnız CRD'lerin gerçekten çözdüğü sorunlar için kullanılır: göç orkestrasyonu, rolling upgrade uygunluk kararı, realm uzlaştırması. CRD ile yönetilen kaynaklar gerçeğin kaynağı değilse bu açıkça yazılır (Keycloak realm-import dersi).
- PG katmanı CNPG ile kurulur (OP-25).
- Statü: PD.

#### 17.9.5 OP-52 Yapılandırma ve sırlar: fail-fast

- **Güvensiz yapılandırmayla başlatma reddedilir, uyarı verilmez** (TI-9 ile uyumlu). Başlangıçta doğrulananlar: issuer/hostname, TLS, admin arayüzünün bağlandığı adres, sync standby sayısı (OP-24; small-provider profilinde bunun yerine `durability: single-node` beyanı ve witness/replica yapılandırması, OP-48), signer süreci erişilebilirliği, JWKS yüklemesi. Eksikse süreç başlamaz. Açık bir "güvensiz geliştirme" bayrağı yalnız tek node geliştirme profilinde vardır ve kayıtlıdır.
- Sırlar dosya tabanlıdır (ESO veya Vault Agent ile bağlanır). Rotasyonda yeniden yüklemeyi uygulama kendisi çözer.
- Vault dinamik DB kimlik bilgileri desteklenir. Havuzdaki mevcut bağlantılar geçerli kalır, yeni bağlantılar yeni parolayı kullanır.
- İmza anahtarları için `mlock` (memsec) kullanılır; anahtar materyali signer sürecindedir (OP-2).
- Anahtar materyali PKCS#11/KMIP soyutlamasıyla HSM/KMS'tedir (CMP-13).
- Sır bootstrap'ı: §15.13 CR-35.
- Statü: FROZEN (fail-fast), PD (araçlar). Garanti: UDC.

#### 17.9.6 Yanlış yapılandırma tuzakları

| Tuzak | Kural | Çapraz referans |
|---|---|---|
| Redirect URI eşleştirmesi | Yalnız tam dizgi eşleşmesi; regex ve joker **hiç gerçeklenmez** (CVE-2024-52289; RFC 9700) | → §10 (OAuth) |
| Issuer/hostname'in istek başlığından türetilmesi | Issuer yapılandırmada sabittir; `Host` başlığından türetilmez (token sahteciliği) | → §10, §12 |
| Proxy başlığı güveni | Varsayılan kapalı. Açıksa güvenilir proxy adres listesi zorunludur; proxy başlıkları eklemez, üzerine yazar. Aksi halde kaba kuvvet sayacı ve IP limitleri sessizce işlevsiz kalır (OP-35) | — |
| Admin konsolu internete açık | Admin API ve konsol ayrı hostname/port'tan sunulur (CMP-15.5) | → §12 |

CVE numarası ve tarihleri yeniden doğrulanmadı.

#### 17.9.7 OP-53 Bağlantı havuzu boyutu ve soğuk başlatma

| Parametre | Değer (PD) | Not |
|---|---|---|
| DB CPU başına aktif bağlantı | 2–4 | — |
| Node başına havuz | 8–16 | Async runtime'da bir bağlantı çok istek servis eder |
| Toplam bağlantı tavanı | `max_connections`'ın %70'i | Kalanı admin, replikasyon, yedekleme, göç içindir |
| Kritik havuz (token doğrulama, introspection) | 4–8, yüksek öncelik | — |
| Admin/rapor havuzu | 2–4, kısa timeout | Admin sorgusu login'i aç bırakmamalıdır |
| Replica havuzu | Ayrı | Yalnız OP-27'de izin verilen sorgular |
| **Sequencer havuzu** | Ayrı kritik havuz; domain başına leader'ın batch yazması için | Çıkarım: sequencer yazma yolu diğer havuzların kuyruğunun arkasında beklememelidir |

Kuyruk uygulamada tutulur ve kuyruk derinliği bir metriktir. Büyük havuz kuyruğu DB'ye taşır ve gecikmeyi görünmez kılar.

Soğuk başlatma: readiness, realm/client cache'i dolana kadar başarısız döner. Epoch cache son pencerenin iptal kümesiyle tek sorguda yüklenir (OP-21). JWKS yüklenemezse süreç başlamaz. Havuz asgari bağlantıyla önceden doldurulur. Başlangıçta 0–5 s rastgele jitter uygulanır ve dağıtım rolling yapılır (thundering herd).

Statü: PD.

#### 17.9.8 OP-54 Topoloji fazları ve kırmızı çizgiler

| Faz | Topoloji | Access karşılığı |
|---|---|---|
| Küçük (~100 kullanıcı) | Tek node + tek PG (identity plane için SQLite tek node seçeneği, OP-48; authority PG ≥ 18), günlük döküm + WAL arşivi | Small-provider profili (T36); beyanlı `durability: single-node`, HL-40 |
| Faz 1 (~100 bin kullanıcı) | Tek bölge, 3 AZ, 3 durumsuz node; PG primary + 2 sync standby (`ANY 1`); havuzlayıcı; yedek bulut depolamaya | Bir cell |
| Faz 2 | Aynı bölgede iki bağımsız cluster + tek sync replike mantıksal DB; siteler arası RTT < 5 ms hedef, < 10 ms tavan | Cell içinde iki K8s cluster; canonical depo yine tek linearizable depodur (FA-2) |
| Faz 3 | Bölge başına hücre (Okta modeli); hücreler arası veri replikasyonu yok; küçük global kontrol düzlemi (tenant → hücre) | Cell modeli + CMP-26 Placement Directory (T28) |
| Büyük (~10M kullanıcı) | Argon2 için ayrı node havuzu, yük atma, büyütülmüş cache, okuma replikaları yalnız izinli sorgularda | Identity plane ölçeği; authority domain'leri cell'lere dağılır |

**Kırmızı çizgiler** (iki plane'de geçerli olanlar işaretli):
- Redis pub/sub ile iptal yayını (OP-19).
- İptal, oturum ve kilit sorgularını replica'ya yönlendirmek (OP-27).
- Mantıksal replikasyonla active-active / LWW (OP-28, iki plane).
- Quorum'suz çok-primary (iki plane).
- Kıtalar arası sync yazma.
- Tek standby ile `synchronous_commit=on` (OP-24, iki plane).
- Gömülü dağıtık cache (Infinispan/Hazelcast tarzı).
- Node başına bağımsız hesap bazlı limit (OP-35).
- Bloom filtresi tabanlı iptal listesi.
- DB'de duran acil durum admin hesabı (OP-46).
- Failover'da `400 invalid_grant` (OP-26).
- Fence kanıtı olmadan cross-cell promote (FA-13).

Boyutlandırma formülleri operatör belgesine girer ve cell parametreleriyle doldurulur. Statü: PD (fazlar), FROZEN (kırmızı çizgiler).

---

### 17.10 Yükseltme, göç, yedekleme ve DR

#### 17.10.1 OP-55 Şema göçü

| Kural | Ayrıntı |
|---|---|
| Ayrı göç işi | Şema değişikliği uygulama başlatmasına bırakılmaz. Göç ayrı, tekil bir Kubernetes Job veya komut olarak çalışır. Göç rolü tabloların sahibidir; uygulama rolü değildir (OP-12) |
| Expand/contract | Her sürüm ya yalnız genişletme ya yalnız daraltma içerir, ikisi birden olmaz. N-1 uyumluluğunun tek güvenli yolu budur |
| Kilit bilinci | `ALTER TABLE` varsayılanı en ağır kilittir. Tabloyu yeniden yazan formlar MVCC-güvensizdir ve 2× disk ister; kimlik verisi taşıyan tabloda kabul edilmez. Kısıtlar `NOT VALID` + ayrı `VALIDATE CONSTRAINT` ile eklenir. PG18'de `SET NOT NULL NOT VALID` aynı deseni boş olmama kısıtına genişletir |
| İndeks | Her zaman `CREATE INDEX CONCURRENTLY`, göç transaction'ının dışında |
| Araç | sqlx migrations. Down göçleri yalnız test içindir. Üretim geri alma planı PITR'dir, down göçü değildir. Dinamik şema adı kullanılmaz |
| Authority log | Domain log ve proof store tablolarında yeniden yazma gerektiren göç yasaktır. Zarf biçimi değişikliği yeni bir `versions` değeri ve activation record'u ile yapılır (OP-56); eski satırlar yeniden kodlanmaz (TI-11) |

Statü: FROZEN TECHNICAL.

#### 17.10.2 OP-56 Rolling upgrade, N-1 ve semantik sürüm kapısı

| Alan | Değer |
|---|---|
| Uyumluluk komutu | Binary, mevcut dağıtım metadata'sına karşı rolling upgrade'in mümkün olup olmadığını makine-okunur raporlar. Çıkış kodları: 0 = rolling mümkün, 3 = mümkün değil (recreate gerekir), 4 = ilgili özellik kapalı (Keycloak modeli). Operator ve CI bu kodla karar verir |
| N-1 (üç bileşen) | (1) Önceden karar veren uyumluluk metadata'sı; (2) uçucu durumun DB'de olması (OP-10); (3) cache geçersizleştirmesinin DB-destekli outbox ile yapılması (OP-20) |
| Leader seçimi sürüm kapısı | Sequencer leader'lığı, cell'de beyan edilen **aktif semantik sürüm kümesini** destekleyen node'larla sınırlıdır. Yeni bir semantik sürüm (core spec, meta-schema, profile; PI-21) ancak domain log'una bir **activation record** yazıldıktan sonra kullanılır. Activation record, ilgili domain'in yetkili meta-Exercise'ıdır veya provider'ın beyanlı sürüm aktivasyonudur. Ayrıntı §5/§6'dadır, burada yalnız operasyon sırası verilir. Sıra: (a) bütün node'lar yeni binary'ye geçer ama eski sürümle değerlendirir; (b) activation record commit edilir; (c) yeni sürüm değerlendirmesi başlar. Activation'dan önce yeni sürümü desteklemeyen node leader olamaz (çıkarım: activation record'un hangi Exercise türü olduğu §5/§6'nın kararıdır) |
| Golden vector CI kapısı | Deterministik CBOR encoder'ın, Merkle ve leaf hash'in ve COSE yapılarının bayt düzeyinde golden vector'leri her derlemede CI kapısıdır. Bir değişiklik vektörü bozarsa birleştirme engellenir (RT8, TI-RT12) |
| Derived | Derived yapılar yeni sürümde fold ile yeniden kurulur. rebuild-diff farkı sev-1'dir (TI-16, RT9) |
| Statü | FROZEN TECHNICAL |
| Garanti | Kayıtta hangi semantik sürümle değerlendirildiğinin görünmesi BS (`versions`, PI-21). Karışık sürümde iki node'un farklı semantikle commit etmemesi UDC (tek leader + sürüm kapısının uygulanması + activation pozisyonu). Olursa replay ile tespit BS (TI-RT12). Rolling upgrade'in kesintisizliği: UDC |

#### 17.10.3 OP-57 Yedekleme, PITR ve kurtarma tatbikatı

| Alan | Değer |
|---|---|
| Yedekleme | pgBackRest (veya wal-g): tam/fark/artımlı yedek, sürekli WAL arşivi, PITR, depo şifreleme, çoklu depo (yerel + bulut), depo bütünlük doğrulaması. Mantıksal döküm tek strateji olamaz |
| RPO bağlantısı | Authority: RPO residency sınıfına göre beyan edilir (T28; regional ↔ multi-region sync). Ayrıca revocation/CT3 kayıtları ack'ten önce provider dışı replica'dadır (SEC23). Identity: Faz 1'de AZ kaybında RPO = 0, async DR profilinde RPO > 0 (OP-29) |
| PITR ile authority log | PITR ile geri dönülen bir domain log'u witness'ın gördüğü checkpoint'in **gerisinde** kalabilir. Bu durumda restore edilen depo doğrudan trafiğe açılmaz. Eksik suffix replica'dan tamamlanır ve kök witness'taki checkpoint'le karşılaştırılır. Tamamlanamıyorsa yol `domain.recover`'dır (FR-0–FR-6; FA-10, U24). Restore, lineage'ı veya pozisyonu yeniden kullanamaz (INV-21, EI-20) |
| Kurtarma tatbikatı (zorunlu, periyodik; PD: çeyrekte bir) | 1. PITR ile belirli bir ana dönüş (yalnız tam restore değil). 2. İmza anahtarlarının tutarlı bir noktada birlikte geri gelmesi (anahtar ayrı sistemdeyse iki restore'un birleşmesi). 3. Restore sonrası JWKS'in aynı `kid`'leri sunması. 4. Göç sürümünün binary sürümüyle uyumu (eski DB + yeni binary). 5. Fark restore ile RTO ölçümü (paralellik ayarlı ve ayarsız). 6. Depo bütünlük doğrulaması. 7. Silme olgularının yeniden uygulanması (OP-42). 8. Authority log'unda zincir + Merkle + son witness'lı checkpoint karşılaştırması ve Genesis'ten fold ile rebuild-diff (FA-14). 9. Break-glass yolunun restore edilmiş ortamda çalışması (OP-46) |
| Statü | FROZEN (tatbikat maddeleri), PD (sıklık, araç) |
| Garanti | Restore'un yanlış lineage üretmemesi: BS (pozisyon yeniden kullanılmaz; witness karşılaştırması). Kayıpsız restore: UDC (replica beyanı, FA-10) |

#### 17.10.4 OP-58 İmza anahtarı DR

- İmza anahtarları DB'nin dışındadır ve **DB yedeğinden bağımsız** bir yedekleme yaşam döngüsüne sahiptir. Gerekçe asimetriktir: DB kaybı kullanıcı kaybıdır, anahtar kaybı bütün token ve oturumların ölmesi ve RP'lerin eski JWT'leri doğrulayamamasıdır.
- Authority plane: T20 + MD-6 hiyerarşisi (HSM'de quorum'lu binding key; domain başına ≤ 24 saatlik operasyonel anahtarlar) kök anahtarı kurtarılabilir kılar. Operasyonel anahtar kaybı yeni bir anahtarla devam edilerek kapatılır.
- **Dışa aktarılamayan bulut KMS kullanılıyorsa** çok bölgeli anahtar veya içe aktarılmış anahtar materyali zorunludur. Aksi halde bölge kaybı anahtar kaybıdır. Per-region KMS seçimi bu şartla yapılır.
- Identity JOSE anahtar rotasyonu: aktif / pasif / devre dışı modeli kullanılır. Pasif anahtar en uzun refresh token ömrü + RP JWKS cache TTL'i kadar yaşar. Rotasyon ayrıntısı → §15.
- Zitadel tipi "sonradan değiştirilemeyen ana anahtar" yoktur. Her KEK rotasyonla değiştirilebilir.
- Statü: FROZEN TECHNICAL. Garanti: UDC (FA-6).

#### 17.10.5 OP-59 Kiracı ve domain bazında geri yükleme

| Plane | Kural |
|---|---|
| Authority | Domain düzeyinde yeniden kurma mümkündür: domain log'u + body store + replica ile Genesis'ten fold yapılır. Kaynak cell'den bağımsız bir hedefte domain HANDOFF/ACCEPTANCE ile kabul edilir (§17.4.1). Pozisyon ve lineage korunur. Bu, "kiracı restore" değil, domain yeniden kurmadır |
| Identity | Satır düzeyinde realm/tenant restore **ürün özelliği olarak vaat edilmez** (HL-32). `pg_restore -t` bağımlılıkları ve yardımcı nesneleri getirmez, büyük nesnelerde ya hep ya hiç davranır. Belgelenen yol "yan restore + mantıksal kopyalama"dır: PITR ayrı bir örneğe yapılır, ilgili realm satırları bağımlılık sırasıyla kopyalanır, silme olguları yeniden uygulanır (OP-42) |
| Statü | FROZEN (vaat sınırı) |

---

### 17.11 Karar kaydı ve reconsider eşikleri

Karar metinleri §16.10'dadır (T1–T42). Burada yalnız "neden reddedildi" ve "ne zaman yeniden açılır" alanları verilir.

| T / OP | Alan | Reddedilenler (özet) | Reconsider if |
|---|---|---|---|
| T4 | Serialization | Çift kanonik kodlama; JSON+JCS kanonik; Protobuf kanonik | Ortak governance Work ile birlikte kodlamayı değiştirirse (PI-18) |
| T5 | Cryptography | Yalnız Ed25519; RSA varsayılan; kendi kripto | ML-DSA için COSE/JOSE kayıtları ve HSM desteği olgunlaşınca hibrit imza; MD-3: ML-DSA-65 opt-in zaten açık; ekleme domain'in kararıdır (SI-18). Kayıt statüsü doğrulanmadı |
| T8 | Persistence | CockroachDB/Spanner; FoundationDB; Kafka/event store as log; blockchain/BFT ledger | Tek domain'in sürekli commit hızı tek primary'yi aşarsa (**> ~5k/s ölçülürse**; tahmin, ölçüm değil) → FoundationDB veya domain-içi conflict-key bölümlemesi. Vaka kanıtı (Ory CRDB 230 ms, Kanidm LWW) dağıtık SQL ret gerekçesini güçlendirir (OP-28) |
| T6 | Coordination | Domain başına Raft grubu; DB SERIALIZABLE; pessimistic kilit | Ölçülen çakışma oranı yüksekse (hot budget node) → o key'ler için kuyruklu serial değerlendirme |
| T12 | Protocol implementation | Kapalı production evaluator + ayrı reference; yalnız spec | Bir üçüncü taraf bağımsız implementasyon yayınlarsa çapraz-implementasyon conformance zorunlu kapı olur |
| T13 | Restriction dili | OPA/Rego; XACML; özel DSL; Datalog/Biscuit (WATCH) | Cedar forbid-only + REQUIRE spike'ı başarısız olursa CEL profili (OQ-MD2) |
| T15 | Timers | Durable workflow engine; cron tabanlı state değişimi | — (semantiğe bağlı; değişmez) |
| T26 | Event backbone | Kafka; outbox'sız doğrudan yayın; CDC tek kaynak | Receiver hacmi NATS stream modelini aşarsa → Kafka bölümlemesi, yine derived |
| T40 | Search/analytics | Global search index; Elasticsearch; analytics'i karar girdisi yapmak | Search hacmi FTS'i aşarsa ayrı engine, yine derived ve viewer-rechecked |
| T35 | Runtime / language | Go kabuk + Rust kernel; plane'e göre dil; tek Go (§16.4.0) | **İlk 6 ayın sonunda AS çekirdeğinin OIDF conformance ilerlemesi tahminin (12–18 geliştirici-ayı) 2 katından fazla geride kalırsa** yalnız AS çekirdeği için ayrı Go süreci (Fosite) değerlendirilir |
| T36 | Infrastructure | Service mesh zorunluluğu; cloud-özel managed servislere protocol yolunda bağımlılık | — |
| T37 | Observability | Body/PII içeren log'lar; telemetriyi audit kaydı yerine kullanmak | — |
| T25 | Offline device security | Yazılım sayaçları; cihaz duvar saati | Platformlar standart güvenli saat API'si sunarsa clock class eklenir |
| T32 | Custody | MPC 2-of-2 (ayrı seçenek); düz HSM; yazılım anahtar deposu | HSM'ler WebAuthn doğrulamasını yerel destekler hale gelirse TEE çıkarılır |
| T33 | Rate limiting | Global senkron rate store; throttling'i gateway'de yapmak | — |
| OP-5 | Argon2 kütüphanesi | — | x86-64'te `argon2` crate'i ile `libargon2` farkı **%20'yi aşarsa** FFI değerlendirilir |
| OP-5 | SAML XML yığını | — | bergshamra ↔ samael/libxml2 spike sonucu; bergshamra test süiti kendi CI'da kırmızıya düşerse samael |
| OP-6 | İç RPC | — | ConnectRPC Rust olgunluğu yetersizse gRPC uyumlu Rust yığını (OQ-MD1) |
| OP-18 | Havuzlayıcı | — | PgBouncer ≥ 1.21 prepared statement davranışı sürücüyle doğrulanırsa sıcak yolda kullanılabilir |
| OP-37 | Authority Merkle shard | — | Authority log'unda tek Merkle ağacının kanıt maliyeti ölçülebilir sorun olursa yıllık shard (WATCH) |
| OP-48 | SQLite tek node | — | SQLite'ın tek-head CAS ve atomik birim şartını small-provider yükünde karşılamadığı gösterilirse PG zorunlu olur. SQLite yalnız identity plane içindir; authority'de SQLite (Suiss binary'si) ancak T8 açıkça değiştirilir ve OQ-1 doğrulaması geçerse açılır |

---

### 17.12 Açık sorular (→ §20)

| Kimlik | Konu | Sahip / not |
|---|---|---|
| **OQ-1** | ENGINEERING ASSUMPTION değerlerinin ölçümü: domain başına commit throughput ve p99, validation çakışma oranları, witness-before-ack dağılımı, ingest kuyruk yaşı, status list gecikmesi, hub tazelik maliyeti, offline cihaz sayaç/saat yetenek dağılımı, K-10 iş sınırı, NTS U değeri; T6/T8 reconsider eşiklerinin tetiklenip tetiklenmediği. **Ek:** OP-32 identity hedefleri, OP-9 batch boyutu, OP-38 identity MMD ≤ 1 s, OP-33 hash dışı CPU oranı | Engineering + SRE |
| **OQ-MD1** | Rust witness/NATS/SPIFFE istemci olgunluğu. **Genişletme:** ConnectRPC Rust implementasyonu, K8s operator/istemci kütüphaneleri, Rust PG sürücüsünün `target_session_attrs` semantiği (OP-26) | MD-20 |
| **OQ-MD2** | Cedar forbid-only + REQUIRE spike'ı (kernel etkisi §16.4.11) | MD-20; sahip §5/§6 |
| **OQ-MD3** | Identity plane outbox teslim algoritması: (A) xid8 watermark üzerinden polling ↔ (B) logical decoding / replication slot. İki aday ortak bir arıza senaryo setinde sınanır: ters commit sırası, uzun tx, retention'dan uzun tüketici kesintisi, tüketici restart, failover'da slot/cursor, çoklu tüketici. Sınanan değişmez OPI-1'dir. Bir senaryoda kaçırılmış iptal üretebilen aday elenir. "Son 5 saniyeyi yeniden tara" doğruluk mekanizması değildir, yalnız hızlandırıcı olabilir | MD-20; OP-20 |
| **OQ-MD4** | Kernel ↔ Wasm/FFI çağrı maliyeti (bilgi amaçlı, kapı değil) | MD-20 |
| — | İptal ve bayatlık sözleşmesi (doğrulama yolu × cache miss × partition × restart × azami bayatlık). MD-7 gereği her satır Δ/horizon beyanıyla guarantee matrisine girer (→ §13). Bu bölüm "cache-miss + DB yok" hücresini kapatır: derhal fail-closed (OPI-3, OP-45). Login/refresh hücreleri OP-26 ve OP-45 ile doldurulmuştur. Partition/restart hücreleri §13'e aittir | → §13 |
| — | Identity plane yetkilendirme cache'inde `READ COMMITTED` snapshot ve uçuştaki kararın geçerlilik anı | → §12/§13 (identity authz); authority plane'de karşılığı AuthorityStateBasis + `applied_pos`'tur, açık değildir |
| — | x86-64'te `argon2` ↔ `libargon2` farkı | OP-5 reconsider |
| — | Ölçüm boşlukları (allocator, PGO, io_uring, PG bağlantı eğrisi, PgBouncer prepared statement, ML-DSA hızları) | OQ-1'e katılır |
| — | bergshamra bağımlılık riski | RR-20; OP-5 |
| — | SAML SP gereksinim doğrulamasının kalanı (Workday ve tabloda "doğrulanmadı" işaretli hücreler; profiller §10.6.1). IdP tarafı SAML conformance süiti yokluğu SA-58 ile kapandı | → §10 |
| — | Ajanın veri modelindeki yeri, kiracı konfigürasyonunun kod olarak yönetimi, journey modeli kaydı, farklılaşma tablosu | → §7, §12, §1 (bu bölümün kapsamı dışında) |
| — | Suiss'in hosted bağımsız witness ve archival replica hizmeti; residency/DR sınıflarının paketlenmesi; self-host lisans/destek | → §18 (D5) / §20 |
| — | Status list `iat` ile operasyonel anahtar penceresinin rotasyon sınırında çakışması | → §15 |
| — | Sessiz domain'de heartbeat checkpoint'in açıkça yazılması: T16 ile kapanmış görünür (60 s heartbeat) | Kapalı sayılır (çıkarım; T16 metni "değişiklik olmasa da" der) |

---

### 17.13 Değişmez adayları ve §13'e aday satırlar

**Değişmezler (OPI-n).** OPI-1…OPI-6 kesin ID'lerdir (§0.4 ID aileleri). IDI veya SAI ailesinde karşılığı olan varsa yalnız "= IDI-n" çapraz notu düşülür.

| Aday | Metin | Kapsam | Dayanak |
|---|---|---|---|
| **OPI-1** | Bir outbox tüketicisinin ilerlemesi ile tüketicinin yeniden kurabildiği durum arasında boşluk yoktur. Kaçırılmış iptal üreten teslim algoritması kabul edilmez | Identity plane (authority'de (domain,pos) ile yapısal) | OP-20 |
| **OPI-2** | Asenkron replica'dan hiçbir güvenlik okuması yapılmaz (iki plane). Authority'de TI-5'in genişlemesidir | İki plane | TI-5; OP-27 |
| **OPI-3** | Cache-miss hiçbir zaman "iptal edilmemiş" anlamına gelmez. Doğruluk kaynağına ulaşılamıyorsa sonuç reddettir. Genişletilmiş metin: ne cache-miss ne de doğruluk kaynağına ulaşılamazken cache-hit "iptal edilmemiş" anlamına gelir; doğruluk kaynağına ulaşılamıyorsa sonuç reddettir (introspection'da `active=false`) | İki plane | MD-7, MD-8; OP-21, OP-45 |
| **OPI-4** | Identity plane güvenlik yazmaları (kimlik bilgisi, MFA, iptal, kilit, refresh rotasyonu, kaba kuvvet sayacı, yetki/rol) sync quorum'a ulaşmadan ack edilmez | Identity; small-provider profili hariç (OP-48, HL-40) | FA-1 eşleniği; OP-24 |
| **OPI-5** | Güvenlik durumunda last-writer-wins çakışma çözümü kullanılmaz | İki plane | OP-28 |
| **OPI-6** | Kabul edilen bir identity güvenlik değişikliği ve onun minimal denetim kaydı aynı transaction'dadır | Identity | T7 eşleniği; OP-10 |

**§13'e bağlanan ve §13'e aday garanti satırları**. Karşılığı olanlar §13 ID'sine bağlanmıştır. Karşılığı olmayanlar §13'te G60+/U60+/N-50+ aralığında numaralanır.

| Aday iddia | Önerilen sınıf | Koşul / not |
|---|---|---|
| Identity plane ack edilmiş güvenlik yazması AZ kaybında kaybolmaz | UDC | ≥ 2 sync standby, `ANY 1`, dürüst fsync (OP-24) → **U32** (identity plane dahil; §13'te U32 kapsamı genişletilir) |
| Identity plane iptali Access yüzeylerinde (login/refresh/introspection) polling aralığı içinde uygulanır | UDC | Outbox tüketicisi çalışır; primary erişilebilir; cache-miss → primary (OP-21); hedef değer EA → **U35** |
| Introspection yapmayan RS'te iptal | NG | Token ömrü kadar (HL-22) → **U36 / N-39** |
| Identity denetim log'unda yayımlanmış checkpoint'ten önceki değişikliğin tespiti | UDC / checkpoint öncesi NG | ≥ 1 bağımsız yayın hedefi (OP-37, HL-33) |
| Async DR profilinde identity veri kaybı | NG | Beyanlı RPO > 0 (HL-31) |
| Satır düzeyinde realm restore | NG (vaat yok) | HL-32 |
| Binding re-anchor sonrası eski binding altında yeni üretimin (checkpoint, excerpt, artefakt) kabul edilmemesi; prospektif, önceden issue edilmiş artefaktlar CR-45 RA-7'ye kadar T20 kuralıyla kabul | UDC | ≥ 1 dürüst witness; gelen algoritmayı doğrulayan witness (RB-0); kırılmadan önce yapılmışsa (OP-60, HL-34) |
| Break-glass yolunun authority kararı üretmemesi | BS | Ayrı kod yolu (OP-46, SI-22) |
| Karışık sürüm rolling upgrade'de farklı semantikle commit olmaması | UDC (sürüm kapısının uygulanması); kayıtta sürümün görünmesi ve replay ile tespit BS (PI-21, TI-RT12) | Sürüm kapısı + activation record (OP-56) |
| Small-provider profilinde ack edilmiş yazmanın node/disk kaybında korunması | NG | Beyanlı `durability: single-node` (OP-48, HL-40) |
| Identity DB erişilemezken introspection'ın `active=true` dönmemesi (cache-hit dahil) | BS (fail-closed kuralı) | OP-45 kural 3; → U37, §13.11 EP-3/EP-6, U39, RR-25 |

**İlgili HL ve RR'ler:** HL-22; HL-31…HL-34 (§13.5); HL-40; RR-18, RR-19, RR-20. HL-30 ve RR-40…RR-42 emekli ID'lerdir; yeniden kullanılmaz ve Ek A'da listelenir.

---

### 17.14 OP karar register'ı (OP-1–OP-71)

| OP | Konu | Statü | Garanti | Dayanak |
|---|---|---|---|---|
| OP-1 | Access Kernel içeriği/arayüzü | FROZEN (MD-1) / PD arayüz | UDC (CI kapısı + diferansiyel vektörler) | — |
| OP-2 | Süreç topolojisi | FROZEN | UDC | MD-6, MD-18 |
| OP-3 | Crate topolojisi + CI kapıları | FROZEN TECHNICAL | UDC (CI) | — |
| OP-4 | Build/panic profili | FROZEN TECHNICAL | UDC (lint + build profili) | MD-2 |
| OP-5 | Bağımlılık yığını ve yasaklar | PD / FROZEN (yasaklar) | — | — |
| OP-6 | Dış bağlamalar, iç RPC | FROZEN | BS (TI-17) | T35 (kolaylık API'leri cümlesi) |
| OP-7 | PostgreSQL 18 asgari | FROZEN TECHNICAL | — | — |
| OP-8 | Dilden bağımsız sertleştirme + profiller | FROZEN | UDC | MD-2 |
| OP-9 | Group commit zorunlu | FROZEN TECHNICAL / EA | BS (semantik değişmez) | — |
| OP-10 | Identity yazma yolu, atomik denetim outbox'ı | FROZEN TECHNICAL | UDC | — |
| OP-11 | PK ve dış kimlikler (UUIDv7, opak) | FROZEN TECHNICAL | BS (dış opaklık) | MD-18 |
| OP-12 | RLS FORCE, bileşik FK, önekli UNIQUE, SET LOCAL | FROZEN (MD-5) | UDC (ikincil katman); PK kuralı (authority `domain_id`) | — |
| OP-13 | Partitioning | PD | — | — |
| OP-14 | Sıcak satırlar | FROZEN TECHNICAL / PD | BS (T9) | — |
| OP-15 | İndeks kuralları | PD | — | — |
| OP-16 | UNLOGGED kuralı | FROZEN TECHNICAL | UDC | — |
| OP-17 | Append-only üç katman | FROZEN TECHNICAL | UDC (önleme) / BS (tespit, authority) | — |
| OP-18 | Havuz modu, SET LOCAL | FROZEN TECHNICAL / PD | UDC | — |
| OP-19 | Yasaklı taşıyıcılar | FROZEN TECHNICAL | BS | — |
| OP-20 | Identity outbox (algoritma açık) | FROZEN (değişmez) / açık | UDC | — |
| OP-21 | `session_epoch` + node cache | FROZEN (MD-7) | UDC / BS (cache-miss) | — |
| OP-22 | Olay kimliği ve sıralama | FROZEN | BS | — |
| OP-23 | NATS rolü, self-host'ta opsiyonel | FROZEN | BS | — |
| OP-24 | Sync replikasyon (`ANY 1`, ≥2 standby, `local` sınırı; small-provider hariç, OP-48) | FROZEN TECHNICAL | UDC / NG small-provider (HL-40) | — |
| OP-25 | Failover orkestratörü + fence şartı | PD / FROZEN | UDC | — |
| OP-26 | Failover'da istemci davranışı (503, asla invalid_grant) | FROZEN / PD | UDC | — |
| OP-27 | Read replica kuralı | FROZEN | UDC (sorgu yönlendirmesi); TI-5 BS | — |
| OP-28 | Çok bölge, LWW yasağı | FROZEN | UDC | — |
| OP-29 | Bölge kaybında plane'e göre davranış | FROZEN | UDC / NG (HL-31) | — |
| OP-30 | Veri yerleşimi | FROZEN | UDC | — |
| OP-31 | Sequencer graceful step-down | FROZEN TECHNICAL | BS (safety) | — |
| OP-32 | SLO/kapasite hedefleri | EA | NG | MD-19.6 |
| OP-33 | Argon2 parametreleri ve planlama | PD / FROZEN TECHNICAL | UDC (izolasyon) | — |
| OP-34 | İmza kapasitesi | EA | — | — |
| OP-35 | İki katmanlı rate limiting | FROZEN TECHNICAL / POLICY DEFAULT | BS (Katman B) / NG (Katman A) | — |
| OP-36 | Load shedding eşlemesi | FROZEN | BS (MD-8) | — |
| OP-37 | Identity denetim log'u bütünlük modeli | FROZEN TECHNICAL / WATCH | UDC / NG | — |
| OP-38 | Checkpoint aralığı beyanı + coalescing | POLICY DEFAULT / EA / FROZEN | BS (coalescing) | — |
| OP-39 | DENY ve başarısız deneme kaydı | FROZEN TECHNICAL | BS / UDC | — |
| OP-40 | Saklama ve katmanlama | POLICY DEFAULT / FROZEN | BS (header) / UDC | — |
| OP-41 | Dış formatlar ve export | FROZEN / PD | — | — |
| OP-42 | Silme, crypto-shred, restore sonrası yeniden shred | FROZEN TECHNICAL | NG (yayılım) / UDC | — |
| OP-43 | Kullanıcıya görünen denetim | PD | — | — |
| OP-44 | Örnekleme yasağı, denetime erişimin denetimi | FROZEN TECHNICAL | UDC | — |
| OP-45 | Identity bozulmuş modu | FROZEN / PD | BS (fail-open yok; introspection `active=false`) / NG (HL-22) | — |
| OP-46 | Operatör break-glass yolu (CMP-25) | FROZEN / PD | BS / NG (HL-2) | — |
| OP-47 | Telemetri kuralları, ClickHouse DERIVED | FROZEN / PD | BS (TI-18) | — |
| OP-48 | Dağıtım formları, tek binary/tek mod, SQLite yalnız identity tek node; small-provider dayanıklılık profili (beyanlı) | FROZEN / PD | BS (TI-17) / NG (HL-40) | — |
| OP-49 | Container imajı ve build | PD | — | — |
| OP-50 | K8s yaşam döngüsü | PD / FROZEN TECHNICAL | — | — |
| OP-51 | Helm, operator, GitOps | PD | — | — |
| OP-52 | Yapılandırma ve sırlar, fail-fast (small-provider'da beyan doğrulaması; sır bootstrap CR-35) | FROZEN / PD | UDC | — |
| OP-53 | Havuz boyutu ve soğuk başlatma | PD | — | — |
| OP-54 | Topoloji fazları, kırmızı çizgiler | PD / FROZEN | — | — |
| OP-55 | Şema göçü | FROZEN TECHNICAL | — | — |
| OP-56 | Rolling upgrade, N-1, sürüm kapısı, golden vector | FROZEN TECHNICAL | BS (`versions`, replay tespiti) / UDC (karışık sürümde commit yokluğu, kesintisizlik) | — |
| OP-57 | Yedekleme, PITR, tatbikat | FROZEN / PD | BS / UDC | — |
| OP-58 | İmza anahtarı DR | FROZEN TECHNICAL | UDC | — |
| OP-59 | Kiracı/domain bazında geri yükleme | FROZEN (vaat sınırı) | — / NG (HL-32) | — |
| OP-60 | Aynı provider içinde binding re-anchor (self-handover / aynı provider profili; RB-0…RB-6; §16.6.1) | FROZEN TECHNICAL | BS (root yetkisi) / UDC (fencing; prospektif `superseded-at`, CR-45 semantiği) / HL-34 | OQ-CR3 (kapandı), CR-45 (§15.18) |
| OP-61 | **Açık ve tekrarlanabilir ölçek ölçümü.** Yük testi düzeneği açık kaynak yayınlanır. Ölçülenler: hücre başına saniyede giriş, saniyede yetki kararı, p50/p99 gecikme, 100 milyon kullanıcılık veri seti, ani yük artışı, düğüm/AZ kaybı. Sonuçlar her sürümle ortam bilgisiyle (donanım, ayar, sürüm) yayınlanır. EA değerleri ölçüldükçe ölçülmüş değere geçer; ölçülmemiş sayı satış dilinde kullanılmaz (§3.3a, B15). İlk müşterilerle (tasarım ortakları) gerçek yük verisi toplanır. Gerekçe: canlı kanıt zamanla gelir; tekrarlanabilir ölçüm yeni ürüne doğrulanabilir güven verir | FROZEN TECHNICAL (açık düzenek, ortamlı yayın, ölçülmemiş sayı yasağı); EA (hedef değerler) | — | OQ-1; §4.10; §3.3a |
| OP-62 | Tek depo (SAML IdP test süiti ayrı depo, SA-58); klasör yapısı; `authority-*` ve `identity-*` crate'lerinin spec bileşenlerine göre bölünmesi (ihtiyaç doğdukça); bağımlılık yönü kuralları CI'da: plane'ler yalnız `internal-api` üzerinden konuşur, yardımcı servisler iç crate'lere bağımlı olamaz (§16.4.3a) | FROZEN TECHNICAL (tek depo, bağımlılık kuralları); PD (adlar) | UDC (CI kapısı) | OP-3; INV-12; SEC19; E24 |
| OP-63 | Kod içi mimari: crate başına `domain`/`ports`/`app`/`adapters` katmanları, saat ve rastgelelik port; sans-I/O protokol durum makineleri, bloklamayan async, zaman aşımları ve sınırlı kuyruklar; `UnitOfWork`, yalnız outbox ile dış etki, idempotency anahtarı; süreç ayarı ile kiracı ayarı ayrımı, güvenliği gevşeten bayrak yasağı (§16.4.3b) | FROZEN TECHNICAL (kalıplar, yasaklar); PD (adlar, değerler) | UDC | TI-3; TI-6; TI-7; TI-8; TI-9; TI-10; MD-14 |
| OP-64 | Kod kalitesi: kod, yorum, commit ve PR İngilizce (spec şimdilik Türkçe); rustfmt ve sabit toolchain; workspace lint'leri ve uyarı = hata; tipli kimlikler; tipli hatalar, karar ≠ hata, RFC 9457, iç ayrıntı sızmaz, numaralandırma-nötr; maskeleyen sır/PII tipleri; spec ID'li yorumlar, `SAFETY:` ve issue'lu `TODO` (§16.4.3c) | FROZEN TECHNICAL; PD (lint ayrıntıları) | UDC | OP-3; OP-4; OP-8; TN-96; §17.8 |
| OP-65 | API: beş aile (standart protokol, yönetim, karar, Frontend API, iç RPC); `/v1` ana sürüm, yalnız eklemeli değişiklik, Deprecation/Sunset; OpenAPI koddan üretilip commitlenir, CI eşitlik ve kırıcı değişiklik kapısı, SDK'lar ondan; iç RPC şema önce (`buf breaking`); ortak kurallar: RFC 9457, opak imleç, Idempotency-Key, ETag/If-Match, önekli opak kimlik, snake_case, RFC 3339, büyük sayı string, Request-Id, RateLimit (§16.4.6a) | FROZEN TECHNICAL; PD (araçlar) | UDC | OP-6; TN-110; TN-112; TN-133; MD-18 |
| OP-66 | Veri katmanı: ORM yok, derleme zamanında denetlenen SQL (`sqlx::query!`, offline meta veri); SQL yalnız `store`'da; göç adlandırma, değişmezlik ve PR kontrol listesi; CI şema güvenlik testleri (RLS FORCE, PK öneki, append-only, rol sahipliği); gerçek Postgres ile paralel testler, builder ile test verisi, üretim verisi yasağı; `CHECK`'li text durumlar, sınırlı JSONB, sorgu planı kapısı (§17.2.9) | FROZEN TECHNICAL; PD (araçlar) | UDC | OP-12; OP-15; OP-17; OP-55; OP-63 |
| OP-67 | Gözlemlenebilirlik kod kuralları: W3C `traceparent` korelasyonu bütün süreçlerde; ortak log alanları ve kalıcı olay adları; iç ağda `/livez`, `/readyz` ve metrik, hazır olmayan süreç trafik almaz; yerel izleme yığını; her alarm bir runbook'a bağlı (§17.8.3) | FROZEN TECHNICAL; PD (alanlar, araçlar) | UDC | OP-47; OP-65; MD-8 |
| OP-68 | Sürümleme ve CI: ürün SemVer'i ile protokol semantik sürümü ayrı; sunucu+servisler ortak sürüm, SDK'lar kendi SemVer'i ve uyumluluk tablosu, son iki minor güvenlik desteği; PR / gece / sürüm CI aşamaları; derleme önbelleği ve değişene göre test; Conventional Commits ile üretilen CHANGELOG, ayrı güvenlik başlığı; amd64/arm64 imzalı imajlar, trusted publishing (§16.4.4a) | FROZEN TECHNICAL; PD (araçlar, destek penceresi) | UDC | F-4…F-10; SA-36…SA-39; OP-56; SA-59 |
| OP-69 | Geliştirici deneyimi: `just dev` ile tek komutluk yerel ortam (Postgres, NATS, SoftHSM, KMS taklidi, Mailpit, izleme); geliştirme modu yok, yerel karşılıklar kullanılır (TI-9); yerel ve CI aynı `just` komutları; `bacon` ve hafif pre-commit; `just gen` ile üretilen dosyalar commitlenir ve CI'da denetlenir; 15 dakikalık ilk gün (§16.4.4b) | FROZEN TECHNICAL; PD (araçlar) | UDC | TI-9; OP-65; OP-67; B24 |
| OP-70 | Dokümantasyon: spec `docs/spec/` altında bölüm başına dosya (İngilizce dosya adları), içerik ve ID'ler değişmez, içindekiler sayfası; kök README İngilizce kısa tanıtım; ayrı ADR yok, kayıt tabloları karar kaydıdır ve “decision” etiketli PR ile güncellenir; Mermaid C4 diyagramları; üretilen API/kod dokümanı; alarm başına runbook; İngilizce dokümanlar, spec şimdilik Türkçe, ilk çeviri “Kısaca Access” (§16.4.4c) | FROZEN TECHNICAL; PD (araçlar) | — | OP-64; OP-65; OP-67; OP-2 |
| OP-71 | Süreç: trunk-based, kısa ömürlü dallar, yalnız squash merge, doğrusal `main`; Claude PR açar, Adem inceleyip birleştirir (onay sayısı kuralı kullanılmaz); PR şablonu, ≤ 400 satır hedefi, `decision` etiketi; güvenlik bildirimi özel kanaldan; `main` koruması, push protection, CODEOWNERS ve hassas yol etiketi; CONTRIBUTING, CODE_OF_CONDUCT, SECURITY (§16.4.4d) | FROZEN TECHNICAL; PD (şablonlar) | — | SA-60; SA-14; OP-70; OP-68 |

---

### 17.15 Bu bölümlerde doğrulanamayan iddialar

1. **EA değerleri ölçülmedi:** OP-32 tablosunun tamamı (kapasite sayıları ve gecikme bütçesi), FA-3 ≤ 250 ms, identity MMD ≤ 1 s, telemetri 90 gün. OQ-1.
2. **Hesaplar:** "batch'siz AZ-sync ~0,5–1k tx/s" ve T8 eşiği "> ~5k/s" birer tahmindir.
3. **Ölçümler tek ortamdadır** (Apple M4, Docker). Örnekler: UUIDv7 1,67× ve %26; RLS %4,4 ve EXISTS %18,6; Argon2 8,95 ms, 4,02× ve p99 25×; imza µs değerleri; `jsonwebtoken` 1,91×. Hash-chained 5.898 ↔ 22.441 tps ölçümü henüz yeniden üretilmedi.
4. **Üçüncü taraf kaynakları:**
   - Bölgeler arası p99 47/84/130 ms, EDB sync maliyeti, Patroni ~25 s, CRDB 230 ms ve follower read ≥ 4,2 s, Keycloak 26.3 1.076 ms.
   - Keycloak sizing (vCPU başına 15 login/s, 120 refresh/s; 286 vCPU).
   - musl 30× yavaşlama raporu (2020).
5. **Tarih ve sürümler doğrulanmadı:**
   - Bitnami 28 Ağustos 2025; QLDB 31 Temmuz 2025; EDPB 16 Ocak 2025; CVE-2024-52289 zaman çizelgesi; RUSTSEC-2026-0136.
   - OCSF 1.9.0 sınıf numaraları; RFC 9967 statüsü; OTel semconv 1.44; PG18 fast-path commit `c4d5cb71d`.
   - Crate sürümleri (8 Eylül 2026 çekimi).
   - CRA tarihleri: bu bölümde tekrarlanmadı (→ §14/§18.11).
6. **Ölçek ve maliyet tahminleri:** 1.200 şema / 383 ms ve 20k şema `pg_dump` > 24 saat; Sunlight ~10k$/yıl; Tessera ~10k yazma/s.
7. **Ekosistem ve olgunluk tahminleri:**
   - MD-1 bedeli: AS 12–18 geliştirici-ayı ve efor tahmini 46–73 ↔ 31–49 geliştirici-ayı (HYPOTHESIS).
   - aws-lc-rs'in `no_std`/Wasm hedefinde derlenmesi (OP-1 çıkarımı).
   - Rust PG sürücüsünün `target_session_attrs` semantiği; PgBouncer ≥ 1.21 prepared statement davranışı.
   - ConnectRPC Rust olgunluğu; Go ekosistem olgunluğu iddiası ("?").
8. **Çıkarımlar (birincil dayanağı yok, bu bölümde türetildi):**
   - OP-1 kripto arka uç ayrımı.
   - OP-2 small-provider'da süreç sınırlarının korunması (OP-48).
   - OP-8 TS `bigint` kuralı.
   - OP-37 authority shard'ı WATCH.
   - CMP-22b'de cell başına denetim anahtarı (§17.6.5).
   - Başarısız denemenin Katman B sayacıyla aynı tx'te yazılması (OP-39).
   - KMS yedeğinin shred listesine tabi olması (OP-42).
   - SQLite'ın TI-17'yi karşılaması (OP-48). Yalnız identity plane tek node ve third-party provider için; Suiss authority deposu PostgreSQL ≥ 18'dir.
   - Sequencer havuzu (OP-53).
   - Activation record'un Exercise türü (OP-56).
   - Sessiz domain'de heartbeat checkpoint sorusunun T16 ile kapanmış sayılması (§17.12).
