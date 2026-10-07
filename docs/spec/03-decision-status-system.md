## 3. Decision Status System

### 3.1 Statüler

Her karar tam olarak bir statü taşır.

| Statü | Anlam | Kapsadığı aileler | Değişim / reopen koşulu |
|---|---|---|---|
| CANONICAL INVARIANT (semantic, ecosystem, experience, protocol, security, technical) | Asla ihlal edilmez; implementasyon bunu korumak zorundadır | CI (INV metni kanoniktir), INV, EI, XI, PI, SI, TI, TI-RT | §3.2 |
| MERKEZİ KARAR | Bütün bölümleri bağlayan merkezi mimari karar (§0.2) | MD-1–MD-20 | Yalnız §3.2'deki dört koşul |
| FROZEN PRODUCT DECISION (thesis, ontology, ownership, deneyim, security) | Bağlayıcı ürün kararı | F, C, E, X, SEC | §3.2 |
| FROZEN LANDSCAPE DECISION | Landscape'ten öğrenilen | L; MKT'nin landscape kararları (§4.13) | Yeni contradiction veya atıf yapılan standardın statüsünün değişmesi |
| FROZEN PROTOCOL DECISION | Protocol kararı | P (+ AP-1–AP-15 yüzeyi) | §3.2 + protocol governance (§9.17) |
| FROZEN TECHNICAL DECISION | Mimari ve teknoloji | T, RT; bölüm aileleri IDP (§10), AG (§11), TN (§12), SA (§14), CR (§15), OP (§17) — her satır statüsünü açıkça yazar | Ölçümle kanıtlanmış sınır, contradiction veya materially stronger evidence ("Reconsider if" gerekçesi) |
| FROZEN STRATEGY DECISION | Frozen bir karardan türeyen ticari kural | B | Türetildiği kararın reopen koşulu; pazar kanıtı B'yi açmaz |
| POLICY DEFAULT | Suiss-hosted şablon değeri; semantik değildir | §13'teki değerler + IDP, AG, TN, SA, CR, OP ailelerinin PD satırları | Kalibrasyon (OQ-2); sıkılaştırma narrowing, gevşetme genişletme sınıfıdır (SI-18) |
| ENGINEERING ASSUMPTION | Ölçülecek sayı | Latency/kapasite hedefleri, commit başı iş sınırı, saat belirsizliği hedefi, etkileşimli revoke'un kısa intent validity değeri (tavanı POLICY DEFAULT'tur); identity plane performans hedefi (§4.10). Efor tahminleri (§18.13) EA değil, HYPOTHESIS (tahmin, ölçüm değil) etiketi taşır | Ölçüm (OQ-1); benchmark alt koşulu §3.1d |
| DECLARED PHYSICAL ASSUMPTION | Mimarinin dayandığı fiziksel varsayım | FA-1–FA-14 | İhlal sonucu FA tablosunda beyan edilir (§16) |
| KNOWN HARD LIMIT | NG / PU sınırı | HL ailesi (kanonik liste §13.5, metin §16.9; emekli kopya ID'ler → kanonik ID, Ek A) | Değişmez; vaat edilemez (RT28, B15) |
| CURRENT UX HYPOTHESIS | Kullanıcı davranışı varsayımı | §8.4 | Kullanıcı araştırması (OQ-6) |
| CURRENT STRATEGIC HYPOTHESIS | Pazar varsayımı | H1–H17 (H13a/H13b dahil); farklılaşma hipotezleri MKT-D1–MKT-D17 (§4.7) | Market, sales, pilot veya ekosistem kanıtı (OQ-3, OQ-4) |
| RECOMMENDED DEFAULT (Adem kararı) | Freeze edilmez; B sınırı içinde kalır | D1–D9, D-10 (MD-12), D-11 (aday, §18.9) | Adem kararı (OQ-7) |
| OPEN / FUTURE TEST | Blocker olmayan izleme | Future Design Tests (§20) | Standart olgunlaşması (OQ-5) |
| OPEN — COMPONENT-BLOCKING | Kanıtı henüz bulunmayan ve uygulanabilir algoritması yazılmamış teknik karar. Ertelenmiş değildir. İlgili bileşenin implementasyonu kapanmadan başlamaz; I/O içermeyen çekirdek ve iskelet bağımsız ilerleyebilir | ör. OQ-MD3 (identity plane outbox teslim algoritması) | Kapatma kanıtı (kabul testi + karşı örnek matrisi) |
| WATCH | Fikir kaynağıdır, bağımlılık değildir; draft'lar standart gibi ele alınmaz | L27 ve §4.3/§4.4'teki WATCH satırları; envanter (§4.6) güncellemesi | Standart veya pazar statüsünün değişmesi |
| CANONICAL INVARIANT ADAYI — PROPOSED FOR FREEZE | Identity, ajan, kiracılık/oturum, güvence ve operasyon alanlarının invariant adayı. §6 bunlara yalnız işaret eder. FREEZE kararı verilene kadar CANONICAL INVARIANT değildir. Yine de implementasyon bunları ihlal etmez. REJECT edilen aday bağlayıcılığını kaybeder | IDI (identity), AGI (ajan), TNI (kiracılık/oturum), SAI (güvence), OPI (operasyon, §17); INV-32–INV-41 (§6.9); EI-25–EI-27 (§7.8); XI-23–XI-26 (§8.19) | FREEZE veya REJECT kararı |
| SECURITY CONTROL, NOT PRODUCT PRIMITIVE | Assurance yöntemi | Formal verification (T38; Kani hedefleri MD-15) | Freeze veya reopen kapısı değildir (F20) |

#### 3.1b DAY-1 niteliği

**IRREVERSIBLE / DAY-1** bir statü değildir; statüye dik bir niteliktir. Anlamı şudur: sonradan değiştirme maliyeti ya uygulanabilir değildir ya da bütün kurulumu durduran bir göç gerektirir. Bu yüzden karar implementasyondan önce kilitlenir. Kayıt satırında statünün yanında yazılır ("FROZEN TECHNICAL · DAY-1").

- Identity plane'in aşağıdaki tablodaki 30 gün-1 kararının hepsi DAY-1 taşır.
- MD'lerde açıkça gün-1 diye yazılanlar da DAY-1 taşır:
  - `algorithm` alanı ve JWKS'te `AKP` modellemesi (MD-3)
  - identity plane, derived, PII vault ve operasyon depolarında PK'de `tenant_id` (+ `realm_id`) ve RLS FORCE; authority canonical log ve kayıtlarında `domain_id`; bileşik FK (MD-5; OP-12)
- Authority plane'in diğer kararlarından DAY-1 taşıyanlar ilgili bölümde işaretlenir.

Gün-1 kararlarının spec'teki yeri aşağıdadır. Register ailesi §19'dadır.

| # | Konu | Yer |
|---|---|---|
| 1, 2, 3, 6, 7, 9 | `tenant_id` PK'de, bileşik FK, RLS FORCE, kiracı-yerel benzersizlik, değişmez slug, `placement_id` | §12 (MD-5); authority log anahtarı `domain_id`'dir (§17 OP-12) |
| 4, 25 | Kiracı/realm başına imza anahtarı; anahtarlar DB dışında, bağımsız yedek | §15 (MD-3, MD-6) |
| 5, 30 | Global benzersiz ve sunucu üretimi `client_id`, ayrı `display_name` | §10 / §12 |
| 8 | Subdomain issuer, RFC 9207 `iss` | §10 / §12 |
| 10, 23, 26 | Partition'lı audit, audit outbox, ayrı göç job'ı | §17 |
| 11 | Opak kimlik tabanlı yetkilendirme | §12 / §16 |
| 12, 13 | WebAuthn RP ID, `user.id` | §10 |
| 14 | Kullanıcı kimliği yeniden kullanılmaz; e-posta kimlik değildir | §12 (MD-5) |
| 15 | I/O'suz çekirdek, CI'da zorlanır | §16 (MD-1 Kernel) |
| 16 | Tipli kimlik doğrulama durum makinesi | §10 |
| 17 | Kullanıcı başına DEK | §15 / §17 |
| 18 | Üç epoch | MD-7 → §9.12, §12, §13 |
| 19, 28 | Kiracı kodu yok; script çalıştırmayan kabuk | §2.8 #15, F23; ayrıntı §12 |
| 20 | Kendi yüzeyde session cookie | §12 |
| 21 | Ayrı platform-admin / realm-admin API | §2.2.2, MD-14 → §12 |
| 22 | Veri katmanında tipli yetki filtresi | §12 / §16 |
| 24 | Tam dizge `redirect_uri` | §2.8 #16; ayrıntı §10 |
| 27 | PostgreSQL 18 asgari | §16 / §17 |
| 29 | Tema kaydı | §12 |

#### 3.1c Karar kaydı alanları

Kapsam: her FROZEN TECHNICAL karar (T, RT, IDP, AG, TN, SA, CR, OP) ve her MKT landscape kararı. Bu kararlar şu alanları taşır:

| Alan | İçerik |
|---|---|
| Kimlik | Kararlı ID |
| Statü | §3.1'deki tek statü (+ varsa DAY-1) |
| Karar | Normatif metin |
| Gerekçe (Why) | 1–3 cümle |
| Reddedilenler (Rejected) | Alternatifler ve neden |
| Geçerlilik koşulu | Kararın dayandığı ölçülmüş veya beyan edilmiş özellik |
| **Kabul testi** | Kararı sabitleyen test veya test dosyası |
| **Geçersiz kılacak karşı örnek veya test sonucu** | Kararı yeniden açtıracak somut gözlem |
| Reconsider if | §3.2 koşullarından hangisine dayanacağı |
| Garanti sınıfı | Uygunsa BS / UDC / NG / PU |

Bir kararın yanlış çıktığı noktalar tipik olarak "karşı örnek" alanının boş olduğu yerlerdir. Bu nedenle alan zorunludur. Kabul testi ve karşı örnek alanları henüz dolmamış T/RT kararları §19 register'ında "doldurulacak" olarak işaretlenir. Bu alanların sonradan doldurulması bir reopen değildir.

#### 3.1d Benchmark alt koşulu

ENGINEERING ASSUMPTION olan her performans sayısı ve benchmark değeri şu kurallara uyar:
- Kod, ham çıktı ve koşum komutu repoda bulunana kadar **"yeniden üretim bekliyor"** etiketi taşır.
- Ölçüm ortamı (donanım, yazılım sürümü, bağlantı sayısı, süre) sayının yanında yazılır.
- Mutlak değerler ürün iddiası değildir. Kapasite, maliyet veya rakip karşılaştırması için kullanılamaz.
- Yalnız aynı koşumdaki karşılaştırmalı oran taşınabilir. Oran da aynı etiketi taşır.
- Örnek: identity plane audit log ölçümü 12 saniyelik pgbench koşumudur (Apple M4, Docker PostgreSQL 18.6, 8 bağlantı) ve "yeniden üretim bekliyor" etiketlidir.

### 3.2 Reopen koşulları

Bir CANONICAL INVARIANT veya FROZEN karar yalnız şu durumlardan biriyle yeniden açılır:

1. Başka bir canonical/frozen kararla **gerçek contradiction** (aynı fact için iki owner, aynı ismin iki anlamı, iki source of truth).
2. **Semantik veya fiziksel imkânsızlık** (karar fiziksel olarak sağlanamayan bir guarantee vaat ediyor).
3. **Materially stronger evidence** (karar dayandığı varsayımın yanlış olduğunu gösteren somut, ölçülmüş kanıt).

Pazar kanıtı, fiyat baskısı veya bir hipotezin çürümesi frozen bir kararı açmaz (B1). Formal model bir counterexample bulursa bu (1) veya (2) için kanıttır; formal model kendisi bir freeze veya reopen kuralı değildir.

MERKEZİ KARARLAR (MD-1–MD-20) ile IDP, AG, TN, SA, CR, OP ailelerinin ve F21–F23'ün FROZEN kararları için dördüncü bir koşul da geçerlidir: (4) sonraki katmanda ortaya çıkan zorunlu model açığı. "Başka türlü de yapılabilir", "vendor farklı yapıyor", "implementation zor" reopen gerekçesi değildir.

Formal model iki katmanlı uygulanır. (a) Model counterexample'ı frozen semantiği yalnız bu bölümdeki koşulla açar. (b) Bir semantik sürüm, vektörleri, differential random testing'i (DRT) ve kanıtları geçmeden release edilmez. DRT'nin spec boyunca tek açılımı budur: Rust Kernel ↔ Lean yürütülebilir model (veya bağımsız oracle) arasında diferansiyel rastgele test (§14.8, §15.19.5). (b) bir release kapısıdır, reopen kapısı değildir.

**"Açık" ne demektir.** "Açık", ertelenmiş değil, kanıtı henüz bulunmayan ve uygulanabilir algoritması henüz yazılmamış anlamındadır. Spec bunu iki statüye ayırır. OQ-1–OQ-7 ampirik, pazar veya Adem kararıdır ve implementation'ı bloklamaz (OPEN / FUTURE TEST). Açık teknik kararlar (ör. iptal/bayatlık ve outbox teslim algoritmaları, OQ-MD3) ise ilgili bileşeni bloklar (OPEN — COMPONENT-BLOCKING). §20'deki her açık soru "Implementation'ı bloklar mı?" sütununu doldurur.

### 3.3 Guarantee sınıfları

Her güvenlik ve davranış iddiası tam olarak bir sınıftadır; iki yönlü iddialar iki satır olarak yazılır (SEC2). Guarantee etiketi olarak yalnız bu sınıflar kullanılır.

| Sınıf | Kısa | Anlam |
|---|---|---|
| GUARANTEED BY SEMANTICS | BS | Kayıtların ve kuralların tanımından çıkar; hiçbir operasyonel koşula bağlı değildir |
| GUARANTEED UNDER DECLARED CAPABILITY / POLICY | UDC | Yalnız beyan edilmiş bir capability (verifier profile, witness, replica, PEP conformance) veya POLICY DEFAULT varken geçerlidir; koşul satırda yazılıdır |
| NOT GUARANTEED | NG | Access vaat etmez; ürün dili bunu garanti diliyle söyleyemez (XI-12) |
| PHYSICALLY UNSATISFIABLE | PU | Hiçbir mimari sağlayamaz (ör. revocation'ın çalışan effect'i durdurması) |

#### 3.3a İddia dili: izin verilen ve verilmeyen ifadeler

Aşağıdaki "izin verilen / verilmeyen ifade" tablosu guarantee sınıflarının ürün dilindeki karşılığıdır. Satırlar §13'teki asla-vaat-edilmez listesine, §8'deki forbidden UI claims listesine ve B15'e eklenir. Ayrıntılı UI karşılıkları §8 ve §13'tedir.

| Konu | İzin verilen | İzin verilmeyen |
|---|---|---|
| Formel doğrulama (genel) | "Authority algebra'sının Lean modeli ve kernel'in belirli fonksiyonları (Kani hedefleri) makine kontrolünden geçirilmiştir; protokol durum makinesi sınırlı model kontrolüne ve conformance süitine tabidir; HTTP ve depolama katmanları fuzz ve deterministik concurrency testine tabidir." | "Access formel olarak doğrulanmıştır." |
| Kripto doğrulama (Kobeissi R4) | "Ed25519 ve P-256 (ES256) imza primitifleri, aws-lc-rs içinde s2n-bignum HOL Light fonksiyonel doğruluk ve sabit zaman ispatları olan implementasyonları kullanır; ML-DSA-65 bu ispat kapsamı dışındadır; parola hash'leme, protokol mantığı ve derleme süreci doğrulama sınırının dışındadır." Kapsam algoritma bazında §15.19.7 ve HL-29'dadır (birincil kaynaktan doğrulanmadı) | Niteliksiz "formally verified". Bu ifade doğrulama sınırı donanıma indirilmiş sistemlere (CompCert, seL4 sınıfı) saklıdır |
| Kiracı izolasyonu | "Belirli yanlış kullanımlar derleme aşamasında engellenir; izolasyonun asıl savunması RLS FORCE, bileşik FK ve realm-kapsamlı anahtarlardır." | "Kiracı izolasyonunu bütünüyle derleyici garanti eder." |
| Performans | "Aynı donanım bütçesinde ve aynı Argon2 maliyetiyle hedef: X (yeniden üretim bekliyor)." | Domain/realm başına throughput garantisi; rakipten "daha hızlı" iddiası (B15) |
| Argon2 / parola | "Parola hash'leme doğrulanmış implementasyon kapsamı dışındadır." (Argon2'nin doğrulanmış implementasyonu hiçbir dilde yok) | "Parola saklama formel olarak doğrulanmıştır." |
| Passkey | "Passkey origin'e bağlıdır ve oltalamaya dayanıklıdır." | "Passkey hesabı ele geçirilemez yapar." (oturum token hırsızlığı ayrı tehdittir) |

### 3.4 Hipotez → invariant sızıntısı kontrolü

Şu öğeler invariant dilinde yazılmaz ve yazılmamıştır: landscape'teki standart statüleri ("kayıt statüsü doğrulanmadı" etiketleri korunur), MD-3'ün post-quantum satırı (ML-DSA-65 opt-in profil) ve §15'in PQC alt bölümü, §13'teki POLICY DEFAULT değerleri, ENGINEERING ASSUMPTION sayıları, H1–H17 ve D1–D9 (+D-10, D-11), farklılaşma hipotezleri (MKT-D1–MKT-D17) ve IdP pazar envanterindeki tarih, sürüm ve fiyat bilgileri. Issuer sırası kaynaklarında yalnız açık `supersedes` zinciri, Party key-event pozisyonu ve taşıyıcı profilinin ayrıca tanımladığı monoton sıra alanı normatiftir; bunların hiçbiri yoksa sıra belirsizdir ve disqualifying kazanır (TI-RT7).

**"Örnek bulunamadı ≠ ilk biz" kuralı**. "Yayımlanmış bir örnek bulunamadı" ifadesi "Access bunu ilk yapan olacak" sonucuna dönüştürülmez. İkincisi ayrı bir iddiadır ve ayrı kanıt gerektirir. Bu kural Access'in "kanıt seviyesi: reviewed landscape; evrensel yokluk iddiası değil" etiketiyle (L1, L2) aynı hastalığa karşıdır. İkisi birlikte uygulanır. Bir farklılaşma iddiası her zaman üç şeyi beyan eder: karşılaştırma kümesi, tarih ve geçersiz kılacak karşı örnek (§4.7). MD-13'ün "authority plane'i olan tek ürün" ifadesi de bu kurala tabidir (§2.1 notu).
