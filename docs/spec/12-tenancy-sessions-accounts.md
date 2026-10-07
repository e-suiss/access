## 12. Kiracılık, Oturum, Hesap Yaşam Döngüsü, Giriş UX ve Yönetim API'si

> **Bağlayıcı merkezî kararlar:** MD-5, MD-6, MD-7, MD-8, MD-9, MD-13, MD-14, MD-18 (ve dolaylı MD-1, MD-2, MD-3, MD-17, MD-19.6). **ID aileleri:** karar `TN-n`, invariant adayı `TNI-n`. HL/RR/guarantee satırları burada numaralanmaz; "§13'e aday" olarak önerilir (§12.10).

### 12.0 Kapsam, plane ataması, terimler ve okuma kuralları

#### 12.0.1 Bu bölüm neyi kapsar

Bu bölüm ürünün **identity plane** tarafındaki işletim yüzeyini ve bu yüzeyin **authority plane** ile dikiş yerlerini tanımlar:

- Kiracılık modeli, Identity Realm'in issuer/anahtar/RP ID kararları, veri izolasyonu ve izolasyon testleri (12.1).
- Identity plane oturumu, sender-constraint (DPoP/mTLS/DBSC), sinyaller (SSF/CAEP/RISC/SCIM olayları), step-up ↔ REQUIRE_ACTION köprüsü, risk ve olay müdahalesi (12.2).
- Hesap yaşam döngüsü: durumlar, kurtarma, bağlama/birleştirme, destek erişimi, silme/tombstone/saklama/taşınabilirlik, kayıt ve enumeration, IdP göçü, B2B organizasyon akışları (12.3).
- Giriş akışları, markalama ve erişilebilirlik/yerelleştirme (12.4).
- Yönetim API'si, devredilmiş yönetim, yapılandırma/GitOps, toplu işlem ve konsol oturumu (12.5).
- İstisnai yetki (destek delegasyonu, break-glass, sahiplik devri, kurtarma gücü) için ortak görünüm (12.6).

Access ürün deneyiminin authority yüzeyleri (S1–S10, durum merdiveni, explain ekranı, agent normları) **→ §8**; ekosistem/ownership matrisi ve seam'ler **→ §7**. Bu bölüm o konulara yalnız dikiş yerinde değer ve bunu açıkça işaretler.

#### 12.0.2 Plane ataması (MD-13) ve L28

Access tam bir IdP'dir (identity plane) ve onun üstünde authority plane'i olan tek üründür (MD-13). Bu bölümdeki her nesne ve her karar şu iki plane'den birine atanır:

| Plane | Bu bölümdeki nesneler | Authority'ye etkisi |
|---|---|---|
| **Identity plane** | Tenant kaydı, Identity Realm, Cell yerleşimi, user record, credential (parola hash'i, passkey, TOTP sırrı, kurtarma kodu), login tanımlayıcısı, identity plane oturumu (login oturumu, BFF çerezi, DBSC oturumu), OAuth/OIDC/SAML client, upstream IdP bağlantısı, davet, doğrulanmış alan adı kaydı, IdentityBinding kaydı, realm JOSE anahtarları, risk sinyali, CAEP/SSF vericisi ve alıcısı, ajan credential broker'ı / token vault | Yalnız Claim (E5, TI-15) veya ADP `commit` üzerinden bir Exercise ile. Identity plane nesnesi **primitive değildir** (§5). |
| **Authority plane** | Party, Instance, Anchor, Grant, Acceptance, Mandate, Exercise, RestrictionPolicy; AIS; ValidityContract; Domain Metadata | Tek pozitif kaynak Grant'tır; her şey daraltır (CI-2). |

- **L28** → §4.2 L28 (kanonik metin). Bu bölümün kısa plane ataması: login oturumu, DBSC, CAEP vericisi/alıcısı, risk tabanlı step-up (risk yalnız daraltır, CI-2) ve ajan credential broker'ı / token vault **identity plane**'dedir. Upstream token teslimi: release kararı bir Exercise'tır; upstream token Access projection'ı değildir, içeriği NOT GUARANTEED, CT2+ varsayılanı broker-as-PEP, `exp` ≤ ValidityContract horizon. PAM, sır kasası, fraud scoring, DLP, SIEM ayrı ürün katmanlarıdır; trusted rendering ve instruction-provenance gerçek dış sahiplerdedir (→ §4.2).

#### 12.0.3 Terim: "oturum"

"Oturum" login oturumu anlamında da kullanılır; "session/oturum" §8.11'de çakışan terim olarak işaretlidir. Bu spec şu eşlemeyi kullanır:

- **Identity plane oturumu** (spec terimi): identity plane'in bir tarayıcı, mobil uygulama veya CLI için tuttuğu authenticated bağlam kaydıdır. Boşta kalma ve mutlak ömür, olay tabanlı iptal ve `session_epoch` bu kayda aittir.
- **İnsan Instance'ı**: domain kapsamlı authority primitive'idir; oturumun bağlı olduğu authority-binding bağlamıdır. Oturum Instance değildir, Instance da oturum değildir. **Kardinalite:** bir identity plane oturumu, cihaz başına ve kullanıldığı **her domain başına** (yönetişim domain'i + her tüketen domain) **en çok bir** insan Instance'ına, aynı KeyBinding üzerinden bağlanır (bağ bir değerdir; yeni nesne yoktur). Instance domain kapsamlıdır; bir domain'de Instance'sız oturum meşrudur. Sürekliliği KeyBinding (DPoP anahtarı, DBSC anahtarı, mTLS sertifikası) taşır (INV-13, L21). Oturumu yenilemek veya oturum ömrünün dolması yeni Instance değildir; boşta kalma/mutlak sınırlar authority tarafında **authentication Claim tazeliği** olarak ifade edilir (C8); ayrı bir "authority oturumu" nesnesi yoktur.
- **Sign-out:** "Sign out" identity plane oturumunu bitirir ve o oturuma bağlı **bütün** Instance'ları (her domain'deki) sonlandırır (`instance.terminate`). Bu bir temizliktir: başka oturum/cihazların Instance'ları ve agent'lara/uygulamalara verilmiş delegation'lar etkilenmez (XI-23 korunur) ve ekran bunu söyler.
- **UI etiketi:** satır birimi "Sign-in on *‹cihaz›*" / "*‹cihaz›* üzerinde giriş"tir. Identity alt durumu ("signed in until … / signed out") ve authority alt durumu ("active in *‹domain›* / ended") ayrı gösterilir. S10 "Sign-ins & instances" yüzeyi ikisini aynı satır biriminde gösterir (→ §8).
- `DelegatedSession` **yoktur**; yerine destek delegasyonu Grant'ı vardır (12.3.4, MD-9).

#### 12.0.4 Okuma kuralları

- **Garanti etiketleri** tam yazılır: *BY SEMANTICS*, *UNDER DECLARED CAPABILITY*, *UNDER DECLARED POLICY*, *NOT GUARANTEED*. Fail-closed her yerde geçerlidir (MD-8): tazeliği kanıtlanamayan authority taşıyan token introspection'da `active=false` alır; RS 5xx'i DENY sayar; rate limiter, risk motoru veya cache arızası hiçbir zaman ALLOW'a dönmez; bozulmuş mod yalnız beyanlı TI-9 / SEC27 / SI-22 yollarıyla çalışır.
- **Statü:** FROZEN (semantik), PD (POLICY DEFAULT; domain/realm daha dar seçebilir, gevşetme SI-18'e göre genişletmedir), EA (ENGINEERING ASSUMPTION), HYPOTHESIS, WATCH (dış standart/ürün durumu izlenir).
- Dış ölçüm ve sayılar kaynaktaki epistemik etiketle taşınır; doğrulanamayanlar öyle işaretlenir ve 12.11'de toplanır.
- "çıkarım" etiketi bu bölümün kendi türetmesini gösterir.
- Başka bölümlerin normları bu bölümde gerektiğinde **tam metin** alıntılanır; tam liste 12.7'dedir. Alt bölümlerde aynı madde ID'siyle anılır.
- **Kanonik kopya kuralı.** T-kararlarının (T20, T26, T27, T28, T31, T33, T35, T39) kanonik yeri §16.10'dur; bu bölüm onlara "→ §16.10 Tn" atfı ve bölüme özgü uygulama cümlesi verir. Bu bölümde tam metinle alıntılanan diğer normların (C, INV, E, X, L, PI, SI, TI, SEC) kanonik yeri §5–§9 ve §13'tür; alıntı yalnız okuma kolaylığı içindir ve çelişkide kanonik metin kazanır. L28'in kanonik metni §4'tedir.
- **Yerel alan kodları.** Bu bölümün alan kodları **TN-K1…TN-K3** (kiracılık), **TN-O1…TN-O4** (oturum/sinyal/risk), **TN-H1…TN-H8** (hesap yaşam döngüsü), **TN-G1…TN-G3** (giriş) ve **TN-Y1…TN-Y5** (yönetim) biçimindedir; §4.4 K-satırları, §18.8 H-hipotezleri ve §13.4 G-garantileriyle karışmaz. Risk sinyal katmanları **SL0–SL2**'dir (§9.1 protokol katmanları L0–L3 ile karışmaz). TN-n karar ID'leri değişmez.

### 12.1 Kiracılık (K)

#### 12.1.1 TN-K1 — Kiracılık modeli: dört eksen

**Normatif kural (MD-5).** Tek "kiracı" kavramı dört eksene ayrılır:

| Eksen | Ne | Semantik mi | Kimlik | Kaynak |
|---|---|---|---|---|
| **Tenant** | Ticari hesap: fatura, kota, sözleşme, destek | Hayır | `tenant_id` (UUIDv7 iç kimlik; dışa opak, MD-18) | MD-5 |
| **AuthorityDomain** | Authority semantiğinin tek birimi: Genesis, log, KEK, operasyonel imza anahtarı kapsamı | **Evet** (T27 korunur) | DomainID = genesis digest (T3) | T27, MD-5 |
| **Identity Realm** | Klasik IdP "kiracı"sı: issuer URL, JOSE anahtarları, RP ID, login ad alanı, user record ve credential'lar, client'lar, marka/tema, giriş politikası | Identity plane'de | `realm_id` + değişmez `slug` | MD-5 |
| **Cell** | Fiziksel yerleşim | Hayır | `placement_id` | T28, MD-5 |

Kardinalite ve sınırlar:

1. Bir Tenant **0..n** AuthorityDomain (realm barındırıyorsa **≥ 1**; 2a) ve **1..n** Identity Realm barındırır. Bir AuthorityDomain hiçbir zaman iki Tenant'a yayılmaz. *[BY SEMANTICS (domain ↔ tenant eşlemesi tektir; authority kararına girmez)]*
2. Varsayılan eşleme **1 realm ↔ 1 domain**'dir. N:M eşleme açık bir kayıtla yapılır: realm tarafında `realm_domain_binding` identity plane kaydı, domain tarafında realm'in issuer'ının o domain'deki Acceptance kümesi (actor-binding ve gerekiyorsa predicate-input; E18). Kayıt olmadan bir realm'in kimlik doğrulaması bir domain'de actor-binding olarak kullanılamaz (→ TN-4). **"N:M" yalnız tüketimdir:** realm'in kimlik Claim'lerini tüketen domain sayısı N olabilir ve her tüketen domain bunu kendi Acceptance'ıyla bildirir; config authority'si 2a'daki yönetişim domain'indedir. Eşleme kaydının kendisi identity plane yapılandırmasıdır, tek başına Acceptance değildir. §5.16 ile §7 arasındaki "Acceptance'tır / değildir" farkı böyle çözülür: yönetişim bir değerdir; tüketim Acceptance'tır.
2a. **Yönetişim domain'i (MD-5a).** Her Identity Realm'in **tam olarak bir** yönetişim AuthorityDomain'i vardır: `realms.governing_domain_id` (NOT NULL; bir değerdir, primitive değildir). MD-14'teki "realm'in AuthorityDomain'i" bu domain'dir. Realm config değişiklikleri (`idp.*` domain action'ları, MD-14) yalnız bu domain'de ADP `commit` ile yetkilendirilir. N:M eşlemede diğer domain'ler realm'in issuer'ını yalnız Acceptance ile kabul eder (TN-4); realm config'i üzerinde authority'leri yoktur ve onların commit'i DENY'dır (`no-covering-authority`). Yönetişim domain'inin değişmesi `idp.realm.rehome` domain action'ıdır: reserved, CT3, iki uçlu (eski ve yeni yönetişim domain'inde ayrı commit; INV-35 deseni). Bir realm, yönetişim domain'i yoksa oluşturulamaz; realm oluşturma, gerekiyorsa önce o domain'in Genesis'ini kurar (TN-111). Bu nedenle realm barındıran her tenant **≥ 1** domain barındırır; MD-5'in "0..n domain" ifadesi "realm'i olmayan tenant için 0" olarak okunur. Domain'siz bir realm config yazma yolu yoktur. *[BY SEMANTICS (tek yönetişim domain'i)]*
3. **`tenant_id` hiçbir authority kararına girdi değildir** (MD-5; INV-29). Ticari durum (fatura askısı, kota) yalnız protocol rejection (SI-20) veya identity plane erişim kısıtı üretir; Grant, Acceptance veya root üretmez ve silmez. *[BY SEMANTICS]*
4. **B2B organizasyonlar** realm içinde **Party + Anchor** olur, ayrı domain olmaz (MD-5). Organizasyonlar arası yetki bridging Grant ile kurulur (E19, C21). Organizasyonun kendi kaynaklarının root'u o organizasyonun Anchor'ıdır; sahipsiz Anchor ifade edilemez (§5 "sahiplik" kuralı).
5. **Hiyerarşi düzdür.** İç içe tenant/realm yoktur; domain içi yapı Grant lineage'ı ile kurulur (derinlik ≤ 16, §13.7.4). Örtük miras yoktur. Identity plane de düz kiracı listesi kullanır ve iç içe kiracıyı reddeder: Zitadel, Auth0, Okta, Entra ve WorkOS iç içe kiracıyı reddetmiş; Frontegg yapmış ve mirası JWT'ye sığmamıştır.
6. **Realm'ler arası köprü** yalnız açık IdentityBinding kaydıyla kurulur (12.3.3). Otomatik e-posta birleştirmesi yoktur.

**Kullanıcı kimliğinin kapsamı.** İki okul vardır: paylaşımlı küresel kullanıcı (Entra B2B, "one managed membership" modelleri) ve kiracıya yerel kullanıcı. Access şunu seçer:

- Credential ve login tanımlayıcısı **realm'e yereldir**: `UNIQUE(realm_id, …)`. Küresel kullanıcı tablosu yoktur. *[UNDER DECLARED CAPABILITY (şema kısıtı + RLS)]*
- PartyID bir **regime referansıdır**, küresel tablo değildir (E4, INV-12). Bir insanın iki realm'deki iki user record'u aynı Party'ye yalnız IdentityBinding kaydıyla bağlanır; IdentityBinding, actor-binding Acceptance'ının girdisi olan bir Claim üretir (E5, E18).
- **E-posta asla anahtar değildir** (MD-5). E-posta, `hd`, `preferred_username`, `unique_name`, `upn` ve görünen ad ile ne yetkilendirme ne birleştirme yapılır; organizasyon yönlendirmesi organizasyon kimliği üzerindendir, e-posta alan adı üzerinden değil (Microsoft iddia doğrulama rehberi). Gerekçe üç bağımsız ihlal sınıfıdır: nOAuth (Semperis 2025: 104 kendin-kaydol Entra galeri uygulamasından 9'u, açıklamadan iki yıl sonra hâlâ zafiyetli), Entra alan adı devralması ve Truffle Security'nin terk edilmiş girişim alan adları bulgusu (13 Ocak 2025 sunumu; >100 bin alan adı; TechCrunch'a göre 116.000). *[BY SEMANTICS (authority tarafı: e-posta hiçbir Acceptance'ın anahtar alanı olamaz); UNDER DECLARED CAPABILITY (identity plane şema kuralları)]*

**Politika çakışması.** "MFA is completed at resource tenancy" (Entra) deseni tek tam cevaptır; tek oturum + politika birliği (union) tasarımından kaçınılır. Access'te bu ontolojiktir: requirement hedef domain'de değerlendirilir (PI-3, INV-17); bir realm'deki login'in assurance'ı hedef domain'in RequirementTerm'ini ancak Acceptance'ı ve tazeliği ile karşılar. Identity plane, farklı realm'lerin giriş politikalarını tek oturumda birleştirmez; her realm kendi oturumunu tutar (TN-7).

**Kiracının kendi AS'ye dönüşmesi.** Üç soru vardır: issuer ayrımı, anahtar ve iptal kapsamı. Bu yetenek birinci günde desteklenmez ama yasaklanmaz. Cevaplar şunlardır: domain ürünü Grant yazmaz (E16); kendi token'ını basan taraf conformant provider'dır (E20) ve kendi issuer'ı, kendi anahtarı ve kendi ValidityContract'ı ile authority plane'e yalnız Acceptance (foreign-authority, reserved) üzerinden girer (E18, E19). Kural: kiracının bastığı token **asla** Suiss realm issuer'ı veya Suiss realm anahtarıyla basılmaz (TN-8).

**Silo kaçış yolu.** `placement_id` kolonu bir kaçış kolonudur: yoksa düzenlemeye tabi bir kiracıyı ayrı bir kümeye taşımak bir mimari yeniden yazımdır. Domain → cell eşlemesi placement directory'dedir (OPERATIONAL) ve hücre değişimi T28 ile yapılır. Bir realm'in yerleşimi varsayılan olarak bağlı olduğu domain'in hücresini izler (çıkarım; ayrı yerleşim açık kayıt ister → TN-9).

**İlgili normlar (tam metin, ayrıca 12.7):**

- **T27** → §16.10 T27 (kanonik metin orada). Bu bölümdeki uygulama: AuthorityDomain authority semantiğinin, yerleşimin, izolasyonun ve shard'ın birimidir; tenant semantik değildir ve hiçbir authority kararına girdi değildir. Tenant ticari eksendir, Identity Realm identity plane eksenidir, Cell fiziksel yerleşimdir (MD-5 dört eksen tablosu). Kotalar protocol rejection'dır ve domain **ve** tenant boyutunda tutulur. Fiziksel izolasyon savunma derinliğidir: identity plane, derived, PII vault ve operasyon depolarında PK'de `tenant_id` (+ `realm_id` / `domain_id`), bileşik FK, RLS FORCE, NOBYPASSRLS, `SET LOCAL`; authority canonical log ve kayıtları `domain_id` ile anahtarlanır, tenant ↔ domain eşlemesi placement directory'dedir (OP-12; 12.1.3).
- **T28** → §16.10 T28. Bu bölümdeki uygulama: realm yerleşimi bağlı olduğu domain'in hücresini izler (TN-9).
- **E19** Five federation things. Identity federation, foreign authority evidence, local bridging Grant, cross-domain delegation ve authority-provider handover ayrı mekanizmalardır ve "generic federation" altında birleştirilmez.

**TN-K1 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-1 | Dört eksen (Tenant / AuthorityDomain / Identity Realm / Cell); tenant 0..n domain (realm varsa ≥ 1), 1..n realm; her realm'in tek yönetişim domain'i (`governing_domain_id`, 2a); domain tek tenant'ta; `tenant_id` authority girdisi değil | FROZEN | BY SEMANTICS | Eksen ayrımı authority semantiğini ticari, identity plane ve fiziksel eksenlerden ayırır | MD-5; T27 |
| TN-2 | Credential ve login tanımlayıcısı realm-yerel `UNIQUE(realm_id, …)`; küresel kullanıcı tablosu yok; PartyID regime referansı; realm'ler arası köprü yalnız IdentityBinding; realm'ler arası bağ iki taraflıdır (her yarı kendi yönetişim domain'inde commit edilir), tek taraflı bağ actor-binding üretmez | FROZEN | UNDER DECLARED CAPABILITY (identity plane); BY SEMANTICS (authority) | Otomatik birleştirme nOAuth sınıfı devralmaya açar | MD-5; E4, INV-12, INV-17 |
| TN-3 | E-posta, `hd`, `preferred_username`, `unique_name`, `upn`, görünen ad ile yetkilendirme ve birleştirme yasak; anahtar `(iss, sub)`; Entra için `(tid, oid)` | FROZEN | BY SEMANTICS (authority); UNDER DECLARED CAPABILITY (identity plane) | Üç bağımsız ihlal kanıtı | MD-5 |
| TN-4 | N:M realm ↔ domain eşlemesi: identity plane `realm_domain_binding` kaydı + domain'de realm issuer'ı için Acceptance kümesi; kayıtsız eşleme actor-binding üretmez; N:M yalnız Acceptance (kimlik kabulü, tüketim) içindir, config authority'si yönetişim domain'indedir (2a) | PD (biçim), FROZEN (Acceptance zorunluluğu E18) | BY SEMANTICS | Varsayılan 1:1; N:M açık kayıtla (MD-5) | MD-5; E18; §5.16 (çıkarım) |
| TN-5 | B2B organizasyon = realm içinde Party + Anchor; ayrı domain değil; cross-org yetki bridging Grant | FROZEN | BY SEMANTICS | Domain sayısını ve operasyon maliyetini sınırlar; cross-org yetki açık | MD-5; E19, C21 |
| TN-6 | Düz hiyerarşi; iç içe tenant/realm yok; iç yapı Grant lineage | FROZEN | BY SEMANTICS | Örtük miras yok; açık daraltma cebiri | — |
| TN-7 | Requirement hedef domain'de değerlendirilir; identity plane farklı realm politikalarını tek oturumda birleştirmez | FROZEN | BY SEMANTICS | Ontolojik eşdeğer; tek oturum uyarısı not olur | PI-3, INV-17 |
| TN-8 | Kiracının kendi token basması = conformant provider (E20), kendi issuer + anahtar + ValidityContract; Suiss realm issuer/anahtarı asla kiracı token'ı basmaz; gün-1'de ürün özelliği değil, yasak da değil | PD (özellik), FROZEN (issuer/anahtar ayrımı) | BY SEMANTICS | Üç soru cevaplı; issuer ayrımı | E16, E20 |
| TN-9 | Realm yerleşimi varsayılan olarak domain'in hücresini izler; ayrı yerleşim açık kayıt; hücre değişimi T28 | EA | UNDER DECLARED CAPABILITY | Placement directory OPERATIONAL; `placement_id` gün-1 | T28 (çıkarım: realm'in domain'i izlemesi) |

#### 12.1.2 TN-K2 — Realm issuer, anahtarlar, client kimliği ve RP ID

**Issuer URL stratejisi.** Müşteri realm'inin issuer'ı varsayılan olarak **alt alan adıdır** (ör. `‹slug›.‹suiss-id-alanı›`, joker sertifikayla); **özel alan adı** bir yükseltmedir (varlığı **ücretlendirilemez**; §18.6; passkey'in ve passkey'li çıkışın tek yolu olduğu için, B3/B11/B19 — sertifika ve DNS otomasyonu konforu ücretlendirilebilir); **path tabanlı** issuer desteklenir ancak varsayılan değildir. Gerekçe köken izolasyonudur: ayrı köken, tarayıcı düzeyinde çerez ve XSS izolasyonu demektir. CVE-2023-6717 (CVSS 6,0, 25 Nisan 2024): bir realm'deki kötü niyetli yönetici, aynı kökeni paylaşan farklı realm'lerdeki kullanıcıları XSS ile hedefleyebilmiştir. Sertifika aritmetiği özel alan adının neden doğrulama arkasında ve kademeli olduğunu açıklar: Let's Encrypt kayıtlı alan adı başına yedi günde 50 sertifika, hesap başına üç saatte 300 yeni sipariş, sertifika başına 100 tanımlayıcı (sayfa tarihi 5 Ağustos 2026).

- **First-party yüzeyler** (Suiss kabuğu, Suiss'in kendi uygulamaları) **tek RP ID ve tek kabuk** kullanır (X4).
- Authority plane'de issuer kavramı DomainID'dir (AP-15); identity plane issuer URL'i bir realm özelliğidir ve DomainID'yi değiştirmez.

**RFC 8414 ile OIDC Discovery path çelişkisi.** Path içeren bir issuer seçildiğinde RFC 8414 well-known'ı path'ten önce, OIDC Discovery ise path'ten sonra ekler; bu yüzden path issuer'lı her realm **iki well-known yolunu da** servis eder. Alt alan adı varsayılanı bu sorunu ortadan kaldırır.

**RFC 9207 `iss` parametresi.** Her realm (ve her domain) ayrı bir authorization server olduğu için mix-up savunması birinci günden gerekir: her authorization response `iss` taşır ve client'lar bunu doğrular. Bu kural FAPI 2.0 profiliyle de uyumludur.

**Realm JOSE anahtarları (MD-6, MD-3).**

1. Realm başına JOSE anahtar seti: **1 aktif + N pasif**, publish-before-use (yeni anahtar JWKS'te imzada kullanılmadan önce yayımlanır), realm başına ayrı KMS anahtarı (T31) (MD-6).
2. `kid` **opak ve küresel benzersizdir**; realm slug'ı veya tenant adı içermez (enumeration kapanır). *[UNDER DECLARED CAPABILITY]*
3. Rotasyon realm başına **bağımsızdır**; varsayılan aralık 3–6 ay (Keycloak verisi) PD'dir. Rotasyon **politikası** (aralık, algoritma) ve acil/elle rotasyon `idp.*` domain action'ıdır; politika dahilinde zamanlanmış rotasyonun yürütülmesi operasyoneldir ve ayrı Exercise gerektirmez (TN-118).
4. Algoritmalar MD-3'e uyar: varsayılan **ES256**; Ed25519 isteğe bağlıdır; RS256 identity plane'de **client başına opt-in**'dir, **yalnız kimlik iddiaları** içindir (authority taşıyan access token dahil hiçbir authority projection'ında RS256 yoktur) ve RSA anahtarı yalnız talep edildiğinde üretilir (RSA anahtar üretimi ~130 kat maliyettir; kiracı başına anahtarı varsayılan RSA ile ekonomik olarak imkânsız kılar). FIPS profili ES256'dır. RFC 9864 fully-specified algoritma tanımlayıcıları kullanılır; `alg: EdDSA` reddedilir; algoritma allowlist'i header'dan değil metadata'dan gelir (MD-3).
5. **Neden realm başına:** Storm-0558 ve CVE-2026-23552 (CVSS 9,1, 23 Şubat 2026: Camel ile Keycloak `iss` doğrulamıyor; bir realm'in token'ı başka bir realm'in politikasınca sessizce kabul ediliyor) paylaşımlı anahtarda tek savunmanın relying party'nin `iss` kontrolü olduğunu ve RP'lerin bunu yapmadığını kanıtlar. Storm-0558 sınıfı (kapsam dışı anahtarın kabulü) bir hard limit adayıdır → 12.10 (MD-6 "HL-8'e eklenir").

**Authority anahtarlarıyla ilişki.** Authority projection'ları T20 hiyerarşisiyle (HSM'de quorum'lu binding key; domain kapsamlı operasyonel anahtar, varsayılan ömür 1 saat, üst sınır 24 saat PD; ayrı signer süreci) imzalanır (MD-6). Realm JOSE anahtarları kimlik iddialarını imzalar: ID token, logout token, userinfo JWT, identity plane'in authority taşımayan (protokol-scope-only) access token'ı, SAML assertion'ı ve SET'ler. Authority taşıyan access token (RAR `authorization_details`) bir authority projection'ıdır ve domain operasyonel anahtarıyla imzalanır; anahtar realm JWKS'te `kid` + Domain Metadata çapraz referansıyla yayımlanır ve verifier DomainID denetimini yapar (§10.4.5). **İki anahtar ailesi birbirinin yerine geçmez**: realm anahtarı authority projection'ı imzalamaz; domain operasyonel anahtarı ID token imzalamaz (çıkarım: "authority projection'ları için T20, ID token'ları için realm başına anahtar" ayrımının anahtar kullanım kuralına çevrilmesi → TNI-2). Binding key kapsamı Domain Metadata'da beyan edilir (MD-6).

**Client kimliği.** `client_id` **küresel benzersizdir** (Keycloak'ın aksine) ve opaktır. RFC 6749 §2.2 `client_id`'yi yalnız yetkilendirme sunucusu içinde benzersiz kılar; küresel benzersizlik paylaşımlı anahtar hatasına karşı **ikinci bağımsız savunma katmanıdır** ve sonradan değiştirilemez. Client kaydı authority vermez; client oluşturma/değiştirme bir domain action'ıdır (MD-14, 12.5).

**Değişmez kısa ad.** DomainID zaten değişmezdir (genesis digest). İnsan okunur realm `slug`'ı ve onun türettiği hostname de **değişmezdir**: regex `^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`; kısa ad issuer URL'indedir ve değişirse her RP'nin keşfi kırılır (Keycloak: "Once defined, the alias cannot be changed."). Ad değişikliği gerekiyorsa yeni realm + göç (12.3.7) yapılır.

**RP ID ve özel alan adı.** WebAuthn RP ID, kayıt anında sabitlenir ve çağıran kökenin kaydedilebilir alan adı sonekiyle sınırlıdır; RP ID değişirse mevcut passkey kayıtları silinmez ama tarayıcı onları girişte sunmaz, kullanıcı yeniden kaydolmak zorundadır (Okta ve Auth0 dokümanları). Bu yüzden:

1. Müşteri realm'i passkey'i etkinleştirmeden **önce** özel alan adı kararını verir; karar onboarding'de **geri dönülemez** olarak işaretlenir ve UI açıkça uyarır.
2. RP ID apeks alan adı olmalıdır; giriş alt alan adı değil ve kesinlikle IdP satıcısının alan adı değil.
3. **Related Origin Requests** (`/.well-known/webauthn` `origins` listesi) birinci sınıf desteklenir; tarayıcılar en fazla **beş benzersiz etiket** (eTLD+1 etiketi) zorlar, fazlası sessizce yok sayılır; bu limit UI'da gösterilir. Destek: Chrome/Edge 128+, Safari 18 (2024), Firefox 152 masaüstü/Android (Mayıs 2026).
4. Kiracı sayısı beş etiketi aşacağı için **her realm kendi RP ID'sini alır**; paylaşımlı RP ID + related origins çok kiracılıkta ölçeklenmez.
5. FIDO Credential Exchange (CXF/CXP) passkey'leri credential provider'lar arasında taşır; RP'den RP'ye taşımaz. CXF 1.0 tarihinin "9 Mart 2026" olması ikincil kaynaklıdır, **doğrulanmadı**.

**İlgili normlar (tam metin, ayrıca 12.7):**

- **T20** → §16.10 T20 (kanonik metin orada). Bu bölümdeki uygulama: operasyonel anahtarın varsayılan ömrü 1 saattir, üst sınırı 24 saattir (PD); anahtar ayrı bir signer sürecinde tutulur; FIPS profilinde HSM'dedir. Identity plane'de realm başına JOSE anahtar seti (1 aktif + N pasif, publish-before-use, ayrı KMS anahtarı) bu hiyerarşiden ayrıdır ve authority projection'ı imzalamaz (TN-14).
- **T31** → §16.10 T31. Bu bölümdeki uygulama: identity plane ayrı cell/cluster/KMS/operatör rolleriyle çalışır, authority plane'e tek kanalı Claim Ingest API'sidir; WebAuthn RP ID kuralı TN-17'dedir.

**TN-K2 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-10 | Realm issuer: alt alan adı varsayılan (joker sertifika), özel alan adı yükseltme (varlığı ücretlendirilemez, §18.6), path destekli ama varsayılan değil; path issuer iki well-known yolunu servis eder | PD (biçim), FROZEN (köken izolasyonu varsayılanı) | UNDER DECLARED CAPABILITY | Köken izolasyonu (CVE-2023-6717), sertifika aritmetiği | — |
| TN-11 | RFC 9207 `iss` her authorization response'ta zorunlu; client doğrular | FROZEN | UNDER DECLARED CAPABILITY (RP'nin doğrulaması) | Her realm/domain ayrı AS → mix-up | — |
| TN-12 | Realm JOSE anahtar seti: 1 aktif + N pasif, publish-before-use, ayrı KMS anahtarı, opak küresel benzersiz `kid`, bağımsız rotasyon (aralık 3–6 ay PD); rotasyon politikası ve acil rotasyon domain action, zamanlanmış yürütme operasyonel | FROZEN (yapı), PD (aralık) | UNDER DECLARED CAPABILITY | Storm-0558, CVE-2026-23552 | MD-6 |
| TN-13 | ES256 varsayılan; Ed25519 opsiyon; RS256 client başına opt-in (yalnız kimlik iddiaları), RSA anahtarı tembel üretim; FIPS = ES256; allowlist metadata'dan; `alg: EdDSA` red | FROZEN | BY SEMANTICS (allowlist kuralı) | Kiracı başına anahtarın ekonomisi (RSA ~130×) | MD-3 |
| TN-14 | Realm JOSE anahtarı authority projection imzalamaz (authority taşıyan access token dahil); domain operasyonel anahtarı kimlik iddiası imzalamaz | FROZEN | BY SEMANTICS (verifier DomainID must-understand, TI-RT6) | Anahtar kullanım ayrımı Storm-0558 sınıfını iki plane arasında da kapatır | MD-6; T20 (çıkarım) |
| TN-15 | `client_id` küresel benzersiz ve opak | FROZEN | UNDER DECLARED CAPABILITY | İkinci bağımsız savunma; sonradan değiştirilemez | — |
| TN-16 | Realm `slug` ve türetilen hostname değişmez (regex 12.1.2); değişiklik = yeni realm + göç | FROZEN | UNDER DECLARED CAPABILITY | Issuer URL'inde; keşif kırılır | — |
| TN-17 | First-party tek RP ID + tek kabuk; müşteri realm'i kendi RP ID'si; özel alan adı passkey'den önce ve geri dönülemez işaretli | FROZEN | NOT GUARANTEED (RP ID değişiminde passkey kaybı önlenemez; yalnız uyarılır) | Geri dönülemez tek WebAuthn kararı | — |
| TN-18 | Related Origin Requests birinci sınıf; beş etiket limiti UI'da; ölçek için realm başına RP ID | PD | UNDER DECLARED CAPABILITY (tarayıcı desteği) | Barındırılan girişe geçişi passkey'i öldürmeden yapar | — |

#### 12.1.3 TN-K3 — Veri izolasyonu, kota, denetim günlüğü ve izolasyon testleri

**İzolasyon kararı (MD-5, MD-19.6).** "İzolasyon: her tablo `domain` anahtarlıdır; PostgreSQL row-level security derinlemesine savunmadır; body'ler domain başına KEK altında body başına DEK ile şifrelidir; kaynak kotaları (CPU, ingest, commit/s) domain ve tenant başına → aşım protocol rejection (SI-20), asla başka domain'in kararını etkilemez." Eksenlere uygulanışı şöyledir: identity plane, derived, PII vault ve operasyon depolarında anahtar `tenant_id` (+ `realm_id` / `domain_id`) ve RLS FORCE zorunludur; authority canonical log ve kayıtları `domain_id` ile anahtarlanır, çünkü append-only log ticari hesap değişince yeniden anahtarlanamaz; tenant ↔ domain eşlemesi placement directory'dedir (OP-12). Fiziksel izolasyon **savunma derinliğidir**, semantik değildir: authority izolasyonu BY SEMANTICS'tir (CI-15, INV-29); fiziksel izolasyon UNDER DECLARED CAPABILITY'dir (koşul: RLS + bileşik FK + tip düzeyinde kapsam; §5.16).

**Gün-1 kuralları (sonradan imkânsız):**

1. Her tabloda ve her **birincil anahtarda** `tenant_id` (+ `realm_id` / `domain_id`) bulunur (SuperTokens: 33 tablo, tüm PK'ler basamaklı, çevrimdışı migration). Kapsam: identity plane, derived, PII vault ve operasyon tabloları; authority canonical log ve kayıtları `domain_id` anahtarlıdır.
2. Her yabancı anahtar **bileşiktir** ve `tenant_id` içerir; tek kolonlu FK çapraz kiracı referansa izin verir ve RLS sonra okumayı 500 ile bozar (Logto PR 7596, 29 Temmuz 2025).
3. **RLS ENABLE + FORCE** her iş tablosunda; uygulama rolü tablo sahibi değildir ve **NOBYPASSRLS**'tir. FORCE olmadan tablo sahibi RLS'i atlar: "uygulamanız tablo sahibi olarak bağlanıyorsa … `ENABLE ROW LEVEL SECURITY` kelimenin tam anlamıyla hiçbir şey yapmamaktadır" (PostgreSQL dokümanı). RLS ya hep ya hiçtir: Logto issue 7685'te ~60'tan fazla tablo eksik bulunmuştur.
4. Politika **RESTRICTIVE** ve **fail-closed**'dur: `current_setting('…tenant_id', true)` ayarlanmamışsa NULL döner ve sıfır satır gelir; `COALESCE`/`OR` ile "admin modu" yazılmaz (fail-open olur). MD-8 ile uyumludur.
5. GUC yalnız **açık işlem içinde `SET LOCAL`** (`set_config(…, true)`) ile ayarlanır. Üç ölümcül tuzak: işlem dışında `SET LOCAL` sessizce etkisizdir; düz `SET` PgBouncer işlem modunda bir sonraki istemciye miras kalır (`DISCARD ALL` çalışmaz); aynı işlemde önce `SET` sonra `SET LOCAL` commit sonrası `SET` değerini bırakır (PgBouncer ve PostgreSQL dokümanları). AWS RDS Proxy PostgreSQL'de `SET`/`set_config` sabitlemeye yol açar ve sabitleme filtresi yoktur; `SET LOCAL` muafiyeti PostgreSQL için **doğrulanmadı**. Havuz `after_release` kancasında `RESET ALL` çalıştırır (kemer + askı).
6. **Gizli kanal savunması:** referential integrity kontrolleri (UNIQUE, PK, FK) RLS'i her zaman atlar; küresel `UNIQUE(email)` başka kiracıda e-postanın varlığını sızdırır. Bu yüzden benzersizlik her zaman `UNIQUE(tenant_id, realm_id, …)` biçimindedir ve bu bir tercih değil gizli kanal savunmasıdır (PostgreSQL dokümanı).
7. `SECURITY DEFINER` fonksiyonlar `SET search_path` içerir; içermeyen bir definer fonksiyonu kiracılık modelinden standart kaçış yoludur (Heroku Postgres, açıklama 29 Ekim 2025, düzeltme 4 Kasım 2025). View'lar `security_invoker = true` ile tanımlanır (PostgreSQL 15+).
8. RLS politika fonksiyonları `(SELECT …)` ile sarılır ve RLS kolonu indekslenir; Supabase ölçümünde fark 178.000 ms → 12 ms'dir (100 bin satır). RLS + generic plan önbelleği etkileşimi **ölçülmemiştir, doğrulanmadı**.
9. RLS CVE örüntüsü: CVE-2026-14666, CVE-2024-10976, CVE-2023-2455 (oturum içinde rol değişince politika önbelleği geçersizleşmiyor), CVE-2023-39418 (MERGE), CVE-2019-10130 (sızdıran operatör, planlayıcı istatistikleri). `SET ROLE` + havuz + RLS birlikte kullanılıyorsa asgari PostgreSQL sürümü sabitlenir ve agresif yamalanır. Access `SET ROLE` ile kiracı değiştirmez (çıkarım: tek uygulama rolü + GUC deseni bu sınıfı tetiklemez).
10. Denetim günlüğü **tenant + zaman** ile bölümlenir; bölüm sayısı yüzlerde tutulur (kilit bütçesi: PostgreSQL ≤17'de arka uç başına 16 fast-path kilit yuvası; PostgreSQL 18 `c4d5cb71d` ile `max_locks_per_transaction`'dan boyutlanır).
11. Yetkilendirme isim tabanlı değil **opak kimlik ve tam yol** tabanlıdır (CVE-2026-19608). Token takasında kiracı kısıtı uygulanır (CVE-2026-18215: Microsoft organizasyon kısıtı token takasında yok sayılmış).
12. Hız limiti ve kota boyutu **şemadadır** (tenant ve domain boyutu).
13. Kiracı/domain kapsamı **tip sisteminde** markalı kapsam olarak bulunur (CVE-2019-14832: unutulmuş `AND realm_id = ?`).
14. İç kimlikler **UUIDv7**'dir; dışa açık kimlikler opaktır (MD-18). Şemada `gen_random_uuid()` varsayılanı kullanılmaz.

**Reddedilen depolama alternatifleri.** Kiracı başına şema: 1.200 şemada 383 ms katalog taraması ve iki saatlik migration; 1.500 şemada ~5 saat; 20 bin şemada `pg_dump` 24 saatten uzun; `search_path` havuzlamayı kırılganlaştırır; sqlx dinamik şema migration'ı vermez. Kiracı başına veritabanı: ~50 kiracı tavanı, havuz çarpımı, işlem ve nesne kimliği baskısı. Realm benzeri ağır kiracı: Keycloak'ın 200–500 tavanı, master realm O(N) bağlaması. "2.000 şema DDL" iddiası bir AI blogundandır, **doğrulanmadı**. Bu, domain-per-DB tasarlayacak bir uygulayıcıya karşı korur; Citus'a geçiş `tenant_id` parça anahtarı olduğu için sonradan eklenebilir.

**Şema iskeleti.**

```sql
-- Identity plane, dört eksenle (MD-5). İç kimlik UUIDv7 (MD-18).
CREATE TABLE tenants (
  id uuid PRIMARY KEY,                       -- UUIDv7, dışa opak
  placement_id text NOT NULL DEFAULT 'pool-default',
  status text NOT NULL CHECK (status IN ('provisioning','active','suspended','purging')),
  created_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE realms (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  id uuid NOT NULL,
  governing_domain_id uuid NOT NULL,         -- tek yönetişim domain'i (12.1.1 2a)
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'), -- DEĞİŞMEZ (TN-16)
  placement_id text NOT NULL,
  PRIMARY KEY (tenant_id, id));

CREATE TABLE realm_hostnames (
  tenant_id uuid NOT NULL, realm_id uuid NOT NULL,
  hostname text NOT NULL, kind text NOT NULL CHECK (kind IN ('subdomain','custom')),
  verified_at timestamptz, reverify_at timestamptz,          -- DNS bir kiralamadır (12.3.8)
  PRIMARY KEY (tenant_id, realm_id, hostname),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES realms(tenant_id, id));
CREATE UNIQUE INDEX realm_hostnames_host_uniq ON realm_hostnames (lower(hostname));

CREATE TABLE users (
  tenant_id uuid NOT NULL, realm_id uuid NOT NULL, id uuid NOT NULL,
  username text NOT NULL, email text, email_verified_at timestamptz,
  status text NOT NULL,                                       -- 12.3.1 durum makinesi
  PRIMARY KEY (tenant_id, realm_id, id),
  UNIQUE (tenant_id, realm_id, username),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES realms(tenant_id, id));
CREATE UNIQUE INDEX users_realm_email_uniq ON users (tenant_id, realm_id, lower(email))
  WHERE email IS NOT NULL;                                    -- ASLA küresel UNIQUE(email)

CREATE TABLE identity_bindings (          -- realm'ler arası AÇIK bağ; her taraf kendi yarısını tutar
  tenant_id uuid NOT NULL, realm_id uuid NOT NULL, user_id uuid NOT NULL,
  binding_id uuid NOT NULL,               -- iki yarının ortak kimliği (UUIDv7, dışa opak)
  peer_ref text NOT NULL,                 -- karşı tarafın opak referansı; FK DEĞİL (gizli kanal yok)
  proof text NOT NULL CHECK (proof IN ('invite_token','admin_exercise','verified_idp_subject')),
  exercise_ref text NOT NULL,             -- bu yarıyı yetkilendiren, bu realm'in yönetişim domain'indeki Exercise
  PRIMARY KEY (tenant_id, realm_id, binding_id),
  FOREIGN KEY (tenant_id, realm_id, user_id) REFERENCES users(tenant_id, realm_id, id));

CREATE TABLE clients (
  tenant_id uuid NOT NULL, realm_id uuid NOT NULL, id uuid NOT NULL,
  client_id text NOT NULL UNIQUE,                            -- KÜRESEL benzersiz (TN-15)
  PRIMARY KEY (tenant_id, realm_id, id));

CREATE TABLE realm_signing_keys (
  tenant_id uuid NOT NULL, realm_id uuid NOT NULL,
  kid text NOT NULL UNIQUE,                                  -- opak, küresel (TN-12)
  alg text NOT NULL CHECK (alg IN ('ES256','Ed25519','RS256')), -- RFC 9864 adları (MD-3)
  state text NOT NULL CHECK (state IN ('published','active','passive','disabled')),
  private_ref text NOT NULL,                                 -- KMS/HSM referansı
  PRIMARY KEY (tenant_id, realm_id, kid));
CREATE UNIQUE INDEX realm_keys_one_active ON realm_signing_keys (tenant_id, realm_id, alg)
  WHERE state = 'active';

-- RLS: her tabloda ENABLE + FORCE; uygulama rolü NOBYPASSRLS, sahip değil.
-- CREATE POLICY … AS RESTRICTIVE TO app_role
--   USING (tenant_id = (SELECT current_setting('app.tenant_id', true)::uuid)
--      AND realm_id  = (SELECT current_setting('app.realm_id',  true)::uuid));
```

`identity_bindings.proof` değeri `admin_action` değil `admin_exercise`'tır ve satır `exercise_ref` taşır: bağlama bir domain action'ıdır ve Exercise kaydıyla attributable'dır (MD-14). `state` kümesi `published` içerir (publish-before-use, MD-6). Authority plane'de identity plane'e benzer operasyon/derived depoları aynı kalıbı kullanır; authority canonical log ve kayıtları ise `domain_id` ile anahtarlanır; ayrıntı → §16/§17.

**`identity_bindings` iki yarılıdır.** Bağ iki yarıdan oluşur ve her yarı kendi tenant/realm bölümündedir. Bağ, iki yarı da kendi yönetişim domain'inde (12.1.1 2a) commit edildiğinde etkin olur. Kullanıcının iki hesabın kontrolünü kanıtlaması (`verified_idp_subject` / `invite_token`) iki tarafın Exercise'ına girdi olur. `admin_exercise` yalnız iki realm aynı tenant'taysa ve her iki tarafın yetkili yöneticisi kendi yarısını commit ederse geçerlidir. Tenant'lar arası FK yoktur (kural 6: FK hatası/başarısı karşı tenant'ta kullanıcının varlığını sızdırırdı). Tek taraflı bağ actor-binding üretmez.

**Derleme zamanı kapsam (MD-1/MD-2).** Domain/tenant kapsamı olmayan sorgu derlenemez (MD-2). Rust deseni üç katman + istek sınırıdır:

1. `TenantId` (ve `RealmId`, `DomainId`) opak tiptir; `Debug` ve `Deserialize` kasten türetilmez (log'a sızmaz, istek gövdesinden gelemez).
2. `generativity` ile markalı kapsam: `TenantScope<'brand>`, `Scoped<'brand, T>`; farklı markalı kapsamlar arası veri taşımak derleme hatasıdır. `generativity` 1.2.1, ~3,99 milyon indirme (26 Nisan 2026); temel GhostCell (ICFP 2021). Çok kiracılığa uygulanmış yayımlanmış örnek yoktur.
3. `TenantTx::begin` tek giriş noktasıdır: açık `BEGIN` + `set_config(…, true)`; kapsamsız sorgu tipi yoktur.
4. İstek sınırı: identity plane yönlendirmesi için realm Host başlığından çözülür (Axum `Extension`, `task_local` değil: `spawn`'a miras kalmaz ve erişimde panic eder); token'daki realm ile route realm'i eşleşmezse `TenantMismatch` (CVE-2026-41166 sınıfı). **Authority için** domain asla Host'tan veya token iddiasından gelmez: AIS'te imzalıdır (PI-7). Host'tan çözülen realm yalnız identity plane yönlendirmesidir (çıkarım: Axum resolver ↔ PI-7). Ne kazandırmadığı da yazılır: yanlış kiracıyı `begin()`'e vermeyi engellemez (4. katmanın işi); ham SQL'de unutulmuş yüklemi engellemez (RLS'in işi).

**Kota, hız limiti, gürültülü komşu.** Değerler §13.7.4'tedir (actor Instance başına); ek boyutlar: **tenant**, **realm** ve **domain** boyutu ayrı sayaçtır; aşım protocol rejection'dır ve asla başka domain'in kararını etkilemez. Üç katmanlı yönetim API'si hız sınırı 12.5.4'tedir.

- **T33** → §16.10 T33 (kanonik metin orada). Bu bölümdeki uygulama: gateway katmanında sayaçlar tenant, realm ve domain boyutunda tutulur; identity plane uç noktalarında (giriş, token, kayıt) ek olarak aktör/IP boyutu vardır (12.3.6, 12.4.1). Limiter arızası ALLOW'a dönmez (MD-8).

**Denetim günlüğü.** Authority log: domain başına append-only log (T3), redaksiyon T39 (12.3.5). Identity plane günlüğü: tenant + zaman bölümlü; sıcak pencere 30–90 gün (Entra 7/30/90 gün saklama referansı) + tenant başına dışa aktarım hedefi; GDPR silmesi bölüm `DETACH` + `DROP` ile. Identity plane olaylarından authority'ye değen her şey Claim olarak girer (TI-15).

**Çapraz kiracı sızıntı test planı.** Access conformance çerçevesi (TI-RT12) altında altı test zorunludur (yayımlanmış olgun bir metodoloji bulunamamıştır; testler hata sınıflarından türetilmiştir):

1. **Şema değişmezi CI kontrolü:** RLS'siz veya FORCE'suz iş tablosu, `tenant_id`'siz tablo, bileşik olmayan FK, `SET search_path`'siz SECURITY DEFINER fonksiyon, BYPASSRLS taşıyan uygulama rolü → derleme kırılır.
2. **İkiz kiracı diferansiyel testi:** tüm entegrasyon paketi iki kiracı için aynı veriyle koşar; A'nın sorgularının B verisiyle kesişimi boş olmalıdır (CVE-2019-14832 sınıfı).
3. **Özellik tabanlı test (proptest):** rastgele tenant/realm/user/client grafiği; hiçbir API çağrısı çağıranın kapsamı dışındaki satırı döndürmez; özellikle route realm'i ≠ token realm'i kombinasyonları (CVE-2026-41166 sınıfı).
4. **Token karışıklığı bulandırıcısı:** realm A'nın token'ı realm B'nin her uç noktasına; beklenen 401/403, asla 200 (Storm-0558, CVE-2026-23552 sınıfı). Authority tarafında ek vektör: domain A projection'ı domain B verifier'ına → DomainID must-understand DENY (TI-RT6).
5. **Gizli kanal testi:** A'da var olan e-postayla B'de kayıt; benzersizlik ihlali asla sızmaz.
6. **Ayarlanmamış GUC testi:** kapsam GUC'u yokken her sorgu sıfır satır döndürür (fail-closed).

İlgili çapraz kiracı CVE'leri: CVE-2026-23552, CVE-2022-36051, CVE-2019-14832, CVE-2026-41166, CVE-2026-18215, CVE-2023-6717, CVE-2020-1697. Wiz/Orca serisi (ChaosDB, ExtraReplica, BingBang), Okta destek ihlalleri ve Asana MCP olayının teknik ayrıntısı **doğrulanmamıştır**.

**TN-K3 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-19 | Identity plane, derived, PII vault ve operasyon depolarında PK'de `tenant_id` (+ `realm_id`/`domain_id`); authority canonical log `domain_id` anahtarlı, tenant ↔ domain eşlemesi placement directory'de; bileşik FK, RLS ENABLE+FORCE, RESTRICTIVE fail-closed politika, NOBYPASSRLS sahip olmayan rol, açık işlemde `SET LOCAL` | FROZEN | UNDER DECLARED CAPABILITY | Kanıtlı RLS ve havuz tuzakları | MD-5, MD-19.6 |
| TN-20 | Benzersizlik daima kapsamlı `UNIQUE(tenant_id, realm_id, …)`; küresel benzersizlik yalnız `client_id`, `kid`, hostname ve slug için (sızıntı içermeyen opak/kamusal değerler) | FROZEN | UNDER DECLARED CAPABILITY | RI kontrolleri RLS'i atlar → gizli kanal | — |
| TN-21 | Kiracı başına şema/DB reddi; satır tabanlı + `placement_id`; Citus sonradan | PD | — | Ölçülmüş katalog/migration tavanları | — |
| TN-22 | Kapsam tip sisteminde (`generativity` markalı kapsam, opak kimlik tipleri, tek `begin`); kapsamsız sorgu derlenmez; authority domain'i AIS'ten, identity plane realm'i Host'tan + token eşleşmesi | FROZEN (kural), EA (crate seçimi) | UNDER DECLARED CAPABILITY | CVE-2019-14832, CVE-2026-41166 | MD-1, MD-2; PI-7 |
| TN-23 | Altı izolasyon testi CI'da zorunlu (şema CI, ikiz kiracı, proptest, token fuzzer, gizli kanal, ayarlanmamış GUC) + authority DomainID vektörü | PD | UNDER DECLARED CAPABILITY (test kapsamı) | Hata sınıflarından sistematik test, Access conformance çerçevesi | TI-RT12 |
| TN-24 | Kota/hız sayaçları tenant, realm, domain boyutunda; aşım protocol rejection; limiter arızası fail-closed | PD (değerler §13.7.4), FROZEN (fail-closed) | BY SEMANTICS (SI-20) | Tenant ve domain boyutu ayrı sayaçtır | T33; MD-8 |
| TN-25 | Identity plane denetim günlüğü tenant + zaman bölümlü, yüzlerde bölüm, sıcak 30–90 gün + dışa aktarım; authority log T3/T39 | PD | UNDER DECLARED CAPABILITY | Kilit bütçesi, silme hakkı | — |
| TN-26 | `SECURITY DEFINER` daima `SET search_path`; view'lar `security_invoker`; RLS fonksiyonları `(SELECT …)` sarılı + indeksli; `SET ROLE` ile kiracı değiştirilmez; asgari PostgreSQL sürümü RLS CVE'lerine göre sabitlenir | PD | UNDER DECLARED CAPABILITY | Heroku kaçışı, RLS CVE örüntüsü, Supabase ölçümü | — |

### 12.2 Oturum, sinyal ve risk

#### 12.2.1 TN-O1 — Identity plane oturumu ve sender-constraint

**Holder-bound zorunluluğu.** Authority taşıyan her projection holder-bound'dur; bearer authority yoktur (PI-11). Access token projection'ında `cnf` zorunludur (DPoP/mTLS), `aud` tek RS/PEP'tir (RFC 8707), authority yalnız RAR'dadır (§9 projection tablosu). DPoP/mTLS bağlama **zorunludur** ve FAPI 2.0 ile uyumludur (PAR, PKCE S256, RFC 9207, refresh rotasyonu).

- **PI-11** Authority taşıyan her projection holder-bound'dur (DPoP/mTLS/PoP); bearer authority yoktur
- Identity plane'in kendi ID token'ı authority taşımaz; identity plane access token'ı da holder-bound'dur (DPoP veya mTLS); bearer access token yalnız authority taşımayan ve realm'in açıkça beyan ettiği eski client profilinde, kısa ömürle ve Domain Metadata'da NOT GUARANTEED satırıyla izinlidir (çıkarım: geçiş istisnası; varsayılan kapalı → TN-27).

**Transport PoP ≠ actor kanıtı.** PEP → ADP bağlantısının DPoP/mTLS'i yalnız PEP'i kanıtlar, intent digest'e bağlı değildir; actor yalnız AIS'ten türetilir (RFC 9449/8705 ADOPT satırı; PI-7). DPoP'un kapatmadığı "PEP-as-actor" açığını bu kapatır.

- **PI-7** Actor yalnız actor Instance'ın KeyBinding'iyle imzalanmış Actor Intent Statement'tan türetilir (domain, nonce, intent digest, PEP audience'a bağlı; başka isteğe taşınamaz); AuthZEN subject, PEP kimliği veya ADP çağrısının transport authentication'ı (mTLS / DPoP / WPT) actor değildir; statement'sız istek Anonymous'tur; her commit/continue kaydı statement'ı taşır.

**DPoP doğrulama profili.** RFC 9449 §4.3 kontrolleri birebir uygulanır: tek `DPoP` başlığı; iyi biçimli JWT; zorunlu claim'ler (`jti`, `htm`, `htu`, `iat`); `typ` = `dpop+jwt`; asimetrik ve allowlist'teki `alg` (MD-3; allowlist metadata'dan); imza başlıktaki `jwk` ile doğrulanır; `jwk` özel anahtar içermez; `htm` eşleşir; `htu` RFC 3986 normalizasyonundan sonra sorgu ve fragment hariç eşleşir; sunucu nonce verdiyse `nonce` eşleşir; `iat` kabul penceresindedir; access token ile sunulduysa `ath` eşleşir ve anahtar token'ın `cnf.jkt`'si ile eşleşir.

**DPoP nonce (MD-18).** Kısa ömürlü (60 s) nonce kullanılmaz; ölçümlü uzun ömürlü model geçerlidir (MD-18):

1. **Uzun ömürlü, paylaşımlı, durumsuz nonce** + kayan pencere: Okta modeli (24 saat + 3 gün tolerans) + ATProto bayat nonce toleransı (≤ 5 dk) + her 200 yanıtında öngörülü yeni nonce (`DPoP-Nonce`).
2. AS `400 use_dpop_nonce`, RS `401` + `WWW-Authenticate: DPoP error="use_dpop_nonce"` döner; AS ve RS nonce'ları ayrıdır; bir istemciye nonce verildikten sonra nonce'suz kanıt kabul edilmez.
3. Nonce durumsuzdur: zaman pencereli, sunucu anahtarıyla MAC'lenmiş değerdir (çıkarım: "shared stateless nonce" uygulaması); hücreler arası paylaşım için anahtar realm başına ve rotasyonludur.

**Replay cache (MD-18).** Anahtar `BLAKE3(htm ‖ htu ‖ jti)`; TTL = **kanıt ömrü + 2 × saat kayması** (Duende örneği: 5 s + 2 × 5 s = 15 s). Dağıtık kurulumda cache hücre içinde senkrondur; hücreler arası replay'i nonce penceresi sınırlar. Cache arızası kanıtı **reddeder** (MD-8). *[UNDER DECLARED CAPABILITY]*

**Refresh token bağlama.**

- Public client'ın refresh token'ı DPoP anahtarına bağlıdır; `dpop_jkt` authorization request'te kodu anahtara bağlar; anahtar kaybı yeniden kimlik doğrulama demektir (RFC 9449 §5, §10).
- **Her refresh yeni bir karardır** (L19; §9 projection tablosu). Refresh token holding değildir; revocation sonrası refresh DENY'dır.
- Refresh **rotasyonu ve reuse detection** zorunludur: kullanılmış bir refresh token'ın yeniden sunulması o token ailesinin tamamını iptal eder ve `session_epoch` artırır. Mobil istemcide eşzamanlı yenileme yarışından doğan yanlış pozitif için istemci tarafında **single-flight** (tek uçuşta yenileme) zorunludur; sunucu tarafında kısa bir ardışık-kullanım toleransı tanımlanmaz (çıkarım: tolerans reuse detection'ı zayıflatır).
- Tarayıcı istemcisinde refresh token varsa rotasyon veya sender-constraint zorunludur ve refresh token ömrü ilk verilme ömrüyle sınırlanır (RFC 10017 / BCP 212; RFC numarası ve tarihi **doğrulanmadı**).

- **L19** Önceki bir authority decision yalnız açık, sınırlı bir freshness/dependency sözleşmesi altında yeniden kullanılabilir veya devam ettirilebilir; uzatma yeniden authority değerlendirmesi gerektirir. Biçimi ValidityContract + continuation DecisionRecord'dur (C31); Access'te ayrı bir "lease" nesnesi yoktur.

**mTLS.** RFC 8705 ADOPT'tur. Dağıtım kuralları: `mtls_endpoint_aliases`; CDN/TLS sonlandırmada güvenilmeyen kaynaktan gelen iletilmiş sertifika başlıkları **soyulur**; sertifika bağlamada "tam olarak bir SAN" kuralı.

**Donanım anahtarı kanıtlaması.** Semantik L21'dir:

- **L21** Holder-bound key'ler bir instance'ı authenticate eder ve bağlar; instance'ın tam kimliğini veya lifecycle'ını tanımlamaz. InstanceID (Access-level mantıksal kimlik/lifecycle referansı) ≠ KeyBinding (DPoP / mTLS / WIT cnf gibi güncel proof materyali) ≠ Attestation (instance/key'e bağlı runtime/ortam claim'i). Runtime attestation yalnız claim'dir.

Doğrulama listeleri: Token Binding ölüdür; WebAuthn'in device-bound public key uzantısı şartnameden kaldırılmıştır; Android key attestation (kök rotasyonu), Apple App Attest ve TPM için ayrı kontrol listeleri uygulanır. Attestation-based client authentication taslağı (draft-11) WATCH'tır.

**DBSC.** Identity plane'in kendi tarayıcı oturumu için iskelet + özellik bayrağı (sınıflandırma: arayüz/iskelet):

- Şartname editör taslağıdır (27 Ağustos 2026); Chrome 146 Windows'ta; Firefox olumsuz; Safari sinyal yok. Statü **WATCH**.
- Başlıklar `Secure-Session-*` olarak yeniden adlandırılmıştır; challenge durumu 403'tür. Kayıt JWT'si `typ: dbsc+jwt`, `jwk`, `jti`, `authorization`; anahtar kimliği RFC 7638 thumbprint. Yalnız `jti` normatiftir; `aud`/`iat` **zorunlu tutulmaz**.
- Yenilemede son 2–3 challenge 60–120 s içinde kabul edilir. Durum semantiği: 403 yeniden dene (yeni challenge), diğer 4xx oturumu öldürür, 429 güvenlidir, **404 asla** dönülmez. Keşif `/.well-known/device-bound-sessions`.
- Performans (kaynak ölçümü): kayıt medyan 3 s / p90 15 s; yenileme 0,3 / 0,6 s; 600 s çerez ömründe 1 milyon oturum başına ~1.667 yenileme/s.
- Bağlanmamış (kayıt öncesi) çerez penceresi düşük ayrıcalıklı durumdur: DBSC bağlanana kadar oturum yalnız düşük CT okuma taşır; challenge ömrü dakikalardır.
- Federe DBSC erkendir; issue 259: tek çıkış (single logout) semantiği yoktur; Rust crate'i yoktur.
- BitB (browser-in-the-browser) DBSC'yi yener (çıkarım). DBSC phishing direnci değildir; çerez hırsızlığına karşıdır.
- Konsol çerezi "DBSC'ye hazır"dır (MD-14; 12.5.5).

**BFF.** Token'ı tarayıcıya hiç vermemek: tek sayfa uygulaması müşterilerine BFF resmî öneridir; tarayıcı içi OAuth istemcisi "iş uygulamaları, hassas uygulamalar ve kişisel veri işleyen uygulamalar için önerilmemektedir" ifadesi dokümantasyonda alıntılanır; örtük akış yasaktır (RFC 10017 §6.1–6.3). BFF'de oturum deposu sıcak bir bağımlılık olur ve bozulmuş modu ayrıca tanımlanır: depo erişilemezse oturum fail-closed'dur (MD-8). DPoP çalınan access token'ın dışa aktarımını engeller ama saldırganın kendi anahtarıyla taze token almasını engellemez; hiçbir depolama yaklaşımı bunu engellemez (RFC 10017) → NOT GUARANTEED (12.10).

**Device code akışı.** Varsayılan **kapalıdır**. Gerekçe 2026 cihaz kodu oltalama salgınıdır (37,5 kat artış, kaynak ölçümü). Realm açarsa: token DPoP'a bağlıdır; onay ekranı ayrı bir trusted yüzeydir ve client adını, istenen kapsamı ve isteği başlatan IP/konumu gösterir. Tycoon kit takedown'ı (4 Mart 2026) ve infostealer istatistikleri tehdit bağlamıdır.

**Oturum ömrü.** Identity plane oturumu (12.0.3) şöyledir:

1. İki katman: **boşta kalma zaman aşımı + mutlak ömür**. Varsayılan başlangıç Auth0 değerleridir: boşta 7 gün (ayar aralığı 1 saat–30 gün), mutlak 30 gün (1 saat–90 gün). Microsoft'un tek katmanlı 1–365 gün aralığı fazla geniştir. Değerler PD'dir.
2. **Olay tabanlı zorunlu iptal** asıl güvenlik mekanizmasıdır: parola değişimi, MFA yöntemi değişimi, cihaz uyumsuzluğu, yönetici iptali, `instance.terminate`, `party.compromise` (MD-7).
3. **Agresif yeniden kimlik doğrulamadan kaçınılır**: Microsoft'a göre sık istem kullanıcıyı düşünmeden kimlik bilgisi girmeye alıştırır ve kimlik avına yardım eder ("Asking users for credentials often seems like a sensible thing to do, but it can backfire…"); Entra varsayılanı 90 günlük kayan penceredir. Authority tarafında yüksek CT için tazelik zaten eylem anında step-up ile sağlanır (§13.7.3), oturum ömrüyle değil.
4. Authority karşılığı: insan Instance'ının "oturumu" ayrı nesne değildir; boşta/mutlak sınırlar authentication Claim tazeliği olarak RequirementTerm'e girer. "Remember this decision" authority için yasaktır; identity plane'in "beni hatırla"sı yalnız login sürtünmesini etkiler ve hiçbir CT2+ requirement'ını karşılamaz.
5. S10 "Sign-ins & instances" yüzeyi oturumları ve Instance'ları aynı satır biriminde ("*‹cihaz›* üzerinde giriş") gösterir; identity ve authority alt durumları ayrı gösterilir; oturum identity plane kaydıdır. Oturum cihaz ve kullanıldığı domain başına en çok bir insan Instance'ına bağlıdır; sign-out o oturuma bağlı bütün Instance'ları sonlandırır, başka oturum/cihazları etkilemez (12.0.3).

**Epoch'lar ve iptal (MD-7).**

- ValidityContract, identity plane token'ları dahil bütün yeniden kullanılabilir artefaktların **semantik** sözleşmesidir. Epoch'lar mekanizmadır (MD-7):
  - `session_epoch`: identity plane oturum/token hızlı iptali; Instance veya Party başına; `instance.terminate` ve `party.compromise` sonrası artar.
  - `key_epoch`: anahtar penceresine eşlenir (T20, TN-12).
  - `authz_epoch`: authority plane'de yerini AuthorityStateBasis ve türetilmiş cache anahtarında `applied_pos` alır (C32).
- **28 saatlik access token + sinyal güdümlü iptal önerisi reddedilir** (MD-7). Identity plane access token'ı CT'ye göre PD alır: yönetimde ≤ 60 dk. Sinyal teslimine güvenlik bağlamak garanti dürüstlüğüne aykırıdır (INV-24). Entra CAE'nin 28 saatlik token'ları ve gruplar için 1 güne kadar yayılması bir karşı örnektir.
- "Cache bu kullanıcıyı hiç görmedi" durumu fail-closed'dur (MD-7). Epoch commit-sonrası garanti vermez (MD-7 gerekçesi).
- **C32** AuthorityStateBasis, DecisionRecord içinde (object, version) bağımlılık kümesi + trusted evaluation time olarak bir value'dur; tek global epoch yoktur.
- **L17** Reusable veya auditable her authority decision, değerlendirildiği authoritative state basis'ini tanımlar (AuthorityStateBasis; C32). Tek global epoch yoktur. Reusable, cacheable, portable veya asenkron uygulanabilir her authorization artefaktı açık bir validity/freshness sınırı (ValidityContract) taşır. Point-in-time bir decision response, expiry taşıdığı için reusable credential'a dönüşmez: Decision ≠ Credential. Her verifier beyan edilmiş bir freshness profiline sahiptir.

**Gecikme katmanları.** ValidityContract Δ (§9.12, T10) semantiktir. Gecikme bütçeleri mekanizma hedefidir (EA): A katmanı her istek, p99 < 1 ms (`arc-swap` ile kopyala-değiştir, IP için patricia ağacı); B katmanı refresh anında 50–200 ms; C katmanı asenkron (outbox).

**TN-O1 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-27 | Authority taşıyan her projection holder-bound (PI-11); identity plane access token'ı da DPoP/mTLS'e bağlı; bearer yalnız authority taşımayan, realm'in beyan ettiği eski profilde, varsayılan kapalı | FROZEN (PI-11), PD (eski profil istisnası) | BY SEMANTICS (authority); NOT GUARANTEED (eski profil) | FAPI 2.0 uyumu | PI-11 |
| TN-28 | DPoP doğrulama: RFC 9449 §4.3 profili birebir; `htu` RFC 3986 normalizasyonu; alg allowlist metadata'dan | FROZEN | UNDER DECLARED CAPABILITY | Uygulanabilir doğrulama profili | — |
| TN-29 | DPoP nonce: uzun ömürlü paylaşımlı durumsuz nonce + kayan pencere + bayat tolerans ≤ 5 dk + her 200'de öngörülü nonce; AS/RS ayrı; nonce verildikten sonra nonce'suz kanıt red | PD (süreler), FROZEN (red kuralı) | UNDER DECLARED CAPABILITY | Ölçümlü E.5 modeli | MD-18 |
| TN-30 | Replay cache anahtarı `BLAKE3(htm‖htu‖jti)`, TTL = kanıt ömrü + 2× saat kayması; cache arızası = red | PD (değerler), FROZEN (fail-closed) | UNDER DECLARED CAPABILITY | Duende boyutlandırması | MD-18; MD-8 |
| TN-31 | Public client refresh token'ı DPoP anahtarına bağlı, `dpop_jkt`; rotasyon + reuse detection (aile iptali + `session_epoch` artışı); mobil single-flight; sunucuda ardışık-kullanım toleransı yok | FROZEN (bağlama, reuse), PD (single-flight SDK davranışı) | UNDER DECLARED CAPABILITY | RFC 9449 §5; L19 her refresh yeni karar | — |
| TN-32 | mTLS dağıtım kuralları: endpoint alias, iletilmiş sertifika başlıklarını soyma, tek SAN | PD | UNDER DECLARED CAPABILITY | Dağıtım acıları | — |
| TN-33 | DBSC: identity plane tarayıcı oturumu için iskelet + bayrak; yalnız `jti` zorunlu; 403/4xx/429/404 semantiği; bağlanmamış pencere düşük ayrıcalık | WATCH (şartname), EA (iskelet) | UNDER DECLARED CAPABILITY (tarayıcı desteği) | Editör taslağı; Chrome-only | — |
| TN-34 | SPA'lara BFF resmî öneri; tarayıcı içi OAuth istemcisi iş/kişisel veri için önerilmez; örtük akış yasak; BFF oturum deposu arızası fail-closed | PD | NOT GUARANTEED (istemci ele geçirmesi) | RFC 10017 (doğrulanmadı) | — |
| TN-35 | Device code varsayılan kapalı; açıksa DPoP'a bağlı + client/kapsam/IP gösteren ayrı onay ekranı | PD | UNDER DECLARED POLICY | 2026 cihaz kodu oltalaması | — |
| TN-36 | Identity plane oturumu: boşta (7 g) + mutlak (30 g) PD; olay tabanlı zorunlu iptal; agresif yeniden doğrulama yok; "beni hatırla" CT2+ karşılamaz | PD (değerler), FROZEN (CT2+ ayrımı) | UNDER DECLARED POLICY | Login oturumu identity plane nesnesidir | — |
| TN-37 | Epoch eşlemesi MD-7: `session_epoch` (identity plane), `key_epoch` → anahtar penceresi, `authz_epoch` → AuthorityStateBasis/`applied_pos`; identity plane access token yönetimde ≤ 60 dk; 28 saat red; "hiç görmedi" fail-closed | FROZEN (eşleme), PD (≤ 60 dk) | BY SEMANTICS (ValidityContract); UNDER DECLARED CAPABILITY (epoch hızı) | INV-24 garanti dürüstlüğü | MD-7 |
| TN-38 | Gecikme katmanları A (<1 ms p99), B (50–200 ms), C (async) mekanizma hedefi; semantik Δ ValidityContract'ta | EA | — | Mekanizma bütçe hedefleri | — |

#### 12.2.2 TN-O2 — Sinyaller: SSF/CAEP/RISC vericisi ve alıcısı, SCIM olayları

**Sinyal güvenlik değildir.** SSF kanalı bir güvenlik mekanizması ("iptali standart kanala taşı") olarak konumlanmaz: sinyal transport'tur; güvenlik expiry, version ve checkpoint'e dayanır (INV-24, L18). Bu satır garanti dürüstlüğünün kendisidir.

- **L18** Shared Signals / CAEP transport olarak benimsenir; güvenlik sinyale dayandırılmaz. Access, authority'ye özgü semantic event tiplerini (revoked, narrowed, expired, budget-exhausted, mandate-ended) kendisi tanımlar.
- **INV-24** Bounded staleness; signals carry no safety. Online olmayan her doğrulama, beyan edilmiş bir ValidityContract içinde bounded staleness ile çalışır. Güvenlik expiry, version ve checkpoint'e dayanır; sinyal teslimine dayanmaz. (CI-9, L16, L18)
- **T26** → §16.10 T26 (kanonik metin orada). Bu bölümdeki uygulama: SSF vericisi outbox kaynaklı olayları yayar; event id domain (identity plane olayları için realm) başına anahtarlı HMAC'tir (TI-RT10); sıra garantisi yoktur, alıcı re-query yapar.

**SSF vericisi — authority olayları.** Semantik ve re-query Access'tedir (§9 "Access semantic event'leri" tablosu: `authority-revoked`, `authority-narrowed`, `authority-expired`, `mandate-ended`, `instance-terminated`, `acceptance-changed`, `budget-exhausted`, `revalidation-required`, `projection-invalidated`, `domain-handover` / `domain-recovered`; tablo → §9). Verici zorunlulukları:

1. Keşif `/.well-known/ssf-configuration` (path'li issuer için `/.well-known/ssf-configuration/{path}`).
2. Beş uç nokta: yapılandırma, durum, özne ekle, özne çıkar, doğrulama. Çoklu stream desteklenmiyorsa ikinci stream oluşturma 409 döner.
3. SET kuralları: üst düzey `sub` yok (`sub_id` kullanılır), `exp` yok, SET başına **tek olay**, `txn`, `typ: secevent+jwt`.
4. Teslim: push RFC 8935 (alıcı 202 döner), poll RFC 8936. Yönetim kapsamları `ssf.read` / `ssf.manage`; bu token'lar ≤ 60 dk'dır.
5. **İmza algoritması:** SSF Interoperability Profile RS256 ≥ 2048 bit ister. MD-3 ile çatışma şöyle çözülür: stream başına algoritma alıcının profilinden seçilir; Interop profili isteyen alıcı için realm'de RS256 anahtarı tembel üretilir (MD-3 "RS256 identity plane'de client başına opt-in"); varsayılan ES256 kalır (çözüm: TN-40).
6. Sıra garantisi yoktur (T26); alıcı olay sonrası **re-query** yapar (P33).
7. SSF/CAEP/RISC 1.0 final tarihleri (29 Ağustos 2025, onay 2 Eylül 2025) ve Interop profilinin "10.10.2026 final" durumu **doğrulanmadı** (MD-18).

**SSF vericisi — identity plane olayları.** Suiss'i IdP olarak kullanan RP'ler için identity plane CAEP olaylarını yayınlar: `session-revoked`, `credential-change`, `assurance-level-change`, `token-claims-change`, `device-compliance-change`, `risk-level-change`, `session-established`, `session-presented` (sekiz CAEP olayı) ve RISC olayları (ör. `account-disabled`, `account-purged`, `identifier-recycled`, `credential-compromise`). **Zorunlu eşleme tablosu** (Access olayı ↔ standart CAEP tipi):

| Kaynak | Access/identity plane olayı | Yayınlanan standart tip | Not |
|---|---|---|---|
| `instance.terminate` / recover | `instance-terminated` | CAEP `session-revoked` | Yaklaşık eşleme; her iki SET de yayınlanır |
| `grant.amend` (daraltma), RestrictionPolicy | `authority-narrowed` | CAEP `token-claims-change` | Yaklaşık; alıcı re-query yapar |
| ValidityContract koşulu, policy değişimi | `revalidation-required` | CAEP `assurance-level-change` | Yaklaşık |
| `grant.revoke` / `mandate.revoke` | `authority-revoked` | — (yeni tür, Access namespace) | CAEP karşılığı yok |
| Identity plane parola/passkey/MFA değişimi | (identity plane) | CAEP `credential-change` | — |
| Identity plane oturum iptali, `session_epoch` artışı | (identity plane) | CAEP `session-revoked` | MD-7 |
| SL2 risk değişimi | (identity plane) | CAEP `risk-level-change` | 12.2.4; risk yalnız daraltır |
| Hesap devre dışı / silme | (identity plane) | RISC `account-disabled` / `account-purged`; SCIM olayı (RFC 9967) | CAEP'te hesap silme/devre dışı olayı yoktur |

Olay id'si domain (identity plane olayları için realm) başına anahtarlı HMAC'tir; özne hash'i değildir (TI-RT10). Yeni Access event türü bu bölümde eklenmez; tablo yalnız mevcut türlerin standart karşılığını sabitler (SI-21 "yeni event türü eklemez" ile uyumlu).

**SSF/CAEP alıcısı.** Semantik Access'tedir: gelen olay Claim'dir (AP-7); narrowing sınıfı Claim kota nedeniyle reddedilmez veya quarantine'e alınmaz (T23; §13.7.4 Claim ingest satırı); gelen olay authority yaratamaz (CI-2). Karşı taraf gerçekliği: Okta üretimde verici; Google SSF öncesi RISC uygulaması (adaptör gerekir); Entra'nın SSF alıcı/verici desteği yoktur; Keycloak deneyseldir; `sigshare` alfadır. Alıcı arayüzü gün-1'de, adaptörler fazlıdır.

**SCIM olayları.** SCIM bir Claim ingest yoludur (S-1). SCIM olay URN'leri (RFC 9967; `prov:delete` yük özniteliği taşımaz) yaşam döngüsü boşluğunu kapatır. RFC 9865/9944/9967 numaraları ve tarihleri **doğrulanmadı**. Deprovision ayrıntısı → 12.3.5.

**TN-O2 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-39 | SSF vericisi: well-known keşif (path'li biçim dahil), beş uç nokta, SET kuralları (`sub_id`, `exp` yok, tek olay, `txn`, `secevent+jwt`), push/poll, `ssf.*` token ≤ 60 dk; sıra yok, re-query | PD (profil), FROZEN (sinyal ≠ güvenlik) | NOT GUARANTEED (teslim; N-2) | Semantik Access'te; verici zorunlulukları SSF profilinden | T26; L18 |
| TN-40 | SET imza algoritması stream başına alıcı profilinden; Interop RS256 için realm'de tembel RSA anahtarı; varsayılan ES256 | PD | — | Interop RS256 ↔ MD-3 ES256 varsayılanı | MD-3 |
| TN-41 | Identity plane CAEP/RISC olayları yayınlanır; Access olayı ↔ standart tip eşleme tablosu zorunlu | PD | NOT GUARANTEED (teslim) | Suiss'i IdP olarak kullanan RP'ler | — |
| TN-42 | Alıcı: gelen olay Claim'dir; narrowing kota dışı; authority yaratamaz; adaptörler (Google RISC) fazlı | FROZEN (Claim semantiği), PD (adaptör) | BY SEMANTICS | AP-7, T23, CI-2 | — |
| TN-43 | SCIM olayları Claim ingest; hesap silme/devre dışı RISC + SCIM olayıyla yayınlanır (CAEP'te yok) | PD; WATCH (RFC numaraları) | NOT GUARANTEED (teslim) | CAEP boşluğu | — |

#### 12.2.3 TN-O3 — Step-up ↔ REQUIRE_ACTION

**Köprü.** RFC 9470 challenge yalnız authentication strength'tir, authority değildir (RFC ADOPT satırı). REQUIRE_ACTION daha zengindir (10 kapalı sınıf + 6 remediation kodu, §9.5–9.7 → §9). Eşleme şöyledir:

1. RS/PEP, unmet bir RequirementTerm yalnız **authentication-strength** sınıfındaysa (actor tazeliği, authenticator sınıfı) `401` + `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="…", max_age=300` döndürebilir.
2. `acr_values` **tavsiye**, `max_age` **zorunludur**: OIDC'ye göre AS `acr_values`'ı karşılamayı deneyebilir, `max_age` aşıldıysa yeniden kimlik doğrulamak zorundadır. Authority tarafında tazelik bu yüzden `max_age` + `auth_time` Claim'i ile doğrulanır; `acr` yalnız Acceptance'ta beyan edilen eşlemeyle assurance sınıfına çevrilir.
3. **Intent-bound term'ler bu yoldan çıkamaz**: CT2/CT3 için step-up H(AAS)'ye bağlıdır (§13.7.3); `WWW-Authenticate` challenge'ı intent digest taşımaz, bu yüzden CT2+ requirement'ları REQUIRE_ACTION + AAS ile karşılanır, RFC 9470 ile değil. *[BY SEMANTICS]*
4. REQUIRE_ACTION wire biçimi (unmet, remediation, position, resolver) → §9 / §8.

**Step-up ekranı.** Step-up hangi **exact eylem** için olduğunu söyler ve yetki vermez (X29). "Neden yeniden doğrulama istendiğini açıkla, aksi hâlde kimlik avından ayırt edilemez" kuralı bunun genel hâlidir; X29 ifadesi daha güçlüdür.

- **X29** Identity honesty. Sign-in yüzeyleri yetki iddia etmez; step-up hangi exact eylem için olduğunu söyler ve yetki vermez; recovery mesajları Instance ve Party recovery'sini ayırır ("Your delegations remain; your devices need to sign in again; instance limits must be set again").

**TN-O3 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-44 | RFC 9470 köprüsü yalnız authentication-strength unmet'leri için; `max_age` zorunlu, `acr_values` tavsiye; `acr` → assurance yalnız Acceptance eşlemesiyle; CT2+ intent-bound term'ler RFC 9470'ten çıkamaz | FROZEN | BY SEMANTICS | REQUIRE_ACTION daha zengin; RFC 9470 yalnız köprü | — |
| TN-45 | Step-up ekranı exact eylemi adlandırır ve yetki vermediğini söyler (X29) | FROZEN | BY SEMANTICS (ifade disiplini) | Genel "nedeni açıkla" kuralından güçlü | X29; §8.17.5.4 |

#### 12.2.4 TN-O4 — Risk ve olay müdahalesi

**Risk yalnız daraltır.** Risk skoru bir **Claim**'dir; karar ADP'de verilir (ALLOW/DENY/REQUIRE_ACTION); identity plane kendi giriş sürtünmesi için riski kullanabilir. Yapısal garanti CI-2'dir (risk authority yaratamaz; L28); risk tabanlı restriction'lar varsayılan `undisclosed`'dır (SEC24, §13.7.5). Üç katman mekanizmadır:

| Katman | Girdi | Sonuç | Kural |
|---|---|---|---|
| **SL0** kriptografik gerçekler | DPoP/mTLS uyuşmazlığı, imza hatası, replay | Bloklar (protocol rejection / DENY) | Deterministik |
| **SL1** deterministik politika | RequirementTerm, CT, tazelik | RFC 9470 step-up veya REQUIRE_ACTION | Deterministik |
| **SL2** risk | Davranış/ağ/cihaz sinyalleri | Step-up isteği + CAEP `risk-level-change` + insan kuyruğu | **Asla kalıcı otomatik kilit**; risk yalnız daraltır |

Yanlış pozitiften kaçınma (sekiz madde): gölge (shadow) mod ile başla; IdP-IP ile RP-IP'yi ayır; öğrenme penceresi 5/14 gün; blok yerine step-up; acil durum yolu (→ break-glass, 12.3.8); FP bütçesi SLO'su; kademeli çıkış; "force-now" yönetici iptali. Saldırı korumalarının (bot tespiti, şüpheli IP, kaba kuvvet, ihlal edilmiş parola) her biri engellemeden yalnız günlüğe yazan **izleme modunda** çalışabilir (Auth0 deseni). Risk motoru arızası ALLOW'a dönmez (MD-8). Wiefling, Dürmuth ve Lo Iacono (ACSAC 2020, arXiv 2010.00339; 65 katılımcı laboratuvar çalışması) RBA'nın 2FA'dan daha kullanılabilir, yalnız paroladan daha güvenli algılandığını bulur; küçük örneklemlidir. Uyarlanabilir MFA'nın istem sayısını ne kadar azalttığına dair üretim verisi yoktur.

**Otomatik kararın hukuki sınırı.** SCHUFA C-634/21 (ABAD, 7 Aralık 2023): otomatik skorlama, karara belirleyici katkı yapıyorsa GDPR m.22 kapsamındadır. Bu, "kalıcı otomatik kilit yok + insan kuyruğu" kuralının hukuki dayanağıdır.

**Biyometri ve duygu çıkarımı yasağı.** Risk motoru davranışsal biyometri ve duygu çıkarımı kullanmaz: GDPR m.9 ve KVKK özel nitelikli veri; AI Act m.5 işyerinde duygu tanıma yasağı 2 Şubat 2025'ten beri yürürlüktedir; Annex III biyometrik doğrulama istisnası ve yüksek risk takviminin tarihi (2 Aralık 2027 / 2 Ağustos 2026) belirsizdir, **doğrulanmadı**.

**Olay müdahalesi sırası.** Containment semantiği: kısıtlama yetkisi olan Party tek bir narrowing Exercise'ı ile kapsamı kısıtlar; kısıtı kaldırmak genişletmedir (SI-4); acil durum yolu yalnız önceden verilmiş reserved Grant'tır (SI-22). Runbook sırası (Elastic deseni): **cihaz nesnesi → oturumlar → token'lar**; devir penceresi 10–20 dk. Sıra:

1. `party.compromise` overlay'i veya ilgili Instance'lar için `instance.terminate` (CT1 narrowing; SI-4). `occurredAt` bilinmiyorsa overlay beyan zamanından 72 saat geriye (§13.7.7).
2. Identity plane: cihaz kaydı (DBSC/DPoP anahtarı, passkey) devre dışı; `session_epoch` artışı; refresh ailesi iptali (MD-7).
3. Projection'lar ValidityContract penceresinde kalır; açık pencere UI'da dürüstçe gösterilir (X12).
4. CAEP/RISC olayları yayınlanır (bilgi; güvenlik değil).

- **SI-4** Containment is one attributable act; un-containment is expansion. Restriction yetkisi olan bir Party tek bir narrowing Exercise'ı ile (quorum olmadan) kapsamını kısıtlayabilir; kısıtı kaldırmak genişletme sınıfıdır *[BY SEMANTICS]*
- **SI-22** No emergency path outside the Exercise. Break-glass, legal order, incident response ve containment yalnız önceden verilmiş reserved Grant'ların Exercise'ıdır; fail-open, kill-switch API veya operatör override'ı yoktur *[BY SEMANTICS]*
- **CI-2** Everything else only narrows. Identity, authentication, membership, controller relation, credential possession, policy, risk, claim, device/workload posture, approval-as-evidence ve Work autonomy authority yaratamaz. Yalnız deny edebilir, daraltabilir veya koşullandırabilir. (Authentication ≠ Authority, Membership ≠ Authority, Risk ≠ Authority ve Controller ≠ Authority bu invariant'ın örnekleridir. Membership bir authority rule'unda connective olabilir; o durumda authority'nin kaynağı rule'u koyan root'tur.)

**TN-O4 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-46 | Risk skoru Claim'dir; SL0/SL1/SL2 katmanları; SL2 asla kalıcı otomatik kilit; gölge mod + FP bütçesi + izleme modu; risk arızası fail-closed | FROZEN (risk yalnız daraltır), PD (katman parametreleri) | BY SEMANTICS (CI-2) | Yapısal garanti CI-2; katmanlar işletim mekanizması | — |
| TN-47 | Davranışsal biyometri ve duygu çıkarımı risk girdisi olamaz | FROZEN | UNDER DECLARED POLICY | GDPR m.9, KVKK, AI Act m.5 | — |
| TN-48 | Olay müdahalesi: containment Exercise'ı → cihaz → oturum → token; açık projection penceresi dürüstçe gösterilir | PD (runbook), FROZEN (SI-4, SI-22) | BY SEMANTICS (containment); NOT GUARANTEED (pencere içi kullanım) | Runbook operasyonel; semantik SI-4/SI-22 | — |

### 12.3 Hesap yaşam döngüsü

**Ortak ilke.** Hesap (user record) identity plane nesnesidir. Hesap yaşam döngüsündeki her olay authority plane'e yalnız Claim olarak girer ve authority state'i kendiliğinden değiştirmez; etkisi restriction, actor-binding başarısızlığı veya açık Exercise iledir (E5). Departure ise varsayılansız, açık bir meta-Exercise'tır (E6).

- **E5** Regime state vs authority state. Party creation, key events, controller değişikliği, Party recovery ve termination regime'indir; IdentityBinding ve authenticator binding issuer'larınındır; domain admission, self-anchor, Instance continuity ve departure AuthorityDomain'indir. Regime olayları Access'e yalnız Claim olarak girer ve authority state'i kendiliğinden değiştirmez; etkileri restriction, actor-binding başarısızlığı veya explicit Exercise iledir.
- **E6** Admission and departure. Domain admission party.register meta-Exercise'ıdır ve self-anchor root'unu açıkça belirtir. Departure explicit bir meta-Exercise'tır ve P'nin bütün holding kanallarını varsayılansız kapsar: self-anchor (anchor.retire/anchor.transfer), extensional Grant'lar, Instance'lar (instance.terminate), rule-shaped holding'ler (retain explicit kabul, grantor'ın conjunctive daraltması veya PartyRef'e bağlı RestrictionPolicy overlay'i) ve yeniden giriş kapısı (Public/self bootstrap Grant'larının P için kapalı/açık olduğu, bootstrap Grant terms'ü veya PartyRef overlay'iyle explicit). "Admitted" bir state primitive'i değildir; Exercise kayıtlarından derived'dır.

#### 12.3.1 TN-H1 — Hesap durumları

**Durum makinesi.** Identity plane hesap durumları (Okta sıralaması + mezar taşı):

| Durum | Anlam | Kim geri alır | Authority'ye etkisi (E5) |
|---|---|---|---|
| `staged` (hazırlanmış) | Oluşturulmuş, aktivasyon başlamamış | — | Yok; Party yoksa Claim yok |
| `pending_user_action` | Doğrulama bekliyor | Kullanıcı | Yok |
| `active` | Kullanılabilir | — | actor-binding mümkün |
| `locked` | **Sistem kaynaklı** (politika, başarısız deneme); kendiliğinden kurtarılabilir | Kullanıcı (süre/kurtarma) | actor-binding başarısız (kimlik doğrulama yapılamaz); authority değişmez |
| `suspended` | **Yönetici kaynaklı** askı | Yönetici | `account.status` Claim'i → domain'in varsayılan güvenlik politikası (Genesis şablonu, PD) o realm üzerinden actor-binding'le kurulmuş Instance'lara DENY overlay'i uygular (E5 restriction kanalı; Claim ingest pozisyonundan itibaren; actor gerektirmez); kaldırma genişletmedir (SI-4) |
| `deactivated` | Devre dışı / sağlaması kaldırılmış; uygulama atamaları kaldırılır | Yönetici (yeniden etkinleştirme) | `suspended` ile **en az aynı** daraltma: `account.status` Claim'i → domain'in varsayılan güvenlik politikası (Genesis şablonu, PD) o realm üzerinden actor-binding'le kurulmuş Instance'lara DENY overlay'i uygular (E5 restriction kanalı; Claim ingest pozisyonundan itibaren; actor gerektirmez); kaldırma genişletmedir (SI-4). `instance.terminate` ve gerekiyorsa departure (E6) ayrı **temizlik** Exercise'larıdır (yönetici veya önceden reserved Grant verilmiş identity plane servis Party'si); güvenlik bunlara dayanmaz |
| `tombstone` | Terminal; kimlik ve tanımlayıcı rezerve | Yok | DENY overlay'i kalır (`account.status = tombstone`); kayıt yalnız referanstır, asla karar girdisi değil (12.3.5) |
| `purging` | Kripto parçalama/imha sürüyor | Yok | Yok |

Kilitlenme ile askıya alma **birleştirilmez**: birleştirmek "bunu kim geri alabilir" özelliğini kaybettirir. Zaten sağlaması kaldırılmış hesapta devre dışı bırakma etkisiz (idempotent) yapılır (Okta'nın idempotent olmayan geçişi bir hatadır). Instance/departure tarafı Access'tedir; "Admitted" derived'dır (E6).

**Devre dışı bırakmanın atomikliği.** "Durum, oturumlar, yenileme token'ları ile çevrimdışı token'lar tek işlemdedir" iddiası yalnız identity plane kayıtları için doğrudur. Kural:

1. **Identity plane kayıtları** (hesap durumu, identity plane oturumları, refresh token aileleri, `session_epoch`, identity plane'in kendi bastığı token'ların durum listesi) **tek işlemde** değişir. *[UNDER DECLARED CAPABILITY]*
2. **Authority daraltması** `account.status` Claim'inin ingest'i ve domain'in varsayılan DENY overlay'iyle gelir (E5 restriction kanalı; CT1 narrowing; actor gerektirmez; `party.compromise` deseni). `instance.terminate` ve departure attributable bir Party'nin temizlik Exercise'larıdır; güvenlik bunlara dayanmaz. Bu ayrı bir owner'ın geçişidir ve çapraz atomiklik yoktur (E29). Hiçbir authority **genişlemesi** kendiliğinden olmaz. *[BY SEMANTICS (overlay; politika kurulu ve Claim ingest edilmişse)]*
3. **Offline projection'lar** (PAP, `checkpointed-offline` artefaktlar) beyan edilmiş ValidityContract penceresinde kalır; UI açık pencereyi dürüstçe gösterir (X12).
4. "Offline token'lar atomik olarak iptal edildi" **asla** iddia edilmez. *[NOT GUARANTEED (pencere içi offline kullanım)]*
5. **UI metni garantiye uygun yazılır.** Identity plane oturumlarının bitişi Instance'ların bitişi olarak sunulmaz; "Active sign-ins ended" denmez. Örnek: "Sign-in disabled 14:03. Sign-in sessions ended (identity). Devices' sign-ins are blocked from 14:03 by *Acme*'s account policy. Offline passes may work until 18:00 if devices follow their profile. Agents' delegations from this person are listed below." (→ §8.13)

- **E29** No semantic cross-product atomicity. Atomicity yalnız tek bir owner'ın kendi geçişleri içindir; cross-product akışlar referans, fail-closed ve compensation ile tutarlı kalır; mekanizma §16'dadır.

**Atıl hesap süpürmesi.** Hareketsizlik süpürmesi **inşa edilir**, miras alınmaz (Keycloak'ın açık konusu). Eşikler PD'dir: CIS 5.3 45 gün, PCI DSS 8.2.6 90 gün (kurumsal); tüketici için Google 2 yıl referansı. Hareketsizlik saati imha saatinden **ayrıdır** (12.3.5). Agent delegation'ında zorunlu bitiş zaten vardır (X10); süpürme insan hesabının identity plane kaydı içindir ve authority etkisi yine E5 yolundandır. Break-glass hesapları süpürmeden muaftır ama tatbikatla doğrulanır (12.3.8).

**TN-H1 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-49 | Hesap durum makinesi `staged → pending_user_action → active ↔ locked / suspended → deactivated → tombstone → purging`; locked ≠ suspended; authority etkisi yalnız Claim/Exercise; `suspended`/`deactivated`/`tombstone` → `account.status` Claim'i ile varsayılan DENY overlay (E5 restriction kanalı), `deactivated` ≥ `suspended` daraltması | PD (durum adları), FROZEN (E5 etkisi) | BY SEMANTICS (E5) | "Kim geri alır" ayrımı | E5, E6 |
| TN-50 | Devre dışı bırakma: identity plane kayıtları tek işlemde; authority daraltması `account.status` Claim'i + varsayılan DENY overlay (actor gerektirmez); `instance.terminate`/departure temizlik; offline projection beyanlı pencerede; "offline atomik iptal" ve "Active sign-ins ended" iddiası yasak | FROZEN | UNDER DECLARED CAPABILITY (identity kayıtları) / BY SEMANTICS (overlay, politika kurulu ve Claim ingest edildiyse) / NOT GUARANTEED (offline pencere) | Çapraz atomiklik yok (E29) | — |
| TN-51 | Atıl hesap süpürmesi yerleşik; eşik PD (45/90 gün kurumsal, 2 yıl tüketici); saati imha saatinden ayrı; break-glass muaf | PD | UNDER DECLARED POLICY | CIS/PCI uyumu | — |

#### 12.3.2 TN-H2 — Kurtarma

**Ayrım.** Parola sıfırlama ≠ hesap kurtarma: parola sıfırlama bir authenticator'ın değiştirilmesidir; kurtarma, kullanıcının bir veya daha fazla authenticator'ın kontrolünü kaybettiği hâldir. Instance recovery ≠ Party recovery (X29): Party recovery regime'indir (E5), Instance recovery domain'indir.

**NIST SP 800-63B-4 §4.2 sınıfları.** Birincil metin:

| Sınıf | Normatif kurallar |
|---|---|
| Kayıtlı kurtarma kodları | ≥ 64 bit, onaylı RBG; onaylı tek yönlü fonksiyonla özetli; kısıtlama kurallarına tabi; kullanım sonrası geçersiz ve **yeni kod verilir**; yenileme bir kurtarma bildirimi üretir |
| Gönderilen kurtarma kodları | ≥ 6 ondalık hane; ömür tavanı: posta ABD içi 21 gün / ABD dışı 30 gün, SMS/sesli 10 dk, e-posta 24 saat; en az iki kurtarma adresine izin |
| Kurtarma kişileri | Gönderilen kod kuralları + 24 saat uzatma; görüntüleme/yönetim arayüzü; yıllık hatırlatma |
| Kimlik tespiti tekrarı | İlk tespit seviyesiyle tutarlı adımlar |
| Destek temsilcisi (agent-assisted) | Dört sınıfa **dahil değil**; alternatif yöntem, risk analizi ve dokümantasyon şartlı |

AAL matrisi: AAL1'de herhangi bir sınıf; **AAL2'de** farklı sınıflardan iki kurtarma kodu, **veya** bir kod + hesaba bağlı tek faktörlü authenticator ile doğrulama, **veya** kimlik tespiti tekrarı; AAL3/IAL3'te yerinde/gözetimli tespitte toplanan biyometrikle karşılaştırma. Sonuç: **AAL2 hesap için tek e-posta bağlantısı geçerli kurtarma değildir.**

**Kurtarma korunandan zayıf olamaz.** Üç uygulanabilir kural:

1. Kurtarma yolunun güvence seviyesi hesabın azami güvence seviyesine eşit veya yüksektir; her kurtarma yöntemi bir güvence etiketi taşır; altında kalan yapılandırma **yapılandırma anında reddedilir** (çalışma zamanı hatası değil). Şema kısıtı duruma koşulludur:
   ```sql
   CHECK (state IN ('requested','throttled','locked','denied')
          OR (achieved_aal IS NOT NULL AND required_aal IS NOT NULL
              AND achieved_aal >= required_aal))
   ```
   Koşulsuz `CHECK` ya satır yazmayı engeller ya NULL yüzünden sessizce geçer; enum sırası `aal1 < aal2 < aal3` bilinçli şema sözleşmesidir.
2. Kurtarma içeri girme değil **yeniden inşa** hakkı verir: kurtarma sonrası oturum yalnız authenticator bağlama yetkisiyle açılır (REBIND_OPEN).
3. **En zayıf yol ölçülür ve gösterilir**: hesabın etkin güvenliği tüm giriş yollarının (kurtarma dahil) güvence seviyelerinin en küçüğüdür; yönetim konsolu, S7 ve S10 bunu hesap/Instance başına gösterir.

Authority tarafı (INV-40): `instance.recover` requirement'ı, o Instance'ın Mandate'lerindeki **en sıkı** RequirementTerm'den zayıf olamaz (INV-10 asimetrisi). Kural iki noktada zorlanır: (i) kurtarma yolu yapılandırılırken, Party'nin o anki holding'lerine karşı (zayıf yapılandırma reddedilir); (ii) successor Instance'a Mandate bind/rebind edilirken ve Party'ye yeni bir (özellikle CT3) Grant verilirken, Party'nin geçerli en zayıf kurtarma yolu sınıfına karşı — eşik karşılanmazsa REQUIRE_ACTION (kurtarma yolunu güçlendir) veya bind DENY. Kurtarma sonucu ve kurtarma yolu sınıfı bir Claim (`recovery-result`) olarak successor'ın actor-binding'ine bağlıdır. *[BY SEMANTICS (bind/issue kararı); UNDER DECLARED CAPABILITY (kurtarma yolunun gerçek gücü)]* FIDO 2025: "The prohibition of phishable methods applies to both login and account recovery processes".

**Tipli durum makinesi.** Kurtarma yapılandırılabilir bir akış değil tipli bir durum makinesidir; adım silinerek atlatılamaz (Keycloak 40744: akıştan adım silmek kimlik doğrulama atlatması üretmiştir):

```
[none] ─initiate→ REQUESTED ─evidence_ok→ EVIDENCE_MET ─(cooldown>0)→ COOLING_DOWN ─elapsed→ REBIND_OPEN
REQUESTED ─evidence_fail→ THROTTLED ─(max)→ LOCKED
COOLING_DOWN ─user_denies | normal login→ DENIED  (kurtarma iptal, kurtarma yolları dondurulur, güvenlik olayı)
REBIND_OPEN ─authenticator_bound→ GRACE_PERIOD ─grace_elapsed→ CLOSED
```

- REQUESTED'a geçişte kurtarma kanalı **hariç** tüm bildirim adreslerine bildirim gider. Yalnız e-postayı bilen birinin bu geçişi tekrarlayarak kurtarmayı kilitletmesi (kurtarma engelleme) ayrı bir sınırla önlenir.
- EVIDENCE_MET → COOLING_DOWN'da ikinci bildirim: "şu tarihte tamamlanacak, siz değilseniz iptal edin".
- **Meşru sahibin normal girişi devam eden kurtarmayı otomatik iptal eder** (Apple davranışı).
- DENIED geçişi oturumları **otomatik** iptal etmez: kurtarma girişimini iptal etmek ile oturumları topluca iptal etmek ayrı güvenlik eylemleridir; ikincisi ayrı gerekçe ve yetkiyle tetiklenir.
- Yetki açan geçiş **tek atomik birimde**: durumu doğrula, kanıtı doğrula, kanıtı **tüket**, yetkiyi oluştur. Kabul testi: aynı kanıtla paralel iki yeniden bağlama denemesi. Ekleme-yalnız geçiş kaydı denetlenebilirlik sağlar, doğruluk sağlamaz.
- Veri modeli `recovery_method`, `notification_address`, `recovery_attempt`, `account_recovery_policy` tablolarıdır; şemada `user_id` yerine `(tenant_id, realm_id, user_id)` bileşik anahtarı kullanılır (TN-19).

**Kurtarma sonucu authority mirası değildir.**

- **INV-13** Instance continuity. Instance kimliği authority-binding sürekliliğini izler: o anki geçerli KeyBinding ile authenticate edilmiş kesintisiz continuity zinciri aynı Instance'tır; kırılma yeni Instance'tır. Recovery tek successor üretir ve authority miras bırakmaz. (L21)
- **Hesap kurtarma her zaman successor Instance doğurur.** Eski geçerli KeyBinding ile authenticate edilmiş bir zincir olmadığı için kurtarma authority plane'de **her zaman** Instance continuity kırılmasıdır: tek successor Instance doğar, eski Instance'ın Mandate'leri miras kalmaz, yeniden bağlama INV-40 kapısından geçer (C8, INV-13, X38). Domain bunu yalnız sıkılaştırabilir (daha uzun soğuma, rebind için ek requirement); gevşetemez. Eski Instance'ın bir authenticator'ıyla authenticate edilmiş "cihaz ekleme" kurtarma değildir. *[BY SEMANTICS]*
- Party Grant'ları kalır; Instance yenilenir; Mandate yeniden bağlanır. Kullanıcı mesajı X29'daki gibidir: "Your delegations remain; your devices need to sign in again; instance limits must be set again." GRACE_PERIOD ↔ SEC18 eşlemesi aşağıdadır.

**Soğuma: iki katman.**

1. **Hesap kurtarmanın tamamlanması** (identity plane) soğuma tablosuyla açılır; soğuma bir **itiraz penceresidir**, farklı kanaldan bildirimle anlam kazanır; kanıt gücüyle ters orantılıdır ve riske duyarlıdır. PD varsayılanlar (tasarım önerisi):

   | Hesap tipi | Kurtarma yöntemi | Soğuma |
   |---|---|---|
   | Tüketici, düşük değer | Kayıtlı kurtarma kodu | 0 |
   | Tüketici, düşük değer | Tek başına e-posta kodu | 24 saat |
   | Tüketici, MFA | İki kanal kombinasyonu | Riske göre 1–24 saat |
   | Tüketici, MFA | Kimlik tespiti tekrarı | 0–1 saat |
   | Kurumsal çalışan | Yönetici onaylı geçici erişim (TAP eşdeğeri) | 0 (bant dışı onay var) |
   | Yüksek değerli / yönetici | Her yöntem | ≥ 24 saat + ikinci yönetici onayı |

   Google'ın ters orantısı ("…your account recovery request might be delayed for longer") ve Apple'ın çalıntı cihaz koruması (iOS 26.4'te varsayılan açık, 1 saat + iki biyometrik doğrulama; MacRumors 16 Şubat 2026) referanstır.
2. **Authority kullanımı** (authority plane): yeni authenticator-binding 24 saat boyunca CT2+ requirement'larını karşılamaz (SEC18). Kurtarma yeni bir authenticator bağlamaktır; 24 saat soğuma uygulanır. SEC18'i gevşetmek SI-18'e göre genişletmedir ve CT3'tür. UI bunu açıkça söyler: "Girişiniz açıldı; ödeme, delegasyon ve diğer yüksek etkili işlemler ‹tarih›'ten itibaren kullanılabilir."

- **SEC18** Yeni authenticator-binding veya issuer designation 24 saat boyunca CT2+ requirement'larını karşılamaz; ingest edildiğinde Party'nin Changes görünümünde görünür (SI-13); key-event'lerin Party'ye bildirimi Party Identity Regime yükümlülüğüdür.

Karşı desenler: bildirimsiz soğuma; bildirimin kurtarma kanalına gitmesi; destek tarafından kısaltılabilen soğuma (Apple: "destekle iletişime geçmek bu süreyi kısaltmaya yardımcı olamamaktadır"); yalnız parola değişiminde soğuma; riske kör sabit süre; iptal bağlantısının kurtarmadan zor olması. Soğuma **vaka başına kısaltılamaz**: destek, yönetici veya break-glass Grant'ı devam eden bir kurtarmanın soğumasını kısaltamaz. Soğuma tablosunun değiştirilmesi yalnız realm politikasının **ileriye dönük** değişimidir; bu bir `policy.set` gevşetmesidir (CT3, SI-18) ve değişiklikten önce başlamış kurtarmalara uygulanmaz.

**Kurtarma sonrası kısıtlı oturum.** GRACE_PERIOD boyunca şu işlemler reddedilir veya ek doğrulama ister: e-posta/telefon değişimi; yeni kurtarma adresi; kurtarma kodu yeniden üretimi; mevcut passkey/MFA silme; ikinci yeni authenticator ekleme (ilki serbest); IdP bağlama/bağ kaldırma; rol yükseltme, üye davet, sahiplik devri; toplu dışa aktarım ve taşınabilirlik talebi; ödeme aracı değişimi, para çekme, fatura adresi; **yeni API anahtarı veya uzun ömürlü token**; hesap silme. Authority tarafında aynı sınıfın karşılığı SEC18 ile zaten kapalıdır (CT2+); identity plane listesi authority dışı işlemleri (API anahtarı, dışa aktarım) kapsar. "Yeni API anahtarı" listede olmazsa soğuma anlamsızdır.

**Bildirim.** NIST SHALL kuralları birebir: her kurtarma bildirim üretir; hesap başına **en az iki** bildirim adresi desteklenir; bildirim posta dışındaki tüm adreslere gider; **kurtarma kanalı o kurtarmanın bildirim kanalı olamaz** (şemada zorunlu: `is_recovery_target` adresi tek bildirim adresi olamaz); bildirim itiraz talimatı ve iletişim bilgisi içerir. Authority tarafında genişletme görünürlüğü SI-21'dir; teslim NG'dir (N-2).

- **SI-21** Expansion about you is visible to you. Bir Party'nin adına veya üzerinde authority genişleten her Access meta-Exercise'ı (instance.create, onun adına grant.issue / alt delegation, onu etkileyen acceptance.*) o Party'nin Authority hub ▸ Changes görünümünde Access kayıtlarından derived olarak görünür ve Relay ile iletilir; frozen event kümesinde karşılığı olanlar (ör. acceptance-changed) ayrıca o event'i üretir. Bu spesifikasyon yeni event türü eklemez; ek namespaced event türü gerekirse governance yoluyla açık protocol eklemesi olarak yapılır. Regime key-event'leri (authenticator-binding, designation) Access commit'i değildir → SI-13 *[BY SEMANTICS (derived görünürlük; teslim ayrı satır → N-2)]*

**Asimetrik eşik.** Kayıp/çalıntı bildirimi **tek faktörle** yapılır (yedek authenticator: parola veya fiziksel authenticator); yeni authenticator ekleme tam kurtarma ister (NIST §4.2; "The consequences of not invalidating a compromised authenticator are usually more significant than the denial-of-service potential of invalidating one in error"). Authority tarafında aynı ilke X11 ve SI-4'tür (daraltma CT1, en kısa yoldan).

- **X11** Asymmetric friction. Genişleten eylemler trusted surface'te, exact preview ve gereken assurance ile; daraltan eylemler kullanıcının herhangi bir authenticated yüzeyinden en kısa yolla yapılır.

**Kod kuralları ve hız sınırı.** Kurtarma kodlarında altı sık hata kapatılır: özetsiz saklama, kullanım sonrası yeni kod vermeme, kısıtlama yokluğu, yenilemenin bildirim üretmemesi, "sakladım" onayının alınmaması, on kodun birlikte geçersizleşmesi (her kod tek tek tek kullanımlıktır). Ardışık başarısız deneme authenticator başına **≤ 100** ve aşımda o authenticator devre dışı (üst sınırdır, hedef değil); bot tespiti ve artan bekleme (30 s → 1 saat) izinlidir; hem kayıtlı hem gönderilen kod aynı kısıtlamaya tabidir. Yeni authenticator bağlama, hesaptaki mevcut azami AAL ile yeni authenticator'ın kullanılacağı azami AAL'den **düşük olanı** kadar kimlik doğrulama ister; cihazlar arası bağlama kodu: tanımlayıcı da giriliyorsa ≥ 40 bit, değilse ≥ 112 bit; tek kullanımlık; ≤ 10 dk; güvensiz kanaldan (e-posta açıkça) iletilmez; elle veya QR ile yerel bant dışı aktarılır.

**Asistanlı kurtarmayı kapatma.** Yüksek değerli hesap "asistanlı kurtarmayı kapat" seçebilir (Apple Recovery Key modeli: "you turn off Apple's standard account recovery process … you'll be locked out of your account permanently"); kalıcı kayıp riski açıkça onaylatılır (`permanent_loss_acknowledged_at`). Domain düzeyindeki eşdeğer dürüstlük ilkesi §13.7.7'deki "Recovery not available" (NG) satırıdır; nesneler farklıdır (hesap ↔ domain).

**Yardım masası.** NIST faktör izolasyonu: "one authentication factor cannot be leveraged to obtain an authenticator of a different factor". Scattered Spider zinciri (AA23-320A, güncelleme 29 Temmuz 2025) önce sıfırlama prosedürünü öğrenir, sonra yardım masasını arar; kurtarma prosedürünün kendisi gizlilik değeri olan bir varlıktır. Vakalar: MGM 2023, Okta müşterileri 2023, Clorox–Cognizant, M&S/Co-op/Harrods 2025, Twitter 2020, Robinhood 2021; MGM ayrıntısı ve 2026 dolaşımdaki rakamlar **doğrulanmadı**. Kural:

1. Identity plane action şemasında **başkasının kimlik bilgisini doğrudan yazan action yoktur** (`credential.set` yok). Bu bir izin ayarı değil **ayrıcalık tavanıdır**. Yalnız **niyet belirteci** (Kanidm `_update_intent` modeli) üreten action vardır: varsayılan ömür 1 saat, tavan 24 saat; tek kullanımlık, işlendiği anda geçersiz; belirteçle açılan oturum yalnız kimlik bilgisi kurabilir; üretim ve kullanım ayrı denetim olaylarıdır, üretim yöneticinin kimliğini taşır; belirteç kurtarma kanalından farklı kayıtlı bir bildirim adresine gönderilir.
2. Niyet belirtecinin üretilmesi bir domain action'ıdır ve Exercise kaydıyla attributable'dır (MD-14). Hedef kullanıcıya SI-21 + identity plane bildirimi gider.
3. Sınırı yazılır: niyet belirteci yardım masası riskini kaldırır, **kanal kaybı riskini kaldırmaz** (adres kaybında akış kalıcı kayıp senaryosuna düşer).

**Kurtarma yetkisi nesnesi.** Entra TAP eşdeğeri (varsayılan ömür 1 saat, aralık 10 dk–30 gün, tek kullanımlık seçeneği, uzunluk 8–48, kullanıcı başına tek kod, kimse kendisi için oluşturamaz) bir **identity plane nesnesidir** (taşıyıcısına kimlik doğrulayıcı bağlama penceresi açan bir authenticator). Verilmesi bir Exercise'tır (attributable; INV-28 disipliniyle reserved/requirement'lı şablon). Varsayılan niyet belirtecidir; TAP yalnız realm açıkça seçerse sunulur, çünkü TAP telefonda okunabilir, niyet belirteci kayıtlı adrese gider. TAP oturumu yalnız authenticator bağlama yapabilir; yeni bağlanan authenticator SEC18 soğumasına tabidir.

**Güvenlik metriği.** Kurtarma ve katılımın yeniden tetiklenme oranı bir güvenlik metriğidir (Unit 42, Ağustos 2026 tavsiyesi; golden passkey saldırısına karşı). Hesap ele geçirmelerin yüzde kaçının kurtarma akışından geçtiğine dair **yayımlanmış veri yoktur**; uydurulmaz.

**Passkey kaybı.** Senkron passkey kullanıcı kaybını çözer, kurtarma sorumluluğunu platforma devreder; platform hesabı kaybı tüm senkron passkey'leri götürür; cihaza bağlı passkey AAL3'e uygundur, senkron (dışa aktarılabilir) anahtar değildir. Kurallar:

1. **Bağımsızlık grubu**: aynı senkronizasyon dokusundaki iki passkey tek authenticator sayılır (AAGUID + BE/BS bayraklarıyla çıkarılır).
2. Senkron passkey tek başına "tam korumalı" sayılmaz; bağımsız ikinci kurtarma yolu (kayıtlı kod, ikinci cihaza bağlı credential, kurtarma kişisi) kurulmadan hesap tam korumalı gösterilmez.
3. BS bayrağının 0→1 değişimi, AAGUID değişimi ve yeni cihazdan ilk kimlik doğrulama risk sinyali olarak günlüğe yazılır.
4. Alan adı/RP ID değişimi bir **güvenlik olayıdır**: tüm kullanıcı tabanı aynı anda en zayıf kurtarma yolunu kullanır; planlanır, kademelendirilir ve kurtarma yolu o dönem için sertleştirilir (TN-17).

**§13.7.7 satırları (tam metin; tablonun tamamı → §13.7.7, burada ilgili satırlar):**

| Parametre | Değer |
|---|---|
| rootTerms `domain.recover` entry'si | 3-of-5 (org) / 2-of-3 (küçük); ≥ 2 donanım-bağlı; **hiçbiri provider/operatör custody'sinde değil**; independence: Joint root'ta distinct Party/controller, Sole root'ta aynı Party'nin ayrı donanım-bağlı recovery Instance'ları (distinct device/assurance path) — kurulamıyorsa S7'de "Recovery not available" (NG); rollback guard: değerlendirici beyan edilmiş her witness'ın en yeni checkpoint Claim'ini ve beyan edilmiş replica'dan yeniden üretilen en yüksek witness'lı checkpoint'i (R*) kendisi sorgular (freshness ≤ 1 saat; quorum = bütün beyan edilmiş witness'lar); N < R* her durumda DENY; replica yok/sorgulanamaz veya R* < witness en yüksek ise ayrıca REQUIRE_ACTION (meta-anchor genel threshold'u) + N = R* + beyanlı kayıp suffix; quorum alınamazsa meta-anchor genel threshold'u (REQUIRE_ACTION); çatallanmada N kayıtlarla yeniden üretilebilen dalı izler (SEC22) |
| Custody | CT3 tutanlar non-custodial; custodial mod user-gated (SEC17) |
| Cooling | Yeni authenticator-binding / designation: 24 saat CT2+ için kullanılamaz (SEC18) |
| `party.compromise` occurredAt bilinmiyorsa | Overlay beyan zamanından 72 saat geriye |
| Operasyonel imza anahtarı ömrü (hedef) | ≤ 24 saat (mekanizma T20) |

Bu satırlara ek: operasyonel imza anahtarı ömrünün varsayılanı 1 saattir, üst sınırı 24 saattir (MD-6); `party.compromise` sonrası identity plane'de `session_epoch` artar (MD-7).

**TN-H2 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-52 | Parola sıfırlama ≠ kurtarma; NIST dört sınıf; destek temsilcisi alternatif yöntem (risk analizi şartlı); AAL2'de tek e-posta kurtarma değildir | FROZEN (ayrım), PD (izinli sınıflar) | UNDER DECLARED POLICY | Birincil NIST metni | — |
| TN-53 | Kurtarma ≥ korunan: yapılandırma anında red; durum-koşullu `CHECK`; atomik kanıt tüketimi; en zayıf yol metriği konsol/S7/S10'da; `instance.recover` ≥ Mandate'lerin en sıkı term'i, ayrıca rebind/yeni Grant anında en zayıf kurtarma yoluna karşı zorlanır (INV-40); kurtarma her zaman successor Instance | FROZEN | UNDER DECLARED CAPABILITY (identity plane); BY SEMANTICS (`instance.recover`, INV-10) | Ölçülebilir değişmez | — |
| TN-54 | Kurtarma tipli durum makinesi; adım silinemez; normal giriş kurtarmayı iptal eder; DENIED oturum iptalini otomatik tetiklemez; kurtarma engelleme için ayrı sınır | FROZEN | UNDER DECLARED CAPABILITY | Keycloak 40744; Apple | — |
| TN-55 | İki katmanlı soğuma: identity plane tablosu (PD, ters orantılı, riske duyarlı, vaka başına kısaltılamaz; tablo değişimi yalnız ileriye dönük `policy.set`, CT3) + SEC18 (CT2+ 24 saat; gevşetme CT3); UI tarihi söyler | FROZEN (SEC18; vaka-başı kısaltma yasağı), PD (tablo; politika değişimi CT3) | BY SEMANTICS (SEC18); UNDER DECLARED POLICY (tablo) | İki ayrı katman | SEC18, SI-18 |
| TN-56 | GRACE_PERIOD kısıt listesi (API anahtarı/uzun ömürlü token dahil) | PD | UNDER DECLARED POLICY | Soğumayı atlatan her mekanizma kapatılır | — |
| TN-57 | ≥ 2 bildirim adresi; kurtarma kanalı ≠ bildirim kanalı (şema); itiraz talimatı | FROZEN | UNDER DECLARED CAPABILITY; NOT GUARANTEED (teslim) | NIST SHALL | — |
| TN-58 | Kayıp bildirimi tek faktör; ekleme tam kurtarma | FROZEN | UNDER DECLARED CAPABILITY | NIST asimetrisi = X11/SI-4 | — |
| TN-59 | Kod kuralları (≥ 64 bit, özet, tek tek tek kullanım, yeniden üretim bildirimli), ≤ 100 deneme, bağlama kodu 40/112 bit ≤ 10 dk e-posta değil, bağlama AAL kuralı | FROZEN (NIST SHALL), PD (eşik altı değerler) | UNDER DECLARED CAPABILITY | Normatif | — |
| TN-60 | Asistanlı kurtarmayı kapatma seçeneği, kalıcı kayıp onayı | PD | NOT GUARANTEED (erişilebilirlik) | Apple modeli; "Recovery not available" dürüstlüğü | §13.7.7 |
| TN-61 | `credential.set` yok (ayrıcalık tavanı); yalnız niyet belirteci (1 s / ≤ 24 s, tek kullanım, ayrı denetim, yalnız credential kurma, farklı adrese teslim); üretimi Exercise | FROZEN | BY SEMANTICS (action şemasında yok) | Scattered Spider zincirini kırar | — |
| TN-62 | TAP eşdeğeri kurtarma yetkisi nesnesi identity plane nesnesi; verilmesi Exercise; varsayılan niyet belirteci; TAP oturumu yalnız bağlama | PD | UNDER DECLARED POLICY | INV-28 disiplini | — |
| TN-63 | Bağımsızlık grubu (aynı senkron doku = 1); senkron passkey tek başına tam koruma değil; BS/AAGUID değişimi sinyal; yeniden tetiklenme oranı metrik; alan adı değişimi güvenlik olayı | PD | UNDER DECLARED CAPABILITY | Golden passkey; NIST ek | — |

#### 12.3.3 TN-H3 — Bağlama ve birleştirme

**Ön ele geçirme.** Sudhodanan ve Paverd (USENIX Security 2022; arXiv 2205.10174): 75 servis, 35 zafiyetli, 56 zafiyet, 252 deneme; beş varyant (klasik–federe birleştirme, süresi dolmayan oturum, truva tanımlayıcısı, süresi dolmayan e-posta değişimi, doğrulamayan IdP) + e-posta doğrulama hilesi. Sınıf hâlâ canlıdır: better-auth GHSA-qq9h-g4jm-xgf3 (26 Haziran 2026, CVSS 8.3): "A password set before anyone proved control of the mailbox kept working after the owner proved control.". Kurallar:

1. **Sahiplik kanıtı geldiğinde, o kanıttan önce oluşturulmuş her kimlik bilgisi ölür** ve oturumlar iptal edilir (değişmez; TNI-5).
2. Onay kodu dönmeden **hesap satırı yaratılmaz** (12.3.6).
3. Parola sıfırlamada: diğer tüm oturumlar ve token'lar düşer; bekleyen e-posta değişimleri iptal edilir; bağlı federe kimlikler/alternatif e-postalar/telefonlar gösterilir ve varsayılan **bağı kopar**dır.
4. MFA etkinleştirildiğinde ondan önce kurulmuş oturumlar geçersizleşir ("the service must also invalidate any sessions created prior to the activation of MFA").
5. E-posta değişim yeteneğinin ömrü asgaridir ve parola sıfırlamada iptal edilir; doğrulanmamış hesaplar budanır, tanımlayıcı başına yeniden oluşturma sert kota yerine bot tespitiyle sınırlanır.

**Güvenli bağlama.** Acceptance hangi use için kabul edildiğini söyler (E18: actor-binding, predicate-input, subject-selection, foreign-authority ayrı Acceptance'lardır); bağlama ayrıca bağlama anında kontrol kanıtı ister. Bağlama bir **identity-binding kaydıdır ve Claim üretir**; realm'ler arası bağlama IdentityBinding'dir (TN-2) ve bir Exercise kaydıyla attributable'dır (MD-14); bağ iki taraflıdır: her yarı kendi realm'inin yönetişim domain'inde commit edilir ve her iki tarafta kontrol kanıtı gerekir (12.1.3). Yedi koşul:

1. E-posta doğrulanmış olmalı ve bu RP'nin **kendi kayıtlarında** olmalı; gelen IdP'nin iddiası yetmez.
2. Gelen IdP açık bir güvenilir doğrulayıcı allowlist'indedir (= o issuer için predicate-input Acceptance'ı); kendi IdP'sini getirenlere toptan güvenilmez (doğrulamayan IdP saldırısı; OneLogin ve Okta test hesapları örneği).
3. Bağlama anında mevcut hesabın kontrolü kanıtlanır (parola tekrarı, bağlı sağlayıcıyla yeniden kimlik doğrulama veya mevcut adrese onay).
4. Mevcut hesap doğrulanmamış veya atılsa, federe/parolasız giriş otoriter sahiplik kanıtıdır ve önceki kimlik bilgisi yok edilir.
5. Bağlama anında diğer oturumlar ve bekleyen e-posta değişimleri iptal edilir.
6. Birleştirme anahtarı `(iss, sub)`'dır; e-posta yalnız arama ipucudur.
7. Gelen tarafın doğrulamadığı e-postayla veya saldırganın kontrol edebileceği bir issuer üzerinden asla otomatik bağlama yapılmaz.

OIDC Core 5.7: kararlı tanımlayıcı yalnız `iss` + `sub`'dır.

- **E18** IdP acceptance uses are distinct. Authentication trust (actor-binding), identity claim acceptance (predicate-input), authority-selecting acceptance (subject-selection, reserved) ve foreign authority acceptance (foreign-authority, reserved) ayrı Acceptance'lardır; biri diğerini ima etmez. External IdP compromise, önceden kabul edilmiş rule-shaped seçim ve ceiling'lerin ötesinde authority üretemez.

**`(iss, sub)` anahtarı ve tanımlayıcı geri dönüşümü.** Anahtar `(iss, sub)`'dır; Entra için `(tid, oid)` (Microsoft'un kendi tavsiyesi: `sub` uygulama başına ikilidir). `sub` değişiminde otomatik yeniden bağlama **yapılmaz**; bir çakışma olayı üretilir ve kullanıcı/yönetici akışına düşer. "Büyük bir sağlayıcıda `sub` girişlerin ~‰4'ünde değişir" itirazı ikincil kaynaktır, **doğrulanmadı**. Tanımlayıcı geri dönüşümü (Google Workspace 20/30 gün, GitHub 90 gün) için `mailbox_owner_since` tutulur ve giden kurtarma postasında RFC 7293 (Require-Recipient-Valid-Since) kullanılır.

**Birleştirme geri alınamaz; bağlama tercih edilir.** Birleştirme metadata kaybettirir (Auth0) ve geri alınamaz; tercih bağlamadır; birleştirme yapılırsa öncesinde anlık görüntü + denetim olayı zorunludur. Authority tarafında: **Party birleşmesi lineage veya authority birleştiremez**; iki Party'nin Grant'ları, Mandate'leri ve Anchor'ları ayrı kalır; birleştirme yalnız identity plane kaydını ve bir IdentityBinding Claim'ini değiştirir (E5; OAuth Grant Management `merge` REJECT). *[BY SEMANTICS]*

**Son kimlik doğrulama yöntemi.** Hesaptaki son kullanılabilir kimlik doğrulama yönteminin kaldırılması **şema seviyesinde** engellenir (Keycloak'ın son credential davranışı). Keycloak ayrıntısı **doğrulanmadı**.

**E-posta değişimi, posta kutusu devri, odak/izdüşüm.** E-posta bir izdüşüm niteliğidir; **hiçbir izdüşüm niteliği odağın anahtarı olamaz** (midPoint odak/izdüşüm kavramı). Kurumsal posta kutusu başkasına geçebilir (Lauinger: ~%10 yeniden kayıt); bu yüzden e-posta bağlaması `mailbox_owner_since` taşır. Access'te aynı ilke E27'dir.

- **E27** References ≠ ownership. PartyRef, ResourceRef, WorkRef, ActionRef, ExerciseID, GrantID, ClaimID, AuthorityDomainID, EffectRef güvenle sınır geçer; hiçbiri işaret ettiği state'in canonical kopyasını taşıma hakkı vermez.

**TN-H3 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-64 | Sahiplik kanıtı önceki kimlik bilgilerini öldürür ve oturumları iptal eder; doğrulama öncesi hesap yok; sıfırlamada oturum düşürme + bekleyen e-posta değişimi iptali + varsayılan bağ koparma; MFA etkinleştirmede önceki oturumlar geçersiz | FROZEN | UNDER DECLARED CAPABILITY | USENIX 2022; better-auth 2026 | — |
| TN-65 | Bağlama = identity-binding kaydı + Claim (realm'ler arası IdentityBinding, Exercise ile attributable; iki yarılı, her iki tarafta kontrol kanıtı ve kendi yönetişim domain'inde commit); yedi koşul; IdP allowlist = predicate-input Acceptance | FROZEN | BY SEMANTICS (E18); UNDER DECLARED CAPABILITY (koşullar) | Bağlama anında kontrol kanıtı + use ayrımı (E18) | — |
| TN-66 | Anahtar `(iss, sub)`; Entra `(tid, oid)`; `sub` değişimi çakışma olayı (otomatik yeniden bağlama yok); `mailbox_owner_since` + RFC 7293 | FROZEN (anahtar), PD (olay akışı) | UNDER DECLARED CAPABILITY | OIDC Core 5.7; Microsoft tavsiyesi | — |
| TN-67 | Birleştirme geri alınamaz, bağlama tercih; birleştirmede anlık görüntü + denetim; Party birleşmesi lineage/authority birleştirmez | FROZEN | BY SEMANTICS (authority); UNDER DECLARED CAPABILITY (snapshot) | Auth0 metadata kaybı; `merge` REJECT | — |
| TN-68 | Son kimlik doğrulama yöntemi şema seviyesinde korunur | PD | UNDER DECLARED CAPABILITY | Kendi kendini kilitleme | — |
| TN-69 | E-posta izdüşümdür, odak anahtarı olamaz; posta kutusu devrine karşı `mailbox_owner_since` | FROZEN | UNDER DECLARED CAPABILITY | E27 ile aynı ilke | — |

#### 12.3.4 TN-H4 — Destek erişimi (kimliğe bürünme yok)

**Model (MD-9).** Kimliğe bürünme semantiği **yoktur** (X20 "impersonation yok"). Destek erişimi iki yoldan birindedir:

1. **Kullanıcının kendi Grant Exercise'ı**: kullanıcı (Party P) destek operatörü Party'sine (veya destek ekibi rule-shaped seçicisine) `grant.issue` ile FOR(P) delegasyon Grant'ı verir; operatör kendi Instance'ından exercise eder (Grant'ın holder'ı Party/seçicidir, Instance'a bağlanan Mandate'tir; C1, C14). Bu Grant iptal edilebilir ve kaskad eder (C16, INV-31 dışı extensional Grant); kullanıcının kendi `grant.issue`'su CT2'dir ve kendi assertion'ıyla karşılanır (§13.7.1 karşılanabilirlik kuralı (b)).
2. **Reserved break-glass Grant'ı**: önceden verilmiş, reserved, requirement'lı, zaman sınırlı (INV-28, SI-22); 12.3.8.

Operatörün etkin yetkisi Exercise başına tek basis'tir (INV-4); dolayısıyla "operatör hakları ∩ özne hakları" kesişimi yapısaldır (ServiceNow modeli). Aşağı akış token'ı (projection) RFC 8693 **delegation** biçimindedir: `sub` = kullanıcı, `act` = operatör; ayrı bir "impersonation token tipi" yoktur. `act` projection ve ipucudur; önceki aktörler lineage'dan doğrulanır (L22). RFC 8693'ün impersonation vs delegation ayrımı, `act`, `may_act`, iç içe `act`'in bilgi amaçlı olması ve token exchange'in revocation yaymaması taşıyıcı profilin girdisidir.

- **X20** Admin experience. Rol sürümleme ve change-impact preview; "Full access" yok; Acceptance ekranı use'u sade dille ve blast radius'uyla gösterir; reserved değişiklikler quorum Gate'iyle koordine edilir; offboarding her kanal için explicit seçim ister; impersonation yok; toplu işlemler attributable Exercise kümeleridir.
- **L22** Token'lardaki actor chain (act) projection ve ipucudur. Prior actor'ler token'dan değil Access lineage'ından doğrulanır.
- **INV-28** No implicit super-authority. Exceptional authority (break-glass, legal order, emergency) yalnız önceden explicit verilmiş, reserved, requirement'lı, zaman sınırlı Grant'lar olarak vardır ve aynı Exercise disiplinine tabidir; ayrı evaluator yoktur. (CI-13)

**Destek delegasyonunun 12 değişmezi → POLICY DEFAULT (MD-9).** `DelegatedSession` nesnesi yoktur; değişmezler destek delegasyonu Grant şablonunun PD'leridir:

| # | Değişmez | Access karşılığı | Statü / garanti |
|---|---|---|---|
| 1 | Token daima `sub` = kullanıcı, `act` = operatör; bürünme modu yok | Projection RFC 8693 delegation biçimi; actor AIS'ten (PI-7) | FROZEN; BY SEMANTICS |
| 2 | Ayrıcalık kesişimi; operatörün yönetici hakları askıda | Exercise başına tek basis (INV-4): yalnız FOR(P) Grant'ı kullanılabilir | FROZEN; BY SEMANTICS |
| 3 | Yasak işlem listesi motor seviyesinde | Yasak liste = `idp.account.*` namespace'inde **reserved** bayraklı action'lar + şablonda dışlama; liste: kimlik bilgisi/MFA değişimi, birincil e-posta/telefon, hesap silme ve toplu/yıkıcı silme, ödeme/faturalama, toplu dışa aktarım, rol yükseltme/izin verme/davet, yeni API anahtarı/uzun ömürlü token | Reserved bayrağı BY SEMANTICS (wildcard ile kapsanamaz, E11); şablonda dışlama PD; yasaklayan RestrictionPolicy UNDER DECLARED POLICY |
| 4 | Gerekçe boş olamaz | **Zorunlu typed PurposeRef**; serbest metin redakte edilebilir intent body'de veya WorkRef'te | PurposeRef zorunluluğu PD (şablon); typed alan TN-73 FROZEN |
| 5 | Mutlak tavan 60 dk; uzatma yeni rıza | Grant validity ≤ 60 dk; uzatma = yeni `grant.issue` (C16) | PD |
| 6 | Başlangıç/bitiş/eylem başına denetim, operatöre atıf | Her Exercise kaydı AIS'li ve operatöre attributable (PI-7, INV-2) | FROZEN; BY SEMANTICS |
| 7 | Özneye bildirim zorunlu | Rıza yolunda SI-21 + Relay. Break-glass Grant'ının **kullanımı** meta-Exercise değildir (SI-21 kapsamı dışı): kullanım kaydı Exercise kaydıdır; özneye bildirim break-glass Grant şablonunun zorunlu `notify-subject` requirement'ıyladır | FROZEN (rıza yolu görünürlüğü); kullanım kaydı BY SEMANTICS; break-glass bildirimi UNDER DECLARED POLICY; teslim NOT GUARANTEED (N-2) |
| 8 | Org politikası izin veriyorsa kullanıcı yasaklayabilir | Rıza yolunda varsayılan "yok"tur: Grant verilmezse erişim yoktur. Kullanıcının kendi RestrictionPolicy'si (self-restriction, X13) destek Grant'ını daraltır; kaldırma kendi Exercise'ı. Break-glass yolu yalnız self-anchor rootTerms'ünde admission'da (E6) beyan edilmiş reserved istisnai Grant olarak vardır; self-restriction'a karşı muafiyeti ancak o policy'de beyanlıysa geçerlidir (12.6 satır 91); beyan yoksa self-restriction break-glass'ı da daraltır | BY SEMANTICS (Grant yoksa erişim yok; kullanım kaydı); PD (self-restriction); UNDER DECLARED POLICY (break-glass muafiyeti) |
| 9 | Özyineleme yasak; derinlik 1 | Delegation derinliği **0** (destek Grant'ı delegable değil) | PD |
| 10 | `may_act` veya org politikası yoksa red | Kullanıcının FOR(P) Grant'ı veya break-glass Grant'ı yoksa DENY; `OrgPolicy` yalnız organizasyonun kendi kaynaklarında | FROZEN; BY SEMANTICS |
| 11 | Devredilmiş oturum öznenin oturumlarını etkilemez; iptal ayrı yayılır | Destek Grant'ı ayrı Grant; `grant.revoke` kaskadı yalnız onu etkiler; kullanıcının Instance'ları etkilenmez | FROZEN; BY SEMANTICS |
| 12 | Destek artefaktları ayrı ayrıcalık sınıfı; token içerenler otomatik redakte | Destek artefaktları (HAR, log, ekran kaydı) ayrı Grant ile okunur; token/çerez içeren alanlar yüklemede otomatik redakte (Okta Ekim 2023 HAR olayı) | PD; UNDER DECLARED CAPABILITY (otomatik tespit); redakte edilmiş kaydın digest doğrulanabilirliği BY SEMANTICS (INV-30) |

**Hesap kaynaklarının ActionRef'i ve root'u.** Destek erişiminin hedefi identity plane hesap kaynakları üzerindeki domain action'larıdır: identity plane `idp.account.*` namespace'ini yayınlar (`read`, `profile.update`, `credential.*`, `email.change`, `delete`, `export` …; E34 uzantısı); yukarıdaki #3 listesindeki eylemler bu namespace'te reserved bayraklıdır. Hesap kaynakları kullanıcının self-anchor kapsamındadır (`scope = Party(P)`). Statü ve garanti sütunları §8.16 ile tek kaynaktır: #1, #2, #6, #10, #11 modelden gelir (FROZEN / BY SEMANTICS); MD-9'daki "PD" ifadesi şablon değerleri için okunur.

**Organizasyon politikasıyla rıza.** Org yöneticisi yalnız FOR(org) verebilir (organizasyonun kendi Anchor'ı altındaki kaynaklar); FOR(Alice) — Alice'in kişisel kaynakları veya Alice adına eylem — yalnız Alice'in kendi Exercise'ıdır. `ConsentRecord::OrgPolicy` varyantı bu sınırla daraltılır. `ConsentRecord::DualApproval` → Grant şablonunda ≥ 2 contribution RequirementTerm'i (SEC10/SEC26); `ConsentRecord::BreakGlass` → reserved break-glass Grant'ı.

**Gerekçe.** Authority sınırı typed PurposeRef'tir ("serbest metin asla", §5.3). Serbest metin gerekçe (vaka numarası, açıklama) redakte edilebilir intent body'de veya WorkRef bağlamında kalır, authority taşımaz. Work ↔ Access dikişi → §7.

**Ürün ve olay bağlamı.** Salesforce, Okta (8 saat salt okuma, çift onay), ServiceNow (kesişim), GitLab (denetim), Zendesk (karşı örnek), Shopify, WorkOS (60 dk), Auth0 (kullanımdan kaldırılmış), Discourse. Twitter 2020 (NYDFS raporu: "require certification or approval by a second employee"), Okta Ekim 2023 (destek sistemi ihlali, bürünme özelliğinin suistimali değil; HAR dosyaları), Robinhood 2021. "Bu listedeki hiçbir ürün on ikisinin hepsini yapmamaktadır".

**TN-H4 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-70 | Kimliğe bürünme yok; destek erişimi = kullanıcının destek operatörü Party'sine/seçicisine FOR(P) `grant.issue`'su (CT2, iptal edilebilir, kaskad; operatör kendi Instance'ından exercise eder) veya self-anchor rootTerms'ünde beyanlı reserved break-glass Grant; projection RFC 8693 delegation (`sub`=kullanıcı, `act`=operatör); ayrı impersonation token tipi yok | FROZEN | BY SEMANTICS | İptal ve kaskad | MD-9 |
| TN-71 | 12 destek değişmezi destek Grant şablonunun PD'leri (tablo); yasak liste = `idp.account.*` reserved action'ları; ≤ 60 dk; derinlik 0; SI-21 (rıza yolu) / `notify-subject` (break-glass); artefakt redaksiyonu; statü/garanti §8.16 ile tek kaynak | PD (şablon değerleri), FROZEN (1, 2, 6, 10, 11) | Satır bazında (tablo) | Model Grant; değişmezler şablon varsayılanı | MD-9 |
| TN-72 | `OrgPolicy` yalnız organizasyonun kendi kaynaklarında; FOR(Alice) yalnız Alice'in Exercise'ı; DualApproval → contribution term; BreakGlass → reserved Grant | FROZEN | BY SEMANTICS | Agency continuity | MD-9 |
| TN-73 | Typed PurposeRef zorunlu; serbest metin redakte edilebilir intent body/WorkRef'te | FROZEN | BY SEMANTICS | "Serbest metin asla" | — |
| TN-74 | Destek artefaktları ayrı ayrıcalık sınıfı; token/çerez içeren alanlar yüklemede otomatik redakte | PD | UNDER DECLARED CAPABILITY | Okta Ekim 2023 | — |
| TN-137 | **Destek erişimi deneyimi (impersonation yasağı korunur, MD-9).** (1) **Tek tıkla talep ve onay:** destek operatörü erişim ister; kullanıcıya uygulama içi, e-posta veya push bildirimiyle onay isteği gider; onay CT2 `grant.issue` Exercise'ıdır (TN-70); talep ve onay yüzeyi hazır bileşen olarak sunulur (TN-133). (2) **Önceden izin:** kullanıcı hesap ayarlarında süreli destek izni açabilir (ör. 24 saat); bu da aynı Grant'tır, iptal edilebilir. (3) **B2B:** organizasyon politikası destek ekibine yalnız **organizasyonun kendi kaynaklarına** önceden erişim verebilir (TN-72); bir çalışanın kendi hesabı adına (FOR(P)) erişim yalnız o çalışanın Grant'ıyla olur. (4) **"Kullanıcının gözünden gör" modu:** operatör kullanıcının yetkileriyle yalnız okuma yapar; hiçbir yazma ve consumption-bearing action exercise edilemez; okuma da Grant kapsamındadır ve kayda girer. (5) 12 destek değişmezi (§8.16, TN-71) aynen geçerlidir: operatör kendi Instance'ıyla çalışır ve kayıtta kendisi görünür; `idp.account.*` reserved action'ları (parola, MFA, silme) destek Grant'ıyla yapılamaz; süre sınırı; kullanıcıya bildirim | FROZEN (model, MD-9, salt okuma modu yazma yapamaz); PD (süreler, bildirim kanalları) | BY SEMANTICS | Destek kolaylığı impersonation'a geçmeden sağlanır; zayıflık kural değil kullanım sürtünmesiydi | MD-9; TN-70; TN-72; §8.16 |

#### 12.3.5 TN-H5 — Sağlama kaldırma, silme, mezar taşı, saklama, taşınabilirlik

**SCIM'in sınırı ve hareket eden çalışan.** SCIM Access için bir Claim kaynağıdır (S-1); SCIM'in `active` niteliğinin anlamı sağlayıcıya bırakılmıştır (RFC 7643 §4.1.1: "The definitive meaning of this attribute is determined by the service provider"); çekirdek SCIM'de mezar taşı veya silinme zamanı yoktur. Kural:

1. SCIM sağlama/sağlama kaldırma olayları identity plane hesap durumunu değiştirir (12.3.1) ve Access'e Claim olarak girer (E5, TI-15).
2. **Hareket eden çalışan** (rol değişimi) için Access'in rule-shaped holding episode modeli (INV-31) birikmeyi yapısal olarak keser: SCIM grubu/niteliği değişip seçim düştüğünde episode kapanır; yeniden nitelenme yeni episode'dur ve eski authority'yi canlandırmaz. Extensional Grant'lar için offboarding her kanal için açık seçim ister (E6, X20). *[BY SEMANTICS (rule-shaped); UNDER DECLARED POLICY (extensional disposition)]*
3. Satıcı davranışları (Okta devre dışı vs silme, Entra 30 günlük geri dönüşüm kutusu ve UPN yeniden atama çakışması, Keycloak oturum tabanlı iptal) referanstır; OneLogin davranışı **doğrulanmadı**. Hareket kaynaklı birikme yüzdeleri ve yetim hesap istatistikleri (Orchid 10 Ağustos 2026, Varonis/Trustle atıfları) **yayımlanmış metodolojiye izlenemez; kullanılmaz**.

- **INV-31** Holding episode continuity. Dinamik selector (Pred, ForeignAuthority) üzerinden bir holder'ın authority'si belirli bir kesintisiz holding episode'una bağlıdır ve HoldingRef ile adlandırılır. Terminal lapse o episode'u ve ondan türeyen her authority'yi kalıcı olarak bitirir. Sonraki re-qualification yeni bir episode yaratır; önceki episode'dan türeyen authority'yi asla canlandırmaz. Staleness episode'u bitirmez (qualification continuity ≠ proof freshness). Intensional Grant'ta holder renounce yoktur.

**Tanımlayıcı asla yeniden kullanılmaz; mezar taşı.** Access tarafında aynı ilke ResourceRef incarnation'ıdır (E14: "Reincarnation yeni incarnation zorunludur ve eski Grant'ları miras almaz"). Identity plane kuralları:

1. Kullanıcı kimliği (iç UUIDv7, dış opak kimlik; MD-18) **koşulsuz asla yeniden kullanılmaz**.
2. SCIM `DELETE` mezar taşı koyar; sonrasında her işlem **404** döner, asla 410 (RFC 7644 §3.6: "…MUST return a 404 (Not Found) error code for all operations associated with the previously deleted resource"); 410 silinmiş hesabın varlığını sızdırır.
3. Tekillik kısıtı **canlı satırlar ve mezar taşları üzerinde** zorlanır (mezar taşlarını içeren benzersiz indeks; Slack davranışı); aksi hâlde yeniden kayıt silinmiş aslın tanımlayıcısını sessizce diriltir. Şemada indeks `(tenant_id, realm_id, …)` önekini taşır (TN-19).
4. Riske katmanlı tanımlayıcı emekliliği: bir token'da, federasyonda veya denetim açısından anlamlı bir yetkide görünmüş tanımlayıcılar kalıcı mezar taşıdır; hiç aktive olmamış `staged` hesapların tanımlayıcıları serbesttir (GitHub ad alanı modeli).
5. E-posta için varsayılan **asla yeniden kullanma**dır (Gmail: "Your Gmail address can't be used by anyone in the future"); realm politikası biberli özet mezar taşını veya "N gün tut, sonra serbest bırak"ı yalnız eski adrese bağlı tüm kurtarma yolları geçersizse ve `mailbox_owner_since` + RFC 7293 uygulanıyorsa seçebilir. Biberli özet takma adlıdır, anonim değildir (WP29 05/2014).
6. **Mezar taşı asla bir kararı beslemez**; risk skoru ve dolandırıcılık listesi olarak kullanılmaz. Authority tarafında karşılığı: mezar taşı kayıtları ADP girdisi değildir (yalnız referans; E27).

**Kripto parçalama, kişi başına anahtar, denetim zinciri.** İki nesne, iki mekanizma:

| Nesne | Mekanizma | Kaynak |
|---|---|---|
| Authority log (Exercise kayıtları, lineage) | Salt'lı body commitment, body başına DEK, crypto-shredding; leaf hash ve digest'ler süresiz; body yalnız canlı derivation'a gerekmiyorsa redakte edilir | T39, INV-30 (FROZEN) |
| Identity plane PII (profil, e-posta, telefon, adres) | Kullanıcı başına veri şifreleme anahtarı (zarf şifreleme, alan seviyesinde); yok etme = anahtar imhası; anahtar imhası gecikmesi varsayılan **30 gün**, yapılandırılabilir asgari **24 saat**; denetim özet zinciri **şifreli metin üzerinden** hesaplanır; anahtar imha kanıtı belgelenir | — |

- **T39** → §16.10 T39 (aynen; kanonik metin orada). Bu bölümdeki uygulama: authority log'da salt'lı body commitment, body başına DEK ve crypto-shredding; leaf hash ve digest'ler süresiz; 400 gün uygunluk POLICY DEFAULT; "canlı derivation" belirsizse redakte edilmez.
- **INV-30** Immutable history, redactable body. Kayıtların existence, attribution, lineage, digest ve zamanları silinemez veya yeniden yazılamaz; body yalnız hiçbir canlı derivation'a gerekmediğinde redakte edilebilir. (Work S19 ile uyumlu, Access'e özgü sınırla)

Uyarı: EDPB koordineli uygulama raporu (18 Şubat 2026; 32 otorite, 764 veri sorumlusu) denetim otoritelerinin kripto parçalama ve anonimleştirme tekniklerinin etkinliğini aktif olarak sorguladığını gösterir; "silmek yerine verimsiz anonimleştirme" açıkça bir başarısızlık modudur. Identity plane anahtarları authority plane anahtarlarından ayrı KMS anahtarlarıdır (TI-15, TN-14).

**GDPR m.17, KVKK m.7, periyodik imha, saklama.**

- KVKK'nın üç yönlü ayrımı (Yönetmelik, RG 28.10.2017/30224, m.4) identity plane'e eşlenir: **silme** (göreli erişilemezlik) = mezar taşı + SCIM 404; **yok etme** (mutlak) = sert silme + kullanıcı anahtarının kripto parçalanması + yedeklerin sona ermesi; **anonim hâle getirme** = denetim satırlarında özne referansının geri döndürülemez koparılması (özet yeterli değildir).
- **Periyodik imha** birinci sınıf bir iştir; aralığı **6 ayı geçemez** (Yönetmelik m.11: "bu süre her hâlde altı ayı geçemez") — bu bir azami aralıktır, saklama süresi değildir. Veri sahibi talebi en geç 30 gün (KVKK m.13); "üç ay" rakamı **doğrulanmadı** ve kullanılmaz.
- **İki saat ayrıdır**: hareketsizlik saati (45/90 gün devre dışı; 12.3.1) ve imha saati (≤ 6 ay).
- GDPR m.17(3) istisnaları ve ICO "beyond use" yedek ilkesi uygulanır.
- Authority log tarafında saklama T39'un "400 gün uygunluk POLICY DEFAULT" kuralıdır; leaf hash ve digest'ler süresizdir. PII ile authority log'un çakıştığı yerde INV-30 geçerlidir: existence/attribution/lineage silinmez, body redakte edilir. *[BY SEMANTICS (INV-30); UNDER DECLARED POLICY (süreler)]*
- Hamburg 900.000 € ceza örneği bağlamdır.

**Veri taşınabilirliği.** İki ayrı dışa aktarım vardır:

1. **Kişi dışa aktarımı** (GDPR m.20; identity plane): tanımlayıcılar, profil, grup/rol/yetki atamaları, rıza ve yetki kayıtları (Access'te: kişinin Grant/Mandate/Acceptance görünümü, derived), bağlı federe kimlikler, MFA kayıt metadata'sı (tip, zaman, cihaz etiketi), giriş geçmişi, yaşam döngüsü durum geçmişi **dahil**; parola özetleri, MFA paylaşılan sırları, OTP tohumları, kurtarma kodları ve WebAuthn özel materyali **hariç** (gerekçelendirilmiş tasarım rehberliği; özet hakkında otoriter düzenleyici ifade bulunamamıştır). Uç nokta hız sınırlı, yükseltilmiş kimlik doğrulama ister, denetlenebilir güvenlik olayıdır; kurtarma GRACE_PERIOD'unda reddedilir (TN-56).
2. **Domain kayıt dışa aktarımı** (B3 tam export/replay; Access): domain'in Exercise kayıtları, lineage ve checkpoint'leri. Kişi dışa aktarımıyla karıştırılmaz.
3. **Yönetici göç dışa aktarımı** (özetler + OTP sırları; 12.3.7) bunlardan üçüncü ve ayrı bir şeydir.

**TN-H5 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-75 | SCIM olayı = identity plane durum değişimi + Claim; hareket eden çalışan birikmesi rule-shaped episode ile kesilir; extensional Grant'lar offboarding'de açık seçim | FROZEN | BY SEMANTICS (INV-31); UNDER DECLARED POLICY (extensional) | SCIM `active` semantiği tanımsız | INV-31, E6 |
| TN-76 | Kullanıcı kimliği asla yeniden kullanılmaz; SCIM 404 (asla 410); tekillik canlı + mezar taşı; riske katmanlı emeklilik; e-posta varsayılan asla; mezar taşı asla karar girdisi | FROZEN (kimlik, 404, tekillik, karar yasağı), PD (e-posta stratejisi) | UNDER DECLARED CAPABILITY | RFC 7644 §3.6; Yahoo 2013; E14 ile aynı ilke | — |
| TN-77 | Authority log: T39/INV-30; identity plane PII: kullanıcı başına anahtar, 30 gün (min 24 s) imha gecikmesi, şifreli metin üzerinde özet zinciri, imha kanıtı | FROZEN (T39/INV-30), PD (gecikme) | BY SEMANTICS (INV-30); UNDER DECLARED CAPABILITY (PII) | İki nesne, iki mekanizma | — |
| TN-78 | KVKK silme/yok etme/anonimleştirme eşlemesi; periyodik imha ≤ 6 ay; talep ≤ 30 gün; hareketsizlik ve imha saatleri ayrı | FROZEN (mevzuat tavanları), PD (aralık) | UNDER DECLARED POLICY | KVKK birincil metni | T39 |
| TN-79 | Kişi dışa aktarımı özet/MFA sırrı içermez, step-up + denetim + hız sınırı; domain dışa aktarımı (B3) ve yönetici göç dışa aktarımı ayrı nesneler | PD (içerik), FROZEN (ayrım) | UNDER DECLARED CAPABILITY | m.20(4), m.32 | — |

#### 12.3.6 TN-H6 — Kayıt ve numaralandırma önleme

**Kayıt akışı.** `party.register` bootstrap Grant hız sınırı §13.7.4'tedir (bootstrap Grant ≤ 10/saat). Sıra:

```
1. Sözdizimi + teslim edilebilirlik           → sert red (MX yok ve A yok)
2. Gizlilik relay allowlist'i                 → sıradan adres muamelesi
3. Ucuz kapı: IP/ASN/subnet token bucket      → KİMLİKTEN BAĞIMSIZ
   + hash worker havuzunda global semafor
4. PAT varsa ve geçerliyse                    → hızlı yol, challenge yok
5. Değilse → Turnstile / Friendly Captcha     → skor, sert kapı değil
6. Suistimal skoru                            → step-up'a besle, RED'e değil
7. HER ZAMAN: bant dışı onay kodu             → HESAP HENÜZ YOK; UI yanıtı AYNI; dallanma e-postanın İÇİNDE
8. Kod döndüğünde hesap oluşur                → email_verified = true
   → (Access) party.register meta-Exercise'ı (E6) bootstrap Grant ile
```

Sekizinci adımda identity plane hesap kaydı oluştuktan sonra Party'nin domain'e kabulü ayrı bir `party.register` meta-Exercise'ıdır (E6) ve bootstrap Grant'ın terms'üne (hız sınırı, kapalı/açık yeniden giriş) tabidir.

15 kayıt değişmezi normdur: (1) onay kodu dönmeden hesap satırı yok; (2) yanıt gövde/durum/uzunluk/zamanlama olarak iki dalda özdeş; (3) posta her iki yolda eşzamansız kuyruk, ıskada boş iş; (4) ~250 ms sabit yanıt tabanı; (5) hız sınırı hem IP hem hesap kapsamlı, IP kapısı özetlemeden önce; (6) Argon2 işçi havuzu sabit boyutlu; (7) ham + kanonik e-posta saklanır, kanonik yalnız suistimal skoru ve kişi başına haklar için; (8) kanonik biçim kullanıcı hatasında yüzeye çıkmaz; (9) nokta normalizasyonu yalnız açık Gmail alan adı listesinde; (10) WebAuthn `user.id` 64 rastgele bayt, asla e-posta/özeti; (11) boş `allowCredentials` + koşullu arayüz varsayılan, gerekirse deterministik hayali değerler; (12) `signalUnknownCredential` kullanılır, "tüm kabul edilenler" sinyali kimliği doğrulanmamış uç noktada asla; (13) reCAPTCHA yok, KVKK gerekçesi belgelenir; (14) kurtarma adresi en az iki; (15) sahtekârlık olayları bağlı taraflara paylaşılan sinyalle bildirilir (SSF; 12.2.2). Değişmez 10 MD-18 ile uyumludur (iç kimlik UUIDv7, dış kimlikler opak; WebAuthn `user.id` ayrı rastgele değerdir) (çıkarım).

**Bot savunması.** CAPTCHA bir bulmaca olarak ölmüştür; skor olarak kalır. Privacy Pass / özel erişim belirteçleri (RFC 9577) **yalnız pozitif sinyaldir**; yokluğu ceza değildir. Tek kullanımlık e-posta asla bloklanmaz, skorlanır; gizlilik aktarıcıları (iCloud Hide My Email, Firefox Relay, DuckDuckGo) tek kullanımlık **değildir** ve allowlist'tedir; artı etiketi kişi başı hak kontrolünde kanonikleştirilir, kullanıcıya gösterilmez. reCAPTCHA kullanılmaz (CNIL 125.000 € kararı ve Avusturya kararı). Rakamlar ölçüm kaynaklıdır.

**Sabit çıktı ve tek mesaj.** Giriş, kayıt ve sıfırlama uç noktaları var/yok, kilitli, devre dışı ve askıda dallarında **özdeş** yanıt verir (kod, gövde, uzunluk, zamanlama); kilitli/devre dışı için kullanıcıya tek mesaj (OWASP). Hesap kapsamlı kilitleme ikinci bir kâhin yaratır; hem hesap hem IP kapsamlı sınır gerekir. Authority karar yüzeyinin karşılığı DL-7 (policy oracle NG) ve kapalı açıklama sınıflarıdır → §9.6 / §13.

**Sahte Argon2 yerine ucuz kapı (MD-18).** Sahte Argon2 tek başına uygulanmaz: bilgi sızıntısını bellek tükenmesi hizmet reddine çevirir (64 MiB × 100 eşzamanlı = 6,4 GB, sıfır geçerli hesapla; örnek RFC 9106'nın 64 MiB parametresiyle hesaplanmıştır, PD m = 7 MiB (CR-36) ile aynı yük ≈ 700 MiB'tır — saldırı sınıfı değişmez). Doğru sıra: (1) kimlikten bağımsız ucuz kapı (IP/ASN/alt ağ jeton kovası + küresel eşzamanlılık semaforu) — aşan istek Argon2 belleği tahsis edilmeden reddedilir; (2) sabit boyutlu özetleme işçi havuzu (işçi = bellek bütçesi / bellek maliyeti); (3) ancak sonra gerçek/sahte özet; (4) tekdüze eşzamansız yanıt; (5) adaptif gecikme / sabit taban (~250 ms); (6) sıfırlama uç noktasında hesap başına sınır (posta bombardımanı yükselteci). (MD-18: "sahte Argon2 yok; adaptif gecikme + kimlikten bağımsız semafor"). Argon2id parametresinin kanonik değeri CR-36'dır (§15.14: m = 7 MiB, t = 5, p = 1, ölçülmüş); §10.2.1 ve IDP-3 buna atıf yapar.

**TN-H6 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-80 | Kayıt akışı 8 adım + `party.register` bootstrap Grant (≤ 10/saat); 15 kayıt değişmezi | FROZEN (1, 2, 5, 6, 10, 12), PD (diğerleri) | UNDER DECLARED CAPABILITY | Ön ele geçirme ve kâhin kapatma | §13.7.4; E6 |
| TN-81 | Bot savunması skor tabanlı; Privacy Pass yalnız pozitif; tek kullanımlık e-posta skorlanır; relay allowlist; reCAPTCHA yok | PD | UNDER DECLARED POLICY | KVKK/CNIL | — |
| TN-82 | Özdeş yanıt (kod/gövde/uzunluk/zamanlama); kilitli/devre dışı için tek mesaj; hesap + IP kapsamlı sınır | FROZEN | UNDER DECLARED CAPABILITY | OWASP | — |
| TN-83 | Sahte Argon2 yok; ucuz kimlikten bağımsız kapı + sınırlı havuz + adaptif gecikme/sabit taban | FROZEN | UNDER DECLARED CAPABILITY | DoS analizi | MD-18 |

#### 12.3.7 TN-H7 — Kimlik sağlayıcı göçü (identity plane'e gelen ve giden)

**Kapsam.** Bu bölüm kullanıcı tabanının bir IdP'den Suiss identity plane'ine (veya tersine) taşınmasıdır. **`domain.handover` (E20) ile karıştırılmaz**: E20 bir AuthorityDomain'in provider değiştirmesidir ve DomainID korunur; IdP göçü identity plane kayıtlarının (hesap, özet, federasyon bağları) taşınmasıdır ve authority state'e yalnız Claim (IdentityBinding) olarak dokunur.

- **E20** Provider hosting. Bir AuthorityDomain herhangi bir conformant provider'da host edilebilir; DomainID provider değişiminde korunur (`domain.handover` meta-Exercise'ı); canonical semantik açık Access protocol'ündür. *GUARANTEED BY SEMANTICS:* authoritative lineage tektir ve root'un handover/recovery Exercise zinciriyle belirlenir. *NOT GUARANTEED (yalnız UNDER DECLARED CAPABILITY):* eski provider'ın yazmayı fiilen kesmesi ve cutover öncesi her commit'in korunması (commit'in root'un kontrol ettiği bağımsız witness'a ve provider-dışı replica'ya ulaşmadan acknowledge edilmemesi; witness/replica-before-ack, SEC23). Forced recovery Exercise'ı devam ettiği checkpoint N'yi StateBasis'inde cite eder; N'nin tanımı SEC21'dir (bağımsız witness co-signed ve kökü recovery tarafındaki kayıtlarla yeniden üretilebilen en yüksek checkpoint). N sonrası eski-provider kayıtları devam eden lineage'da authoritative değildir; eski provider'ın o pozisyondan sonra verdiği projection/reusable Decision'lar geçersizdir (fail closed); kayıp revoke/draw riski recovery Exercise'ında beyan edilir; kayıp suffix'teki bir revocation yeni bir revoke Exercise'ıyla prospective olarak yeniden yapılır. Read federation kopyaları projection'dır; Anchor'lar domain'ler arasında kimlik koruyarak taşınmaz.

**İçe aktarım.**

- Hedef format listesi Ory Kratos'unkidir: bcrypt'in tüm önekleri, Argon2'nin iki varyantı, scrypt, Firebase scrypt, PBKDF2'nin tüm fonksiyonları, dizin şemaları, crypt türevleri, biberli format. Ön özet ve biber eklenti noktası vardır. **Parametre tavanı yoktur** (Cognito'nun bellek tavanı, belgelenmiş en yaygın göç başarısızlığıdır). Dışa/içe aktarım kendini tanımlayan **PHC** dizgisi biçimindedir. bcrypt varyantları, 72 bayt kesme ve PBKDF2 kodlamaları ayrıca ele alınır.
- **Tembel göç**: girişte otomatik yeniden özetleme senkron ve başarısızlığı ölümcül değil; doğrulama sabit zamanlı; eski özet sayacı yönetim panosunda birinci sınıf metrik (WorkOS kuralları). Tembel göç sırasında eski IdP'ye yapılan doğrulama çağrısı dış bir bağımlılıktır; o çağrı başarısızsa giriş başarısızdır (fail-closed, MD-8) (çıkarım).
- Ürün ürün özet dışa/içe aktarım durumu (Auth0 destek süreci, Okta altı algoritma içe aktarım, Keycloak CLI, Cognito 15 Temmuz 2026 içe aktarım, Firebase tek gerçek dışa aktaran, Entra yok) referanstır.

**Dışa aktarım.** Suiss identity plane özetleri ve OTP sırlarını kendin-yap biçimde **dışa aktarabilir**; bu yönetici göç dışa aktarımıdır ve kişi taşınabilirliğinden (12.3.5) ayrıdır. Kural: göç dışa aktarımı realm'in yönetişim domain'inde bir **`idp.*` domain action Exercise'ıdır** (MD-14; meta-Exercise değildir), **reserved** ilan edilir ve bu nedenle CT3'tür (kalıcı kimlik bilgisi sızıntısı riski geri alınamaz); quorum, step-up ve denetim olayı ister; sonuç bundle'ı realm'e bağlı bir anahtarla şifrelenir. CT3, §13.7.1 tanımından ("`reserved` action'lar") türer; çıkarım değildir.

**Göç edilemeyenler.**

- **Passkey'ler alan adı değişiminde ölür**; RP ID geri dönülemezdir (TN-17). Related origins (`/.well-known/webauthn`, 5 etiket sınırı arayüzde gösterilir) barındırılan arayüze geçişi passkey'leri öldürmeden yapar. CXF (Credential Exchange) RP'den RP'ye göç aracı **değildir**.
- OTP sırları: yalnız Keycloak dışa aktarır; çoğu göçte yeniden kayıt gerekir.
- Oturumlar, refresh token'ları, rızalar ve denetim geçmişi taşınamaz; Access tarafında rızaların karşılığı Grant'lardır ve göçte **yeniden verilir** (Exercise), kopyalanmaz (INV-2).
- **Özne tanımlayıcı problemi**: Google `sub` kararlı; Apple takım kapsamlı; Entra ikili (`oid` + `tid` ile anahtarla); Facebook uygulama kapsamlı. Yukarı akış sosyal sağlayıcılarda **istemci kimliği yeniden kullanımı zorunlu**, farklı kimlik girilirse açık uyarı. Apple transfer tanımlayıcı akışı yerleşik ve **60 günlük pencere sayacı** vardır; kaçırılırsa kurtarılamaz.

**Sıfır kesinti.** Token değişimi uç noktası eski sağlayıcının token'ını eski JWKS ile doğrulayıp yerel identity plane oturumu basar (kesimde kimse çıkış yapmaz); çift JWKS / çift `iss` doğrulaması **en uzun refresh token ömrü** boyunca bir arada yaşama modudur. Basılan yerel oturum yeni bir Instance authority-binding'i **değildir**: Instance kimliği KeyBinding sürekliliğini izler (INV-13); göçte kullanıcı cihazları yeni KeyBinding ile Instance kurar (çıkarım; X29 dili: "your devices need to sign in again"). Çift `iss` kabulü realm'in RFC 9207 doğrulamasını gevşetmez: eski issuer açık bir `predicate-input`/`actor-binding` Acceptance'ıdır ve süre sonunda kalkar (SI-18: gevşetme genişlemedir).

Vakalar: Mimo 6M, Keymate 20M, Poppy 6 ay, Avusturya BRZ, Cognito; MojoAuth rakamları satıcı iddiasıdır (**doğrulanmadı**).

**TN-H7 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-84 | IdP göçü ≠ `domain.handover` (E20); göç identity plane kayıtlarıdır, authority'ye yalnız IdentityBinding Claim'i olarak dokunur; rızalar Grant olarak yeniden verilir | FROZEN | BY SEMANTICS (INV-2, E5) | İki ayrı taşıma | E20 |
| TN-85 | İçe aktarım Kratos format listesi, PHC, tavan yok, ön özet/biber eklentisi; tembel göç senkron, ölümcül olmayan, sabit zamanlı; eski özet sayacı metrik; eski IdP çağrısı başarısızsa giriş başarısız | PD | UNDER DECLARED CAPABILITY | En yaygın göç başarısızlıklarını kapatır | MD-8 |
| TN-86 | Göç dışa aktarımı (özet + OTP) `idp.*` domain action Exercise'ı, reserved, CT3 (§13.7.1'den türer), step-up + denetim, şifreli bundle; kişi taşınabilirliğinden ayrı | PD (reserved ilanı), CT3 §13.7.1'den | BY SEMANTICS (Exercise); UNDER DECLARED POLICY (CT3) | Dürüst dışa aktarım + yazma yolu tekliği | MD-14 |
| TN-87 | Sosyal sağlayıcı istemci kimliği yeniden kullanımı zorunlu; Entra `(tid, oid)`; Apple transfer 60 gün sayacı; CXF RP→RP değil | FROZEN (anahtar), PD (uyarı) | UNDER DECLARED CAPABILITY | İkili özne tuzağı | — |
| TN-88 | Sıfır kesinti: token değişimi + çift JWKS/`iss` en uzun RT ömrü boyunca; eski issuer açık Acceptance, süre sonunda kalkar; yerel oturum Instance devamı değildir | PD | UNDER DECLARED CAPABILITY; BY SEMANTICS (INV-13, SI-18) | Kesimde çıkış yok, gevşetme genişleme | — |

#### 12.3.8 TN-H8 — İşletmeler arası (B2B) organizasyon akışları

**Model (MD-5).** B2B organizasyonu realm içinde bir **Party + Anchor**'dır (TN-5). Üyelik bir identity plane kaydıdır. **Rol, sürümlü named AuthoritySet'tir** (C28, MD-4). Bir üyeye rol verilmesi o AuthoritySet'i taşıyan bir Grant'tır (extensional ya da rule-shaped; rol sürümleme X20). Organizasyon ≠ tenant: `tenant_id` hiçbir zaman authority girdisi değildir (TNI-1). Identity plane yapıları şöyle eşlenir:

| Yapı | Access karşılığı | Not |
|---|---|---|
| `Invitation { token_hash, invited_email_normalized, binding_mode, role, inviter_id, expires_at, consumed_at, revoked_at, scanner_clicks }` | Identity plane nesnesi; `role` → davet edilen Grant şablonuna referans; kabul = davet edenin önceden imzaladığı değil, **kabul anında** yürütülen `grant.issue` Exercise'ı (rol atama yetkisi yeniden kontrol) | PK `(tenant_id, realm_id, id)` |
| `Membership { role, source, external_id, is_breakglass }` | Identity plane üyelik kaydı + org Anchor'ı altında Grant(lar); `source ∈ {Invite, Scim, Jit, DomainAutojoin}` denetim için; `is_breakglass` alanı **authority taşımaz** — break-glass yalnız reserved Grant'tır (INV-28). **Grup üyeliği için tek issuer:** her grubun tek bir üyelik issuer'ı vardır — (a) identity-plane-managed grup (Claim realm issuer'ından, konsol değişikliği `idp.group.*` domain action'ı) veya (b) domain-local grup (`claim.issue`) ya da belirli bir upstream; aynı grup için ikinci yazma yolu reddedilir; `Pred(membership(g))` grubun issuer'ını adlandırır | |
| `VerifiedDomain { method, verified_at, reverify_after, autojoin, is_consumer_domain }` | DNS/HTTPS/IdP doğrulaması bir **Claim**'dir; `reverify_after` = Claim freshness; autojoin = rule-shaped Grant (C13) | Doğrulama kalıcı değildir |

**Davet.** Kurallar: (1) davet opak belirteç, veritabanı satırı, SHA-256 özetli; JWT değil; (2) rol satırdan okunur, istekten asla (Dropbox, Budibase CVE-2026-25040); (3) rol atama yetkisi hem oluşturmada hem **kabulde** yeniden kontrol edilir — kabuldeki `grant.issue` Exercise'ı davet edenin o anki AuthoritySet'iyle değerlendirilir; davet edenin yetkisi düşmüşse DENY (çıkarım: davet önceden imzalanmış bir yetki değildir); (4) adres NFKC + küçük harf (GitLab #321324); (5) kabul yalnız doğrulanmış tanımlayıcıyla eşleşir; (6) tüketici alan adlarında tam eşleşme, kurumsal gevşetme yalnız doğrulanmış alan adında; (7) kabul atlanamaz; (8) kabul sayfasında `Referrer-Policy: no-referrer` + sihirli kod yedeği; (9) tarayıcı tıklaması belirteci tüketmez; (10) farklı doğrulanmış alan adında güçlü ara sayfa, **ilk kabulde asla sahip/yönetici**; (11) kiracı oluşturma/toplu davet hız sınırlı ve itibar kontrollü; organizasyon adı, davet eden adı ve özel mesaj saldırgan girdisidir. Davet süresi varsayılan 7 gün, en çok 30 gün. "İlk kabulde sahip yok" kuralı identity plane'dedir. Authority tarafında yeni katılanın **yeni bağlanan** authenticator'ları SEC18'e tabidir; mevcut authenticator'la katılım SEC18 tetiklemez; katılımın verdiği reserved/CT3 kapsamı TN-109'a tabidir (rule-shaped autojoin ise).

Davet bildirimi Work ↔ Access dikişindedir: davet e-postası identity plane'in işlemsel postasıdır; Work Gate'i veya Relay ile bildirim → §7.

**Alan adı doğrulaması ve otomatik katılım.** DNS doğrulaması bir Claim'dir ve süresi dolar (Claim freshness); otomatik katılım bir **rule-shaped Grant**'tır (C13: "doğrulanmış alan adındaki doğrulanmış e-postaya sahip Party'ler") ve holding episode'larıyla çalışır (INV-31). Kurallar: yeniden doğrulama zamanı zorunlu; MX kaydı veya tescil değişimi yeniden doğrulamayı tetikler (Truffle, npm 2.818 / 8.494 bakımcı alan adı); aynı alan adını birden çok organizasyon doğrulayabiliyorsa talep kilitli ve alarmlı (yarış koşulu); tüketici, **Türkiye ulusal ücretsiz posta, ISS ve üniversite** alan adları tüketici işaretlidir ve otomatik katılım yasaktır; otomatik katılım varsayılan **kapalı**, erişim talebi ara seçenek. Organizasyon yönlendirmesi organizasyon kimliği üzerindendir, e-posta alan adı üzerinden değil (TN-3). Rule-shaped otomatik katılım Grant'ının kapsamı reserved/CT3 action içeriyorsa yeni episode SEC18 benzeri soğuma + SI-21 bildirimi alır (TN-109). Ürün tablosu (Entra, Slack 72 saat, Atlassian, Google 9/21 gün, Notion 14 gün), Entra yönetici devralması (10 gün), Obsidian %20/%28, nOAuth (Semperis 1.017 / 104 / 9) referanstır. Dürüstlük notu: doğrulanmış bir otomatik katılım suistimal olayı bulunamamıştır.

**Sahiplik devri.** Organizasyonun "sahibi" org Anchor'ının root'udur (§8.11 "Owner" ≠ hukuki sahip). Devir `anchor.transfer` meta-Exercise'ıdır (CT3, ≥ 24 saat yürürlük gecikmesi, §13.7.3) ve Anchor'a dayanan Grant'ların akıbetini açıkça belirtir:

- **C10** Root transfer, Anchor'a dayanan Grant'ların akıbetini açıkça belirtir; varsayılan yoktur.

Sahiplik kuralları ve karşılıkları:

| # | Kural | Access karşılığı | Garanti |
|---|---|---|---|
| 1 | ≥ 1 aktif sahip, veri katmanında, her yolda | **Sahipsiz Anchor ifade edilemez** (root bir değerdir, §5.7); identity plane'de org Party'sinin ≥ 1 aktif sahip üyeliği kuralı ayrıca veri katmanında zorlanır (SCIM sağlama kaldırma, SSO süpürmesi, faturalama iptali, hesap silme dahil) | BY SEMANTICS (Anchor); UNDER DECLARED CAPABILITY (üyelik) |
| 2 | Teklif + kabul; alıcı doğrulanmış aktif üye | `anchor.transfer` RequirementSet'inde **alıcının contribution'ı** zorunlu RequirementTerm | BY SEMANTICS |
| 3 | Soğuma + tüm sahiplere bildirim + geri alma penceresi | ≥ 24 s yürürlük gecikmesi (§13.7.3) + SI-21 + **tüm root'lara** bildirim; gecikme içinde iptal mevcut root'un daraltmasıdır | BY SEMANTICS (gecikme); NOT GUARANTEED (teslim) |
| 4 | Kendi rolünü değiştirme yasak | Kendi Grant'ını genişletme INV-10 ve contributor ≠ actor (SEC10) ile kapalı; kendi rolünü daraltma serbesttir (X11) | BY SEMANTICS |
| 5 | Sahiplik ≠ faturalama | Root ≠ hukuki sahip; budget ≠ finansal (§8.11) | BY SEMANTICS |
| 6 | Vefat/ayrılma: DNS bant dışı kanıt | **DNS yalnız Genesis rootTerms'te önceden beyan edilmiş bir `domain.recover`/Anchor kurtarma entry'si olarak**: DNS Claim'i + Acceptance; CT3; ≥ 24 s gecikme; tüm root'lara bildirim. Beyan yoksa DNS kurtarma yolu yoktur (N-18) | BY SEMANTICS (beyan); UNDER DECLARED POLICY |

Ürün politikaları (GitHub, Stripe, Notion 14 gün, Microsoft 10 gün, Vercel) referanstır.

**Break-glass.** Model INV-28 ve SI-22'dir; operasyon disiplini aşağıdadır.

- **SI-22** No emergency path outside the Exercise. Break-glass, legal order, incident response ve containment yalnız önceden verilmiş reserved Grant'ların Exercise'ıdır; fail-open, kill-switch API veya operatör override'ı yoktur *[BY SEMANTICS]*
- **SEC27** Availability fail-open ile değil, önceden issue edilmiş continuity envelope'larıyla (küçük slice'lı, kısa horizon'lu projection'lar; break-glass için offline PAP) sağlanır.

Operasyon disiplini (POLICY DEFAULT):

1. **En az iki** break-glass Grant'ı, ayrı Party/Instance'larda; yalnız bulut (federasyon yok, şirket içi yok), kişisel telefon yok, tek ağ yolu yok.
2. Normal yöneticilerden **farklı** kimlik avına dirençli yöntem (FIDO2 donanım veya sertifika tabanlı); faktör kaldırılmaz, güçlüsü ikame edilir.
3. Yeter sayı seçeneği: AWS kök çok kişili onay modeli `Joint(k)`/`count = k` ile ifade edilir; parola ve MFA farklı gruplarda → iki ayrı contribution.
4. Her kullanımda **en yüksek önem derecesinde alarm** ve zorunlu inceleme sınıflandırması (tatbikat / acil durum / suistimal); break-glass Exercise'ları §13.7.7'deki CT3 %100 örnekleme kapsamındadır.
5. **90 günlük** doğrulama tatbikatı; üç aylık muafiyet testi; personel ayrılışında kasa rotasyonu. Tatbikat break-glass Grant'ının gerçek bir Exercise'ıdır ve kayıtta "drill" PurposeRef'i taşır (çıkarım).
6. **Muafiyet beyan edilir** (CISA): break-glass muafiyeti RestrictionPolicy içeriğinde açıkça beyan edilmiş bir istisnadır; o `policy.set` CT3'tür. Deny-overrides (§5.8) kuralı değişmez: beyan edilmemiş bir restriction break-glass'ı da durdurur. Muafiyet yalnız **engelleyici** politikalardan verilir (Microsoft); kayıt, denetim ve requirement'lardan muafiyet yoktur.
7. Stytch'in `is_breakglass` üye bayrağı referanstır; Access modelinde bayrak authority taşımaz, break-glass Grant'ını verme (`grant.issue`, reserved, CT3) izinli eylemdir.

Dürüstlük notu: break-glass kimlik bilgilerinin adı geçen bir kamu ihlalinde suistimal edildiğine dair doğrulanmış olay bulunamamıştır; dolaşan kilitlenme hikâyeleri **doğrulanmadı**. Break-glass offline PAP mekanizması → §16 (SEC27).

**SSO zorlaması: süpürme ve önizleme.** SSO zorlaması organizasyon düzeyinde bir RestrictionPolicy (actor-binding Acceptance daraltması) + identity plane süpürmesidir. Süpürme kapsamı: mevcut parolalar, API token'ları, identity plane oturumları ve OAuth yetkileri (refresh token aileleri); **bekleyen davetlerin akıbeti açıkça tanımlıdır** (iptal veya SSO'ya yönlendirme; varsayılan yok — C10'un ruhu, çıkarım). Zorlama öncesi **önizleme** kimlerin erişimini kaybedeceğini gösterir, **servis hesapları dahil** (GitHub zorlama günü kesintisi) — X20 change-impact preview'ın bir satırıdır. Daraltma yönündeki zorlama CT1'dir (SI-4); zorlamayı kaldırma genişlemedir. GitHub CVE-2024-4985 / CVE-2024-9487 (SAML imza atlatması) dersi → §10 (SAML), §14 (SAML doğrulama).

**SAML ele geçirme, zehirli kiracı.** Push Security (17 Ağustos 2023): SAML ele geçirmede saldırgan kontrolündeki kiracının SSO ayarı saldırganın IdP'sine yönlendirilir; zehirli kiracıda hedef şirketin adıyla kiracı açılıp ürünün kendi davet işleviyle meşru görünen davetler gönderilir. Canlı örnek: Push'un 26 Haziran 2026 OpenAI zehirli kiracı incelemesi. Kurallar: IdP bağlantısının *kaydı* realm'in yönetişim domain'inde bir `idp.upstream.*` domain action'ıdır; upstream IdP'nin *güveni* (actor-binding Acceptance) bir meta-Exercise'tır; ikisi ayrı Exercise'tır. İkisi de reserved ve **CT3**'tür (MD-14; §13.7.1: `acceptance.establish`) — bağlantıyı değiştiren Exercise soğuma ve tüm root'lara bildirim alır (SEC18: issuer designation; IdP bağlantısı değişikliği yeni designation'dır); TN-89 davet kuralları (#10 ara sayfa, #11 saldırgan girdisi) uygulanır; kiracı oluşturma hız sınırı ve itibar kontrolü.

**SCIM otoriter; davetler kapanır.** SCIM etkinken üyelik için otoriterdir; davetler devre dışı veya erişim talebine indirgenmiştir; her üyelik `source` alanı taşır; SCIM sağlama kaldırma bekleyen davetleri de iptal eder. Access tarafı: SCIM kaynağının otoriterliği bir **`subject-selection` Acceptance'ıdır** (reserved, protected; E18); bu Acceptance'ı vermek/değiştirmek CT3'tür. SCIM grubu → rule-shaped Grant seçimi INV-31 episode'larıyla çalışır. Grup üyeliğinin tek issuer'ı vardır: SCIM kaynaklı bir grubun üyeliği konsoldan ikinci bir yoldan yazılamaz. Upstream grup → realm grubu eşlemesi, protocol mapper ve JIT/SCIM kaynak bağlama gibi, bir subject-selection Acceptance'ı olan claim class'ının üyeliğini toplu değiştirebilen her identity plane config action'ı **reserved** bir requirement ile korunur ve o Acceptance'ı genişletmekle aynı sınıfı taşır (CT3); ya da eşleme sonucu üretilen Claim upstream issuer atfını korur ve ayrı Acceptance ister.

**Kimlikten yetki asla e-postadan.** Yetkilendirme asla e-posta, `preferred_username` veya UPN üzerinden yapılmaz (TN-3).

**TN-H8 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-89 | Davet = identity plane nesnesi (opak, SHA-256, satırdan rol, NFKC, tam/doğrulanmış alan eşleşmesi, atlanamaz kabul, no-referrer + sihirli kod, tarayıcı tıklaması tüketmez, 7/30 gün); kabul anında `grant.issue` Exercise'ı davet edenin o anki yetkisiyle; ilk kabulde sahip/yönetici yok | FROZEN (1–3, 7, 10), PD (süre, ara sayfa metni) | BY SEMANTICS (kabulde Exercise); UNDER DECLARED CAPABILITY (belirteç) | Dropbox/Budibase/GitLab/Slack/OpenAI | — |
| TN-90 | Alan adı doğrulaması = süresi dolan Claim; autojoin = rule-shaped Grant (C13, INV-31); varsayılan kapalı; TR tüketici alan adları yasak; yeniden doğrulama + MX/tescil tetikleyici; talep kilidi | FROZEN (Claim modeli, tüketici yasağı), PD (süreler) | BY SEMANTICS (rule-shaped); UNDER DECLARED POLICY | Truffle, npm, Obsidian | — |
| TN-91 | Sahiplik devri `anchor.transfer` (CT3, ≥ 24 s, C10 akıbet), alıcı contribution'ı zorunlu term, tüm root'lara bildirim; sahipsiz Anchor ifade edilemez + identity plane ≥ 1 sahip; kendi rol genişletme yasak; sahiplik ≠ faturalama | FROZEN | BY SEMANTICS; NOT GUARANTEED (bildirim teslimi) | Sahiplik kuralları Access primitive'lerine eşlenir | — |
| TN-92 | DNS ile kurtarma yalnız Genesis rootTerms'te önceden beyan edilmiş entry (DNS Claim + Acceptance, CT3, ≥ 24 s, tüm root'lara bildirim); beyan yoksa yol yok | FROZEN | BY SEMANTICS | DNS aynı zamanda saldırı yolu | N-18 |
| TN-93 | Break-glass = ≥ 2 reserved Grant; farklı phishing-resistant yöntem; Joint(k) seçeneği; en yüksek alarm + sınıflandırma; 90 gün tatbikat; muafiyet RestrictionPolicy içinde beyanlı (CT3), yalnız engelleyici politikalardan; offline PAP | FROZEN (model, beyan), PD (operasyon) | BY SEMANTICS (INV-28, SI-22); UNDER DECLARED POLICY (disiplin) | Microsoft/CISA/AWS; deny-overrides korunur | — |
| TN-94 | SSO zorlaması = org RestrictionPolicy + identity plane süpürmesi (parola, API token, oturum, OAuth); bekleyen davet akıbeti açık; servis hesapları dahil önizleme | FROZEN (önizleme), PD (kapsam) | BY SEMANTICS (SI-4); UNDER DECLARED CAPABILITY (süpürme) | GitHub dersleri | — |
| TN-95 | IdP bağlantısı kaydı `idp.upstream.*` domain action'ı + güveni actor-binding Acceptance meta-Exercise'ı, reserved, CT3, soğuma (SEC18 issuer designation) + bildirim; SCIM otoriterliği `subject-selection` Acceptance (CT3); grup üyeliği tek issuer, upstream grup eşlemesi reserved; SCIM etkinken davetler kapalı; SCIM sağlama kaldırma davetleri iptal eder | FROZEN | BY SEMANTICS | SAML ele geçirme; zehirli kiracı | — |
| TN-134 | **Self-servis SSO/SCIM kurulum portalı.** Kiracı, organizasyonun BT yöneticisine bir **kurulum bağlantısı** gönderir veya kendi uygulamasına `<OrganizationSSO />` bileşenini gömer (TN-133). Portal tek akışta: IdP'ye özel adım adım sihirbaz (Entra, Okta, Google Workspace, ADFS, JumpCloud, OneLogin, Ping; diğerleri için genel SAML/OIDC), alan adı doğrulaması, SCIM kurulumu, bağlantı testi. **Güvenlik kuralları:** (1) bağlanan IdP'nin actor-binding Acceptance'ı yalnız organizasyonun **doğrulanmış alan adlarındaki** Party'leri kapsar; başka alan adındaki kullanıcı için kimlik iddiası kabul edilmez; (2) kurulum TN-95'teki CT3 kurallarına tabidir (organizasyon sahibinin CT3 onayı, soğuma, bildirim); (3) alan adı doğrulaması süreli bir Claim'dir ve yenilenmezse bağlantının kapsamı düşer. Kurulum bağlantısı tek kullanımlık, süreli ve organizasyona bağlıdır. Portal ücretsizdir (§18.9) | FROZEN (kapsam kuralı, CT3); PD (sihirbaz listesi, bağlantı süresi) | BY SEMANTICS (alan adı kapsamı, CT3); UNDER DECLARED CAPABILITY (IdP'nin doğruluğu) | Kurumsal müşteriye SSO verme süresi günlerden dakikalara iner; organizasyon yöneticisinin başka alan adlarında kimlik iddia etmesi yapısal olarak kapalıdır | TN-95; TN-133; C13 |

### 12.4 Giriş deneyimi

**Ortak ilke.** Giriş akışı identity plane'in sunumudur; çıktısı tipli bir kimlik doğrulama sonucudur (TN-103) ve authority plane'e yalnız Claim/projection olarak ulaşır (TI-15). Access'in dürüst ifade disiplini (§8.10 forbidden claims, X29) identity plane mesajlarına da uygulanır. Login ekranı hiçbir zaman "yetki verdi" demez; authority yalnız Exercise'tadır (X29, TN-O3).

- **TI-15** Identity plane speaks only Claims. Identity plane ile Authority plane arasında ortak tablo, DB rolü, KMS anahtarı veya operatör rolü yoktur; tek kanal Claim Ingest API'sidir

#### 12.4.1 TN-G1 — Akış, numaralandırma, passkey, MFA, barındırılan giriş, hatalar

**Önce tanımlayıcı ve kiracı başı numaralandırma modu.** Önce tanımlayıcı varsayılandır; numaralandırma davranışı **realm başına yapılandırılabilir bir mod**dur (Clerk modeli: toplu koruma / katı koruma); katı modun imkânsız kıldıkları (kullanıcı adı tanımlayıcısı, parolayla başlangıç, yalnız davetle katılım) dokümante edilir. Önce tanımlayıcı yapısal olarak sızdırır (CVE-2026-4633 sınıfı). Tanımlayıcı adımının çıktısı sabittir: aynı HTTP durumu, gövde boyutu, gecikme; kilitli ve devre dışı dahil tek mesaj (TN-82). Önce tanımlayıcıyı atlayan **"passkey ile giriş"** yolu her zaman sunulur; boş `allowCredentials` ile keşfedilebilir kimlik bilgisi sunucuya hiçbir tanımlayıcı sızdırmaz ve numaralandırma yüzeyini sıfırlar. IdP'de bu kurallar geçerlidir (sabit yanıt, kiracı başına mod, izleme modu); authority karar yüzeyinin sınırlı değerlendirmesi SI-20'dir.

- **SI-20** Bounded evaluation. Lineage derinliği, proof sayısı, selector karmaşıklığı, istek boyutu ve oranı sınırlıdır; aşım gerekçeli protocol rejection'dır (outcome değil, kayıt yok, nonce tüketilmez, effect yok) *[BY SEMANTICS (sınırın varlığı); değerler POLICY DEFAULT]*

**Passkey numaralandırması.** Boş `allowCredentials` + koşullu arayüz varsayılan; tanımlayıcı gerekiyorsa kullanıcı adından **deterministik hayali** credential ID'leri; Signal API: `signalUnknownCredential` başarısız passkey denemesinden sonra güvenlidir (tek ID, sayı sızdırmaz); `signalAllAcceptedCredentials` yalnız doğrulanmış kullanıcı için ve **tam listeyle** (kısmi liste meşru passkey'leri gizler); destek Chrome/Edge 132+.

**Karar yüzeyi sızıntısı → §9.6 / §13.** Authority karar yüzeyinin açıklama sızıntısı (kapalı sınıflar, disclosure scope; P14, PI-16, SEC24, TI-RT10, EI-3) §9.6 / §13'te işlenir; "403 ifşadır" gözlemi oraya bağlanır. Burada yalnız identity plane yüzeyi vardır.

**Ev alanı keşfi kapalı; `domain_hint` politikayı ezmez.** HRD varsayılan **kapalı**; açıksa hedef kiracı kullanıcıya onaylatılır (Microsoft Nisan 2023 onay penceresi; otomatik hızlandırma FIDO'yu engeller ve misafirleri kırar). İstemcinin gönderdiği `domain_hint`/`login_hint` benzeri parametreler **realm politikasını ezmez**; sıra baştan "realm politikası > istemci ipucu"dur. Organizasyon yönlendirmesi organizasyon kimliği üzerindendir, e-posta alan adından değil (TN-3).

**Koşullu arayüz tek yol değil; telemetri; QR son çare.** Koşullu arayüz desteklenir ama asla tek yol değildir: her zaman açık bir passkey düğmesi + `AbortController`; koşullu arayüz Windows 10, eski ChromeOS ve uygulama içi tarayıcılarda sessizce hiçbir şey göstermez ve site bunu ölçemez. Telemetri körlüğü telafi eder: istemci yetenek sonucu, tanımlayıcı alanı odak olayı ve koşullu sözün çözülüp çözülmediği ayrı ölçülür. Platform tespit edilir, cihazlar arası QR son çaredir (özellikle Windows: web başarı %45–60, girişlerin %40–65'i cihazlar arası; Android tarayıcı isteminden QR'a geçiş %29; Corbado). Benimseme rakamları (FIDO anketi, Google %63,8 / %13,8, Microsoft %98 / %32) anket veya seçim yanlılığı taşır. FIDO'nun iki zorunlu deseni (hesap ayarlarında passkey oluşturma/görme/yönetme; passkey ile giriş + zarif yedek yol) ürün gereksinimidir; yedek yok bir seçenek değildir.

**Anlık bildirimde sayı eşleştirme.** Login push'unda sayı eşleştirme zorunludur; tek istisna aynı cihaz tespiti (Microsoft; giyilebilirler kapsam dışı). **Authority onayı** için Access kuralı daha güçlüdür ve ayrıdır: bildirim içi onay yalnız CT1 + H(AAS)'ye bağlı intent ile (§13.7.3); CT2+ için bildirim içi onay yoktur. Sayı eşleştirmenin canlıda MFA yorgunluğunu ortadan kaldırdığı iddiasının birincil sayısal karşılığı **doğrulanmadı**.

**"Beni hatırla", oturum ömrü.** Login oturumunun iki katmanı (boşta 7 gün + mutlak 30 gün, PD) ve olay tabanlı iptal TN-O1'dedir (TN-36). Authority tarafında "Remember this decision" yasaktır; bu ayrı bir konudur (X29, §8.10). Agresif yeniden kimlik doğrulama kaçınılır; Microsoft 90 gün önerisi ikincil kaynaktandır (**doğrulanmadı**).

**İki üretim modu: gömülü bileşenler ve barındırılan sayfalar (TN-133); BFF; sistem tarayıcısı.** Access iki modu birlikte ve tam destekli sunar:
1. **Gömülü bileşenler (varsayılan).** Kiracı hazır bileşenleri kendi uygulamasına koyar: giriş ve kayıt, kullanıcı menüsü, hesap ayarları (S11'in gömülü hâli), organizasyon seçici ve organizasyon ayarları, ajan bağlantıları (hangi ajan hangi bağlı hesabı kullanıyor; tek tıkla iptal). Bileşenler aynı düğüm sözleşmesini ve gereksinim modelini (TN-132) kullanır; görünüm tema ayarlarıyla değiştirilir. Web'de React ile başlanır, web components ile diğer çatılar kapsanır; diğer platformlar → §18.3 / SDK kararı.
2. **Barındırılan sayfalar.** Access giriş, kayıt ve hesap ayarları sayfalarını kendisi sunar (realm'in alan adında, realm markasıyla); kiracı yalnız yönlendirir. Özelleştirme betiksiz şablon ve tema kaydıyla yapılır (F23). Kiracı tek bir ayarla bütün akışları barındırılan moda alabilir; uygulama başına mod seçilebilir.

**Gömülü modun güvenlik koşulları.** Özel alan adı zorunludur (üçüncü taraf çerez engeli ve passkey RP ID; TN-17). Giriş passkey önceliklidir; parola ikincil yöntemdir. Gerekçe kayda geçer: gömülü formda kiracı sitesindeki XSS parolayı çalabilir (Okta vakası); passkey bu yolla çalınamaz. Oturum çerezi realm alt alan adında, HttpOnly'dir.

**Her zaman barındırılan sayfada kalanlar.** Kiracı gömülü modu seçse bile şu üç yüzey gömülemez: (a) üçüncü taraf uygulama izin (consent) ekranı (OAuth: izin istemcinin kendi sayfasında istenmez); (b) CT3 onayları ve authority genişletme sınıfı meta-action'lar (güvenilir yüzey, X11); (c) yönetim konsolu (12.5.5). SPA müşterilerine BFF resmî öneridir; RFC 10017'nin ifadesi dokümantasyonda alıntılanır; örtük akış yasaktır; refresh token varsa rotasyon veya gönderen kısıtlaması zorunludur (TN-O1). Suiss'in kendi yönetim konsolu ve barındırılan girişi OAuth değil doğrudan oturum çerezi kullanır — konsol çerezi yalnız gezinmeyi ve identity plane'in kendi (authority taşımayan) ekranlarını taşır; authority grafiği/audit okuması ve her yazma AIS (veya holder-bound okuma projection'ı) ister (12.5.5, MD-14). Yerel SDK'da sistem tarayıcısı zorunlu (RFC 8252); first-party apps akışı (draft-04) varsayılan **kapalı**, istemci kanıtlaması zorunlu, sunucu her aşamada tarayıcıya düşürebilir.

**Askıya alınabilir ve sürdürülebilir kimlik doğrulama.** Sihirli bağlantı, bant dışı onay ve CIBA akışın ortasında duraklayıp başka cihazda/zamanda sürmeyi gerektirir; bu durum **tipli durum makinesinde** modellenir, aksi hâlde denetlenmeyen bir yan kanalda gerçeklenir. Dört kural:

1. Askıdaki durum **sunucuda** tutulur. İstemciye yalnız **opak bir tanıtıcı** verilir; tanıtıcı authority veya güvence taşımaz (AGI-6 ile aynı ilke).
2. Tanıtıcı **tek kullanımlıktır** ve akışa ve başlatan tarayıcı bağlamına bağlıdır.
3. Askı penceresinin **mutlak bir ömrü** vardır (PD).
4. Sürdürme, askıya alma anındaki güvence seviyesini **yükseltmez**: eksik faktörler hâlâ eksiktir; sürdürme yalnız askıya alınırken beyan edilen adımı tamamlar (TNI-9).

Ek kurallar (çıkarım):

5. Sürdürülen akış önceki adımları yeniden çalıştırmaz ve atlayamaz.
6. Sürdürme ve sona erme ayrı denetim olaylarıdır; sihirli bağlantının e-posta tarayıcısı tarafından tıklanması akışı tüketmez (12.3.8 #9 ile aynı ilke).

Ping'in 2026 geri kanal yolculukları referanstır.

**Kimlik doğrulama → token: tipli tek değer.** Durum makinesi ile token üretimi arasındaki arayüz **tipli tek bir değer**dir (serbest talep haritası değil): kullanılan yöntem, ulaşılan güvence seviyesi, bağlanan authenticator ve realm bağlamı; token üretimi kimlik doğrulama yolunun kendisine erişemez (PingFederate/AD FS ayrıntıları **doğrulanmadı**). Access tarafında bu değer Claim Ingest'e giden Claim'in kaynağıdır (TI-15) ve ayrı cell/KMS sınırıyla daha güçlüdür; `tenant_id` bu değerde yalnız yönlendirme bağlamıdır, authority girdisi değildir (TN-1).

**OAuth hata gösterimi.** Geçersiz `redirect_uri` veya `client_id`'de **yönlendirme yapılmaz**, kullanıcıya hata gösterilir (RFC 6749); diğer OAuth hataları ham gösterilmez; geliştirici hataları için yalnız korelasyon kimliği taşıyan nazik mesaj.

**Kurtarma ve hata mesajı dürüstlüğü.** Jenerik mesaj numaralandırmayı kapatır; ama kullanıcı kendi oturumunda ise durum dürüstçe söylenir (kurtarma soğuması tarihi, TN-55; offline pencere, TN-50). Access'in forbidden claims listesi (§8.10) ve degraded-state kuralı (§8.13, X26) identity plane metinlerine de uygulanır: "erişim kaldırıldı" ancak gerçekten öyleyse; açık bir ValidityContract penceresi varsa "within the declared window" denir (X12). Terk verisi satıcı içeriğidir (**doğrulanmadı**). Ayrıntılı deneyim kuralları → §8 (D-Exp).

**REQUIRE_ACTION wire biçimi.** 10 kapalı sınıf + 6 remediation kodu → §8/§9.6; identity plane'deki RFC 9470 köprüsü TN-O3'tedir (TN-44).

**Adaptif risk ve rate limit.** Risk skoru bir Claim'dir; karar ADP'dedir; IdP kendi giriş sürtünmesi için kullanabilir (TN-O4, TN-46). Bot/rate limit kuralları TN-H6'dadır.

**TN-G1 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-96 | Önce tanımlayıcı varsayılan; realm başına numaralandırma modu (toplu/katı); sabit çıktı; passkey ile giriş yolu her zaman | FROZEN (sabit çıktı, passkey yolu), PD (mod) | UNDER DECLARED CAPABILITY | CVE-2026-4633; OWASP | — |
| TN-97 | Passkey numaralandırma: boş `allowCredentials`, deterministik hayali ID, Signal API kuralları | FROZEN | UNDER DECLARED CAPABILITY | WebAuthn şartnamesi | — |
| TN-98 | HRD varsayılan kapalı, onaylı; realm politikası > istemci ipucu | FROZEN | UNDER DECLARED CAPABILITY | Microsoft dersi | — |
| TN-99 | Koşullu arayüz + açık düğme + AbortController; ayrık telemetri; QR son çare; FIDO iki zorunlu desen | PD | NOT GUARANTEED (platform davranışı) | Platform verisi | — |
| TN-100 | Login push sayı eşleştirme (aynı cihaz istisnası); authority onayı bildirimde yalnız CT1 + H(AAS) | FROZEN | UNDER DECLARED CAPABILITY (login); BY SEMANTICS (CT1 sınırı) | İki ayrı onay | §13.7.3 |
| TN-101 | İki üretim modu (gömülü bileşenler varsayılan, barındırılan sayfalar tam destekli; TN-133); gömülüde özel alan adı ve passkey önceliği; SPA için BFF; örtük akış yok; sistem tarayıcısı; first-party apps varsayılan kapalı + kanıtlama | FROZEN (örtük yasak), PD (diğerleri) | UNDER DECLARED CAPABILITY | RFC 10017, RFC 8252 | — |
| TN-102 | Askıya alınabilir kimlik doğrulama tipli durum. Dört kural: sunucu tarafı durum + opak tanıtıcı, tek kullanım + bağlama, mutlak askı ömrü, güvence yükseltmez. Ek kurallar: adım atlamaz, ayrı denetim | FROZEN (1–4), PD (ömür değeri, 5–6) | UNDER DECLARED CAPABILITY | Magic link/CIBA durum makinesi içinde | — |
| TN-103 | Kimlik doğrulama → token arayüzü tipli tek değer (yöntem, güvence, authenticator, realm); token üretimi yola erişemez; Claim kaynağı | FROZEN | UNDER DECLARED CAPABILITY; BY SEMANTICS (TI-15) | Serbest talep haritası yükseltme yüzeyidir | — |
| TN-104 | Geçersiz `redirect_uri`/`client_id`'de yönlendirme yok; korelasyon ID'li nazik mesaj; mesaj dürüstlüğü §8.10 ile | FROZEN | UNDER DECLARED CAPABILITY | RFC 6749 | — |
| TN-133 | Gömülü bileşenler ve barındırılan sayfalar birlikte sunulur; gömülü varsayılandır. Gün-1 bileşenleri: giriş/kayıt, kullanıcı menüsü, hesap ayarları, organizasyon seçici/ayarları, ajan bağlantıları. Gömülüde özel alan adı zorunlu, passkey öncelikli. Üçüncü taraf izin ekranı, CT3 onayları ve yönetim konsolu her zaman barındırılan sayfadadır | FROZEN (iki mod, gömülemeyen üç yüzey); PD (varsayılan mod, bileşen listesi) | UNDER DECLARED CAPABILITY (kiracı sitesinin bütünlüğü); BY SEMANTICS (gömülemeyen yüzeyler) | Kiracı ekranlarına Clerk kadar kolay erişir; en riskli anlar Access'in denetimindeki yüzeyde kalır | TN-132; X11; TN-17 |

#### 12.4.2 TN-G2 — Özelleştirme ve markalama

**Akış kompozisyonu kiracıya kapalı.** Adım sırasını kiracının değiştirebilmesi (kompozisyon) Keycloak 40744 sınıfını üretir ve reddedilir; askıya alınabilirlik (TN-102) ise açıktır. Çekince kayda geçer: red gerekçesi tek üründeki tek hataya dayanır; Ping'in yolculuk ürünü ve Janssen Agama tasarımı incelenmemiştir. TN-132 sonrası bu çekince kararı zayıflatmaz: kiracıya verilen esneklik (sıra ve ekran) sunucu güvenliğini sıraya bağlamaz. Ping/Agama incelemesi yalnız sunucu tarafı kompozisyon yeniden açılırsa gereklidir. Access tarafında karşılığı T13'tür (akış tanımı kod/şema ile; çıkarım: T13 kanonik metni §16.10'dadır).

**Gereksinim modeli: sıra ve ekran kiracıda, kurallar sunucuda (TN-132).** Sunucu akışın adım sırasına bakmaz; yalnız **tamamlanması gerekenlerin listesini** ve bozulamaz kuralları tutar. Kiracının sırayı değiştirmesi bu yüzden Keycloak 40744 sınıfını üretmez: güvenlik kararı sıraya değil, listenin tamamlanmış olmasına bağlıdır.

1. **Kiracı panelden gereksinimleri seçer:** açık giriş yöntemleri (e-posta, telefon, kullanıcı adı, sosyal sağlayıcılar, passkey), zorunlu profil alanları, MFA zorunluluğu, kayıt için domain izin/engel listesi. Bu seçimler realm config'tir (`idp.*` domain action, MD-14).
2. **Sunucu her adımda eksikleri bildirir** (düğüm sözleşmesi, aşağıda madde 4): "e-posta girildi, doğrulanmadı; telefon eksik" gibi tipli bir durum döndürür.
3. **Toplama sırası ve ekranlar kiracıdadır.** Kiracı bilgileri istediği sırayla toplar (ör. önce telefon, sonra e-posta), adımları farklı sayfalara böler, aralara kendi ekranlarını koyar.
4. **Bozulamaz kurallar sunucudadır ve sıradan bağımsızdır:** doğrulanmamış bilgiyle hesap etkinleşmez ve oturum açılmaz; zorunlu MFA atlanamaz; kurtarma güvencesi korunan şeyden düşük olamaz (MKT-D6); güvence yükseltilmez (TN-102). Liste tamamlanmadan oturum yoktur.
5. **Görsel tasarımcı (yol haritası).** Bu modelin üstüne, yalnız ekranların sırasını ve görünümünü düzenleyen sürükle-bırak bir tasarımcı eklenir. Tasarımcı sunucu kurallarına ve gereksinim listesine dokunmaz; ürettiği şey istemci tarafı ekran düzenidir. Sunucuda adım dizme (kompozisyon) kapalı kalır (TN-105).

**Markalama: betiksiz şablon, CSP, düğüm sözleşmesi, sunucu tarafı kod yasağı.**

1. Kiracıya **asla sunucu tarafı şablon çalıştırma** verilmez (Keycloak FreeMarker: "kötü niyetli bir şablon süreç olarak kod çalıştırabilir").
2. Yasak şablona özgü değildir: WSO2 uyarlanabilir kimlik doğrulama betikleri, Zitadel eylemleri ve authentik ifade politikaları gibi **kiracının yazdığı kodu IdP sürecinde koşturan her yüzey** kapsamdadır. Bu, kiracı kodu ve özelleştirme yürütmesinin ortak kuralıdır.
3. Özelleştirme betiksiz şablonlama + CSP izin listesiyle sınırlanır; CSP önce yalnız rapor modu, sonra zorlanan mod (Okta deseni). Auth0 Liquid'in karakter izin listesi her bağlamda XSS'i kapatmaz.
4. Özelleştirme bir **düğüm sözleşmesi**yle verilir (Ory Kratos UI node modeli): sunucu tipli bir yapı döndürür, çizimi istemci yapar; sunucu istemcinin göndermediği/uydurduğu alanları reddeder; düğüm sözleşmesi **bir güvenlik sınırı değildir**.
5. Markalama ve şablon değişiklikleri realm config'tir ve realm'in yönetişim domain'inde `idp.*` domain action Exercise'ı ile yazılır (MD-14); CSP izin listesini genişletmek bir genişlemedir (SI-18'in ruhu, çıkarım).

**Özel alan adı passkey'den önce → TN-K2.** RP ID kararı TN-K2'dedir (TN-17); burada yalnız UX kuralı: özel alan adı passkey'lerden **önce** zorunludur ve alan adı değişimi arayüzde geri dönülemez olarak işaretlenir.

**TN-G2 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-105 | Akış kompozisyonu kiracıya kapalı; askıya alınabilirlik açık | FROZEN | BY SEMANTICS (yüzey yok) | Keycloak 40744 | — |
| TN-106 | Kiracı kodu IdP sürecinde asla (şablon, betik, eylem, ifade politikası); betiksiz şablon + CSP (rapor → zorlama); düğüm sözleşmesi; markalama değişikliği `idp.*` domain action Exercise'ı | FROZEN (yasak), PD (CSP modu) | BY SEMANTICS (yüzey yok); UNDER DECLARED CAPABILITY (CSP) | RCE/XSS kanıtları | MD-14 |
| TN-132 | Gereksinim modeli: kiracı panelden gereksinimleri seçer (yöntemler, zorunlu alanlar, MFA, domain listesi); toplama sırası ve ekranlar kiracıdadır; sunucu sıraya bakmaz, yalnız gereksinim listesinin tamamlanmasını ve bozulamaz kuralları (doğrulanmamış bilgiyle etkinleşme yok, zorunlu MFA atlanamaz, kurtarma ≥ korunan şey, güvence yükseltme yok) uygular. Yalnız ekran düzenini değiştiren görsel tasarımcı yol haritasındadır; sunucu kompozisyonu kapalı kalır (TN-105) | FROZEN (model, kurallar); WATCH (görsel tasarımcı) | BY SEMANTICS (kuralların sıradan bağımsızlığı); UNDER DECLARED CAPABILITY (kiracı ekranı) | Kiracı esnekliği Keycloak 40744 sınıfını üretmeden sağlanır; güvenlik sıraya değil listenin tamamlanmasına bağlıdır | TN-102; TN-105; MKT-D6 |
| TN-135 | **Dış çağrı noktaları (inline hook).** Access belirli anlarda (kayıt öncesi, token üretimi, giriş sonrası) kiracının kayıtlı HTTPS adresini imzalı bir istekle çağırır; kod kiracının sunucusunda çalışır, Access sürecinde çalışmaz (F23 korunur). Cevap tipli şemayla okunur ve yalnız şunları yapabilir: kaydı/girişi reddetmek; token'a yetki taşımayan identity plane claim'i eklemek. Cevap Claim olarak girer, authority üretemez (INV-12); reserved protokol claim'lerini yazamaz (must-never #18). Zaman aşımı veya hata: fail-closed (MD-8); yalnız claim ekleme türü çağrılarda kiracı "cevap yoksa eklemeden devam" seçebilir. Çağrı noktası kaydı realm config'tir (`idp.*` domain action, MD-14) | FROZEN (kod Access'te çalışmaz, yalnız daraltma/yetkisiz claim, fail-closed); PD (çağrı noktası listesi, zaman aşımı) | BY SEMANTICS (authority üretmeme); UNDER DECLARED CAPABILITY (kiracı sunucusunun cevabı) | Claim zenginleştirme, kayıt engelleme ve özel risk kararı RCE riski olmadan karşılanır | F23; INV-12; MD-8 |
| TN-136 | **Webhook'lar.** Access identity ve authority olaylarını (kullanıcı oluşturma/güncelleme/askı, organizasyon üyeliği, oturum iptali, tercih ve belge onayı değişikliği, ajan askısı vb.) kiracının kayıtlı adreslerine kendisi teslim eder: Standard Webhooks formatında imzalı, en az bir kez teslim, yeniden deneme, olay başına benzersiz kimlik (idempotency). Olaylar outbox'tan beslenir (TI-7). Webhook bildirimdir, authority kaynağı değildir: teslimin kaybı veya gecikmesi hiçbir kararı etkilemez (INV-24). Relay bu webhook'ları tüketebilen sistemlerden biridir. Datadog, Splunk, Kafka ve AWS EventBridge için hazır log/olay akışları yol haritasındadır | FROZEN (bildirim ≠ authority, imza, en az bir kez); PD (olay kataloğu); WATCH (hazır akışlar) | UNDER DECLARED CAPABILITY (teslim) | Kiracı sistemleri senkron kalır; IDP-36/IDP-37'deki dışa aktarımın taşıyıcısıdır | INV-24; TI-7; E30 |

#### 12.4.3 TN-G3 — Erişilebilirlik ve yerelleştirme

**WCAG 2.2 AA, EAA, erişilebilir kimlik doğrulama.**

1. WCAG 2.2 SC 3.3.8 (Accessible Authentication, Minimum, AA): bilişsel işlev testi yasaktır; **yapıştırma asla engellenmez**, parola yöneticisi otomatik doldurması asla bloklanmaz; OTP alanları **tek alanlı ve yapıştırılabilir**; "belirli karakterleri girin" istemi doğrudan başarısızdır; `autocomplete` / girdi amacı kriterine uyulur.
2. CAPTCHA yerine etkileşimsiz bot savunması (hız sınırlama, iş kanıtı, bal küpü, sezgisel yöntemler, WebAuthn); CAPTCHA AA'da nesne tanıma istisnasıyla geçer, **AAA'da geçmez**.
3. Koşullu arayüzde ekran okuyucuya açılır pencere duyurulur; **QR asla tek yol değildir** (FIDO denetimi: QR hareket/görme kısıtlı kullanıcı için bariyer).
4. AA uyumu bir **satış gereksinimi**dir. EAA'nın 28 Haziran 2025 uygulama tarihi, kapsamı ve mikro işletme muafiyeti (<10 çalışan, <2 M €) yalnız ikincil kaynaklardandır — **doğrulanmadı**.

**Yerelleştirme zinciri, RTL, izleme modu, FIDO desenleri.**

1. Çok kademeli yedek zinciri + realm seviyesinde metin ezme; yön (RTL) desteği baştan (Keycloak 7 kademeli zincir; Auth0 80+ dil, RTL erken erişim); arayüz yerel ayarı yukarı akış sağlayıcılara iletilir (`ui_locales`).
2. Terim eşlemesi: canonical → UI terimleri EN/TR (§8.8) ve "oturum" terimi 12.0.3'e göre: identity plane oturumu UI'da "Sign-in on ‹cihaz›" / "‹cihaz› üzerinde giriş"tir; authority kavramları (Mandate, Instance) login metinlerine taşınmaz.
3. Saldırı korumasına **izleme modu** (bot tespiti, şüpheli IP kısıtlaması, kaba kuvvet, ihlal edilmiş parola tespiti engellemeden günlüğe yazar); realm bir korumayı açmadan etkisini ölçer (TN-O4 TN-46 ile aynı ilke). İzleme modu yalnız identity plane sürtünmesi içindir; authority karar yolunda "izleme modunda ALLOW" yoktur (TI-9, MD-8).
4. FIDO'nun iki zorunlu deseni (12.4.1).

- **TI-9** No fail-open code path. Decision path'teki her arıza protocol rejection, DENY veya REQUIRE_ACTION üretir; fail-open, degraded-allow veya bypass konfigürasyonu kodda tanımlı değildir

**TN-G3 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-107 | WCAG 2.2 AA zorunlu: yapıştırma/otomatik doldurma serbest, tek alanlı yapıştırılabilir OTP, etkileşimsiz bot savunması, QR tek yol değil, ekran okuyucu duyurusu | FROZEN | UNDER DECLARED CAPABILITY | Satış gereksinimi; EAA (tarih doğrulanmadı) | — |
| TN-108 | Yerelleştirme zinciri + realm ezmesi + RTL + `ui_locales` iletimi; terimler §8.8 ve 12.0.3; izleme modu yalnız identity plane sürtünmesi için (authority yolunda yok) | PD (zincir), FROZEN (izleme modu sınırı) | UNDER DECLARED CAPABILITY; BY SEMANTICS (TI-9) | Terimler §8.8; mekanizma identity plane | — |

### 12.5 Yönetim API'si, devredilmiş yönetim, yapılandırma ve konsol

**Ortak ilke (MD-14).** Yönetim **yüzeyleri** ayrıdır (audience, scope ad alanı, hız bütçesi); **yazma yolu** tektir: her authority state değişikliği bir meta-Exercise'a, her realm config değişikliği (client, redirect URI, IdP bağlantısı, realm ayarı, markalama, anahtar politikası) realm'in yönetişim domain'inde (12.1.1 2a) bir `idp.*` **domain action** Exercise'ına indirgenir; Access karar verir, identity plane PEP olarak kendi kaydını yazar; ikisi de aynı ADP sözleşmesinden ve CT tazeliğinde AIS ile geçer. Konsol çerezi yalnız gezinmeyi ve identity plane'in kendi (authority taşımayan) ekranlarını taşır; authority grafiği ve audit okuması ile her yazma AIS (okuma CT0) veya holder-bound okuma projection'ı ister. Ayrı bir "admin token" sınıfı yoktur.

- **PI-4** Authority state'ini değiştiren veya okuyan her istek tek Exercise contract'ından geçer (meta-action'lar, okuma, export dahil); ayrı "admin" yazma yolu yoktur.
- **INV-2** Single write path (authority state). Genesis dışında authority state (Anchor, Grant, Mandate, Acceptance, RestrictionPolicy, Instance authority-binding, budget terms, authority config) yalnız bir meta-action Authority Exercise'ının committed ALLOW'u ile değişir. Admin, provider, first-party ürün veya operator için başka yazma yolu yoktur. Claim corpus ayrıdır: dış Claim ingest'i authority mutation değildir, positive authority üretemez ve karara yalnız aktif scoped Acceptance ile girer; domain-issued Claim claim.issue meta-Exercise'ıdır. (L11, CI-15)
- §9.7 (tam metin): "Sonuç: **Bir "admin API" ayrı bir yazma yolu olamaz.** Bir implementasyon kolaylık için REST/gRPC yönetim uç noktaları sunabilir; ama her biri bir meta-Exercise Request'e indirgenmek zorundadır ve aynı actor proof, basis, capacity, requirement ve kayıt kurallarına tabidir (PI-4). Conformance suite bunu test eder: actor proof'u olmayan bir yönetim çağrısı authority state'ini değiştiremez."

§9.7 kapsamı: "authority state" kapsamına realm config'i de girer — identity plane'in client, redirect, IdP bağlantısı ve realm ayarı değişiklikleri **domain action**'larıdır ve realm'in yönetişim domain'inde ADP `commit` ile yazılır; identity plane yönetim uç noktası bu Exercise'ın kaydı olmadan config değiştiremez. Identity plane'in kendi operasyonel kayıtları (oturum, refresh ailesi, hesap durumu sayaçları) bu kuralın dışındadır; onlar identity plane'in kendi geçişleridir (E29).

#### 12.5.1 TN-Y1 — API şekli ve tek yazma yolu

**Tek yazma yolu.** Yukarıdaki PI-4/INV-2/§9.7 + MD-14. "Hiçbir aktör kendi etkin izin kümesinin üstünde bir izni hiçbir yolla verememelidir" (HRU güvenlik problemi genel hâlde karar verilemezdir); Access'te bu değişmez ontolojiktir (INV-10, Exercise başına tek basis) ve conformance testlidir.

**Genesis / önyükleme.** "İlk yöneticiyi kim yaratır" sorusu Genesis ile kapanır; ikinci bir "bootstrap admin" yazma yolu yoktur.

- **C4** Genesis, domain başına tek unconditioned kayıttır; meşruiyeti dışsaldır; sonrası yalnız Exercise. Hosting provider root değildir.

Genesis kurulum UX'i: realm oluşturma sihirbazı, realm'in yönetişim domain'i yoksa (12.1.1 2a) o domain'in Genesis kaydını kurucunun cihaz-bağlı authenticator'ıyla imzalanmış tek kayıt olarak üretir; meta-anchor root'u `Joint(k ≥ 2)` önerilir (§13.7.7), `Sole` seçilirse "Recovery not available" uyarısı ve rootTerms `domain.recover` entry'si kurulamıyorsa NG beyanı gösterilir (TN-60, §13.7.7). **Genesis'te beyan edilen root anahtarları ve authenticator'ları SEC18 anlamında "yeni binding" değildir** (Genesis unconditioned'dır, C4); Genesis sonrası her binding SEC18'e tabidir. Kurucunun identity plane hesabının yönetim **yetkisi** Genesis'teki kurucu agency/bootstrap Grant'ından veya root'un Exercise'ından gelir (§5 "önyükleme yolu yoktur"); hesap ↔ Party bağı IdentityBinding Claim'idir ve yalnız actor-binding girdisidir (CI-2, E5).

**API şekli.** Protokol sürümü §9.17'dedir (ADP kural sürümü). REST ergonomisi:

1. Sürüm **kaynak başına** ve yolun sonunda (`/admin/api/{realm}/clients/v2` deseni; Keycloak 26.7.0); küresel sürüm göçü yok.
2. `PUT` = ekle-veya-güncelle, `POST` = oluştur, `PATCH` = JSON Merge Patch (RFC 7396; açık `null` problemini çözer).
3. Oluşturma `201` + tam temsil gövdesi.
4. Kaynaklar hem benzersiz kimlikle hem kararlı, insan okunur **doğal anahtarla** adreslenir (GitOps'ta sahte fark önler). Dış kimlikler opaktır (MD-18).
5. Sorgu: SCIM filtre alt kümesi; **bilinmeyen alan → 400** (sessiz yok sayma tüm kayıtları döndürür, güvenlik hatasıdır).
6. İmleç tabanlı sayfalama; `Link` başlığı (RFC 8288).
7. Kaynak tek istekte tam yaratılabilir (client + roller); genişletme desteği.
8. OpenAPI **koddan üretilir**, SDK'lar şartnameden derlenir.

Ek kural: her yazan REST çağrısı sunucu tarafında bir meta-Exercise (authority state) veya `idp.*` domain action Exercise'ı (realm config) Request'ine derlenir ("kolaylık API'leri ADP'ye derlenir", T35); REST yanıtı Exercise kaydının referansını (`exercise_id`, `position`) döner (çıkarım: S-satırı kayıt referansı X14'ün dürüst durum merdiveniyle uyumlu).

- **T35** → §16.10 T35 (kanonik metin orada). Bu bölümdeki uygulama: kolaylık API'leri ADP'ye derlenir.

T35: sunucu tarafı tek dil Rust'tır — authority plane (sequencer, Core, ADP, ingest, witness istemcisi) ve identity plane (OAuth/OIDC AS, oturum, hesap, SCIM, **admin API**); kripto aws-lc-rs; konsol TypeScript; istemci SDK'ları dil başına tek pakettir ve Kernel'e bağlanır (T41, MD-1). "Kolaylık API'leri ADP'ye derlenir" kuralı geçerlidir. Runtime ayrıntısı → §16.

**Yetki filtresi veri katmanında; uç nokta izin manifesti.**

- **TI-20** Disclosure filter last and monotone. Her okuma yolu (cevap, explain, search, event, export) son aşamada disclosure scope filtresinden geçer; daha derin kademe daha sığ olanla çelişmez
- **TI-RT12** Semantik sonuç değiştiren her kural L0/L2 normatif metinde ve conformance vektörlerindedir; implementasyon davranışı ölçüt değildir

Yetki filtresi **veri erişim katmanında**dır, işleyicide değil (CVE-2026-17059: kullanıcılar uç noktası süzüyor, rol üyeleri uç noktası süzmüyordu); Rust tip sisteminde süzülmemiş koleksiyonun serileştirilebilir tipe dönüşmesi derleme zamanında imkânsızdır. Her yolun gerektirdiği izin **makine okunur manifestte** durur; manifestsiz yol CI'da derlemeyi kırar; her yol için "bu izin olmadan 403/404" testi otomatik üretilir (Zitadel CVE-2025-27507: 12 uç nokta). Kaynak gizleme varsayılandır: yetkin olmadığınız kaynak listede görünmez, 403 bile alınmaz (karar yüzeyi tarafı §9.6 / §13).

**Yetki testleri bellek güvenliğine bırakılmaz.** Keycloak danışmanlıklarının ilk sayfasındaki 10 kayıttan 7'si atlatma sınıfıdır, sıfır bellek güvenliği hatası; yola dayalı yetkilendirmede karşılaştırmadan önce **tek bir kanonikleştirme fonksiyonu** ve özellik testi zorunludur.

**TN-Y1 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-110 | Tek yazma yolu: her authority state yazması meta-Exercise, her realm config yazması yönetişim domain'inde `idp.*` domain action Exercise'ı; REST yanıtı Exercise referansı döner; ayrı admin token sınıfı yok | FROZEN | BY SEMANTICS | PI-4, INV-2, §9.7 | MD-14 |
| TN-111 | Genesis tek unconditioned kayıt; bootstrap admin yolu yok; kurulum sihirbazı (yönetişim domain'i yoksa) `Joint(k ≥ 2)` önerir, Sole'de NG uyarısı; Genesis'te beyan edilen root anahtarları/authenticator'ları SEC18 anlamında yeni binding değildir, sonrası SEC18'e tabidir; kurucu hesabının yönetim yetkisi Genesis'teki kurucu agency/bootstrap Grant'ından veya root Exercise'ından; hesap ↔ Party bağı IdentityBinding Claim'i (yalnız actor-binding girdisi, CI-2) | FROZEN (C4), PD (UX) | BY SEMANTICS | C4 | §13.7.7 |
| TN-112 | REST ergonomisi (kaynak başı sürüm, Merge Patch, 201+gövde, doğal anahtar, SCIM filtre + bilinmeyen alan 400, imleç, tek istekte yaratma, OpenAPI koddan) | PD | UNDER DECLARED CAPABILITY | Keycloak pişmanlık listesi | — |
| TN-113 | Yetki filtresi veri katmanında (tip sistemiyle); uç nokta izin manifesti + otomatik 403/404 testi; kaynak gizleme varsayılan; tek kanonikleştirme + özellik testi | FROZEN | UNDER DECLARED CAPABILITY; BY SEMANTICS (TI-20) | CVE-2026-17059, Zitadel | — |

Not: TN-109 TN-Y2 tablosundadır; TN-H8 ona ileri referans verir.

#### 12.5.2 TN-Y2 — Devredilmiş yönetim

**Model.** Devredilmiş yönetim = meta-action ActionRef'leri üzerinde Grant'lar; rol = sürümlü, pin'li named AuthoritySet (C28); "Full access" yoktur (X20). Ek kurallar: kiracı (realm) başına **kademeli açma bayrağı** ve "v1 → v2 otomatik göç vaadi yok" (Keycloak FGAP v2: Nisan 2025'ten sonraki ~14 ayda ≥ 5 yükseltme açığı). Okta kaynak kümeleri ve Entra kısıtlı yönetim birimleri/korunan eylemler referanstır.

- **C28** Named AuthoritySet'ler (role/template) Grant'ta sürümüyle pin'lenir; canlı dolaylılık yoktur.
- **X20** (12.3.4'te tam metin).

**Yükseltme kapatma değişmezi.** Hiçbir aktör kendi etkin izin kümesinin üstünde bir izni hiçbir yolla veremez. Access'te bu INV-10 ve Exercise başına tek basis (INV-4) ile yapısaldır; Keycloak'ın beş ayrı açığı kontrolün her yolda uygulanmamasındandır (CVE-2025-7784, CVE-2026-9099, CVE-2026-3121, CVE-2026-9795, CVE-2026-9796; authentik CVE-2024-37905; Zitadel CVE-2025-53895, CVE-2026-27946; GitLab CVE-2026-35595, CVE-2026-6267; üç 2026 açığının puan/yolu **doğrulanmadı**).

**Hiyerarşi mutasyonu iki uçta izin; taşıma etkin izni artıramaz.** CVE-2026-9099: alt grup ekleme yetki kontrolü yapmıyordu; düşük yetkili grup yöneticisi alan yöneticisi grubunu kendi altına taşıyıp tam alan devralıyordu. Access'te Anchor reparent yoktur; resource move domain'indir (E14). **E14'e ek kural**: bir kaynak taşıma niyeti **iki ucu da adlandırır** ve hem kaynak hem hedef üzerinde izin ister, **veya** yeni incarnation üretir (eski Grant'ları miras almaz). Taşıma, taşıyanın etkin izin kümesini artıramaz. (E14) Hedef scope'un holder'larının kazandığı erişim, hedef uçta authority sahibinin aynı Exercise'taki onayına bağlıdır ve change-impact önizlemesinde gösterilir; kaynak scope'tan türeyen authority hedefe taşınmaz (INV-35).

- **E14** Resource lifecycle. Resource varlığı, incarnation, move, split/merge domain'indir; Anchor ve root Access'indir. Domain Anchor root'unu yazamaz; Access resource varlığını beyan edemez. Reincarnation yeni incarnation zorunludur ve eski Grant'ları miras almaz. Domain sahiplik değişikliği root'u değiştirmez; anchor.transfer Exercise'ı gerekir.

**Seçim yoluyla yükseltme.** IdP grup yöneticisi bir kullanıcıyı bir gruba ekleyerek rule-shaped Grant'ın seçimine sokabilir (SI-3: "ceiling içinde seçim"). Kural: kapsamı **reserved veya CT3** action içeren bir rule-shaped Grant'ta **yeni holding episode**'u SEC18 benzeri 24 saat soğuma (CT2+ için) ve SI-21 bildirimi alır (PD). Bu, seçimi yapan issuer'ın (SCIM/IdP) ele geçirilmesinde patlama yarıçapının SI-3'ün beyan ettiği "mevcut ceiling içinde seçim"in de altında, gecikmeli olmasını sağlar.

- **SI-3** Compromise blast radius equals the declared use. Bir issuer'ın ele geçirilmesi yalnız kabul edildiği Acceptance use'unun beyan edilmiş etkisini üretebilir: actor-binding → subjectClass'taki Party'lerin mevcut authority'si kadar impersonation; predicate-input → yalnız daraltma/requirement; subject-selection → mevcut ceiling'ler içinde seçim; foreign-authority → bridging ceiling'i; schema-definition → pin'li digest'in anlamı. Hiçbiri Grant, Acceptance, reserved veya meta-action yetkisi üretmez *[BY SEMANTICS]*

**Sahip alanı değişmezliği.** Kimlik bilgisi ve token nesnelerinin sahip alanı yaratılışta sabitlenir, hiçbir güncelleme yolu değiştiremez (authentik CVE-2024-37905: API token'ının kullanıcı kimliği değiştirilerek süper kullanıcı olunuyordu). Access'te: holder değişimi = yeni Grant (C16); Instance'ın Party'si sabittir; projection holder-bound'dur (PI-11). Identity plane nesneleri (API anahtarı, refresh ailesi, passkey kaydı) için aynı kural açıkça yazılır. *[BY SEMANTICS (Access); UNDER DECLARED CAPABILITY (identity plane şeması)]*

- **C16** Grant revizyonlu tek kimliktir: scope/terms/validity/delegability/budget değişikliği revizyon; holder veya basis değişikliği yeni Grant; tek istisna intensional selector'ın conjunctive daraltılmasıdır (narrowing revizyonu). Expired/revoked Grant canlanmaz. Budget ledger revizyonlar boyunca süreklidir.

**Scope mapping / protocol mapper.** Token'a iddia yazabilen her mekanizma, yetkilendirme kararını etkiliyorsa yetki veren bir işlemdir. Access'te yapısal olarak kapalıdır: mapper'lar yalnız identity plane claim'i üretir; OAuth scope ≠ Access authority (L24, S-2); projection'daki claim'ler authority kaynağı değildir. Mapper yapılandırması realm config'tir: yönetişim domain'inde `idp.*` domain action Exercise'ıdır (MD-14). Bir subject-selection Acceptance'ı olan claim class'ının üyeliğini toplu değiştirebilen mapper/upstream grup eşlemesi reserved bir requirement ile korunur (CT3) ve her grubun tek üyelik issuer'ı vardır (12.3.8).

- **L24** OAuth ailesi (RFC'ler; OAuth 2.1 draft olarak etiketlenir) projection ve transport'tur. OAuth scope ≠ Access authority; RAR envelope'un taşıyıcısıdır, semantiği Access'tedir. Projection'lar holder-bound ve audience-bound'dur; token passthrough yoktur.

**Korunan eylemler = eylem anında step-up.** Entra korunan eylemlerinin modeli (politika eylem anında; yetkinin yerine değil üstüne) Access'te RequirementTerm'dir (§13.7.1, SEC10). Aday liste CT3'e şöyle bağlanır: **kalıcı silme** ve **realm imza anahtarı rotasyonu** (rotasyon politikası değişikliği ve acil/elle rotasyon; politika içinde zamanlanmış yürütme operasyoneldir) **reserved action ilan edilir** (→ CT3, §13.7.1); IdP bağlantısı (actor-binding `acceptance.establish`), SCIM `subject-selection` Acceptance (TN-95), break-glass muafiyeti `policy.set` gevşetmesi (TN-93) ve göç dışa aktarımı (reserved, TN-86) zaten §13.7.1 CT3 tanımındadır.

- **INV-10** Meta-authority asymmetry. Genişletme daraltmadan daha sıkı requirement taşıyabilir, tersi asla. Bir requirement'ı gevşetmek mevcut (daha sıkı) requirement'ı karşılamayı gerektirir. (L11)

**Platform ↔ kiracı yüzeyleri; kiracı bağlamı.** Yüzeyler ayrıdır: platform yönetim API'si ve realm yönetim API'si ayrı audience, ayrı scope ad alanı, ayrı hız bütçesi (Auth0 My Organization API, 21 Nisan 2026). "Ana kiracıdan her şeyi yönet" modeli yoktur (Keycloak master realm). Kiracı/domain bağlamı **istemciden alınmaz**: authority domain AIS'te imzalıdır (PI-7) — "token'dan türet" kuralından güçlüdür; yolda/alt alan adında görünen realm her istekte AIS ve token audience'ıyla eşleşir. Provider/operatörün authority'si yoktur (INV-29):

- **INV-29** No semantic privilege; custody ≠ root. Hosting provider, Suiss first-party ürünleri ve operator'lar genesis'te veya sonradan explicit verilmemiş hiçbir authority'ye sahip değildir ve aynı sözleşmeyi kullanır. (CI-15, Work)
- **PI-7** Actor yalnız actor Instance'ın KeyBinding'iyle imzalanmış Actor Intent Statement'tan türetilir (domain, nonce, intent digest, PEP audience'a bağlı; başka isteğe taşınamaz); AuthZEN subject, PEP kimliği veya ADP çağrısının transport authentication'ı (mTLS / DPoP / WPT) actor değildir; statement'sız istek Anonymous'tur; her commit/continue kaydı statement'ı taşır.
- **XI-18** No first-party surface path. Suiss yüzeyleri, aynı sözleşmeyi kullanan conformant third-party yüzeyin yapamayacağı hiçbir authority eylemini yapamaz; first-party fark yalnız deneyim kalitesidir. (E24, EI-13, INV-29)

**"Platform yöneticisi bile göremesin".** Access'te bu bir seçenek değil **varsayılandır** (INV-29, X31, SI-14): operatör içerik okuma yetkisini ancak domain'in açıkça verdiği bir Grant ile alır. Entra kısıtlı yönetim biriminin tuzağı (PIM/hak yönetimiyle çalışmaması) burada yoktur, çünkü izolasyon ve yönetişim aynı Grant mekanizmasıdır. İdentity plane operasyon personeli için okuma erişimi de bir Grant'tır; destek erişimi TN-H4 modelindedir.

- **X31** Default visibility. Bir Party varsayılan olarak (a) kendi holding'lerini, (b) verdiği Grant'ları (capacity'si ne olursa olsun; tamlık kuralı) ve onların alt ağacını, (c) FOR(kendisi) capacity'siyle veya kendi verdiği Grant'lar üzerinden yapılmış kullanımları görür; ötesi explicit authority gerektirir. Bu bir ürün varsayılanıdır; daha sıkı varsayılanlar Security'de belirlenebilir.

**Kiracı BT sorumlusu (üçüncü aktör).** WorkOS yönetim portalı modeli: müşteri kuruluşunun BT sorumlusu kendi SSO/dizin bağlantısını kurar ve alan adını doğrular. Model: **named şablon Grant "kurumsal bağlantı yöneticisi"** — dar AuthoritySet: yalnız kendi domain'inin actor-binding Acceptance **taslağı**, IdP bağlantısı taslağı ve alan adı doğrulama Claim'i başlatma; süreli (PD 7 gün), davet bağlantısıyla verilir (`grant.issue`, CT2), delegable değil. Taslağı **yürürlüğe sokmak** (`acceptance.*` reserved, CT3) realm root'unun/yetkili yöneticinin Exercise'ıdır. Yüzey ayrı audience ve scope ad alanı taşır.

**Kimlik bilgisini yazan uç nokta yasağı → TN-H2 (TN-61).** Yönetim API'sinde `credential.set` yoktur; yalnız niyet belirteci üreten uç nokta vardır.

**Change-impact ve yetim uyarısı.** Change-impact preview ve rol sürümleme X20/C28'dir. "Yetim tuple" uyarısı önizlemenin bir satırıdır: bir şema/model değişikliği veya rol sürümü yükseltmesi, artık hiçbir action'a çözülmeyen Grant kapsamlarını, hiçbir holder seçmeyen rule-shaped Grant'ları ve sahibi kalmayan identity plane nesnelerini listeler ("orphan uyarısı"). Şema evrimi pin'li katalog + Acceptance'lı şemadır (E11, EI-16, C28); geçersiz tuple yok sayılmaz, change-impact'te görünür.

- **E11** No live action inheritance. Grant'taki namespace prefix, issue anında pin'lenen namespace katalog sürümüne çözülür; sonradan eklenen action'lar grant.amend olmadan kapsanmaz. Reserved action'lar hiçbir sürümde wildcard ile kapsanmaz; reserved bayrağının kaldırılması broadening'dir.

**Governance quorum koordinasyonu.** Reserved değişiklikler quorum Gate'iyle koordine edilir (X20); Access'in istek kuyruğu yoktur:

- **X5** Access has no request queue. İnsan eylemi gerektiren her authority talebi coordinator'ın dikkat yüzeyine (Suiss'te Work Gate/Condition → Needs Attention; third-party'de compatible coordinator) girer. Authority hub'ında "Requests" yoktur; "Changes" yalnız bilgidir. Governance quorum'ları da Work Gate veya IGA ile koordine edilir.
- **C26** Quorum authority composition'dır: Anchor.root Joint(k) veya RequirementTerm count=k, aynı intent digest'ine bağlı attributable contribution Exercise'larıyla; workflow değildir.

Admin deneyiminin yüzey/ekran tarafı (rol sürümü ekranı, Acceptance blast radius, offboarding) → §8 (D-Exp).

**TN-Y2 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-109 | Reserved/CT3 içeren rule-shaped Grant'ta yeni holding episode'u 24 s soğuma (CT2+) + SI-21 bildirimi | PD | BY SEMANTICS (episode, SI-21); UNDER DECLARED POLICY (soğuma) | CVE-2026-9099 sınıfı seçimle yükseltme | SI-3, SEC18, INV-31 |
| TN-114 | Devredilmiş yönetim = meta-action Grant'ları + pin'li rol sürümleri; realm başına kademeli bayrak; otomatik göç vaadi yok | FROZEN (model), PD (bayrak) | BY SEMANTICS | FGAP v2 dersi | — |
| TN-115 | Kaynak taşıma niyeti iki ucu adlandırır ve iki uçta izin ister veya yeni incarnation; taşıma taşıyanın etkin iznini artıramaz, hedef holder'ların kazancı hedef uç onayına bağlı (E14 eki, INV-35) | FROZEN | BY SEMANTICS | CVE-2026-9099 | — |
| TN-116 | Identity plane kimlik bilgisi/token sahip alanı değişmez | FROZEN | UNDER DECLARED CAPABILITY; BY SEMANTICS (C16) | authentik CVE-2024-37905 | — |
| TN-117 | Mapper/scope yalnız identity plane claim'i üretir; authority kaynağı değil; mapper ayarı `idp.*` domain action Exercise'ı; grup üyeliği tek issuer, upstream grup eşlemesi reserved requirement | FROZEN | BY SEMANTICS (L24) | Keycloak mapper yükseltmesi | — |
| TN-118 | Korunan eylem = RequirementTerm; kalıcı silme ve realm imza anahtarı rotasyonu (politika/acil) **reserved action** ilan edilir (→ CT3, §13.7.1); IdP bağlantısı, SCIM subject-selection, break-glass muafiyeti ve göç dışa aktarımı zaten §13.7.1 CT3 tanımındadır | PD (reserved ilanı); CT3 §13.7.1'den | BY SEMANTICS (INV-10) | Aynı ayrım | — |
| TN-119 | Platform ve realm yönetim yüzeyleri ayrı (audience, scope, bütçe); master realm modeli yok; domain AIS'ten (PI-7), yol/alt alan adı eşleşmesi her istekte; operatör yetkisiz (INV-29) varsayılan | FROZEN | BY SEMANTICS | Auth0 21.04.2026; Keycloak master | — |
| TN-120 | "Kurumsal bağlantı yöneticisi" named şablon Grant: yalnız taslak (Acceptance/IdP bağlantısı/alan adı Claim'i), süreli (7 g PD), delegable değil; yürürlüğe alma CT3 root/yönetici Exercise'ı; ayrı yüzey | PD | BY SEMANTICS | WorkOS üçüncü aktör | — |
| TN-121 | Change-impact'e yetim satırları (çözülmeyen kapsam, holder seçmeyen rule-shaped Grant, sahipsiz identity plane nesnesi) | PD | UNDER DECLARED CAPABILITY | Yetim tuple uyarısı | X20, C28, E11 |

#### 12.5.3 TN-Y3 — Yapılandırma yönetimi ve GitOps

**Uzlaştırıcı bir Party'dir.** Deklaratif yapılandırma uzlaştırıcısı **kendi Instance'ı ve Grant'ı olan bir agent Party'sidir**; her uygulama bir Exercise'tır (INV-2); fark (drift) bir okumadır. Kurallar:

1. Dışa aktarım **deterministik ve fark alınabilir**: sıralı diziler; üretilmiş kimlikler ve zaman damgaları isteğe bağlı çıkarılabilir; doğal anahtar adresleme (TN-112).
2. **Sırlar referansla** ayrılır (ortam değişkeni / sır yöneticisi işaretçisi); asla gömülü, asla maskeli değil.
3. Tam CRUD + kayma uzlaştırması; yalnız-oluşturan içe aktarım değil.
4. **İstenen durum ile çalışma zamanı durumu API seviyesinde ayrılır**; okuma, kullanıcının ayarlamadığı alanları ayarlanmış gibi göstermez (sahte kayma yok).
5. Sıraya bağlı yapılandırma (kimlik doğrulama yürütmeleri) kaynağın kendi alanıdır, ayrı çağrı değil. (Akış kompozisyonu kiracıya kapalıdır, TN-105; bu kural Suiss'in kendi akış tanımları içindir.)
6. **Uzlaştırma yönü ve çakışma semantiği açıktır** (authentik'in 60 dakikalık sessiz yeniden uygulaması acil kapatılan bir istemciyi geri getirebilir): yönetilen alanlar konsolda salt okunurdur; bant dışı yazma reddedilir; **acil kaçış** işaretlidir ve **denetimli bir restriction Exercise'ıdır** (daraltma, CT1; SI-4); uzlaştırıcı, aktif bir restriction'ı geri almaz — kaldırma genişlemedir ve kendi requirement'ıyla ayrı Exercise'tır.
7. Uzlaştırıcının Grant'ı reserved action içermez (E11); reserved değişiklikler (CT3 adayları, TN-118) GitOps'ta yalnız **önerilir**, quorum Gate'iyle yürürlüğe girer (X20) (çıkarım).

Altyapı kodu (OpenTofu) yalnız altyapıdır (T36); realm config'in GitOps'u bu bölümün kuralındadır. Terraform sağlayıcısı/operatör olgunluğu ayrıca izlenir (tarih ayrıntıları yaklaşık).

**TN-Y3 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-122 | Uzlaştırıcı = kendi Instance'ı ve Grant'ı olan agent Party; her uygulama Exercise; reserved yok, yalnız öneri | FROZEN | BY SEMANTICS (INV-2) | Tek yazma yolu | — |
| TN-123 | Deterministik export, sır referansı, istenen/çalışma zamanı ayrımı, tam CRUD + kayma, sıra kaynağın alanı | PD | UNDER DECLARED CAPABILITY | Keycloak/Terraform dersleri | — |
| TN-124 | Uzlaştırma yönü açık: yönetilen alan salt okunur, bant dışı yazma red; acil kaçış = denetimli restriction Exercise'ı (CT1); uzlaştırıcı restriction'ı geri almaz | FROZEN | BY SEMANTICS (SI-4) | authentik 60 dk | — |

#### 12.5.4 TN-Y4 — Toplu işlem, hız sınırı, idempotency

**Toplu işlem = attributable Exercise kümesi.** Her öğe ayrı Exercise'tır; atomiklik yoktur (§9.7 batch bağımsız, E29); toplu revoke/amend attributable Exercise kümesidir (X20). İş ergonomisi:

1. Asenkron **iş API'si**: `POST` iş → `202` + iş kaynağı → yoklama; ~10 sn'den uzun her işlem LRO; ilerleme ve kısmi hatalar terminal sonuçtan ayrı. SCIM `/Bulk`'a yatırım yapılmaz (kimse uygulamıyor).
2. İş sonuçları yeterince uzun saklanır; **öğe başına yapılandırılmış hata dosyası** (her satırda Exercise referansı veya protocol rejection nedeni). Auth0'ın 2 eşzamanlı iş / 2 saat / 24 saat sınırları tekrarlanmaz.
3. Zarf hız sınırlı ama zarf boyutu sınırlı (Entra modeli: çağrı başına operasyon + günlük çağrı); **zarf 200 dönüp içi 429 olmaz** — herhangi bir öğe kısıtlandıysa zarf bunu taşır.
4. Bağımlılık varsa yığın ya tamamen sıralı ya tamamen paralel; başarısız bağımlılık `424`.
5. Commit işi sınırlıdır; toplu episode olayları O(1) işaret + deterministik tembel hesapla uygulanır:

- **TI-RT9** Bir commit'in işi sınırlıdır; toplu episode olayları O(1) işaret + deterministik tembel hesapla uygulanır; tembel since = pozisyon sırasındaki son false→true geçişi (INV-31); qualification'ı değiştirmeyen amend HoldingRef'i yeniden adlandırmaz

**Quorum.** AWS iki grup parola/MFA modeli `Joint(k)` / `count = k` ile ifade edilir; threshold imza tek katkıdır (C26). Break-glass'ta uygulaması TN-H8'dedir (TN-93).

**Idempotency.**

- **TI-8** Idempotent nonce. (domain, nonce) tekildir; retry, failover veya tekrar gönderim ikinci bir consumption üretmez; aynı nonce + farklı intent protocol hatasıdır

REST yüzeyinde `Idempotency-Key` başlığı **tüm değiştiren uç noktalarda** birinci günden desteklenir ve AIS nonce'ına eşlenir (IETF draft semantiği):

| Durum | Yanıt | Access karşılığı |
|---|---|---|
| Başlık eksik (zorunlu uç noktada) | `400` | Protocol rejection (nonce yok) |
| Aynı anahtar, farklı yük parmak izi | `422` | Aynı nonce + farklı intent = protocol hatası (TI-8) |
| Aynı anahtar, ilk istek hâlâ işleniyor | `409` | Commit beklemede; ikinci consumption yok |
| Aynı anahtar, ilk deneme başarılı | Kayıtlı yanıt (kısa devre) | Aynı Exercise kaydı döner |
| Aynı anahtar, ilk deneme doğrulamada başarısız | Yeniden çalıştırılır | Nonce tüketilmemiştir (SI-20: rejection nonce tüketmez) |

Sonuç yalnız çalıştırma başladıktan sonra kalıcılaştırılır (Stripe v2 davranışı). Saklama süresi PD (Stripe 24 saat referansı); anahtar ≤ 255 karakter. WorkOS'un sessiz yutma davranışı (aynı anahtarla farklı yükü sessizce eski yanıtla karşılama) yasaktır (çıkarım: 422 kuralının doğal sonucu).

**Hız sınırı katmanları ve gözlemlenebilirlik.** Üç bağımsız katman (Okta modeli): kova tabanlı zaman penceresi (yöntem + en uzun önek eşleşmeli uç nokta grupları), eşzamanlılık semaforu, **aktör bazlı koruma** (kullanıcı başına uç nokta başına; Microsoft 30 Eylül 2025'te sonradan eklemek zorunda kaldı). Değerler §13.7.4'tedir ve SI-20'nin "değerler POLICY DEFAULT" kuralına tabidir; aşım protocol rejection'dır. Hız sınırı gözlemlenebilirliği bir ürün özelliğidir: kova başına anlık yüzde, 24 s/1 s ortalama, en çok tüketen 10 kırılımı, ayrı olay tipleri, eşik uyarısı; **metrik etiketleri istekten türetilmez** (kardinalite patlaması). Okta/Auth0 sayısal tavanları **doğrulanmadı**.

**TN-Y4 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-125 | Toplu işlem: her öğe ayrı Exercise; asenkron iş API'si (202, LRO, öğe başı hata dosyası); zarf içi kısıtlama zarfta görünür; sıralı-ya-paralel + 424 | FROZEN (Exercise kümesi), PD (ergonomi) | BY SEMANTICS (E29, X20); UNDER DECLARED CAPABILITY | Atomiklik yok | — |
| TN-126 | `Idempotency-Key` → AIS nonce eşlemesi; 400/422/409; başarılı kısa devre, doğrulama hatası yeniden çalışır; sessiz yutma yok | FROZEN (eşleme), PD (saklama süresi) | BY SEMANTICS (TI-8) | Nonce semantiği + IETF draft | — |
| TN-127 | Üç katmanlı hız sınırı (kova, semafor, aktör bazlı); gözlemlenebilirlik panosu; istekten türetilmiş metrik etiketi yok | PD | UNDER DECLARED CAPABILITY | Okta modeli; Microsoft 2025 | §13.7.4 |

#### 12.5.5 TN-Y5 — Konsol ve yönetici oturumu

**Konsolun kimlik doğrulaması: çerez ↔ AIS (MD-14).** Suiss yönetim konsolu BFF'dir; doğrudan oturum çerezi kullanır (OAuth değil; RFC 10017) ve DBSC'ye hazırdır (TN-33). Çerez yalnız gezinmeyi ve **identity plane'in kendi, authority taşımayan ekranlarını** taşır (ör. kendi profil, kendi oturum listesi). **Authority state okuması** (Grant/Acceptance envanteri, authority grafiği, explain, search, audit, export) PI-4 gereği ADP üzerinden yapılır: actor kullanıcının cihaz-bağlı Instance'ıdır (PI-7); konsol istemcisi okuma için de AIS üretir (okuma CT0'dır, step-up istemez) ya da bu Instance'a verilmiş holder-bound, yalnız-okuma bir projection kullanır (`cnf` = tarayıcıdaki Instance anahtarı; BFF holder olamaz). Her yazma (meta-Exercise veya `idp.*` domain action) kullanıcının cihaz-bağlı Instance anahtarıyla imzalanmış bir **AIS** ister (PI-7); konsol AIS'i istemci tarafında (WebAuthn/platform anahtarı veya bağlı cihaz) üretir, BFF yalnız iletir. Böylece çalınan konsol çerezi ne yazabilir ne de authority state okuyabilir; yalnız çerezle gelen authority okuması `Anonymous`'tur ve yalnız Public'i görür. *[BY SEMANTICS]*

**Yönetici oturum politikası.** Konsol oturumu (identity plane) için Okta modeli PD'dir: **12 saat** mutlak ömür, **15 dakika** boşta, ASN bağlama, isteğe bağlı IP bağlama. Okta'nın hatası tekrarlanmaz: politika **tüm yönetim yüzeylerini** kapsar (konsol, CLI, SDK token'ları, kurumsal bağlantı portalı). Meta-Exercise'ın assurance'ı ise CT step-up tazeliğidir (§13.7.3: ≤ 15/5/5 dk) ve konsol oturum yaşından bağımsızdır.

**Yönetim token'ı.** Ayrı bir admin token sınıfı yoktur (MD-14). Otomasyon (CLI, CI) bir agent/servis Instance'ıdır; ADP çağrıları holder-bound projection ve AIS ile yapılır (PI-11). Identity plane yönetim uç noktasına erişim token'ı (yalnız okuma) kısa ömürlü (≤ 60 dk, MD-7), **holder-bound (TN-27)** ve iptal edilebilirdir; Auth0'ın 24 saatlik iptal edilemez token'ı karşı örnektir. Çalınan yönetim token'ı anahtarsız kullanılamaz; anahtarla bile yazamaz (yazma AIS ister).

**Konsol güvenliği.** Konsol **ayrı bir kökende** çalışır; kiracı kontrollü her dizgi (realm adı, client adı, markalama, organizasyon adı, davet mesajı) güvenilmezdir; CSRF belirteci oturuma bağlıdır; sıkı CSP; **Host başlığına güvenilmez** (Keycloak depolanmış XSS ve Host yansıması açıkları: düşük yetkili yönetici, yüksek yetkili yöneticinin tarayıcısında kod çalıştırır; devredilmiş yönetimde kiracı izolasyonunu tek hamlede çökertir). AIS gereksinimi XSS'in etkisini sınırlar ama kaldırmaz: XSS, kullanıcının imzaladığı intent'in gösterilen preview ile eşleşmesini bozabilir; bu yüzden imza ekranı ayrı, güvenilir bir yüzeydir (X11: "trusted surface") (çıkarım; §13'e HL adayı, 12.10).

**Kimliğe bürünme → H4.** "Impersonation token'ı `act` iddiası taşısın" modeli kullanılmaz (MD-9): bürünme yoktur, delegation vardır (TN-70).

**TN-Y5 karar tablosu**

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| TN-128 | Konsol BFF + çerez (DBSC hazır) yalnız gezinme ve identity plane'in authority taşımayan ekranları; authority state okuması AIS (CT0) veya holder-bound okuma projection'ı; her yazma istemcide üretilen AIS ile Exercise | FROZEN | BY SEMANTICS | Çalınan çerez yazamaz ve authority state okuyamaz | MD-14; PI-7 |
| TN-129 | Yönetici oturum politikası 12 s / 15 dk / ASN (+IP) PD, tüm yönetim yüzeylerinde; meta-Exercise assurance CT tazeliğinden | PD | UNDER DECLARED POLICY | Okta modeli, Okta hatası olmadan | — |
| TN-130 | Admin token sınıfı yok; otomasyon = Instance + holder-bound projection + AIS; identity plane okuma token'ı ≤ 60 dk, holder-bound (TN-27), iptal edilebilir; "bearer yönetim token'ı" yok | FROZEN | BY SEMANTICS (PI-11) | Auth0 karşı örneği | MD-14; MD-7 |
| TN-131 | Konsol ayrı köken, kiracı dizgileri güvenilmez, oturuma bağlı CSRF, CSP, Host'a güven yok; imza ekranı güvenilir yüzey | FROZEN | UNDER DECLARED CAPABILITY | Keycloak XSS/Host | X11 |

### 12.6 Destek, break-glass ve sahiplik kararlarının özeti

Destek, break-glass ve sahiplik kararları bu bölümde TN-H4 ve TN-H8'e dağılmıştır. Tek tabloda:

| Konu | Karar | Yer |
|---|---|---|
| Quorum = authority composition (AWS iki grup) | `Joint(k)` / `count = k`; threshold imza tek katkı | 12.5.4, TN-93 |
| Bürünme semantiği yok | MD-9; projection delegation biçiminde | TN-70 |
| Destek delegasyonu | FOR(P) Grant; 12 destek değişmezi PD | TN-71 |
| Org politikasıyla rıza | OrgPolicy yalnız FOR(org) | TN-72 |
| Zorunlu gerekçe | Typed PurposeRef; serbest metin WorkRef/body | TN-73 |
| Ayrıcalık kesişimi | Exercise başına tek basis (INV-4) | TN-70 |
| Özneye bildirim | SI-21 (rıza yolu); break-glass kullanımında `notify-subject` requirement'ı (UNDER DECLARED POLICY); teslim NG (N-2) | TN-71 #7 |
| `act` / `may_act` | Projection ipucu; lineage doğrular (L22) | TN-70 |
| Break-glass modeli | Reserved Grant + break-glass disiplini PD | TN-93 |
| Break-glass politika muafiyeti | Policy içinde beyanlı istisna; `policy.set` CT3; kullanıcının self-restriction'ına karşı muafiyet yalnız self-anchor rootTerms'ünde beyanlıysa, aksi hâlde self-restriction break-glass'ı da daraltır | TN-93, TN-71 #8 |
| Sahiplik devri | `anchor.transfer` + alıcı contribution + tüm root'lara bildirim | TN-91 |
| Son sahip koruması | Sahipsiz Anchor ifade edilemez + identity plane ≥ 1 sahip | TN-91 |
| DNS ile sahiplik kurtarma | Yalnız Genesis rootTerms'te beyanlı entry | TN-92 |
| Sahiplik ≠ faturalama | Root ≠ hukuki sahip; budget ≠ finansal | TN-91 |
| Kurtarma gücü (yetki tarafı) | `instance.recover` ≥ en sıkı Mandate term'i; en zayıf yol S7/S10 | TN-53 |
| Birleştirme yetkiyi birleştirmez | Party birleşmesi lineage birleştirmez | TN-67 |

### 12.7 Bu bölümde uygulanan normlar

Bu bölümde **tam metinle** uygulanan normlar ve kanonik yerleri:

| Norm | Yer | Not |
|---|---|---|
| L28 | 12.0.2 | Kanonik metin §4.2; burada yalnız plane ataması |
| T27 | 12.1.1 | Kanonik: §16.10 T27 (MD-5); burada uygulama cümlesi |
| T28 | 12.1.1 | Kanonik: §16.10 T28 |
| E19 | 12.1.1 | — |
| T20 | 12.1.2 | Kanonik: §16.10 T20 (MD-6) |
| T31 | 12.1.2 | Kanonik: §16.10 T31 (RP ID kuralı TN-17) |
| T33 | 12.1.3 | Kanonik: §16.10 T33 (MD-5) |
| PI-11, PI-7, L19, L21, C32, L17 | 12.2.1, 12.5.2 | Epoch eki (TN-37) |
| L18, INV-24 | 12.2.2 | — |
| T26 | 12.2.2 | Kanonik: §16.10 T26 |
| X29 | 12.2.3 | — |
| SI-4, SI-22, CI-2 | 12.2.4, 12.3.8 | — |
| E5, E6, E29 | 12.3, 12.3.1 | — |
| INV-13, SEC18, SI-21, X11 | 12.3.2 | — |
| §13.7.7 ilgili satırları | 12.3.2 | + operasyonel anahtar, `party.compromise` epoch |
| E18, E27 | 12.3.3 | — |
| X20, L22, INV-28 | 12.3.4 | `ConsentRecord` |
| INV-31, INV-30 | 12.3.5 | — |
| T39 | 12.3.5 | Kanonik: §16.10 T39 |
| E20 | 12.3.7 | — |
| C10, SEC27 | 12.3.8 | — |
| TI-15, SI-20, TI-9 | 12.4 | — |
| PI-4, INV-2, §9.7 "admin API" paragrafı | 12.5 | + kapsam |
| C4, TI-20, TI-RT12 | 12.5.1 | — |
| T35 | 12.5.1 | Kanonik: §16.10 T35 (MD-1) |
| C28, E14, SI-3, C16, L24, INV-10, INV-29, XI-18, X31, E11, X5, C26 | 12.5.2 | E14 iki uç / yeni incarnation ekiyle |
| TI-RT9, TI-8 | 12.5.4 | — |

Bu bölümde uygulanan ek kararlar: 28 saatlik token reddedilir (TN-36, TN-37); `ConsentRecord::OrgPolicy` yalnız FOR(org) biçimindedir (MD-9); kayıt `party.register` ile yapılır; yönetim değişiklikleri domain action'ıdır (MD-14); sahte (dummy) Argon2 yoktur (MD-18); e-posta küresel benzersiz değildir, benzersizlik kapsamlıdır (MD-5, TN-20).

### 12.8 TN indeksi

| Aralık | Alt bölüm |
|---|---|
| TN-1 … TN-9 | 12.1.1 TN-K1 Kiracılık modeli |
| TN-10 … TN-18 | 12.1.2 TN-K2 Issuer, anahtarlar, client, RP ID |
| TN-19 … TN-26 | 12.1.3 TN-K3 Veri izolasyonu, kota, denetim |
| TN-27 … TN-38 | 12.2.1 TN-O1 Oturum, sender-constraint, epoch |
| TN-39 … TN-43 | 12.2.2 TN-O2 Sinyaller |
| TN-44 … TN-45 | 12.2.3 TN-O3 Step-up |
| TN-46 … TN-48 | 12.2.4 TN-O4 Risk ve olay |
| TN-49 … TN-51 | 12.3.1 TN-H1 Hesap durumları |
| TN-52 … TN-63 | 12.3.2 TN-H2 Kurtarma |
| TN-64 … TN-69 | 12.3.3 TN-H3 Bağlama/birleştirme |
| TN-70 … TN-74, TN-137 | 12.3.4 TN-H4 Destek erişimi |
| TN-75 … TN-79 | 12.3.5 TN-H5 Silme, mezar taşı, saklama |
| TN-80 … TN-83 | 12.3.6 TN-H6 Kayıt, numaralandırma |
| TN-84 … TN-88 | 12.3.7 TN-H7 IdP göçü |
| TN-89 … TN-95, TN-134 | 12.3.8 TN-H8 B2B |
| TN-96 … TN-104, TN-133 | 12.4.1 TN-G1 Giriş akışı |
| TN-105 … TN-106, TN-132, TN-135, TN-136 | 12.4.2 TN-G2 Özelleştirme |
| TN-107 … TN-108 | 12.4.3 TN-G3 Erişilebilirlik |
| TN-109, TN-114 … TN-121 | 12.5.2 TN-Y2 Devredilmiş yönetim |
| TN-110 … TN-113 | 12.5.1 TN-Y1 API şekli |
| TN-122 … TN-124 | 12.5.3 TN-Y3 GitOps |
| TN-125 … TN-127 | 12.5.4 TN-Y4 Toplu, idempotency, hız sınırı |
| TN-128 … TN-131 | 12.5.5 TN-Y5 Konsol |

### 12.9 Invariant adayları (TNI)

Bunlar §6 invariant listesine **aday**dır; INV numarası §6'da verilir. Hiçbiri yeni authority primitive'i değildir; her biri mevcut INV/PI/SI'nin identity plane'e veya kiracılığa uygulanmasıdır.

| ID | Aday invariant | Dayanak | Garanti |
|---|---|---|---|
| TNI-1 | **Tenant is never an authority input.** → INV-37 (kanonik; EI-27 ile aynı kısıt). Bu bölümün ek kapsamı: organizasyon adı, e-posta ve e-posta alan adı da hiçbir ADP kararına girdi değildir; authority domain yalnız AIS'ten (PI-7) gelir | MD-5; TN-1, TN-3 | BY SEMANTICS |
| TNI-2 | **Key-family separation.** Realm JOSE anahtarı authority projection imzalamaz; domain operasyonel anahtarı identity plane token'ı imzalamaz; ayrı KMS anahtarları (TI-15 genişlemesi) | MD-6; TN-14 (çıkarım) | UNDER DECLARED CAPABILITY |
| TNI-3 | **Isolation by construction.** Her identity plane, derived, PII vault ve operasyon deposunda PK `tenant_id` (+ realm/domain) içerir; authority canonical log `domain_id` anahtarlıdır; FK bileşiktir, RLS FORCE + NOBYPASSRLS + `SET LOCAL`; kapsamsız sorgu tip sisteminde ifade edilemez | MD-5; TN-19, TN-22 | UNDER DECLARED CAPABILITY |
| TNI-4 | **Recovery is never weaker than what it protects.** Identity plane'de kurtarma yolu ≥ hesabın azami güvencesi (yapılandırma anında red); authority plane'de `instance.recover` requirement'ı ≥ o Instance'ın Mandate'lerindeki en sıkı term; kural yapılandırma anında ve ayrıca rebind ile CT3 Grant issue anında Party'nin en zayıf kurtarma yoluna karşı zorlanır (INV-40); kurtarma her zaman successor Instance doğurur ve authority miras bırakmaz (INV-13) | TN-53; INV-10, INV-13, INV-40 | BY SEMANTICS (authority); UNDER DECLARED CAPABILITY (identity) |
| TNI-5 | **Proof of ownership kills prior credentials.** Bir tanımlayıcının kontrolü kanıtlandığında, o kanıttan önce kurulmuş her kimlik bilgisi ve oturum geçersizdir; doğrulama öncesi hesap satırı yoktur | TN-64, TN-80 | UNDER DECLARED CAPABILITY |
| TNI-6 | **No credential write for others.** Hiçbir action (identity plane veya authority plane) başka bir Party'nin authenticator'ını seçemez veya yazamaz (`credential.set` yok); yalnız niyet belirteci; bir faktör başka sınıftan bir faktör elde ettiremez | TN-61; NIST faktör izolasyonu | BY SEMANTICS (action şemasında yok) |
| TNI-7 | **No grant above own effective set; moves cannot amplify.** Hiçbir aktör kendi etkin izin kümesinin üstünde izin veremez; kaynak taşıma iki uçta izin ister ve taşıyanın etkin iznini artıramaz (INV-35); holder/sahip alanı değişmez | TN-115, TN-116; INV-10, C16 | BY SEMANTICS |
| TNI-8 | **Lifecycle events change authority only through Claims and Exercises.** Hesap durumu, SCIM, kurtarma, bağlama ve birleştirme olayları authority state'i kendiliğinden değiştirmez; etkileri Claim + restriction'dır (`account.status` → varsayılan DENY overlay); `instance.terminate` / departure temizlik Exercise'ıdır; offline pencereler beyan edilir, "atomik iptal" iddia edilmez | E5, E29; TN-49, TN-50, TN-75 | BY SEMANTICS |
| TNI-9 | **Suspended authentication cannot raise assurance.** Askıya alınmış bir kimlik doğrulama akışı sürdürüldüğünde yalnız beyan edilmiş bekleyen adımı tamamlar; önceki adımları atlayamaz, ulaşılmış güvenceyi beyanın ötesine yükseltemez | TN-102 (birincil kaynak) | UNDER DECLARED CAPABILITY |
| TNI-10 | **Tombstones never decide; identifiers never return.** Kullanıcı kimliği koşulsuz yeniden kullanılmaz; mezar taşı hiçbir karar girdisi değildir; tekillik canlı + mezar taşı üzerinde | TN-76; E14 | UNDER DECLARED CAPABILITY |
| TNI-11 | **Merging identities never merges authority.** Party/hesap birleştirmesi lineage, Grant, Mandate veya Anchor birleştirmez | TN-67; E5 | BY SEMANTICS |
| TNI-12 | **A console session cannot write or read authority state.** Konsol/BFF çerezi, yönetim API okuma token'ı veya herhangi bir bearer kimlik authority state'ini ya da realm config'i değiştiremez ve authority state okuyamaz; her yazma ve authority okuması AIS'li Exercise (veya holder-bound okuma projection'ı) ile yapılır | MD-14; TN-110, TN-128, TN-130; PI-4, PI-7 | BY SEMANTICS |
| TNI-13 | **Support is delegation, never impersonation.** Destek erişimi yalnız öznenin FOR(P) Grant'ı veya reserved break-glass Grant'ıdır; projection'da `sub` özne, `act` operatördür; ayrı impersonation token tipi yoktur | MD-9; TN-70 | BY SEMANTICS |

### 12.10 §13'e devredilen HL/RR/guarantee satırları

Bu satırların numaraları §13'te verilir.

- §13'e aday: HL — **Realm/consumer anahtarı ile kurumsal token'ın karışması (Storm-0558 sınıfı).** Bir anahtar ailesinin başka bir ailenin token'ını imzalayabilmesi; TNI-2 ve MD-6 ayrı KMS ile kapatılır; kalan risk doğrulayıcıların `iss`/`kid` ailesi kontrolünü atlaması (CVE-2026-23552 sınıfı).
- §13'e aday: HL — **Ortak kiracı yan kanalı.** Paylaşılan PostgreSQL/önbellek üzerinde zamanlama veya istatistik yan kanalı (MD-17; 12.1.3 örtülü kanal notu); RLS bunu kapatmaz.
- §13'e aday: guarantee (NOT GUARANTEED) — **DPoP taze-token saldırısını durdurmaz.** İstemci cihazı ele geçirilmişse saldırgan geçerli DPoP kanıtları üretebilir; holder-binding çalınmış token'ın başka yerde kullanılmasını kapatır, ele geçirilmiş istemciyi değil.
- §13'e aday: RR — **RP ID değişimi passkey'leri öldürür.** Alan adı/RP ID değişimi tüm kullanıcıları aynı anda en zayıf kurtarma yoluna iter (TN-17, TN-63).
- §13'e aday: guarantee (NOT GUARANTEED) — **Sinyal teslimi.** SSF/CAEP/RISC ve SI-21 bildirimlerinin alıcıya ulaşması garanti değildir (N-2 ile aynı aile); güvenlik sinyal teslimine bağlanmaz.
- §13'e aday: HL — **Tarayıcı içinde tarayıcı (BitB) ve gerçek zamanlı kimlik avı proxy'leri.** DBSC ve phishing-resistant authenticator dışındaki login yolları için kalan risk.
- §13'e aday: HL — **Yardım masası / kanal kaybı.** Niyet belirteci yardım masası riskini kaldırır, kayıtlı adresin kaybını kaldırmaz (TN-61); Scattered Spider sınıfı.
- §13'e aday: HL — **Konsol XSS ile imza ekranı manipülasyonu.** AIS zorunluluğu çalınan çerezi etkisiz kılar, ama aynı kökende XSS kullanıcıya imzalattığı intent ile gösterilen preview'ı ayırabilir; imza yüzeyi ayrı ve güvenilir olmalıdır (TN-131).
- §13'e aday: HL — **Seçim yoluyla yükseltme.** IdP/SCIM grup yöneticisinin rule-shaped seçimle reserved kapsama kullanıcı sokması (CVE-2026-9099 sınıfı); TN-109 soğuma + bildirim ile hafifletilir.
- §13'e aday: HL — **Zehirli kiracı / SAML ele geçirme.** Ürünün kendi davet postasının kimlik avı kanalı olması (TN-89, TN-95).
- §13'e aday: guarantee (UNDER DECLARED POLICY) — **Kurtarma soğuması itiraz penceresidir**: meşru sahip bildirimi görmezse soğuma koruma sağlamaz.
- §13'e aday: CT3 listesi eklemeleri — §13.7.1 "Örnek" sütununa kalıcı silme, realm imza anahtarı rotasyonu (politika/acil) ve yönetici göç dışa aktarımı eklenir (reserved ilanı ile; TN-86, TN-118); IdP bağlantı ayarı, SCIM `subject-selection` Acceptance (TN-95), break-glass muafiyetini beyan eden `policy.set` (TN-93), SEC18 gevşetmesi (SI-18) ve soğuma tablosunun ileriye dönük gevşetilmesi (TN-55) zaten §13.7.1 tanımındadır.
- §13'e aday: HL — **Yeni tenant/Genesis SEC18'e tabi olmadan CT2+ yapılandırma yapabilir.** Zehirli kiracı açmanın maliyeti kiracı oluşturma hız sınırı ve itibar kontrolüyle sınırlanır (TN-89, TN-111).
- §13'e aday: RR — **Ana akım MCP istemcileri yalnız Public kapsam alır.** Sender-constraint/AIS desteği gelene kadar Access-korumalı MCP sunucuları bugünkü bearer MCP istemcilerine yalnız Public kapsam sunar (benimseme riski; PI-11 bilinçli korunur; §11.8.3).
- §13'e aday: PD — **Hesap durumu overlay'i.** Her domain'in varsayılan güvenlik politikası (Genesis şablonu) realm issuer'ının `account.status ∈ {suspended, deactivated, tombstone}` Claim'ini DENY overlay'i olarak uygular (TN-49, TN-50).

### 12.11 Doğrulanmayan iddialar (bu bölümde kullanılan)

1. SSF/CAEP/RISC'in son yayın tarihleri ve SCIM olay RFC numarası (RFC 9967 atfı) — MD-18 gereği "doğrulanmadı" (12.2.2).
2. AI Act yasak/uygulama tarihleri (davranışsal biyometri/duygu çıkarımı) — 12.2.4.
3. MGM 2023 ayrıntısı ve 2026'da dolaşan kayıp rakamları.
4. Hesap ele geçirmelerin ne kadarının kurtarma akışından geçtiği — yayımlanmış veri yok.
5. "`sub` girişlerin ~‰4'ünde değişir" (Truffle aktarımı).
6. Keycloak son credential davranışı ayrıntısı.
7. OneLogin sağlama kaldırma davranışı.
8. Hareket kaynaklı birikme ve yetim hesap yüzdeleri (Orchid/Varonis/Trustle) — kullanılmadı.
9. KVKK silme talebi için "üç ay" — yalnız 30 gün doğrulanmış.
10. MojoAuth göç rakamları (satıcı iddiası).
11. Doğrulanmış bir otomatik katılım suistimal olayı ve break-glass kimlik bilgisi suistimal olayı yoktur; kilitlenme hikâyeleri teyitsiz.
12. FIDO/Corbado/Google/Microsoft passkey benimseme ve başarı oranlarının metodolojisi (anket, seçim yanlılığı).
13. Microsoft MFA hatırlama 90 gün önerisi; sayı eşleştirmenin yorgunluğu ortadan kaldırdığına dair sayısal birincil kaynak.
14. EAA uygulama tarihi (28 Haziran 2025), kapsamı ve mikro işletme muafiyeti.
15. PingFederate/AD FS tipli değer hattı ayrıntıları.
16. Okta/Auth0 yönetim API hız tavanları; üç Keycloak 2026 CVE'sinin puan ve yolu; Terraform/operatör sürüm tarihleri.
17. Giriş/parola akışı terk verileri (satıcı içeriği).

### 12.12 Notlar ve devredilen sorular

1. **TN-86 CT3 sınıfı (göç dışa aktarımı).** TN-86 reserved ilan edildiği için CT3, §13.7.1 tanımından türer.
2. **Askıya alınabilir kimlik doğrulamanın dört kuralı (TN-102).** TN-102 ve 12.4.1 dört kuralı birincil kaynağa dayanarak yazar.
3. **Identity plane okuma token'ı ≤ 60 dk (TN-130) ile Okta 12 saatlik konsol oturumu (TN-129).** Çelişki yok: biri token, biri çerez oturumu. Yazma her durumda AIS ister.
4. **Break-glass muafiyeti ile deny-overrides.** Muafiyet policy içinde beyan edilir (TN-93). Offline PAP ile break-glass'ın kesişimi → §16.
5. **E14 eki (TN-115).** E14'ün FROZEN metni "iki uç / yeni incarnation" ekini taşır; E14'ün §7'deki metni için de aynı ek geçerlidir.
6. **Genesis UX (TN-111).** §5 "önyükleme yolu yoktur" metniyle hizalıdır: yetki Genesis kurucu/bootstrap Grant'ından veya root Exercise'ından, hesap ↔ Party bağı IdentityBinding Claim'i.
7. **Oturum ↔ N:M Instance tüketimi.** Oturum cihaz ve kullanıldığı domain başına en çok bir Instance'a bağlanır; sign-out o oturumun bütün Instance'larını sonlandırır.
