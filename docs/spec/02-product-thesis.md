## 2. Product Thesis / IS / IS NOT

### 2.1 Tez

Access ürün olarak tam bir IdP'dir (identity plane) ve onun üstünde authority plane'i taşır. Access'in tezi authority-merkezlidir ve sınırı **exercise**'dadır: Access authority'nin kaynağını, delegation'ını, Mandate'ini ve exact intent için kullanılabilirliğini sahiplenir; effect'i, domain gerçekliğini ve koordinasyonu sahiplenmez. Identity plane bu tezin ön koşulunu ürün düzeyinde eksiksiz karşılar, ama authority üretmez. Agent'lar ayrı bir güvenlik evreni değildir; insan, service, workload ve agent aynı authority semantiğini kullanır. Agent'lar delegation, Mandate, provenance, long-running exercise ve controller ≠ authority açısından daha güçlü gereksinim taşır; bu Access'in hedeflenen farklılaştırıcısıdır (semantik kısım FROZEN; pazar farklılaştırıcısı olması CURRENT STRATEGIC HYPOTHESIS, H1).

MD-13'ün ticari cümlesi "Access tam bir IdP'dir ve onun üstünde authority plane'i olan tek üründür" §18.2'de kullanılır. Cümlenin "tek ürün" kısmı bir pazar iddiasıdır. Bu nedenle CURRENT STRATEGIC HYPOTHESIS'tir (reviewed landscape; "örnek bulunamadı ≠ ilk biz", §3.4). Semantik tez bu iddiaya dayanmaz.

### 2.2 Identity ve Authority: aynı ürün, ayrı iki plane

**FROZEN PRODUCT DECISION (semantik zorunluluk değil).** Access first-party Identity/Authentication plane'ini **tam bir identity provider olarak** ve Authority plane'i birlikte sunar. Gerekçe: security coupling, assurance, instance binding, recovery, revocation response, delegation UX ve administrative coherence. Ayrıca hazır IdP'lerin veri modeli Identity ≠ Authority ayrımını ve tek yazma yolunu sağlamaz (§4.9).

```text
Access product
→ bundles first-party Identity plane (complete IdP:
     authentication, accounts, credentials, sessions,
     OIDC/OAuth AS, SAML, SCIM, LDAP, Kerberos, RADIUS, WS-Fed,
     OpenID Federation, MCP/agent identity, admin API)
+ Authority plane

BUT

Authority semantics
→ does not require identity to originate from Access.
External Identity Provider → allowed
External Workload Identity → allowed
Identity plane → gives the Authority plane only Claims
```

İlgili canonical invariant yalnız **Identity ≠ Authority**'dir: Identity plane hiçbir zaman positive authority üretmez ve Authority plane'e yalnız Claim verir (INV-12, E3). Access *bir* identity binding issuer'ıdır; tek identity kaynağı değildir. Party kimliği product-neutral Party Identity Regime'dedir (E4); Access Identity plane bu regime'de bir controller-custodian ve issuer implementasyonudur (custody ≠ controller ≠ root). Identity plane bundle'ı ticari olarak opsiyoneldir (B7).

#### 2.2.1 Identity plane kapsamı

Aşağıdaki tablo identity plane kapsamını ve her alanın bu spec'teki normatif yerini gösterir. Normatif metin ilgili bölümdedir. Faz sırası bir yol haritası önerisidir (§18.13), kapsam sınırı değildir.

| Alan | İçerik | Normatif yer |
|---|---|---|
| Kimlik doğrulama yöntemleri | Parola (Argon2id), passkey/WebAuthn, OTP, magic link, push, sosyal login, kurumsal SSO, sertifika ve donanım tabanlı yöntemler, PQ hazırlığı | §10 |
| OAuth 2.1 AS / OIDC OP | OIDC Core, Discovery, JWKS, RFC 8414, RFC 9728 PRM, RFC 8707 `resource`, RFC 9207 `iss`, DPoP, mTLS-bound token, CIMD, RFC 8693 token exchange (`act`, `may_act`), ID-JAG üretimi ve tüketimi, PAR/RAR/JAR/JARM, FAPI 2, CIBA | §10, protokol eşlemesi §9 |
| Kurumsal protokoller | SCIM 2.0 sunucu, SAML 2.0 IdP, LDAP sunucu, OpenID Federation, Kerberos/SPNEGO, RADIUS, WS-Fed. Kenar gateway'ler ayrı süreçtir (MD-1) | §10 |
| MCP ve ajan kimliği | MCP authorization profili; ajan kimliği; Faz 3 kalemleri: imzalı hop başına `delegation_chain` (projection), `sub_profile`, `agent_instance_id`, attestation tabanlı client auth, transaction token, SCIM `/Agents`, A2A Agent Card imzalama servisi, ajan credential broker / token vault | §11 |
| Oturum | Sunucu tarafı oturum, BFF, DBSC'ye hazır arayüz, logout, SSF/CAEP vericisi ve alıcısı | §12 |
| Hesap yaşam döngüsü | Kayıt, doğrulama, kurtarma (kurtarma güvencesi ≥ korunan şey), hesap bağlama, silme, göç (pre-hash import), B2B organizasyonlar | §12 |
| Giriş UX ve markalama | Identifier-first, passkey UX, MFA kaydı, script çalıştırmayan şablon kabuğu, tema kaydı | §12 |
| Yönetim API'si | Platform-admin ve realm-admin yüzeyleri, delege yönetim, `Idempotency-Key`, veri katmanında yetki filtresi | §12 (yetkisi MD-14) |
| Gözlemlenebilirlik, denetim, dağıtım, operasyon | OCSF, tamper-evident audit (Merkle checkpoint, dış tanık), tek binary/tek komut, şema göçü ayrı job, yedekleme | §17 |
| Güvence | Tehdit modeli, açık yönetimi, sertleştirme, tedarik zinciri, test stratejisi, CRA | §14 |
| Kripto ve anahtarlar | aws-lc-rs, algoritmalar (MD-3), realm anahtar setleri (MD-6), yan kanal, PQC | §15 |

#### 2.2.2 Plane'ler arası kurallar

1. **Identity plane yetkilendirme kararı vermez.** Cedar ve ReBAC graf katmanı identity plane'de değil, authority plane'dedir. Pozitif yetki yalnız Grant lineage'ından gelir. Restriction dili Cedar'ın forbid-only alt kümesidir. Zanzibar/ReBAC motoru türetilmiş graf indeksi (CMP-9) ve sorgu motoru (CMP-11) olur ve hiçbir zaman commit-mode ALLOW üretmez (MD-4, TI-5). Identity plane token'ları yalnız iki tür içerik taşır: (a) identity Claim'leri, (b) authority plane'in onayladığı projection içeriği. Token'daki grup/org **üyeliği** (a) sınıfındadır: identity Claim'idir, authority taşımaz ve RP'ye authority kanıtı olarak sunulmaz; seçim etkisi yalnız authority plane'de, Acceptance'lı rule-shaped Grant üzerinden olur (INV-16). Yalnız rol claim'i (named AuthoritySet ataması) bir Grant'ın projection'ıdır: ⊆ (AuthoritySet ∩ Mandate), `projection.issue` (§5.4, §5.17). Gerekçe: INV-12 canonical invariant'tır. İzin değişiminde cache tazeliği için ayrı epoch gerekmesi sorunu TI-5 ile yapısal olarak kapanır, çünkü commit-mode ALLOW cache'ten çıkmaz. `authz_epoch` karar cache'i yalnız advisory kullanımda geçerlidir (MD-4, MD-7).
2. **İki tür scope.** Protokol scope'ları (`openid`, `profile`, `email`, `offline_access` gibi) identity plane semantiğidir. Kaynak erişimi ifade eden her scope veya `authorization_details` ancak bir `grant.issue` + `projection.issue` sonucudur (S-1, S-2; §9). Üçüncü taraf RP'nin consent ekranı bir Grant Exercise'ına derlenir. Böylece genel AS kapsamı sağlanır ve "OAuth scope ≠ Access authority" (L24) ezilmez.
3. **Yönetim yüzeyleri ayrı, yazma yolu tek (MD-14).** Platform-admin API'si ile realm-admin API'si ayrı yüzeylerdir: ayrı audience, ayrı scope namespace'i, ayrı rate bütçesi. Ayrılık yalnız transport ve kota düzeyindedir. Authority state'ini değiştiren her yönetim çağrısı (grant, Acceptance, policy, `claim.issue`), hangi yüzeyden gelirse gelsin, ADP meta-Exercise'ına derlenir; Access hem decider hem PEP'tir (L11, INV-2). Identity plane yapılandırması (client, redirect URI, upstream IdP bağlantısı, şablon, protocol mapper, realm config) authority state değildir: realm'in yönetişim domain'inde (`realms.governing_domain_id`) bir `idp.*` domain action Exercise'ıdır. Access karar verir; identity plane PEP olarak bunu ADP `commit` ile yetkilendirir ve kendi kaydını kendisi yazar (MD-14, E34). SCIM ve upstream kaynaklı üyelik dış Claim ingest'idir, authority mutation değildir. İki sınıf da aynı ADP Exercise sözleşmesinden geçer ve CT tazeliğinde AIS ister; ayrı authorization universe yoktur (L11). Konsol çerezi (BFF, DBSC'ye hazır) yalnız gezinmeyi ve identity plane'in authority taşımayan kendi ekranlarının okunmasını taşır (ör. kendi profil, kendi oturum listesi). Authority grafiği ve audit okuması (Grant/Acceptance envanteri, explain, search, audit, export) PI-4 gereği ADP üzerinden yapılır: actor kullanıcının cihaz-bağlı Instance'ıdır (PI-7) ve istek AIS (CT0, step-up yok) ya da bu Instance'a verilmiş holder-bound, yalnız-okuma bir projection taşır; BFF holder olamaz. Çerez tek başına hiçbir authority değişikliğini yetkilendiremez ve authority state okuyamaz. Ayrı bir "admin token" sınıfı yoktur (MD-14).
4. **Kimliğe bürünme yoktur (MD-9).** Destek erişimi kullanıcının kendi iptal edilebilir ve kaskad eden Grant Exercise'ı veya reserved break-glass Grant'tır. 12 destek-erişimi değişmezi POLICY DEFAULT'tur (§12).
5. **Linkability (MD-10).** Identity plane OIDC/SAML'de varsayılan pairwise `sub` kullanır (NIST 800-63C PPII). Public `sub` client başına opt-in'dir. Authority plane'de domain dışına çıkan projection ve PAP'larda PartyRef domain-pairwise türetilmiş takma addır.
6. **Kiracılık eksenleri (MD-5).** Tenant (ticari hesap) ≠ AuthorityDomain (authority semantiğinin birimi) ≠ Identity Realm (issuer, anahtarlar, RP ID, login ad alanı, kullanıcı, client) ≠ Cell (fiziksel yerleşim). `tenant_id` hiçbir authority kararına girdi değildir. Her Identity Realm'in tam olarak bir yönetişim domain'i vardır (`realms.governing_domain_id`; bir değerdir, primitive değildir); realm config değişiklikleri bu domain'de ADP commit'idir. Realm'in kimlik Claim'lerini tüketen domain sayısı N olabilir; her tüketen domain bunu kendi Acceptance'ıyla bildirir. "N:M realm↔domain" ifadesi "1 yönetişim domain'i + N tüketen domain" olarak okunur (MD-5a). Ayrıntı §12'dedir.
7. **Suiss'in kendi yüzeyleri.** Hosted login, admin konsolu ve S1–S10 identity plane session cookie kullanır. OAuth yalnız üçüncü taraflar içindir. Ayrıntı §12'dedir.

#### 2.2.3 Ajanın yeri

"Ajan `users` tablosunun bir varyantı mı, ayrı birinci sınıf varlık mı?" sorusu Access ontolojisiyle kapanır. Ajan actor-capable Party + Instance'tır, users varyantı değildir (C5, C6, F18; ontoloji §5). "Ajan birinci sınıf vatandaştır" ilkesi bu modelle uyumludur. Ajanın identity plane'deki kaydı (credential, client kaydı, CIMD) identity plane nesnesidir. Ajanın authority'si yalnız Grant ve Mandate'ten gelir.

### 2.3 Trust'ın tek anlamı

Access'te **trust** şu demektir ve yalnız bu demektir:

> **Explicit, scoped, prospectively revocable acceptance relationships:** hangi issuer'ın, hangi Claim/artefakt class'ı için, hangi subject class'ı hakkında, hangi assurance floor ile, hangi domain'de, hangi geçerlilikle ve hangi **use** için kabul edildiği.

Şekli: *issuer × claim class × subject class × domain × assurance × validity × use*. Tek nesnesi Acceptance'tır (C18). Kapsar: identity assurance, authentication assurance, authority issuer trust, federation trust, device posture issuer ve workload attestation issuer kabulü. Kapsamaz: operator trust (Work regime'inin accountability konusu), evidence içeriğinin doğruluğu (issuer'ın), davranışsal güven, reputation ve global trust score (yasak).

Bu tanım Access'in kendi identity plane'i için de geçerlidir. Identity plane'in ürettiği risk skoru, cihaz posture'u, grup üyeliği ve AAL değeri Claim'dir. Authority plane bunları ancak açık bir Acceptance ile ve yalnız daraltıcı ya da seçici (authority-selecting, L6) girdi olarak kullanır. Access'in kendi identity plane'i de Acceptance'tan muaf değildir (first-party ≠ semantic privilege, must-never #13).

### 2.4 Access IS

| Access IS | Plane | Seviye |
|---|---|---|
| Authority control plane (root'lar, provenance, attenuating delegation, Mandate) | Authority | **Core** |
| Authority exercise decision point: hizmet verdiği authority domain'lerinde authoritative ALLOW / DENY / REQUIRE_ACTION (first-party/reference authority provider; compatible provider'lar mümkün) | Authority | **Core** |
| Authority provenance ve exercise record sistemi ("why can X do Y", "ne kullanıldı") | Authority | **Core** |
| Cross-domain authority acceptance noktası (foreign authority artefaktı kabulü) | Authority | **Core** |
| Doğrulanabilir, attenuable authority artefaktı issuer'ı (online, offline, cross-org) | Authority | **Core** |
| Authority-related revocation ve exercisability-over-time kaynağı | Authority | **Core** |
| Actor kaydı (Instance; Party'ye PartyRef ile atıf; principal bir roldür) ve kendi identity domain'i için identity binding issuer | Identity (+ authority ontology) | **Core (identity plane)**; authority açısından gerekli capability |
| Authentication & assurance servisi (standards-based, teknoloji-agnostik semantik) | Identity | **Core (identity plane)** |
| Identity federation (foreign identity kabulü; upstream IdP, SAML/OIDC brokering, OpenID Federation identity rolü) | Identity | **Core (identity plane)** |
| OIDC OP / OAuth 2.1 AS (FAPI 2, CIBA, DPoP, mTLS, PAR/RAR/JAR/JARM, token exchange, ID-JAG, CIMD) | Identity | **Core (identity plane)** |
| SAML 2.0 IdP, WS-Fed | Identity (kenar gateway) | **Core (identity plane)** |
| SCIM 2.0 sunucu (ve kurumsal provisioning) | Identity | **Core (identity plane)** |
| LDAP sunucu, Kerberos/SPNEGO, RADIUS | Identity (kenar gateway, ayrı süreç) | **Core (identity plane)** |
| OpenID Federation: identity federation rolü ve trust bootstrap rolü (L26) | Identity + Authority | **Core** |
| Oturum yönetimi: login oturumu, sunucu tarafı oturum, BFF, DBSC, logout, CAEP vericisi ve alıcısı | Identity | **Core (identity plane)** |
| Hesap yaşam döngüsü: kayıt, doğrulama, kurtarma, bağlama, silme, göç, B2B organizasyonlar | Identity | **Core (identity plane)** |
| Risk tabanlı step-up (risk yalnız daraltır, CI-2) | Identity | Capability |
| MCP authorization server profili ve ajan kimliği; ajan credential broker / token vault (possession ≠ authority; upstream token'ın ajana verilmesinin release kararı bir Access Exercise'ıdır; upstream token Access projection'ı değildir) | Identity (+ authority kararı) | Capability, first-class |
| Giriş UX, markalama ve tema (script çalıştırmayan şablon) | Identity | **Core (identity plane)** |
| Yönetim API'si (platform-admin ve realm-admin yüzeyleri; authority state'ini değiştiren çağrı ADP meta-Exercise'ıdır, identity plane yapılandırması `idp.*` domain action Exercise'ıdır; MD-14) | Identity + Authority | **Core** |
| Gözlemlenebilirlik ve denetim: OCSF olayları, tamper-evident audit, SSF/CAEP yayını, audit export | Platform / engineering | Capability (§17) |
| Authority governance (access review, JML-driven değişiklik, SoD, time-bound delegation) | Authority | Aynı semantik üzerinde capability |
| Disclosure/release authority kararı | Authority | Capability (IFC'nin authority kısmı) |

Identity satırları ürün çekirdeğidir (identity plane). Bu seviye identity plane'e authority üretme yetkisi vermez (INV-12, must-never #1, #3).

### 2.5 Plane ataması

Her kalem bir plane'e, ayrı bir ürün katmanına veya gerçek bir dış sahibe atanır (MD-13). Gerçek dış sahipler Work, One, Pay, Money, Relay, Executor ve domain ürünleridir. "Ayrı ürün katmanı" bir kapsam dışı ilanı değildir. Anlamı şudur: o kalemin kendisi Access'in plane'lerinde yaşamaz; Access onun authority kısmına karar verir, olay ve sinyal üretir. Must-never'ler hiçbir atamayla gevşemez (§2.8).

L28'in kanonik metni §4.2'dedir. Bu tablo onun kısa plane atamasıdır; çelişkide §4.2 L28 kazanır.

| Konu | Atama | Access'in rolü |
|---|---|---|
| Work manager, Commitment sahibi, accountability sistemi | Dış sahip: **Work** | Approval authority, Gate'i geçme authority'si, Mandate (§2.7) |
| Workflow engine, plan orchestrator, approval-collection akışı | Dış sahip: **Work / Executor** | Plan/step'e bağlı authority (F10) |
| Agent orchestrator, agent runtime, agent memory/reasoning | Dış sahip: **One / Executor Runtime** | Ajanın kimliği (identity plane) ve authority'si (authority plane) |
| Execution engine, fencing sistemi, distributed transaction coordinator | Dış sahip: **Executor / domain PEP / Pay** | Envelope tanımı, consumption-bearing state'in at-most-once commit'i (F7) |
| Effect truth veya receipt author'ı | Dış sahip: **Executor / domain** | Attested outcome'un envelope'a karşı doğrulanması |
| Payment engine, settlement, financial hold | Dış sahip: **Pay (Money)** | Ödeme authority'si ve envelope'u |
| Money ledger, balance | Dış sahip: **Money** | Authority budget (F9) |
| Domain business-rule / eligibility engine | Dış sahip: **Domain ürünü (Commerce, Serve, …)** | Domain predicate'ini tüketir (Test C) |
| MDM / device compliance kaynağı | Dış sahip: **Device management** | Identity plane cihaz posture Claim'ini tüketir; cihaza bağlı oturum (DBSC) identity plane'dedir |
| Genel amaçlı secrets vault | **Ayrı ürün katmanı** | Sır serbest bırakmanın authority kısmına karar verir; olay ve sinyal üretir |
| Ajan credential broker / token vault | **Identity plane** | Upstream token'ın ajana verilmesinin release kararı bir Access Exercise'ıdır; upstream token Access projection'ı değildir ve içeriği NOT GUARANTEED'dır. CT2+ için token ajana gitmez; yalnız kayıtlı bir yürütücüye (Access Executor servisi veya müşterinin kayıtlı yürütücüsü) iş başına verilir ve çağrıyı yürütücü yapar. Access çağrıyı kendisi yapmaz (AG-40). Token ajanın koduna teslim edilirse `exp` ≤ kararın ValidityContract horizon'u. Possession ≠ authority; token passthrough yasağı korunur (L24) |
| PAM proxy, ayrıcalıklı oturum aracılığı ve kaydı | **Ayrı ürün katmanı** | JIT aktivasyon, onay eşiği, süreli authority Access'tedir; olay ve sinyal üretir |
| Login oturumu ve oturum yönetimi | **Identity plane** | — |
| SIEM | **Ayrı ürün katmanı** | Access OCSF olayları, SSF semantic event akışı ve Record Export üretir (P32, P33; §17) |
| Risk / fraud scoring motoru | **Ayrı ürün katmanı** veya dış input | Identity plane risk tabanlı step-up uygular. Risk yalnız daraltır (CI-2, must-never #3) |
| CAEP vericisi ve alıcısı | **Identity plane** | Güvenlik teslimata dayanmaz (L18) |
| DLP, data classification sistemi | **Ayrı ürün katmanı** (data governance) | Disclosure/release authority Access'tedir (F11); Access olay ve sinyal üretir |
| Notification / delivery | Dış sahip: **Relay** | Semantik ihtiyacı tanımlar (§2.7) |
| Approval UI / trusted rendering surface | Dış sahip: **Experience / Work Approval Surface** (ortak conformance profile'ı) | CT3 bağımsız render yolu gereksinimi Access'tedir |
| Instruction-provenance / prompt-injection savunması | Dış sahip: **One / Executor Runtime** | Authority kısmı Access'tedir; Grant ∩ Mandate dışına çıkılamaz (RR-12, L28) |
| Global trust / reputation sistemi | **Hiç kimse (yasak)** | — |
| Employment, legal incorporation gibi gerçek dünya kayıtlarının sistemi | Dış sahip: **HR / registry / issuer** | Identity plane SCIM/HR kaynaklı öznitelikleri Claim olarak alır |
| Zorunlu bağımlılık | **Hiç kimse** | Work ve diğerleri compatible provider kullanabilir; authority plane external IdP ile çalışır (B7) |

### 2.6 Canonical boundary rule

> **Domain products decide what is true and what domain effects are valid or eligible. Access decides whether a specific actor may exercise a specific authority, under specific provenance and constraints, to request an otherwise domain-defined effect.**
>
> **A. Domain Truth / Eligibility Test.** Kural resource, effect veya domain state hakkındaysa (order shipped, refund window expired, inventory unavailable, insufficient funds, restaurant closed, payment settled) actor'den bağımsız domain truth/eligibility'dir. Sahibi domain ürünüdür. Access bunları yalnız attributable, typed predicate/input olarak tüketir.
>
> **B. Authority Exercise Test.** Kural *who, on whose behalf, under what authority provenance, through which delegation, with which assurance, with which scope/parameter bounds, with which authority budget, with which co-authority/quorum, under which mandate* sorusunu cevaplıyorsa Access'indir. Bu kural authority root'unu da sınırlayabilir: "two-of-three authority holders required" veya "CEO dahil hiçbir executive €1M'yi ikinci bir authority holder olmadan authorize edemez" authority composition/governance'tır, domain eligibility değildir.
>
> **C. Composition Rule.** Bir karar hem domain truth hem authority içeriyorsa domain predicate'i hesaplar ve sahiplenir; Access predicate'i tüketir ve authority exercise'ı değerlendirir. Access domain predicate'ini yeniden hesaplamaz; domain ürünü authority üretmez.
>
> **Vocabulary guard.** Access constraint dili yalnız Test B'deki authority boyutlarını ifade eder. Bunların dışındaki her mantık domain'de değerlendirilir ve Access'e predicate olarak gelir. Bu, Access'in general business-rule engine'e dönüşmesini engeller.

*Root Test (yalnız heuristic, kural değil):* "Kural root'u da bağlıyorsa domain'dir, yalnız delegeleri bağlıyorsa Access'tir" çoğu durumda doğru yönü gösterir ama quorum/governance kurallarında yanılır; yalnız açıklayıcı yardımcıdır.

| Kural | Sahip | Gerekçe |
|---|---|---|
| Agent X may refund up to 500 TRY | **Access** | Test B: parameter bound |
| Order has already shipped | **Commerce** | Test A: domain truth |
| Agent X may disclose customer file to Vendor Y | **Access** | Test B: disclosure authority; dosyanın sınıfı data owner'dan input (Test C) |
| Customer account has 2,000 TRY | **Money** | Test A |
| Agent X may initiate a transfer up to 500 TRY/day | **Access** | Test B: authority budget |
| Transfer settled | **Pay** | Test A |
| This Work requires a legal approval | **Work** | Gate placement (coordination) |
| Party X is authorized to provide that approval | **Access** | Test B: approval authority |
| This browser is managed | **Device mgmt (Claim)** | Test A; Access tüketir |
| Only managed browsers may access payroll | **Access** | Test B (assurance/actor-side constraint) + Test C ("managed" MDM'den input) |
| Refund allowed only within 30 days | **Commerce** | Test A: refund window eligibility'dir |
| Support agent yalnız `order.age < 30 days` iken iade edebilir | **Commerce + Access** | Test C: Commerce predicate'i hesaplar, Access support-agent authority'sini o predicate'e bağlar |
| CEO dahil hiçbir executive €1M'yi tek başına authorize edemez | **Access** | Test B: co-authority/quorum; root'u da bağlar ama eligibility değildir |
| User X, Finance grubunun üyesidir (identity plane dizini veya SCIM) | **Identity plane (Claim)** | Test A tipi fact; authority değildir (must-never #1) |
| Finance grubu üyeleri 10.000 TRY'ye kadar ödeme onaylayabilir | **Access (authority plane)** | Test B: rule-shaped Grant (L5). Grup Claim'i authority-selecting claim class'tır, Acceptance ister (L6) |
| Kullanıcı son 5 dakikada passkey ile doğrulandı | **Identity plane (assurance Claim)** | Requirement girdisidir (Test B'nin assurance boyutu tüketir) |
| Bu RP `openid profile` scope'u alabilir | **Identity plane** | Protokol scope'u; kaynak authority'si değildir (§2.2.2) |
| Agent X kullanıcının takvimine yazabilir (upstream OAuth token ile) | **Access (Grant + release Exercise) + identity plane (credential broker)** | Test B; token'a sahip olmak authority değildir; upstream token Access projection'ı değildir (§2.5) |

Commerce'teki bir eligibility ayarını değiştirmek de ayrıca bir authority exercise'dır ve kararı Access verir; effect yine Commerce'te kalır.

Identity plane'deki kullanıcı öznitelikleri (grup, rol etiketi, departman, AAL, cihaz posture) Test A/C girdisi, yani Claim sayılır. Bunlar Access'in kendi identity plane'inden gelse de değişmez.

**Access nerede başlar:** bir actor kendi identity domain'inde bir Instance'a bağlandığında veya foreign bir identity explicit Acceptance ile kabul edildiğinde; bir resource için authority root beyan edildiğinde (resource domain'de yaşar, Access yalnız AuthorityAnchor'ını tutar); bir holder authority'sini delege ettiğinde veya bir Instance'a Mandate bağladığında. Identity plane açısından Access daha önce başlar: kayıt, kimlik doğrulama ve oturum açma anında.

**Access nerede biter:** bound intent için verilen kararda; consumption-bearing authorization state'in at-most-once commit'inde (intent nonce, single-use evidence, single-use contribution, authority budget draw, one-shot allowance, step-bound consumption); Exercise kaydında; exercisability değişikliği sinyalinde (semantic event); post-hoc conformance doğrulamasında (başkasının attest ettiği outcome'u envelope'a karşı okuma). Authority örtük olarak single-use değildir; execution idempotency Executor/domain PEP'tedir.

**Access'in kesmeyeceği çizgi:** domain eligibility'yi hesaplamak; Gate yerleştirmek; adımları sıralamak; execution'ı fence'lemek; effect'i gerçekleştirmek veya gerçekleştiğini beyan etmek; parayı tutmak/ayırmak; bildirimi teslim etmek.

### 2.7 Komşu sınırları

| Komşu | Komşunun sahipliği | Access'in sahipliği | Sınır kuralı |
|---|---|---|---|
| **Work** | Commitment, work delegation, coordination, Gate placement (neden ve nerede onay gerekir), autonomy, accountability, handoff | Approval authority (kim onaylayabilir), Gate'i geçme authority'si, authority delegation/revocation, Mandate | Mandate ≠ Autonomy: Mandate Instance'ın kullanabileceği authority'nin dış sınırıdır; autonomy Work'ün o sınır içindeki "sor/ilerle" politikasıdır. Authority delegation ≠ work delegation. Access Work state'ine bakmaz; `WorkRef/StepRef/purpose` yalnız opaque constraint olarak karşılaştırılır |
| **Executor** (Model B) | Pre-execution conformance enforcement, execution idempotency/fencing, gerçek effect, receipt/attestation, pause/cancel/takeover | Authorized effect envelope'unun tanımı ve kararı; yalnız açıkça consumption-bearing authorization state'in atomik ve at-most-once commit'i; Exercise kaydı; attested outcome'un envelope'a karşı doğrulanabilmesi | Access execution engine veya transaction coordinator değildir; ALLOW executor'ın yaptığı her şeye blanket izin değildir |
| **Relay** | Kanal, timing, retry, fallback, presence, realtime transport | Semantik ihtiyaç (step-up gerekli, approval authority sahibi gerekli, security intervention, authority revoked/narrowed): kime, neden, hangi intent'e bağlı, ne zamana kadar | Work Gate'lerinde alıcıyı Work seçer; eligible approver kümesini Access verir |
| **One** | Memory, reasoning, planning, kişisel davranış | One'ın actor olarak kimliği, user'dan gelen delegation ve Instance Mandate'i | Access kararı için One'ın private context'ine ihtiyaç duymaz; "user bana güveniyor" authority değildir |
| **Money** | Accounts, balances, funds, availability | Authority budget: bir holder'ın kullanabileceği yetki miktarı | "Max 5,000 TRY/day authorize" Access'tir; "account has 5,000 TRY" Money'dir |
| **Pay** | Payment execution, authorization hold, settlement, refund, payout; ödeme effect'inin PEP'i | Initiate/approve/authorize authority'si ve ödeme envelope'u (amount ≤, recipient =, purpose) | Financial hold ile authority budget draw iki ayrı kayıttır ve birbirinin yerine geçmez |
| **Commerce** | Catalog, order, pricing, refundability, eligibility, merchant/marketplace kuralları; kendi effect'lerinin PEP'i | Commerce actor'lerinin (merchant staff, support agent, buyer agent) Commerce action'ları üzerindeki authority'si | Sınırı Test A/B/C çizer |
| **Serve** | Restoran operasyonu, masa/sipariş/mutfak state'i, fulfillment | Staff/agent/device authority'si ("kasiyer X TRY'ye kadar void edebilir"); POS/edge'de portable authority artefaktı | Offline profile Serve'ün ihtiyaçlarından beslenir ama Access semantiğidir |
| **Harici IdP'ler** (Entra, Okta, Google, Keycloak, SPIFFE …) | Kendi kullanıcıları, kimlik doğrulaması, oturumları | Upstream federasyonu (identity plane) ve onların Claim'lerinin Acceptance'ı (authority plane) | External IdP Access'in kendi identity plane'iyle aynı Acceptance koşullarıyla girer. Authority plane'in hiçbir özelliği Access identity plane kullanımına bağlanamaz (B7) |
| **Ayrı güvenlik ürün katmanları** (PAM oturum kaydı, genel sır kasası, SIEM, DLP, fraud motoru) | Oturum custody'si ve kaydı, sır saklama, olay korelasyonu, sınıflandırma, risk skoru | Bunların authority kısmı (JIT, onay eşiği, disclosure, sır serbest bırakma kararı); olay ve sinyal üretimi | Risk ve sınıflandırma Claim'dir, yalnız daraltır. Bu ürünler authority üretmez |

### 2.8 Access must-never listesi

| # | Must-never |
|---|---|
| 1 | Access must never infer authority from identity, authentication, membership, controller relation or credential possession. |
| 2 | Restriction policy must never mint authority, silently or explicitly; any rule that grants authority is a Grant and carries provenance. |
| 3 | Access must never let risk, claims or posture create authority. |
| 4 | Access must never amplify authority through delegation, projection, federation or offline carriage. |
| 5 | Access must never own domain truth; it consumes attributed inputs. |
| 6 | Access must never become a workflow engine or hold plan/step progression state. |
| 7 | Access must never become an execution engine, fencing system or distributed transaction coordinator. |
| 8 | Access must never operate a global reputation or trust score. |
| 9 | A signature proves issuer attribution, not truth; Access must never act on a Claim outside an explicit issuer × claim-class × use acceptance. |
| 10 | Access must never promise that an effect happened, was correct, or physically stopped. |
| 11 | Access must never fail open. |
| 12 | Access must never let an ALLOW be reused beyond its bound intent envelope. |
| 13 | Access must never grant first-party products semantic privilege unavailable to compatible third parties. |
| 14 | Access must never require private context (One memory, Work content) beyond the authority-relevant facts of a decision. |
| 15 | Access must never execute tenant-, realm-administrator- or customer-supplied Turing-complete code on the server side: templates, scripts, rules, hooks and token-claim expressions alike. |
| 16 | Access must never match a `redirect_uri` other than by exact string comparison; regex and wildcard matching are not implemented even as opt-in (the only exception is the loopback port rule of RFC 8252 §7.3). |
| 17 | Access must never let an administrator set or choose a user's credential; an administrator may only issue a single-use, short-lived reset intent and the user enrolls the credential interactively. |
| 18 | Access must never let a tenant or realm define, shadow or override reserved protocol claims (`iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `nbf`, `act`, `may_act`, `cnf`, `scope`, `client_id`); token content is chosen only from a predefined claim set. |
| 19 | Access must never let an operator, administrator or support agent act as a user (impersonation); support access is the user's own revocable Grant Exercise or a reserved break-glass Grant. |

**Statü ve kural**. 15–19 FROZEN PRODUCT DECISION statüsündedir ve 1–14 ile aynı bağlayıcılığı taşır. Identity plane'in kapsamı 1–14'ten hiçbirini gevşetmez. Özellikle #1, #3 ve #9 Access'in kendi identity plane'inin Claim'lerine de uygulanır. Gerekçeler:
- #15: Kiracının sunucuda kod çalıştırması tenant-admin yetkisini RCE'ye çevirir. FreeMarker şablonları, adaptive auth betikleri, actions ve expression policy'leri bu riskin örnekleridir. Bu madde F23'ün dilidir.
- #16: Kaynak authentik CVE-2024-52289 ve RFC 9700'dür.
- #17: Kaynak Kanidm'in intent token modelidir. Servis masasının ele geçirilmesi hesabın ele geçirilmesine dönüşmez.
- #18: Claim adı çakışması protokol claim'lerini gölgeleyebilir.
- #19: Kaynak MD-9'dur.

CVE atıfları birincil kaynaktan kontrol edilmedi.

### 2.9 Frozen product decisions (F1–F23)

Statü: **FROZEN PRODUCT DECISION**; reopen koşulu §3.2.

- **F1** Thesis. Access authority-merkezli bir control plane'dir; sınırı effect'te değil exercise'dadır.
- **F2** Fundamental problem. Access'in tek fundamental problemi *legitimacy of authority exercise*'dır: kim, kimin adına, hangi kaynaktan, hangi sınırlarla, bu exact intent için şimdi.
- **F3** Identity + Authority aynı Suiss ürününde, ayrı plane'lerdir (product decision, semantik zorunluluk değil). Authority semantiği identity'nin Suiss Access'ten gelmesini gerektirmez; external IdP ve external workload identity desteklenir. İlgili canonical invariant yalnız Identity ≠ Authority'dir.
  - Identity plane tam bir IdP'dir (F21). Bu, F3'ün "product decision, semantik zorunluluk değil" niteliğini değiştirmez.
- **F4** Trust domain değildir. Trust = explicit, scoped, prospectively revocable issuer/assurance acceptance (Acceptance). Global trust veya reputation yoktur.
- **F5** Unit of value = Authority Exercise.
- **F6** Canonical boundary rule = Domain Truth/Eligibility Test (A) + Authority Exercise Test (B) + Composition Rule (C), vocabulary guard ile. Authority Exercise Test authority root'unu da sınırlayabilir (quorum, co-authority, governance). Root Test yalnız heuristic'tir.
- **F7** Access ↔ Executor = Model B. Access envelope'u tanımlar, yalnız açıkça consumption-bearing olan authorization state'i atomik ve at-most-once commit eder (authority örtük single-use değildir), kaydeder ve doğrulayabilir. Execution idempotency, enforcement, fencing, effect ve receipt Executor/domain'dedir.
- **F8** Approval dörde bölünür. *Neden/nerede gerekli*: Work (Gate) veya domain. *Kim onaylayabilir* ve *approval proof geçerli mi*: Access. *Effect'i kim yürütür*: domain/Executor. Authority composition olarak konan approval/co-authority koşulu (root'u da bağlayabilir) Access'tedir.
  - Yürütme ortasında HITL (human-in-the-loop) soyutlaması F8'e eşlenir. Onay ihtiyacı Work'ün veya domain'in, onay authority'si ve proof'u Access'indir. CIBA bir onay *kanalıdır* (identity plane, §10), onay authority'si değildir.
- **F9** Budget rule. Bir sayaç authority exercise'ın ne kadar kullanılabileceğini sınırlıyorsa (root'u da bağlasa bile) Access'in BudgetTerm'idir. Kimin kullandığından bağımsız var olan bir varlığı, miktarı veya ticari hakkı ölçüyorsa domain'in (Money/Pay dahil) fact'idir. Authority budget ≠ financial limit ≠ financial hold.
- **F10** Plan ve adım ilerlemesi Access'te değildir. Access yalnız `PlanRef/StepRef/purpose`'a bağlı authority'yi ve varsa step-bound consumption'ın at-most-once commit'ini tutar.
- **F11** IFC = Option B. Access disclosure/release ve declassification *authority*'sine sahiptir. Classification, label ve DLP dışarıdadır; label data owner'ın Claim'idir.
- **F12** Long-running exercisability Access'indir. "Delegated authority hâlâ kullanılabilir mi" sorusunun authority domain'i içindeki tek authoritative sahibi Access'tir (veya o domain'in compatible authority provider'ı); değişiklik commit anından itibaren prospectively authoritative'dir ve semantic event olarak yayınlanır. Enforcement gecikmesi verifier'ın connectivity/freshness profiliyle sınırlıdır. Durdurma Executor/Work'ündür. Mekanizma ValidityContract + continuation'dır (C31).
  - İptal ve bayatlık sözleşmesi şudur: ValidityContract semantiktir, epoch'lar mekanizmadır. `session_epoch` identity plane oturum ve token iptali, `key_epoch` anahtar penceresi olur. Authority plane'de `authz_epoch`'un yerini AuthorityStateBasis ve `applied_pos` alır. Identity plane iptal ve bayatlık tablosunun her satırı §13'te bir Δ/horizon satırıdır (→ §9.12, §13).
- **F13** Delegation core primitive'dir (Grant). Authority delegation ≠ work delegation.
  - RFC 8693 `act`/`may_act` ve imzalı `delegation_chain` projection'dır. Lineage Access kayıtlarındadır (L22). Delegasyon zinciri değişmezleri için Kani hedefi, algebra'nın implementasyon güvencesi olarak Kernel'de karşılanır (MD-1, MD-15; → §15, §16).
- **F14** Mandate problemi gerçektir ve Access'indir; Mandate ayrı bir primitive'dir (C14). Mandate ≠ Autonomy.
- **F15** Agent ayrı bir security universe değildir. İnsan, service, workload ve agent aynı authority semantiğini kullanır. Agent'lar delegation, Mandate, provenance, long-running exercise ve controller ≠ authority açısından daha güçlü gereksinim taşır (semantik kısım FROZEN; farklılaştırıcı olması CURRENT STRATEGIC HYPOTHESIS).
  - Ajan users varyantı değildir (§2.2.3).
- **F16** Federation, portability ve provider rolü. Cross-domain authority acceptance core'dur; identity federation identity plane'in çekirdeğidir (upstream IdP federasyonu, SAML/OIDC brokering, OpenID Federation identity rolü). Doğrulanabilir, attenuable authority artefaktları core'dur; offline/edge profilleri protocol/profile seviyesindedir ve revocation'ı bounded expiry/staleness semantiğiyle uygular. Her authority domain/object için tek authoritative lineage vardır; Suiss Access first-party/reference authority provider'dır, global tek provider değildir; interoperability Suiss-hosted Access gerektirmez. Identity federation hiçbir zaman authority federation değildir (L25, L26).
- **F17** Authentication tez değildir; identity plane'in çekirdeğidir. Authority semantiği WebAuthn/OIDC/SAML'a değil assurance semantiğine bağlıdır. Identity plane'in tipli kimlik doğrulama sonucu (yöntem, ulaşılan AAL, bağlanan authenticator, realm bağlamı) bu assurance semantiğini taşıyan Claim'in şeklidir (→ §9.13, §10).
- **F18** Actor modeli üç katmanlıdır: authority-bearing represented entity (Party, holder rolünde) ≠ authenticatable actor (actor-capable Party) ≠ concrete execution instance (Instance). Ayrıntı C5, C6.
  - Identity plane'in `users` ve `clients` tabloları bu üç katmana eşlenir: kullanıcı ve client identity plane kayıtlarıdır. Authority taşıyan karşılıkları Party ve Instance'tır (→ §5 IdP varlık eşlemesi).
- **F19** Exceptional authority (break-glass, legal order, constitutional) yalnız INV-28 olarak vardır: önceden explicit verilmiş, reserved, requirement'lı, zaman sınırlı Grant'lar; makinesi governance profile'ıdır. Expiry her zaman çalışan tek revocation'dır.
  - `is_breakglass` alanı identity plane'de bir hesap niteliği olarak kalır. Bu hesap birinci sınıf, izinli ve alarmlıdır. Bayrak authority üretmez. Authority ancak reserved Grant'tan gelir (→ §12).
- **F20** Freeze ve reopen kuralı §3.2'dir. Formal verification bir assurance yöntemidir (SECURITY CONTROL, NOT PRODUCT PRIMITIVE); product primitive üretmez ve reopen kapısı değildir.
  - İki katman geçerlidir. (a) Model counterexample'ı frozen semantiği yalnız §3.2 koşuluyla açar. (b) Bir semantik sürüm, vektörleri, DRT'si ve kanıtları geçmeden release edilmez (→ §15).
- **F21** **Access tam bir IdP'dir.** Identity plane'in kapsamı §2.2.1'dedir: kimlik doğrulama, hesap ve credential yaşam döngüsü, oturum, OIDC OP / OAuth 2.1 AS, SAML, SCIM, LDAP, Kerberos, RADIUS, WS-Fed, OpenID Federation, MCP ve ajan kimliği, yönetim API'si, giriş UX'i. Identity plane positive authority üretmez ve authority plane'e yalnız Claim verir (INV-12). Identity plane'in kendi yapılandırmasındaki değişiklikler realm'in yönetişim domain'indeki (`realms.governing_domain_id`) `idp.*` domain action'larıdır ve ADP ile yetkilendirilir (MD-14). Her realm'in tam olarak bir yönetişim domain'i vardır; realm'in kimlik Claim'lerini tüketen domain sayısı N olabilir ve her tüketen domain bunu kendi Acceptance'ıyla bildirir (MD-5a). Identity plane nesneleri (realm, kullanıcı kaydı, credential, oturum, client) authority primitive'i değildir. Yeni authority primitive'i eklenmez.
- **F22** **Kapsam sorusu plane atamasıdır.** Değerli bir fikir için sorulan soru "Access'e ait mi?" değil, "Access ürününün hangi plane'ine veya katmanına aittir?" sorusudur: identity plane, authority plane, platform/engineering, ayrı ürün katmanı ya da gerçek dış sahip (§2.5). Gerçek dış sahipler (Work, One, Pay, Money, Relay, Executor, domain ürünleri) sahip olarak kalır. Wrong-layer disiplini bu anlamda uygulanır. Hiçbir atama bir must-never'ı gevşetemez.
- **F23** **Müşteri kodu yoktur.** Kiracı, realm yöneticisi veya müşteri tarafından sağlanan Turing-tam kod sunucu tarafında yürütülmez (must-never #15). Özelleştirme şu yollarla yapılır: veri (tema kaydı), önceden tanımlı claim kümesinden seçim, script çalıştırmayan şablon (fonksiyon çağrısı yok, tanımsız ada başvuru hata), statik maliyetli, forbid-only restriction dili (MD-4) ve kiracının kendi sunucusunda çalışan dış çağrı noktaları (TN-135; kod Access sürecinde çalışmaz). Bu tek ilke authority plane'deki T13 statik maliyet kuralını ve identity plane'deki şablon/betik yasağını kapsar. Kabul testi ve karşı örnek alanları §12'dedir (gün-1 kararı #28, §3.1b).

F21–F23 statüsü: FROZEN PRODUCT DECISION (MD-13). Reopen koşulu §3.2'dir.
