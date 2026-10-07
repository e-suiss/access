## 10. Identity Plane — kimlik doğrulama, federasyon ve protokol yüzeyi

> **Bağlayıcı merkezi kararlar:** MD-1, MD-3, MD-5, MD-6, MD-7, MD-10, MD-11, MD-14, MD-18 (ayrıca MD-8 fail-closed, MD-9, MD-13).
>
> **Yönlendirme:** Garanti matrisi ve HL/RR → **§13**. Tehdit modeli ve conformance testleri → **§14**. Kripto, anahtar ve PQC ayrıntısı → **§15**.
> **Numara aileleri:** kararlar **IDP-n**, invariant adayları **IDI-n**. HL/RR/guarantee satırları burada numaralanmaz; "§13'e aday" diye önerilir (bkz. §10.12).
>
> **Komşu bölümler:** Claim Ingest taşıyıcı alanları, issuer tanımlama, regime ↔ Claim, ingest kuralları 1–7, Acceptance wire karşılığı, SPP/katalog pin → **§9.13**. `projection.issue`, `cnf`, tek `aud`/RFC 8707, RAR, refresh = yeni karar, reuse detection/single-flight → **§9.9** (§9.9.3). REQUIRE_ACTION eşlemesi → **§9.9.5**. SSF/CAEP → **§9.16.2**; AuthZEN/ADP → **§9.5**. MCP/CIMD-MCP profili, ID-JAG/EMA, ajan modeli, Txn Tokens/SPIFFE/WIMSE → **§11**. Oturum, kurtarma, risk, rate limit, yönetim yüzeyi → **§12**.
>

Bu bölüm identity plane'i tanımlar ve **Access'in tam bir IdP olduğu** kararını (MD-13) normatif hale getirir.

### 10.0 İlkeler

| # | İlke | Garanti | Kaynak |
|---|---|---|---|
| P-ID-1 | **Identity ≠ Authority.** Identity plane hiçbir zaman authority yaratmaz. Authority plane'e yalnız Claim verir. Claim de karara yalnız açıkça kaydedilmiş bir Acceptance'ın izin verdiği kadar girer. | BY SEMANTICS | INV-12, TI-15, E3, §5.12 |
| P-ID-2 | **Access tam bir IdP'dir.** Access, OAuth AS, OIDC OP, SAML IdP, SCIM server, LDAP yüzeyi ve SPNEGO acceptor olarak çalışır. Authority plane'i olan tek üründür. Identity bundle müşteri açısından opsiyonel kalır. External IdP aynı Acceptance koşullarıyla girer (B7). Enterprise'da varsayılan external IdP'dir (H13). | UNDER DECLARED POLICY | MD-13, L28; F3, B7, H13 |
| P-ID-3 | **Protokol icadı yok.** Yeni bir identity protokolü tasarlanmaz. Standartlar ADOPT/PROFILE/EXTEND/REJECT olarak sınıflanır (§9.4). Taslak standartlar WATCH ya da PROFILE (varsayılan kapalı) etiketiyle girer. | BY SEMANTICS (süreç kuralı) | L20 |
| P-ID-4 | **Kenar protokoller kapsamdadır.** SAML, LDAP, Kerberos/SPNEGO, RADIUS ve WS-Fed kapsamdadır. Aşamalandırılır, ama atılmaz. | UNDER DECLARED POLICY | MD-18, MD-1 |
| P-ID-5 | **Süreç hibriti, dil hibriti değil.** Çekirdek Rust/aws-lc-rs ile yazılır. SAML, LDAP, Kerberos/SPNEGO, RADIUS ve WS-Fed kenar gateway'leri **ayrı süreçlerdir**. Kerberos C FFI (libgssapi) yalnız izole süreçte ve ayrı imaj varyantında yüklenir. Kenar süreçleri authority plane'e doğrudan erişmez; Claim Ingest API'yi kullanır. | UNDER DECLARED CAPABILITY | MD-1, T35 |
| P-ID-6 | **Phishing-resistant varsayılandır.** Passkey/WebAuthn birincil yöntemdir. Parola, OTP ve push fallback'tir ve assurance'ı sınırlanır. **Her CT (CT0 dahil, §13.7.3)** yalnız phishing-resistant authenticator ile karşılanır. | UNDER DECLARED POLICY | §13.7.3 |
| P-ID-7 | **Sinyal kapı değildir.** Attestation, AAGUID, cihaz bütünlüğü (App Attest/Play Integrity), RASP ve risk skoru Claim girdisidir. Tek başına hiçbir şeyi açmaz. | BY SEMANTICS (girdi sınıfı) / NOT GUARANTEED (sinyalin doğruluğu) | — |
| P-ID-8 | **Fail-closed.** Tazelik, imza zinciri, metadata ya da trust chain doğrulanamıyorsa sonuç reddettir. Introspection'da `active=false` döner, RS 5xx'i DENY sayar. Primary'ye ya da tazelik kaynağına ulaşılamıyorsa **her token için, cache-hit dahil** `active=false` döner; introspection 503 dönmez. Fail-open penceresi (ör. 60–300 sn) yoktur. | BY SEMANTICS | MD-8, MD-7 |
| P-ID-9 | **E-posta asla anahtar değildir.** Kullanıcı kaydı opak ID ile tutulur. Dış kimlik `(provider, provider_subject_id)` ile bağlanır. Realm'ler arası bağ yalnız açık IdentityBinding ile kurulur. | BY SEMANTICS | MD-5 |
| P-ID-10 | **Pairwise varsayılandır.** OIDC `sub` ve SAML persistent NameID RP/SP başına pairwise üretilir. Public `sub` client başına opt-in'dir. | UNDER DECLARED POLICY | MD-10; NIST 800-63C PPII |

### 10.1 Düzlem sınırı ve kimlik nesneleri

#### 10.1.1 Düzlem sınırı

**Plane kuralı (§2.2):** Identity ve Authority aynı üründe, ayrı plane'ler olarak bulunur. Bu bir FROZEN PRODUCT DECISION'dır (bundling). External IdP ve external workload identity'ye izin verilir (F3).

**Seam kuralları (§5.12):**
- Identity → Authority: tek kanal Claim'dir (Claim Ingest API). Karara yalnız Acceptance kadar girer (E3, TI-15).
- Authority → Identity: yok; **identity kaydı yazılmaz.** Authority plane identity plane'e yalnız (i) derived semantic event'ler (`instance-terminated`, `projection-invalidated` …, §9.16) ve InstanceID referansı, (ii) identity plane PEP'inin ADP çağrılarına verdiği Decision Response'lar (public PEP sözleşmesi, TI-15; MD-14) ulaştırır. Identity plane kendi kaydını kendisi yazar; Authority plane authenticator bağlayamaz, PartyID değiştiremez (§7 seam satırı; §7.9.1.2).
- Ortak tablo, ortak DB rolü, ortak KMS anahtarı ya da ortak operatör rolü yoktur (TI-15, T31).
- Identity plane custody anahtarları provider rolünde kullanılmaz (SEC19).

**Seam satırları (§7.3):**

| Seam | Access sahiplenir | Karşı taraf sahiplenir | Yasak bağlar |
|---|---|---|---|
| Access ↔ Identity regime | Domain admission (`party.register`, self-anchor), Instance, identity issuer'larının Acceptance'ı, departure disposition | PartyID, key-event history, controller, Party recovery, termination | Global Party registry; regime olayının authority state'i otomatik değiştirmesi; Party recovery'nin Instance'ları sessizce taşıması |
| Access ↔ external IdP | Acceptance (use-typed), Instance, actor-binding sonucu | AuthN, dizin, attribute'lar, kendi oturumları | IdP'nin authority issuer olması; grup claim'inin Acceptance'sız selection'a girmesi |
| Access ↔ IGA | — | Erişim kampanyaları ve kararları | IGA kararları yalnız Exercise talebi olarak gelir |
| Access ↔ PAM/vault | — | Secret'lar | Access secret tutmaz |
| Access ↔ MDM | — | Posture ve risk | Posture ve risk Claim'dir |

**Realm ekseni (MD-5, bağlayıcı).** Identity plane'in kiracılık birimi **Identity Realm**'dir. Realm şunları taşır: issuer URL, JOSE anahtar seti, WebAuthn RP ID, login ad alanı, kullanıcı/credential kayıtları, client'lar, marka ve giriş politikası. Her realm'in **tam olarak bir yönetişim domain'i** vardır (`realms.governing_domain_id`; bu bir değerdir, primitive değildir). Realm config değişiklikleri (MD-14) bu domain'de ADP commit'tir. Realm'in kimlik Claim'lerini **N domain tüketebilir**; her tüketen domain bunu kendi Acceptance'ıyla bildirir. Realm↔domain ilişkisi "1 yönetişim domain'i + N tüketen domain"dir; yönetişim bir değerdir, tüketim Acceptance'tır. Varsayılan: yönetişim domain'i aynı zamanda tek tüketen domain'dir. Credential ve login tanımlayıcısı realm'e yereldir (`UNIQUE(tenant_id, realm_id, …)`). İki realm'deki aynı e-posta iki ayrı kullanıcıdır. Bağ yalnız açık `identity-binding` Claim'iyle kurulur. Veritabanında RLS FORCE, bileşik FK ve PK'de `tenant_id` zorunludur. **BY SEMANTICS** (şema kısıtı). Realm'in operasyonel ayrıntısı (cell yerleşimi, kiracı silme) → §12/§5.

Realm, user record, credential, session ve client **identity plane nesneleridir**. Authority primitive'i değildir ve ontology'ye yeni primitive eklemez.

#### 10.1.2 Claim Ingest — protokol başına taşıyıcı ayrıntısı

Taşıyıcı alan tablosu, issuer identification tablosu, regime ↔ Claim sınıfları, ingest kuralları 1–7, Acceptance wire karşılığı ve SPP/katalog pin **→ §9.13**. Burada tekrarlanmaz.

Bu alt bölüm yalnız identity plane'in **kendi ürettiği** Claim'lerin protokol kaynağına göre hangi alanlardan türetildiğini tanımlar. Bu bölüm normatiftir. Eşleme dışında kalan alan Claim'e girmez.

| Kaynak protokol | Claim sınıfı | Subject kaynağı | Issuer kaynağı | Zorunlu alanlar (türetme) |
|---|---|---|---|---|
| WebAuthn (yerel RP) | `authentication` | credential → `IdentitySubject` → Instance | Realm'in identity issuer'ı | method class=`webauthn`, UV, UP, BE/BS bayrakları, AAGUID (ipucu), sign count, `auth_time`, assurance, statement digest |
| WebAuthn kayıt | `authenticator-binding` | `IdentitySubject` | Realm issuer | credential ID özeti, alg, attestation formatı ve sonucu (sinyal), BE, transports; **asla secret** |
| OIDC (upstream IdP) | `authentication` + `identity-binding.person` | `(iss, sub)` çifti, e-posta değil | Upstream IdP'nin `iss` değeri, Acceptance ile | `acr`, `amr`, `auth_time`, `iss` (RFC 9207 ile doğrulanmış), ID token `jti`/digest |
| SAML (upstream IdP) | `authentication` + `identity-binding.person` | NameID (persistent) + IdP EntityID | IdP EntityID, Acceptance ile | `AuthnContextClassRef`, `AuthnInstant`, `SessionIndex`, assertion ID, digest |
| SCIM (gelen provisioning) | `identity-binding.*`, membership | `externalId` + SCIM client kimliği | SCIM client'ın kayıtlı issuer'ı | resource type, `meta.version`, işlem |
| SCIM SET (RFC 9967) | Olay Claim'i (prov/sig) | `sub_id` (format `scim`) | SET `iss` | `txn`, `version`, olay URI'si |
| LDAP bind (kenar) | `authentication` | DN → `IdentitySubject` | Realm issuer (LDAP gateway süreci üzerinden) | method class=`ldap-bind`, credential sınıfı (ayrı LDAP credential) |
| SPNEGO/Kerberos (kenar) | `authentication` | Kerberos principal → `IdentitySubject` | Realm issuer, Kerberos realm'i Acceptance ile | method class=`kerberos`, ticket zamanı |
| mTLS / PIV | `authentication` | Sertifika subject + issuer DN → binding | Realm issuer, CA güveni Acceptance ile | method class=`x509`, sertifika parmak izi, EKU |
| Cihaz attestation | `runtime-attestation` / `device-posture` | Instance / cihaz anahtarı | Platform kökü (Apple/Google), Acceptance ile | verdict, zaman, nonce bağı |

Kurallar:
1. Upstream IdP Claim'i ham assertion digest'ini taşır. Ham assertion PII vault'ta saklanır, Claim'e girmez. **UNDER DECLARED POLICY.**
2. `amr`/`acr`/`AuthnContextClassRef` değerleri upstream IdP'nin beyanıdır. Assurance'a etkisi Acceptance'taki eşleme tablosuyla sınırlıdır. Eşleme yoksa assurance en düşük sınıfa iner. **BY SEMANTICS** (eşleme kuralı) / **NOT GUARANTEED** (upstream'in doğruluğu).
3. Kenar gateway süreçleri (LDAP, SPNEGO, SAML, RADIUS) kendi başlarına issuer değildir. Realm issuer'ı adına, iç kanaldan Claim ürettirirler. Bu kanal mTLS ile kimliklendirilir ve gateway başına ayrı iç kimlik kullanır (MD-1 süreç izolasyonu). **UNDER DECLARED CAPABILITY.**

**İstemci kimliği çözümleme sırası (istemci çözümleme katmanı).** Bir `client_id` için üç kaynak vardır: yerel kayıt/DCR, CIMD (Client ID Metadata Document) ve OIDF entity. Bunlar **tek bir resolver**dan geçer:
1. `client_id` bir HTTPS URL ise önce OIDF entity configuration denenir (well-known'da `openid-federation`). Zincir çözülürse OIDF yolu kullanılır. Çözülmezse CIMD belgesi denenir.
2. `client_id` URL değilse yerel kayıt kullanılır (statik ya da DCR).
3. URL biçimindeki bir `client_id` **asla** yerel kayda düşmez. Aynı dizgi yerelde kayıtlı olsa bile düşmez (karışıklık saldırısı).
4. Çözümleme sonucu bir **güven seviyesi** alanı taşır: `local-registered` | `dcr` | `cimd` | `oidf-chain(+trust_mark)`. Bu alan politika girdisidir. **Onay atlamaz** (§10.7.1).
5. Yollar realm başına açılır ya da kapatılır. Bu bir realm config değişikliğidir, yani ADP `commit` domain action'ıdır (MD-14). Varsayılanlar: CIMD kapalı, DCR kapalı, OIDF kapalı. DCR açıksa `/register` çağrısı RFC 7591 initial access token ister. Bu token yalnız kayıt endpoint'ine erişim kapısıdır, authority değildir. Initial access token'ın verilmesi de bir domain action'dır.
6. Uzak belge getirme önbellekli ve SSRF korumalıdır.

Bu sıra **AS tarafı** `client_id` çözümleme sırasıdır ve normatiftir (IDP-1). Bir MCP istemcisinin hangi kayıt yolunu seçeceği (**istemci tarafı kayıt yolu seçimi**: ön kayıt → CIMD → DCR → kullanıcıya sor) ayrı bir perspektiftir ve §11.3.8'dedir.

CIMD -02'nin URL kuralları, doğrulama sırası, önbellek, SSRF, 5 KB sınırı, loopback eşleme ve MCP profili **→ §11.3** (tek kaynak; loopback §11.3.9). DCR'ın MCP'de terk edilmesinin gerekçesi §11.3.7'dedir.

#### 10.1.3 Actor ve identity modeli; Instance / KeyBinding / Attestation

**Actor ve identity katmanları (§5.6):**

| Katman | Ontology | Not |
|---|---|---|
| Party (holder rolünde) | PartyRef — product-neutral, Party Identity Regime'deki kimliğe atıf | Access Party yaratmaz ve ikinci bir Party registry'si tutmaz (C5, E4) |
| Actor-capable Party | Derived kapasite | Organizasyonlar ve joint gruplar Instance'a sahip olmaz; org authority'si FOR(org) capacity'siyle exercise edilir (C6) |
| Instance | Primitive | Kimliği authority-binding sürekliliğidir; key rotation aynı Instance'tır, continuity kırılması yeni Instance'tır; recovery tek successor üretir ve authority miras bırakmaz (C8, INV-13) |
| ActorContext | Value | `Authenticated(InstanceID)` veya `Anonymous(context)`; Anonymous yalnız Public Grant kullanır, hiçbir şey tutmaz, quorum'a sayılmaz (INV-11) |
| Principal | Rol | On-behalf-of rolüdür; `Exercise.capacity`'den (basis Grant AgencyTerms ile yetkilendirilmiş) türetilir, lineage'dan değil; entity değildir (C5) |

IdentityBinding, authenticator binding, authentication event, runtime attestation, device posture, membership ve controller/sponsor/operator ilişkisi **Claim sınıflarıdır** (C7). InstanceID ≠ KeyBinding ≠ Attestation (L21).

**Identity plane iç kayıtları ve Instance ilişkisi (IDP-2).** Identity plane'in kullanıcı kaydına **`IdentitySubject`** denir. Bu bir identity plane nesnesidir ve ontology'deki Party ya da Instance ile karıştırılmaz.
- Bir `IdentitySubject`, bir `identity-binding.person` Claim'i aracılığıyla bir PartyRef'e bağlanır.
- Bir ya da daha çok authenticator, `authenticator-binding` Claim'i aracılığıyla bir **Instance**'a bağlanır. Instance'ın sürekliliği authority plane'de, Acceptance ile değerlendirilir.
- Passkey ekleme ya da silme, cihaz değişimi ve parola değişimi Instance'ı değiştirmez. Bunlar yeni `authenticator-binding` Claim'idir; SEC18 cooling uygulanır. Kurtarma hariçtir; kurtarma successor Instance'tır (INV-13).
- Hesap kurtarma (→ §12.3.2) yeni authenticator bağlar. Eski geçerli KeyBinding ile authenticate edilmiş bir zincir olmadığı için bu, authority plane'de **her zaman** Instance continuity kırılmasıdır: tek successor Instance doğar, eski Instance'ın Mandate'leri miras kalmaz, yeniden bağlama INV-40 kapısından geçer (C8, INV-13, X38). **BY SEMANTICS.** Domain bunu yalnız sıkılaştırabilir: daha uzun cooling, rebind için ek requirement. Varsayılan cooling, kurtarma ile gelen authenticator'ın CT2+ requirement'larını 24 saat karşılamamasıdır (SEC18; **POLICY DEFAULT**). Kurtarma sırasında eski Instance'ın bir authenticator'ı ile authenticate edilmiş bir "cihaz ekleme" kurtarma değildir; IDP-2 kapsamındadır.

**Attestation sinyaldir (IDI-3 adayı).** Şu olgular aynı sonuca götürür:
- WebAuthn attestation, AAGUID ve MDS kaydı **anahtarın nerede üretildiği** hakkında beyandır.
- App Attest anahtarın gerçek olduğunu söyler, ortamın temiz olduğunu söylemez.
- Play Integrity istek başına verdict verir.
- Relay saldırısı OID 1.3.6.1.4.1.11129.2.1.17 ile izlenebilir.

Bu nedenle hepsi `runtime-attestation`/`device-posture` Claim'idir. Bir Acceptance ancak `predicate-input` kullanımında bunları okuyabilir. Hiçbir attestation tek başına Instance kimliği, KeyBinding ya da Grant üretmez. **BY SEMANTICS** (sınıf) / **NOT GUARANTEED** (platformun beyanının doğruluğu).

**Cihaz anahtarı kaydı.** Uygulama-bağlı cihaz anahtarları (MD-11 "uygulama-kontrollü faktör") identity plane'de şu şemayla tutulur: `device_id, identity_subject_id, public_key, key_type, algorithm, attested_at, status, created_at, last_seen`. `public_key` kaydı bir `authenticator-binding` Claim'i üretir.

#### 10.1.4 Acceptance — kullanım tipleri

**Kullanım tipleri (C18/E18):** Acceptance use ∈ {`actor-binding`, `predicate-input`, `subject-selection`, `foreign-authority`, `schema-definition`}. IdP acceptance kullanımları ayrıdır (E18). Hiçbir dış artefakt Acceptance + Grant olmadan authority değildir: scope, trust chain, trust mark, VC, ID-JAG, CIBA cevabı (PI-3).

Wire karşılığı ve ingest kuralları → §9.13.

Identity plane'e özgü normatif notlar:
1. **Grup ve rol Claim'leri.** Upstream IdP'den gelen `groups`, `roles` ya da SAML attribute'ları ancak `subject-selection` kullanımlı bir Acceptance varsa selection'a girer (§7.3 yasak bağı). Yoksa yalnız bilgi amaçlı saklanır. **BY SEMANTICS.** Her grubun **tek bir üyelik issuer'ı** vardır: domain ya da belirli bir upstream (IdP / SCIM client). Upstream grup mapping'i reserved bir requirement ile korunur.
2. **Suiss Identity'nin ayrıcalığı yoktur.** Access'in kendi identity plane'i de aynı Claim sınıflarını ve aynı Acceptance yolunu kullanır. Suiss'e özel sınıf ya da örtük Acceptance yoktur (§9.13.2, first-party neutrality). **BY SEMANTICS.**
3. **Varsayılan Acceptance şablonu.** Yeni bir AuthorityDomain, eşlenik realm'inin (yönetişim ya da tüketim) issuer'ı için yalnız `actor-binding` kullanımlı bir Acceptance şablonuyla doğar. Şablon `acceptance.establish` meta-Exercise'ı olarak Genesis paketinde commit edilir (Acceptance bir identity config değil, authority primitive'idir; §13.7.1 CT3). `predicate-input` ve `subject-selection` açıkça eklenir. **UNDER DECLARED POLICY.**

#### 10.1.5 Party Identity Regime

**Regime ayrımları (E4/E5):** Party Identity Regime custody ≠ controller ≠ root ayrımını taşır (E4). Regime olayları Claim'dir ve authority state'i kendiliğinden değiştirmez (E5).

**Regime Claim sınıfları (§9.13):**

| Claim class | Issuer | Subject | Zorunlu alanlar | Acceptance use | Etki |
|---|---|---|---|---|---|
| `party.key-state` | Regime (controller imzalı key-event) | PartyRef | key set, designated issuer kümesi, sequence | actor-binding / predicate-input | Designated issuer kümesi Acceptance ile conjunction olarak uygulanır (yalnız daraltır) |
| `party.compromise` | Regime | PartyRef | compromise zamanı, kapsam | predicate-input | Ingest-time cutoff; geriye dönük authority değiştirmez |
| `party.recovered` | Regime | PartyRef | önceki/yeni key-state | actor-binding | Successor Instance kuralı (C8); authority miras yok |
| `party.terminated` | Regime | PartyRef | zaman | predicate-input | Departure disposition (Access sahiplenir) |
| `party.identity-break` | Regime | PartyRef | neden | actor-binding | Yeni Instance zorunlu |
| `controller-of` | Regime | PartyRef ↔ controller | ilişki | predicate-input | Bilgi; authority değildir |
| `identity-binding.<kind>` (person/organization/workload/agent/legal-representative) | Identity issuer | PartyRef ↔ dış kimlik | binding tipi, kanıt digest'i | actor-binding / subject-selection | Actor-binding sonucu |
| `authenticator-binding` | Identity issuer | Instance | credential özeti, alg, sınıf; **asla secret** | actor-binding | Instance'a authenticator bağlar; SEC18 cooling |
| `authentication` | Identity issuer | Instance | method class, human presence, UV, binding (Instance/intent/statement digest), auth time, assurance, ham assertion evidence digest'i | actor-binding / predicate-input | Exercise'ın actor kanıtı |
| `operated-by` / `agent-kind` / `sponsored-by` | Identity issuer / regime | Agent Party | operatör, tür, sponsor | predicate-input | → §11 ajan modeli |

**Controller'ın issuer yetkilendirmesi (§9.13.1):**
1. Designation regime'dedir, Grant değildir.
2. `party.key-state` designated issuer kümesi conjunction olarak uygulanır: Acceptance ∧ designation. Bu kural yalnız daraltır.
3. Custody ≠ controller. Garanti **UNDER DECLARED CAPABILITY**'dir.
4. Designation iptali prospective'tir. Ingest-time cutoff uygulanır.

#### 10.1.6 Assurance değeri

**Assurance ilkesi (F15, F17):** Authentication first-class capability'dir. Authority semantiği assurance'a bağlıdır.

`authentication` Claim'i bir **assurance vektörü** taşır. Vektörün bileşenleri:
- `aal`: NIST 800-63B-4 AAL1–3.
- `loa_eidas`: low/substantial/high.
- `phishing_resistant`: bool. Channel binding ya da verifier name binding vardır.
- `hardware_bound`: bool.
- `non_custodial`: bool.
- `uv`: bool.
- `human_presence`: bool.
- `app_controlled_factor`: bool (MD-11).
- `synced`: bool. BS bayrağından gelir.
- `auth_time`.

CT tablosu (kanonik §13.7.3; identity plane eşlemesi §10.3.3) ve RequirementTerm bu vektörü okur. Tek skaler "seviye" alanı türetilmiş görünüm olabilir, ama karar vektör üzerinden verilir. **BY SEMANTICS** (alan semantiği) / **UNDER DECLARED POLICY** (eşik değerleri). Sınıfların ayrıntısı → §10.3.

#### 10.1.7 Bileşenler, custody ve PII vault

**Identity plane bileşeni (CMP-15, §16.3):** WebAuthn RP, authenticator registry, `authentication`/`authenticator-binding`/`identity-binding.*` issuance, custody signer, regime key-event store, PII vault. Kendi kayıtları CANONICAL'dır (ikinci source of truth, E3). Protokol parçası AP-7, AP-8 (issuer rolü). Authority plane'e yalnız Claim verir.

**Altyapı ayrımı (T31):** Identity plane şunlara sahiptir: ayrı cell/cluster, ayrı KMS, ayrı operatör rolleri. Tek kanal Claim Ingest API'dir. WebAuthn RP buradadır. PII crypto-shredding uygulanır.

**Güven tablosu, Identity plane satırı (§13.2):** Issuer ve custodian rolüyle şu Claim'leri yayınlamaya güvenilir: `authentication`, `authenticator-binding`, `identity-binding`. Authority yaratmaya güvenilmez. Kötüye kullanımda etkisi, actor-binding kabul edildiği subjectClass'taki Party'lerin zaten tuttuğu authority kadar impersonation'dır; custodial ise designation değişikliği de eklenir. Hafifletme: Acceptance narrowing, ingest-time cutoff, non-custodial controller (P21 conjunction).

**Custody (DL-1, SEC19):** Custodial anahtar **NOT GUARANTEED**'dir (DL-1). Custody anahtarları provider rolünde kullanılmaz (SEC19).

**Alt bileşenler:**

| Alt bileşen | Görev | Süreç | Anahtar/KMS | Kaynak |
|---|---|---|---|---|
| AS/OP çekirdeği | OAuth 2.x AS, OIDC OP, discovery, JWKS, token, introspection, revocation | Rust çekirdek süreç | Realm JOSE seti (kimlik iddiaları); domain operasyonel anahtarı, ayrı signer süreci (authority taşıyan token'lar; MD-6) | MD-1, MD-3 |
| WebAuthn RP + authenticator registry | Kayıt, doğrulama, BE/BS politikası, MDS | Rust çekirdek | — | — |
| Credential store | Parola hash, TOTP secret, recovery code, cihaz anahtarları | Rust çekirdek; şifreli sütun | Kiracı KEK (T20 hiyerarşisi) | — |
| Claim issuer | `authentication` / `*-binding` Claim'lerini imzalar ve Claim Ingest'e gönderir | Rust çekirdek | Ayrı issuer anahtarı (COSE, Ed25519, MD-3) | §16.3 |
| Custody signer | Custodial kullanıcı adına imza | Ayrı süreç, HSM | HSM; kiracı başına KEK | SEC19, DL-1 |
| Regime key-event store | `party.key-state` olayları | Rust çekirdek | — | §9.13 |
| PII vault | Ham assertion, KYC belgeleri, e-posta/telefon, adres | Ayrı depolama | Kiracı başına KEK; crypto-shredding | T31 |
| SAML gateway | IdP ve upstream SP/IdP | Ayrı süreç, izole XML parser worker | SAML imza anahtarı (HSM/KMS, MD-3 rsa-sha256 istisnası) | MD-18 |
| SCIM server | Gelen ve giden provisioning | Rust (çekirdek ya da ayrı) | — | — |
| LDAP gateway | Salt okunur dizin yüzeyi | Ayrı süreç | — | — |
| SPNEGO acceptor | Kerberos | Ayrı süreç/imaj (C FFI) | Keytab (kasada) | MD-1 |
| RADIUS / WS-Fed gateway | Ağ erişimi / legacy federasyon | Ayrı süreç | — | MD-18 |
| Federation resolver | OIDF zincir, CIMD, DCR | Rust çekirdek; SSRF korumalı fetcher | Federasyon anahtarı ≠ token anahtarı | — |

**Anahtarlar (MD-6, bağlayıcı).**
- Realm başına JOSE anahtar seti tutulur: 1 aktif + N pasif.
- Anahtar kullanılmadan önce yayımlanır (publish-before-use).
- Her realm'in ayrı bir KMS anahtarı vardır.
- RSA anahtarı yalnız bir client talep edince üretilir; yalnız kimlik iddialarını imzalar (§10.4.5).
- Kapsam dışı bir anahtarın kabul edilmesi (Storm-0558 sınıfı) HL-8 kapsamındadır → §13.
- Federasyon anahtarı (OIDF entity statement) ile token imza anahtarı ayrıdır. Domain Metadata OIDF kabında yayınlanırsa Access entity type metadata'sı içinde **ayrıca imzalı** (yayın anahtarı) bir nesne olarak taşınır; dış entity statement'ı federasyon anahtarı imzalar ve yalnız "domain'in kim olduğunu" doğrular; verifier authority anahtarlarını yalnız iç nesneden alır (→ §9.15).
- SAML imza anahtarı ayrıdır.

**Yapılandırma yetkisi (MD-14, bağlayıcı).**
- Client, redirect URI, upstream IdP, SAML SP, SCIM client, realm config ve anahtar rotasyon **politikası** (aralık, algoritma, acil rotasyon) değişiklikleri realm'in yönetişim AuthorityDomain'indeki **domain action**'lardır. ADP `commit` ile yetkilendirilir. Politika dahilinde zamanlanmış rotasyonun yürütülmesi (MD-6 operasyonel anahtar ömrü, realm JOSE rotasyonu, SAML metadata yeniden imzası, keytab rotasyonu) operasyoneldir ve ayrı bir Exercise gerektirmez; acil rotasyon ve algoritma değişikliği domain action'dır.
- Ayrı bir "admin token" yoktur. Konsol BFF çerezi kullanır. Çerez yalnız gezinmeyi ve identity plane'in kendi ekranlarını taşır; authority grafiği ve audit okuması AIS (CT0) ya da holder-bound okuma projection'ı ister.
- Meta-Exercise CT tazeliğinde AIS ister.

Ayrıntı → §12 (yönetim yüzeyi). **BY SEMANTICS** (tek yetki yolu). → **IDI-1**.

**Identity iç veri modeli (normatif):**

| Tablo | Anahtar alanlar | Kural |
|---|---|---|
| `identity_subjects` | `(tenant_id, realm_id, id)`; `id` UUID v7 (iç), dışa opak ID (MD-18) | E-posta PK değildir; hard delete yerine durum + tombstone |
| `identities` | `(tenant_id, realm_id, provider, provider_subject_id)` UNIQUE; `verified_at` | Doğrulanmışlık kimlik başına bir özelliktir |
| `credentials` | `(tenant_id, realm_id, id)`; `type`, **`algorithm`**, `created_at`, `last_used_at`, `status` | `algorithm` alanı gün-1'de bulunur (MD-3); credential realm'e yereldir |
| `sessions` | → §12 | `session_epoch` (MD-7) |
| `clients` | `(tenant_id, realm_id, client_id)`; `allowed_algs`, `subject_type` (pairwise/public), `token_endpoint_auth_method`, `dpop_bound`, `profile` (default/fapi2) | Alg allowlist buradan okunur (MD-3); değişiklik ADP commit ister (MD-14) |
| `device_keys` | §10.1.3 | — |
| `pairwise_subjects` | `(identity_subject_id, sector_id)` UNIQUE → rastgele değer | MD-10; SAML persistent NameID aynı tablo modelini kullanır |

### 10.2 Kimlik doğrulama yöntemleri

Bu bölüm her yöntem için dört şeyi tanımlar: yöntemin konumu, en yüksek assurance tavanı, zorunlu korumalar ve varsayılan durum. Yöntem haritasının özeti aşağıdadır. Phishing direnci, AiTM ve infostealer ile ilgili tehdit tabloları → §14.

| Yöntem | Phishing-resistant | AAL tavanı | CT tavanı | Varsayılan |
|---|---|---|---|---|
| Passkey, cihaza bağlı / donanım anahtarı | Evet | AAL3 (donanım, FIPS 140-3) | CT3 (UV + donanım-bağlı + non-custodial) | Açık, birincil |
| Passkey, senkronize | Evet | AAL2 | CT2 (UV) | Açık, birincil |
| Sertifika / PIV / mTLS | Evet | AAL3 (donanım) | CT3 | Kiracı başına |
| Push + number matching | Hayır | AAL2 (ikinci faktör olarak) | Hiçbir CT'yi tek başına karşılamaz (yalnız oturum girişi / ikinci faktör; §13.7.3, §10.3.3) | Kiracı başına |
| TOTP | Hayır | AAL2 (ikinci faktör olarak) | Hiçbir CT'yi tek başına karşılamaz | Kiracı başına |
| E-posta OTP / magic link | Hayır | AAL1 | Hiçbir CT'yi karşılamaz | Kiracı başına |
| SMS OTP | Hayır | AAL2'de izinli ama önerilmez (restricted) | Hiçbir CT'yi karşılamaz; TR ödeme şablonunda yalnız kurulum ve aktivasyon | Kapalı |
| Parola | Hayır | AAL1 | Hiçbir CT'yi karşılamaz | Açık (fallback) |
| Social login | Upstream'e bağlı | Acceptance eşlemesine bağlı | Acceptance eşlemesine bağlı | Kiracı başına |
| Kurumsal SSO (OIDC/SAML upstream) | Upstream'e bağlı | Acceptance eşlemesine bağlı | Acceptance eşlemesine bağlı | Enterprise'da varsayılan (H13) |

#### 10.2.1 Parola

**Saklama (normatif).**

| Algoritma | Parametre | Konum |
|---|---|---|
| Argon2id | Varsayılan parametreler §15.14 CR-36'dadır (**m = 7 MiB, t = 5, p = 1**, PD; ölçüm ≈ 9 ms). OWASP'ın eşdeğer setleri (ör. m=19 MiB, t=2, p=1; m=46 MiB, t=1, p=1) kalibrasyon aralığıdır, varsayılan değildir. | Varsayılan (→ §15.14) |
| Argon2id (RFC 9106) | t=1, p=4, m=2 GiB ya da t=3, p=4, m=64 MiB | Yüksek bellek profili (opsiyonel) |
| scrypt | N=2^17, r=8, p=1 | Yalnız göç kaynağı |
| bcrypt | maliyet ≥10 (tercihen 12); 72 bayt sınırı | Yalnız göç kaynağı |
| PBKDF2 | SHA-256 ile 600 000, SHA-512 ile 220 000 iterasyon | **Yalnız FIPS profili** |

Kurallar:
- Salt ≥16 bayttır.
- Pepper, hash üstünde bir AES-GCM katmanı olarak uygulanır. Anahtarı KMS'tedir ve kiracı KEK hiyerarşisine bağlıdır (T20).
- Göç "sarmala ve sonraki girişte yeniden hash'le" kalıbıyla yapılır (`PasswordNeedsRehash`). Dış sistemden gelen hash'ler taşınmaz; tembel göç uygulanır (60–90 gün) → §12.
- Argon2 parametre göçünde eski ve yeni parametrelerin süre farkı ölçülür. Fark ortalama doldurma penceresinden büyükse kullanıcı giriş yaptığında migration zorlanır.

**Politika (NIST 800-63B-4).**
- Uzunluk en az 8'dir; 15 önerilir. Üst sınır en az 64 karakterdir.
- Kompozisyon kuralı yoktur. Periyodik rotasyon yoktur. Güvenlik sorusu yoktur.
- Yapıştırma serbesttir. Unicode serbesttir; NFKC normalizasyonu uygulanır (çıkarım: 800-63B'nin Unicode önerisi).
- Sızıntı listesi kontrolü (HIBP k-anonymity) zorunludur.
- Rate limit zorunludur → §12.

**Enumeration ve zamanlama (MD-18; bağlayıcı).**
1. Login akışı önce tanımlayıcıyı alır (identifier-first, TN-96). İkinci adım hesap var olsun olmasın aynıdır: passkey seçeneği ve parola formu her zaman gösterilir; MFA sonra gelir. Hesap varlığı hiçbir kanalda sızmaz (CR-40).
2. **Var olmayan kullanıcı için dummy Argon2 çalıştırılmaz**, çünkü DoS üretir. Bunun yerine adaptif gecikme uygulanır: koşan başarılı login ortalaması tutulur ve başarısız yanıt bu ortalamaya doldurulur (Rauthy modeli).
3. `max_hash_threads` semaforu ve `hash_await_warn_time` metriği eklenir. Kuyruk doluluğu kullanıcının var olup olmamasına bağlı değildir.
4. IP başına başarısız giriş sayacı ve üstel kara liste uygulanır. Değerler: 7 denemede 60 s, 10'da 600 s, 15'te 900 s, 20'de 3600 s, 25'te 24 saat (Rauthy değerleri; varsayılan, PD).
5. Enumeration regresyon süiti şu akışların her biri için var olan ve olmayan kullanıcıyı karşılaştırır: login, kayıt, sıfırlama, MFA enroll, SCIM, device flow ve OIDC hata. Karşılaştırılanlar: durum kodu, gövde (bayt bayt), header seti, redirect hedefi, p50 ve p95 süreleri. → §14.
6. Kayıtta "e-posta zaten kullanımda" bilgisi arayüzde gösterilmez, e-postayla bildirilir.
7. HTTP/2'de Timeless Timing savunması değerlendirilir: rastgele gecikme ya da kritik endpoint'lerde multiplexing sınırı (WATCH).

Garanti: **UNDER DECLARED POLICY** (zamanlama eşitliği ölçümle doğrulanır; kesin değildir). §13'e aday: **RR** — "Kullanıcı varlığı yan kanalı istatistiksel olarak azaltılır, kriptografik olarak sıfırlanmaz."

Parola **hiçbir CT'de (CT0 dahil)** tek başına yeterli değildir (§13.7.3 CT0 dipnotu). Passkey'e geçiş kalıbı: parola 12–18 ay fallback olarak tutulur. Kullanıcıların ~%60'ı passkey kaydettiğinde, kiracı politikasıyla emekliye ayrılabilir (oranlar satıcı kaynaklıdır).

#### 10.2.2 OTP, TOTP ve magic link

- **TOTP** (RFC 6238): 30 s adım, ±1 adım pencere, kullanılmış kod tekrar reddedilir. Secret şifreli credential store'da tutulur. TOTP phishing'e açıktır. **Recovery code eşlikçisi zorunludur.** Recovery code'lar tek kullanımlıktır ve Argon2id ile hash'lenir.
- **SMS OTP**: AiTM ve SIM swap'a açıktır. NIST AAL2'de "restricted" statüdedir. Varsayılan kapalıdır. TR ödeme şablonunda yalnız kurulum ve aktivasyonda kullanılabilir. SIM değişikliğinden sonra 90 gün boyunca SIM tabanlı yöntem kullanılamaz (§10.3.4).
- **E-posta OTP ve magic link**: Önizleme botları linki tüketebilir. Bu yüzden link, tüketen bir GET değildir: bir onay ekranı açar ya da bir kod gösterir. Bağlantının başka cihazda açılması desteklenir, ama oturum **başlatan cihaza** bağlanır. Başka cihazda tamamlanması açık onay ister. Ömür ≤15 dk, tek kullanımlık.
- Askıya alınabilir akış durumu (link ve OTP beklemesi) → §12.4.1 (TN-102).

#### 10.2.3 Push ve number matching

- Push onayı **number matching ile zorunludur**. İstisna: kullanıcı onayı aynı cihazda verir ve bağlam gösterilir.
- Bildirimde işlem bağlamı (uygulama, konum, eylem) gösterilir.
- Push fatigue savunması: oran sınırı ve ret sonrası bekleme → §12.
- Push AiTM'e karşı koruma **sağlamaz**. Bu yüzden phishing-resistant sayılmaz ve hiçbir CT'nin authenticator class koşulunu tek başına karşılamaz. §13.7.3'e (kanonik) göre CT1 ve üstü phishing-resistant authenticator ister; CT0'a CT1 değerleri uygulanır ve bu dipnot authenticator class satırı dahil bütün satırları kapsar. §13.7.3'teki "bildirim içi hızlı onay" (yalnız CT1) bir **Approval Surface** biçimidir; push bildirimindeki onayın kendisi WebAuthn/SPC gibi phishing-resistant bir assertion'la H(AAS)'a bağlanmalıdır. **BY SEMANTICS** (CT eşlemesi).

#### 10.2.4 Passkey ve WebAuthn

**RP ID (bağlayıcı) → IDP-5, IDI-4.**
- RP ID realm başına tanımlanır (MD-5).
- Kiracının özel alan adı **passkey kaydından önce** sabitlenmek zorundadır.
- RP ID değişimi passkey'leri geçersiz kılar ve **geri dönülemez** bir işlem olarak işaretlenir. Bu bir domain action'dır, ADP commit ister (MD-14) ve CT3 sınıfındadır (çıkarım: etkisi tüm kullanıcıların credential'ını kaybetmesidir).
- Related origins (`/.well-known/webauthn`) yalnız kiracının kendi markaları için ve ≤5 etiketle kullanılır.

**Kayıt ve doğrulama (normatif):**

| Konu | Kural |
|---|---|
| UV | Varsayılan `preferred`. CT2+ ve AAL2+ için UV=1 zorunlu. Bazı regülasyonlarda platform UV delegasyonu kabul edilmez (TR: platform biyometrisi tek başına güçlü unsur değildir, MD-11). |
| Discoverable credential | Varsayılan `preferred`. `credProps.rk` kontrol edilir. |
| Conditional get | Kullanıcı adı alanında autofill desteklenir. |
| Conditional create | Attestation istenmez, kullanıcıya bildirim gönderilir, `excludeCredentials` doldurulur, `credProps.rk` kontrol edilir. |
| Transports / hybrid | Bilinmeyen transport değerleri reddedilmez, kabul edilir. |
| Uzantılar | `credProps` ve `credProtect` seviye 2 kullanılır. `devicePubKey` L3'ten çıkarıldı; kullanılmaz. |
| PRF | Salt alan ayrımı yapılır. Sunucu kimlik bilgisi başına salt ve `prf.enabled` saklar; **çıktıyı asla saklamaz**. first/second ile rotasyon yapılır. Platform desteği eksiktir, bu yüzden yedek yol şarttır. |
| largeBlob | Bağımlılık kurulmaz. |
| BE/BS | BE değişmez; değişirse doğrulama reddedilir. BS güncellenir. BS 1→0 geçişinde uyarı verilir. BE=0 ile BS=1 birlikte geçersizdir. Sayaç politikası BE'ye bağlanır: senkronize credential'da sayaç 0 olabilir. Kurumsal politika BE=0 şartı koyabilir. → **IDI-5** |
| Sign count | BE=0 ise `new > old` beklenir; ihlal sinyal Claim'i olur ve kiracı politikasına göre ret uygulanır. BE=1 ise sayaç zorunlu değildir. |
| AAGUID | İpucudur, güven kaynağı değildir. Topluluk listesi ve MDS 3.1.1 kullanılır. |
| Attestation | Tüketicide `none`. Kurumsalda kiracı bayrağıyla `direct` + MDS + AAGUID allowlist. Enterprise attestation desteklenir. Attestation sinyaldir (§10.1.3). |
| Signal API | Üç metot kullanılır: `signalUnknownCredential`, `signalAllAcceptedCredentials`, `signalCurrentUserDetails`. Silinen credential ve isim değişikliği bildirilir. Tam liste gönderilir, sayfalama yoktur. Chrome 132 ve Android 144'ten beri vardır (sürüm numarası bağımsız doğrulanmadı; Android 144 olağan dışı bir sürüm numarasıdır). |
| `uiMode: immediate` | L4 özelliğidir, yalnız Chrome 149'da var. WATCH. |
| Algoritmalar | Kabul: ES256 (−7), **ESP256** (RFC 9864 fully-specified), Ed25519 (−19/−8, fully-specified tercih), RS256 (yalnız legacy authenticator için). `pubKeyCredParams` sırası ESP256/ES256 → Ed25519 → RS256'dır. ML-DSA, FIDO Server Req 2.3'te tanımlıdır; WATCH (→ §15). ES256 (−7) zorunlu doğrulamadır; WebAuthn assertion algoritmaları WebAuthn kurallarına göre kabul edilir; "fully-specified" kuralı imza üretimi ve yeni artefaktlar içindir (CR-5). RS256 authenticator yalnız oturum girişi `authentication` Claim'i üretebilir (ingest'te doğrulama, §15.2.2 "RSA doğrulaması (ingest)"). Instance KeyBinding'i olarak AIS/AAS assertion'ı imzalayamaz. Bu authenticator ile hiçbir CT karşılanmaz. |

**Kütüphane.** webauthn-rs 0.5.5 SUSE denetiminden geçmiştir. PRF ve BE/BS genel API'de bulunmaz: `danger-credential-internals` özelliği ya da upstream PR gerekir. fido-mds mevcuttur. Kararı **IDP-6**'dadır.

**Passkey dağıtımı.** Senkronize passkey AAL2 sayılır, cihaza bağlı passkey AAL2'nin üstündedir, donanım anahtarı AAL3'tür. Benimseme istatistikleri satıcı kaynaklıdır ve normatif değildir.

#### 10.2.5 Sertifika, PIV ve mobil imza

- **mTLS client auth** (RFC 8705): FAPI ve M2M için kullanılır. Tarayıcı ile mTLS client'ın aynı host'ta olması sorun çıkarır. Bu yüzden mTLS ayrı bir host ya da port üzerinden sunulur ve `mtls_endpoint_aliases` ile ilan edilir.
- **PIV/CAC**: Sertifika subject ve issuer'ı `identity-binding` Claim'ine eşlenir. CA güveni Acceptance ile kurulur (`actor-binding`). İptal kontrolü (OCSP/CRL) fail-closed'dur (MD-8).
- **Donanım anahtarı**: Kullanıcı başına en az iki kayıt önerilir. Kurumsal break-glass hesapları için zorunludur (§10.2.6).
- **Mobil imza** (operatör tabanlı, TR'de yaygın): Upstream bir assertion olarak modellenir. Assurance eşlemesi Acceptance'tadır. Sağlayıcı listesi → §10.9.

#### 10.2.6 Social ve kurumsal SSO

**Social.**
- Token **backend'de doğrulanır**: imza, `iss`, `aud`, `exp` ve `nonce` kontrol edilir.
- Anahtar `(iss, sub)` çiftidir. E-posta anahtar değildir (P-ID-9).
- Doğrulanmış e-posta da otomatik hesap birleştirme gerekçesi değildir. Birleştirme açık kullanıcı eylemi ve mevcut hesaba yeniden kimlik doğrulama ister → §12.
- Apple kuralı: uygulama başka bir social SSO sunuyorsa "Apple ile Giriş" de sunulmalıdır (App Store kuralı). Bu bir kiracı yapılandırma uyarısıdır.

**Kurumsal SSO.**
- **JIT provisioning**: İlk girişte `IdentitySubject` oluşturulur. Grup ve rol bilgisi yalnız Acceptance ile selection'a girer (§10.1.4).
- **Domain doğrulama**: DNS TXT ile yapılır. Doğrulanmamış bir alan adı için home realm discovery yönlendirmesi yapılmaz.
- **Break-glass hesabı**: SSO'dan bağımsızdır, donanım anahtarlıdır ve kullanımı alarm üretir. Destek erişimi impersonation değildir, Grant ile kurulur (MD-9) → §12.
- **SP-initiated akış tercih edilir.** IdP-initiated akış varsayılan kapalıdır (§10.6.1).
- **Upstream IdP kaydı** bir domain action'dır (MD-14).

### 10.3 Güvence çerçeveleri

#### 10.3.1 NIST SP 800-63-4

NIST SP 800-63-4 finaldir. Access'in assurance vektörü (§10.1.6) bu çerçeveye eşlenir:

| Seviye | Tanım (800-63-4) | Access karşılığı |
|---|---|---|
| IAL1 | Yeniden tanımlandı; temel kanıt | KYC sağlayıcısından gelen `identity-binding.person` Claim'i (§10.9) |
| IAL2 | Uzaktan gözetimsiz kimlik tespiti tam yoldur | Upstream IDV sağlayıcısı + Acceptance (`predicate-input`) |
| IAL3 | Gözetimli tespit | Yalnız upstream; Access IAL3 IDV yapmaz |
| AAL1 | Tek faktör | Parola, e-posta OTP |
| AAL2 | İki faktör + replay direnci; **phishing-resistant seçenek sunmak zorunlu**; SMS izinli ama önerilmez | Senkronize passkey; parola + TOTP/push |
| AAL3 | PKC sahiplik kanıtı, phishing-resistant, dışa aktarılamaz anahtar, açık niyet, FIPS 140-3; **senkronize passkey kabul edilmez** | Cihaza bağlı passkey/donanım anahtarı (BE=0), PIV |
| FAL1 | Bearer assertion | Varsayılan dışı |
| FAL2 | Sahiplik kanıtı / şifreli assertion | DPoP/mTLS bağlı token; SAML'de şifreli assertion |
| FAL3 | İmzalı assertion + endpoint doğrulaması (HoK) | FAPI 2.0 profili + PAR + DPoP/mTLS |

Phishing direnci için iki tanınan yol vardır: **channel binding** (mTLS, TLS-bağlı) ve **verifier name binding** (WebAuthn origin/RP ID). Access, `phishing_resistant` bayrağını yalnız bu iki yoldan biri kanıtlanırsa set eder. **BY SEMANTICS.** 800-63C'nin FAL, `jti`, PPII ve FAL2+ şifreleme gereksinimleri §10.4 ve MD-10 ile karşılanır.

#### 10.3.2 eIDAS ve EUDI seviyeleri

- eIDAS LoA: **Low / Substantial / High**. EUDI Wallet High'ı hedefler.
- Eşleme: High ≈ AAL3 + IAL3/IAL2+ (çıkarım; resmi eşleme yok). Substantial ≈ AAL2.
- `loa_eidas` alanı yalnız upstream bir notified eID ya da EUDI sunumundan gelir. Access kendi yöntemleriyle "High" iddia etmez. **UNDER DECLARED POLICY.**
- VC/OID4VP ayrıntısı → §10.7.2.

#### 10.3.3 CT tier tablosu

**CT assurance tablosu → §13.7.3** (kanonik; POLICY DEFAULT; CT0 dipnotunun kapsamı dahil). Bu alt bölüm tabloyu tekrar etmez. Yalnız identity plane karşılama koşullarını (aşağıdaki IDP-8 tablosu) ekler. Bu koşullar §13.7.3'ü daraltır, değiştirmez.

**Identity plane karşılama koşulları (§13.7.3 tablosunu değiştirmez, karşılama koşullarını somutlar) → IDP-8:**

| Konu | CT1 | CT2 | CT3 | Kaynak |
|---|---|---|---|---|
| Phishing-resistant kanıt yolu | WebAuthn/passkey/SPC/mTLS | Aynı + UV=1 | Aynı + UV=1 + BE=0 (cihaza bağlı) + non-custodial | — |
| Senkronize passkey (BS=1) | Karşılar | Karşılar | **Karşılamaz** (AAL3 kuralı) | — |
| Push + number matching | Karşılamaz (phishing-resistant değil); yalnız oturum girişi ve ikinci faktör | Karşılamaz | Karşılamaz | — |
| Upstream IdP authentication | Acceptance'ta `phishing_resistant` eşlemesi varsa | Aynı + `acr`/`amr` UV kanıtı | Yalnız upstream donanım-bağlı kanıt + Acceptance açık beyanı; varsayılan **karşılamaz** | §10.1.2 kural 2 |
| Step-up isteği (RFC 9470) | `max_age` zorunlu, `acr_values` tavsiye | Aynı | Aynı | — |
| Uygulama-kontrollü faktör (MD-11) | Domain şablonuna göre | TR ödeme şablonunda zorunlu | TR ödeme şablonunda zorunlu | §10.3.4 |

Uygulama-kontrollü faktör (MD-11) §13.7.3'ün phishing-resistant sınıfını **tek başına karşılamaz**. TR ödeme şablonunda CT2/CT3 için phishing-resistant authenticator **ve** uygulama-kontrollü faktör birlikte istenir; bu bir şablon daraltmasıdır, gevşetme değildir.

Not: §13.7.3 CT0 dipnotu gereği parola, OTP, TOTP ve push hiçbir CT'yi (CT0 dahil) tek başına karşılamaz; yalnız authority etkisi olmayan oturum girişinde ve ikinci faktör olarak kullanılır.

#### 10.3.4 PSD2 SCA, TR GKD ve MD-11

**PSD2 SCA.**
- Üç kategoriden iki bağımsız unsur gerekir.
- **Dynamic linking**: kimlik doğrulama kodu tutara ve alıcıya bağlanır.
- Access'te bu, AAS → H(AAS) binding'idir (§13.7.3 "binding = H(AAS)"). Ödeme için SPC (Secure Payment Confirmation) kullanılır.
- Decoupled akış için standart teslim kanalı CIBA'dır (§10.5.3). Onay yine AAS'tir.

**Türkiye — ÖHY ve BS Tebliği GKD (normatif TR ödeme şablonu) → IDP-9.**
- Dayanak: 6493 sayılı Kanun, ÖHY ve BS Tebliği (yürürlük 1 Ara 2021) m.10 GKD, MASAK 19.
- **Platform biyometrisi tek başına güçlü unsur sayılmaz.** Gerekli olan, uygulama-kontrollü faktördür: app PIN + app'e bağlı anahtar çifti. RequirementTerm assurance sınıfına `app_controlled_factor` eklenir (§10.1.6).
- SMS OTP yalnız kurulum ve aktivasyon durumlarında kullanılabilir.
- SIM değişikliğinden sonraki 90 gün boyunca SIM tabanlı yöntem kullanılamaz. Bu bir RestrictionPolicy girdisidir; SIM-swap sinyali sağlayıcıdan Claim olarak gelir.
- İşlem kodu, müşteriye atanmış anahtarla imzalanır (dynamic linking).
- Anne kızlık soyadı ve kimlik belgesi bilgisi doğrulama unsuru olarak kullanılamaz.
- **4 Eyl 2026, RG 33360** değişikliği: biyometri, NFC ve canlılık eklendi. m.10/8'e göre kimlik belgesi (NFC çip) ile PIN, biyometri ya da güvenli e-imza birlikte GKD sayılır. Bu tarih bağımsız olarak doğrulanmadı.
- Dokümantasyon m.22/7'ye göre tutulur. m.22/6'ya göre yılda iki test yapılır.
- SPK VII-128.10 ayrıca uygulanır.

Garanti: **UNDER DECLARED POLICY** (şablon). Mevzuata uygunluk **NOT GUARANTEED**'dir; hukuki değerlendirme kiracının sorumluluğundadır. Diğer uyum rejimleri (GDPR/KVKK, PCI DSS 4.0 Req 8, HIPAA, FedRAMP, OMB M-22-09, NIS2, DORA) → §12/§14 uyum eşlemesi. Burada yalnız authentication gereksinimleri alınır: PCI DSS 4.0 Req 8 kart verisi ortamına her erişimde MFA ister; OMB M-22-09 phishing-resistant MFA ister.

### 10.4 OAuth 2.x Authorization Server ve OIDC OP

Standart sınıflandırması (ADOPT/PROFILE/EXTEND/REJECT) **→ §9.4**'tedir. Bu bölüm o sınıflandırmanın identity plane'deki **uygulama profilidir**. Token'ın authority semantiği **→ §9**'dadır: `projection.issue`, `cnf`, tek `aud`/RFC 8707, RAR, "refresh = yeni karar", reuse detection ve single-flight. Authority taşıyan access token bir **projection**'dır, authority değildir (PI-3).

**Token sınıfları (→ §9).** Identity plane'in ürettiği token'lar iki sınıftır. (i) **Authority taşıyan** her token (RAR `authorization_details` taşıyan ya da kaynak erişimi ifade eden access token, refresh token, exact-intent/bounds token) bir `projection.issue` ürünüdür, tam ValidityContract taşır ve holder-bound'dur (§9.9, PI-11, S-1). (ii) **Kimlik iddiaları** (ID token, SAML/WS-Fed assertion, logout token, LDAP/SPNEGO oturumu, protokol-scope-only access token: `openid`/`profile`/`userinfo`) authority taşımaz (E39), `projection.issue` Exercise'ı gerektirmez ve MD-7'nin ValidityContract semantiğine **kimlik-iddiası profiliyle** tabidir: `horizon` = `exp`/`NotOnOrAfter`, hızlı iptal `session_epoch`, `issuing_exercise` yok. Kenar gateway süreçleri yalnız (ii) sınıfını üretir ve ADP çağırmaz (P-ID-5, IDI-11).

#### 10.4.1 Grant tablosu

| Grant | RFC | Durum | Koşul |
|---|---|---|---|
| Authorization Code + PKCE | 6749, 7636 | **Varsayılan**, tüm client tipleri | PKCE S256 zorunlu, confidential client dahil; `plain` reddedilir |
| Refresh Token | 6749 | Açık | Public client'ta rotasyon + DPoP bağı; ayrıntı → §9.9.3; identity plane uygulaması §12.2.1 (TN-31) |
| Client Credentials | 6749 | Açık | Yalnız confidential client; `private_key_jwt` ya da mTLS tercih edilir |
| Device Authorization | 8628 | **Varsayılan kapalı** | Açıksa DPoP bağlı ve onay ekranında client, konum ve kod bağlamı gösterilir. Device code phishing nedeniyle kiracı başına açılır |
| Token Exchange | 8693 | PROFILE | §10.4.4 |
| JWT Bearer assertion | 7523 | Açık | `iss`/`sub`/`aud`/`exp`/`jti` zorunlu; `jti` replay cache |
| SAML 2.0 Bearer assertion | 7522 | Legacy, kiracı başına | SAML kurallarına (§10.6.1) tabi |
| CIBA | OIDC CIBA | PROFILE | §10.5.3 |
| Implicit | — | **Reddedilir** | OAuth 2.1 / RFC 9700 |
| ROPC (password) | — | **Reddedilir** | OAuth 2.1 / RFC 9700. Göç istisnası yoktur. |

OAuth 2.1 güvenli varsayılanları uygulanır. OAuth 2.1 §9.4'te "informative"dir. RFC 9700 (OAuth 2.0 Security BCP) referans alınır. Redirect URI **tam dize eşleşmesiyle** doğrulanır. Tek istisna native loopback'tir: port-agnostik eşleşme (RFC 8252); ayrıntı → §11.3.9. **BY SEMANTICS** (reddedilen grant'lar kodda bulunmaz).

#### 10.4.2 → §9

`projection.issue`, `cnf`, tek `aud` / RFC 8707 resource indicator, RAR (`authorization_details`), refresh token = yeni karar, reuse detection ve mobil single-flight **→ §9.9** (§9.9.3). Refresh token'ın identity plane uygulaması §12.2.1'dedir.

#### 10.4.3 Güvenlik uzantıları ve DPoP profili

| Uzantı | RFC | Profil |
|---|---|---|
| PKCE | 7636 | Her zaman S256 |
| PAR | 9126 | Varsayılan açık. FAPI profili ve yüksek sonuçlu client'ta **zorunlu** (`require_pushed_authorization_requests`) |
| JAR | 9101 | PAR ile birlikte; yüksek sonuçta zorunlu |
| JARM | OIDF JARM | Yüksek sonuçta zorunlu |
| RAR | 9396 | EXTEND → §9 |
| Resource Indicators | 8707 | ADOPT → §9. Replay'i çözer, consent'i çözmez |
| DPoP | 9449 | ADOPT; aşağıdaki profil |
| mTLS | 8705 | ADOPT; sertifika-bağlı token + client auth |
| Step-up challenge | 9470 | ADOPT; `max_age` zorunlu, `acr_values` tavsiye |
| Mix-up koruması (`iss` parametresi) | **9207** | **Zorunlu**: her authorization response `iss` taşır. Client doğrulaması bayt-özdeştir (→ §11.4.4). `authorization_response_iss_parameter_supported: true` |
| JWT access token | 9068 | ADOPT |
| Protected Resource Metadata | 9728 | ADOPT → §11.5.2 |
| Introspection | 7662 | ADOPT; tazelik kanıtlanamazsa `active=false` (MD-8). Primary'ye ya da tazelik kaynağına ulaşılamıyorsa her token için, cache-hit dahil, `active=false`; 503 dönmez |
| Revocation | 7009 | ADOPT |

DPoP ve mTLS bir **actor proof değildir**: token'ın sahiplik bağıdır. Instance kimliği ayrıca `authentication` Claim'iyle kurulur. **BY SEMANTICS.**

**DPoP profili (MD-18) → IDP-11.**
1. **Doğrulama** 12 adımı izler: `typ=dpop+jwt`; `alg` client metadata allowlist'inden gelir (MD-3); `jwk` public olmalıdır; imza; `htm`; `htu` normalize edilerek karşılaştırılır (sorgu ve fragment atılır); `iat` penceresi; `jti` replay; `nonce`; `ath` (RS'de); `cnf.jkt` eşleşmesi.
2. **Nonce**: Uzun ömürlüdür (saatler mertebesinde) ve tüm oturumlarda **paylaşılır**. Durumsuz üretilir. Kayan pencerede yakın zamanda bayatlamış nonce kabul edilir. Her 200 yanıtında `DPoP-Nonce` ile öngörülü nonce verilir. Bu model Okta modelini ATProto bayat-nonce toleransıyla birleştirir. AS'de `400 use_dpop_nonce`, RS'de `401` döner. AS ve RS nonce'ları ayrıdır. Bir client'a nonce verilmişse nonce'suz kanıt reddedilir. Nonce rotasyon süresi PD'dir.
3. **Replay cache**: TTL = kanıt ömrü + 2 × saat kayması. Örnek: 5 s + 2×5 s = 15 s. Anahtar `BLAKE3(htm ‖ htu_normalized ‖ jti)`, sabit uzunluktadır (cache taşmasına karşı). Boyut: 10 000 istek/s × 15 s ≈ 150 000 kayıt × ~80 B ≈ 12 MiB. Darboğaz boyut değil, dağıtık senkronizasyon gecikmesidir. Nonce düğüm yakınlığı taşır.
4. **Refresh bağı**: public client'ın refresh token'ı DPoP anahtarına bağlıdır. Confidential client'ta bağ zorunlu değildir; client auth yeterlidir. `dpop_jkt` authorization request'te desteklenir.
5. **RS tarafı**: "DPoP kullanıyoruz" demek replay koruması var demek değildir. Access'in RS SDK'sı ve gateway'i replay kontrolünü **kendisi** yapar. Bu kontrol → §14 conformance testlerinde bulunur.
6. Doğrulama maliyeti: ES256 doğrulaması 20–50 µs'dir (**çıkarım, ölçülmedi**).

Garanti: Sahiplik bağı **BY SEMANTICS**'tir (anahtar yoksa token kullanılamaz). Client anahtarının kendisinin çalınmasına karşı **NOT GUARANTEED**'dir. §13'e aday: **RR** — "DPoP anahtarı aynı cihazda çalınırsa (infostealer) bağ koruma sağlamaz; DBSC/donanım anahtarı ile azaltılır."

**mTLS ve DPoP seçimi.** M2M ve FAPI kurumsal client'larında mTLS kullanılır. Tarayıcı, mobil ve SPA'da DPoP kullanılır. Token Binding ölüdür ve kullanılmaz. mTLS ayrı bir host ya da port üzerinden sunulur (§10.2.5).

#### 10.4.4 Token Exchange

RFC 8693 PROFILE (§9.4).
- Desteklenen `subject_token_type` değerleri: access token, ID token, JWT ve SAML2 (Acceptance'lı issuer'dan).
- `requested_token_type`: access token ya da ID-JAG (→ §11.11). Access'in ürettiği ID-JAG authority taşımayan bir kimlik iddiası projection'ıdır; authority scope içermez, `scope` yalnız ipucudur. Authority RS tarafında Access Grant'ından gelir (§11.11.2–§11.11.3).
- Exchange **yeni bir karardır**: sonuçtaki projection, mevcut Grant + Acceptance ile yeniden değerlendirilir. Gelen token'ın scope'u authority değildir (PI-3).
- Downscoping zorunludur: sonuç gelen token'dan geniş olamaz. **BY SEMANTICS.**
- `act` claim ve delegation/capacity semantiği → §9.9.4, §11.10. `may_act` yalnız Grant AgencyTerms ile desteklenir.
- Cross-domain ve cross-realm exchange'te hedef domain, gelen token'ın **kaynak issuer**'ı için aktif bir `actor-binding` Acceptance'ına sahip olmalıdır (§9.13). Sonuç projection hedef domain'deki bir Grant'tan türer (PI-3). Gelen token yalnız Claim'dir.

#### 10.4.5 JWT, JWKS ve algoritmalar

**Algoritmalar (MD-3, bağlayıcı) T5.**

| Artefakt | Varsayılan | Seçmeli | Opt-in | Asla |
|---|---|---|---|---|
| **Authority taşıyan access token** (RAR `kind=intent\|bounds`, RFC 9068) | **ES256** | Ed25519 (RFC 9864 fully-specified `Ed25519`) | — (RS256 **yok**, MD-3/§15.2.2) | `none`, `HS*`, RSA*, `alg: EdDSA` |
| **Kimlik iddiaları ve protokol artefaktları** (ID token, logout token, userinfo JWT, protokol-scope-only access token, JAR/JARM, introspection JWT) | **ES256** | Ed25519 (RFC 9864 fully-specified `Ed25519`) | RS256 (client başına; `profile=fapi2` ile açılamaz), ML-DSA-65 (AKP) | `none`, `HS*` (public client ile paylaşılmaz), `alg: EdDSA` (polimorfik; reddedilir), RSA1_5 |
| JWE (opsiyonel ID token şifreleme) | `ECDH-ES+A256KW` + `A256GCM` | — | `RSA-OAEP-256` (legacy) | `RSA1_5` |
| SAML | rsa-sha256 (ekosistem varsayılanı/istisnası, §10.6.1); SP destekliyorsa ecdsa-sha256 **tercih edilir** (MD-3/§15.2.2) | ecdsa-sha256/384 | rsa-sha384/512 | SHA-1 (yalnız uyarı loglayan uyumluluk bayrağıyla) |
| FIPS profili | ES256 / ESP256 her yerde | — | — | Ed25519 (FIPS profilinde yok; CloudHSM FIPS modunda EdDSA yok, MD-3) |

- **alg allowlist** JOSE header'dan değil, **client/Domain metadata**'dan okunur. Downgrade testi zorunludur. **BY SEMANTICS.** → IDI-6.
- `rsa` crate'i kullanılmaz. RS256 aws-lc-rs ile uygulanır (`jsonwebtoken` CryptoProvider). `cargo tree -i rsa` CI kontrolüdür.
- RSA anahtarı yalnız bir client RS256 talep ettiğinde üretilir (MD-6). RSA anahtarı en az 2048 bittir. RS256 yalnız kimlik iddialarında kullanılır; authority taşıyan access token dahil hiçbir authority projection'ı RSA ile imzalanmaz; `profile=fapi2` client'ta RSA imza yoktur (§10.5.1).
- **Authority taşıyan access token'ın imza anahtarı** domain operasyonel anahtarıdır (MD-6 authority plane, T20; ayrı signer süreci); realm JOSE anahtarı authority projection'ı imzalamaz (§12). Bu anahtar realm JWKS'te `kid` + Domain Metadata çapraz referansıyla yayınlanır. Verifier, anahtarın Domain Metadata'daki binding'e çözüldüğünü ve DomainID eşleşmesini denetler (§9.10 adım 1; TI-RT6, MD-6 must-understand).

**JWKS (MD-6).**
- Realm başına 1 aktif + N pasif anahtar tutulur.
- **Yayınla → bekle → kullan**: yeni anahtar en az bir JWKS cache ömrü boyunca yayında durduktan sonra imzaya geçilir.
- Emekli anahtar, onunla imzalanmış en uzun ömürlü token'ın süresi kadar yayında kalır.
- `kid` zorunludur. `kty: AKP` (ML-DSA) gün-1'de modellenir ama varsayılan kapalıdır (→ §15).
- JWKS yanıtı `Cache-Control` taşır.

**Doğrulama kuralları.**
- `iss`, `aud` (OAuth access token'da tek değer, → §9.9.3 k.1; PAP/ValidityContract audience'ı verifier kümesi olabilir), `exp`, `nbf` ve `iat` zorunludur.
- Saat kayması ±60 s'dir (PD).
- Algoritma karışıklığına karşı kural: anahtar tipi ile `alg` eşleşmelidir. HS* ile public key kabul edilmez.
- `private_key_jwt` client assertion'ında `jti` replay cache'i ve `aud` = token endpoint (ya da issuer) zorunludur. İstemci saatinin sapmasına karşı AS hata yanıtı HTTP `Date` header'ı taşır.

**Token ömürleri (MD-7).**
- Access token ömrü bir üst sınırdır: authority taşıyan token'ın horizon'u = min(5–15 dk PD, varsayılan 10 dk; §13.7.2 tavanı). Tavan, token bounds'undaki en yüksek CT'den gelir. CT2+ action için bounds token verilmez, yalnız exact-intent token verilir (≤ 5 dk, count = 1). CT3 için projection verilmez. 28 saatlik access token reddedilir (MD-7).
- Yönetim yüzeyinde ayrı bir token sınıfı yoktur (MD-14). Konsolun okuma/gezinme projection'ı (CT0) ≤ 60 dk'dır (PD). Hiçbir meta-Exercise'ı yetkilendirmez. Her meta-Exercise AIS + ADP `commit` ister.
- ID token ≤5 dk'dır (PD, çıkarım: yalnız bir kerelik tüketim içindir).
- Refresh ve session ömürleri → §9.9.3 / §12.2.1.

#### 10.4.6 Discovery, CIMD, logout ve Native SSO

**Discovery.**
- `/.well-known/openid-configuration` (OIDC) ve `/.well-known/oauth-authorization-server` (RFC 8414) realm issuer'ı altında yayınlanır. Path-suffix kuralına uyulur.
- Metadata yalnız açılmış özellikleri ilan eder. Kapalı grant ve yöntemler ilan edilmez.
- `code_challenge_methods_supported: ["S256"]`, `dpop_signing_alg_values_supported`, `authorization_response_iss_parameter_supported: true` ve `require_pushed_authorization_requests` (profil başına) ilan edilir.
- AS endpoint, metadata ve davranış listesinin MCP profili için tam hali → §11.4.5.

**İstemci kaydı.**
- Statik kayıt bir domain action'dır (MD-14).
- DCR (RFC 7591/7592) varsayılan kapalıdır. Açıksa yalnız initial access token ile kullanılır; bu token kayıt endpoint'ine erişim kapısıdır, authority değildir; verilmesi domain action'dır (MD-14). DCR'ın MCP'de deprecate edilmesi → §11.3.7.
- CIMD -02 varsayılan kapalıdır. Realm başına açılır. Çözümleme §10.1.2'deki tek resolver'dan geçer. Kurallar → §11.3.
- OIDF otomatik ve açık kayıt → §10.7.1.

**Logout.**
- RP-Initiated Logout 1.0 ADOPT: `id_token_hint` ya da `client_id` + `post_logout_redirect_uri` tam eşleşme ister.
- **Back-Channel Logout 1.0 varsayılan**dır: logout token ES256 ile imzalanır, `events` ve `sid`/`sub` taşır, `nonce` taşımaz.
- Front-Channel Logout yalnız legacy ve opt-in'dir (üçüncü taraf çerez kısıtları).
- Session Management (iframe) desteklenmez.
- Logout best-effort'tur. Kesin iptal `session_epoch` artışıyla yapılır (MD-7) → §12.2.1. Identity plane oturumu cihaz başına tam olarak bir insan Instance'ına bağlıdır; sign-out oturumu bitirir ve o Instance'ı sonlandırır. Bu temizliktir; başka Instance'ların authority'si etkilenmez (XI-23). Garanti: RP'nin oturumu kapatması **NOT GUARANTEED**, Access tarafında yeni token verilmemesi **BY SEMANTICS**'tir.

**Diğer OIDC uzantıları.**
- `prompt=create` desteklenir.
- `prompt=login`, `max_age` ve `acr_values` desteklenir (RFC 9470 ile birlikte).
- **Native SSO for Mobile Apps** (OIDF taslak) PROFILE, varsayılan kapalıdır. `device_secret` cihaz anahtarına bağlanır. Aynı vendor'ın uygulamaları arasında token exchange (§10.4.4) ile çalışır. Taslak olduğu için WATCH.
- Claims parametresi ve `userinfo` desteklenir. `userinfo` pairwise `sub` döndürür (MD-10).

**Pairwise subject (MD-10).**
- Varsayılan `subject_type=pairwise`'dır. `sector_identifier_uri` desteklenir.
- Public `sub` client başına opt-in'dir ve ADP commit ister.
- Pairwise değer rastgele üretilir ve `pairwise_subjects` tablosunda saklanır (HMAC türetme değildir; rotasyon kırılganlığını önler).
- ID token / userinfo `sub`'ı sector-pairwise'dır. Authority projection'larındaki (access token, receipt, PAP) `sub` ise domain-pairwise takma addır (§9.9.3 k.8). İkisinin eşit olması garanti edilmez ve RS bunu varsaymaz.

§13'e aday: **RR** — "Pairwise `sub`'a rağmen e-posta, ad ve telefon gibi claim'ler RP'ler arası korelasyona izin verir; claim minimizasyonu kiracı politikasıdır."

#### 10.4.7 Uygulama ve conformance

MD-1 kararıyla AS Rust'ta yazılır. Bedel tahmini 12–18 geliştirici-ayıdır (tahmin, ölçüm değil). Telafi önlemleri:
1. **OIDF conformance suite** (MIT lisanslı) CI'da çalıştırılır. Kapsamı OIDC Basic/Config/Dynamic, FAPI 2.0 Security Profile + Message Signing, FAPI-CIBA ve Logout'tur.
2. **Fosite hata sınıfları regresyon derlemi** (MD-1) kullanılır.
3. Sertifikasyon ücreti 700/3.500 $, → §14.
4. **Reconsider tetikleyicisi (MD-1):** 6. ayda AS conformance ilerlemesi tahminin 2 katından fazla gerideyse, yalnız AS için ayrı bir Go süreci (Fosite) değerlendirilir. **WATCH.**

Negatif test listesi → §14.

### 10.5 Yüksek güvence profilleri: FAPI 2.0, FiPA, CIBA

#### 10.5.1 FAPI 2.0

§9.4'te "FAPI 2.0 Security Profile + Message Signing | ADOPT (yüksek-sonuç projection profili)" satırı vardır. Bu bölüm o satırın uygulama profilidir.

**Profil (FAPI 2.0 Security Profile Final, Şubat 2025) → IDP-12.** Client başına `profile=fapi2` alanı ile açılır. Profil açıksa:
- **Sender-constrained token zorunludur**: DPoP ya da mTLS. Bearer yoktur.
- **Yalnız confidential client** kabul edilir. Mobil public client FAPI dışıdır.
- Client authentication yalnız `private_key_jwt` ya da mTLS ile yapılır. `none` ve `client_secret_*` yasaktır.
- **PAR zorunludur.** Authorization endpoint'e doğrudan parametre gönderilmez.
- PKCE S256 zorunludur. RFC 9207 `iss` zorunludur.
- ROPC ve Implicit yoktur (zaten reddedilir).
- İmza: ES256 tercih edilir. RSA kullanılıyorsa ≥2048 bit ve PS256 olmalıdır (çıkarım: FAPI RSA için PS256 ister).
- `profile=fapi2` client'ta RSA imza yoktur; ES256 (veya Ed25519) kullanılır. PS256 MD-3 tablosunda olmadığı için desteklenmez. RS256 opt-in fapi2 profiliyle birlikte açılamaz.
- **Message Signing** (JAR/JARM, HTTP Message Signatures) yüksek sonuçlu client'ta zorunludur (§9.4).
- Refresh token rotasyonu olağanüstü durumlar dışında kullanılmaz (FAPI önerisi). Bu kural §9'un "refresh = yeni karar" semantiği ile çelişmez: rotasyon olmasa bile her refresh yeni karardır.
- Authorization code ömrü ≤60 s'dir (PD).

Sertifikalı ürün referansları: Authlete 3.0, IBM, node oidc-provider ≥9.2.0, go-oidc ≥0.11.0, Auth0 HRI, WSO2 7.1, Keycloak 26.4. Access için hedef FAPI 2.0 OP sertifikasıdır → §14. Garanti: **UNDER DECLARED POLICY** (profil client başına seçilir).

#### 10.5.2 FiPA — First-Party Apps

- Durum: draft-04, 1 Tem 2026. Taslak 2 Oca 2027'de expire olur. **PROFILE, WATCH, varsayılan kapalı**. → IDP-13.
- `authorization_challenge_endpoint` desteklenir. Yalnız **first-party** client için açılır; SPA için açılmaz.
- İstemci kanıtlaması zorunludur (App Attest / Play Integrity, Claim olarak, §10.1.3). Phishing-resistant olmayan yöntemler bu akışta CT tavanını değiştirmez.
- Akış her an **tarayıcıya düşebilmelidir** (`redirect_to_web` hatası). Passkey ve step-up tarayıcıda tamamlanır.
- Taslak expire olursa ya da büyük değişiklik olursa özellik kapalı kalır.

#### 10.5.3 CIBA

- OIDC CIBA **PROFILE**: "yalnız davet / taşıma". Onay AAS'tir (§9.4). Semantik kural → **§9.4/§9.14**. CIBA cevabı tek başına authority değildir (PI-3).
- Modlar: **poll** varsayılandır. **ping** opsiyoneldir. **push** reddedilir. Push modunda token client'a doğrudan iletilir ve FAPI-CIBA push'u dışlar (çıkarım: FAPI-CIBA profili push'u yasaklar).
- `login_hint_token` ya da `id_token_hint` kullanılır. Serbest metin `login_hint` yalnız kiracı izniyle kabul edilir (enumeration riski, §10.2.1).
- `auth_req_id` ↔ REQUIRE_ACTION nonce eşlemesi, polling `authorization_pending` = nonce açık, `expires_in` tavanı ve onayın `act` türü (kapsayan Grant varsa `contribution`, yoksa `authority-act` + ardından aynı nonce ile `projection.issue`) → §9.14.5 k.2. Bekleyen tek nesne REQUIRE_ACTION almış nonce'tur (P54).
- `binding_message` gösterilir, ama bağlayıcı değildir; yalnız iki cihazı eşleştiren kısa koddur. CIBA payload'ı **bağlamaz**. Dynamic linking AAS → H(AAS) ile sağlanır, onay ekranı WYSIWYS kuralına tabidir → §9.14.
- Decoupled cihazda onay CT kurallarına (§13.7.3) tabidir. CT2/CT3'te bildirim içi hızlı onay yoktur.
- FAPI-CIBA profili §10.5.1 kurallarını devralır.

#### 10.5.4 İşlem imzalama ve AAS'in authenticator tarafı

AAS'in semantiği, yani H(AAS), surface conformance ve dynamic linking, **→ §9.14** bölümündedir. Identity plane, AAS'e bağlanan assertion'ı **üretir**. WYSIWYS ilkesi 5 adımla uygulanır:
1. İşlem içeriği kanonik olarak serileştirilir (AAS).
2. Kullanıcıya gösterilecek metin AAS'ten deterministik üretilir. Bu metin conformant surface'te tam render edilir.
3. WebAuthn `challenge` = H(AAS) olur. Ödemede SPC (Secure Payment Confirmation) kullanılır. Uygulama-kontrollü faktörde (MD-11) cihaz anahtarı H(AAS)'i imzalar.
4. Sunucu imzayı doğrular. `clientDataJSON.challenge` H(AAS) ile eşleşmelidir.
5. İmzalı assertion `authentication` Claim'ine "binding = statement digest" alanıyla girer.

Garanti: Gösterilen ile imzalanan arasındaki bağ, conformant surface varsa **UNDER DECLARED CAPABILITY**'dir. Uyumsuz ya da ele geçirilmiş bir istemci ekranında **NOT GUARANTEED**'dir. §13'e aday: **RR** — "Ele geçirilmiş cihazda gösterilen metin ile H(AAS) farklı olabilir; bağımsız surface (CT3) bunu azaltır."

### 10.6 Kurumsal protokoller: SAML, SCIM, LDAP, Kerberos, RADIUS, WS-Fed

Bu protokollerin hepsi kapsamdadır (MD-18; P-ID-4). Kenar protokoller ayrı süreçlerde çalışır (MD-1). Faz tablosu:

| Protokol | Faz 1 (zorunlu) | Faz 2 (opsiyonel) | Faz 3 / talep üzerine (WATCH) | Efor |
|---|---|---|---|---|
| SAML 2.0 IdP | Web SSO, Redirect + POST binding, metadata, imzalı assertion, şifreli assertion, persistent/transient NameID | SLO (best effort), ECP (MS zengin istemciler), upstream SAML SP rolü | Artifact binding, MDQ | 14–16 hafta + 8 hafta |
| SCIM 2.0 server | Users/Groups CRUD, PATCH, filtre, sayfalama, ServiceProviderConfig/Schemas/ResourceTypes; giden SCIM client (IDP-29) | İmleç sayfalama (RFC 9865), SET (RFC 9967) | Bulk, `/Me` | 16–18 hafta (giden client eforu ayrıca ölçülür) |
| LDAP (salt okunur) | Bind, search, unbind, abandon, StartTLS, WhoAmI, paged results | SASL EXTERNAL, RFC 3062 parola değişimi (yalnız LDAP credential sınıfı, §10.6.3) | — (yazma: tasarım gereği yok, aşağıdaki not) | 10–11 hafta |
| Kerberos/SPNEGO | SPNEGO acceptor (HTTP Negotiate), keytab, AD sync (LDAP çekme) | S4U2Proxy | — (KDC: tasarım gereği yok, aşağıdaki not) | 9 hafta |
| OIDF | → §10.7.1 | | | (toplam içinde) |

**Tasarım gereği yok** (gerekçeli tasarım kararı): LDAP yazma operasyonları (53 döner; IDP-16: LDAP bir uyumluluk yüzeyidir, yazma yolu IDI-1/IDI-11'i atlatırdı) ve Access'in KDC olması (IDP-17: yalnız SPNEGO acceptor). Faz 3 sütunundaki kalemler (Artifact binding, MDQ, SCIM Bulk, `/Me`) kapsamdadır; talep üzerine açılır (WATCH).

Toplam efor yaklaşık 95 haftadır. Önerilen sıra: SCIM → SAML → LDAP → OIDF → Kerberos. AD sync öne alınır. Bu sıra bir **PD**'dir; satış kapısına göre değişebilir. Kerberos "satış kapısıdır".

**Ortak altyapı (7 katman).** Şu katmanlar protokoller arasında paylaşılır:
- realm/kiracı çözümleme
- `IdentitySubject` deposu
- Claim issuer kanalı
- anahtar ve HSM soyutlaması
- audit
- oran sınırı
- sağlık ve metrik

Her kenar süreci bu katmanlara yalnız iç API ile erişir (MD-1).

#### 10.6.1 SAML 2.0 IdP (MD-18)

**Süreç ve parser (MD-18, bağlayıcı) → IDP-15.**
- SAML kapsamdadır.
- XML **izole bir parser worker sürecinde** ayrıştırılır. Bu worker'ın yetkisi düşürülmüştür, anahtar erişimi yoktur ve bellek/zaman limitleri vardır.
- **XSW regresyon derlemi** CI'da çalışır.
- **XML c14n fuzz** önceliği 1'dir (→ §14).
- Kütüphane: **bergshamra** (saf Rust XMLDSig/XMLEnc/C14N; xmlsec süitinden 1148/1151 geçer) + Access'in kendi SAML katmanı. İmza soyutlaması:
  `trait XmlSigner { fn sign(&self, doc: &mut Document, ref_id: &str, key: &SigningKey) -> Result<()>; }`
  HSM için kryptering (PKCS#11) kullanılır.
- samael (C zinciri) kullanılmaz. gamlastan'ın SPID iddiası kanıt değildir.

**AuthnRequest işleme.**
- `ForceAuthn` ve `IsPassive` birlikte true ise `IsPassive` kazanır. Kullanıcı etkileşimi gerekiyorsa `NoPassive` döner.
- **ACS URL ya da `AssertionConsumerServiceIndex` her zaman SP metadata'sına karşı tam eşleşmeyle** doğrulanır (SAMLProf §4.1.4.1). Eşleşme yoksa hata kullanıcıya gösterilir, SP'ye gönderilmez. **BY SEMANTICS.**
- `NameIDPolicy AllowCreate` tuzağı: `false` ise ve bu SP için persistent ID yoksa `InvalidNameIDPolicy` döner.
- `Scoping` ayrıştırılır. `ProxyCount` saklanır, `RequesterID` audit'e yazılır. Proxy'leme yapılmaz.
- İmzalı AuthnRequest, SP metadata'sı `AuthnRequestsSigned=true` ise zorunludur.
- Gelen AuthnRequest ve LogoutRequest ID'leri replay için saklanır (IdP yükümlülüğü). Assertion replay'i SP'nin yükümlülüğüdür.

**Response ve Assertion (10 normatif madde).**
1. Assertion şema sırası: Issuer, Signature, Subject, Conditions, Advice, Statement.
2. `Destination`, `InResponseTo` (SP-initiated'da) ve `Issuer` zorunludur.
3. `Conditions`: aynı `AudienceRestriction` içindeki `Audience`'lar VEYA ile, ayrı `AudienceRestriction`'lar VE ile birleşir. Audience = SP EntityID.
4. `SubjectConfirmation` yöntemi bearer'dır. `SubjectConfirmationData` `Recipient`, `NotOnOrAfter` ve `InResponseTo` taşır, **`NotBefore` yazmaz**.
5. `AuthnStatement`: `AuthnInstant`, `SessionIndex` (= assertion ID, her zaman üretilir), `SessionNotOnOrAfter` (örnek 8 saat, PD) ve `AuthnContextClassRef` (assurance vektöründen eşlenir) taşır.
6. **İmza**: enveloped, tek `Reference` (`#id`), exclusive c14n, `InclusiveNamespaces PrefixList`. Önce Assertion, sonra Response imzalanır. Varsayılan ikisi birdendir; SP başına `sign_response` / `sign_assertion` ayarlanabilir.
7. **Şifreleme**: önce imzala, sonra şifrele. `aes256-gcm` ve xmlenc11 `rsa-oaep` kullanılır. **`rsa-1_5` asla kullanılmaz.** EncryptedKey varsayılan olarak iç yerleşimdedir.
8. `KeyInfo` içindeki `X509Certificate` yaprak sertifikadır. **İpucudur, güven kaynağı değildir.** Güven SP metadata'sından gelir.
9. ID üretimi: alt çizgi + 160 bit rastgele hex.
10. **İmzalı çıktı üretimi bir authN olayına bağlıdır**: imzalı Response yalnız tamamlanmış bir authentication oturumundan üretilir (CVE-2022-39299 sınıfı). → **IDI-7.**

**Algoritmalar (RFC 9231; MD-3 SAML istisnası).**
- Üretim varsayılanı **rsa-sha256**'dır (ekosistem istisnası).
- rsa-sha384/512 ve ecdsa-sha256/384 yapılandırmayla açılır.
- SHA-1 yalnız uyarı loglayan bir uyumluluk bayrağıyla kullanılabilir. Entra/M365 rsa-sha1 çelişkisi vardır.
- PSS ve Ed25519 yalnız tip olarak tanımlıdır, üretimde kullanılmaz.
- SHA-384 URI tuzağına dikkat edilir: `xmldsig-more#rsa-sha384` doğru URI'dir.

**NameID (MD-10).**

| Format | Kural |
|---|---|
| persistent | Varsayılan. Rastgele 32 bayt, base64url. `(identity_subject_id, sp_entity_id)` UNIQUE (`pairwise_subjects`). HMAC ile durumsuz türetme kullanılmaz (IDP-24): anahtar sızıntısı bütün ID'leri çözülebilir kılar ve anahtar rotasyonu ID'leri değiştirir. Kullanıcı isteğinde pairwise değer yenilenebilir. **Asla e-posta.** Affiliation (`SPNameQualifier`) desteklenir. |
| transient | Her assertion'da yeni üretilir. |
| emailAddress | Yalnız SP gerektirirse (Google) ve kiracı açık izin verirse. |
| unspecified | Legacy; SP başına. |

1.1 ve 2.0 format URI önek tuzağına dikkat edilir: `nameid-format:emailAddress` 1.1'dir, persistent ve transient 2.0'dır.

**Attribute'lar.** `NameFormat` varsayılan `uri`'dir; SP başına override edilebilir (örnek: MS `IDPEmail`). `FriendlyName` eşleşmede **asla** kullanılmaz.

**IdP-initiated SSO.** `allow_idp_initiated` varsayılan false'tur. Açıksa:
- `RelayState` HMAC'lenir.
- Yalnız `isDefault` ACS kullanılır.
- Assertion ömrü kısaltılır.
- `InResponseTo` yazılmaz.

**Binding'ler.**
- HTTP-Redirect: ham DEFLATE kullanılır (zlib değil). İmza dizisi `SAMLRequest|SAMLResponse=…&RelayState=…&SigAlg=…` biçimindedir ve **orijinal URL-encoded değerlerle** kurulur. `RelayState` yoksa dizide yer almaz. 302/303 döner.
- HTTP-POST desteklenir.
- `Destination` zorunludur. `RelayState` ≤80 bayttır.
- Artifact faz 3 / talep üzerine (WATCH). ECP yalnız MS zengin istemcileri için ve faz 2'dedir.

**SLO.** Yapısal olarak kırıktır, bu yüzden best effort'tur. Ön kanalda çalışır. `PartialLogout` döndürülebilir. Yerel çıkış **her zaman** başarılıdır; `session_epoch` artırılır (MD-7).

**Zaman pencereleri (PD).**
- `NotBefore` = şimdi − 60 s; `NotOnOrAfter` = şimdi + 5 dk.
- Saat kayması toleransı ±3 dk.
- `OneTimeUse` varsayılan kapalıdır.
- Zamanlar UTC `Z` ile yazılır.

**Metadata ve rotasyon.**
- `validUntil` +14 gün, `cacheDuration` PT6H. Otomatik yeniden imzalanır.
- MD IOP: PKIX yoktur; uzun ömürlü self-signed sertifika doğrudur.
- İki fazlı rotasyon: T0'da yeni sertifika eklenir; Δ ≥14 gün beklenir; T1'de imza yeni sertifikaya geçer; T1+Δ'da eski sertifika kaldırılır.
- **Entra metadata okumaz**, bu yüzden manuel prosedür gerekir.
- MDQ v1'de gereksizdir.
- Sertifika değişimi bir domain action'dır (MD-14).
- Rotasyon politikası (aralık, algoritma) ve acil sertifika değişimi domain action'dır (MD-14). Politika dahilinde zamanlanmış iki fazlı rotasyonun ve metadata'nın otomatik yeniden imzalanmasının yürütülmesi operasyoneldir, ayrı bir Exercise gerektirmez (§10.1.7).

**Saldırı yüzeyi ve savunma.**
- **XSW**: tek ayrıştırıcı kullanılır. Duplicate ID reddedilir. İmza doğrulanan düğüm ile işlenen düğüm **referans eşitliğiyle** aynı olmalıdır. → IDI-8.
- **XXE/DoS**: DTD reddedilir. Akışlı açmada 1 MB tavanı vardır (`Read::take`). Sıkıştırma oranı >100 olan girdi reddedilir. Derinlik ve eleman sayısı limitlidir.
- **Golden SAML** (ATT&CK T1606.002): imza anahtarı HSM/KMS'tedir. Her imza audit'e yazılır. Rutin rotasyon yapılır. §13'e aday: **HL** — "SAML imza anahtarının sızması tüm SP'lerde impersonation sağlar; etki SP'lerin authority'si kadardır, Access authority'si değil."
- İlgili CVE'ler regresyon derlemine girer (→ §14): 2025-25291/25292, 2025-25293, 2024-45409, 2025-29774/29775, 2017-11427/11428, 2022-39299, 2023-28119, 2018-0489, 2025-23369, 2025-54419, 2025-66578.

**SP uyumluluk profilleri.**

| SP | Gereksinim |
|---|---|
| AWS | Attribute adları `https://aws.amazon.com/SAML/Attributes/Role`, `RoleSessionName`,...; IdP-initiated akış yaygındır (bu SP için açılır) |
| Entra / M365 | Yalnız persistent NameID; ImmutableID ≤64 karakter; `IDPEmail` attribute'u; rsa-sha1 çelişkisi; POST/Redirect binding; metadata okumaz; ECP |
| Google Workspace | NameID emailAddress; attribute boyutu 2 kB sınırı |
| AWS IAM SAML federasyonu | NameID biçimi serbest (persistent, transient, emailAddress, unspecified). Zorunlu: `https://aws.amazon.com/SAML/Attributes/Role` (çok değerli, her değer `rolARN,providerARN`) ve `.../RoleSessionName` (2–64 karakter, boşluksuz); adlar büyük/küçük harfe duyarlı. Opsiyonel: `SessionDuration` (900–43200), `PrincipalTag:*`, `SourceIdentity`. Tam olarak bir `SubjectConfirmation` (`NotOnOrAfter` + `Recipient`). Şifreli assertion desteklenir ve zorunlu yapılabilir (AES-128/256, RSA-OAEP; rotasyon için 2 anahtar). Metadata yüklenir (UTF-8, BOM yok); sertifika ≥ 1024 bit, süre kontrol edilmez. Belgelenen akış IdP-initiated'dır. İmza yeri, algoritma, SLO: doğrulanmadı |
| AWS IAM Identity Center | NameID **emailAddress zorunlu**, değer IdC kullanıcı adıyla birebir. Attribute gerekmez (kullanıcılar SCIM ile). **Şifreli assertion desteklenmez.** Metadata ≤ 75.000 karakter (entityID, X509, SSO servisi). AuthnRequest imzalanmaz. Çok bölgeli kurulumda birden fazla ACS URL. İmza yeri, algoritma, SLO: doğrulanmadı |
| Salesforce | **Assertion imzası zorunlu.** RSA + SHA-1 veya SHA-256. Kimlik NameID'de veya bir attribute'ta; tip Username, Federation ID veya User ID. JIT'te Federation ID zorunlu. Şifreleme opsiyonel. SLO var. Audience varsayılanı `https://saml.salesforce.com`; Recipient = login URL; assertion ID tekrar kontrolü; zaman penceresi 5 dk ± 3 dk. Kaynak eski resmî kılavuz (Summer '21); güncel durumla aynılığı **doğrulanmadı** |
| ServiceNow | NameID Policy ve "User Field" ile yapılandırılır (ör. e-posta). Şifreli assertion opsiyonu var. SLO var. Saat kayması toleransı varsayılan **60 sn**. Metadata URL'den otomatik sertifika yenileme. İmzalı AuthnRequest opsiyonel. İmza yeri, algoritma seçenekleri, IdP-initiated: doğrulanmadı |
| Workday | Metadata tüketmez: Issuer, X509 ve SSO URL elle girilir. SP-initiated ayarı var. Ayrıntılar yalnız ikincil kaynakta (resmî belgeler girişe kapalı): **doğrulanmadı** |
| Slack | **Response imzası zorunlu.** NameID **persistent**, opak ve değişmeyen. `User.Email` zorunlu; `User.Username` ve ad alanları opsiyonel. **Yalnız HTTP-POST** binding (Redirect yok). **SLO yok.** Sertifika PEM olarak elle girilir. Entity ID `https://slack.com`, ACS `https://<alan>.slack.com/sso/saml`. JIT ve SCIM var. Algoritma: doğrulanmadı |
| Zoom | Response imzası doğrulanır. SHA-1 veya SHA-256 seçilebilir. NameID herhangi bir benzersiz tanımlayıcı. `email`, `givenName`, `sn` ve geniş attribute eşleme. Şifreli assertion opsiyonel. SLO var (imzalı logout isteği). POST veya Redirect binding. JIT var. IdP-initiated: doğrulanmadı |
| Atlassian Cloud | **Assertion imzası zorunlu.** NameID e-posta; SCIM `emails[work]` ile aynı kaynaktan eşlenir. Attribute'lar WS-Fed claim URI'leri (`givenname`, `surname`, `name`); değişmeyen kimlik e-posta olmamalı. `EncryptedAttribute` reddedilir. SLO yalnız uygulama tarafından başlatılan ve yalnız belirli IdP'lerle. Doğrulanmış alan adı gerekir. Algoritma, IdP-initiated: doğrulanmadı |

Profiller 2026-10-07'de resmî belgelerden derlenmiştir; kaynaklar: AWS IAM (`docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html`, `id_roles_providers_create_saml.html`), AWS IAM Identity Center (`docs.aws.amazon.com/singlesignon/latest/userguide/other-idps.html`), Salesforce (SSO Implementation Guide; `help.salesforce.com` `sf.sso_saml_validation_errors`), ServiceNow (`servicenow.com/docs` Yokohama, SAML 2.0 SSO), Workday (ikincil: `saml-doc.okta.com`), Slack (`slack.com/help/articles/205168057`), Zoom (`support.zoom.com` KB0060673; Zoom SSO field guide), Atlassian (`support.atlassian.com` SAML SSO ve SAML single logout). Bu profiller IDP-28 katalog şablonlarının ve IDP-40 farklılık profillerinin ilk taslağıdır; uyumluluk laboratuvarında doğrulanarak güncellenir.

**Profillerden çıkan IdP kuralları** (mevcut kurallarla uyumludur):
- Varsayılan olarak hem Response hem Assertion imzalanır (madde 6): Slack Response, Salesforce ve Atlassian Assertion imzası ister.
- RSA-SHA256 (≥ 2048 bit) varsayılandır; ECDSA hiçbir SP belgesinde doğrulanmadı. SHA-1 yalnız uyumluluk bayrağıyla açılır.
- NameID biçimi SP şablonu başına seçilir: Slack persistent/opak (pairwise varsayılanla uyumlu), AWS IdC ve Atlassian e-posta, Salesforce Federation ID veya kullanıcı adı. E-posta NameID'si yalnız şablon açıkça isterse kullanılır (MD-10).
- Attribute eşlemesi SP şablonu başına ayrıdır; çok değerli ve büyük/küçük harfe duyarlı adlar şablonda sabittir.
- Şifreleme SP başına opsiyoneldir; attribute düzeyinde şifreleme (`EncryptedAttribute`) üretilmez.
- SLO SP başına opsiyoneldir (Slack'te yok).
- Response her zaman HTTP-POST ile de gönderilebilir.
- Saat kayması toleransları dardır (ServiceNow 60 sn): IdP saati NTP ile senkron, `NotOnOrAfter` kısa, assertion ID benzersizdir.
- Metadata sunulur; ek olarak elle kurulum için PEM sertifika indirme ve SSO URL gösterimi vardır (Slack, Workday, Atlassian). Rotasyon için metadata'da birden fazla sertifika yayınlanabilir.

**21 aksiyon** (0. öncelik 1–16, 1. öncelik 17–21) uygulama planına alınır.

#### 10.6.2 SCIM 2.0 server

**RFC seti.** SCIM altı RFC'den oluşur:
- 7642 (kavramlar), 7643 (şema), 7644 (protokol)
- 9865 (imleç sayfalama, Eki 2025)
- 9944 (cihaz şeması, May 2026)
- 9967 (SET profili, May 2026)

Errata'lar uygulanır: 5368, 5606, 5607, 6004, 7522, 8415, 8361 ve PATCH için 8097 ile 7122.

**Normatif kurallar.**
- **PATCH motoru** kendimiz yazılır; hiçbir crate'te yok.
  - `add` yedi kurala uyar. Aynı değer eklendiğinde `meta.lastModified` değişmez.
  - `remove`: hedef yoksa `noTarget` döner. Olmayan bir üyeyi silmek başarıdır.
  - `replace`: eşleşme yoksa `noTarget` döner.
  - İstek atomiktir: tek operasyon başarısızsa tüm istek geri alınır.
- **Filtre**: ABNF'ye uyulur ve errata 7319, 4690, 7322, 4670 uygulanır. Derinlik, uzunluk ve sonuç sayısı DoS limitleriyle sınırlıdır. `co` operatörü indeks gerektirir.
- **Durum kodları**: 409 (uniqueness) ile 412 (ETag) ayrılır. `scimType` listesine 9865 eklemeleri dahildir.
- **Sayfalama**: indeks varsayılandır. İmleç RFC 9865'e göredir (`pagination` bloğu).
- **Projeksiyon**: önce `always` attribute'lar, sonra `default` katmanı uygulanır. `never` attribute'lar düşer.
- **Tolerans**: 17 maddelik istemci tolerans listesi vardır. İstemci başına hoşgörü katmanı uygulanır. **Entra ile Okta davranışları çelişir.** Entra uyumluluk bayrağı `aadOptscim062020`'dir.
- **SET (RFC 9967)**:
  - `sub_id` formatı `scim`'dir (`sub` değil).
  - `txn` ve `version` alanları taşınır.
  - 12 olay URI'si vardır; notice ve full modları desteklenir.
  - Asenkron yanıt `Set-Txn` header'ı ile verilir. `securityEvents` bloğu kullanılır.
  - İşlem 6 adımlı sıra izler.
  - Şifre gizlilik uyarısı geçerlidir: parola SET içinde taşınmaz.
  - Akış yönetimi SSF ile yapılır → §9.16.2.
- **Gelen SCIM bir Claim kaynağıdır** (§10.1.2). SCIM client'ı bir domain action ile kaydedilir (MD-14). Gelen grup üyeliği yalnız Acceptance ile selection'a girer (§10.1.4). Her grubun tek bir üyelik issuer'ı vardır (domain ya da belirli bir upstream SCIM client / IdP); aynı gruba ikinci bir kaynaktan üyelik yazılmaz; upstream grup mapping'i reserved bir requirement ile korunur. SCIM server ayrı süreçte koşarsa IDI-11'e tabidir.
- **Giden SCIM** (Access → SaaS) bir provisioning sonucudur. Authority'nin projection'ı değildir; IGA seam'i geçerlidir (§10.9.1).

Rust durumu: scim_v2, scim_proto ve scim-server crate'leri var ama yetersiz. Yazılacak 11 katman vardır.

#### 10.6.3 LDAP gateway

LDAP **bir uyumluluk yüzeyidir, dizin ürünü değildir**. Salt okunur LDAP kullanım durumlarının ~%95'ini karşılar → IDP-16.
- **Operasyonlar**: bind, search, unbind, abandon, StartTLS, WhoAmI desteklenir. Add, Delete ve ModDN için `unwillingToPerform` (53) döner.
- **RootDSE** ve dolu bir `cn=Subschema` sunulur.
- **Ağaç**: sahte OU modeli kullanılır.
  - `groupOfNames` ile `posixGroup` aynı girdide bulunur.
  - `memberOf` operasyonel bir attribute'tur.
  - `uidNumber`/`gidNumber` UUID'den deterministik türetilir.
- **Filtre çevirisi**: derinlik 16 ile sınırlıdır. Zincir eşleme kuralı (`1.2.840.113556.1.4.1941`) desteklenir. DN normalize edilir, kaçış kuralları uygulanır, sonuç ve süre limitleri vardır.
- **Kontroller**: paged results zorunludur. Çerez opaktır ve HMAC'lenir.
- **Kimlik doğrulama**:
  - Ayrı bir **LDAP credential sınıfı** vardır (Kanidm dersi). `dn=token` desteklenir. Bağlantı kurulduktan sonra yetki düşürülür.
  - SASL zorunlu değildir; EXTERNAL opsiyoneldir. SCRAM Argon2 ile imkânsızdır. DIGEST-MD5 asla kullanılmaz.
  - Unauthenticated bind reddedilir. Anonim erişim yalnız RootDSE içindir.
- **Taşıma**: LDAPS varsayılandır. StartTLS varsayılan kapalıdır. StartTLS açıkken TLS olmadan düz bind `confidentialityRequired` (13) döner.
- RFC 3062 parola değişimi yalnız **LDAP credential sınıfını** değiştirir. Birincil parola ve diğer authenticator'lar LDAP yolundan değiştirilemez. Değişiklik iç identity API'sinin credential değişikliği kurallarına (§12: mevcut LDAP credential'la kimlik doğrulama, kullanıcıya bildirim, `session_epoch` artışı) tabidir. Yeni `authenticator-binding` Claim'i SEC18 cooling'ine girer.
- Kütüphane `ldap3_proto` 0.8.1'dir. Ayrı süreçte çalışır (MD-1).

#### 10.6.4 Kerberos / SPNEGO

- Access **KDC olmaz**. Yalnız **SPNEGO acceptor** olur (RFC 4559). S4U2Proxy faz 2'dedir → IDP-17.
- **HTTP Negotiate akışı**:
  - Durum bağlantıya bağlıdır; HTTP/2 ve proxy'lerde bozulur. Bu yüzden ayrı bir HTTP/1.1 endpoint'i kullanılır.
  - Tarayıcı allowlist'i gerekir.
  - **Fallback zorunludur**: başarısızlıkta normal login'e düşülür.
- **Keytab**:
  - SPN birebir eşleşmelidir. AES256 kullanılır, kvno takip edilir.
  - Keytab paylaşılan bir sırdır; kasada tutulur ve bellekten yüklenir.
  - Rotasyon politikası ve acil rotasyon domain action'dır (MD-14); politika dahilinde zamanlanmış keytab rotasyonunun yürütülmesi operasyoneldir (§10.1.7).
- **AD senkronizasyonu**: LDAP çekme varsayılandır. Alternatifleri SCIM itme ve ajandır. Parola için delegasyon ya da SPNEGO kullanılır. **Hash sync (DCSync) önerilmez.**
- **NTLM kesinlikle yoktur.**
- 2026 bağlamı: Microsoft PRT'ye geçti. Kerberos yine de bir satış kapısıdır.
- **Uygulama**: libgssapi (C FFI) yalnız izole süreçte ve **ayrı imaj varyantında** kullanılır (MD-1). Kullanılacak kütüphaneler cross-krb5 ve axum-negotiate-layer'dır.

#### 10.6.5 RADIUS ve WS-Federation

MD-18'e göre ikisi de kapsamdadır. **Ayrıntılı araştırma yoktur.** Bilinen yalnız kullanım alanlarıdır ("RADIUS: ağ/VPN"; "WS-Fed: neredeyse legacy"). Aşağıdaki profil bu nedenle **çıkarım**dır ve HYPOTHESIS statüsündedir → IDP-18.
- **RADIUS** (RFC 2865; TLS üzerinden RadSec, RFC 6614): Ayrı gateway sürecinde çalışır. Tek kullanım alanı VPN/ağ erişimi için `authentication` Claim'i üretmektir. PAP yalnız RadSec içinde kullanılabilir. MS-CHAPv2 yoktur (çıkarım: NTLM türevidir, NTLM yasağıyla tutarlıdır). Faz 2'dedir.
- **WS-Federation** (passive requestor): Ayrı gateway'dedir ve SAML 1.1/2.0 token'ı üretir. §10.6.1'in XML ve imza kurallarını (izole parser, XSW, imzalı çıktı = authN) aynen devralır. Faz 2'dedir. Yalnız legacy MS/ADFS göçü için kullanılır.
- İkisi için de araştırma eksiği → §10.13.

### 10.7 Federasyon: OpenID Federation, Acceptance ve dijital kimlik cüzdanları

Beş federasyon mekanizması vardır (E19). Identity federation actor-binding Claim'leri getirir; authority federasyonu değildir. OIDF benimsenir. Bir identity issuer'ın authority issuer rolü engellenebilir (L26).

SSF/CAEP → **§9.16.2**; AuthZEN/ADP → **§9.5**.

#### 10.7.1 OpenID Federation ve Acceptance

**Durum.** OIDF 1.0 Final 17 Şub 2026'da yayımlandı. 1.1 6 May 2026'da çıktı ve 1.0'ın ayrıştırılmış halidir; yayın tarihinde kaynaklar arası çelişki vardır (§10.13). Kanıt sınırı TIIME interop (9 ülke) ile çizilir. Rust ekosistemi boştur. crates.io'da isim işgali (salasebas) uyarısı vardır. Statü: §9.4 PROFILE + EXTEND.

**Normatif profil → IDP-19.**
1. **Varlık rolleri.** Access iki rolü üstlenebilir:
   - Leaf (OP/AS, RP) rolünde fetch/list endpoint'i sunmaz.
   - Opsiyonel olarak Intermediate/TA rolünde fetch, list, resolve ve trust mark status endpoint'lerini sunar.
2. **Entity statement doğrulaması** 25 adımlı doğrulamayı izler. Path-suffix well-known (`/.well-known/openid-federation`) kullanılır.
3. **Zincir çözümleme** 8 adımdır. Zincirin geçerliliği `min(exp)`'tir. Uzunluk sınırı ve döngü tespiti zorunludur. Saat kayması 60 s'dir. Offline `trust-chain+json` kabul edilir.
4. **Metadata politikası**: yedi operatör (`value`, `add`, `default`, `one_of`, `subset_of`, `superset_of`, `essential`) sırayla uygulanır ve birleştirilir. Politika **yalnız daraltır**. Çelişkide zincir reddedilir (fail-closed). **BY SEMANTICS.**
5. **Anahtarlar**: federasyon anahtarları token anahtarlarından ayrıdır. İki katmanlı anahtar vardır (MD-6). Domain Metadata OIDF kabında taşınırsa iç nesne yayın anahtarıyla ayrıca imzalıdır; dış entity statement'ı federasyon anahtarı imzalar; verifier authority anahtarlarını yalnız iç nesneden alır (→ §9.15).
6. **Trust mark**: `trust_mark_type` alanı kullanılır (OIDF'in önceki taslaklarında `id`). Trust mark status endpoint'i sorgulanır, sonuç önbelleklenir.
7. **Kayıt**: otomatik kayıt (`jti` + `exp` replay kontrolü) ve açık kayıt desteklenir. Her ikisi de kiracı başına varsayılan kapalıdır.
8. **Cache ve TA yükü**: zincir sonuçları `min(exp)` süresince önbelleklenir. TA'ya giden istekler oran sınırlıdır. Fetch SSRF korumalıdır.

**OIDF ile Acceptance ilişkisi → IDP-20, IDI-9.**
- Bir trust chain ya da trust mark **Acceptance değildir**. Onay (AAS) **atlanamaz**.
- Trust mark yalnız açıkça kaydedilmiş bir Acceptance'ın `predicate-input`'u olabilir. Etkisi yalnız şunlardır: (i) bir RequirementTerm/RestrictionPolicy girdisi (daraltma), (ii) render'a **ek** bilgi (ör. consent ekranında "doğrulanmış federasyon üyesi" rozeti). UI'a rozet ekler; render daraltılamaz: render'dan alan çıkarılamaz, `material_fields` ve CT'nin tam render koşulu (§13.7.3) değişmez. Grant oluşturmak yine AAS ister.
- "Güven seviyesi birinci sınıf alan" fikri korunur (§10.1.2 resolver kural 4). Bu alan politika girdisidir, authority değildir.
- **Zincir kaybı:** OIDF zinciri artık çözülemiyorsa (TA iptali, `exp`, politika çelişkisi) o issuer'dan gelen Claim girdisi **ileriye dönük** kesilir (ingest-time cutoff). Acceptance kaydı **iptal edilmez**. Acceptance yönetim kararıdır ve ADP ile değişir. Zincir geri geldiğinde Claim girdisi otomatik yeniden başlar. Garanti: **BY SEMANTICS** (fail-closed girdi kesimi).
- Identity issuer'ın authority issuer rolü Domain politikasıyla engellenebilir (L26). Varsayılan engelli; `foreign-authority` kullanımı açık Acceptance ister.

**İstemci çözümleme sırası**: DCR / CIMD / OIDF tek resolver'dan geçer (§10.1.2). URL biçimindeki `client_id` için önce OIDF denenir. Bu AS tarafı sıradır; istemci tarafı kayıt yolu seçimi §11.3.8'dedir.

#### 10.7.2 Doğrulanabilir kimlik bilgileri, OID4VP ve EUDI Wallet

**Statü (§9.4):**
- VC: PROFILE.
- SD-JWT (RFC 9901): ADOPT.
- OID4VCI/OID4VP/HAIP: PROFILE.

**Standart durumu.**
- OID4VP 1.0 Final (Tem 2025), OID4VCI 1.0 (Eyl 2025), HAIP (Ara 2025).
- Formatlar: SD-JWT VC ve mdoc (ISO 18013-5 mDL).

**EUDI takvimi.**
- 2024/1183 yürürlüktedir.
- **Aralık 2026**: her üye devlet bir wallet sunmak zorundadır.
- **Aralık 2027**: düzenlenmiş özel sektörde kabul zorunluluğu başlar.
- ARF 3.0.0 (Temmuz 2026) yayımlandı.

**Normatif profil → IDP-21.**
1. Access bir **verifier (RP)** olarak başlar. Issuer rolü yoktur. Issuer rolü WATCH'tadır.
2. **Ayrı servis**: OID4VP verifier ayrı bir bileşendir. Doğrulanan sunum bir `identity-binding.person` ya da attribute Claim'i üretir ve Claim Ingest'ten geçer.
3. Sunumun authority etkisi **yalnız Acceptance** iledir (`predicate-input` ya da `actor-binding`). VC tek başına authority değildir (PI-3). **BY SEMANTICS.**
4. Same-device ve cross-device modları desteklenir. Cross-device QR akışı oturum-sabitleme (phishing) riski taşır; DCQL ile minimum attribute istenir (çıkarım: veri minimizasyonu, GDPR).
5. Issuer güveni EUDI trusted list / LoTL üzerinden kurulur. Güven listesi Acceptance'ın `schema-definition` ve `actor-binding` girdisidir.
6. `loa_eidas=high` yalnız PID sunumu ile set edilir (§10.3.2).
7. RP efor tahmini: 4–6, 8–12, 2–4, 2–4 ve 4–8 hafta.

**DID/SSI**: DID v1.0 (2022) Recommendation'dır, v1.1 yorum aşamasındadır. SSO'nun yerini almaz. Access verifier tarafında `did:web` ve `did:jwk` çözer (çıkarım), diğer yöntemler WATCH'tadır. → §10.9.

### 10.8 Gelecek standartları: WebAuthn L3/L4, CTAP, CXF, DBSC

#### 10.8.1 WebAuthn, CTAP ve CXF

**Durum ve MD-18 doğrulama işareti.**

| Konu | Durum | MD-18 işareti | Bu spec'teki kullanım |
|---|---|---|---|
| WebAuthn Level 3 | W3C Recommendation, **25 Ağu 2026**. CR 26 May 2026'dan beri değişiklik yok. | "Doğrulanmadı" korunur | L3 özellikleri (BE/BS, Signal, conditional create, hybrid) **normatif hedef**tir. Statü tarihi "bağımsız doğrulanmadı" diye anılır. |
| WebAuthn Level 4 | FPWD 9 Eyl 2026; hedef 2028 Q4 | — | WATCH. İzlenen issue'lar: #2291 (immediate), #2078 (sign), #2437 (algoritma göçü), #2393 (ML-DSA), #2377, #2150 |
| CTAP | 2.1; 2.2 (14 Tem 2025); **2.3 (26 Şub 2026)**; 2.3.1 WD | "Doğrulanmadı" korunur | CTAP 2.3 hedef alınır; sürüm tarihi bağımsız doğrulanmadı |
| FIDO Server Requirements 2.3 | ML-DSA-44/65/87, ESP256/384/512, Ed25519 | — | ESP256 ve Ed25519 gün-1'de. ML-DSA WATCH (→ §15) |
| CXF | 1.0 Proposed Standard (14 Ağu 2025) + errata | — | İçe aktarılan credential'da sayaç sıfırlanır ve AAGUID eskir. Bu yüzden içe aktarım yeni `authenticator-binding` Claim'idir (SEC18 cooling). |
| CXP | WD (3 Eki 2024) | — | WATCH |

Kural (MD-18): Normatif davranış "Durum" sütununa dayanır. Statü ve tarih iddiaları "doğrulanmadı" işaretini korur (§10.13). Bunlar W3C/FIDO sayfalarından bağımsız teyit edilene kadar **WATCH-verify** etiketindedir.

**WebAuthn/CTAP aksiyon listesi (12 madde)** §10.2.4'te normatif kurallar olarak yer alır.

#### 10.8.2 DBSC — Device Bound Session Credentials

- Durum: Chrome 146, Nisan 2026, Windows'ta GA.
- MD-13 kararına göre DBSC identity plane'e aittir.
- Profil (→ IDP-22): **PROFILE, kiracı başına opt-in.**
  - Tarayıcı oturum çerezi cihaz anahtarına (TPM) bağlanır.
  - Kısa ömürlü çerez yenilemesi DBSC kanıtı ister.
  - Kanıt başarısızsa oturum `session_epoch` artışıyla düşürülür (MD-7).
  - Destekleyen tarayıcı yoksa davranış değişmez (progressive).
- Garanti: Infostealer çerez hırsızlığına karşı koruma **UNDER DECLARED CAPABILITY**'dir (tarayıcı ve TPM desteği şarttır). Aynı cihazda çalışan malware'e karşı **NOT GUARANTEED**'dir.
- Oturum yaşam döngüsü ayrıntısı → §12.

#### 10.8.3 Algoritmalar, PQC ve TLS

Kripto ayrıntısı **→ §15**. Identity plane'e etkisi:
- JOSE ve COSE algoritmaları için MD-3 geçerlidir (§10.4.5).
- RFC 9864 fully-specified tanımlayıcılar kullanılır. Polimorfik `alg: EdDSA` reddedilir.
- JWKS'te `kty: AKP` (ML-DSA, RFC 9964) gün-1'de modellenir. Varsayılan kapalıdır.
- Token boyutu: ML-DSA-44 imzası 2.420 B'dir. Bu boyut header ve çerez sınırlarını etkiler → §15.
- JWE için PQ yöntemi yoktur → WATCH.
- FIDO PQC 2028+ beklenir. WebAuthn ML-DSA L4 #2393 ile izlenir.
- TLS 1.3 kullanılır; hibrit anahtar değişimi X25519MLKEM768'dir → §15.
- SAML'de PQ yoktur; rsa-sha256 ekosistem istisnası sürer (MD-3).

### 10.9 Ekosistem eki — bilgilendirici

Bu alt bölüm **bilgilendiricidir (informative)**. Normatif bir kural taşımaz. Ürün, sürüm ve satın alma bilgileri (Ekim 2026) tek ikincil kaynağa dayanabilir; bir kısmı doğrulanmamıştır.

#### 10.9.1 Komşu kategoriler ve Access seam'i

| Kategori | Örnek ürünler | Access ile ilişki | Seam kuralı |
|---|---|---|---|
| IGA | SailPoint, Saviynt, Omada, One Identity, Entra ID Governance, Okta IG | Erişim kampanyaları, SoD, SOX 404 | IGA kararları Exercise talebi olarak gelir; Grant authority plane'de verilir |
| PAM | CyberArk, BeyondTrust, Delinea, Saviynt, Teleport, HashiCorp Vault | Secret ve oturum kasası | Access secret tutmaz. Karar kuralı: oturum kaydı ve secret kasası PAM'dedir; "kim, neyi, hangi şartla" Access'tedir |
| Ulusal eID | 51 ülkede 86 şema | `identity-binding.person` kaynağı (upstream IdP ya da EUDI) | Acceptance ile girer. Çoğu şema sınır ötesi çalışmaz. "ID phone home" eleştirisi (merkezi eID'nin RP kullanımını görmesi) not edilir |
| DID/SSI | DID v1.0 (2022), v1.1 yorumda | Verifier olarak başla; SSO'nun yerini almaz | §10.7.2 |
| Biyometri | NEC (NIST FRTE) ve diğerleri | Upstream IDV/KYC girdisi | Platform biyometrisi tek başına güçlü unsur değildir (MD-11). Satıcı doğruluk iddiaları NIST FRTE ile karşılaştırılır |
| KYC/IDV | İHS Udentify, SCSoft ve diğerleri | `identity-binding.person` + IAL kanıtı | Claim; `predicate-input` |
| Fraud / risk motorları | — | Risk skoru | Claim; karar ADP'de verilir (→ §9, §12) |
| RASP / uygulama koruması | — | Cihaz bütünlüğü | "Çıktı sinyaldir" (P-ID-7) |
| Bot yönetimi | — | Oran ve bot sinyali | → §12 |
| Mobil imza / operatör | TR operatör mobil imza | Upstream assertion | §10.2.5 |

#### 10.9.2 Senaryo playbook'ları ve IoT

B2C, B2B SaaS, kurumsal workforce, finans, sağlık, kamu, e-ticaret, mobil-öncelikli ve geliştirici platformu senaryoları Access'te **realm şablonu** olarak hazırlanır. Şablon realm politikasının varsayılanlarıdır (yöntem seti, CT eşlemesi, profil) ve ADP commit ile uygulanır. Şablon kataloğu → §12.

**IoT.** Matter cihaz attestation zinciri (DAC/PAI/PAA), DPP, BRSKI/EST/MUD, FIDO Device Onboard (FDO) ve zero-touch provisioning bu kapsamdadır. Access'te bunlar `runtime-attestation` ve workload `identity-binding` Claim kaynaklarıdır. Ayrı protokol uygulaması **WATCH**'tadır. Workload kimliği (SPIFFE) → §11.

#### 10.9.3 Ürün karşılaştırması

Özet:

| Ürün | Dil / lisans | Protokol kapsamı (özet) | Access'e göre fark |
|---|---|---|---|
| Keycloak 26.7 | Java, Apache-2.0 | OIDC, SAML, SCIM (önizleme), LDAP-src, Kerberos, passkey, FAPI 2, DPoP, CIBA; MCP/CIMD/ID-JAG (deneysel) | Authority plane yok; realm modeli var |
| ZITADEL v4 | Go, AGPL-3.0 | OIDC, SAML, LDAP-src, passkey, SCIM | Event-sourced, Organizations; authority plane yok |
| authentik 2026.8 | Python+Go, open core | OIDC, SAML, SCIM, LDAP-srv, RADIUS, WS-Fed (ent.) | Kenar protokol kapsamı geniş |
| Ory (Hydra/Kratos/Keto) | Go, Apache-2.0 + ticari | Hydra OIDC (sertifikalı), Keto Zanzibar | Fosite (MD-1 regresyon kaynağı) |
| WSO2 IS 7.2 | Java | OIDC, SAML, SCIM 2, WS-Fed, FAPI 2 (sertifikalı) | Ajan kimliği birinci sınıf |
| Kanidm v1.11 | Rust, MPL-2.0 | OIDC, salt okunur LDAPS, passkey, RADIUS; SAML yok | LDAP modeli için referans (§10.6.3) |
| Rauthy v0.36 | Rust, Apache-2.0 | OIDC, passkey; SAML/LDAP yok | Enumeration/zamanlama modeli referansı (§10.2.1) |
| Okta / Entra / Ping / Auth0 | Ticari SaaS | Tam workforce/CIAM | Kapalı; authority plane yok |

**Gözlemler:**
1. Ajan kimliği 2026'da standart özellik oldu.
2. Tam özellikli bir Rust IdP (SAML + OIDC + SCIM + çok kiracılık) yok. Access bu boşlukta konumlanır.
3. Konsolidasyon hızlı.

Rekabet konumlandırması → §1–§3.

### 10.10 Karar register'ı (IDP-n)

Sütunlar:
- **Statü**: FROZEN, PD (POLICY DEFAULT), EA (ENGINEERING ASSUMPTION), HYPOTHESIS ya da WATCH.
- **Garanti**: BS (BY SEMANTICS), UDC (UNDER DECLARED CAPABILITY/POLICY; tek sınıf, §3.3; policy kaynaklı satırlar "UDC (policy)" yazılır) ya da NG (NOT GUARANTEED).

| ID | Karar | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| IDP-1 | Identity plane Claim'leri §10.1.2 tablosundaki protokol başına alan eşlemesiyle üretilir. Eşleme dışı alan Claim'e girmez. DCR/CIMD/OIDF tek resolver'dan geçer; URL `client_id` asla yerel kayda düşmez; çözümleme sonucu `trust_level` alanı taşır; bu AS tarafı sıradır, istemci tarafı kayıt yolu seçimi §11.3.8 | FROZEN | BS | Tek taşıyıcı tablo ve tek resolver sırası | §9.13 |
| IDP-2 | Identity plane kullanıcı kaydı `IdentitySubject` adını alır (identity plane nesnesi, primitive değil). Authenticator değişimi Instance'ı değiştirmez, yeni `authenticator-binding` Claim'idir (kurtarma hariç; kurtarma successor Instance'tır, INV-13) | FROZEN | BS | L21, C7; isim çakışmasını önler | — |
| IDP-3 | Parola: Argon2id, varsayılan parametreler CR-36 (§15.14: m = 7 MiB, t = 5, p = 1); PBKDF2 yalnız FIPS; AES-GCM pepper; NIST 800-63B-4 politikası; HIBP k-anonymity; dummy Argon2 yok, adaptif gecikme + varlıktan bağımsız semafor (MD-18) | PD (parametreler), FROZEN (dummy hash yok) | UDC (policy) | — | MD-18 |
| IDP-4 | SMS OTP varsayılan kapalı; magic link tüketen GET değildir ve başlatan cihaza bağlanır; push number matching zorunludur (aynı cihaz istisnası); push/TOTP/OTP/parola hiçbir CT'nin authenticator class koşulunu tek başına karşılamaz (yalnız oturum girişi ve ikinci faktör) | PD | BS (CT eşlemesi) / UDC (policy) | Phishing-resistant olmayan yöntemler CT1+ karşılayamaz (§13.7.3) | — |
| IDP-5 | RP ID realm başına; kiracı özel alan adı passkey'den önce sabitlenir; RP ID değişimi geri dönülemez domain action'dır (ADP commit, CT3); related origins ≤5, yalnız kendi markası | FROZEN | BS | Passkey kaybı geri alınamaz | MD-5, MD-14 |
| IDP-6 | WebAuthn kütüphanesi webauthn-rs 0.5.5 (denetimli). PRF ve BE/BS için `danger-credential-internals` ya da upstream PR. Upstream PR tercih edilir (çıkarım: bakım yükü) | EA | — | Tek denetimli Rust RP kütüphanesi | — |
| IDP-7 | Grant tablosu §10.4.1: AuthCode+PKCE varsayılan; Device Flow varsayılan kapalı ve DPoP bağlı; Implicit/ROPC yok; redirect URI tam eşleşme | FROZEN | BS | OAuth 2.1 / RFC 9700 | §9.4 |
| IDP-8 | CT tablosuna identity plane karşılama koşulları eklenir (§10.3.3): senkronize passkey CT3'ü karşılamaz; upstream IdP CT3'ü varsayılan karşılamaz; RFC 9470'te `max_age` zorunlu | PD | BS (eşleme) | CT tablosunu daraltır, değiştirmez | — |
| IDP-9 | TR ödeme realm şablonu: uygulama-kontrollü faktör zorunlu, platform biyometrisi tek başına yetmez, SMS yalnız kurulum/aktivasyon, SIM değişimi sonrası 90 gün SIM yöntemi yok | PD (şablon) | UDC (policy); mevzuat uygunluğu NG | MD-11 | MD-11 |
| IDP-10 | JOSE: ES256 varsayılan, Ed25519 seçmeli, RS256 client başına opt-in (yalnız kimlik iddiaları; authority taşıyan access token domain operasyonel anahtarıyla, RSA'sız); alg allowlist client metadata'dan; JWKS publish-before-use, emekli anahtar en uzun token ömrü kadar tutulur; access token 5–15 dk (üst sınır; §13.7.2) | FROZEN (alg), PD (ömür) | BS | Merkezi kararların identity plane uygulaması | MD-3, MD-6, MD-7 |
| IDP-11 | DPoP profili: 12 adımlı doğrulama; uzun ömürlü paylaşılan durumsuz nonce + bayat nonce penceresi + öngörülü nonce; replay TTL = kanıt ömrü + 2×skew; `BLAKE3(htm‖htu‖jti)` anahtar; RS tarafı replay'i kendi yapar | FROZEN (yapı), PD (süreler) | BS (bağ) / NG (anahtar hırsızlığı) | MD-18 | — |
| IDP-12 | FAPI 2.0 client başına `profile=fapi2`: sender-constrained, confidential, `private_key_jwt`/mTLS, PAR zorunlu; RSA imza yok (PS256 desteklenmez, RS256 opt-in açılamaz); OIDF FAPI 2.0 OP sertifikası hedeflenir | FROZEN (profil), WATCH (sertifika tarihi) | UDC (policy) | §9.4 ADOPT satırının uygulama profili | §9.4 |
| IDP-13 | FiPA PROFILE, varsayılan kapalı, yalnız first-party (SPA dışı), istemci kanıtlaması zorunlu, tarayıcıya düşebilir; taslak expire olursa kapalı kalır | WATCH | UDC (policy) | draft-04 | — |
| IDP-14 | CIBA: poll varsayılan, ping opsiyonel, **push reddedilir**; `binding_message` bağlayıcı değil; onay AAS; `auth_req_id` ↔ REQUIRE_ACTION eşlemesi §9.14.5 k.2 | PD (push reddi HYPOTHESIS: çıkarım) | BS (CIBA ≠ authority) | Push modu token'ı client'a doğrudan iter; FAPI-CIBA ile uyumsuz (çıkarım) | §9.4 |
| IDP-15 | SAML IdP: izole parser worker, bergshamra + kendi SAML katmanı + `XmlSigner` trait, imza HSM/KMS; ACS tam eşleşme; imzalı çıktı = authN; IdP-initiated varsayılan kapalı; rsa-sha256 varsayılan; persistent NameID rastgele + pairwise | FROZEN | BS (kurallar) / UDC (parser izolasyonu) | CVE geçmişi | MD-1, MD-3, MD-18 |
| IDP-16 | LDAP: salt okunur uyumluluk yüzeyi, ayrı LDAP credential sınıfı (RFC 3062 yalnız bu sınıfı değiştirir), LDAPS varsayılan, anonim yalnız RootDSE, yazma operasyonları 53 | FROZEN | BS | Kullanım durumlarının ~%95'i | — |
| IDP-17 | Kerberos: yalnız SPNEGO acceptor, KDC değil, NTLM yok, libgssapi ayrı imaj varyantında; AD sync LDAP çekme varsayılan; DCSync önerilmez | FROZEN | UDC | Güvenlik ve kapsam sınırı | MD-1 |
| IDP-18 | RADIUS (RadSec, PAP yalnız TLS içinde, MS-CHAPv2 yok) ve WS-Fed (SAML kurallarını devralır) faz 2, ayrı gateway | HYPOTHESIS | UDC | MD-18 kapsamda tutar; ayrıntılı araştırma yok | MD-18 |
| IDP-19 | OIDF profili: leaf fetch/list sunmaz; 7 operatör yalnız daraltır, çelişkide ret; chain = min(exp); federasyon anahtarı ≠ token anahtarı; otomatik/açık kayıt varsayılan kapalı | FROZEN | BS | Fail-closed federasyon | §9.4 |
| IDP-20 | Trust chain/trust mark Acceptance değildir; onay atlanmaz; trust mark yalnız kayıtlı Acceptance'ın `predicate-input`'u (UI'a rozet ekler; render daraltılamaz). Chain kaybında Claim girdisi ileriye dönük kesilir, Acceptance iptal edilmez | FROZEN | BS | PI-3; Acceptance yönetim kararıdır | — |
| IDP-21 | VC/OID4VP: Access önce verifier; ayrı servis; sunum yalnız Acceptance ile etki eder; `loa_eidas=high` yalnız PID sunumundan | PD; issuer rolü WATCH | BS (PI-3) | EUDI takvimi Ara 2026/Ara 2027 | §9.4 |
| IDP-22 | DBSC PROFILE, kiracı başına opt-in, kanıt hatası `session_epoch` artışı | WATCH → PD | UDC / NG (yerel malware) | Infostealer savunması | MD-7, MD-13 |
| IDP-23 | SCIM server: kendi PATCH motoru (atomik), 6 RFC, istemci başına tolerans katmanı (Entra `aadOptscim062020`), RFC 9967 SET; gelen SCIM Claim kaynağıdır, grup → selection yalnız Acceptance ile | FROZEN | BS (seam) | provisioning ≠ Grant | — |
| IDP-24 | Pairwise `sub`/NameID varsayılan, rastgele değer tablosu (HMAC değil); back-channel logout varsayılan, front-channel opt-in, Session Mgmt iframe yok; Native SSO PROFILE/WATCH | PD | BS (yeni token yok) / NG (RP oturumu) | MD-10; üçüncü taraf çerez kısıtları | MD-10 |
| IDP-25 | Protokol sırası: SCIM → SAML → LDAP → OIDF → Kerberos (AD sync öne alınır); toplam ~95 hafta | PD | — | Satış kapısına göre değişebilir | — |
| IDP-26 | Kenar gateway süreçleri issuer değildir; realm issuer'ı adına, gateway başına iç kimlikle, mTLS iç kanaldan Claim ürettirir | FROZEN | UDC | Süreç izolasyonu; TI-15 | MD-1 |
| IDP-27 | Upstream IdP `acr`/`amr`/`AuthnContextClassRef` assurance'a yalnız Acceptance eşleme tablosuyla girer; eşleme yoksa en düşük sınıf | FROZEN | BS (eşleme) / NG (upstream doğruluğu) | F17; E18 | — |
| IDP-28 | **SSO uygulama kataloğu.** En çok kullanılan 50–100 SaaS uygulaması için küratörlü SAML/OIDC bağlantı şablonları sunulur; bakımı Access ekibindedir. Şablon veridir (attribute eşlemesi, NameID biçimi, imza/şifreleme ayarı, metadata URL'si), kod değildir (F23). Şablondan bağlantı kurmak realm config değişikliğidir ve yönetişim domain'inde `idp.*` domain action Exercise'ıdır (MD-14). Şablon authority-selecting claim eşlemesi içeriyorsa L6 reserved requirement'ı uygulanır. Katalog kapsamı ve önceliği PD'dir | FROZEN (katalog var, veri biçimi); PD (kapsam, öncelik) | UDC (şablonun uygulamayla uyumu) | Workforce satışında katalog giriş koşuludur; elle yapılandırma hata ve kurulum süresi üretir | MD-14; F23; L6 |
| IDP-29 | **Giden provisioning.** Giden SCIM 2.0 client Faz 1'dedir: kullanıcı ve grup yaşam döngüsü SCIM destekleyen uygulamalara itilir. SCIM desteklemeyen uygulamalar için uygulamaya özel bağlayıcı Access'te yoktur; bu ayrı ürün katmanıdır (IGA / entegrasyon platformu, E22). Giden SCIM bağlantısı realm config'tir (`idp.*` domain action, MD-14). Gönderilen üyelik hedef uygulamada authority yaratmaz; hedefin kendi yetkilendirmesidir | FROZEN | UDC (teslim, hedefin SCIM uyumu) | Workforce yaşam döngüsü (JML) uçtan uca kapanır; uygulamaya özel bağlayıcı kodu Access'e girmez | MD-14; E22 |
| IDP-30 | **İç uygulama koruması: forward-auth ve Access Proxy.** (1) **Forward-auth uç noktası:** Access, Nginx (`auth_request`), Traefik (ForwardAuth), Caddy (`forward_auth`) ve Envoy (`ext_authz`) protokollerine cevap verir; kiracının kendi proxy'si Access'e bağlanır. Proxy PEP'tir, Access karar verir: her istek gerçek bir Access kararıdır (süre, iptal, ajan erişimi dahil); karar önbelleği ValidityContract'a bağlıdır. (2) **Access Proxy:** proxy'si olmayan kiracı için Access'in sunduğu hazır kapı; kurulumda iki motordan biri seçilir: **Envoy** (büyük kurulum, Kubernetes) veya **Caddy** (küçük/orta kurulum, otomatik HTTPS). Proxy sıfırdan yazılmaz; motorlar hazır paketlenir (Docker imajı, Kubernetes şablonu). Kiracı tek bir ayar dosyası yazar; yapılandırma aracı bunu seçilen motorun (ve Traefik'in) ayarına çevirir; motor değişiminde ayar dosyası aynı kalır. İki motor ortak davranış testlerinden geçer. (3) **Uygulamaya giden kimlik:** Access'in imzaladığı kısa ömürlü token; düz kimlik header'ı yalnız uyumluluk için gönderilir ve uygulamaya yalnız proxy üzerinden erişilebilmesi koşuluna bağlıdır (dokümantasyon ve kurulum kontrolü) | FROZEN (forward-auth, karar = Access kararı, imzalı token); PD (motor listesi, önbellek süresi) | BS (karar kaydı) / UDC (proxy'nin kararı uygulaması) / NG (proxy atlatılarak doğrudan erişilen uygulama) | Proxy'nin sorusu Access'in tek sorusudur; iç uygulamalar kod değişikliği olmadan korunur | F7; L11; B22 |
| IDP-31 | **Sosyal giriş sağlayıcıları.** (1) **Gün-1:** Google, Apple, Microsoft (kişisel ve iş hesabı), GitHub, LinkedIn, Facebook; ayrıca her OIDC/OAuth2 sağlayıcısı için genel bağlayıcı. (2) **İkinci dalga (talebe göre):** Discord, Slack, GitLab, X, Amazon; Asya: LINE, Kakao, Naver, WeChat. (3) **Tanım veridir** (F23): adresler, istenen izinler, logo ve **e-posta güvencesi** (sağlayıcı e-postayı doğruluyor mu, hangi alan adları için yetkili). Yalnız e-posta eşleşmesiyle hesap bağlanmaz; bağlama açık bir işlemdir (§12.3.3) ve sağlayıcının doğrulamadığı e-posta hiçbir zaman eşleme anahtarı olmaz (nOAuth sınıfı). (4) **Geliştirme anahtarları:** geliştirme/sandbox realm'inde Access'in ortak test anahtarlarıyla sosyal giriş hemen çalışır; üretim realm'inde kiracının kendi anahtarı zorunludur ve ortak anahtarlar üretimde reddedilir. (5) **Apple:** iOS'ta başka sosyal giriş açılırsa konsol App Store gizlilik kuralı uyarısı verir ve Apple ile girişi önerir. Sağlayıcı eklemek/açmak realm config'tir (`idp.*` domain action, MD-14) | FROZEN (veri biçimi, e-posta kuralı, üretimde ortak anahtar yasağı); PD (sağlayıcı listeleri) | UNDER DECLARED CAPABILITY (sağlayıcının beyanı) / BY SEMANTICS (doğrulanmamış e-postanın eşleme anahtarı olmaması) | B2C kayıt dönüşümü; beş dakikada çalışan giriş | F23; MD-14; §12.3.3 |
| IDP-32 | **Linux ve SSH erişimi.** (1) **SSH sertifika otoritesi:** Access kısa ömürlü OpenSSH kullanıcı sertifikaları verir; sertifika bir projection'dır (holder-bound, ValidityContract'a bağlı, varsayılan ömür PD). Sertifikanın principal'ları (sunucu kullanıcı adları) ve kapsamı (sunucu grupları, `force-command`/`source-address` gibi kısıtlar) kişinin veya ajanın Grant'larından türetilir; sertifikanın kendisi authority kaynağı değildir. Sunucular realm'in SSH CA anahtarına güvenir; kalıcı kullanıcı anahtarı gerekmez. Komut satırı aracı (`access ssh login`) tarayıcıda passkey/MFA girişiyle sertifika alır. Ajanlara aynı yolla dar kapsamlı, kısa ömürlü sertifika verilir. (2) **PAM/NSS modülü ve Linux istemcisi:** Access'in Linux istemcisi (ayrı daemon, Rust) NSS ile kullanıcı/grup çözümlemesini, PAM ile konsol girişini ve `sudo`'yu Access'e bağlar. Konsol girişi ve `sudo` passkey (yerel FIDO2) veya tarayıcı/telefon onayıyla (device flow) yapılır; `sudo` bir step-up'tır ve CT sınıfına göre RequirementTerm uygular. Önbellek: çevrimdışı sunucuda NSS verisi ve son başarılı kimlik doğrulama ValidityContract horizon'u içinde kullanılır; horizon aşılırsa fail-closed (MD-8); yerel acil erişim yalnız önceden verilmiş reserved break-glass Grant'ıyla (SI-22). (3) **Kapsam dışı:** oturum kaydı ve aracılığı ayrı ürün katmanıdır (E22); KDC yoktur (IDP-17) | FROZEN (sertifika = projection, Grant'tan türetme, fail-closed önbellek); PD (sertifika ömrü, önbellek süreleri) | BY SEMANTICS (sertifika kapsamı ⊆ Grant); UNDER DECLARED CAPABILITY (sunucunun CA ve PAM yapılandırması) | Kalıcı SSH anahtarlarının yarattığı deprovisioning açığı kapanır; Linux konsol ve `sudo` passkey ile korunur; ajan sunucu erişimi dar ve süreli olur | E22; SI-22; MD-8; IDP-17 |
| IDP-33 | **Akademik federasyon öncelikli segment değildir.** CAS protokolü talep üzerinedir (WATCH): yalnız gerçek bir müşteri ihtiyacında eklenir. eduGAIN için özel yatırım yapılmaz: SAML metadata toplu sorgusu (MDQ) Faz 3'te WATCH olarak kalır; akademik özellik setleri (`eduPerson*`) ve REFEDS profilleri (R&S, SIRTFI, MFA) yalnız talep gelirse eklenir. OpenID Federation (§10.7.1) ve RADIUS (eduroam dahil) mevcut plandadır | PD (segment önceliği); WATCH (CAS, eduGAIN profilleri) | — | Akademik pazar öncelikli değildir; kapsam büyütülmez | §10.7.1; IDP-25 |
| IDP-34 | **e-Devlet ve kimlik tespiti (KYC).** (1) **e-Devlet:** hazır upstream bağlayıcısı yalnız kamu kurumu müşterileri içindir; kullanım kurumun e-Devlet Kapısı entegrasyon protokolüne bağlıdır. e-Devlet'ten gelen kimlik bilgisi actor-binding Acceptance'ı olan bir Claim'dir (TN-95 kuralları). (2) **Access KYC uygulaması değildir:** NFC kimlik kartı okuma, yüz eşleştirme, canlılık testi ve uzaktan kimlik tespiti Access'te yapılmaz. Kimlik tespiti sonucu, kiracının Acceptance ile kabul ettiği dış bir sağlayıcıdan Claim olarak gelir (kim doğruladı, yöntem, güvence seviyesi: NIST IAL / eIDAS LoA, zaman); Access bu Claim'i requirement ve predicate girdisi olarak kullanabilir (ör. belirli tutarın üstü için tespit edilmiş kimlik şartı). Access kendi yöntemleriyle tespit güvencesi iddia etmez (§10.3.2) | FROZEN (Access KYC yapmaz; sonuç = Claim); PD (e-Devlet bağlayıcısının kapsamı) | UNDER DECLARED CAPABILITY (sağlayıcının tespit doğruluğu) | e-Devlet kimlik doğrulama hizmeti kamu kurumlarına açıktır; kimlik tespiti ayrı uzmanlık alanıdır | §10.3.2; TN-95; MD-11 |
| IDP-35 | **İK kaynaklı provisioning ve JML.** (1) **Alım:** gün-1'de genel alım yolu: gelen SCIM, toplu API ve CSV yükleme; İK verisi (departman, unvan, yönetici, başlama/çıkış tarihi, istihdam durumu) İK issuer'ından gelen Claim'dir. Workday, SAP SuccessFactors, BambooHR, HiBob, Personio ve Türkiye'de yaygın İK yazılımları için hazır bağlayıcılar aşamalı gelir; bağlayıcılar Access'in yanında çalışan ayrı bir servistir, Access çekirdeğine kod girmez (IDP-29 ile aynı ilke). İK kaynağının kabulü `subject-selection` Acceptance'ıdır ve CT3'tür (TN-95). (2) **İşe giren:** hesap açılır; departman/unvana göre temel yetkiler rule-shaped Grant ile gelir (C13); passkey kurulum daveti gönderilir. (3) **Pozisyon değiştiren:** eski seçimden düşülür, yenisine girilir; rule-shaped Grant gereği elle silme gerekmez; reserved/CT3 kapsamlı Grant'ta yeni holding episode'u 24 s soğumaya tabidir (TN-109). (4) **Ayrılan:** hesap anında askıya alınır, oturumlar kapanır (`session_epoch`), bağlı uygulamalara CAEP sinyali gider; sorumlusu olduğu ajanlar askıya alınır (AG-41); veri silinmez, saklama kuralları uygulanır (TN-H5). (5) **İleri tarihli kayıtlar** (başlama/çıkış tarihi) tarihinde otomatik işlenir | FROZEN (İK = Claim, CT3 kabul, ayrılanda askı, ajan askısı); PD (bağlayıcı listesi ve sırası) | BY SEMANTICS (rule-shaped seçim, askı sonrası exercise yok); UNDER DECLARED CAPABILITY (İK verisinin zamanında gelmesi) | Yetki birikmesi ve unutulan hesaplar kapanır; JML uçtan uca otomatikleşir | C13; TN-95; TN-109; AG-41 |
| IDP-36 | **Kiracı analitiği.** Konsolda hazır analitik paneli kiracıya şu soruların cevabını verir: (1) kayda/girişe kaç kişi başladı, kaçı bitirdi, en çok hangi adımda vazgeçildi (adım bazında huni); (2) kullanıcılar hangi yöntemle giriş yapıyor (passkey, sosyal giriş, parola, SSO); (3) passkey kullanan kullanıcı oranı zaman içinde nasıl değişiyor; (4) MFA kurulumunu kaç kişi tamamladı; (5) kaç kişi parolasını unuttu, kaçı hesabını kurtarabildi; (6) başarısız giriş denemelerinde ani artış var mı (saldırı belirtisi uyarısı). Ek olarak ajan göstergeleri: aktif ajan sayısı, ret oranı, en çok kullanılan bağlantılar. Ham olaylar webhook'larla kiracının kendi analitik aracına aktarılabilir. **Kurallar:** veriler toplu ve kişisel veri içermeden gösterilir; analitik hiçbir zaman karar, restriction veya derived authority girdisi değildir (TI-18); giriş ve kayıt yüzeylerine üçüncü taraf takip kodu konamaz (CSP, TN-106) | FROZEN (TI-18 bağı, takip kodu yasağı, toplu veri); PD (metrik listesi) | NG (analitik doğruluğu karar garantisi değildir) | B2C kayıt dönüşümü gelir etkisidir; passkey ve MFA benimsemesi güvenlik göstergesidir | TI-18; T40; §18.4 |
| IDP-37 | **Belge onayları ve tercih merkezi.** (1) **Belge onayları** (kullanım koşulları, KVKK aydınlatma metni, gizlilik politikası): hangi metin, hangi sürüm (digest), ne zaman, hangi yöntemle onaylandığı identity plane'de kaydedilir ve tamper-evident denetim kaydına girer; yeni sürüm yayımlanınca kayıt ve girişte yeniden onay istenebilir (gereksinim modeli, TN-132). (2) **Tam tercih merkezi:** pazarlama izinleri kanal bazında (e-posta, SMS, arama, push) ve konu bazında (kampanya, bülten, ürün haberleri); geri çekme; bütün değişikliklerin geçmişi. Kayıt ekranında, hesap ayarlarında ve ayrı "Tercihlerim" bileşeninde yönetilir (TN-133, gömülü ve barındırılan). (3) **İzinler yetki değildir:** pazarlama izni ve tercih bir Grant değildir; karar, restriction veya derived authority girdisi olmaz. Değişiklikler olay olarak (webhook) kiracının sistemlerine gider. (4) **İYS:** Access İleti Yönetim Sistemi'ne doğrudan yazmaz; **Access İYS servisi** (B23) izin değişikliklerini İYS'ye kaydeder ve kayıt durumunu geri bildirir. Access, İYS'nin istediği alanları (izin tarihi, kaynak, kanal, alıcı) eksiksiz üretir | FROZEN (izin ≠ yetki, belge onayı kaydı); PD (kanal ve konu listesi) | BY SEMANTICS (onay kaydının değişmezliği); UNDER DECLARED CAPABILITY (İYS teslimi) | B2C rıza yönetimi ve Türkiye'de ticari ileti izninin İYS'ye kaydı zorunluluğu | TN-132; TN-133; B23 |
| IDP-38 | **Active Directory ile birlikte çalışma, yerine geçme değil.** IDP-16 (LDAP salt okunur) ve IDP-17 (KDC yok) korunur. Access AD'nin yerine geçmeyi hedeflemez; AD ile birlikte çalışır (AD'den çekme, SPNEGO acceptor). Windows domain ve KDC kapsamı ayrı ürün alanıdır (Samba AD, FreeIPA, JumpCloud). **Kontrollü LDAP yazma** talep üzerinedir (WATCH): eklenirse eski uygulamanın LDAP yazma operasyonu tek yazma yoluna çevrilir (yetki kararı + kayıt, IDI-1/IDI-11); LDAP yazması hiçbir zaman bu yolu atlayan ikinci bir kapı olamaz | FROZEN (IDP-16, IDP-17, çeviri koşulu); WATCH (kontrollü LDAP yazma) | — | Kurumların çoğu AD'yi yerinde tutar; AD'yi kaldırma ayrı ve büyük bir ürün alanıdır; tek yazma yolu korunur | IDP-16; IDP-17; IDI-1; IDI-11 |
| IDP-39 | **Ayrı ürün katmanlarıyla entegrasyon (E22).** Bu katmanlar için ayrı Suiss servisi yapılmaz. (1) **PAM:** Access karar verir (JIT erişim kararı, kısa ömürlü SSH sertifikası, IDP-32); PAM araçları AuthZEN karar API'siyle sorar; oturum kaydı ve şifre kasası PAM ürünündedir; hazır entegrasyon Teleport ve CyberArk. (2) **Fraud/risk:** dış risk puanı SSF sinyali veya dış çağrı noktası (TN-135) ile Claim olarak girer ve yalnız daraltır (CI-2, E38); Access'in kendi temel sinyalleri identity plane'dedir: imkânsız seyahat, sızdırılmış parola kontrolü, şüpheli cihaz. (3) **IGA:** temel yetki gözden geçirme kampanyaları Access içindedir: periyodik olarak yöneticiye ekibinin Grant'ları sunulur, "kalsın" bir onay kaydı, "kaldır" bir `grant.revoke` Exercise'ıdır; kampanya kendisi authority üretmez. Rol madenciliği, çok aşamalı onay iş akışları ve SoD raporlaması IGA ürünündedir; IGA kararları Access'e Exercise talebi olarak gelir (§7.3). (4) **SIEM:** OCSF biçimli olay ve denetim akışı Access'in dışa aktarım özelliğidir; Splunk, Microsoft Sentinel, Datadog ve Elastic için hazır akışlar sunulur (TN-136'daki yol haritası kalemi SIEM için öne çekilir) | FROZEN (risk yalnız daraltır, kampanya authority üretmez, ayrı katman sınırı); PD (entegrasyon listeleri) | BY SEMANTICS (risk daraltması, revoke Exercise'ı); UNDER DECLARED CAPABILITY (dış ürünlerin uygulaması) | Ayrı katman kararı korunur; kurumsal müşterinin ilk entegrasyon soruları (PAM, risk, gözden geçirme, SIEM) cevaplanır | E22; CI-2; E38; §7.3; TN-136 |
| IDP-40 | **Uyumluluk (interop) laboratuvarı ve farklılık profilleri.** (1) **Test matrisi:** her sürümde CI'da otomatik uyumluluk testleri: SCIM istemcileri (Entra, Okta, Google Workspace, OneLogin, JumpCloud) ve SAML SP'leri (Salesforce, ServiceNow, Workday, AWS, Google Workspace, Slack, Zoom, Atlassian, ADFS, Shibboleth SP, SimpleSAMLphp). (2) **Farklılık profilleri:** sistemlere özgü bilinen sapmalar veri olarak tutulur (F23) ve SSO kataloğu şablonlarına bağlanır (IDP-28); şablon seçildiğinde profil uygulanır. (3) **Herkese açık uyumluluk tablosu:** hangi sistemle hangi sürümde test edildiği yayınlanır. (4) **Bildirimden profile:** her uyumluluk sorunu bir test vakasına ve profil güncellemesine dönüşür. (5) **Güvenlik sınırı:** profil yalnız biçim farklarını tolere eder; imza doğrulaması, süre/saat kontrolü, audience/recipient kontrolü ve XML ayrıştırıcı izolasyonu hiçbir profil tarafından gevşetilemez | FROZEN (güvenlik sınırı, profil = veri); PD (test matrisi listesi) | BY SEMANTICS (profilin güvenlik kontrollerini gevşetememesi) / UDC (karşı sistemin davranışı) | SAML/SCIM interop birikimi deneyimle kazanılır; sistemli toplanmazsa her müşteri sorunu ayrı yangındır; bakım yükü RR olarak beyanlıdır | IDP-28; F23; §4.9 |

### 10.11 Invariant adayları (IDI-n)

§6.10'a göre kanonik metin burada durur; §6 ile çelişkide §6 kanoniktir.

| ID | Invariant adayı | Garanti | Dayanak |
|---|---|---|---|
| IDI-1 | Identity plane yapılandırması (client, redirect URI, upstream IdP, SAML SP, SCIM client, realm config, anahtar rotasyon **politikası** (aralık, algoritma, acil rotasyon), RP ID) yalnız realm'in yönetişim AuthorityDomain'inde ADP `commit` ile değişir; başka yazma yolu yoktur. Politika dahilinde zamanlanmış rotasyonun yürütülmesi operasyoneldir | BS | MD-14 |
| IDI-2 | Credential ve login tanımlayıcısı realm'e yereldir; realm'ler arası eşleme yalnız açık `identity-binding` Claim'iyle kurulur; e-posta hiçbir tabloda anahtar değildir | BS | MD-5; P-ID-9 |
| IDI-3 | Hiçbir attestation, AAGUID, cihaz bütünlüğü ya da risk sinyali tek başına Instance, KeyBinding ya da Grant üretmez; yalnız Acceptance'lı `predicate-input` olarak okunur | BS | L21 |
| IDI-4 | Bir realm'in RP ID'si, o realm'de en az bir passkey kayıtlıyken yalnız geri dönülemez olarak işaretlenmiş bir CT3 domain action ile değişir | BS | IDP-5 |
| IDI-5 | Bir WebAuthn credential'ın BE bayrağı kayıttan sonra değişirse doğrulama reddedilir; BE=0 ∧ BS=1 geçersizdir | BS | — |
| IDI-6 | İmza doğrulamada kabul edilen `alg`, artefaktın header'ından değil, client/Domain metadata allowlist'inden belirlenir; `none`, polimorfik `EdDSA` ve RSA1_5 hiçbir allowlist'e giremez | BS | MD-3 |
| IDI-7 | İmzalı bir kimlik çıktısı (SAML Response, ID token, logout token) yalnız tamamlanmış bir authentication oturumundan ya da kayıtlı bir oturum olayından üretilir | BS | §10.6.1 (CVE-2022-39299) |
| IDI-8 | SAML'de imzası doğrulanan düğüm ile işlenen düğüm referans eşitliğiyle aynıdır; duplicate ID olan belge reddedilir | BS | §10.6.1 XSW |
| IDI-9 | Trust chain, trust mark, VC, CIBA cevabı ya da upstream token tek başına Grant üretmez ve AAS'i atlatmaz | BS | PI-3 |
| IDI-10 | URL biçimindeki `client_id` yerel/DCR kaydına hiçbir zaman çözümlenmez | BS | IDP-1 |
| IDI-11 | Kenar gateway süreçleri authority plane'e ve identity plane deposuna doğrudan yazamaz; tek çıkışları Claim Ingest ve iç identity API'dir. SCIM server ayrı süreçte koşarsa aynı kurala tabidir. LDAP yolundan yazılabilen tek credential LDAP credential sınıfıdır (§10.6.3) | UDC | MD-1; TI-15 |
| IDI-12 | Federasyon/trust chain doğrulanamadığında o issuer'dan Claim girdisi kesilir (fail-closed); Acceptance kaydı yalnız ADP ile değişir | BS | MD-8 |

### 10.12 §13'e aday HL / RR / guarantee önerileri

Numara verilmez; numaralar §13'te atanır.

- **§13'e aday: RR** — Kullanıcı varlığı (enumeration) yan kanalı istatistiksel olarak azaltılır, kriptografik olarak sıfırlanmaz (§10.2.1).
- **§13'e aday: RR** — DPoP/DBSC anahtarı aynı cihazdaki malware ile kötüye kullanılırsa sahiplik bağı koruma sağlamaz (§10.4.3, §10.8.2).
- **§13'e aday: RR** — Pairwise `sub`'a rağmen e-posta, telefon ve ad claim'leri RP'ler arası korelasyona izin verir (MD-10 kalan yüzey; §10.4.6).
- **§13'e aday: RR** — Ele geçirilmiş istemci ekranında gösterilen metin ile H(AAS) farklı olabilir (§10.5.4).
- **§13'e aday: HL** — SAML imza anahtarının sızması (Golden SAML) tüm SP'lerde impersonation sağlar. Etki SP'lerin kendi authority'si kadardır, Access authority plane'ine yayılmaz (§10.6.1).
- **§13'e aday: HL** — Realm JOSE anahtarının sızması o realm'in RP'lerinde impersonation sağlar. Authority plane'e etkisi, actor-binding Acceptance'ının kapsamı kadardır (HL-8 ile ilişkili).
- **§13'e aday: guarantee** — "Upstream IdP authentication'ın doğruluğu" NOT GUARANTEED; "Access'in bu Claim'i Acceptance kapsamı dışında kullanmaması" BY SEMANTICS (§10.1.2 kural 2, IDP-27).
- **§13'e aday: guarantee** — "Logout sonrası RP oturumunun kapanması" NOT GUARANTEED; "Access'in logout sonrası yeni token vermemesi" BY SEMANTICS (§10.4.6).
- **§13'e aday: guarantee** — "Kimlik iddiasının (ID token, SAML assertion, logout token) RP'de iptali" NOT GUARANTEED; "Access'in iptal sonrası yeni kimlik iddiası üretmemesi" BY SEMANTICS (§10.4 token sınıfları).
- **§13'e aday: guarantee** — "Mevzuata (PSD2, TR GKD) uygunluk" NOT GUARANTEED; şablonun kurallarını uygulamak UNDER DECLARED POLICY (§10.3.4).

### 10.13 Doğrulanamayan iddialar ve kapsam notları

**Doğrulanamayan ya da tek kaynaklı iddialar (olduğu gibi işaretli):**
1. WebAuthn L3'ün W3C Recommendation tarihi (25 Ağu 2026) ve CTAP 2.3 tarihi (26 Şub 2026) bağımsız doğrulanmadı. MD-18 bunları "doğrulanmadı" diye işaretler. Kaynaklar arasında CTAP 2.2 / 2.3 tutarsızlığı vardır.
2. SSF/CAEP final tarihi doğrulanmadı → §9.
3. OIDF 1.1 yayın tarihi kaynaklar arasında çelişkilidir.
4. TR RG 33360 (4 Eyl 2026) değişikliği tek kaynağa dayanır. Bağımsız teyit edilmedi.
5. ES256 doğrulama süresi (20–50 µs) çıkarımdır, ölçülmemiştir.
6. Passkey benimseme oranları ve "%60" geçiş eşiği satıcı kaynaklıdır.
7. SAML SP gereksinimleri §10.6.1 profil tablosundadır (2026-10-07, resmî belgeler). Doğrulanamayanlar: Workday'in büyük kısmı (resmî belgeler girişe kapalı), Salesforce'un güncel belgelerle aynılığı, birçok SP'de imza algoritması ve IdP-initiated desteği; bunlar tabloda "doğrulanmadı" olarak işaretlidir.
8. RADIUS ve WS-Fed için ayrıntılı araştırma yoktur. §10.6.5 profili çıkarımdır (IDP-18 HYPOTHESIS).
9. FAPI'nin RSA için PS256 istemesi (kural: fapi2'de RSA yok, §10.5.1), CIBA push reddi, `did:web`/`did:jwk` çözümü ve NFKC normalizasyonu bu bölümde **çıkarım** olarak işaretlidir.
10. Ürün sürüm ve satın alma bilgileri (§10.9.3) tek ikincil kaynağa dayanabilir.

**Kapsam notları:**
- **Bileşen etiketi**: Identity plane bileşeni **CMP-15**'tir (MD-19; §16.3, eşleme §16.3.3). Ontology'deki C15 (delegasyon kanonik kuralı) ile karıştırılmaz.
- **CIMD / AS metadata ayrıntısı**: Tek kaynak §11.3–§11.4'tür. Bu bölüm yalnız genel kuralı ve **AS tarafı** resolver sırasını (IDP-1) normatif olarak verir; istemci tarafı kayıt yolu seçimi §11.3.8'dedir.
