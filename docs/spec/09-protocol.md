## 9. Protocol

**Bölüm notu.**

- **Plane ataması (MD-13).** §9 **authority plane**'in protokolüdür.
  - Identity plane'in protokolleri §10'dadır: OAuth/OIDC AS'nin grant tablosu, PKCE/PAR/JAR/DPoP uygulama profili, token exchange mekaniği, JWT/JWKS, discovery, logout, FAPI/FiPA/CIBA uygulaması, SAML/SCIM/LDAP/Kerberos, OIDF protokol ayrıntısı.
  - MCP ve ajan kimliği §11'dedir.
  - İki plane arasındaki dikiş değişmez: identity plane authority plane'e yalnız Claim verir ve bunu Claim Ingest (§9.13) üzerinden yapar (INV-12, F3, T31).
  - Identity plane'in ürettiği token'lar iki sınıftır. (i) **Authority taşıyan** her token (RAR `authorization_details` taşıyan ya da kaynak erişimi ifade eden access token, refresh token, exact-intent/bounds token) bir `projection.issue` ürünüdür, tam ValidityContract taşır ve holder-bound'dur (§9.9, PI-11, S-1). (ii) **Kimlik iddiaları** (ID token, SAML/WS-Fed assertion, logout token, LDAP/SPNEGO oturumu, protokol-scope-only access token: `openid`/`profile`/`userinfo`) authority taşımaz (E39). `projection.issue` Exercise'ı gerektirmez. MD-7'nin ValidityContract semantiğine **kimlik-iddiası profiliyle** tabidir: `horizon` = `exp`/`NotOnOrAfter`, hızlı iptal mekanizması `session_epoch`, `issuing_exercise` yok. Kenar gateway süreçleri yalnız (ii) sınıfını üretir ve ADP çağırmaz (P-ID-5, IDI-11). Access'in ürettiği ID-JAG ara bir durumdur: verilip verilmemesi bir `projection.issue` kararıdır, ama ürünü authority taşımayan bir kimlik iddiası projection'ıdır ve authority scope içermez (§11.11.2).
- **Karar kimlikleri.** §9'un protocol kararları P-ailesindedir (P1–P34, §9.18; **P35–P60**, §9.18.1). §11'in kararları **AG-n**, invariant adayları **AGI-n** ailesindedir. HL, RR ve guarantee satırları burada numaralanmaz; "§13'e aday" diye önerilir.

### 9.1 Verdict ve katmanlar

**Verdict: Access hem bir protocol hem bir üründür; ikisi aynı şey değildir.** Bir AuthorityDomain herhangi bir conformant provider'da host edilebildiği ve canonical semantik açık spesifikasyonda olduğu için Access zorunlu olarak bir protocol'dür (CI-15, E20, E24). Açık standartlar **taşıyıcıdır**; semantik Access'tedir. Hiçbir standardın semantiği ontology'yi değiştirmeye zorlamaz; standartların boş bıraktığı her yer (provenance, attenuation algebra, Mandate, budget, consumption, Exercise kaydı, REQUIRE_ACTION) Access'in varlık nedenidir (§4).

| Katman | İçerik | Statü |
|---|---|---|
| **L0 Access Core Semantic Specification** | Ontology'nin serileştirmeden bağımsız tanımı: primitive'ler, record'lar, value'lar, meta-action schema'ları, closed attenuation type system, evaluation kuralları (deny-overrides, subsumption, lineage budget draw), record-fold ve SYNC-DERIVED türetim fonksiyonları, determinism yükümlülüğü, reason/remediation ve event sınıfları | Açık, normatif |
| **L1 Interoperability Profiles** | Her biri bir standardın PROFILE/EXTEND'i: Decision (AuthZEN), Projection (OAuth/RAR/DPoP), Signals (SSF/CAEP), Claim Ingest (OIDC/SPIFFE/VC/SCIM), Trust Bootstrap (OpenID Federation), Agent Tool (MCP), Agent Task (A2A), Call-chain context | Açık, normatif |
| **L2 Access-native protocol parts** | Actor Intent Statement, Approval Act Statement, Portable Authority Proof + ValidityContract + offline report, Schema Publication Package, Authority Record Exchange + checkpoints + handover/recovery (§9.17 custom justification) | Açık, normatif |
| **L3 Conformance** | Kriterler + suite + test vektörleri: Provider, Decision PEP, Offline Verifier, Approval Surface (Work ile ortak), Claim Issuer, Schema Publisher, Coordinator, Event Receiver | Açık |
| **Implementation** (protocol değil) | Access Core (L0 semantiğinin open-source implementasyonu; Suiss production onu kullanır), reference verifier, Offline Verifier Core, replica agent, Suiss-hosted provider operasyonu, Experience yüzeyleri | Normatif değildir |

**Normatif tanım L0/L2 metni + conformance vektörleridir** (RT8, TI-RT12). Access Core bir implementasyondur; kod ile spec ayrıştığında spec kazanır (G38) ve fark bir implementasyon hatasıdır. Lisans biçimleri D4'te (Adem kararı) belirlenir; hiçbir lisans export, handover, replay veya protocol kullanımını kısıtlayamaz (B10).

**Ürün ile protocol arasındaki kural.**
- Suiss protocol'ün sahibi değildir; protocol semantiği açık bir governance sürecinde değişir (D3). Suiss-hosted provider protocol'ün **bir** conformant implementasyonudur (E20, E24, INV-29).
- Conformance suite referanstır, endorsement değildir: suite'i geçmek "Suiss onaylı" anlamına gelmez; suite'i geçmeyen Suiss implementasyonu da conformant değildir.
- Protocol ≠ ürün yüzeyi. S1–S10 protocol değildir; protocol yalnız bu yüzeylerin gönderdiği Exercise taleplerinin ve okuduğu projection'ların sözleşmesidir. Third-party bir Experience aynı yüzeyleri aynı sözleşmeyle kurabilir (XI-18).

**Protocol refinement'ları (standartların Access semantiğini ezmemesi için).**

| # | Refinement |
|---|---|
| R1 | **Tek Exercise girişi.** Domain action'ları ve meta-action'lar aynı Exercise Request / Decision sözleşmesinden geçer; "management API" ayrı bir semantik yol değildir (§9.7) |
| R2 | **AuthZEN boolean'ı fail-closed eşlenir**; AuthZEN `subject` canonical actor değildir: actor yalnız doğrulanmış Actor Intent Statement'tan türetilir; statement'sız istek `Anonymous(context)`'tir |
| R3 | **OAuth scope Access authority taşımaz**; authority yalnız RAR `authorization_details` içinde typed taşınır |
| R4 | **Decision receipt ≠ credential**; reusable kullanım yalnız ValidityContract taşıyan `projection.issue` ürünüdür |
| R5 | **Approval Act Statement**: tek authenticating user act, iki owner'ın digest'lerini birlikte taahhüt eder; `contribution` ve `authority-act` iki ayrı act türüdür; AAS her iki türde proof'tur, IntentEnvelope değildir |
| R6 | **Portable authority proof Access-tanımlı içerik, standart kapta** (JWT/SD-JWT veya COSE); VC, Biscuit, UCAN normatif taşıyıcı değildir |
| R7 | **Must-understand**: authority'yi sınırlayan her alanı tanımayan verifier/evaluator onu "kapsanmıyor" sayar (DENY) |

### 9.2 Protocol parçaları (AP-1–AP-15)

Her parça: amaç · semantik owner · taşıyıcı (standart) · ontology sınıfı. Semantik owner §7.1 matrisinden gelir; protocol owner değiştirmez.

| # | Parça | Amaç | Semantik owner | Taşıyıcı |
|---|---|---|---|---|
| **AP-1** | **Exercise Request & Decision** | Bir actor Instance'ının, adlandırılmış bir basis ile, beyan edilmiş capacity'de, exact intent için karar istemesi; ALLOW'da Exercise'ın doğumu | Access (AuthorityDomain provider) | **AuthZEN Authorization API 1.0** (PROFILE + EXTEND); actor proof = **Actor Intent Statement** (Access-tanımlı içerik, JWS/COSE kabında, ADP `context` üyesi; actor Access'i doğrudan çağırıyorsa HTTP Message Signatures); PEP kimliği = ADP çağrısının transport authentication'ı (mTLS / OAuth client auth / DPoP / WIMSE WPT) — ikisi ayrı alan, ayrı taşıyıcıdır |
| **AP-2** | **Advisory Check & Explain** | "Would this be allowed now?" ve "neden?" — kaydedilmeyen, söz olmayan değerlendirme; viewer-scoped açıklama | Access | AuthZEN evaluation (advisory mode) + AuthZEN search API'leri (PROFILE) |
| **AP-3** | **Meta-Exercise** (grant/mandate/acceptance/policy/anchor/instance/claim.issue/contribute/consumption.release/projection.issue) | Authority state'in tek yazma yolu | Access | AP-1'in aynısı; action = core namespace ActionRef |
| **AP-4** | **Continuation** | Long-running/intermittent kullanımda aynı Exercise üzerinde yeni karar | Access | AP-1 (continuation modu) |
| **AP-5** | **Projection** (online/intermittent token, offline Portable Authority Proof) | Reusable/portable authority artifact'ı; ValidityContract taşır | Access (`projection.issue` Exercise'ı); verifier davranışı verifier operatörünün (E13) | **OAuth** (RFC 6749/9700, 8693, 9068, 9396 RAR, 9449 DPoP, 8705, 8707) PROFILE+EXTEND; offline: Access-tanımlı içerik, imzalı JWT/SD-JWT (RFC 9901) veya COSE kabı; status: Token Status List / Bitstring Status List |
| **AP-6** | **Contribution / Approval Act** | Approval'ın authority act'i; tek user act → contribution Exercise + Work Declaration (`act = contribution`); kullanıcının kendi authority act'leri (`act = authority-act`: `grant.issue`/`amend`/`revoke` …; actor = kullanıcının Instance'ı, contribution yok) | Access (contribution), Work (Gate/Declaration), Approval Surface (render + user act) | Access-native **Approval Act Statement** + WebAuthn/passkey assertion (veya W3C SPC, ödeme bağlamında) |
| **AP-7** | **Claim Ingest** | Dış iddiaların attributable kaydı | Issuer (içerik), Access (ingest kaydı) | OIDC ID Token, SET/SSF (CAEP/RISC), SCIM, VC/SD-JWT, OID4VP, SPIFFE SVID, domain-signed Claim; hepsi PROFILE |
| **AP-8** | **Party Identity Regime binding** | PartyRef, key-state, recovery, controller, issuer designation | Party + controller (regime); Work Protocol ile ortak | Regime key-event history (Work Protocol); Access'e Claim olarak |
| **AP-9** | **Schema Publication** | Namespace, katalog sürümü, typed schema, parametre tip/sınıfı, compatibility beyanı | Publisher (anlam), Access (tip sistemi + Acceptance) | Access-native **Schema Publication Package** (imzalı, digest kimlikli); RAR type registration |
| **AP-10** | **Connectivity artifacts** | ValidityContract, verifier profile beyanı, offline exercise report, authority-state ack | Access (contract), verifier operatörü (rapor, ack) | AP-5 içinde; rapor ve ack Claim olarak (AP-7 kanalları) |
| **AP-11** | **Semantic Events** | Derived state geçişlerinin bildirimi | Access (içerik), Relay / SSF transmitter (teslim) | **SSF 1.0 + SET** (PROFILE) + Access event types (EXTEND) |
| **AP-12** | **Federation** (identity, foreign authority evidence, bridging, cross-domain delegation; handover AP-13'te) | E19'un beş mekanizmasının her biri için ayrı protocol karşılığı (tablosu): identity federation, foreign authority evidence, local bridging Grant, cross-domain delegation (burada) ve authority-provider handover (AP-13) | Yerel AuthorityDomain (Acceptance, bridging Grant, foreign Party'ye yerel Grant); home domain (kendi lineage'ı ve budget draw'u) | OpenID Federation (trust bootstrap), Identity Chaining, Portable Authority Proof (`foreign-authority` Acceptance + bridging Grant); cross-domain delegation = mevcut `grant.issue` + `actor-binding` Acceptance |
| **AP-13** | **Authority Record Exchange, Checkpoints & Provider Handover** | Kayıtların dışa aktarımı, doğrulanabilir checkpoint, provider handover / forced recovery (`domain.handover` / `domain.recover`, domain-scope AuthorityDomain geçişi; E19'un beşinci mekanizması; pozisyon tabanlı kesim, §9.15) | AuthorityDomain root; provider (custody attestation) | Access-native record exchange; Work federation record kurallarıyla hizalı |
| **AP-14** | **Audit Export** | SIEM/auditor için projection; doğrulanabilir | Access (canonical kayıt); SIEM (kopya) | AP-13 export'unun projection'ı + SSF/SET (opsiyonel akış) |
| **AP-15** | **Domain Metadata & Discovery** | DomainID, provider endpoint'leri, desteklenen profiller, benimsenmiş core/meta-schema sürümleri, minimum sürüm, imza anahtarlarının domain'e bağı | AuthorityDomain (genesis/handover kayıtlarından türetilen projection) | OpenID Federation entity statement (EXTEND: Access entity types) + `/.well-known/authzen-configuration` (AuthZEN) |

### 9.3 Ortak kurallar

1. **Her parça bir mevcut ontology sınıfına eşlenir**. Protocol nesnesi canonical primitive olamaz; kanonik olan yalnız AuthorityDomain'in kayıtlarıdır (C2).
2. **Her mesaj ya bir Exercise talebidir, ya bir projection'dır, ya bir Claim'dir, ya bir derived bildirimdir.** Dördüncü bir "komut" türü yoktur; authority state'i değiştirmek isteyen her istek bir meta-Exercise talebidir (R1, PI-4).
3. **Hiçbir parça Suiss-hosted bir bileşen gerektirmez.** Endpoint'ler domain metadata'sından keşfedilir; trust anchor'lar domain'in kendi Acceptance'larından ve OpenID Federation trust chain'lerinden gelir (PI-14).
4. **Taşıyıcı yalnız taşır.** Bir standardın alanı Access'te karşılığı olmayan bir anlam taşıyorsa (OAuth scope, AuthZEN subject, `act` zinciri, SPIFFE trust domain, VC "credentialSubject" doğruluğu, CAEP event'inin teslim edilmiş olması), Access o anlamı **kullanmaz**; alan ya yok sayılır ya yalnız ipucu/girdidir.

### 9.3A Protocol nesnesi → ontology sınıfı (PI-1 tablosu)

| Protocol nesnesi | Ontology sınıfı | Canonical karşılık / dayanak | Asla |
|---|---|---|---|
| Exercise Request (Actor Intent Statement, basis, capacity, IntentEnvelope, proofs, nonce, mode) | **PROTOCOL construct** taşıyan **VALUE**'lar; kaydedilirse **Exercise opening record** içeriği | Opening record; ActorContext, HoldingRef, ExerciseCapacity, IntentEnvelope (§4) | Kendi kimliği olan bir "request" nesnesi |
| Decision Response (outcome, reasons, unmet terms, remediation, ExerciseID, ValidityContract) | **VALUE** (Decision) + kayıtlıysa **DecisionRecord** referansı | C31, §12.3 | Credential |
| Decision Receipt (imzalı ALLOW özeti) | **PROJECTION** (DecisionRecord'un) | C31 "portable/reusable artifact'lar ayrı projection'lardır" | Başka intent/PEP için yetki |
| Advisory Check sonucu | **DERIVED result** (kaydedilmez) | C30, INV-22 | Söz, cache'lenmiş izin |
| Explain cevabı | **DERIVED** (proof inşası) | "Why can X do Y?" | Viewer'ın yetkisi dışı graph |
| Meta-Exercise talebi (`grant.issue` …) | Exercise Request (yukarıdaki) | — | Ayrı admin API semantiği |
| Projection artifact (OAuth AT, Portable Authority Proof) | **PROJECTION** (`projection.issue` Exercise'ının ürünü) | C3, C31, §12.3 | Source of truth, Grant |
| ValidityContract | **VALUE** | — | Lease, TTL'den ibaret |
| Offline slice | **VALUE** (BudgetTerm draw'u, `projection.issue` DecisionRecord'unun consumption effect'i; draw issuance'ta tamamdır, ayrı reserve/finalize adımı yoktur) | — | Ayrı bütçe nesnesi, rezervasyon |
| Actor Intent Statement (actor proof) | **VALUE** (actor Instance'ın KeyBinding'iyle domain/nonce/intent digest/PEP audience/capacity/basis ref üzerine imzalı statement); kaydedilen Exercise opening record'unun / DecisionRecord'un proof'u | Mevcut Exercise / IntentEnvelope + Instance KeyBinding (ActorContext = `Authenticated(InstanceID)`); E17 | Yeni primitive veya record türü; PEP kimliği; transport PoP (DPoP/mTLS/WPT) |
| Approval Act Statement | **VALUE** (digest'e bağlı, immutable); her iki act türünde **proof**'tur, hiçbir Exercise'ın IntentEnvelope'u değildir: `act = contribution`'da contribution Exercise opening record'unun, `act = authority-act`'te kullanıcının kendi meta-Exercise opening record'unun (`target` = o Exercise'ın typed IntentEnvelope digest'i; AAS kendi digest'ini içermez) ve (varsa) Work Declaration'ının proof'u | INV-20 (proof = rol) | Yeni record türü, Gate kaydı |
| Authentication assertion (WebAuthn/SPC) | **CLAIM** (`authentication`, binding = statement digest / Instance) | — | Authority |
| Party key-state, compromise, recovery, termination, identity-break, controller-of | **CLAIM** sınıfları | §7.9.2.3–§7.9.2.4 | Access'in Party kaydı |
| Schema Publication Package | **CLAIM** (issuer = publisher, class `schema.publication`); kullanılabilirliği **Acceptance** (`schema-definition`, exact digest) | §7.9.3.2, §6.6 | Access'in schema anlamı |
| Compatibility declaration | **CLAIM** (issuer = publisher) | E10 | Kendiliğinden kullanılabilir mapping |
| Namespace catalog version | **VALUE** (Schema Publication Claim'inin içeriği; Grant AuthoritySet'inde pin) | E11 | Canlı katalog |
| Verifier profile declaration | **CLAIM** (issuer = verifier operatörü; conformance) | E13 | Access'in verifier davranışı |
| Offline exercise report | **CLAIM** (issuer = verifier operatörü, subject = projection ExerciseID); "kullanılan / kullanılmayan / contract dışı" ayrımı **DERIVED** | §7.9.4.1, §3 | Exercise (her offline kullanım ayrı Exercise değildir); release; Access-issued ihlal Claim'i |
| Authority-state ack | **CLAIM** (issuer = PEP/verifier) | E30 | Authority değişikliği |
| Effect attestation / non-execution | **CLAIM** | EI-10, INV-21 | Effect truth beyanı |
| Semantic event (SET) | **DERIVED notification** (PROJECTION transport) | §7.9.8.1 | Commit, canonical geçiş |
| Domain checkpoint (pozisyon + head digest) | **CLAIM** (issuer = provider, Domain Metadata'da domain'e bağlı anahtarıyla; custody attestation; witness co-sign = ayrı Claim) | Genesis "custody attestation (authority değil)" | Authority |
| Record Export Package | **PROJECTION** (canonical kayıtların doğrulanabilir kopyası) | C2, §7.9.12.5 | Yeni source |
| Handover package | **Exercise** (AuthorityDomain'in "provider handover" geçişinin meta-Exercise'ı; scope = `Domain(D)`: kooperatifte `domain.handover`, basis = domain meta-anchor root'u + rootTerms requirement'ları, eski + yeni provider'ın checkpoint Claim'leri proof; forced'da `domain.recover`, basis = AnchorRoot(domain meta-anchor), capacity OWN, requirement = rootTerms'in Genesis'te beyan edilmiş `domain.recover` entry'si (reserved power; genel root threshold'u değil), actor'ler bu entry'nin tanımladığı KeyBinding'li root Party Instance'ları, cite edilen checkpoint N) + Record Export | §7.9.11.2, E20 | Provider'ın authority'si; Anchor alanı / `anchor.amend` |
| Domain metadata / entity statement | **PROJECTION** (Genesis/handover/Acceptance kayıtlarından; AuthorityDomain'in Genesis / `domain.*` Exercise'larıyla bağlanan provider binding'indeki yayın anahtarıyla imzalı; recovery sonrası eski provider anahtarlarının durumunu `superseded-at checkpoint N` olarak taşır); trust chain'deki ifadeler **CLAIM** girdisi | E20 | Acceptance'ın yerine geçmek |
| Foreign Authority Proof | Foreign domain'de **PROJECTION**; yerelde **CLAIM** (foreign authority chain claim); yalnız `foreign-authority` Acceptance'ıyla bridging Grant'ın `ForeignAuthority` seçicisine girer | §7.9.11.3, C21 | Yerel basis; `predicate-input` / `subject-selection` girdisi |
| OIDF trust mark, entity statement | **CLAIM** girdisi | L26 | Acceptance |
| Txn-Token, `act` claim | **PROJECTION / ipucu** (context transport) | L22 | Basis, lineage kanıtı |
| Authority request (agent → coordinator) | **Access nesnesi değil** — coordinator'ın (Work) girdisi; içinde Decision Response verisi | X5, XI-7 | Access kuyruğu |

Tabloda **primitive** sütununa düşen tek protocol nesnesi yoktur. PI-1.

**MCP, ID-JAG ve ajan nesneleri.** Bu nesneler tabloya §11.2 ve §11.22'deki eşlemelerle eklenir: MCP tool → ActionRef, MCP tool call → Exercise Request veya `kind=intent` RAR, ID-JAG → CLAIM girdisi, `requestState` / state handle → protocol nesnesi değildir (authority taşımaz), consent kaydı → identity plane UI kaydı (`grant_ref` ile). Hiçbiri primitive sütununa düşmez (PI-1).
- ID-JAG iki ayrı sınıftadır. Access'te **tüketilen** ID-JAG = CLAIM girdisi (`actor-binding`/`predicate-input`). Access'in **ürettiği** ID-JAG = authority taşımayan bir **kimlik iddiası PROJECTION**'ı. Verilmesi `projection.issue` kararının ürünüdür, ama authority taşımaz ve authority scope içermez; taşınan bir `scope` varsa yalnız Resource AS için ipucudur (R3). Authority-bearing olmadığı için PI-11 kapsamına girmez. Resource AS'teki yetki o AS'in kendi kararıdır; Resource AS Access ise oradaki Access Grant'ından gelir (§11.11.3).

### 9.4 Standards mapping (ADOPT / PROFILE / EXTEND / REJECT)

Kayıt statüleri landscape incelemesindeki statülerdir ("doğrulanmadı" etiketleri korunur). "Asla" sütunu standardın semantiğinin Access'i ezemeyeceği yeri yazar.

| Standart | Karar | Access semantiğini ezemeyeceği yer / not |
|---|---|---|
| **A. Authorization / delegation substrate** | | |
| **OAuth 2.0 RFC'leri** (RFC 6749/6750, RFC 9700 BCP 240) | **PROFILE** | **OAuth Grant ≠ Access Grant**; authorization code / refresh token Access holding'i değildir; OAuth client registration authority vermez |
| **OAuth 2.1** | **PROFILE (informative baseline)** | Normatif bağımlılık RFC'lere; 2.1 RFC olunca profil ona hizalanır, semantik değişmez |
| **OAuth scope** | **REJECT** (authority taşıyıcısı olarak) | **OAuth scope ≠ Access authority.** Access projection'ı authority-bearing scope üretmez; scope-only RS conformant adapter PEP üzerinden bağlanır (R3) |
| **RFC 8693 Token Exchange** | **PROFILE** | `act` zinciri lineage kanıtı değildir (L22); token exchange holding yaratmaz; daha geniş token üretemez (INV-3). Capacity → `sub`/`act`/`may_act` yazımı §9.9.4'tedir; ayrıştırıcı ≥ 4 seviye iç içe `act` destekler, ajan Grant şablonu varsayılanı depth ≤ 1 kalır (§11.9). Token exchange mekaniği (URN'ler, `requested_token_type`) → §10 |
| **RFC 9396 RAR** | **EXTEND** (Access-registered types) | **RAR authorization_details ≠ AuthoritySet**: subsumption semantiği Access'tedir; RFC 9396 ortak alanları (`locations`, `actions`, `datatypes`, `identifier`, `privileges`) Access sınırı ifade etmez |
| **RFC 9449 DPoP / RFC 8705 mTLS** | **ADOPT** | Key = Instance kimliği değildir (L21); PEP → Access bağlantısının DPoP/mTLS'i **actor proof değildir** (yalnız PEP'i kanıtlar; intent digest'e bağlı değildir). DPoP nonce: uzun ömürlü paylaşılan nonce; replay cache TTL = kanıt ömrü + 2× saat kayması (MD-18). DPoP uygulama profili (`jkt`, nonce, replay) → §10 |
| **RFC 9126 PAR / RFC 9101 JAR / JARM** | **ADOPT** (yüksek-sonuç profilde zorunlu) | — |
| **RFC 8707, 9068, 9728, 7662, 7009, 9470, 9207** | **ADOPT** | RFC 7009 token revocation ≠ `grant.revoke` (cascade etmez); RFC 9470 challenge yalnız authentication strength'tir, authority değildir; RFC 8707: kayıtsız `resource` → `invalid_target`, tek `aud` (§9.9.3); RFC 7662: tazeliği kanıtlanamayan authority taşıyan token `active=false` (MD-8); RFC 9207: `iss` başarılı ve hatalı yanıtta, metadata `issuer` ile bayt-özdeş (ayrıntı §11.4) |
| **FAPI 2.0 Security Profile + Message Signing** | **ADOPT** (yüksek-sonuç projection profili) | — |
| **Grant Management for OAuth 2.0** | **REJECT** | `merge` semantiği mevcut grant'ı genişletebilir (INV-3, C16 ile çelişir). Grant'ın sorgulanması ve iptali ADP `check`/explain ve `grant.revoke` meta-Exercise'ıyla yapılır |
| **GNAP** (RFC 9635, 9767) | **REJECT** (WATCH, L27) | Deploy sınırlı; delegation chain / subset kuralı yok; continuation semantiği Access'te zaten AP-4 ile tanımlı; ikinci bir negotiation protocol'ü interop yükünü artırır, semantik kazanç getirmez |
| **B. Decision surface** | | |
| **OpenID AuthZEN Authorization API 1.0** | **PROFILE + EXTEND** ("Access Decision Profile") | **AuthZEN subject ≠ canonical actor model**; boolean `decision` Access outcome'unun tamamı değildir; batch evaluations atomik bir çoklu-Exercise değildir |
| AuthZEN Obligations Profile / **AARP** (Access Request and Approval Profile, WG Draft 1, Eylül 2026; WG taslağı 15 Haziran 2026'da onaylandı) | **REJECT** (normatif bağımlılık olarak) / **WATCH** + **eşleme hazır** | Draft'a bağımlılık yok (L27). AARP'ın "talep edilebilir ret" + opak görev tutamağı + "onaydan sonra taze değerlendirme" + "reddedilmiş karar reddedilmiş kalır" kuralları REQUIRE_ACTION + aynı nonce + C30 ile birebir örtüşür; eşleme tablosu §9.9.5'tedir. Final olursa REQUIRE_ACTION'ın taşıyıcısı olarak PROFILE adayıdır |
| AuthZEN COAZ / COAZ-MCP binding (Draft 1, Şubat 2026) | **REJECT** (WATCH) | Agent'ı `context`'e koyan model ("The human user is represented as the AuthZEN Subject; the AI agent appears in the Context") canonical actor modelini bozar. COAZ'ın tool-çağrısı başına öneri ihtiyacı ADP + MCP profiliyle (§11.5) karşılanır; WATCH olarak izlenir |
| **CIBA Core 1.0** | **PROFILE** (yalnız davet/transport) | `binding_message` onay içeriği değildir; CIBA cevabı contribution değildir. CIBA `binding_message` serbest metindir ve çalıştırma ortası onayına uymaz (AIMS §10.7). Onay AAS'tir (§9.14); CIBA uç noktası ve modları → §10 |
| **C. Signals / events / status** | | |
| **Shared Signals Framework 1.0 + RFC 8417 SET + RFC 8935/8936** | **PROFILE** | Teslimat güvenlik varsayımı değildir (INV-24); stream durumu authority durumu değildir. Identity plane SSF vericisi ve alıcısı tam uygulanır (MD-13); güvenlik garantisi ValidityContract/expiry'dedir, sinyal "best effort"tur (§9.16.2). Final yayın tarihi kaynaklar arasında çelişkilidir (2 Eylül 2025 / 29 Ağustos 2025) — **doğrulanmadı** (MD-18) |
| **CAEP 1.0** | **PROFILE** (girdi) + **EXTEND** (Access event types) | CAEP `session-revoked` bir Grant revocation'ı değildir; Access event'i bir commit değildir. CAEP 1.0 Final'de ajana özgü olay tipi yoktur; Access event'leri bu boşluğu Access namespace'inde doldurur (§9.16.2). Tuzak: eski draft URL'si 2021 draft-02'yi döndürür |
| **RISC 1.0** | **PROFILE** (girdi) | Positive authority |
| **Token Status List** | **ADOPT** (RFC olunca normatif; o zamana kadar profile alternatifi) | Status listesinde "valid" görünmek authority değildir; yalnız projection'ın iptal edilmediğinin cache'lenmiş kanıtıdır |
| **W3C Bitstring Status List v1.0** | **ADOPT** (VC bağlamında Claim'lerin durumu) | — |
| **D. Identity, workload, attestation (Claim girdileri)** | | |
| **OpenID Connect Core 1.0** | **ADOPT** | ID Token authority değildir; `groups` claim'i Acceptance'sız selection'a giremez (INV-15) |
| **OpenID Federation 1.0 / 1.1** | **PROFILE + EXTEND** (Access entity types) | **Trust chain ≠ Acceptance**: bir chain'in geçerli olması hiçbir use için kabul değildir; Acceptance yine meta-Exercise'tır. Identity issuer'ın authority issuer rolü entity-type/metadata policy ile engellenebilir (L26) |
| **SPIFFE** (ID, SVID, Workload API, Federation) | **ADOPT** (girdi) | **SPIFFE trust domain ≠ AuthorityDomain** (L25); SPIFFE federation = authentication federation, authority federation değil |
| **IETF WIMSE** (arch, identifier, WIT/WPT, http-signature) | **PROFILE (informative; RFC olunca normatif)** | Draft'a normatif bağımlılık yok; WPT Actor Intent Statement'ın yerine geçmez |
| **WIMSE AIMS** (`draft-klrc-aiagent-auth-03`, bireysel, 6 Temmuz 2026) | **REJECT** (normatif bağımlılık) / **WATCH**; Access Agent Binding Profile buna hizalanır | AIMS'in "The Large Language Model MUST NOT have access to an agent's credentials" kuralı ve "local UI confirmation alone" yetki değildir kuralı Access semantiğiyle aynıdır ve §11.12'de normatif kural olarak alınır |
| **Attestation-Based Client Authentication** (`draft-ietf-oauth-attestation-based-client-auth-11`, 3 Eylül 2026) | **PROFILE (RFC olunca normatif)** | Attestation authority değildir; InstanceID ≠ KeyBinding ≠ Attestation (L21). DPoP birleşik modu (Client Instance Key = DPoP Key) KeyBinding'in tek anahtarla hem attestation hem sender-constraint görmesine izin verir; attestation'ı kimin topladığı sorusu §11.11'dedir |
| **SCIM 2.0** (+ SCIM Agent draft) | **ADOPT** (RFC) | SCIM provisioning'i Grant yazmak değildir |
| **W3C VC Data Model 2.0** | **PROFILE** (yalnız Claim ingest) | **VC ≠ Claim truth** (INV-14); VC Access projection'ının normatif taşıyıcısı değildir (R6) |
| **SD-JWT** (RFC 9901, Kasım 2025 — kayıt doğrulandı) | **ADOPT** | Seçici açıklama redaksiyon değildir (INV-30); kap semantik değildir |
| SD-JWT VC | **PROFILE (informative)** | Draft'a normatif bağımlılık yok |
| **OID4VCI 1.0 / OID4VP 1.0 / HAIP 1.0** | **PROFILE** | Sunum yetki değildir |
| **E. Call chain / cross-domain** | | |
| **Transaction Tokens** (`draft-ietf-oauth-transaction-tokens-11`, 30 Temmuz 2026; `typ: txntoken+jwt`, `Txn-Token` başlığı) | **PROFILE (RFC olunca normatif; o zamana kadar informative)** | **Txn-Token trust domain ≠ AuthorityDomain**; Txn-Token basis değildir, downstream PEP'in kendi Exercise'ının yerine geçmez (E17, EI-17). Ajan zincirinde kullanımı §11.11 |
| **Identity & Authorization Chaining** | **PROFILE** | Lineage'ı korumaz; Access proof'u ayrıca taşınır |
| **ID-JAG (Cross App Access)** (`draft-ietf-oauth-identity-assertion-authz-grant-04`) + **MCP Enterprise-Managed Authorization** | **PROFILE (Claim/assertion taşıyıcısı olarak; identity plane hem üretir hem tüketir)** / **REJECT (Access authorization grant'ı olarak)** | IdP-mediated "authorization grant" Access Grant'ı değildir; IdP grantor olamaz (L6, E18). Tüketildiğinde ID-JAG bir `actor-binding`/`predicate-input` Claim'idir; resource AS'in verdiği token `projection.issue` çıktısıdır; bağlantı politikası tuple'ı Acceptance + Grant şablonuna derlenir (§11.11.2). Üretilen ID-JAG authority taşımaz ve authority scope içermez; Resource AS'teki yetki o AS'in kendi kararıdır (Access ise §11.11.3 Grant'ı) |
| **RFC 9200 ACE-OAuth** | **PROFILE** (constrained/edge verifier, opsiyonel binding) | — |
| **F. Attenuable capabilities** | | |
| **Biscuit** | **REJECT** (WATCH; gerekçeli) | Datalog check'leri Access'in closed attenuation type system'i değildir (INV-8, E12); Biscuit'i Access projection'ı olarak kullanmak ya Datalog'u ⊑ kanıtına sokmayı (L9 ihlali) ya da onu bir Access alt kümesine kısıtlayan ağır bir profile'ı gerektirir; kazanç yok. Offline attenuation deseninin PAP'ta karşılığı yoktur (holder tarafı daraltma tanımlı değil); alt-ajan delegasyonu çevrimiçi `grant.issue`'dur, çünkü cascade revocation ve açıklanabilirlik ondan gelir ("format değil fikir") |
| **UCAN 1.0** | **REJECT** (WATCH; pattern kaynağı) | UCAN'da capability possession authority'dir; Access'te possession ≠ authority ve Decision ≠ Credential; invocation semantiği Access Exercise'ı değildir |
| **ZCAP** | **REJECT** | Draft; linked-data capability semantiği Access dışı |
| Macaroons | **REJECT** | Format N/A |
| **G. Agent ecosystems** | | |
| **MCP Authorization** (rev. 2026-07-28) | **PROFILE** (hedef; normatif profil §11) | MCP'nin kendi consent/elicitation akışı approval değildir (EI-18); MCP server kimliği tool tanımının doğruluğu değildir (tool description = authority-opaque, instruction değil, A-7). Rol ve ontology eşlemesi §9.4.1'dedir |
| **A2A** (1.0.0, Linux Foundation — kayıt doğrulandı; v1.0 tarihi kaynaklarda çelişkilidir: Mart / Ağustos 2026 — **doğrulanmadı**) | **ADOPT** (agent↔agent task transport) + **EXTEND** (A2A extension: authority request ve causal ref taşıma) | Agent Card authority değildir; A2A task devri authority devri değildir (E8); A2A mesajındaki onay contribution değildir. Rol ve ontology eşlemesi §9.4.1; identity plane'in A2A `securitySchemes` desteği §11.15 |
| **AP2** (v0.2 — kayıt doğrulandı: Checkout Mandate + Payment Mandate, SD-JWT) | **REJECT** (Access semantiği olarak) — **Pay'in PROFILE'ı** (scheme artifact) | **AP2 "mandate" ≠ Access Mandate** (E21, X24); AP2 imzası Access contribution'ı değildir |
| **PSD2 consent / Open Banking consent nesneleri** | **REJECT** (Access semantiği olarak) — Pay/ASPSP artifact'ı | Consent objesi Access source'unu genişletemez (E21) |
| **PSD2 RTS Art. 5 dynamic linking** | **ADOPT (ilke)** → Approval Surface profile | Genel "Confirm?" |
| **W3C SPC** | **PROFILE (informative; Pay/Experience owner)** | SPC'nin gösterdiği veri canonical render'ın yerine geçmez; eşleşmezse onay yok |
| **H. Work Protocol ile ortak katmanlar** | | |
| **PartyID + key-event history; Identity Binding** | **ADOPT (tek ortak regime)** | Access ayrı bir Party regime'i tanımlamaz; PartyRef = regime referansı (E4, EI-7). Regime ↔ Claim sınıfları (§9.13) regime olaylarının Access'e giriş biçimidir |
| **Portable authority proof — üç kontrol** (cryptographic validity, issuer trust for scope, semantic coverage) | **ADOPT** | Foreign Authority Proof doğrulaması aynı üç kontrolü yapar, artı Access'in tazelik koşulu; Work bir Access ExerciseID'yi aynı üç kontrolle doğrular |
| **Determinism** | **ADOPT** | INV-27 ile aynı form; "farklı trusted issuer kümesi → açık divergence, protocol hatası değil" Access için de geçerlidir |
| **Conformance profiles** (Verifier, Federation Peer, Executor, Approval Surface, Practice Package, Witness) | **PROFILE + EXTEND** | Approval Surface profile **ortaktır**; Access kendi profillerini ekler (Provider, Decision PEP, Offline Verifier, Claim Issuer, Schema Publisher, Coordinator, Event Receiver). Witness profili ortak kullanılabilir (checkpoint co-sign) |
| **Approval Contract** | **PROFILE (ortak)** | Approval Act Statement Work Approval Contract'ın Access tarafıdır; üçüncü semantik owner yaratmaz |
| **Signed semantic records, receipts, checkpoints; deterministic encoding** | **ADOPT (aile)** | Access Record Exchange aynı imzalı-kayıt ve checkpoint ailesini kullanır; Work'ün deterministic CBOR/CDDL kararı Access record exchange için **varsayılan hizalama** olarak alınır (ayrılma gerekçe ister); byte encoding §16'dadır |
| **Open/proprietary boundary, vendor exit** | **ADOPT** | aynı ayrımı uygular |
| **Executor Contract** (A2A profile) | **PROFILE** | Continuation hook'ları (E31), stop/confirmed-stopped Claim'leri ve effect attestation Executor Contract'ın içinde, Access sözleşmesine referansla |
| **Federation admission** (admit / quarantine / reasonedly reject; silent drop yok) | **ADOPT** | Authenticated foreign Claim/proof ingest'inde aynı kural |

**Standart semantiği Access semantiğini sessizce ezemez — yedi kural (S-1–S-7).**

| # | Standart semantiği | Access kuralı | Nasıl korunur |
|---|---|---|---|
| S-1 | OAuth Grant / refresh token "kullanıcı izin verdi" | Holding yalnız `grant.issue` Exercise'ıyla doğar | OAuth authorization yalnız S1/AP-6 üzerinden alınmış bir `grant.issue` + `projection.issue` sonucunu taşır |
| S-2 | Scope string'i yetkidir | OAuth scope ≠ Access authority | Projection'da authority-bearing scope yok (R3) |
| S-3 | AuthZEN subject = karar konusu | Actor yalnız doğrulanmış Actor Intent Statement'tan (actor Instance'ın KeyBinding'iyle); capacity ve basis açık | Statement'sız istek Anonymous; PEP transport kimliği actor olmaz (R2) |
| S-4 | `act` zinciri = delegation kanıtı | Lineage Access kayıtlarında | `act` ipucudur (L22); Decision lineage'ı kayıtlardan doğrular |
| S-5 | Trust chain / trust mark = güven | Trust = use-typed Acceptance | Trust chain yalnız Acceptance'ın girdisidir (INV-15, L26) |
| S-6 | Signal teslim edildi = uygulandı | Delivery ack ≠ authority-state ack; güvenlik expiry + checkpoint + version'a dayanır | E30, INV-24 |
| S-7 | Geçerli VC/imza = doğru | Claim ≠ Truth | INV-14; VC yalnız Claim taşıyıcısı |

Bu yedi kural PI-2'nin içeriğidir: **bir standardın alanı Access'te karşılığı olmayan bir anlam taşıyorsa, Access o anlamı kullanmaz.**

#### 9.4.1 Agent ecosystems: rol ve ontology eşlemesi

Bu tablo §9.4 G satırlarının "Rol" ve "Ontology eşlemesi"ni verir. Bu sütunlar MCP profilinin (§11.2) dayanağıdır.

| Standart | Statü | Karar | Rol | Ontology eşlemesi | Asla |
|---|---|---|---|---|---|
| **MCP Authorization** (rev. 2026-07-28) | Vendor/open spec | **PROFILE** (hedef) | MCP server = resource server + (ya kendisi ya arkasındaki sistem) domain PEP; MCP client = agent Instance; token = Access projection; RFC 8707 resource indicator zorunlu; token passthrough yok | MCP tool = publisher'ın schema'sındaki ActionRef; tool call = Exercise Request veya projection'ın `kind=intent` RAR'ı içinde | MCP'nin kendi consent/elicitation akışı approval değildir (EI-18); MCP server kimliği tool tanımının doğruluğu değildir (tool description = authority-opaque, instruction değil, A-7) |
| **A2A** (1.0.0, Linux Foundation — kayıt doğrulandı) | Open spec | **ADOPT** (agent↔agent task transport) + **EXTEND** (A2A extension: authority request ve causal ref taşıma) | Agent'lar arası görev, streaming, push; Agent Card securitySchemes OAuth/OIDC/mTLS'e eşlenir; "in-task authorization" Access REQUIRE_ACTION verisini taşıyabilir | A2A Task state = transport/Claim (Work §20.2); Agent Card = issuer'ın (operatörün) self-assertion'ı → Claim | Agent Card authority değildir; A2A task devri authority devri değildir (E8); A2A mesajındaki onay contribution değildir |
| **AP2** (v0.2 — kayıt doğrulandı: Checkout Mandate + Payment Mandate, SD-JWT) | Vendor spec | **REJECT** (Access semantiği olarak) — **Pay'in PROFILE'ı** (scheme artifact) | AP2 mandate'leri Pay'in scheme artifact'ıdır; GrantID/ExerciseID'ye referans verebilir | AP2 open/closed ayrımı ↔ Access Grant (zarf) / Exercise (exact intent) (L15) | **AP2 "mandate" ≠ Access Mandate** (E21, X24 §14.4); AP2 imzası Access contribution'ı değildir |
| **PSD2 consent / Open Banking consent nesneleri** | Regülasyon / scheme | **REJECT** (Access semantiği olarak) — Pay/ASPSP artifact'ı | Consent nesnesi Access Grant'ının scheme-uyumlu projection'ı veya ayrı regülasyon kaydı | Grant'a referans | Consent objesi Access source'unu genişletemez (E21) |
| **PSD2 RTS Art. 5 dynamic linking** | Regülasyon | **ADOPT (ilke)** → Approval Surface profile | Tutar + alıcıya bağlı onay | L14, AP-6 | Genel "Confirm?" |
| **W3C SPC** | W3C CR Draft | **PROFILE (informative; Pay/Experience owner)** | Ödeme intent'i için trusted UI + authentication assertion | SPC assertion = `authentication` Claim, binding = statement digest (§9.14) | SPC'nin gösterdiği veri canonical render'ın yerine geçmez; eşleşmezse onay yok |

#### 9.4.2 Ek standart ve taslak satırları

§9.4 tablosunun kapsamadığı standart ve taslaklar burada aynı karar dilinde yer alır. Statüler Eylül 2026 Datatracker taramasındandır. "Doğrulanmadı" etiketleri korunur. Taslağa normatif bağımlılık yoktur (L27). "Arayüz hazır" kararı, alanın ayrıştırılıp Claim veya projection'a eşlenebildiğini, ama Access semantiğine girdi olmadığını söyler.

| Standart / taslak | Durum | Karar | Access semantiğini ezemeyeceği yer / not |
|---|---|---|---|
| **AuthZEN Authorization API 1.0** | Final, 11 Ocak 2026; onay 12 Ocak 2026, 81 kabul / 1 ret / 25 çekimser | **PROFILE + EXTEND** (ADP) | Final statüsü API yüzeyini dondurur; ADP'nin taşıyıcısı sabittir. Uyum kontrol listesi §9.5.1 |
| AuthZEN **OAuth 2.0 token verme profili** | openid/authzen deposunda taslak | **WATCH** | Token verme kararını dışsallaştırır; Access'te token verme zaten `projection.issue` kararıdır (§9.9). Profil Final olursa `projection.issue`'nun AuthZEN görünümü olarak PROFILE adayıdır |
| AuthZEN **token değişimi bağlaması** (`draft-gazitt-oauth-authzen-token-exchange-01`) | Bireysel taslak, 2 Eylül 2026 | **WATCH** | İki değerlendirme (özne kapısı, isteyen taraf kapısı) Access'te actor-binding + basis/capacity kontrolüne denk düşer; actor yine AIS'ten türer (R2) |
| AuthZEN **yetkilendirme iddiaları profili** | openid/authzen deposunda taslak | **WATCH** (iki katmanlı token'ın kaba katmanı için aday) | Token'a gömülen iddia **tek başına yetki kanıtı değildir** ("kritik kural"); Access'te projection ⊆ AuthoritySet ∩ Mandate ve ValidityContract taşır (§9.9.6) |
| AuthZEN **erişim isteği ve onay profili** (AARP) | WG taslağı, 15 Haziran 2026 | **WATCH + eşleme** | §9.4 AARP satırı ve §9.9.5 |
| AuthZEN **MCP araç yetkilendirmesi profili** (COAZ-MCP) | WG taslağı | **REJECT / WATCH** | §9.4 COAZ satırı |
| `draft-ietf-oauth-rar-metadata-remediation-00` | WG Doc, 23 Ağustos 2026 | **WATCH; arayüz hazır** | `insufficient_authorization` hata kodu ve `authorization_remediation` REQUIRE_ACTION'ın OAuth görünümüdür (§9.9.5). `authorization_details_types_metadata_endpoint` SPP'nin RAR görünümü olabilir (§9.13.5); type tanımı yine SPP + `schema-definition` Acceptance'tır |
| `draft-ietf-oauth-refresh-token-expiration-03` | WG Doc, 6 Temmuz 2026 | **WATCH; arayüz hazır** | "The refresh token MUST NOT expire later than the user authorization expires" kuralı Access'te zaten yapısaldır: refresh, yeni `projection.issue` kararıdır ve Grant/Mandate sona erince DENY olur (§9.9). `authorization_expires_in` değeri Grant'ın validity'sinin requester'a görünür projection'ıdır |
| `draft-ietf-oauth-identity-chaining-17` | IESG'den geçti, RFC Editor kuyruğunda, Proposed Standard, 19 Temmuz 2026 | **PROFILE** (§9.4 satırı; RFC olunca normatif) | Lineage'ı korumaz; Access proof'u ayrıca taşınır. ID-JAG bunun profilidir (§11.11) |
| `draft-ietf-oauth-first-party-apps-04` (FiPA) | WG uzlaşısı | → §10 | `insufficient_authorization` hata kodu §9.9.5 eşlemesinde kullanılır |
| `draft-ietf-oauth-spiffe-client-auth-02` | WG Doc, 15 Haziran 2026 | **PROFILE (RFC olunca normatif)**; identity plane istemci kimlik doğrulaması olarak | Workload istemci kimlik doğrulamasıdır; sonucu `identity-binding.workload` Claim'idir, authority değildir (L25). §11.12 |
| `draft-ietf-oauth-client-id-metadata-document-02` (CIMD) | WG Doc, 6 Temmuz 2026 | **ADOPT (-02; -00 uyumluluğu belgelenir)** | CIMD `client_id` bir actor değildir (PI-7); istemci kaydı identity plane kaydıdır. Normatif ayrıntı §11.3 |
| Delegasyon zinciri taslakları (7 rakip; `draft-liu-oauth-chain-delegation-00`, `draft-mcguinness-oauth-actor-profile-00`, `draft-asor-wimse-agent-delegation-chain-01`, `draft-niyikiza-…-01`, `draft-hamr-…-01`, `draft-li-…-03`, `draft-mcguinness-oauth-mission-00`) | Hepsi bireysel; hiçbiri WG'de değil | **WATCH**; `delegation_chain` yalnız PROFILE seçeneği (§11.10) | Kanonik zincir Access lineage kaydıdır; token'daki zincir yalnız imzalı excerpt / ipucudur (L22) |
| Ajan claim taslakları (`draft-mora-oauth-entity-profiles-01`, `draft-mcguinness-oauth-ai-agent-instance-00`, `draft-sharif-openid-agent-identity-01`) | Bireysel | **WATCH; `sub_profile` ve `agent_instance_id` arayüz hazır** | Bu alanlar Claim'dir; `agent_trust_score` gibi değerler hiçbir zaman Grant veya Acceptance yerine geçmez (§11.17) |
| `draft-ietf-oauth-transaction-tokens-11`, WIMSE WIT/WPT (`draft-ietf-wimse-*`) | WG Doc'lar; WIMSE'den henüz RFC yok | §9.4 satırları geçerlidir; ayrıntı §11.12 | — |
| MCP SEP'leri: SEP-1932 (DPoP), SEP-1933 (Workload Identity Federation), SEP-2752 (HTTP Message Signing), SEP-2643 (Structured Authorization Denials), SEP-2848 (Asynchronous Approval for Tool Calls), SEP-2817 (AI Invocation Audit Context), SEP-3149 (CIMD token endpoint auth) | Açık, 8 Eylül 2026 itibarıyla | **WATCH**; SEP-2643/2848 REQUIRE_ACTION ile eşlenir (§9.9.5, §11.8) | MCP içindeki ret/onay yapıları Access outcome'unun taşıyıcısıdır, kaynağı değildir |
| RFC 8414 / OIDC Discovery 1.0 | RFC / Final | **ADOPT** (identity plane) | OIDC/AS discovery kimlik belgesidir; Access Domain Metadata ayrı belgedir (§9.15.1; ayrıntı §10, §11.4) |
| RFC 7591 DCR | RFC; MCP 2026-07-28'de kullanımdan kaldırıldı | **PROFILE (yalnız geriye uyumluluk)** | §11.3 |

### 9.5 Access Decision Profile (ADP): Exercise Request ve Decision Response

**Denenen standart:** OpenID AuthZEN Authorization API 1.0 (Final). PEP ↔ PDP sözleşmesi, evaluation / evaluations / search API'leri ve discovery metadata'sı Access'in PEP-facing yüzeyinin ihtiyacını karşılıyor. **Yetmeyen yerler** (L23): subject PEP-asserted string'tir; decision boolean'dır (REQUIRE_ACTION yoktur); decision'ın kimliği, imzası, geçerlilik süresi yoktur; delegation / basis / capacity / consumption kavramı yoktur.

**Seçim: EXTEND, yeni protocol değil.** AuthZEN'in `context` alanları ve response `context`'i Access üyelerini taşımaya yeterlidir; AuthZEN'in tanımladığı her alan aynı anlamla kullanılır, yalnız Access semantiğini taşıyamayan alanların anlamı **daraltılır** (subject). Adı: **Access Decision Profile (ADP)**. Alan adları ve JSON/CBOR biçimi Technical'dadır; aşağıdakiler semantik zorunlu alanlardır.

**Exercise Request — semantik zorunlu alanlar**

| Alan | Zorunluluk | Semantik | Ontology | AuthZEN taşıyıcısı |
|---|---|---|---|---|
| `domain` | Her modda | Hedef AuthorityDomain (DomainID) | AuthorityDomain ref | `context` |
| `mode` | Her modda | `commit` (relied-upon karar; ALLOW = Exercise doğumu) · `continue` (mevcut Exercise üzerinde continuation) · `check` (advisory; kaydedilmez, söz değildir) | — | `context` |
| `nonce` | `commit`, `continue` | Exercise kimliğinin anahtarı; domain içinde tek; aynı nonce + farklı intent ifade edilemez | Exercise identity | `context` |
| **actor proof** (Actor Intent Statement) | `commit`/`continue` için Authenticated actor gerekiyorsa | **Message-level**, actor-imzalı request statement: actor Instance'ın güncel KeyBinding'iyle imzalanmış; içerik = `domain` (audience = AuthorityDomain), `nonce`, intent digest, PEP audience, `mode`, `capacity`, basis ref, zaman (`continue`'da + ExerciseID). PEP statement'ı **iletir ama üretemez**; kayıtta proof olarak saklanır | ActorContext = `Authenticated(InstanceID)`; mevcut Exercise/IntentEnvelope + Instance KeyBinding (yeni primitive değil) | `context` üyesi; kap standart (JWS/COSE ailesi; actor Access'i doğrudan çağırıyorsa HTTP Message Signatures); kap/algoritma Technical. **DPoP / mTLS / WIMSE WPT actor proof değildir** (sunuldukları HTTP isteğini/kanalı bağlar, intent digest/nonce içermez). AuthZEN `subject` Access tarafından **türetilir** |
| `basis` | `commit`/`continue`'da zorunlu; `check`'te opsiyonel | AnchorRoot · HoldingRef ⟨GrantID, holder, since⟩ · PublicGrant | INV-4 | `context` |
| `capacity` | `commit`/`continue`'da zorunlu | `OWN` veya `FOR(PartyRef)`; basis Grant'ın AgencyTerms'ünde olmalı | ExerciseCapacity | `context` |
| `intent` | Her modda | IntentEnvelope: ActionRef (namespace + name + version + schema digest), ResourceRef'ler (+ incarnation), authority-relevant typed parametreler, authority-opaque parametrelerin digest'leri, recipient, purpose, context ref'leri (WorkRef / CommitmentRef / StepRef / upstream ExerciseID), validity window | IntentEnvelope (VALUE); **digest'i Access canonical içerikten hesaplar** (caller hash seçemez) | `action` (ActionRef), `resource` (birincil ResourceRef), `context` (geri kalanı) |
| `proofs` | Gerektiğinde | Cited Claim'ler (inline veya ClaimID), contribution ExerciseID'leri, Foreign Authority Proof'lar, authentication assertion'ları | Proof rolü (Claim \| Exercise; C20) | `context` |
| `pep` | Her modda | İsteği ileten/uygulayacak PEP'in kendi authenticated kimliği (audience); Actor Intent Statement'taki PEP audience'ıyla eşleşmelidir | PEP ≠ actor (E17); opening record'da context olarak kaydedilir | ADP çağrısının transport authentication'ı (mTLS / OAuth client auth / DPoP / WIMSE WPT); yalnız PEP kimliğini kanıtlar |
| `reuse` | Opsiyonel | ValidityContract talebi (long-running/intermittent): istenen horizon, checkpoint planı | Talep; vermek domain'in kararı (E13) | `context` |

**Kurallar:**

1. **AuthZEN `subject` canonical actor değildir.** ADP'de `subject` Access'in doğruladığı Actor Intent Statement'tan türetilir (`InstanceID`, Party'si). PEP'in `subject` içine yazdığı her özellik (`properties`) authority girdisi değildir; en fazla kaydedilmeyen bir ipucudur. Bu, AuthZEN'in "PDP PEP'e güvenir" varsayımını Access için kapatır (L23).
2. **Statement'sız istek `Anonymous(context)`'tir.** Actor Intent Statement yoksa ActorContext `Anonymous(context)` olur; PEP'in transport kimliği (mTLS sertifikası, DPoP anahtarı, WPT) hiçbir zaman ActorContext'e dönüşmez. INV-11 gereği yalnız Public Grant'lar değerlendirilebilir; anonymous actor hiçbir şey tutamaz, contribution yapamaz, meta-action kullanamaz. Böylece Access profilini bilmeyen düz bir AuthZEN PEP Access'e bağlanabilir ama yalnız Public authority'den yararlanabilir; aksi her şey DENY'dır (fail closed).
3. **PEP actor değildir.** PEP kendi kimliğiyle actor yerine istek kuramaz; Actor Intent Statement actor Instance'ından gelmelidir (E17, X21 "service account acts for user" yok). PEP'in authenticated kimliği yalnız audience ve audit context'idir. Statement'ın `domain`, `nonce`, intent digest'i, `mode` veya PEP audience'ı istekle eşleşmezse istek **protocol hatasıdır** (Exercise yok); forward edilen bir statement başka bir intent'e veya başka bir nonce'a bağlanamaz (replay: nonce + digest bağlama). **Alternatif yol:** PEP ADP `commit` yerine actor'ün sunduğu exact-intent projection'ını doğrular; o durumda actor binding token'ın `cnf`'idir ve projection actor'ün kendi `projection.issue` Exercise'ının ürünüdür.
4. **Basis ve capacity açık beyan edilir** (A-1, INV-4). `commit` modunda eksiklerse istek bir değerlendirme değil **protocol hatasıdır** (malformed request): değerlendirme yapılmaz, kayıt yazılmaz, nonce tüketilmez, Exercise doğmaz. Protocol hatası bir Decision outcome'u değildir (dördüncü bir outcome yoktur); PEP için yalnız "ALLOW yok" demektir ve effect üretilmez (fail closed, INV-26). `check` modunda Access aday basis'leri advisory olarak döndürebilir (viewer/requester yetkisi kadar, E26).
5. **Idempotency.** Aynı nonce + aynı intent digest + aynı actor ile tekrar gelen `commit` isteği aynı DecisionRecord'u döndürür; ikinci bir consumption yapılmaz (INV-21). Aynı nonce + farklı intent digest reddedilir (imkânsız geçiş). DENY verilmiş nonce terminaldir (C30); REQUIRE_ACTION verilmiş nonce, eksik proof'lar eklenince aynı nonce ile yeniden değerlendirilir.

**Decision Response — semantik zorunlu alanlar**

| Alan | Ne zaman | Semantik | AuthZEN eşlemesi |
|---|---|---|---|
| `decision` (AuthZEN boolean) | Her zaman | `true` ⇔ outcome = ALLOW | AuthZEN `decision` |
| `outcome` | Her zaman | `ALLOW` · `DENY` · `REQUIRE_ACTION`. **UNKNOWN yoktur** (EI-21, INV-26) | response `context` |
| `advisory` | `check` modunda | Sonucun kaydedilmediği ve söz olmadığı bayrağı ("would be allowed now") | response `context` |
| `exercise` | `commit`/`continue` ALLOW | ExerciseID (DomainID + nonce'a bağlı), DecisionRecord ref | response `context` |
| `validity` | Reusable istendi ve verildiyse | ValidityContract | response `context` |
| `receipt` | `commit`/`continue` ALLOW | Decision Receipt | response `context` |
| `blockers` | DENY | Başarısız **tüm** engellerin kümesi | response `context` |
| `unmet` | REQUIRE_ACTION | Her karşılanmamış RequirementTerm + contribution için eligible set (requester'ın görme yetkisi kadar) | response `context` |
| `remediation` | DENY / REQUIRE_ACTION | Engel başına typed remediation kodu | response `context` |
| `evaluation_record` | Kaydedilen DENY/REQUIRE_ACTION | Nonce'a bağlı evaluation DecisionRecord ref'i (Exercise değil) | response `context` |
| `basis_ref` | ALLOW ve kaydedilen kararlar | AuthorityStateBasis'in referansı. Audit kapsamında açık (DomainID, pozisyon, version-vector digest); audit kapsamının altındaki requester/viewer'a domain anahtarıyla türetilmiş **opaque token** olarak gider ve pozisyon sızdırmaz (TI-RT10); başka anlam taşımaz | response `context` |
| `causal_binding` | Upstream causal ref'li ALLOW | `enforced` (causal-bound allowance uygulandı) · `audit-only` | response `context` |
| `witnessed_through` | Derived okumalarda | Okumanın yansıttığı witness'lı pozisyon (mevcut checkpoint verisi); UI'ın "confirming (witness pending)" niteliğinin kaynağı (§8.7) | response `context` |
| `versions` | Her zaman | Değerlendirmede kullanılan core spec / meta-schema / profile sürümleri | response `context` |

**Fail-closed eşleme (R2).** `decision = true` yalnız ALLOW'dur. DENY ve REQUIRE_ACTION `false` döner; Access profilini anlamayan bir PEP REQUIRE_ACTION'ı DENY gibi uygular. Bu yanlış yönde bir sonuç değildir: effect üretilmez; yalnız insan/claim adımı fırsatı kaybolur. Ters yön (REQUIRE_ACTION'ın `true` olarak eşlenmesi) yasaktır.

**Access-unavailable.** Access'e ulaşılamaması PEP'in UNKNOWN'udur, Access'in kararı değildir; PEP o effect için fail closed davranır, geçerli bir ValidityContract veya offline slice içinde değilse effect üretmez (E25, E28). Protocol bir "timeout ⇒ allow" seçeneği tanımlamaz (X21).

#### 9.5.1 AuthZEN 1.0 PDP uyum kontrol listesi (ADP'nin taşıyıcı yükümlülükleri)

AuthZEN 1.0 Final'in teknik içeriği.
- **Güven modeli Access'indir.** AuthZEN güvenlik bölümü "the PDP must trust the PEP" der. ADP bunu R2 ve kural 1–3 ile kapatır: subject AIS'ten türetilir, PEP actor değildir.
- **Taşıyıcı yükümlülükleri aşağıdaki tablodadır.**

| # | Gereksinim | AuthZEN seviyesi | ADP'deki karşılığı |
|---|---|---|---|
| 1 | `POST /access/v1/evaluation` | Zorunlu | `commit` / `continue` / `check` modlarının tek-öğe taşıyıcısı |
| 2 | `POST /access/v1/evaluations` + üç `evaluations_semantic` değeri | İsteğe bağlı; yapılır | Batch (§9.7); kısa devre yalnız `check`'te (§9.7.1) |
| 3 | `POST /access/v1/search/resource` | İsteğe bağlı; yapılır | "What can X reach?" (§9.7) |
| 4 | `POST /access/v1/search/subject` | İsteğe bağlı; erişim incelemesi için gerekli | "Who can do Y?", eligible set (§9.7) |
| 5 | `POST /access/v1/search/action` | İsteğe bağlı | Viewer-scoped action listesi |
| 6 | `GET /.well-known/authzen-configuration` | Zorunlu | Domain Metadata'dan türetilen discovery belgesi (AP-15, §9.15). `policy_decision_point` iyi bilinen adresin inşa edildiği tanımlayıcıyla aynı olmalıdır. `capabilities` dizisi ADP profilini, explain operasyonunu ve `consistency_token`'ı ilan eder. `signed_metadata` Domain Metadata imzasıyla verilir (MD-3) |
| 7 | Ret = HTTP 200 + `{"decision": false}` | Zorunlu | DENY ve REQUIRE_ACTION 200 + `decision=false` döner. Protocol hatası (kural 4) 400'dür. 401/403 PEP'in PDP'ye erişim yetkisi sorunudur, bir Decision değildir. Bu ayrımı karıştırmak fail-open sınıfı hatadır |
| 8 | `X-Request-ID` yankısı | Varsa zorunlu | İz korelasyonu; DecisionRecord'un context'ine yazılır, authority girdisi değildir |
| 9 | Bilinmeyen alanları yok say | Zorunlu | **Yalnız AuthZEN taşıyıcı alanları için.** ADP'nin must-understand üyeleri (R7, P34) yok sayılmaz; anlaşılmayan must-understand üyesi DENY'dır. İki kural çelişmez: AuthZEN'in ileri uyumluluk kuralı taşıyıcıya, R7 Access semantiğine uygulanır |
| 10 | TLS; PEP kimlik doğrulaması (mTLS / OAuth / API anahtarı) | Sırasıyla zorunlu / önerilen | `pep` alanının transport authentication'ı (§9.5 tablo). ADP'de PEP kimlik doğrulaması zorunludur. API anahtarı yalnız Public-only PEP'lerde kabul edilir (çıkarım: anonim PEP zaten yalnız Public authority'den yararlanır, kural 2) |
| 11 | I-JSON (RFC 7493), UTF-8, IEEE 754 sınırları | Önerilen | Zorunlu. Authority-relevant sayısal parametreler closed type'ta (E12) birimli tamsayı/ondalık olarak taşınır; IEEE 754 kayan nokta authority sınırı ifade etmez (çıkarım; T-kararları §16) |
| 12 | DoS korumaları: yük boyutu, istek sayısı, geçersiz JSON, iç içe JSON, bellek | Önerilen | Zorunlu; sınır değerleri §14 (parser/DoS) |
| 13 | `reason_admin` / `reason_user` ayrımı | İsteğe bağlı; yapılır | Disclosure scope'un AuthZEN görünümü (§9.6.1) |

Taşıma: HTTPS + JSON bağlaması normatiftir. Uç noktalar `v1` içerir. JSON üye sıralaması varsayılmaz. gRPC/CoAP bağlamaları profilde tanımlanabilir. ADP'nin CBOR biçimi §16'dadır.

#### 9.5.2 ADP ek kuralları

1. **Tutarlılık belirteci `context.consistency_token`.**
   - AuthZEN'de tutarlılık belirteci için ayrılmış alan yoktur.
   - ADP bunu istekte ve yanıtta `context.consistency_token` üyesiyle taşır ve discovery `capabilities` dizisinde ilan eder.
   - Değeri `at_least(position)` / `as_of(position)` okuma sınıfının (§9.7A.2) opak taşıyıcısıdır; requester'a giden biçimi `basis_ref` gibi opaque token'dır (TI-RT10).
   - **Yalnız `check`, search ve explain'de anlamlıdır.** `commit` / `continue` her zaman head okur; belirteç verilse bile commit'i gevşetemez.
   - Bu boşluk AuthZEN WG'ye bildirilir (§9.17.5).
   -
2. **Contextual tuple yoktur.**
   - AuthZEN/OpenFGA'nın "istek kapsamlı tuple"ı ("yalnızca GÜVENİLEN PEP'lerden kabul edilmeli") ADP'de authority girdisi olarak kabul edilmez.
   - PEP'in sunduğu bağlam olgusu yalnız şu koşulda değerlendirmeye girer: PEP, aktif bir Acceptance'ı olan bir issuer olarak `predicate-input` use'unda Claim sunar.
   - Bu Claim yalnız RequirementTerm/RestrictionPolicy girdisidir; pozitif holder seçimine (`subject-selection`) giremez.
   - Gerekçe: PEP'e güven, confused deputy açık sınıfını yeniden açar.
   -
3. **Kiracı/domain bağlamı imzadan gelir.**
   - Kararın domain'i AIS'te actor'ün imzaladığı `domain` alanıdır.
   - Token'daki `tenant` iddiası veya PEP'in yazdığı bağlam domain seçemez.
   - `tenant_id` hiçbir authority kararına girdi değildir (MD-5).
4. **Kaynak parametresi gün-1'den zorunludur.**
   - ADP `intent` her zaman ActionRef + ResourceRef taşır; kaynaksız "rol kontrolü" ifade edilemez.
   - Bu, RBAC→ReBAC geçiş dersinin sonucudur.
5. **Idempotency-Key → nonce.**
   - REST yönetim uç noktaları (§9.7 "admin API ayrı yazma yolu olamaz") `Idempotency-Key` başlığını kabul edebilir.
   - Bu anahtar meta-Exercise'ın `nonce`'una deterministik olarak eşlenir. Semantik kural 5'tir:
     - gereken yerde anahtar yok → 400;
     - aynı anahtar + aynı intent → aynı DecisionRecord;
     - aynı anahtar + farklı intent (yük parmak izi farklı) → 422 (imkânsız geçiş);
     - aynı anahtarı paylaşan eşzamanlı uçuştaki istek → 409.
   - Anahtar en fazla 255 karakterdir ve kişisel veri içermez. Saklama penceresi yayımlanır (referans: Stripe'ın 30 günü).
   - "Başarısız ilk deneme yeniden çalıştırılır" kuralı yalnız **protocol hatası** (kural 4: değerlendirme yok, nonce tüketilmez) için geçerlidir. DENY verilmiş nonce terminaldir (C30); aynı anahtarla yeniden gönderim aynı DENY DecisionRecord'unu döndürür. Bu bir çıkarımdır.
6. **PEP SDK'sında derleme zamanı yetki kanıtı.**
   - Access PEP SDK'sı (Rust, MD-1) handler imzalarında `Authorized<R, A>` tipini sunar.
   - Yapıcısı private'tır; yalnız ALLOW almış bir ADP kararından ya da doğrulanmış bir projection kontrolünden üretilir.
   - Değer ExerciseID'yi ve intent digest'ini taşır.
   - Handler effect'ten önce INV-19 kontrolünü yapar: gerçek parametrelerin digest'i intent digest'iyle eşleşmelidir.
   - Bu, "kontrolü unutma" sınıfını yapısal olarak kapatır.
   - Garanti sınıfı: SDK'yı kullanan PEP için **UNDER DECLARED CAPABILITY**. Conformant olmayan PEP için **NOT GUARANTEED**. PEP enforcement'ı Access'in kontrolünde değildir (E17).
7. **Görülemeyen kaynakta DENY = yokluk.**
   - Requester'ın görme yetkisi olmayan bir kaynak için DENY cevabı "kaynak yok" cevabından ayırt edilemez.
   - Blocker `position`'ı ve resolver kimliği E26 kapsamında gizlenir.
   - 403 ile 404 ayrımı bir ifşadır. PEP SDK varsayılanı gizlemedir.
   -
8. **Fail-closed eşlemenin HTTP görünümü (MD-8).**
   - PEP, ADP çağrısında 5xx, zaman aşımı veya ayrıştırılamayan yanıt alırsa effect üretmez (DENY gibi davranır). Bu Access'in kararı değildir (Access-unavailable kuralı yukarıda).
   - Rate limiter, risk motoru veya cache arızası hiçbir zaman ALLOW'a dönmez.

### 9.6 Blocker, remediation, seviye ve açıklama derinliği

**Blocker** (DENY'ın her elemanı) semantik zorunlu alanları:

| Alan | Değer kümesi | Not |
|---|---|---|
| `class` | X19'daki on sınıf: `no-covering-authority`, `outside-instance-limits`, `restricted`, `budget-exhausted`, `ended`, `capacity-mismatch`, `source-not-accepted`, `schema-not-accepted`, `nonce-closed`, `foreign-status-unavailable` | **Kapalı küme.** Yeni üst-düzey sınıf protocol governance ister |
| `subcode` | Namespaced, opsiyonel (ör. `ended/expired`, `ended/revoked`, `ended/lapsed`, `restricted/policy:<PolicyRef>`, `nonce-closed/pre-recovery`, `budget-exhausted/release-exceeds-draw`) | Bilinmeyen subcode üst sınıf olarak yorumlanır (P15) |
| `position` | Engelin requester'ın basis zincirindeki yeri: `instance` (actor'ün Mandate'i / Instance restriction), `hop(k)` (basis'ten köke doğru k'ıncı lineage halkası; 0 = requester'ın basis Grant'ı), `anchor` (root terms), `domain-policy` (kapsam RestrictionPolicy'si), `foreign` (foreign domain), `actor-side` | Seviye bu konumdan türetilir. Halkanın kimliği (GrantID, grantor) requester'ın görme yetkisi kadar açılır, aksi hâlde yalnız `hop(k)` döner (E26) |
| `resolver` | Engeli kimin kaldırabileceğinin **sınıfı**: `grantor-of-hop(k)`, `root`, `restriction-owner`, `issuer`, `domain-admin`, `actor`, `actor-party` (Mandate için), `time` | "Who can: …" satırının kaynağı (X8); kişi listesi değil sınıf; kişiler viewer-scoped explain'de (aşağıda) |
| `remediation` | Altı kod: `route-to-coordinator`, `refresh-claim`, `self-authenticate`, `wait-until(T)`, `not-satisfiable-by-actor`, `new-request-required` | Planlama verisidir, talimat değildir (A-7); serbest metin alanı yoktur |
| `wait_until` | `remediation = wait-until` ise | Budget penceresinin trusted-time'daki sıfırlanma anı |

**Unmet RequirementTerm** (REQUIRE_ACTION'ın her elemanı) biçiminin projection'ıdır: `proofKind`, `class`, `count` (kalan), `binding` (none / actor Instance / intent digest / resource), `freshness`, `independence`, `consumption`, `source` (Claim için kabul edilmiş issuer kapsamı; contribution için eligible set'in requester'ın görebildiği kadarı), `position` (requirement'ın hangi halkadan / politikadan geldiği), `satisfiable_by_actor` (bool; insan-varlığı gerektiren ve actor bir agent Instance'ı ise `false` → `not-satisfiable-by-actor`, X19).

**Seviye nasıl hesaplanır (X8).** Protocol seviyeyi viewer'a göre **göreli** iletmez; çünkü cevap requester'a (agent'a) gider, viewer (Alice) başka biridir. İki adım:

1. Agent-facing cevap yalnız `position`'ı (requester'ın zincirine göre) taşır.
2. Kullanıcının yüzeyi (S3/S1/S5) aynı DecisionRecord veya evaluation ref'i için **viewer-scoped explain** ister (AP-2). Access viewer'ın kendi lineage konumunu bilir ve her engel için `relative_to_viewer ∈ {below-viewer, at-or-above-viewer, outside-viewer-lineage}` döndürür. "Give access once" seçeneğinin sunulup sunulmayacağı (X8) bu alandan hesaplanır; Experience'ın uydurduğu bir şey değildir.

**Açıklama derinliği.** Default / Expert / Audit Experience kademeleridir; protocol'deki karşılığı **disclosure scope**'tur: `requester` (Decision Response'un kendisi), `viewer(PartyRef)` (viewer-scoped explain; viewer'ın authority'si kadar), `audit` (Audit yetkisi gerektirir; StateBasis içeriği, cited Claim/Acceptance/policy sürümleri, consumption). Her kapsam, ilgili Party'nin authority'si ile sınırlıdır (E26); daha derin kademe daha az derin kademeyle çelişemez (X25). Explanation oracle'ına karşı rate ve detay sınırları Security'dedir (§13).

**Recovery ve budget blocker'ları (kapalı sınıfların subcode'ları; yeni üst-düzey sınıf yoktur, P14).**

| Blocker | Ne zaman | Resolver | Remediation |
|---|---|---|---|
| `nonce-closed/pre-recovery` | Forced recovery'den önce zamanlı, nonce'u devam eden lineage'da bulunmayan bir AIS ile istek (SEC22 R1 (c); U28). Mekanizma tektir: ilk değerlendirmede AIS yaşı ≤ intent validity tavanı (profile kuralı) + CT3 ile kaldırılabilen SEC22 R1 quarantine policy'si | `actor` (yeni nonce + yeni AIS ile yeniden imzalama) | `new-request-required` |
| `budget-exhausted/release-exceeds-draw` | Bir `consumption.release` Exercise'ının Σrelease'i ilgili Exercise'ın draw'unu aşardı (TI-RT8) | `actor` / `issuer` (grounded Claim düzeltmesi) | `not-satisfiable-by-actor` veya `refresh-claim` |

#### 9.6.1 AuthZEN `reason_admin` / `reason_user` ↔ disclosure scope

AuthZEN 1.0 ret yanıtında iki gerekçe tanımlar: `context.reason_admin` (yönetici tam nedeni görür) ve `context.reason_user` (kullanıcıya bilgi sızdırmayan mesaj). ADP bu iki alanı disclosure scope'un **taşıyıcı görünümü** olarak doldurur. Yeni bir açıklama kanalı açmaz.

| AuthZEN alanı | ADP içeriği | Kural |
|---|---|---|
| `reason_user` | `requester` kapsamı. Blocker sınıfları, `position` (yalnız `hop(k)`), remediation kodu | Serbest metin yoktur. Kullanıcı dilindeki metin Experience'ın kod → metin çevirisidir (A-7: açıklama talimat değildir) |
| `reason_admin` | `audit` kapsamı: StateBasis ref'i, cited Claim/Acceptance/policy sürümleri, consumption | Yalnız çağıran PEP'in audit authority'si varsa doldurulur. Yoksa alan hiç yer almaz. Yer alması bir ifşadır (E26) |
| (yok) | `viewer(PartyRef)` kapsamı | AuthZEN'de karşılığı yoktur. Viewer-scoped explain operasyonuyla (§9.7) alınır |

Gerekçe: AuthZEN'in iki gerekçe ayrımı Access'in üç kademeli disclosure scope'unun iki kademesine denk düşer. Viewer kademesi Access'e özgüdür.

### 9.7 Advisory check, explain, batch, meta-action ve Exercise yaşam döngüsü

| İşlem | ADP karşılığı | Ontology | Kural |
|---|---|---|---|
| "Would this be allowed now?" | `mode = check` evaluation | DERIVED result | Kaydedilmez; `advisory = true`; cevap credential değildir, cache'lenip izin olarak kullanılamaz (A-10, L17) |
| "Who can do Y?", "What can X reach?" | AuthZEN Subject / Resource / Action Search (PROFILE) | DERIVED graph sorgusu | Sonuç requester'ın görme yetkisi kadardır (E26); eligible set sorgusu (Work Gate için) aynı yoldan |
| "Why was this allowed/denied?" | Explain (AuthZEN dışı bir Access operasyonu; AuthZEN discovery'de ilan edilir) | DERIVED proof inşası | Disclosure scope'a tabidir; geçmiş karar için DecisionRecord'dan, varsayımsal için advisory'den; ikisi etiketle ayrılır |
| Agent'ın kendi durumu | `check` + kendi Instance'ı için summary | DERIVED | Principal'ın diğer delegation'larını göstermez |

**Batch.** AuthZEN `evaluations` çağrısı ADP'de **bağımsız isteklerin kümesidir**: her öğe kendi nonce'unu (commit modunda), kendi Actor Intent Statement'ını ve kendi kararını taşır; öğeler arası atomicity yoktur (E29; ontology'de çok-intent'li tek Exercise yoktur). AuthZEN'in kısa-devre değerlendirme seçenekleri **yalnız `check` modunda** kullanılabilir; `commit` modunda her öğe değerlendirilir ve her ALLOW kendi Exercise'ıdır. "Hepsi ya da hiçbiri" isteyen bir domain akışı bunu Executor/domain'in compensation'ıyla çözer, Access'te değil.

**Meta-action'lar aynı sözleşmeden geçer.** `grant.issue`, `grant.amend`, `grant.revoke`, `grant.renounce`, `mandate.*`, `acceptance.*`, `policy.set`, `anchor.*`, `domain.handover` / `domain.recover`, `instance.*`, `claim.issue`, `contribute`, `consumption.release`, `projection.issue` Exercise Request'in `intent.action`'ında core namespace ActionRef olarak gelir. Payload (ör. yeni Grant içeriği) IntentEnvelope'un typed parametreleridir; core meta-schema'lar Access Core Semantic Spec'in parçasıdır. Access-internal action'larda Access hem decider hem PEP'tir; ALLOW commit effect'in kendisidir.

Sonuç: **Bir "admin API" ayrı bir yazma yolu olamaz.** Bir implementasyon kolaylık için REST/gRPC yönetim uç noktaları sunabilir; ama her biri bir meta-Exercise Request'e indirgenmek zorundadır ve aynı actor proof, basis, capacity, requirement ve kayıt kurallarına tabidir (PI-4). Conformance suite bunu test eder: actor proof'u olmayan bir yönetim çağrısı authority state'ini değiştiremez.

**Exercise yaşam döngüsünün wire karşılığı.**

```text
commit(nonce, intent, basis, capacity, proofs)
├─ REQUIRE_ACTION(unmet, remediation) ── evaluation; nonce açık kalır (intent validity'ye kadar)
│ └─ commit(aynı nonce, aynı intent, + proofs) → yeniden değerlendirme
├─ DENY(blockers) ── nonce terminal (C30); yeni deneme yeni nonce + state değişikliği
└─ ALLOW(exercise, receipt[, validity]) ══ Exercise doğar; consumption atomik commit (INV-21)
├─ continue(exercise, checkpoint) → ALLOW (yeni DecisionRecord, yeni StateBasis, yeni ValidityContract)
│ → DENY (Exercise ileriye dönük kapanır; geçmiş ALLOW geçerli kalır)
├─ attest(effect.attestation | effect.non-execution Claim, ExerciseID) ── Executor/domain issuer
└─ consumption.release(ExerciseID, grounded Claim) ── meta-Exercise
```

Wire'da açık olmayan tek şey effect'tir: Access'e effect hakkında yalnız Claim gelir (INV-18).

**Continuation.**

| Alan | Semantik |
|---|---|
| `mode = continue` | Mevcut Exercise üzerinde yeni karar |
| `exercise` | Devam ettirilen ExerciseID |
| actor proof | **Aynı Instance**'tan Actor Intent Statement (`mode = continue`, ExerciseID'ye bağlı; Executor kendi adına continuation isteyemez) |
| `checkpoint` | Executor'ın beyan ettiği checkpoint ref'i (opaque) ve o ana kadarki attested ilerleme (opsiyonel Claim) |
| `intent` | Aynı IntentEnvelope digest'i; envelope değiştiyse continuation değil yeni `commit` gerekir (INV-19) |

Access continuation'ı kendi güncel StateBasis'iyle değerlendirir; bu bir "renewal" değil yeni bir karardır (L19). DENY, Exercise'ı ileriye dönük kapatır; Executor yeni consequential effect başlatmaz (A-8). Executor Contract (Work) bu hook'u taşır; A2A binding'inde continuation bir A2A extension mesajıyla tetiklenebilir, ama karar yine ADP üzerinden Access'ten gelir.

#### 9.7.1 Search, batch ve explain: taşıyıcı ayrıntısı ve sınırlar

**Search API'leri.** AuthZEN 1.0'da üç search uç noktası Final şartnamenin içindedir: `search/subject`, `search/resource`, `search/action`. Hepsi `page.next_token` zorunlu sayfalamayla gelir; boş `next_token` listenin bittiğini söyler. ADP'de:

- Search her zaman **DERIVED** bir sorgudur, `advisory = true` taşır ve hiçbir zaman bir Exercise doğurmaz (§9.7 tablo).
- Sonuç requester'ın görme yetkisiyle sınırlıdır (E26). Sayfa içeriği ve `page.total` aynı disclosure filtresinden geçer. Toplam sayı, filtre dışı kayıtların varlığını sızdırmamalıdır (çıkarım).
- **Zorunlu sınırlar** (kotalar; EA):

  | Sınır | Değer |
  |---|---|
  | Sert son tarih | 1 s |
  | Sayfa başına azami sonuç | 1000 |
  | Sayfalama | Zorunlu |

  Son tarih aşılırsa cevap kısmi değildir. Hata döner, ADP dilinde advisory'de "cevap yok" olur. Kısmi liste bir izin listesi gibi okunamaz.
- **Check/List tutarlılığı.** Aynı consistency token altında `search/resource` sonucunda görünen her (subject, action, resource) için `check` aynı cevabı vermelidir. Bunun tersi de geçerlidir.
  - OpenFGA/SpiceDB'de beş açığın kaynağı bu sınıftır.
  - AGI adayı değildir; §6'daki Check/List uyumu adayına işaret eder.

**Batch semantik eşlemesi.** AuthZEN `evaluations_semantic` değerleri ADP'de şöyle eşlenir:

| `evaluations_semantic` | `check` modunda | `commit` / `continue` modunda |
|---|---|---|
| `execute_all` | İzinli | **Tek izinli değer.** Her öğe değerlendirilir, her ALLOW kendi Exercise'ıdır |
| `deny_on_first_deny` | İzinli. Sıcak yol kancası olarak kullanılır. Değerlendirilmeyen öğeler "değerlendirilmedi" döner, DENY değil | **Protocol hatası.** Kısa devre hangi öğenin commit edildiğini belirsiz bırakır |
| `permit_on_first_permit` | İzinli | **Protocol hatası** |

**Batch = tekil değişmezi**: Bir batch'teki her öğenin sonucu, aynı consistency token altında tek başına `evaluation` çağrısının sonucuyla aynıdır. Varsayılan alan devralma (üst seviye subject/action/context) yalnız kodlama kısaltmasıdır. Commit modunda her öğe kendi AIS'ini taşıdığı için devralınan `subject` hiçbir öğenin actor'ünü belirlemez.

**Explain.** Explain viewer-scoped bir DERIVED proof inşasıdır (§9.6, §9.7). `explain → DecisionTrace` tarzı operasyonlar ve Cedar Diagnostics benzeri örneklenmiş izler **debug telemetrisidir**:
- Disclosure scope'a tabidir.
- Audit kapsamı dışında yalnız operatörün kendi gözlemlenebilirlik verisidir.
- Hiçbir zaman requester'a ham karar ağacı olarak dönmez (explanation oracle sınırları §13).

### 9.7A Türetilmiş graf indeksi, okuma tutarlılık sınıfları, önbellek ve sıcak yol

- **Semantik.** Pozitif yetki yalnız Grant lineage'ından gelir. ReBAC/Zanzibar motoru türetilmiş indeks (CMP-9) ve sorgu motorudur (CMP-11). Bu motor hiçbir zaman commit-mode ALLOW üretmez (MD-4, TI-5).
- **Teknik.** Leopard tarzı indeks, tutarlılık belirteci, önbellek ve kotalar teknik katmandır.
- **Bileşen ayrıntısı.** Bileşen kimlikleri ve bileşen tarafı §16'da, veri ve operasyon tarafı §17'dedir. Burada yalnız protocol'e görünen kurallar yazılır.

#### 9.7A.1 Türetilmiş graf indeksi

- **Ne türetir.** İndeks kanonik log ve kabul edilmiş Claim'lerden türetilir:
  - grup üyeliği = Claim;
  - grup → izin = rule-shaped Grant'ın holder seçicisi;
  - rol = named AuthoritySet;
  - doğrudan paylaşım = extensional Grant (MD-4).
- **Neyi servis eder.** Yalnız `check`, search, explain ve eligible set sorgularını servis eder.
- **Teknik.**
  - Geçişli grup kapanışı önceden hesaplanır ve sıralı tamsayı listeleri / roaring bitmap olarak saklanır. Üyelik testi `(MEMBER2GROUP(U) ∩ GROUP2GROUP(G)) ≠ ∅` kesişimine iner (Leopard).
  - Zanzibar ölçümü: Leopard araması medyan 150 µs'nin, p99 1 ms'nin altında. Yazma yükü saniyede 25 bin iken indeks güncellemesi medyan yaklaşık 500/s'dir (Google üretim verisi, Zanzibar makalesi §4.4).
  - `differential-dataflow` ile üretimde ReBAC gerçekleyen örnek bulunamamıştır, **doğrulanmadı**. Güvenli yol elle yazılmış artımlı kapanış + roaring bitmap'tir.
- **Commit yolu bu indeksi okumaz.** Selector değerlendirmesi SYNC-DERIVED episode tablosundan yapılır (T9). Bu bedel bu yüzden bilinçli olarak kabul edilir.
- **İndeksin yanlış olması.** Yalnız advisory, search veya explain yanlışlığı üretir. Garanti sınıfı:
  - commit kararları için **BY SEMANTICS** (indeks girdi değildir);
  - advisory doğruluğu için **UNDER DECLARED CAPABILITY** (F0 referansına karşı diferansiyel test).

#### 9.7A.2 Okuma tutarlılık sınıfları

| Okuma sınıfı | Access tanımı | Zanzibar/SpiceDB karşılığı | Hangi modda |
|---|---|---|---|
| `head` | Head CAS + q−1 + tam read-set. Tek tutarlı snapshot | `fully_consistent` (her commit'te zorunlu hâli) | **`commit`, `continue`, `projection.issue`: tek izinli sınıf** |
| `at_least(position)` | Verilen pozisyondan en az o kadar taze derived okuma (T11) | `at_least_as_fresh` | `check`, search, explain |
| `as_of(position)` | Tam o pozisyon (sayfalama, audit replay) | `at_exact_snapshot` | `check`, search, explain, audit |
| `minimize_latency` | Önbellekten. Yeni düşman penceresi açık | `minimize_latency` | Yalnız `check`/search/explain ve `advisory = true` ile. **Commit'te ifade edilemez** |

Kurallar:
1. **Replica'dan ALLOW yoktur.**
   - "İzin verme replica'ya yönlendirilebilir" kuralı reddedilir.
   - Gerekçe: bir kararın revocation'dan etkilenip etkilenmeyeceği karardan önce bilinemez.
   - Replica yalnız `at_least` / `as_of` / `minimize_latency` advisory okumalarını servis eder.
2. **Varsayılan bayat değildir.** `Consistency::MinimizeLatency` ADP'de varsayılan değildir.
   - `check` modunda `consistency_token` verilmezse varsayılan `at_least(requester'ın son gördüğü pozisyon)` olur. Bu pozisyon yoksa `head` kullanılır (çıkarım: varsayılan-bayat Zanzibar'ın çözdüğü yeni düşman problemini geri açar).
3. **Belirteç süresi.** `as_of` belirteci derived deponun saklama penceresinden eskiyse "anlık görüntü süresi doldu" hatası döner ve istemci `head`'e düşer.
   - Önerilen pencere 24 saattir. Değer EA'dır, §17'de bağlanır.
4. **CockroachDB uyarısı**: "fully_consistent does not guarantee read-after-write consistency on CockroachDB" (düğüm saat kayması).
   - Access commit'i saat değil head CAS + pozisyon üzerine kurduğu için etkilenmez.
   - Uyarı, derived deponun arka ucu seçilirken §17'de girdidir.

#### 9.7A.3 İçerik nedenselliği: "yeni düşman" Örnek B

Zanzibar makalesindeki Örnek B:
1. Alice, Bob'u bir belgenin ACL'inden çıkarır.
2. Ardından Charlie belgeye yeni içerik ekler.
3. Bayat ACL ile yapılan denetim Bob'a yeni içeriği gösterebilir.

SI-7 ve INV-24 penceresi yalnız revocation'ın kendisini sınırlar; projection yolunda bu durum ayrı bir kural ister.

**Kural.** Bir PEP korunan içeriğin yazıldığı pozisyonu (`content_position`; Zanzibar'ın zookie'si gibi kaynağın yanında saklanır) biliyorsa şunu uygular:
- Projection'ın `basis_ref` pozisyonu `content_position`'dan eskiyse, o projection o içerik için **reddedilir** ve online karar istenir.
- Biçim: "kaynak q'dan sonra yazıldıysa `as_of < q` olan projection reddedilir".
- Bu adım PAP verifier kuralına opsiyonel sekizinci kontrol olarak eklenir (§9.10.1).

Garanti:
- İçerik pozisyonunu saklayan ve kontrolü yapan PEP için **UNDER DECLARED CAPABILITY**.
- Saklamayan PEP için kalan pencere ValidityContract'ın beyan ettiği penceredir; daha fazlası değildir (**BY SEMANTICS** sınıflandırma).

§13'e aday: guarantee — "yeni içerik + bayat projection" penceresinin UDC satırı.

#### 9.7A.4 Karar önbelleği

- **Commit yolunda karar önbelleği yoktur** (TI-5). Önbellek yalnız advisory, search ve explain için kullanılır, ayrıca derived alt-problem sonuçları için.
- **Anahtar**:
  - `blake3(len‖tenant/store ‖ len‖domain ‖ len‖subject ‖ len‖action ‖ len‖resource ‖ len‖model/policy sürümü ‖ len‖applied_pos)`.
  - **Uzunluk önekli** hash kullanılır, string birleştirme değil. Gerekçe önbellek anahtarı çakışması sınıfıdır. İlgili CVE numarası "CVE-2026-48096" olarak bildirilir; NVD ile **doğrulanmadı**.
  - Anahtarda revizyon/`authz_epoch` yerine **`applied_pos`** bulunur (MD-7). Pozisyon kiracı genelinde bir sayaçtan daha incedir ve nedenselliği korur.
- **Geçersizleştirme** üç mekanizmayla birlikte yapılır:
  1. Anahtardaki pozisyon (yapısal; ana mekanizma).
  2. İzleme akışıyla etkilenen alt ağaçların düşürülmesi.
  3. TTL son savunma hattıdır: olumlu 10 s, **olumsuz ≤ 1 s**. Yetki veren her Exercise ilgili olumsuz girdileri senkron düşürür.
- **İsabet gerçekçiliği.** Zanzibar'ın gerçek önbellek isabet oranları %1'in altı ile %24 arasıdır (Google üretim verisi). Önbellek bir sıcak nokta çözümüdür, gecikme çözümü değildir. Alt-problem sonuçlarını önbelleklemek asıl kazançtır. Kapasite planlaması %90 isabet varsaymaz (OQ-1 girdisi; §17).
- **"Cache bu kullanıcıyı hiç görmedi" fail-closed'dur** (MD-7). Bayat önbellek ile hiç görülmemiş durum ayrı ele alınır. Hiç görülmemiş durumda zaman penceresi uygulanmaz.

#### 9.7A.5 Zorunlu kotalar (EA)

| Limit | Değer | Gerekçe |
|---|---|---|
| Çözümleme derinliği | 25 | Döngü koruması (OpenFGA ile aynı) |
| Çözümleme genişliği | 10 | Yayılım patlaması |
| Advisory `check` zaman aşımı | 100 ms | Sıcak yol bütçesi |
| Search son tarihi | 1 s, sert | Nesne listeleme tehlikesi |
| Search azami sonuç | 1000 | Sayfalama zorunlu |
| Yazma başına demet | 1000 | Türetilmiş indeks toplu güncellemesi için. Access'te yazma = Exercise. Bu sınır yalnız derived indeksin ingest partisidir (çıkarım) |
| Depo başına tip | 200 | Model karmaşıklığı |

Kotaya takılan advisory sorgu "cevap yok" döner, hiçbir zaman ALLOW dönmez (MD-8). Commit yolunun kendi sınırları (lineage derinliği, requirement sayısı) §5 ve §14'tedir.

#### 9.7A.6 Sıcak yol hedefleri (ENGINEERING ASSUMPTION)

Mertebe haritası (her satır ölçüm ortamıyla, kaynaktaki etiketle):

| Katman | Gecikme | Ölçüm ortamı |
|---|---|---|
| HMAC koşul doğrulama | 2,6 µs | Python, ~160 satır, dizüstü, 2×10⁵ çağrı (arXiv 2609.00267). **ReBAC değildir** |
| Cedar politika değerlendirme | medyan 4–11 µs, p99 10–20 µs altı | Rust, EC2 m5.4xlarge, 100 bin istek (arXiv 2403.04651) |
| Leopard indeks araması | medyan < 150 µs, p99 < 1 ms | Zanzibar §4.4 |
| OpenFGA süreç içi denetim | medyan 89–746 µs, p99 283–3012 µs | Go, bellek veritabanı, optimize edilmemiş (arXiv 2403.04651) |
| Zanzibar güvenli / yakın zamanlı denetim | p95 9,46 ms / 60,0 ms | Zanzibar Tablo 2 |

Advisory/projection yolu hedefleri (**EA**, ölçülmedi, §17'de OQ-1 ile doğrulanır):

| Yol | p99 hedef |
|---|---|
| Projection doğrulama + kaba yetki (token katmanı) | < 5 µs |
| İnce taneli advisory `check`, önbellek isabeti / gerçeklenmiş indeks | < 100 µs |
| İnce taneli advisory `check`, önbellek ıskası, yerel veritabanı | < 5 ms |
| Search / nesne listeleme | < 50 ms (zorunlu son tarihle) |

- **Commit yolu bu tabloya dahil değildir.** Commit gecikmesi head CAS, read-set ve imzalı DecisionRecord içerir. Hedefi ayrı bir EA'dır (§16, §17; SLO sayıları MD-19 #6 ile EA'dır).
- 2,6 µs rakamı Access'in commit veya ReBAC hedefi olarak kullanılamaz ("kategori hatası").

#### 9.7A.7 Harici motorlar, gömülü ve durumsuz karar noktası (ayrıntı §4)

- **Harici motorlara bağımlılık yoktur.** OpenFGA, SpiceDB, Keto, casbin, oso ve regorus değerlendirmesi bu kararın kanıtıdır. Örnek: OSV'de OpenFGA 26, SpiceDB 16 danışmanlık; 8 Eylül 2026. Ayrıntı landscape bölümündedir (§4).
- **Restriction dili.** Cedar forbid-only alt kümesi kullanılır (MD-4; OQ-MD2 spike'ı).
- **Gömülü / istemci içi karar noktası (Cedarling).**
  - Access'te bunun karşılığı ValidityContract'lı bir projection'ın **yerel doğrulanmasıdır**: bounds token veya PAP + Offline Verifier.
  - İstemci içi bir karar noktası politika ve varlık verisini önceden alıp yerel karar veriyorsa:
    - bu bir `intermittent` / `offline` connectivity profilidir;
    - bayatlık penceresi ValidityContract'ta (`max_staleness`, `horizon`) beyan edilmek zorundadır;
    - verifier Verifier Profile Claim yayınlar (§9.12.1).
  - Beyansız istemci içi karar **NOT GUARANTEED**'dır ve conformant değildir.
  - Cedarling'in hangi durumu tuttuğu ve iptali nasıl aldığı **doğrulanmadı**.
- **Durumsuz karar fonksiyonu.**
  - Access'in değerlendirme fonksiyonu saf ve deterministiktir (INV-27).
  - Veri getirme (StateBasis'in okunması) ayrı katmandır.
  - Bu ayrım ("karar katmanı saf fonksiyon, veri getirme ayrı") özellik testlerinin veri deposu olmadan koşmasını sağlar (§14).
  - Ters sorgu (search) durumsuz fonksiyonla ifade edilemez; bu yüzden türetilmiş indeks gerekir (9.7A.1).

### 9.8 Decision Receipt

| Alan | Semantik |
|---|---|
| issuer | DomainID; provider'ın domain'e bağlı imza anahtarı (custody attestation, authority değil) |
| ExerciseID, DecisionRecord ref | Hangi kararın receipt'i |
| intent digest | Receipt yalnız bu digest için |
| actor | InstanceID (+ KeyBinding referansı) + Actor Intent Statement digest'i |
| capacity, basis ref | Beyan edilmiş capacity; basis'in HoldingRef'i / AnchorRoot ref'i |
| audience | Kararı uygulayacak PEP |
| trusted evaluation time | Kararın zamanı |
| validity | Yalnız ValidityContract verildiyse; yoksa receipt "point-in-time"dır |
| consumption özeti | Draw yapıldı mı (miktar requester'ın görme yetkisi kadar) |

**Receipt ≠ credential (R4).** Receipt bir PEP'in "bu effect, bu intent için, bu actor tarafından Access'ten ALLOW aldı" iddiasını offline doğrulamasını ve audit'te attribution'ı sağlar. Başka bir intent, başka bir PEP veya başka bir nonce için sunulamaz; ikinci bir effect'i desteklemez (INV-19). Zincirli PEP'lerde upstream receipt downstream PEP için yalnız **causal referanstır**; downstream PEP kendi Exercise'ını ister (E17). Reusable kullanım receipt'ten değil, `projection.issue`'dan veya ValidityContract'lı continuation'dan doğar.

**Recovery ve handover koşulu receipt için de geçerlidir.** Domain Metadata eski provider anahtarını `superseded-at` olarak taşıyorsa (forced recovery'de N, kooperatif handover'da C_{h+1}), o anahtarla imzalı bir receipt §9.10 verifier kuralının recovery/handover predicate'ine tabidir: receipt'in exact içeriğinin (ExerciseID, intent / target digest, actor, audience …) `N_cited`'de commit edilmiş kayıtla eşleştiğine dair inclusion proof yoksa kabul edilmez (yerel DENY / Gate karşılanmadı); receipt'teki ExerciseID tek başına yetmez.

### 9.9 Projection issuance ve OAuth binding

Projection, Access'in **sağladığı tek reusable/portable artifact'tır**; her biri bir `projection.issue` meta-Exercise'ının ürünüdür ve bir ValidityContract taşır (C31, INV-22).

```text
holder Instance ──projection request──► Access
(actor proof, basis, capacity, requested bounds | exact intent,
requested profile, verifier audience, requested horizon, offline slice request)
Access: projection.issue Exercise
• requested bounds ⊆ Exercisable(Instance) ? (INV-3)
• profile ≤ domain policy; verifier profile Claim accepted ? (E13)
• Δ (max staleness) ≤ lineage/rootTerms/RestrictionPolicy tavanı (E13)
• offline slice: lineage budget'larından ÖNCEDEN draw
→ ALLOW + ValidityContract + artifact
```

**OAuth binding (PROFILE).**

| OAuth öğesi | Access karşılığı | Kural |
|---|---|---|
| Authorization request (+ RAR, PAR) | Kullanıcının authority act'i gerekiyorsa (yeni delegation): S1 + Approval Act Statement (`act = authority-act`; actor = kullanıcının Instance'ı, assertion challenge = H(AAS); AAS `target` = `grant.issue` intent digest'i, contribution yok) ile `grant.issue` (+ `mandate.bind`); sonra `projection.issue` | Consent ekranı = S1 exact preview ("Connect"); OAuth "consent" kaydı Access Grant'ının yerine geçmez |
| Token endpoint / RFC 8693 exchange | `projection.issue` Exercise Request | Her token issuance bir karardır; Access cevabı ALLOW değilse token yok |
| Access token (RFC 9068 JWT veya opaque + introspection) | PROJECTION | İçerik; `cnf` zorunlu (DPoP/mTLS; bearer yok), `aud` tek RS/PEP (RFC 8707), authority yalnız RAR'da |
| Refresh token | Yeni bir `projection.issue` talep etme yeteneğinin projection'ı | **Her refresh yeni bir karardır** (L19); refresh token holding değildir; revocation sonrası refresh DENY |
| RFC 7009 revocation | Projection temizliği | `grant.revoke` değildir; cascade etmez |
| RFC 7662 introspection | Projection'ın güncel durum sorgusu (online verifier için) | Cevap advisory değil projection durumudur; authority kararı yine Grant'tan türer |

#### 9.9.1 Projection türleri

| Tür | Connectivity profili | Taşıyıcı | İçerik özü | Ne değildir |
|---|---|---|---|---|
| **Receipt** (§9.8) | Online | ADP response | Tek ExerciseID, tek intent | Reusable |
| **Exact-intent token** | Online/intermittent (ör. MCP tool çağrısı için tek kullanımlık) | OAuth AT + RAR `kind=intent` | Tek intent digest, kısa horizon, count=1 | Bounds yetkisi |
| **Bounds token** | Intermittent | OAuth AT + RAR `kind=bounds` | AuthoritySet ∩ Mandate projection'ı (⊆), kısa ValidityContract, status ref | Consumption-bearing action için yeterli değil (aşağıda) |
| **Portable Authority Proof** | Offline; cross-domain | Access-tanımlı içerik; imzalı JWT/SD-JWT (RFC 9901) veya COSE kabı | §9.10 | VC, Biscuit, UCAN |
| **Continuation contract** | Long-running (`long-running` class, `checkpoint-continuation` variant; §9.12) | Receipt + ValidityContract | Horizon + checkpoint planı | Lease (Work/Executor'ın) |

Bu tablo ve consumption-bearing kuralı §9.10 `local_requirements` / `offline_slice` alanlarının ve §9.15A home-budget kuralının dayanağıdır.

#### 9.9.2 PEP zinciri (E17) protocol'de

- Downstream PEP'teki effect, basis'i tutan Party'nin Instance'ının **kendi** Exercise Request'iyle desteklenir; Request'in `intent.context`'inde upstream ExerciseID **causal ref** olarak bulunur.
- Domain içi call chain'de bu bağlam Transaction Token ile taşınabilir (RFC olunca normatif; §9.4 E). Txn-Token yalnız taşır; downstream kararın girdisi yine Access'teki RestrictionPolicy + causal-bound allowance'tır (count=1 BudgetTerm, upstream ExerciseID'ye anahtarlı). Bunlar declared ise bağ **GUARANTEED UNDER DECLARED POLICY**'dir; değilse causal ref yalnız audit/detection'dır (§7.9.7.4). Protocol bu ayrımı Decision Response'ta ayrı bir üyeyle görünür kılar: `causal_binding = audit-only` (upstream bağı uygulanmadı) veya `enforced`; `basis_ref` bu işareti taşımaz (yalnız AuthorityStateBasis ref'idir) (X21 console uyarısının kaynağı).

#### 9.9.3 OAuth binding kuralları

Aşağıdaki kurallar §9.9 OAuth binding tablosunu daraltır. Hiçbiri genişletmez.

1. **Tek `aud` ve `invalid_target`.**
   - Her **OAuth access token projection'ı** (exact-intent ve bounds token) tek bir RS/PEP için verilir (RFC 8707). PAP ve ValidityContract `audience`'ı bir verifier kümesi olabilir; consumption-bearing slice'ta küme yalnız SEC13'ün ortak sayaç koşuluyla kurulur.
   - AS, gelen `resource` değerini domain'de kayıtlı korunan kaynaklara karşı doğrular. Kayıtlı korunan kaynaklar, PEP / verifier kümesi Domain Metadata ve Verifier Profile'dan gelir. Kaynak MCP ise kanonik URI kuralları §11.4'tedir.
   - Bilinmeyen `resource` için `invalid_target` döner. Aksi hâlde AS keyfi audience'lı token üreten bir oracle'a dönüşür.
   - Audience'sız veya çoklu audience'lı OAuth access token hiçbir zaman verilmez.
   -
2. **`cnf` zorunlu, bearer yok.**
   - Her access token DPoP (`cnf.jkt`) veya mTLS (`cnf.x5t#S256`) ile holder-bound'dur (PI-11).
   - "Public client FAPI dışıdır" notu bu kuralı kırmaz; public client DPoP ile karşılanır.
   - DPoP nonce ve replay kuralı MD-18'dedir. Uygulama profili §10'dadır.
   - WIMSE WIT de bearer olarak kullanılamaz. Workload tarafı aynı kurala hizalıdır (§11.12).
3. **Authority yalnız RAR'da; scope projection etiketidir.**
   - Scope bir kaba etikettir. RS'nin scope hiyerarşisi (MCP RS-M11) authority sınırı ifade etmez.
   - Scope-only bir RS, Access'e conformant adapter PEP üzerinden bağlanır (R3).
4. **Access token ömrü (MD-7, PD).**
   - Identity plane access token'ı CT'ye göre POLICY DEFAULT alır: yönetim yüzeyinde ≤ 60 dk (yalnız CT0 okuma/gezinme; §13.7.2 tavanı geçerlidir).
   - Ömür PD'si bir **üst sınırdır**. Authority taşıyan token'ın gerçek horizon'u = min(ömür PD'si, §13.7.2 tavanı). Tavan, token bounds'undaki en yüksek CT'den gelir. CT2+ action için bounds token verilmez, yalnız exact-intent token verilir (≤ 5 dk, count = 1). CT3 için projection verilmez. Yönetim yüzeyinde ayrı bir token sınıfı yoktur (MD-14); yönetim meta-Exercise'ları token'la değil AIS + ADP `commit` ile yapılır.
   - 28 saatlik access token ömrü **reddedilir**.
   - Tipik aralık 5–15 dk'dır.
   - Ajan projection'ları için varsayılan daha kısadır: exact-intent token tek kullanımlık ve kısa horizon'ludur (§9.9.1). Ajan bounds token'ının varsayılan horizon'u §11.9'dadır.
   - Uzun ömür yalnız beyanlı bir ValidityContract horizon'u olarak mümkündür (UDC).
   -
5. **Introspection ve fail-closed (MD-8).**
   - Tazeliği kanıtlanamayan authority taşıyan token RFC 7662 introspection'da `active=false` alır. Örnek: StateBasis okunamadı, status kaynağı Δ'yı aştı.
   - RS, introspection veya JWKS uç noktasından 5xx aldığında DENY uygular.
   - Introspection DB kaybında "aktif" cevabı verilmez (MD-18 → MD-8).
   - Primary'ye veya tazelik kaynağına ulaşılamıyorsa her token için `active=false` döner; önbellek isabeti (cache-hit) dahildir; 503 dönmez. 60–300 s fail-open pencereleri reddedilir (OPI-3, §14.8, §16.7.1, §17.7 OP-45 ile aynı cümle).
   -
6. **Refresh: rotasyon, reuse detection ve single-flight.**
   - Her refresh yeni bir `projection.issue` kararıdır (L19).
   - Refresh token her kullanımda rotate edilir. Harcanmış bir refresh token tekrar görülürse o token ailesinin bütün projection'ları iptal edilir (RFC 7009 anlamında projection temizliği; `grant.revoke` değildir) ve bir `projection-invalidated` semantic event'i üretilir.
   - **İstemci SDK'sı tek bir refresh'i uçuşta tutar** (single-flight). Eşzamanlı çağıranlar aynı sonucu bekler. Aksi hâlde çok ekranlı mobil istemci kendi reuse detection'ını tetikler. Bu davranış testle kapsanır.
   - Hareketsizlik ve mutlak tavan birlikte uygulanır. Refresh token'ın ömrü Grant/Mandate validity'sini aşamaz. Bu kural `draft-ietf-oauth-refresh-token-expiration-03`'teki "MUST NOT expire later than the user authorization expires" kuralının Access'teki yapısal karşılığıdır (§9.4.2).
   -
7. **İmza algoritması (MD-3).**
   - JOSE projection'ları varsayılan olarak ES256 ile imzalanır; Ed25519 seçmelidir.
   - FIPS profilinde her yerde ES256/ESP256 kullanılır.
   - RS256 yalnız identity plane'de, client başına opt-in imzadır. Authority artefaktları (receipt, PAP, ValidityContract) hiçbir zaman RSA ile imzalanmaz.
   - RS256 yalnız kimlik iddialarında (ID token, logout token, userinfo JWT, protokol-scope-only access token; realm JOSE anahtarı) kullanılabilir. Authority taşıyan access token (RAR `kind=intent|bounds`, RFC 9068) dahil hiçbir [AU] projection'ı RSA ile imzalanmaz. Authority taşıyan token'ı **domain operasyonel anahtarı** imzalar (MD-6 authority plane, T20; ayrı signer süreci). Bu anahtar realm JWKS'te `kid` + Domain Metadata çapraz referansıyla yayınlanabilir, ama realm anahtarı değildir; realm JOSE anahtarı hiçbir authority projection'ı imzalamaz. Verifier §9.10 adım 1'deki DomainID denetimini yapar (TI-RT6). Ayrıntılı tablo §10.4.5'tedir.
   - Tanımlayıcılar RFC 9864 fully-specified biçimdedir; JWS doğrulamada `alg: EdDSA` reddedilir.
   - Algoritma allowlist'i header'dan değil, client/Domain Metadata'dan gelir.
   -
8. **Linkability (MD-10).**
   - **Her** projection'da (access token, receipt, PAP, ValidityContract) `sub`, `act.sub` ve RAR içindeki PartyRef'ler domain-pairwise türetilmiş takma addır. Projection tanımı gereği domain kaydının dışına çıkan bir artefakttır. Takma ad value-level'dir, yeni primitive değildir; iç PartyID değişmez. ID token / userinfo `sub`'ı sector-pairwise'dır (§10.4.6). Access token `sub`'ı ile eşit olması garanti edilmez ve RS bunu varsaymaz.
   - Identity plane OIDC/SAML'de varsayılan pairwise `sub` kullanılır; public `sub` client başına opt-in'dir (ayrıntı §10).
   - Kalan korelasyon yüzeyi (aynı KeyBinding, zamanlama) §13'e adaydır: HL/RR — "aynı `cnf` anahtarı veya zamanlama ile domain'ler arası korelasyon".
   -
9. **Token passthrough yok (L24, MCP RS-M8/M10).**
   - Bir RS/PEP upstream API'yi çağırırken istemcinin token'ını iletmez. Upstream çağrı kendi `projection.issue` kararıyla alınmış ayrı bir projection'dır (§11.13).

#### 9.9.4 Capacity → `sub` / `act` / `may_act` eşlemesi

Piyasa RS'leri `sub` = principal, `act.sub` = actor bekler. Entra Agent ID üretimde bu ayrımı kullanır. RFC 8693 §4.1'e göre önceki aktörler yalnız bilgilendiricidir. Eşleme tanımlanmazsa her implementasyon farklı yazar ve RS'ler `sub`'ı authority sanar. Access'in capacity'si token'a şöyle yazılır:

| Access durumu | `sub` | `act` | Ek alanlar | Not |
|---|---|---|---|---|
| `OWN`; actor = basis holder Party'nin Instance'ı (insan, servis veya kendi Party'si olan ajan) | Basis holder Party'nin PartyRef'i (domain-pairwise takma ad, §9.9.3 k.8) | **Yok** | `cnf` = actor Instance KeyBinding. InstanceID ValidityContract `holder` alanında (RAR Access üyesi `validity`). Interop için opsiyonel `agent_instance_id` Claim'i (§11.17) | "Otonom ajan: `sub` ajandır, `act` yoktur" kuralına denk düşer. Ajan bir operatör Party'sinin Instance'ıysa `sub` operatör Party'sidir; ajan ayrımı InstanceID ile yapılır |
| `FOR(P)`; actor = başka bir Party'nin Instance'ı (ör. ajan operatörü) | P'nin PartyRef'i (pairwise) | `act.sub` = actor Party'nin PartyRef'i (pairwise), `act.iss` = domain issuer. Kanonik actor kimliği `(act.iss, act.sub)` ikilisidir (actor profile) | `act` içinde actor InstanceID (`agent_instance_id` biçiminde, opsiyonel); `cnf` = actor Instance KeyBinding | `act` **projection ve ipucudur** (L22). RS authority'yi RAR'dan okur, `sub`/`act`'tan değil (S-2, S-4) |
| `FOR(P)`; çok halkalı lineage (P → A → B) | P | En dıştaki `act` = doğrudan actor (B); iç içe `act` = önceki halkalar (A) | — | İç içe `act` **Access lineage kaydından** üretilir; gelen bir `subject_token` veya `actor_token`'dan kopyalanmaz. Böylece splicing (§11.10) yapısal olarak imkânsızdır. Ayrıştırıcı ≥ 4 seviye `act` destekler; ajan şablonu varsayılanı depth ≤ 1 kalır |
| `may_act` (exchange'e konu subject token'da) | — | — | `may_act` = bu token'la RFC 8693 exchange isteyebilecek actor kümesinin **ipucu** projection'ı (Grant AgencyTerms'ünden türetilir) | `may_act` yetki vermez. Exchange yine actor'ün kendi `projection.issue` Exercise'ıdır ve actor'ün FOR(P) Grant'ı olmalıdır |
| Destek erişimi (sektördeki adıyla impersonation; MD-9) | Kaynağın sahibi P | `act` = destek personelinin Party'si (zorunlu) | Ayrı token tipi **yoktur**: standart `at+jwt`, RFC 8693 delegation biçimi; authority RAR'dadır (TN-70, TNI-13, MD-9) | Reserved Grant + AAS ile verilir: kullanıcının kendi `grant.issue`'su veya reserved break-glass Grant'ı. Ayrıntı §12. **`act` olmadan "saf impersonation" token'ı üretilmez** |

Kurallar:
1. Rezerve claim adları (`iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `nbf`, `act`, `may_act`, `cnf`, `scope`, `client_id`) kiracıya kapalıdır (kiracı token sınırı). Kiracı yalnız önceden tanımlı Claim kümesinden seçer (§9.9.6).
2. RFC 9068 RS'leri `sub`'ı principal olarak görüntüleyebilir ve audit'e yazabilir. Authority kararı için RAR `authorization_details` + `cnf` + ValidityContract kullanılır.
3. Gelen bir token'daki `act` zinciri (ör. inbound ID-JAG, upstream Txn-Token) Access'te hiçbir zaman lineage kanıtı değildir. En fazla `actor-binding` Claim girdisidir (§9.13, §11.11).

#### 9.9.5 REQUIRE_ACTION'ın OAuth, MCP, AuthZEN ve A2A yüzeylerindeki görünümü

**Temel kural.** REQUIRE_ACTION her yüzeyde DENY'dan **ayırt edilebilir** taşınır. Yüzey bunu ifade edemiyorsa REQUIRE_ACTION DENY gibi uygulanır (fail-closed, R2). Ters yön yasaktır. Bekleyen tek nesne REQUIRE_ACTION almış **nonce**'tur:
- intent validity'sine kadar açıktır;
- aynı nonce + eklenen proof ile yeniden değerlendirilir;
- ayrı bir "pending authorization" nesnesi yoktur.

Bu, "tek bekleyen yetkilendirme soyutlaması"nın Access'teki karşılığıdır.

| Yüzey | REQUIRE_ACTION görünümü | DENY görünümü | Kaynak / statü |
|---|---|---|---|
| **ADP** | `decision=false`, `outcome=REQUIRE_ACTION`, `unmet`, `remediation`, `evaluation_record` | `decision=false`, `outcome=DENY`, `blockers` | §9.5 (FROZEN) |
| **OAuth token endpoint** (`projection.issue`: code, refresh, RFC 8693, `jwt-bearer`) | `remediation ∈ {refresh-claim, self-authenticate}` → `error=insufficient_authorization` + `authorization_remediation`. Bu üye Access remediation kodunu ve `exercise_ref = (DomainID, nonce)`'u taşır. İnsan katkısı gerekiyorsa (`route-to-coordinator`) → `error=interaction_required` + `interaction_uri` (Approval Surface / S1 adresi) + `interval` + `expires_in` (= intent validity) | RFC 6749 §5.2 hatası (`invalid_grant`); blocker sınıfı Access uzantı üyesinde, serbest metin değil | `insufficient_authorization`: `draft-ietf-oauth-rar-metadata-remediation-00` (WG Doc) ve FiPA-04. `interaction_required`/`interaction_uri`: `draft-parecki-oauth-jwt-grant-interaction-response-00` (bireysel). **Taslak → WATCH**; eşleme profili PD |
| **OAuth authorization endpoint** | Kullanıcı tarayıcıdaysa S1/Approval Surface aynı akışta gösterilir (AAS, §9.14) | `error=access_denied` | RFC 6749 (ADOPT) |
| **RS / MCP server challenge** | Authentication strength eksikse → RFC 9470 `insufficient_user_authentication` (+ `acr_values` tavsiye, `max_age` zorunlu). Projection'ın RAR bounds'u yetersizse → 403 `insufficient_scope` + `resource_metadata` (+ RAR remediation, taslak). Contribution gerekiyorsa → 403 + `error=insufficient_authorization` (taslak) | 403 + RFC 6750 hatası | RFC 9470, RFC 6750 (ADOPT); MCP RS SHOULD |
| **MCP (JSON-RPC)** | SEP-2643 Structured Authorization Denials ve SEP-2848 Asynchronous Approval for Tool Calls Final olursa, REQUIRE_ACTION verisi (unmet, remediation, `exercise_ref`) bu yapılara eşlenir. O zamana kadar RS challenge satırı geçerlidir. **MCP elicitation (`elicitation/create`, MRTR `input_required`) yalnız Approval Surface adresini iletmek için kullanılabilir; elicitation cevabı approval değildir** (EI-18, A-5) | Tool hatası / 403 | SEP'ler açık → WATCH |
| **AuthZEN AARP** | `access_request` nesnesi. Opak görev tutamağı = `exercise_ref (DomainID, nonce)`. "Survives PEP restart, replacement, or handoff" özelliği nonce'un domain'de kayıtlı olmasıyla sağlanır. Onaydan sonra PEP taze değerlendirme ister = aynı nonce ile yeniden `commit` | "Reddedilmiş bir karar reddedilmiş kalmalıdır" = DENY nonce terminaldir (C30) | AARP Draft 1 → WATCH; Final olursa PROFILE |
| **A2A** | `TASK_STATE_AUTH_REQUIRED` / `TASK_STATE_INPUT_REQUIRED` + A2A extension üyeleri (unmet, remediation, `exercise_ref`) | Görev hatası | A2A EXTEND (§9.4) |
| **CIBA** | Yalnız davet: `remediation=route-to-coordinator` iken kullanıcıyı onay cihazına çağırır. `binding_message` onay içeriği değildir; onay AAS'tir | — | §9.4 CIBA satırı |

Ek kurallar:
1. `remediation=not-satisfiable-by-actor` hiçbir yüzeyde `interaction_required`'a dönüştürülmez. Requirement'ın contribution kabul edip etmediği requirement'ın kendisinden okunur (§8.18.3; §11.16).
2. Hata gövdeleri serbest metin taşımaz (A-7). Remediation kodları kapalı kümedir (§9.6).
3. `interaction_uri` yalnız conformant bir Approval Surface'e işaret eder. URI'nin kendisi authority taşımaz. Onay AAS + assertion ile ve kullanıcının kendi Instance'ından gelir.

#### 9.9.6 İki katmanlı token ve claim eşleme

Yaygın sentez iki katmandır:
- **Kaba katman:** token'a gömülür; roller, kiracı/org üyeliği, plan; sabit boyut; kısa TTL; µs mertebesi doğrulama.
- **İnce katman:** her istekte kaynak başına sorgu.

"Kritik kural": token'daki yönetici rolü iddiası bir karar değildir. Access'te karşılığı üç katmandır:

| Katman | Access nesnesi | Kural |
|---|---|---|
| Kimlik iddiaları (rol, grup, kiracı, plan, `acr`) | ID token / access token'daki **Claim**'ler | Hiçbir zaman authority değildir. Karara yalnız Acceptance'lı Claim olarak girer (INV-15). Token şişmesi sınırları gerçektir: çerez 4 KiB, yaygın başlık sınırı 8 KiB (değerler yaygın varsayılandır, **doğrulanmadı**) |
| Bounds token (kaba authority) | `projection.issue` ürünü, RAR `kind=bounds` | ⊆ AuthoritySet ∩ Mandate, holder-bound, ValidityContract'lı. Consumption-bearing action'ları kapsamaz (§9.9.1) |
| İnce karar | ADP `commit` veya exact-intent projection (RAR `kind=intent`) | Her effect kendi ALLOW'unu veya exact-intent projection'ını ister (INV-19) |

**Claim eşleme bir yükseltme yüzeyidir.**
- Scope mapping ve protocol mapper, token'a authority etkili bir iddia yazabiliyorsa yetki veren bir işlemdir (Keycloak'taki iki açık aynı ailedendir).
- Access'te:
  - (a) Mapper hiçbir zaman authority üretemez. Projection içeriği ⊆ AuthoritySet ∩ Mandate'tir (PI-8) ve mapper bu kümeyi genişletemez.
  - (b) Kiracı yalnız önceden tanımlı bir Claim kümesinden seçer; serbest ifade veya şablon yoktur.
  - (c) Rezerve claim adları kiracıya kapalıdır (§9.9.4 kural 1).
  - (d) Mapper yapılandırmasının değişmesi bir identity plane config değişikliğidir, yani ADP `commit` domain action'ıdır (MD-14).
-

### 9.10 Portable Authority Proof

| Alan | Semantik | Neden zorunlu |
|---|---|---|
| `issuer` | DomainID + provider'ın domain'e bağlı imza anahtarı (custody attestation) | Cryptographic validity (Work kontrol 1) |
| `projection_exercise` | `projection.issue` ExerciseID'si | Meşruiyet zinciri |
| `holder` | InstanceID + KeyBinding `cnf`; (veya cross-domain'de foreign Party'nin PartyRef'i + KeyBinding) | Holder-bound; possession ≠ authority |
| `capacity` | İzin verilen capacity (`OWN` / `FOR(P)`) | INV-4 |
| `bounds` | AuthoritySet ∩ Mandate'in closed-algebra projection'ı; ActionRef'ler schema digest'leriyle; namespace prefix'leri **pin'li katalog sürümüyle** | Semantic coverage (kontrol 3); E11 |
| `local_requirements` | Verifier'ın yerelde doğrulayabileceği RequirementTerm'ler (ör. yerel authentication, posture Claim) | Yerelde doğrulanamayan requirement'ı olan action'lar bounds'a **giremez** (fail closed) |
| `validity` | ValidityContract | INV-24 |
| `offline_slice` | Budget boyutu başına önceden draw edilmiş miktar; slice'ın hangi lineage node'larından çekildiği (digest) | INV-21; reconciliation |
| `status` | Token Status List / eşdeğeri ref'i ve yerel freshness şartı | Intermittent revocation yakalama |
| `lineage_commitment` | Basis lineage yolunun digest'i (+ seçici açıklama ile açılabilen halkalar) | Foreign/audit doğrulaması; tam graph'ı ifşa etmeden (E26) |
| `audience` | Verifier kümesi (PartyRef / verifier profile) | Yanlış verifier'da kullanım yok |
| `must_understand` | Verifier'ın anlaması gereken core spec / meta-schema / profile sürümleri ve closed-type'lar | R7 |

**Verifier kuralı (Offline Verifier conformance profile; yedi adım).**

| Adım | Kontrol | Başarısızlıkta |
|---|---|---|
| 1 | İmza zinciri Domain Metadata'daki provider binding'e çözülür; gömülü binding-imzalı anahtar excerpt'inin DomainID'si artefaktın domain'iyle eşleşir (TI-RT6); imza zamanı (`iat`) operasyonel anahtar penceresi içindedir | Yerel DENY |
| 2 | Verifier'ın beyan ettiği trusted clock'a göre horizon içindedir; kabul süresi min(horizon, iat + yerel tavan); tavanlar yalnız Domain Metadata / Verifier Profile'dan (`cap_horizon`: CT gerçekleştirilen intent'ten, class/variant Verifier Profile'dan; artefaktın beyanı kullanılmaz) | Yerel DENY |
| 3 | Holder PoP doğrulanır | Yerel DENY |
| 4 | İstenen intent `⊑ bounds` (closed algebra) ve `local_requirements` karşılanır | Yerel DENY |
| 5 | Slice'tan yerel draw yeterlidir | Yerel DENY |
| 6 | Status freshness ≤ Δ; Domain Metadata tazeliği verifier'ın pinli kümesinden bağımsız bir witness'ın ≤ Δ (yoksa ≤ 1 saat) cosign'ıyla ölçülür (TI-RT5); metadata'nın kendi `iat`'i tek başına tazelik kanıtı değildir | Online'a düş veya DENY |
| 7 | Her must-understand öğesi tanınır | Yerel DENY |

**Recovery / handover predicate'i (adım 1'in parçası).** Domain Metadata eski provider anahtarını `superseded-at` olarak taşıyorsa, o anahtarla imzalı artefakt yalnız şu durumda kabul edilir: artefaktın **exact içeriğinin** (digest'i veya authority-relevant alanları: bounds, holder, audience, horizon, slice, target digest) lineage'ı değiştiren kaydın cite ettiği checkpoint'te (`N_cited`) commit edilmiş kayıtla (`projection.issue` / DecisionRecord içeriği) eşleştiğini kanıtlayan bir **inclusion proof** vardır — ya da artefakt yeni provider tarafından yeniden issue edilmiştir.

| Geçiş | `N_cited` | Eski anahtarın statüsü | Kanıt |
|---|---|---|---|
| Forced recovery (`domain.recover`) | Recovery Exercise'ının cite ettiği N (SEC21) | `superseded-at checkpoint N` | N'ye karşı exact-content inclusion |
| Kooperatif handover (`domain.handover`) | Handover kaydının cite ettiği C_k | `superseded-at C_{h+1}` | C_k'ye karşı inclusion + C_{h+1}'e consistency path (U27) |
| Aynı provider içinde binding değişimi (OP-60 self-handover profili; PQ re-anchor, §15.18 CR-45) | Binding re-anchor kaydının cite ettiği checkpoint | Eski anahtar yalnız **yeni üretim** için `superseded` olur | Kırılma ilanına (CR-45 RA-7) kadar eski anahtarla imzalı artefakt bu predicate'e takılmaz; ilandan sonra bundle'sız klasik artefakt reddedilir, inclusion bundle'ı (T19) ile kabul edilir. CR-45 semantiği kanoniktir |

`N_cited` her zaman lineage'ı değiştiren kayıttan (`domain.recover` / `domain.handover`) alınır; artefaktın kendi alanları (`projection_exercise`, `validity.basis_ref`, zaman) kesimde kullanılmaz. Artefaktın ExerciseID'si yalnız aranacak kaydın adresidir, kanıt değildir; aynı ExerciseID'yi taşıyıp içeriği kaydın commit ettiğinden farklı olan artefakt reddedilir. Kural eski anahtarla imzalı **her** artefakt türüne uygulanır: PAP, ValidityContract, reusable Decision, Decision Receipt, exact-intent token. Verifier'ın bu kurala gerçekten uyması verifier operatörünün beyanıdır: sınıf UDC (U12, U27; E13); capability, metadata tazeliği (TI-RT5) ile witness'lı checkpoint ve inclusion kanıtının **birlikte** bulunmasıdır. Kurala uymayan verifier'da kalan pencere U25 / N-26 sınıfındadır.

#### 9.10.1 PAP ek kuralları

1. **İmza (MD-3).**
   - PAP, Decision Receipt, ValidityContract ve checkpoint COSE authority artefaktlarıdır.
   - Varsayılan imza Ed25519'dur. ES256/ESP256 doğrulaması zorunludur.
   - FIPS profilinde ES256/ESP256 kullanılır. ML-DSA-65 opt-in profildir.
   - Verifier algoritma allowlist'ini Domain Metadata'dan alır, artefaktın header'ından almaz.
   - SD-JWT / JWT kabı (R6) seçilirse JOSE kuralları geçerlidir (§9.9.3 kural 7).
   -
2. **DomainID must-understand; binding key kapsamı (MD-6).**
   - Adım 1'deki DomainID eşleşmesi must-understand'dir.
   - Binding key'in kapsamı Domain Metadata'da beyan edilir.
   - Kapsamı dışında bir anahtarla imzalı artefaktın kabulü (Storm-0558 sınıfı) DENY'dır.
   - §13'e aday: HL — "kapsam dışı anahtarın kabulü (Storm-0558 sınıfı)"; MD-6 bunu HL-8'e bağlar.
   -
3. **Pairwise holder (MD-10).**
   - Cross-domain `holder` alanındaki foreign Party PartyRef'i ve `audience` PartyRef'leri domain-pairwise takma addır.
   - Domain'ler arası korelasyon yalnız açık bridging Grant veya IdentityBinding ile kurulur.
   -
4. **Opsiyonel adım 8: içerik nedenselliği (§9.7A.3).**
   - Verifier korunan içeriğin yazıldığı pozisyonu biliyorsa ve PAP'ın `validity.basis_ref` pozisyonu bu pozisyondan eskiyse, PAP o içerik için kabul edilmez. Verifier online'a düşer veya DENY eder.
   - Adım, Verifier Profile Claim'inde (§9.12.1) "içerik pozisyonu kontrolü" yeteneği olarak beyan edilir. Beyan eden verifier için UDC'dir.
   - Not: `basis_ref` audit kapsamının altındaki verifier'a opaque token olarak gider (TI-RT10). Karşılaştırma için domain, verifier'a ayrıca karşılaştırılabilir bir pozisyon taahhüdü verebilir. Biçimi §16'dadır (çıkarım: opaque token ile sıralama karşılaştırması aynı anda sağlanamaz; bu bir §20 açık sorusudur).

### 9.11 Revocation ile etkileşim — guarantee sınıfları

| İddia | Sınıf | Dayanak |
|---|---|---|
| Revocation commit anında semantik olarak etkilidir; sonraki her online `commit`/`continue`/`projection.issue` DENY'dır | **BS** | INV-23 |
| Açık bir ValidityContract horizon'una / offline proof sonuna kadar envelope içi kullanım beyan edilmiş staleness penceresidir, outside authority değildir | **BS** (sınıflandırma); pencerenin fiilen kapanması **UDC** | CI-9, INV-24, X12, X17 |
| Conformant verifier horizon'dan sonra DENY eder | **UDC** | E13 |
| SSF event'i receiver'a zamanında ulaşır | **NG** | L18, SSF 1.0 metni |
| Revocation çalışan executor'ı durdurur | **NG** (Executor teyidi ancak UDC) | EI-11 |
| Status list'te iptal görünen projection verifier tarafından reddedilir | **UDC** (verifier'ın status freshness'ı ≤ Δ) | — |

Ack edilmemiş bir revocation'ın okuma cevaplarında `witnessed_through` ile nitelendirilmesi §8.7'dedir; commit sonrası semantik etki (G4) ile forced recovery'de kayıpsızlık (U10, yalnız witness/replica-before-ack ile) ayrı iddialardır.

#### 9.11.1 Epoch mekanizmalarının eşlenmesi (MD-7)

- **ValidityContract semantiktir; epoch'lar mekanizmadır.**
- ValidityContract, identity plane token'ları dahil bütün yeniden kullanılabilir artefaktların semantik sözleşmesidir (MD-7). L17, L19 ve INV-24 korunur.

| Mekanizma | Access'teki yeri | Garanti dili |
|---|---|---|
| `session_epoch` | Identity plane oturum/token hızlı iptali (kimlik-iddiası profili). Instance veya Party başına; `instance.terminate` ve `party.compromise` sonrası artar | Hızlandırıcıdır. Authority garantisi ValidityContract horizon'una dayanır. Epoch kontrolü yapan verifier için pencere daralır (UDC) |
| `key_epoch` | Anahtar penceresi: Domain Metadata / JWKS rotasyonu ve operasyonel anahtar penceresi (MD-6: varsayılan 1 sa, üst sınır 24 sa, PD) | §9.10 adım 1 (`iat` operasyonel anahtar penceresi içinde) |
| `authz_epoch` | **Authority plane'de kullanılmaz.** Yerini AuthorityStateBasis (karar tarafında) ve türetilmiş önbellek anahtarındaki `applied_pos` (§9.7A.4) alır | Epoch commit sonrası garanti vermez. Pozisyon nedenselliği korur |

Ek kurallar:
- "Cache bu kullanıcıyı hiç görmedi" durumu fail-closed'dur (MD-7). Zaman tabanlı degraded pencere yalnız "cache bayat" durumuna uygulanır.
- `authz_epoch` karar cache'i yalnız advisory kullanımda geçerlidir (MD-4 son madde).

#### 9.11.2 Doğrulama yolları: iptal ve bayatlık satırları (§13'e aday)

- **Kural.** MD-7'ye göre her satır Δ/horizon beyanıyla guarantee matrisine bir satır olarak girer.
- **Numaralama.** Satırların numaralanması ve sınıf hücrelerinin kesinleşmesi §13'e aittir. Burada protocol tarafının **önerdiği** sınıflandırma verilir.

| Doğrulama yolu | Önerilen Access kuralı | Önerilen sınıf | §13'e aday |
|---|---|---|---|
| Identity plane içi: login | DB erişilemezse 503. Önbellekte hiç görülmemiş kullanıcı için fail-closed. Login authority değildir; sonucu `authentication` Claim'idir | Kullanılabilirlik NG; yanlış ALLOW yok **BS** (Claim authority değildir) | guarantee — "login yolunda DB kaybı: fail-closed, Claim üretilmez" |
| Identity plane içi: refresh | Refresh = `projection.issue` kararı. StateBasis okunamazsa 503 + `Retry-After`, `invalid_grant` değil | Yeni projection yok **BS** | guarantee — "refresh yolunda StateBasis kaybı: projection üretilmez" |
| Identity plane içi: introspection | Tazelik kanıtlanamıyorsa `active=false` (MD-8). Primary'ye veya tazelik kaynağına ulaşılamıyorsa her token için `active=false` döner; önbellek isabeti (cache-hit) dahildir; 503 dönmez. 60–300 s fail-open pencereleri reddedilir (OPI-3, §14.8, §16.7.1, §17.7 OP-45 ile aynı cümle) | **BS** (fail-closed) | guarantee — "introspection: tazelik kanıtlanamazsa `active=false`" |
| Salt-JWT doğrulayan RS (sinyal tüketmez) | İptal bilgisi önbelleği yoktur. JWKS anahtar önbelleği iptal durumu değildir. Azami bayatlık ≈ access token ömrü = ValidityContract horizon'u | Pencere içi kullanım beyanlı pencere **BS** (sınıflandırma); pencerenin kapanması **UDC** | guarantee — "salt-JWT RS: bayatlık ≤ horizon (≤ 60 dk yönetim PD)" |
| Sinyal tüketen RS (SSF/CAEP) | Sinyal hızlandırıcıdır; teslim garantisi yok. Güvenlik ValidityContract'a dayanır | Teslim **NG**; horizon'a uyma **UDC** | guarantee — "SSF/CAEP tüketen RS: sinyal best effort, pencere horizon'la sınırlı" |
| Advisory önbellek / türetilmiş indeks | `applied_pos` anahtarlı. Olumsuz TTL ≤ 1 s. Hiç görülmemiş → fail-closed | Commit girdisi değil **BS**; advisory tazelik **UDC** | guarantee — "advisory önbellek: ALLOW üretmez, bayatlık beyanlı" |

- **Geçersiz kılma koşulu**: "Veritabanı düşse dahi doğrulama sürer" ile "iptal en geç 250 ms içinde uygulanır" garantileri aynı yolda birlikte verilemez.
- Access bunu yapısal olarak çözer:
  - Degraded mode yalnız beyanlı TI-9 / SEC27 / SI-22 yollarıyla çalışır (MD-8).
  - Yayılım hedefleri (250 ms / 1 s) bir profil satırının EA hedefidir; garanti değildir.

### 9.12 ValidityContract ve connectivity profile'ları

ValidityContract bir **value**'dur; kendi başına authority taşımaz. Wire'da projection-issue Exercise'ının sonucuna ve Portable Authority Proof'a gömülü taşınır; ontology karşılığı: `projection.issue` Exercise'ının DecisionRecord'undaki value + projection credential'ının içeriği.

| Alan | Semantik | Kural |
|---|---|---|
| `issuing_exercise` | `projection.issue` ExerciseID | Kaynak; hesap verebilirlik ve offline report bağlantısı |
| `basis_ref` | AuthorityStateBasis referansı; audit kapsamının altındaki verifier/holder için opaque token (TI-RT10) | Contract'ın "neye göre" olduğu |
| `holder` | Holder binding (actor Instance'ın key binding'i; DPoP/mTLS veya proof-of-possession anahtarı) | Bearer contract yasak (PI-11) |
| `audience` | Verifier / RS / PEP kümesi | Başka verifier'da geçersiz |
| `bounds` | Bounded projection (AuthoritySet ∩ Mandate ∩ local requirements; catalog pin'li) | Asla Grant'ın tam AuthoritySet'i değil, yalnız amaçlanan action'lar (E19) |
| `profile` | Connectivity profile **class** + **variant** + parametreler. Class kapalı kümesi frozen dört sınıftır (L16): `online` · `intermittent` · `offline` · `long-running`. Variant'lar protocol kataloğudur ve her biri tek bir class'a eşlenir: `online-strict` → online; `bounded-staleness`, `revalidate-on-reconnect` → intermittent; `checkpointed-offline` → offline; `checkpoint-continuation` → long-running | Class ve variant must-understand; parametre değerleri (Δ, N, horizon) yerel; yeni class veya variant governance. Ayrı bir yerel AuthorityDomain (tesis/robot filosu) profile değildir; deployment pattern'idir |
| `horizon` | Mutlak bitiş zamanı (expiry) | Verifier'ın yerel saatine göre; clock evidence kuralı aşağıda |
| `max_staleness` (Δ) | `bounded-staleness` için verifier'ın son status/revocation tazeleme zamanından itibaren kabul edilebilir yaş | Δ aşıldıysa offline kabul yasak, yalnız online |
| `freshness_sources` | Status list URL'leri / SSF stream'leri / checkpoint kaynakları | Bilgi kanalıdır, safety mekanizması değil |
| `revalidation` | Koşullar (ör. her N kullanımda, her reconnect'te, belirli action class'larında) ve checkpoint'ler | `revalidate-on-reconnect`'te bağlantı geldiğinde yeni karar zorunlu |
| `offline_slice` | Consumption-bearing action'lar için `projection.issue` anında lineage BudgetTerm'lerinden **önceden draw edilmiş** budget/sayaç dilimi: miktar, birim, BudgetTerm ref'i | Slice dışı tüketim offline yapılamaz; draw `projection.issue` commit'inde tamamdır (ayrı reserve/finalize adımı yoktur; merkezde aynı kapasite ikinci kez harcanamaz) |
| `local_requirements` | Verifier'ın yerel olarak karşılayabileceği RequirementTerm'ler (ör. yerel UV) | Karşılanamayan requirement → offline kabul yok |
| `verifier_profile_ref` | Verifier Profile Claim'inin digest'i | Profile'ın desteklemediği contract'ı verifier kabul etmez (must-understand) |
| `clock` | Kabul edilebilir saat kaynağı sınıfı ve skew toleransı | Verifier yerel zamanı + clock evidence'ı report'a yazar |
| `must_understand` | Contract'ın verifier'ın anlaması zorunlu extension'ları | Anlaşılmayan → reddet (PI-12) |

**İmza ve guarantee.** Contract'ın imzası domain'in (Access provider'ın) projection anahtarıyla; verifier bunu Domain Metadata'daki anahtar bağlamasına göre doğrular. Guarantee sınıfları X17 ile aynıdır: horizon ve bounds içi kullanımın authority içi (beyan edilmiş pencere) sayılması **BS** (sınıflandırma); verifier'ın horizon/bounds/Δ'ya fiilen uyması ve horizon içinde merkezde yapılan revoke'un offline verifier'a ulaşmadığı pencerenin fiilen kapanması **UDC** (pencere `horizon` ve Δ ile sınırlı ve contract'ta açık).

**Profile class tablosu.**

| Class (frozen, L16) | Variant | Projection | Verifier yükümlülüğü | Revoke etkisi | Guarantee |
|---|---|---|---|---|---|
| `online` | `online-strict` | Yalnız decision receipt / exact-intent token (kısa, tek kullanım) | Her action'da ADP çağrısı | Anında | Revoke'un sonraki her karara etkisi **BS**; PEP'in kararı effect'ten önce uygulaması **UDC** |
| `intermittent` | `bounded-staleness` | Bounds token + status kaynağı | Status'u Δ içinde tazeleme; aşıldıysa online | ≤ Δ | **UDC** (pencere Δ, contract'ta açık) |
| `intermittent` | `revalidate-on-reconnect` | Bounds token / PAP | Bağlantı gelince yeni karar; kesintide horizon'a kadar | ≤ kesinti süresi ≤ horizon | **UDC** (pencere ≤ horizon, contract'ta açık) |
| `offline` | `checkpointed-offline` | PAP + offline slice + report yükümlülüğü | Slice, local requirements, chain'li report | ≤ horizon; tüketim ≤ slice | Slice içi merkez double spend yok **BS**; pencere ve slice'a fiilen uyma **UDC** |
| `long-running` | `checkpoint-continuation` | Receipt + ValidityContract (horizon + checkpoint planı; continuation contract) | Executor her checkpoint'te `continue` ister; DENY'da yeni consequential effect başlatmaz | Sonraki checkpoint'te (≤ checkpoint aralığı ≤ horizon) | Continuation DENY'ı **BS**; Executor'ın checkpoint'te sorması **UDC**; çalışan effect'in durması **NG** (EI-11) |

Ayrı bir yerel AuthorityDomain (ör. tesis/robot filosu) bir profile class'ı değildir: bridging Grant'lı ayrı bir domain'dir; oradaki projection'lar yine bu dört class'tan birini taşır.

#### 9.12.1 Verifier Profile Claim

Verifier'ın (PEP, robot, offline cihaz, RS) kendi yeteneklerini beyan ettiği Claim'dir; class `verifier.profile`, issuer = verifier'ın operatörü (veya cihaz attestation'ı ile birlikte operatörü).

Semantik zorunlu alanlar: verifier kimliği (InstanceID veya workload ID), desteklenen connectivity profile class'ları ve parametre sınırları, desteklenen core spec / meta-schema / profile sürümleri, güvenli saat yeteneği (clock source class), slice tutma yeteneği (tamper-evident sayaç var/yok), offline report yeteneği, attestation evidence ref'i (varsa; RATS/EAT gibi format **informative**), status/revocation kaynaklarına erişim yeteneği.

Bir domain bir verifier profile'ını `predicate-input` Acceptance ile kabul eder; `projection.issue` politikası "yalnız şu profile'ları karşılayan verifier'lara `checkpointed-offline` contract" gibi kurallar koyar. **Issuer, verifier'ın profile'ının kapsamadığı bir contract'ı issue etmez** (PI-12'nin issuer tarafı).

#### 9.12.2 Offline Exercise Report

Offline verifier'ın merkezle yeniden bağlandığında gönderdiği rapordur. Ontology'de bir **Claim**'dir (class `offline.exercise-report`, issuer = verifier, subject = projection ExerciseID). Access'te ingest edilir; **raporun kendisi authority state değiştirmez** ve remaining'i tek başına değiştirmez (E5, PI-22). Etkisi:

- **Draw zaten yapılmıştır.** Slice, `projection.issue` DecisionRecord'unun consumption effect'i olarak issuance anında lineage budget'larından draw edilmiştir; "kesinleştirme" adımı yoktur (draw rezervasyonun kendisidir, release düzeltmedir). Access raporu projection'a bağlar (§7.9.4.1); rapordan türeyen **kullanılan / kullanılmayan / contract dışı** ayrımı **derived** state'tir (S4/S9 status'unda görünür).
- **Kullanılmayan slice'ın iadesi** yalnız explicit, attributable bir `consumption.release` meta-Exercise'ıdır. Actor yetkili olandır: **orijinal exerciser** (projection'ı alan holder Instance'ı) veya **lineage holder**; Exercise raporu (ve gerekiyorsa başka grounded Claim'leri) grounded Claim olarak cite eder. Domain policy bu Exercise'ı otomasyonla tetikleyebilir, ama actor yine o Party'nin Instance'ıdır; **Access release yapmaz** ve bir actor değildir. Rapordaki hatalı `slice_unused` değeri, ancak bir yetkili actor onu grounded Claim olarak cite edip release ederse etkili olur; o release o Party'ye attributable'dır.
- Raporda bounds dışı, horizon sonrası veya slice aşan bir giriş varsa: bu derived **contract dışı kullanım** state'idir (verifier veya holder hatasının kanıtı rapor Claim'inin kendisidir); **Access ayrı bir Claim issue etmez**. Ardından gelecek yaptırım (RestrictionPolicy overlay, `instance.*`, `grant.revoke`) yetkili Party'nin explicit Exercise'ıdır. Otomatik authority değişikliği yok (E5).

Semantik zorunlu alanlar:

| Alan | Semantik |
|---|---|
| `verifier` | Verifier kimliği + profile digest'i |
| `projection` | Kapsadığı `projection.issue` ExerciseID ve contract digest'i |
| `period` | Raporun kapsadığı yerel zaman aralığı |
| `entries[]` | Her biri: intent digest, authority-relevant parametreler (veya digest'leri), yerel zaman + clock evidence, verifier'ın yerel outcome'u (ALLOW/DENY), slice'tan çekilen miktar, holder proof ref'i |
| `chain` | Girişlerin sıra numarası + hash chain'i (gizleme/sıralama değişikliğini tespit edilebilir kılar) |
| `slice_unused` | Kullanılmayan slice miktarı |
| `profile_version` | Uygulanan profile sürümü |

**Guarantee:** Slice içi tüketimde merkez tarafında double spend yok (draw `projection.issue` commit'inde) → **GUARANTEED BY SEMANTICS**; verifier'ın slice'ı ve horizon'u fiilen aşmaması → **UNDER DECLARED CAPABILITY** (verifier profile'ı, tamper-evident sayaç); rapor chain'indeki gizleme/sıra değişikliğinin tespiti → **UNDER DECLARED CAPABILITY** (verifier'ın imza/sayaç capability'si); rapor gönderilmemesi veya cihazın kaybolması → **NOT GUARANTEED** (önlenemez; eksiklik derived olarak görünür); rapor doğruluğu (kötü niyetli verifier'ın yanlış rapor vermesi) → **NOT GUARANTEED** (verifier trust; Acceptance + attestation ile daraltılır; Security OQ §20).

#### 9.12.3 Authority-state acknowledgement

Bir PEP/verifier'ın belirli bir authority-state değişikliğini (revoke, narrow, mandate end, instance terminate) **uyguladığını** beyan ettiği Claim'dir (class `authority-state.ack`, issuer = PEP). Semantik zorunlu alanlar: PEP kimliği, subject event (ilgili ExerciseID veya semantic event id'si §9.16), applied-at (PEP yerel zamanı + clock evidence), PEP'in uyguladığı basis pozisyonu, kapsam (hangi cache/token/session'lar etkilendi).

Kullanım: revocation'ın "nerede etkili oldu" görünürlüğü (S4/S9 status), domain politikası ("şu PEP'ler ack vermeden revoke tamam sayılmaz" yalnız **raporlama** koşuludur; revoke Access'te ack'ten bağımsız olarak hemen etkilidir — INV-21). Ack yokluğu bir **detection** sinyalidir, safety değil.

#### 9.12.4 Kanallar: bilgi vs safety

| Kanal | Rol | Safety kaynağı mı? |
|---|---|---|
| Token Status List / Bitstring Status List | Revocation durumunun çekilmesi | Hayır, tek başına değil; safety = horizon + Δ + fail-closed kural |
| SSF/CAEP/Access event'leri (§9.16) | Hızlı bildirim | Hayır; teslim garantisi yok, receiver re-query yapar |
| Online decision (ADP) | Kesin karar | Evet (online profile'larda) |
| ValidityContract horizon + bounds + slice | Offline sınır | Evet (offline profile'larda; UNDER DECLARED CAPABILITY — verifier conformant ise) |

Kural: **Hiçbir event kaybı authority genişletmez** (PI-9). Event'i kaçıran bir receiver en kötü ihtimalle contract'ın beyan ettiği pencereyi yaşar; daha fazlasını değil.

**Verifier Profile Claim ek alanları (9.12.1).**
- Verifier Profile Claim'e iki yetenek alanı eklenir:
  - "içerik pozisyonu kontrolü" (§9.10.1 adım 8);
  - "epoch / status tazeleme aralığı". Bu alan salt-JWT RS ile sinyal tüketen RS ayrımını (§9.11.2) beyan eder.
- İstemci içi karar noktaları (§9.7A.7) da bu Claim'i yayınlamadan `intermittent` / `offline` contract alamaz.
- Ayrıca MCP/OAuth RS davranış listesindeki (§11.5.6) uygulama yükümlülükleri, RS'nin Verifier Profile'ında conformance beyanı olarak yer alır.

### 9.13 Claim ingest, Party Identity Regime, Acceptance ve schema publication

Access'in her taşıyıcıdan çıkardığı şey aynı **Claim record**'udur. Taşıyıcı değişir, record alanları değişmez.

| Claim alanı | Zorunlu | OIDC ID Token | SET (SSF/CAEP/RISC) | VC / SD-JWT | SCIM | SPIFFE SVID / WIMSE WIT | Domain-signed Claim |
|---|---|---|---|---|---|---|---|
| claim identity | Evet | `jti` / token digest | `jti` | credential id / digest | resource id + version digest | SVID digest | issuer-scoped id |
| issuer | Evet | `iss` | `iss` | `issuer` | SCIM servis kimliği (authenticated channel) | trust domain bundle'ı | issuer PartyRef / key |
| subject | Evet | `sub` (+ `iss`) → PartyRef çözümü | subject identifier | `credentialSubject.id` | user/group id → PartyRef | SPIFFE ID → PartyRef/Instance | açık |
| class | Evet | Profile eşlemesi (`authentication`, `identity-binding.*`) | event type → class | credential type → class | `member`, `identity-binding.*` | `identity-binding.workload` + KeyBinding | açık |
| value \| digest | Evet | claim değerleri (minimize, E26) | event payload | açıklanan alanlar (SD) | attribute'lar | — | açık |
| issuedAt | Evet | `iat` / `auth_time` | `iat` | `validFrom` | `meta.lastModified` | `iat` | açık |
| validity | Evet | `exp` | event'e göre | `validUntil` + status | issuer beyanı / profile varsayılanı | `exp` | açık |
| attribution evidence | Evet (biçimi değil, varlığı) | imza | imza | imza / proof | authenticated channel (ingest kaydıyla) | imza | imza veya authenticated channel |
| ingest time | Evet | Access trusted time | aynı | aynı | aynı | aynı | aynı |
| supersedes | Opsiyonel | — | — | status / yeni credential | — (sıra kaynağı değildir) | — | açık |

**Ingest kuralları.**

1. **Ingest ≠ Acceptance.** Claim ingest'i Claim corpus'a eklemedir; karara yalnız aktif bir Acceptance'ın use'u için girer (INV-2, INV-15).
2. **Assurance floor taşıyıcıyı belirler, taşıyıcı assurance'ı değil.** İmzasız ama authenticated kanaldan gelen Claim attributable'dır; Acceptance'ın assurance floor'u imza istiyorsa o Claim o use için kullanılmaz (C19).
3. **Admit / quarantine / reasoned reject.** Authenticated bir issuer'dan gelen ama Acceptance kapsamına girmeyen bir Claim sessizce düşürülmez: ya kaydedilir ama kullanılmaz (ingest quarantine, `quarantine:<reason>`; açıklamada `source-not-accepted`), ya gerekçeli reddedilir (Work ile aynı ilke).
4. **Gelecekten gelen Claim kullanılamaz** (C33): `issuedAt` > trusted evaluation time (Acceptance'ın skew toleransı dışında) → unusable.
5. **Minimizasyon.** Taşıyıcı daha fazla alan getirse bile Access yalnız karar için gerekeni ingest eder (E26); seçici açıklama (SD-JWT, RFC 9901) tercih edilir.
6. **Issuer sırası.** "Yeni / sonraki" Claim issuer sırasına göredir, varış sırasına göre değil (TI-RT7). Sıra kaynakları yalnız şunlardır: (i) açık `supersedes` zinciri; (ii) Party key-event pozisyonu; (iii) taşıyıcı profilinin ayrıca tanımladığı monoton sıra alanı. Hiçbiri yoksa sıra belirsizdir ve disqualifying kazanır; eski / sırasız Claim kaydedilir ama episode açmaz (G36).
7. **Kota.** Ingest kotasını aşan Claim'lere ingest quarantine yalnız qualifying (genişletici) etki için uygulanır; narrowing sınıfı Claim kota nedeniyle reddedilmez veya quarantine'e alınmaz, yalnız SI-20 sınırlarına tabidir (G44).

**Party Identity Regime ↔ Access.** Regime'in kendisi (PartyID, key-event history, controller, recovery kuralları) Work Protocol ile ortak, product-neutral spesifikasyondadır (E4). Access regime'den yalnız Claim sınıfları tüketir: `party.key-state`, `party.compromise`, `party.recovered`, `party.terminated`, `party.identity-break`, `controller-of`, `identity-binding.<kind>`, `authenticator-binding`. Her birinin Access'teki tek etki kanalı restriction, actor-binding girdisi veya explicit Exercise'tır; hiçbiri authority state'ini kendiliğinden değiştirmez (E5). `occurredAt` yalnız daraltmayı seçer (INV-23); yeni PartyID hiçbir authority miras almaz.

**Acceptance'ın wire karşılığı.** Acceptance bir **meta-Exercise ile yaratılan primitive**'tir; protocol'de ayrı bir "trust configuration" mesajı yoktur. `acceptance.establish / amend / revoke` Exercise Request'inin payload'ı Acceptance alanlarını taşır: `issuer` (değişmez), `use` (değişmez), `artifactClasses`, `subjectClass`, `domain` (+ opsiyonel Anchor scope), `assuranceFloor`, `validity` (+ ingest-time sınırı).

**Issuer'ın protocol'de tanımlanması** (issuer identification method; Acceptance'ın `issuer` alanının değer biçimleri):

| Yöntem | Ne zaman | Not |
|---|---|---|
| PartyRef (regime) | Party olan issuer'lar (HR servisi, Commerce, Executor) | Önerilen varsayılan |
| OpenID Federation entity identifier (+ trust anchor / chain kısıtı) | OIDC IdP'ler, OIDF ekosistemindeki issuer'lar | Trust chain **girdidir**; chain'in metadata policy'si (ör. `allowed_entity_types`) Acceptance'ı daraltabilir, genişletemez (L26) |
| SPIFFE trust domain + bundle | Workload identity | Trust domain ≠ AuthorityDomain (L25) |
| Pinned key set | Küçük/kapalı ortamlar | Rotasyon explicit `acceptance.amend` ister |

Bir issuer'ın OIDF trust chain'inin geçerli olması veya bir trust mark taşıması **hiçbir use için kabul değildir**; Acceptance yine explicit meta-Exercise'tır (PI-3).

**Schema Publication Package (SPP).**

SPP publisher'ın imzalı yayınıdır. Ontology'de bir **Claim**'dir (issuer = publisher, class `schema.publication`); Access'teki kopyası ingest kaydıdır. Bir domain'de kullanılabilir olması, exact digest'ini pin'leyen bir `schema-definition` Acceptance'ına bağlıdır (E10).

| Alan | Semantik | Kural |
|---|---|---|
| `publisher` | PartyRef / issuer identification | Namespace'in sahibi iddiası; domain hangi publisher'ı kabul ettiğine Acceptance ile karar verir; global registry yok |
| `namespace` | Namespace URI | İki publisher aynı prefix'i iddia edebilir; domain birini kabul eder |
| `catalog_version` | Sıralı, immutable katalog sürümü | Grant'taki namespace prefix'i bu sürüme çözülür (E11) |
| `catalog_digest` | Katalog içeriğinin digest'i (action listesi + her action'ın schema digest'i + reserved bayrakları) | Kimlik = digest; aynı sürüm adı + farklı digest = publisher sözleşme ihlali |
| `actions` | Her biri Action Schema | — |
| `compatibility` | Önceki sürümlere compatibility declaration'ları; her biri ayrıca ayrı Claim olarak da yayınlanabilir | Kullanılabilirliği ayrı Acceptance pin'ine bağlı |
| `retirements` | Retired action/sürüm beyanları | Retirement hiçbir şeyi genişletemez; DENY domain restriction'ıyla |
| `core_spec_min` | Schema'nın dayandığı minimum core meta-schema / closed-type sürümü | Must-understand |

**Katalog sürümü ve prefix pin'i.**

- Grant'ın AuthoritySet'inde namespace prefix kullanılıyorsa `grant.issue` payload'ı `(namespace, catalog_version, catalog_digest)` üçlüsünü taşır; Access issue anında bu üçlüyü pin'ler (E11). Bu bir value'dur; Grant'ın yeni alanı değil, AuthoritySet'in actions boyutunun kapalı biçimidir.
- Reserved action'lar prefix'le hiçbir katalogda kapsanmaz (INV-9).
- Yeni katalog sürümüne geçiş `grant.amend`'dir (toplu olabilir; her biri attributable Exercise; genişletme içeriyorsa genişletme requirement'ları). Migration mekaniği: publisher'ın compatibility declaration'ı + domain'in Acceptance pin'i + amend Exercise kümesi; ayrı bir "migration" nesnesi yoktur.

#### 9.13.1 Controller'ın issuer yetkilendirmesi

Soru: bir issuer (ör. Suiss Identity plane) bir Party için `authenticator-binding` yayınlıyorsa, bu yetki nereden gelir ve Access bunu nasıl görür?

**Karar:**

1. **Yetkilendirme regime'dedir, Access'te değil.** Controller, Party'nin key-event history'sine class başına bir **issuer designation** key-event'i yazar (regime kaydı; Work Protocol §21.4 kapsamında). Bu bir Access Grant'ı değildir ve hiçbir AuthorityDomain'de authority vermez (Controller ≠ Authority).
2. **Access onu `party.key-state` Claim'inin designated issuer kümesi olarak görür.** Bir `authenticator-binding` (ve onu kullanan `authentication`) Claim'i, subject Party için yalnız **iki koşul birlikte** sağlanırsa actor-binding'de kullanılabilir: (a) issuer o class için domain'de aktif bir `actor-binding` Acceptance'ına sahip (domain'in güveni), **ve** (b) issuer, subject'in güncel key-state'inde o class için designated (Party'nin rızası). Bu bir conjunction'dır, yani yalnız daraltır; Acceptance'ın biçimi değişmez, yalnız Claim'in attribution kontrolü sıkılaşır.
3. **Custody ≠ controller.** Suiss Identity plane bir Party'nin anahtarlarını custodial tutuyorsa designation key-event'ini Party adına imzalayan custodian'dır; bu Suiss'i controller veya root yapmaz (E4), ama custodian'ın kötüye kullanımı bir risk olarak kalır: guarantee sınıfı **UNDER DECLARED CAPABILITY** (custodial olmayan controller anahtarı; aksi hâlde beyan edilmiş custodial risk). Ayrıntı Security'dedir (§21 OQ1).
4. **Designation iptali prospective'tir.** Controller bir issuer'ın designation'ını kaldırırsa, o issuer'ın sonraki Claim'leri (ingest time'a göre) attribution kontrolünden geçmez; önceden kaydedilmiş Exercise'lar geçerli tarih olarak kalır (INV-23). Compromise sonrası ingest-time cutoff aynı mekanizmayla uygulanır (§7.9.11.1).

#### 9.13.2 First-party neutrality

Suiss Identity plane bu bölümdeki Claim sınıflarını, taşıyıcıları (OIDC, VC, `authentication` assertion) ve Acceptance yolunu **aynen** kullanır; Suiss'e özel bir Claim sınıfı, issuer identification yöntemi veya örtük Acceptance yoktur (E3, E24, §7.9.1.3). Bir domain Suiss Identity plane'i hiç kabul etmeyip yalnız external IdP kullanabilir.

#### 9.13.3 Action Schema: semantik zorunlu alanlar

| Alan | Semantik |
|---|---|
| `name`, `version`, `schema_digest` | ActionRef'in kimliği (namespace + name + version + digest) |
| `reserved` | Publisher'ın reserved beyanı; domain yerel olarak ek action'ları reserved işaretleyebilir (yalnız daha sıkı) |
| `consumption_bearing` | Action'ın budget/single-use birim tüketip tüketmediği; projection türünü belirler (§9.9.1) |
| `parameters[]` | Her parametre için: `name`, `class` ∈ {`authority-relevant`, `authority-opaque`}, authority-relevant ise **closed type** (E12: `Enum/set`, `Equality`, `Ordered numeric + unit`, `Count`, `Time interval`, `ResourceRef/prefix/structural selector`, `SubjectSelector`, `PurposeRef set`, `Boolean`), unit / enum domain'i; authority-opaque ise **body digest rule** (§9.14.2) |
| `resource_types` | Hangi ResourceRef türlerine uygulanır |
| `purpose_vocabulary` | PurposeRef kümesi ve (varsa) açıkça beyan edilmiş kapsama ilişkileri |
| `render` | Approval Surface / S1 için insan-okunur etiketler, alan sırası, yerelleştirmeler; **authority-opaque sunum verisidir**: authority sınırı ifade etmez ve agent için talimat değildir (A-7). Render tanımı schema digest'ine dahildir; böylece onaylanan render kabul edilen schema'dan gelir (XI-8) |
| `effect_class` | Geri alınabilirlik / irreversibility sınıfı (Approval Surface'in "material fields"ı için; Work §17.6) |

Tipe eşlenemeyen authority-relevant parametre SPP'de geçerli olabilir ama **`schema-definition` Acceptance'ında reddedilir** (E12); Acceptance incelemesi bu alanlar üzerinden yapılır (§8.17.10.2 developer console uyarısının kaynağı).

#### 9.13.4 Compatibility declaration: semantik zorunlu alanlar

| Alan | Semantik |
|---|---|
| `from` | ActionRef @ schema digest (eski) |
| `to` | ActionRef @ schema digest (yeni) |
| `relation` | `representation-equivalent` · `narrowing` · `broadening` · `incompatible` (§7.9.3.2) |
| `mapping` | `to`-intent'ini `from`-intent'ine çeviren **field mapping**; yalnız closed-algebra işlemleriyle ifade edilir: alan yeniden adlandırma, enum değer eşlemesi, sabit ve exact unit dönüşümü, alan sabitleme/düşürme (yalnız authority-opaque). Serbest fonksiyon, dış çağrı yok → decidable (INV-8) |
| `mapping_digest` | Mapping'in kimliği |
| `issuer` | Publisher |

**Kullanım kuralı (E10):** Mapping yalnız domain onun `mapping_digest`'ini reserved bir `acceptance.amend` ile pin'lediyse kullanılır ve yalnız non-broadening yönde otomatik uygulanır: bir v2 intent'i v1 Grant'ıyla değerlendirilirken Access `mapping(intent_v2) ⊑ AuthoritySet_v1` kontrolünü yapar. `broadening` / `incompatible` beyanlarının mapping'i hiçbir zaman otomatik kullanılmaz. Etiketin doğruluğu publisher trust'ıdır (**NOT GUARANTEED**; kurtarma: Acceptance revoke + ingest-time cutoff).

#### 9.13.5 RAR eşlemesi (RFC 9396 EXTEND)

| RAR öğesi | Access eşlemesi |
|---|---|
| `type` | ActionRef'in canonical string biçimi: namespace URI + action name + version; **schema digest ayrı bir Access üyesi olarak zorunludur** (aynı sürüm adı + farklı digest ayırt edilir) |
| Access üyesi `kind` | `intent` (tek IntentEnvelope; exact) veya `bounds` (AuthoritySet ∩ Mandate projection'ı) — iki kullanım hiçbir zaman karışmaz |
| Typed parametre üyeleri | Schema'daki authority-relevant parametreler; `kind=intent`'te değer, `kind=bounds`'ta closed-type constraint |
| Opaque parametreler | Yalnız digest'leri (`kind=intent`) |
| RFC 9396 ortak alanları (`locations`, `actions`, `datatypes`, `identifier`, `privileges`) | **Access sınırı ifade etmez.** `locations` yalnız audience/RS ipucu olarak RFC 8707 `resource` ile tutarlı olmak zorundadır; diğerleri Access projection'ında **kullanılmaz** (belirsizlik kaynağıdır). Gelen bir istekte bulunurlarsa authority girdisi değildir |
| Access üyeleri (`domain`, `exercise`, `basis_ref`, `capacity`, `validity`, `catalog` pin'i) | Projection'ın Access semantiği |

RAR type'larının IANA/OAuth registry'sine kaydı gerekip gerekmediği bir standards backlog maddesidir (§9.17.5); semantik bundan bağımsızdır (type URI-tabanlı ve publisher namespace'idir).

#### 9.13.6 Benimseme akışı (domain)

```text
publisher: SPP v3 yayınlar (imzalı; catalog_digest, schema digest'leri, compatibility v2→v3)
Access (domain D): SPP'yi Claim olarak ingest eder (ingest ≠ kabul)
domain admin(ler)i: S7 Sources ▸ Action definitions (§8.17.9.3) — diff, tipler, reserved, beyan
   → acceptance.amend(schema-definition, + v3 digest'leri, + mapping_digest)   [reserved; quorum tipik]
   → mevcut Grant'lar v2'de kalır; v3 intent'leri yalnız pin'li non-broadening mapping ile v2 Grant'larıyla
     değerlendirilebilir; aksi `schema-not-accepted` / `no-covering-authority`
```

#### 9.13.7 Core namespace (Access meta-schema'ları)

`grant.*`, `mandate.*`, `acceptance.*`, `anchor.*`, `domain.handover` / `domain.recover`, `instance.*`, `party.register`, `claim.issue`, `contribute`, `consumption.release`, `projection.issue`, `policy.set` ve `approve` / `disclose` / `declassify` core class'ları **Access Core Semantic Spec**'in yayınladığı bir SPP'dir; publisher = protocol governance (Suiss-hosted Access değil, §7.9.3.1). Domain yeni bir core meta-schema sürümünü kendi constitution'ında bir reserved meta-Exercise ile benimser (`anchor.amend(rootTerms)` meta-anchor üzerinde); benimsenmemiş sürüm o domain'de hiçbir şey değiştirmez (§9.17.2).

Bu belgede adı geçen diğer core action'lar ayrı primitive veya yeni meta-action değildir: `access.read` ve `access.audit.export` core namespace'in Access-internal **okuma** action'larıdır (authority state değiştirmez; §9.15A.5, §9.16). `domain.handover` ve `domain.recover` domain-scope meta-action'lardır ve frozen AuthorityDomain geçişinin ("provider handover") **adlarıdır**, yeni primitive veya yeni geçiş değildir. Provider binding Anchor'ın alanı değildir; AuthorityDomain'in Genesis'e bağlı değeridir ve yalnız bu iki action'la değişir. Kural: scope yalnız `Domain(D)`; `domain.handover` (kooperatif) basis = domain meta-anchor'ının root'u ve rootTerms requirement'ları + eski provider ve yeni provider katkıları (proof); `domain.recover` (zorunlu) root'un Exercise'ıdır: basis = AnchorRoot(domain meta-anchor), capacity OWN (INV-4'ün kapalı kümesi; ayrı bir "recovery basis'i" yoktur); requirement = rootTerms'te bu action için Genesis'te beyan edilmiş recovery entry'si (reserved power; ör. offline recovery anahtarları + quorum — meta-anchor'ın diğer meta-action'lar için geçerli genel root threshold'undan farklı olabilir, provider imzası gerektirmez); actor'ler bu entry'nin tanımladığı KeyBinding'lere sahip root Party Instance'larıdır (Joint root'ta katkılar k-of-n; Anonymous istek `domain.recover` yapamaz; recovery anahtarlarının Instance olarak tutulması Security'de, §21 OQ1(f)); son doğrulanmış checkpoint N'yi cite eder. Recovery entry'sinin değiştirilmesi `anchor.amend(rootTerms)` ile değişir (gevşetmek mevcut daha sıkı requirement'ı karşılamayı gerektirir). Herhangi bir alt (ör. carve edilmiş) Anchor root'unun provider binding değiştirme isteği ifade edilemez → DENY; domain'de provider binding tektir ("eşzamanlı iki provider" imkânsız). `anchor.amend` provider binding için kullanılmaz; `anchor.amend(rootTerms)` meta-anchor üzerinde core spec benimsemesi için kalır (§9.15).

#### 9.13.8 Ek kurallar: taşıyıcılar, identity plane ve federasyon

1. **Identity plane = Access'in kendi IdP'si, aynı kanal (MD-13, §9.13.2).**
   - Access tam bir IdP'dir. Identity plane'in ürettiği her iddia authority plane'e yalnız bu bölümdeki Claim Ingest kanalından girer: OIDC ID Token, SET, SCIM, VC, SVID/WIT, ID-JAG, WebAuthn assertion'ı.
   - First-party neutrality (§9.13.2) değişmez:
     - Suiss identity plane'e özel Claim sınıfı, issuer identification yöntemi veya örtük Acceptance yoktur.
     - External IdP aynı Acceptance koşullarıyla eşit girer.
   - Taşıyıcıların protokol alan ayrıntısı (OIDC claim'leri, SAML assertion'ı, SCIM şeması, SVID biçimi) §10'dadır. Bu tablo canonical Claim alanlarını tanımlar; §10 taşıyıcı başına alan ayrıntısını verir.
2. **ID-JAG ve inbound `act` taşıyıcı olarak (MD-18).**
   - Inbound bir ID-JAG (`typ: oauth-id-jag+jwt`) ve bir token içindeki `act` zinciri Claim taşıyıcısıdır. Eşleme:
     - claim identity = `jti`
     - issuer = `iss` (IdP AS)
     - subject = `sub` (+ `iss`) → PartyRef çözümü
     - class = `identity-binding.*` / `authentication` (profil eşlemesi)
     - value = `scope`, `resource`, `client_id`, `email` / `aud_sub` (minimize edilmiş, E26)
     - validity = `exp`
     - attribution evidence = imza
   - `scope` değeri Claim'in value'sudur; Access'te authority taşımaz (R3).
   - Ingest kural 1 geçerlidir: ID-JAG karara yalnız aktif bir `actor-binding` veya `predicate-input` Acceptance'ının use'u için girer.
   - ID-JAG hiçbir zaman authorization grant değildir. Resource AS rolündeki Access'in verdiği token `projection.issue` çıktısıdır ve dayanağı Grant'tır (§11.11).
   - IdP AS rolünde Access'in **ürettiği** ID-JAG authority taşımayan bir kimlik iddiası projection'ıdır; authority scope içermez (§11.11.2).
3. **Issuer tanımlama ve istemci tanımlama farklı eksenlerdir.**
   - Yukarıdaki issuer identification tablosu Claim **issuer**'ını tanımlar: PartyRef / OIDF entity / SPIFFE trust domain / pinned key.
   - **İstemci tarafı kayıt yolu seçimi** (ön kayıt → CIMD → DCR → kullanıcıya sor; §11.3.8) OAuth **client**'ın bir AS'e nasıl kaydolacağını seçer. AS tarafı `client_id` çözümleme sırası §10.1.2'dedir (IDP-1).
   - OAuth client bir actor değildir (PI-7) ve hiçbir Claim'in issuer'ı olarak kendiliğinden kabul edilmez. Ayrıntı §11.3 ve §10'dadır.
4. **OIDF chain-kısıtlı Acceptance.**
   - Issuer identification yöntemi "OpenID Federation entity identifier + trust anchor / chain kısıtı" olan bir Acceptance için şu koşul geçerlidir. Bir Claim'in o Acceptance altında karar girdisi olması için **üçü birlikte** sağlanmalıdır:
     - (a) Acceptance aktiftir;
     - (b) trust chain Claim'in ingest anında çözülür;
     - (c) chain'in tazeliği ≤ Δ'dır. Chain geçerliliği zincirdeki statement'ların `exp` değerlerinin minimumudur.
   - **Zincir kaybı** şu durumları kapsar: min(exp) dolması, subordinate statement'ın geri çekilmesi, trust mark'ın iptali. Zincir kaybı **Acceptance'ı revoke etmez**. O issuer'ın Claim'lerinin karar girdisi olmasını ileriye dönük keser:
     - ingest-time cutoff, INV-23;
     - ilgili episode'lar INV-31 ile kapanır.
   - Sınıflandırma: bu bir **lapse**'tir (Claim'in kullanılabilirlik koşulu düştü). Restriction değildir, çünkü yeni bir policy kaydı yoktur. Önceki Exercise'lar geçerli tarih olarak kalır.
   - Zincir yeniden çözülürse yeni Claim'ler tekrar girdi olur. Revoke edilmiş bir Acceptance ise yalnız yeni `acceptance.establish` ile geri gelir.
5. **Trust mark ile onay atlanamaz (§10.7.1).**
   - Bir trust mark ancak açıkça kaydedilmiş bir Acceptance'ın `predicate-input`'u olabilir. Etkisi yalnız şunlardır: (i) bir RequirementTerm/RestrictionPolicy girdisi (daraltma), (ii) render'a **ek** bilgi (ör. "doğrulanmış federasyon üyesi" rozeti). Render'dan alan çıkarılamaz. `material_fields` ve CT'nin tam render koşulu (§13.7.3) değişmez. Grant oluşturma AAS ister (§9.14).
   - "Güven seviyesi" birinci sınıf bir alandır ve bu Acceptance'ın parametresidir.
6. **Federasyon anahtarı ≠ token / Domain Metadata anahtarı.**
   - OIDF entity statement imza anahtarı, Domain Metadata yayın anahtarı ve projection imza anahtarı ayrı anahtarlardır (T20, MD-6).
   - Access entity type adları ve `allowed_entity_types` değerlerinin somut alanları §10'dadır (OIDF protokol ayrıntısı). Kural L26'dır: identity issuer'ın authority issuer rolü entity-type / metadata policy ile engellenebilir olmalıdır.
7. **SCIM grup üyeliği.**
   - SCIM grubu bir `member` Claim'idir. Grant ancak Acceptance + rule-shaped Grant şablonuyla oluşur (MD-4).
   - SCIM provisioning Grant yazmak değildir (§9.4).
8. **SPP ve RAR metadata keşfi.**
   - `draft-ietf-oauth-rar-metadata-remediation-00`'ın `authorization_details_types_metadata_endpoint`'i domain'in kabul ettiği SPP'lerin RAR type görünümü olarak sunulabilir (WATCH; §9.13.5).
   - Type tanımının kaynağı yine SPP + `schema-definition` Acceptance'tır.

### 9.14 Approval Act Statement (AAS)

Tek kullanıcı fiili tek bir **Approval Act Statement** üretir: approver'ın Instance'ı tarafından onaylanan (authentication assertion'ı statement'a bağlı), içeriği iki sistemin de bağımsız doğrulayabileceği bir statement. Statement **yeni bir primitive değildir**. Access tarafında AAS **her zaman bir proof'tur, hiçbir Exercise'ın IntentEnvelope'u değildir**: IntentEnvelope Access canonical içerikten hesaplanan typed envelope'dur, AAS onun digest'ini `target` olarak imzalar ve kendi digest'ini hiçbir okumada içermez. Böylece intent digest yüzey-bağımsızdır (`render_digest`, `surface`, `issued_at`, `expires_at`, `work_gate` intent'e girmez). İki act türü vardır (`act`):

- **`act = contribution`** — Access tarafında: `contribute` class bir **Authority Exercise**'ın proof'udur; o Exercise'ın IntentEnvelope'u core `contribute` meta-schema'sının typed envelope'udur (subject = target digest; actor = approver Instance; capacity OWN veya FOR(P)); başkasının (ör. agent'ın) Exercise'ındaki bir RequirementTerm'i karşılar. Quorum (ikinci admin'in onayı) da bu yoldadır.
- **`act = authority-act`** — Access tarafında: kullanıcının **kendi** meta-Exercise'ının (`grant.issue` / `amend` / `revoke` vb., genişletme sınıfı dahil) proof'udur; IntentEnvelope o meta-Exercise'ın exact typed preview'ından (core meta-schema render'ı) türetilen typed envelope'dur; actor = kullanıcının Instance'ı (E17: actor'ün Party'si = basis holder), statement'ın `target`'ı o envelope'un intent digest'idir; assertion H(AAS)'ye bağlıdır; **contribution yoktur** (INV-16). `render_digest` ve `surface` aynı Exercise'ın proof/context'idir.
- Her iki türde submit edilen Exercise Request'in Actor Intent Statement'ı approver Instance'ından gelir; statement'sız istek §9.5 kural 2 gereği Anonymous'tur.
- Her iki türde Work tarafında (`work_gate` varsa): Gate'i karşılayan **Approval Declaration**'ın içeriğidir (Work; Work'ün kendi ontology'si).
- Kanıt: `authentication` class Claim'i — binding alanı statement digest'idir.

AAS semantik zorunlu alanları:

| Alan | Semantik |
|---|---|
| `act` | `contribution` · `authority-act` (kapalı küme) |
| `approver` | Approver InstanceID (+ PartyRef); `authority-act`'te meta-Exercise'ın actor'ü |
| `capacity` | OWN / FOR(P) |
| `contribution_class` | Yalnız `act = contribution`'da zorunlu: `contribute` alt sınıfı (ör. `approve`, `co-sign`, `witness`, `disclose`, `declassify`) — namespaced, Access'te Grant'la yetkilendirilen action |
| `target` | Hedef digest: `contribution`'da RequirementTerm'i karşılanacak isteğin **intent digest**'i (REQUIRE_ACTION almış nonce'un; veya başkasının meta-action'ının intent digest'i); `authority-act`'te kullanıcının kendi meta-Exercise'ının intent digest'i; Work için Gate payload digest'i |
| `exercise_ref` | `(DomainID, nonce)` — ExerciseID henüz oluşmadan iki tarafın bağlayabileceği stabil referans: `contribution`'da contribution Exercise'ının nonce'u, `authority-act`'te meta-Exercise'ın kendi nonce'u |
| `work_gate` | (Opsiyonel) Work Gate ref'i + Work Declaration content digest'i; yoksa statement yalnız Access içindir |
| `surface` | Approval Surface conformance ref'i (profile + sürüm) — onayın hangi conformant yüzeyde verildiği |
| `render_digest` | Kullanıcıya gösterilen render'ın digest'i (render schema digest'ine dahil tanımdan üretilir) |
| `material_fields` | Gösterilen materyal alanların listesi (Work ile aynı küme; effect class'a göre) |
| `issued_at` | Approver tarafı zaman |
| `expires_at` | Statement'ın geçerlilik sonu (kısa) |

#### 9.14.1 Akış

```text
(A) act = contribution
1. Requester (agent Instance) → Access: commit(n1, intent, basis, capacity) → outcome REQUIRE_ACTION,
   `unmet` = { proofKind: contribution, class: contribute:approve, source: <eligible set>, binding: intent digest }
   (evaluation; Exercise yok; n1 intent validity'sine kadar açık — §6.1)
2. Approval Surface (Suiss veya üçüncü taraf conformant yüzey): AAS'yi kurar (act = contribution, target = n1'in
   intent digest'i); render, material fields
3. Approver: tek WebAuthn / SPC assertion; challenge = H(AAS)   → `authentication` Claim (binding = AAS digest)
4. Surface → Access: commit(n_c, contribute intent [typed envelope; subject = n1'in intent digest'i],
       actor = approver Instance [Actor Intent Statement, §5.2], proofs ∋ AAS + assertion)
       Access: actor-binding, Grant(approver, contribute:approve), target digest eşleşmesi → Exercise COMMIT
       → ContributionExerciseID
5. Surface → Work (gerekiyorsa): Approval Declaration = AAS + assertion + ContributionExerciseID
       Work: assertion'ı ve AAS'yi bağımsız doğrular; ContributionExerciseID'yi Access'in Portable Authority
       Proof / Decision Receipt'iyle (veya Access Record Export ile) doğrular → Gate karşılandı
       (Recovery sonrası eski provider anahtarlı receipt / PAP §9.10 recovery koşuluna tabidir: içerik eşleşmesi
        N'ye inclusion proof'la kanıtlanmadan Gate karşılanmış sayılmaz; §5.8)
6. Requester aynı nonce ile yeniden commit eder: commit(n1, aynı intent, proofs ∋ ContributionExerciseID)
       Access: RequirementTerm contribution ile karşılandı → ALLOW; Exercise burada doğar

(B) act = authority-act (kullanıcının kendi grant.issue / amend / revoke'u; ör. X8 "Give access once")
1. S1 (Suiss veya üçüncü taraf conformant yüzey): meta-Exercise'ın exact typed preview'ı (core meta-schema render'ı)
2. AAS { act = authority-act, approver = kullanıcının Instance'ı, target = grant.issue intent digest, exercise_ref = (D, n) }
3. Kullanıcı: tek assertion; challenge = H(AAS) → `authentication` Claim (binding = AAS digest)
4. S1 → Access: commit(n, grant.issue intent, actor = kullanıcının Instance'ı [Actor Intent Statement, §5.2],
   proofs ∋ AAS + assertion) → ALLOW → kullanıcının kendi meta-Exercise'ı; contribution yok
   (Gerekli requirement'lar — ör. quorum — eksikse REQUIRE_ACTION; ikinci admin (A) yoluyla katkı verir,
    kullanıcı aynı nonce ile yeniden commit eder)
```

Tek ceremony her iki türde de korunur: Work Declaration bağlaması (`work_gate`) aynıdır; assertion ile Actor Intent Statement'ın bayt seviyesinde tek imzada birleştirilip birleştirilmeyeceği Technical'dadır (§21 OQ2).

**Sıralama kuralı (contribution): Access önce commit eder, Work sonra doğrular.** Gerekçe: Work'ün ihtiyaç duyduğu şey "approver bu action'ı onaylama authority'sine sahip miydi?" sorusunun cevabıdır ve bu cevap Access'te doğar; Work bunu Access'e bağımlı olmadan, açık protocol artefaktı (receipt / PAP / record export) üzerinden doğrular. Ters sıra (Work önce) Work'ün Access'in kararını tahmin etmesini gerektirirdi.

**Bağımsızlık:** Access Work'ün varlığını bilmek zorunda değildir (`work_gate` opsiyonel); Work Suiss Access'i değil, **herhangi bir conformant Access provider**'ı doğrular (Domain Metadata §11.1). İki taraf da birbirinin implementasyonuna değil, statement + assertion + receipt'e dayanır (PI-14).

#### 9.14.2 Opaque body doğrulaması

Authority-opaque parametreler (ör. mesaj gövdesi, sözleşme metni) intent'e yalnız **digest** olarak girer. Kural: action schema'sı (§9.13.3) her opaque parametre için **body digest rule**'u tanımlar (canonicalization sınıfı + digest algoritması ref'i — bayt seviyesi Technical'da). Approval Surface render'ı body'nin kendisinden üretir, digest'ini hesaplar ve AAS'deki intent digest'iyle eşleşmezse **onay toplamaz** (Approval Surface conformance kuralı). PEP effect üretmeden önce gerçek body'nin digest'ini intent'tekiyle karşılaştırır; eşleşmezse effect yok (`intent-mismatch`, fail closed).

Guarantee: Onaylanan digest = Exercise'ın intent digest'i → **GUARANTEED BY SEMANTICS** (AAS ve kayıt aynı digest'e bağlı); icra edilen body'nin bu digest'e uyması → **UNDER DECLARED CAPABILITY** (conformant Surface + conformant PEP); conformant olmayan bir surface'in farklı bir render gösterip doğru `render_digest`'i raporlaması → **NOT GUARANTEED** (render_digest'i ve surface ref'i rapor eden surface'in kendisidir; kayıttan tespit edilemez; surface trust'ı Approval Surface Acceptance'ı / attestation ile daraltılır, E32).

#### 9.14.3 Authority act'ler (grant.issue / amend / revoke)

`grant.issue`, `grant.amend`, `grant.revoke` gibi meta-action'lar aynı yoldan geçer (R1, PI-4) ve iki durum ayrıdır:

- **Kullanıcının kendi authority act'i** (`act = authority-act`, §9.14.1 B): actor kullanıcının Instance'ıdır; IntentEnvelope meta-Exercise'ın (`grant.issue` / `amend` / `revoke`) typed envelope'udur; AAS o Exercise'ın **proof**'udur ve `target`'ı envelope'un intent digest'idir; assertion challenge'ı H(AAS)'dir; contribution yoktur. Intent digest yüzey-bağımsızdır: aynı `grant.issue` her conformant S1'de aynı digest'i üretir. Third-party conformant S1 aynı conformance kuralıyla bunu yapabilir (E23, X8).
- **Başkasının meta-action'ını onaylamak** (ikinci admin / quorum; `act = contribution`, §9.14.1 A): `contribute` Exercise'tır; target = o meta-action'ın intent digest'i; meta-action'ın actor'ü aynı nonce ile yeniden commit eder.

Approval Surface render'ı her iki durumda core meta-schema'nın render tanımından gelir. Böylece "admin'in yeni bir Grant vermesi için ikinci admin onayı" (quorum) ile "ödeme için kullanıcı onayı" aynı protocol nesnesidir (contribution); kullanıcının kendi delegation'ı ise aynı statement biçiminin `authority-act` türüdür.

#### 9.14.4 Decline ve reddedilen alternatifler

- **Decline yalnız Work'tedir**; Access'te "negatif contribution" yoktur — onay toplanmaması tek başına yeterli. Decline'ın kaydı Work'ün Declaration'ıdır. Access'te bekleyen bir Exercise yoktur: REQUIRE_ACTION almış nonce'un intent validity'si dolunca o nonce ile re-commit artık değerlendirilemez (yeni deneme yeni nonce).
- **Reddedilen:** (a) iki ayrı imza (UX + iki statement arasında tutarsızlık riski); (b) Access'in Work'e (veya tersinin) onay relay etmesi (hidden dependency, PI-14 ihlali); (c) AAS'yi bir Grant türü yapmak (onay authority vermez, bir requirement'ı karşılar; INV-16).

#### 9.14.5 Ek kurallar: WYSIWYS, CIBA, OAuth/MCP onay kaydı

1. **WYSIWYS.**
   - İşlem imzalama kalıbı şöyledir: sunucu aksiyon payload'ını üretir (ne yapılacağı, nonce, timestamp); istemci bunu gösterir; imzalanan ile görülen aynıdır.
   - Bu kalıp AAS'in görüntüleme gereksinimine eklenir:
     - `render_digest` render'ın kendisinden hesaplanır;
     - `material_fields` (effect class'a göre) render'da görünür olmak zorundadır;
     - opaque body digest'i eşleşmezse onay toplanmaz (§9.14.2).
   - Approval Surface conformance'ı (§8) bu kuralı test eder.
   - Platform biyometrisi tek başına güçlü kimlik doğrulama unsuru sayılmaz. Ödeme şablonunda "uygulama-kontrollü faktör" sınıfı istenir (MD-11).
   - Assurance sınıfı ve AAL eşlemesi §10'dadır.
2. **CIBA yalnız davettir.**
   - CIBA kullanıcıyı onay cihazına çağırır.
   - `binding_message` serbest metindir ve payload'ı bağlamaz. Onay içeriği değildir.
   - Onay AAS + assertion'dır. CIBA yanıtı ne contribution ne authority-act'tir.
   - Auth0'ın CIBA + RAR kombinasyonu (`authorization_details` onay sonrası token'da aynen taşınır) Access'te şöyle karşılanır: CIBA daveti → Approval Surface → AAS (`target` = intent digest) → `projection.issue`'nun RAR `kind=intent`'i. Neyin onaylandığı token'dan değil, AAS ve DecisionRecord'dan doğrulanır.
   - Eşleme: CIBA backchannel isteği bir `projection.issue` (veya exact intent) `commit`'idir. REQUIRE_ACTION alırsa `auth_req_id` = `exercise_ref (DomainID, nonce)`'un opak taşıyıcısıdır. Polling'deki `authorization_pending` = nonce açık. `expires_in` ≤ intent validity ve ≤ AAS `expires_at` (CT tablosu §13.7.3). İstemcinin kapsayan Grant'ı **varsa** kullanıcı onayı `act = contribution`'dır (`target` = REQUIRE_ACTION almış isteğin intent digest'i, §9.14.1 A). Grant **yoksa** (yeni delegation) `act = authority-act`'tir (`target` = `grant.issue` intent digest'i, §9.14.1 B) ve ardından aynı nonce ile `projection.issue` gelir. `binding_message` yalnız iki cihazı eşleştiren kısa koddur.
3. **OAuth/MCP onay (consent) kaydı = UI kaydı.**
   - Sunucu tarafı onay kaydı `(user_id, client_id, resource, scopes, source, metadata_hash)` identity plane'de bir **UI / oturum kaydı** olarak tutulur ve tekrar sormayı engeller.
   - Yetki yalnız AAS-imzalı `grant.issue` (+ gerekirse `mandate.bind`) ile oluşur (§9.9 OAuth binding tablosu, ilk satır).
   - Kayıt bu Grant'a `grant_ref` ile atıf yapar. Grant revoke edilirse veya lapse olursa kayıt geçersizleşir ve bir sonraki istekte onay yeniden istenir.
   - Kaydın kendisi hiçbir zaman authority değildir: kayıt var ama Grant yoksa → DENY.
   - Onay çerezi, CSRF, `state`, onaydan önce oturum kurmama gibi uygulama kuralları §11.6'dadır.

### 9.15 Domain Metadata, provider handover ve forced recovery

**Domain Metadata & Discovery (AP-15).**

Her AuthorityDomain bir **Domain Metadata** yayınlar; ontology'de domain'in Genesis, handover ve Acceptance kayıtlarından türetilen bir **PROJECTION**'dır (AP-15); imzası AuthorityDomain'in provider binding'indeki (Genesis'te tanımlı, `domain.handover` / `domain.recover` Exercise'larıyla bağlanan) yayın anahtarıyladır. Ayrı bir Claim class'ı değildir.

Semantik zorunlu alanlar: DomainID (genesis digest'inden türetilmiş; provider'dan bağımsız), genesis ref'i, güncel **provider binding** (hangi Access provider'ın bu domain'in decision ve projection anahtarlarını tuttuğu; Genesis / `domain.*` kaydıyla bağlı; domain'de tektir), decision/projection/receipt doğrulama anahtarları, handover veya recovery kaydı varsa eski provider anahtarlarının durumu (`superseded-at checkpoint N` veya `superseded-at C_{h+1}`, `N_cited` ile; §9.10 predicate'i), beyan edilmiş witness ve provider-dışı replica kümesi, ADP endpoint'leri, desteklenen core spec / profile sürümleri ve **domain minimum sürümü**, kabul edilen issuer'lar için yayın politikası (opsiyonel, özet), status/event kaynakları, record export endpoint'i, checkpoint kaynakları.

**Discovery:** `.well-known` URI tabanlı (RFC 8615 ADOPT) ve/veya OpenID Federation entity statement (PROFILE: domain bir federation entity olarak; trust chain **domain'in kim olduğunu** doğrulamaya yardım eder, domain'in authority'sini değil). Hangi URL'nin yayınlandığı transport/topology'dir (§16).

OIDF kabında Domain Metadata, Access entity type metadata'sı içinde **ayrıca imzalı** (yayın anahtarı, MD-3 COSE/JWS) bir nesne olarak taşınır. Dış entity statement'ı federasyon anahtarı imzalar ve yalnız "domain'in kim olduğunu" doğrular. Verifier authority anahtarlarını yalnız iç nesneden alır.

**Anahtar bağlamasının kökü provider değil genesis'tir:** Domain Metadata'nın imza anahtarı rootTerms'te değil (rootTerms bir RequirementSet'tir ve root-level meta-action'ların requirement'larını taşır; `domain.handover` ve `domain.recover` entry'leri bunlar arasındadır. Yayın anahtarı bir requirement değildir, provider binding'dedir), AuthorityDomain'in Genesis'teki provider binding'inde tanımlıdır; provider değişince yeni provider anahtarları domain-scope `domain.handover` veya `domain.recover` meta-Exercise'ıyla bağlanır (AuthorityDomain geçişi; Anchor alanı değil). Böylece verifier "bu domain'in kararı" iddiasını Suiss'e sormadan doğrular (PI-13).

**Tazelik.** Domain Metadata'nın verifier'daki cache'i ≤ Δ'dır ve tazeliği bağımsız witness cosign'ıyla ölçülür (TI-RT5, §9.10 adım 6). Sessiz domain'de de cosign tazelenir, çünkü heartbeat checkpoint'leri değişiklik olmasa da üretilir (§9.16).

**Handover ve recovery'nin semantiği.** İkisi de AuthorityDomain'in domain-scope meta-Exercise'larıdır; yeni basis türü yoktur. Basis = AnchorRoot(meta-anchor); requirement = rootTerms'in Genesis'te beyan edilmiş ilgili entry'si. Hiçbir Anchor değişikliği provider binding'i değiştiremez (PI-15).

| | Kooperatif handover (`domain.handover`) | Forced recovery (`domain.recover`) |
|---|---|---|
| Ne zaman | Eski provider işbirliği yapıyor (vendor exit, migration) | Eski provider ulaşılamaz, kötü niyetli veya anahtarı ele geçirilmiş |
| Katkılar | Eski provider + yeni provider + meta-anchor root | Meta-anchor root (rootTerms recovery entry'si; provider dışı custody, U16) |
| Kesim | Pozisyon tabanlı: eski provider freeze → k = head + 1 → root AIS'i (k'yı cite eder) → witness'lı C_k → handover batch'i (pos k..h; inline proof Claim'leri + pos h'de handover kaydı, C_k'yi cite eder) → yeni provider witness'lı C_{h+1} ile h+1'den devam | Pozisyon tabanlı: N (SEC21) = bağımsız witness co-signed **ve** kökü recovery tarafındaki kayıtlarla (provider-dışı replica veya dürüst provider'ın Record Export'u) yeniden üretilebilen en yüksek checkpoint |
| Rollback guard | — | Değerlendirici R*'ı kendisi sorgular; N < R* → DENY. Replica yoksa, sorgulanamıyorsa veya R* < witness en yüksek ise REQUIRE_ACTION (meta-anchor genel threshold'u), N = R* ve (N, witness en yüksek] StateBasis'te beyanlı kayıp suffix'tir (SEC22). Witness çatallanmasında N kayıtlarla desteklenen dalın en yüksek checkpoint'idir |
| State kurma | Record-fold (TI-RT1): kayıtlı DecisionRecord effect'leri kayıtlı hâliyle + Claim'lerden L0 normatif türetim; checkpoint kökü kayıtlardan yeniden üretilir | Aynı (N'ye kadar) |
| Yeniden değerlendirme farkı | Doğrulamadır, kapı değildir. Divergence set StateBasis'te beyan edilir; divergence quarantine (TI-RT1) divergent kaydın genişletici effect'lerini handover, recovery ve rebuild-diff yollarının hepsinde DENY eder; daraltıcı/consumption effect'leri kayıtlı hâliyle uygulanır. Uyuşmazlık çıkışı durdurmaz (G32) | Aynı |
| Kurulan policy | Divergence varsa divergence quarantine policy'si (root / Security Party'nin narrowing `policy.set`'i; aynı Exercise kümesinde veya rebuild-diff bildiriminden sonra; kaldırma CT3) | Post-recovery quarantine policy'si (SEC22 R1 (a)–(c)): (a) N'den önce issue edilmiş projection'lar yalnız exact-content inclusion veya re-issue ile; (b) CT2+ REQUIRE_ACTION; (c) `nonce-closed/pre-recovery`; kaldırma CT3. Divergence varsa ayrıca, SEC22 R1 deseninde ayrı bir divergence quarantine policy'si; kaldırılması ayrı bir CT3'tür |
| Eski anahtarlar | `superseded-at C_{h+1}`; handover drain (RT14) | `superseded-at checkpoint N` |
| Kayıp | Yok (freeze + batch) | Kayıp suffix'teki revocation'lar yeni revoke Exercise'larıyla prospective yeniden yapılır; ack edilmiş revocation/CT3 kaybı yok (U10, SEC23) |
| `basis_ref` / event-id anahtarı | Record Export Package içinde yalnız yeni provider'a açık biçimde taşınır | Recovery tarafında yoksa eski token'lar çözülmez ve fail closed olur; yalnız korelasyon ve explain kaybedilir, authority etkisi yoktur |
| Sınıf | Çıkışın kendisi UDC (U24 / işbirliği); eski-anahtarlı artefaktın reddi U27 | Recovery yapılabilmesi U24 (recovery re-anchor dahil); kayıpsızlık U10 / N-14 |

Teknik akış (sıra, fencing, re-anchor, drain) §16.6'dadır.

#### 9.15.1 Domain Metadata: ek alanlar ve ayrımlar

1. **İmza ve algoritma alanları (MD-3, MD-6).**
   - Domain Metadata şu alanları taşır:
     - binding key'in kapsamı (hangi DomainID'ler için);
     - operasyonel anahtar penceresi (varsayılan 1 sa, üst sınır 24 sa, PD);
     - her anahtar için `algorithm` alanı (gün-1'den; RFC 9864 fully-specified);
     - kabul edilen algoritma allowlist'i;
     - PQ profili ilanı (ML-DSA-65 opt-in; JWKS'te `AKP` anahtar tipi gün-1'den modellenir).
   - Verifier'lar allowlist'i artefakt header'ından değil buradan alır.
2. **Üç ayrı discovery belgesi.**
   - (a) **Domain Metadata**: authority (AP-15).
   - (b) **OIDC Discovery / RFC 8414 AS metadata**: identity plane'in kimlik ve OAuth AS belgesi (ayrıntı §10, MCP gereksinimleri §11.4).
   - (c) **`/.well-known/authzen-configuration`**: ADP'nin AuthZEN discovery'si (§9.5.1 #6).
   - (b) AS metadata realm'indir (MD-5) ve Domain Metadata'ya çapraz atıf yapar; (c) `authzen-configuration` Domain Metadata'dan türetilir. İkisi de Domain Metadata'nın yerine geçmez.
   - Kimlik belgesindeki bir `issuer` authority iddiası değildir.
3. **Identity plane yapılandırmasının yetkisi (MD-14).**
   - Client, redirect URI, upstream IdP bağlantısı, şablon, CIMD alan adı güven politikası ve realm config değişiklikleri realm'in **yönetişim domain'indeki** (`realms.governing_domain_id`; her realm'in tam olarak bir yönetişim domain'i vardır) domain action'larıdır. Identity plane PEP'i bunları ADP `commit` ile yetkilendirir. Realm'in kimlik Claim'lerini tüketen N domain'in her biri bunu kendi Acceptance'ıyla bildirir.
   - Ayrı bir "admin token" sınıfı yoktur.
   - Konsol çerezi yalnız gezinti ve okumayı taşır. Her meta-Exercise CT tazeliğinde AIS ister.

### 9.15A Federation: identity, foreign authority, bridging ve read federation (AP-12)

Bu bölüm AP-12'nin (§9.2) ve P31'in (§9.18) mekanizmalarını protocol karşılıklarıyla tanımlar. E19'un beşinci mekanizması (handover) §9.15'tedir.

#### 9.15A.1 Identity federation

Başka domain'lerin veya organizasyonların IdP'leri, Access için yalnız **issuer**'dır (§7.4). Identity federation (OIDC, SAML gateway, OIDF chain) actor-binding Claim'leri getirir; **authority federasyonu değildir**. Bir kullanıcının başka şirketin IdP'siyle authenticate olması ona bu domain'de hiçbir şey vermez; Grant gerekir.

#### 9.15A.2 Foreign Authority Proof (yabancı domain'in authority'sine dayanma)

Domain B'nin bir action'ı, A domain'inin bir Instance'ının A'daki authority'sine dayanacaksa (ör. A'nın "satın alma yetkilisi" olarak B'de sipariş vermek), B'nin kullandığı şey A'nın **Portable Authority Proof**'udur (§9.10) — ontology'de B'ye gelen bir **Claim** (issuer = A domain'i, foreign authority chain claim), B'de **yalnız** `foreign-authority` Acceptance'ı ile kullanılır (reserved use; use'lar birbirini ima etmez, E18).

B'nin verifier'ının yaptığı kontroller Work §21.5'in **üç kontrolüne** eşlenir, artı Access'in tazelik koşulu:

1. **Cryptographic validity:** PAP'ın A'nın Domain Metadata'sındaki projection anahtarıyla imzalı olduğu (A'da recovery kaydı varsa §9.10 recovery koşulu dahil).
2. **Issuer trust for scope:** B'de A için, PAP'ın authority class'ını kapsayan aktif bir `foreign-authority` Acceptance'ı olduğu.
3. **Semantic coverage:** İstenen intent'in PAP'ın bounds'u içinde olduğu (B'nin pin'lediği catalog/schema'ya göre; farklıysa yalnız pin'li non-broadening mapping ile — §9.13.4).
4. **Tazelik koşulu (Access'e özgü):** ValidityContract horizon/Δ/status — A'daki revoke'un B'ye ne kadar sürede ulaşacağı contract'ta açık (**UNDER DECLARED CAPABILITY**, pencere contract'ta beyanlı).

Bu kontroller geçse bile B'de **ALLOW yalnız B'nin kendi authority'si** ile mümkündür ve kullanılan Grant bir **bridging Grant**'tır:

```text
Bridging Grant { basis: B'nin yerel AnchorRoot'u (veya yerel Grant)
                 holder: ForeignAuthority(domain = A, authorityClass = C)
                 authority: CEILING (B'nin AuthoritySet'i); terms: delegability, requirements, budget, validity }
Acceptance     { issuer = A authority issuer, use = foreign-authority, classes = {C proofs} }
Exercise (B):  basis = ⟨BridgingGrant, foreign holder⟩
               proofs ⊇ { foreign authority chain Claim (PAP), foreign identity Claim (actor-binding) }
               effective = Ceiling(BridgingGrant) ∩ Map(foreign chain) ∩ Mandate(I)
```

Örnek ceiling: "A'da C sınıfı satın alma authority'si tutan herkes B'de `order.create` yapabilir, ≤ 10k / sipariş". Foreign proof `ForeignAuthority` seçicisine **yalnız** `foreign-authority` use'u ile girer; `predicate-input` veya `subject-selection` Acceptance'ıyla ingest edilmiş bir foreign authority proof hiçbir Grant'ın holder seçimine girmez → DENY (`source-not-accepted`). Foreign authority B'de **asla doğrudan authority değildir** (PI-3: dış proof `foreign-authority` Acceptance + bridging Grant olmadan authority olmaz).

#### 9.15A.3 E19'un beş mekanizması, cross-domain delegation ve budget

E19 / §7.9.11.3 beş mekanizmayı ayrı sayar; her birinin protocol karşılığı ayrıdır ve hiçbiri "generic federation" altında birleşmez:

| Mekanizma | Protocol karşılığı | Ne değildir |
|---|---|---|
| **Identity federation** | Foreign IdP / Party Claim'i, `actor-binding` Acceptance ile (§9.15A.1, §9.13) | Authority kabulü |
| **Foreign authority evidence** | Foreign PAP = yerelde Claim; yalnız `foreign-authority` use'u (§9.15A.2) | Yerel authority; predicate-input / subject-selection girdisi |
| **Local bridging Grant** | `grant.issue` ile holder = `ForeignAuthority(D_f, class)` olan rule-shaped Grant; effective = Ceiling ∩ Map(foreign chain) ∩ Mandate (§9.15A.2, §9.15A.4) | Foreign basis |
| **Cross-domain delegation** | Yerel bir holder'ın, foreign bir Party'yi (`actor-binding` Acceptance ile tanınmış) holder yapan **yerel extensional Grant**'ı: mevcut `grant.issue` + `actor-binding` Acceptance; yeni nesne yok (vendor erişimi ve ortaklıklarda varsayılan ve daha güvenli yol). Budget draw'u Grant'ı veren domain'in (home) lineage'ındadır | Foreign domain'e authority yazmak |
| **Authority-provider handover** | Kooperatif handover veya forced recovery (§9.15, AP-13) | Federation (tek domain) |

- **Domain'ler arası authority yazma yoktur:** hiçbir domain başka bir domain'in Authority Record'una kayıt yazamaz; her mekanizma yerel bir Exercise veya yerel bir Acceptance kullanımıdır. Revocation zinciri domain sınırında kopmaz: A'da revoke → PAP status'u → B'de tazelik koşulu başarısız; B kendi bridging Grant'ını veya Acceptance'ını her an revoke edebilir (yerelde kesin).
- **Home budget home'da draw edilir** (INV-21): home domain lineage'ına dayanan bir exercise'ın budget draw'u home'un kaydıdır. Target domain'de home authority'sine dayanan **consumption-bearing** bir action için PAP, home'un `projection.issue` ile önceden draw ettiği `offline_slice`'ı **zorunlu** taşır (toplam tüketim ≤ slice); slice yoksa home'da online exercise gerekir (home ADP'de `commit`; draw home'da; target'a home'un o exact intent için verdiği receipt / exact-intent projection'ı sunulur). Slice'sız bir PAP'ın Map(foreign chain)'ı consumption-bearing action'ı kapsamaz → target'ta yerel kararla ALLOW yok (§9.9.1 ve §9.10'daki "yerelde doğrulanamayan budget bounds'a giremez" kuralının cross-domain karşılığı).
- **Target'ın kendi BudgetTerm'i** (bridging Grant'ın terms'i) **ek bir daraltmadır**, home lineage budget'ının yerine geçmez. Lock, settlement ve reconciliation Pay/Executor/domain'dedir.

#### 9.15A.4 Bridging Grant ve yerel domain

Bir tesis, robot filosu veya ayrık ağ kendi AuthorityDomain'i olarak çalışabilir. Bu bir **deployment pattern**'idir, ValidityContract'ın connectivity profile class'ı değildir (§9.1). Ana domain'le ilişki: ana domain'in bir Instance'ı (yerel domain'in operatörü) ana domain'de bir Grant'a sahiptir; yerel domain'in root'u ana domain için bir `foreign-authority` Acceptance'ı kurar ve holder'ı `ForeignAuthority(ana domain, class)` olan bir **bridging Grant** verir (effective = Ceiling ∩ Map(foreign chain) ∩ Mandate). Ana domain lineage'ına dayanan consumption-bearing kullanım, ana domain'in önceden draw ettiği slice ile veya ana domain'de online exercise ile olur (§9.15A.3). Yeni nesne yok; Grant + PAP + `foreign-authority` Acceptance + bridging Grant.

#### 9.15A.5 Read federation

Başka domain'in kayıtlarını görmek (ör. denetçi, partner) yeni bir mekanizma değildir: okuma da bir action'dır (`access.read` / `access.audit.export` core action'ları; §9.13.7) ve aynı Exercise contract'ından geçer (PI-4). Dış okuyucu foreign Party'ye yerel Grant (cross-domain delegation, §9.15A.3) veya bridging Grant (§9.15A.2) ile yetkilendirilir; disclosure scope (§5.4) uygulanır.

**Identity plane karşılıkları.**

- Identity federation (9.15A.1) identity plane'de OIDC/SAML/OIDF/WS-Fed ile uygulanır; ayrıntısı §10'dadır. Sonucu her zaman `actor-binding` Claim'idir.
- Cross-domain agent zincirleri ve ID-JAG'ın alanlar arası kullanımı §11.11'dedir. ID-JAG bir identity federation taşıyıcısıdır, foreign authority evidence değildir.
- Pairwise PartyRef (MD-10) foreign Party'ye yerel Grant verilirken korunur: yerel Grant foreign Party'nin yerel takma adına yazılır. Korelasyon yalnız açık IdentityBinding ile kurulur.

### 9.16 Audit export, checkpoints ve semantic event'ler

**Record Export Package (AP-14).**

Domain'in Authority Record'unun (Genesis + Exercise/DecisionRecord + ingest edilmiş Claim'ler + meta-Exercise'lar) **kendi kendine doğrulanabilir** dışa aktarımı. Semantik zorunlu alanlar:

| Alan | Semantik |
|---|---|
| `domain` | DomainID + genesis |
| `range` | Kapsanan kayıt aralığı (record position'ları) |
| `records` | Kayıtlar (disclosure scope'a göre tam veya redacted; redacted kayıtlar digest'leriyle). Her `commit`/`continue` kaydı actor'ün **Actor Intent Statement**'ını içerir (redacted export'ta digest'i; replay coverage'da beyan edilir) |
| `checkpoints` | Aralıktaki checkpoint'ler |
| `versions` | Kayıtların değerlendirildiği core spec / meta-schema / schema / profile sürümleri ve digest'leri |
| `schemas` | Referans verilen SPP'lerin kendileri veya digest'leri |
| `claims` | Karar girdisi olan Claim'ler (veya minimize edilmiş digest'leri; E26) |
| `export_exercise` | Export'u yapan `access.audit.export` ExerciseID'si |

**Doğrulama Suiss olmadan:** Açık core spec + herhangi bir conformant evaluator (open reference evaluator dahil) export'tan record-fold ile checkpoint köklerini yeniden üretir ve kararları yeniden değerlendirerek doğrular (INV-27, PI-6); fark kanıttır, çıkış kapısı değildir (G32). Redacted kayıtlar replay'i yalnız digest seviyesinde destekler; bu açıkça beyan edilir ("replay coverage").

**Checkpoints.**

Checkpoint, belirli bir record pozisyonundaki domain state'inin commitment'ıdır (Authority Record hash chain/Merkle kökü + basis pozisyonu + sürüm vektörü). Ontology: `checkpoint` class bir **Claim**; issuer = provider, Domain Metadata'da domain'e bağlı anahtarıyla imzalar (custody attestation, authority değil). Witness co-sign ayrı bir Claim'dir. **Heartbeat:** cadence checkpoint'i değişiklik olmasa da üretilir, witness'lara gönderilir ve log'a `checkpoint` Claim kaydı olarak ingest edilir (handover freeze'i hariç); böylece sessiz domain'de de witness cosign tazelenir (TI-RT5) ve status list `iat`'i tazelenir (T16).

- Domain checkpoint'leri **provider dışına** kopyalayabilir (domain'in kendi depolaması, üçüncü taraf witness/transparency log). Witness seçimi domain'indir; Suiss zorunlu witness değildir (PI-13). Transparency log formatı **informative** (ör. C2SP / SCITT tipi yaklaşımlar; durumu doğrulanmadı, Technical).
- Equivocation (provider'ın aynı pozisyon için farklı izleyicilere iki farklı checkpoint göstermesi, geçmişi yeniden yazması): tespiti yalnız domain'in **declared witness / transparency log (gossip) capability**'si altındadır → **UDC**; witness/gossip yoksa hiçbir taraf iki checkpoint'i birlikte görmeyebilir → **NG**. Equivocation'ın fiziksel önlenmesi **NG**'dır (fencing/witness mekaniği §16).
- Actor attribution: provider veya PEP, actor adına bir Exercise Request üretemez; çünkü Record Export'ta korunan her `commit`/`continue` kaydı, actor Instance'ının KeyBinding'iyle intent digest + nonce + audience'a bağlı **Actor Intent Statement**'ı taşır → **BS** (KeyBinding sızmadıkça; statement'ın Record Export'ta korunması şartıyla).
- Provider'ın değerlendirme doğruluğu: provider yanlış bir ALLOW/DENY üretebilir; bu **önlenmez** (**NG**); export + open reference evaluator ile replay erişimi olan taraf için tespit edilebilir (**UDC**; INV-27).

**Access semantic event'leri (SSF EXTEND).**

Access, SSF stream'i üzerinden SET olarak aşağıdaki event türlerini yayınlar (Access namespace'inde; CAEP'e karşılığı olanlar CAEP event'iyle **birlikte** veya onun yerine profile'a göre):

| Event | Kaynak | CAEP karşılığı (yaklaşık) |
|---|---|---|
| `authority-revoked` | `grant.revoke` / `mandate.revoke` | `session-revoked` değil; token-claims-change'e benzemez — yeni tür |
| `authority-narrowed` | `grant.amend` (daraltma), RestrictionPolicy değişimi | `token-claims-change` (yaklaşık) |
| `authority-expired` | Validity sonu (bilgi amaçlı; expire zaten deterministik) | — |
| `mandate-ended` | Mandate end/revoke | — |
| `instance-terminated` | `instance.terminate` / recover | `session-revoked` (yaklaşık) |
| `acceptance-changed` | `acceptance.amend` / revoke | — |
| `budget-exhausted` | BudgetTerm sınırı | — |
| `revalidation-required` | ValidityContract koşulu, policy değişimi | `assurance-level-change` (yaklaşık) |
| `projection-invalidated` | Bir projection'ın (token/PAP) bounds'unun artık geçerli olmadığı | — |
| `domain-handover` / `domain-recovered` | `domain.handover` / `domain.recover` | — |

Her event'in semantik zorunlu alanları: event id (domain başına anahtarlı HMAC; subject hash'i değildir, TI-RT10), domain, kaynak ExerciseID (veya Claim id'si), subject (Grant/Mandate/Instance/projection ref'i — receiver'ın anlayacağı kadarı), etkili zaman, basis referansı (receiver'ın disclosure scope'una göre açık veya opaque token).

**Receiver kuralları:**
1. **Event authority değildir ve genişletmez** (PI-9). Bir event yalnız "yeniden sor" sinyalidir; receiver kesin durumu ADP'ye (veya status kaynağına) re-query ile öğrenir.
2. **Sıra varsayılmaz;** karşılaştırma ADP re-query ile yapılır.
3. **Kayıp event** contract'ın beyan ettiği pencereyi aşan bir genişlemeye yol açamaz.
4. Event'ler disclosure scope'a tabidir (receiver'ın görmeye yetkili olmadığı Grant içerikleri event'te yer almaz).

#### 9.16.1 SIEM projection

SIEM/log sistemlerine akış, Record Export'un (veya event'lerin) **salt-okunur projection**'ıdır; SIEM'de görünen hiçbir şey authority kaynağı değildir. Alan eşlemesi (OCSF vb.) informative; Technical backlog.

- SIEM ayrı bir ürün katmanıdır (plane ataması MD-13). Access onun authority kısmına karar verir: SIEM'e akış bir `access.audit.export` Exercise'ı veya bir SSF stream aboneliğidir. Access olay ve sinyal üretir.
- Alan eşlemesi (OCSF vb.) §17'dedir.

#### 9.16.2 SSF/CAEP: identity plane vericisi ve alıcısı (MD-13)

1. **Plane ataması.**
   - SSF/CAEP vericisi ve alıcısı identity plane'in capability'sidir (MD-13). Gönderim ve alım tam uygulanır.
   - SSF 1.0, CAEP 1.0 ve RISC 1.0 Final metinleri esas alınır. Final yayın tarihi **doğrulanmadı** (MD-18).
   - CAEP 1.0 Final sekiz olay tipi tanımlar. Tuzak: eski URL hâlâ 2021 draft-02'yi döndürür; Final sürüm `openid-caep-1_0-final.html` adresindedir.
2. **Garanti sınıfı.**
   - Sinyal **hızlandırıcıdır**. Güvenlik ValidityContract / expiry / checkpoint'e dayanır (INV-24, L18).
   - Teslim **NOT GUARANTEED**'dır ("best effort"). Sinyali tüketen RS'nin penceresi horizon'la sınırlıdır (§9.11.2).
3. **Giden (outbound).** Identity plane iki tür olay yayınlar:
   - (a) Kendi oturum ve kimlik olayları CAEP/RISC olaylarıdır. Örnek: oturum iptali (`session_epoch` artışı), kimlik bilgisi değişimi, hesap ele geçirme şüphesi.
   - (b) Authority plane'in Access semantic event'leri (§9.16 tablo).
   - CAEP'e karşılığı olanlar (yaklaşık eşlemeler tablodadır) profile göre CAEP olayıyla birlikte veya onun yerine gönderilir.
4. **Gelen (inbound).** Upstream IdP'den veya kurumsal kaynaktan gelen CAEP/RISC SET'i bir **Claim**'dir (SET taşıyıcısı, §9.13 tablo).
   - Etki kanalı yalnız şunlardır:
     - (a) yeniden sor: ilgili projection'lar için yeniden değerlendirme tetiklenir (`revalidation-required` iç olayı);
     - (b) Acceptance'lı ise restriction / actor-binding girdisi: ör. `credential-change` → `identity-binding` episode kapanışı.
   - Gelen sinyal hiçbir zaman genişletmez (PI-9). Gelen `session-revoked` bir Grant revocation'ı değildir. Etkisi actor-binding'in düşmesi ve `session_epoch` artışıdır.
   - Risk sinyali yalnız daraltır (CI-2). Risk tabanlı step-up identity plane'dedir (MD-13). Kararı yine ADP verir; risk motoru arızası ALLOW'a dönmez (MD-8).
5. **Ajana özgü olay boşluğu.**
   - CAEP 1.0'da ajana özgü olay tipi yoktur ve bu açık bir boşluktur.
   - Access event'leri bu boşluğu Access namespace'inde kapatır:
     - `instance-terminated` (ajan oturumu / Instance sonu);
     - `mandate-ended`;
     - `authority-narrowed`;
     - `projection-invalidated` (ajan token ailesi).
   - Ek bir olay gerekmez, çünkü ajan = Instance'tır (§11.9).
   - Bu türlerin OpenID SSF WG'ye önerilmesi §9.17.5 backlog'undadır.
6. **Toplu / kitlesel iptal (açık problem).**
   - Standart yoktur. Access'te bir Party'nin veya operatörün bütün ajan Instance'larının kapatılması `instance.terminate` meta-Exercise'larının bir kümesidir; her biri attributable'dır.
   - `POST /agents/{id}/revoke-all` uç noktası bu kümenin kolaylık yüzeyidir. Ayrı yazma yolu değildir (R1, PI-4).
   - Global token revocation taslağının (`draft-parecki-oauth-global-token-revocation-06`) durumu çelişkilidir: **WATCH**.

#### 9.16.3 Karar log'u ve denetim

- Her `commit`/`continue` DecisionRecord'u AIS'i taşır (§9.16 "Actor attribution").
- Advisory, search ve explain çağrıları kaydedilmez (C30). Operatör gözlemlenebilirliği için örneklenmiş iz tutulabilir. Bu iz disclosure scope'a tabidir ve authority kaydı değildir (§9.7.1).
- Identity plane olaylarında denetim olayı iş değişikliğiyle atomik minimal kayıt olarak yazılır; Merkle, imza ve egress arka planda yapılır. Authority plane kaydı zaten Exercise'ın kendisidir.
- Denetim log'unun veri ve operasyon tarafı §17'dedir.

### 9.17 Governance, versioning, open / proprietary sınırı ve custom protocol gerekçesi

**Governance ilkeleri.**

1. **Açık ve vendor-neutral:** Core Semantic Spec, profiller ve conformance suite'in değişikliği açık bir süreçle; Suiss tek başına normatif değişiklik yapamaz. Governing body'nin kimliği D3'tür (Adem kararı; recommended default: neutral vakıf / SDO); protocol'ün geçerliliği buna bağlı değildir çünkü domain sürüm benimsemesi yereldir.
2. **Genişleme yerel, anlam değişikliği merkezi:** Namespaced her şey governance'sız eklenir; kapalı kümeler (outcome, blocker class, closed types, core Claim class'ları, profile class'ları, Acceptance use'ları) yalnız governance ile değişir.
3. **Hiçbir extension authority genişletemez:** Bir extension'ın anlaşılmaması red sebebidir (must-understand, PI-12), varsayılan genişleme değil.
4. **Work ile ortak katmanlar** (Party Identity Regime, signed record ailesi, Approval Surface conformance, deterministic encoding) ortak governance altındadır; Access tek taraflı değiştiremez (PI-18).

**Compatibility ve versioning kuralları.**

1. **AuthorityStateBasis sürümleri cite eder:** Her DecisionRecord core spec, meta-schema, schema digest'leri ve profile sürümünü kaydeder; replay aynı sürümlerle yapılır (INV-27). Sürüm yükseltme geçmiş kararları yeniden yorumlamaz.
2. **Benimsenmemiş sürüm hiçbir şey değiştirmez:** Yeni core spec sürümü domain explicit meta-Exercise ile benimsemedikçe o domain'de etkisizdir.
3. **Must-understand:** Her projection/receipt/PAP/ValidityContract, verifier'ın anlaması zorunlu özellikleri listeler; anlamayan verifier reddeder (fail closed). **Issuer, verifier profile'ının kapsamadığı bir artefakt issue etmez**.
4. **Downgrade koruması:** Sürüm ve profile kimliği imzalı içeriğin parçasıdır; Domain Metadata'daki **domain minimum sürümü**nün altındaki istek/projection kabul edilmez. Minimum'u **düşürmek genişletme sınıfı bir meta-Exercise'tır** (reserved + genişletme requirement'ları), yükseltmek daraltmadır.
5. **Geriye dönük uyumluluk tek yönlü:** Yeni sürüm eski sürümle üretilmiş kayıtları doğrulayabilmelidir; eski verifier yeni sürüm artefaktını must-understand ile reddeder, yanlış kabul etmez.
6. **Standart sürüm değişimi** (ör. AuthZEN'in sonraki sürümü, OAuth 2.1'in RFC olması) yalnız profile sürümünü değiştirir; Access semantiği değişmez (PI-2).

**Üç katman.**

| Katman | İçerik | Sahiplik ilkesi |
|---|---|---|
| **Open specification** | Core Semantic Spec, meta-schema'lar, interop profile'ları (ADP + Actor Intent Statement, OAuth/RAR, SSF event'leri, PAP/ValidityContract, AAS, SPP, Record Export/checkpoint/handover, regime eşlemesi), conformance profile'ları (Provider, Decision PEP, Offline Verifier, Approval Surface, Claim Issuer, Schema Publisher, Coordinator, Event Receiver) | Açık; vendor-neutral governance (D3); lisans biçimi D4 |
| **Open reference** | Reference evaluator (replay için), reference verifier (PAP/receipt/checkpoint), conformance test suite, test vektörleri | Açık; Suiss olmadan çalışır; lisans biçimi D4 |
| **Suiss ticari hizmet** | Suiss-hosted Access provider operasyonu, Identity plane'in hosted operasyonu, SLA, destek, yönetilen onboarding, ayrılmış altyapı. Kod (Experience yüzeyleri, analitik, öneri motorları, policy authoring araçları dahil) açık kaynaktır (D4) | Ticari olan hizmettir, kod değil; **hiçbiri protocol'de ayrıcalıklı bir yol değildir** |

Suiss ticari hizmet katmanı B3'te sayılan yüzeyleri (verification, export / replay, handover / recovery, change-impact preview, audit-scope explain, honest status, güvenlik POLICY DEFAULT'ları, açık SDK'lar) hiçbir zaman içermez. Ücretli kısım konfor ve otomasyondur (B4).

**Anti-hostage kuralları.**

1. **DomainID provider'dan bağımsızdır** (genesis digest'i).
2. **Tam export her zaman mümkündür**, domain'in kendi authority'si ile (`access.audit.export`); Suiss bunu ticari koşula bağlayamaz (export bir protocol yükümlülüğüdür, Provider conformance'ın parçası).
3. **Suiss registry veya trust anchor değildir:** Domain'lerin, issuer'ların, schema publisher'ların keşfi Suiss'e bağımlı değildir; Suiss bir OIDF trust anchor'ı işletebilir ama hiçbir domain onu kabul etmek zorunda değildir.
4. **Handover ve forced recovery protocol'dedir** (§9.15); recovery yolu (rootTerms'in recovery entry'si) Suiss-hosted domain'lerde varsayılan olarak beyan edilir (PI-15). Recovery sonrası eski provider anahtarlı artefakt yalnız exact-content inclusion proof'uyla kabul edilir; kayıpsızlık ve eski provider'ın durması koşulsuz garanti edilmez, yalnız declared witness / replica / fencing capability altında korunur.
5. **Conformance ≠ endorsement:** Conformance test'ini geçmek Suiss onayı veya Suiss ticari ilişkisi gerektirmez.

**Custom protocol gerekçesi.**

Kural: Custom protocol yalnız (a) mevcut standart denenip (b) Access semantiğini sessiz anlam kaybı olmadan taşıyamadığı gösterildiğinde ve (c) mümkün olan en dar biçimde (önce PROFILE, sonra EXTEND, en son yeni içerik) gerekçelendirilir. Yeni içerik bile mümkünse standart bir **container** içinde taşınır.

| # | Custom öğe | Denenen standart(lar) | Neden yetmez | Biçim |
|---|---|---|---|---|
| 1 | **Access Core Semantic Spec** (değerlendirme kuralları, outcome/blocker, closed types, meta-schema'lar, record semantiği) | XACML/ALFA, Cedar, OPA/Rego, Zanzibar/ReBAC, AuthZEN | Bunlar policy dili veya karar transport'udur; Grant/Mandate/Acceptance/Anchor lineage'ı, capacity, contribution, AuthorityStateBasis ve replay semantiği yoktur (§4) | **Yeni içerik** (semantik); transport'u AuthZEN EXTEND |
| 2 | **Approval Act Statement** | CIBA, WebAuthn, SPC, AP2 mandate, PSD2 SCA dynamic linking | Hiçbiri "tek user act → iki owner'ın bağımsız doğruladığı contribution + declaration" ve render/material field bağlamasını tanımlamaz; WebAuthn/SPC yalnız assertion'ı taşır | **Yeni içerik** WebAuthn/SPC challenge'ında (ADOPT); Access'te her iki act türünde Exercise'ın proof'u, IntentEnvelope değil |
| 3 | **Portable Authority Proof içeriği + ValidityContract + Offline Exercise Report** | OAuth JWT access token + RAR, VC DM 2.0, SD-JWT, Biscuit/UCAN/ZCAP, Token Status List | Container olarak JWT/SD-JWT yeterli; ama bounds-lineage commitment, capacity, offline slice, horizon/Δ, verifier profile ve report chain'i hiçbirinde yok; Biscuit/UCAN zincirli attenuation Access'in revocation ve Acceptance semantiğiyle çelişir (REJECT) | **Yeni içerik** standart container'da (JWT/SD-JWT + RAR `kind=bounds`; status = Token Status List ADOPT) |
| 4 | **Schema Publication Package + compatibility declaration** | JSON Schema, OpenAPI, RAR type registry, MCP tool schema | Bunlar biçim tanımlar; authority-relevant/opaque ayrımı, closed type eşlemesi, reserved bayrağı, consumption/effect class, digest pin'li compatibility algebra'sı yoktur | **Yeni içerik**; parametre biçim tanımı için JSON Schema benzeri bir alt dil **informative** (Technical) |
| 5 | **Authority Record Exchange, checkpoints, provider handover/forced recovery** | SCIM, OIDF, transparency log yaklaşımları, Work record exchange | Hiçbir standart bir authority provider'ının kayıtlarının record-fold ile doğrulanabilir taşınmasını ve DomainID'yi koruyan provider değişimini tanımlamaz | **Yeni içerik**; imzalı-kayıt/checkpoint ailesi Work Protocol ile **ortak** (ADOPT family). Handover/recovery'nin semantiği yeni değildir: `domain.handover` / `domain.recover` AuthorityDomain geçişinin adlarıdır; yeni olan yalnız taşıma ve recovery sonrası inclusion proof kuralıdır |
| 6 | **Actor Intent Statement** (actor proof) | AuthZEN `subject`, DPoP (RFC 9449), mTLS (RFC 8705), WIMSE WPT, HTTP Message Signatures | AuthZEN `subject` PEP-asserted'dır; DPoP/WPT sunuldukları HTTP isteğini (`htm`/`htu`/`ath`) imzalar, Access'in intent digest'ini, nonce'unu ve PEP audience'ını değil; mTLS hiçbir payload'ı imzalamaz ve PEP → Access bağlantısında yalnız PEP'i kanıtlar (E17 ihlali riski); transport PoP kayda geçmez ve başka intent'e taşınabilir | **Yeni içerik, standart kapta** (JWS/COSE ailesi; actor doğrudan çağırıyorsa HTTP Message Signatures); ontology'de mevcut Exercise/IntentEnvelope + Instance KeyBinding'in proof'u, yeni primitive değil |

**Custom olmayanlar (açıkça):** karar transport'u (AuthZEN), token issuance/exchange ve holder binding (OAuth/RFC 8693/PAR/JAR/DPoP), RAR, signaling (SSF/CAEP), status (Token Status List / Bitstring), kimlik (OIDC/SCIM/SPIFFE/VC/OID4VP), assertion (WebAuthn/SPC), agent transport (MCP/A2A), domain discovery (`.well-known`, OIDF). Bunların hepsinde Access yalnız PROFILE veya EXTEND yapar.

#### 9.17.1 Neyi kim genişletebilir

| Extension noktası | Kim | Governance gerekir mi | Kural |
|---|---|---|---|
| Action namespace'leri / SPP | Herhangi bir publisher | Hayır | Domain Acceptance ile pin'ler (§9.13) |
| Domain-yerel action'lar, reserved işaretleri | Domain | Hayır | Yalnız daha sıkı |
| Claim class'ları (namespaced) | Herhangi bir issuer | Hayır | Use'a Acceptance ile girer; core class'ların (`party.*`, `authentication`, `authenticator-binding`, `checkpoint`, `offline.exercise-report`, `authority-state.ack`, `verifier.profile`, `schema.publication`) anlamını değiştiremez |
| Core Claim class'ları | Protocol governance | **Evet** | Work ile paylaşılanlar (regime) ortak governance |
| Contribution sınıfları (`contribute:<ns>/<name>`) | Publisher | Hayır | Grant ile yetkilendirilir; core `approve`/`co-sign`/`witness`/`disclose`/`declassify` governance'ta |
| Connectivity profile parametre değerleri (Δ, N, horizon) | Domain | Hayır | Mevcut class + variant içinde |
| Yeni connectivity profile variant'ı | Protocol governance | **Evet** | Frozen dört class'tan (online / intermittent / offline / long-running) birine eşlenmeli; guarantee sınıfı ve verifier yükümlülüğü tanımlanmadan eklenemez |
| Yeni connectivity profile class'ı | Protocol governance | **Evet** | Dört class L16'da frozen'dır; yeni class aynı zamanda frozen modelin değişikliğidir |
| Closed type system (E12) yeni tip | Protocol governance | **Evet** | **Decidability kanıtı** (INV-8) ve must-understand bayrağıyla |
| Reason subcode'ları | Herkes (namespaced) | Hayır | Bilinmeyen subcode → üst sınıf (P15); 10 kapalı class governance'ta |
| Remediation kodları, outcome'lar | Protocol governance | **Evet** | Outcome kümesi kapalıdır (dördüncü outcome yok) |
| AuthZEN / RAR / SSF extension üyeleri | Protocol governance (Access profile'ı) | **Evet** | Upstream'e önerilebilir (§9.17.5) |

#### 9.17.2 Ayrı sürüm izleri

| İz | Ne | Kim yayınlar | Domain'de nasıl yürürlüğe girer |
|---|---|---|---|
| Core Semantic Spec | Değerlendirme kuralları, outcome/blocker kümeleri, closed types | Protocol governance | `anchor.amend(rootTerms)` meta-Exercise (reserved, quorum tipik) |
| Core meta-schema | Meta-action SPP'si (§9.13.7) | Protocol governance | Aynı |
| Interop profile'ları | ADP (AuthZEN), OAuth/RAR, SSF event'leri, PAP, regime eşlemesi | Protocol governance | Domain Metadata'da desteklenen profile sürümleri; her mesaj kendi profile sürümünü taşır |
| Action schema'ları | Publisher SPP'leri | Publisher | `schema-definition` Acceptance pin'i |
| Connectivity profile'ları | Profile class + variant + parametre | Governance (class, variant) / domain (parametre) | ValidityContract'ta |

#### 9.17.3 Healthy defensibility (framework §10.2)

Suiss'in savunulabilirliği **daha iyi implementasyon, deneyim, güvenilirlik ve ekosistem** üzerinedir; kullanıcı verisini, DomainID'yi, kayıtları veya trust'ı rehin tutmak üzerine değil.

#### 9.17.4 No hidden first-party dependency

Her protocol yolu için kontrol: "Suiss (veya herhangi bir tek vendor) ortadan kalksa bu yol çalışır mı?"

| Yol | Suiss'e bağımlı mı | Neden değil |
|---|---|---|
| Karar (ADP) | Hayır | Herhangi bir conformant provider; Domain Metadata provider binding'i |
| Projection doğrulama | Hayır | Anahtarlar Domain Metadata'da, kökü genesis |
| Claim / identity | Hayır | Her issuer Acceptance ile; Suiss Identity plane opsiyonel |
| Schema | Hayır | Publisher namespace'i; core meta-schema governance'tan |
| Approval | Hayır | Herhangi bir conformant Approval Surface; AAS + assertion bağımsız doğrulanır |
| Work entegrasyonu | Hayır | Work, herhangi bir conformant Access provider'ın receipt/PAP'ını doğrular (§9.14.1) |
| Audit / replay | Hayır | Open reference evaluator + export |
| Provider değişimi | Hayır | Cooperative handover veya forced recovery |
| Governance | Hayır (Suiss tek başına değiştiremez) | §9.17 governance ilkeleri; governing body D3 |

Kalan bağımlılık: **custodial anahtar** senaryosunda (Suiss Identity plane anahtarı tutuyorsa) custodian riski — bu gizli değil **beyan edilmiş** bir bağımlılıktır ve Security'ye devredilir (§21 OQ1).

Access tam bir IdP'dir (MD-13); "Suiss Identity plane opsiyonel" satırı yine geçerlidir: bir domain identity plane'i hiç kullanmadan external IdP ile çalışabilir (§9.13.2).

#### 9.17.5 Cross-Product / Standards Backlog

| Madde | Hedef | Not |
|---|---|---|
| Access SSF event türlerinin OpenID SSF WG'ye önerilmesi | Upstream (OIDF) | §9.16; Access namespace'inde başlar |
| AuthZEN Access Decision Profile'ın OIDF AuthZEN WG'ye profile olarak sunulması | Upstream | §9.5 |
| RAR `type` / Access üyeleri için kayıt ihtiyacı | IETF OAuth / IANA | §9.13.5 |
| Party Identity Regime spesifikasyonu (ortak) | Work + Access governance | §9.13; Access yalnız tüketir |
| Work errata: Approval Declaration'ın AAS'yi ve ContributionExerciseID'yi taşıması | Work | §9.14.1 |
| Pay: AP2 / PSD2 SCA artefaktlarının AAS ve projection'a eşlenmesi | Pay | Access semantiği değil (R-REJECT) |
| Executor continuation hook'ları; A2A extension'ı (Access üyeleri) | Executor / upstream A2A | §9.9, §11.19 |
| SIEM alan eşlemesi (OCSF vb.) | Technical | §9.16.1 |
| Reference evaluator, verifier, conformance suite, SDK'lar | Technical (Stage 8) | §9.17 |
| Txn-Tokens / WIMSE / attestation RFC olunca PROFILE güncellemesi | Profile sürümü | Şimdilik informative |

Ek backlog maddeleri:

| Madde | Hedef | Not |
|---|---|---|
| AuthZEN'de tutarlılık belirteci alanı eksikliği (`context.consistency_token`) | Upstream (OIDF AuthZEN WG) | §9.5.2 kural 1; boşluk çalışma grubuna bildirilmelidir |
| REQUIRE_ACTION ↔ AARP eşlemesi; AARP Final olursa PROFILE | Upstream (OIDF AuthZEN WG) | §9.9.5 |
| Ajana özgü CAEP olay tipleri (Access `instance-terminated`, `mandate-ended` vb. üzerinden) | Upstream (OIDF SSF WG) | §9.16.2 kural 5 |
| MCP: REQUIRE_ACTION verisinin SEP-2643 / SEP-2848'e eşlenmesi; `subscriptions/listen` için token süresi davranışı; `server/discover` yetkilendirme muafiyeti netliği | Upstream (MCP SEP süreci) | §11.5, §11.8 |
| `act` profili ve delegasyon zinciri: Access'in "iç içe `act` yalnız lineage'dan üretilir" kuralının actor-profile taslaklarına girdi olarak sunulması | Upstream (IETF OAuth WG, complex delegation) | §9.9.4, §11.10 |
| Capacity → `sub`/`act`/`may_act` eşleme vektörleri ve REQUIRE_ACTION yüzey eşleme vektörleri | Conformance (L3) | §9.9.4–9.9.5 |
| MCP conformance çatısının (`modelcontextprotocol/conformance`, `auth` süiti) Access CI'ına bağlanması | §14 test stratejisi | §11.8 |

### 9.18 Frozen protocol decisions (P1–P34)

- **P1** Access Protocol açık, vendor-neutral bir spesifikasyondur: L0 Core Semantic Spec, L1 Interop Profiles, L2 Access-native parts, L3 Conformance; implementasyon kapsam dışıdır
- **P2** Suiss Access protocol'ün bir implementasyonudur; conformance profile'ları Provider, Decision PEP, Offline Verifier, Approval Surface, Claim Issuer, Schema Publisher, Coordinator, Event Receiver'dır (L3 ile aynı liste); conformance ≠ endorsement
- **P3** DomainID genesis'ten türetilir; provider binding Anchor alanı değil, AuthorityDomain'in Genesis'e bağlı değeridir ve yalnız domain-scope `domain.handover` / `domain.recover` meta-Exercise'ıyla (AuthorityDomain'in provider geçişleri ve aynı provider içindeki binding değişimi — OP-60 self-handover profili; bu profilde eski anahtarın statüsü CR-45 semantiğine tabidir, §9.10 predicate tablosu) değişir; Domain Metadata imza anahtarı rootTerms'te değil bu binding'dedir; Domain Metadata bir PROJECTION'dır (ayrı bir Claim class'ı değildir) ve `.well-known` (ADOPT) ve/veya OIDF entity statement (PROFILE) ile keşfedilir.
- **P4** Cooperative handover (`domain.handover`: eski + yeni provider + domain meta-anchor root katkısı) ve forced recovery (`domain.recover`) protocol'ün parçasıdır. Forced recovery root'un `domain.recover` Exercise'ıdır (basis = AnchorRoot(meta-anchor), requirement = rootTerms'in Genesis'te beyan edilmiş recovery entry'si; yeni basis türü yok); cite ettiği checkpoint N'ye (SEC21 tanımı; değerlendirici R*'ı kendisi sorgular, N < R* DENY; replica yok, sorgulanamıyor veya R* < witness en yüksek ise REQUIRE_ACTION, N = R* ve (N, witness en yüksek] beyanlı kayıp suffix — SEC22) göre keser ve kayıp revocation'ları yeniden yapar. Devralan provider state'i record-fold ile kurar (TI-RT1). Recovery sonrası eski provider anahtarlı artefakt yalnız exact içeriğinin N'de commit edildiğini kanıtlayan inclusion proof'uyla kabul edilir (artefaktın kendi basis_ref / projection_exercise / zamanı ve işaret ettiği kaydın varlığı yetmez; PAP, receipt, token için aynı; aksi fail closed); handover sonrası eski anahtarlar `superseded-at C_{h+1}`'dir. Equivocation tespiti yalnız declared witness capability altındadır.
- **P5** Standart kararları §9.4 tablosudur (ADOPT/PROFILE/EXTEND/REJECT) ve S-1…S-7 kuralları bağlayıcıdır.
- **P6** Karar protocol'ü AuthZEN üzerinde Access Decision Profile'dır (PROFILE + EXTEND); yeni bir karar transport'u tanımlanmaz
- **P7** Exercise Request'in semantik zorunlu alanları ve commit / continue / check modları §9.5'teki gibidir; idempotency nonce ile; continue yalnız ALLOW ile doğmuş bir Exercise üzerindedir, REQUIRE_ACTION sonrası aynı nonce ile yeniden commit edilir.
- **P8** Eksik/bozuk commit isteği protocol hatasıdır: değerlendirme, kayıt, nonce tüketimi ve Exercise yoktur
- **P9** Subject Actor Intent Statement'tan (message-level, actor-imzalı; JWS/COSE kabında context üyesi) türetilir; PEP ≠ actor; PEP'in transport kimliği actor olmaz; statement'sız istek Anonymous olarak değerlendirilir
- **P10** Response: fail-closed boolean + üç outcome + advisory + blockers + unmet RequirementTerm projeksiyonu + remediation
- **P11** Meta-action'lar ve okuma/export aynı Exercise contract'ından geçer
- **P12** Batch bağımsız öğelerdir; atomiklik yok; short-circuit yalnız check'te
- **P13** Decision Receipt imzalı bir karar kanıtıdır, credential değildir
- **P14** Blocker = kapalı 10 class + namespaced subcode + position + resolver class + 6 remediation kodu + wait_until. Recovery ve budget güvenliği için yeni üst-düzey sınıf yoktur; yalnız subcode vardır: `nonce-closed/pre-recovery` ve `budget-exhausted/release-exceeds-draw`.
- **P15** Bilinmeyen subcode üst class olarak yorumlanır; bilinmeyen class yoktur (kapalı küme)
- **P16** Açıklama derinliği disclosure scope'tur (requester / viewer / audit); viewer-scoped explain relative_to_viewer döner
- **P17** Projection türleri: receipt, exact-intent token, bounds token, Portable Authority Proof, continuation contract; OAuth binding §9.9 tablosundadır (refresh = yeni karar).
- **P18** PAP'ın semantik zorunlu alanları ve verifier'ın 7 adımlı kuralı §9.10'daki gibidir. Kural recovery ve handover koşulunu içerir: `superseded-at` eski provider anahtarlı artefakt yalnız exact içeriğinin (digest'i veya authority-relevant alanları) lineage'ı değiştiren kaydın cite ettiği checkpoint'te (`N_cited`; recovery'de N, handover'da C_k → C_{h+1}) commit edilmiş kayıtla eşleştiğini kanıtlayan inclusion proof'uyla kabul edilir; ExerciseID'nin dahil olması yetmez; receipt için de geçerlidir. Domain Metadata tazeliği bağımsız witness cosign'ıyla ölçülür (TI-RT5); kendi `iat`'i tazelik kanıtı değildir.
- **P19** Claim ingest taşıyıcı-bağımsız alan kümesiyle yapılır; admit / quarantine / reasoned reject; gelecekten gelen Claim kullanılamaz
- **P20** Access, Party Identity Regime'den key-event, designation, authenticator-binding ve recovery Claim class'larını tüketir; hiçbiri authority state'ini değiştirmez.
- **P21** Issuer yetkilendirmesi = domain Acceptance'ı ve subject'in key-state'indeki class designation (conjunction); iptal prospective
- **P22** Acceptance issuer'ı PartyRef, OIDF entity (+chain kısıtı), SPIFFE trust domain veya pinned key set ile tanımlanır; chain girdidir, kabul değildir
- **P23** SPP ve Action Schema'nın semantik zorunlu alanları bağlayıcıdır (namespace, katalog sürümü, typed parametreler ve closed-type eşlemesi, authority-relevant/opaque ayrımı, reserved bayrağı, consumption/effect class, render tanımı); render authority-opaque'tır ve schema digest'ine dahildir.
- **P24** Compatibility mapping closed algebra ile ifade edilir, digest'le pin'lenir, yalnız non-broadening yönde otomatik kullanılır
- **P25** RAR: type = ActionRef (+ zorunlu schema digest üyesi), kind=intent|bounds; RFC 9396 ortak alanları Access sınırı taşımaz
- **P26** ValidityContract'ın semantik zorunlu alanları §9.12'deki gibidir; profile = dört class (online / intermittent / offline / long-running) + bunlara eşlenen variant; guarantee etiketleri yalnız dört guarantee sınıfıdır (§3.3); Verifier Profile Claim must-understand'in issuer tarafını bağlar.
- **P27** Offline Exercise Report bir Claim'dir ve remaining'i tek başına değiştirmez; slice `projection.issue` anında draw edilmiştir (ayrı finalize yok); kullanılmayan slice'ın iadesi orijinal exerciser veya lineage holder'ın grounded `consumption.release` Exercise'ıdır (Access release yapmaz; Σrelease ≤ draw); contract dışı kullanım derived state'tir, yaptırım explicit Exercise ile.
- **P28** Authority-state ack bir detection sinyalidir; revoke'un etkinliği ack'e bağlı değildir
- **P29** Tek user act → tek Approval Act Statement + tek assertion; iki act türü: contribution (contribute Exercise; Access önce commit eder, Work bağımsız doğrular; requester REQUIRE_ACTION almış nonce ile yeniden commit eder) ve authority-act (kullanıcının kendi meta-Exercise'ı; actor = kullanıcının Instance'ı; IntentEnvelope = meta-Exercise'ın typed envelope'u, AAS onun proof'u ve target'ı envelope digest'i; assertion H(AAS)'ye bağlı, contribution yok); her iki türde AAS proof'tur, IntentEnvelope değildir, ve intent digest yüzey-bağımsızdır; submit edilen Request'in Actor Intent Statement'ı approver Instance'ındandır; Access Work'ü bilmek zorunda değildir
- **P30** Opaque parametreler schema'nın body digest rule'u ile intent'e bağlanır; Surface ve PEP digest'i doğrular
- **P31** Federation: E19'un beş mekanizması ayrı karşılıklarla. Foreign authority: PAP + Work'ün üç foreign-proof kontrolü + tazelik koşulu + foreign-authority Acceptance + bridging Grant (ForeignAuthority holder; effective = Ceiling ∩ Map(foreign chain) ∩ Mandate); cross-domain delegation = foreign Party'ye yerel extensional Grant (`grant.issue` + actor-binding); home budget home'da draw edilir (online veya slice). Ayrı bir yerel AuthorityDomain (ör. tesis veya robot filosu) bir profile class'ı değildir; bridging Grant'lı ayrı bir domain'dir.
- **P32** Record Export Package ve checkpoint'ler Suiss olmadan doğrulanabilir; witness seçimi domain'indir
- **P33** Access semantic event'leri SSF üzerinden SET olarak (EXTEND); receiver re-query yapar
- **P34** Extension yerel ve namespaced; kapalı kümeler governance ile; ayrı sürüm izleri; downgrade = genişletme sınıfı. Semantik sonuç değiştiren her kural (opaque `basis_ref` token ve HMAC event id kuralları dahil) L0/L2 metnine ve conformance vektör kapsamına girer (TI-RT12).

#### 9.18.1 Ek protocol kararları (P35–P60)

Statü dili:
- "FROZEN (türetilmiş: X)": kararın, X'in zaten frozen olan kuralının uygulanması olduğunu söyler. Yeni semantik getirmez; gözden geçirme X ile birlikte yapılır.
- Sayısal değerler PD veya EA'dır.
- Taslağa bağlı eşlemeler WATCH ile birlikte PD'dir.

Garanti kısaltmaları: BS = BY SEMANTICS, UDC = UNDER DECLARED CAPABILITY/POLICY, NG = NOT GUARANTEED.

| # | Karar | Statü | Garanti | Gerekçe | Kaynak / alt bölüm |
|---|---|---|---|---|---|
| **P35** | ADP, AuthZEN 1.0 PDP kontrol listesinin 13 maddesini taşıyıcı yükümlülüğü olarak uygular. Ret = 200 + `decision=false`; protocol hatası 400. Bilinmeyen alanları yok sayma kuralı yalnız AuthZEN taşıyıcı alanlarına uygulanır; ADP must-understand üyeleri yok sayılmaz | FROZEN (türetilmiş: L23, R2, R7) + taşıyıcı ayrıntısı PD | BS (fail-closed eşleme) | Güven modeli Access semantiğindedir; taşıyıcı yükümlülükleri AuthZEN kontrol listesindedir | §9.5.1 |
| **P36** | Tutarlılık belirteci `context.consistency_token` ile taşınır ve `capabilities` dizisinde ilan edilir. Yalnız `check`/search/explain'de anlamlıdır; `commit`/`continue`/`projection.issue` daima `head` okur | FROZEN (türetilmiş: TI-2/3/5, T11) + alan adı PD | BS (commit için) | AuthZEN'de alan yok; varsayılan-bayat karar yeni düşmanı geri açar | §9.5.2, §9.7A.2 |
| **P37** | Contextual tuple yoktur. PEP'in sunduğu olgu yalnız Acceptance'lı `predicate-input` Claim'i olarak RequirementTerm/RestrictionPolicy girdisidir; holder seçimine giremez | FROZEN (türetilmiş: R2, INV-15) | BS | Confused deputy sınıfı | §9.5.2 |
| **P38** | Kararın domain'i actor'ün AIS'te imzaladığı `domain`'dir; token'daki `tenant` iddiası ve `tenant_id` karar girdisi değildir | FROZEN (türetilmiş: PI-7, MD-5) | BS | İmzalı bağlam token iddiasından güçlüdür | §9.5.2 |
| **P39** | REST `Idempotency-Key` meta-Exercise nonce'una eşlenir: eksik 400, farklı yük 422, eşzamanlı 409. DENY nonce terminal kalır; yeniden çalıştırma yalnız protocol hatasında | PD | BS (INV-21 idempotency) | C30 | §9.5.2 |
| **P40** | Access PEP SDK'sı `Authorized<R,A>` derleme zamanı kanıt tipini sunar. Değer ExerciseID + intent digest taşır | PD (MD-1'e bağlı) | UDC (SDK'yı kullanan PEP), NG (diğer) | "Kontrolü unutma" sınıfını yapısal kapatır | §9.5.2 |
| **P41** | Görülemeyen kaynakta DENY yokluktan ayırt edilemez. `reason_user` = requester kapsamı, `reason_admin` = audit kapsamı; viewer kapsamı explain'dedir | FROZEN (türetilmiş: E26) + eşleme PD | BS | İfşa kontrolü | §9.6.1 |
| **P42** | Search: 1 s sert son tarih, ≤ 1000 sonuç, zorunlu sayfalama, advisory. Check/List tutarlılığı. Batch'te kısa devre yalnız `check`'te; batch = tekil | Sınırlar EA; kısa devre kuralı FROZEN (§9.7) | Commit BS; advisory UDC | Nesne listeleme tehlikesi; commit'te her ALLOW bir Exercise | §9.7.1 |
| **P43** | Türetilmiş graf indeksi yalnız `check`/search/explain/eligible set servis eder; commit girdisi değildir. Okuma sınıfları `head` / `at_least` / `as_of` / `minimize_latency`; replica'dan ALLOW yoktur; `check` varsayılanı bayat değildir | FROZEN (türetilmiş: MD-4, TI-5) + varsayılan PD | BS (commit), UDC (advisory doğruluğu) | Pozitif yetki tek kaynaktan | §9.7A.1–2 |
| **P44** | İçerik nedenselliği: içerik pozisyonu q'yu bilen verifier `as_of < q` projection'ı o içerik için reddeder (PAP opsiyonel adım 8) | PD | UDC | Zanzibar Örnek B projection yolunda tanımsızdır | §9.7A.3, §9.10.1 |
| **P45** | Advisory önbellek anahtarı uzunluk önekli blake3 (tenant, domain, subject, action, resource, model sürümü, `applied_pos`). Olumsuz TTL ≤ 1 s; yetki veren Exercise olumsuz girdileri senkron düşürür; "hiç görülmedi" fail-closed | Anahtar kuralı PD; TTL EA | BS (commit'te önbellek yok) | Önbellek anahtarı çakışması sınıfı; MD-7 | §9.7A.4 |
| **P46** | Kotalar (derinlik 25, genişlik 10, check 100 ms, search 1 s / 1000) ve advisory sıcak yol hedefleri (p99 < 5 µs / < 100 µs / < 5 ms / < 50 ms). Commit yolu hedefleri ayrıdır | EA | — | Ölçülmedi; OQ-1 | §9.7A.5–6 |
| **P47** | İstemci içi / gömülü karar noktası bir `intermittent`/`offline` connectivity profilidir: ValidityContract + Verifier Profile Claim olmadan conformant değildir. Değerlendirme fonksiyonu saf; veri getirme ayrı katman | FROZEN (türetilmiş: L16, E13, INV-27) | UDC (beyanlı), NG (beyansız) | Cedarling deseni bayatlığı beyan etmeden kopyalanamaz | §9.7A.7 |
| **P48** | OAuth binding: tek `aud` (OAuth access token; PAP/ValidityContract audience'ı verifier kümesi olabilir, SEC13); kayıtsız `resource` → `invalid_target`; `cnf` zorunlu; scope yalnız etiket; token passthrough yok. ID-JAG (`token_type=N_A`) authority-bearing projection değildir; bu kuralın kapsamı dışındadır (§11.11.2) | FROZEN (türetilmiş: PI-11, L24, R3) + `invalid_target` PD | BS | Audience oracle'ı ve passthrough sınıfları | §9.9.3 |
| **P49** | Identity plane access token ömrü CT'ye göre PD: yönetimde ≤ 60 dk (yalnız CT0 okuma/gezinme; §13.7.2 tavanı geçerlidir). Authority taşıyan token'ın horizon'u = min(ömür PD'si, §13.7.2 tavanı). 28 saatlik token reddedilir. Introspection'da tazelik kanıtlanamazsa `active=false`; RS 5xx'i DENY sayar | PD (ömür); FROZEN (türetilmiş: MD-7, MD-8) | Pencere BS (sınıflandırma) / UDC (kapanma) | INV-24 garanti dürüstlüğü | MD-7, MD-8; §9.9.3 |
| **P50** | Refresh rotasyonu + reuse detection (aile iptali = projection temizliği + `projection-invalidated` event). İstemci SDK'sında single-flight zorunlu ve testli. Refresh ömrü ≤ Grant/Mandate validity | PD | BS (yeni karar), UDC (reuse detection) | Çalınan token tespit edilebilir olaya döner | §9.9.3 |
| **P51** | Projection ve authority artefaktı imzaları MD-3'e göre: COSE Ed25519 (ES256/ESP256 doğrulama zorunlu), JOSE ES256, RS256 yalnız identity plane opt-in. RS256 yalnız kimlik iddialarında; authority taşıyan access token dahil hiçbir [AU] projection'ında yok; authority taşıyan token domain operasyonel anahtarıyla imzalanır (MD-6). Allowlist metadata'dan; `alg: EdDSA` reddedilir | FROZEN (MD-3) | BS (allowlist) | Algoritma karıştırma sınıfı; interop | MD-3; §9.9.3, §9.10.1, §9.15.1 |
| **P52** | Projection'larda (her projection: access token, receipt, PAP, ValidityContract) PartyRef domain-pairwise takma addır | FROZEN (MD-10) | BS (Access artefaktlarında ham PartyRef yok); unlinkability NG (aynı `cnf`, zamanlama → §13 RR) | NIST 800-63C PPII | MD-10; §9.9.3, §9.10.1 |
| **P53** | Capacity → `sub`/`act`/`may_act` eşlemesi §9.9.4 tablosudur. İç içe `act` yalnız lineage kaydından üretilir; `may_act` ipucudur; destek erişimi `act` ile, ayrı token tipi olmadan (standart `at+jwt`, RFC 8693 delegation biçimi; TN-70, TNI-13), `act`'sız impersonation yok | PD (wire biçimi); FROZEN (türetilmiş: L22, INV-4, MD-9) | BS (splicing'e bağışıklık) | Interop'un en çok kırılacağı yer | §9.9.4 |
| **P54** | REQUIRE_ACTION her yüzeyde DENY'dan ayırt edilebilir taşınır; ifade edilemiyorsa DENY uygulanır. Bekleyen tek nesne REQUIRE_ACTION almış nonce'tur. OAuth: `insufficient_authorization` / `interaction_required`; RS: RFC 9470 / `insufficient_scope`; AARP, SEP-2643/2848, A2A eşlemeleri | PD + WATCH (taslaklar) | BS (fail-closed) | Saf OAuth/MCP istemcisi REQUIRE_ACTION'ı DENY'dan ayırt edemez | §9.9.5 |
| **P55** | İki katman: kimlik iddiaları (Claim) ≠ bounds token (projection) ≠ ince karar. Claim mapper authority üretemez; kiracı yalnız önceden tanımlı Claim kümesinden seçer; rezerve claim adları kapalıdır; mapper değişikliği ADP `commit`'tir | FROZEN (türetilmiş: PI-8, INV-15, MD-14) + rezerve liste PD | BS | Mapper bir yükseltme yüzeyidir | §9.9.6 |
| **P56** | Epoch'lar: `session_epoch` identity plane hızlı iptali; `key_epoch` anahtar penceresi; `authz_epoch` yerine AuthorityStateBasis + `applied_pos` | FROZEN (MD-7) | Hızlandırıcı UDC; garanti ValidityContract | Epoch commit sonrası garanti vermez | MD-7; §9.11.1–2 |
| **P57** | OIDF chain-kısıtlı Acceptance: Claim girdisi için Acceptance aktif ∧ chain çözülür ∧ tazelik ≤ Δ. Zincir kaybı lapse'tir, Acceptance'ı revoke etmez. Trust mark onay atlatmaz; yalnız UI'a rozet ekleyen ya da daraltan Acceptance'ın girdisidir (render daraltılamaz) | PD (kural); FROZEN (türetilmiş: PI-3, L26) | BS | OIDF tek zincirle beş use'u ayırt edemez | §9.13.8 |
| **P58** | OAuth/MCP onay kaydı UI kaydıdır, `grant_ref` taşır; Grant revoke/lapse ile geçersizleşir. CIBA yalnız davettir (eşleme §9.14.5 k.2). AAS'e WYSIWYS gereksinimi eklenir | FROZEN (türetilmiş: INV-16, E23) + kayıt alanları PD | BS (yetki yalnız `grant.issue`'dan); render doğruluğu UDC | Consent ≠ authority | §9.14.5 |
| **P59** | SSF/CAEP verici ve alıcısı identity plane'de tam. Gelen sinyal Claim'dir: yalnız yeniden sor veya Acceptance'lı daraltma. Ajan olayları Access event'leridir; toplu iptal `instance.terminate` kümesidir | FROZEN (türetilmiş: L18, INV-24, PI-9) | Teslim NG; güvenlik ValidityContract (UDC) | Sinyal hızlandırıcıdır | MD-13; §9.16.2 |
| **P60** | Domain Metadata, OIDC/RFC 8414 AS metadata ve `authzen-configuration` ayrı belgelerdir; AS metadata realm'indir (MD-5) ve Domain Metadata'ya çapraz atıf yapar; `authzen-configuration` Domain Metadata'dan türetilir. Domain Metadata algoritma, binding key kapsamı, anahtar penceresi ve PQ ilanını taşır. Identity plane config değişikliği ADP `commit`'tir | FROZEN (türetilmiş: AP-15, MD-3, MD-6, MD-14) | BS | Kimlik belgesi authority iddiası değildir | §9.15.1 |
