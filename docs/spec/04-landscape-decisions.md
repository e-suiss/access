## 4. Landscape Decisions

### 4.1 Verdict

Landscape verdict'i **VALIDATE WITH REFINEMENTS**'tır. İncelenen olgun standart ve ürünlerin hiçbiri Access'in authority semantiğinin tam kombinasyonunu (provenance, attenuation algebra, Mandate, budget, consumption, authoritative exercise record) taşımaz; standartlar projection, transport ve input katmanlarıdır (kanıt seviyesi: reviewed landscape; evrensel yokluk iddiası değil). Standart kararlarının tablosu §9.4'tedir.

**Landscape iki parçalıdır**:
- **Authority landscape:** L1–L28 (§4.2–§4.4). Verdict'i yukarıdaki gibidir.
- **Identity landscape:** §4.5–§4.11. Verdict'i ayrı yazılır. Tam IdP yetenekleri olgun bir pazardır ve Access identity plane'inde yeni bir protokol icat etmez (L20). Identity plane'in farklılaşması protokol yüzeyinde değil, şu üç yerde aranır:
  - authority plane ile bütünleşmede (Identity ≠ Authority, tek yazma yolu),
  - gün-1 kararlarında,
  - güvence disiplininde (§14).

  Bu farklılaşma hipotezdir (§4.7).

L2'nin evrensel-olmayan dili ("reviewed landscape; evrensel yokluk iddiası değil") iki landscape'e de uygulanır.

### 4.2 Frozen landscape decisions (L1–L28)

Statü: **FROZEN LANDSCAPE DECISION**.

- **L1** Landscape verdict'i VALIDATE WITH REFINEMENTS'tır. Thesis kararlarıyla (F1–F20) gerçek contradiction yoktur.
  - F21–F23 ile de contradiction yoktur. F21 identity plane kapsamını tanımlar. Authority landscape'inin vardığı sonuç (authority kombinasyonu standartlarda yok) bundan etkilenmez.
- **L2** İncelenen ilgili olgun standart ve ürünlerin hiçbirinde Access'in authority semantiğinin tam kombinasyonu (provenance, attenuation algebra, mandate, budget, consumption, authoritative exercise record) bulunamadı. Access bunları kendisi tanımlar; standartlar projection, transport ve input katmanlarıdır. (Kanıt seviyesi: reviewed landscape; evrensel yokluk iddiası değil.)
  - 2025–26'da büyük oyuncuların hemen hepsi ayrı bir ajan ürünü veya GA özellik çıkarmıştır. Örnekler: Okta Cross App Access ve Agent SSO, Okta for AI Agents, Auth0 for AI Agents (Token Vault, CIBA, FGA), Entra Agent ID, Ping Identity for AI, Keycard, Descope Agentic Identity Hub, Gravitee, WSO2 IS 7.2 ajan registry'si. L2'nin iddiası bu ürünlere karşı yeniden sınanmalıdır. Sınama yapılana kadar L2 aynı kanıt seviyesiyle durur. Yeniden sınama §20'de açık iştir. L2'yi açacak karşı örnek: provenance + attenuation + budget + cascade revocation + exportable exercise record'u birlikte sunan bir ürünün gösterilmesi. Bu durumda yalnız H12 değişir (B1), L2'nin semantik sonucu değişmez.
- **L3** Access'in katmanları: core semantics (authority plane) / identity plane ürün katmanı / open interoperability profiles / ayrı ürün katmanları (adjacent) / security tooling. Commercial packaging semantic ownership kanıtı değildir.
- **L4** Landscape'in en güçlü desteklediği kavramsal yön, explicit Grant'lar merkezli, provenance taşıyan bir authority graph'tır; capability-style attenuation semantiği ve instance-bound exercise ile. ReBAC tuple tek başına yetersizdir; policy tek başına yetersizdir; capability token tek başına yetersizdir; provenance ve attenuation first-class'tır. İmzalı capability token'lar source değil projection'dır.
  - Cedar'ı permit modeliyle gömüp üstüne ayrı bir ReBAC katmanı kurmak bu kararla çelişir: Cedar'ın permit modeli L7'ye ve must-never #2'ye aykırıdır. Karar MD-4'tür. Pozitif yetki yalnız Grant'tan gelir. Cedar yalnız forbid-only restriction dili olarak girer. ReBAC türetilmiş indekstir.
- **L5** Bir Grant intensional (rule-shaped) subject veya resource taşıyabilir. Positive authority veren her kural, issuer'ı ve basis'i olan bir rule-shaped Grant'tır. "Restriction policy must not mint authority" kuralı geçerlidir ve rule-shaped Grant ile çelişmez.
- **L6** Bir claim issuer, claim'i bir grant predicate'ine katıldı diye authority grantor olmaz. Ama bir issuer'a *authority-selecting* bir claim class için güvenmek kendisi authority-sensitive bir konfigürasyondur, çünkü o issuer intensional bir grant'ın kapsamına kimin girdiğini etkileyebilir. Üç kavram ayrıdır: Authority Grantor (positive authority'nin kaynağı/delegator), Fact/Claim Issuer (dış fact'in attributable kaynağı), Authority Selector Authority (root'un bir issuer'a claim class üzerinden üyelik belirleme gücünü açıkça tanıması). Decision proof authority lineage'ı ve fact dependency'yi ayrı gösterir.
  - Bu karar Access'in kendi identity plane'i için kritiktir. Access'in kendi identity plane'inin grup ve rol Claim'leri de Acceptance olmadan selection'a giremez. Kendi IdP'mizin realm admin'i, grup üyeliğini değiştirerek bir rule-shaped Grant'ın kapsamını etkileyebilir. Bu nedenle iki kural geçerlidir:
    - (i) **Bir grup = bir üyelik issuer'ı.** Her grup tam olarak bir issuer beyan eder. Identity-plane-managed grupta kayıt identity plane'dedir; Claim realm issuer'ından veya beyanlı tek bir upstream issuer'dan gelir; konsol değişikliği `idp.group.*` domain action'ıdır. Domain-local grupta identity plane kaydı yoktur; Claim `claim.issue` meta-Exercise'ıyla domain'den gelir. Aynı grup için ikinci yazma yolu reddedilir. `Pred(membership(g))` selector'ı grubun issuer'ını adlandırır; başka issuer'dan gelen aynı adlı Claim seçime girmez (§5.17).
    - (ii) **Upstream grup mapping'i reserved requirement ile korunur.** Bir authority-selecting claim class'ının üyeliğini toplu olarak değiştirebilen her identity plane config action'ı (upstream grup mapping, protocol mapper, JIT/SCIM kaynak bağlama), o issuer'ın subject-selection Acceptance'ını genişletmekle aynı reserved requirement sınıfını taşır (CT3). Ya da mapping sonucu üretilen Claim upstream issuer atfını korur ve ayrı Acceptance ister.
- **L7** Non-monotonic granting yasaktır. "Allow unless X" biçimli bir kural, positive grant + restriction olarak ifade edilmek zorundadır.
- **L8** Relationship tuple Access'te canonical authority edge değildir. Fact edge'ler issuer'ı belli claim'dir; ReBAC graph bir index/projection olabilir.
  - Zanzibar deneyimi derived index tasarımına girer (CMP-9 graf indeksi, CMP-11 sorgu motoru; → §16.3). Bu bilgi: new-enemy penceresi, izin kaldırmanın read replica'dan okunmaması, zookie benzeri tutarlılık token'ı. İndeks check, search, explain ve eligible set sorgularına cevap verir. Commit-mode ALLOW üretmez (TI-5).
- **L9** Attenuation algebra decidable olmalıdır; tüm local restriction mantığı olmak zorunda değildir. *Canonical authority constraint algebra* (delegation, attenuation, portable authority ve subset proof'a katılan constraint'ler) typed, closed ve decidable'dır; intersection, subsumption, normalization ve deterministic evaluation tanımlıdır; child ⊆ parent mekanik olarak belirlenebilir. *Local restriction policy* yalnız DENY/REQUIRE üretebilir; positive delegated authority kanıtlayamaz veya yaratamaz; canonical algebra'da ifade edilemiyorsa child ⊆ parent kanıtı olarak serialize edilemez.
- **L10** Delegability explicit'tir ve reserved (express-only) authority sınıfları vardır. Asgari semantik `delegable` boolean'ıdır; bounded depth ve `downstreamHolderClass` canonical algebra'dadır (C15) ve hiçbir zaman provenance veya accountability'nin yerine geçmez. Wildcard-subject ("gelecekteki tüm authority") delegation ifade edilemez.
  - Zincir derinliği değişmezi için Kani hedefi aynı kuralın implementasyon doğrulama hedefidir (Kernel, MD-1; → §15).
- **L11** Authority'yi değiştirmek kendisi bir Authority Exercise'tır ve aynı canonical intent/exercise semantiğinden geçer. Reserved powers, daha güçlü assurance, quorum, delay veya başka daha sıkı requirement'larla yönetilebilir; ama authority modelini bypass etmez veya çatallamaz (ayrı authorization universe / ayrı evaluator yok). Genişletme daraltmadan daha sıkı requirement taşıyabilir; tersi asla.
  - Ayrı platform-admin ve realm-admin API yüzeyleri bu kararla uyumludur, çünkü ayrılık yalnız transport ve kota düzeyindedir. Authority state'ini değiştiren her çağrı ADP meta-Exercise'ına derlenir. Identity plane yapılandırması realm'in yönetişim domain'inde bir `idp.*` domain action Exercise'ıdır. İkisi de aynı ADP Exercise sözleşmesinden geçer (§2.2.2).
- **L12** Revocation derivation lineage'ı takip eder (cascade). Bir lineage'ın geçersizliği türettiği tüm grant, mandate ve projection'ları prospectively geçersiz kılar (CI-6 ile tutarlı).
  - Cascade authority içindir. `session_epoch` identity plane'de oturum ve token iptalidir. İkisi ayrı mekanizmadır. `party.compromise` ve `instance.terminate` her ikisini birden tetikleyebilir (→ §9.12, §12).
- **L13** Access quorum'u authority domain tarafından doğrulanabilir olmalıdır. Yalnız tek bir aggregate kriptografik kimlik gösteren threshold yapısı, bağımsız doğrulanabilir katılımcı katkıları, kimlikleri ve intent binding'leri authority domain'ine sunulmadıkça Access sınırında tek bir authority holder sayılır. Crypto threshold otomatik olarak governance quorum değildir. Quorum contribution'ları aynı intent digest'ine bağlıdır ve bağımsızlık sınıfı taşıyabilir.
- **L14** Approval evidence onaylanan exact intent'in digest'ine bağlıdır; intent değişirse approval geçersizdir (PSD2 Art. 5 ilkesi). Generic serbest metin onayı Access için geçerli approval evidence değildir.
- **L15** Mandate (açık constraint envelope) ile Exercise (kapalı, exact intent) ayrımı landscape tarafından bağımsız olarak doğrulandı (AP2 open/closed, PSD2, UK OB consent) ve korunur.
- **L16** Continuous exercisability tek mekanizma değildir. Dört connectivity sınıfı (online, intermittent, offline, long-running executor) ayrı profil taşır.
  - Identity plane iptal ve bayatlık tablosu L16 profillerinin identity plane örneğidir. Doğrulama yolları: login, refresh, introspection, salt-JWT doğrulayan RS, sinyal tüketen RS. Her hücre ValidityContract diliyle yazılır ve §13 guarantee matrisine satır olarak girer (MD-7; → §9.12, §13).
- **L17** Reusable veya auditable her authority decision, değerlendirildiği authoritative state basis'ini tanımlar (AuthorityStateBasis; C32). Tek global epoch yoktur. Reusable, cacheable, portable veya asenkron uygulanabilir her authorization artefaktı açık bir validity/freshness sınırı (ValidityContract) taşır. Point-in-time bir decision response, expiry taşıdığı için reusable credential'a dönüşmez: Decision ≠ Credential. Her verifier beyan edilmiş bir freshness profiline sahiptir.
  - Üç epoch (`session_epoch`, `key_epoch`, `authz_epoch`) bu kararın mekanizma tarafıdır: semantik ValidityContract'tır, epoch'lar mekanizmadır. "Tek global epoch yoktur" kuralı gün-1 kararı #18'in gerekçesiyle aynıdır ("tek sayaca indirgenirse her izin değişikliği tüm oturumları düşürür").
- **L18** Shared Signals / CAEP transport olarak benimsenir; güvenlik sinyale dayandırılmaz. Access, authority'ye özgü semantic event tiplerini (revoked, narrowed, expired, budget-exhausted, mandate-ended) kendisi tanımlar.
  - Identity plane CAEP vericisi ve alıcısıdır. SSF transmitter implementasyonu iki plane'de ortaktır. Teslimata güvenlik dayanmaz kuralı identity plane için de geçerlidir. SSF/CAEP spesifikasyon tarihleri doğrulanmadı (MD-18).
- **L19** Önceki bir authority decision yalnız açık, sınırlı bir freshness/dependency sözleşmesi altında yeniden kullanılabilir veya devam ettirilebilir; uzatma yeniden authority değerlendirmesi gerektirir. Biçimi ValidityContract + continuation DecisionRecord'dur (C31); Access'te ayrı bir "lease" nesnesi yoktur.
- **L20** Q3 verdict'i EXISTING STANDARDS + ACCESS PROFILE/BINDING SUFFICIENT'tır. Access yeni bir identity protokolü icat etmez.
  - Identity plane de standart implementasyon yapar. Protokol listesi §9.4 PROFILE tablosunda ve §10'dadır.
- **L21** Holder-bound key'ler bir instance'ı authenticate eder ve bağlar; instance'ın tam kimliğini veya lifecycle'ını tanımlamaz. InstanceID (Access-level mantıksal kimlik/lifecycle referansı) ≠ KeyBinding (DPoP / mTLS / WIT cnf gibi güncel proof materyali) ≠ Attestation (instance/key'e bağlı runtime/ortam claim'i). Runtime attestation yalnız claim'dir.
  - PI-11 authority projection'ları içindir. "Bearer varsayılan değildir" kuralı identity plane token'larına uzanır: varsayılan sender-constrained'dır (DPoP, mTLS-bound, JWT-SVID). Bearer yalnız legacy RP opt-in'idir ve beyan edilir (I3; → §9.9, §10). 3 Ağustos 2026 ölçümüne göre incelenen 15 halka açık issuer'ın hiçbiri DPoP ilan etmiyor. Bu ölçüm henüz yeniden üretilmedi.
- **L22** Token'lardaki actor chain (act) projection ve ipucudur. Prior actor'ler token'dan değil Access lineage'ından doğrulanır.
  - İmzalı, hop başına `delegation_chain` da projection ve ipucudur. Lineage kayıtlardadır (→ §11).
- **L23** AuthZEN Authorization API 1.0 Access'in PEP-facing karar yüzeyi olarak benimsenir. Access profili şunları ekler: doğrulanmış credential'dan türetilen subject/actor, require-action eşlemesi, authority context ve imzalı decision receipt. AuthZEN'in PEP-asserted subject modeli Access için yeterli değildir.
  - ADP çekirdektir ve unit of value'nun yüzeyidir. Bu nedenle AuthZEN PDP Faz 1'dedir (§18.13).
- **L24** OAuth ailesi (RFC'ler; OAuth 2.1 draft olarak etiketlenir) projection ve transport'tur. OAuth scope ≠ Access authority; RAR envelope'un taşıyıcısıdır, semantiği Access'tedir. Projection'lar holder-bound ve audience-bound'dur; token passthrough yoktur.
  - Identity plane tam bir OAuth 2.1 AS'tir ve RP'ler için scope üretir. Ancak authority taşıyan scope bir Grant'ın projection'ıdır (§2.2.2). OAuth 2.1'in IESG'ye Aralık 2026'da sunulacağı ve MCP'nin `draft-13`'e referans verdiği bilgisi birincil kaynakta doğrulanmadı.
- **L25** SPIFFE/WIMSE kimlikleri actor binding girdisidir. SPIFFE trust domain ≠ Access identity domain ≠ Access authority domain. Workload federation hiçbir zaman authority federation değildir.
  - Identity plane JWT-SVID'i birinci sınıf client kimlik doğrulaması olarak kabul eder. L25'in ayrımları aynen geçerlidir.
- **L26** OpenID Federation issuer/provider trust bootstrap için benimsenir. Identity issuer'ın authority issuer rolünü alması metadata/entity-type düzeyinde engellenebilir olmalıdır.
  - OpenID Federation'ın Access'te iki rolü vardır: identity federation ve trust bootstrap (Access). L26'nın issuer rol engeli her iki rolde korunur.
- **L27** GNAP, Biscuit, UCAN, ZCAP ve agent-related individual I-D'ler WATCH'tır: fikir kaynağıdır, bağımlılık değildir. Draft'lar standart gibi ele alınmaz.
  - ID-JAG / Cross App Access parite kalemidir (MKT-10). Identity plane ID-JAG'ı identity assertion olarak üretir ve tüketir. ID-JAG'ın authorization grant semantiği reddedilir: authority Access Grant'tan gelir. Access'in ürettiği ID-JAG authority taşımayan bir kimlik iddiası projection'ıdır ve authority scope içermez; authority RS tarafında Access Grant'ından gelir. Karar MD-18'dir, ayrıntı §9.4 ve §11'dedir.
- **L28** Credential/token vault, session recording/brokering, risk scoring, trusted rendering ve instruction-provenance savunması tek bir "Access değildir" kalemi olarak yazılmaz; her biri bir plane'e veya ayrı ürün katmanına atanır (§2.5). Login oturumu, DBSC, CAEP vericisi ve alıcısı, risk tabanlı step-up (risk yalnız daraltır, CI-2) ve ajan credential broker'ı / token vault **identity plane**'dedir. Upstream token'ın ajana verilmesinin release kararı bir Access Exercise'ıdır; upstream token Access projection'ı değildir (içeriği NOT GUARANTEED; CT2+ için varsayılan: broker PEP olarak çalışır; teslim edilen token'da `exp` ≤ ValidityContract horizon); possession ≠ authority. PAM oturum kaydı/aracılığı, genel amaçlı sır kasası, fraud scoring motoru, DLP ve SIEM **ayrı ürün katmanlarıdır**. Trusted rendering yüzeyinin **gerçek dış sahibi** Experience / Work Approval Surface conformance profile'ıdır. Instruction-provenance savunmasının **gerçek dış sahibi** One / Executor Runtime'dır. Access bunların *authority* kısmına karar verir, olay ve sinyal üretir. Bu metin L28'in tek kanonik metnidir; §2.5, §7.6 ve §12.0.2 buna atıf yapar ve yalnız kısa plane ataması verir.

### 4.3 Landscape'ten benimsenen kalıplar ve reddedilenler

| Kalıp | Karar | Access karşılığı |
|---|---|---|
| Explicit Grant graph + capability-style attenuation | ADOPT | Grant, AuthoritySet ⊑, DelegationTerms (C11, C15, C22) |
| Policy-only (XACML/ALFA, Cedar, OPA/Rego) | Yalnız restriction rolü | RestrictionPolicy = Cedar'ın forbid-only alt kümesi: sabit taban `permit`, kullanıcı politikaları yalnız `forbid`, REQUIRE forbid'e bağlı RequirementSet referansıyla. Spike başarısız olursa CEL profili korunur ve SMT eşdeğerlik analizi eklenir (OQ-MD2) |
| ReBAC tuple'ı canonical edge olarak | REJECT | ReBAC index bir projection'dır (L8). Zanzibar/Leopard motoru türetilmiş graf indeksi (CMP-9) ve sorgu motoru (CMP-11) olarak korunur; commit-mode ALLOW üretmez (TI-5) |
| Zincirli bearer capability (Biscuit, UCAN, ZCAP) | WATCH / REJECT (canonical olarak) | Access revocation ve Acceptance semantiğiyle çelişir; fikir kaynağıdır (L27) |
| AuthZEN karar API'si | PROFILE + EXTEND | Access Decision Profile (P6) |
| OAuth / RAR / DPoP | PROFILE + EXTEND | Projection ve transport (L24, P25) |
| SSF / CAEP | PROFILE + EXTEND | Semantic event transport'u; güvenlik sinyale dayanmaz (L18, P33) |
| OpenID Federation | PROFILE | Trust bootstrap; trust chain Acceptance girdisidir (L26) |
| SPIFFE / WIMSE | PROFILE | Actor binding girdisi; workload federation ≠ authority federation (L25) |
| PSD2 dynamic linking, AP2 open/closed mandate, UK OB consent | ADOPT (ilke) | Exact-intent approval (L14), Mandate ↔ Exercise ayrımı (L15) |
| Tam OIDC OP / OAuth 2.1 AS (FAPI 2, CIBA, PAR/RAR/JAR/JARM, token exchange, CIMD) | ADOPT (identity plane) | §10; scope ayrımı §2.2.2 |
| SAML 2.0 IdP, SCIM 2.0, LDAP, Kerberos/SPNEGO, RADIUS, WS-Fed | ADOPT (identity plane; kenar gateway'ler ayrı süreç, MD-1) | §10 |
| ID-JAG / Cross App Access | PROFILE (identity assertion / Claim taşıyıcı); authorization grant semantiği REJECT | §9.4, §11 |
| MCP authorization (PRM, `resource`, `iss`, CIMD) | PROFILE | §11 |
| Kiracının sunucuda yürüttüğü şablon, betik, action, expression policy (FreeMarker, adaptive auth scripts, actions) | REJECT | F23, must-never #15 |
| Çalışma zamanında yorumlanan, adımı silinebilir auth "flow" konfigürasyonu | REJECT | Tipli kimlik doğrulama durum makinesi (§10) |
| Identity plane audit'inde olay başına hash zinciri | REJECT (identity plane audit için); authority log'unda T3 zinciri kalır | Identity plane: düz append-only + ~1 sn Merkle checkpoint + dış tanık. Authority log: tek sequencer, batch içinde amortize zincir (→ §17) |
| Dağıtık cache'in doğruluk kaynağı olması (Redis/Infinispan); Postgres `LISTEN/NOTIFY` | REJECT | Derived ≠ canonical; outbox (→ §16, §17) |

### 4.4 Authority landscape kategori haritası ve katman testi

Bu harita L3'ün dayanağıdır. Temsilciler ve tarihler 2026-10-06 erişimlidir ve eskir etiketi taşır (MKT-3).

| # | Kategori | Temsilciler (2026) | Access'e göre konumu |
|---|---|---|---|
| K1 | Workforce/customer IAM platform | Entra, Okta/Auth0, Google Cloud IAM, AWS IAM + Identity Center, Ping, Keycloak, Ory | **Access identity plane bu kategorinin tam üyesidir** (F21). Authority plane bu kategoriye girmez. External IdP aynı Acceptance koşullarıyla desteklenir (F3, B7) |
| K2 | Fine-grained authorization (ReBAC) | Zanzibar, SpiceDB, OpenFGA, Ory Keto, Okta FGA | **Kısmi örtüşme.** Grant store'un sorgu ve indeks yönü; provenance yok. Access'te derived index (CMP-9/CMP-11, MD-4) |
| K3 | Policy-as-code / PDP | Cedar + AVP, OPA, Cerbos, Oso Cloud | **Restriction dili.** Access'te policy construct; positive authority kaynağı değil (Cedar forbid-only, MD-4) |
| K4 | Authorization interoperability | OpenID AuthZEN 1.0, COAZ, Obligations, AARP | **Projection yüzeyi.** Access AuthZEN-uyumlu PDP olarak görünebilir (ADP) |
| K5 | Delegated authorization protocols | OAuth 2.0/2.1, RAR, DPoP, PAR/JAR, Token Exchange, Txn-Tokens, Identity Chaining, ID-JAG, GNAP | **Projection + transport.** OAuth grant ≠ Access Grant. Identity plane bu protokollerin AS'idir |
| K6 | Capability / signed authority tokens | Macaroons, Biscuit, UCAN 1.0, ZCAP, SPKI | **Portable artifact deseni.** Access'in portable/offline projection'ı |
| K7 | Workload identity | SPIFFE/SPIRE, WIMSE, cloud workload identity federation | **Identity input.** Authority değil |
| K8 | Agent identity / AI authorization | AIMS (WIMSE -00), Entra Agent ID, Okta for AI Agents, Auth0 for AI Agents, Google Agent Identity, AWS AgentCore Identity/Policy, Ping Identity for AI, ~30 individual IETF draft | **Access'in hedeflenen farklılaştırıcı alanı.** Mevcut ürünler identity'yi çözüyor, bounded delegated authority'yi çözmüyor (reviewed landscape; L2 notu) |
| K9 | Continuous access / shared signals | SSF/CAEP/RISC 1.0, Entra CAE, Okta ITP + Universal Logout | **Sinyal transportu.** Identity plane CAEP vericisi ve alıcısıdır (MD-13) |
| K10 | PAM | CyberArk, Teleport, BeyondTrust, Entra PIM | **Authority kısmı Access'tir.** Oturum kaydı/aracılığı ve kasa ayrı ürün katmanıdır. Ajan credential broker'ı identity plane'dedir |
| K11 | Identity governance (IGA) | Entra ID Governance, SailPoint, SAP GRC, SCIM 2.0 | **Aynı authority semantiği üzerinde capability.** Workflow'lar canonical ontology değildir. SCIM sunucusu identity plane'dedir |
| K12 | Federation | OpenID Federation 1.0/1.1, SAML federations, SPIFFE federation | **Trust acceptance'ın taşıyıcısı.** Identity federation identity plane çekirdeği; authority federation core (F16) |
| K13 | Transaction / intent authorization | PSD2 RTS Art. 5, FAPI 2.0, RAR, CIBA, SPC, UK OB / Berlin Group consents, AP2 v0.2, Stripe SPT, Visa TAP | **Access'in Exercise/Envelope semantiğinin en güçlü precedent'i** |
| K14 | Verifiable credentials / status | OID4VCI/VP 1.0, SD-JWT VC, Token Status List, W3C Bitstring Status List | **Claim input + offline status projection** |
| K15 | Provenance / transparency | in-toto, SLSA 1.1, Sigstore, CT (RFC 9162) | **Exercise record'un assurance deseni** (security control) |
| K16 | Non-software precedent | POA, agency law, DoA matrisleri, two-person rule, maker-checker, LOTO, RFC 5280 path validation | **Fikir kaynağı**, kopyalanmaz |

**Katman testi ("anti-Frankenstein")**. Soru şudur: "Yanlışlıkla `Okta + Zanzibar + Cedar + SPIFFE + CyberArk + Macaroons + CAEP + GNAP`'ı tek ürün olarak mı tasarlıyoruz?" Access bilinçli olarak tam IdP'yi içerir (F21). Risk, plane'lerin semantik olarak karışmasıdır. Sınır şöyle çizilir:

| Katman | İçerik | Access'te mi? |
|---|---|---|
| **Authority core semantics** | Authority root, grant (rule-shaped dahil), delegation + delegability, mandate, constraint algebra, requirement (proof/approval/quorum), authority budget + consumption, decision, exercise record, revocation/exercisability semantiği, foreign authority acceptance, actor/instance binding semantiği | **Evet** (authority plane) |
| **Identity plane ürün katmanı** | Kimlik doğrulama, hesap ve credential yaşam döngüsü, oturum, OIDC/OAuth AS, SAML, SCIM, LDAP, Kerberos, RADIUS, WS-Fed, OIDF, MCP/ajan kimliği, ajan credential broker, risk tabanlı step-up, CAEP vericisi/alıcısı, yönetim API'si | **Evet** (identity plane; authority üretmez) |
| **Open interoperability profiles** | AuthZEN PDP surface, OAuth/RAR token projection, Token Exchange `act` projection, DPoP/WIT binding, SPIFFE/WIMSE identity consumption, SSF/CAEP event emission, Token Status List, OpenID Federation trust bootstrap, signed capability offline profile | **Access tarafından sağlanan profil**; ontology değil |
| **Ayrı ürün katmanları** | Genel sır kasası, PAM oturum aracılığı/kaydı, fraud/risk motoru, IGA review workflow motoru, SIEM, DLP | **Access'in plane'lerinde değil**; Access authority kısmına karar verir, olay ve sinyal üretir |
| **Gerçek dış sahipler** | Approval UI / trusted rendering → Experience / Work Approval Surface; instruction-provenance savunması → One / Executor Runtime; MDM → Device management (§2.5, L28) | **Access'in plane'lerinde değil**; Access authority-relevant içeriği ve authority kısmını sahiplenir |
| **Security tooling / assurance** | Transparency log, formal analysis, canary credentials, shadow-agent discovery, decision receipt signing | **Assurance**; primitive değil |

Kontrol sorusu iki parçalıdır. (1) "Bu fikir Access'in tek sorusunun ('may this actor, on this authority, do this exact thing now?') cevabını değiştiriyor mu?" Değiştiriyorsa authority core'dur. (2) Değiştirmiyorsa: "Bu bir identity plane yeteneği mi?" Değilse plane ataması tablosuna (§2.5) göre yerleştirilir.

### 4.5 Identity landscape: ürün kategorileri

Tablo bilgi amaçlıdır. "Access'te" sütunu Access'in kararıdır (MKT-2).

| # | Kategori | Ne yapar | Ne yapmaz | Örnekler | Access'te |
|---|---|---|---|---|---|
| 1 | Tam IdP ve IAM platformu | Kimlik deposu, login arayüzü, protokol, admin konsolu | Ürünün içine gömülmez | Keycloak, Zitadel, Authentik | **Evet:** identity plane (F21) |
| 2 | Headless kimlik altyapısı | API üzerinden kimlik ve token | Hazır login ekranı vermez | Ory, Logto, SuperTokens | Kategori olarak hedeflenmez. Yönetim API'si ve SDK'lar bu kullanımı kısmen karşılar (çıkarım) |
| 3 | Uygulama içi kütüphane | Auth'u backend'in parçası yapar | Diğer uygulamalara SSO vermez | Better Auth, Auth.js | Hedeflenmez. İstemci SDK'ları RP tarafını kapsar (§18.3) |
| 4 | Yönetilen CIAM (SaaS) | Her şeyi barındırır | Veri egemenliği ve maliyet kontrolü vermez | Auth0, Clerk, WorkOS | Teslim modeli olarak: Suiss-hosted operasyon (infrastructure rolü, §18.3). Self-host ve çıkış hakkı korunur (B10). Çıkarım |
| 5 | Protokol motoru | Sertifikalı OAuth ve OIDC mantığı | Kullanıcı deposu ve arayüz vermez | Authlete, Duende, node oidc-provider | **Evet:** identity plane AS çekirdeği (OIDF conformance, MD-1) |
| 6 | Yetkilendirme motoru | Erişim kararı | Kimlik doğrulama yapmaz | OpenFGA, SpiceDB, Cerbos | **Karar kısmı evet:** authority plane. ReBAC/policy motorları Access'te derived index ve restriction dilidir (MD-4) |
| 7 | Workload ve ajan kimliği | İnsan olmayan aktörlerin kimliği | İnsan login'i yapmaz | SPIFFE/SPIRE, Entra Agent ID | **Evet:** identity plane (ajan kimliği, §11). Workload kimliği girdi olarak (L25) |
| + | **Authority layer** (yeni kategori hipotezi) | Provenance, attenuation, Mandate, budget, exercise record | Effect yürütmez | — (L2, reviewed landscape) | **Evet:** authority plane. Kategori olarak satın alınması H1'dir |

Beş yakın kategori ve Access karşılığı:

| Kategori | Ne | Access'te |
|---|---|---|
| IAM | Çalışan kimliği: dizin, kurumsal SSO, cihaz politikaları | Identity plane (SAML/OIDC, SCIM, LDAP, Kerberos); enterprise girişte external IdP varsayılan kalabilir (H13a) |
| CIAM | Müşteri kimliği: kayıt akışı, sosyal login, tüketici ölçeği, dönüşüm | Identity plane (hesap yaşam döngüsü, giriş UX, §12) |
| IGA | Yönetişim: erişim gözden geçirmeleri, onay akışları, sertifikasyon | Authority governance capability (§2.4); review workflow motoru ayrı ürün katmanı (§4.4) |
| PAM | Ayrıcalıklı erişim: kasa, oturum kaydı, JIT yükseltme | JIT ve onay eşiği authority plane'de; kasa ve oturum kaydı ayrı ürün katmanı (L28) |
| NHI | İnsan olmayan kimlikler: servis hesapları, workload'lar, API anahtarları, ajanlar | Identity plane (client'lar, ajan kimliği) + authority plane (Instance, Mandate) |

### 4.6 IdP pazar envanteri (özet)

**Normatif ek referansı.** Bu bölüm IdP pazar envanterinin özetidir (bölüm A–J, yaklaşık 110 ürün; tam envanter "en güçlü / en zayıf yanı" sütunlarını, ürün profillerini, karşılaştırma ve fiyat modeli tablolarını da içerir). Listeden ürün düşmez. Okuma kuralları:
- **Bilgi amaçlıdır.** Envanter karar gerekçesi değil, bağlam bilgisidir. Lisanslar yalnız bilgi olarak listelenir; iyi/kötü diye değerlendirilmez.
- **Eskir etiketi.** Sürüm, tarih, fiyat ve satın alma bilgisi 3–6 ayda kayabilir. Envanter 2026-10-06 tarihlidir.
- **`?` doğrulanamadı demektir.** Satın alma tarih ve tutarlarının bir kısmı tek ikincil kaynağa dayanır. Kullanmadan önce birincil kaynaktan teyit edilir.
- **Kaynak kalitesi.** Ürün karşılaştırmalarının çoğu satıcı bloglarından gelir ve taraflı olabilir. Lisans ve sürüm gibi doğrulanabilir olgular çapraz teyit edilmiştir. "En iyi" türü yargılar edilmemiştir.

**A. Açık kaynak: tam IdP / IAM platformları (self-host)**

| Ürün | Lisans | Dil | Protokoller (özet) | Ajan / MCP (özet) |
|---|---|---|---|---|
| Keycloak | Apache-2.0 | Java (Quarkus) | OIDC, SAML, SCIM (önizleme), LDAP-src, Kerberos, PK, FAPI 2, DPoP, CIBA | MCP AS rehberleri, CIMD (deneysel), RFC 8693, SPIFFE/K8s SA federated client auth, ID-JAG (deneysel), AuthZEN, SSF |
| ZITADEL | AGPL-3.0 (v3'ten); API ve SDK Apache-2.0 | Go | OIDC, SAML, LDAP-src, PK, SCIM v2 | RFC 8693, private-key JWT servis kullanıcıları |
| authentik | Open core: çekirdek MIT, `enterprise/` tescilli | Python + Go outpost | OIDC, SAML, SCIM, LDAP-srv, LDAP-src, RADIUS, PK, WS-Fed (ent.) | RFC 8693 actor token; Agent Accounts ve DCR enterprise'da |
| Ory (Kratos, Hydra, Keto, Oathkeeper, Polis) | Apache-2.0 + Ory Enterprise License | Go (Polis: TS) | Hydra OIDC (sertifikalı); Kratos PK, SCIM, SAML SP; Polis SAML→OIDC + SCIM; Keto Zanzibar | Hydra MCP AS; Agent DX; Ory Agent Security |
| Logto | MPL-2.0 | TypeScript | OIDC/OAuth 2.1, SAML, PK, SCIM ? | MCP AS dokümanları, MCP server |
| Casdoor | Apache-2.0 | Go + React | OIDC, SAML, CAS, LDAP-srv, RADIUS, SCIM, PK | MCP Auth Provider (DCR, PRM, RFC 8707); CIMD yok |
| WSO2 Identity Server | Kaynak Apache-2.0; indirilen binary ticari EULA | Java | OIDC, SAML, SCIM 2, LDAP-src, PK, WS-Fed, FAPI 2 (sertifikalı) | 7.2: ajan kimliği registry'si, MCP şablonları |
| Janssen Project | Apache-2.0 (Linux Foundation) | Java (Cedarling: Rust) | OIDC, SCIM, PK, LDAP-src, SAML ? | Cedarling gömülebilir Cedar motoru |
| Gravitee Access Management | Open core: Apache-2.0 CE + EE | Java | OIDC, SAML, SCIM, LDAP-src, PK | CIMD, RFC 8693, SPIFFE/SPIRE, MCP ajan kimlikleri |
| Authgear | Apache-2.0 | Go | OIDC, SAML, PK, MFA | CIMD, on-behalf-of token exchange |
| Kanidm | MPL-2.0 | Rust | OIDC, LDAPS-srv (salt okunur), PK, RADIUS, SCIM sync; SAML yok | ? |
| Rauthy | Apache-2.0 | Rust | OIDC, PK/FIDO2, PAM/NSS; SAML ve LDAP yok | ? |
| MaxKey | Apache-2.0 | Java | OIDC, SAML, CAS, JWT, SCIM, LDAP sync | ? |
| TopIAM | AGPL-3.0 (CE) | Java | OIDC, SAML, CAS, JWT, SCIM 2 | ? |
| OpenIAM | CE lisansı ? | Java | SAML, OIDC, IGA | ? |
| Univention UCS / Nubus | AGPL-3.0 ? | Python | LDAP-srv, SAML/OIDC (Keycloak tabanlı), SCIM ? | ? |

**B. Açık kaynak: akademik, altyapı, hafif ve forward-auth**

| Ürün | Lisans | Dil | Protokoller (özet) |
|---|---|---|---|
| Shibboleth IdP | Apache-2.0 | Java | SAML, CAS, OIDC (plugin), LDAP-src, PK (plugin) |
| Apereo CAS | Apache-2.0 | Java | CAS, SAML, OIDC, WS-Fed, LDAP-src, PK, SCIM |
| SimpleSAMLphp | LGPL-2.1+ | PHP | SAML IdP/SP, OIDC (modül) |
| SATOSA | Apache-2.0 | Python | SAML ↔ OIDC proxy |
| LemonLDAP::NG | GPL-2.0+ | Perl | OIDC, SAML, CAS, LDAP-src, PK |
| FreeIPA / Red Hat IdM | GPL-3.0 | Python + C | LDAP-srv, Kerberos, CA, PK (SSSD); yerel OIDC/SAML IdP yok |
| OpenAM (Open Identity Platform) | CDDL-1.0 | Java | SAML, OIDC, LDAP |
| Wren:AM | CDDL-1.0 | Java | SAML, OIDC |
| Dex | Apache-2.0 | Go | OIDC (LDAP/SAML yalnız upstream connector) |
| Authelia | Apache-2.0 | Go | OIDC, LDAP-src, PK |
| Pocket ID | BSD-2-Clause | Go + Svelte | OIDC (sertifikalı), yalnız passkey, PAR, LDAP/SCIM provisioning |
| TinyAuth | AGPL-3.0 | Go | Temel OIDC OP (sertifikalı), forward-auth, PK |
| VoidAuth | AGPL-3.0 | TypeScript | OIDC, PK/MFA |
| LLDAP | GPL-3.0 | Rust | LDAP-srv (hafif) |
| Samba AD / OpenLDAP / 389-ds | GPL / OpenLDAP PL | C | LDAP, Kerberos |

**C. Açık kaynak: gömülü IdP, BaaS auth ve kütüphaneler**

| Ürün | Lisans | Dil | Ne sağlar (özet) |
|---|---|---|---|
| SuperTokens | Open core: Apache-2.0 + `ee/` tescilli | Java çekirdek; Node/Python/Go SDK | Oturum, sosyal/passwordless giriş, çok kiracılık |
| Supabase Auth | MIT | Go | OAuth 2.1/OIDC server, SAML SP, MFA |
| Hanko | Backend AGPL-3.0, Elements MIT | Go | Passkey-first, OAuth SSO, SAML SP |
| Stack Auth → Hexclave | Sunucu AGPL-3.0, SDK MIT | TypeScript | OAuth, PK, teams, RBAC |
| Tesseral | MIT | Go | SAML, SCIM, OIDC, PK |
| Better Auth | MIT | TypeScript | OIDC provider (DPoP, device grant), SAML SSO, SCIM, PK; @better-auth/mcp |
| Auth.js / NextAuth | ISC | TypeScript | OAuth/OIDC client kütüphanesi (IdP değil) |
| Lucia | MIT | TypeScript | Oturum kütüphanesi (deprecate) |
| OpenAuth (SST) | MIT | TypeScript | OAuth2 (beta) |
| node oidc-provider | MIT | JavaScript | OIDC, FAPI 1/2, DPoP, PAR, RAR, CIBA, mTLS (sertifikalı) |
| OpenIddict | Apache-2.0 | C# | OAuth2/OIDC framework, RFC 8693 |
| Spring Authorization Server | Apache-2.0 | Java | OAuth 2.1/OIDC (Spring Security 7.0'a taşındı) |
| go-oidc / fosite | Apache-2.0 | Go | OIDC client / OAuth2 framework (Hydra'nın çekirdeği) |
| PocketBase / Appwrite / Nhost Auth | MIT / BSD-3 / MIT | Go / PHP / Go | BaaS'a gömülü auth |
| django-allauth, Devise, Passport.js | çeşitli | Python / Ruby / JS | Uygulama içi auth |

**D. Kaynak-görünür / ticari self-host ve protokol motorları**

| Ürün | Sahip | Lisans | Protokoller (özet) |
|---|---|---|---|
| FusionAuth | FusionAuth | Tescilli freeware (Community ücretsiz); açık kaynak değil | OIDC, SAML, SCIM, LDAP connector, PK |
| Duende IdentityServer | Duende Software | Ticari, kaynak görünür; küçük kuruluşlara ücretsiz Community | OIDC, SAML (Advanced), CIBA, FAPI 2 raporu |
| Gluu Flex | Gluu | Ticari (Janssen tabanlı) | Janssen ile aynı |
| Curity Identity Server | Curity AB | Ticari | OIDC, SAML, SCIM, PK, FAPI (sertifikalı), token exchange, RAR |
| Authlete | Authlete | Ticari | OIDC, FAPI 1/2 (sertifikalı), CIBA; MCP AS için CIMD |
| Broadcom SiteMinder (+ VIP, Layer7) | Broadcom | Ticari | SAML, OIDC, WS-Fed |
| OpenText Access Manager (NetIQ) | OpenText | Ticari | SAML, OIDC, WS-Fed |
| Oracle Access Manager / OUD | Oracle | Ticari | SAML, OIDC, LDAP |
| Microsoft AD FS | Microsoft | Windows Server bileşeni | SAML, WS-Fed, sınırlı OIDC |
| IBM Verify Access | IBM | Ticari | SAML, OIDC, LDAP, FIDO2 |

**E. Ticari workforce IAM (SaaS ağırlıklı)**

| Ürün | Sahip | Ajan / MCP (özet, 2025–26) |
|---|---|---|
| Okta Workforce Identity | Okta | Cross App Access (XAA) ve Agent SSO GA 24 Ağu 2026; Okta for AI Agents ayrı SKU |
| Microsoft Entra ID | Microsoft | Entra Agent ID GA (kesin tarih ?); ajanlar için Conditional Access |
| Google Cloud Identity / Workspace | Google | Gemini Enterprise Agent Registry ve Agent Gateway GA; Vertex Agent Identity SPIFFE/X.509 |
| AWS IAM Identity Center | Amazon | Bedrock AgentCore Identity GA |
| Ping Identity (PingOne, PingFederate, PingAM) | Thoma Bravo | Identity for AI GA 31 Mar 2026 |
| CyberArk Identity → Idira | Palo Alto Networks | Secure AI Agents; CIAM'in kapatıldığı bildiriliyor (tek kaynak, teyit edilmedi) |
| IBM Security Verify | IBM | IBM Agent Identity public preview; Vault Agentic IAM GA |
| Oracle OCI IAM Identity Domains | Oracle | ? |
| OneLogin | One Identity | ? |
| JumpCloud | JumpCloud | Agentic IAM (MCP/A2A gateway) |
| Cisco Duo | Cisco | Duo Agentic Identity GA |
| RSA ID Plus | RSA (STG) | Pazarlamada var, ayrı ürün yok |
| Thales SafeNet Trusted Access | Thales | Imperva üzerinden ajan gateway |
| SecureAuth | SecureAuth | ? |
| Imprivata | Thoma Bravo | Agentic Identity Mgmt duyuruldu, GA ? |
| Salesforce Identity | Salesforce | Agentforce ajanları kullanıcı olarak modelleniyor (?) |
| SAP Cloud Identity Services (IAS) | SAP | Yol haritasında |
| Fortinet FortiAuthenticator / FortiIdentity | Fortinet | — |
| Zoho Directory, Rippling SSO | Zoho / Rippling | — |
| Beyond Identity | Beyond Identity | Ceros ajan güvenliği |
| HYPR | HYPR | "Çalışan ve ajan" güvencesi |

**F. Hyperscaler CIAM:** AWS Cognito; Microsoft Entra External ID (Azure AD B2C'nin yerine); Google Identity Platform (+ Firebase Auth).

**G. Ticari CIAM / geliştirici auth (SaaS) — fiyat modeli bilgisiyle**

| Ürün | Sahip | Fiyat modeli (kaynaktaki beyan) | Ajan / MCP (özet) |
|---|---|---|---|
| Auth0 | Okta | MAU | Auth0 for AI Agents (Token Vault, CIBA, FGA); Auth for MCP; XAA |
| Clerk | Bağımsız | MRU (50k ücretsiz) + bağlantı başı | DCR, CIMD |
| WorkOS (AuthKit) | Bağımsız | 1M MAU'ya kadar ücretsiz + bağlantı başı (65–125 USD) | AuthKit MCP auth, CIMD |
| Stytch | Twilio | MAU + bağlantı | Connected Apps (OAuth/MCP AS) |
| Descope | Bağımsız | MAU + ajan başı ("Monthly Active Tokens") | Agentic Identity Hub 2.0; XAA |
| Frontegg | Bağımsız | MAU + org SSO | AgentLink, Agen.co |
| Kinde | Bağımsız | MAU | ? |
| PropelAuth | Bağımsız | MAU | MCP auth GA (DCR + CIMD) |
| Scalekit | Bağımsız | 1M MAU ücretsiz + bağlantı | Auth stack for AI apps |
| SSOJet | Bağımsız | Bağlantı ? | MCP Authentication |
| Strivacity | Bağımsız | MAU | Strivacity for Agentic AI |
| LoginRadius | Bağımsız | Satış odaklı | — |
| MojoAuth | Bağımsız | MAU | ? |
| Authress | Rhosys AG | Kullanım | ? |
| Userfront | Bağımsız | Kullanım | — |
| Authing | Steamory | ? | ? |
| Transmit Security (Mosaic) | Bağımsız | Kurumsal | Ajan keşfi, JIT scoped token |
| Thales OneWelcome | Thales | Kurumsal | — |
| SAP Customer Data Cloud (Gigya) | SAP | Kurumsal | — |
| Nevis | Nevis | Kurumsal | ? |
| Ubisecure | Ubisecure | Kurumsal | ? |
| Signicat | Nordic Capital | İşlem başı | ? |
| Yönetilen OSS bulutları (ZITADEL Cloud, Ory Network, Logto Cloud, Authgear Cloud, FusionAuth Cloud, Hanko Cloud, Cloud-IAM / Phase Two, Asgardeo) | Ürün sahipleri | MAU / küme başı; Ory Network aDAU | A–C ile aynı |

**H. Katman ürünleri (tam IdP değil):** Corbado, Authsignal, Privy (Stripe), Dynamic (Fireblocks), Web3Auth (Consensys / MetaMask Embedded Wallets), Magic (wallet işi Payward'a geçti), Cloudflare Access (ZTNA; MCP Server Portals).

**I. Ajan / workload kimliği uzmanları (IdP'ye komşu):** SPIFFE/SPIRE (CNCF graduated, Apache-2.0), Teleport Machine ID (çekirdek AGPL ? + ticari), Aembit, Keycard, Arcade.dev (arcade-mcp OSS, motor kapalı), Composio (SDK OSS), Nango (ELv2), HashiCorp Vault Agentic IAM (IBM; OpenBao MPL-2.0 çatalı), Astrix / Oasis / Entro / Natoma / SGNL / Veza (2025–26'da satın alındı).

**J. Kapanan, EOL olan ve birleşenler:** 1Password Passage (16 Oca 2026 kapandı); Akamai Identity Cloud (31 Ara 2027 hizmet sonu); Azure AD B2C (yeni satış durdu, destek en az 2030); ForgeRock (Ping'e katıldı, PingAM); CyberArk Identity (Idira'ya katıldı); Lucia (deprecate); Auth.js (Better Auth bünyesinde bakım); Spring Authorization Server ayrı repo (Spring Security 7.0'a taşındı); Gluu Server 4 (yalnız bakım); SAP Identity Management on-prem (bakım sonu, tarih ?); IdentityServer4 (arşivlendi).

**Gözlemler (bilgi):**
1. Ajan kimliği 2026'da standart özellik olmuştur. Büyük oyuncuların hemen hepsi ayrı ürün veya GA özellik çıkarmıştır. Açık kaynakta Keycloak, Gravitee, authentik, WSO2, Better Auth ve Casdoor MCP AS / RFC 8693 / CIMD desteği sunar. Sonuç: L2 notu ve MKT-10.
2. Rust IdP'ler küçüktür: Kanidm, Rauthy, LLDAP. Envanterde tam özellikli (SAML + OIDC + SCIM + çok kiracılık) bir Rust IdP yoktur. Bu bir dil gözlemidir, ürün farklılaşması değildir. Dil kararı MD-1'dedir (→ §16).
3. Konsolidasyon hızlıdır. 2025–26'da Stytch, CyberArk, Astrix, Better Auth, Permiso, Veza, SGNL, Oasis, Entro, Natoma, Privy ve Dynamic satın alınmıştır.

Bağlam notu: 2026-07-28 tarihli MCP yetkilendirme spesifikasyonu revizyonu CIMD'yi ve on-behalf-of token exchange benimsenmesini hızlandırmıştır. Okta, Auth0 ve Descope Eylül 2026'da sekiz gün içinde Cross App Access (ID-JAG) çıkarmıştır. Bu not birincil kaynaktan doğrulanmadı.

### 4.7 Farklılaşma hipotezleri

Statü: **CURRENT STRATEGIC HYPOTHESIS.** Her madde §3.4'teki kurala tabidir: karşılaştırma kümesi, tarih ve geçersiz kılacak karşı örnek beyan edilir.

**Authority farklılaşma hipotezleri:**
- L2: authority kombinasyonu (reviewed landscape).
- H11: kalıcı savunma güvenilirlik, trust, deneyim ve integration'dan gelir; semantik öncelik geçicidir.
- H12: incumbent'lar yakın vadede vendor-neutral bounded delegated authority sunmaz.

Karşı örnekleri L2 notunda ve §18.8'dedir.

**Identity plane farklılaşma maddeleri (MKT-D1–MKT-D17).**
- Karşılaştırma kümesi 15 üründür: Keycloak, Okta, Auth0, Entra ID, WorkOS, Stytch (ilk sınama) ve Ping (PingOne, PingFederate, PingAM/ForgeRock), WSO2 IS / Asgardeo, Janssen / Gluu Flex, Kanidm, Duende IdentityServer, authentik, ZITADEL, FusionAuth, midPoint (2–13 aralığı için 2026-10-07 sınaması; güncel resmî belgeler, açık kaynaklarda kaynak kod ve issue'lar). "Hiçbir üründe yok" ifadesi yalnız bu 15 ürün için geçerlidir; sektörün tamamı için doğrulanmamıştır. "Bulunamadı ≠ kesin yok" (§3.4).
- 2026-10-07 sınamasının sonucu: MKT-D9 düştü (parite); MKT-D10 "yalnız biz" olarak düştü ve daraltıldı; MKT-D2, D7, D8, D11, D12 daraltıldı; MKT-D3, D4, D5, D6, D13 ayakta. Ayrıntı her satırın "Gözlenen durum" sütunundadır.
- İzlenecekler: Janssen OpenID Federation (issue #12357, 2.6.0 hedefi; MKT-D3), ZITADEL break-glass (#11487; MKT-D11) ve son yöntem koruması (#11587; MKT-D12) issue'ları.

| ID | Farklılaşma | Gözlenen durum | Statü | Geçersiz kılacak karşı örnek |
|---|---|---|---|---|
| MKT-D1 | ID-JAG üretimi | **Farklılaşma düşmüştür.** Okta Agent SSO 24 Ağu 2026'da GA; Auth0 Temmuz 2026 sonu erken erişim; Keycloak yalnız tüketiyor | **Parite kalemi** (MKT-10) | — (düşmüş) |
| MKT-D2 | DPoP'un **varsayılan** sender-constraint olması; mTLS-bound ve JWT-SVID'in birlikte birinci sınıf desteği | İncelenen 15 halka açık issuer'ın hiçbiri DPoP ilan etmiyor (3 Ağu 2026). 2026-10-07: DPoP ve/veya mTLS-bound token FusionAuth (Enterprise, istemci başına), PingFederate/PingAM, WSO2 (uygulama başına), Janssen, Duende (Enterprise; `RequireDPoP` varsayılan false) ve authentik'te (yalnız ID token bağlanır) **isteğe bağlı** olarak var; JWT-SVID yalnız Janssen'de ve varsayılan kapalı. Hiçbirinde DPoP varsayılan değil | H (daraltıldı: "destek" değil "varsayılan + üçlü") | Karşılaştırma kümesinden bir ürünün DPoP'u varsayılan sender-constraint yapması |
| MKT-D3 | OpenID Federation | "Rust'ta mevcut implementasyon yok". 2026-10-07: 9 üründe de sevk edilmiş OpenID Federation bulunamadı; Janssen 2.6.0 için planlıyor (issue #12357) | H | Karşılaştırma kümesindeki bir IdP'nin OpenID Federation'ı sevk etmesi. Dil-göreli yokluk ürün farklılaşması sayılmaz |
| MKT-D4 | A2A Agent Card imzalama servisi (RFC 8785 JCS + JWS) | Hiçbir mainstream IdP sunmuyor. 2026-10-07: 9 ek üründe de bulunamadı | H | Bir IdP'nin Agent Card imzalama servisi çıkarması |
| MKT-D5 | Branded lifetime ile derleme zamanı kiracı izolasyonu | Mekanizma olgun; çok kiracılığa uygulanmış yayımlanmış örnek bulunamadı. 2026-10-07: 9 ek üründe de bulunamadı | H (implementasyon tekniği) | Bu bir implementasyon tekniğidir. Ürün iddiası olarak yalnız §3.3a'daki izin verilen biçimde söylenir. Geçersiz kılan: yayımlanmış bir çok-kiracılı uygulama. "Bulunamadı ≠ ilk biz" |
| MKT-D6 | `achieved_aal >= required_aal` şema kısıtı | Hiçbir IdP kurtarma yolunun AAL değerini modellemiyor. 2026-10-07: 9 ek üründe de bulunamadı | H | Karşılaştırma kümesindeki bir ürünün kurtarma yolu AAL'ini modellemesi |
| MKT-D7 | `independence_group` ile sync fabric farkındalığı | Bağımsızlığı ölçen ürün yok. 2026-10-07: PingOne FIDO politikası senkronize passkey'i BE bayrağıyla ayırt edip izin/zorlama ayarı veriyor, ancak aynı sync fabric'i ve bağımsızlık grubunu modellemiyor | H (daraltıldı: BE ayrımı değil, fabric/bağımsızlık modeli) | Authenticator bağımsızlığını sync fabric düzeyinde ölçen bir ürün |
| MKT-D8 | Delege oturumda ayrıcalık kesişimi ve **12 invariant'ın tamamı** | En yakın örnekler: ZITADEL (~3,5/12), authentik (2–3/12), WSO2 (1 tam + 3 kısmi; CVE-2025-12627 refresh'te operatör izini kaybediyordu), WorkOS (4/12), ServiceNow (2/12), PingAM ve midPoint (~1–2/12). Ayrıcalık kesişimi, motor seviyesinde yasak liste, 60 dk tavan, kullanıcının bürünülmeyi yasaklaması ve özyinelemeli devretme yasağı hiçbirinde bulunamadı | H (daraltıldı: "tamamı"). Access'te MD-9 ile Grant modelindedir (kimliğe bürünme yok) | 12 değişmezin ≥ çoğunluğunu sunan bir ürün |
| MKT-D9 | Hash ve TOTP sırlarının self-servis dışa aktarımı | **Farklılaşma düşmüştür.** ZITADEL admin `ExportData` API'si `with_passwords` ve `with_otp` ile ikisini birden veriyor (2026-10-07). Keycloak TOTP sırlarını veriyor; FusionAuth ve midPoint kısmen | **Parite kalemi.** Access'te ücretsizdir (B19) | — (düşmüş) |
| MKT-D10 | Ön-hash ve pepper'ın **kod/eklenti yazmadan, veri olarak tanımlanan** hash şemasıyla içe aktarımı | `bcrypt(sha256(pw))` ve peppered hash'ler çoğu üründe göç edemiyor. 2026-10-07: FusionAuth (Java hash eklentisi) ve Duende (`IPasswordHashAlgorithm` kodu) bunu **kodla** yapabiliyor; PingOne, ZITADEL, Kanidm, authentik çok sayıda hazır şemayı alıyor ama pepper/özel şema yok; WSO2 dış servisle göç | H (daraltıldı: "yalnız biz" düştü; ayrım veriyle tanım ve F23) | Pre-hash/pepper şemasını kod yazmadan tanıtan bir ürün |
| MKT-D11 | `is_breakglass` alanının birinci sınıf, izinli ve **alarmlı** olması | Yalnız Stytch'te, B2B'ye özgü. 2026-10-07: Kanidm belgelerinde `admin`/`idm_admin` break-glass hesabı ve `recover-account` var, ancak alan ve alarm yok; ZITADEL'de açık istek (#11487) | H (daraltıldı: belgelenmiş acil hesap değil, alan + izin + alarm). Bayrak authority üretmez (F19 notu) | Genel amaçlı bir IdP'de aynı alan |
| MKT-D12 | Son kimlik doğrulama yöntemi korumasının **şemada** olması | İncelenen dört üründe uygulama katmanında. 2026-10-07: Kanidm sunucu tarafında reddediyor (`can_commit` → `NoValidCredentials`) ama uygulama mantığında; PingOne yalnız UI uyarısı; ZITADEL'de açık istek (#11587) | H (daraltıldı: sunucu kontrolü değil, şema düzeyi) | Şema düzeyinde koruma sunan bir ürün |
| MKT-D13 | Kurtarma ve onboarding yeniden tetikleme oranının güvenlik metriği olması | Unit 42'nin tavsiyesi; hiçbir üründe yok. 2026-10-07: 9 ek üründe de bulunamadı | H. Türetilmiş ürün metriğidir (§18.4) | Metriği sunan bir ürün |
| MKT-D14 | Tamper-evident denetim logu (Merkle checkpoint, imza, dış tanığa yayın) | Keycloak: DB erişimi olan satır değiştirebilir; Okta, Auth0, Entra bütünlük garantisi sunmuyor | H. Authority plane'de bu frozen'dır (T3, T16, witness). Identity plane'e uzanır (→ §17) | Karşılaştırma kümesinden bir ürünün dış tanıklı tamper-evident audit sunması |
| MKT-D15 | `Idempotency-Key` desteği tüm mutating endpoint'lerde | Okta, Auth0, Entra desteklemiyor; WorkOS tek endpoint'te | H | Tam kapsamlı destek sunan bir ürün |
| MKT-D16 | Uzun sıcak denetim penceresi | Hiçbir büyük IdP PCI'ın 12 aylık gereksinimini kendi içinde karşılamıyor: Okta 90 gün, Entra P1/P2 30 gün, Auth0 Starter 1 gün | H. Policy minimumu ücretsiz baseline'dır (SEC32, §18.6) | 12 ay sıcak pencere sunan bir büyük IdP |
| MKT-D17 | Denetim logunun request path'inde bulunmaması | Keycloak'ta login isteği event insert'ini bekliyor | H | Karşılaştırma kümesinde aynı ayrıştırmayı yapan ürün |

Not: Rakamlar ve ürün durumları birincil kaynaktan tekrar doğrulanmadı.

### 4.8 Seçim eksenleri ve yönlendirme

11 seçim ekseni identity plane'in **segment gereksinimleri** olarak alınır. Eksenlerin listesi FROZEN LANDSCAPE'tir (gereksinim kümesi). Segment önceliği hipotezdir (H13a, H13b, H14). Lisans ekseni yalnız müşterinin kendi kısıtı olarak yazılır, değerlendirme yapılmaz.

| # | Eksen (etki sırasıyla) | Access identity plane'in cevabı |
|---|---|---|
| 1 | Aktörler: tüketici, çalışan, servis, cihaz, ajan | Hepsi tek modelde: Party / actor-capable Party / Instance (F18), §1.7 |
| 2 | Üçüncü taraf istemci olacak mı (gerçek AS, muhtemelen FAPI) | Tam OAuth 2.1 AS, FAPI 2, CIBA (§10); consent Grant Exercise'ı |
| 3 | Kurumsal federasyon (SAML, SCIM) | SAML IdP, SCIM 2.0 sunucu, LDAP, Kerberos (§10) |
| 4 | B2C mi B2B mi | İkisi: B2B organizasyonlar realm içinde Party + Anchor (MD-5) |
| 5 | Regülasyon (sağlık, finans, kamu genelde self-host ister) | Self-host profili (§16/§17), FIPS profili (MD-3), CRA (§18.11) |
| 6 | Ölçek ve fiyat modeli | Fiyat ekseni MAU değildir (MD-17, §18.5) |
| 7 | Operasyon kapasitesi ("hangi topoloji gerekir") | Small-provider profili ≈ tek binary (→ §16/§17). Single-node profili beyanlı bir dağıtım biçimidir (`durability: single-node`): ilgili garanti satırları UDC → HL olarak beyan edilir, ≥ 2 sync standby şartı bu profilde kalkar; authority plane deposu için T8/OP-7 geçerlidir, SQLite yalnız T8'in izin verdiği yerde (OP-48) |
| 8 | Lisans (müşterinin lisans politikası) | Bilgi: §18.10; karar D4 |
| 9 | Mobil ana akış mı | Tarayıcı redirect'i olmayan kalıp gereksinimi → §10 / §12 |
| 10 | Göç maliyeti (hash taşınmaz; lazy migration; 60–90 gün) | Pre-hash/pepper import, lazy migration (→ §12); hash/TOTP export ücretsiz (B19) |
| 11 | Kripto çevikliği (PQC satın alma gereksinimi) | `algorithm` alanı gün-1, ML-DSA-65 opt-in (MD-3; → §15) |

**Hızlı yönlendirme (bilgi).** Pazarın bugünkü yönlendirme tablosu aşağıdadır. Access'in hangi satırlarda aday olduğu hipotezdir. Tablo karar gerekçesi değildir.

| Durum | Pazarın tipik önerisi |
|---|---|
| Protokol genişliği ve olgunluk gerekiyor, operasyon kapasitesi var | Keycloak |
| B2B çok kiracılık; lisans politikası AGPL-3.0 çekirdeğe izin veriyor | Zitadel |
| Apache-2.0 lisanslı çok kiracılık | Keycloak Organizations |
| Kendi auth arayüzü ve ölçek hedefi | Ory Hydra ve Kratos |
| Reverse proxy arkasında iç uygulamalar | Minimal: Authelia; flow, LDAP, SCIM: Authentik |
| Tüketici uygulaması, gömülü auth | SuperTokens |
| JavaScript/TypeScript ile hızlı ürün | Logto veya Better Auth |
| Next.js ve React, 100.000 MAU altı | Clerk |
| B2B kurumsal SSO hızlı | WorkOS |
| Kurumsal genişlik ve FGA, bütçe var | Auth0 |
| AWS-native ve yüksek MAU | Cognito |
| Microsoft-native ve FedRAMP | Entra External ID |
| Supabase üzerinde | Supabase Auth ve RLS |
| En geniş sosyal login, özellikle Asya | Casdoor |
| FAPI sertifikası | Authlete, WSO2 IS, Curity |
|.NET ve in-process token server | Duende IdentityServer |
| Node'da sertifikalı AS | node oidc-provider |
| Akademik federasyon | Shibboleth, CAS |
| İnce taneli yetkilendirme | OpenFGA veya SpiceDB |
| Çalışma zamanı bağlamlı karar | Cerbos |
| Workload ve ajan kimliği | SPIFFE, SPIRE ve OAuth |
| IoT filosu | mTLS, PKI ve zero-touch provisioning |

### 4.9 Yap / al kararı

**Karşı görüş.** Yaygın pazar görüşü şudur: "Sıfırdan IdP yazmak savunulamaz … Kendi SAML ve SCIM implementasyonunu yazmak ayrıca kötüdür." Access ise bir IdP kurar.

**Karar (MKT-5, FROZEN LANDSCAPE DECISION).** Access identity plane'i kurar. Gerekçeler açık kayda geçer:
1. Identity ≠ Authority ve tek yazma yolu hazır IdP'lerin veri modeliyle sağlanamaz. Bilinen uyarı da budur: "Kullanıcı durum verisi IdP'nin user modeline zorlanırsa iki doğruluk kaynağı ortaya çıkar".
2. Identity plane'in 30 gün-1 kararı (§3.1b) mevcut ürünlerde yoktur. Bu iddianın doğrulama kapsamı 6 üründür (§4.7).
3. Access'in authority plane'i, identity plane yapılandırmasını kendi ADP'si üzerinden `idp.*` domain action Exercise'ı olarak yetkilendirir (MD-14). Bu yalnız identity plane aynı üründe olduğunda yapısal olarak sağlanır.

**Alınanlar.** Semantiği bozmayan yerde kütüphane alınır:
- WebAuthn kütüphanesi
- XMLDSig/C14N kütüphanesi
- LDAP codec'i
- protokol tip kütüphaneleri
- kripto (aws-lc-rs, MD-1)
- Cedar motoru (MD-4)

Crate seçimleri §16'dadır.

**Beyan edilen bedel.** SAML ve SCIM'in sürekli interop bakımı yaklaşık %30–40'tır (tahmin). Bu RR olarak beyan edilir (→ §13/§14). Rust'ta olgun OAuth 2.1 AS kütüphanesi yoktur, bunun bedeli 12–18 geliştirici-ayıdır (tahmin, ölçüm değil). Bu bedel MD-1'de kabul edilmiştir.

**Yönetilen broker alternatifi** (ör. bir vakada 45 dakikada SAML kurulumu). Bu alternatif ürünün kendi identity plane'i için reddedilir. Müşteri tarafında ise upstream bağlantı olarak desteklenir (identity federation).

**Kurumda kalan işler**. Hangi ürün seçilirse seçilsin şunlar kurumda kalır: cihaz kaydı, ürüne özgü kurtarma tasarımı, risk sinyalleri, doğrulama sonrası oturum izleme, ürüne özgü yaşam döngüsü. Access bunları identity plane capability'si olarak sunar (§12). Müşterinin domain verisi Access'e taşınmaz (§2.6 Test A).

### 4.10 Performans hedefi

Statü: **ENGINEERING ASSUMPTION** (identity plane). Benchmark alt koşulu §3.1d geçerlidir.

**Hedef.** Aynı donanım bütçesinde ve aynı Argon2 maliyetiyle daha yüksek login/sn taşımak. Karışık profilde login'in refresh'i aç bırakmaması ayrı bir kabul kriteridir.

**Hedef "Keycloak'ı geçmek" değildir.** Keycloak'ın referans değerleri 2.000 login/sn ve 10.000 token yenileme/sn'dir. Bunlar vendor yayınıdır ve doğrulanmadı. Keycloak'ın ölçüt seçilme nedeni şudur: yeniden üretilebilir rakam ve koşum yöntemi yayımlayan tek IdP'dir. 1:5 login:refresh oranı Keycloak'ın kıyaslama tercihidir, ölçülmüş bir üretim oranı değildir.

**Ölçülecek iddialar** (ölçüm/hedef beyanıdır; ham veri henüz yok, yeniden üretim bekliyor):
- "Login CPU'sunun ~%97'si Argon2 + imza"
- "çekirdek başına 15 yerine 40–60 login/sn"

**Kazancın kaynağı.** Argon2'nin hızlandırılması değildir. Kazanç hash dışındaki maliyetin azaltılmasından gelir. Ayrıca `spawn_blocking` + çekirdek sayısı mertebesinde semafor kullanılır (→ §16).

**Satış dili.** Bu hedef satış dilinde garanti olarak kullanılamaz (B15). Authority plane'in commit throughput ve p99 hedefleri ayrıca EA'dır (OQ-1; → §16).

### 4.11 Standart olgunluk özeti

Protokol karar tablosu §9.4'tedir; identity protokollerinin ayrıntısı §10'dadır. Aşağıdaki tablo olgunluk özetidir. Statü etiketleri Access'in "doğrulanmadı" disiplinindedir. MD-18 gereği WebAuthn L3 statüsü ve CTAP sürümü doğrulanmamış olarak işaretli kalır.

| Teknoloji | Pazar statüsü | Üretime alınır mı | Access etiketi |
|---|---|---|---|
| OAuth 2.1 ve PKCE | Konsolide | Evet | OAuth 2.1 draft olarak etiketlenir (L24) |
| DPoP | RFC, yaygın | Evet | RFC 9449 |
| PAR, RAR, JAR, JARM | RFC | Evet | — |
| Token Exchange | RFC | Evet | RFC 8693 |
| Step-up (RFC 9470) | RFC | Evet | — |
| FAPI 1.0 ve 2.0 | Final, sertifikalı | Evet; 2.0 confidential client ile | — |
| CIBA | Final | Evet | — |
| WebAuthn L2 ve passkey | Yaygın | Evet | — |
| WebAuthn L3 | W3C Recommendation'a önerildi | Kısmen | **doğrulanmadı** (MD-18) |
| SCIM 2.0 | Olgun | Evet | — |
| Argon2id (RFC 9106) | Standart | Evet | — |
| Yeni nesil (ID-JAG, FiPA, DBSC, EUDI, SSF/CAEP tarihleri) | Hareketli | — | Hızla eskir; SSF/CAEP tarihi doğrulanmadı (MD-18) |

### 4.12 Bilinen başarısızlık kalıpları

Bilinen başarısızlık kalıpları F ailesiyle (frozen product decisions) karışmaması için **LFP-n** olarak anılır. LFP-1–LFP-22 authority kalıplarıdır; LFP-23–LFP-29 identity plane kalıplarıdır (identity plane gün-1 kararlarının gerekçeleri, §3.1b). Statü: FROZEN LANDSCAPE DECISION'ın kanıt eki. Karşı önlemlerin normatif yeri ilgili bölümdür. Gerçek dünya örneklerindeki CVE atıfları birincil kaynaktan kontrol edilmedi.

| # | Başarısızlık kalıbı | Gerçek dünya örneği | İhlal edilen ilke | Access karşı önlemi |
|---|---|---|---|---|
| LFP-1 | Delegation impersonation'a dönüşür | Kerberos unconstrained delegation; S4U2Self; CVE-2025-55241 Actor tokens | Explicit, scoped delegation; CI-3 | Delegation her zaman delegator + delegate + scope taşır; "act as" ≠ "be" |
| LFP-2 | Provenance token exchange'te kaybolur | Entra OBO önceki `azp`'yi düşürür; RFC 8693 nested `act` karar dışı; Identity Chaining claim rewrite | CI-6 | Lineage token'da değil Access'te; token yalnız referans taşır |
| LFP-3 | Kapsamsız issuer trust identity'yi authority yapar | Storm-0558, Golden SAML, CVE-2025-55241 | CI-10, Trust tanımı | Issuer × claim class × subject class × domain acceptance; identity issuer authority issuer olamaz (L26) |
| LFP-4 | Bearer token = apparent authority | GitHub/Heroku OAuth 2022, Okta HAR session tokens 2023, Salesloft Drift 2025 | CI-5 | Holder-bound projection varsayılan; identity plane token'ları da sender-constrained varsayılan (I3) |
| LFP-5 | Third-party integration standing, geniş, uzun ömürlü delegation tutar | Salesloft Drift, Okta XAA connection'ları, Token Vault yoğunlaşması | Mandate, budget | Mandate instance'a ve süreye bağlı; authority budget; per-tenant revocation |
| LFP-6 | Policy sessizce authority basar | OPA default-allow/negation hataları; Cerbos derived roles; Cedar'da author kontrolü yok | Must-never #2 | Rule-shaped grant issuer + basis taşır; non-monotonic grant yasak; Cedar yalnız forbid-only (MD-4) |
| LFP-7 | Claim issuer'ı effective access'i fark edilmeden belirler | `owner` kolonu; RBCD attribute write; Cedar entity data; AWS session tag spoofing | CI-2, CI-11 | Authority-selecting claim class için issuer acceptance authority-sensitive konfigürasyon (L6) |
| LFP-8 | Relationship graph kazara business truth olur | Zanzibar dual-write | CI-11 | Fact edge'ler issuer'ı belli claim; Access canonical domain truth tutmaz |
| LFP-9 | Scope'lar akıl yürütülemez hâle gelir | Entra consent grant'ları süresiz; MCP union-of-scopes step-up; role explosion | Envelope, constraint algebra | Typed envelope; decidable constraint; scope yalnız projection |
| LFP-10 | Continuous authorization fazla söz verir | Entra CAE 28h token; SSF timing garantisi yok | CI-9 | Semantik ≠ propagation ≠ enforcement; 28 saatlik token reddedilir (MD-7) |
| LFP-11 | Offline revocation çalışmaz | OCSP soft-fail; Federation core revocation yok | CI-9, F16 | Bounded staleness, offline budget, kısa ömür, status list |
| LFP-12 | İnsan exact intent'i anlamadan onaylar | Bybit blind signing; MFA push bombing (Uber 2022) | CI-8, CI-14 | Approval evidence intent digest'ine bağlı (L14) |
| LFP-13 | Quorum tek bir görüşe çöker | Bybit: 3 imzacı aynı kompromize UI | Quorum semantiği | Contribution'lar aynı intent'e bağlı, bağımsızlık sınıfı taşır (L13) |
| LFP-14 | Authority değişikliği gevşek requirement'la geçer | Bybit delegatecall; RBCD attribute; federation trust ekleme (SolarWinds) | CI-4 | Authority değişikliği aynı exercise semantiğinde, daha sıkı requirement'la (L11); identity plane config dahil (MD-14) |
| LFP-15 | Runtime identity agent identity ile karıştırılır | Pod/SA kimliği agent'ın authority'si sayılır; Entra agent user insan gibi görünür | CI-2, F18 | Kind ≠ identity ≠ instance; runtime attestation yalnız claim (L21) |
| LFP-16 | Ambient authority + confused deputy | AWS cross-account deputy; MCP tool poisoning / token passthrough | CI-8, Model B | Exercise authority + intent'i birlikte taşır; audience-bound projection; passthrough yok (L24) |
| LFP-17 | Servis global chokepoint olur | Merkezi PDP; Zanzibar hot spot; Okta/Entra outage | CI-15 | Authority-domain scoped provider; projection; ama fail-closed (MD-8) |
| LFP-18 | Permission administration yönetilemez olur | Role explosion, rubber-stamp certification, consent sprawl | — | Grant'lar sorgulanabilir veri; review sonucu authority-sensitive action |
| LFP-19 | Uzun ömürlü anahtar/grant unutulur | Storm-0558 2016 anahtarı; GCP SA key sprawl | CI-4, expiry | Her projection/grant için açık validity; expiry tek her-zaman-çalışan revocation |
| LFP-20 | Tek tıkla "her şeyi devret" | UCAN Powerline; Google domain-wide delegation | CI-3, CI-5 | Wildcard-subject delegation reddedilir (L10) |
| LFP-21 | PEP-asserted context authority üretir | AuthZEN "PDP must trust the PEP"; OpenFGA contextual tuples | CI-2 | Subject/actor doğrulanmış credential'dan türetilir (L23) |
| LFP-22 | Kayıt yok veya executor kendi kaydını yazar | CVE-2025-55241 issuance log'u yok; Okta 14 gün detection gap | Exercise record | Exercise record'u Access üretir; receipt executor'ın |
| LFP-23 | Çalışma zamanında yorumlanan auth flow'dan adım silmek bypass üretir | Keycloak #40744 | Assurance semantiği (F17) | Tipli kimlik doğrulama durum makinesi (§10). Sunucu adım sırasına bağlı karar vermez; güvenlik yalnız gereksinim listesinin tamamlanmasına bağlıdır (TN-132), bu hata sınıfı yapısal olarak oluşmaz. Ping/ForgeRock ve Agama incelemesi yalnız sunucu tarafı akış dizme (TN-105) yeniden açılırsa gereklidir |
| LFP-24 | Kiracı şablonu/betiği sunucuda kod çalıştırır (RCE) | Keycloak FreeMarker; WSO2 adaptive auth; Zitadel actions; authentik expression policies | F23 | Must-never #15 |
| LFP-25 | Regex/wildcard redirect eşleşmesi saldırgana yönlendirir | authentik CVE-2024-52289 | RFC 9700 | Must-never #16 |
| LFP-26 | Kiracılar arası paylaşılan imza anahtarı + çakışan `client_id` | Storm-0558, CVE-2026-23552 (gün-1 kararları #4, #5) | Kapsam dışı anahtarın kabulü (HL-8, MD-6) | Realm başına anahtar seti; global `client_id`; verifier DomainID/issuer kontrolü (MD-6) |
| LFP-27 | İsim tabanlı yetkilendirme yeniden adlandırmada kırılır | CVE-2026-19608 | Opak kimlik | Opak kimlik / tam yol (→ §12) |
| LFP-28 | Handler başına yetki filtresi bir endpoint'te atlanır | CVE-2026-17059 | Veri katmanı filtresi | Tipte kodlanmış veri katmanı filtresi; domain/tenant kapsamı olmayan sorgu derlenemez (MD-2; → §12, §16) |
| LFP-29 | Servis masası ele geçirilince hesap ele geçirilir (admin credential belirler) | Admin'in credential belirlediği servis masası akışları (Kanidm modeli karşıtı) | Kurtarma güvencesi | Must-never #17 |

### 4.13 MKT kararları (§4 ek ailesi)

Her satır §3.1c alanlarının özetidir. Tam gerekçe ilgili alt bölümdedir.

| ID | Karar | Statü | Gerekçe (kısa) | Kabul testi / karşı örnek | Yer |
|---|---|---|---|---|---|
| MKT-1 | Landscape iki parçalıdır: authority landscape (L1–L28) ve identity landscape (§4.5–§4.11); L2'nin evrensel-olmayan dili ikisine uygulanır | FROZEN LANDSCAPE | Authority semantiği ile IdP pazarı farklı sorular sorar; tek verdict ikisini karıştırır | Karşı örnek: tek landscape'in iki soruyu birlikte cevaplayabildiğinin gösterilmesi | §4.1 |
| MKT-2 | Access identity tarafında kategori 1, 5, 7'yi; authority tarafında kategori 6'nın karar kısmını ve "authority layer"ı kapsar. Kategori 2, 3, 4 teslim modeli veya kısmi karşılıktır (çıkarım) | FROZEN LANDSCAPE (kapsam); kategori olarak satın alınması H1 | F21 + L2 | Karşı örnek: kapsanan bir kategorinin gereksiniminin karşılanamaması | §4.5 |
| MKT-3 | IdP pazar envanteri bilgi amaçlıdır; eskir etiketi taşır; `?` doğrulanmadı; lisanslar yargılanmaz; tam liste normatif ek referansıyla bağlıdır | WATCH (güncelleme döngüsü) | Envanter karar gerekçesi değil bağlamdır | Kabul testi: her kullanımda tarih ve kaynak beyanı | §4.6 |
| MKT-4 | Farklılaşma maddeleri HYPOTHESIS'tir; her biri karşılaştırma kümesi ve geçersiz kılacak karşı örnek taşır; "örnek bulunamadı ≠ ilk biz" | FROZEN LANDSCAPE (kural); maddeler H | Bir farklılaşma maddesinin (MKT-D1) karşı örnek alanı olmadan aylarca yanlış kalabilmesi | Karşı örnek alanı boş bir maddenin yayımlanması kural ihlalidir | §4.7; §3.4 |
| MKT-5 | Access identity plane'i kurar; semantiği bozmayan yerde kütüphane alır; SAML/SCIM interop bakımı RR olarak beyan edilir | FROZEN LANDSCAPE | Identity ≠ Authority ve tek yazma yolu hazır IdP modeliyle sağlanamaz | Karşı örnek: hazır bir IdP'nin veri modelinin INV-12 ve MD-14'ü sağlaması | §4.9 |
| MKT-6 | §4.8'deki 11 seçim ekseni identity plane segment gereksinimidir | FROZEN LANDSCAPE (liste); segment önceliği H | Seçim rehberi alıcı gereksinimlerinin en iyi kaynağı | Karşı örnek: pilotlarda listede olmayan belirleyici bir eksen | §4.8 |
| MKT-7 | Pazar konumlandırmasının dışında tutulan alanlar (dikey ürünler, uyum ürünleri, hafif IdP konumlandırması) yetenek dışlaması değil konumlandırma hipotezidir | Kural FROZEN; içerik H17 | Konumlandırma ile yetenek kapsamı ayrı kararlardır | Karşı örnek: listenin bir yeteneğin düşürülmesine gerekçe yapılması | §18.8 |
| MKT-8 | Identity plane performans hedefi EA'dır; satış dilinde garanti değildir | ENGINEERING ASSUMPTION | Ölçüm henüz yeniden üretilmedi ("yeniden üretim bekliyor") | Kabul testi: §3.1d koşulları | §4.10 |
| MKT-9 | Standart olgunluk statüleri Access'in "doğrulanmadı" disiplinindedir; protokol kararları §9.4 ve §10'dadır | FROZEN LANDSCAPE | Statü etiketleri hızla eskir | Karşı örnek: doğrulanmamış statünün invariant dilinde kullanılması | §4.11 |
| MKT-10 | ID-JAG / Cross App Access parite kalemidir; identity assertion olarak üretilir ve tüketilir; Access'in ürettiği ID-JAG authority scope içermez; authorization grant semantiği reddedilir | FROZEN LANDSCAPE | Okta Agent SSO GA ile farklılaşma düşmüştür | Karşı örnek: ID-JAG'ın grant olarak kabul edildiği bir akış (MD-18 ihlali) | MD-18; §4.2 L27 |
| MKT-11 | LFP-1–LFP-29 landscape'in kanıt ekidir ve identity plane'e de uygulanır | FROZEN LANDSCAPE | Bilinen başarısızlık kalıpları karşı önlemlerin kanıtıdır; identity plane kalıpları gün-1 kararlarının gerekçesidir | Karşı örnek: bir LFP'nin karşı önleminin ilgili bölümde bulunmaması | §4.12 |
