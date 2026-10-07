## 5. Canonical Ontology / Conceptual Architecture

Access'in semantiği yedi authority primitive'i, bir policy construct'ı, üç kayıt türü ve bunların değerleri üzerine kuruludur. Kanonik olan kayıtlardır; güncel authority graph'ı kayıtların deterministik projection'ıdır (C2). Primitive'lerin **içeriği** onları yaratan ve değiştiren kayıtlarda durur; **durumları** türetilir.

**Merkezi kararların ontolojiye etkisi.** Aşağıdaki merkezi kararlar ontolojiyi etkiler. Hiçbiri yeni authority primitive'i eklemez.

| Karar | Ontolojiye etkisi | İşlendiği yer |
|---|---|---|
| MD-4 | Pozitif yetki yalnız Grant lineage'ından gelir. Identity plane'in kullanıcı/grup/rol/ReBAC kavramları mevcut primitive'lere eşlenir. Zanzibar/Leopard motoru türetilmiş graf indeksi (bileşen CMP-9) ve sorgu motoru (bileşen CMP-11) olarak kullanılır ve commit-mode ALLOW üretmez. RestrictionPolicy dili Cedar'ın forbid-only alt kümesidir | §5.4, §5.8, §5.17, INV-2, INV-8, TI-5, TI-14, INV-33, INV-34, INV-36 |
| MD-5 | Dört eksen: Tenant (ticari, semantik değil), AuthorityDomain (authority semantiğinin tek birimi), Identity Realm (identity plane'in "kiracı"sı), Cell (fiziksel yerleşim). Credential ve login tanımlayıcısı realm'e yereldir. Realm'ler arası bağ yalnız açık IdentityBinding ile kurulur | §5.1 ekleri, §5.6, §5.12, §5.14, §5.16, INV-12, INV-32, INV-37 |
| MD-10 | Domain dışına çıkan her projection ve PAP'ta PartyRef domain-pairwise türetilmiş takma addır (value düzeyinde). İç PartyID değişmez | §5.3 eki, §5.18, PI-8, INV-38 |
| MD-13 | Access tam bir IdP'dir (identity plane) ve onun üstünde authority plane'i olan üründür. Identity plane nesneleri (realm, user record, credential, session, client) identity plane nesneleridir, authority primitive'i değildir | §5.1 eki, §5.12, §5.16 |

Ontolojiyi etkileyen diğer merkezi kararlar:
- MD-7: ValidityContract identity plane token'larını da kapsar; epoch'lar mekanizmadır (§5.3, §5.11).
- MD-8: fail-closed her yerde (INV-26).
- MD-9: bürünme yoktur; destek erişimi Grant'tır (§5.7, INV-28).
- MD-11: uygulama-kontrollü faktör bir assurance sınıfıdır (§5.3 Assurance).
- MD-14: identity plane yapılandırması domain action'ıdır (§5.12, INV-12, TI-15).
- MD-15: release kapısı (TI-RT12).
- MD-18: UUIDv7 iç ID, dışa açık ID'ler opak; ID-JAG yalnız assertion/Claim taşıyıcısıdır (§5.3, §5.13).
- MD-19.1: INV-4 tam metniyle geçerlidir.

**Bileşen etiketleri (MD-19.5).** Ontology kararları "C*n*" biçimindedir (C1–C34), **C15 dahil** (C15 = delegability kararı, §5.15). Bileşenler §16'da "CMP-*n*" biçimindedir. Bu bölümde CMP-9 = Derivation Workers + Derived Store, CMP-11 = Query Service, CMP-15 = Identity plane'dir. Eşleme §16.3.3 tablosundadır.

### 5.1 Canonical primitive set

Yedi authority primitive ve bir policy construct. Her biri altı testi geçer: kendi kimliği var, kendi lifecycle'ı var, diğerlerinden deterministik türetilemez, source of truth olmak zorunda, silinirse semantik bilgi kaybolur, Access'in fundamental problemine ait. Primitive'lerin **içeriği** onları yaratan ve değiştiren kayıtlarda durur; **durumları** türetilir.

| Primitive | Why it must exist | Identity | Lifecycle | Source of truth |
|---|---|---|---|---|
| **AuthorityDomain** | "Bir authority object için tam olarak bir authoritative lineage" kuralının kapsamı (CI-15). Foreign acceptance, kayıt sıralaması ve provider bağlılığı ona referans verir | `DomainID`, genesis kaydıyla doğar; provider değişse de aynı kalır | genesis → active → (constitution amend, provider handover) → terminated | Genesis record + domain meta-anchor üzerindeki meta-Exercise'lar |
| **AuthorityAnchor** | Domain'de yaşamayan bir resource scope'u üzerindeki positive authority'nin başlangıç noktası. Root, Anchor'ın değeridir (`Sole(Party)` / `Joint(Parties, k, independence)`). "Owner attribute" değildir | `AnchorID`; resource scope (ResourceRef, namespace veya domain'in kendisi) + domain | create (covering root'un veya genesis'in exercise'ı) → active → root transfer / composition amend (her biri explicit disposition ile) → retired | Anchor create/transfer/retire Exercise'ları |
| **Grant** | Positive authority'nin explicit, provenance taşıyan türetilmesi; delegation'ın tek temsili. Rule-shaped (intensional) ve extensional biçimler aynı primitive | `GrantID`; basis + holder selector sabit. İçerik revizyonları aynı kimlikte, append-only | issue → (pending →) active ⇄ restricted (overlay) → amended* → revoked / expired / renounced (yalnız extensional) (terminal); holder bazında: holding episode'ları açılır ve terminal olarak kapanır (derived) | Grant issue/amend/revoke Exercise'ları + lineage + claim'ler (holder set, holding episode'ları ve validity türetilir) |
| **Mandate** | Holding ≠ exercisability (CI-5). Bir Party'nin tuttuğu authority'nin belirli bir Instance'ında kullanılabilecek sabit zarf. Lineage'a girmez | `MandateID`; tam bir Instance'a bağlı, Instance değişmez | bind → active → narrowed / rebound (widening, explicit) → ended (revoke, expiry, instance termination; terminal) | Mandate bind/rebind/revoke Exercise'ları |
| **Instance** | Authority'nin exercise edildiği somut authenticated execution / sign-in bağlamı. Mandate'in hedefi, exercise'ın actor'ü | `InstanceID`; Party'ye sabit bağlı. KeyBinding değişse de continuity kanıtlanırsa aynı kalır | genesis (ceremony) → active ⇄ restricted → rekey* → terminated / recovered→successor (terminal) / expired | Instance genesis/rekey/recover/terminate Exercise'ları |
| **Acceptance** | Trust'ın tek kesin anlamı (F4): explicit, scoped, revocable issuer acceptance. Dış iddiaların ve foreign authority kanıtlarının hangi amaçla girdi olabileceğini belirler | `AcceptanceID`; issuer + use sabit, scope revize edilebilir | establish → active ⇄ restricted → narrowed / expanded (meta) → revoked / expired | Acceptance Exercise'ları |
| **Authority Exercise** | Unit of value. Bir actor'ün (ActorContext), belirli bir basis'i, beyan ettiği bir capacity'de, belirli bir intent için, belirli bir trusted anda **committed ve relied-upon** olarak kullanması; authority state değişikliklerinin de taşıyıcısı. Advisory evaluation ve DENY Exercise değildir | `ExerciseID` = domain içinde intent nonce'a bağlı; aynı nonce + farklı intent ifade edilemez. Pending transaction (REQUIRE_ACTION) aynı nonce'u taşır, ama Exercise ilk ALLOW commit'inde doğar | ALLOW commit (doğum) → continuation* → closed (horizon / intent expiry / continuation DENY); consumption release ve outcome attestation sonradan bağlanır | Nonce'a bağlı DecisionRecord'lar (ilk committed ALLOW ve sonrası) |
| **RestrictionPolicy** *(policy construct; primitive testlerini geçer ama sınıfı policy'dir)* | Positive authority'den bağımsız deny / require / narrow. Authority-side ve actor-side kısıtların tek yeri | `PolicyID`; içerik sürümlü | set → version* → detached / retired | policy.set Exercise'ları |

**Primitive olmayanlar, bilinçli olarak:** Party (PartyRef: product-neutral external identity reference), ActorContext (value), AgencyTerms ve ExerciseCapacity (value), Authorization Evaluation (derived result), Claim (record), Decision (value + record), Intent (value), Requirement (value), Budget (value + derived), AuthorityStateBasis (value), Evidence (rol), Approval (derived), Quorum (derived), Role (value), Credential (projection), Revocation (meta-Exercise), Resource (external ref), Action (namespace value).

RestrictionPolicy'nin tabloda yer alması bir istisna değil, bir dürüstlük notudur: kimliği, sürümleri ve source-of-truth zorunluluğu var, ama **sınıfı POLICY CONSTRUCT'tır** ve positive authority üretmez. Primitive sayımı **yedi authority primitive + bir policy construct** olarak okunmalıdır.

**Identity plane nesneleri primitive değildir.** Identity plane tam bir IdP'dir. Şunlar **identity plane nesneleridir**: Tenant, Identity Realm, Cell, user record, credential (parola hash'i, passkey, TOTP sırrı…), login tanımlayıcısı, oturum, OAuth/OIDC client, upstream IdP bağlantısı, IdentityBinding kaydı. Kimlikleri ve lifecycle'ları identity plane'dedir (§10, §12). Authority plane'e etkileri yalnız mevcut sınıflarla ifade edilir:
- Claim: authentication, authenticator-binding, identity-binding, membership.
- Instance: oturumun bağlı olduğu authority-binding bağlamı. Bir identity plane oturumu cihaz başına tam bir insan Instance'ına bağlanır; oturum Instance değildir. Oturum yenilemek veya oturum süresinin dolması yeni Instance değildir, authentication Claim tazeliğidir (C8, §12). Sign-out oturumu bitirir ve o Instance'ı sonlandırır; bu temizliktir, başka Instance'ların authority'si etkilenmez (XI-23).
- PartyRef: kullanıcının authority tarafındaki referansı.
- Domain action: identity plane yapılandırma değişiklikleri (MD-14). Realm'in yönetişim domain'inde karar alır; meta-Exercise değildir (§5.12, §5.16).

Altı test bu nesnelerin hiçbirinin authority primitive'i olmasını gerektirmez. Her biri ya identity plane'in kendi source of truth'udur (§5.12) ya da authority plane'de Claim, value veya derived'dır. Eşleme tabloları §5.16 ve §5.17'dedir.

**AuthorityDomain ve kiracılık eksenleri.** AuthorityDomain'in semantiği T27'dir: authority semantiğinin tek birimidir ve DomainID genesis digest'idir. "Kiracı" iki ayrı şeye bölünür: ticari **Tenant** ve identity plane'in **Identity Realm**'i. Fiziksel izolasyon savunma derinliğidir, semantik değildir: bileşik PK'de `tenant_id` + `domain_id`/`realm_id`, bileşik FK, RLS FORCE, NOBYPASSRLS, `SET LOCAL`. Bir domain hiçbir zaman iki tenant'a yayılmaz. Fiziksel anahtarlama kuralı: `tenant_id` + RLS FORCE identity plane, derived, PII vault ve operasyon tablolarında zorunludur; authority canonical log'u ve kayıtları `domain_id` ile anahtarlanır ve tenant↔domain eşlemesi placement directory'dedir (append-only log, ticari hesap değişince yeniden anahtarlanamaz; OP-12). Ayrıntı §5.16'da, fiziksel kurallar §12 ve §17'dedir.

### 5.2 Canonical record set ve iki corpus

Access'in semantik source of truth'u üç kayıt türünden oluşur: Genesis, Exercise (nonce'a bağlı opening record + DecisionRecord'ları tek tür sayılır) ve Claim. Hepsi **immutable (existence, attribution, lineage, digest), attributable ve append-only**'dir. Hiçbiri yerinde değiştirilmez; düzeltme yeni kayıtla yapılır.

**İki corpus:**

| Corpus | İçerik | Nasıl yazılır |
|---|---|---|
| **Authority state** | Genesis + meta-action Exercise'ları; bunlardan türeyen Anchor, Grant, Mandate, Acceptance, RestrictionPolicy, Instance authority-binding lifecycle, budget terms, authority configuration | Yalnız authorized meta-Exercise'ın committed ALLOW'u |
| **Claim corpus** | Dış issuer'ların (HR, MDM, Commerce, Executor, IdP, attester) ve domain'in kendisinin attributable Claim'leri | Dış Claim: ingest (Exercise değil). Domain-issued Claim (ör. local membership): `claim.issue` meta-Exercise'ı. Her grubun (membership class örneği) tek bir üyelik issuer'ı vardır; `claim.issue` yalnız domain-local grubun üyeliğini yazar (§5.17 grup sahipliği) |

Claim ingest authority mutation değildir: bir Claim positive authority üretemez, hiçbir authority-state nesnesini değiştiremez ve karara yalnız aktif, scoped bir Acceptance kapsamında girer. Bir claim'in *seçimi* değiştirmesi (rule-shaped Grant'ın holder set'i) authority state değişikliği değildir; aynı Grant'ın derived extension'ının değişmesidir ve o kapıyı açan Acceptance zaten bir meta-Exercise'la kurulmuştur.

**Kayıt kuralı:** Advisory evaluation canonical tarih olmak zorunda değildir. DENY ve REQUIRE_ACTION, auditable veya security-significant ise nonce'a bağlı evaluation DecisionRecord'u olarak kaydedilebilir, ama bir Authority Exercise değildir.

| Record | Yazan | Ne kaydeder | Neyi kaydetmez | Not |
|---|---|---|---|---|
| **Genesis** | Domain'in kurucu root holder'ları (katkılarıyla) + provider'ın custody attestation'ı (authority değil) | DomainID, ilk meta-anchor ve root kompozisyonu, kurucu agency Grant'ları, bootstrap Grant'ları (public/self selector), ilk Acceptance'lar, reserved power tanımları, meta-action requirement'ları | Provider'a authority | Domain başına tek. Regress'in bittiği yer: genesis'in meşruiyeti dışsaldır (hukuki/örgütsel gerçeklik), içeride tartışılmaz; sonrası yalnız Exercise |
| **Exercise opening record** | Access (authoritative decider), actor'ün talebinden | nonce, ActorContext (`Authenticated(I)` / `Anonymous(ctx)`), basis referansı, beyan edilen ExerciseCapacity, IntentEnvelope (veya digest + redaksiyon edilebilir body), sunulan proof referansları | Effect, effect sonucu | Talep ilk kaydedilen DecisionRecord ile kayda girer; Authority Exercise'a ancak bir ALLOW commit edilince dönüşür |
| **DecisionRecord** | Access | outcome (ALLOW / DENY / REQUIRE_ACTION + yapılandırılmış eksikler), cited proofs, AuthorityStateBasis, trusted evaluation time, validity contract (yalnız reusable ise), consumption effects (draw, single-use tüketimleri), meta-action ise uygulanan state change | Effect'in gerçekleştiği | Bir nonce'a 1..n DecisionRecord bağlanır: evaluation (DENY / REQUIRE_ACTION, kaydedilirse), ALLOW commit (Exercise'ın doğumu), continuation, release |
| **Claim** | Issuer (dış veya domain'in kendisi); Access ingest eder | issuer, subject, claim class, value veya digest, issuedAt, validity, attribution kanıtı, ingest zamanı, (varsa) supersedes | Gerçeğin kendisi | Access gerçeği değil, *kimin neyi iddia ettiğini* kaydeder |

**Revocation neden ayrı bir record türü değil?** Çünkü revocation bir authority-sensitive action'dır (L11) ve yazan, yetkisi ve zamanı olan bir Exercise olarak zaten kayda girer: `grant.revoke(G)` Exercise'ının ALLOW DecisionRecord'u revocation'ın kendisidir. Aynı mantık şunlara uygulanır:

| Aday kayıt | Bu modelde |
|---|---|
| Revocation record | `grant.revoke` / `mandate.revoke` / `acceptance.revoke` Exercise'ı |
| Grant issuance record | `grant.issue` Exercise'ı (intent payload = Grant içeriği) |
| Supersession / amendment | `grant.amend` Exercise'ı (aynı GrantID, yeni revizyon) |
| Approval / contribution | `contribute(intentDigest)` Exercise'ı (approve bir contribution sınıfıdır) |
| Consumption record | ALLOW DecisionRecord'un consumption effects alanı |
| Budget release | `consumption.release(ExerciseID)` Exercise'ı, grounded non-execution Claim'i zorunlu |
| Instance genesis / recovery | `instance.create` / `instance.recover` Exercise'ları |
| Key rotation / continuity event | `instance.rekey` Exercise'ı (mevcut KeyBinding ile authenticated) |
| Local membership | `claim.issue(membership)` Exercise'ı; etkisi domain'in issuer olduğu bir Claim. Yalnız domain-local gruplar için: issuer'ı identity plane veya bir upstream olan grubun üyeliği `claim.issue` ile yazılamaz (§5.17 grup sahipliği) |
| Semantic events (revoked, narrowed, expired, budget-exhausted, mandate-ended) | Derived notification; transport'u projection (SSF/CAEP) |

**Access-internal action'larda Decision ve effect neden aynı commit'te?** Çünkü authority state'inin domain'i Access'tir. Bir `grant.issue` için Access hem decider hem PEP'tir; effect (Grant'ın var olması) DecisionRecord'un kendisidir. Domain action'larında (refund, transfer, read) effect Executor/domain'dedir ve Decision ≠ Effect tam olarak korunur. Bu ayrım Model B'yi değiştirmez; Model B'nin Access'in kendi domain'ine uygulanmış hâlidir.

**Önyükleme (bootstrap) yolu yoktur.** "İlk yöneticiyi kim yaratır?" sorusunun cevabı Genesis'tir (C4). Genesis domain başına tek unconditioned kayıttır ve kurucu root'larıyla, ilk Acceptance'larıyla birlikte bir kez, imzalı olarak kurulur. Sonrası yalnız Exercise'tır. Identity plane'in ilk realm yöneticisi de aynı yoldan yetkilenir: Genesis'teki bootstrap Grant'ı veya kurucu root'un sonraki Exercise'ı (MD-14). Ayrı bir bootstrap yazma yolu kalıcı bir arka kapı olurdu; bu yüzden yoktur (INV-2). Kurulum UX'i → §12. Genesis protokolü → §9.

**DecisionRecord ve karar günlüğü.** Karar günlüğü ve örneklenmiş karar izi operasyonel telemetridir (TI-18, SEC31). Relied-upon ALLOW'un kanonik kaydı DecisionRecord'dur. Telemetri bu kayda baskın gelmez ve karar girdisi değildir.

### 5.3 Canonical value / envelope tipleri

Kimliği içeriğinden ibaret, lifecycle'sız değerler. Primitive ve record'ların içinde yaşarlar.

| Value | Nerede yaşar | İçerik (semantik minimum) | Neden primitive değil |
|---|---|---|---|
| **ResourceRef** | Anchor scope, AuthoritySet, Intent | domain namespace + domain-owned resource id + incarnation | Resource domain'indir; Access yalnız atıf yapar. Incarnation, silinip aynı id ile yeniden yaratılan resource'un eski authority'yi miras almasını engeller. İç kimlikler UUIDv7'dir, dışa açık kimlikler opaktır. Bu ek bir savunmadır; semantik koruma incarnation'dır |
| **ActionRef** | AuthoritySet, Intent | namespace + action name + schema version; reserved bayrağı schema'dan gelir | Action vocabulary'si domain'in (core meta-action'lar Access'in); kimliği isim+sürüm |
| **SubjectSelector** | Grant holder, delegation terms, requirement source | `Party(ref)` (extensional) · `Pred(φ)` (intensional; φ yalnız subject-selection Acceptance'ı olan claim class'ları üzerinde, canonical selector dilinde) · `Public` · `ForeignAuthority(domain, authorityClass)` | Seçici bir değerdir; seçtiği küme derived'dır |
| **AuthoritySet** | Grant, Mandate envelope, Anchor scope | {actions} × resource selector × parameter bounds (typed) × recipient/counterparty selector × purpose set | Attenuation algebra'nın taşıyıcısı; kendi lifecycle'ı yok |
| **ConstraintSet** | Grant, Mandate | validity window, while-conditions (ör. instance yaşadığı sürece), budget terms | Değer |
| **DelegationTerms** | Grant | `delegable: bool`, `depth: ℕ` (opsiyonel, kalan derinlik), `downstreamHolderClass: SubjectSelector` (opsiyonel) | Değer; `delegable=false ≡ depth=0` |
| **RequirementSet** | Grant, Anchor root terms, Mandate, policy output, REQUIRE_ACTION | requirement term'leri | Kimliği/lifecycle'ı yok; karşılanması proof'larla olur |
| **BudgetTerm** | Grant, Mandate ConstraintSet | dimension (count / amount+unit), capacity, window kuralı | Kimlik = (lineage node, term); kalan miktar derived |
| **IntentEnvelope** | Exercise | action, resource(s), typed parameters, recipient, purpose, context refs (WorkRef/StepRef/PlanRef opaque), validity window, nonce; digest canonical içerikten türetilir | Exercise'a hash-bound immutable değer; kendi lifecycle'ı yok |
| **AuthorityStateBasis** | DecisionRecord | okunan canonical nesnelerin (object, version/position) kümesi + trusted evaluation time + bağımlılık zaman sınırları | Kararın metadata'sı; tek global epoch değil |
| **ValidityContract** | DecisionRecord (reusable ise), projection'lar | horizon (≤ en erken bağımlılık sınırı ve profil max staleness), freshness profili, re-validation koşulu | Değer. Identity plane token'ları dahil (ID/access/refresh token, oturum çerezi) bütün yeniden kullanılabilir artefaktların semantik sözleşmesidir. `session_epoch` ve `key_epoch` mekanizmadır; ValidityContract'ın yerine geçmez |
| **Assurance** | Claim value, Requirement, Acceptance floor | method class (ör. phishing-resistant; uygulama-kontrollü faktör = app PIN + app anahtar çifti), human presence, binding strength, issuer assurance, age | Teknoloji değil semantik; passkey/WebAuthn/OIDC bunu doldurmanın yolları. Platform biyometrisi tek başına güçlü kimlik doğrulama unsuru sayılmaz |
| **PurposeRef** | AuthoritySet, Intent | typed purpose code veya opaque referans (WorkRef/AimRef) | Algebra'da yalnız eşitlik/küme üyeliği; serbest metin asla. Serbest gerekçe metni (ör. destek erişiminde zorunlu gerekçe) intent'in redakte edilebilir gövdesinde veya WorkRef'te zorunlu alan olarak durabilir. Değerlendirmeye girmez |
| **HoldingRef** | Grant basis, Exercise basis, Mandate pin, DecisionRecord | `⟨GrantID, holder PartyRef, since⟩`; `since` = holding episode'unu açan canonical geçiş (extensional: Grant'ın created-by Exercise'ı; dinamik selector: qualification'ı false→true yapan Claim ingest'i veya Acceptance / Grant Exercise'ı) | Derived bir episode'un kararlı koordinatıdır; kendi lifecycle'ı yoktur, episode'un durumu kayıtlardan türer |
| **ActorContext** | Exercise opening record, DecisionRecord | `Authenticated(InstanceID)` veya `Anonymous(context)`; context = kanal, network, rate, transport assurance gibi actor-independent bağlam | Actor'ün beyanıdır; lifecycle'ı Instance'ındır veya yoktur. Anonymous bir Instance değildir, hiçbir şey tutmaz |
| **AgencyTerms** | Grant (AnchorRoot için örtük {OWN}) | `set of capacities ⊆ {OWN, FOR(PartyRef)}`. OWN: holder kendi adına exercise eder. FOR(Q): holder Q adına exercise eder | Grant'ın bir terimi; agency continuity kuralına tabi |
| **ExerciseCapacity** | Exercise opening record | `OWN` veya `FOR(PartyRef)`; basis Grant'ın AgencyTerms'ünde olmak zorunda | On-behalf-of'un tek kaynağı; Exercise'ın açık beyanı |
| **Named AuthoritySet (role/template)** | Grant içinde sürümüyle pin'lenir | isim + sürüm + AuthoritySet | Canlı dolaylılık yok: rol tanımını değiştirmek Grant'ları sessizce değiştiremez |

**Rol.** Rol (`admin`, `editor`) bir named AuthoritySet sürümüdür. Rol ataması o sürümü pin'leyen bir Grant'tır (extensional veya rule-shaped). Identity plane token'ındaki rol claim'i bir projection'dır ve tek başına yetki kanıtı değildir.

**PartyRef'in domain dışı biçimi.** PartyRef bir değerdir ve yeni bir primitive gerektirmez. Domain içinde PartyRef, Party Identity Regime'deki kimliğe atıf yapar (E4). Domain dışına çıkan her projection'da (token, PAP, Decision Receipt, export'ta audit altı görünüm) Party, **domain-pairwise türetilmiş bir takma ad** ile gösterilir: `PartyRef_ext = f(domain_key, PartyID)`. Bu takma ad aynı domain için kararlı, farklı domain'ler arasında ilişkisizdir. İç PartyID değişmez; lineage, holding episode ve budget ledger iç PartyID üzerinden tutulur. Türetim fonksiyonu ve anahtar yönetimi → §9 ve §15 (TI-RT10'daki domain başına opaque token deseniyle aynı aile; çıkarım). Kural INV-38'dir. Identity plane'deki pairwise `sub` (NIST 800-63C PPII) bunun identity plane karşılığıdır → §10.

### 5.4 Derived state

Canonical olmayan, ama ürünün ana yüzleri olan kavramlar. Hepsi canonical record'lar + kabul edilmiş claim'ler + trusted time + schema/profile sürümleri üzerinden **deterministik** hesaplanır. Hiçbiri kendi başına source of truth değildir; bir projection (index, cache) bunlardan biriyle çelişirse projection yanlıştır.

| Derived concept | Nasıl türetilir | Bağlam bağımlılığı |
|---|---|---|
| Grant status (active / pending / restricted / revoked / expired / lapsed) | Grant Exercise'ları + lineage + time + restriction overlay | Lapse, subject-selection claim'lerine bağlı |
| **Holder set** of a Grant (`Holders(G,t)`: kim şu an qualify ediyor?) | Extensional: sabit. Intensional: selector'ın, aktif Acceptance kapsamındaki **asserted** (superseded / retracted / distrusted olmayan; freshness'tan bağımsız) claim'ler üzerinde değerlendirilmesi | Claim değişince *aynı Grant farklı küme seçer* |
| **Holding episode'ları** (`Holdings(G,t)`: hangi kesintisiz qualification üzerinden tutuyor?) | Qualified(G,p)'nin maksimal kesintisiz aralıkları; her biri bir HoldingRef ile adlandırılır | Affirmative disqualification episode'u bitirir; staleness bitirmez |
| **Effective authority** of a holder via a lineage | Lineage boyunca AuthoritySet ∩ ConstraintSet ∩ requirement birikimi; budget'lar lineage üzerindeki tüm terimlerden | Time, claim'ler |
| **Exercisable authority** of an Instance | Effective authority (Party'nin tuttuğu) ∩ Mandate envelope ∩ actor-side restriction ∩ karşılanabilir requirement'lar | Assurance freshness, posture claim'leri |
| On-behalf-of (principal) | `Exercise.capacity`: OWN ise actor Party'nin kendisi, FOR(P) ise P; basis Grant'ın AgencyTerms'üyle doğrulanır. **Lineage'dan türetilmez** | — |
| Authority provenance | Exercise basis'inin lineage'ı: authority kimden geldi. On-behalf-of'tan ayrı soru | — |
| Budget remaining | capacity − Σ draws (pencere içinde, lineage node başına) + Σ grounded releases | Time (pencere) |
| Instance status, Mandate status, Acceptance status | İlgili Exercise'lar + time + cascade | — |
| "Who can do Y?", "What can X reach?", "Why can X do Y?" | Graph sorgusu + proof inşası (lineage path + cited claims + acceptances + policies) | Claim'ler; sorgu zamanı |
| "What does revoking G affect?" | G'nin lineage alt ağacı + G'ye basis veren Mandate kapsamları + G'yi basis'inde taşıyan reusable Decision'lar ve projection'lar | — |
| Eligible approvers / contributors | `approve` / `contribute` authority'sini exercise edebilecek holder'lar | Work'e Gate için verilir |
| Current mandate coverage | Mandate envelope ∩ Party'nin güncel holding'i | — |
| Exercise outcome state (unattested / attested-conforming / attested-nonconforming) | Exercise + ilgili effect-attestation Claim'leri + envelope karşılaştırması | Receipt gelmeyebilir; *unknown* first-class |
| Revocation impact, staleness exposure | Revocation zamanı vs. projection validity contract'ları | Offline profile |
| Semantic events | Derived state'teki geçişlerin bildirimi | Transport = projection |
| ReBAC/relationship index, AuthZEN cevabı, token | Projection (sınıflandırması) | — |
| Tuple deposu, Leopard benzeri bitmap indeksi, ConsistencyToken/watch, sorgu motoru (check, search, explain, eligible set) | DERIVED index (bileşen CMP-9) ve sorgu servisi (CMP-11). Kanonik log + kabul edilmiş Claim'lerden türetilir. Commit-mode girdisi değildir (TI-5). Zanzibar/Leopard tasarımı bu katmanın tekniğidir | Okuma tutarlılık sınıfı (`at_least`/`as_of`, T11) → §9 |
| Identity plane token'ındaki rol/grup/org claim'i | Projection ⊆ (AuthoritySet ∩ Mandate). Kaba katmandır, tek başına kanıt değildir. Token'daki rol claim'i (named AuthoritySet ataması) bir Grant'ın projection'ıdır: ⊆ (AuthoritySet ∩ Mandate), `projection.issue` (S-1). Token'daki grup/org **üyeliği** bir identity Claim'idir (§2.2.2 (a)); authority taşımaz ve RP'ye authority kanıtı olarak sunulmaz. Seçim etkisi yalnız authority plane'de, Acceptance'lı rule-shaped Grant üzerinden olur (INV-16) | → §9.9 |
| Yetim (orphan) veya geçersiz tuple sayacı | Derived index metriği. Kanonik modelde canlanma ifade edilemez (INV-5, C16) | — |

**Determinism sınırı.** Derived state, *aynı* canonical kayıtlar ve *aynı* kabul edilmiş claim kümesi üzerinde deterministiktir. Dış dünyaya bağımlı olan şey claim kümesinin kendisidir: HR bir claim yayınlayınca bir intensional Grant'ın holder set'i değişir. Bu bağımlılık gizli değildir: her committed Decision kullandığı claim'leri ve acceptance'ları AuthorityStateBasis'inde listeler. Bir dış risk skoru ancak bir Claim olarak (issuer'ı belli, kabul edilmiş, kayda geçmiş) ve yalnız restriction rolünde karara girebilir.

**Türetilmiş katmanın tutarlılığı.** `MinimizeLatency` tutarlılığı (önbellekten servis) yalnız advisory yollarda geçerlidir: `check`, search, explain. Bu yolların cevabı `advisory=true` etiketi taşır. Commit-mode'da tutarlılık seçeneği yoktur, karar daima head'den verilir (TI-2, TI-3, TI-5). "İzin verme replica'ya yönlendirilebilir" kuralı reddedilir. Gerekçe: bir kararın revocation'dan etkilenip etkilenmeyeceği karardan önce bilinemez. Replica'dan verilen her ALLOW, replike olmamış bir revoke'u kaçırabilir. Türetilmiş katmanın kendi doğruluk kuralı INV-34'tür. Teknik ayrıntı → §9 ve §16.

### 5.5 Canonical relations

Yalnız kayıtlardan türetilemeyen ilişkiler canonical'dır. Yedi tane:

| Relation | From → To | Anlam | Sabit mi |
|---|---|---|---|
| **instance-of** | Instance → PartyRef | Bu execution bağlamı bu Party'ye aittir | Genesis'te sabitlenir, değişmez |
| **bound-to** | Mandate → Instance | Bu zarf yalnız bu Instance'ta kullanılabilir | Değişmez |
| **based-on** | Grant → basis (`AnchorRoot` veya `HoldingRef ⟨GrantID, holder, since⟩`) | Authority lineage'ın tek kenarı; dinamik holder'da belirli holding episode'una bağlanır | Değişmez; değişmesi yeni Grant demektir |
| **created-by** | Primitive (Grant, Mandate, Acceptance, Anchor, Instance, Policy) → Exercise | Nesnenin hangi authority exercise'ıyla doğduğu | Değişmez |
| **targets** | Meta-Exercise → primitive | Hangi nesnenin değiştirildiği (amend, revoke, rekey, transfer…) | Kayıtla sabit |
| **cites** | DecisionRecord → {Claim, contribution Exercise, Acceptance, Policy version, Grant revision, Mandate version} | Kararın dayandığı kanıt ve state | Kayıtla sabit |
| **succeeds** | Claim → Claim (supersession, aynı issuer/subject/class); Instance → Instance (recovery successor, tek) | Önceki kaydın yerine geçme; geriye dönük değil | Kayıtla sabit |

**Canonical olmayan ilişkiler ve nereden türedikleri:**

| Aday relation | Durum | Nereden |
|---|---|---|
| holds / grants-to | Derived | Grant holder selector + claim'ler |
| delegates / derived-from | = based-on | — |
| on-behalf-of | Derived | `Exercise.capacity` ∈ basis Grant AgencyTerms (lineage değil) |
| exercised-by | Exercise'ın attribute'u (actor) | Opening record |
| revokes / supersedes (Grant) | = targets | Meta-Exercise |
| accepted-from | Acceptance'ın attribute'u (issuer) | — |
| constrained-by | Grant/Mandate değerleri + policy attachment | — |
| concerns-resource | Anchor scope / Intent attribute'u | — |
| represents / controlled-by / sponsored-by / operated-by / member-of | **Claim** | Issuer'ı belli iddialar; authority değil |
| contributes-to | contribution Exercise'ının intent'i (hedef intent digest) | — |

Work ile ilişki: Work'ün sekiz canonical relation'ı (engaged-in, concerns, part-of, serves, supersedes, derived-from, on-behalf-of, references) Access'te kopyalanmaz. `on-behalf-of` Work'te canonical'dır; Access'te Exercise'ın açıkça beyan edilen ve basis Grant'ın AgencyTerms'üyle yetkilendirilmiş capacity'sinden türetilir. **Seam kuralı:** *Work'ün on-behalf-of atfı, açıkça yetkilendirilmiş exercise capacity ile uyumlu olmak zorundadır; authority provenance ayrıca incelenir.* Lineage root'u ile on-behalf-of eşleşmesi aranmaz: Alice'in Bob'a kendi kullanımı için açtığı paylaşım (provenance Alice, capacity Bob OWN) bir eşleşmezlik değildir.

**Claim güncelliği.** "Asserted", "yeni" ve "sonraki" Claim ifadeleri issuer sırasına göredir (TI-RT7), varış sırasına göre değil. Daha eski bir Claim kaydedilir ama asserting değildir. Sıra kaynakları açık `supersedes` zinciri, Party key-event pozisyonu veya taşıyıcı profilinin ayrıca tanımladığı monoton sıra alanıdır; sıra belirsizse disqualifying kazanır. Bu kural holder set'i, holding episode'larını (INV-16, INV-31) ve re-qualification'ı bağlar.

**Kaynak hiyerarşisi canonical relation değildir.** Tuple modelinde kaynak hiyerarşisi `doc#parent@folder` gibi bir tuple'la taşınır. Access'te bu hiyerarşi domain'in resource olgusudur (E14): ya domain-issued bir Claim'dir ya da bir ResourceRef selector'ıdır. Yetki mirası iki yoldan biriyle kurulur: Anchor scope iç içeliği veya resource selector'lu Grant. Hiyerarşinin değişmesi (taşıma, yeniden ebeveynleme) yeni bir canonical relation getirmez. Taşımanın authority sonucu aday INV-35 ile bağlanır.

### 5.6 Actor ve identity modeli

| Katman | Ontology | Not |
|---|---|---|
| Party (holder rolünde) | PartyRef — product-neutral, Party Identity Regime'deki kimliğe atıf | Access Party yaratmaz ve ikinci bir Party registry'si tutmaz (C5, E4) |
| Actor-capable Party | Derived kapasite | Organizasyonlar ve joint gruplar Instance'a sahip olmaz; org authority'si FOR(org) capacity'siyle exercise edilir (C6) |
| Instance | Primitive | Kimliği authority-binding sürekliliğidir; key rotation aynı Instance'tır, continuity kırılması yeni Instance'tır; recovery tek successor üretir ve authority miras bırakmaz (C8, INV-13) |
| ActorContext | Value | `Authenticated(InstanceID)` veya `Anonymous(context)`; Anonymous yalnız Public Grant kullanır, hiçbir şey tutmaz, quorum'a sayılmaz (INV-11) |
| Principal | Rol | On-behalf-of rolüdür; `Exercise.capacity`'den (basis Grant AgencyTerms ile yetkilendirilmiş) türetilir, lineage'dan değil; entity değildir (C5) |

IdentityBinding, authenticator binding, authentication event, runtime attestation, device posture, membership ve controller/sponsor/operator ilişkisi **Claim sınıflarıdır** (C7). InstanceID (Access-level mantıksal kimlik) ≠ KeyBinding (DPoP / mTLS / WIT `cnf` gibi güncel proof materyali) ≠ Attestation (Instance/anahtara bağlı runtime Claim'i) (L21).

**Identity plane kullanıcısı, oturum ve credential.**

| Identity plane kavramı | Authority plane karşılığı | Not |
|---|---|---|
| Kullanıcı (`users`), servis hesabı, ajan | Party (PartyRef) | Kullanıcı kaydı identity plane'dedir. PartyID bir regime referansıdır, global tablo değildir (E4, INV-12) |
| Login tanımlayıcısı, credential (parola, passkey, TOTP, sertifika) | Yok (identity plane nesnesi). Authority'ye etkisi yalnız `authentication` ve `authenticator-binding` Claim'idir | Realm'e yereldir: `UNIQUE(realm, …)`. E-posta asla anahtar değildir (MD-5) |
| Oturum (login oturumu, `DelegatedSession`) | Instance'ın authenticated bağlamı | Oturum lifecycle'ı (boşta kalma, yenileme, `session_epoch`) identity plane'dedir. Instance lifecycle'ı (create, rekey, terminate, recover) authority plane'dedir. `instance.terminate` ve `party.compromise` identity plane'de `session_epoch` artışını tetikler (MD-7). Oturum ↔ Instance eşlemesinin kesin biçimi → §12. **Kardinalite:** bir identity plane oturumu cihaz başına tam bir insan Instance'ına bağlanır; oturum Instance değildir. Sign-out oturumu bitirir ve o Instance'ı sonlandırır (`instance.terminate`); bu temizliktir, başka Instance'ların authority'si etkilenmez (XI-23). Oturum yenilemek yeni Instance değildir |
| Hesap durumu (`suspended`, `deactivated`, `tombstone`) | Claim (`account.status`). Domain'in varsayılan güvenlik politikası bu Claim'i, o realm üzerinden actor-binding'le kurulmuş Instance'lara DENY overlay olarak uygular (E5 restriction kanalı; actor gerektirmez; overlay Claim'in ingest pozisyonundan itibaren geçerlidir, kaldırılması genişletmedir, SI-4) | Durum identity plane'de değişir. Authority daraltması Claim ingest'i ve overlay ile gelir. `instance.terminate` ve departure temizliktir; güvenlik bunlara dayanmaz. UI metni garantiye uygun yazılır (XI-12). Ayrıntı → §7.1, §7.7, §12 |
| Hesap kurtarma | Authority plane'de **her zaman** yeni bir successor Instance (`instance.recover`; C8, INV-13). Eski Instance'ın Mandate'leri miras kalmaz; yeniden bağlama INV-40 kapısından geçer | Domain bunu yalnız sıkılaştırabilir (daha uzun cooling, rebind için ek requirement). Eski Instance'ın authenticator'ıyla authenticate edilmiş "cihaz ekleme" kurtarma değildir. Ayrıntı → §12 |
| Realm'ler arası hesap bağı (`identity_links.proof`) | IdentityBinding Claim'i + actor-binding Acceptance | Realm'ler arası bağ yalnız açık IdentityBinding ile kurulur (MD-5) |
| Hesap birleştirme | Bir identity-binding kaydı ve onun Claim'i | Party birleşmesi lineage birleştirmez (INV-39). Hesap birleştirme geri alınamaz; bağlama tercih edilir |
| Kullanıcı ID'sinin yeniden kullanılmaması | PartyID, realm-yerel `sub`, InstanceID ve ResourceRef yeniden atanmaz | Geri dönüştürülen bir tanımlayıcı, yeni sahibine eski hesabın erişimini devreder. Aday INV-32 |

`act` / `may_act` taşıyıcıları (RFC 8693) bir projection'dır. Önceki aktörler lineage'dan ve Exercise kayıtlarından doğrulanır. On-behalf-of token'dan değil, Exercise capacity'sinden türer (C12). Taşıyıcı profil → §9 ve §11.

### 5.7 Authority modeli

**AuthorityAnchor ve root.** Root bir değerdir: `Sole(Party)` veya `Joint(Parties, k, independence)`; Anchor'ın değeri olarak tutulur (C9). Anchor scope'ları domain içinde ayrık veya iç içedir; bir resource'un root'u onu kapsayan en özel Anchor'dadır; kapsanmayan resource'ta authority yoktur. Root transfer Anchor'a dayanan Grant'ların akıbetini açıkça belirtir; varsayılan yoktur (C10). Genesis domain başına tek unconditioned kayıttır; meşruiyeti dışsaldır; hosting provider root değildir (C4).

**Grant.** Bir basis'ten bir holder seçicisine AuthoritySet'i terimleriyle türeten kimlikli derivation edge'idir; tek basis'i vardır: AnchorRoot veya HoldingRef ⟨GrantID, holder, since⟩. Lineage bir ağaçtır; decision proof bir DAG'dir (C11). Grant devretmez: grantor yetkisini kaybetmez; tek holding semantiği vardır. Provenance ≠ capacity: Grant `agency ⊆ {OWN, FOR(PartyRef)}` taşır; Exercise capacity'si basis Grant'ın agency'sinde olmalıdır; agency continuity ile bir Grant yalnız OWN ve issuing principal için FOR verebilir (C12, INV-4). Root devri `anchor.transfer`'dır. Grant revizyonlu tek kimliktir; holder veya basis değişikliği yeni Grant'tır; budget ledger revizyonlar boyunca süreklidir (C16).

**Rule-shaped Grant.** Aynı primitive'dir. Claim değişince yeni Grant doğmaz; aynı Grant farklı bir holder kümesi seçer. Seçici yalnız subject-selection Acceptance'ı olan Claim class'larını kullanabilir. Holding, kesintisiz qualification episode'ları olarak derived'dır ve HoldingRef ile adlandırılır; affirmative değişiklik episode'u terminal kapatır, staleness kapatmaz (REQUIRE_ACTION), re-qualification yeni episode açar ve eski türevleri canlandırmaz (C13, INV-31).

**Mandate.** Holder Party'nin kendi Instance'ına bağladığı sabit zarf. Holding yaratmaz, lineage'a girmez, delege edilemez, Instance değiştiremez. Zarf içinde holding'i izler; genişleme rebind'dır; reserved sınıflar HoldingRef'e pin ister ve pin sonraki episode'a yalnız explicit rebind ile geçer (C14). Exercisable = Holding ∩ Mandate ∩ actor-side restriction ∩ karşılanabilir requirement'lar.

**Meta-authority.** Authority'yi değiştirmek kendisi bir Authority Exercise'tır (L11). Genişletme daraltmadan daha sıkı requirement taşıyabilir, tersi asla; bir requirement'ı gevşetmek mevcut (daha sıkı) requirement'ı karşılamayı gerektirir (INV-10). Reserved action'lar wildcard veya namespace prefix ile kapsanmaz (INV-9).

**Sahiplik.** `#owner` tuple'ı ve "org sahibi" kavramı Anchor root'una eşlenir. Bir kaynak, sahibinin Anchor'ı altında doğar; sahipliği ayrıca yazmaya gerek yoktur. Ayrı bir sahip gerekiyorsa ayrı bir Anchor kurulur. Root bir değer olduğu için **sahipsiz bir Anchor ifade edilemez**. "Veri katmanında ≥1 sahip" kuralı bu yüzden authority plane'de semantik olarak sağlanır. Org Party'sinin identity plane kaydı için ise kural identity plane'de kalır (§12). Root, hukuki sahip değildir (§8.11 "Owner"). Authority budget finansal değildir. Faturalama sahipliği Tenant eksenindedir (MD-5).

**Mandate pin varsayılanı.** C14 geçerlidir. Mandate'in zarf içinde holding'i izlemesi (snapshot almaması) bilinçli bir tercihtir ve zarfla sınırlıdır. Ancak geniş zarflı, uzun ömürlü bir agent Instance'ı Party'ye sonradan verilen non-reserved authority'yi sessizce kullanabilir. Bu yüzden kural şudur: **CT2 ve üstü action sınıflarında Mandate varsayılan olarak HoldingRef pin'i ister.** Statü: POLICY DEFAULT. Semantik aynıdır; pin'siz Mandate ifade edilebilir kalır. Değer ve CT tablosu → §13.7.1.

**Bürünme yok; destek erişimi ve istisnai yetki.** Kimliğe bürünme semantiği yoktur (X20). Destek temsilcisi için kural şudur:
- Destek temsilcisi kendi Instance'ıyla, kendi Party'si adına hareket eder.
- Kullanıcıya ait kaynaklarda bunu yalnız iki basis'ten biriyle yapabilir:
  - (a) Kullanıcının kendi Exercise'ıyla verdiği, iptal edilebilir ve kaskad eden bir FOR(kullanıcı) Grant'ı.
  - (b) Önceden verilmiş reserved break-glass Grant'ı (INV-28).
- Org politikasıyla rıza (`ConsentRecord::OrgPolicy`) yalnız organizasyonun kendi kaynaklarında, FOR(org) capacity'siyle geçerlidir. Gerekçe: agency continuity (INV-4). Organizasyonun kullanıcı adına rıza vermesi, on-behalf-of'u lineage'dan türetmek olurdu.
- Ayrıcalık kesişimi (ServiceNow modeli) yapısaldır: her Exercise'ın tek bir basis'i vardır.

12 destek değişmezi POLICY DEFAULT'tur: yasak işlem listesi = reserved dışlama, ≤ 60 dk, depth=0, SI-21 bildirimi, artefakt redaksiyonu, zorunlu typed PurposeRef ve diğerleri. Break-glass'ın politika muafiyeti örtük değildir: politikanın kendi içeriğinde beyan edilir (break-glass action sınıfını dışlayan koşul) ve o `policy.set` genişletme olduğu için CT3'tür. Ayrıntı ve operasyonel disiplin (≥2 hesap, 90 gün tatbikat) → §12.

### 5.8 Constraint / attenuation algebra

| Kategori | Boyutlar | Canonical algebra'da mı? | Attenuation yönü |
|---|---|---|---|
| **A. AuthoritySet (ne)** | actions (reserved dahil), resource selector, typed parameter bounds, recipient/counterparty selector, purpose set | Evet | child ⊑ parent |
| **B. Validity (ne zaman)** | validFrom/validUntil, while-conditions | Evet | child aralığı ⊆ parent aralığı; while-conditions birikir |
| **C. DelegationTerms (kime aktarılabilir)** | delegable, depth, downstreamHolderClass | Evet | parent delegable olmalı; depth kesin azalır; holder sınıfı ⊆ |
| **D. RequirementSet (ne sunulmalı)** | assurance, freshness, Claim requirement'ları, approval/co-authority/quorum, independence | Evet (normalize term kümesi) | child ⊒ parent |
| **E. BudgetTerms (ne kadar)** | count, amount+unit, window | Hayır (subset kontrolü yok) | Her exercise lineage'daki tüm budget'lardan düşer; amplification yapısal olarak imkânsız |
| **F. Restriction policy (yerel kısıt)** | analyzable her kısıt | Hayır | Yalnız DENY / REQUIRE; subset kanıtına giremez |

```text
Child ⊆ Parent ⇔
AuthoritySet(Child) ⊑ AuthoritySet(Parent)
∧ Validity(Child) ⊆ Validity(Parent) ∧ while(Child) ⊇ while(Parent)
∧ Parent.delegable ∧ depth(Child) < depth(Parent) ∧ holder(Child) ∈ downstreamHolderClass(Parent)
∧ Requirements(Child) ⊒ Requirements(Parent)
```

| Boyut | Constraint biçimleri (kapalı küme) | `⊑` |
|---|---|---|
| actions | finite set ∪ namespace prefix; reserved action'lar prefix'e dahil değil | küme kapsama; prefix kapsama reserved hariç |
| resource | ResourceRef ∪ namespace prefix ∪ intensional selector | kapsama |
| parameters | schema'nın beyan ettiği tipler: aralık, ≤/≥, enum kümesi, eşitlik, conjunction | tip bazında kapsama |
| recipient | SubjectSelector | kapsama |
| purpose | PurposeRef kümesi (eşitlik) | küme kapsama |

**Decidability.** Her boyutun constraint dili kapalı bir tip kümesidir; her tip için `intersect`, `⊑` ve `normalize` tanımlıdır ve sonlanır; conjunction dışında bağlaç yoktur; positive authority'de negation yoktur (L7); serbest predicate, Turing-complete ifade ve dış çağrı yoktur. Intensional selector dili Claim class'ları üzerinde eşitlik / küme üyeliği / sıralı karşılaştırma conjunction'larıyla sınırlıdır (INV-8). Closed attenuation type system: enum/set, equality, ordered numeric+unit, count, time interval, resource selector, subject selector, purpose set, boolean; eşlenemeyen authority-relevant parametre schema-definition Acceptance'ında reddedilir (E12).

**İki katmanlı güvenlik.** (1) Issue anında `Child ⊆ Parent` kontrol edilir; sağlanmazsa `grant.issue` DENY. (2) Evaluation anında effective authority lineage boyunca **intersection** olarak hesaplanır. İkincisi tek başına non-amplification'ı garanti eder; birincisi analiz, açıklanabilirlik ve portable chain doğrulaması için gereklidir.

```text
CanonicalAuthority: AuthoritySet ⊗ Validity ⊗ DelegationTerms ⊗ RequirementSet
typed, closed, decidable; ⊆, ∩, normalize tanımlı
→ positive authority'yi taşıyabilen tek dil; portable projection'lara ve subset kanıtlarına girebilen tek dil

RestrictionPolicy: analyzable dil (Access Restriction Profile = Cedar forbid-only alt kümesi;
spike başarısızsa CEL profili + SMT eşdeğerlik analizi, OQ-MD2)
girdi: Intent, actor, lineage, cited Claim'ler, derived state, time
çıktı: NO_OBJECTION | DENY(reason) | REQUIRE(RequirementSet)
→ positive authority üretemez, genişletemez
```

Decision = `if no valid basis covers intent → DENY; else combine(basis requirements, Mandate requirements, policy outputs)`, **deny-overrides**. Policy bir intent'i yalnız bastırabilir veya koşullandırabilir.

**Restriction dili (MD-4).**
- **Rol.** RestrictionPolicy forbid-only'dir. Çıktısı NO_OBJECTION, DENY veya REQUIRE'dır. Pozitif yetki üretemez (INV-1, INV-6, TI-14).
- **Somut dil: Cedar'ın forbid-only alt kümesi.** Sabit taban bir `permit`'tir; kullanıcı politikaları yalnız `forbid` olabilir. REQUIRE, forbid politikasına bağlı bir RequirementSet referansıyla ifade edilir: eşleşen politika DENY yerine REQUIRE üretir. Bu eşlemenin Cedar annotation'larıyla yapılabileceği bir **çıkarımdır**; birincil kaynakta yoktur. Spike ile kanıtlanır (OQ-MD2). Spike başarısız olursa CEL profili korunur ve ona SMT tabanlı eşdeğerlik analizi eklenir. cel-rust olgunluğu doğrulanmadı.
- **Gerekçe.** Cedar Lean'de kanıtlanmış 7 özellik ve SMT eşdeğerlik analizi sunar; OSV'de sıfır atlatma kaydı vardır. OSV iddiası 8 Eylül 2026 tarihli bir çekime dayanır ve yeniden doğrulanmadı. Kernel Rust olduğu için (MD-1) Cedar doğrudan gömülür. Forbid-only kısıtı, Cedar'ın "forbid trumps permit" özelliğiyle doğal olarak uyumludur.
- **Sınır.** Cedar'ın teoremleri Access'in pozitif cebirini (⊑, ∩, normalize) kapsamaz. Grant algebra'sının Lean modeli ayrıca yazılır (INV-8).
- **Analiz.** Polarite analizi (T13) korunur. Cedar SMT eşdeğerlik/kapsama analizi `policy.set` önizlemesine ve rol sürümü önizlemesine eklenir: "yetki değişti mi?" sorusu CI'da sorulur (≈75 ms; ölçüm doğrulanmadı). Restriction motoru → §16 (T13).
- **Sonlanma.** Statik maliyet sınırı Access'indir (TI-14, SI-20). Çözümleme kotaları (derinlik 25, genişlik 10, 100 ms, arama 1 s) türetilmiş indeks ve search içindir: ENGINEERING ASSUMPTION / POLICY DEFAULT → §9, §16. Dilden bağımsız kural aday INV-36'dır.
- **Koşullu tuple / ABAC koşulu.** Pozitif yetkideki bir koşul kapalı cebirde olmak zorundadır (INV-8). Ya AuthoritySet parametre sınırına veya while-condition'a çevrilir ya da RestrictionPolicy'ye taşınır. Pozitif yetki koşulu için Cedar çağrılmaz: zengin bir koşul dili ⊑ kanıtını ve portable subset kanıtını bozar.
- **Break-glass muafiyeti.** Deny-overrides kuralı geçerlidir. Muafiyet yalnız politikanın kendi içeriğinde beyan edilir (§5.7).

**Purpose** canonical algebra'da first-class bir boyuttur ama yalnız küme/eşitlik semantiği taşır; vocabulary domain'in veya Work referanslarıdır; iki purpose arasında "daha geniş" ilişkisi yalnız domain schema'sı açıkça beyan ettiyse (ve schema-definition Acceptance'ı varsa) kullanılır; serbest metin purpose authority sınırı olamaz (C23).

**Budget** = BudgetTerm value'su + derived remaining (C27). Bir exercise basis lineage'ındaki **her** node'un ve Mandate'in BudgetTerm'lerinden aynı anda draw yapar. Remaining = capacity − Σdraws + Σgrounded releases (pencere içinde). Release yalnız grounded non-execution veya daha düşük gerçek miktarın kabul edilmiş Claim'iyle olur ve bir Exercise/projection için Σrelease ≤ draw'dır (TI-RT8). Draw rezervasyonun kendisidir, release düzeltmedir; amend ledger sürekliliğini korur (sayaç sıfırlamak genişletmedir). Authority budget ≠ financial hold (F9).

**Consumption units.** Intent nonce, single-use Claim, single-use contribution, BudgetTerm kapasitesi, one-shot Grant (count=1), step-bound allowance, recovery slot. Her tüketilebilir birim için onu tüketen committed ALLOW'lar domain commit sırasında totally ordered'dır ve kapasiteyi aşmaz; AuthorityStateBasis'i commit anında birimlerin güncel durumunu yansıtmayan ALLOW commit edilemez (INV-21). Authority örtük olarak single-use değildir. Tek kullanımlık davet ve niyet token'ları birer consumption unit örneğidir: single-use Claim veya one-shot Grant.

**Named AuthoritySet (role/template).** Grant, named AuthoritySet'in sürümünü pin'ler; canlı dolaylılık yoktur; yeni sürüme geçmek her Grant için `grant.amend`'dir (C28). Model/şema evrimi (değişmez model kimliği, geçersiz tuple'ın yok sayılması) pin'li katalog ve Acceptance'lı şema ile karşılanır (E11, EI-16). "Yetim uyarısı" change-impact önizlemesinin bir satırıdır → §12.

### 5.9 Requirement, approval ve quorum

```text
RequirementTerm {
proofKind: Claim | Contribution(Exercise)
class: claim class | contribution class (approve, co-authorize, consent, …)
source: accepted issuer scope (Claim) | holders of AuthoritySet S (Contribution; eligibility derived)
count: k (≥1)
binding: none | actor Instance | intent digest | resource
freshness: max age (trusted time'a göre)
independence: distinct Party | distinct controller | distinct surface/assurance path | ≠ actor principal
consumption: reusable | single-use | per-intent
}
```

| İhtiyaç | RequirementTerm |
|---|---|
| Stronger authentication | Claim · authentication · binding=Instance · assurance floor · freshness |
| Approval | Contribution · approve · source = holders of `approve:<action class>` · binding=intent digest · single-use |
| Co-authority | Contribution · co-authorize · source = holders of S · binding=intent digest |
| Quorum | Contribution · count=k · independence · binding=intent digest |
| Fresh claim | Claim · class · freshness |
| Device posture | Claim · posture.device · binding=Instance |
| Runtime attestation | Claim · attestation.runtime · binding=Instance/KeyBinding |
| Foreign authority acceptance | Claim · foreign-authority proof · binding=holder |
| Grounded non-execution (release için) | Claim · effect.non-execution · source=effect attestor · binding=Exercise |

**REQUIRE_ACTION** = karşılanmamış RequirementTerm'lerin yapılandırılmış listesi + (Contribution için) derived eligible contributor kümesi. DENY değildir; aynı nonce eksik proof'lar sunulunca yeniden değerlendirilir.

**Approval dört soruya bölünür (F8):**

| Soru | Sahip | Bu modelde |
|---|---|---|
| Neden / nerede onay gerekiyor | Work (Gate) veya domain | Work Gate; Access'te yalnız authority composition ise Grant/Anchor RequirementTerm'i |
| Kim onaylayabilir | Access | `approve:<action class>` üzerinde Grant tutanlar (derived eligible set) |
| Approval authority geçerli mi | Access | Approver'ın `contribute` Exercise'ının Decision'ı |
| Onay eylemi | Approver; Work Declaration ona atıf yapar | Approver'ın `contribute(approve, intentDigest)` Exercise'ı |

`approve` ordinary bir authority class'ıdır; `approve:payment.create` tutmak `payment.create` tutmak değildir (CI-14, INV-20). SoD bir `independence` term'idir (`contributor ≠ actor principal`).

**Quorum** authority composition'dır, workflow değildir (C26): Anchor root `Joint(k)` veya RequirementTerm `count=k`, aynı intent digest'ine bağlı attributable contribution Exercise'larıyla. Tek aggregate kimlik gösteren threshold imzası tek contribution'dır (L13); Public selector contribution kaynağı olamaz. Toplama, hatırlatma, sıra ve timeout Work (Gate) + Relay'indir.

**Onay mekanizmaları tek RequirementTerm biçimine iner.** Okta çift onayı, AWS çok kişili onayı ve "korunan eylem" step-up'ı ayrı mekanizmalar değildir. Hepsi RequirementTerm örnekleridir:
- Okta çift onay → Contribution · approve · count=2 · independence.
- AWS iki grup parola/MFA modeli → Anchor root `Joint(k)` veya `count=k`. Threshold imza tek katkıdır (L13).
- Korunan eylem → Claim · authentication · freshness. Bu bir yetki değil, requirement'tır (INV-10).

Korunan eylem aday listesi (kalıcı silme, imza anahtarı rotasyonu, IdP bağlantı ayarı) CT3 sınıflandırmasına girer → §12, §13.

### 5.10 Intent, Decision ve Exercise

Intent hash-bound immutable bir value'dur: core generic envelope + domain-defined typed schema; schema'lar sürümlü ve schema-definition Acceptance'ı ile kabul edilir; digest'i Access canonical içerikten hesaplar (C29). Evaluation ≠ committed Exercise (C30).

```text
pending transaction (nonce) ── evaluation; Exercise değil
opened ├─► REQUIRE_ACTION ──(proofs added)──► re-evaluate* ─┐
├─► DENY ─────────────────────────────────────────────┴─► closed (bu nonce için terminal)
└─► ALLOW (committed) ══ AUTHORITY EXERCISE DOĞAR ══
│ [consumption committed]
└─► continuation* ─┬─► ALLOW (yeni DecisionRecord, kendi StateBasis'i)
├─► DENY on continuation → exercisability ileriye dönük biter → closed
└─► closed (intent validity / horizon elapsed)
sonradan bağlanan: outcome attestation Claim'leri (derived outcome state), consumption.release Exercise'ı
```

Continuation DENY'ı geçmiş ALLOW'u geçersiz kılmaz (prospective); Exercise'ı kapatır. İmkânsız geçişler: aynı nonce için DENY → ALLOW; aynı nonce ile farklı intent; ALLOW'un ikinci kez farklı consumption ile commit edilmesi; Exercise'ın actor'ünü, capacity'sini veya basis'ini değiştirmek.

**Continuation.** Long-running veya intermittent kullanımda aynı Exercise üzerinde yeni bir DecisionRecord; kendi AuthorityStateBasis'iyle yeniden değerlendirilir; "renewal" değil yeni karardır (L19). ValidityContract bir sonraki continuation'ın en geç ne zaman gerekeceğini söyler. Execution ve control kontrolü Work/Executor'ındır.

**Projected exercises.** Bir PEP Access'in yayınladığı bir projection'a karşı yerel olarak karar verdiğinde her kullanım Access'te ayrı bir Exercise olarak doğmaz; meşruiyet zinciri `projection.issue` Exercise'ı (ValidityContract ile) → PEP'in contract içindeki yerel kararıdır. Consumption-bearing veya auditable action sınıfları ya online Exercise ister ya da önceden draw edilmiş offline slice taşır.

**Karar semantiği.**
- **Üç sonuç.** Sonuç yalnız ALLOW, DENY veya REQUIRE_ACTION'dır; UNKNOWN yoktur. `allowed: bool` yüzeyinde REQUIRE_ACTION asla `true`'ya eşlenmez. AuthZEN Access Request & Approval profili REQUIRE_ACTION'ın taşıyıcı adayıdır (FDT-5). Profilin onay statüsü doğrulanmadı. API → §9.
- **Advisory önbellek.** `check` sonucunun önbelleğe yazılması yalnız advisory cevap üretebilir. Effect yetkilendiremez (C30, TI-5).
- **PEP'in verdiği olgular (contextual tuple).** Tuple tabanlı modellerde "güvenilen PEP"ten istek kapsamlı tuple kabul edilir; AuthZEN de "the PDP must trust the PEP" der. Access'te PEP actor değildir (PI-7). PEP yalnız Acceptance'ı olan bir issuer olarak ve yalnız `predicate-input` use'unda Claim sunabilir. Bu Claim pozitif seçimde kullanılamaz. Gerekçe: PEP'e güvenmek confused-deputy sınıfını yeniden açar.
- **Saf Core.** Core saf, durumsuz bir karar fonksiyonudur. Core ve Kernel kodu aynı crate'tir (MD-1); bu kod paylaşımıdır, ayrıcalıklı yol değildir. Identity plane dahil her PEP commit-mode kararı (commit, continue, `projection.issue`) ADP üzerinden domain leader'ından alır (TI-5, TI-15, EI-13). Kernel'i yerel çalıştıran her tüketici, identity plane dahil, yalnız ValidityContract'lı bir projection'a karşı karar verir; bu bir advisory veya projected exercise'tır (§5.10 "Projected exercises"). Cedarling benzeri istemci içi PDP'nin bayatlık penceresi doğrulanmadı. Bu yüzden ancak ValidityContract'lı bir projection olarak kabul edilir.
- **Batch.** Kısa devre (`deny_on_first_deny`) yalnız `check` modundadır (PI-23). Commit'te her ALLOW bir Exercise'tır ve consumption taşır; kısa devre hangi öğenin commit edildiğini belirsiz bırakırdı.

### 5.11 Zaman, revocation ve continuity

- **Normatif zaman** authority domain'inin trusted time'ıdır; authority backdate edilemez; `occurredAt` / `issuedAt` yalnız daraltmayı seçer (C33, INV-23). Trusted time ≥ 2 bağımsız kaynakla tutulur (TI-RT2).
- **AuthorityStateBasis** DecisionRecord içinde (object, version) bağımlılık kümesi + trusted evaluation time olarak bir value'dur; tek global epoch yoktur (C32).
- **Revocation** bir meta-Exercise'tır; commit anından itibaren prospectively authoritative'dir; tamamlanmış Exercise'lar tarih olarak kalır. Revocation ≠ physical stop.
- **Exercisability over time** dört connectivity class'ıyla ifade edilir: `online`, `intermittent`, `offline`, `long-running` (L16; protocol karşılığı §9.12).
- **Recovery** Instance için tek successor üretir ve authority miras bırakmaz; Party recovery Party Identity Regime'indir. Identity plane hesap kurtarması authority plane'de her zaman yeni bir successor Instance doğurur; domain bunu yalnız sıkılaştırabilir (§5.6).
- **Redaction:** kayıtların existence/attribution/lineage/digest/zamanı silinemez; body yalnız hiçbir canlı derivation'a gerekmediğinde redakte edilir (C34, INV-30).

**Invalidity vs restriction:**

| | Invalidity | Restriction |
|---|---|---|
| Örnekler | revoke, expire, renounce, affirmative lapse, Instance termination | suspend, containment, RestrictionPolicy |
| Etki | Terminal; türetilmiş her Grant, Mandate kapsamı, reusable Decision ve projection prospectively geçersiz (cascade) | Overlay; yalnız DENY veya REQUIRE üretir; lineage'ı kırmaz |
| Geri alma | Yok; yeni explicit Grant gerekir | Kaldırma genişletme sınıfında bir meta-Exercise'tır |
| Invariant | INV-5, C17 | INV-6, SI-4 |

**Revocation semantiği ve epoch'lar.** Semantik:
- Revocation commit anında prospektiftir (G4).
- Kaskad eder (INV-5).
- Post-revocation her pencere önceden beyanlı bir ValidityContract'tır (SI-7).

Üç epoch mekanizma olarak şöyle eşlenir:

| Epoch | Access'teki yeri |
|---|---|
| `session_epoch` | Identity plane oturum/token hızlı iptali (Instance veya Party başına). `instance.terminate` ve `party.compromise` sonrası artar |
| `key_epoch` | Anahtar penceresi (Domain Metadata / realm JWKS rotasyonu) |
| `authz_epoch` | Authority plane'de yeri yoktur. Yerini AuthorityStateBasis (C32) ve türetilmiş önbellek anahtarında `applied_pos` alır. Gerekçe: pozisyon, kiracı genelindeki sayaçtan daha incedir ve nedenselliği korur. `authz_epoch` nedensel tutarlılık garantisi vermez |

Ek kurallar:
- "Önbellek bu kullanıcıyı hiç görmedi" durumu fail-closed'dur (MD-7, MD-8).
- RFC 8693 token exchange iptali yaymaz. Access'te bu boşluğu lineage kaskadı kapatır: exchange edilmiş token bir projection'dır ve basis'i geçersizleşince prospektif olarak geçersizdir (INV-5, PI-10).
- Uzun ömürlü token + sinyal güdümlü iptal modeli (ör. 28 saat) reddedilir (MD-7). Uzun ömür yalnız beyanlı bir ValidityContract horizon'u olarak mümkündür (UDC). SSF/CAEP bir hızlandırıcıdır; güvenlik sinyale dayanmaz (INV-24). Sinyal teslimi NOT GUARANTEED'dir (N-2).

Yol başına yayılım profilleri ve guarantee sınıfları → §9.11–9.12 ve §13.

### 5.12 Planes ve iki source of truth

| Plane | Canonical mı? | İçerik |
|---|---|---|
| **Identity plane** | Evet (kendi issue ettiği kayıtlar) | Ceremony'ler, authenticator binding'leri, kendi issue ettiği Claim'ler, custodial kayıtlar, PII. Ayrıca tam IdP nesneleri: Identity Realm, user record, credential, login tanımlayıcısı, oturum, OAuth/OIDC client, upstream IdP bağlantısı, IdentityBinding, realm JOSE anahtarları |
| **Authority plane** | Evet (AuthorityDomain log'u) | Genesis, Exercise/DecisionRecord, Claim ingest; Acceptance dahil authority state |
| Trust / Acceptance | Ayrı source of truth değil | Acceptance Authority plane'in primitive'idir |
| Decision / Evaluation | Ayrı source of truth değil | Kayıtlar + kabul edilmiş Claim'ler üzerinde deterministik fonksiyon |

| Plane seam'i | Kural |
|---|---|
| Identity → Authority | Tek kanal Claim'dir (Claim Ingest API); karara yalnız Acceptance kadar girer (E3, TI-15) |
| Authority → Identity | Yalnız derived semantic event'ler (revoked, terminated, compromise), ADP kararları (identity plane PEP rolünde) ve InstanceID referansı. Authority plane identity kaydı yazmaz; identity plane bu girdilere kendi kaydıyla tepki verir (`session_epoch`) |
| Identity plane yapılandırması | Client, redirect URI, upstream IdP bağlantısı, şablon ve realm config değişiklikleri realm'in AuthorityDomain'inde domain action'larıdır. Bu domain realm'in tek **yönetişim domain'idir** (`realms.governing_domain_id`, §5.16); bu action'lar meta-Exercise değildir. Identity plane PEP'i bunları herhangi bir PEP gibi ADP `commit` ile yetkilendirir. Actor, değişikliği yapan yöneticinin Instance'ıdır (AIS, CT tazeliği); çerez tek başına hiçbir authority değişikliğini yetkilendiremez. ALLOW'dan sonra identity plane kendi kaydını kendisi yazar. Authority plane yine identity kaydı yazmaz. Ayrı bir "admin token" sınıfı yoktur. Authority grafiği ve audit okuması da AIS (CT0) veya holder-bound okuma projection'ı ister; çerez yalnız gezinmeyi ve identity plane'in kendi ekranlarını taşır |
| Identity plane `credential.set` | Identity plane action şemasında başkasının kimlik bilgisini doğrudan yazan bir action yoktur. Yalnız reset-intent akışı vardır. Bu bir tavandır → §12 |
| Identity plane custody anahtarları | Access provider rolünde kullanılmaz; görev ayrılığı beyanlıdır (SEC19) |

**Not.** Identity plane yapılandırması için ADP `commit` kullanılması TI-15 ve INV-12'deki "tek kanal Claim'dir" kuralıyla çelişmez. ADP çağrısı bir PEP rolüdür: bu yolla identity plane authority plane'e olgu vermez, bir yöneticinin authority kullanımını talep eder. Kural, üçüncü taraf PEP'lerin kullandığı public sözleşmenin aynısıdır (CI-15, EI-13). Ortak tablo, DB rolü veya KMS anahtarı yine yoktur (TI-15). Identity plane'in Core'a süreç içi ayrıcalıklı yolu da yoktur; Kernel ortaklığı kod paylaşımıdır (§5.10). Süreç içi ayrıcalık ayrımı (yetki yazma yolunun süreç içinde ayrıca yetkilendirilmesi) bir mühendislik kuralıdır → §16.

### 5.13 Federation

E19'un beş mekanizması ayrıdır: identity federation, foreign authority evidence, local bridging Grant, cross-domain delegation ve authority-provider handover. Foreign identity yalnız actor-binding'dir. Foreign authority yerelde yalnız yerel bir root'tan türeyen bridging rule-shaped Grant'ın ceiling'i içinde ve foreign-authority Acceptance'ı ile etkilidir; foreign lineage cited olarak korunur (C21, INV-17). Daha basit yol foreign Party'ye yerel extensional Grant'tır (cross-domain delegation). Home lineage'ına dayanan exercise home budget'ını draw eder; target'ın BudgetTerm'i yalnız ek daraltmadır.

**Identity plane federasyonu.**
- Upstream IdP ve SCIM güveni bir yapılandırma değil, bir Acceptance'tır: actor-binding, subject-selection veya predicate-input use'unda, scoped ve iptal edilebilir (C18). Yapılandırma değişikliği bir meta-Exercise'tır (MD-14). Upstream IdP/SCIM *güveni* Acceptance'tır ve değişikliği meta-Exercise'tır. *Bağlantı kaydı* `idp.upstream.*` domain action'ıdır (yönetişim domain'inde). İkisi ayrı Exercise'tır. Upstream grup → realm grubu eşlemesi reserved requirement'a tabidir (§5.17 grup sahipliği).
- ID-JAG bir authorization grant olarak değil, assertion/Claim taşıyıcısı olarak kullanılır. Authority Access Grant'ından gelir (MD-18, PI-3). Access'in ürettiği ID-JAG authority taşımayan bir kimlik iddiası projection'ıdır; authority scope içermez; authority RS tarafında Access Grant'ından gelir.
- Domain'ler arası korelasyon yalnız açık bridging Grant veya IdentityBinding ile kurulur (MD-10, INV-38).

### 5.14 Naming

| Canonical ad | Not |
|---|---|
| AuthorityAnchor | Root bir değerdir; ayrı bir root nesnesi yoktur |
| Authority Exercise | Tek entity |
| DecisionRecord | Relied-upon karar kaydı |
| ValidityContract | Reusable kullanımın semantik sözleşmesi; continuation ile birlikte uzun süreli exercisability'yi taşır |
| Acceptance | Trust'ın tek nesnesi |
| Instance | Somut execution / sign-in bağlamı |
| PartyRef | Product-neutral Party referansı |
| principal (rol) | Capacity'den türeyen rol |
| SubjectSelector | Tek seçici value'su |
| BudgetTerm | Authority budget'ı; finansal çağrışım taşımaz |
| Contribution | Exercise'ın bir sınıfı; ayrı approval nesnesi yoktur |
| Tenant | Ticari hesap (fatura, kota, sözleşme, destek). Semantik değildir; authority anlamında kullanılmaz [MD-5] |
| Identity Realm | Identity plane ad alanı: issuer URL, JOSE anahtarları, RP ID, login ad alanı, client'lar, marka. Yaygın IdP dilindeki "kiracı" budur; Access metninde "kiracı" kelimesi yalnız Tenant için kullanılır [MD-5] |
| Cell | Fiziksel yerleşim (`placement_id`); semantik değildir [MD-5] |
| IdentityBinding | Realm'ler veya regime'ler arası bağın kaydı ve onun Claim sınıfı (C7); authority birleştirmez [MD-5, INV-39] |
| Derived graph index | Zanzibar/Leopard tekniğiyle kurulan türetilmiş indeks (CMP-9); "tuple store" kanonik değildir [MD-4] |

### 5.15 Frozen ontology decisions (C1–C34)

Statü: **FROZEN PRODUCT DECISION (ontology)**.

- **C1** Access'in canonical primitive'leri: AuthorityDomain, AuthorityAnchor, Grant, Mandate, Instance, Acceptance, Authority Exercise. RestrictionPolicy canonical bir policy construct'tır. Canonical record türleri: Genesis, Exercise (opening + DecisionRecord'lar), Claim. Başka primitive yoktur.
- **C2** Semantik source of truth her authority domain'in append-only, attributable kayıtlarıdır; current authority graph bunların deterministik projection'ıdır ve kayıtlara baskın gelemez.
- **C3** Genesis dışında authority state'inin tek yazma yolu meta-action'ların committed ALLOW'lu Authority Exercise'larıdır. Claim corpus ayrıdır: dış Claim ingest'i mutation değildir; domain-issued Claim claim.issue Exercise'ıdır. Grant/Mandate/Acceptance/Policy/Anchor/Instance lifecycle geçişleri, revocation, approval, budget release ve projection issuance birer Exercise'tır.
- **C4** Genesis, domain başına tek unconditioned kayıttır; meşruiyeti dışsaldır; sonrası yalnız Exercise. Hosting provider root değildir.
- **C5** Access Party yaratmaz; product-neutral, protocol-level bir PartyRef ile ortak/uyumlu identity regime'e atıf yapar; PartyRef Work object'i değildir ve Access Work'e bağımlı değildir. "Principal" Access'te entity değildir; on-behalf-of rolüdür ve Exercise'ın capacity'sinden (basis Grant AgencyTerms ile yetkilendirilmiş) türetilir, lineage'dan değil.
- **C6** Üç actor katmanı (F18): holder rolündeki Party · actor-capable Party (derived kapasite) · Instance (primitive). Exercise actor'ü Authenticated(InstanceID) veya Anonymous(context) value'sudur; Anonymous yalnız Public Grant kullanır ve hiçbir şey tutmaz. Organizasyonlar ve joint gruplar Instance'a sahip olmaz; org authority'si actor-capable Party'lerin FOR(org) capacity'siyle exercise edilir.
- **C7** IdentityBinding, authenticator binding, authentication event, runtime attestation, device posture, membership ve controller/sponsor/operator relation Claim sınıflarıdır.
- **C8** Instance kimliği authority-binding sürekliliğini izler. Key rotation aynı Instance'tır; continuity kırılması yeni Instance'tır; recovery tek successor üretir ve authority miras bırakmaz.
- **C9** Authority Root ve Resource Authority Anchor tek primitive'dir (AuthorityAnchor); root, Anchor'ın değeridir. Anchor scope'ları domain içinde ayrık veya iç içedir; bir resource'un root'u onu kapsayan en özel Anchor'dadır; kapsanmayan resource'ta authority yoktur.
- **C10** Root transfer, Anchor'a dayanan Grant'ların akıbetini açıkça belirtir; varsayılan yoktur.
- **C11** Grant, bir basis'ten bir holder seçicisine AuthoritySet'i terimleriyle türeten kimlikli derivation edge'dir. Tam olarak bir basis'i vardır: AnchorRoot veya HoldingRef ⟨GrantID, holder, since⟩. Lineage bir ağaçtır; decision proof bir DAG'dir.
- **C12** Transfer/exercise grant ayrımı yoktur. Provenance ≠ exercise capacity: Grant agency: {OWN, FOR(PartyRef)} taşır; Exercise capacity'si basis Grant'ın agency'sinde olmalıdır; agency continuity ile bir Grant yalnız OWN ve issuing principal için FOR verebilir. Root devri anchor.transfer'dır. Her Exercise basis'ini ve capacity'sini tek ve explicit adlandırır. Work seam'i: on-behalf-of atfı yetkilendirilmiş capacity ile uyumlu olmalı; provenance ayrıca incelenir.
- **C13** Rule-shaped Grant aynı primitive'dir. Claim değişince yeni Grant doğmaz; aynı Grant farklı bir holder kümesi seçer. Seçici yalnız subject-selection Acceptance'ı olan claim class'ları kullanabilir. Holding, kesintisiz qualification episode'ları olarak derived'dır ve HoldingRef ile adlandırılır; downstream Grant, Exercise, pin ve Decision episode'u cite eder. Affirmative değişiklik episode'u terminal kapatır (cascade); staleness kapatmaz (REQUIRE_ACTION); re-qualification yeni episode açar, eski türevleri canlandırmaz. Renounce yalnız extensional Grant'ta vardır.
- **C14** Mandate ayrı primitive'dir: holder Party'nin kendi Instance'ına bağladığı sabit zarf. Holding yaratmaz, lineage'a girmez, delege edilemez, Instance değiştiremez. Zarf içinde holding'i izler; genişleme rebind'dır; reserved sınıflar HoldingRef'e pin ister ve pin sonraki episode'a yalnız explicit rebind ile geçer. Mandate ≠ Work Autonomy.
- **C15** Delegability: delegable boolean + opsiyonel depth + opsiyonel downstreamHolderClass canonical algebra'dadır. Reserved action'lar wildcard ile kapsanmaz. Depth provenance/accountability'nin yerine geçmez.
- **C16** Grant revizyonlu tek kimliktir: scope/terms/validity/delegability/budget değişikliği revizyon; holder veya basis değişikliği yeni Grant; tek istisna intensional selector'ın conjunctive daraltılmasıdır (narrowing revizyonu). Expired/revoked Grant canlanmaz. Budget ledger revizyonlar boyunca süreklidir.
- **C17** Invalidity (revoke, expire, renounce, lapse, termination) terminal ve cascade'dir; restriction (suspend, containment, policy) overlay'dir ve kaldırılması genişletme sınıfındadır.
- **C18** Trust'ın tek nesnesi Acceptance'tır: issuer × artifact classes × subject class × domain × assurance floor × validity × use. Use ∈ {actor-binding, predicate-input, subject-selection, foreign-authority, schema-definition}. Issuer ve use kimliğin parçasıdır. Tüm Acceptance değişiklikleri meta-Exercise'tır; subject-selection, foreign-authority ve schema-definition reserved'dır.
- **C19** Claim imzalı olmak zorunda değildir; verifiable issuer attribution zorunludur; imza bir assurance profilidir.
- **C20** Proof bir roldür: her cited proof ya Claim ya Exercise'tır. Credential conceptual modelde primitive değildir.
- **C21** Foreign authority yerelde yalnız yerel bir root'tan türeyen bridging rule-shaped Grant'ın ceiling'i içinde ve foreign-authority Acceptance'ı ile etkilidir; foreign lineage cited olarak korunur. ForeignAuthority seçimi de holding episode'larıyla çalışır: foreign authority'nin kaybı episode'u kapatır, yeniden kazanılması yeni episode açar.
- **C22** Constraint kategorileri: AuthoritySet, Validity, DelegationTerms, RequirementSet (canonical algebra'da); BudgetTerms (algebra dışı, lineage draw ile non-amplifying); RestrictionPolicy (algebra dışı, yalnız DENY/REQUIRE).
- **C23** Purpose canonical algebra'da yalnız küme/eşitlik semantiği olan first-class bir boyuttur; vocabulary domain'in veya Work referanslarıdır.
- **C24** Requirement tek RequirementTerm biçimine sahip bir value'dur; approval, co-authority, quorum, step-up, fresh claim, posture, attestation ve grounded release onun örnekleridir.
- **C25** Approval authority, approve action'ı üzerinde ordinary Grant'tır; approval act bir contribution Exercise'ıdır; Work Gate Declaration ona referans verir.
- **C26** Quorum authority composition'dır: Anchor.root Joint(k) veya RequirementTerm count=k, aynı intent digest'ine bağlı attributable contribution Exercise'larıyla; workflow değildir.
- **C27** Budget, Grant/Mandate üzerindeki BudgetTerm value'su + derived remaining'dir. Her exercise lineage'daki tüm budget'lardan draw eder. Release yalnız grounded'dır.
- **C28** Named AuthoritySet'ler (role/template) Grant'ta sürümüyle pin'lenir; canlı dolaylılık yoktur.
- **C29** Intent, hash-bound immutable bir value'dur: core generic envelope + domain-defined typed schema; schema'lar sürümlü ve schema-definition Acceptance'ı ile kabul edilir.
- **C30** Evaluation ≠ committed Exercise. Authority Exercise, intent nonce'a bağlı kimliği olan ve o nonce için ilk committed ALLOW ile doğan canonical entity'dir; continuation ve release DecisionRecord'larını taşır. REQUIRE_ACTION ve DENY evaluation sonuçlarıdır (auditable ise kaydedilir); DENY o nonce için terminal'dir. Continuation DENY Exercise'ı ileriye dönük kapatır.
- **C31** Decision bir value'dur. Authority state'i değiştiren, canonical authorization state'i tüketen, reusable/portable authority yaratan veya consequential dış effect'i yetkilendiren her relied-upon ALLOW durable, attributable DecisionRecord'dur; saf advisory evaluation canonical tarih değildir. Portable/reusable artefaktlar ayrı projection'lardır. Uzun süreli exercisability ValidityContract + continuation DecisionRecord ile ifade edilir.
- **C32** AuthorityStateBasis, DecisionRecord içinde (object, version) bağımlılık kümesi + trusted evaluation time olarak bir value'dur; tek global epoch yoktur.
- **C33** Authority backdated edilemez; normative time authority domain'in trusted time'ıdır; trusted time conceptual requirement'tır.
- **C34** Kayıtların existence/attribution/lineage/digest/zamanı silinemez; body yalnız canlı derivation'a gerekmediğinde redakte edilir.

C15 ontology kararıdır (MD-19.5). Liste C1–C34 ile kapalıdır. Identity plane'in ontolojik etkileri §5.16–§5.18'de MD referanslarıyla, invariant etkileri §6.9'daki aday invariant'larla ifade edilir.

### 5.16 Kiracılık eksenleri ve identity plane nesnelerinin yeri (MD-5)

Statü: **MERKEZİ KARAR (MD-5)**. Ontoloji açısından FROZEN ontology kararlarının (C1, C5, C7, CI-15) uygulamasıdır; yeni primitive yoktur.

| Eksen | Ne | Semantik mi | Authority karşılığı |
|---|---|---|---|
| **Tenant** | Ticari hesap: fatura, kota, sözleşme, destek | Hayır | Yok. `tenant_id` hiçbir authority kararına girdi değildir (INV-37) |
| **AuthorityDomain** | Authority semantiğinin tek birimi: Genesis, log, DomainID = genesis digest, KEK, operasyonel imza anahtarı kapsamı | Evet (T27) | Primitive (§5.1) |
| **Identity Realm** | Issuer URL, JOSE anahtarları, RP ID, login ad alanı, kullanıcı/credential, client'lar, marka/tema, giriş politikası | Identity plane'de | Realm'in authority etkisi yalnız domain'de kabul edilmiş Claim'lerle (Acceptance) ve realm yapılandırmasının domain action'larıyla (MD-14) olur. Domain action'lar yalnız realm'in tek yönetişim domain'inde karar alır |
| **Cell** | Fiziksel yerleşim (`placement_id`) | Hayır | Yok. Cell değişimi TI-2'nin HANDOFF/ACCEPTANCE kuralına tabidir; semantik etkisi yoktur |

**Kardinalite.**
- Bir tenant 0..n domain ve 1..n realm barındırır.
- Bir domain hiçbir zaman iki tenant'a yayılmaz.
- Varsayılan eşleme 1 realm ↔ 1 domain'dir. N:M eşleme açık bir kayıtla yapılır. Bu kayıt realm'in domain'deki Acceptance'larıdır (çıkarım: N:M kaydının ontolojik karşılığı bir Acceptance kümesidir; kayıt biçimi → §12).
  - **Yönetişim ≠ tüketim.** "N:M realm↔domain" ifadesi "1 yönetişim domain'i + N tüketen domain" olarak okunur. Her Identity Realm'in tam olarak bir yönetişim AuthorityDomain'i vardır: `realms.governing_domain_id` (NOT NULL). Bu bir değerdir, primitive değildir. Realm yapılandırmasının `idp.*` domain action'ları (MD-14) yalnız o domain'de ADP commit ile karar alır (CI-15). Realm'in kimlik Claim'lerini tüketen domain sayısı N olabilir; her tüketen domain bunu kendi use-typed Acceptance'ıyla bildirir. Eşleme kaydı identity plane yapılandırmasıdır ve tek başına Acceptance değildir: yönetişim bir değerdir, tüketim Acceptance'tır (§7.1). Yönetişim domain'inin değiştirilmesi iki uçlu bir Exercise'tır (eski ve yeni yönetişim domain'inde; reserved, CT3; INV-35 deseni; `idp.realm.rehome`, → §12.1). Yönetişim domain'i olmayan realm oluşturulamaz. Bu yüzden realm barındıran her tenant ≥ 1 domain barındırır; yukarıdaki "0..n domain" bu kısıtla okunur. *[BY SEMANTICS (tek yönetişim domain'i)]*
- Bir kiracı birden çok domain barındırabilir; örneğin sandbox domain'i (X21) veya tesis domain'i.

**B2B organizasyonlar.** Organizasyonlar realm içinde Party + Anchor olur, ayrı domain olmaz. Org root'u `Joint(k)` yöneticilerdir. Org yetkisi FOR(org) capacity'siyle kullanılır (C6). Cross-org yetki bridging Grant ile kurulur (C21).

**Kimlik kapsamı.** Credential ve login tanımlayıcısı realm'e yereldir: `UNIQUE(realm, …)`. PartyID bir regime referansıdır; global bir tablo değildir (E4, INV-12). Realm'ler arası bağ yalnız açık IdentityBinding ile kurulur (C7). E-posta asla anahtar değildir.

**Fiziksel savunma derinliği (gün-1).** Her depoda:
- PK'de `tenant_id` (+ `domain_id` / `realm_id`),
- bileşik FK,
- RLS FORCE, NOBYPASSRLS, `SET LOCAL`.

**Anahtarlama kapsamı.** `tenant_id` + RLS FORCE şu tablolarda zorunludur: identity plane, derived, PII vault ve operasyon tabloları. Authority canonical log'u ve kayıtları `domain_id` ile anahtarlanır. Tenant↔domain eşlemesi placement directory'dedir. Gerekçe: append-only log ticari hesap değişince yeniden anahtarlanamaz (OP-12).

MD-2'ye göre domain/tenant kapsamı olmayan sorgu derlenemez. RLS kararı bu karar altındadır (MD-19.6). Ayrıntı → §12, §16, §17. Guarantee: fiziksel izolasyon UDC'dir (koşul: RLS + bileşik FK + tip düzeyinde kapsam). Authority izolasyonu BS'dir (CI-15, INV-37).

**Gerekçe.** Eksen ayrımı semantik izolasyonu sağlar. Fiziksel izolasyon, nOAuth/Truffle ve CVE kanıtlarının gösterdiği sızıntı sınıfına karşı savunma derinliğidir. İkisi birlikte kiracı sızıntısı sınıfını hem fiziksel hem semantik olarak kapatır.

### 5.17 IdP varlıklarının authority modeline eşlenmesi (MD-4)

Statü: **MERKEZİ KARAR (MD-4)**. Tek pozitif yetki kaynağı Access Grant lineage'ıdır (INV-1, L4, L7, must-never #2). ReBAC motoru türetilmiş graf indeksi (CMP-9) ve sorgu motoru (CMP-11) olarak konumlanır. Aşağıdaki tablo bağlayıcıdır. Bir IdP kavramının authority etkisi yalnız bu tablodaki karşılığıyla ifade edilir (aday INV-33).

| IdP kavramı | Access'teki yeri | Kanonik mi |
|---|---|---|
| Kullanıcı (`users`), servis hesabı, ajan | Party (PartyRef, identity plane rejimi). Çalışan kopya = Instance; identity plane oturumu cihaz başına tam bir insan Instance'ına bağlanır, oturum Instance değildir | Party identity plane'de; Instance authority plane'de |
| Organizasyon / kiracı içi org | Party (org) + o org'un kaynaklarını kapsayan Anchor (root = `Joint(k)` yöneticiler). Org yetkisi FOR(org) ile kullanılır | Evet (Anchor) |
| Grup üyeliği, org üyeliği (`member` tuple'ı, SCIM, JIT, davet) | **Claim** (`membership`). Yerel davet/üyelik bir `claim.issue` Exercise'ıdır. SCIM/IdP kaynaklı üyelik Acceptance'lı bir dış Claim'dir. Her grubun tek bir üyelik issuer'ı vardır: domain (domain-local grup, yalnız `claim.issue`) veya belirli bir upstream (identity plane realm issuer'ı ya da adlandırılmış upstream IdP/SCIM kaynağı). Aynı grup için ikinci yazma yolu yoktur (aşağıda "Grup sahipliği") | Claim corpus |
| Grup → izin ("Finance grubu faturaları görür") | **Rule-shaped Grant**: holder = `Pred(membership(Finance))`, basis = ilgili Anchor root'u. Grup iç içeliği selector'da açık conjunction olarak veya issuer'ın düzleştirdiği Claim olarak ifade edilir | Evet (Grant) |
| Rol (admin, editor) | **Named AuthoritySet** sürümü. Rol ataması o sürümü pin'leyen bir Grant'tır (extensional veya rule-shaped) | Evet (Grant) |
| Doğrudan paylaşım (`doc#viewer@user:bob`) | **Extensional Grant** (`grant.issue` Exercise'ı, UI'da "Give access") | Evet |
| Sahiplik (`doc#owner@alice`) | Kaynak sahibinin Anchor'ı altında doğar; sahipliği ayrıca yazmaya gerek yoktur. Ayrı bir sahip gerekiyorsa ayrı Anchor kurulur | Evet (Anchor) |
| Kaynak hiyerarşisi (`doc#parent@folder`) | Domain'in resource olgusu (E14): domain-issued Claim veya ResourceRef selector'ı. Yetki mirası = Anchor scope iç içeliği veya resource selector'lu Grant | Olgu: Claim. Yetki: Grant |
| Koşullu tuple / ABAC koşulu | AuthoritySet parametre sınırı veya while-condition (kapalı cebir). Daraltıcı koşul ise RestrictionPolicy | Evet / policy |
| Tuple deposu, Leopard bitmap'i, ConsistencyToken, watch | **DERIVED index (CMP-9)**: kanonik log + kabul edilmiş Claim'lerden türetilir. `check`, search, explain ve eligible set'i servis eder. Token = `at_least`/`as_of` (T11) | Hayır (projection) |
| Token'daki rol/org claim'i | Projection (⊆ AuthoritySet ∩ Mandate). Kaba katmandır, tek başına kanıt değildir. Token'daki rol claim'i (named AuthoritySet ataması) bir Grant'ın projection'ıdır: ⊆ (AuthoritySet ∩ Mandate), `projection.issue` (S-1). Token'daki grup/org **üyeliği** bir identity Claim'idir (§2.2.2 (a)); authority taşımaz ve RP'ye authority kanıtı olarak sunulmaz. Seçim etkisi yalnız authority plane'de, Acceptance'lı rule-shaped Grant üzerinden olur (INV-16) | Hayır (rol: projection; üyelik: Claim) |
| Upstream IdP / SCIM güveni | Acceptance (actor-binding, subject-selection, predicate-input). Bağlantı kaydı ayrıca bir `idp.upstream.*` domain action'ıdır; upstream grup mapping'i reserved requirement'a tabidir | Evet (Acceptance) |
| Hesap birleştirme / hesap bağlama | IdentityBinding kaydı + Claim. Lineage birleştirmez (INV-39) | Claim |
| Destek oturumu (`DelegatedSession`) | Destek temsilcisinin kendi Instance'ı + FOR(kullanıcı) Grant'ı veya reserved break-glass Grant'ı (§5.7, MD-9) | Evet (Grant) |

**Grup sahipliği: bir grup = bir üyelik issuer'ı.** Membership bir Claim'dir (MD-4). Ama her grup (membership class örneği) tam olarak bir üyelik issuer'ı beyan eder (CI-11, INV-25, EI-1):
- (a) **Upstream / identity-plane-managed grup.** Kayıt identity plane'dedir. Claim belirli bir upstream issuer'dan gelir: identity plane realm issuer'ı ya da adlandırılmış bir upstream IdP/SCIM kaynağı. Konsoldan yapılan değişiklik bir `idp.group.*` domain action'ıdır (yönetişim domain'inde, §5.16).
- (b) **Domain-local grup.** Identity plane kaydı yoktur. Claim yalnız `claim.issue` ile domain'den gelir.
- Aynı grup adı veya ID'si için ikinci bir yazma yolu (ikinci issuer) reddedilir. Domain-local grup ile identity plane grubu aynı grup olamaz.
- Selector `Pred(membership(g))` grubun issuer'ını adlandırır. Başka issuer'dan gelen aynı adlı Claim seçime girmez. Claim güncelliği issuer başına olduğu için (TI-RT7) bu kural iki issuer'ın birbirini supersede edememesi sorununu kapatır.
- **Upstream grup mapping'i reserved requirement ile korunur (L6).** Realm issuer'ının subject-selection Acceptance'ı olan bir claim class'ının üyeliğini toplu değiştirebilen her identity plane config action'ı (upstream grup → realm grubu mapping'i, protocol mapper, JIT/SCIM kaynak bağlama) o Acceptance'ı genişletmekle aynı requirement sınıfını taşır: reserved, CT3 (C18). Requirement karşılanmadan yapılan mapping değişikliği ALLOW almaz; ürettiği üyelik seçime girmez.
- Kontrol senaryosu: rule-shaped Grant holder = `Pred(membership(Finance))`. Finance bir identity plane grubuysa konsoldan domain-issued "Bob ∈ Finance" eklemesi reddedilir. SCIM ile "Bob ∉ Finance" geldiğinde Bob holder set'inden çıkar. *[BY SEMANTICS (tek issuer, selector'da issuer adı, reserved mapping requirement'ı)]*
- Ayrıntı → §7.1 (SCIM satırı), §12 (grup yönetimi).

**Gerekçe:**
1. **Semantik doğruluk.** Tuple; provenance, capacity (FOR/OWN), budget, holding episode ve Acceptance taşımaz. Tuple tabanlı sistemlerde görülen bulgular bu eksiklerin belirtisidir: yetim tuple'ın canlanması, ID yeniden kullanımında sızıntı, dual-write. Access'te üçü de semantik olarak kapalıdır (C16, ResourceRef incarnation, Anchor kapsaması).
2. **Garanti dürüstlüğü.** Commit kararları canonical + SYNC-DERIVED girdiden verilir (TI-5). Böylece en riskli bileşen (graf çözümleyici ve önbellek) hiçbir zaman ALLOW üretmez. OpenFGA/SpiceDB'nin 5 Check/List CVE'si ve önbellek anahtarı CVE'leri (doğrulanmadı) en kötü durumda advisory yanlışlığına iner. Bu yanlışlık Check/List uyum vektörüyle de yakalanır (INV-34).
3. **Kanıt kalitesi.** Yayımlanmış ölçümler türetilmiş katmanın tasarımına aynen uygulanır: Leopard 150 µs, Cedar 4–11 µs, Zanzibar %10 önbellek isabeti. Leopard ve Zanzibar sayıları yayın özetidir; doğrulanmadı. Cedar ölçümü AWS'nin kendi makalesine dayanır ve bağımsız replikasyonu yoktur.
4. **Uygulanabilirlik.** IdP'nin günlük modeli (kullanıcı, grup, rol) kullanıcıya aynı kelimelerle görünür (§8.8 "Role delegation"). Altında Claim + rule-shaped Grant çalışır. "Kaynak parametresi gün-1'de zorunlu" kuralı ve `check(subject, action, resource)` imzası ADP intent'iyle birebir örtüşür. ADP zaten kaynaksız intent kabul etmez.

**Bedel (dürüst beyan).**
- (a) Grup üyeliği değişince holder set'i türetilir. Ama commit yolunda selector değerlendirmesi SYNC-DERIVED episode tablosundan okunmak zorundadır (T9). Büyük gruplarda ingest maliyeti artar.
- (b) Sık paylaşım bir Exercise'tır (imzalı AIS, DecisionRecord). Bu, Zanzibar tuple yazmasından pahalıdır.

İkisi de ENGINEERING ASSUMPTION'dır ve ölçüm bekler (OQ-1). Bu maliyet yetkiyi atfedilebilir kılmanın bedelidir.

**Yetki verisini kim yazar.** Sahiplik yazma gerektirmez (Anchor kapsaması). Paylaşım Grant'ı, domain outbox'ı + aynı-nonce retry ile yazılır (TI-8, EI-23). Outbox ve idempotent yazma deseni bu yolun mekanizmasıdır. Kaynağın silinmesi incarnation'ın sonudur; "art arda silme API'si" türetilmiş indeksin temizliğidir, authority olayı değildir. Tuple deposuna log'dan türetim dışında yazma yolu yoktur (aday INV-33).

**Bu tablonun başka bölümlerdeki karşılıkları.** Karar API'si, derived index tutarlılığı ve projection → §9. Yönetimsel yetki ve istisnai yetki → §12. Revocation → §9.11–9.12, §13. Doğrulama vektörleri → §15. Harici motor değerlendirmesi (OpenFGA, SpiceDB, Keto, casbin, oso, regorus) → §4 ve §9.

### 5.18 Linkability: domain-pairwise PartyRef (MD-10)

Statü: **MERKEZİ KARAR (MD-10)**. Yeni primitive yoktur; kural value düzeyindedir.

- **Identity plane.** OIDC/SAML'de varsayılan `sub` pairwise'dır (NIST 800-63C PPII). Public `sub` client başına opt-in'dir → §10.
- **Authority plane.** Domain dışına çıkan her projection'da ve PAP'ta PartyRef, domain-pairwise türetilmiş bir takma addır (§5.3). İç PartyID değişmez.
- **Korelasyon.** Domain'ler arası korelasyon yalnız açık bir bridging Grant (C21) veya IdentityBinding (C7) ile kurulur.
- **Kalan yüzey.** Aynı KeyBinding, zamanlama ve Claim içeriği gibi korelasyon yüzeyleri NOT GUARANTEED'dir. HL ve RR satırı olarak beyan edilir → §13, §20.
- **Tutarlılık.** E4 (PartyID ve key-event history Party + identity controller'ındır) geçerlidir: takma ad bir projection değeridir, ikinci bir Party registry'si değildir (INV-12). PI-8 (projection ⊆ source) geçerlidir: takma ad authority taşımaz, yalnız referansı gizler. Federasyon (§5.13) içinde foreign domain'in gördüğü PartyRef de pairwise'dır. Cross-domain delegation (foreign Party'ye yerel extensional Grant), foreign Party'nin kendi domain'indeki referansına değil, yerel domain'de kabul edilmiş actor-binding'ine dayanır (çıkarım; protokol karşılığı → §9.13).
- Aday invariant: INV-38.
