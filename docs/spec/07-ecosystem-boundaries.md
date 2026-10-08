## 7. Ecosystem / Ownership Boundaries

Access'in ekosistemdeki yeri tek cümleyle: **Access tam bir IdP'dir (identity plane) ve onun üstünde authority control plane'i olan üründür; business state hub değildir.** Authority plane authority control plane'dir; business state hub değildir. Identity plane "gerekli capability" değil, ürün kapsamıdır (MD-13). Bu bölüm her fact'in tek owner'ını (§7.1), terimlerin tek anlamını (§7.2), Access'in her komşuyla dikişini (§7.3) ve bunları bağlayan ecosystem kararlarını (§7.4) tanımlar. Ayrıca şunları tanımlar:
- plane ataması (§7.6)
- identity plane ↔ authority plane iç sınırları (§7.7)
- ek ecosystem kararları E33–E40 (§7.8)
- seam ayrıntı metni (§7.9)

**Bölüm okuma kuralı.**
1. §7.9 frozen ayrıntıdır. §7.9 ile §7.1–§7.5 veya E-kararları çelişirse §7.1–§7.5 ve E-kararları kazanır.
2. "Wrong layer" bir konuyu atmak için kullanılmaz. Her konu "hangi plane'e veya hangi ürün katmanına ait" sorusuyla yerleştirilir.
3. Identity plane'in genişlemesi hiçbir must-never'i ve hiçbir E/EI kuralını gevşetmez (MD-13).

**Plane'ler.**
- **Identity plane:** tam IdP. Kapsamı: OIDC OP / OAuth AS, SAML IdP, SCIM, LDAP, Kerberos, RADIUS, WS-Fed, OpenID Federation, login oturumu, hesap yaşam döngüsü, credential'lar, realm yapılandırması, ajan credential broker'ı / token vault, CAEP/SSF vericisi ve alıcısı, risk tabanlı step-up. Ayrıntısı §10, §11 ve §12'dedir.
- **Authority plane:** AuthorityDomain kayıt defteri, Acceptance ve evaluation dahil.
- Plane'ler bir ownership birimidir; modül, servis veya deployment kararı değildir (§7.9.1.1). Süreç topolojisi §16'dadır (MD-1: kenar protokol gateway'leri ayrı süreçtir).

### 7.1 Ownership matrix (canonical; tek owner, tek source of truth)

Kurallar:
- Her fact'in tek bir canonical owner'ı vardır; diğer her kopya observed, cached veya projected'dır (EI-1).
- "Access" = ilgili AuthorityDomain'in authoritative provider'ı: Suiss-hosted veya conformant üçüncü taraf, aynı rol.
- Provider semantik ayrıcalık taşımaz (G24, PI-13, PI-14).
- ** "Identity plane" satırları.** "Identity plane" = ilgili Identity Realm'i barındıran Access identity plane'i. Suiss-hosted veya self-host, aynı rol. Bu satırlar tablonun sonundaki "Identity plane ve kiracılık satırları" bloğundadır. Identity plane nesneleri (realm, user record, credential, login oturumu, client) identity plane nesneleridir, authority primitive'i değildir. Authority etkileri yalnız mevcut primitive'lerle ifade edilir.

| Fact | Canonical owner | Access'teki biçim | Kopyalar / not | Dayanak |
|---|---|---|---|---|
| Party identity (PartyID, key-event history) | Party Identity Regime (Party + identity controller); merkezi Suiss registry yok | External reference (PartyRef) | Access Identity plane = controller-custodian + issuer implementasyonu; custody ≠ controller ≠ root | C5, E4, B7 |
| Principal | — | Rol: Exercise.capacity (basis Grant AgencyTerms ile) | Entity değildir | C5 |
| IdentityBinding / authentication assurance | Issuer (Access Identity plane veya compatible IdP) | Claim + Acceptance(actor-binding) | Access yalnız kendi issue ettiği Claim'lerin owner'ıdır | E4 |
| AuthorityDomain, Genesis, rootTerms, `domain.recover` entry'si | Domain root (meta-anchor) | Primitive + Genesis kaydı | DomainID provider'dan bağımsızdır | C1, PI-15, SEC20 |
| Provider binding (domain'in signing anahtarları) | AuthorityDomain (yalnız `domain.handover` / `domain.recover` ile değişir) | Domain değeri | Anchor root'un amend yetkisi provider binding'i kapsamaz | PI-15, P4 |
| AuthorityAnchor, Grant, Mandate, Instance, Acceptance, RestrictionPolicy | Access (domain ledger'ı) | Primitive / policy construct | Hub, projection ve token'lar yalnız projection'dır | C1–C3, EI-1 |
| Authority Exercise, DecisionRecord, AuthorityStateBasis | Access | Primitive / record / value | Unit of value (B17) | C30, INV-27 |
| Authority state | Domain log (canonical) | Record-fold (TI-RT1) | DERIVED ve SYNC-DERIVED katmanlar log'a asla baskın gelmez; snapshot yalnız hızlandırıcıdır | TI-1, TI-RT1, TI-RT4 |
| Kayıt kimliği | Commitment (leaf / body digest) | — | Commitment-eşleşen kopyadan geri yükleme meşrudur | TI-RT11 |
| Checkpoint | Provider imzalar; witness cosign eder | Claim | Tazelik = bağımsız witness cosign (TI-RT5); heartbeat checkpoint'i de `checkpoint` Claim'i olarak ingest edilir | SEC21–SEC23 |
| Witness ve replica seçimi | Domain root (Genesis / Domain Metadata beyanı) | Beyan | Suiss kendi host ettiği domain'de bağımsız sayılmaz (B13); D5 yalnız önerir | P32, SI-12, B13, D5 |
| N (recovery'de cite edilen checkpoint) | Recovery Exercise'ı (root) | StateBasis'te cite | Tanım SEC21 | SEC21, SEC22 |
| Quarantine policy (divergence, nonce-closed); RestrictionPolicy overlay'i | Root / Security Party'nin narrowing `policy.set`'i (handover / recover ile aynı Exercise kümesinde veya rebuild-diff bildiriminden sonra); provider yalnız kanıt bildirir | Restriction | Divergence kapsamı (TI-RT1): divergent kaydın genişletici effect'leri recovery, handover ve rebuild-diff yollarının hepsinde DENY; `nonce-closed/pre-recovery` SEC22 R1 policy'sinin parçasıdır; kaldırma CT3. Ingest quarantine (Claim disposition) bu satır değildir (§7.2) | C3, SEC22 R1, TI-RT1, TI-RT3 |
| Claim içeriği ve doğruluğu | Issuer | Record (ingest kaydı Access'te) | Claim ≠ Truth; güncellik issuer sırasıyla (TI-RT7) | INV-14, RT15 |
| Effect ve effect receipt | Executor / domain PEP | Claim (input) | Access effect beyan etmez | INV-18, EI-10 |
| Gate placement, Commitment, autonomy | Work | External (opaque ref) | Gate satisfied ≠ ALLOW | G30, E7 |
| Approval act | Approver (Access contribution Exercise'ı) | Exercise | Work Declaration ayrı bir fact'tir, ikinci kaynak değildir | C1, E7 |
| Approval render (AAS) | Access (AAS) + conformant Surface | Protocol construct | CT3 bağımsız render yolu | AP-6, §9.14, U7 |
| Funds / balance / financial hold | Money / Pay | External | Budget ≠ balance | E21, F9 |
| Classification, label, DLP | Data owner / governance | Claim | Disclosure authority Access'tedir | F11 |
| Resource ve action schema | Domain | External + Acceptance(schema-definition) | Prefix katalog sürümüne pin'lidir | E11, AP-9 |
| Projection (token, PAP, AuthZEN cevabı, SSF event) | Access (issuance); taşıyan sistem (transport) | Protocol construct | Projection ⊆ source | G2, G18 |
| Domain Metadata | AuthorityDomain (provider yayımlar) | Derived yayın | Verifier cache ≤ Δ; tazelik TI-RT5 | T29, TI-RT5 |
| Verifier Profile (yerel tavanlar) | Verifier | Beyan | `cap_horizon` kaynağı | U25 |
| `basis_ref` / event-id anahtarı | AuthorityDomain (domain başına) | Secret | Opaque `basis_ref` token'ı ve HMAC event id bu anahtardan türer; anahtar domain'in authoritative provider'ı dışına çıkmaz; kooperatif handover'da Record Export Package içinde yalnız yeni provider'a açık biçimde taşınır; forced recovery'de anahtar yoksa eski token'lar çözülmez ve fail closed olur | TI-RT10, T11 |
| POLICY DEFAULT değerleri | Genesis / template içeriği (domain) | Policy | Sıkılaştırma narrowing, gevşetme genişletmedir | SEC8, SI-18 |
| L0–L3 normatif metin + conformance vektörleri | Protocol governance (D3: neutral vakıf / SDO) | Spec | Access Core bir implementasyondur | P1, RT8, B9 |
| Reference evaluator sürümleri | Suiss (açık reference'ta korur) | Kod | B12 | RT8, B12 |
| Ticari fiyat ve paket | Suiss (B1–B18 sınırında) | — | Semantiği değiştiremez | B1 |

**Identity plane ve kiracılık satırları.** Aşağıdaki her satır identity plane'in (veya ticari/fiziksel eksenin) tek owner'ını yazar. "Access'teki biçim" sütunu, fact'in authority plane'e hangi mevcut biçimle girdiğini gösterir. Yeni authority primitive'i yoktur.

| Fact | Canonical owner | Access'teki biçim (authority plane) | Kopyalar / not | Dayanak |
|---|---|---|---|---|
| **Tenant** (ticari hesap: fatura, kota, sözleşme, destek) | Suiss ticari sistemi (B1–B18 sınırında) | Yok. `tenant_id` hiçbir authority kararına girdi değildir | Depolarda savunma derinliği anahtarıdır: identity plane, derived, PII vault ve operasyon tablolarında PK'de `tenant_id`, bileşik FK, RLS FORCE. Authority canonical log ve kayıtları `domain_id` ile anahtarlanır; tenant ↔ domain eşlemesi placement directory'dedir (append-only log ticari hesap değişince yeniden anahtarlanamaz; OP-12). Semantik değildir. Mekanizma §12 ve §17'dedir | MD-5, T27 |
| **Cell / yerleşim** (`placement_id`) | Platform operasyonu | Yok | Fiziksel yerleşimdir. Domain ve realm kimliği cell'den bağımsızdır | MD-5, T27, T28 |
| **AuthorityDomain ↔ Tenant ilişkisi** | Tenant (barındırma kaydı). Domain kimliği tenant'tan bağımsızdır | Domain Metadata'da beyan edilmez; authority girdisi değildir | Bir tenant 0..n domain barındırır; realm barındıran tenant en az 1 domain barındırır, çünkü her realm'in tam olarak bir yönetişim domain'i vardır. Bir domain asla iki tenant'a yayılmaz. Handover domain'i tenant'sız taşır | MD-5, E20 |
| **Identity Realm yapılandırması** (issuer URL, realm JOSE anahtar seti, RP ID, login ad alanı, marka/tema, giriş politikası, enumeration modu) | Identity plane (realm) | Değişikliğin **yetkisi**, realm'in **yönetişim domain'inde** (`realms.governing_domain_id`; tektir; bir değerdir, primitive değildir) bir `idp.*` domain action Exercise'ıdır (ADP `commit`). Config **değeri** identity plane'in domain truth'udur (E16 sözleşmesi). Realm'in kimlik Claim'lerini tüketen diğer domain'ler config yetkisi taşımaz; yalnız kendi Acceptance'larını taşır | Config değeri yalnız committed ALLOW'a referansla yazılır. Exercise intent'i değişikliğin digest'ini bağlar. Varsayılan: 1 realm ↔ 1 domain (yönetişim domain'i aynı zamanda tek tüketen domain'dir). Genel durum "N:M" değil, **1 yönetişim domain'i + N tüketen domain**'dir; her tüketen domain bunu kendi Acceptance'ıyla bildirir. Yönetişim domain'inin değişmesi `idp.realm.rehome` meta-Exercise'ıdır (reserved, CT3; eski ve yeni domain'de commit; `anchor.transfer` gibi iki uçlu) | MD-5, MD-14, E16, E34 |
| **Realm ↔ AuthorityDomain ilişkisi** (yönetişim + tüketim) | Yönetişim: realm kaydının `governing_domain_id` değeri (identity plane kaydı; değişikliği yalnız `idp.realm.rehome` iki uçlu reserved Exercise'ıyla). Tüketim: her tüketen domain'in kendi Acceptance kaydı | Yönetişim bir **değerdir**, Acceptance değildir. Tüketim **Acceptance'tır**: domain realm'in issuer'ını use-typed kabul eder (actor-binding vb.). §5.16 ile bu tablo arasındaki "Acceptance'tır / değildir" ayrımı budur | Yönetişim bağı realm'e authority vermez. Authority girişi yalnız Acceptance kadardır (§7.9.1.3). Realm config'ini yalnız yönetişim domain'i yetkilendirir; tüketen bir domain'in `idp.*` commit'i DENY'dır (`no-covering-authority`) | MD-5, MD-14, E3, E18 |
| **Client / RP kaydı** (client_id, redirect URI, izinli grant tipleri, imza algoritması allowlist'i, upstream IdP bağlantısı) | Identity plane (realm) | Yetki: `idp.client.*` / `idp.upstream.*` domain action'ı (MD-14). Client'ın Access authority'si yoksa Grant da yoktur | Algoritma allowlist'i header'dan değil client/Domain Metadata'dan gelir (MD-3). Redirect yalnız tam eşleşmeyle yapılır | MD-14, MD-3 |
| **User record** (realm-yerel login tanımlayıcısı, profil öznitelikleri, PII) | Identity plane (realm). `UNIQUE(realm, …)` | Gerekli identity Claim'leri (değer veya digest) | E-posta asla anahtar değildir. PartyRef regime referansıdır, global tablo değildir (E4, INV-12) | MD-5, E4, E26 |
| **Hesap durumu** (active / disabled / locked / recovery / tombstone) | Identity plane | Claim (`account.status`). Domain'in varsayılan güvenlik politikası (Genesis şablonu, POLICY DEFAULT) realm issuer'ının kabul edilmiş `account.status ∈ {suspended, deactivated, tombstone}` Claim'ini, ilgili PartyRef'in o realm üzerinden actor-binding'le kurulmuş Instance'larına **DENY overlay'i** olarak uygular (E5 restriction kanalı; Claim'in ingest pozisyonundan itibaren; actor gerektirmez; kaldırılması genişletmedir, SI-4). `instance.terminate` ve departure, attributable bir Party'nin ayrı **temizlik** Exercise'larıdır; güvenlik bunlara dayanmaz | Durum identity plane'de tek işlemde değişir. Authority daraltması Claim ingest'iyle ve kabul edilmiş politikayla gelir. Hiçbir authority **genişlemesi** kendiliğinden olmaz. Actor-binding başarısızlığı yalnız yeni `instance.create`'i engeller; mevcut Instance'ları overlay daraltır. `suspended` ve `deactivated` en az aynı daraltmayı üretir. Offline projection'lar beyan edilmiş pencerede kalır | MD-13, E5, E29 |
| **Credential / authenticator** (passkey public key, parola hash'i, TOTP sırrı, kurtarma kodları) ve authenticator binding | Identity plane (issuer olarak). Suiss-hosted Party'lerde controller-custodian | `authenticator-binding` / `authentication` Claim'i | Authority kaydı değildir. Authority kayıtları sır içermez. Yönetim API'si kullanıcının credential'ını yazamaz; yalnız tek kullanımlık kurulum niyeti üretir (→ §12). Yeni binding SEC18'e tabidir | E4, §7.9.12.4, SEC18 |
| **Login oturumu** (identity plane oturumu: çerez/refresh durumu, boşta kalma ve mutlak süre, DBSC/DPoP bağı) | Identity plane | Bir identity plane oturumu cihaz başına tam olarak bir insan **Instance**'ına bağlanır (bağ: aynı KeyBinding; değerdir, yeni nesne yoktur). Sürekliliği KeyBinding taşır (INV-13). Identity plane oturumunun kendisi authority değildir; oturum Instance değildir, Instance da oturum değildir | Boşta kalma ve mutlak süre authentication Claim tazeliği olarak ifade edilir. `instance.terminate` sonrası identity plane ilgili identity plane oturumunu ve token'ları kapatır (§7.9.1.2). Sign-out oturumu bitirir ve o oturuma bağlı Instance'ı sonlandırır (`instance.terminate`; temizliktir, başka Instance'ların authority'si etkilenmez, XI-23). Oturum ömrü (boşta/mutlak) dolduğunda bağlı Instance actor-binding tazeliğini karşılayamaz (PD) | MD-13, INV-13 |
| **`session_epoch`** (identity plane hızlı iptal sayacı; Instance veya Party başına) | Identity plane | Mekanizmadır. Semantik sözleşme ValidityContract'tır | `instance.terminate` ve `party.compromise` sonrası tetiklenir. Authority semantiğini (StateBasis, cascade, status list) değiştirmez | MD-7 |
| **Identity plane token'ları** (ID token, access/refresh token, SAML assertion, logout token) | Identity plane issuance. Taşıyan sistem transport'tur | Authority taşıyan içerik bir Grant'ın projection'ıdır (`projection.issue`, S-1). Protokol scope'ları (`openid`, `profile`, `offline_access`) identity plane semantiğidir | Semantik sözleşme ValidityContract'tır (MD-7). Yönetimde access token ≤ 60 dk (PD). Pairwise `sub` varsayılandır (MD-10) | MD-7, MD-10, L24 |
| **Üçüncü taraf RP consent'i** (kaynak erişimi ifade eden scope / `authorization_details`) | Authority plane: S1 exact preview'den sonra `grant.issue` Exercise'ı | Grant + projection | Identity plane'in consent kaydı bu Grant'ın projection'ı veya cache'idir; çelişkide Grant kazanır. Protokol scope'larının (claim release) consent'i identity plane'dedir | X9, L24 |
| **IdentityBinding (realm'ler arası bağ, upstream IdP bağlantısı)** | Issuer (identity plane veya upstream IdP) | Claim + Acceptance(actor-binding) | Realm'ler arası bağ yalnız açık IdentityBinding ile kurulur. E-posta eşleşmesiyle otomatik bağlama yoktur | MD-5, E4, E18 |
| **Upstream IdP kimlik doğrulaması** (Access identity plane bir RP / federation broker olduğunda) | Upstream IdP | Claim (`authentication`, attribute) | Upstream grup claim'i Acceptance'sız selection'a giremez (E18, L6) | E18, L6 |
| **SCIM kaynakları** (Access SCIM sunucusu olduğunda: provisioned User/Group) | Identity plane (kayıt). Gerçek dünya truth'u (istihdam, ekip) issuer'ındır (HR / upstream dizin) | Grup üyeliği = Claim (MD-4). Grup → izin = rule-shaped Grant | SCIM yazımı Grant değildir. SCIM DELETE tombstone semantiği §12'dedir. Her grubun tek bir üyelik issuer'ı vardır (domain veya belirli bir upstream); upstream grup mapping'i reserved bir requirement ile korunur | MD-4, E15, CI-2 |
| **Giden SCIM / provisioning** (Access client olduğunda) | Hedef uygulama (kendi kullanıcı deposu) | Yok (hedef uygulamanın state'i) | Access hedefteki hesabın varlığını beyan etmez. Hedefin raporu Claim'dir | E25, EI-3 |
| **Organizasyon (B2B, realm içinde)** | Organizasyonun kendisi bir Party'dir. Yapısı Party + Anchor'dır | Party (PartyRef) + AuthorityAnchor + Grant | Ayrı domain değildir. Cross-org yetki bridging Grant'tır | MD-5, C10 |
| **Token vault / ajan credential broker'ı** (upstream OAuth token'larının saklanması) | Identity plane (custody) | Upstream token'ın bir ajana verilmesinin **release kararı** bir Exercise'tır (Access kararı). Upstream token Access projection'ı değildir; içeriği NOT GUARANTEED'dır (G2 "projection ⊆ source" upstream token içeriğine uygulanmaz). Token `exp` ≤ kararın ValidityContract horizon'u. CT2+ için varsayılan: broker PEP olarak çalışır. Possession ≠ authority | Authority kayıtları sır içermez. Vault yalnız geçerli bir Exercise referansına karşı serbest bırakır | MD-13, §7.9.12.4, E36 |
| **Genel sır / credential custody** (sunucu parolaları, statik SSH anahtarları, credential injection, PAM oturum aracılığı ve kaydı) | Ayrı ürün katmanı (Vault / PAM / Executor / Pay). Kısa ömürlü SSH sertifikası verme ve Linux PAM/NSS bağlantısı Access'tedir (IDP-32) | "Kim kullanabilir" kararı Access'tedir (Grant + RequirementTerm + Mandate) | Access bu katmana karar ve projection verir, ondan olay ve sinyal alır | MD-13, E22 |
| **Identity plane audit akışı** | Identity plane | Projection (SIEM'e) | Düz append-only + Merkle checkpoint + dış witness. Authority log'u T3 olarak kalır | — |
| **CAEP/SSF yayını** | Identity plane (identity olayları). Authority semantic event içeriği Access'indir (L18) | Derived semantic event | Güvenlik teslimata dayanmaz. Transport Relay veya SSF'dir | L18, MD-13 |
| **Gelen CAEP/SSF ve risk sinyalleri** | Sinyalin issuer'ı | Claim (`risk.*`, posture). Yalnız daraltır (CI-2) | Sinyal kaybı veya cache arızası ALLOW'a dönmez (MD-8) | CI-2, MD-8, MD-13 |
| **Destek erişimi** (support access) | Destek isteyen Party'nin authority'si (kullanıcının Grant Exercise'ı) veya reserved break-glass Grant'ı | Grant (+ requirement'lar). Impersonation yoktur. Hedef, identity plane hesap kaynakları üzerindeki `idp.account.*` domain action'larıdır (E34); kaynakların root'u kullanıcının self-anchor'ıdır (`scope = Party(P)`). Break-glass yalnız self-anchor rootTerms'ünde admission'da (E6) beyan edilmiş reserved istisnai Grant olarak vardır | Destek erişiminin 12 değişmezinin şablon değerleri PD'dir; statü ve guarantee satır satır §8.16'dadır | MD-9, X20, INV-28 |
| **Pairwise takma ad türetimi** (OIDC/SAML `sub`, domain dışı projection'lardaki PartyRef) | Identity plane (OIDC/SAML). AuthorityDomain (domain-pairwise PartyRef türetim anahtarı) | Value-level türetim. Yeni primitive yoktur | İç PartyID değişmez. Domain'ler arası korelasyon yalnız açık bridging Grant veya IdentityBinding ile kurulur. Türetim anahtarı `basis_ref` anahtarıyla aynı kurala tabidir: domain'in authoritative provider'ı dışına çıkmaz, kooperatif handover'da Record Export Package içinde taşınır. Forced recovery'de anahtar yoksa yeni anahtar recovery Exercise'ında beyan edilir ve takma ad sürekliliği kaybı NOT GUARANTEED olarak açıklanır (E20 deseni). İç PartyID hiçbir durumda dışarı çıkmaz | MD-10 |
| **Binding key kapsamı beyanı** | AuthorityDomain (Domain Metadata) | Domain değeri | Verifier DomainID'yi must-understand olarak denetler. Storm-0558 sınıfı HL-8'dedir | MD-6 |

**Sonuç:** İki source of truth yoktur; hiçbir fact iki owner'a bölünmemiştir. Ownership, handover veya recovery sırasında da değişmez: değişen yalnız provider binding'dir ve o da AuthorityDomain'in kendi kaydıdır.

**İki kayıt, iki fact (identity plane yapılandırması).** Bir realm yapılandırma değişikliğinde iki ayrı fact vardır:
- (a) değişikliğin yetkilendirilmesi: authority plane'deki Exercise/DecisionRecord;
- (b) yapılandırmanın değeri: identity plane'in domain truth'u.

Bu bir Generic Domain Product ilişkisidir (E16): identity plane kendi config'inin PEP'idir ve Access kararı ister. Aynı fact'in iki owner'ı yoktur. (b), (a)'nın digest'iyle bağlıdır. Committed ALLOW'a referans vermeyen config yazımı bir uygulama hatasıdır ve fail-closed reddedilir (MD-8). Çelişki tespit edilirse config yanlıştır, çünkü kaynağı yetkilendirilmemiş bir yazımdır. Kurtarma yeni bir Exercise ile yapılır.

### 7.2 Canonical terminoloji

Her terimin tek anlamı vardır. Aşağıdaki terimler spec boyunca bu anlamda kullanılır; UI eşlemesi §8.8'dedir.

| Canonical | Anlam (tek) | Dayanak / not |
|---|---|---|
| AuthorityAnchor | Resource authority kökü (root değeri taşır) | C1 |
| Grant | Holding yaratan meta-Exercise ürünü | Grantor yetkisini kaybetmez |
| Mandate | Instance-bounded sınır | UI'da "Instance limits" |
| Instance | Somut execution / sign-in örneği | UI render: "Sign-in on *device*" / "Running copy" |
| ValidityContract + continuation | Uzun süreli exercisability | C31 |
| DecisionRecord | Relied-upon karar kaydı | C1 |
| SubjectSelector | Rule-shaped Grant seçicisi | C1 |
| BudgetTerm | Authority budget | F9, E21 |
| Principal | Rol (capacity) | C5 |
| Party Identity Regime | Party kimliğinin owner'ı | C5, B7 |
| witness/replica-before-ack (SEC23) | Revocation / CT3 ack koşulu | SEC23 |
| N | SEC21 checkpoint'i | SEC21 |
| R* | Replica'dan yeniden üretilebilen en yüksek witness'lı checkpoint | SEC22 |
| record-fold | Devralan provider'ın ve SYNC-DERIVED'ın state kurma biçimi: kayıtlı DecisionRecord effect'leri + Claim'lerden L0 türetim | TI-RT1 |
| Access Core | L0 semantiğinin open-source implementasyonu; normatif değildir (normatif = L0/L2 + vektörler) | T12, RT8, TI-RT12 |
| FA-13 / FA-14 | Cross-cell fence / depolama bozulması tespiti (iki ayrı varsayım) | §16.2, TI-RT11 |
| `budget-exhausted/release-exceeds-draw` | Σrelease > draw blocker'ı | TI-RT8, RT25 |
| `nonce-closed/pre-recovery` | K-3 blocker'ı (mekanizma: profile kuralı + SEC22 R1 quarantine policy'si; policy CT3 ile kaldırılır) | SEC22 R1, TI-RT3 |
| Heartbeat checkpoint | Değişiklik olmasa da üretilen, witness'lara gönderilen ve `checkpoint` Claim'i olarak ingest edilen cadence checkpoint'i (log ilerler; quiet domain'de status `iat` tazelenir; handover freeze'inde askıdadır) | T16, SEC21 |
| ingest quarantine (`quarantine:<reason>`) | Claim ingest disposition'ı (P19: admit / quarantine / reasoned reject): kaydedilir, karar girdisi olmaz | P19 |
| quarantine policy | RestrictionPolicy DENY overlay'i (SEC22 R1 post-recovery quarantine; divergence quarantine); kaldırma CT3 | SEC22 R1, TI-RT1, TI-RT3 |
| `witnessed_through` | Okuma cevabındaki witness'lı pozisyon | SEC23, RT24 |
| Hub cache | Viewer-scoped okuma snapshot'ı | T30, SI-15 |
| Root Test | Yalnız heuristic; boundary kuralı değildir (boundary kuralı §2.6: Domain Truth / Eligibility Test + Authority Exercise Test + Composition Rule; "WHO acts" kuralı kullanılmaz) | F6 |

**Identity plane ve kiracılık terminolojisi.** Aşağıdaki terimler de tek anlamlıdır. Aynı kelimelerin sektördeki farklı kullanımları bu tabloya göre okunur.

| Canonical | Anlam (tek) | Karşılık / not | Dayanak |
|---|---|---|---|
| **Tenant** | Ticari hesap: fatura, kota, sözleşme, destek. Semantik değildir. Hiçbir authority kararına girdi değildir | Issuer, anahtar ve kullanıcı ad alanı anlamındaki "kiracı" **Identity Realm**'dir. "Kiracı" yalnız ticari anlamda Tenant'tır | MD-5 |
| **AuthorityDomain** | Authority semantiğinin tek birimi: Genesis, log, DomainID = genesis digest, KEK, operasyonel imza anahtarı kapsamı | — | MD-5, T27, C1 |
| **Identity Realm** (kısaca realm) | Identity plane ad alanı: issuer URL, realm JOSE anahtarları, RP ID, login ad alanı, kullanıcı ve credential'lar, client'lar, marka/tema, giriş politikası | Keycloak "realm"; "kiracı" (tenant) olarak da anılır. Varsayılan eşleme 1 realm ↔ 1 domain'dir | MD-5 |
| **Cell** | Fiziksel yerleşim birimi (`placement_id`) | `placement_id` | MD-5, T27 |
| **Identity plane oturumu** (login session) | Identity plane'deki giriş sürekliliği: çerez/refresh durumu, boşta kalma ve mutlak ömür, DBSC/DPoP bağı. Authority değildir | Spec'te nitelemesiz "oturum/session" kullanılmaz | MD-13 |
| **Experience oturumu** | Work'ün ephemeral Experience session'ı (Work-owned) | — | §8.11 |
| **PAM oturumu** | Ayrı ürün katmanının (PAM) privileged session'ı. Access yalnız açma kararını verir; aracılık ve kayıt PAM'indir | — | E22, §7.6 |
| **RP uygulama oturumu** / **upstream IdP oturumu** | Dış owner'ların (RP, upstream IdP) kendi oturum kayıtları. Access'in kaydı değildir | — | §7.3 |
| **Instance** | Somut execution / sign-in örneği (authority primitive, domain kapsamlı). Bir identity plane oturumu cihaz başına tam olarak bir insan Instance'ına, aynı KeyBinding üzerinden bağlanır. Oturum Instance değildir ve Instance da oturum değildir. Sign-out oturumu bitirir ve o Instance'ı sonlandırır (temizlik; başka Instance'lar etkilenmez). Sürekliliği KeyBinding'dir | Identity plane oturumu ile insan Instance'ı ayrı kayıtlardır; insan Instance'ı authority kaydıdır | C1, INV-13 |
| **Credential** (nitelemesiz) | Identity plane kimlik doğrulama bilgisi (authenticator): passkey, parola, TOTP, kurtarma kodu | "Decision ≠ Credential" ilkesi bu tanımla çelişmez. Anlamı şudur: karar, sunulabilir bir erişim credential'ına dönüşmez. Token kastedildiğinde "projection" veya "token" yazılır | E4 |
| **Client** | Identity plane'e kayıtlı OAuth/OIDC/SAML istemcisi (RP) | "İstemci" | MD-14 |
| **IdentityBinding** | Bir issuer'ın, bir authenticator/hesabın bir PartyRef'e bağlı olduğu iddiası (Claim). Realm'ler arası bağın tek yolu | `identity_links.proof` ≈ actor-binding Acceptance altında ingest edilen IdentityBinding Claim'i | E4, MD-5 |
| **`session_epoch` / `key_epoch`** | Identity plane hızlı iptal ve anahtar penceresi **mekanizmaları**. Semantik sözleşme değildir (semantik = ValidityContract) | Authority plane'de `authz_epoch` kullanılmaz; yerini AuthorityStateBasis ve `applied_pos` alır | MD-7 |
| **Organizasyon (B2B)** | Realm içinde Party + AuthorityAnchor. Ayrı domain değildir | "Organizasyon" | MD-5 |
| **Token vault / credential broker** | Identity plane'de upstream token custody'si. Serbest bırakılması Access kararıdır: release kararı bir Exercise'tır; upstream token projection değildir | "Federated credential vault" | MD-13 |
| **Ayrı ürün katmanı** | Access'in authority kısmına karar verdiği, olay ve sinyal ürettiği ama sahiplenmediği yetenek: PAM oturum aracılığı/kaydı, DLP, SIEM, genel sır kasası, risk/fraud skorlama motoru, MDM, IGA kampanyası | Plane atamasında (§7.6) Access'in sahiplenmediği yetenekleri adlandıran terim | MD-13, §7.6 |

**"Quarantine" kelimesinin iki ayrı anlamı.** Spec bu kelimeyi tek başına kullanmaz; her zaman nitelikli yazar:

| Terim | Tür | Ne yapar | Kim koyar / kaldırır | Authority etkisi |
|---|---|---|---|---|
| **ingest quarantine** (`quarantine:<reason>`) | Claim ingest disposition'ı (P19: admit / quarantine / reasoned reject) | Claim kaydedilir ama karar girdisi olmaz | Ingest kuralı (kota, tazelik, issuer sırası); Acceptance kuralına göre yeniden değerlendirilir | Hiçbir authority genişletmez veya daraltmaz; yalnız girdiyi dışarıda tutar |
| **quarantine policy / quarantine overlay** | RestrictionPolicy DENY overlay'i (SEC22 R1 post-recovery quarantine; TI-RT1 divergence quarantine; `nonce-closed/pre-recovery`) | Kapsamındaki genişletici effect'leri DENY eder | Root / Security Party'nin narrowing `policy.set`'i koyar; kaldırma genişletmedir ve CT3 ister (TI-RT3) | Restriction: yalnız daraltır (INV-11) |

### 7.3 Pairwise seam matrix

| Seam | Access owns | Other side owns | Shared contract | Forbidden coupling |
|---|---|---|---|---|
| **Access ↔ Identity regime** | Domain admission (`party.register` + self-anchor), Instance (authority-binding), Acceptance of identity issuers, departure disposition | PartyID, key-event history, identity controller, Party recovery, Party termination | PartyRef; regime olayları Claim olarak; Access Identity plane = bir controller-custodian/issuer implementasyonu | Access'in global Party registry'si olması; regime olayının authority state'ini otomatik değiştirmesi; Party recovery'nin Instance'ları sessizce taşıması |
| **Access ↔ Work** | Authority, authority delegation, approval authority, contribution Exercise, Exercise kaydı, capacity doğrulaması | Commitment, work delegation, Gate placement & satisfaction, autonomy, accountability, handoff, Work evidence | ExerciseID / GrantID referansları; Gate digest'i; eligible set; `commitment.active` Claim'i (narrow-only); on-behalf-of ⊆ capacity | Work'ün authority yaratması/genişletmesi/Access DENY'ını Gate ile aşması; Access'in Work state'i okuması; iki taraftan birinin diğerinin kaydını kopyalayıp canonical sayması |
| **Access ↔ One** | One Party'nin domain'e kabulü, One Instance'ları, user→One Grant'ları, Mandate, capacity FOR(user) | Memory, reasoning, planning, personal preference, private provenance, personal continuity | IntentEnvelope (minimal), user'ın kendi Instance'ından explicit contribution/grant | One'ın konuşmadan/hafızadan authority üretmesi; Access'in One private context'i istemesi; One'ın user yerine approval vermesi (agency ve independence izin vermiyorsa) |
| **Access ↔ Executor** | Authorized intent envelope, Decision, Exercise, ValidityContract, StateBasis, continuation DecisionRecord | Execution, sandbox, fencing, idempotency, pause/cancel/takeover, effect, checkpoint, stop state | ExerciseID, ValidityContract, re-check noktaları, effect attestation Claim'i | Access'in execution lifecycle'ına katılması; Executor'ın ALLOW'u başka intent'e uygulaması; "revoked ⇒ stopped" |
| **Access ↔ Relay** | Semantic event içeriği (derived): kime, neden, hangi intent/Grant'a bağlı, ne zamana kadar | Kanal, timing, retry, fallback, presence, realtime, delivery ack | Semantic event (derived notification) + adresleme ipuçları. Transport Relay'in **veya** identity plane'in SSF/CAEP vericisinin (delivery adapter) işidir; her iki durumda delivery state ve ack authority state'i değildir (E30), güvenlik teslimata dayanmaz (INV-24) | Relay'in authority truth'u veya event'in commit sayılması; delivery ack'in authority-state değiştirmesi |
| **Access ↔ Money** | Hesap üzerindeki authority (Anchor root, Grant, authority budget) | Account, balance, funds, ledger, account ownership kaydı, dışsal (bank/scheme/regülasyon) financial limits; principal'ın koyduğu ödeme authority limitleri Access BudgetTerm'idir | ResourceRef(account), `funds.*` predicate Claim'leri, ownership Claim'i | Access'te bakiye/hold; Money'nin Anchor root'unu yazması |
| **Access ↔ Pay** | Initiate / approve / refund / payout authority, ödeme authority envelope'u, authority budget | Payment execution, authorization hold, settlement, refund, payout, financial idempotency, network/acquirer state, payment-scheme mandate/consent artifact'ları, network token | Pay PEP'i Access kararı ister; Pay effect attestation Claim'i döner; scheme artifact'ları GrantID/ExerciseID'ye referans verebilir | "Payment mandate" = Access Mandate eşitlemesi; financial hold = authority budget; network token = authority |
| **Access ↔ Commerce** | Commerce action'ları üzerindeki authority (create/change/approve/refund/admin) | Catalog, merchant, cart, order, price, inventory, refund eligibility, seller state, domain policy | Commerce action schema'ları (schema-definition), predicate Claim'leri, membership Claim'leri, ResourceRef | Refund window'un Access'te tutulması; Commerce'in merchant admin'i kendi tablosunda "authority" olarak tutması |
| **Access ↔ Serve** | Operasyonel action'lar üzerindeki authority (void, refund, menu edit, drawer, admin), offline POS projection'ları | Restoran, menü, lokasyon, vardiya, sipariş, mutfak, teslimat, operasyon | Serve schema'ları, `shift.*` / `role.*` Claim'leri, offline exercise raporları | Access'in vardiya planlaması; vardiya listesinin Grant sayılması |
| **Access ↔ external IdP** | Acceptance (use-typed), Instance, actor-binding sonucu | Kimlik doğrulama, kullanıcı dizini, attribute'lar, kendi (upstream IdP) oturumları | Claim'ler (authentication, attribute, group) | IdP'nin authority issuer olması; IdP grup claim'inin Acceptance'sız selection'a girmesi |
| **Access ↔ external authority provider** | (Suiss Access olarak) kendi hosted domain'leri; Access **protocol** semantiği her ikisi için ortak | Kendi hosted domain'lerinin authority state'i | Ortak Access protocol; read federation projection'ları; handover meta-Exercise'ı | Bir domain için iki authoritative lineage (semantik olarak tek: root'un handover/recovery Exercise zinciri; eski provider'ın fiilen susması yalnız declared capability); provider'ın root sayılması; Suiss-hosted Access zorunluluğu |
| **Access ↔ IGA** | Grant/Acceptance değişikliğinin kendisi (Exercise) | Review kampanyası, certification, role mining, JML workflow, SoD analizi | IGA kararları Exercise talebi olarak gelir; Access authority graph sorgularını cevaplar | IGA'nın Access state'ini doğrudan yazması; öneri = revocation sayılması |
| **Access ↔ PAM / vault** | "Kim bu privileged action'ı / credential'ı kullanabilir" kararı; JIT activation requirement | Secret custody, credential injection, session brokering, recording | Credential opaque referansı; Exercise ref'i ile custody erişimi | Access'in secret tutması; vault'un kendi başına authority kararı vermesi |
| **Access ↔ MDM / security tooling** | Requirement/restriction olarak posture ve risk kullanımı; containment overlay | Enrollment, compliance, patch, inventory, detection, risk scoring, SIEM korelasyonu | Posture/risk Claim'leri; audit projection'ları | Posture/risk'in authority vermesi; SIEM kopyasının authority source sayılması |

**PAM / vault ve security tooling satırlarının okunuşu.** Yukarıdaki iki satırın "other side" sütunundaki yetenekler (session brokering, recording, risk scoring, SIEM korelasyonu) **ayrı ürün katmanı** olarak okunur, "kapsam dışı" olarak okunmaz. Access bu katmanların authority kısmına karar verir; onlara olay ve sinyal üretir. İki istisna identity plane'e atanır:
- Ajan credential broker'ı / token vault: upstream OAuth token custody'si.
- Identity plane'in kendi giriş-risk sinyalleriyle tetiklediği step-up. Risk yalnız daraltır (CI-2).

Bu iki istisna için forbidden coupling sütunu aynen geçerlidir: authority kayıtları sır içermez ve risk authority vermez.

**Identity plane seam'leri.**

| Seam | Access owns | Other side owns | Shared contract | Forbidden coupling |
|---|---|---|---|---|
| **Identity plane ↔ Authority plane** (Access içi) | Identity plane: realm, user record, credential, login oturumu, client, SCIM kaynakları, token vault, kendi issue ettiği Claim'ler. Authority plane: authority state, Acceptance, Exercise/DecisionRecord | — (iki plane de Access'tir, iki ayrı source of truth) | Identity → Authority yalnız Claim. Authority → Identity derived semantic event (ör. `instance.terminated`) ve InstanceID. Identity config değişiklikleri realm'in yönetişim domain'inde ADP `commit` ile yetkilendirilir (MD-14). Hızlı iptal mekanizması `session_epoch` (MD-7) | Identity plane'in Grant/Mandate/Acceptance yazması; kendi Claim'ine Acceptance vermesi; "admin" kısayolu; ayrı "admin token" sınıfı (MD-14); authority plane'in authenticator bağlaması (§7.9.1.2, INV-12) |
| **Access identity plane ↔ RP / OAuth client** (OIDC, SAML, WS-Fed, LDAP bind tüketen uygulamalar) | Issuer, token issuance, identity plane oturumu, protokol scope consent'i, pairwise `sub` | RP'nin kendi uygulama oturumu, kendi kullanıcı deposu kopyası, Access'e bağlanmamış yerel kararları | OIDC/OAuth/SAML/WS-Fed profilleri (§10). Kaynak erişimi ifade eden scope = Grant projection'ı (S-1). Back-channel logout, CAEP | RP'nin ID token'ı authority sayması (identity ≠ authority); Grant'sız kaynak scope'u basılması; RP'nin rezerve claim yazması; bearer'ın sessiz varsayılan olması |
| **Access identity plane ↔ upstream IdP** (Access federation broker / RP rolünde) | Kendi realm'indeki IdentityBinding kaydı, kendi identity plane oturumu, realm politikası. Domain'de actor-binding Acceptance | Upstream kullanıcılarının kimlik doğrulaması, dizini, upstream IdP oturumu | OIDC/SAML federation. `domain_hint` / login ipucu realm politikasını ezmez (→ §12) | E-postayla otomatik hesap bağlama (nOAuth sınıfı); upstream grup claim'inin Acceptance'sız selection'a girmesi (E18); upstream'in authority issuer olması |
| **Access identity plane ↔ HR / dizin** (SCIM gelen) | SCIM sunucusu kayıtları (user record), ingest edilen membership Claim'leri | İstihdam, ekip, organizasyon şeması gerçeği | SCIM 2.0 (RFC 7643/7644). Üyelik = Claim (MD-4). Seçim yalnız `subject-selection` Acceptance ile (reserved) | SCIM yazımının Grant sayılması; HR verisinin authority vermesi (CI-2); staleness'ın rol kaybı sayılması (C13) |
| **Access ↔ ajan tool sağlayıcısı / upstream API** (token vault) | Upstream token custody'si (identity plane); token'ın hangi ajana, hangi Exercise'la verileceği kararı (authority plane) | Upstream API'nin kendi yetkilendirmesi ve token semantiği | OAuth token exchange / ID-JAG (yalnız identity assertion, MD-18; authority scope içermez). Release, Exercise referansına bağlıdır. Release kararı bir Exercise'tır; upstream token Access projection'ı değildir ve içeriği NOT GUARANTEED'dır; `exp` ≤ ValidityContract horizon; CT2+ sınıflarda varsayılan broker-as-PEP | Exercise'sız token release; token possession'ın authority sayılması; token passthrough (L24) |
| **Access ↔ Suiss ticari sistem** (Tenant) | Hiçbir authority fact'i | Tenant, fatura, kota, sözleşme, destek paketi | `tenant_id` yalnız depolama ve izolasyon anahtarıdır (MD-5) | Tenant admin'inin örtük domain root'u sayılması; ticari paketin semantiği değiştirmesi (B1); güvenlik özelliğinin paywall arkasına konması (B3) |
| **Access ↔ destek operatörü** (Suiss desteği, kiracının destek ekibi) | Destek erişiminin authority'si (kullanıcının Grant'ı veya reserved break-glass Grant'ı), Exercise kayıtları | Destek vakası, ticket, serbest metin gerekçe (Work veya destek sistemi) | PurposeRef (typed, vaka referansı). `act` taşıyan projection | Impersonation / "view as user"; serbest metin gerekçenin authority taşıması; OrgPolicy'nin organizasyonun kendi kaynakları dışında geçerli olması (MD-9) |
| **Access ↔ PAM oturum aracılığı ve kaydı** (ayrı ürün katmanı) | "Kim bu PAM (privileged) oturumunu açabilir, hangi koşulla (JIT, approval, süre)" kararı; Exercise kaydı; semantic event'ler | PAM oturum aracılığı, kayıt, keystroke/komut denetimi, credential injection | Exercise ref'i ile PAM oturumu açma; kayıt ve olay Claim/projection olarak | Access'in PAM oturum kaydı tutması veya sır saklaması; PAM'in kendi başına authority kararı vermesi (E22) |

### 7.4 Frozen ecosystem decisions (E1–E32)

- **E1** No silent expansion. Hiçbir sistem başka bir sistemin authority'sini sessizce (veya açıkça, kendi yetkisi dışında) genişletemez. Positive authority yalnız AuthorityDomain'in yerel Anchor lineage'ında meta-Exercise ile doğar.
- **E2** One owner per semantic fact. §7.1 ownership matrisi canonical'dır; her satırın tek owner'ı vardır, diğer kopyalar observed, cached veya projected'dır.
- **E3** Access internal planes. Access'te iki source of truth vardır.
  - **Identity plane:** kendi issue ettiği Claim'ler, authentication ceremony'leri, custodial kayıtlar, PII, Identity Realm yapılandırması, realm-yerel user record'ları ve hesap durumu, credential/authenticator verifier materyali, identity plane oturumları, client kayıtları, SCIM kaynakları ve token vault içeriği.
  - **AuthorityDomain kayıt defteri:** Genesis, Exercise/DecisionRecord, Claim ingest; Acceptance dahil authority state.

  Acceptance ve Evaluation ayrı source of truth değildir. Identity plane authority plane'e yalnız Claim verir ve yalnız Acceptance kadar girer. Identity plane yapılandırmasının değiştirilme yetkisi, realm'in yönetişim domain'indeki (`realms.governing_domain_id`) domain action Exercise'ıdır (MD-14, E34). Identity plane'in genişlemesi bu sınırı gevşetmez.
- **E4** Party Identity Regime. Party kimliği protocol-level, product-neutral bir regime'dedir: PartyID ve key-event history Party + identity controller'ındır; merkezi Suiss registry yoktur. Access ve Work aynı regime'in tüketicileridir. Access Identity plane bir controller-custodian ve issuer implementasyonudur; custody ≠ controller ≠ root.
- **E5** Regime state vs authority state. Party creation, key events, controller değişikliği, Party recovery ve termination regime'indir; IdentityBinding ve authenticator binding issuer'larınındır; domain admission, self-anchor, Instance continuity ve departure AuthorityDomain'indir. Regime olayları Access'e yalnız Claim olarak girer ve authority state'i kendiliğinden değiştirmez; etkileri restriction, actor-binding başarısızlığı veya explicit Exercise iledir.
- **E6** Admission and departure. Domain admission party.register meta-Exercise'ıdır ve self-anchor root'unu açıkça belirtir. Departure explicit bir meta-Exercise'tır ve P'nin bütün holding kanallarını varsayılansız kapsar: self-anchor (anchor.retire/anchor.transfer), extensional Grant'lar, Instance'lar (instance.terminate), rule-shaped holding'ler (retain explicit kabul, grantor'ın conjunctive daraltması veya PartyRef'e bağlı RestrictionPolicy overlay'i) ve yeniden giriş kapısı (Public/self bootstrap Grant'larının P için kapalı/açık olduğu, bootstrap Grant terms'ü veya PartyRef overlay'iyle explicit). "Admitted" bir state primitive'i değildir; Exercise kayıtlarından derived'dır.
- **E7** Approval: one mechanism, two facts. Approval act, approver'ın contribute(approve, digest) Exercise'ıdır (Access). Gate satisfaction, o ExerciseID'yi cite eden Work Declaration'ıdır (Work). Intent-bound Gate'te digest hedef intent'in, coordination Gate'te Work'ün canonical Gate payload'ının digest'idir. Eligible set her durumda Access'ten gelir. Work Gate Access requirement'ını karşılayamaz; Gate satisfied ≠ ALLOW.
- **E8** Work delegation and authority delegation are independent and non-atomic. Commitment authority yaratmaz; Grant Commitment yaratmaz; ikisi tek transaction değildir. Grant, Work'ün commitment.active Claim'ine bağlı while-condition ile Commitment-scoped yapılabilir: Work authority'yi bu kanalla bitirebilir, asla başlatamaz.
- **E9** Seam reading of on-behalf-of. Work on-behalf-of atfı Exercise'ın authorized capacity'siyle uyumlu olmalıdır; authority provenance ayrıca incelenir ve on-behalf-of principal'ıyla eşleşmesi aranmaz (lineage root'u ile on-behalf-of eşleşmesi bir koşul değildir). Accountability Work regime'inindir; Access attribution kanıtı sunar.
- **E10** Schema ownership. Domain action namespace'leri, sürümleri ve parametre anlamı publisher'ındır; core meta-action namespace'i Access protocol'ündür. Bir namespace bir domain'de yalnız schema-definition Acceptance'ı ile anlam kazanır. Yayımlanmış sürüm immutable'dır (kimlik = digest). schema-definition Acceptance'ı kabul edilen sürüm ve compatibility mapping digest'lerini exact olarak pin'ler; yeni sürüm veya mapping reserved bir acceptance.amend Exercise'ı ister; compatibility beyanı Claim olarak ingest edilebilir ama kullanılabilirliği o exact digest'i adlandıran Exercise'a bağlıdır. Semantic broadening hiçbir zaman otomatik değildir; yalnız böyle kabul edilmiş non-broadening eşlemeler (representation-equivalent, narrowing) otomatik uygulanır. *GUARANTEED BY SEMANTICS:* kabul edilmemiş sürüm/mapping hiçbir Grant'ın kapsamını değiştiremez. *NOT GUARANTEED:* açıkça kabul edilmiş bir mapping'in publisher tarafından doğru etiketlendiği (publisher trust; kurtarma: Acceptance revoke + ingest-time cutoff).
- **E11** No live action inheritance. Grant'taki namespace prefix, issue anında pin'lenen namespace katalog sürümüne çözülür; sonradan eklenen action'lar grant.amend olmadan kapsanmaz. Reserved action'lar hiçbir sürümde wildcard ile kapsanmaz; reserved bayrağının kaldırılması broadening'dir.
- **E12** Closed attenuation type system. Authority-relevant her parametre Access'in kapalı tip kümesine (enum/set, equality, ordered numeric+unit, count, time interval, resource selector, subject selector, purpose set, boolean) eşlenir; eşlenemeyen authority-relevant parametre schema-definition Acceptance'ında reddedilir. Authority-opaque parametreler digest'e girer, subsumption'a girmez. RAR eşlemesi Access protocol profile'ıdır.
- **E13** Connectivity ownership. Profile semantiği Access protocol'ünün; bir projection'ın hangi profile ile çıkarılacağı AuthorityDomain'in (projection.issue Exercise'ı; staleness riskini (Δ) issuance Exercise'ının actor'ü attributable olarak beyan eder, Δ tavanını lineage terms, rootTerms ve RestrictionPolicy koyar, kayıt AuthorityDomain'dedir); verifier davranışı verifier operatörünün; revocation transport'u Relay'in; offline reconciliation'ın authority tarafı Access'in, effect/finansal tarafı domain/Pay/Executor'ün; liability allocation hukuk/sözleşme/scheme'in; physical stop Executor/domain PEP'in; control koordinasyonu Work'ündür. Revocation ve semantic event transport'u Relay'in **veya** identity plane'in SSF/CAEP vericisinin (delivery adapter) işidir. Her iki durumda delivery state ve ack authority state'i değildir (E30). Güvenlik teslimata dayanmaz (INV-24).
- **E14** Resource lifecycle. Resource varlığı, incarnation, move, split/merge domain'indir; Anchor ve root Access'indir. Domain Anchor root'unu yazamaz; Access resource varlığını beyan edemez. Reincarnation yeni incarnation zorunludur ve eski Grant'ları miras almaz. Domain sahiplik değişikliği root'u değiştirmez; anchor.transfer Exercise'ı gerekir.
- **E15** Domain predicates. Predicate schema'sı ve truth'u domain'in, issuer'ı domain servisinin, freshness beyanı issuer'ın, Acceptance ve use AuthorityDomain'indir. Predicate authority yaratmaz; yalnız önceden explicit kurulmuş bir rule-shaped Grant'ın seçimini etkileyebilir.
- **E16** Generic Domain Product contract. Her domain ürünü (first-party, third-party, gelecekteki) aynı sözleşmeyle bağlanır: schema yayınlar, domain truth'u ve resource'ları sahiplenir, Claim üretir, kendi effect'inin PEP'idir veya Executor'a delege eder, Access kararı ister; Anchor/Grant/Acceptance yazmaz. Yeni ürün yeni authority ontology'si gerektirmez.
- **E17** Every consequential effect at every PEP is backed by its own Exercise whose actor holds the basis; PEPs enforce, never hold. PEP kararı ister/doğrular ve uygular; authority tutmaz, almaz, ödünç vermez; hiçbir Exercise'ta actor'ün Party'si basis holder'ından farklı değildir. Yukarı akış ExerciseID causal context'tir ve tek başına yalnız audit/detection sağlar; proof değildir. Upstream bağ mevcut mekanizmalarla kurulur: RestrictionPolicy (cited upstream ExerciseID committed ALLOW, ActionRef'i policy'nin adlandırdığı kabul edilen upstream action, principal aynı ve envelope'u downstream parametreleri kapsıyor, aksi DENY) + grantor'ın downstream Grant'a koyduğu, upstream ExerciseID'ye anahtarlı count=1 causal-bound allowance (BudgetTerm). Bunlar declared ise bağ GUARANTEED UNDER DECLARED POLICY'dir. Yeni proofKind yoktur.
- **E18** IdP acceptance uses are distinct. Authentication trust (actor-binding), identity claim acceptance (predicate-input), authority-selecting acceptance (subject-selection, reserved) ve foreign authority acceptance (foreign-authority, reserved) ayrı Acceptance'lardır; biri diğerini ima etmez. External IdP compromise, önceden kabul edilmiş rule-shaped seçim ve ceiling'lerin ötesinde authority üretemez. Bu kural Access'in kendi identity plane'i için de aynen geçerlidir. Access realm'inin grup/rol claim'i (SCIM grubu dahil) Acceptance olmadan selection'a giremez. Grup üyeliği bir Claim'dir (MD-4). Identity plane compromise'ının authority sınırı external IdP compromise'ınınkiyle aynıdır.
- **E19** Five federation things. Identity federation, foreign authority evidence, local bridging Grant, cross-domain delegation ve authority-provider handover ayrı mekanizmalardır ve "generic federation" altında birleştirilmez.
- **E20** Provider hosting. Bir AuthorityDomain herhangi bir conformant provider'da host edilebilir; DomainID provider değişiminde korunur (`domain.handover` meta-Exercise'ı); canonical semantik açık Access protocol'ündür. *GUARANTEED BY SEMANTICS:* authoritative lineage tektir ve root'un handover/recovery Exercise zinciriyle belirlenir. *NOT GUARANTEED (yalnız UNDER DECLARED CAPABILITY):* eski provider'ın yazmayı fiilen kesmesi ve cutover öncesi her commit'in korunması (commit'in root'un kontrol ettiği bağımsız witness'a ve provider-dışı replica'ya ulaşmadan acknowledge edilmemesi; witness/replica-before-ack, SEC23). Forced recovery Exercise'ı devam ettiği checkpoint N'yi StateBasis'inde cite eder; N'nin tanımı SEC21'dir (bağımsız witness co-signed ve kökü recovery tarafındaki kayıtlarla yeniden üretilebilen en yüksek checkpoint). N sonrası eski-provider kayıtları devam eden lineage'da authoritative değildir; eski provider'ın o pozisyondan sonra verdiği projection/reusable Decision'lar geçersizdir (fail closed); kayıp revoke/draw riski recovery Exercise'ında beyan edilir; kayıp suffix'teki bir revocation yeni bir revoke Exercise'ıyla prospective olarak yeniden yapılır. Read federation kopyaları projection'dır; Anchor'lar domain'ler arasında kimlik koruyarak taşınmaz.
- **E21** Money/Pay layering. Bakiye, funds, ledger, hold, settlement, refund/payout execution, scheme artifact'ları (payment mandate, consent), network token ve dışsal (bank/scheme/regülasyon) finansal limitler Money/Pay'indir. Initiate/approve/refund/payout/hold-create authority'si ve authority budget Access'indir; principal'ın koyduğu ödeme authority limitleri Access BudgetTerm'idir (Work, F9). Payment mandate ≠ Access Mandate; Pay authorization ≠ Access ALLOW; network token possession ≠ authority; authority budget ≠ financial limit ≠ financial hold. Access ontology'si ödeme terminolojisi yüzünden yeniden adlandırılmaz.
- **E22** Adjacent capabilities → ayrı ürün katmanları. Aşağıdakiler **ayrı ürün katmanlarıdır**: genel credential/secret custody ve credential injection (vault / PAM / Executor / Pay), PAM oturum aracılığı ve kaydı, device posture (MDM), genel risk/fraud skorlama (security tooling), review kampanyaları (IGA), audit arama ve korelasyon (SIEM), veri sınıflandırma ve DLP (data governance). Access bunların authority kısmına karar verir; onlardan Claim veya Exercise talebi alır; onlara karar, projection, olay ve sinyal verir. IGA ve tooling Access state'ini yalnız yetkili bir Party'nin Exercise'ıyla değiştirebilir. Identity plane'e taşınan yetenekler: ajan credential broker'ı / token vault (upstream token custody'si; release kararı bir Exercise'tır, upstream token Access projection'ı değildir, possession ≠ authority) ve identity plane'in kendi giriş-risk sinyalleriyle tetiklenen step-up (risk yalnız daraltır, CI-2). Authority kayıtları sır içermez. Bu katmanlarla entegrasyon ve Access içinde kalan temel parçalar IDP-39'dadır.
- **E23** One boundary. One'ın memory, reasoning, planning ve inference'ı hiçbir zaman authority değildir ve Access'e geçmez. One yalnız user'ın verdiği Grant ∩ Mandate içinde exercise eder. User'ın kendi authority'sini gerektiren her eylem (Grant, genişletme, approval, rebind) user'ın kendi Instance'ından explicit, attributable bir Exercise'tır. One'ın issuer olarak Claim'leri, her personal-delegate / inference-üreten issuer'la aynı issuer-class varsayılanına tabidir; ürün adına bağlı bir Acceptance yasağı yoktur (E24).
- **E24** First-party neutrality. First-party ürünler (Identity plane, Work, One, Executor Runtime, Pay, Commerce, Serve) third-party ile aynı sözleşmeyi kullanır; native integration deneyim avantajı olabilir, semantic privilege olamaz. Farklı muamele yalnız aynı public modelde ifade edilmiş Acceptance/assurance farkıyla olur. Identity plane'in kendi yapılandırması için Access kararı istemesi (dogfooding, MD-14), first-party'nin third-party Generic Domain Product ile aynı sözleşmeyi kullanmasının (E16) örneğidir. Suiss'in kendi hosted giriş sayfası da kiracının yazabileceği bir istemciyle aynı düğüm sözleşmesini (node contract) kullanır (üçüncü sınır → §12).
- **E25** Failure ownership. Bir fact için pozitif/negatif truth yalnız owner'ından gelir; her tüketici başkasının fact'i hakkında UNKNOWN raporlayabilir ve göstermek zorundadır; hiçbir sistem UNKNOWN'u başarıya/durmaya çeviremez; Access'in kendi kararı UNKNOWN değildir. Her sistem yalnız kendi fact'i için reconciliation sahibidir. Access kararı belirsizlikte DENY veya REQUIRE_ACTION'dır; consequential effect'ler Access kararı veya geçerli ValidityContract olmadan yapılmaz. Kullanıcıya gösterilen her gerçek o fact'in owner'ından gelir.
- **E26** Authority-relevance minimization. Access yalnız opaque referansları, authority-relevant typed parametreleri ve gereken Claim'leri alır; domain body'leri, Work içeriği, One memory ve özel veri Access'e geçmez. Access açıklamaları requester'ın authority'si kadar döner.
- **E27** References ≠ ownership. PartyRef, ResourceRef, WorkRef, ActionRef, ExerciseID, GrantID, ClaimID, AuthorityDomainID, EffectRef güvenle sınır geçer; hiçbiri işaret ettiği state'in canonical kopyasını taşıma hakkı vermez.
- **E28** Synchronous before consequential effect; everything else may be asynchronous. Consequential effect öncesi authority (online karar veya contract içi yerel karar) senkron şarttır; state propagation, effect raporu ve bildirim asenkrondur; hiçbir sistem yokluktan başarı çıkarmaz.
- **E29** No semantic cross-product atomicity. Atomicity yalnız tek bir owner'ın kendi geçişleri içindir; cross-product akışlar referans, fail-closed ve compensation ile tutarlı kalır; mekanizma §16'dadır.
- **E30** Relay and acknowledgements. Semantic event derived bir notification'dır; Relay teslim eder ve sahiplenmez. Delivery ack, Work semantic acknowledgement ve PEP authority-state acknowledgement ayrı fact'lerdir; hiçbiri authority state'ini değiştirmez.
- **E31** Executor boundary. Executor her yeni consequential intent'ten önce, ValidityContract horizon'u/checkpoint'te ve pause/takeover/recovery sonrası Access'e döner; continuation'ı actor Instance'ı ister. Stop state, "confirmed stopped" ve uygulanan gerçek parametreler Executor/domain'indir ve Access'e yalnız Claim olarak girer. Revocation ≠ stop.
- **E32** Trusted approval surface. Access exact approval authority'sini, digest'i ve assurance'ı; approval surface sadık render'ı ve user act'i; Work/domain approval'ın nedenini; Executor/domain effect'i sahiplenir. Generic bildirim veya agent prose'u approval artifact'ı değildir.

### 7.5 Anti-monolith testi

> *Access, her Suiss ürününün buluştuğu yer olduğu için her şeyin owner'ı hâline mi geldi?*

> *Have we accidentally made Access the place where every Suiss product meets and therefore the owner of everything?*

| Risk noktası | Kontrol | Sonuç |
|---|---|---|
| Party registry | Party regime'de; Access yalnız admission ve Instance | Sahiplenilmedi |
| Approval toplama / Gate | Work + Relay; Access yalnız contribution geçerliliği ve eligible set | Sahiplenilmedi |
| Schema anlamı | Publisher; Access yalnız tip eşlemesi ve Acceptance | Sahiplenilmedi |
| Revocation teslimi | Relay | Sahiplenilmedi |
| Offline effect reconciliation | Domain/Pay/Executor; Access yalnız authority tarafı | Sahiplenilmedi |
| Risk / posture / IGA / PAM / SIEM | Ayrı ürün katmanları; Claim veya Exercise talebi; Access authority kısmına karar verir, olay/sinyal üretir | Sahiplenilmedi |
| Credential custody | Genel sır custody'si Vault/PAM/Executor/Pay'dedir (ayrı ürün katmanı). Ajan upstream token'ları identity plane token vault'undadır ve release Exercise'a bağlıdır | Genel custody sahiplenilmedi; token vault identity plane'e sınırlandı (authority kaydına sır girmez) |
| **Identity plane'in genişlemesi** (tam IdP: oturum, hesap yaşam döngüsü, SCIM, protokol gateway'leri) | Identity plane facts'i ayrı source of truth'tur (E3). Authority plane'e yalnız Claim verir (INV-12). Config değişiklikleri Exercise'tır (MD-14) | Sahiplenildi, ama ayrı plane olarak. Authority plane'e sızmadı |
| **Ticari tenant'ın authority eksenine dönüşmesi** | `tenant_id` authority girdisi değildir. Domain ve realm ayrı eksenlerdir | Sınırlandı |
| **Destek araçlarının gizli yol olması** | Impersonation yoktur. Destek erişimi Grant'tır | Sahiplenilmedi (gizli yol yok) |
| Stop / control | Executor + Work | Sahiplenilmedi |
| Claim corpus'un data lake'e dönüşmesi | Minimization kuralı (E26) + redaction (C34) | Sınırlandı |
| "Who can do Y" analizinin IGA'ya dönüşmesi | Yalnız derived sorgu; kampanya ve UX IGA'nın | Sınırlandı |

Access'te kalan sahiplik: authority state (Anchor, Grant, Mandate, Instance binding, Acceptance, Policy, budget terms), Exercise/DecisionRecord kayıtları, Claim ingest kayıtları ve Identity plane'in kendi issue ettiği Claim'ler. Geri kalan her şey **referans** veya **Claim**'dir. **Sonuç: Access bir authority control plane'dir, central business state hub değildir.** Azaltma gerekmedi.

**İki plane için anti-monolith sonucu.** Access'te kalan sahiplik iki plane'dedir:
- **Authority plane:** yukarıdaki liste.
- **Identity plane:** Identity Realm yapılandırması, realm-yerel user record'ları ve hesap durumu, credential verifier materyali, identity plane oturumları, client kayıtları, SCIM kaynakları, token vault içeriği, identity plane audit akışı ve kendi issue ettiği Claim'ler.

İş, para, effect, teslimat, schema anlamı, istihdam gerçeği ve ayrı ürün katmanlarının (PAM kaydı, DLP, SIEM, MDM, IGA kampanyası, genel sır kasası) state'i yine referans veya Claim'dir. **Sonuç: Access, tam bir identity plane'i ve onun üstünde bir authority control plane'i olan üründür; central business state hub değildir.** Azaltma gerekmedi. Identity plane'in ürün kapsamında olması hiçbir fact'i iki owner'a bölmez.

### 7.6 Plane ataması

L28'in tek kanonik metni §4'tedir. Bu bölüm metni tekrarlamaz; yalnız aşağıdaki kısa plane atamasını verir.

**Kural (MD-13).**
- Access "X Access değildir" biçiminde dışlama yapmaz; **plane ataması** yapar. Her yetenek üç yerden birine yerleşir: identity plane, authority plane veya ayrı ürün katmanı.
- Gerçek dış sahipler (Work, Pay, Money, Relay, One, Executor, Commerce, Serve, HR/registry) korunur. Onların fact'leri Access'e taşınmaz.
- Must-never'lerin hepsi korunur.
- L28'in metni §4'tedir ve kanoniktir; §2 ve §12.0.2 de ona atıf yapar. §2.5 IS/IS NOT tablosu §2'dedir. Bu tablo ownership tarafındaki kısa plane atamasıdır; §4 ile çelişirse §4 kazanır. Trusted rendering ve instruction-provenance savunması "ayrı ürün katmanı" değildir, **gerçek dış sahiplere** atanır (aşağıdaki iki satır; E32, X3)

| Yetenek | Atandığı yer | Access'in rolü | Guarantee notu | Dayanak |
|---|---|---|---|---|
| Login oturumu, "beni hatırla", boşta kalma + mutlak ömür + olay tabanlı iptal | **Identity plane** | Sahip | Identity plane oturumu authority değildir. Cihaz başına tam olarak bir insan Instance'ına bağlanır; sign-out o Instance'ı da sonlandırır (temizlik) | MD-13 |
| DBSC ve DPoP ile oturum/token bağlama | **Identity plane** | Sahip | Sender-constraint UNDER DECLARED CAPABILITY'dir (tarayıcı/istemci desteği). DBSC desteği "doğrulanmadı" etiketlidir | MD-13 |
| CAEP/SSF vericisi | **Identity plane** (identity olayları). Authority semantic event içeriği authority plane'dedir (L18) | Sahip | Güvenlik teslimata dayanmaz (L18, INV-24) | MD-13, L18 |
| CAEP/SSF alıcısı | **Identity plane** ingest. Sonuç authority plane'e Claim olarak girer | Sahip (alıcı) | Gelen sinyal yalnız daraltır (CI-2). Sinyal kaybı ALLOW'a dönmez (MD-8) | MD-13, CI-2 |
| Risk tabanlı step-up | **Identity plane** (ceremony). Gereklilik authority plane'de RequirementTerm'dir | Sahip | Risk yalnız daraltır (CI-2). Fail-closed (MD-8) | MD-13, CI-2 |
| Identity plane'in kendi giriş-risk sinyalleri (bot, velocity, impossible travel gibi) | **Identity plane**. Ayrıntısı §12 TN-O4'tedir | Sahip | Authority vermez; yalnız step-up, deny veya `risk.*` Claim üretir | MD-13 (çıkarım) |
| Genel risk/fraud skorlama motoru | **Ayrı ürün katmanı** (security tooling) | Karar verir (restriction/requirement), `risk.*` Claim tüketir | Risk ≠ authority | MD-13, E22 |
| Ajan credential broker'ı / token vault | **Identity plane** | Custody sahibi | Upstream token'ın ajana verilmesinin release kararı bir Exercise'tır; upstream token Access projection'ı değildir; possession ≠ authority | MD-13, E36 |
| Upstream token'ın ajana verilmesi | **Authority plane** kararı (release Exercise'ı). Upstream token Access projection'ı değildir | Karar | E36 ile aynı: release kaydı BY SEMANTICS; broker'ın verme kararı ve her release yolunda zorlama UNDER DECLARED CAPABILITY; upstream token içeriği NOT GUARANTEED (G2 uygulanmaz; risk release Exercise'ında beyan edilir); `exp` ≤ ValidityContract horizon; CT2+ sınıflarda broker-as-PEP varsayılan | MD-13 |
| OIDC OP / OAuth AS, SAML IdP, WS-Fed, LDAP, Kerberos, RADIUS, SCIM sunucusu, OpenID Federation | **Identity plane**. Kenar gateway'ler ayrı süreçtir (MD-1) | Sahip | Protokol ayrıntısı §10–§11'dedir | MD-1 |
| Hesap yaşam döngüsü (kayıt, kurtarma, bağlama, silme, göç) | **Identity plane** | Sahip | Ayrıntı §12'dedir | MD-13 |
| Yönetim API'si ve konsol | Identity plane yüzeyleri. Authority değiştiren her çağrı ADP Exercise'ıdır | Sahip | Ayrı "admin token" sınıfı yoktur (MD-14). Konsol çerezi yalnız gezinmeyi ve identity plane'in kendi ekranlarını taşır; authority grafiği ve audit okuması AIS (CT0) veya holder-bound okuma projection'ı ister (§7.7) | MD-14 |
| PAM oturum aracılığı ve kaydı | **Ayrı ürün katmanı** | "Kim, hangi koşulla" kararı; Exercise kaydı; olay ve sinyal | Access PAM oturum kaydı veya sır tutmaz | MD-13, E22 |
| Genel sır kasası, credential injection | **Ayrı ürün katmanı** (Vault / PAM / Executor / Pay) | Release kararı (Exercise referansı) | Authority kayıtları sır içermez | E22, §7.9.12.4 |
| DLP, veri sınıflandırma | **Ayrı ürün katmanı** (data governance) | Disclosure authority'si (F11); label Claim'i tüketir | — | MD-13, F11 |
| SIEM (arama, korelasyon, tespit) | **Ayrı ürün katmanı** | Audit projection'ı üretir | SIEM kopyası source of truth değildir (X22) | MD-13, E22 |
| MDM / device compliance | **Ayrı ürün katmanı** | `posture.*` Claim'ini requirement/restriction olarak tüketir | Device ≠ authority | E22, §7.9.12.2 |
| IGA kampanyası, certification, role mining | **Ayrı ürün katmanı** | Derived sorgular ("who/why/impact"); kararlar Exercise'tır | — | E22, §7.9.12.3 |
| Trusted rendering / Approval Surface | **Gerçek dış sahip:** Experience / Work Approval Surface conformance profile'ı. Suiss yüzeyleri conformant client'lardır | Authority-relevant içerik (kim, digest, assurance, independence) | E32 | E32, X3 |
| Instruction-provenance savunması | **Gerçek dış sahip:** One / Executor Runtime | Açıklama talimat değildir (A-7). Tool description authority-opaque'tır | — | A-7, §8.18 |
| Work, Pay, Money, Relay, One, Executor, Commerce, Serve, HR | **Gerçek dış sahipler** | §7.3 seam'leri | — | E1–E32 |

### 7.7 Identity plane ↔ Authority plane iç sınırları

§7.9.1 dört semantic plane (identity, authority, trust/acceptance, decision/evaluation) ve iki source of truth tanımlar. Identity plane'in tam IdP kapsamı bu sözleşmeyi değiştirmez:

| Konu | Kural | Guarantee | Dayanak |
|---|---|---|---|
| **Yön** | Identity → Authority yalnız Claim'dir (authentication, authenticator-binding, identity-binding, recovery-result, hesap durumu Claim'leri, SCIM üyelik Claim'leri). Authority → Identity derived semantic event'ler ve InstanceID'dir; ayrıca identity plane PEP'inin ADP çağrılarına verilen Decision Response'lar (MD-14, TI-15). Authority plane identity kaydı yazmaz; identity plane bu girdilere kendi kaydıyla tepki verir (`session_epoch`) | BY SEMANTICS | INV-12, §7.9.1.2 |
| **Config yetkisi** | Client, redirect URI, upstream IdP bağlantısı, şablon ve realm config değişiklikleri realm'in yönetişim domain'inde (`realms.governing_domain_id`; tek) `idp.*` domain action'larıdır. Realm'i tüketen diğer domain'ler config yetkisi taşımaz, yalnız Acceptance taşır. Identity plane PEP'i bunları ADP `commit` ile yetkilendirir | BY SEMANTICS (yetki kaydı). Uygulamanın her yazım yolunda bunu zorlaması UNDER DECLARED CAPABILITY'dir (conformance testi, TI-RT12) | MD-14, E34 |
| **Konsol** | Konsol çerezi (BFF, DBSC'ye hazır) yalnız gezinmeyi ve identity plane'in kendi, authority taşımayan ekranlarını taşır (ör. kendi profil, kendi oturum listesi). **Authority grafiği ve audit okuması** (Grant/Acceptance envanteri, explain, search, audit, export) PI-4 gereği ADP üzerinden yapılır: AIS (CT0; step-up istemez) veya kullanıcının cihaz-bağlı Instance'ına verilmiş holder-bound, yalnız-okuma projection'ı ister. BFF holder olamaz, yalnız iletir (PI-7). Her meta-Exercise CT tazeliğinde AIS ister. Çerez tek başına hiçbir authority değişikliğini yetkilendiremez ve authority state okuyamaz. Ayrı "bearer yönetim token'ı" yoktur | BY SEMANTICS (PI-4, PI-7) | MD-14, PI-4, PI-7 |
| **Hızlı iptal** | `instance.terminate` ve `party.compromise` sonrası identity plane `session_epoch` ile identity plane oturumlarını ve token'ları kapatır. Semantik sözleşme ValidityContract'tır | İptalin semantiği BY SEMANTICS. Yayılma UNDER DECLARED CAPABILITY'dir | MD-7, §7.9.1.2 |
| **Hesap devre dışı bırakma** | Identity plane kayıtları tek işlemde değişir. Authority daraltması `account.status` Claim'inin ingest'i ve domain'in varsayılan DENY overlay'iyle gelir (E5 restriction kanalı, CT1 narrowing; actor gerektirmez). `instance.terminate` / departure temizliktir. Offline projection'lar beyan edilmiş pencerede kalır. "Çevrimdışı token'lar tek işlemde iptal edildi" garanti olarak yazılmaz | Identity kayıtları UNDER DECLARED CAPABILITY (tek işlem). Overlay'in uygulanması, politika kurulu ise ve Claim ingest edildiyse BY SEMANTICS. Offline yayılma NOT GUARANTEED (pencere UNDER DECLARED CAPABILITY) | E29, E5 |
| **Kurtarma** | Party Grant'ları kalır, Instance yenilenir, Mandate yeniden bağlanır. Kurtarma **her zaman** yeni bir successor Instance doğurur; domain bunu yalnız sıkılaştırabilir. Yeni authenticator GRACE penceresinin authority karşılığı SEC18'dir (yeni authenticator-binding 24 saat CT2+ karşılamaz) | BY SEMANTICS (INV-13) + PD (SEC18) | INV-13, SEC18 |
| **Ayrıcalıksızlık** | Suiss identity plane bir domain'e yalnız Acceptance kadar girer. Bir domain Suiss identity plane'i hiç kabul etmeyebilir | BY SEMANTICS | §7.9.1.3, E24 |
| **Fail-closed** | Tazeliği kanıtlanamayan authority taşıyan token introspection'da `active=false` alır. Primary'ye veya tazelik kaynağına ulaşılamıyorsa introspection her token için `active=false` döner (cache-hit dahil); 503 dönmez. 60–300 sn'lik fail-open pencereleri hiçbir plane'de kabul edilmez (OPI-3, §17.7 OP-45). Rate limiter, risk motoru veya cache arızası ALLOW'a dönmez. "Cache bu kullanıcıyı hiç görmedi" durumu fail-closed'dur | BY SEMANTICS (karar kuralı) | MD-8, MD-7 |
| **Kiracı ekseni** | `tenant_id` hiçbir authority kararına girdi değildir. Realm-yerel credential'lar `UNIQUE(realm, …)` ile tutulur. Realm'ler arası bağ yalnız açık IdentityBinding ile kurulur | BY SEMANTICS | MD-5 |

### 7.8 Ek ecosystem kararları (E33–E40)

Statü: **PROPOSED FOR FREEZE**. Freeze kararıyla FROZEN olur. Her karar ilgili MD'den türer ve onunla aynı reopen koşuluna tabidir (§0.2).

| ID | Karar | Statü | Guarantee | Gerekçe ve kaynak |
|---|---|---|---|---|
| **E33** | **Plane ataması.** Her yetenek identity plane'e, authority plane'e veya ayrı ürün katmanına atanır (§7.6). "Kapsam dışı" ifadesi gerçek dış sahipler dışında kullanılmaz. Ayrı ürün katmanlarında Access authority kısmına karar verir, olay ve sinyal üretir | PROPOSED FOR FREEZE | — (ownership kuralı) | MD-13. Access sahiplik sınırını korur; tam IdP kapsamı korunur |
| **E34** | **Identity plane kendi yapılandırması için bir domain ürünüdür.** `idp.*` namespace'ini yayınlar, config truth'unu sahiplenir, PEP'tir ve Access kararı ister (E16). Ayrı admin yazma yolu, ayrı admin token sınıfı ve kiracıya açık bir "süper admin" yolu yoktur. Bir realm'in yönetişim domain'i tektir (`realms.governing_domain_id`); realm'i tüketen N domain config yetkisini bölmez, yalnız Acceptance taşır. Identity plane ayrıca `idp.account.*` namespace'ini yayınlar (`read`, `profile.update`, `credential.*`, `email.change`, `delete`, `export` …). Destek yasak listesindeki eylemler (§8.16 #3) bu namespace'te **reserved** bayraklıdır. Hesap kaynakları kullanıcının self-anchor kapsamındadır | PROPOSED FOR FREEZE | BY SEMANTICS (yetki kaydı); UNDER DECLARED CAPABILITY (her yazım yolunda zorlama; conformance) | MD-14, PI-4, INV-2. "Tek merkezî fonksiyon" ilkesi aynı sonuca gelir (→ §12) |
| **E35** | **Dört eksen, dört owner.** Tenant ticari sisteme, AuthorityDomain authority plane'e, Identity Realm identity plane'e, Cell platform operasyonuna aittir. Bir domain iki tenant'a yayılmaz. B2B organizasyon realm içinde Party + Anchor'dır. `tenant_id` authority girdisi değildir | PROPOSED FOR FREEZE | BY SEMANTICS (girdi yasağı); izolasyon mekanizması (RLS vb.) UNDER DECLARED CAPABILITY (§12, §17) | MD-5. Eksen ayrımı + fiziksel izolasyon |
| **E36** | **Token vault: custody identity plane'de, release authority plane'de.** Upstream token'ın bir ajana veya PEP'e verilmesinin **release kararı** bir Exercise'tır (Access'in kendi kararı); release kaydı Access projection'ıdır, upstream token değildir. Token `exp` ≤ kararın ValidityContract horizon'u. CT2+ sınıflarda broker-as-PEP modu (broker çağrıyı kendisi yapar ve her çağrıyı intent ⊑ Grant olarak denetler, §11.13) varsayılandır. Possession ≠ authority. Authority kayıtları sır içermez. Vault, Exercise referansı olmadan release yapmaz | PROPOSED FOR FREEZE | "Exercise'sız release yetkisizdir" kuralı ve release kaydı BY SEMANTICS. Broker'ın verme kararı ve vault'un her release yolunda bunu zorlaması UNDER DECLARED CAPABILITY (conformance; E34 ile aynı yapı). Upstream token içeriğinin Grant'ı aşmaması NOT GUARANTEED: G2 (projection ⊆ source) upstream token içeriğine uygulanmaz; bu risk release Exercise'ında beyan edilir. Upstream sağlayıcının token'ı kendi tarafında doğru sınırlaması NOT GUARANTEED (dış owner) | MD-13. Federated credential vault + §7.9.12.4 |
| **E37** | **Destek erişimi: impersonation yok.** Destek operatörü bir Party'dir. Erişim kullanıcının kendi Grant Exercise'ıyla (iptal edilebilir, kaskad eder) veya reserved break-glass Grant'ıyla verilir. `OrgPolicy` yalnız organizasyonun kendi kaynaklarında geçerlidir. Serbest metin gerekçe Work veya destek bağlamında kalır; authority taşıyan alan PurposeRef'tir | PROPOSED FOR FREEZE | Model BY SEMANTICS. 12 değişmezin şablon değerleri POLICY DEFAULT'tur; statü ve guarantee satır satır §8.16 tablosundadır ve §12.3.4 TN-71 ile aynıdır | MD-9 |
| **E38** | **Sinyaller.** CAEP/SSF vericisi ve alıcısı identity plane'dedir. Authority semantic event tipleri Access'indir (L18). Gelen sinyaller `risk.*` / posture Claim'idir ve yalnız daraltır. Sinyal kaybı, gecikme veya alıcı arızası hiçbir zaman ALLOW'a dönmez | PROPOSED FOR FREEZE | Daraltma BY SEMANTICS. Teslim NOT GUARANTEED (güvenlik ona dayanmaz) | MD-13, MD-8, L18, CI-2. Mekanizma ve eşleme tablosu §12 TN-O2'dedir |
| **E39** | **Identity plane ↔ RP sınırı.** RP'ye verilen ID token / assertion kimlik iddiasıdır, authority değildir. Kaynak erişimi taşıyan her scope veya `authorization_details` bir Grant'ın projection'ıdır (S-1). Varsayılan `sub` pairwise'dır (MD-10). RP rezerve claim yazamaz. Redirect yalnız tam eşleşmeyle yapılır | PROPOSED FOR FREEZE | BY SEMANTICS (Access tarafı). RP'nin ID token'ı yanlış kullanması NOT GUARANTEED (dış owner) | MD-10, L24 |
| **E40** | **Access ve Relay birbirinden bağımsız çalışır, birlikte sürtünmesiz çalışır.** (1) **Access, Relay olmadan:** insana giden kendi mesajlarını (e-posta doğrulama, kurtarma, güvenlik uyarısı, OTP, CIBA daveti) yerleşik **doğrudan gönderim** moduyla yollar: e-posta için SMTP, SMS için tek bir genel HTTP sağlayıcısı, basit retry. Fallback, sağlayıcı yedeği, tercih merkezi ve sessiz saat bu modda yoktur. (2) **Access, Relay ile:** bu mesajların tamamı Relay'den gider. Access Relay'de yalıtılmış bir platform kiracısıdır: kendi gönderen alan adı, diğer kiracılardan ayrı izlenen itibar. Mesaj içeriği ve "kime, neden" Access'indir; kanal, zamanlama, retry, fallback ve teslim durumu Relay'indir (§7.9.8). CIBA'da Access OP'dir, Relay davetin teslim kanalıdır; onay Access onay yüzeyinde verilir (E32). (3) **Relay, Access olmadan:** kendi API anahtarları, operatör girişi ve abone jetonuyla çalışır; başka bir IdP ile standart OIDC üzerinden de çalışabilir. **Relay, Access ile:** operatör girişi ve step-up, abone jetonu, ajan kimliği ve pazarlama izni Access'ten gelir; denetim kayıtları birbirine bağlanır. (4) **Sürtünmesizlik:** iki ürün tek bir bağlantı ayarıyla bağlanır (keşif otomatik); aynı webhook imza profili, aynı event biçimi (CloudEvents) ve aynı kiracı eşlemesi kullanılır; Relay eklendiğinde ya da kaldırıldığında müşteri kodu değişmez, Access gönderim yolunu kendisi değiştirir. Hiçbir özellik öbür ürün yokken sessizce bozulmaz; öbür ürünü gerektiren özellik bunu açıkça belirtir. (5) Teslim ve ack hiçbir durumda authority state'i değildir (E30, INV-24); Relay'in cevabı onay değildir (EI-18) | Adem kararı | Ayrım BY SEMANTICS; doğrudan gönderim modunun teslim garantisi NOT GUARANTEED (basit retry) | MD-13, E30, E32, §7.9.8. Access tek başına tam IdP olarak kurulabilir; Relay bağımsız açık kaynak üründür |

**Ecosystem invariant adayları.** Statü: aday (PROPOSED FOR FREEZE).

- **EI-25 (aday)** Identity plane config changes are Exercises. Identity plane yapılandırmasının (client, redirect URI, upstream IdP, şablon, realm config) her değişikliği, realm'in yönetişim domain'inde committed bir domain action Exercise'ına bağlıdır. Bağlı olmayan yazım fail-closed reddedilir. (MD-14, E34) *[BY SEMANTICS (yetki kaydı); UNDER DECLARED CAPABILITY (her yazım yolunda zorlama)]*
- **EI-26 (aday)** Possession is never release authority. Token vault'taki bir upstream token yalnız geçerli bir Exercise referansına karşı serbest bırakılır. Token'ı tutmak hiçbir sisteme authority vermez. Release kaydı Access projection'ıdır; upstream token içeriği değildir. (MD-13, E36) *["Exercise'sız release yetkisizdir" BY SEMANTICS; zorlama UNDER DECLARED CAPABILITY; upstream token içeriği NOT GUARANTEED]*
- **EI-27 (aday)** Commercial tenancy never enters authority. `tenant_id`, `realm_id`, ticari paket ve `placement_id`/cell hiçbir authority kararının, Acceptance'ın veya ValidityContract'ın girdisi değildir (INV-37'nin ekosistem okuması; çakışmada INV-37 kanoniktir). (MD-5, E35) *[BY SEMANTICS]*

### 7.9 Seam ayrıntıları

**Statü ve okuma kuralı.**
- Aşağıdaki metin FROZEN normatif ayrıntıdır. E1–E32 ve §7.1–§7.5 bu ayrıntının karar özetidir.
- Metin içindeki "Work §n" atıfları Work spec'inin numaralandırmasıdır.
- SEC21–SEC23, TI-RT* ve X26 timeout kuralı §7.1–§7.5'teki karar metnindedir. Çelişkide §7.1–§7.5 ve E/EI kararları kazanır.
- Boundary ve pairwise seam matrislerinin güncel hâli §7.1 ve §7.3'tür, EI-1–EI-24 §6'dadır, E1–E32 §7.4'tedir. Açık kalanlar §20'dedir.
- Ecosystem verdict'in karşılığı §7 giriş cümlesi ve §7.5 anti-monolith sonucudur.

#### 7.9.1 Internal Access Plane Boundaries

##### 7.9.1.1 Karar

Suiss Access tek bir üründür (product decision). İçinde **dört semantic plane** vardır, ama **iki source of truth** vardır. Plane yalnız ownership birimidir; modül, servis, deployment veya ayrı ürün kararı değildir (Technical Architecture).

| Plane | Semantik sorusu | Source of truth mu? | Sahip olduğu canonical şey | Asla |
|---|---|---|---|---|
| **Identity plane** (first-party identity/authentication capability) | "Bu authenticator/oturum hangi Party'ye, hangi assurance ile bağlı?" | **Evet (kendi kapsamında)** | Kendi issue ettiği Claim'ler (`authentication`, `authenticator-binding`, `identity-binding.*`), authentication ceremony'leri, Suiss-hosted Party'ler için controller-custodian kayıtları, kişisel identity verisi (PII) | Grant/Mandate/Acceptance yazmak; kendi Claim'ine Acceptance vermek; PartyID'nin sahibi olmak |
| **Authority plane** (authority state) | "Kim neyi, hangi kaynaktan, hangi sınırlarla tutuyor ve kullanabilir?" | **Evet** — AuthorityDomain'in append-only kayıt defteri | Genesis, meta-Exercise'lar ve bunlardan türeyen Anchor, Grant, Mandate, Instance authority-binding lifecycle, RestrictionPolicy, budget terms; Claim ingest kayıtları | Party yaratmak; domain truth'u kaydetmek; Claim'in doğruluğunu beyan etmek |
| **Trust / Acceptance plane** | "Hangi issuer'ın hangi iddiası hangi use için girdi olabilir?" | **Hayır, ayrı değil** — Acceptance authority state'tir ve aynı kayıt defterinde, aynı tek yazma yolundan (meta-Exercise) değişir | Acceptance (primitive) | Acceptance'ı Exercise dışında değiştirmek; bir use için kabulü başka use'a taşımak |
| **Decision / Evaluation plane** | "Bu actor bu intent için şimdi exercise edebilir mi?" | **Hayır, ayrı değil** — bir fonksiyondur; ürettiği tek canonical şey Exercise/DecisionRecord'dur ve o da Authority plane kayıt defterine yazılır | Decision value; relied-upon ALLOW'larda Exercise + DecisionRecord | Authority state'i ALLOW commit dışında değiştirmek; Claim yazmak; kendi kararını Credential gibi yaymak |

> Identity plane satırının "Sahip olduğu canonical şey" sütunu ayrıca şunları kapsar: Identity Realm yapılandırması, realm-yerel user record ve hesap durumu, credential verifier materyali, identity plane oturumları, client kayıtları, SCIM kaynakları, token vault. Semantik sorusu "bu authenticator/oturum hangi Party'ye, hangi assurance ile bağlı?"dır. "Asla" sütunu aynen geçerlidir. Yapılandırma değişikliklerinin yetkisi authority plane'dedir (E34). Güncel tablo §7.1 ve §7.7'dedir.

**Neden Acceptance ayrı source of truth değil:** Acceptance'ın kendi kayıt defteri olsaydı, "kim bu issuer'a subject-selection güveni verdi" sorusu authority lineage'ından kopardı ve L6'nın "authority-selecting acceptance authority-sensitive'dir" kuralı iki sistem arasındaki bir senkronizasyona dönüşürdü. Acceptance, Grant ile aynı genesis'ten, aynı meta-anchor rootTerms'ünden ve aynı commit sırasından geçer.

**Neden Evaluation ayrı source of truth değil:** Decision bir value'dur (C31). Kaydedilen her şey (Exercise, DecisionRecord, consumption) authority domain'inin commit sırasına girmek zorundadır, çünkü at-most-once consumption (INV-21) ve StateBasis (C32) o sıraya bağlıdır. Ayrı bir "decision store" ikinci bir sıralama ve iki source of truth yaratır.

##### 7.9.1.2 Planes arası sözleşme

```text
Identity plane ──(Claim only)──► Authority plane (Claim corpus, Acceptance kapsamında)
       ▲                                │
       │ semantic events (derived)      │ meta-Exercise ALLOW (tek yazma yolu)
       │ ör. instance.terminated        ▼
       └──────────────────────── Authority state + Exercise records
                                        ▲
Evaluation plane ──reads basis──────────┘ ──writes──► Exercise/DecisionRecord (aynı defter)
```

| Seam | Truth owner | Mutate | Reference | Narrow | Never expand | Crosses | Never crosses |
|---|---|---|---|---|---|---|---|
| Identity → Authority | Identity plane (Claim içeriği); Authority plane (ingest kaydı) | Identity plane yalnız kendi Claim'lerini issue/supersede/retract eder | Authority plane Claim'leri ID ile cite eder | Identity Claim'i restriction/requirement/selection girdisi olarak daraltabilir | Identity plane hiçbir zaman Grant, Mandate veya Acceptance üretemez (INV-12) | Claim (authentication, authenticator-binding, identity-binding, recovery-result) | Authority state yazması; "admin" kısayolu; PII body'leri (yalnız digest/gerekli değer) |
| Authority → Identity | Authority plane | — | Identity plane InstanceID ve semantic event'leri referans alır | Authority plane bir Instance'ı terminate edince Identity plane ilgili oturum/token'ları kapatabilir (projection temizliği) | Authority plane authenticator bağlayamaz, PartyID değiştiremez | Derived semantic event'ler, InstanceID | Identity state mutasyonu |
| Acceptance ↔ Evaluation | Authority plane | Yalnız `acceptance.*` meta-Exercise'ı | Evaluation, StateBasis'te Acceptance sürümünü cite eder | — | Evaluation bir Claim'i kabul edilmemiş use'ta kullanamaz (INV-15) | Acceptance sürümleri | — |
| Evaluation → Authority state | Authority plane | Yalnız meta-action ALLOW commit | — | — | Evaluation bypass ifade edilemez (INV-2) | DecisionRecord | Doğrudan state yazımı |

##### 7.9.1.3 Identity plane'in ayrıcalıksızlığı

Suiss Access Identity plane, bir AuthorityDomain'e **yalnız o domain'in genesis'inde veya sonradan meta-Exercise ile verilmiş Acceptance kadar** girer (founding Acceptances). External IdP ile aynı sözleşmeyi kullanır: issuer'dır, grantor değildir. Bir domain Suiss Identity plane'i hiç kabul etmeyebilir ve yalnız external IdP kullanabilir; Authority plane bundan etkilenmez (Work §27.4 "no mandatory Suiss Access").

**Bundling'in değeri** (security coupling, assurance, instance binding, recovery, revocation response) **operasyoneldir, semantik değildir**: aynı ürün içinde olmak iki plane'in kayıt defterlerini birleştirmez ve Identity plane'e Acceptance dışı bir yol açmaz.

#### 7.9.2 Party Identity Regime Contract

##### 7.9.2.1 First principles

Party kimliği üç ayrı soruya cevap verir ve üçünün sahibi farklıdır:

| Soru | Fact türü | Sahip |
|---|---|---|
| "Bu aynı Party mi?" (süreklilik) | Kriptografik continuity: PartyID + signed key-event history | **Party + identity controller**, ortak regime kuralları altında |
| "Bu Party gerçek dünyada kim?" | Issuer iddiası (IdentityBinding) | **Issuer** (Identity plane, IdP, HR, registry, devlet) |
| "Bu Party bu authority domain'inde ne tutabilir/kullanabilir?" | Authority state | **AuthorityDomain** (Access) |

İlk soru hiçbir ürüne ait değildir. Access'e ait olsaydı Work ve diğer ürünler Access'e bağımlı olurdu (Work §27.4 "no mandatory Suiss Access" ile çelişir); Work'e ait olsaydı Access Work'e bağımlı olurdu. Doğru yer **protocol seviyesinde product-neutral bir regime**'dir: tanımı açık spesifikasyondadır, state'i her Party'nin kendi key-event history'sindedir, hiçbir merkezi registry gerekmez (Work §21.4, §21.7).

##### 7.9.2.2 Karar

```text
Party Identity Regime        → protocol-level, product-neutral foundational identity layer
                               semantics: open spec (Work Protocol §21.4 ile ortak, tek regime)
                               state: her Party'nin signed key-event history'si (Party + controller)
                               merkezi Suiss registry YOK

Access Identity plane        → regime'in bir implementasyon rolü:
                               (a) Suiss-hosted Party'ler için controller-custodian
                                   (controller authority'si Party'nindir; Suiss custodian'dır)
                               (b) identity-binding / authentication / authenticator-binding issuer'ı
                               Ayrıcalığı yok: başka custodian ve issuer'lar aynı sözleşmeyle çalışır

Access Authority plane       → PartyRef + Claim tüketir; domain admission, self-anchor,
                               Instance, Grant, Mandate onun
```

**Custody ≠ controller ≠ root.** "Root ≠ custody" ilkesi identity'ye de uygulanır: Suiss'in bir Party'nin anahtarlarını custodial olarak tutması, Suiss'i o Party'nin controller'ı yapmaz (controller authority'si key-event kurallarında tanımlı Party'dedir) ve hiçbir AuthorityDomain'de root yapmaz.

##### 7.9.2.3 State ownership — satır satır

| Concern | Owner | Canonical record nerede | Access'e nasıl girer | Asla |
|---|---|---|---|---|
| **Party creation** | Party'nin ilk controller'ı (insan için kendisi veya custodian aracılığıyla; agent/service için onu yaratan org'un controller'ı) | Regime: inception key-event | Yok (Access Party'nin varlığını yalnız Claim ve admission ile öğrenir) | Access'in Party yaratması; Party yaratmanın herhangi bir authority vermesi |
| **PartyID continuity** | Regime kuralları + controller | Key-event history | Gerekirse `party.key-state` Claim'i (issuer = regime verifier / Identity plane) | Bir ürünün PartyID'yi yeniden atadığı alias tabloyu canonical sayması |
| **Identity controller** | Regime (controller değişikliği key-event'tir) | Key-event history | `controller-of` Claim'i | Controller'ın root veya authority sayılması (Controller ≠ Authority) |
| **Party key events** (rotate, add/remove key, delegate signing) | Controller | Key-event history | Claim, yalnız authority-relevant olduğunda (ör. compromise) | Party key rotation'ın Instance KeyBinding'i değiştirmesi (Party key ≠ Instance KeyBinding) |
| **IdentityBinding Claims** | Issuer | Issuer'ın kaydı; Access'te ingest kaydı | Claim, `actor-binding` veya `predicate-input` / `subject-selection` Acceptance'ı ile | Binding'in PartyID değiştirmesi; binding'in authority olması |
| **Authenticator binding** | Controller'ın yetkilendirdiği issuer (Suiss-hosted'da Identity plane) | Issuer'ın kaydı | `authenticator-binding` Claim'i | Authority plane'in authenticator bağlaması |
| **Party recovery** | Regime'in recovery kuralları + controller'ın önceden beyan ettiği recovery yolu (social/org/custodian). Suiss tek recovery authority'si değildir (Work §18.1) | Key-event history (recovery event) | `party.recovered` Claim'i | Party recovery'nin Access Instance'larını veya Mandate'leri otomatik taşıması |
| **Domain admission** | **AuthorityDomain (Access)** | `party.register` meta-Exercise'ı; aynı commit'te self-anchor (`scope = Party(P)`, root açıkça belirtilir) | — (Access'in kendi kaydı) | Regime olayının veya IdP login'inin domain admission sayılması |
| **Self-anchor creation** | AuthorityDomain | Admission Exercise'ı | — | Örtük self-authority; controller/operator olmanın root vermesi |
| **Domain departure** | AuthorityDomain | Explicit departure meta-Exercise'ı, P'nin **bütün** holding kanallarını varsayılansız kapsar: self-anchor için `anchor.retire` veya `anchor.transfer`; P'nin tuttuğu extensional Grant'lar için disposition; Instance'lar için `instance.terminate`; P'yi seçen **rule-shaped holding'ler** için `retain` (explicit kabul; seçim issuer'ında kalır), grantor/authority source'un conjunctive daraltması (`grant.amend`) veya PartyRef'e bağlı RestrictionPolicy overlay'i; ve **yeniden giriş kapısı**: Public/self bootstrap Grant'larının (`party.register`, `instance.create(self)`) P için kapalı mı açık mı olduğu, bootstrap Grant terms'ü veya PartyRef overlay'iyle explicit. "Admitted" bir state primitive'i değildir; Exercise kayıtlarından derived'dır | — | Varsayılan disposition; departure'ın PartyID'yi etkilemesi; departure'ın rule-shaped holding'leri veya re-admission'ı sessiz bırakması |
| **Access Instance continuity** | Access (Instance primitive) | `instance.create / rekey / recover / terminate` Exercise'ları | Identity plane'in `authentication` Claim'i ceremony'yi kanıtlar | Instance continuity'nin Party key continuity'den türetilmesi |
| **Party termination / rotation** (ölüm, org dissolution, deliberate identity break) | Regime + controller (rotation); termination fact'i issuer'ındır (ör. registry) | Key-event / issuer kaydı | `party.terminated` / `party.identity-break` Claim'i | Access'in termination ilan etmesi |

##### 7.9.2.4 Regime olaylarının Access'teki etkisi

INV-2 gereği **hiçbir regime olayı authority state'i kendiliğinden değiştirmez**. Etki üç kanaldan biriyle doğar ve hepsi mevcut mekanizmadır:

| Regime olayı | Kanal | Sonuç |
|---|---|---|
| Party key compromise beyanı | Claim → RestrictionPolicy (domain'in varsayılan güvenlik politikası) | P'nin, compromise zamanından sonra kurulan Instance'ları için DENY overlay'i; terminal temizlik `instance.terminate` / `instance.recover` Exercise'ıyla |
| Party recovery tamamlandı | Claim → yeni `instance.create` için actor-binding girdisi | Yeni Instance'lar yeni authenticator'la doğar; eski Instance'lar recovery successor değildir (Instance recovery ≠ Party recovery); Grant'lar PartyRef'e bağlı olduğu için yaşar |
| Party termination | Claim → actor-binding başarısız (fail closed) + RestrictionPolicy | P artık hiçbir Instance kuramaz; mevcut Instance'lar DENY overlay'i altında; Grant'ların akıbeti domain'in explicit Exercise'ıdır (ör. FOR(P) taşıyan vekâletler hukuki gerçekliğe göre ayrıca revoke edilir) |
| IdentityBinding retraction / supersession | Claim | Actor-binding veya selection'da affirmative değişiklik; rule-shaped Grant'larda episode kapanışı (INV-31) |
| Controller değişikliği | Claim (`controller-of` supersession) | Yalnız controller'ı selector olarak kullanan rule-shaped Grant'ları etkiler; root'u değiştirmez |

##### 7.9.2.5 Admission ve self-anchor root kuralı

Admission Exercise'ı self-anchor'ın root'unu **açıkça** yazar: doğal kişi için kendisi; agent/service için onu yaratan org (veya org'un belirlediği Party); bir başka kişinin temsil ettiği Party için (vasi altındaki kişi) hukuki gerçekliği kanıtlayan Claim'lere dayanan explicit root. Root'u belirlemek admission'ı yapan domain'in kararıdır ve meta-anchor rootTerms'üne tabidir. Bu bir Access kararıdır, regime'in değil: aynı Party iki domain'de farklı self-anchor root'larına sahip olabilir (ör. bir agent'ın şirket domain'indeki root'u şirket, vendor domain'indeki root'u vendor).

##### 7.9.2.6 Work ile ortak regime

Work Party ile Access PartyRef **aynı regime'in aynı referansıdır**. Work'ün "Party" ontolojisi (§5.2) ve Access'in PartyRef'i ikinci bir kimlik yaratmaz. Work'ün Party için tuttuğu roller (engaged-in, obligor, principal, operator) Work fact'leridir; Access'in tuttuğu holding'ler Access fact'leridir; hiçbiri diğerinden türetilmez.

#### 7.9.3 Action / Intent Schema Governance

##### 7.9.3.1 Üç katman

| Katman | Sahip | Ne |
|---|---|---|
| **Access core namespace** (meta-action'lar: `grant.*`, `mandate.*`, `acceptance.*`, `anchor.*`, `instance.*`, `party.register`, `claim.issue`, `contribute`, `consumption.release`, `projection.issue`, `policy.set`; core cross-domain class'lar: `approve`, `disclose`, `declassify`) | **Access protocol spesifikasyonu** (Suiss-hosted Access değil) | Meta-schema'lar; sürümleri protocol governance ile değişir; her domain yeni meta-schema sürümünü kendi meta-Exercise'ıyla benimser |
| **Domain product namespace'leri** (`commerce.*`, `pay.*`, `serve.*`, `work.*`, `money.*`) | İlgili ürün (publisher) | Action vocabulary, typed parametre schema'ları, parametre anlamı, reserved beyanı |
| **Third-party namespace'leri** | Third-party publisher | Aynı sözleşme; first-party ile semantik fark yok |

##### 7.9.3.2 Ownership kararları

| Soru | Karar |
|---|---|
| **ActionRef namespace'inin sahibi kim?** | Namespace'i yayınlayan publisher (kimliği bir PartyRef'e / doğrulanabilir issuer'a bağlı). Bir namespace bir AuthorityDomain'de **ancak o domain belirli bir publisher'ı o namespace için `schema-definition` Acceptance'ı ile kabul ettiğinde** anlam kazanır. İki publisher aynı prefix'i iddia ederse domain birini kabul eder; global namespace registry gerekmez |
| **Schema'ları kim versiyonlar?** | Publisher. Yayımlanmış sürüm immutable'dır; kimliği içerik digest'idir. Aynı sürüm adı + farklı digest, publisher sözleşme ihlalidir ve Acceptance'ın revoke gerekçesidir |
| **Parametre anlamının sahibi kim?** | Publisher (domain semantiği, Test A). Access yalnız parametrenin **closed attenuation type system'deki tipini** ve sınıfını (authority-relevant / authority-opaque) tüketir |
| **Compatibility nasıl çalışır?** | Publisher iki sürüm arasındaki ilişkiyi beyan eder: `representation-equivalent`, `narrowing`, `broadening`, `incompatible`. Beyan bir Claim olarak ingest edilebilir (issuer = publisher), ama **standing Acceptance onu kullanılabilir kılmaz**: `schema-definition` Acceptance'ının scope'u kabul edilen schema sürüm digest'lerini ve compatibility mapping digest'lerini **exact olarak pin'ler** (C28 ile aynı ilke: canlı dolaylılık yok). Yeni bir sürüm veya yeni bir mapping, o exact digest'i adlandıran reserved bir `acceptance.amend` Exercise'ı ister (C18). Böyle kabul edilmiş bir eşleme yalnız **non-broadening** yönde otomatik kullanılabilir. Etiketin (ör. `representation-equivalent`) doğruluğu semantik guarantee değildir, **publisher trust**'ıdır (INV-14); kurtarma: Acceptance revoke + ingest-time cutoff (açık nokta → §20) |
| **Schema değişince mevcut Grant'lara ne olur?** | Hiçbir şey. Grant ve Intent sürümü pin'ler. Bir v2 intent'i v1 Grant'ı tarafından yalnız domain'in **o exact mapping digest'ini explicit bir `acceptance.amend` Exercise'ıyla kabul ettiği** ve mapped intent'in v1 AuthoritySet'inde ⊑ olduğu kanıtlanabilen bir eşlemeyle kapsanır. Kabul edilmemiş sürüm/mapping hiçbir Grant'ın kapsamını değiştiremez. Aksi hâlde `grant.amend` gerekir (genişletme ise genişletme requirement'larıyla) |
| **Access'in closed attenuation type system'i nedir?** | §7.9.3.4 |
| **RAR mapping nereye ait?** | Access protocol profile'ı (projection/transport). RAR `type` ↔ ActionRef (namespace + name + version) eşlemesi ve `authorization_details` ↔ IntentEnvelope serileştirmesi **DEFER TO PROTOCOL**. Semantik Access'te, taşıyıcı RAR'da (L24) |

##### 7.9.3.3 Schema governance soruları

| Soru | Cevap |
|---|---|
| Domain owner aynı sürümde parametre semantiğini genişletebilir mi? | **Hayır.** Sürüm immutable'dır; anlam değişikliği yeni sürümdür. Access prose anlamını mekanik olarak denetleyemez; bu yüzden "aynı sürüm ⇒ aynı anlam" publisher'ın sözleşme yükümlülüğüdür ve Acceptance onun üzerine kurulur. İhlal, publisher'ın `schema-definition` Acceptance'ının revoke ve compromise prosedürü gerekçesidir (Security) |
| Yeni schema sürümü mevcut Grant'ı sessizce genişletebilir mi? | **Hayır** (E10). Broadening hiçbir zaman otomatik değildir; kabul edilmemiş bir sürüm veya mapping hiçbir Grant'ın kapsamını değiştiremez. Ama publisher'ın "non-broadening" etiketi bir beyandır: Access prose anlamını denetleyemediği için açıkça kabul edilmiş bir mapping'in doğru etiketlendiği garanti edilmez (publisher trust; kurtarma: Acceptance revoke + ingest-time cutoff) |
| Wildcard authority gelecekteki action'ları kapsayabilir mi? | **Hayır** (E11, R5). Bir Grant'taki namespace prefix, issue anında pin'lenen **namespace katalog sürümüne** çözülür. Publisher'ın sonradan eklediği action'lar ancak `grant.amend` (genişletme) ile girer. Gerekçe: aksi hâlde schema publisher, grantor olmadan authority yaratırdı (L6, INV-1) ve bu C28'deki "canlı dolaylılık yok" ilkesinin ihlalidir |
| Reserved action wildcard ile hiç kapsanabilir mi? | **Hayır, hiçbir sürümde** (INV-9). Reserved bayrağını publisher beyan eder; AuthorityDomain yerel olarak ek action'ları reserved işaretleyebilir (yalnız daha sıkı). Bir sonraki sürümde reserved bayrağının kaldırılması *broadening*'dir |

##### 7.9.3.4 Closed attenuation type system (Access-owned)

Authority-relevant her parametre şu kapalı tip kümesinden birine eşlenir; her tip için `⊑`, `∩`, `normalize` tanımlı ve decidable'dır (INV-8):

| Tip | Constraint biçimleri | Örnek |
|---|---|---|
| `Enum` / finite set | üyelik, alt küme | `reason ∈ {damaged, late}` |
| `Equality` (opaque değer) | eşitlik | `order = ord_123` |
| `Ordered numeric` (+ unit) | ≤, ≥, aralık; unit eşit olmak zorunda | `amount ≤ 500 TRY` |
| `Count` | ≤ | `items ≤ 3` |
| `Time interval` | aralık kapsaması | `deliveryWindow ⊆ [t1, t2]` |
| `ResourceRef` / namespace prefix / structural selector | kapsama | `resource ∈ merchant:M/orders/*` |
| `SubjectSelector` | kapsama | `recipient = Party(Alice)` |
| `PurposeRef` set | küme üyeliği | `purpose ∈ {complaint-resolution}` |
| `Boolean flag` | eşitlik | `partial = false` |

Yalnız conjunction; negation yok; serbest predicate yok; dış çağrı yok.

**Parametre sınıflandırması (publisher beyan eder, domain Acceptance'la onaylar):**

- **authority-relevant**: yukarıdaki tiplerden birine eşlenmek zorunda; Grant'lar bu parametreyi sınırlayabilir.
- **authority-opaque**: Grant'lar sınırlayamaz; intent digest'ine girer (approval bunu bağlar), ama subsumption'a girmez.

Tipe eşlenemeyen ama authority-relevant olan bir parametre, schema-definition Acceptance'ında reddedilmelidir; çünkü opaque ilan edilmiş authority-relevant bir parametre (ör. serbest metin `recipient`) Grant sınırlarını atlatan bir kanal olurdu. Bu inceleme, `schema-definition`'ın reserved meta-Exercise olmasının (C18) somut nedenidir.

##### 7.9.3.5 Schema evolution kuralı

| Değişiklik sınıfı | Davranış |
|---|---|
| Representation change (aynı anlam, farklı serileştirme) | Domain'in exact digest'iyle `acceptance.amend` ile kabul ettiği `representation-equivalent` eşlemesiyle protocol/profile otomatik eşler; etiketin doğruluğu publisher trust'ıdır |
| Compatible narrowing | Exact digest'iyle kabul edilmiş `narrowing` eşlemesiyle v2 intent'leri v1 Grant'larıyla değerlendirilebilir (mapped intent ⊑ v1) |
| Kabul edilmemiş sürüm veya mapping | Hiçbir etkisi yok: v2 intent'i v1 Grant'ı tarafından kapsanmaz (DENY), ta ki domain o digest'i explicit Exercise ile kabul edene kadar |
| Semantic broadening | **Asla otomatik değil.** Mevcut Grant'lar v1'de kalır; v2'nin geniş yüzeyi `grant.amend` ister |
| Yeni action / yeni authority surface | Explicit authority-sensitive benimseme: yeni Grant veya amend; prefix'ler kapsamaz |
| Reserved bayrağının kaldırılması | Broadening |
| Action retirement | Publisher Claim'i; mevcut Grant'lar tarih olarak kalır; retired sürüme intent'ler domain policy'siyle DENY edilebilir (restriction); retirement hiçbir şeyi genişletemez |
| Incompatible | Eşleme yok; yeni Grant |

Migration mekaniği (toplu amend, katalog sürümü encoding'i) **DEFER TO PROTOCOL**.

##### 7.9.3.6 Ontology'nin schema deposuna dönüşmemesi

Access domain schema'larının *anlamını* depolamaz; yalnız (1) kabul edilmiş schema sürümlerinin ve compatibility mapping'lerinin digest'lerini ve tip eşlemelerini (Acceptance scope'unda exact pin'li), (2) hangi publisher'ın hangi namespace için kabul edildiğini (Acceptance) tutar. Schema'nın kendisi publisher'ın yayınıdır; Access'teki kopyası bir Claim'in ingest kaydıdır.

#### 7.9.4 Connectivity Ownership Model

##### 7.9.4.1 Karar tablosu

| Sorumluluk | Owner | Access'in payı | Neden |
|---|---|---|---|
| **Connectivity profile semantiği** (online / intermittent / offline / long-running; ValidityContract'ın anlamı; bounded staleness) | **Access protocol** | Tanım | L16 |
| **Bir projection'ın hangi profile altında çıkarılacağı** | **AuthorityDomain** (`projection.issue` meta-Exercise'ı, rootTerms/policy'ye tabi) | Karar + kayıt | Profile seçimi kabul edilen staleness riskini belirler; authority-sensitive'dir |
| **Verifier behavior** (yerel karar, cache, clock, contract'a uyum) | **Verifier'ı işleten sistem** (domain PEP, Executor, POS/edge cihazı operatörü) | Yok; Access yalnız contract'ı ve proof'u verir | Verifier fiziksel olarak başka yerdedir; Access onu göremez |
| **Verifier'ın kendi profilini beyan etmesi** | Verifier operatörü (conformance beyanı; Claim) | Kabul (Acceptance) ve profile uyum kontrolü issuance'ta | Access kendisine dürüstçe beyan edilmeyen profile projection vermemelidir |
| **Revocation signal transport** | **Relay** (veya SSF/CAEP transport, delivery adapter) | Semantic event içeriği (derived) | Semantic event = derived notification |
| **Offline reconciliation — authority tarafı** | **Access** | Offline exercise raporlarını (verifier'ın Claim'leri) projection'a bağlar; contract içi/dışı ayırımı derived; kullanılmayan slice'ın grounded release'i | Authority budget ve exercise meşruiyeti Access'indir |
| **Offline reconciliation — effect / finansal taraf** | **Domain / Pay / Executor** | Yok | Effect ve para onların |
| **Staleness-window risk declaration** | **AuthorityDomain** (issuance Exercise'ındaki ValidityContract, attributable olarak) | Kayıt ve kanıt | Δ'yı (`revocation sonrası ≤ Δ süre onurlandırılabilir` riski) `projection.issue` Exercise'ının actor'ü attributable olarak beyan eder (authority = ilgili holding + Mandate); Δ'nın tavanını lineage terms, rootTerms ve RestrictionPolicy (root'un ve üst holder'ların kararı) koyar; kayıt AuthorityDomain'dedir |
| **Liability allocation** (staleness penceresindeki zararı kim taşır) | **Hukuk / sözleşme / scheme kuralları** (ödemede network kuralları; organizasyonda Work accountability regime) | Yok; Access yalnız hangi contract'ın yürürlükte olduğunun kanıtını sağlar | Legal liability Access ontology'si değildir (§7.9.12.7) |
| **Physical stop** | **Executor / domain PEP** (stop state, "confirmed stopped") | Yok | CI-9, Work §15.1 |
| **Control coordination ve dürüst gösterim** | **Work** (control lease, take-control akışı) + Experience | Yok | Work §15 |

##### 7.9.4.2 Sınıf bazında ownership

| Sınıf | Access | Verifier / PEP | Relay | Work / Executor |
|---|---|---|---|---|
| **Online** | Her exercise için ALLOW commit (consumption atomik) | Effect'ten önce senkron karar ister; karar yoksa fail closed | Rolü yok (güvenlik açısından) | — |
| **Intermittent** | `projection.issue` + kısa ValidityContract; yenileme = yeni continuation/projection kararı | Contract içinde yerel karar; horizon'da yeniden bağlanır; bağlanamazsa contract biter ve DENY | Revocation event'ini taşır (hız kazandırır, güvenlik vermez) | — |
| **Offline** | Projection + önceden draw edilmiş offline slice + bounded staleness | Slice ve contract içinde yerel karar; offline exercise kayıtlarını tutar ve bağlanınca raporlar | Bağlantı geldiğinde event'leri iletir | Effect reconciliation |
| **Long-running executor** | Checkpoint başına continuation DecisionRecord; horizon | Executor checkpoint'te continuation ister; DENY'da yeni consequential effect başlatmaz | Event'i iletir | Executor stop'u; Work control |

##### 7.9.4.3 Değişmeyen semantik

- **Semantic revocation commit = Access'te, commit anında.** Propagation (Relay) ve physical enforcement (verifier/Executor) onu değiştirmez ve hızlandırması güvenlik varsayımı değildir (INV-24).
- **Absence ≠ success.** Bir effect receipt'inin, delivery ack'in veya stop teyidinin gelmemesi hiçbir sistemde başarı veya durma olarak yorumlanmaz.
- **Freshness sayıları, profile katalogu, offline report formatı, clock kaynağı** Protocol + Security aşamasındadır (açık nokta → §20).

#### 7.9.5 Work Seam

##### 7.9.5.1 Kavram eşlemesi (frozen, yeniden tasarlanmadı)

| Work kavramı | Access karşılığı | İlişki |
|---|---|---|
| Work Commitment | — | Authority yaratmaz. Access onu yalnız opaque `CommitmentRef` (Intent context) veya Work'ün `commitment.active` Claim'i olarak görür |
| Work delegation (Commitment devri, handoff) | Grant (authority delegation) | Bağımsız iki fact. Biri diğerini ima etmez |
| Work Gate | RequirementTerm (yalnız authority composition ise) + contribution Exercise | Gate placement Work'ün; kimin satisfy edebileceği ve contribution'ın geçerliliği Access'in |
| Work autonomy | Mandate / Exercisable | `Autonomy ⊆ Exercisable` |
| Work accountability | Exercise attribution + provenance | Access kanıt sunar; accountability kararı Work regime'inindir |
| Work Party | PartyRef | Aynı regime, aynı referans (§7.9.2.6) |
| Work on-behalf-of | `Exercise.capacity` (OWN / FOR(P)) | Work atfı ⊆ authorized capacity; provenance ayrıca |
| Work evidence (Claim, Act, Observation) | Claim (yalnız Acceptance ile) | Work Claim'leri Access'e ancak Work bir issuer olarak kabul edilmişse ve yalnız kabul edildiği use için girer |
| Work Declaration (approval, waiver, instruction) | contribution Exercise (approval için) | Declaration authority değildir; authority-relevant approval Declaration'ı bir contribution Exercise'ına referans verir |

##### 7.9.5.2 Seam kuralları

| Soru | Cevap |
|---|---|
| **Truth owner** | Work: Commitment, Gate, autonomy, accountability, handoff, Work evidence. Access: authority state, contribution ve Exercise kayıtları |
| **Who may mutate** | Her taraf yalnız kendi kayıtlarını, kendi tek yazma yoluyla (Work: eligible Declaration; Access: meta-Exercise) |
| **Who may reference** | Work → ExerciseID, GrantID, MandateID, DecisionRecord projection. Access → WorkRef, CommitmentRef, GateRef, StepRef (opaque) |
| **Who may narrow** | Work: autonomy kararıyla (proceed/notify/Gate/deny), Gate ile, ve `commitment.active` Claim'iyle Commitment-scoped Grant'ları bitirerek. Access: kendi DENY/restriction'larıyla |
| **Who may never expand** | Work hiçbir zaman authority yaratamaz, genişletemez, Access DENY'ını Gate veya waiver ile aşamaz. Access hiçbir zaman Commitment yaratamaz veya Gate kaldıramaz |
| **What crosses** | IntentEnvelope'taki opaque Work ref'leri; Gate payload digest'i; eligible contributor kümesi; ExerciseID'ler; Decision outcome (ALLOW/DENY/REQUIRE_ACTION + unmet requirement özeti); Work'ün dar Claim'leri |
| **What must never cross** | Work içeriği, internal Condition/Aim yapısı, attention state (Access'e); Grant/Mandate'in tam kopyası Work'te canonical olarak (Work'e) |

##### 7.9.5.3 Flow A — Work Gate yaratır, onay gelir

```text
Work: Gate G yerleştirir (neden, nerede, k, deadline)                      ← Work Declaration
Work → Access: "G'yi kim satisfy edebilir?" (gate class, resource, digest)  ← soru; kayıt değil
Access: eligible set = holders of approve:<class> (derived)                  ← Access
Work + Relay: eligible kişilere iletir                                       ← Work alıcı seçer, Relay teslim eder
Approver (kendi Instance'ından, trusted approval surface üzerinden):
   contribute(approve, digest) Exercise                                      ← ACCESS canonical: approval act
Work: "G satisfied by ExerciseID X" Declaration                              ← WORK canonical: Gate satisfied
```

**Tek mekanizma, iki fact, iki kaynak değil:**

| Fact | Source of truth | Kayıt | Diğerine referans |
|---|---|---|---|
| "Approver A, digest D'yi bu authority ile, bu assurance'la onayladı" | **Access** | contribution Exercise | Work Declaration ExerciseID'yi cite eder |
| "Gate G kapandı; Work bundan sonra ilerleyebilir" | **Work** | Declaration | Access Gate'i bilmez; yalnız digest'i bilir |

**Digest'i kim tanımlar?** Gate bir Access intent'ine bağlıysa (ör. ödeme onayı), digest = hedef IntentEnvelope'un digest'i ve contribution aynı zamanda hedef Exercise'ın authority requirement'ını karşılayabilir. Gate saf koordinasyon ise (ör. "tasarımı onayla"), digest = Work'ün canonical Gate payload'ının digest'i; ActionRef `work.gate.satisfy` (Work namespace'i, Work publisher). Her iki durumda eligible set Access'ten gelir (Work §12: "Gate'i kimin satisfy edebileceğini authority provider belirler").

**Uyumsuzluk kuralları:**

- Work Declaration'ı geçersiz/olmayan/DENY'lı bir contribution'a referans veriyorsa → Declaration eligible değildir; Gate açık kalır. Work, Declaration'ı kabul etmeden önce referansı doğrular.
- Access'te geçerli contribution var ama Work Declaration yok → Gate Work'te açık kalır; contribution yalnız Access requirement'ı için kullanılabilir.
- **Gate satisfied ≠ authority ALLOW.** Gate'in kapanması hedef action'ın Access'te ALLOW alacağı anlamına gelmez; Work bunu "authority onaylandı" diye gösteremez.
- Work Gate'i, bir Access RequirementTerm'ünü (contribution count=k) **karşılayamaz**; Access requirement'ı yalnız contribution Exercise'larıyla karşılanır (E7).

##### 7.9.5.4 Flow B — Work işi bir agent'a devreder

```text
Work: Commitment C (obligor = Agent A, principal = Merchant M)    ← Work; authority değişmez
Access: (ayrı, bağımsız) grant.issue → A, agency FOR(M), bounds  ← Access; Commitment yaratmaz
```

**Atomic olmalı mı? Hayır.** İki farklı owner'ın iki farklı fact'idir; ikisini tek transaction'a bağlamak semantik olarak gereksizdir, çünkü hiçbir ara durum güvenli olmayan bir sonuç üretmez:

| Ara durum | Sonuç | Güvenli mi |
|---|---|---|
| Commitment var, Grant yok | A'nın exercise'ları DENY / REQUIRE_ACTION; Work "authority eksik" Condition'ını gösterir | Evet (fail closed) |
| Grant var, Commitment yok | A authority'yi tutar ama Work'te sorumluluğu yok | Evet, ama istenmiyorsa Grant **Commitment-scoped** yapılır (aşağıda) |
| Commitment release/handoff, Grant duruyor | Grant kendiliğinden ölmez (Work authority'yi değiştiremez) | Commitment-scoped değilse grantor'ın explicit revoke'u gerekir |

**Commitment-scoped authority (R7):** Grantor, Grant'ın ConstraintSet'ine `while commitment.active(CommitmentRef)` koşulu koyar; bu Work'ün issue ettiği ve domain'in `predicate-input` Acceptance'ıyla kabul ettiği bir Claim'dir. Work Commitment'ı release/handoff edip affirmative `commitment.active = false` Claim'ini yayınlayınca Grant terminal olarak geçersizleşir. Bu, Work'ün authority'yi **bitirebildiği ama asla başlatamadığı** tek kanaldır ve tamamen mevcut mekanizmalarla ifade edilir. Önerilen sıralama (ürün varsayılanı, semantik zorunluluk değil): Work Commitment'ın aktivasyonunu bir epistemic Condition'a ("authority mevcut") bağlayabilir; Condition Access'in ilgili Grant/Mandate'in var olduğunu doğrulayan cevabıyla satisfy edilir.

##### 7.9.5.5 Flow C — Work autonomy'yi daraltır

```text
Exercisable(I)    = Holding ∩ Mandate ∩ ActorRestrictions        ← Access
Autonomy(I, w)    ⊆ Exercisable(I)                               ← Work
```

Work Grant veya Mandate mutate etmez. Work'ün kararı yalnız şudur: agent bu Exercisable alan içinde *sormadan ilerleyebilir mi, bildirerek mi, Gate ile mi, hiç mi*. Agent'ın Access'e giden her talebi yine Access'te değerlendirilir; Work "proceed" dese de Access DENY verebilir; Access ALLOW verse de Work "require-Gate" diyebilir. İkisi farklı sorulardır (may vs. should-now).

##### 7.9.5.6 Flow D — Accountability

| Soru | Owner | Access'in katkısı |
|---|---|---|
| Kim exercise etti, hangi capacity'de, hangi provenance ile? | **Access** (fact) | Exercise kaydı |
| Kim sorumlu (responsible), kim accountable endpoint? | **Work** (records + regime) | Yok; Access'in kaydı bir girdi |
| Outcome'dan kim hukuken sorumlu? | **Hukuk / sözleşme** | Yok |
| Organizasyon kuralı ("agent'ın operatörü onun davranışından sorumlu") | Work regime / organization rule | Yok |

**"Authority holder = accountable" eşitliği yoktur.** Access'teki attribution "kimin yaptığını" kanıtlar; "kimin hesap vereceğini" belirlemez. Work regime bu kanıtı kullanır.

##### 7.9.5.7 Work S4 seam okuması (R4)

Work §17.2 S4 "authority root and onBehalfOf root must match for on-behalf-of action" der. Authority provenance Access-owned semantiktir; Access bu eşitliği kabul etmez (Alice → Bob paylaşımında provenance Alice, capacity Bob OWN; eşleşmezlik değil). Seam kuralı:

> **Work'ün on-behalf-of atfı, Exercise'ın açıkça yetkilendirilmiş capacity'si ile uyumlu olmalıdır: Work "A, P adına" diyorsa Exercise.capacity = FOR(P) olmalı. Authority provenance root'u ayrıca incelenir ve on-behalf-of principal'ıyla eşleşmesi aranmaz.**

Bu Work'ün kendi semantiğini (on-behalf-of relation'ı canonical Work relation'ı olarak) değiştirmez; yalnız Work metnindeki "authority root" ifadesinin Access-owned anlamını düzeltir. Work spec errata'sı açık noktadır (→ §20).

##### 7.9.5.8 Work-like third-party coordinator

Bir third-party coordinator (ör. başka bir iş platformu) Access'i Suiss Work ile **aynı sözleşmeyle** kullanır: coordinator bir Party'dir; Gate karşılığı kendi kayıtlarındadır; contribution Exercise'ları ve eligible set Access'ten gelir; `commitment.active` benzeri Claim'leri yalnız domain onu issuer olarak kabul ederse girer. Suiss Work'e özel bir alan, özel bir requirement tipi veya özel bir Acceptance yolu yoktur (E24).

#### 7.9.6 One Seam

##### 7.9.6.1 Ownership

| One owns | Access owns |
|---|---|
| Private memory, reasoning, planning, personal preference, private provenance, personal continuity, cross-Work kişisel bağlam | One'ın PartyRef'inin domain'lere kabulü, One Instance'ları, user → One Grant'ları (agency `FOR(user)`), Mandate, capacity doğrulaması, One'ın exercise kayıtları |

One bir Party'dir (agent); Access'te özel bir statüsü yoktur. Agent ayrı bir security universe değildir.

##### 7.9.6.2 Sorular

| Soru | Karar |
|---|---|
| **One memory → Claim mi?** | Varsayılan **hayır**. One'ın hafızası One'ın private state'idir ve Access'e girmez. One bir issuer olarak Claim yayınlayabilir, ama bir AuthorityDomain onu yalnız açıkça Acceptance ile kabul edebilir. Personal-delegate / inference-üreten issuer'ların (One veya third-party kişisel asistan, ayrımsız) Claim'leri varsayılan olarak yalnız narrowing use'larda kabul edilir (ör. kullanıcının "X ile paylaşma" tercihi → restriction girdisi); `subject-selection` / `foreign-authority` kabulü domain'in reserved, explicit kararıdır (C18); `actor-binding` yalnız issuer'ın kendi Instance'ları için. Bu bir issuer-class varsayılanıdır, ürün adına bağlı bir yasak değildir (E24, INV-29) |
| **One inference → never authority?** | **Asla authority değildir.** "Kullanıcı muhtemelen bunu ister" bir Grant değildir; One bir intent'i yalnız mevcut Grant + Mandate içinde exercise edebilir. Bu sınır içinde *hangi* action'ı seçeceği One/Work autonomy'sidir; authority üretimi değildir |
| **User intent ne zaman Access Intent olur?** | One bir action'ı exercise etmek için bir IntentEnvelope kurduğunda (One'ın kendi Exercise'ı, kendi basis'iyle). Kullanıcının *kendi* authority'sini gerektiren her şey (One'a yeni Grant, Grant genişletmesi, kullanıcı adına approval, Mandate rebind) kullanıcının **kendi Instance'ından** explicit, attributable bir Exercise'la olur |
| **One planning → never canonical authority?** | Plan One'ındır (veya Work'e explicit disclosure ile Work'ün). Access plan state'i tutmaz; yalnız PlanRef/StepRef opaque context'tir |
| **Private context → minimum ne geçer?** | IntentEnvelope'un authority-relevant parametreleri, opaque context ref'leri, purpose. Konuşma, memory, gerekçe metni, kişisel çıkarım **geçmez** (§7.9.15) |

##### 7.9.6.3 Critical rule

> **One must never silently manufacture authority from user conversation, memory or inferred preference.**

Yapısal karşılığı:

1. One'ın kullanabildiği authority = user'ın One'a verdiği Grant'lar ∩ One Instance'ının Mandate'i. One kendine Grant veremez (basis'i yoktur); user adına Grant verebilmesi, user'ın One'a `grant.issue` delegability'si açıkça vermesine ve agency continuity'ye (INV-4) tabidir.
2. "Kullanıcı sohbette 'evet' dedi" bir contribution değildir. Approval, user'ın kendi Instance'ından, trusted approval surface üzerinden, exact digest'e bağlı contribution Exercise'ıdır (L14, Work S11).
3. User One'a `approve` authority'sini FOR(user) olarak verse bile, RequirementTerm'in `independence` alanı (`contributor ≠ actor principal`, human presence assurance) One'ın kendi exercise'ını kendisinin onaylamasını engelleyebilir; yüksek sonuçlu sınıflarda bu domain'in varsayılan politikasıdır.
4. Authority-sensitive bir kullanıcı eylemi her zaman **explicit, attributable, Access-facing** bir eylem olur; One onu yalnız hazırlar (draft intent), tetiklemez.

#### 7.9.7 Executor Seam

##### 7.9.7.1 Ownership (Model B, frozen)

| Access | Executor |
|---|---|
| Authorized intent envelope (IntentEnvelope) | Tool execution, sandbox, browser, terminal, computer use |
| Authority Decision ve Authority Exercise | Execution fencing, idempotency |
| ValidityContract, AuthorityStateBasis | Pause / cancel / takeover, control capability beyanı |
| Continuation DecisionRecord'ları | Checkpoint, execution state |
| Effect attestation'ın envelope'a karşı conformance'ı (derived) | Effect'in kendisi, uygulanan gerçek parametreler, stop state |

Executor runtime operatörü bir Party'dir ama **actor değildir**: actor, runtime'da çalışan agent Party'nin Instance'ıdır. Operator ≠ principal ≠ accountable (Work §11.3).

##### 7.9.7.2 Sorular

| Soru | Karar (boundary seviyesi) |
|---|---|
| **Executor ne zaman Access'e yeniden sormak zorunda?** | (1) Mevcut ALLOW'un envelope'u dışında kalan her consequential effect'ten önce (yeni intent = yeni Exercise). (2) ValidityContract horizon'u dolmadan veya beyan edilmiş her checkpoint'te (continuation). (3) Pause/takeover/recovery sonrası yeniden başlamadan önce. (4) Bir semantic event aldığında (best-effort hızlandırma; güvenlik varsayımı değil) |
| **Continuation nasıl istenir?** | Actor Instance'ı aynı Exercise üzerinde continuation ister; Access kendi StateBasis'iyle yeniden değerlendirir ve yeni DecisionRecord yazar (C30). Executor'ın kendi adına continuation istemesi yoktur |
| **Effect receipt / attestation ne demek?** | Executor'ın (veya effect'i gerçekleştiren domain'in) ExerciseID'ye bağlı **Claim**'i: "şu parametrelerle şu effect gerçekleşti / gerçekleşmedi". Truth değildir; conformance derived'dır; *unknown* first-class'tır |
| **Stop state'in sahibi kim?** | **Executor.** Work bunu control akışında koordine eder ve gösterir |
| **"Execution confirmed stopped" kimin?** | **Executor'ın Claim'i / Act report'u.** Access onu ne üretir ne garanti eder. Work, Executor desteklemiyorsa bunu açıkça gösterir (Work §15.2) |
| **Uygulanan gerçek parametrelerin sahibi kim?** | **Executor / domain** (effect truth). Access yalnız attest edilen parametreleri envelope'la karşılaştırır |

##### 7.9.7.3 Critical

```text
Access revocation committed   ≠   Executor stopped
Access DENY on continuation   ≠   effect rolled back
Missing receipt               ≠   effect did not happen
```

Bir Executor revocation'ı görmezden gelirse Access onu fiziksel olarak durduramaz. Sonraki her consequential effect bir Exercise'a bağlanamayacağı için **unauthorized** olarak tespit edilebilir (INV-19); tepki containment (Executor'ın veya agent'ın Instance'larına restriction), Work escalation ve accountability'dir (§7.9.14).

##### 7.9.7.4 PEP'ler arası zincir (R6)

**PEP ≠ actor ≠ holder.** Bir effect birden çok PEP'ten geçiyorsa (ör. Commerce refund → Pay refund), **her PEP'teki her consequential effect, basis'ini tutan Party'nin Instance'ının kendi Exercise'ıyla desteklenir**. PEP kararı ister veya doğrular ve uygular; authority tutmaz, almaz, ödünç vermez. Hiçbir Exercise'ta actor'ün Party'si basis holder'ından farklı değildir (INV-4, INV-11, CI-6). Örnek: `pay.refund` Exercise'ının actor'ü Commerce service Party'si S'nin Instance'ıdır, basis S'nin merchant M'den aldığı `pay.refund` holding'idir, capacity FOR(M)'dir; Pay bu Exercise'ın PEP'idir (§7.9.13 satır 8).

Aşağı akış intent'i yukarı akış ExerciseID'yi causal context olarak taşır. **Causal ExerciseID tek başına yalnız audit/detection referansıdır**; RequirementTerm proof'u değildir (C24'ün proofKind'ları yalnız Claim | Contribution'dır) ve tüketilebilir bir birim değildir. Yukarı akış bağı mevcut iki mekanizmayla kurulur:

1. **RestrictionPolicy** (girdileri lineage, derived state ve cited ref'lerdir): downstream intent'in cite ettiği upstream ExerciseID committed ALLOW değilse, **upstream Exercise'ın ActionRef'i policy'nin adlandırdığı kabul edilen upstream action değilse** (ör. yalnız `commerce.refund@vN`; satın alma, kendi önceki `pay.refund`'ı veya başka bir action cite edilemez), upstream capacity downstream capacity ile aynı principal'ı (FOR(M)) taşımıyorsa veya onun IntentEnvelope parametreleri downstream parametreleri kapsamıyorsa (aynı resource; amount ≤) → DENY.
2. **Tek kullanım — causal-bound allowance:** S'nin Grant'ında upstream ExerciseID'ye anahtarlanmış **count=1 BudgetTerm** (StepRef'e bağlı count=1 budget ile aynı value biçimi; anahtar opaque context ref). Aynı upstream Exercise ikinci bir downstream effect'i destekleyemez.

**Guarantee sınıfı:** grantor (M) S'nin Grant'ına bu BudgetTerm'ü ve RestrictionPolicy'yi koyduysa (policy root veya üst holder tarafından da beyan edilebilir) bağ **GUARANTEED UNDER DECLARED POLICY**'dir; koyulmadıysa causal ExerciseID yalnız audit/detection sağlar ve S'nin kendi Grant sınırları (ör. `pay.refund ≤ 5000 TRY`) dışında bir bağ garanti edilmez. Confused deputy (Work §17.3) böylece yalnız declared policy altında kapanır; yapısal bir iddia değildir. Yeni proofKind, yeni primitive veya yeni record türü yoktur; encoding Protocol'dedir.

#### 7.9.8 Relay Seam

##### 7.9.8.1 Semantic event'in sınıfı

| Aday | Karar |
|---|---|
| Canonical Access state transition mı? | **Hayır.** Canonical geçiş, onu doğuran meta-Exercise (ör. `grant.revoke`) veya Claim ingest'idir (ör. HR supersession → episode kapanışı) |
| Derived event mi? | **Evet.** Semantic event = derived state'teki bir geçişin bildirimi |
| Relay object mi? | **Hayır.** Relay'in nesnesi *mesaj / teslimat*tır; event'in içeriğini taşır, sahiplenmez |

```text
grant.revoke Exercise (commit)  ──►  derived event "authority revoked"  ──►  Relay message(s)
   CANONICAL (Access)                  DERIVED (Access üretir)                 DELIVERY (Relay)
```

##### 7.9.8.2 Ownership

| Access owns | Relay owns |
|---|---|
| Event içeriği: ne değişti (revoked, narrowed, mandate-ended, acceptance-changed, budget-exhausted, revalidation-required), hangi Grant/Mandate/Exercise, hangi intent'e bağlı, ne zamandan beri, kimin bilmesi authority açısından gerekli (eligible set, etkilenen Instance'lar) | Kanal, timing, retry, fallback, presence, realtime transport, delivery status |
| Work Gate'lerinde: eligible set | Work Gate'lerinde: Work alıcıyı seçer, Relay teslim eder (Work §13.2) |

##### 7.9.8.3 Acknowledgement semantiği

| Ack türü | Owner | Anlamı | Authority'ye etkisi |
|---|---|---|---|
| **Delivery ack** | Relay | Mesaj hedef endpoint'e ulaştı | **Yok** |
| **Semantic acknowledgement** (Work notification'ı için) | Work | Kişi okudu/kabul etti | Yok (Work fact'i) |
| **Authority-state acknowledgement** ("PEP P, revocation R'yi uyguladı") | PEP / verifier (issuer) | Verifier'ın yerel durumunu güncellediğine dair Claim | **Yok** — yalnız revocation impact/staleness exposure derived görünümünü besler |

Delivery ack ≠ authority-state ack. Hiçbir ack türü revocation'ın geçerliliğini değiştirmez; revocation commit anında geçerlidir. Ack yokluğu "uygulanmadı" demek de değildir; "bilinmiyor"dur.

##### 7.9.8.4 Relay asla

- Authority, Gate veya effect truth'unun kaynağı olmaz.
- Teslim edemediği bir event yüzünden bir authority değişikliğini geri almaz veya geciktirmez.
- Bir bildirimin cevabını approval sayamaz (Work §21.9: "Relay notification itself cannot satisfy high-consequence approval").

#### 7.9.9 Money + Pay Seam

##### 7.9.9.1 Ownership

| Money owns | Pay owns | Access owns |
|---|---|---|
| Account, balance, funds, ledger, financial state, account ownership kaydı (KYC/legal), beneficiary listeleri, finansal limitler (bank/scheme limitleri) | Payment initiation execution, authorization hold, settlement, refund, payout, financial idempotency, network/acquirer state, scheme artifact'ları (payment mandate/consent), network token | Hesap ve ödeme action'ları üzerindeki authority: initiate, approve, refund, payout, create-hold, add-beneficiary; authority budget (principal'ın koyduğu ödeme authority limitleri dahil, BudgetTerm; Work §12, F9); ödeme authority envelope'u |

##### 7.9.9.2 Ownership örnekleri

| İfade | Owner | Access'teki karşılığı |
|---|---|---|
| "Account has 5000 TRY" | **Money** | Gerekirse `funds.available` predicate Claim'i (predicate-input) |
| "Available funds ≥ amount" | **Money** (Test A) | Predicate; Access yeniden hesaplamaz |
| "Account ownership" (hesabın hukuki sahibi) | **Money** (domain truth) | Anchor oluşturulurken ownership Claim'i root'un belirlenmesinde kanıt; **root'un kendisi Access'tir** |
| "Account controller" (hesabı kim yönetir) | Domain kaydı Money'nin; **yönetme authority'si Access'in** | Anchor root'tan türeyen Grant'lar; `controller-of` Claim'i yalnız selector olabilir |
| "Beneficiary X kayıtlı" | **Money / Pay** | Recipient selector Grant'ta Access value'su olarak X'e referans verebilir; "beneficiary ekleyebilir" authority'si Access'tir |
| "Daily financial limit" (bankanın/scheme'in limiti) | **Money / Pay** (Test A, eligibility) | Yok; Access'in authority budget'ından ayrı fact |
| "Agent may authorize ≤ 5000 TRY/day" | **Access** | BudgetTerm (authority budget) |
| "Kullanıcının Pay ekranında kendine/agent'ına koyduğu ödeme limiti" | **Access** (principal'ın koyduğu ödeme authority limiti; Work §12 "Payment authority/limits → Access", F9) | BudgetTerm; Pay ekranı yalnız Access'e `grant.amend` / `policy.set` isteyen bir yüzeydir, limitin ikinci kopyasını tutmaz |
| "500 TRY is held" | **Pay / Money** | Yok; authority draw ≠ financial hold (F9) |
| "Agent may create hold" | **Access** | `pay.hold.create` Grant'ı |

**İki limit bir arada durabilir ve ikisi de uygulanır**, farklı yerlerde: Access authority budget'ını, Pay/Money kendi finansal limitini uygular. Aynı fact'in iki kopyası değil, iki farklı fact'tir.

**Root transfer ve domain ownership değişikliği:** Hesabın hukuki sahibi değişirse (Money truth), Anchor root'u kendiliğinden değişmez. Değişiklik bir `anchor.transfer` Exercise'ıdır; bunu mevcut root yapar veya Anchor oluşturulurken rootTerms'e yazılmış reserved, koşullu bir Grant (ör. bankanın legal-ops Party'si, Money'nin `ownership.changed` predicate Claim'i şartıyla) yapar (CI-13 exceptional authority). Domain root'u yazamaz; Access hukuki sahipliği beyan edemez.

##### 7.9.9.3 Terminology collisions (Pay)

Access ontology'si yeniden adlandırılmaz; katmanlar eşlenir:

| Terim | Gerçek owner | Sınıf | Access ile ilişki |
|---|---|---|---|
| **Payment mandate** (SEPA DD mandate, UPI mandate, AP2 mandate, recurring card mandate) | **Pay / scheme** | Scheme'in domain artifact'ı (payer consent kaydı, scheme kurallarına tabi) | Arkasındaki *delegation* bir Access Grant'tır; scheme artifact'ı GrantID/ExerciseID'ye referans verebilir. **Access Mandate değildir** |
| **Payment consent** (PSD2/Open Banking consent) | **Pay / ASPSP / scheme** | Scheme/regülasyon artifact'ı | Kullanıcının TPP'ye/agent'a authority vermesi Access Grant'ıdır; consent objesi onun scheme-uyumlu projection'ı veya ayrı regülasyon kaydıdır, Access source'unu genişletemez |
| **Payment authorization** (card auth / hold) | **Pay** | Effect (financial) | Access'in "authorize" kararı değildir; Pay'in effect'idir |
| **Access Mandate** | **Access** | Primitive: Instance exercisability zarfı | Ödemeyle ilgisi yalnız, ödeme action'larının bir Instance'ın zarfında olup olmaması |
| **Pay authorization ≠ Access ALLOW** | — | — | ALLOW = "bu actor bunu isteyebilir"; Pay authorization = "issuer/acquirer parayı ayırdı" |
| **Network token** (card-on-file token, agentic token) | **Pay / network** (custody: Pay veya vault) | Credential / scheme artifact | Possession ≠ authority; token'ı kullanma authority'si Access Grant'ıdır |
| **Merchant authority** ("merchant müşterinin kartından çekebilir") | **Access** | Grant: müşterinin ödeme aracı Anchor'ından merchant'a, agency OWN, recipient = merchant, bounds | Pay'in merchant-initiated transaction kaydı scheme artifact'ıdır |

##### 7.9.9.4 Akış (Work §13.5 ile hizalı)

```text
Work: fulfillment evidence + acceptance → payment Commitment Condition satisfied   ← Work
Payer/agent Instance (Pay PEP aracılığıyla) → Access: pay.initiate intent          ← Access ALLOW + budget draw
  (amount, recipient, purpose, context refs; actor = basis'i tutan Party'nin Instance'ı)
Pay: executes (hold/settle)                                                       ← Pay effect
Pay → Access: effect attestation Claim (ExerciseID)                               ← Access conformance (derived)
Pay → Work: Reference; Work records Act report                                    ← Work
```

Access hiçbir adımda para tutmaz, ledger yazmaz, settlement beyan etmez. Pay PEP'tir: kararı ister/doğrular ve uygular, authority tutmaz, almaz, ödünç vermez (§7.9.7.4). Zincirlenen bir refund'da (Commerce → Pay) `pay.refund` Exercise'ının actor'ü Commerce service Party'si S'nin Instance'ıdır (basis = S'nin holding'i, capacity FOR(M)); upstream bağ RestrictionPolicy + causal-bound allowance ile GUARANTEED UNDER DECLARED POLICY'dir (§7.9.7.4, §7.9.13 satır 8).

#### 7.9.10 Commerce + Serve Seam

##### 7.9.10.1 Commerce

| Concern | Owner | Access'teki karşılığı |
|---|---|---|
| Catalog, cart, order, price, inventory, seller state | **Commerce** | ResourceRef'ler; gerekirse predicate Claim'ler |
| **Merchant identity** | Party (regime) + IdentityBinding (KYB issuer) + Commerce merchant profili (domain) | PartyRef; merchant org'u kendi namespace Anchor'ının root'u |
| **Seller membership** ("Alice merchant M'nin çalışanı") | **Issuer**: Commerce'in merchant staff kaydı veya merchant'ın HR'ı | Claim (`member(Alice, M)`), subject-selection Acceptance'ı ile |
| **Merchant admin** | **Access** | Merchant root'tan türeyen (genellikle rule-shaped) Grant; "admin" bir AuthoritySet'tir ve reserved action'ları kapsamaz |
| **Order ownership** ("order O müşteri C tarafından verildi") | **Commerce** (domain truth) | Yapısal Claim (`placed-by(O, C)`); müşterinin kendi siparişi üzerindeki hakları, Anchor root'undan (domain kararı: merchant veya marketplace) türeyen rule-shaped Grant ile ifade edilir |
| **Refund rule** ("30 gün içinde iade edilebilir") | **Commerce** (Test A) | Predicate (`order.refundable`) |
| **Refund authority** ("Alice bu siparişi ≤ 500 TRY iade edebilir") | **Access** (Test B) | Grant; Test C ile predicate'e bağlanabilir |
| Commerce'teki eligibility ayarını değiştirmek | Effect Commerce'te; **authority kararı Access'te** | `commerce.policy.update` Exercise'ı |

Örnek, ownership ile:

```text
Order is refundable                          → Commerce (truth) → Claim, predicate-input
Alice may refund that order                  → Access (Grant + Exercise)
Alice is a merchant employee                 → External Claim (Commerce staff kaydı / HR)
That membership selects a rule-shaped Grant  → Access (subject-selection Acceptance + Grant)
```

##### 7.9.10.2 Serve

| Kavram | Owner | Sınıf |
|---|---|---|
| Restoran, menü, lokasyon, sipariş, mutfak, teslimat operasyonu | **Serve** | Domain truth |
| **Restaurant manager** | Rol Claim'i (Serve/HR) + **Access** rule-shaped Grant | Claim → selection; authority Grant |
| **Staff shift** ("Bob şu an vardiyada") | **Serve** (scheduling domain truth) | Claim (`on-shift(Bob, store, now)`), kısa validity; rule-shaped Grant'ın selector'ı veya RestrictionPolicy/while-condition girdisi |
| **Courier identity** | Party + IdentityBinding | PartyRef; teslimat ataması Serve'ün domain kaydıdır (veya çok taraflı koordinasyon gerekiyorsa Work Commitment) |
| **Kitchen role** | Serve rol Claim'i | Selection girdisi |
| **Store admin** | **Access** | Grant (store namespace Anchor root'undan) |
| **Refund** | Effect Commerce/Serve'de; authority **Access** | `serve.refund` Grant + Exercise |
| **Menu edit** | Effect Serve'de; authority **Access** | `serve.menu.edit` Grant |
| **Cash drawer authority** | **Access** (`serve.drawer.open`, `serve.void ≤ X`) | Grant + budget; çekmecedeki nakit Serve'ün operasyon kaydıdır (Money'ye entegre ise Money'nin) |
| **POS offline kullanım** | Access (projection + offline slice); POS operatörü (verifier) | §7.9.4 |

**Access workforce scheduling'e dönüşmez:** vardiya planı, kim hangi vardiyada, mola, takas Serve'ündür. Access yalnız "vardiyada olan X rolündeki biri Y yapabilir" Grant'ını tutar ve vardiya Claim'ini tüketir. *Shift membership is a Claim; authority is a Grant.*

##### 7.9.10.3 Generic Domain Product contract (future products)

Access sekiz mevcut Suiss ürününe hardcode edilmez. Her domain ürünü (first-party, third-party veya henüz var olmayan) aynı sözleşmeyle bağlanır:

```text
Domain Product
  → publishes: action namespace + typed schemas (+ reserved beyanı, parametre sınıflandırması)
  → owns: resources (ResourceRef + incarnation) ve domain truth / eligibility
  → produces: attributable predicate / lifecycle / effect Claim'leri (kendi issuer kimliğiyle)
  → enforces: kendi effect'lerinin PEP'idir, veya enforcement'ı bir Executor'a delege eder
  → requests: Access authority decision'larını (her consequential effect için)
  → never: Anchor root yazmaz, Grant yazmaz, Acceptance yazmaz, authority beyan etmez

AuthorityDomain (Access)
  → accepts: schema'yı (schema-definition), predicate'leri (predicate-input),
                  gerekiyorsa membership'i (subject-selection) — her biri meta-Exercise
  → owns: Anchor'lar, Grant'lar, Mandate'ler, Exercise'lar
```

**Anahtar test — yeni ürün yeni ontology gerektirmemeli.** Hipotetik iki ürünle sınandı:

| Ürün | Domain truth | Access'te gereken | Yeni primitive? |
|---|---|---|---|
| "Suiss Ride" (ulaşım) | Yolculuk, sürücü uygunluğu, fiyat, konum | `ride.*` schema'sı, sürücü üyelik Claim'i + rule-shaped Grant, "agent ≤ 300 TRY yolculuk çağırabilir" budget'ı | Hayır |
| "Suiss Health" (randevu/kayıt) | Hasta kaydı, randevu, klinik uygunluk | `health.*` schema'sı (`disclose` core class'ı ile), vasi Claim'i + explicit self-anchor root, minimizasyon (§7.9.15) | Hayır |

##### 7.9.10.4 Resource lifecycle seam

| Olay | Domain owns | Access owns | Kural |
|---|---|---|---|
| **Resource create** | Varlık, ResourceRef, ilk incarnation | Kapsayan Anchor'ın authority'si (otomatik, en özel Anchor) | Farklı bir root gerekiyorsa ayrı `anchor.create/carve` Exercise'ı; domain bunu yazamaz |
| **Resource delete** | Silme fact'i (lifecycle Claim) | Anchor/Grant'lar tarih olarak kalır; `anchor.retire` ayrı Exercise | Access resource'un var olduğunu veya olmadığını beyan etmez |
| **Reincarnation** (aynı id ile yeniden yaratma) | Yeni incarnation vermek **zorunlu** | Eski incarnation'a ait Grant'lar yeni incarnation'ı kapsamaz | Incarnation'ı yeniden kullanmak domain'in sözleşme ihlalidir; authority resurrection'ın tek kapısıdır (E14) |
| **Resource move** | Yapısal değişiklik (`parent-of` Claim'i) | Kapsayan en özel Anchor değişebilir; rule-shaped resource selector'lar yeni kümeyi seçer | Beklenen ve açıklanabilir değişiklik |
| **Split / merge** | Yeni ResourceRef'ler | Eski Grant'lar yeni resource'lara kendiliğinden genişlemez | Kapsayan namespace Anchor'ı varsa onun altına düşer, yoksa fail closed |
| **Ownership / root transfer** | Domain'deki sahiplik kaydı (ör. mağaza satışı) | `anchor.transfer` + explicit disposition | Domain sahiplik değişikliği root'u değiştirmez; Exercise gerekir (§7.9.9.2'deki reserved koşullu Grant deseni dahil) |

##### 7.9.10.5 Domain predicate ownership

`order.refundable = true`, `account.status = active`, `restaurant.shift = open`, `device.compliant = true` için:

| Boyut | Owner |
|---|---|
| **Schema** (predicate'in adı, tipi, anlamı) | Domain publisher |
| **Issuer** (iddiayı kim yapar) | Domain servisi (kendi Party kimliğiyle) |
| **Freshness** (iddianın geçerliliği) | Issuer beyan eder; Access RequirementTerm daha sıkı freshness isteyebilir |
| **Truth** | Domain |
| **Acceptance** (girdi olabilir mi) | AuthorityDomain (Acceptance meta-Exercise'ı) |
| **Use** (hangi karar yerine girer) | Acceptance'ın `use` boyutu: genellikle `predicate-input` |

Domain predicate **authority yaratmaz**; tek dolaylı etkisi, trust sınırı daha önce explicit kurulmuş (subject-selection Acceptance'ı) bir rule-shaped Grant'ın seçimini değiştirmesidir (INV-16).

#### 7.9.11 External Identity + Authority Provider Seam

##### 7.9.11.1 External Identity Providers

OIDC provider, enterprise IdP, workload identity issuer (SPIFFE/WIMSE), device attester, HR, government identity: hepsi **issuer**'dır. Hiçbiri otomatik olarak authority issuer olmaz.

| Acceptance kullanımı | Ne demek | Tipik issuer | Blast radius (issuer compromise) | Meta-requirement |
|---|---|---|---|---|
| **Authentication trust** (`actor-binding`, class `authentication`) | Bu oturum/anahtar hangi Party'nin Instance'ı | OIDC/enterprise IdP, Identity plane, SPIFFE | subjectClass içindeki Party'lerin impersonation'ı; o Party'lerin **zaten tuttuğu** authority kadar | strong |
| **Identity claim acceptance** (`predicate-input`, class `identity-binding.*`, attribute'lar) | Restriction/requirement girdisi | IdP, HR, KYC provider | Yalnız daraltma veya requirement karşılama; positive authority yok | normal |
| **Authority-selecting acceptance** (`subject-selection`, class `membership`/`group`/`role`) | Rule-shaped Grant'ların holder kümesi | HR, IdP grupları | Önceden var olan rule-shaped Grant'ların ceiling'leri içinde seçim | **reserved; quorum tipik** |
| **Foreign authority acceptance** (`foreign-authority`) | Bridging Grant seçicisi | Foreign AuthorityDomain | Bridging Grant ceiling'i | **reserved; quorum tipik** |

Bir IdP'nin `actor-binding` için kabul edilmesi, aynı IdP'nin grup claim'lerinin `subject-selection`'a girmesine izin vermez (INV-15); bir identity issuer'ın authority issuer rolünü alması metadata düzeyinde engellenebilir (L26).

**IdP compromise kuralı (E18):** *External IdP compromise must not silently mint authority beyond already accepted rule-shaped selection.* En kötü durumda saldırgan (a) actor-binding kapsamındaki Party'leri taklit eder, (b) subject-selection kabul edilmişse önceden var olan rule-shaped Grant'ların ceiling'leri içinde kendini seçtirir. Hiçbir durumda yeni Grant, yeni Acceptance, ceiling üstü authority, reserved action veya meta-action yetkisi oluşmaz. Kurtarma: Acceptance revoke (prospective), ingest-time cutoff ("T'den sonra kaydedilen claim'leri kabul etme"), etkilenen episode'ların affirmative kapanışı.

> Bu tabloda Access identity plane de bir issuer'dır. Ayrıca Access identity plane, kendi RP'leri için bir OIDC OP / SAML IdP'dir (§7.3 "identity plane ↔ RP" seam'i). Access bir federation broker olduğunda upstream IdP'ler bu tablonun issuer'larıdır. Hesap bağlama yalnız açık IdentityBinding ile yapılır; e-postayla otomatik bağlama yoktur (MD-5).

##### 7.9.11.2 External authority provider

| Soru | Karar |
|---|---|
| **Bir AuthorityDomain başka conformant provider'da host edilebilir mi?** | **Evet** (CI-15). Suiss Access first-party/reference provider'dır, zorunlu değildir |
| **Provider değişirken DomainID aynı kalabilir mi?** | **Evet.** **Kooperatif handover**, domain root'unun ve eski/yeni provider'ın katkılarıyla yapılan bir meta-Exercise'tır; kayıt defteri (Genesis'ten itibaren) taşınır ve eski provider katkı verdiği için continuity doğrulanabilir. **Zorunlu migration** (eski provider erişilemez) domain root'unun genesis'te tanımlanmış reserved recovery yoluyla olur ve farklı bir guarantee sınıfındadır: recovery Exercise'ı devam ettiği **son doğrulanmış ledger pozisyonunu** StateBasis'inde cite eder; o pozisyondan sonraki eski-provider kayıtları devam eden lineage'da authoritative değildir; eski provider'ın o pozisyondan sonra verdiği projection'lar ve reusable Decision'lar geçersizdir (fail closed); kayıp revoke/draw/single-use tüketim riski recovery Exercise'ında **beyan edilir**. Kayıp suffix'te bulunan bir revocation, recovery sonrası yeni bir revoke Exercise'ıyla yeniden yapılmalıdır (prospective). Bu yolda continuity ve kayıpsızlık **garanti edilmez**; yalnız declared capability (ör. her commit'in root'un kontrol ettiği bir witness/replica'ya ulaşmadan acknowledge edilmemesi) altında korunur. Mekaniği (fencing, witness) Security/Technical |
| **Canonical semantiği kim tanımlar?** | **Access protocol spesifikasyonu** (açık, vendor-neutral; Work Protocol §21.2 ile aynı ilke). Suiss-hosted implementasyon semantiğin sahibi değildir; conformance suite referanstır |
| **Work dış authority'ye nasıl atıf yapar?** | `DomainID + ExerciseID` (+ gerekiyorsa DecisionRecord'un doğrulanabilir projection'ı, portable authority proof). Work hangi provider'ın host ettiğini bilmek zorunda değildir; Work §21.5'in üç kontrolü (cryptographic validity, issuer trust, semantic coverage) bu proof üzerinde yapılır |
| **İki provider eşzamanlı writer olabilir mi?** | **Hayır, semantik olarak** (E20). Bir domain için authoritative lineage tektir ve root'un handover/recovery Exercise zinciriyle belirlenir; handover bir cutover'dır. Eski provider'ın yazmayı **fiilen** kesmesi semantik bir guarantee değildir: zorunlu migration'da eski provider'ın cutover'ı bilmeyen client'lardan yazı kabul etmeye devam etmesi (equivocation) fiziksel olarak engellenemez; bu yazılar devam eden lineage'da authoritative değildir. Fiziksel tek-writer yalnız declared capability altındadır (fencing/witness, Technical) |
| **Read federation vs authority migration?** | **Read federation**: başka sistemlerin (verifier'lar, Work, SIEM, başka provider'lar) bir domain'in kayıtlarının veya projection'larının kopyalarını okuması; kopyalar projection'dır, yazamaz. **Authority migration**: bir domain'in authoritative writer rolünün handover meta-Exercise'ıyla devri. İkisi karıştırılamaz |
| **Bir Anchor bir domain'den diğerine taşınabilir mi?** | Kimlik koruyarak **hayır** (Anchor scope'u domain'in içindedir). Yeni domain'de yeni Anchor + eski domain'de `anchor.retire`/disposition; tarih eski domain'de kalır; iki domain arasındaki köprü gerekiyorsa bridging Grant |

##### 7.9.11.3 Federation peer — beş ayrı şey

| Şey | Ne | Mekanizma | Ne değildir |
|---|---|---|---|
| **Identity federation** | Foreign Party'nin kimliğini tanımak | Acceptance `actor-binding` | Authority kabulü |
| **Foreign authority evidence** | Foreign domain'de türetilmiş authority'nin kanıtı | Claim (foreign chain digest + issuer) | Yerel authority |
| **Local bridging Grant** | Foreign authority'yi yerel bir ceiling içinde etkili kılmak | Yerel root'tan rule-shaped Grant, `ForeignAuthority` selector + `foreign-authority` Acceptance | Foreign basis |
| **Cross-domain delegation** | Yerel bir holder'ın başka domain'deki bir Party'ye authority vermesi | Yerel domain'de, foreign Party'yi (actor-binding ile tanınmış) holder yapan extensional Grant; budget draw home domain'de | Foreign domain'e authority yazmak |
| **Authority-provider handover** | Aynı domain'in authoritative writer'ının değişmesi | Handover meta-Exercise'ı (kooperatif) veya root'un reserved recovery Exercise'ı (zorunlu migration; kayıp suffix riski beyan edilir, §7.9.11.2) | Federation (iki domain değil, tek domain) |

Hiçbiri "generic federation" başlığı altında birleşmez; her biri farklı bir Acceptance use'u veya farklı bir Exercise'tır.

#### 7.9.12 Governance / PAM / MDM / Security Tooling Seam

Ortak ilke (L28): **security-important ≠ Access-owned.** Bu araçların Access'e verebileceği şey Claim veya Exercise *talebi*dir; Access'in onlara verdiği şey karar ve projection'dır.

> Bu araçlar "ayrı ürün katmanı"dır (§7.6, E22). Access bunlara karar, projection, olay ve sinyal üretir. Token vault ve identity plane'in kendi step-up'ı identity plane'e atanmıştır. "security-important ≠ Access-owned" ilkesi "security-important ≠ authority-plane-owned" olarak okunur.

##### 7.9.12.1 Risk / security tooling

| Kaynak | Access'e nasıl girer | Yapabilir | Yapamaz |
|---|---|---|---|
| Risk score, compromise signal, fraud alert, impossible travel, behavior anomaly | `risk.*` Claim (predicate-input) | DENY, REQUIRE (step-up/stronger proof), containment overlay, ValidityContract kısaltma | Positive authority üretmek, Grant'ı genişletmek |
| Containment kararı (SOC) | SOC Party'sinin explicit `instance.*` / `grant.revoke` / restriction Exercise'ı (önceden verilmiş reserved Grant'la) | Terminal revoke dahil | Exercise dışı "kill switch" |

Access genel risk tespiti yapmaz; risk skorunun anlamı issuer'ındır. Deterministic evaluation için risk yalnız kayda geçmiş Claim olarak ve yalnız restriction rolünde girer (INV-27).

> Identity plane'in kendi giriş-risk sinyalleri ve risk tabanlı step-up identity plane'dedir (§7.6). Bu sinyaller de authority plane'e yalnız `risk.*` Claim olarak ve yalnız daraltıcı rolde girer. Risk motoru arızası ALLOW'a dönmez.

##### 7.9.12.2 Device / MDM

MDM: enrollment, compliance, patch, inventory. Access: `posture.device` Claim'ini (subject = Instance veya device) RequirementTerm/restriction olarak tüketir. **Device ≠ authority**: bir cihaz ancak kendi PartyRef'i ve explicit Grant'ı varsa (POS terminali, robot) authority holder'dır. "Yönetilen cihaz" olmak authority vermez; "yalnız yönetilen cihazlar payroll'a erişebilir" Access'in actor-side requirement'ıdır (Test B + C).

##### 7.9.12.3 IGA / governance workflows

| IGA owns | Access owns |
|---|---|
| Access review kampanyası, manager certification, role mining, JML workflow, SoD analizi, öneri | Grant issue/revoke/amend, Acceptance değişikliği: **her biri Authority Exercise** |

IGA'nın kararı Access'e **Exercise talebi** olarak gelir; talebi yapan, gerekli meta-authority'yi tutan bir Party'dir (ör. reviewer'ın `grant.revoke` Grant'ı). IGA önerisi Access'i sessizce değiştiremez; workflow authority mutation bypass'ı değildir (INV-2). Access, IGA'nın ihtiyaç duyduğu analiz sorgularını ("who can do Y", "why", "revoke impact") derived olarak cevaplar; review UX'i ve kampanya state'i IGA'nındır.

##### 7.9.12.4 PAM / credential & secret custody

| Concern | Owner |
|---|---|
| "Kim bu credential'ı / privileged oturumu kullanabilir, hangi koşulla (JIT, approval, süre)" | **Access** (Grant + RequirementTerm + Mandate) |
| Secret / token / refresh token saklama, credential injection, session brokering, recording | **Vault / PAM / Executor Runtime / Pay (network token)** |
| Authenticator verifier materyali (passkey public key vb.) | Identity plane (issuer olarak); authority kaydı değil |

Access authority kayıtları secret içermez (Work §17.5 ile aynı). Vault, bir credential'ı yalnız geçerli bir Exercise referansına karşı serbest bırakır; vault kendi başına authority kararı vermez. Credential custody canonical Access state'i değildir (E22).

> Ajan upstream OAuth token'larının custody'si (token vault / credential broker) identity plane'dedir. Bu tablodaki "Secret / token / refresh token saklama" satırı genel sır kasası ve PAM için geçerlidir. Token vault'tan release, bu tablonun "vault yalnız geçerli bir Exercise referansına karşı serbest bırakır" kuralına aynen tabidir. Identity plane'in kendi issue ettiği refresh token'lar identity plane kaydıdır; authority kaydı değildir.

##### 7.9.12.5 Audit / SIEM

Access canonical authority kayıtlarının sahibidir. SIEM arama, korelasyon, tespit, alarm ve kopya saklama yapar; tükettiği şey **projection**'dır ve authority source değildir. Audit export şunları korumak zorundadır (format Protocol'de): provenance (lineage), attribution (actor, capacity, issuing Exercise), AuthorityStateBasis, Exercise ↔ DecisionRecord ↔ contribution ↔ cited Claim ilişkileri, redaction sonrası digest doğrulanabilirliği. SIEM kopyası canonical kayıtla çelişirse kopya yanlıştır.

##### 7.9.12.6 Trusted approval surface

| Owner | Sorumluluk |
|---|---|
| **Access** | Exact approval authority (kim), exact intent/Gate digest'i, gereken assurance (human presence, phishing-resistant, freshness), independence şartları; contribution'ın geçerliliği |
| **Trusted approval surface** (Approval Surface conformance profile; Experience, first- veya third-party client) | Exact intent'i sadakatle render etmek, authenticating user act'i toplamak, digest'i bağlamak |
| **Work / domain** | Approval'ın *neden* var olduğu (Gate, eligibility) |
| **Executor / domain** | Effect |

Generic bildirim, "Allow?" düğmesi veya agent'ın yazdığı prose, exact authority-relevant approval artifact'ının yerine geçemez (L14, Work S11, Work §21.9). Approval Surface profile'ı Work'ün Approval Contract'ı ile Access'in contribution binding şartlarının ortak protocol yüzeyidir; üçüncü bir semantik owner yaratmaz. UI tasarımı Product Experience'tadır.

##### 7.9.12.7 Legal / organizational reality

Şirket kuruluşu, istihdam, vasilik, vekâletname, mahkeme kararı: **genesis meşruiyeti ve bu fact'lerin doğruluğu dışsaldır.** Access bunları doğru ilan etmez; attributable Claim olarak kabul eder ve bunlardan doğan authority'yi yalnız explicit Grant/Acceptance/Anchor Exercise'ı olarak modeller (ör. vekâletname → `FOR(Alice)` agency'li Grant; mahkeme kararı → önceden tanımlı reserved legal-process Grant'ının Exercise'ı, CI-13). Legal liability Access ontology'si değildir; bir Exercise'ın hukuki sonucu jurisdiction/profile meselesidir.

#### 7.9.13 Cross-System Scenario Walkthrough

Senaryo: Merchant M'nin destek agent'ı A, bir şikâyeti çözmek için 300 TRY iade yapar; sonra çeşitli değişiklikler olur. Her satır: owner · canonical record · sınırı geçen referans · olamayacak şey.

| # | Olay | Owner | Canonical record | Sınırı geçen referans | Olamaz |
|---|---|---|---|---|---|
| 1 | **User logs in** (M'nin yöneticisi Y) | Identity plane (veya external IdP) → Authority plane | `authentication` Claim (Identity plane); `instance.create` + `mandate.bind` Exercise'ı (Access) | InstanceID, authentication ClaimID | Login'in authority vermesi; UI session'ın Instance sayılması |
| 2 | **Agent is created** | Regime (PartyID, controller = M'nin controller'ı); Access (admission); Executor Runtime (process) | Inception key-event (regime); `operated-by` / `agent-kind` Claim'leri; `party.register` + self-anchor (root = M) Exercise'ı; çalışınca `instance.create` | PartyRef(A), InstanceID | Agent yaratmanın authority vermesi; operator'ın root olması |
| 3 | **Agent gets authority to refund ≤ 500 TRY** | Access | `grant.issue` Exercise'ı (Y'nin Instance'ı, basis = Y'nin M'den gelen holding'i, capacity FOR(M)); Grant {`commerce.refund@vN`, amount ≤ 500 TRY, resource = M orders, agency {FOR(M)}, delegable=false}; A'nın Instance'ına `mandate.bind` | GrantID, MandateID | Work'ün veya Commerce'in bu Grant'ı yazması; Y'nin kendi tutmadığından fazlasını vermesi (INV-3) |
| 4 | **Work delegates "resolve complaint" to agent** | Work | Commitment C (obligor A, obligee destek lideri, principal M) Declaration'ları | CommitmentRef (Intent context'inde opaque) | Commitment'ın authority yaratması veya genişletmesi |
| 5 | **Commerce says order is refundable** | Commerce | Domain kaydı; `order.refundable(O#inc)` Claim'i (issuer Commerce, kısa validity) | ClaimID | Access'in refund window'u hesaplaması; predicate'in authority vermesi |
| 6 | **Agent asks Access to exercise refund authority** | Access (değerlendirme); talep A'nın Instance'ından (Commerce PEP aracılığıyla) | Nonce'a bağlı opening record: actor Authenticated(I_A), basis ⟨G3, A, since⟩, capacity FOR(M), IntentEnvelope {commerce.refund@vN, O#inc, 300 TRY, purpose, context: WorkRef/CommitmentRef} | Intent digest | Konuşma veya Work içeriğinin Access'e gitmesi |
| 7 | **Access returns ALLOW** | Access | ALLOW DecisionRecord = **Exercise doğar**; budget draw; StateBasis (Grant revizyonu, Mandate, Claim, Acceptance, schema sürümü); (gerekiyorsa) ValidityContract | ExerciseID, Decision projection | ALLOW'un başka bir intent'e veya başka PEP'e uygulanması |
| 8 | **Pay/Commerce executes refund** | Commerce (order refund effect, PEP); Pay (para hareketi, kendi PEP'i) | Commerce domain kaydı; `pay.refund` Access Exercise'ı: **actor = Commerce service Party'si S'nin Instance'ı**, basis = S'nin M'den aldığı `pay.refund` holding'i, capacity FOR(M), context = ExerciseID_7; **Pay bu Exercise'ın PEP'idir** (kararı doğrular ve uygular) + Pay effect kaydı. Upstream bağ: RestrictionPolicy (ExerciseID_7 committed ALLOW, action'ı policy'nin adlandırdığı `commerce.refund@vN`, aynı principal FOR(M), envelope'u kapsıyor: aynı O#inc, amount ≤ 300 TRY) + S'nin Grant'ında ExerciseID_7'ye anahtarlanmış count=1 causal-bound allowance (§7.9.7.4) | ExerciseID_7 (causal context), `pay.refund` ExerciseID | Pay'in actor veya holder olması; Pay'in Commerce'in sözüne dayanarak authority varsayması (R6); ExerciseID_7'nin ikinci bir refund'ı veya farklı order/tutarı desteklemesi (declared policy altında DENY; policy yoksa yalnız audit/detection); Access'in para hareket ettirmesi |
| 9 | **Effect attestation arrives** | Commerce / Pay (issuer) | `effect.attestation` Claim'leri (ExerciseID'lere bağlı); Access'te conformance derived; Work'te Act report + Reference | ClaimID, EffectRef | Attestation'ın decision tarihini değiştirmesi; attestation yokluğunun başarı sayılması |
| 10 | **User revokes agent authority** (Y, G3'ü) | Access | `grant.revoke(G3)` Exercise'ı; cascade derived; A'nın Mandate kapsamı daralır | Derived semantic event | Revocation'ın geçmiş ALLOW'u (adım 7) geçersiz kılması (INV-23) |
| 11 | **Executor is still running** | Executor | Execution state (Executor) | — | Access'in "durdu" demesi; sonraki continuation/yeni intent ALLOW alması; Executor yeni consequential effect'i Exercise'sız yaparsa bu unauthorized'dır |
| 12 | **Relay sends revocation event** | Relay (teslim); Access (içerik) | Relay delivery kaydı | Event + delivery ack | Delivery'nin revocation commit'i sayılması; ack'in authority değiştirmesi |
| 13 | **HR removes employee E from Finance** | HR | HR kaydı; Access'te superseding `member(E, Finance) = false` Claim ingest'i | ClaimID | HR'ın Grant'ı doğrudan revoke etmesi (gerek yok, yetkisi de yok) |
| 14 | **Rule-shaped Grant no longer selects E** | Access (derived) | Kayıt yazılmaz; E'nin holding episode'u trusted time'da terminal kapanır; o HoldingRef'e dayanan alt Grant'lar, Mandate pin'leri, reusable Decision'lar prospective olarak geçersiz | Derived event | Staleness'ın episode'u kapatması (yalnız affirmative değişiklik); geçmiş exercise'ların silinmesi |
| 15 | **E rejoins Finance later** | HR (fact); Access (derived) | Yeni `member(E, Finance)` Claim'i → **yeni episode**, yeni `since` | ClaimID | Eski episode'un türevlerinin dirilmesi (INV-31); eski Mandate pin'inin kendiliğinden yeni episode'a geçmesi (explicit `mandate.rebind` gerekir) |
| 16 | **External company X presents foreign authority** | X'in AuthorityDomain'i (foreign lineage) | X'in domain'indeki kayıtlar; yerelde foreign authority chain Claim'i (ingest) | Foreign chain digest + issuer | Foreign chain'in yerel authority sayılması (CI-10) |
| 17 | **Local domain accepts foreign authority class** | Yerel AuthorityDomain | `acceptance.establish(issuer = X authority issuer, use = foreign-authority, classes = {C})` reserved meta-Exercise'ı | AcceptanceID | Identity acceptance'ının authority acceptance sayılması; Acceptance'ın Exercise dışı kurulması |
| 18 | **Domain creates bridging Grant** | Yerel AuthorityDomain | `grant.issue` Exercise'ı: basis = yerel AnchorRoot, holder = ForeignAuthority(X, C), ceiling = yerel AuthoritySet, delegable=false | GrantID | Ceiling üstü authority; foreign lineage'ın basis olması |
| 19 | **Work requires two approvals** | Work (coordination Gate, k=2); authority composition da 2 istiyorsa Access (RequirementTerm count=2) | Work Gate Declaration; (varsa) Grant/Policy'deki RequirementTerm | GateRef, Gate digest / intent digest | Work Gate'inin Access requirement'ını karşılaması veya tersi |
| 20 | **Two eligible approvers contribute** | Access (contribution'lar); Work (eligible kişilere iletme, Relay ile) | İki `contribute(approve, digest)` Exercise'ı (her biri kendi Instance, basis, capacity, assurance); her biri için Work Declaration (ExerciseID referanslı) | ExerciseID'ler, eligible set | Aynı Party'nin iki contribution sayılması; agent prose'unun approval sayılması; Public selector'ın contribution kaynağı olması |
| 21 | **Access validates quorum** | Access | Hedef Exercise'ın REQUIRE_ACTION'dan ALLOW'a geçen DecisionRecord'u; contribution'lar cited ve single-use tüketilmiş; independence değerlendirilmiş | ExerciseID | Contribution'ın başka intent'e yeniden kullanılması; threshold aggregate'in iki katkı sayılması (L13) |
| 22 | **Work Gate is satisfied** | Work | Gate satisfaction Declaration (contribution ExerciseID'lerini cite eder; Work referansları doğrular) | ExerciseID'ler | Gate satisfied'ın Access ALLOW sayılması; Access'in Gate'i kapatması |

##### 7.9.13.1 Senkron / asenkron sınıflandırma

| Sınıf | Etkileşimler |
|---|---|
| **Must synchronously authorize before effect** | Domain PEP / Executor → Access, her consequential effect'ten önce (online profile) veya geçerli ValidityContract/offline slice içinde yerel karar (diğer profiller); meta-action'lar (Access içi, karar = effect); contribution'ın hedef Exercise'ta tüketimi |
| **May asynchronously propagate state** | Access → verifier'lar: revocation/narrowing'in yayılması (bounded staleness içinde); Claim ingest (issuer → Access); projection yenileme |
| **May asynchronously report effect** | Executor / domain → Access: effect attestation; → Work: Act report; offline exercise raporları |
| **May asynchronously notify** | Access semantic event'leri → Relay → insanlar/sistemler; Work attention/Gate bildirimleri |
| **Must never infer success from absence** | Receipt yokluğu ≠ effect oldu; ack yokluğu ≠ uygulanmadı/uygulandı; stop teyidi yokluğu ≠ durdu; Claim yokluğu ≠ negatif fact (staleness lapse değildir) |

Event delivery semantic revocation commit'i değildir; commit Access'te, event yalnız onun bildirimidir.

##### 7.9.13.2 Dağıtık transaction mitolojisi yok

Senaryodaki hiçbir adım tek atomik cross-product transaction gerektirmez. Her adımda tek bir authoritative sistem vardır ve atomicity yalnız **bir owner'ın kendi içinde** gereklidir (ALLOW + consumption, meta-Exercise + state change, contribution tüketimi). Cross-product tutarlılık; referanslar (ExerciseID, ClaimID), fail-closed karar kuralları, idempotency, outbox, saga ve compensation ile sağlanır; bunların seçimi Technical Architecture'dadır. Semantik olarak kaçınılmaz bir cross-product atomicity yoktur.

#### 7.9.14 Failure Ownership

| Arıza | UNKNOWN diyebilen | Fail closed olmak zorunda | Reconciliation owner | User-facing truth owner |
|---|---|---|---|---|
| **Access unavailable** | PEP/Executor/Work: "authority durumu bilinmiyor" | Online profile'daki her consequential effect (karar yoksa effect yok). Geçerli ValidityContract/offline slice içindeki kararlar contract sınırına kadar devam edebilir; contract biter bitmez DENY | Access (geri gelince continuation/offline raporların ingest'i) | Work (iş neden bekliyor), domain (effect yapılmadı) |
| **Domain product unavailable** | Access: predicate Claim'i yok/stale → REQUIRE_ACTION | Access (predicate'i uydurmaz); domain PEP'i zaten yok → effect yok | Domain | Domain / Work |
| **Relay delayed** | Relay (delivery bilinmiyor) | Hiçbir güvenlik kararı Relay'e dayanmaz; verifier'lar expiry/contract'a göre davranır | Relay (teslim); semantik etkisi yok | Work (bildirim durumu) |
| **Effect receipt lost** | Executor/domain: outcome *unknown*; Access derived outcome = unattested | Budget release yapılmaz (grounded non-execution yok); aynı nonce tekrar ALLOW almaz; yeni deneme yeni intent/nonce | Executor / domain (effect reconciliation, idempotency); Access yalnız sonradan gelen attestation/non-execution Claim'iyle release | Executor/domain (effect), Work (Act/Claim olarak gösterim) |
| **External IdP stale** | Access: authentication freshness karşılanmıyor → REQUIRE_ACTION | Actor-binding fresh kanıt isteyen her requirement; **staleness subject-selection episode'unu kapatmaz** (yalnız affirmative değişiklik) | IdP (veri); Access (yeni Claim'lerle yeniden değerlendirme) | Identity plane / IdP (giriş durumu) |
| **Foreign authority provider unreachable** | Access: foreign status stale → REQUIRE_ACTION / DENY (profile'a göre) | Bridging Grant üzerinden exercise'lar fresh foreign proof gerektiğinde; yerel taraf her an Acceptance/bridging Grant'ı revoke edebilir (yerelde kesin) | Foreign domain (kendi state'i); yerel Access (yeni proof'larla) | Yerel domain |
| **Hosting provider unreachable / forced migration** | Root ve verifier'lar: son doğrulanmış pozisyondan sonraki ledger suffix'i *unknown* | Eski provider'ın, recovery Exercise'ının cite ettiği pozisyondan sonra verdiği projection'lar ve reusable Decision'lar geçersiz; yeni provider recovery Exercise'ı commit olmadan karar vermez; kayıp suffix'teki revocation yeniden yapılmadan ilgili Grant'lar root/üst holder policy'siyle restrict edilebilir | Domain root (recovery Exercise'ı, kayıp revoke/draw riskinin beyanı, kayıp revocation'ların yeni revoke Exercise'ıyla prospective tekrarı); eski provider (geri dönerse kayıtları yalnız audit girdisi, devam eden lineage'da authoritative değil) | AuthorityDomain (yeni provider'daki devam eden lineage) |
| **Work state ve Access state uyuşmuyor** | — | Work, Access'in DENY ettiği veya doğrulayamadığı bir authority basis'iyle ilerleyemez; Access Work state'ine dayanmaz | Her biri kendi fact'i için: authority sorusunda Access kaydı, Commitment/Gate sorusunda Work kaydı kazanır; Work referanslarını Access'e karşı yeniden doğrular | Work (iş durumu), Access (authority durumu) |
| **Executor ignores revocation** | Work/Executor: stop durumu *unknown* | Access: sonraki her continuation/yeni intent DENY; Exercise'sız effect unauthorized | Executor operator'ı (fiziksel); Access (containment: agent/executor Instance'larına restriction, gerekiyorsa Acceptance revoke); Work (escalation, accountability) | Work + Executor (dürüst control durumu); Access yalnız "authority yok" der |

> Identity plane arızaları için ek satırlar (identity plane erişilemez, upstream IdP erişilemez, CAEP sinyali gecikti, hesap devre dışı ama offline token'lar var) §8.13'teki identity plane satırlarıdır. Kural aynıdır: owner UNKNOWN der; Access belirsizlikte DENY veya REQUIRE_ACTION verir (MD-8).

**Genel kural (E25):** Bir fact için pozitif veya negatif **truth** yalnız o fact'in owner'ından gelir. Her tüketici, başkasının fact'i hakkında UNKNOWN raporlayabilir ve bunu dürüstçe göstermek zorundadır (ör. Work'ün execution/stop için *unknown* göstermesi, Work S8, Work §15.2; PEP'in "authority durumu bilinmiyor" demesi). Hiçbir sistem UNKNOWN'u başarıya veya durmaya çeviremez. Access'in kendi kararı hiçbir zaman UNKNOWN değildir: belirsizlik DENY veya REQUIRE_ACTION üretir (INV-26). Her sistem yalnız kendi fact'i için reconciliation sahibidir ve kullanıcıya gösterilen "gerçek" o fact'in sahibinden gelir.

#### 7.9.15 Data-Minimization Rules

##### 7.9.15.1 Canonical kural

> **Authority-relevance minimization (E26).** Access bir karar için yalnız (1) opaque referansları, (2) action schema'sında authority-relevant olarak sınıflandırılmış typed intent parametrelerini, (3) requirement, selection veya predicate için gereken Claim'leri (değer, mümkünse digest + seçici açıklama) alır. Domain body'leri, Work içeriği, One memory, sohbet, gerekçe metni, sağlık/hukuk/özel veri Access'e gönderilmez ve Access onları istemez. Access cevabında yalnız Decision, unmet requirement'lar ve requester'ın görmeye yetkili olduğu kadar açıklama döner.

##### 7.9.15.2 Sınır bazında

| Seam | Access'e geçer | Geçmez |
|---|---|---|
| Domain → Access | Typed predicate Claim, opaque ResourceRef (+ incarnation), authority-relevant parametreler; authority-opaque parametrelerin digest'i | Sipariş gövdesi, müşteri profili, ürün içeriği |
| Work → Access | WorkRef / CommitmentRef / GateRef / StepRef (opaque), Gate digest'i, `commitment.active` | Work içeriği, Aim/Condition yapısı, Claim gövdeleri, attention state |
| One → Access | IntentEnvelope (minimal), purpose ref | Memory, konuşma, çıkarım, gerekçe |
| Identity plane / IdP → Access | Gerekli identity/authentication Claim'leri (değer veya digest) | Tam kişisel profil |
| Identity plane ↔ RP | RP'ye: istenen protokol scope'larına karşılık gelen claim'ler (pairwise `sub` varsayılan, MD-10) ve Grant projection'ları | Tam profil, iç PartyID, diğer RP'lerdeki `sub` değerleri |
| Executor → Access | Effect attestation (attest edilen parametreler veya digest'leri) | Execution trace, tool output |
| Access → herkes | Decision + reason codes; "why/who can" açıklamaları requester'ın authority'si kadar | Başka Party'lerin authority graph'ı; cited Claim gövdeleri |

**Access cross-product data lake değildir.** Claim corpus, karar için gereken iddiaların ingest kaydıdır; redaction kuralı (C34) ve "yalnız canlı derivation'a gereken body tutulur" ilkesi Claim'lere de uygulanır.

##### 7.9.15.3 Cross-system referanslar

| Ref | Owner | Sınırı güvenle geçer mi | Kim kopyalayamaz |
|---|---|---|---|
| **PartyRef** | Identity regime | Evet (herkesin ortak referansı) | Hiçbir ürün kendi Party registry'sini canonical sayamaz |
| **ResourceRef** (+ incarnation) | Domain | Evet | Access resource truth'unu kopyalamaz |
| **WorkRef / CommitmentRef / GateRef / StepRef** | Work | Evet, opaque | Access Work state'ini tutmaz |
| **ActionRef** (namespace + name + version + digest) | Publisher | Evet | — |
| **ExerciseID** | Access (domain-scoped; DomainID ile) | Evet | Work Exercise'ı referans alır, Grant state'ini kopyalamaz |
| **GrantID** | Access | Evet (görüntüleme, provenance) | Hiçbir dış sistem Grant içeriğini canonical kopya olarak tutamaz |
| **ClaimID** | Issuer (içerik); Access (ingest) | Evet | — |
| **AuthorityDomainID** | Access protocol (genesis) | Evet | Provider değişse de aynı |
| **EffectRef** | Effect'i gerçekleştiren domain/Executor | Evet | Access effect'i sahiplenmez |
| **InstanceID / MandateID** | Access | Evet (Executor, Work görüntüleme) | — |
| **HoldingRef** | Access (value) | Evet (projection'larda) | — |

**Lokal kalan nesneler:** Grant/Mandate/Acceptance içeriği (Access), Commitment/Gate/Declaration içeriği (Work), memory (One), execution state (Executor), ledger/balance (Money), order body (Commerce). **Cross-product reference ≠ ownership** (E27): bir ID'yi tutmak o nesneyi sahiplenmek değildir.

#### 7.9.16 First-Party Neutrality Test

| Test | Sonuç | Koşul / kanıt |
|---|---|---|
| **Third-party Work-like coordinator Access'i kullanabilir mi?** | **Evet** | Coordinator bir Party; eligible set, contribution, ExerciseID referansı aynı sözleşme (§7.9.5.8). Suiss Work'e özel requirement tipi veya Acceptance yolu yok |
| **Third-party executor Access'i kullanabilir mi?** | **Evet** | Executor Contract (Work §20.4) ve Access karar/continuation sözleşmesi aynı; first-party Executor Runtime ayrıcalıksız |
| **Third-party IdP Access'i besleyebilir mi?** | **Evet** | Use-typed Acceptance; Suiss Identity plane da aynı Acceptance ile girer (§7.9.1.3) |
| **Access identity plane third-party bir authority provider'la (veya third-party IdP Access authority plane'iyle) kullanılabilir mi?** | **Evet** | İki plane birbirinden bağımsız kullanılabilir: identity plane'in Claim'leri herhangi bir conformant authority provider'a Acceptance ile girer; authority plane herhangi bir IdP'yi kabul eder (E24, B7 → §18). Identity plane yapılandırmasının yetkilendirilmesi (E34) hangi provider'da host edilirse edilsin aynı ADP sözleşmesiyle yapılır |
| **Third-party authority provider birlikte çalışabilir mi?** | **Evet** | Açık Access protocol; DomainID provider'dan bağımsız; bridging Grant / foreign-authority Acceptance; kooperatif handover (§7.9.11.2). Zorunlu migration'da (provider erişilemez) tek authoritative lineage semantik olarak root'un recovery Exercise'ıyla belirlenir; kayıp suffix ve eski provider equivocation'ı first-party ve third-party provider için aynı şekilde beyan edilmiş risk veya declared capability'dir |
| **Third-party Pay/domain PEP Access kararlarını uygulayabilir mi?** | **Evet** | Generic Domain Product contract (§7.9.10.3); schema-definition Acceptance first-party ile aynı |

**Neutrality kuralı (E24):** First-party integration daha iyi deneyim (düşük gecikme, ortak UX, hazır Acceptance önerileri) sunabilir; ama **semantic privilege yasaktır**. Bir first-party ürünün farklı muamele görmesi ancak aynı public modelde ifade edilmiş gerçek bir trust/assurance farkıyla olabilir (ör. bir domain'in Suiss Identity plane'e daha yüksek assurance floor'lu Acceptance vermesi bir meta-Exercise'tır ve herhangi bir issuer'a da verilebilir). Hidden authority path, implicit Acceptance, kapalı action namespace ayrıcalığı yoktur (INV-29, Work §3.3, framework §4.2).
