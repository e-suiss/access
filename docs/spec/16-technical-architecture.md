## 16. Technical Architecture

**Bu bölümün kuralları.**
- **Bileşen kimlikleri (MD-19.5).** Bileşenler **CMP-*n*** adını taşır. "C*n*" biçimi yalnız ontology kararlarını (C1–C34) gösterir; C15 de dahil (C15 = delegability kararı, §5). Bileşen notları §16.3.3'tedir.
- Bu bölüm ve §17 normatif kararları **OP-*n*** ailesiyle numaralar (OP-1–OP-71). Register özeti §17.14'tedir. Bölüm içi yerel etiketler: §17.1 at-most-once senaryoları **OP-S1…OP-S12** (§8.5 yüzeyleri S1–S11 ile karışmasın diye), OP-60 binding re-anchor adımları **RB-0…RB-6** (RA-n etiketi yalnız §15.18 CR-45'tedir). Bileşen anlamında çıplak C*n* kullanılmaz, CMP-*n* kullanılır.
- Garanti sınıfları §3.3'teki gibidir. Kısaltmalar: BS = GUARANTEED BY SEMANTICS, UDC = GUARANTEED UNDER DECLARED CAPABILITY/POLICY, NG = NOT GUARANTEED. Fail-closed her yerde geçerlidir (MD-8).
- Sayı ve ölçümler epistemik etiketleriyle verilir. Ölçümlerin mutlak değerleri tek ortama aittir: Apple M4, Rust 1.98.1, PostgreSQL 18.6, Docker. Taşınabilir olan oranlardır. ENGINEERING ASSUMPTION (EA) değerleri ölçülmüş sayı gibi yazılmaz.

### 16.1 Verdict

**Verdict: ARCHITECTURE PRESERVES MODEL WITH DECLARED ASSUMPTIONS.** Frozen semantik, protocol ve güvenlik gereksinimleri bilinen, açık ve provider-neutral teknolojilerle inşa edilebilir; model değişikliği gerektiren bir fiziksel impossibility yoktur. Mimari modelin en zor üç iddiasını şu yapılarla taşır:

| # | Zor iddia | Mimari cevap | Neden yeter |
|---|---|---|---|
| A1 | **At-most-once consumption + ALLOW atomikliği** (INV-21) concurrency, retry ve failover altında | Domain başına **tek sequencer** (leader) + **optimistic read-set validation** + **tek DB transaction**'da `records ∪ sync-derived state ∪ outbox ∪ head CAS(position, epoch)` (T6, T7) | Total order DB'deki tek satırlık head CAS'tan gelir, process'in kendini leader sanmasından değil; iki leader aynı anda var olsa bile ikinci append fiziksel olarak reddedilir (TI-2). Bu tek linearizable depo içindedir; cell/bölge değişimi HANDOFF/ACCEPTANCE mührü veya kanıtlanmış fence ile yapılır, aksi domain durur (FA-13) |
| A2 | **Stale state ALLOW üretemez** (INV-26) | Commit-mode kararlar yalnız domain leader'ında, `q−1` pozisyonundaki state'e karşı değerlendirilir; replica/index/cache yalnız advisory, search ve explain'e hizmet eder (T10, T11, TI-3, TI-5) | Eventual consistency yalnız *söz olmayan* cevaplarda (C30) ve önceden issue edilmiş ValidityContract pencerelerinde (SI-7) bulunur |
| A3 | **Provider'a karşı doğrulanabilirlik ve çıkış** (E20, PI-6, PI-15, SEC21–SEC25) | Merkle-commitment'lı domain log'u + bağımsız witness co-sign'ı + exact-content inclusion proof (artefakt digest'i DecisionRecord'da) + domain-controlled replica + record-fold ve open reference evaluator ile doğrulama (T16–T22, T12) | Conformant bir üçüncü taraf, Suiss'e hiçbir şey sormadan kayıtları doğrular, state'i record-fold ile kurar, kararları yeniden değerlendirir ve lineage'ı devralır; yeniden değerlendirme farkı çıkışı durdurmaz (G32) |

Commit-mode kararlar yalnız domain leader'ında `q−1` pozisyonundaki state'e karşı verilir; hiçbir derived store, cache, index veya replica canonical olamaz (TI-1, TI-5, TI-16); eventual consistency beyan edilmiş ValidityContract pencereleri dışında ALLOW üretemez (TI-3, TI-5); at-most-once consumption concurrency, retry ve failover altında korunur (TI-2, TI-7, TI-8); conformant üçüncü taraf provider aynı protocol'ü Suiss'e özgü bağımlılık olmadan uygular (TI-17). Normatif tanım L0/L2 + vektörlerdir; Access Core bir implementasyondur (§9). Bu bölüm lisans türü belirtmez; lisans kararları D4'tedir (§18.9).

**Tek cümlelik sonuç:**

> **Access teknik olarak şudur: her AuthorityDomain için bir tane fenced, append-only, Merkle-commitment'lı log; o log'a tek transaction'da yazan tek bir sequencer; log'dan deterministik türeyen ve hiçbir zaman ona baskın gelmeyen her şey; ve bunların hepsini Suiss'siz doğrulayıp devralmaya yeten açık bir spesifikasyon, onun open-source implementasyonu (Access Core), witness ve replica.**

#### 16.1.1 Identity plane verdict'i

Yukarıdaki verdict ve A1–A3 authority plane içindir. Access tam bir IdP'dir (identity plane, MD-13). Identity plane'in teknik verdict'i şudur:

> **Identity plane, realm başına (MD-5) PostgreSQL primary'sini tek yazar kabul eden, durumsuz süreçlerden oluşan bir IdP'dir. Uçucu durumunu (kimlik doğrulama oturumu, authorization code, refresh ailesi, kaba kuvvet sayacı) senkron replike edilmiş veritabanında tutar. Authority plane'e yalnız Claim Ingest ile bağlanır (T31, INV-12). Yapılandırma değişikliklerini kendi AuthorityDomain'inde ADP `commit` ile yetkilendirir (MD-14).**

Gerekçe: sektör 2026'da ayrı dağıtık durum katmanlarından (Infinispan, Redis) senkron replike veritabanına yakınsamıştır. Kimlik iş yükünde bölgeler arası senkron yazma çalışmaz; çok bölgelilik hücre izolasyonuyla çözülür. Bu, authority plane'in cell modeli (T28) ile aynı sonuçtur.

Identity plane'in mimariyi belirleyen gün-1 kararları bu spec'te şu yerlerde normatiftir:

| Konu | Spec'teki yeri |
|---|---|
| `tenant_id`/kapsam her PK'de, composite FK, RLS FORCE, realm-yerel benzersizlik | MD-5; §17 OP-12; §12 |
| Realm başına imza anahtarı, anahtarlar DB dışında ve bağımsız yedekli | MD-3, MD-6; CMP-22; §17 OP-58; §15 |
| `client_id` global benzersiz ve üretilen | §10 |
| Slug, issuer, `placement_id` | §12; CMP-26 |
| Denetim log'u kiracı ve zaman bölümlü | §17 OP-13 |
| Saf çekirdek, I/O yok, CI'da zorlanır | §16.4 OP-3 |
| Tipli kimlik doğrulama durum makinesi | §10; §16.4 (crate topolojisi) |
| Kullanıcı başına DEK | §15; §17 OP-42 |
| Üç epoch | MD-7; §17 OP-21 |
| Kiracıya sunucu tarafında kod çalıştırma yok | §2; §12 |
| Yetki filtresi veri erişim katmanında, tipte | §17 OP-12; §12 |
| Denetim olayı iş değişikliğiyle atomik minimal outbox satırı | §17 OP-10 |
| Şema göçü ayrı job | §17 OP-55 |
| PostgreSQL 18 asgari | §16.4 OP-7 |

### 16.2 Fiziksel ve failure varsayımları (FA-1–FA-14)

Verdict bu varsayımlara koşulludur. FA-13 cross-cell / cross-region fence'tir; FA-14 depolama bozulması tespitidir (ikisi ayrı varsayımdır).

| # | Varsayım | Neye dayanır | İhlalde sonuç |
|---|---|---|---|
| FA-1 | Canonical DB tek primary; ack edilmiş commit **aynı depo içinde** kaybolmaz | Sync quorum replication (aynı cluster veya cross-region sync WAL quorum), HA yöneticisinin fencing'i, dürüst fsync; **farklı AZ'lerde ≥ 2 sync standby, `synchronous_standby_names = ANY 1 (…)`; tek standby ile sync commit yasak**. Identity plane canonical cluster'ı için de geçerlidir | Ack edilmiş kayıt kaybı; witness'ta yalnız kök kalır, revocation/CT3 kayıtları önek olarak replica'dadır (SEC23); devam yalnız FA-13 kuralıyla, aksi `domain.recover`; small-provider (single-node) profilinde FA-1 karşılanmaz, beyanlıdır (OP-48, HL-40) |
| FA-2 | Head CAS satır seviyesinde linearizable (tek depo içinde) | PostgreSQL MVCC + satır kilidi | Çift append (TLA+ modelinin — **planlı** — varsayımı) |
| FA-3 | Provider trusted time'ı ≥ 2 bağımsız zaman kaynağıyla, sınırlı ilerleme ve witness cosign zamanı çapraz kontrolüyle beyan edilen belirsizlik içindedir (hedef ≤ 250 ms; ENGINEERING ASSUMPTION) | İki bağımsız kaynak, monotonic sınırlı ilerleme, witness çapraz kontrolü (TI-RT2) | Kaynak uyuşmazlığında commit durur; ihlalde sapma kadar kayma (UDC, TI-RT2, U29); bütün kaynaklar ve witness'lar topluca yalan söylerse HL-6 (NG, N-28); backdating yok (TI-19) |
| FA-4 | SHA-256, Ed25519, ES256 (ve opt-in profillerde RS256, ML-DSA-65) güvenli | Kriptografik varsayım | Algoritma geçişi (SI-18) |
| FA-5 | Kayıtlar ve imzalar uzun süre doğrulanabilir; algoritma kırılırsa witness zaman sabitlemesi "existed by T" verir — **yalnız kırılmadan önce PQ algoritmayla imzalanmış ve en az bir bağımsız witness'ın PQ cosign'ını almış bir re-anchor checkpoint'inin kapsadığı kayıtlar için ve verifier o PQ anahtarlarına kırılmadan önce güvenmişse** (§15.18) (tek kanonik metin burasıdır; §15.18 buna atıf verir) | Witness cosign (PQ) | U21; aksi NG (RR-35) |
| FA-6 | HSM anahtarları (binding key, KEK ve FIPS profilindeki operasyonel anahtar) extract edilemez; binding key'in aktivasyonu ve politikası quorum'lu (imza başına değil) | HSM sertifikasyonu, operasyon | SEC21 yolu |
| FA-7 | Leader liveness süreleri yalnız liveness içindir; doğruluk head CAS'tan gelir | Tasarım (TI-2) | Saat hatası yalnız gecikme üretir |
| FA-8 | TEE ölçümü ve attestation'ı dürüsttür | TEE üreticisi | User-gated custody NG'ye düşer (DL-1) |
| FA-9 | ≥ 1 witness provider/operatörden bağımsız | Organizasyonel | Equivocation tespiti yok (N-13) |
| FA-10 | Forced recovery için N'ye kadar kayıtlar (önek) provider dışında erişilebilir | Replica beyanı + SEC23 replica-before-ack + mirror-before-witness (TI-13) | Kayıpsız recovery yapılamaz: SEC22 kol (ii) → REQUIRE_ACTION + N = R\* + beyanlı kayıp suffix (NG, N-14); domain kilitlenmez (U24) |
| FA-11 | Offline verifier donanımı (SE/TPM) beyan ettiği sayaç/saat yeteneğine sahiptir | Attestation | Pencere/slice aşımı (U2–U4 → NG) |
| FA-12 | Ağ teslimatı garanti değil; hiçbir güvenlik özelliği teslimata dayanmaz | Tasarım (INV-24) | Yalnız gecikme |
| FA-13 | Cross-cell / cross-region promotion yalnız eski canonical depo kanıtlanmış biçimde fenced iken ve son commit'li head'i devam log'unda tam kapsanırken yapılır | HANDOFF/ACCEPTANCE mührü veya kapsam dışı STONITH + eski head'in okunabilirliği; otomasyonun varsayılanı promote etmemek | Çift yazar / pozisyon yeniden kullanımı → INV-21, EI-20, U10 ihlali; bu yüzden şüphede domain fail-closed durur ve yol `domain.recover`'dır |
| FA-14 | Depolama sessiz bozulması tespit edilir (page checksum, ECC, okumada leaf/body commitment doğrulaması) | Depolama katmanı + commitment doğrulaması (TI-RT11) | Tespitte commit durur, hakem Genesis'ten fold'dur; kayıt kimliği commitment olduğu için commitment-eşleşen kopyadan geri yükleme düzeltme değil, aynı kaydın geri yüklenmesidir. Tespit sonrası bozuk satıra dayalı karar yok (UDC, U30); tespit öncesi yanlış karar NG (N-29) |

### 16.3 Bileşenler

Bileşen kimlikleri **CMP-*n*** biçimindedir (notlar §16.3.3). Gövdede tek başına "C*n*" yalnız ontology kararlarını (C1–C34) gösterir. Etiketler: CANONICAL (log kayıtları), SYNC-DERIVED (aynı transaction'da log'dan türeyen, karar girdisi), DERIVED (asenkron, advisory), PROJECTION, OPERATIONAL.

| # | Bileşen | Sorumluluk | Etiket | Protocol parçası | Not / asla |
|---|---|---|---|---|---|
| CMP-1 | **Protocol Gateway** | AuthZEN ADP, OAuth AS (token, PAR, introspection), SSF endpoint'leri, ingest endpoint'leri, explain/search, export, `.well-known` | OPERATIONAL | AP-1…AP-15 | Karar vermez; transport kimliğini actor'e çevirmez (PI-7) |
| CMP-2 | **Request Verifier** | Boyut/derinlik limitleri (SI-20), AIS imza doğrulaması exact byte üzerinde, domain/nonce/digest/audience/mode eşleşmesi, pin'li SPP ile IntentEnvelope tiplemesi, canonical CBOR, intent digest | OPERATIONAL (pure) | AP-1, AP-3 | Caller'ın verdiği digest'e güvenmez |
| CMP-3 | **Domain Sequencer** | Domain başına tek leader; nonce kontrolü, evaluation orkestrasyonu, read-set validation, batch append, head CAS, ack gating | Yazdığı şey CANONICAL; kendi in-memory durumu SYNC-DERIVED kopyası | AP-1, AP-3, AP-4, AP-5 | Tek yazma yolu (INV-2); leader olmak authority değildir (INV-29) |
| CMP-4 | **Access Core** | Algebra Engine, Requirement Resolver, Restriction Engine (Cedar forbid-only alt kümesi; spike başarısızsa CEL profili, OQ-MD2), Decision Combinator, Explain builder, Federation verifier, record-fold | Pure function | L0 semantiğinin open-source implementasyonu (normatif değil; normatif = L0/L2 + vektörler); saf parçaları CMP-24 Access Kernel crate'indedir | State'e yalnız versioned StateView üzerinden erişir (TI-4) |
| CMP-5 | **Canonical Store** | Domain log, body store, sync-derived tablolar, outbox tablosu, head (position, epoch) satırları | CANONICAL + SYNC-DERIVED + OPERATIONAL (ayrı tablolar) | AP-13 | Sequencer dışı DB rolü yalnız okuma |
| CMP-6 | **Checkpointer & Witness Client** | Checkpoint üretimi (cadence/heartbeat + out-of-cycle), witness gönderimi, cosign toplama, gossip karşılaştırması | `checkpoint` Claim'leri (CANONICAL olarak log'a ingest edilir); karşılaştırma DERIVED | AP-13, P32 | Mirror-before-witness (TI-13); recovery'de değerlendirici-tarafı witness sorgusu (§16.6) |
| CMP-7 | **Projection Issuer / Signer** | İmza işlemi ayrı signer sürecindedir (CMP-22a); `projection.issue` / ALLOW DecisionRecord'undan artefakt payload'ı, digest'i commit öncesi, imza commit sonrası; Token Status List yayını (`iat`/`as_of` = yansıtılan pozisyonun `recorded_at`'i; heartbeat checkpoint'iyle sessiz domain'de de tazelenir) | PROJECTION | AP-5 | Kayıtta digest'i olmayan Decision artefaktı imzalanmaz (TI-12); eski status içeriği taze `iat` ile imzalanmaz |
| CMP-8 | **Claim Ingest Pipeline** | Carrier adapter'ları, issuer authentication, normalize, minimize, dedup, quota, Claim record append (sequencer üzerinden) | Yazdığı CANONICAL (Claim record); kuyruk OPERATIONAL | AP-7, AP-8, AP-10 | Authority-state satırına dokunmaz (PI-22) |
| CMP-9 | **Derivation Workers + Derived Store** | Graph index (Zanzibar-benzeri), search, eligible set, revocation impact, compromise impact sorgusu (SEC15), status list girdisi (projection geçerlilik bit'leri, `applied_pos` ile), offline reconciliation görünümü | DERIVED | AP-2, AP-11 | Commit-mode girdisi değildir (TI-5); SEC14 contract durumu ve ingest disposition burada değil, SYNC-DERIVED / canonical'dadır |
| CMP-10 | **Outbox Relay + SSF Transmitter** | Outbox → NATS → SET imzalama → push/poll; event id domain başına HMAC | PROJECTION (event) | AP-11, P33 | Event ≠ commit (E30) |
| CMP-11 | **Query Service** | `check`, search, eligible set, explain, viewer-scoped okuma cevapları; `basis_ref` (audit altı opaque token) / `at_least`; `witnessed_through` | DERIVED | AP-2 | Advisory cevap credential değildir (C30) |
| CMP-12 | **Export & Replay** | Record Export Package (AP-14), streaming export, record-fold doğrulaması, örneklemeli yeniden değerlendirme agent'ı | PROJECTION | AP-13, AP-14 | Export bir Exercise'tır (PI-4) |
| CMP-13 | **Key Management** | Binding key, operasyonel anahtarlar, rotasyon, sertifika excerpt'leri; PKCS#11/KMIP soyutlaması | OPERATIONAL (anahtar materyali) | AP-15 | Anahtar evaluator değildir |
| CMP-14 | **Domain Metadata Publisher** | Genesis/`domain.*`/Acceptance kayıtlarından Domain Metadata; `.well-known`, OIDF entity statement | PROJECTION | AP-15, P3 | Kökü Genesis'teki provider binding'dir |
| CMP-15 | **Identity plane** (şemsiye; alt bileşenler CMP-15.1–15.10, §16.3.1) | WebAuthn RP, authenticator registry, `authentication`/`authenticator-binding`/`identity-binding.*` issuance, custody signer, regime key-event store, PII vault | Kendi kayıtları CANONICAL (ikinci source of truth; E3) | AP-7, AP-8 (issuer rolü) | Authority plane'e yalnız Claim (INV-12, TI-15) |
| CMP-16 | **Experience backend** (açık kaynak, D4) | Authority hub aggregator, S1–S10 render verisi, decision lab | PROJECTION / DERIVED | — | Authority tutmaz/yazmaz (XI-3) |
| CMP-17 | **SDK'lar ve open reference** | Dil başına tek paket (`auth` + `authorize`, T41), ayrı doğrulama paketi (Offline Verifier Core), Reference Verifier, Replay CLI, conformance runner | Kütüphane | L3 Conformance | PEP SDK'da fail-open yok (X21) |
| CMP-21 | **Replica Mirror** | Kayıtları domain'in beyan ettiği replica'ya (domain-controlled object storage veya archival witness) sürekli kopyalar | PROJECTION | AP-13 | Witness gönderiminden önce (TI-13) |

#### 16.3.1 Alt bileşenler ve ek bileşenler

Identity plane tam bir IdP olduğu için (MD-13) CMP-15 alt bileşenlere açılır. Ayrıca MD-1 (Kernel crate'i ve süreç hibriti) ve MD-6 (signer süreci) ek bileşen satırları getirir. CMP-18–CMP-20 numaraları kullanılmaz.

| # | Bileşen | Sorumluluk | Etiket | Plane / süreç | Not / asla |
|---|---|---|---|---|---|
| CMP-15.1 | **OIDC OP / OAuth AS (identity)** | Authorization code + PKCE, refresh rotasyonu ve reuse tespiti, client_credentials, device grant, token exchange, PAR, JAR/JARM, DPoP, introspection, revocation, discovery/JWKS, DCR, pairwise `sub`, logout | Kendi kayıtları CANONICAL (identity store) | Identity core süreci | Authority taşıyan token'da tazeliği kanıtlanamayan durum `active=false` (MD-8). Upstream token'ın ajana verilmesi bir Access kararıdır (MD-13). Release kararı bir Exercise'tır; upstream token'ın kendisi projection değildir ve içeriği NOT GUARANTEED'dır; broker'ın verme kararı UDC'dir; CT2+ için broker varsayılan olarak PEP'tir; token `exp` ≤ ValidityContract horizon. Ayrıntı §10 |
| CMP-15.2 | **Oturum ve token durumu** | Login oturumu, uçucu auth durumu (DB'de), `session_epoch` (Instance/Party başına), node-yerel epoch cache, outbox tüketicisi | CANONICAL (oturum satırları) + OPERATIONAL (node cache) | Identity core süreci | Cache-miss primary'ye sorar, DB yoksa DENY (MD-7, OP-21). Ayrıntı §12 |
| CMP-15.3 | **Hesap yaşam döngüsü ve kurtarma** | Kayıt, bağlama, kurtarma, silme, B2B organizasyon (Party + Anchor, MD-5) | CANONICAL | Identity core süreci | Admin credential yazamaz, yalnız reset intent üretir. Ayrıntı §12 |
| CMP-15.4 | **SCIM** | SCIM sunucu ve istemci; SCIM kaynaklı Claim'ler | CANONICAL (identity) / Claim (authority'ye CMP-8 üzerinden) | Identity core süreci | Sıra yalnız issuer-sırası kaynaklarından (RT15). Ayrıntı §10 |
| CMP-15.5 | **Yönetim API'si** | Platform-admin ve realm-admin yüzeyleri ayrı (audience, scope, rate bütçesi) | OPERATIONAL (yüzey) | Identity core süreci | Authority değiştiren her çağrı ADP meta-Exercise'ına derlenir. Ayrı "admin token" sınıfı yoktur (MD-14; T35'in "kolaylık API'leri ADP'ye derlenir" cümlesi). Ayrıntı §12 |
| CMP-15.6 | **Login / hosted UI / tema / konsol BFF** | Hosted login, script çalıştırmayan şablon kabuğu, realm teması, konsol için çerez tabanlı BFF | PROJECTION / OPERATIONAL | Identity core süreci | Çerez tek başına authority değişikliğini yetkilendiremez (MD-14). Çerez yalnız gezinmeyi ve identity plane'in kendi ekranlarını taşır; authority grafiği ve audit okuması AIS (CT0) veya holder-bound okuma projection'ı ister. Ayrıntı §8, §12 |
| CMP-15.7 | **WebAuthn RP + authenticator registry** | WebAuthn RP ve authenticator registry görevi | CANONICAL (identity) | Identity core süreci | `authenticator-binding` Claim'leri yalnız public materyal digest'i |
| CMP-15.8 | **Claim issuer + custody signer + regime key-event store** | `authentication`/`authenticator-binding`/`identity-binding.*` issuance; attested TEE custody signer (T32); controller-custodian key-event history | CANONICAL (identity) | Identity core süreci + TEE | Authority plane'e yalnız Claim (INV-12, TI-15) |
| CMP-15.9 | **PII vault** | Kullanıcı/Party başına DEK ile alan şifreleme; silme = crypto-shredding | CANONICAL (identity) | Identity store | Authority log'da yalnız PartyRef (pseudonymous) |
| CMP-15.10 | **Identity federation (OpenID Federation, upstream IdP)** | OIDF entity statement'ları, trust chain, upstream IdP bağlantıları | PROJECTION / DERIVED cache | Identity core süreci | Trust bootstrap rolü (authority) CMP-14'tedir; L26 issuer rol engeli korunur. Ayrıntı §10 |
| CMP-22 | **Signer süreçleri** | (a) Authority signer: domain kapsamlı operasyonel anahtar (MD-6) ile receipt/PAP/token/checkpoint/SET/status list imzası. (b) Identity signer: realm başına JOSE anahtar seti (1 aktif + N pasif). Ağ syscall'ı yok (seccomp), Landlock ile yalnız key store okunur, `memfd_secret`; istek Unix domain socket + `SCM_CREDENTIALS` ile kimliklenir | OPERATIONAL (anahtar materyali) | Ayrı süreçler; (a) ve (b) anahtar deposu veya operatör rolü paylaşmaz (T31) | Anahtar evaluator değildir. FIPS profilinde operasyonel anahtar HSM'dedir. Signer kayıtta digest'i olmayan Decision artefaktını imzalamaz (TI-12; CMP-7 kuralı signer sınırında da denetlenir). Kaynak: MD-6 |
| CMP-23 | **Kenar protokol gateway'leri** | CMP-23.1 SAML IdP; CMP-23.2 LDAP (salt okunur); CMP-23.3 Kerberos/SPNEGO; CMP-23.4 RADIUS; CMP-23.5 WS-Fed | OPERATIONAL (gateway) | Her biri ayrı süreç; identity core'u iç API'den tüketir | XML/ASN.1 ayrıştırma ayrı, yok edilebilir worker'da (MD-18 SAML satırı). Kerberos C FFI yalnız izole süreçte (MD-1, MD-2). Ayrıntı §10 |
| CMP-24 | **Access Kernel** (`no_std` crate) | Deterministik CBOR ve digest, ⊑/∩/normalize, ValidityContract aritmetiği (checked), COSE doğrulama, JWS/SD-JWT doğrulama (yalnız doğrulama; T24 receipt ve PAP profilleri), inclusion/consistency proof doğrulama, 7 adımlı verifier kuralı (§9), identity plane'in saf parçaları (epoch/expiry karşılaştırması, delegasyon zinciri değişmezleri), restriction motoru (Cedar forbid-only alt kümesi, MD-4) | Kütüphane (pure) | Sunucu, offline verifier, edge/Wasm, mobil FFI'da aynı kod | I/O yok, CI'da zorlanır (OP-3). Kani hedefleri buradadır (MD-15). İmza üretimi ve identity plane'e özgü JOSE (JWE, JAR/JARM) `access-crypto`'dadır; doğrulama yolu Kernel'dedir. Ayrıntı §16.4 OP-1 |
| CMP-25 | **Operatör break-glass yolu** | Cell operatörünün altyapı erişimi için ayrı kod yolu; çevrimdışı doğrulanabilir M-of-N FIDO2 kimliği | OPERATIONAL | Her cell'de ayrı; DB'ye bağımlı değil | Authority kararı üretemez, authority state'e yazamaz (SI-22). Ayrıntı §17 OP-46 |
| CMP-26 | **Placement Directory** | DomainID → cell, realm (issuer/slug) → cell, tenant → cell eşlemesi | OPERATIONAL | Global, küçük, replike | Yanlışsa leader reddeder. Hiçbir karar girdisi değildir. Hücrelerin çalışması için gerekli değildir, yalnız yönlendirme için kullanılır |
| CMP-27 | **Identity Audit & Signal pipeline** | Minimal audit outbox (iş değişikliğiyle aynı tx), Merkle checkpointer, OCSF/SET/CAEP/CEF adaptörleri, iki yayın kanalı (CAEP akışı, tam denetim akışı) | CANONICAL (outbox kaydı) / PROJECTION (export) | Identity core süreci + arka plan görevleri | İmza ekleme yolunda beklenmez. Ayrıntı §17 OP-37–OP-44 |

#### 16.3.2 Süreç ve güven sınırları

```text
── Authority cell (canonical cluster + derived cluster) ─────────────────────────────
   CMP-1 Gateway ─ CMP-2 Request Verifier ─ CMP-3 Sequencer (+CMP-4 Core → CMP-24 Kernel)
   CMP-5 Canonical Store · CMP-6 Checkpointer · CMP-21 Replica Mirror · CMP-8 Ingest
   CMP-9/11 Derived + Query · CMP-10 Outbox Relay/SSF · CMP-12 Export · CMP-14 Metadata
   CMP-7 Projection Issuer ──(UDS)──► CMP-22a Authority Signer ──► CMP-13 HSM/KMS
──────────────── ayrı güven sınırı (SEC19, TI-15; yalnız Claim Ingest API) ──────────
── Identity cell/cluster (ayrı KMS, ayrı operatör rolleri, T31) ────────────────────
   Identity core süreci: CMP-15.1–15.10, CMP-27 (aynı Kernel crate'i, CMP-24)
   CMP-15.x ──(UDS)──► CMP-22b Identity Signer (realm JOSE anahtarları)
   CMP-23.1–23.5 kenar gateway süreçleri ──(iç API)──► identity core
        └─ XML/ASN.1 parser worker'ları (yok edilebilir, RLIMIT + timeout)
── Global ─────────────────────────────────────────────────────────────────────────
   CMP-26 Placement Directory (OPERATIONAL) · CMP-25 her cell'de ayrı break-glass yolu
── Kütüphane / dağıtım ───────────────────────────────────────────────────────────
   CMP-17 SDK'lar (her dilde tek paket: auth + authorize; Kernel bağlamaları; T41) · CMP-16 Experience backend
```

Kural: dil hibriti yoktur, süreç hibriti vardır (MD-1). Süreçler arası sınır güven sınırıdır. Her sınır ya standart bir protokol bağlaması (ADP, OAuth, SSF, Claim Ingest) ya da kimliği doğrulanmış yerel IPC'dir (signer için UDS + `SCM_CREDENTIALS`).

#### 16.3.3 Bileşen notları [MD-19.5]

| Bileşen | Not |
|---|---|
| CMP-1 Protocol Gateway | Identity plane OAuth AS uç noktaları CMP-15.1'dedir; CMP-1'in OAuth AS uç noktaları authority projection token'ları içindir |
| CMP-4 Access Core | Restriction Engine dili Cedar forbid-only alt kümesidir (MD-4); saf parçaları CMP-24 Kernel'dedir [MD-1] |
| CMP-5 Canonical Store | RLS kuralları §17 OP-12 |
| CMP-6 Checkpointer & Witness Client | Coalescing §17 OP-38 |
| CMP-7 Projection Issuer / Signer | İmza işlemi CMP-22a signer sürecinde [MD-6] |
| CMP-9 Derivation Workers + Derived Store | ReBAC graf indeksi burada (MD-4) |
| CMP-11 Query Service | ReBAC sorgu motoru burada (MD-4) |
| CMP-13 Key Management | Anahtar hiyerarşisi MD-6'ya göredir |
| CMP-15 Identity plane | CMP-15.1–CMP-15.10 alt bileşenlerine açılır. Bileşen adı ontology kararı **C15 (delegability)** ile karışmaz |
| CMP-17 SDK'lar ve open reference | Offline Verifier Core = Kernel (CMP-24) + platform adaptörleri [MD-1] |
| CMP-22 Signer süreçleri | [MD-6] |
| CMP-24 Access Kernel | [MD-1] |

### 16.4 Runtime, dil ve teknoloji yığını

Dil kararı MD-1'dir. Aşağıdaki metin MD-1'in bağlayıcı içeriğini ve uygulama kurallarını verir. T35, T12, T25 ve T38'in metinleri §16.10'dadır.

#### 16.4.0 Karar (MD-1): tek backend dili Rust

**Statü: FROZEN (MERKEZİ KARAR).**

- Access'in sunucu tarafı tek dilde, Rust ile yazılır. Bu, authority plane'i (sequencer, Core, ADP, ingest, witness istemcisi) ve identity plane'i (OAuth/OIDC AS, oturum, hesap, SCIM, admin API) kapsar.
- Kripto kütüphanesi aws-lc-rs'tir.
- Deterministik CBOR, ⊑/∩/normalize, ValidityContract aritmetiği, COSE ve proof doğrulama tek bir `no_std` crate'te yaşar: **Access Kernel (CMP-24)**. Bu crate sunucuda, offline verifier'da, edge/Wasm'da ve mobil FFI'da aynıdır.
- İstemci SDK'ları ve konsol TypeScript ile yazılır. Kernel'e Wasm ile bağlanırlar.
- Kenar protokol gateway'leri (SAML, LDAP, Kerberos/SPNEGO, RADIUS, WS-Fed) ayrı süreçtir (CMP-23). İlke "dil hibriti değil süreç hibriti"dir. Kerberos'ta C FFI yalnız izole süreçte kullanılır.

**Gerekçe.**
1. Go lehine "Work bu dili kullanıyor" ve "ekip bölünmesi" gerekçeleri hiçbir Access gereksinimine dayanmaz ve reddedilir. Work ile seam protokoldür (ADP), kod paylaşımı değildir. T12'de "aynı kod" iddiası yoktur.
2. Kernel zaten Rust olmak zorundadır: `no_std`, Wasm, FFI ve tarayıcı/edge/mobil verifier gerektirir. Backend Go olsaydı ⊑/CBOR/ValidityContract en az iki dilde yeniden yazılırdı. Bu, HL-12 çok-implementasyon riskidir. Tek dilde sunucu ve verifier aynı kodu çalıştırır. Bu, kararın en büyük semantik kazancıdır.
3. Implementasyon düzeyinde kanıt (Kani, Flux), checked aritmetik (budget, slice, tutar), sır hijyeni (`zeroize`, `secrecy`, `memfd_secret`) ve tipte kiracı/domain kapsamı (branded lifetime) Rust'ta güçlüdür. Go'da yoktur ya da zayıftır.
4. Restriction dili Cedar forbid-only alt kümesine geçer (MD-4). Böylece cel-go avantajı düşer. Lean ile kanıtlanmış motor kernel'e yerel olarak gömülür.

**Bedel (dürüst beyan).**
- Rust'ta olgun, genel amaçlı bir OAuth 2.1 AS kütüphanesi yoktur. Tahmini ek iş 12–18 geliştirici-ayıdır (Fosite karşılığı yok). Bu tahmindir, ölçüm değildir. Bedel kabul edilir. Telafisi:
  - OIDF conformance süiti ilk günden CI'da koşar.
  - AS durum makinesi tip ve property testleriyle doğrulanır.
  - Fosite'ın hata geçmişinden çıkarılan hata sınıfları regresyon derlemine girer (§14).
- Witness, NATS, SPIFFE ve K8s ekosistemleri Go'da daha olgundur. Bu iddia doğrulanmadı ("?"). Bunlar protokolle konuşulan dış bileşenlerdir. Rust istemci olgunluğu açık sorudur (OQ-MD1).
- Tedarik zincirinde `build.rs` vektörü vardır. Telafisi `cargo-vet`/`cargo-deny`, build sandbox'ı ve tedarik zinciri kurallarıdır (§14).
- İşe alım havuzu daha dardır (HYPOTHESIS, B/H ekseni).

**Reconsider tetikleyicisi.** İlk 6 ayın sonunda AS çekirdeğinin OIDF conformance ilerlemesi bu tahminin 2 katından fazla geride kalırsa, yalnız AS çekirdeği için ayrı bir Go süreci (Fosite) değerlendirilir. Bu bir süreç hibriti olur. Kernel her durumda Rust kalır.

**Reddedilenler.**
- (c) Go kabuk + Rust kernel: iki backend dili, Wasm/FFI sınırı ve "%5 kapısı" belirsizliği getirir. Kani kazancının yarısı kaybolur.
- (d) Plane'e göre dil: iki backend dili ve kripto altyapısının iki kez yazılması gerekir. "Dil hibriti değil süreç hibriti" ilkesine de aykırıdır.
- Tek Go: kernel yine Rust olmak zorunda kalır, (c)'nin bütün bedelleri geçerli olur.

**Dil seçiminin performans gerekçesi değildir.** Bir parola login'inin CPU maliyetinin yaklaşık %97'si Argon2 ve imzadır, ikisi de dilden bağımsızdır (ölçüm ortamı M4, oran taşınır). Kazanç Argon2'yi hızlandırmaktan değil, hash dışı maliyeti azaltmaktan gelir (OP-32).

#### 16.4.1 OP-1 Access Kernel (CMP-24): içerik ve arayüz

**Statü: FROZEN (MD-1'den türer); arayüz ayrıntısı PD.**

Garanti: "ikinci implementasyon yok" kuralının uygulanması UNDER DECLARED CAPABILITY/POLICY'dir (CI kapısı + diferansiyel vektörler). Kodun bir kurala uyması BS değildir.

Kernel şunları içerir ve başka hiçbir yerde ikinci bir implementasyonu yoktur:
- deterministik CBOR kodlama ve digest (RFC 8949 §4.2; T4)
- ⊑ / ∩ / normalize (INV-8 cebiri)
- ValidityContract ile zaman ve bütçe aritmetiği, checked; taşma = DENY (MD-2)
- COSE_Sign1 doğrulama, RFC 9864 fully-specified algoritma tanımlayıcıları, metadata'dan gelen allowlist (MD-3)
- JWS compact/JSON ve SD-JWT doğrulama (yalnız doğrulama; T24 receipt ve PAP profilleri), RFC 9864 tanımlayıcıları, `alg: EdDSA` reddi ve metadata allowlist'i (MD-3). Kabul kümesi: ES256 (-7) zorunlu doğrulamadır; WebAuthn assertion algoritmaları WebAuthn kurallarına göre kabul edilir; "fully-specified" kuralı imza üretimi ve yeni artefaktlar içindir. Gerekçe: aksi hâlde Wasm/edge/mobil verifier JOSE'yi ikinci kez yazar (HL-12, MD-1 gerekçe 2)
- inclusion ve consistency proof doğrulama (T19, RFC 9162 tipi)
- §9'daki 7 adımlı verifier kuralı
- record-fold'un saf türetim fonksiyonları ve SYNC-DERIVED türetim fonksiyonları (TI-RT1, RT22)
- restriction motoru: Cedar forbid-only alt kümesi (MD-4); spike başarısızsa CEL profili (OQ-MD2)
- identity plane'in saf parçaları: epoch ve expiry karşılaştırması, delegasyon zinciri değişmezleri, kimlik doğrulama durum makinesinin geçiş fonksiyonu

Kurallar:
1. Kernel I/O yapmaz. `async fn`, `tokio::`, `sqlx::`, `reqwest::` ve ağ/dosya API'leri kernel crate'inde yasaktır ve CI'da zorlanır. Bu kural authority plane'in saf çekirdeği (CMP-4, TI-4) için de geçerlidir.
2. Kernel `#![no_std]` + `alloc` ile derlenir. `#![forbid(unsafe_code)]` geçerlidir. Tek istisna kripto arka uç bağlamasıdır (OP-3 allowlist).
3. Kripto arka ucu bir trait arkasındadır. Sunucu ve signer'da arka uç aws-lc-rs'tir (FIPS profili dahil, MD-3). Wasm/edge ve kaynak-kısıtlı cihaz hedeflerinde yalnız doğrulama yapan ayrı bir arka uç kullanılabilir. Bu ayrım **çıkarımdır**: aws-lc-rs'in `no_std`/Wasm hedeflerinde derlenip derlenmediği doğrulanmadı. İki arka uç aynı test vektörleriyle diferansiyel olarak sınanır. Saf-Rust P-256 ve `rsa` crate'i sunucu üretim yolunda kullanılmaz.
4. Kernel'in public API'si sürümlüdür. Her semantik sürümün kernel'i korunur (RT8, T12).
5. Kernel'e bağlanma yolları: sunucu ve signer'da doğrudan Rust bağımlılığı; TS SDK ve konsolda Wasm; iOS/Android'de FFI. Kernel ↔ Wasm/FFI çağrı maliyeti bilgi amaçlı ölçülür, kapı değildir (OQ-MD4).

#### 16.4.2 OP-2 Süreç topolojisi

**Statü: FROZEN (MD-1/MD-6'dan türer).**

| Süreç | İçerik | İzolasyon |
|---|---|---|
| Authority core | CMP-1, CMP-2, CMP-3 (+CMP-4/CMP-24), CMP-6, CMP-7 (payload ve digest; imza CMP-22a'da), CMP-8, CMP-10, CMP-12, CMP-14, CMP-21 | Authority cell; identity store'a erişimi yok (SEC19) |
| Authority derived/query | CMP-9, CMP-11 | Derived cluster; commit-mode girdisi değil (TI-5) |
| Authority signer (CMP-22a) | Domain kapsamlı operasyonel anahtarlar; CMP-13 Key Management'ın HSM/KMS istemcisi (PKCS#11) ve rotasyon/excerpt işlemleri bu süreç sınırındadır | Ağ syscall'ı yok (seccomp), Landlock (yalnız key store okuma), `memfd_secret`, `PR_SET_DUMPABLE=0` |
| Identity core | CMP-15.1–15.10, CMP-27 | Identity cell/cluster, ayrı KMS ve operatör rolleri (T31) |
| Identity signer (CMP-22b) | Realm JOSE anahtarları | CMP-22a ile aynı kısıtlar; anahtar deposu paylaşılmaz |
| Kenar gateway'leri (CMP-23.x) | SAML, LDAP, Kerberos/SPNEGO, RADIUS, WS-Fed | Her biri ayrı süreç, en az yetki |
| Parser worker'ları | XML (SAML/WS-Fed), ASN.1 (Kerberos/LDAP) | Yok edilebilir, `RLIMIT_AS`/`RLIMIT_STACK` + timeout; bir abort yalnız worker'ı öldürür |

Gerekçe: anahtar materyalinin HTTP sürecinin adres alanında bulunmaması yüksek değerlidir. Ağ syscall'ları yasak bir signer'dan anahtar sızdırmak fiziksel olarak engellenir. Parser izolasyonu tarihsel olarak sorunlu formatlarda stack exhaustion'ın tüm IdP'yi düşürmesini önler (OpenSSH 9.8 ayrıcalık ayrıştırma emsali). Maliyet: UDS IPC imza başına yaklaşık 10–50 µs (tahmin, ölçüm değil) ve süreç yaşam döngüsü yönetimi. Garanti: anahtarın HTTP süreci ele geçirildiğinde okunamaması UNDER DECLARED CAPABILITY/POLICY'dir (çekirdek, seccomp/Landlock ve HSM'in beyan edilen davranışına bağlı). Çekirdek açığı veya yan kanal NOT GUARANTEED'dir.

SAML süreç sınırı: SAML protokol mantığı CMP-23.1 gateway sürecindedir ve kullanıcı/oturum durumunu identity core'un iç API'sinden okur. XML ayrıştırma ve XMLDSig doğrulama ayrı, yok edilebilir worker'dadır (MD-18). Gerekçe: XSW ve libxml2 sınıfı açıkların etki alanı en küçük süreçte kalır.

#### 16.4.3 OP-3 Crate topolojisi ve CI kapıları

**Statü: FROZEN TECHNICAL (PD isimlendirme). Garanti: UDC (CI kapılarının uygulanması).**

```text
access-kernel/    #![no_std] #![forbid(unsafe_code)]  I/O yok, async yok. CBOR, ⊑/∩, ValidityContract,
                                                       COSE/proof doğrulama, restriction motoru, saf durum
                                                       makineleri, epoch mantığı. Kani hedefi.
access-proto/     #![forbid(unsafe_code)]  ADP/PAP/OIDC/OAuth/SCIM/SAML tipleri
access-parse/     #![forbid(unsafe_code)]  Bütün parser'lar; derinlik ve uzunluk sınırları decode'dan önce
access-authority/ #![forbid(unsafe_code)]  Sequencer, ingest, checkpointer, derived worker'lar
access-identity/  #![forbid(unsafe_code)]  AS, oturum, hesap, SCIM, admin API
access-http/      #![forbid(unsafe_code)]  axum handler'ları (her iki plane)
access-store/     #![forbid(unsafe_code)]  sqlx/tokio-postgres, RLS, SET LOCAL, tipte kapsam
access-crypto/    (FFI izinli)             aws-lc-rs sarmalayıcısı. İstisna 1
access-sandbox/   #![deny(unsafe_code)]+   seccomp/Landlock/prctl. İstisna 2
access-signer/    ayrı binary hedefi       CMP-22a/b
access-gw-*/      ayrı binary hedefleri    CMP-23.x (Kerberos FFI yalnız access-gw-kerberos içinde, İstisna 3)
```

`access-kernel` JWS/SD-JWT doğrulamasını da içerir (OP-1); `access-crypto` imza üretimi ve JWE/JAR/JARM içindir.

CI kapıları (birleştirme koşulu):
- `cargo geiger --forbid-only`; allowlist dışında `unsafe` yok.
- `access-kernel` ve `access-authority`'nin saf modüllerinde `async fn`, `tokio::`, `sqlx::`, `reqwest::` için grep yasağı.
- `cargo-vet`, `cargo-deny` (RUSTSEC, lisans, yasaklı crate'ler, OP-5), `cargo-auditable`.
- Deterministik CBOR encoder için bayt düzeyinde golden-vector testi (OP-56).
- OIDF conformance süiti (MD-1 bedel telafisi).
- `clippy::unwrap_used`, `expect_used`, `indexing_slicing`, `panic`, `arithmetic_side_effects` istek yolu crate'lerinde `deny` (OP-4).

Tip düzeyi kapsam: `access-store` bir tenant/domain/realm kapsamı olmadan sorgu tipini derlemez (MD-2 son madde). Branded lifetime (`generativity`) belirli yanlış kullanımları derleme zamanında engeller. **İzin verilmeyen ifade:** "kiracı izolasyonunu derleyici garanti eder". Asıl savunma RLS ve bileşik anahtarlardır (OP-12).

#### 16.4.3a OP-62 Depo ve klasör yapısı

**Statü: FROZEN TECHNICAL (tek depo, bağımlılık kuralları); PD (klasör ve crate adları). Garanti: UDC (CI kapılarının uygulanması).**

**Tek depo (monorepo).** Rust sunucusu, SDK'lar, Kernel bağlamaları, yardımcı servisler, konsol, conformance ve dağıtım dosyaları tek depodadır: bir API değişikliği sunucuyu, SDK'ları ve konsolu tek commit'te değiştirir ve birlikte test edilir. **İstisna:** açık kaynak SAML IdP test süiti (SA-58) tarafsızlık için ayrı depodadır.

**Klasör yapısı.**

```text
access/
├── Cargo.toml            Rust workspace
├── crates/               kütüphaneler; iş mantığı burada
│   ├── kernel/           no_std çekirdek (CMP-24)
│   ├── proto/            protokol tipleri
│   ├── parse/            bütün ayrıştırıcılar
│   ├── crypto/           aws-lc-rs sarmalayıcısı
│   ├── sandbox/          seccomp/Landlock/prctl
│   ├── store/            PostgreSQL erişimi, RLS, tipte kapsam
│   ├── internal-api/     iki plane arasındaki tek sözleşme
│   ├── authority-*/      authority plane bileşenleri (aşağıda)
│   ├── identity-*/       identity plane bileşenleri (aşağıda)
│   ├── http/             HTTP katmanı (her iki plane)
│   ├── telemetry/        log, trace, metrik, OCSF
│   └── testkit/          ortak test yardımcıları
├── bins/                 çalıştırılabilir programlar; ince, yalnız birleştirir
│   ├── access-server/    authority ve identity çekirdekleri (OP-2 süreçleri; small-provider profili tek binary)
│   ├── access-signer/    CMP-22a/b
│   ├── access-gw-saml/ -ldap/ -kerberos/ -radius/ -wsfed/   CMP-23.x
│   ├── access-parser-worker/
│   └── access-cli/       yönetim, `access ssh login` (IDP-32), replay
├── services/             Access'in sunduğu ayrı servisler
│   ├── executor/         B21, AG-40
│   ├── proxy/            B22, IDP-30: Envoy/Caddy paketleri ve yapılandırma aracı
│   ├── iys/              B23
│   └── linux-client/     IDP-32: daemon, PAM ve NSS modülleri
├── sdks/                 T41
│   ├── openapi/          API tanımı (SDK'ların kaynağı)
│   ├── bindings/         Kernel bağlamaları (uniffi, Wasm, C ABI)
│   └── typescript/ python/ go/ java/ dotnet/ swift/ kotlin/ react-native/
├── web/                  konsol ve gömülebilir UI bileşenleri (TN-133)
├── conformance/          OIDF, karşılaştırmalı testler (T42), uyumluluk laboratuvarı (IDP-40), test vektörleri
├── fuzz/                 fuzz hedefleri
├── load/                 açık yük testi düzeneği (OP-61)
├── deploy/               Docker, Helm, örnek altyapı
├── docs/                 spec (bölüm başına dosya), mimari diyagramlar, runbook'lar
├── xtask/                geliştirme otomasyonu ve kural kontrolleri
└── .github/              CI
```

**Crate bölünmesi.** OP-3'teki temel crate'ler korunur; `access-authority` ve `access-identity` spec bileşenlerine göre bölünür:
- authority: `authority-core` (CMP-4), `authority-sequencer` (CMP-3), `authority-ingest` (CMP-8), `authority-checkpoint` (CMP-6), `authority-query` (CMP-9, CMP-11), `authority-export` (CMP-12);
- identity: `identity-oauth` (CMP-15.1), `identity-session` (15.2), `identity-account` (15.3), `identity-scim` (15.4), `identity-admin` (15.5), `identity-ui` (15.6), `identity-webauthn` (15.7), `identity-federation` (15.10).

Her crate tek bir spec bileşenine karşılık gelir. Crate'ler ihtiyaç doğdukça açılır; ilk sürümde yalnız kullanılanlar vardır. Bölme ilkesi ve adlar bu bölümdedir.

**Bağımlılık yönü (CI'da `xtask` ile zorlanır; ihlal birleştirmeyi durdurur).**

| Crate | Bağımlı olabileceği iç crate'ler |
|---|---|
| `kernel` | hiçbiri |
| `proto` | kernel |
| `parse`, `crypto` | kernel, proto |
| `store` | kernel, proto |
| `authority-*` | kernel, proto, parse, crypto, store, internal-api, telemetry; **`identity-*` yasak** |
| `identity-*` | kernel, proto, parse, crypto, store, internal-api, telemetry; **`authority-*` yasak** |
| `http` | plane'lerin servis arayüzleri |
| `bins/*` | hepsi; iş mantığı içermez |
| `sdks/bindings` | kernel, proto |
| `services/*` | yalnız herkese açık parçalar: kernel, proto, SDK'lar; iç crate'ler yasak |

İki plane yalnız `internal-api` üzerinden konuşur: identity plane authority üretmez (INV-12) ve authority çekirdeği identity deposuna erişmez (SEC19) kuralları kod düzeyinde korunur. Yardımcı servislerin iç crate'lere erişememesi, protocol'de ayrıcalıklı yol olmadığını (B21, B22, E24) kodda kanıtlar: müşterinin kendi yürütücüsü veya proxy'si aynı parçalarla aynı şeyi yapabilir.

#### 16.4.3b OP-63 Kod içi mimari kalıplar

**Statü: FROZEN TECHNICAL (saf çekirdek, portlar, outbox, güvenliği gevşeten ayar yasağı); PD (adlandırma, zaman aşımı değerleri). Garanti: UDC.**

**1. Katmanlar: saf çekirdek, ince kabuk (portlar ve adaptörler).** Her bileşen crate'i dört katmana ayrılır:

| Katman | İçerik | Kural |
|---|---|---|
| `domain` | İş kuralları ve tipler | Saf: veritabanı, ağ, saat ve rastgelelik yoktur; aynı girdi aynı çıktıyı verir (TI-3) |
| `ports` | Dış ihtiyaçların arayüzleri: `Store`, `Clock`, `Signer`, `Rng`, `Outbox` | Yalnız trait tanımı |
| `app` | Kullanım senaryoları | `domain`'i çağırır; dış dünyaya yalnız `ports` üzerinden dokunur |
| `adapters` | Portların gerçek uygulamaları (PostgreSQL, HTTP, KMS) | Genelde `store`, `http`, `crypto` crate'lerinde |

Saat ve rastgelelik porttur: güvenilir zaman (TI-10) tek kaynaktan gelir ve testte sabitlenebilir. Kernel bu modelin en saf hâlidir (OP-1).

**2. Async ve eşzamanlılık.** Sunucularda Tokio çok iş parçacıklı çalışma zamanı kullanılır. Protokol mantığı (OAuth, SAML, SCIM akışları) I/O içermeyen (sans-I/O) durum makineleri olarak yazılır; ağ işini kabuk yapar. Async kod bloklanmaz: Argon2 ve ağır kriptografik işler `spawn_blocking` ile ayrılır. Her dış çağrının zaman aşımı vardır; kanallar ve kuyruklar sınırlıdır. İptal güvenliği: yarıda kesilen istek yarım iş bırakmaz.

**3. Transaction, outbox, idempotency** (TI-6, TI-7, TI-8'in kod kalıbı):
- Her kullanım senaryosu tek bir veritabanı transaction'ında çalışır (`UnitOfWork`).
- Dışarıya her etki (webhook, SSF/CAEP sinyali, e-posta, Relay olayı) aynı transaction'da outbox'a yazılır ve commit'ten sonra ayrı bir süreç tarafından gönderilir; doğrudan gönderim yoktur.
- İmza, yanıt ve dış istek dayandığı kayıt kalıcı olmadan çıkmaz (TI-6).
- Değişiklik yapan her istek `Idempotency-Key` taşır; anahtar istek özetiyle saklanır. Aynı anahtar aynı içerikle ilk sonucu döndürür; farklı içerikle hata döner.

**4. Yapılandırma.** İki tür ayar karıştırılmaz:
- **Süreç ayarı** (port, veritabanı adresi, log seviyesi): katmanlı (varsayılan < dosya < ortam değişkeni), tipli ve açılışta doğrulanır; hatalı ayarla süreç başlamaz. Sırlar dosyada veya ortam değişkeninde bulunmaz; süreç kendi workload kimliğiyle KMS'ten alır (§15).
- **Kiracı ayarı** (client, redirect URI, upstream IdP, politika): veritabanındadır ve yalnız `idp.*` domain action Exercise'ıyla değişir (MD-14); dosyayla değişmez.
- **Özellik bayrakları:** isteğe bağlı protokoller derleme zamanında açılır/kapanır (Cargo feature). Güvenliği gevşeten hiçbir bayrak, ayar veya "geliştirme modu" kodda tanımlı değildir (TI-9).

#### 16.4.3c OP-64 Kod kalitesi kuralları

**Statü: FROZEN TECHNICAL (dil, lint kapısı, tipli kimlik, hata ve log kuralları); PD (lint ayrıntıları). Garanti: UDC (CI ve inceleme).** OP-3, OP-4 ve OP-8'deki kurallar aynen geçerlidir; bu bölüm onları tamamlar.

1. **Dil.** Kod, tanımlayıcılar, kod yorumları, commit mesajları, PR ve issue metinleri İngilizcedir. Spec şimdilik Türkçedir. Spec terimleri (Grant, Mandate, Exercise, Acceptance, ValidityContract…) kodda birebir kullanılır; eş anlamlı uydurulmaz.
2. **Biçimlendirme ve araç sürümü.** `rustfmt` ayarı depodadır; biçimsiz kod CI'da reddedilir. Rust sürümü `rust-toolchain.toml` ile sabittir (edition 2024).
3. **Lint'ler.** Workspace düzeyinde tek yerde tanımlanır (`[workspace.lints]`): OP-3'teki `deny` listesi; `unsafe_code = "forbid"` varsayılan, yalnız OP-3 allowlist'indeki crate'lerde açılır; `clippy::pedantic` uyarı seviyesinde; herkese açık crate'lerde `missing_docs` yasak. CI'da her uyarı hatadır.
4. **Tipli kimlikler.** Her kimlik kendi tipindedir (`GrantId`, `DomainId`, `TenantId`, `RealmId`…); hiçbir kimlik çıplak `String` veya `Uuid` olarak dolaşmaz.
5. **Hata yönetimi.**
   - Kütüphanelerde tipli hatalar (`thiserror`); her crate kendi hata türünü tanımlar.
   - Yetki kararı (ALLOW / DENY / REQUIRE_ACTION) bir sonuçtur, hata değildir; hata yalnız işlemin yapılamadığını bildirir.
   - Dışarıya hata biçimi RFC 9457 Problem Details'tır; hata kodları kalıcıdır.
   - İç ayrıntı (stack trace, SQL hatası, dosya yolu) yanıta girmez.
   - Kimlik doğrulama ve hesap varlığıyla ilgili hatalar dışarıya tek biçimdedir (numaralandırma-nötr, TN-96).
6. **Loglama.** Yapılandırılmış log (`tracing`). Sır, token, anahtar ve kişisel veri taşıyan tipler kendini maskeler (`secrecy`, türetilmiş `Debug` yok; §17.8); bu tipler loga açık metin olarak yazılamaz. Seviyeler: `error` müdahale gerektirir; `warn` beklenmeyen ama yönetilen durum; `info` önemli iş olayı; `debug`/`trace` geliştirme.
7. **Yorum ve doküman.**
   - Yorum neyi değil nedeni anlatır.
   - Bir spec kuralını uygulayan kod kuralın ID'sini anar (ör. `// INV-2: single write path`); spec ile kod arasında iz sürülebilir.
   - Her `unsafe` bloğunun üstünde `// SAFETY:` açıklaması zorunludur.
   - `TODO` yalnız bir issue numarasıyla yazılır.

#### 16.4.4 OP-4 Build ve panic profili

**Statü: FROZEN TECHNICAL. Garanti: UDC (lint + build profili).**

- Release profilinde `overflow-checks = true`. Gerekçe: wraparound bir IdP'de ve bir authority motorunda yetki mantığı hatasıdır (token sayaçları, TTL, budget, slice, `len - offset`). Maliyet tipik olarak %1–5 CPU (beyan, ölçüm değil). Kernel'de ayrıca checked aritmetik kullanılır, taşma = DENY (MD-2).
- Panic politikası (MD-2):
  - İstek yolunda panic yoktur. Panic'e giden yollar lint ile yasaktır (OP-3).
  - Ağ süreçlerinde (`access-http`, gateway'ler) `panic = "abort"` yasaktır. Tek bir parser panic'i tam DoS olmamalıdır. Tokio `unhandled_panic` davranışı bilinçli seçilir.
  - `no_std` kernel'i gömen izole signer ve parser worker süreçlerinde `abort` serbesttir. Orada abort fail-closed davranıştır ve yalnız o süreci öldürür.
- Özyinelemeden önce derinlik kontrolü: her özyinelemeli parser'da derinlik ≤ 32 (PD) ve fuzz hedefi.
- HTTP limitleri açıkça ayarlanır (hyper HTTP/1 ve HTTP/2 limitlerinin tamamı). Ürün düzeyi limit değerleri §13.7.4'tedir.
- io_uring kullanılmaz (seccomp'u bypass eder).

#### 16.4.4a OP-68 Sürümleme, CI aşamaları ve yayın

**Statü: FROZEN TECHNICAL (iki sürüm ayrımı, CI kapıları, güvenlik günlüğü, trusted publishing); PD (araçlar, destek penceresi). Garanti: UDC.** F-4…F-8 (§14.7), SA-36…SA-39, OP-4 ve OP-56 aynen geçerlidir.

**1. Sürümleme.** İki sürüm türü karıştırılmaz:
- **Ürün sürümü** (sunucu binary'leri, servisler, SDK'lar): SemVer. Sunucu ve servisler tek ürün sürümünü paylaşır ve birlikte yayımlanır. SDK'lar kendi SemVer'ini taşır; uyumlu sunucu sürümleri bir uyumluluk tablosunda yayımlanır. Son iki minor sürüm güvenlik düzeltmesi alır (PD; OP-56 N-1 ile uyumlu).
- **Protokol semantik sürümü** (L0–L3): MD-15(b) ve OP-56 kurallarına tabidir; ürün sürümünden bağımsız ilerler.

**2. CI aşamaları.**
- **Her PR (≤ 10 dk, SA-59):** biçim ve lint (uyarı = hata, OP-64); kural kontrolleri (bağımlılık yönü OP-62, `store` dışında SQL yok OP-66, Kernel'de I/O yok OP-3); build ve testler (`cargo-nextest`; birim, entegrasyon, şema güvenlik testleri); API kapıları (OpenAPI eşitlik ve kırıcı değişiklik, `buf breaking`; OP-65); güvenlik (`cargo-deny`, `cargo-vet`, sır taraması, CodeQL, Semgrep; SA-60).
- **Her gece:** fuzz, karşılaştırmalı testler, OIDF conformance, sabit zaman testleri, mutation testing, uzun property-based ve metamorfik testler, `cargo-audit`.
- **Sürüm:** çift tekrarlanabilir build ve digest karşılaştırması (F-4); SBOM, provenance, Sigstore imzası (F-5…F-7); release checkpoint'inin witness co-sign'ı (SA-39); imaj ve SDK yayını.

**3. Build hızı.** Derleme önbelleği (`sccache` veya CI önbelleği); PR'da yalnız değişen crate'ler ve onlara bağımlı olanlar test edilir, gece ve sürüm build'leri her şeyi test eder; imajlarda bağımlılık katmanı ayrı önbelleğe alınır (`cargo-chef`).

**4. Değişiklik günlüğü.** Commit mesajları Conventional Commits biçimindedir; CHANGELOG commit'lerden üretilir. Güvenlik düzeltmeleri günlükte ayrı başlık altında ve ilgili GHSA duyurusuna bağlı olarak yer alır (B20).

**5. Yayın hedefleri.** İmajlar `amd64` ve `arm64`, GitHub Container Registry, imzalı. Kernel ve doğrulama paketi crates.io'da. SDK'lar her dilin kendi kayıt sisteminde (npm, PyPI, Maven Central, NuGet, Go modules, Swift Package Manager). Mümkün olan her yerde trusted publishing kullanılır; kalıcı yayın token'ı tutulmaz (F-10).

#### 16.4.4b OP-69 Geliştirici deneyimi

**Statü: FROZEN TECHNICAL (geliştirme modu yasağı, yerel ve CI'da aynı komutlar, üretilen dosyaların denetimi); PD (araçlar). Garanti: UDC.**

1. **Yerel ortam.** Tek komutla (`just dev`) `docker compose` ortamı kalkar: PostgreSQL 18, NATS, SoftHSM (PKCS#11), yerel KMS taklidi, Mailpit (e-posta ve SMS gerçekten gönderilmez) ve izleme yığını (OP-67).
2. **Geliştirme modu yoktur.** Güvenliği gevşeten ayar yasağı (TI-9) yerel ortamda da geçerlidir: “imzayı atla”, “HSM'siz çalış” gibi yollar yazılmaz; gerçek bileşenlerin yerel karşılıkları kullanılır. Kod her ortamda aynı yoldan çalışır. WebAuthn için `localhost` güvenli bağlamdır; özel alan adında `mkcert` sertifikası kullanılır.
3. **Görev çalıştırıcı.** `just`: `dev`, `test` (PR'da çalışan testlerin aynısı), `check` (CI kontrollerinin aynısı), `gen` (kod üretimi), `db-reset` (sıfırlama ve sentetik tohum verisi). Yerel ortam ve CI aynı komutları kullanır. Rust sürümü `rust-toolchain.toml` ile kurulur; isteğe bağlı devcontainer sağlanır.
4. **Hızlı geri bildirim.** Kaydetmede otomatik derleme ve test (`bacon`); commit öncesi yalnız hafif kontroller (biçim, sır taraması); ağır testler CI'dadır.
5. **Kod üretimi.** `just gen` OpenAPI belgesini, Protobuf kodunu, sqlx sorgu meta verisini ve Kernel bağlamalarını üretir. Üretilen dosyalar commitlenir; CI yeniden üretip farkı denetler (OP-65).
6. **İlk gün.** `CONTRIBUTING.md`: klonla, `just dev`, `just test`; hedef 15 dakikada çalışan ortam. İlk katkılar için “good first issue” etiketli işler (B24).

#### 16.4.4c OP-70 Dokümantasyon

**Statü: FROZEN TECHNICAL (spec'in yeri ve bölünmesi, kayıt tablolarının karar kaydı olması, dil kuralı); PD (araçlar, şablonlar).**

1. **Spec'in yeri.** Spec `docs/spec/` altında, ana bölüm başına bir dosyadır (dosya adları İngilizce, ör. `01-executive-definition.md`). İçerik, § numaraları ve ID'ler bölünmeyle değişmez; çapraz atıflar § ve ID ile yapılır. `docs/spec/README.md` içindekiler sayfasıdır. Kök `README.md` İngilizce, kısa bir proje tanıtımıdır (ne olduğu, durumu, spec bağlantısı, lisans, katkı).
2. **Karar kayıtları.** Ayrı bir ADR klasörü yoktur; spec'in karar kayıt tabloları (IDP, TN, AG, OP, SA, T, B…) karar kaydının tek doğruluk kaynağıdır. Bir kararı ekleyen veya değiştiren PR “decision” etiketi taşır ve kayıt tablosunu, bölüm başlığındaki aralığı ve §19.1'i birlikte günceller.
3. **Diyagramlar.** Mermaid ile Markdown içinde; C4'ün bağlam ve konteyner seviyeleri `docs/architecture/` altındadır (konteyner seviyesi OP-2 süreç topolojisidir). Daha ayrıntılı diyagramlar ihtiyaç doğdukça eklenir.
4. **API ve kod dokümanı.** API dokümanı OpenAPI belgesinden üretilir (OP-65); crate dokümanı `rustdoc` ile (OP-64 `missing_docs`); SDK dokümanları OpenAPI'den beslenir. Kullanıcı doküman sitesi ilk sürüme yakın kurulur.
5. **Runbook'lar.** `docs/runbooks/` altında her alarm için bir dosya (OP-67); ortak şablon: anlamı, etkisi, teşhis, düzeltme, haber verilecekler.
6. **Dil.** Kök README, CONTRIBUTING, runbook'lar, API ve kod dokümanı İngilizcedir. Spec şimdilik Türkçedir (OP-64); ilk çeviri adımı “Kısaca Access” bölümünün İngilizcesidir (`docs/overview.md`).

#### 16.4.4d OP-71 Süreç ve katkı

**Statü: FROZEN TECHNICAL (trunk-based, PR ile birleştirme, Adem'in birleştirmesi, güvenlik bildiriminin özel kanalı); PD (şablonlar, etiketler, satır hedefi).** SA-60 (F-13…F-18) aynen geçerlidir.

1. **Branch modeli.** Trunk-based: `main` her zaman çalışır durumdadır; iş kısa ömürlü dallarda yapılır (`feat/…`, `fix/…`, `docs/…`). Birleştirme yalnız squash ile; PR başlığı Conventional Commits biçimindedir ve `main`'de tek commit olur; `main` geçmişi doğrusaldır.
2. **Çalışma akışı.** Claude dal açar, değişikliği yapar, testleri çalıştırır, dalı pushlar ve PR açar; CI çalışır; Adem inceler ve birleştirir. Birleştirme yetkisi yalnız Adem'dedir. PR'lar Adem'in hesabıyla açıldığından GitHub'ın onay sayısı kuralı kullanılmaz (kişi kendi PR'ını onaylayamaz); inceleme, birleştirmenin yalnız Adem tarafından yapılmasıdır (F-17). Bu akış branch koruması açıldığında spec çalışmaları dahil bütün değişikliklere uygulanır.
3. **PR kuralları.** Şablon: ne ve neden, etkilenen spec kuralları (ID ile), test, kırıcı değişiklik, hassas yolda kısa tehdit değerlendirmesi (F-18). Hedef 400 satırın altı; büyük iş birden çok PR'a bölünür. Birleştirme koşulu: CI yeşil, şablon dolu. Karar değiştiren PR `decision` etiketi taşır (OP-70).
4. **Issue'lar ve etiketler.** Hata ve özellik şablonları. Güvenlik açığı herkese açık issue olarak bildirilmez; `SECURITY.md` GitHub özel güvenlik bildirimine yönlendirir (SA-14). Etiketler: `decision`, `security-sensitive`, `good first issue`, `phase:0`…`phase:3`, bileşen etiketleri. Sürüm kapsamı milestone'larla izlenir.
5. **GitHub ayarları.** `main` koruması: PR zorunlu, gerekli CI kontrolleri, imzalı commit, doğrusal geçmiş, force-push ve silme yasak. Push protection ve secret scanning açık (F-13). Yalnız squash merge. `CODEOWNERS` bütün depo için Adem; hassas yollar (Kernel, kripto, store, signer, kimlik doğrulama akışları, göçler) ayrıca işaretlenir ve bu yollara dokunan PR'lar `security-sensitive` etiketi alır.
6. **Açık kaynak dosyaları.** `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1 uyarlaması), `SECURITY.md`, `.github/` altında PR ve issue şablonları ve `CODEOWNERS`; `LICENSE` lisans seçilince (D4).

#### 16.4.5 OP-5 Bağımlılık yığını ve yasaklar

**Statü: PD (sürümler), FROZEN TECHNICAL (yasaklar).**

| Katman | Seçim | Not |
|---|---|---|
| HTTP ve runtime | axum 0.8 + hyper 1.x + tower-http; tokio 1.x | Benchmark değil ekosistem kütlesi. Argon2 izolasyonuyla (OP-33) |
| TLS | rustls 0.23, aws-lc-rs sağlayıcısı, `fips` özelliği | PQ hibrit anahtar değişiminin varsayılan açık olduğu doğrulanmadı |
| Kripto | aws-lc-rs | MD-1, MD-3. Ed25519 imza 4,10 µs, ES256 11,05 µs (M4 ortamı) |
| JOSE/JWT | `access-crypto` içinde ince, kendi JOSE kodlayıcı/çözücü (aws-lc-rs üzerinde) | `jsonwebtoken` 11 (`aws_lc_rs` özelliğiyle) yerine kendi kodlayıcı seçilir (1,91× kazanç, ölçüm M4). Ek gerekçe: algoritma allowlist'i header'dan değil client/Domain Metadata'dan gelir ve `alg: EdDSA` reddedilir (MD-3). `jsonwebtoken` yalnız diferansiyel test oracle'ı olarak kullanılır. İmza **üretimi** ve identity plane'e özgü JOSE (JWE, JAR/JARM) `access-crypto`'dadır; doğrulama yolu Kernel'dedir (OP-1) |
| COSE | Kernel içinde (CMP-24) | T4, MD-3 |
| WebAuthn | webauthn-rs 0.5 | PRF hariç hazır |
| Parola hash | argon2 0.6 | x86'da `libargon2` ile fark ölçülecek; fark %20'yi aşarsa FFI değerlendirilir |
| Veri erişimi | tokio-postgres + deadpool sıcak yolda (sequencer, token yolu); sqlx 0.9 göçler ve soğuk yollar | sqlx yönetişim uyarısı. Sıcak yolda elle hazırlanmış ifade |
| Politika | cedar-policy 4 (forbid-only alt küme, kernel'de) | MD-4; spike OQ-MD2 |
| SAML XML | bergshamra (saf Rust) ile samael/libxml2 arasında spike; ikisi de izole worker'da | bergshamra tek geliştiricili ve 0.9; test süiti kopyası kendi CI'da. samael seçilirse libxml2 ≥ 2.15.4 ve fork'lanmış pin |
| LDAP | ldap3_proto 0.8 (yalnız codec; semantik bizim) | — |
| SCIM | scim_v2 0.5 (model + filtre parser'ı; endpoint bizim) | — |
| Rate limit (Katman A) | governor (GCRA, süreç içi) | OP-35 |
| Sır hijyeni | secrecy, zeroize, `memfd_secret`; imza anahtarı için mlock (memsec) | — |
| Gözlemlenebilirlik | tracing + opentelemetry-rust, ince cephe arkasında | OP-47 |

Yasaklar:

| Yasak | Gerekçe |
|---|---|
| `rsa` crate'i; `jsonwebtoken` + `rust_crypto` özelliği; `openidconnect` (sunucu için); `josekit` | Marvin zamanlama yan kanalı; `openidconnect` istemcidir ve `rsa`'ya bağımlıdır; josekit C OpenSSL'e bağlı |
| Saf-Rust `p256` sunucu üretim yolunda | aws-lc-rs'e göre imzada 7,6×, doğrulamada 4,9× yavaş |
| `ntex`, `poem`, `h3` | Ekosistem/bakım |
| `diesel` < 2.3.8 (kullanılırsa) | RUSTSEC-2026-0136 (doğrulanmadı) |
| PostgreSQL `LISTEN/NOTIFY` (her iki plane) | Transaction-mode havuzla çalışmaz; kuyruk dolarsa commit düşer. OP-19 |
| Redis/Infinispan'ı doğruluk kaynağı yapmak; Redis pub/sub'ı iptal taşıyıcısı yapmak | At-most-once teslim. OP-19 |
| Identity denetim log'unda olay başına hash zinciri | Seri bağımlılık; ölçülen koşulda 3,8× kayıp (ölçüm henüz yeniden üretilmedi). Authority log'unda T3 zinciri korunur, çünkü zincir sequencer belleğinde batch içinde hesaplanır |
| `gamlastan` SAML domain modeli olarak | XSW savunması bu katmandadır |
| `serde_stacker` + `disable_recursion_limit` | Sınırsız derinlik meşru değildir |
| `unshare` crate'i; `cap` crate'i limit olarak | Bakımsız; limit aşımı abort üretir |
| musl varsayılan allocator'ıyla | Çok iş parçacıklı yükte ciddi yavaşlama raporu (rapor 2020, doğrulanmadı) |
| Üretimde `-Zsanitizer=cfi`, `-Zstack-protector` | Nightly; tekrarlanabilir build'i bozar |

Crate envanteri, sürüm tarihleri ve olgunluk tabloları bu bölümün **normatif ekidir**. Sürüm numaraları 8 Eylül 2026 çekimine aittir ve yeniden doğrulanmadı.

#### 16.4.6 OP-6 Dış bağlamalar ve iç RPC

**Statü: FROZEN.**

- Protocol uç noktaları standart bağlamalarla aynen sunulur: AuthZEN HTTP/JSON, OAuth, SSF, `.well-known`, OIDF. Third-party PEP Suiss'e özgü bir şey bilmeden bağlanır (TI-17).
- İç RPC ConnectRPC/Protobuf'tur. Rust implementasyonlarının olgunluğu doğrulanmadı ve OQ-MD1'e eklenir. Olgunluk yetersizse gRPC uyumlu bir Rust yığını (tonic sınıfı) eşdeğer kabul edilir. Bu yalnız iç bağlamadır, protocol yolunda değildir.
- Suiss kolaylık API'leri ve identity plane'in admin API'si (CMP-15.5) authority değişikliği için ADP `commit`'e derlenir ve AIS ister (MD-14).
- Kiracının veya müşterinin sunucu tarafında yürüttüğü Turing-tam kod yoktur (ayrıntı §2).

#### 16.4.6a OP-65 API aileleri ve ortak API kuralları

**Statü: FROZEN TECHNICAL (aileler, sürümleme, şema zinciri, ortak kurallar); PD (araç seçimleri, süreler). Garanti: UDC.** OP-6, TN-110, TN-112 ve TN-113 aynen geçerlidir.

**1. API aileleri.**

| Aile | Kullanan | Kural |
|---|---|---|
| Standart protokol uçları (OAuth/OIDC, SAML, SCIM, AuthZEN, SSF, `.well-known`, OIDF) | Dış uygulamalar, IdP'ler, PEP'ler | Standardın birebir aynısı; uzantı yalnız standardın izin verdiği yerde (OP-6, TI-17) |
| Yönetim API'si (REST) | Kiracı backend'i, konsol, GitOps uzlaştırıcısı | Aşağıdaki ortak kurallar; yazmalar Exercise'a derlenir (TN-110) |
| Karar API'si (ADP: AuthZEN + Access uzantıları) | PEP'ler, SDK `authorize` modülü | §9 protocol kuralları |
| Frontend API | Gömülü UI bileşenleri, tarayıcı ve mobil istemciler (TN-133) | Kiracının özel alan adında; kendi çerez, CORS ve CSRF kuralları; aşağıdaki ortak kurallar |
| İç RPC (ConnectRPC/Protobuf) | Access süreçleri | Dışarıya açık değildir (OP-6) |

**2. Sürümleme.** Yönetim ve Frontend API'sinde ana sürüm adrestedir (`/v1/...`); bir ana sürüm içinde yalnız eklemeli değişiklik yapılır. Kaldırma önce `Deprecation` (RFC 9745) ve `Sunset` (RFC 8594) başlıklarıyla duyurulur. Standart protokoller kendi sürümlemesini izler. İç RPC'de Protobuf uyumluluk kuralları CI'da `buf breaking` ile denetlenir.

**3. Şema zinciri.**
- Yönetim ve Frontend API'si **koddan** belgelenir (TN-112): OpenAPI belgesi Rust kodundan üretilir ve `sdks/openapi/` altında depoya commitlenir.
- CI, koddan yeniden üretilen belgenin commitlenmiş belgeyle aynı olduğunu ve ana sürüm artırılmadan kırıcı değişiklik yapılmadığını denetler; ihlal birleştirmeyi durdurur.
- SDK'lar bu belgeden üretilir (T41).
- İç RPC'de **şema önce** gelir: `.proto` dosyaları yazılır, kod ondan üretilir.

**4. Ortak kurallar (Yönetim ve Frontend API'si).**
- Hata biçimi RFC 9457 (OP-64).
- Sayfalama opak imleçle; sayfa numarası veya offset yoktur.
- Değişiklik yapan her istekte `Idempotency-Key` (MKT-D15, OP-63).
- Eşzamanlı güncelleme: kaynak sürümü `ETag` olarak döner; güncelleme `If-Match` ister; uyuşmazlıkta 412.
- Dış kimlikler opak ve türe göre öneklidir (ör. `grt_…` Grant, `rlm_…` realm); içeride UUIDv7 (MD-18).
- Alan adları `snake_case`.
- Zaman RFC 3339, UTC.
- Büyük tamsayılar (tutar, sayaç) JSON'da string olarak taşınır (OP-8 TypeScript profili).
- Her yanıtta `Request-Id` başlığı.
- Hız sınırı bilgisi standart `RateLimit` başlıklarıyla döner.

#### 16.4.7 OP-7 PostgreSQL 18 asgari sürüm

**Statü: FROZEN TECHNICAL. Ölçüm kanıtı: tek ortam.**

PostgreSQL kararı T8'dir. Asgari sürüm PostgreSQL 18'dir. Gerekçeler: yerleşik `uuidv7()` (insert'te 1,67×, PK indeksi %26 küçük; M4/PG18.6 Docker), çok partition'lı iş yükünde fast-path kilit düzeltmesi (commit `c4d5cb71d`, doğrulanmadı), `SET NOT NULL NOT VALID` ile expand/contract sadeleşmesi, `idle_replication_slot_timeout`. Expand/contract'ın kendisi PG12'den beri mümkündür ve PG18 gerekçesi değildir. Third-party provider başka bir ACID depo kullanabilir. Şart teknoloji değil, tek-head CAS ve atomik birimlerdir (TI-17).

#### 16.4.8 OP-8 Dilden bağımsız sertleştirme kuralları ve profiller [MD-2]

**Statü: FROZEN. Garanti: UDC (kuralların uygulanması; CI ve inceleme).**

Spec normatif kuralları dilden bağımsız yazar. Rust ana profildir. Kurallar:
- checked aritmetik; taşma = DENY
- allowlist dışında `unsafe`/FFI yok
- istek yolunda panic yok; ağ süreçlerinde `abort` yasak, `no_std` kernel ile izole signer/parser worker'ında serbest
- özyinelemeden önce derinlik kontrolü
- açık HTTP limitleri
- DST'ye uygun saf sequencer durum makinesi (deterministik simülasyon testi; §14)
- domain/tenant/realm kapsamı olmayan sorgu derlenemez

Profiller:

| Profil | Kapsam | Kural uyarlaması |
|---|---|---|
| Rust (ana) | Bütün sunucu süreçleri, Kernel | OP-3, OP-4 |
| TypeScript | İstemci SDK'ları, konsol | Kernel Wasm'dan çağrılır; ⊑/CBOR/ValidityContract TS'de yeniden yazılmaz. Sayısal değerler `number` değil `bigint`/string ile taşınır (çıkarım: JS `number` 2^53 üstünde kesinlik kaybeder). PEP SDK'da fail-open yoktur (X21) |
| C FFI | Yalnız CMP-23.3 Kerberos gateway süreci | FFI izole süreçte; seccomp/Landlock; ASN.1 ayrıştırma parser worker'ında; süreç ele geçirilse bile identity core'un iç API'si dışında yetkisi yoktur |

#### 16.4.9 Prior-art dersleri

Mimari gerekçe eki: iki Rust IdP'sinin (Kanidm, Rauthy) kaynak kodu incelemesinden çıkan dersler.
1. **IdP iş yükü ilişkisel join değil, indeksli entry lookup'tır.** Depolama motoru yazılmaz, ama üstündeki indeks ve cache katmanının yazılması gerekebilir.
2. **Tek yazıcı ve kilitlenmeyen okuyucu doğru takastır, ama replikasyonu baştan belirler.** Kanidm iki node'da tıkanmıştır. Bu ders T6 (domain başına tek sequencer, DB'de head CAS) ile uyumludur.
3. **Bellek güvenliği güvenlik bütçesinin küçük bir kısmını kapatır.** Kanidm'in 2026'daki on advisory'sinin hiçbiri buffer overflow değildir: parser stack exhaustion, sabit zamanlı olmayan karşılaştırma, XSS, authenticated arbitrary write. Kural seti: her parser'a decode'dan önce derinlik ve uzunluk sınırı (OP-4), bütün secret karşılaştırmalarında `subtle`, erişim kontrolü için property-based test (§14).
4. **Ölçek gerçekçiliği.** Rauthy'nin 84.000 satırı tek kişinin üç yılda yazdığı, yalnız OIDC sunan bir IdP'dir. Access bunun üstüne SAML, LDAP, SCIM, çok kiracılık ve bütün authority plane'i ekler.

**İzin verilmeyen ifade:** "Rust olduğu için güvenli." Rust bellek güvenliği verir, güvenlik vermez.

#### 16.4.10 Efor ve risk beyanı

- Efor tahmini: Rust ≈ 46–73, Go ≈ 31–49 geliştirici-ayı (IdP kapsamı; yaklaşık 1,5×). Farkın neredeyse tamamı OAuth AS kalemidir (12–18 ve 3–5 geliştirici-ayı). **HYPOTHESIS / tahmin, ölçüm değil.** Authority plane'in eforu bu tahmine dahil değildir.
- Risk kayıtları: **RR-40, RR-41, RR-42 emeklidir**; kanonik satırlar RR-18, RR-19, RR-20'dir (§13.9). Aşağıdaki azaltma maddeleri o satırların izleme sütunundadır.
  - **RR-40 → RR-18** (emekli) OAuth/OIDC AS'in sıfırdan yazılması. Hata doğrudan kimlik doğrulama atlatmasıdır. Azaltma: OIDF süiti CI'da ilk günden, PKCE S256 zorunlu, implicit/ROPC hiç yok, refresh reuse tespiti baştan.
  - **RR-41 → RR-19** (emekli) Korele tek-bakımcı crate riski: webauthn-rs, ldap3_proto ve concread aynı ekipten; bergshamra ailesi tek kişiden. Azaltma: `cargo vendor`, fork kapasitesi, CI'da bloklayıcı `cargo-audit`/`cargo-deny`.
  - **RR-42 → RR-20** (emekli) SAML'in altındaki XML yığını: libxml2 C yığını (samael yolu) veya genç saf-Rust yığın (bergshamra yolu). Azaltma: izole parser worker, XSW regresyon derlemi, XML c14n fuzz önceliği 1 (MD-18).

#### 16.4.11 Bu alt bölümün açık soruları (→ §20)

- **OQ-MD1** Rust witness/NATS/SPIFFE istemci olgunluğu. Bu bölüm kapsamı genişletir: ConnectRPC Rust implementasyonu ve K8s operator/istemci kütüphaneleri de aynı soruya dahildir.
- **OQ-MD4** Kernel ↔ Wasm/FFI çağrı maliyeti. Bilgi amaçlıdır, kapı değildir. Ölçüm kernel'in hem sunucu (doğrudan bağlama) hem tarayıcı/mobil (Wasm/FFI) yolunu kapsar.
- **OQ-MD2** (MD-4 sahibi §5/§6; burada yalnız kernel etkisi): Cedar forbid-only + REQUIRE spike'ı başarısız olursa kernel'e CEL profili gömülür. cel-rust olgunluğu doğrulanmadı.

### 16.5 Temel mekanizmalar

| Mekanizma | Kural | Dayanak |
|---|---|---|
| Domain log ve commit | Domain başına tek sequencer; optimistic read-set validation (negatif okumalar dahil); tek DB transaction'da `records ∪ sync-derived ∪ outbox ∪ head CAS(position, epoch)`; ikinci leader'ın append'i fiziksel olarak reddedilir | T6, T7, TI-2 |
| Kayıt zarfı | RecordEnvelope canonical CBOR; AIS digest yalnız `proof_commit` içinde taahhüt edilir (tek commitment) | T3, TI-RT11 |
| Kayıt kimliği | Kayıt kimliği commitment'tır (leaf / body digest); commitment-eşleşen kopyadan geri yükleme meşrudur; bozulma tespitinde commit durur (FA-14) | TI-RT11, G34 |
| State kurma | Record-fold: kayıtlı DecisionRecord effect'leri kayıtlı hâliyle + Claim'lerden L0 normatif türetim; SYNC-DERIVED ve leader cold-start yalnız Genesis'ten fold veya fold-doğrulanmış canonical-taraf snapshot'tan | TI-RT1, TI-RT4, TI-16 |
| Rebuild-diff | Fold farkı → commit durur, Genesis'ten fold hakemdir. Yeniden değerlendirme farkı → divergence prosedürü (beyan + divergence quarantine; canlı tablo ezilmez, commit durmaz) | TI-RT4, G33 |
| Read-path | strong / at_least / as_of sınıfları; derived cevaplar advisory'dir; `basis_ref` audit kapsamında açık, altında opaque anahtarlı token; okuma cevapları `witnessed_through` taşır | T10, T11, TI-RT10 |
| `derived.*` whitelist | **Kapalıdır.** Yalnız kayıtlardan deterministik hesaplanan ve version key'i olan şu on bir fonksiyondan oluşur: (1) Party toplam consumption (pencere; actor-side Party toplamı, §13.7.6); (2) requester açık REQUIRE_ACTION sayısı (SEC28 throttling, §13.7.4); (3) selector holder **geçiş** sayısı (mass-selection guard, §13.7.6); (4) cited contribution actor Instance durumu (SEC11); (5) mapping pin yaşı (SEC16 probation); (6) Claim `recorded_at` yaşı (SEC18 cooling); (7) `derived.unreported_contracts(verifier, time)` (SEC14, §13.7.2; SYNC-DERIVED `verifier_contract`, `contracts@verifier(V)` key'i; zaman bağımlılığı τ'ya girer); (8) rollback guard girdisi: değerlendiricinin beyanlı witness kümesinin tamamından kendisinin çektiği ve aynı batch'te `checkpoint` Claim'i olarak ingest ettiği en yeni checkpoint'lerin en yükseği, beyanlı replica'nın record-fold'uyla kökü yeniden üretilen en yüksek witness'lı checkpoint R* ve aynı size için çelişen kökler (requester'ın sunduğu alt küme girdi değildir; SEC21–SEC22); (9) Instance × action class `projection.issue` sayısı (pencere; §13.7.4); (10) Instance başına açık offline PAP sayısı (§13.7.4); (11) eşik-bitişik tekrar sayacı (§13.7.6). Her biri §16.5.1'deki bir yapıdan hesaplanır ve §16.5.2'deki bir key'le read-set'e girer; open spec'te tanımlıdır (SI-8). Whitelist dışı fonksiyona dayanan policy `policy.set` DENY'dır | RT26, SI-8 |
| Access Restriction Profile | Restriction dili Cedar forbid-only alt kümesidir (MD-4; ayrıntı §5/§6). Spike başarısız olursa (OQ-MD2) kapalı CEL alt kümesi kullanılır ve şu polarite kuralı geçerlidir: parametreyi içeren karşılaştırma yalnız `&&` / `\|\|` altında olabilir ve parametre başka bir operatörün argümanı olamaz; değerlendirme hatası DENY | T13, RT22 |
| Claim currency | Issuer sırası (açık `supersedes` zinciri, Party key-event pozisyonu veya taşıyıcı profilinin tanımladığı monoton sıra alanı); belirsizlikte disqualifying kazanır; eski Claim kaydedilir, asserting değildir | TI-RT7, RT15 |
| Release | Σrelease ≤ draw; grounding dedup; aşım `budget-exhausted/release-exceeds-draw` | TI-RT8 |
| Toplu episode | O(1) işaret + deterministik tembel hesap (`since` = son false→true geçişi); commit başı iş sınırı ENGINEERING ASSUMPTION; `holdings@party(P)` yalnız materyalize episode değişikliğinde artar | TI-RT9, RT19 |
| Zaman disiplini | ≥ 2 bağımsız zaman kaynağı, monotonic sınırlı ilerleme; kaynak uyuşmazlığı > U → commit yok; witness cosign zamanı çapraz kontrolü | TI-RT2, FA-3 |
| Nonce ve AIS yaşı | Nonce lookup (arşiv dahil) sonrası nonce yoksa: AIS yaşı ≤ intent validity tavanı (POLICY DEFAULT = hot-path nonce saklama ufku) + pre-recovery kuralı; her istekte `t ∈ intent.validity`; nonce satırı olan istek (aynı-nonce re-commit, idempotent retry) etkilenmez | TI-RT3, RT7 |
| Checkpoint ve heartbeat | Checkpoint = (domain, size, Merkle root, head leaf, recorded_at, version vector digest), operasyonel anahtarla COSE; cadence 60 s / 1,000 kayıt (POLICY DEFAULT) + out-of-cycle; cadence checkpoint'i değişiklik olmasa da üretilir, witness'lara gönderilir ve log'a `checkpoint` Claim kaydı olarak ingest edilir (handover freeze'inde askıda); sessiz domain'de metadata tazeliğini ve status list `iat`'ini besler | T16, TI-RT5 |
| Mirror-before-witness | Replica beyan eden domain'de checkpoint witness'a ancak kapsadığı bütün önek replica'ya durable yazıldıktan sonra gönderilir; dürüst provider'da R* = witness en yüksek | TI-13, SEC23 |
| Witness/replica-before-ack | Revocation sınıfı ve CT3 commit'leri, kapsayan checkpoint bağımsız witness co-sign'ı alıp önek replica'ya ulaşmadan ack edilmez; o sırada okuma "Revoked — confirming (witness pending)" verir | SEC23, RT24 |
| Anahtar hiyerarşisi | HSM'de quorum'lu binding key; ≤ 24 saat domain-başı operasyonel anahtarlar; artefakta gömülü binding-imzalı excerpt {DomainID, kid, alg, validFrom, validUntil, usage}; verifier DomainID eşleşmesi ister; yeni operasyonel anahtarın validity başlangıcı aktivasyondan en az status-list derived gecikme tavanı kadar önce beyan edilir (status list `iat` penceresi örtüşür; pencere sonu değişmez) | T20, TI-RT6 |
| `cap_horizon` | `cap_horizon(class, variant, CT)`: CT verifier'ın gerçekleştirdiği intent'ten, class ve variant Verifier Profile'dan alınır; artefaktın beyanı kullanılmaz | T20, U25 |
| Metadata tazeliği | Domain Metadata / foreign metadata cache'inin tazeliği pinli kümeden bağımsız witness'ın ≤ Δ (yoksa ≤ 1 saat) cosign'ıyla ölçülür; kendi `iat`'i kanıt değildir | TI-RT5, T29 |
| Örtük bilgi | Audit kapsamının altında pozisyon taşıyan her tanımlayıcı domain anahtarıyla opaque token; event id HMAC; Merkle index pozisyonu HL-10 olarak beyanlıdır | TI-RT10, T26 |
| Hub cache | Viewer-scoped okuma snapshot'ı; projection değildir; authority taşımaz | T30, SI-15 |
| SCIM ve dış sıra | SCIM kaynaklı Claim'lerde sıra yalnız yukarıdaki issuer-sırası kaynaklarından gelir; opak sürüm etiketleri sıra kaynağı değildir | RT15 |
| Normatif kural dağılımı | Proof seçimi (T14), ilk-commit AIS yaşı + pre-recovery kuralı, issuer sırası, Σrelease tavanı, episode fonksiyonu, restriction dili alt kümesi (MD-4), token kuralı ve SYNC-DERIVED türetim fonksiyonları L0/L2 metnine ve conformance vektörlerine girer | TI-RT12, RT22 |

#### 16.5.1 Derived yapılar

| Derived kavram | Teknik yapı | Sınıf | Nasıl güncellenir | Kim okur |
|---|---|---|---|---|
| Budget remaining | `budget(node, term, window)` sayaçları | SYNC-DERIVED | Commit tx'inde | Leader (commit) |
| Nonce / single-use durumu | `nonce`, `single_use` tabloları | SYNC-DERIVED | Commit tx'inde | Leader |
| Güncel authority state (Grant/Mandate/Acceptance/Instance/Policy revizyonları, status) | `authority_current` satırları + version key'leri | SYNC-DERIVED | Meta-Exercise tx'inde | Leader |
| Holder set'leri ve holding episode'ları | `episode(grant, party, since_pos, until_pos?, cause)` + selector indeksi (claim class → selector'lar) | SYNC-DERIVED | Claim append ve ilgili meta-Exercise tx'inde; toplu olaylar O(1) işaret + tembel hesap (TI-RT9) | Leader |
| Rolling aggregate'ler (actor-side Party toplamı, requester throttling, mass-selection guard, eşik-bitişik tekrar, `projection.issue` sayısı, açık offline PAP sayısı) | Pencere-kovalı sayaçlar | SYNC-DERIVED | Commit tx'inde | Leader (Restriction Engine girdisi) |
| Release toplamları | `released@(ExerciseID)`, `released@(projection)` | SYNC-DERIVED | `consumption.release` tx'inde | Leader (Σrelease ≤ draw, TI-RT8) |
| Claim güncelliği | `current@(issuer, subject, class)` (issuer sırası) | SYNC-DERIVED | Claim append tx'inde | Leader (TI-RT7) |
| Per-verifier açık contract / report durumu (SEC14 girdisi) | `verifier_contract(verifier, projection_pos, horizon, reported_pos?)` | SYNC-DERIVED | Offline/intermittent `projection.issue` ve offline report Claim append tx'inde | Leader (`derived.unreported_contracts`) |
| Issuer kota sayaçları | `issuer_quota(issuer, window)`; sonuç Claim header'ında canonical disposition alanı | SYNC-DERIVED (sayaç) / CANONICAL (disposition) | Claim append tx'inde; narrowing sınıfı Claim'ler sayaca girmez | Bileşen CMP-8; qualifying etki yalnız `admit` Claim'lerden; `quarantine:quota` Claim'in narrowing etkisi yine uygulanır |
| Effective / exercisable authority graph | Graph index (ters indeks: holder → Grant, Grant → alt ağaç, resource prefix → Grant) | DERIVED | Async | Search, eligible set, impact, hub |
| Eligible approvers / contributors | Graph index sorgusu | DERIVED | Async | Work Gate (bilgi), S-yüzeyleri |
| Revocation impact, staleness exposure | Alt ağaç + açık ValidityContract'lar + projection kayıtları | DERIVED | Async; önizlemede `at_least` | X12 önizleme, aftermath |
| Compromise impact sorgusu (SEC15) | Instance/issuer/key × zaman penceresi indeksleri | DERIVED | Async | Security Party, S-yüzeyleri |
| Exercise outcome state (attested / unknown) | Effect attestation Claim'leri ⋈ Exercise | DERIVED | Async | Audit, S4 |
| Offline kullanılan / kullanılmayan / contract dışı görünümü | Offline report Claim'leri ⋈ projection kaydı | DERIVED | Async | S4/S9; `consumption.release` önerisi (karar girdisi değil) |
| Status list (Token Status List) | Projection'ların geçerlilik bit'leri | PROJECTION (derived'dan) | Async; `iat`/`as_of` = yansıttığı `applied_pos`'un `recorded_at`'i → derived gecikmesi Δ'yı tüketir, uzatmaz (SI-7); derived kesintisinde yeni liste yok (G43); revocation sınıfı öncelikli; heartbeat checkpoint'i sessiz domain'de tazeler | Verifier'lar |
| Semantic events | Outbox | SYNC-DERIVED kuyruk → PROJECTION | Commit tx'inde | Relay |

Rollback guard girdisi (whitelist 8) bir tablo değildir: değerlendirici recovery batch'inde witness `checkpoint` Claim'lerini ingest eder ve R*'ı replica'nın record-fold'undan hesaplar; ikisi de StateBasis'te cite edilir (SEC22).

#### 16.5.2 Koleksiyon key tablosu (read-set tamlığı)

Optimistic validation'ın doğruluğu read-set'in tam olmasına bağlıdır: sonucu değiştirebilecek her canonical değişiklik read-set'teki bir key'in version'ını değiştirir. Negatif okumalar koleksiyon key'leriyle yakalanır; yanlış çakışma üretebilirler, kaçırılmış çakışma üretmezler (TI-4).

| Koleksiyon key'i | Hangi append'ler version'ını artırır | Hangi okumayı korur |
|---|---|---|
| `policies@scope(S)` | S'yi veya üst scope'u kapsayan her `policy.set` | Yeni restriction'ın kaçırılması |
| `acceptances@(issuer, use)` | O issuer/use için her `acceptance.*` | Cutoff'un kaçırılması (SI-10) |
| `claims@(subject, class)` | O subject/class için her Claim append'i (supersede, retract dahil) | Disqualification'ın kaçırılması; Claim `recorded_at` yaşı (whitelist 6) |
| `current@(issuer, subject, class)` | Issuer sırasını değiştiren her Claim append'i | Claim güncelliği (TI-RT7) |
| `holdings@party(P)` | P'nin episode'larını materyalize değiştiren her kayıt | Holder set değişikliği; selector holder geçiş sayısı (whitelist 3) |
| `instance@(I)` | `instance.*`, `mandate.*` | Terminate/rebind; cited contribution actor Instance durumu (whitelist 4) |
| `contrib@(target digest)` | Hedef digest'e her `contribute` | Contribution seçimi |
| `contracts@verifier(V)` | V için her offline/intermittent `projection.issue` ve V'nin her offline report Claim'i | SEC14 raporlanmamış contract kontrolü (whitelist 7) |
| `domain-config` | rootTerms değişikliği, `domain.*`, minimum sürüm, `schema-definition` Acceptance pin'leri | Spec/profile sürüm değişimi; mapping pin yaşı (whitelist 5) |
| `budget@(node, term, window)` | Her draw/release ve pencere-kovalı aggregate güncellemesi | Kalan miktar; Party toplamı, throttling, `projection.issue` / açık PAP sayaçları, eşik-bitişik tekrar (whitelist 1, 2, 9, 10, 11) |
| `released@(ExerciseID)`, `released@(projection)` | Her `consumption.release` | Σrelease ≤ draw (TI-RT8) |

### 16.6 Handover ve recovery — teknik akış

**Kooperatif handover (`domain.handover`).**

| Adım | İçerik |
|---|---|
| HO-1 | Eski provider **freeze**: yeni kayıt kabul etmez; freeze süresince checkpoint/cosign Claim ingest'i askıdadır |
| HO-2 | **k = head + 1** belirlenir (handover batch'inin ilk pozisyonu) |
| HO-3 | Root, rootTerms requirement'larını karşılayan `domain.handover` için AIS'ini imzalar; AIS k'yı cite eder |
| HO-4 | **C_k** (pos 0..k−1) imzalanır ve en az bir bağımsız witness cosign'ı alır; Record Export Package (zarflar + body'ler + raw evidence + checkpoint'ler, C_k'ye kadar; `basis_ref` / event-id anahtarı yalnız yeni provider'a açık biçimde) yeni provider'a verilir |
| HO-5 | Yeni provider Genesis'ten k−1'e **record-fold** yapar; Merkle kökünü yeniden hesaplayıp C_k'yi üretir ve imzalı checkpoint Claim'iyle beyan eder. Kararların yeniden değerlendirmesi doğrulamadır; fark divergence set olarak beyan edilir ve divergence quarantine uygulanır; handover durmaz |
| HO-6 | **Handover batch'i** pos k..h: inline proof Claim'leri (eski provider'ın no-write beyanı, yeni provider'ın C_k beyanı; ikisi de C_k'yi cite eder, döngü yok) + pos h'de `domain.handover` (eski provider log'unun son kaydı) |
| HO-7 | Eski provider handover kaydını kapsayan **C_{h+1}**'i eski anahtarla üretir; witness'lar C_{h+1}'i C_k'dan consistency proof'la cosign eder, yeni binding'i kayıt h'nin inclusion proof'undan öğrenir ve eski anahtarlı size > h+1 checkpoint'i cosign etmez (fencing) |
| HO-8 | Yeni provider pos k..h kayıtlarını + witness'lı C_{h+1}'i alır, fold eder ve h+1'den devam eder; Domain Metadata yeni binding'i ve eski anahtarları `superseded-at C_{h+1}` olarak yayınlar |
| HO-9 | **Handover drain**: eski-anahtarlı artefaktlar C_k bundle'ı + `consistency_path` → C_{h+1} ile doğrulanır; offline cihazlar yeniden issue alır (RT14) |

Redakte kayıtlar yalnız digest seviyesinde doğrulanır ("replay coverage" beyan edilir). Adım etiketleri (HO-1–HO-9, FR-0–FR-6, PR-0–PR-5) register ID'si değildir.

**Aynı provider profili (self-handover).** `domain.handover`'ın giden ve gelen provider kimliğinin aynı olduğu profili *binding re-anchor*'dır (OP-60, §16.6.1; adımlar RB-0…RB-6, register ID'si değildir). HO-1–HO-9 bu profilde RB farklarıyla çalışır. Fark `superseded-at` statüsünün semantiğindedir:
- **Provider geçişinde** (eski ≠ yeni provider) yukarıdaki akış aynen geçerlidir: handover predicate'i (§9.10, U27) C_{h+1}'den itibaren uygulanır ve drain (HO-9) zorunludur.
- **Aynı provider profilinde** `superseded-at C_{h+1}` **prospektiftir**; CR-45 semantiği kanoniktir. Eski binding yalnız yeni üretim (yeni excerpt, checkpoint, artefakt) için emekli olur. Daha önce issue edilmiş eski-binding excerpt'li artefaktlar T20 kabul kuralıyla kabul edilmeye devam eder. Bundle'sız klasik artefakt ancak kırılma ilanıyla (CR-45 RA-7) reddedilir. Bu, prospektif revocation ile tutarlıdır. Binding key kaybı veya ele geçirilmesi bu profilin konusu değildir; yol `domain.recover`'dır (SEC21).
- P3 ve PI-15'teki handover tanımı bu profili "aynı provider profili" olarak kapsar (§9, §6).

**Forced recovery (`domain.recover`).**

| Adım | İçerik |
|---|---|
| FR-0 | Ön koşul (FA-10): domain replica'sı witness'lanmış checkpoint'lere kadar öneki tutar (SEC23, TI-13). Replica yoksa recovery yine mümkündür: kol (ii) + beyanlı kayıp suffix |
| FR-1 | Yeni provider replica'dan log'u alır ve record-fold yapar; yeniden üretilen checkpoint kökleri bilinir |
| FR-2 | Değerlendirici-tarafı guard girdisi: yeni provider beyanlı **her** witness'tan en yeni imzalı checkpoint'i (freshness ≤ 1 saat) kendisi çeker ve recovery kararıyla aynı batch'te, kararın önünde `checkpoint` Claim'i olarak ingest eder; R* hesaplanır ve StateBasis'te cite edilir. Requester'ın getirdiği checkpoint'ler yalnız ipucudur. Quorum alınamazsa REQUIRE_ACTION |
| FR-3 | Recovery entry'sinin AIS'leriyle `domain.recover` değerlendirilir: N (SEC21); N < R* → DENY; kol (i)/(ii) ve çatallanma kuralı (SEC22). Recovery batch'i pos N'den başlar: witness Claim'leri pos N..N+w−1, `domain.recover` pos r = N+w, post-recovery quarantine `policy.set` r'den sonra |
| FR-4 | Domain Metadata: yeni binding + eski anahtarlar `superseded-at checkpoint N` |
| FR-5 | Witness'lar recovery kaydının imzalarını entry'nin C_N'deki KeyBinding'lerine karşı k-of-n doğrular, binding'i günceller ve eski anahtarlı size > N checkpoint'leri reddeder (fencing; U11). **Recovery re-anchor** (kol (ii) ve çatallanma): witness cite edilen C_N'yi kendi cosign geçmişinden (veya consistency ile) doğrular, C_N'den recovery kaydını kapsayan C''ye consistency + inclusion proof'unu doğrular ve append-only tabanını C''ye taşır; eski zincirin N ötesi "superseded" tarihsel kanıt olarak saklanır |
| FR-6 | PR-2–PR-5 (§13.6): kayıp revocation keşfi ve yeni revoke Exercise'ları |

**Witness protokolü.** Witness domain için son cosign ettiği checkpoint'i ve cosign geçmişini (size, root) saklar; yeni checkpoint'i yalnız tabanla arasındaki consistency proof doğrulanırsa ve imzalayan anahtar güncel binding'in operasyonel anahtarıysa cosign eder. Checkpoint ve cosign COSE; consistency proof RFC 9162 tipi; normatif biçim open spec'te CDDL'dir. Gossip: domain'in monitor'ü bütün witness'lardan son cosign'ları çeker; aynı `size` için farklı `root` equivocation kanıtıdır. Profil Work Protocol'ün Witness conformance profile'ıdır.

#### 16.6.1 OP-60 Aynı provider içinde binding-key rotasyonu: self-handover / binding re-anchor

**Soru (OQ-CR3, §15'ten).** T20'ye göre binding değişimi yalnız `domain.handover` / `domain.recover` ile yapılır. ML-DSA binding key'e geçiş (PQ re-anchor; §15.18 "PQ re-anchoring mekaniği", §15.17 "PQC notu") aynı provider içinde bir binding değişimidir.

**Terim ayrımı.** *Recovery re-anchor* (T17, `domain.recover`, §16.6 FR-5), *PQ re-anchor checkpoint'i* (CR-45, algoritma geçişi, adımlar RA-1…RA-7, §15.18) ve *binding re-anchor* (OP-60, aynı provider içinde binding değişimi, adımlar **RB-0…RB-6**) üç ayrı mekanizmadır. CR-45 RA-1b bu bölümdeki binding re-anchor ile yapılır. OQ-CR3 bu kararla **kapanmıştır** (§15.23).

**Karar. Statü: FROZEN TECHNICAL (akış), PD (zamanlama).** Aynı provider içinde binding-key rotasyonu, kooperatif `domain.handover`'ın **giden ve gelen provider kimliğinin aynı olduğu profili** olarak yapılır. Bunun adı *binding re-anchor*'dır. Yeni bir meta-Exercise veya authority primitive'i açılmaz. Kayıt yine `domain.handover`'dır, rootTerms requirement'larına ve root AIS'ine tabidir (HO-3). Genesis ve DomainID korunur (P3). Pozisyon ve lineage kesintisizdir.

| Adım | Self-handover profili (HO adımlarına göre fark) |
|---|---|
| RB-0 (ön koşul) | Beyanlı witness'lardan en az biri gelen binding'in algoritmasıyla (PQ re-anchor'da ML-DSA) cosign doğrulamasını Domain Metadata'da beyan etmiştir (CR-45 RA-1c). Aksi hâlde self-handover başlatılmaz (DENY `domain.handover`). Gerekçe: h+1'den sonraki checkpoint'ler cosign alamaz ve witness/replica-before-ack sınıfı ack'ler süresiz bekler |
| RB-1 (HO-1, HO-2) | Kısa freeze; k = head + 1. Freeze, k ile h arasındaki batch'in tek yazarlı olması içindir |
| RB-2 (HO-3) | Root `domain.handover` AIS'ini imzalar. Intent, gelen binding'in açık anahtarını ve algoritmasını taşır (ör. ML-DSA-65 veya hibrit; MD-3) |
| RB-3 (HO-4, HO-5) | C_k imzalanır ve ≥ 1 bağımsız witness cosign'ı alır. Record Export ve record-fold **atlanabilir**, çünkü depo aynıdır. Provider isterse fold'u doğrulama olarak çalıştırır |
| RB-4 (HO-6) | Handover batch'i k..h iki inline proof Claim'i taşır: (a) **eski binding key ile** imzalı "bu binding k'dan sonra yazmaz" beyanı, (b) **yeni binding key ile** imzalı "C_k'yi kabul ediyorum" beyanı. İkisi de C_k'yi cite eder. Kayıt h `domain.handover`'dır. Böylece geçiş **çift imzalıdır**: eski ve yeni binding aynı C_k'ye bağlanır |
| RB-5 (HO-7) | C_{h+1} eski operasyonel anahtarla üretilir. Witness'lar onu C_k'dan consistency proof'la cosign eder, yeni binding'i kayıt h'nin inclusion proof'undan öğrenir ve eski binding altında size > h+1 checkpoint'i cosign etmez (fencing, HO-7 ile aynı) |
| RB-6 (HO-8, HO-9) | h+1'den itibaren yeni binding'in operasyonel anahtarlarıyla devam edilir. Domain Metadata eski anahtarları `superseded-at C_{h+1}` olarak yayınlar. Drain HO-9 gibidir. Bu profilde `superseded-at` **prospektiftir** (CR-45 semantiği kanoniktir): eski binding h+1'den sonra yeni excerpt, checkpoint veya artefakt üretimi için kabul edilmez (RB-5 witness fencing; verifier'da T20 penceresi). C_{h+1}'den önce issue edilmiş eski-binding excerpt'li artefaktlar (PAP, receipt, token) T20 kabul kuralıyla (`min(horizon, iat + yerel tavan)`, excerpt `validUntil`) kabul edilmeye devam eder; inclusion bundle istenmez. Handover predicate'inin bundle şartı (§9.10, U27) ve bundle'sız klasik artefaktın reddi ancak kırılma ilanıyla (CR-45 RA-7) devreye girer. Bu yüzden "Drain HO-9 gibidir" ifadesi şöyle okunur: drain bu profilde re-anchor anında zorunlu değildir; bundle üretimi ve çevrimdışı cihazların yeniden issue'su RA-7'den **önce** planlanır (RR-35) |

**Gerekçe.** Witness fencing'i (eski binding'in size > h+1 checkpoint'ini reddetmek) ve root yetkisi zaten `domain.handover`'da vardır. Aynı provider durumunda farklı olan yalnız veri taşımanın gereksiz olmasıdır. Bu yüzden ayrı primitive gerekmez. Çift imza, eski anahtarın yeni anahtarı yetkilendirdiğini bağımsız witness'ın tanıklığıyla log'a bağlar.

**Garanti.**
- Yeni binding'in root tarafından yetkilendirilmiş olması BS'dir (meta-Exercise, AIS).
- Eski binding'in h+1'den sonra kabul edilmemesi UDC'dir (≥ 1 dürüst witness, FA-9; K-7 kuralı). Kapsam: eski binding altında h+1'den sonra yeni checkpoint, excerpt veya artefakt üretiminin kabul edilmemesidir (prospektif). Önceden issue edilmiş artefaktlar kırılma ilanına (CR-45 RA-7) kadar T20 kuralıyla kabul edilir. Bu bir sınıf değişikliği değil, kapsam beyanıdır. Aynı artefakt için OP-60 ve CR-45 aynı kabul sonucunu verir.
- **Sınır, HL-34:** Re-anchor anında eski (klasik) binding key zaten kırılmış veya ele geçirilmiş sayılıyorsa (CRQC senaryosu), eski anahtarın çift imzası sürekliliği kanıtlamaz. Bu durumda süreklilik yalnız re-anchor'dan önce alınmış witness zaman sabitlemesine dayanır: "existed by T" (FA-5, U21). Koşul: süreklilik yalnız kırılmadan önce alınmış **PQ** witness cosign'lı bir re-anchor checkpoint'ine (CR-45) ve verifier'ın o PQ anahtarlarına kırılmadan önce güvenmiş olmasına dayanır (FA-5, U21); aksi NG (RR-35). Kırılmadan sonra klasik witness cosign'ı da sahtelenebilir; yalnız klasik cosign'lı sabitleme sürekliliği kanıtlamaz. Kırılmadan sonra yapılan bir re-anchor sahte bir eski-binding imzasından ayırt edilemez. Bu nedenle re-anchor **kırılmadan önce** yapılmalıdır. Zamanlama tetikleyicisi §15.17/§15.18'dedir. Binding key kaybı veya ele geçirilmesi durumunda yol self-handover değil `domain.recover`'dır (SEC21).

**Kaynak.** HO-1–HO-9 (bu bölüm); T20; MD-3; §15.17, §15.18; OQ-CR3 (kapandı); CR-45 (semantiği kanonik).

### 16.7 Failure contracts

**Technical.** Her arıza için sistemin dürüst davranışı. "Ne olmaz" sütunu garantidir (sınıfı parantezde).

| Arıza | Sistem ne yapar | Ne olmaz | Kullanıcıya |
|---|---|---|---|
| Leader çöker (commit öncesi/sonrası) | Yeni epoch; retry aynı nonce | Çift Exercise (BS, TI-8) | "Checking…" (CL-1) |
| DB primary failover | Sync standby promote | Ack'li kayıp (UDC, FA-1) | Kısa gecikme |
| Region kaybı | Fence + replica tamamlama veya recover | İki yazar (UDC, FA-13) | "Unavailable" |
| Zaman kaynakları uyuşmaz | Commit durur | Erken genişleme, uzayan horizon (UDC, K-2) | "Unavailable — time check" |
| Zaman kaynakları topluca yalan | Witness çapraz kontrolü yakalarsa durur | — (HL-6, NG) | — |
| Sessiz depolama bozulması (tespit edilmemiş) | Tespit edilene kadar sistem bilmez | — (tespit öncesi yanlış karar NG, N-29) | — |
| SYNC-DERIVED / depolama bozulması tespit edildi | Commit durur; Genesis'ten fold (TI-RT1) hakem | Bozuk satıra dayalı karar (tespitten sonra; UDC, FA-14, U30) | "Unavailable" |
| Kayıt bozulması | Commitment-eşleşen kopyadan geri yükleme | Log'un içerik değişimi (BS, TI-RT11) | — |
| Rebuild-diff farkı | Fold farkı: commit durur, Genesis'ten fold hakem. Yeniden değerlendirme farkı: K-1 divergence prosedürü (beyan + quarantine), canlı tablo ezilmez, commit durmaz | Derived'ın canonical'ı ezmesi; hakemin kayıtlı DecisionRecord effect'ini ezmesi (BS, TI-RT1/TI-RT4) | Fold farkında "Unavailable" |
| Derived kesintisi | Commit sürer; status yayını durur | Taze imzalı stale status (BS, G43) | Okumalar gecikir |
| Witness kesintisi | Revocation etkili, ack bekler | Ack'siz "confirmed" (BS, SEC23 + CL-2) | "Confirming" |
| HSM kesintisi | Kayıt commit, imza gecikir | Imzasız artefakt (BS, TI-12) | Artefakt gecikir |
| Toplu meta-Exercise | O(1) commit; tembel episode | Domain kilidi (UDC — ENGINEERING iş sınırı; K-10) | Normal |
| Hot domain/hot key | Retry/rejection | Commit'siz ALLOW (BS, TI-9) | "Busy — retry" |
| Yeniden değerlendirme farkı (handover / recover / rebuild-diff) | Divergence set beyanlı; divergence quarantine (genişletici effect'ler DENY; kaldırma CT3); geçiş sürer | Farkın çıkışı durdurması (BS, G32, TI-RT1); çıkışın kendisi UDC (U24 / handover işbirliği) | Root'a karar listesi |
| Forced recovery | N sonrası kayıp beyanlı; nonce'u lineage'da olmayan pre-recovery AIS DENY | Kayıp act'in tekrarı (UDC — quarantine policy + trusted time, FA-3/K-2; K-3) | "Changes after N may be lost; repeat revocations; re-sign pending requests" |
| Eski provider stale metadata yayınlar | Verifier ≤ Δ + cadence sonra fail closed | Süresiz eski lineage (UDC, K-5) | — |
| Kooperatif handover | `superseded-at C_{h+1}` + handover predicate'i (§9); drain. Aynı provider profilinde (OP-60) `superseded-at` prospektiftir, predicate'in bundle şartı kırılma ilanıyla (CR-45 RA-7) | Lineage dışı eski-anahtarlı kabul (UDC, K-7; kurala uymayan verifier'da `validUntil + yerel tavan` ile sınırlı, U25/N-26) | Offline cihazlar yeniden issue |
| İstemci timeout | Aynı nonce'la retry; commit edebilen retry intent validity penceresiyle sınırlı (pencere sonunda sonuç sabit); pencere sonrası aynı-nonce isteği yalnız sonuç sorgusu (commit edemez; lookup arşivi kapsar) | Çift etki (BS, TI-8); kuyruklu/pending revoke (UDC, U31); kayıtlı revoke için "Not recorded" (XI-12) | "Not confirmed — checking" (Access cevabına kadar; HL-5) → "Revoked — confirming (witness pending)" / "Revoked", veya nonce devam eden lineage'da (arşiv dahil) yoksa "Not recorded — try again" (CL-1) |
| Claim burst | Kota → ingest quarantine yalnız qualifying etkiye; narrowing öncelikli ve kota dışı | Kota üstü episode (BS, G44) | Issuer'a bildirim |
| Sırasız Claim | Issuer sırası | Eski iddianın episode açması (BS, K-8) | — |

**Semantic.**

| Semantik arıza | Dürüst davranış | Sınıf |
|---|---|---|
| Provider yanlış karar verir | Tespit (yeniden değerlendirme, bağımsız implementasyon); divergence beyanı; çıkış açık | Önleme NG (HL-2, N-13); tespit UDC (U13); divergence'ın çıkışı durdurmaması BS (G32, TI-RT1); çıkışın kendisi UDC (U24 / handover işbirliği) |
| Spec ↔ implementasyon ayrışması | Spec kazanır; yeni `versions`; geçmiş tarih kalır | BS (TI-RT12) — vektör kapsamı HL-12 |
| Issuer yalan söyler | Radius = Acceptance kapsamı; cutoff | NG (N-1), radius BS (SI-3) |
| Issuer sırası belirsiz | Disqualifying kazanır | BS (TI-RT7) |
| Release kötüye kullanımı | Σ ≤ draw | BS (TI-RT8) |
| Kayıp suffix | Beyan; nonce'u lineage'da olmayan pre-recovery AIS tekrar edilemez | Kayıp NG (N-14); tekrar yokluğu UDC (TI-RT3; quarantine policy + trusted time) |
| Örtük bilgi (pozisyon, event id) | Opaque token; HMAC | BS (TI-RT10); Merkle index HL-10 |
| Lineage dışı imza | Witness tazeliği + inclusion | UDC (TI-RT5, K-7); bütün witness'lar kötü NG |
| Başka domain'in anahtarı | Excerpt DomainID | BS (TI-RT6); partition korelasyonu HL-8 |
| UI'ın bilinemeyeni bildirmesi | "Not confirmed — checking" Access cevabına kadar; "witness pending"; "Not recorded" yalnız nonce devam eden lineage'da (arşiv dahil) yoksa | Metin BS (CL-1/CL-2); sonucun pencere sonunda sabitlenmesi UDC (K-3); sonucun öğrenilmesi NG (HL-5) |
| Sessiz depolama bozulması | Tespit edilene kadar bilinmez; tespitte commit durur ve Genesis'ten fold hakemdir | Tespit öncesi NG (N-29); tespit sonrası UDC (U30); log içeriğinin değişmemesi BS (G34) |

#### 16.7.1 Identity plane failure contract'ları

Yukarıdaki tablo authority plane içindir. Identity plane'in arıza davranışı aşağıdadır. Ayrıntılı kurallar §17'dedir (OP-24–OP-29, OP-45).

| Arıza | Davranış | Garanti |
|---|---|---|
| PG primary failover (aynı cluster, sync standby promote) | Token endpoint'i yazma gerektiren grant'lerde **503 + `Retry-After`** döner, asla `invalid_grant` dönmez (client refresh token'ını atmasın). Havuz hızla tahliye edilir; yeniden bağlantı `target_session_attrs=read-write` ile yapılır. Kaynak zaman çizelgesi yaklaşık 25 s'dir (üçüncü taraf kaynak, ölçüm değil) | Ack edilmiş identity yazmalarının korunması UDC (FA-1, ≥2 standby; small-provider profilinde NG, OP-48, HL-40); kesinti süresi NG |
| Sync standby'lerin tümü yok | Primary yazma yapamaz (`ANY 1` bekler); identity plane yazma gerektiren işlemlerde 503 + Retry-After; okuma ve imzalı token doğrulaması sürer | Ack edilmiş yazma kaybı yok UDC; availability NG |
| Node-yerel epoch cache stale | Cache bir *pozitif* hızlandırıcıdır. Cache-miss her durumda primary'ye sorar; DB'ye ulaşılamazsa istek reddedilir (MD-7, MD-8) | "Cache-miss = iptal edilmemiş" çıkarımı yapılmaz: BS (OPI-3). Doğruluk kaynağına ulaşılamazken cache-hit de "iptal edilmemiş" kanıtı değildir (OPI-3 genişletilmiş; OP-45) |
| Identity DB tamamen erişilemez | Bozulmuş mod (OP-45): önceden imzalı, ömrü beyan edilmiş self-contained token'lar RS'te ömürleri boyunca doğrulanır; yeni login, refresh, introspection ve revocation reddedilir. Yeni login, refresh ve revocation 503 + `Retry-After` ile reddedilir (asla `invalid_grant`). Primary'ye veya tazelik kaynağına ulaşılamıyorsa introspection her token için `active=false` döner; cache-hit dahildir; 503 dönmez (OP-45 kural 3; §14.8; §13.11) | Token ömrü içinde iptalin RS'e ulaşmaması NG (HL-22); fail-open yok BS |
| Identity bölge kaybı (regional, async DR profili) | DR promote yalnız beyan edilmiş RPO>0 profilinde yapılır; promote sonrası bütün session/refresh epoch'ları artırılır, herkes yeniden login olur | Kayıp penceresindeki identity yazmaları NG (HL-31); authority plane'e etkisi yalnız Claim girdisidir (TI-15) |
| Identity plane kesintisi → authority plane | Yeni `authentication` Claim'i yok → ilgili RequirementTerm karşılanmaz → REQUIRE_ACTION/DENY; cihaz-bağlı KeyBinding'li Instance'lar AIS imzalamaya devam eder (E25) | BS (fail-closed) |
| Argon2 havuzu dolu | Kapasite shedding: 503 + `Retry-After` (OP-33, OP-36). Hesap ve istemci başına limit aşımı: 429 | Doğru parola için kesinti NG; bypass yok BS |
| Identity signer (CMP-22b) erişilemez | Token üretimi durur, 503; signer'sız imza yolu yoktur | Fail-closed BS |

### 16.8 Red-team sonucu

**Verdict: HOLDS AFTER CORRECTIONS.** Hiçbir saldırı bir frozen invariant'ın semantiğinin yanlış olduğunu göstermedi; model-level break yoktur. Red-team **13 kırılma (K-1–K-13) + 2 cross-layer (CL-1, CL-2)** buldu, hepsi düzeltildi; düzeltmeler mevcut mekanizmalarla (technical fix, POLICY DEFAULT, profile kuralı, metin) yapıldı ve bu spesifikasyonun gövdesindedir.

| Bulgu | Konu | Canonical düzeltme |
|---|---|---|
| K-1 | Yeniden değerlendirme farkının handover/recovery'yi durdurması (hostage); implementasyonun spec yerine geçmesi | Record-fold; doğrulama kapı değil; divergence quarantine; normatif = L0/L2 + vektörler (TI-RT1, TI-RT12, RT3) |
| K-2 | Fark edilmemiş saat sıçraması | İki bağımsız zaman kaynağı + sınırlı ilerleme + witness çapraz kontrolü (TI-RT2) |
| K-3 | Kayıp suffix'teki AIS'in yeni lineage'da tekrar Exercise açması | İlk-commit AIS yaşı ≤ intent validity tavanı + SEC22 R1 `nonce-closed/pre-recovery` (quarantine policy'si CT3 ile kaldırılır) (TI-RT3, RT6, RT7) |
| K-4 | Derived snapshot'ın SYNC-DERIVED'ı ezmesi | Yalnız canonical-taraf kaynak; rebuild-diff farkı commit durdurur veya divergence prosedürüne gider (TI-RT4) |
| K-5 | Kendi beyanlı metadata tazeliği | Bağımsız witness cosign tazeliği + heartbeat (TI-RT5) |
| K-6 | Operasyonel anahtar excerpt'inde DomainID yokluğu | Excerpt'e DomainID; domain-başı operasyonel anahtar (TI-RT6) |
| K-7 | Handover sonrası eski anahtar statüsü | `superseded-at C_{h+1}` + predicate + drain (U27, RT13) |
| K-8 | Varış sırasıyla Claim güncelliği | Issuer sırası (TI-RT7) |
| K-9 | Release'in draw'u aşması | Σrelease ≤ draw (TI-RT8) |
| K-10 | Toplu meta-Exercise'ın domain'i kilitlemesi | O(1) işaret + tembel episode (TI-RT9) |
| K-11 | Sessiz depolama bozulması | Kayıt kimliği = commitment; FA-14 (TI-RT11) |
| K-12 | Pozisyon ve event id sızıntısı | Opaque token + HMAC (TI-RT10) |
| K-13 | Normatif kuralların kodda kalması | L0/L2 + vektör kapsamı (TI-RT12, RT22) |
| CL-1 | UI'ın timeout'ta sonucu bilir gibi konuşması | "Not confirmed — checking" + aynı-nonce retry (RT23) |
| CL-2 | Ack edilmemiş durumun ack edilmiş gibi gösterilmesi | `witnessed_through` + "confirming (witness pending)" (RT24) |

### 16.9 Known Hard Limits (HL-1–HL-14)

- **HL-1** Domain başına throughput tek sequencer'la sınırlı; hot key seri
- **HL-2** Provider/operatörün yanlış kararı önlenemez
- **HL-3** Offline pencerede revocation etkisi gecikir
- **HL-4** Forced recovery'de kayıp suffix (slice çift harcaması dahil)
- **HL-5** İstemci timeout'ta sonucu Access'ten cevap gelene kadar bilemez; commit penceresi yalnız sonucu sabitler (UDC, K-3), bilgiyi sınırlamaz
- **HL-6** Bütün zaman kaynakları + witness'lar birlikte yalan söylerse zaman-bağlı terimler kayar
- **HL-7** Equivocation önlenemez, yalnız tespit edilir
- **HL-8** Paylaşılan HSM partition'ındaki domain'ler korelasyonlu ihlal; Storm-0558 sınıfı (kapsam dışı anahtarın kabulü) bu sınıra eklenir — verifier DomainID'yi must-understand olarak denetler
- **HL-9** Fiziksel silme (redaksiyon ≠ erase); dağıtılmış kopyalar
- **HL-10** Inclusion proof'taki Merkle index pozisyonu gösterir
- **HL-11** Status list herd privacy liste boyutuyla sınırlı
- **HL-12** Çapraz-implementasyon determinizmi vektör kapsamı kadar; Claim'den SYNC-DERIVED türetim farkı (episode, currency) kayıtta görünmez, yalnız etkilenen ilk sonraki DecisionRecord'un yeniden değerlendirmesinde divergence olarak beyanlanır
- **HL-13** Revocation çalışan effect'i durdurmaz
- **HL-14** TEE/SE yan kanalları; secure clock donanım yalanı

#### 16.9.1 Identity plane ve operasyon hard limit'leri (HL-31–HL-34, HL-40)

HL-1–HL-14 yukarıdadır. Identity plane ve operasyon aşağıdaki sınırları ekler. Kanonik HL listesi §13.5'tir; HL-31…HL-34 ve HL-40 orada da satır olarak yer alır. Identity plane token ömrü sınırı HL-22'dir (§13.5) ve aşağıda hatırlatılır. RT28 ve B15'in "hard limit ürün vaadine giremez" kuralı bu listenin tamamına uygulanır.

- **HL-22** (§13.5) Identity plane'in self-contained JWT access token'ı RS'te ömrü boyunca geçerli kalabilir. Session/epoch iptali introspection yapmayan RS'e token ömrü dolana kadar ulaşmaz (gecikme bütçesi: "RS = token ömrü"). Varsayılan ömür §10'dadır. Authority projection token'larında bu sınır ValidityContract ve status list ile beyan edilir (HL-3).
- **HL-31** Identity plane'in async DR profilinde (tek bölge + async kopya) RPO > 0'dır. Promote sonrası kayıp penceresindeki login, kayıt ve kimlik bilgisi değişiklikleri kaybolabilir. Epoch artırımı oturumları güvenli tarafa çeker, kayıp veriyi geri getirmez (OP-29).
- **HL-32** Identity plane'de kiracı veya realm bazında, satır düzeyinde geri yükleme yoktur. Kurtarma ancak cluster PITR'i ile ayrı bir ortama yapılıp seçici veri aktarımıyla olur. Authority plane'de domain düzeyinde yeniden kurma vardır (OP-59).
- **HL-33** PostgreSQL superuser'ı, `BYPASSRLS` rolü veya tablo sahibi DB düzeyindeki koruma katmanlarını (RLS, append-only trigger'ları) atlatabilir. Bu tür bir değişiklik authority log'unda zincir, Merkle, witness ve replica karşılaştırmasıyla tespit edilir (G34, FA-14). Identity denetim log'unda Merkle checkpoint yayınından önceki pencerede tespit edilmeyebilir (OP-37, OP-38). Önleme UDC'dir (operatör rol ayrımı), tespit dış tanığa bağlıdır.
- **HL-34** Aynı provider içinde binding re-anchor (OP-60, §16.6.1) eski binding key kırılmadan veya ele geçirilmeden önce yapılmalıdır. Kırılmadan sonra eski anahtarın çift imzası sürekliliği kanıtlamaz; süreklilik yalnız önceden alınmış witness zaman sabitlemesine dayanır (FA-5, U21). PQ geçişinin zamanlaması bu sınıra tabidir (§15.17, §15.18). Kesin koşul: süreklilik yalnız kırılmadan önce alınmış **PQ** witness cosign'lı bir re-anchor checkpoint'ine (CR-45) ve verifier'ın o PQ anahtarlarına kırılmadan önce güvenmiş olmasına dayanır (FA-5, U21); aksi NG (RR-35). **Kırılmadan sonra klasik witness cosign'ı da sahtelenebilir**; yalnız klasik cosign'lı sabitleme sürekliliği kanıtlamaz. Re-anchor öncesi pencere riski RR-35'tir (§15.18); HL-34 ve RR-35 aynı koşulu söyler.
- **HL-40** Small-provider (single-node) profilinde FA-1 karşılanmaz: ack edilmiş yazma node veya disk kaybında kaybolabilir (NG). Authority plane'de witness/replica-before-ack sınıfı (SEC23, T18, T21) korunur; kayıp suffix `domain.recover` ile ele alınır (FA-10, U24). Identity plane'de OPI-4 bu profilde geçerli değildir. Profil Domain Metadata'da ve realm DR beyanında `durability: single-node` olarak yayımlanır (OP-48). Bu profilde garanti satırları UDC yerine bu HL ile beyan edilir.

### 16.10 Frozen technical decisions (T1–T42)

Bu register T-kararlarının **tek kanonik kopyasıdır**. §12 ve §15'teki kopyalar "→ §16.10 Tn" atfına ve bölüme özgü açıklamaya iner. Çelişkide bu metin kazanır.

- **T1** Verdict ARCHITECTURE PRESERVES MODEL WITH DECLARED ASSUMPTIONS; varsayımlar FA-1–FA-14 (§16.2).
- **T2** İki canonical depo: AuthorityDomain log'u (+ committed body'ler) ve Identity plane store'u; her bileşen CANONICAL / SYNC-DERIVED / DERIVED / PROJECTION / OPERATIONAL etiketlerinden tam birini taşır.
- **T3** Domain başına tek append-only log; bütün kayıtlar (Claim dahil) tek total order'da; prev hash chain + Merkle ağacı; DomainID = genesis digest'i.
- **T4** Kanonik tek kodlama + projection: deterministic CBOR + CDDL; wire'da standart biçimler; imzalı bayt'lar aynen.
- **T5** Kripto suite: SHA-256; Ed25519 + ES256; COSE_Sign1 / JWS; TLS 1.3; PKCS#11/KMIP. Varsayılanlar: COSE authority kayıtları Ed25519 (ES256/ESP256 zorunlu doğrulama); JOSE projection'ları ES256 (Ed25519 seçmeli); FIPS profili her yerde ES256/ESP256; RS256 yalnız identity plane client başına opt-in, authority artefaktları asla RSA değil; SAML rsa-sha256 ekosistem istisnası; ML-DSA-65 opt-in. Tanımlayıcılar RFC 9864 fully-specified; JWS'te `alg: EdDSA` reddedilir; allowlist header'dan değil metadata'dan. Kripto kütüphanesi aws-lc-rs (MD-1). Ayrıntı §15. Kanonik metin (§15.2.1): digest SHA-256, algoritma etiketli (CR-1); imza tablosu MD-3; tanımlayıcılar RFC 9864 fully-specified, JWS'te `alg: EdDSA` reddedilir (CR-5); kabul kümesi: ES256 (-7) zorunlu doğrulamadır, WebAuthn assertion algoritmaları WebAuthn kurallarına göre kabul edilir, "fully-specified" kuralı imza üretimi ve yeni artefaktlar içindir; kaplar COSE_Sign1 / JWS (T24); TLS 1.3, X25519MLKEM768 hibrit anahtar değişimi tercih edilir (CR-12); kripto kütüphanesi aws-lc-rs (MD-1, CR-13); HSM erişimi PKCS#11 (`cryptoki`), **KMIP WATCH** (CR-28); FIPS profili domain veya realm başına (CR-15). PQ notu: ML-DSA-65 opt-in, JWKS'te `AKP` gün-1'de modellenir (MD-3); ekleme CT3'tür (CR-8); ayrıntı §15.17.
- **T6** Domain başına tek sequencer, epoch fencing, optimistic read-set validation (koleksiyon key'leri dahil), head CAS.
- **T7** Commit batch = tek transaction: kayıtlar + sync-derived + outbox + head CAS; batch'leme semantik atomiklik değildir.
- **T8** PostgreSQL canonical + derived cluster'ları, cell başına. Asgari sürüm PostgreSQL 18 (§16.4 OP-7); replikasyon ayarı §17 OP-24.
- **T9** SYNC-DERIVED yalnız commit-mode girdileri içindir ve her commit-mode girdisi canonical veya SYNC-DERIVED'dır: nonce, version key'leri, budget sayaçları, `released@` sayaçları, single-use, episode'lar, rolling aggregate'ler, güncel authority satırları, per-verifier açık contract / report durumu (SEC14), issuer kota sayaçları (yalnız qualifying etkiyi sınırlar; narrowing sınıfı sayaç dışı). Claim ingest disposition (admit / ingest quarantine) canonical header alanıdır; kota nedeniyle ingest quarantine'e alınan bir Claim'in narrowing etkisi uygulanır.
- **T10** Commit-mode kararlar yalnız leader'da; evaluation async derived store okumaz; fail-closed matrisi bağlayıcıdır.
- **T11** Read-path consistency sınıfları (strong / at_least / as_of). `basis_ref` = (DomainID, q−1, version-vector digest) audit scope'ta açıktır; audit kapsamının altındaki viewer'a pozisyon taşıyan her tanımlayıcı opaque anahtarlı token olarak gider (TI-RT10). Derived okuma cevapları `witnessed_through` taşır.
- **T12** Normatif tanım L0/L2 spec + conformance vektörleridir (RT8, TI-RT12). Access Core'un saf çekirdeği open-source **Rust `no_std` Access Kernel crate'idir (CMP-24)**; sunucu, offline verifier, edge/Wasm ve mobil FFI aynı kodu kullanır; Suiss production onu kullanır. Differential oracle, Lean yürütülebilir modeli (**planlı**; henüz yazılmadı) ve o hazır olana kadar naif F0 reference evaluator'dır (CR-49; §15.19.1). Yayınlanmış her semantik sürümün evaluator'ı korunur (RT8; sürüm emekliliği yok); B12 ayrı bir ticari taahhüttür.
- **T13** Restriction dili **Cedar'ın forbid-only alt kümesidir**: sabit taban `permit`, kullanıcı politikaları yalnız `forbid`; REQUIRE, forbid politikasına bağlı RequirementSet referansıyla ifade edilir; Lean'de kanıtlı özellikler, SMT eşdeğerlik analizi, Rust-native gömme (CMP-24). policy.set sınıflandırması yapısal, muhafazakâr ve mekanik doğrulanmış kalır; yazar beyanı yalnız çapraz kontrol (uyuşmazlık DENY), kanıtlanamayan parametre değişikliği genişletme sınıfı. Spike başarısız olursa (OQ-MD2) yedek tasarım geçerlidir: Access Restriction Profile = CEL alt kümesi, forbid-only, statik maliyet, determinism kuralları, parametre polaritesi CEL AST'den statik türetilir, artı SMT eşdeğerlik analizi. ReBAC graf indeksi ve sorgu motoru CMP-9/CMP-11'dedir ve commit-mode ALLOW üretmez (MD-4).
- **T14** Requirement Resolver'ın kanonik seçimi: birden çok tatmin eden proof kümesinde en erken pozisyonlu.
- **T15** Semantik timer yoktur (TI-10).
- **T16** Checkpoint = (domain, size, Merkle root, head leaf, recorded_at, version vector digest), operasyonel anahtarla COSE; cadence 60 s / 1,000 kayıt + out-of-cycle; state commitment yok. Cadence checkpoint'i (60 s, POLICY DEFAULT) değişiklik olmasa da üretilir (heartbeat), log'a kayıt olarak ingest edilir ve witness'lara gönderilir (log pozisyonu ve `recorded_at` ilerler; handover freeze'inde askıda); TI-RT5 tazeliğinin ve sessiz domain'de status list `iat` tazelenmesinin kaynağıdır.
- **T17** Witness protokolü: consistency-proof doğrulayan, binding-farkında, Genesis recovery entry'sini ve cosign geçmişini saklayan cosign'cılar; geçerli domain.recover kaydında recovery re-anchor (cite edilen C_N → recovery kaydını kapsayan checkpoint; eski dal superseded kanıt; eski anahtarla size > N cosign yok); gossip ile equivocation kanıtı; Work Witness profile'ı ortak.
- **T18** Witness/replica-before-ack (SEC23): kapsayan checkpoint'e kadar önek replica'ya → out-of-cycle checkpoint → ilk bağımsız cosign → ack; revocation commit anında etkilidir, yalnız ack bekler.
- **T19** Inclusion proof bundle: artifacts payload digest'i + leaf çekirdeği + yalnız artifacts alanının açılışı + kardeş alan commitment'ları + Merkle path + witness'lı checkpoint N (+ opsiyonel consistency_path); recovery durumunda N = cite edilen N_cited veya consistency proof'la onun öneki, N_cited Domain Metadata'dan; leaf salt'lı alan commitment'larına, proof bayt'ları proof_commit digest'lerine bağlıdır → bundle seçici açıklamayı ve undisclosed kuralını delmez, redakte export'tan leaf/zincir/Merkle yeniden hesaplanır.
- **T20** Provider anahtar hiyerarşisi: HSM'de quorum'lu binding key, ≤ 24 saat domain-başı operasyonel anahtarlar, artefakta gömülü binding-imzalı excerpt {DomainID, kid, alg, validFrom, validUntil, usage} (verifier DomainID eşleşmesi ister; TI-RT6); pencere imza zamanını (`iat`) sınırlar ve verifier'da must-understand'dir; yeni operasyonel anahtarın validity başlangıcı aktivasyondan en az status-list derived gecikme tavanı kadar önce beyan edilir; kabul süresi min(horizon, iat + yerel tavan), tavanlar yalnız Domain Metadata / Verifier Profile'dan (`cap_horizon`: CT gerçekleştirilen intent'ten, class/variant Verifier Profile'dan; artefaktın beyanı kullanılmaz); HSM partition paylaşımı beyan edilir (FA-8 eki); binding değişimi yalnız `domain.handover` / `domain.recover`. Operasyonel anahtar varsayılan ömrü 1 saat, üst sınır 24 saat (PD); operasyonel anahtar ayrı signer sürecindedir (CMP-22a: ağ syscall'ı yok, Landlock/seccomp, yalnız key store okuma, `memfd_secret`); FIPS profilinde HSM'dedir. Identity plane: realm başına JOSE anahtar seti (1 aktif + N pasif, publish-before-use, ayrı KMS anahtarı; CMP-22b). Binding key kapsamı Domain Metadata'da beyan edilir. Aynı provider içinde binding rotasyonu §16.6.1 OP-60 (self-handover profili). Identity plane'in realm JOSE anahtar seti bu hiyerarşiden ayrıdır ve authority projection'ı imzalamaz. Aynı provider içinde binding rotasyonunda eski binding'in `superseded-at`'i prospektiftir (OP-60 RB-6; CR-45 semantiği).
- **T21** Replica mirror: domain'in beyan ettiği provider-dışı replica'ya sürekli CBOR sequence; mirror-before-witness (TI-13; SEC23 replica-before-ack önek'inin güçlü biçimi); Suiss-hosted şablonu witness ile birlikte replica beyanını zorunlu tutar (TI-13).
- **T22** Handover/recovery teknik akışları §16.6'tedir. Devralan provider state'i record-fold ile kurar (TI-RT1); q−1 yeniden değerlendirmesi doğrulamadır, kapı değildir; divergence set StateBasis'te beyan edilir ve divergence quarantine uygulanır. `domain.handover` = eski provider freeze (checkpoint Claim ingest'i askıda) → k = head + 1 → root AIS'i (k'yı cite eder) → witness'lı C_k → handover batch'i pos k..h (inline proof Claim'leri + pos h'de handover kaydı, eski provider'ın son kaydı; C_k'yi cite eder) → yeni provider witness'lı C_{h+1} ile h+1'den devam; eski anahtarlar `superseded-at C_{h+1}`; handover drain. `domain.recover` = değerlendirici-tarafı witness + replica sorgusu (aynı batch'te ingest, R*), N (SEC21), N < R* DENY, kol (ii) REQUIRE_ACTION + beyanlı kayıp suffix, çatallanma kuralı (SEC22); yeni provider'da recovery batch'i pos N'den; witness fencing + recovery re-anchor.
- **T23** Claim ingest hattı: carrier adapter'ları, issuer authentication, normalize, minimize, dedup, kota, sequencer append; Acceptance otoriter olarak evaluation'da; ingest disposition (admit / ingest quarantine) canonical header alanı, ingest quarantine'deki Claim'in qualifying etkisi karar/episode girdisi değildir; kota yalnız qualifying etkiyi sınırlar, narrowing sınıfı Claim ingest'i kota nedeniyle reddedilmez veya ingest quarantine'e alınmaz (yalnız SI-20); Claim currency issuer sırasıyladır (TI-RT7); inline proof'lar aynı batch'te, kendi pozisyonlarında; ingest decision path'ten sınırlı öncelikle yalıtılır: narrowing sınıfı Claim'ler commit'lerle aynı/üst öncelikte, diğer ingest için asgari pay + kuyruk yaşı tavanı.
- **T24** Projection: imza commit'ten sonra, digest commit'ten önce; receipt COSE/JWS; token RFC 9068 + RAR; PAP COSE/CWT kanonik + SD-JWT profili; Token Status List derived'dan, iat/as_of = yansıtılan pozisyonun recorded_at'i (derived gecikmesi Δ'yı tüketir, uzatmaz); introspection at_least = head ile.
- **T25** Offline Verifier Core = Access Kernel crate'i (CMP-24; Rust `no_std`) + platform adaptörleri (FFI/Wasm); secure element/TPM sayaç, imzalı zaman + monotonic süre, chained report, grup sayaç servisi; yerel kabul kuralı (anahtar penceresi + yerel horizon/slice tavanları, Reference Verifier ile ortak test vektörleri). Sunucu ile verifier aynı kernel kodunu çalıştırır.
- **T26** Events: transactional outbox → NATS JetStream → SSF transmitter; event id domain başına anahtarlı HMAC'tir (TI-RT10); sıra garantisi yok. Self-host küçük formda NATS opsiyoneldir, polling yeterlidir; LISTEN/NOTIFY ve Redis pub/sub taşıyıcı olarak yasaktır (§17 OP-19, OP-23).
- **T27** AuthorityDomain = yerleşim, izolasyon ve shard birimi; tenant semantik değildir; domain başına KEK, body başına DEK; kotalar protocol rejection. Eksenler Tenant / AuthorityDomain / Identity Realm / Cell; savunma derinliği gün-1'den: PK'de `tenant_id` (+ `domain_id` / `realm_id`), bileşik FK, RLS FORCE + NOBYPASSRLS + `SET LOCAL` (§17 OP-12). `tenant_id` hiçbir authority kararına girdi değildir. Kanonik metin: AuthorityDomain = authority semantiğinin, yerleşimin, izolasyonun ve shard'ın birimidir; tenant semantik değildir ve hiçbir authority kararına girdi değildir. Tenant ticari eksendir, Identity Realm identity plane eksenidir, Cell fiziksel yerleşimdir (MD-5 dört eksen tablosu). Domain başına KEK, body başına DEK; kotalar protocol rejection'dır ve domain **ve** tenant boyutunda tutulur. Savunma derinliği gün-1'den vardır ve PK kapsam önekiyle başlar: authority canonical log ve kayıtları `domain_id` ile anahtarlanır (domain tek tenant'a aittir; tenant ↔ domain eşlemesi placement directory'de (CMP-26) ve ticari tablolarda tutulur ve değişebilir; append-only log ticari hesap değişince yeniden anahtarlanamaz, OP-17); `tenant_id` + RLS FORCE identity plane, derived, PII vault ve operasyon tablolarında zorunludur (identity tablolarında + `realm_id`); ticari tablolarda `tenant_id`. Bileşik FK, RLS FORCE, NOBYPASSRLS ve `SET LOCAL` her depoda geçerlidir (§17 OP-12).
- **T28** Multi-region: domain'in aynı anda tek yetkili cell/epoch'u; active-active canonical yazma yok; cell/bölge değişimi Work HANDOFF/ACCEPTANCE + epoch CAS; async kopya promote edilmez; plansız devam yalnız kanıtlanmış fence + eski son head'in tam kapsanmasıyla, aksi domain fail-closed ve domain.recover (FA-13); RPO residency sınıfıyla beyan. Identity plane'de async DR promote yalnız beyanlı RPO>0 profilinde ve toptan epoch artırımıyla (§17 OP-29, HL-31); LWW her iki plane'de yasak (OP-28).
- **T29** Federation Verifier Access Core'dadır; foreign Domain Metadata DERIVED cache'tir ve tazeliği pinli kümeden bağımsız bir witness'ın ≤ Δ (yoksa ≤ 1 saat) cosign'ıyla ölçülür (TI-RT5); recovery veya handover durumunda inclusion bundle zorunludur ve `N_cited` predicate'ine tabidir.
- **T30** Authority hub keşfi = ipucu + PI-4 contract'lı viewer-scoped kayıtsız doğrulama okuması (SI-15, G28); hub cache viewer-scoped okuma snapshot'larıdır, projection değildir; kayıtlı `access.read` / `access.audit.export` Exercise'ı yalnız consequential okuma/export'ta; global registry/index yok; satır başına as_of; tamlık iddiası yok.
- **T31** Identity plane ayrı cell/cluster/KMS/operatör rolleri; tek kanal Claim Ingest API'si; WebAuthn RP; PII crypto-shredding. Identity plane realm başına izole (MD-5); realm JOSE anahtarları ayrı signer sürecinde (CMP-22b); identity plane alt bileşenleri CMP-15.1–15.10 (§16.3.1).
- **T32** User-gated custody = attested TEE custody signer + HSM KEK; assertion challenge imzalanacak payload digest'i.
- **T33** Rate limiting iki katman: gateway'de yaklaşık protocol-rejection limitleri; decision path'te deterministik policy sayaçları. Identity plane: Katman A süreç içi GCRA (governor), Katman B PostgreSQL'de kesin atomik sayaç; hesap başına güvenlik limitleri asla node-yerel değil (§17 OP-35). Gateway katmanında sayaçlar tenant, realm ve domain boyutunda tutulur; identity plane uç noktalarında (giriş, token, kayıt) ek olarak aktör/IP boyutu vardır (§12.3.6, §12.4.1); limiter arızası ALLOW'a dönmez (MD-8).
- **T34** Explain = q−1 rekonstrüksiyonu + aynı normatif değerlendirme (reference implementasyon Access Core); disclosure filtresi son aşama; open Replay CLI ve replay agent; export streaming CBOR sequence.
- **T35** Runtime: **backend tek dilde Rust** (aws-lc-rs); Access Kernel `no_std` crate (CMP-24); TypeScript client'lar Kernel'e Wasm ile bağlanır; kenar protokol gateway'leri (SAML, LDAP, Kerberos/SPNEGO, RADIUS, WS-Fed) ayrı süreçtir ("dil hibriti değil süreç hibriti"; C FFI yalnız izole Kerberos sürecinde). Protocol uç noktaları standart bağlamalarla, internal ConnectRPC (Rust olgunluğu OQ-MD1); kolaylık API'leri ADP'ye derlenir. Bedel: Rust'ta olgun OAuth 2.1 AS kütüphanesi yok, AS 12–18 geliştirici-ayı ek iş (tahmin). Reconsider: ilk 6 ayın sonunda AS OIDF conformance ilerlemesi bu tahminin 2 katından fazla geride kalırsa yalnız AS çekirdeği için Go (Fosite) süreci değerlendirilir; kernel her durumda Rust kalır. Ayrıntı §16.4.
- **T36** Infrastructure: Kubernetes per cell, OpenTofu, Argo CD, Cilium/Envoy, SPIFFE/SPIRE (transport kimliği ≠ actor); self-host small-provider profili. Açık bileşenler (Access Core, reference verifier, Offline Verifier Core, conformance suite, replica agent) D4'teki lisans kararıyla dağıtılır; self-host provider binary'lerinin lisansı D4'tedir (recommended default, Adem kararı); hiçbir lisans export, handover, replay veya protocol kullanımını kısıtlayamaz (B10); protocol yolu Suiss binary'si gerektirmez (TI-17). Small-provider profili tek binary / tek mod; self-host birinci sınıf artefaktı Helm chart; SQLite yalnız tek node (§17 OP-48–OP-51). SQLite yalnız identity plane'in tek node kurulumundadır; authority plane Suiss binary'lerinde PostgreSQL ≥ 18'dir (T8, OP-7). Small-provider profili beyanlı `durability: single-node` profilidir (HL-40).
- **T37** Observability: OpenTelemetry yığını; telemetri minimize, pseudonymous, karar girdisi değil. Metriklerde tenant/realm/domain etiketi yok; OTel ince cephe arkasında; PII/sır taşıyan tipte türetilmiş `Debug` yok; ClickHouse analitiği DERIVED (§17 OP-47).
- **T38** Formal verification planı (TLA+ commit/handover/witness; Lean algebra; differential test) assurance pratiğidir; freeze veya reopen kuralı değildir. Üç katman: TLA+ (dağıtık protokol), Lean (algebra; Cedar'ın teoremleri pozitif cebiri kapsamaz, Grant algebra Lean modeli ayrıca), Kani (implementasyon; hedefler Access Kernel crate'inde, CMP-24). Bir semantik sürümün vektörleri, DRT'si ve kanıtları geçmeden o sürüm release edilmez (MD-15 (b)); model counterexample'ı frozen semantiği yalnız MD-15 (a) koşuluyla açar.
- **T39** Redaction: salt'lı body commitment, body başına DEK, crypto-shredding, derived temizlik; leaf hash ve digest'ler süresiz; 400 gün uygunluk POLICY DEFAULT; "canlı derivation" belirsizse redakte edilmez.
- **T40** Search/analytics/realtime derived'dır ve viewer-rechecked'dır; global search index yok.
- **T41** SDK'lar:
  1. **Her dilde tek paket, iki modül.** Paket `auth` (giriş, oturum, kullanıcı/organizasyon yönetimi; identity plane) ve `authorize` (karar isteme ve uygulama, PEP; authority plane) modüllerini taşır. Modüller kod düzeyinde ayrıdır: `auth` modülü authority üretmez (INV-12). Yalnız authority plane'i kullanan kiracı (external IdP, F3) aynı paketi kurar ve yalnız `authorize` modülünü kullanır.
  2. **Ayrı doğrulama paketi.** Access müşterisi olmayan doğrulayıcılar (karşı taraf, denetçi, internetsiz cihaz) için yalnız Offline Verifier Core'u taşıyan hafif paket (CMP-17, §1.4 vaat 7).
  3. **Backend dilleri, gün-1:** TypeScript/Node, Python, Go, Java, .NET. Ardından PHP ve Ruby.
  4. **Mobil, gün-1:** iOS (Swift), Android (Kotlin), React Native (Expo dahil). Ardından Flutter. Mobil paketler TN-133 bileşenlerinin mobil karşılıklarını, passkey ve platform biyometrisini, oturum ve token yenilemeyi (single-flight) taşır.
  5. **Web:** React; diğer çatılar web components ile (TN-133).
  6. **Üretim yöntemi.** API istemcileri OpenAPI tanımından üretilir. Karar, doğrulama ve kanonik kodlama her dilde aynı Kernel'den gelir (CMP-24; uniffi ile Swift/Kotlin/Python, Wasm ile tarayıcı/Node, C ABI ile Go/Java/.NET). Elle yazılan katman yalnız dile özgü kolaylık katmanıdır. Gerekçe: diller arası aynı girdi → aynı karar; yetki ürününde diller arası farklı karar kabul edilemez. Kernel bağlamalarının conformance vektörlerini geçmesi her dilde CI kapısıdır (TI-RT12).

  Statü: FROZEN (1, 2, 6); PD (3–5'teki dil ve platform listeleri, sıra).
- **T42** Protokol bileşenleri Rust'ta yazılır ve olgun referanslarla karşılaştırmalı test edilir (MD-1 bedelinin kabulü ve risk azaltma):
  1. **Bedel kabulü.** OAuth 2.1 / OIDC AS Rust'ta Access tarafından yazılır; başka dilde ayrı AS süreci kullanılmaz (MD-1). Protokol kapsamı aşamalıdır: önce OAuth 2.1 ve OIDC temeli, sonra FAPI 2, CIBA, token exchange.
  2. **Karşılaştırmalı (differential) test ilkesi.** Her protokol bileşeni aynı girdilerle olgun bir referansa karşı CI'da test edilir; referans bir hakemdir, kod kaynağı değildir: Access kodu standart metninden yazılır, referans kodu kopyalanmaz. Referanslar: OAuth/OIDC AS → node oidc-provider + OIDF conformance süiti; OIDC istemcisi (SDK'lar) → openid-client + OIDF RP conformance; WebAuthn → FIDO Alliance conformance araçları + olgun referans kütüphane; SAML → xmlsec, Shibboleth, SimpleSAMLphp (IDP-40); SCIM → SCIM uyumluluk testleri + Entra/Okta istemcileri (IDP-40); LDAP → OpenLDAP araçları; JOSE/COSE ve kripto → Wycheproof vektörleri (SA-T11).
  3. **Fark çözümü.** Referansla fark çıktığında referans otomatik olarak doğru sayılmaz; standart metni kazanır. Her fark incelenir; sonuç (Access'in düzeltilmesi veya referans sapmasının belgelenmesi) kayda geçer ve test vakası olur.
  4. **Ek güvence.** Fuzzing her protokol ayrıştırıcısı için CI'dadır; bağımsız crystal-box denetimi ilk açık sürümden öncedir (SA-17).
  5. **Tek bakımcılı kritik bağımlılıklar (bergshamra vb.).** Bağımlılığın kendi test süiti ve ilgili referans vektörleri (bergshamra için xmlsec test süiti) her derlemede Access CI'ında koşar; kırılan test derlemeyi durdurur. Yeni bir sürüme geçiş ancak bu testlerin hepsi geçerse yapılır. Kod `cargo vendor` ile depoda tutulur. Bakımcı 6 ay boyunca güvenlik bildirimlerine yanıt vermezse veya projeyi bırakırsa fork kararı otomatik olarak gündeme gelir; fork açık kaynak olarak sürdürülür (D4). Kapsam: bergshamra ve §13'teki tek bakımcılı bağımlılık riski satırlarında adı geçen kütüphaneler.

  Statü: FROZEN (1–5); PD (referans listesi, 6 aylık eşik).

### 16.11 Frozen red-team decisions (RT1–RT30)

- **RT1** Verdict: HOLDS AFTER CORRECTIONS; frozen semantik kırılmadı
- **RT2** K-1: state = record-fold (DecisionRecord effect'leri kayıtlı hâliyle + Claim'den L0 türetim); yeniden değerlendirme = doğrulama; hakem = fold; divergence set StateBasis'te (TI-RT1)
- **RT3** K-1: divergence quarantine (SEC22 R1 deseni): divergent kaydın genişletici effect'leri recovery, handover ve rebuild-diff'te quarantine overlay'i altındadır; quarantine root'un veya Security Party'nin narrowing `policy.set`'idir (provider yalnız kanıt bildirir ve commit'i durdurabilir); kaldırma CT3.
- **RT4** K-2: iki bağımsız zaman kaynağı + sınırlı ilerleme + witness çapraz kontrolü (TI-RT2)
- **RT5** K-2: FA-3 "ihlalde sonuç" = sapma kadar kayma; UDC; topluca yalan HL-6
- **RT6** K-3: SEC22 R1 quarantine policy'sine `nonce-closed/pre-recovery` kuralı (yalnız nonce'u lineage'da olmayan istek); quarantine policy'si CT3 ile kaldırılır; sınıf UDC (U28).
- **RT7** K-3: ilk değerlendirmede (nonce lookup sonrası, nonce yoksa) AIS yaşı ≤ intent validity tavanı; her istekte `t ∈ intent.validity`; validity tavanı POLICY DEFAULT'tur (§13.7.3 REQUIRE_ACTION nonce validity değerleri; CT0 için CT1 değeri) ve hot-path nonce saklama ufkuna eşittir (arşiv lookup'ta kalır); aynı-nonce re-commit etkilenmez (TI-RT3).
- **RT8** Normatif tanım = L0/L2 spec + vektörler; Access Core implementasyondur; her semantik sürümün evaluator'ı korunur
- **RT9** K-4: canonical-taraf snapshot; rebuild-diff fold farkı = commit durdurma + Genesis'ten fold hakem; yeniden değerlendirme farkı = K-1 divergence prosedürü: provider kanıtı domain'e bildirir, quarantine root'un veya Security Party'nin narrowing `policy.set`'idir, kaldırma CT3; provider restriction yazamaz (TI-RT4).
- **RT10** K-5: Domain Metadata tazeliği = pinli kümeden bağımsız witness cosign tazeliği; heartbeat checkpoint (60 s) kaynağı (TI-RT5).
- **RT11** K-6: domain-bağlı excerpt; domain-başı operasyonel anahtar (TI-RT6)
- **RT12** K-6: HSM partition paylaşımı FA-8 eki olarak beyan
- **RT13** K-7: handover'da `superseded-at C_{h+1}` + §16.6 handover predicate'i; `N_cited` = lineage değiştiren kayıttan (`domain.recover` / `domain.handover`) (U27).
- **RT14** K-7: handover drain prosedürü (C_k'ye karşı bundle + consistency_path ile C_{h+1}'e bağlanır)
- **RT15** K-8: issuer-sırası currency; sıra kaynakları: açık `supersedes` zinciri, Party key-event pozisyonu veya taşıyıcı profilinin tanımladığı monoton sıra alanı; eski Claim kaydedilir, asserting değildir (TI-RT7).
- **RT16** K-8: sıra belirsizliğinde disqualifying kazanır
- **RT17** K-9: Σrelease ≤ draw; released@ key'i (TI-RT8)
- **RT18** K-9: grounding içerik dedup'ı
- **RT19** K-10: tembel deterministik toplu episode (`since` = son false→true geçişi); commit başı iş sınırı ENGINEERING ASSUMPTION (TI-RT9); `holdings@party(P)` yalnız materyalize episode değişikliğinde artar.
- **RT20** K-11: kayıt kimliği = commitment; FA-14 (TI-RT11)
- **RT21** K-12: audit kapsamının altında opaque anahtarlı `basis_ref` token; HMAC event id (TI-RT10); anahtar domain başınadır, kooperatif handover'da Record Export Package içinde yalnız yeni provider'a açık taşınır; forced recovery'de anahtar yoksa eski token'lar çözülmez ve fail closed olur (yalnız korelasyon ve explain kaybı; authority etkisi yok).
- **RT22** K-13: T14 (proof seçimi), K-3 kuralı (ilk-commit AIS yaşı + pre-recovery), K-8 (issuer sırası), K-9 (Σrelease tavanı), K-10 (episode fonksiyonu), restriction dili alt kümesi (Cedar forbid-only; OQ-MD2 durumunda CEL), K-12 token kuralı ve TI-RT1(ii) SYNC-DERIVED türetim fonksiyonları L0/L2 normatif metnine + vektörlere girer (TI-RT12).
- **RT23** CL-1: timeout'ta "Not confirmed — checking" + aynı nonce'la retry; commit edebilen retry intent validity penceresiyle sınırlıdır (pencere sonunda sonuç sabit, UDC); pencere sonrası aynı-nonce isteği yalnız sonuç sorgusudur; sonuç Access'in ilk cevabıyla öğrenilir (HL-5): "Revoked" / "Revoked — confirming (witness pending)" veya — yalnız nonce devam eden lineage'da (arşiv dahil) yoksa — "Not recorded — try again"; pending/queued yok (§8).
- **RT24** CL-2: derived okuma cevaplarında `witnessed_through` + "Revoked — confirming (witness pending)" render'ı.
- **RT25** Yeni blocker sınıfı yok; yalnız subcode: `nonce-closed/pre-recovery` ve `budget-exhausted/release-exceeds-draw` (P14).
- **RT26** `derived.*` whitelist'i kapalıdır ve §16.5 whitelist satırındaki on bir girdiden oluşur; her girdi §16.5.1 derived yapılar tablosundaki bir yapıdan deterministik hesaplanır ve §16.5.2 koleksiyon key tablosundaki bir version key'iyle read-set'e girer.
- **RT27** Episode'u açan Claim ve güncel iddia canlı derivation'dır, redakte edilmez.
- **RT28** HL-1–HL-14 kabul edilmiş sınırlardır; ürün vaadine giremez
- **RT29** Red-team'de dayanan senaryolar mimarinin değişmeyen kısımlarıyla kabul edilir; ek değişiklik gerektirmez.
- **RT30** Red-team düzeltmeleri yalnız ilgili K/CL bulgusunun gerekçelendirdiği mimari yerleri değiştirir; diğer her yerde §16'daki mimari kararlar geçerlidir.
