## 1. Executive Definition

### 1.1 Tek cümlelik tanım

> **Access is Suiss's first-party identity and authority control plane: a complete identity provider (the identity plane) that authenticates actors, manages their accounts, credentials and sessions and speaks the standard identity protocols, and above it an authority plane that establishes which actor instance is acting and on whose behalf, maintains where its authority originates and how it is delegated and bounded, and, as the authoritative decision authority within the authority domains it serves, decides whether that authority may be exercised for an exact intent now, while domain truth, coordination and the effect itself remain with their owners.**

Gerekçe: Tanım iki plane'i adlandırır ("identity and authority control plane"). Identity plane'i yalnız "establishes which actor instance is acting" ile değil, tam IdP olarak adlandırır. Dil (Rust) tanıma girmez, çünkü dil tanıma ait değildir. Dil kararı MD-1'dir ve §16'dadır.

Tanımın taşıyıcı seçimleri:

| Öğe | Anlamı |
|---|---|
| "a complete identity provider (the identity plane)" | Identity plane tam bir IdP'dir. Kimlik doğrulama, hesap ve credential yaşam döngüsü, oturum, standart identity protokolleri (OIDC OP / OAuth 2.1 AS, SAML, SCIM, LDAP, Kerberos, RADIUS, WS-Fed, OpenID Federation), MCP ve ajan kimliği ile yönetim API'si bu plane'dedir (§2.2.1, §10–§12, §4) |
| "above it" | Katmanlama bağımlılık değildir. Authority plane identity plane'den yalnız Claim alır (INV-12, E3). External IdP'leri ve workload identity'leri aynı Acceptance koşullarıyla kabul eder (F3, B7). "Above" ilişkisi yalnız ürün içindeki sırayı anlatır. Identity'nin authority ürettiği anlamına gelmez (must-never #1) |
| "exact intent" | Access envelope'u tanımlar ve ona karar verir; effect'i tanımlamaz ve yürütmez |
| "now" | Zaman boyutu, kararın her an yeniden sorulabilmesiyle karşılanır; mekanizma (ValidityContract, continuation) tanıma girmez |
| "within the authority domains it serves" | Access first-party / reference authority provider'dır; compatible authority provider'lar aynı rolü kendi domain'lerinde üstlenebilir |
| Son clause | Access'in nerede durduğu tanımın parçasıdır: domain truth, coordination ve effect sahiplerinde kalır |
| "trust" | Ayrı bir domain değildir; "establishes … acting" içinde assurance ve scoped acceptance olarak yer alır (§2.3) |

### 1.2 Tek paragraflık tanım

Access iki plane'den oluşur. **Identity plane** tam bir identity provider'dır. İnsanları (tüketici, çalışan, geliştirici, yönetici), servisleri, workload'ları, cihazları ve agent'ları standart protokollerle doğrular. Hesaplarını, credential'larını ve oturumlarını yönetir. Kendi realm'leri içinde kimlik bağlar ve bu bağı authority plane'e yalnız Claim olarak verir. **Authority plane**, insanlar, agent'lar, servisler, workload'lar ve organizasyonlar için authority'nin kaynağını, taşınmasını ve kullanılmasını yöneten control plane'dir. Bir actor'ü somut bir instance'a ve doğrulanabilir bir assurance'a bağlar; authority'nin hangi root'tan, hangi explicit delegation zinciriyle geldiğini ve her adımda yalnız daralarak nasıl sınırlandığını tutar; bir instance'ın o authority'nin hangi alt kümesini kullanabileceğini (Mandate) belirler. Hizmet verdiği authority domain'leri içinde, bir intent geldiğinde ALLOW / DENY / REQUIRE_ACTION kararını veren authoritative kaynaktır ve kullanılan authority'nin doğrulanabilir kaydını üretir. Suiss'in first-party authority provider'ıdır; interoperability Suiss-hosted Access gerektirmez ve compatible authority provider'lar aynı rolü kendi domain'lerinde üstlenebilir. Domain gerçekliğini ve eligibility'yi domain ürünlerinden, işin koordinasyonunu Work'ten devralmaz. Effect'i yürütmez ve gerçekleştiğini iddia etmez. Authority artefaktları Access dışında ve organizasyon sınırları ötesinde doğrulanabilir; hiçbir projection, federation veya offline taşıma authority'yi büyütemez. Identity plane'in genişliği authority semantiğini değiştirmez: hiçbir login, token, grup üyeliği, oturum veya risk skoru authority üretmez.

### 1.3 Fundamental problem

> **Bir actor'ün — kendi adına veya başkası adına — authority kullanmasının meşru olup olmadığını, o authority'nin kaynağından bu kullanıma kadar açık, daraltıcı (attenuating) ve prospectively revocable bir zincirle, ilgili authority domain'i içinde tek authoritative kaynak olarak belirlemek.**

Kısaca: **legitimacy of authority exercise.** Problemin beş parçası:

| # | Soru | İçerik |
|---|---|---|
| 1 | Kim hareket ediyor? | Actor binding: hangi somut Instance, hangi assurance ile |
| 2 | Kimin authority'siyle? | Root → derivation → delegation → Mandate; provenance; ayrıca hangi capacity'de (kendi adına / başkası adına) |
| 3 | Hangi sınırlar içinde? | Scope, parametreler, budget, zaman, purpose; zincir boyunca yalnız daralan |
| 4 | Şu an, bu exact intent için kullanılabilir mi? | Requirement'lar, proof, approval authority, revocation, restriction |
| 5 | Ne kullanıldı? | Attributable Exercise kaydı |

**Identity plane alt problemi**. Satır 1 ("Kim hareket ediyor?") identity plane'de ayrı bir ürün problemi olarak açılır: *Bu actor kim, hangi yöntemle ve hangi assurance ile, hangi realm'de ve hangi oturumda doğrulandı; hesabı, credential'ları ve oturumu nasıl yaşar ve nasıl geri alınır?* Bu alt problem identity plane'in ürün problemidir. Authority açısından satır 1'in ön koşuludur. Fundamental problem (F2) değişmez: identity alt problemi tamamen çözülmüş olsa bile authority meşruiyeti satır 2–5 ile ayrıca kurulur. Identity plane'in çözdüğü problem authority plane'e yalnız Claim olarak geçer (INV-12).

Bir authority domain'i içinde belirli bir authority object için tam olarak bir authoritative authority-state lineage ve decision authority vardır. Suiss Access bu rolün Suiss'teki first-party implementasyonudur; protocol modeli compatible authority provider'lara izin verir. **One authoritative source per authority domain/object ≠ one global Suiss authority provider.**

| Alan | Statü | Not |
|---|---|---|
| Authority | Varlık nedeni | Kaynak, sahiplik, sınır |
| Delegation | Varlık nedeni | Agentic dünyada authority'nin normal taşınma biçimi |
| Mandate (instance-bounded exercise) | Varlık nedeni | Holding ≠ exercisable |
| Authority provenance | Varlık nedeni | Delegation ve revocation'ın ön koşulu |
| Federated authority | Varlık nedeni | Organizasyon sınırı aşan provenance |
| Execution authorization (bound intent decision) | Varlık nedeni | Unit of value'nun kendisi |
| Agent authority | Varlık nedeninin en güçlü kullanım alanı | Ayrı bir security universe değildir (F15) |
| Identity, Authentication | Identity plane çekirdeği (ürün kapsamı); authority açısından gerekli capability | Authority bir actor'e bağlanmadan kullanılamaz; teknoloji değil assurance semantiği |
| Oturum, hesap yaşam döngüsü, credential yönetimi | Identity plane çekirdeği (ürün kapsamı) | Authority üretmez; iptali (`session_epoch`) authority cascade'inden ayrı mekanizmadır (MD-7, L12 notu) |
| Ajan credential broker / token vault | Identity plane capability'si | Possession ≠ authority; upstream token'ın ajana verilmesinin *release kararı* bir Access Exercise'ıdır; teslim edilen upstream token Access projection'ı değildir ve içeriği NOT GUARANTEED'dır |
| Instance | Gerekli capability | Somut execution / sign-in bağlamı |
| Membership | Gerekli capability | Authority rule'ları için connective input; kendi başına authority değil |
| Authorization | Varlık nedeninin operasyonu | "Decide" adımı; tek başına tez değil |
| Policy | Gerekli capability | Restriction-only |
| Evidence | Gerekli capability | Proof semantiği, içerik değil |
| Approval | Kısmen varlık nedeni | Approval *authority* evet; approval *ihtiyacı* hayır |
| Trust | Umbrella isim | Domain değil; scoped acceptance (§2.3) |
| Risk | Dış input | Yalnız daraltır. Identity plane risk tabanlı step-up uygular, risk yine yalnız daraltır (CI-2, MD-13) |
| Governance | Capability ailesi | Aynı authority semantiği üzerinde (access review, JML, SoD) |
| Execution conformance | Sınır capability'si | Envelope tanımı ve doğrulanabilirlik Access'te; enforcement dışarıda |
| Information-flow authority | Kısmen | Disclosure authority evet; classification / DLP hayır |

Passkey, OAuth, OIDC, SAML, RBAC, ReBAC, ABAC ve JWT tez değildir; interoperability veya ifade mekanizmasıdır. Bunlar identity plane'in **ürün kapsamıdır**. Yine de tez değildirler: authority semantiği bunlara değil, assurance ve Grant semantiğine bağlıdır (F17).

**Bu ürünü ne gereksiz kılardı?** Her sistem yalnız kendi standing authority'siyle hareket etseydi ve hiçbir actor başkası adına iş yapmasaydı, Access bir IdP + ACL'ye indirgenirdi. Agentic sistemlerde neredeyse her consequential action delegated olduğu için bu koşul gerçekleşmez. Access'in varlık nedeni budur.

"IdP" kısmı ürünün kendisidir. Yukarıdaki cümle tezi değiştirmez: ürünün identity yarısı tam IdP'dir, varlık nedeni ise authority yarısıdır. Identity plane tek başına satılabilir (H13b, §18.8). Bu durumda bile authority plane'in semantiği ve must-never'ler aynen geçerlidir.

### 1.4 Core product promise

Access kullanan bir ürün şu cevapları güvenilir şekilde alır:

| # | Vaat | İçerik |
|---|---|---|
| 1 | **Actor** | Şu an hareket eden somut Instance hangisi, hangi Party'ye ait ve bu bağın assurance'ı ne? |
| 2 | **Representation & provenance** | Kimin adına hareket ediyor (capacity)? Authority'si hangi root'tan, hangi explicit delegation/exercise zinciriyle geliyor? |
| 3 | **Bounds** | Bu kullanım hangi sınırlar altında (scope, parametreler, budget, zaman, purpose, Mandate)? Sınırların zincir boyunca yalnız daraldığı garantidir |
| 4 | **Decision** | Bu authority bu exact intent için şimdi kullanılabilir mi? Cevap ALLOW, DENY veya eksikleri yapılandırılmış biçimde söyleyen REQUIRE_ACTION'dır |
| 5 | **Continuity** | Revocation, narrowing veya kanıt süresinin dolması, authority source'unda commit edildiği andan itibaren devam eden kullanım dahil gelecekteki kullanım için prospectively authoritative'dir. Enforcement gecikmesi verifier'ın beyan ettiği connectivity/freshness profiliyle sınırlıdır. Vaat *validity* üzerinedir; anlık global enforcement veya fiziksel durdurma değildir |
| 6 | **Record** | Gerçekte hangi authority'nin, hangi envelope için kullanıldığının attributable kaydı; bir effect'in bu envelope'a uyup uymadığı bu kayda karşı doğrulanabilir |
| 7 | **Portability** | Authority artefaktları Access'e online sormadan ve organizasyon sınırları ötesinde doğrulanabilir; hiçbir projection, federation veya offline taşıma authority'yi büyütmez |

**Identity plane vaatleri**. Identity plane'in üç tasarım ilkesi (MCP ve ajan kimliği birinci sınıf, sender-constrained token varsayılan, çok kiracılık gün-1'de doğru) birer vaattir. Her vaat bir guarantee sınıfıyla yazılır (§3.3).

| # | Vaat | İçerik | Guarantee sınıfı |
|---|---|---|---|
| I1 | **Standart-tam kimlik** | Tek ürün OIDC OP / OAuth 2.1 AS (FAPI 2, CIBA, PAR/RAR/JAR/JARM, token exchange, ID-JAG, CIMD), SAML 2.0 IdP, SCIM 2.0, LDAP, Kerberos/SPNEGO, RADIUS, WS-Fed ve OpenID Federation konuşur (§10) | Kapsam vaadidir, guarantee değildir. Protokol uygunluğu: UDC. Koşul: OIDF conformance süitinin CI'da geçmesi (MD-1 telafisi, B9) ve ilgili interop profili |
| I2 | **Ajan ve MCP kimliği birinci sınıf** | Agent actor-capable Party + Instance'tır (C5, C6), users tablosunun varyantı değildir. MCP authorization server profili ve ajan kimliği §11'dedir | Ajanın token'ı veya credential'ı authority değildir: BS (INV-12, must-never #1). Ajan kimliğinin doğruluğu: UDC (beyanlı attestation/KeyBinding, L21) |
| I3 | **Sender-constrained varsayılan** | Identity plane token'ları varsayılan olarak DPoP, mTLS-bound veya JWT-SVID ile bağlıdır. Bearer yalnız beyanlı legacy RP opt-in'idir (L21 notu) | UDC. Koşul: RS'in binding'i doğrulaması. Binding'i doğrulamayan RS'te çalınan token'ın kullanılmaması: NG |
| I4 | **Çok kiracılık gün-1'de doğru** | Realm izolasyonu (MD-5), realm başına JOSE anahtar seti (MD-6), global benzersiz ve sunucu üretimi `client_id`; identity plane, derived, PII vault ve operasyon tablolarında PK'de `tenant_id` + RLS FORCE; authority canonical log ve kayıtları `domain_id` ile anahtarlanır, tenant ↔ domain eşlemesi placement directory'dedir (append-only log ticari hesap değişince yeniden anahtarlanamaz; OP-12); bileşik FK (MD-5) | UDC. Koşul: beyanlı kontroller (RLS, bileşik FK, realm-kapsamlı anahtar, verifier'ın DomainID/issuer kontrolü). "Kiracı izolasyonunu derleyici garanti eder" ifadesi yasaktır (§3.3a) |
| I5 | **Identity continuity** | Oturum ve identity token iptali (`session_epoch`, `instance.terminate`, `party.compromise`) beyanlı Δ/horizon içinde etkili olur. Identity token'ları da ValidityContract semantiğine tabidir (MD-7) | UDC. Koşul: verifier'ın beyanlı yolu (login, refresh, introspection, salt-JWT RS, sinyal tüketen RS). Salt-JWT RS'te bayatlık ≈ token ömrü (NG: anında iptal). "Cache bu kullanıcıyı hiç görmedi" durumu fail-closed'dur (MD-7, MD-8) |

**Vaat olmayanlar:** effect'in gerçekleştiği; effect'in doğru olduğu; execution'ın durduğu; domain koşulunun doğru olduğu; actor'ün "güvenilir" olduğu. Guarantee sınıfları §13'tedir; ürün hiçbir yüzeyde §13'teki asla-vaat-edilmez ifadeleri kullanmaz.

**Identity plane için ek vaat olmayanlar**:
- "Access formel olarak doğrulanmıştır" (niteliksiz). İzin verilen biçim §3.3a'dadır.
- "Kiracı izolasyonunu derleyici garanti eder". Branded lifetime yalnız belirli yanlış kullanımları derleme aşamasında engeller.
- "Keycloak'tan hızlı" veya "X login/sn garanti". Performans hedefi ENGINEERING ASSUMPTION'dır (§4.10, B15).
- "Oturum her yerde anında kapandı". Salt-JWT doğrulayan RS'te bayatlık token ömrüne eşittir (I5).
- "Passkey ile hesap ele geçirilemez". Passkey oltalamayı durdurur. Doğrulamadan sonra oturum token'ının çalınmasını durdurmaz. Bunun azaltımı cihaza bağlı oturumdur (DBSC, DPoP; §12).

### 1.5 Unit of value

> **Authority Exercise.** Belirli bir actor Instance'ının, provenance'ı bilinen bir authority'yi, belirli bir intent envelope'u için, belirli bir anda kullanması ve bunun kararı + kaydı.

| Aday | Neden merkez değil |
|---|---|
| Identity / Authentication / Login | Ön koşul; değer onların neye izin verdiğiyle ortaya çıkar |
| Permission | Statik; provenance, delegation ve zaman boyutu yok |
| Authorization Decision | Fazla düşük seviyeli: provenance ve kayıt olmadan stateless bir boolean'a indirgenebilir |
| Authority Relationship (Grant) | Enabling/governance state'tir ve hiç kullanılmadan da değerli olabilir (break-glass, standby delegation); ama ana transactional unit of value değildir |
| Delegation | Authority'nin taşınma biçimi; tek başına sonuç değil |
| Trusted Effect | Domain execution'ı Access'e çeker; Access'in gözlemleyemediği şeyi vaat eder |

Authority Exercise iki yönü birlikte tutar: geriye doğru provenance (root → delegation → Mandate) ve ileriye doğru envelope (Access'in tanımladığı, effect'in uyması gereken sınır). Effect'e değil envelope'a kadar uzanır. Kesin ontology anlamı C30'dur: bir intent nonce'u için ilk committed ALLOW ile doğan canonical entity. Ticari value metric de budur (B17).

Unit of value Authority Exercise'tır. Identity plane'in ürettiği login, oturum ve token tabloda "ön koşul" olarak reddedilmiştir. Identity plane için türetilmiş ürün metrikleri (kurtarma yeniden tetikleme oranı, phishing-resistant kimlik doğrulama oranı) §18.4'tedir. Bunlar unit of value veya fatura birimi değildir.

### 1.6 Access'in tek sorusu

> **"May this actor, on this authority, do this exact thing now?"**

| Soru | Sahip |
|---|---|
| Bu effect dünyada geçerli mi? Koşullar sağlanıyor mu? (*is / is eligible*) | Domain ürünü |
| Bu üzerinde anlaşılmış iş mi? Devam etmeden önce birinin onayı gerekiyor mu? (*should / when*) | Work |
| **Bu actor, bu authority ile, bunu şimdi yapabilir mi? (*may*)** | **Access** |
| Tam olarak bağlanan şekilde gerçekleşti mi? (*did*) | Executor / domain PEP |
| Doğru taraf haberdar oldu mu? (*was told*) | Relay |
| Kişi ne düşünüyor, neyi hatırlıyor, ne planlıyor? (*thinks*) | One |
| Para nerede, hareket etti mi? (*holds / moved*) | Money / Pay |

Identity plane'in cevapladığı "bu actor kim, hangi assurance ile doğrulandı?" (*is who*) sorusu bu sorunun ön koşuludur ve Access'in identity plane'inde (veya kabul edilmiş bir external IdP'de) cevaplanır. Bu ayrı bir "tek soru" değildir. Cevabı authority sorusuna yalnız Claim olarak girer (INV-12).

### 1.7 Primary actors

| Rol | Örnek |
|---|---|
| Acting actors | İnsan, agent (One dahil), service, workload, device |
| Authority holders / roots | Kişi, şirket, merchant, joint ownership grubu, tenant organizasyon |
| Relying products (PEP) | Work, Pay, Commerce, Serve, Executor'lar, third-party sistemler |
| Authority administrators | Org admin, resource owner, security/governance ekipleri |
| Verifiers / auditors | İç denetim, karşı organizasyon, regülatör, dispute çözümü |
| Son kullanıcı: tüketici | Uygulama kullanıcısı; passkey, sosyal login, magic link ile doğrulanır |
| Son kullanıcı: çalışan | Kurumsal personel; kurumsal SSO (SAML/OIDC), phishing-resistant MFA |
| Relying party / geliştirici | OIDC/SAML RP'leri, OAuth client'ları, MCP client'ları; API tüketicisi (client credentials, `private_key_jwt`) |
| Üçüncü taraf uygulama | Kullanıcı adına entegrasyon; consent'i Grant Exercise'ına derlenir (§2.2.2) |
| Realm / tenant yöneticisi | Kendi realm'inin client, tema, upstream IdP ve giriş politikası yönetimi. Authority state'ini değiştiren her işlem (grant, Acceptance, policy, `claim.issue`) ADP meta-Exercise'ıdır. Identity plane yapılandırması (client, redirect URI, upstream IdP, şablon, realm config) authority state değildir: realm'in yönetişim domain'inde bir `idp.*` domain action Exercise'ıdır; Access karar verir, identity plane PEP olarak kendi kaydını yazar (MD-14, E34) |
| Platform yöneticisi | Suiss veya self-host operatörü; platform-admin API yüzeyi realm-admin yüzeyinden ayrıdır (audience, scope namespace, rate bütçesi) |
| Destek personeli | Kimliğe bürünme yoktur. Destek erişimi kullanıcının kendi Grant Exercise'ı veya reserved break-glass Grant'tır (MD-9, must-never #19) |
| Anonim / misafir | Kayıtsız ziyaretçi; oturum kimliği, sonradan kayıtlı hesaba yükseltme (§12) |

Not: IAM (çalışan), CIAM (müşteri), IGA (yönetişim), PAM (ayrıcalıklı erişim) ve NHI (insan olmayan kimlik) ayrımlarının Access'teki karşılığı §4.5'tedir.
