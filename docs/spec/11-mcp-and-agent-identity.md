## 11. MCP Yetkilendirme ve Ajan Kimliği

**Bu bölümün kapsam notu.**
- **Konu.** Bu bölüm MCP yetkilendirmesini ve AI ajan kimliğini Access semantiği altında normatif olarak tanımlar.
- **Bağlayıcı kararlar.** MD-13 (credential broker / token vault) ve MD-18 (ID-JAG). A-1…A-12 ajan sözleşmesi normları §8.18.2'dedir (MD-19).
- **ID'ler.** Kararlar **AG-1…AG-43** (§11.22), invariant adayları **AGI-1…AGI-8** (§11.22).
- **§10 ile sınır.**
  - Genel OAuth/OIDC AS'nin grant tablosu, PKCE/PAR/JAR/DPoP uygulama profili, token exchange mekaniği, JWT/JWKS, logout ve FAPI/FiPA/CIBA uygulaması §10'dadır.
  - CIMD ve MCP AS/RS ayrıntısının tek kaynağı bu bölümdür (§11.3–§11.5).
  - §10, discovery/CIMD/RFC 9207 için kısa normatif kural ve "→ §11.4" atfı verir.

### 11.0 Kapsam, plane ataması ve ilkeler

1. **Ajan ayrı bir güvenlik evreni değildir (F15, FROZEN).**
   - İnsan, servis, workload ve ajan aynı authority semantiğini kullanır.
   - Ajanlar delegation, Mandate, provenance, long-running exercise ve controller ≠ authority açısından daha güçlü gereksinim taşır.
   - Farklılaştırıcı olması CURRENT STRATEGIC HYPOTHESIS'tir.
2. **Plane ataması (MD-13).**

   | Yetenek | Plane | Not |
   |---|---|---|
   | MCP Authorization Server (OAuth 2.1 AS, CIMD/DCR, consent, token endpoint) | Identity plane | Token issuance = `projection.issue` (§9.9) |
   | MCP Resource Server referans implementasyonu / PEP SDK | Domain'in PEP'i (verifier) | Access'in kendisi değil; conformance profili Decision PEP / Verifier |
   | Ajan kimlik kaydı (`IdentitySubject`, ajan tipi, sahip/sponsor ilişkileri) | Identity plane | Authority plane'e Claim olarak çıkar (§11.9) |
   | Ajan credential broker / token vault | Identity plane | Upstream token'ın ajana verilmesi bir Access kararı + projection'dır (§11.13) |
   | SSF/CAEP verici ve alıcısı | Identity plane | §9.16.2 |
   | Ajanın authority'si (Grant, Mandate, capacity, budget, contribution) | Authority plane | Tek kaynak Grant lineage'ı (MD-4) |

3. **Access yeni bir identity protokolü icat etmez (L20).**
   - MCP, OAuth, ID-JAG, WIMSE, SPIFFE ve A2A taşıyıcıdır.
   - Access bunların boş bıraktığı yeri doldurur: delegation lineage, attenuation, Mandate, budget, consumption, Exercise kaydı, REQUIRE_ACTION.
4. **Token'daki actor zinciri projection ve ipucudur (L22).** Önceki aktörler token'dan değil Access lineage'ından doğrulanır.
5. **InstanceID ≠ KeyBinding ≠ Attestation (L21).** SPIFFE trust domain ≠ AuthorityDomain (L25). Workload federation authority federation değildir.
6. **Taslaklar standart gibi ele alınmaz (L27).** Ajan ekosistemindeki 200'ü aşkın internet taslağının hiçbiri Access'in normatif bağımlılığı değildir.
7. **Plane ataması (MD-13).** Credential/token vault, session recording/brokering, risk scoring, trusted rendering ve instruction-provenance savunması:
   - ya identity plane capability'sidir;
   - ya ayrı ürün katmanıdır.
   Access her durumda bunların authority kısmına karar verir. "Kapsam dışı" ifadesi kullanılmaz (MD-13).
8. **Access'in tezi:** "Yetkilendirmeyi modelden çıkar, deterministik bir aracıya koy". Prompt enjeksiyonu yetkilendirme katmanında çözülemez. Yetkilendirme katmanı, ele geçirilmiş bir ajanın yapabileceklerini Grant ∩ Mandate ∩ budget ile sınırlar.

### 11.1 Standart durumu (Eylül 2026)

**MCP**:

| Öğe | Değer |
|---|---|
| Yürürlükteki revizyon | 2026-07-28. `/specification/draft/` normalize diff'te birebir aynı; `/specification/latest` 2026-07-28'e yönlenir |
| Bir önceki | 2025-11-25 (CIMD bu revizyonda geldi, SEP-991) |
| Yetkilendirme | MCP için OPTIONAL |
| HTTP transport | Bu spesifikasyona SHOULD uyar |
| STDIO transport | SHOULD NOT takip eder; kimlik bilgilerini ortamdan alır |
| Diğer transport'lar | Kendi protokollerinin güvenlik en iyi uygulamalarını MUST takip eder |
| Referans standartlar | OAuth 2.1 (`draft-ietf-oauth-v2-1-13`), RFC 6750, 8414, 7591 (kullanımdan kaldırıldı), 8707, 9728, 9207, CIMD (-00), OIDC Discovery 1.0, OIDC DCR 1.0 |
| Spesifikasyon gecikmesi | MCP OAuth 2.1 -13 ve CIMD -00'a atıf yapar. Güncel sürümler -16 (3 Eylül 2026) ve -02'dir (6 Temmuz 2026) |
| DCR | Kullanımdan kaldırıldı (PR #2858). Geriye uyumluluk penceresi en az 12 ay: 2027-07-28 veya sonrasında yayımlanacak ilk revizyona kadar (SEP-2596) |
| Stratejik sinyal | TypeScript SDK `main` dalında AS implementasyonu `packages/server-legacy/`'ye taşındı. SDK yalnız RS metadata'sını tutuyor; ayrı bir AS ürünü doğru konumdur |

**IETF OAuth WG ve ajan işi**:
- `charter-ietf-oauth-06` 4 Haziran 2026'da onaylandı ve "Complex Delegation" maddesini içerir. Eylül 2026 itibarıyla hiçbir ajana özgü doküman WG tarafından kabul edilmedi.
- Başkanlar gelen taslak hacmini işleyemediklerini açıkça söylüyor; dokuz kümelik sınıflandırma önerildi (IETF 126).
- agentproto BoF (IETF 126, 23 Temmuz 2026) kimlik ve yetkilendirmeyi WIMSE ve OAuth'a yönlendirdi ve yeni iş yaratmadı. Ajan denetlenebilirliği BoF'u (AUDIT) reddedildi.

Aktif WG dokümanları (tarih ve durum Datatracker'dan):

| Taslak | Rev. | Tarih | Durum | Bu spec'teki yeri |
|---|---|---|---|---|
| `draft-ietf-oauth-v2-1` | 16 | 3 Eylül 2026 | Aralık 2026'da IESG kilometre taşı | §10 |
| `draft-ietf-oauth-attestation-based-client-auth` | 11 | 3 Eylül 2026 | WG Doc | §11.12 |
| `draft-ietf-oauth-transaction-tokens` | 11 | 30 Temmuz 2026 | WG uzlaşısı | §11.12 |
| `draft-ietf-oauth-first-party-apps` | 04 | 1 Temmuz 2026 | WG uzlaşısı | §10; hata kodu §9.9.5 |
| `draft-ietf-oauth-client-id-metadata-document` | 02 | 6 Temmuz 2026 | WG Doc | §11.3 |
| `draft-ietf-oauth-identity-assertion-authz-grant` (ID-JAG) | 04 | 21 Mayıs 2026 | WG Doc | §11.11 |
| `draft-ietf-oauth-spiffe-client-auth` | 02 | 15 Haziran 2026 | WG Doc | §11.12 |
| `draft-ietf-oauth-security-topics-update` | 03 | 5 Temmuz 2026 | WG Doc | §10, §14 |
| `draft-ietf-oauth-refresh-token-expiration` | 03 | 6 Temmuz 2026 | WG Doc | §9.4.2 |
| `draft-ietf-oauth-rar-metadata-remediation` | 00 | 23 Ağustos 2026 | WG Doc (yeni) | §9.9.5 |

RFC kuyruğunda `identity-chaining-17`, `rfc7523bis-11`, `sd-jwt-vc-19` ve `status-list-21` vardır. Yeni RFC'ler: RFC 10017 (Browser-Based Apps BCP) ve RFC 10027 (Cross-Device Flows BCP), Ağustos 2026.

### 11.2 MCP ile Access arasındaki rol ve ontology eşlemesi (Access MCP profili)

Eşlemenin özeti §9.4.1'dedir. Normatif MCP profili şudur:

| MCP kavramı | Access karşılığı | Kural |
|---|---|---|
| MCP client | Ajan **Instance**'ı (veya insan kullanıcının istemci Instance'ı). Actor proof = AIS; projection holder'ı = Instance KeyBinding | CIMD `client_id` bir **OAuth client kimliğidir**, actor değildir (PI-7). Aynı CIMD'yi kullanan binlerce Instance aynı client, farklı actor'dür |
| MCP server | OAuth **resource server** + domain **PEP**'i (kendisi veya arkasındaki sistem) | PEP ≠ actor (E17). Server, ajanın AIS'ini ADP `context`'inde iletir veya exact-intent projection'ı doğrular |
| MCP AS (PRM `authorization_servers`) | Identity plane AS. Token endpoint = `projection.issue` | Her token issuance bir karardır (§9.9) |
| MCP tool | Publisher SPP'sindeki **ActionRef** (namespace + name + version + schema digest) | Tool description authority-opaque'tır, instruction değildir (A-7). MCP server kimliği tool tanımının doğruluğu değildir |
| `tools/call` | Exercise Request (ADP `commit`) **veya** projection'ın RAR `kind=intent`'i (exact-intent token) | ALLOW envelope'a bağlıdır (INV-19). Parametre değişirse yeni intent |
| `tools/list`, `resources/list`, `server/discover` | DERIVED, viewer-scoped search sonucu (§9.7) | Filtreli liste bir **disclosure** kararıdır. `cacheScope` kuralı §11.5.4 |
| Access token | PROJECTION (bounds token veya exact-intent token) | `cnf` zorunlu, tek `aud` = MCP sunucusunun kanonik URI'si, authority yalnız RAR'da, passthrough yok |
| MCP elicitation / consent ekranı | Approval **değildir** (EI-18, A-5) | Onay yalnız Approval Surface + AAS ile (§9.14). Elicitation yalnız Surface adresini iletebilir (§9.9.5) |
| State handle, `requestState` | Protocol nesnesi değildir; authority taşımaz | "A handle is a name, not a capability". Kural §11.5.5 |
| `subscriptions/listen` (uzun ömürlü stream) | Long-running kullanım: ValidityContract horizon'u / continuation | Kural §11.5.7 |
| MCP Enterprise-Managed Authorization (ID-JAG) | Identity plane assertion üretimi/tüketimi; Claim taşıyıcısı | §11.11 |

### 11.3 Client ID Metadata Documents (CIMD): istemci kaydı

**Access kuralı (AG-3, AG-4).**
- CIMD ile tanımlanan şey bir OAuth **client**'tır. Actor değildir, Claim issuer'ı değildir, authority holder'ı değildir (PI-7, §9.13.8 madde 3).
- Bir istemcinin kabul edilmesi, redirect URI'si, alan adı güven politikası ve kayıt yöntemi identity plane yapılandırmasıdır. Bu yapılandırmanın değişmesi realm'in AuthorityDomain'indeki bir domain action'ıdır ve ADP `commit` ile yetkilendirilir (MD-14).
- CIMD dokümanının içeriği istemcinin **beyanıdır**. Onay ekranında gösterilen `client_name` ve `logo_uri` authority-opaque'tır (A-7'nin istemci tarafı karşılığı, çıkarım).

#### 11.3.1 IETF durumu ve -00/-02 farkı

| Öğe | Değer |
|---|---|
| Güncel revizyon | `draft-ietf-oauth-client-id-metadata-document-02` |
| Yayın | 6 Temmuz 2026; sona erme 7 Ocak 2027; 20 sayfa |
| Yazarlar | Aaron Parecki (Okta), Emelia Smith |
| WG durumu | WG Document, kabul edilmiş; WGLC'de değil, IESG'de değil; RFC numarası yok |
| Geçmiş | Bireysel `draft-parecki-*` -00…-03 (Temmuz 2024 – Temmuz 2025); 8 Ekim 2025 WG kabulü; WG -00 (12 s.), -01 (1 Mart 2026, 14 s.), -02 (6 Temmuz 2026, 20 s.) |

MCP 2026-07-28 normatif olarak -00'a atıf yapar. -02'nin getirdiği ve -00'da bulunmayan normatif kurallar:

| -02'deki yeni kural | Seviye |
|---|---|
| Özel amaçlı IP adreslerine (RFC 6890) getirme yasaktır | MUST NOT |
| HTTP yönlendirmeleri otomatik takip edilmez | MUST NOT |
| Yanıt 200 OK olmalıdır; diğer tüm durum kodları hatadır | MUST |
| Simetrik sır tabanlı `token_endpoint_auth_method` yasaktır | MUST NOT |
| `client_secret` ve `client_secret_expires_at` yasaktır | MUST NOT |
| Özel anahtar materyali yasaktır; yalnız public key | MUST NOT |
| Basit string karşılaştırması; port normalizasyonu yok | MUST |
| Privacy Considerations bölümü (§9) | Yeni |

- MCP'nin -00 §6 ve §6.2 atıfları -02'de §8 ve §8.2'ye karşılık gelir.
- Uçuştaki düzeltmeler: PR #3235 "Use updated OAuth Client ID Metadata Document RFC" (12 Ağustos 2026, açık) ve SEP-3149 "Require Token Endpoint Auth Methods Supported in CIMD" (28 Temmuz 2026, açık).
- **Karar (AG-3):** -02 implemente edilir, -00 uyumluluğu belgelenir. -02'nin MUST'ları -00'ın katı bir üst kümesidir.

#### 11.3.2 Client Identifier URL kuralları

- `https` şeması MUST. userinfo MUST NOT. Port MAY. Path MUST (`https://example.com` geçersiz, `https://example.com/client.json` geçerli). `.` ve `..` path bileşenleri MUST NOT. Query SHOULD NOT. Fragment MUST NOT.
- Karşılaştırma basit string karşılaştırmasıdır (RFC 3986 §6.2.1): `https://example.com/client` ≠ `https://example.com:443/client`.
- Kısa ve kararlı URL önerilir. URL kısaltıcılar yönlendirme kullandığı için uygun değildir. Çıplak `/` path'i önerilmez.
- `localhost` bir Client Identifier URL'i olamaz (https zorunluluğu + §8.6 özel amaçlı IP yasağı). Asimetri: `redirect_uris` içinde `http://localhost:3000/callback` sorunsuzdur; yasak olan `client_id` URL'inin kendisidir.

#### 11.3.3 Doküman şeması

- Taslak alan listesi vermez; RFC 7591 istemci metadata kayıt defterine devreder.
- Tek açık zorunlu alan `client_id`'dir: değeri Client Identifier URL'iyle ve AS'in fiilen getirdiği URL'le basit string karşılaştırmasıyla eşleşmelidir.
- `redirect_uris` dolaylı olarak zorunludur (§4.2 → RFC 9700). Yönlendirmesiz grant'lar (client_credentials, token exchange) muaftır.
- MCP ek şartı: en az `client_id`, `client_name` ve `redirect_uris`.
- AS metadata alanı: `client_id_metadata_document_supported` (boolean). -02 §6'da "AS MUST include" ile IANA kaydındaki OPTIONAL çelişir (editoryal). **Access kuralı:** alanın yokluğu "desteklenmiyor" olarak yorumlanır.
- Açık TBD: `client_id_expires_at` (geçici istemci) önerisi. → WATCH.

#### 11.3.4 AS doğrulama sırası

1. HTTP 200 kontrol edilir; diğer her durum hatadır (MUST).
2. Yönlendirmenin takip edilmediği doğrulanır (MUST NOT follow).
3. Dokümandaki `client_id` = Client Identifier URL = fiilen getirilen URL (basit string karşılaştırması).
4. Authorization isteğindeki `redirect_uri` dokümandaki kayıtlı URI'lerden biriyle tam string eşleşir. Loopback istisnası §11.3.9'dadır.

- Getirme başarısızsa taslak authorization isteğinin iptalini SHOULD seviyesinde ister. **Access kuralı (AG-4):** getirme başarısızlığında istek iptal edilir (MUST'a yükseltme; fail-closed, R2).
- **En büyük interop tuzağı.** Origin veya önek eşleştirmesi zorunlu değildir. §8.1 `redirect_uri`'yi CIMD ile aynı origin'e kısıtlamayı opsiyonel bırakır (Solid-OIDC geriye uyumluluğu). Aynı doküman bir AS'te çalışıp diğerinde reddedilebilir.
- Taslakta bulunmayanlar, yani varsayılmaması gerekenler: HTTP metodu (GET ima edilir, yazılmaz), Accept başlığı, TLS sürümü ve sertifika doğrulama şartı, zaman aşımı, hız sınırı, User-Agent. `application/json` içerik türü şartı da açıkça yoktur. **Access kuralı:** bunların hepsi identity plane'in yapılandırılmış ve beyanlı parametresidir (EA); varsayılanlar §11.4.5 #11'dedir.

#### 11.3.5 Önbellekleme

> "The authorization server MAY cache the client metadata… SHOULD respect HTTP cache headers [RFC9111]… but MAY define its own upper and/or lower bounds… MUST NOT cache error responses… MUST NOT cache documents which are invalid or malformed."

- Varsayılan TTL, ETag yeniden doğrulaması ve stale-while-revalidate yoktur.
- §8.8 `logo_uri` içeriğinin önceden getirilip önbelleklenmesini önerir.
- §9.1: her istekte getirme, kullanıcı aktivite zamanlamasını istemcinin sunucusuna sızdırır (gizlilik yan kanalı).
- **Access kuralı:** önbellek alt/üst sınırları identity plane yapılandırmasıdır (MD-14). Doküman hash'i değişince yeniden onay §11.4.5 #17'dedir.

#### 11.3.6 SSRF ve hizmet reddi

- §8.6 (taslağın en güçlü normatif metni): AS, `client_id` URL'ini **veya doküman içindeki herhangi bir URL'i** RFC 6890 özel amaçlı adreslere çözülüyorsa getirmez. Kapsam `jwks_uri`, `logo_uri`, `policy_uri`, `tos_uri` dahil tüm iç URL'lerdir.
- Loopback istisnası yalnız AS'in kendisi de loopback'te çalışan geliştirme/test kurulumu içindir. Üretimde MUST NOT.
- Bilinmeyen URI şemaları (`javascript:` gibi) getirilmez ve ayrıştırılmaz.
- §8.7: önerilen azami okuma **5 KB**'tır. Sınır dosya boyutuna değil okunan veri miktarına uygulanır; `Content-Length`'e güvenilmez, okuma kesilir.
- Taslağın kapsamadıkları: AS'in istemci sunucusuna karşı hizmet reddi/amplifikasyon, getirme hız sınırı, zaman aşımı, eşzamanlılık sınırı, metadata önbellek zehirlenmesi. Bunlar tamamen implementasyon sorumluluğudur.
- MCP güvenlik en iyi uygulamaları ek rehberlik verir:
  - Engellenecek aralıklar: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `::1`, `169.254.0.0/16` (bulut metadata), `fc00::/7`, `fe80::/10`.
  - "Avoid implementing IP validation manually. Attackers exploit encoding tricks (octal, hex, IPv4-mapped IPv6) that custom parsers often miss."
  - Yönlendirme hedefleri aynı doğrulamaya tabidir. Çıkış vekili önerilir (Stripe Smokescreen adıyla anılır).
  - DNS kontrol/kullanım arası farkı: "Consider pinning DNS resolution results between check and use."
- Diğer §8 maddeleri:
  - §8.1: `redirect_uri` kısıtı opsiyonel; kısıt yoksa bir istemci daha tanınmış bir istemciyi taklit edebilir.
  - §8.2: simetrik sır imkânsız; `private_key_jwt` bildirilirse AS istemci kimlik doğrulamasını RFC 7523 §2.2 uyarınca zorunlu kılar; attestation ve SPIFFE istemci kimlik doğrulaması taslaklarına atıf.
  - §8.3: değişen URL tamamen yeni istemcidir; "loss of control over the URL — for example through domain expiry or reassignment — would allow a third party to assume the client's identity".
  - §8.4: doküman istemci kontrolündedir ve değişebilir. AS, `redirect_uris`, `token_endpoint_auth_method`, `scope`, `grant_types`, `jwks`, `client_name` veya `logo_uri` değiştiğinde mevcut grant'ları geçersiz kılmayı ya da yeniden onay istemeyi seçebilir.
  - §8.5: AS `client_id` hostname'ini onay arayüzünde gösterir.
  - §8.9: ilk 100 kullanıcı için ek uyarı ekranı, alan adı itibarı ve yaş kontrolleri, `*.example.com` biçiminde allowlist.
  - §8.10: barındırılan bir CIMD servisi statik istemci kaydı vekili gibi davranır; bu istemciler kullanıcıya görsel olarak ayırt ettirilir.
  - §9 (gizlilik, -02'de yeni): AS getirmeleri kullanıcı aktivitesini sızdıran bir yan kanaldır; `logo_uri` ve `jwks_uri` çapraz alan adı izleme fırsatı yaratır.

**Access kuralı, CIMD dokümanının değişmesi (AG-5).**
- CIMD §8.4'ün "AS seçebilir" dediği yerde Access şunu seçer: §8.4 listesindeki authority-etkili alanlardan (`redirect_uris`, `token_endpoint_auth_method`, `scope`, `grant_types`, `jwks`) biri değişirse:
  - o istemciye bağlı onay kayıtları (§9.14.5 madde 3) geçersizleşir;
  - bir sonraki istekte AAS'li onay yeniden istenir.
- Grant'ın kendisi bu nedenle revoke edilmez. Grant istemciye değil holder'a/actor'e verilmiştir. Bu bir UI ve client-binding kararıdır (çıkarım: Access'te `client_id` Grant'ın holder'ı olmadığı için).
- Görsel alanlar (`client_name`, `logo_uri`) değişirse yalnız ekranda uyarı gösterilir (PD).
- Alan adı el değiştirmesi (§8.3) yeni istemcidir. Eski istemcinin canlı projection'ları ValidityContract horizon'una kadar yaşar; hızlandırıcı olarak o `client_id`'ye bağlı onay kayıtlarının iptali, introspection `active=false` ve etkilenen Instance'ların `session_epoch` artışı kullanılır (MD-7: `session_epoch` Instance veya Party başınadır, istemci başına değil; §9.11.1).
- §13'e aday: HL — "CIMD alan adı süresinin dolması / yeniden satışıyla istemci kimliğinin devralınması; onay kaydı ve canlı projection'lar horizon'a kadar etkilenir".

#### 11.3.7 CIMD ile DCR karşılaştırması ve DCR'ın terk edilmesi

| | CIMD | DCR |
|---|---|---|
| Çözdükleri | AS hiçbir şey yazmaz; kimlik bir URL'dir. Kayıt endpoint'i kaynaklı hizmet reddi yüzeyi yoktur. Kimlik AS'ler arasında taşınabilirdir ("No re-registration is needed when the authorization server changes"). Alan adı kontrolüne demirlidir, denetlenebilir; itibar anlamlıdır. Paylaşılan sır yoktur; confidential yol `private_key_jwt` + yayımlanmış JWKS'tir | — |
| Getirdiği problemler | AS'te dışa getirme = SSRF yüzeyi. Değişken kimlik (metadata onaydan sonra değişebilir). Erişilebilirlik bağımlılığı (üçüncü taraf HTTPS sunucusu). Alan adı ömrü riski. Taklit/oltalama çözülmemiş (aynı origin opsiyonel). Gizlilik yan kanalı. Yerel geliştirmeye düşman (localhost `client_id` olamaz). İstemci sunucusuna okuma amplifikasyonu ele alınmamış | Sınırsız veritabanı büyümesi (kayıtlar taşınamaz). İstemci süresinin dolması bir kara deliktir. Örnek başına karmaşa (aynı uygulama için yüzlerce kayıt). Kimlik doğrulamasız `/register` = AS veritabanına yazan DoS yüzeyi |
| Kaynak | — | MCP blog yazısı, Paul Carleton, 22 Ağustos 2025 |

- Sayısal gerçeklik ikincil kaynaktandır: Obsidian Security taramasında 660 AS'ten 27'si (%4) DCR, 78'den 3'ü CIMD destekliyordu (**doğrulanmadı**).

#### 11.3.8 İstemci kayıt öncelik sırası

1. Sunucu için ön kayıtlı istemci bilgisi varsa o kullanılır.
2. AS metadata'sında `client_id_metadata_document_supported: true` varsa CIMD kullanılır.
3. AS'te `registration_endpoint` varsa DCR yedek olarak kullanılır.
4. Başka seçenek yoksa kullanıcıya sorulur.

- Bu sıra OAuth **client**'ı tanımlar. Claim issuer tanımlaması ayrı bir eksendir (§9.13.8 madde 3). Bu sıra istemci tarafıdır; AS tarafı `client_id` çözümleme sırası §10.1.2'dedir (IDP-1).

#### 11.3.9 `application_type` ve loopback yönlendirmesi

- **Sorun (SEP-837).** OIDC DCR'da `application_type` atlanırsa varsayılan `"web"`tir. `"web"` istemcileri için HTTPS ve localhost-olmayan redirect URI şarttır. Çoğu MCP istemcisi yerel/CLI uygulamasıdır ve `http://localhost:PORT/callback` kullanır; kayıt sessizce reddedilir.
- **Çözüm (SEP-837, merged 28 Temmuz 2026).**
  - İstemciler DCR'da uygun `application_type`'ı belirtmelidir (MUST).
  - Yerel uygulamalar `"native"` (SHOULD), uzak tarayıcı tabanlılar `"web"` (SHOULD) kullanır.
  - İstemci redirect URI kısıtı kaynaklı kayıt hatalarını ele alabilmelidir (MUST) ve anlamlı hata gösterir (SHOULD).
  - OIDC olmayan sunucular parametreyi güvenle yok sayar.
- **Kapsam sınırı.** Spesifikasyonda gereksinim yalnız DCR altındadır; CIMD için yoktur. Pratikte gerekir: VS Code'un CIMD dokümanı (`https://vscode.dev/oauth/client-metadata.json`, 8 Eylül 2026'da çekildi) `"application_type": "native"` taşır. **Access kuralı:** AS `application_type`'ı CIMD dokümanından da okur ve dikkate alır.
- **Loopback port eşleştirmesi (kritik interop kuralı).**
  - Claude Code'un CIMD dokümanı (`https://claude.ai/oauth/claude-code-client-metadata`, 8 Eylül 2026'da çekildi) redirect URI'leri portsuz bildirir (`http://localhost/callback`, `http://127.0.0.1/callback`) ve çalışma zamanında geçici bir porta bağlanır.
  - Anthropic dokümantasyonu: "your authorization server must accept both with the port component ignored. RFC 8252 section 7.3 requires this for the IP-literal form (`127.0.0.1`); apply the same port-agnostic match to `localhost` so Claude Code works, even though RFC 8252 section 8.3 discourages `localhost`."
  - Bu, CIMD -02'nin basit string karşılaştırması ve tam eşleşme kuralıyla doğrudan çelişir.
- **Karar (AG-6).**
  - Şema, host ve path tam eşleşir.
  - Host `localhost`, `127.0.0.1` veya `[::1]` ise port bileşeni yok sayılır.
  - Loopback olmayan URI'lerde hiçbir gevşetme yapılmaz.
  - Yalnız loopback yönlendirmesi olan istemciye ek uyarı gösterilir; sessiz onay yoktur.

### 11.4 MCP Authorization Server gereksinimleri

**Plane.**
- MCP AS, identity plane AS'nin bir profilidir.
- Her token issuance `projection.issue`'dur (§9.9), dolayısıyla §9.9.3 OAuth bağlama kuralları burada da geçerlidir: tek `aud`, `cnf`, RAR, passthrough yok. Ayrıca P48, P49 ve P51 uygulanır.
- Aşağıdaki listeler MCP AS'nin normatif gereksinim listesidir. Access notu yalnız Access semantiğinin değiştirdiği yerde yazılır.

#### 11.4.1 MUST

| # | Gereksinim | MCP kaynak bölümü | Access notu |
|---|---|---|---|
| AS-M1 | OAuth 2.1'i confidential ve public istemciler için uygun güvenlik önlemleriyle implemente eder | Overview §1 | §10 |
| AS-M2 | En az bir keşif mekanizması: RFC 8414 AS Metadata veya OIDC Discovery 1.0 | Overview §5 | Access ikisini birden sunar. AS metadata Domain Metadata'dan türetilir (P60) |
| AS-M3 | `iss` yayınlıyorsa metadata'da `authorization_response_iss_parameter_supported: true` | Authorization Response Validation | §11.4.4 |
| AS-M4 | Tüm AS endpoint'leri HTTPS | Communication Security | — |
| AS-M5 | Tüm redirect URI'ler `localhost` veya HTTPS | Communication Security | — |
| AS-M6 | Redirect URI'leri ön kayıtlı değerlerle tam eşleşmeyle doğrular | Open Redirection | Loopback istisnası AG-6 |
| AS-M7 | Kullanıcı aracısını güvenilmeyen URI'lere yönlendirmez (OAuth 2.1 §7.12.2) | Open Redirection | Geçersiz redirect'e hata yönlendirmesi yoktur (§10) |
| AS-M8 | Public istemciler için refresh token rotasyonu | Token Theft | P50: reuse detection + aile iptali |
| AS-M9 | OIDC Discovery sunuyorsa `code_challenge_methods_supported` metadata'da | Authorization Code Protection | — |
| AS-M10 | CIMD destekliyorsa CIMD §6 (-02'de §8) güvenlik implikasyonları | CIMD Security | §11.3.6 |
| AS-M11 | CIMD'de getirilen dokümanın `client_id`'si URL ile tam eşleşir | Client Registration | §11.3.4 |
| AS-M12 | CIMD'de `redirect_uri` dokümana karşı doğrulanır | Client Registration | §11.3.4 |
| AS-M13 | CIMD'de doküman geçerli JSON ve zorunlu alanlar | Client Registration | §11.3.3 |
| AS-M14 | CIMD'de redirect URI hostname'i onayda açıkça gösterilir | Localhost Redirect URI Risks | Approval Surface conformance'ına girer (§9.14.5) |
| AS-M15 | Statik istemci kimliği kullanan MCP proxy'leri, üçüncü taraf AS'e yönlendirmeden önce her dinamik kayıtlı istemci için kullanıcı onayı alır | Confused Deputy | §11.6 |

#### 11.4.2 SHOULD ve MAY

| # | Seviye | Gereksinim | Access notu |
|---|---|---|---|
| AS-S1 | SHOULD | CIMD destekler | Access: destekler (AG-3) |
| AS-S2 | SHOULD | Hata dahil tüm authorization yanıtlarında `iss` (RFC 9207 §2) | **Access: MUST** (AG-7) |
| AS-S3 | SHOULD | Kısa ömürlü access token | P49: yönetimde ≤ 60 dk (PD); ajan varsayılanı §11.9.4 |
| AS-S4 | SHOULD | URL formatlı `client_id` görünce metadata getirir | — |
| AS-S5 | SHOULD | HTTP cache başlıklarına saygılı önbellek | §11.3.5 |
| AS-S6 | SHOULD | CIMD §6 değerlendirmelerini takip eder | §11.3.6 |
| AS-S7 | SHOULD | Metadata getirirken SSRF riskleri | Access: MUST (§11.3.6) |
| AS-S8 | SHOULD | Yalnız `localhost` redirect'li istemciye ek uyarı | Access: MUST (AG-6) |
| AS-S9 | SHOULD | Yalnız güvenilen redirect URI'lerine otomatik yönlendirme | — |
| AS-A1 | MAY | DCR (RFC 7591), yalnız geriye uyumluluk | PROFILE (§9.4); §11.4.5 #31–35 |
| AS-A2 | MAY | CIMD kabulü için alan adı tabanlı güven politikası | Access: politika bir identity plane config'idir (MD-14) |
| AS-A3 | MAY | Ek attestation mekanizmaları | §11.12.4 |

#### 11.4.3 RFC 8707 nüansı ve kanonik URI

- Spesifikasyon AS'in RFC 8707 desteğini hiçbir yerde MUST yapmaz ("when the Authorization Server supports the capability"). MUST'lar istemciye (`resource` gönder) ve RS'e (audience doğrula) düşer. RS audience doğrulamak zorunda olduğundan destek fiilen zorunludur: "spesifikasyon MUST'ı değil, pazar MUST'ı".
- `resource` değeri mutlak URI'dir (RFC 3986 §4.3). Fragment MUST NOT, query SHOULD NOT. Birden çok `resource` parametresi mümkündür. Hata kodu `invalid_target`'tır.
- RFC 8707'ye göre AS token'ı `resource`'a "SHOULD audience-restrict" eder. AS değeri aynen veya daha genel bir URI'ye eşleyerek kullanabilir. `resource` yoksa varsayılanla işleyebilir veya zorunlu kılabilir.
- MCP kanonik URI:
  - Geçerli: `https://mcp.example.com/mcp`, `https://mcp.example.com`, `https://mcp.example.com:8443`, `https://mcp.example.com/server/mcp`.
  - Geçersiz: şemasız `mcp.example.com`, fragment'lı `https://mcp.example.com#fragment`.
  - İstemci en spesifik URI'yi verir (SHOULD). Kanonik biçim küçük harf şema/host kullanır; implementasyon büyük harfi kabul eder (SHOULD). Sonlandırıcı eğik çizgisiz biçim tercih edilir.
- **Access kuralı (P48 ile aynı; AG-8):**
  - AS `resource`'u kayıtlı korunan kaynaklara karşı doğrular. Bilinmeyene `invalid_target` döner; aksi hâlde AS keyfi audience'lı token üreten bir oracle olur.
  - Token tek `aud` taşır. `resource` yoksa MCP profili istemi reddeder (`invalid_target`), varsayılan kaynak kullanılmaz (PD; çıkarım: tek-`aud` kuralının MCP'deki doğal sonucu).
  - Audience'sız veya çoklu audience'lı token verilmez.

#### 11.4.4 RFC 9207 `iss` (SEP-2468)

- SEP-2468 "Recommend Issuer (iss) Parameter in MCP Auth Responses": Final, Standards Track, 25 Mart 2026.
- AS için SHOULD, istemci için MUST: "MCP authorization servers SHOULD include the `iss` parameter in authorization responses, including error responses." `iss` yayınlayan AS `authorization_response_iss_parameter_supported: true` ilan eder (MUST). İstemci RFC 9207 §2.4 doğrulamasını uygular (MUST).
- İstemci karar tablosu:

  | `authorization_response_iss_parameter_supported` | Yanıtta `iss` | İstemci davranışı |
  |---|---|---|
  | `true` | Var | Kaydedilen issuer ile basit string karşılaştırması (RFC 3986 §6.2.1) |
  | `true` | Yok | Reddeder |
  | `false` / yok | Var | Yerel politikaya göre karşılaştırır |
  | `false` / yok | Yok | Devam eder |

- İstemciler `iss`'i çözdükten sonra büyük/küçük harf katlaması, varsayılan port atlaması, sonlandırıcı eğik çizgi veya yüzde kodlama normalizasyonu yapmaz (MUST NOT). `https://as.example.com` ≠ `https://as.example.com/`.
- Spesifikasyonun mix-up uyarısı: "PKCE alone does not prevent this attack… Resource indicators do not help… This mitigation depends on honest authorization servers emitting `iss`; it provides no protection against an honest server that does not."
- Gelecek: "A future revision… is expected to upgrade authorization server inclusion of `iss` from SHOULD to MUST."
- Neden issuer başına redirect URI değil: CIMD ile mümkün değil, DCR ile pahalı (SEP-2468 gerekçesi).
- **Karar (AG-7):** Access AS'si başarılı ve hatalı her authorization yanıtında `iss` yayınlar. Değer metadata'daki `issuer` ile **bayt bayt özdeştir**. `issuer` Domain Metadata'dan türetildiği için (P60) değişmesi MD-14 commit'idir.
- OpenAI tarafı bunu sert gereksinim olarak uygular (§11.8.3).

#### 11.4.5 AS endpoint'leri, metadata ve davranış listesi

**Endpoint'ler.**

| Endpoint | Zorunluluk | Notlar |
|---|---|---|
| `GET /.well-known/oauth-authorization-server` | MUST (bu veya OIDC) | RFC 8414. Path içeren issuer için `/.well-known/oauth-authorization-server/{path}` |
| `GET /.well-known/openid-configuration` | Alternatif veya ek | Path içeren issuer için hem `/.well-known/openid-configuration/{path}` hem `/{path}/.well-known/openid-configuration`; istemciler üçünü de dener |
| `GET /authorize` | MUST | PKCE S256, `resource` kabulü, `iss`, onay ekranı |
| `POST /token` | MUST | `application/x-www-form-urlencoded` zorunlu. Yalnız JSON ayrıştıran endpoint yaygın hatadır; 415 dönerse Claude bağlanamaz |
| `GET /jwks.json` | Pratikte zorunlu | Anahtarlar MD-3 / P51 |
| `POST /register` | MAY, kullanımdan kalktı | Hız sınırı, kayıt üst sınırı, TTL temizliği şart |
| `POST /revoke` | Önerilir | RFC 7009 |
| `POST /introspect` | Opsiyonel | RFC 7662. Opak token'da gerekli. Tazelik kanıtlanamazsa `active=false` (MD-8, P49) |
| `GET /userinfo` | Opsiyonel | OpenAI kurumsal alan adı kısıtı için gerekli |
| `GET`/`POST /consent` | Proxy senaryosunda MUST | Approval Surface'tir; onay AAS'tir (§9.14) |

**AS metadata, Access düzeltmeleriyle.**

```json
{
  "issuer": "https://as.example.com",
  "authorization_endpoint": "https://as.example.com/authorize",
  "token_endpoint": "https://as.example.com/token",
  "jwks_uri": "https://as.example.com/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none", "private_key_jwt", "client_secret_basic"],
  "token_endpoint_auth_signing_alg_values_supported": ["ES256", "RS256"],
  "scopes_supported": ["..."],
  "authorization_response_iss_parameter_supported": true,
  "client_id_metadata_document_supported": true,
  "registration_endpoint": "https://as.example.com/register",
  "revocation_endpoint": "https://as.example.com/revoke",
  "dpop_signing_alg_values_supported": ["ES256", "Ed25519"]
}
```

- Alan gerekçeleri:
  - `code_challenge_methods_supported: ["S256"]` yoksa MCP istemcileri devam etmeyi reddeder. OIDC keşfi sunuluyorsa orada da bulunur.
  - `authorization_response_iss_parameter_supported: true` yoksa ChatGPT/Codex uyuşmazlığı veya eksik `iss`'i reddeder.
  - `client_id_metadata_document_supported: true` CIMD'nin tek interop sinyalidir.
  - `token_endpoint_auth_methods_supported` içindeki `"none"` kritiktir; Claude CIMD'yi ancak ikisi birlikte varsa seçer, yoksa DCR'a düşer.
  - `offline_access` `scopes_supported`'a eklenirse Claude refresh token için onu ister.
  - İleride `authorization_grant_profiles_supported: ["urn:ietf:params:oauth:grant-profile:id-jag"]` ve `dpop_signing_alg_values_supported` eklenir. Access bunlardan ikincisini şimdiden ekler; ID-JAG alanı §11.11'dedir.
- **Access düzeltmeleri**:
  - (a) `token_endpoint_auth_signing_alg_values_supported` istemci assertion'ı **doğrulama** allowlist'idir. ES256 varsayılandır. RS256 yalnız identity plane'de istemci başına opt-in olarak kabul edilir; örneğin ChatGPT'nin CIMD'si `private_key_jwt` + `RS256` bildirir. Access'in kendi imzaladığı hiçbir authority artefaktı RSA kullanmaz.
  - (b) `dpop_signing_alg_values_supported` RFC 9864 fully-specified adlarla yazılır. `EdDSA` ilan edilmez ve JWS doğrulamada reddedilir (MD-3). Bu nedenle değer `["ES256","Ed25519"]`'dir; `["ES256","EdDSA"]` kullanılmaz.
  - (c) `client_secret_basic` yalnız ön kayıtlı confidential istemciler içindir. CIMD istemcilerinde simetrik sır yasaktır (§11.3.1).
  - (d) Algoritma allowlist'i header'dan değil, istemci kaydından ve metadata'dan gelir (MD-3).

**AS davranış listesi (36 madde).** Access notu `→` ile verilir.

*Authorization endpoint*
1. PKCE zorunlu; yalnız `S256`; PKCE'nin atlanabildiği hiçbir kod yolu yok (CVE-2025-4144 bir atlamaydı).
2. `redirect_uri` hem `/authorize`'da hem token takasında doğrulanır (CVE-2025-4143 yalnız takasta doğruluyordu).
3. Eşleştirme tam string; wildcard/desen yok; tek istisna loopback portu (AG-6).
4. `resource` kabul edilir, kayıtlı kaynaklara karşı doğrulanır, bilinmeyene `invalid_target` (AG-8).
5. Onay ekranı gösterilir; CIMD istemcileri için varsayılan olarak. → Ekran Approval Surface'tir; Grant AAS ile oluşur (§11.6).
6. Onay verilene kadar state çerezi kurulmaz.
7. Başarılı ve hatalı yanıtlarda `iss`, metadata `issuer`'ıyla bayt bayt özdeş (AG-7).
8. `application_type` CIMD dokümanından veya DCR kaydından okunur.
9. Yalnız loopback yönlendirmeli istemciye ek uyarı; yönlendirme hostname'i her zaman gösterilir.

*CIMD işleyicisi*
10. URL formatlı `client_id` tespiti: `https`, path var, fragment yok, userinfo yok.
11. Yönlendirme takip edilmez; yalnız 200; 5 KB'ta okuma kesilir; zaman aşımı; istemci başına hız sınırı. → Zaman aşımı ve hız sınırı değerleri EA/PD'dir.
12. RFC 6890 SSRF savunması `client_id` URL'i ve doküman içindeki tüm URL'ler için; IP doğrulaması elle yazılmaz; DNS kontrol/kullanım arasında pinlenir; mümkünse çıkış vekili.
13. Dokümandaki `client_id` getirilen URL'le basit string eşleşir.
14. Simetrik `token_endpoint_auth_method` veya `client_secret` alanı varsa ret.
15. HTTP cache başlıklarına saygı; hata/bozuk doküman önbelleklenmez; kendi üst/alt TTL sınırları.
16. `logo_uri` önceden getirilir ve sunucu tarafında önbelleklenir.
17. Doküman hash'inin anlık görüntüsü alınır; değişirse yeniden onay. → AG-5 alan sınıflandırmasıyla.
18. Alan adı güven politikası. → MD-14 config'i.

*Token endpoint*
19. `/token` `application/x-www-form-urlencoded`; `/register` `application/json`.
20. Authorization code takası atomik ve tek kullanımlık: karşılaştır-ve-değiştir (önce oku sonra yaz değil). Stateless yeniden denemeler çift takası rutinleştirir. → Code, `projection.issue` Exercise'ının girdisidir. Tek kullanımlık olması identity plane depo garantisidir (çıkarım: aynı code'la ikinci `projection.issue` nonce çakışması gibi davranır).
21. `resource`'a göre audience kısıtlı token; audience'sız veya çoklu audience'lı token yok.
22. Public istemciler için refresh rotasyonu. → P50.
23. Geçersiz refresh token'da `invalid_grant`. → StateBasis okunamıyorsa 503 + `Retry-After` (§9.11.2).
24. Kısa ömürlü access token. → P49.
25. Yanıt < 10 s (Anthropic: keşif/kayıt/token 10 s, yenileme 30 s); ters vekil veya WAF yanıtı tutmamalı.

*Onay ve iptal*
26. Sunucu tarafı onay kaydı `(user_id, client_id, resource, scopes, source, metadata_hash)`. → UI kaydıdır, `grant_ref` taşır (§9.14.5, P58).
27. Onay çerezi `__Host-` önekli, `Secure`, `HttpOnly`, `SameSite=Lax`; imzalı ve `client_id`'ye bağlı.
28. Onay sayfasında `frame-ancestors 'none'` veya `X-Frame-Options: DENY` ve CSRF token'ı.
29. Onay iptali canlı access ve refresh token'larını geçersiz kılar. → Onayın iptali bağlı Grant'ın `grant.revoke`'udur. Canlı projection'lar ValidityContract horizon'una kadar yaşayabilir; introspection ve `session_epoch` hızlandırıcıdır (§9.11). "Geçersiz kılar" garantisi UDC'dir, BS değildir.
30. Onay kimliği doğrulanmış kullanıcı kimliğine bağlanır, anonim tarayıcı oturumuna değil.

*DCR (geriye uyumluluk)*
31. IP ve kiracı bazında hız sınırı, kayıt üst sınırı, kullanılmayanlarda TTL.
32. Wildcard/desen `redirect_uri` reddi.
33. DCR kimlik bilgilerine kendi `issuer` değeri damgalanır; çapraz issuer sunumu sert reddedilir.
34. `application_type` onurlandırılır; sessiz ret yerine açık hata.
35. Redirect URI politikası sıkılaştırılınca önceki kayıtlar geriye dönük geçersiz kılınır (Square dersi).

*Çok kiracılık*
36. Çapraz kiracı okumaları açıkça test edilir (Asana olayı, §11.7). → Kararın domain'i AIS'ten gelir (P38).

### 11.5 MCP Resource Server: PEP profili

**Plane.**
- MCP sunucusu domain'in PEP'idir; Access'in kendisi değildir.
- Access, MCP RS için bir **Decision PEP / Verifier conformance profili** ve referans PEP SDK sunar (§9.12, §9.12.1 Verifier Profile Claim).
- RS'in token doğrulaması §9.10 (PAP verifier) ve §9.9.3 kurallarının MCP'ye uygulanmasıdır.
- RS-M8 ve RS-M10 (passthrough yasağı) L24 ve P48 ile birebir aynıdır.

#### 11.5.1 MUST ve SHOULD

| # | Gereksinim | Access notu |
|---|---|---|
| RS-M1 | RFC 9728 PRM implemente eder | §11.5.2 |
| RS-M2 | PRM en az bir AS içeren `authorization_servers` taşır | — |
| RS-M3 | Keşif: 401'de `WWW-Authenticate: Bearer resource_metadata="…"` veya well-known'da metadata | — |
| RS-M4 | Access token'ları OAuth 2.1 §5.2'ye göre doğrular | + `cnf` sahiplik kanıtı (DPoP/mTLS), ValidityContract horizon'u, ve varsa introspection (MD-8) |
| RS-M5 | Token'ın kendisi için üretildiğini doğrular (RFC 8707 §2) | Tek `aud` = kanonik URI (P48) |
| RS-M6 | Geçersiz/süresi dolmuş token'a 401 | — |
| RS-M7 | Yalnız kendi kaynakları için geçerli token'ı kabul eder | — |
| RS-M8 | Başka hiçbir token'ı kabul etmez veya transit ettirmez | L24 |
| RS-M9 | İsteği işlemeden önce token doğrular | INV-19: ALLOW effect'ten önce |
| RS-M10 | Upstream API çağırıyorsa istemcinin token'ını geçirmez | Upstream için ayrı projection (§11.13) |
| RS-M11 | Scope hiyerarşisini hesaba katar; geniş scope dar olanı kapsar | Scope yalnız etikettir (L24). Kapsama ilişkisi SPP'deki ActionRef hiyerarşisinden okunur; RAR varsa RAR esastır (çıkarım) |
| RS-M12 | Tüm gelen istekleri doğrular; state handle'a sahip olmak kimlik doğrulaması değildir | §11.5.5 |
| RS-M13 | `requestState` saldırgan kontrollü girdidir; yetkilendirmeyi etkiliyorsa HMAC/AEAD ile korunur; doğrulanamayan state reddedilir | §11.5.5 |
| RS-M14 | Başlık değerleri gövdeyle uyuşmazsa 400 + `-32020 HeaderMismatch` | Gövde otoritedir |
| RS-M15 | `Origin` mevcut ve geçersizse 403 | DNS rebinding savunması |
| RS-M16 | Sayfalı listelerde tüm sayfalara aynı `cacheScope` | §11.5.4 |
| RS-M17 | Primitif başına erişim kontrolü; yalnız `cacheScope`'a güvenilmez | §11.5.4 |
| RS-M18 | `ttlMs` ≥ 0 | — |
| RS-M19 | Sonraki istek için önceki isteklerden bağlam çıkarılmaz | §11.5.3 |

SHOULD:
- `WWW-Authenticate`'te `scope` parametresiyle gerekli scope'lar verilir (RFC 6750 §3).
- Yetersiz scope: 403 + `error="insufficient_scope"`, `scope="…"`, `resource_metadata`. → REQUIRE_ACTION ile ayrımı §9.9.5'tedir.
- Bir operasyonun bütün scope'ları tek challenge'da verilir; artımlı challenge UX'i bozar.
- Scope dahil etme stratejisi tutarlıdır.
- `offline_access` `WWW-Authenticate` scope'una veya PRM `scopes_supported`'a konmaz (SHOULD NOT); refresh token bir kaynak gereksinimi değildir.
- State handle'lar CSPRNG ile üretilir ve sunucu tarafında `<user_id>:<handle>` biçiminde token'dan türetilen kullanıcıya bağlanır.
- Tool'lar deterministik sırada döner (önbellek verimliliği).

#### 11.5.2 Protected Resource Metadata (RFC 9728)

| Alan | RFC seviyesi | MCP / Access notu |
|---|---|---|
| `resource` | REQUIRED | Kanonik MCP sunucu URI'si; RFC 8707 `resource` ile hizalı |
| `authorization_servers` | RFC'de OPTIONAL | MCP'de MUST, en az bir eleman |
| `jwks_uri` | OPTIONAL | RS'in kendi imza anahtarları (yanıt imzalama); token doğrulama anahtarları değildir. HTTPS |
| `scopes_supported` | RECOMMENDED | Temel işlevsellik için minimal küme, tüm katalog değil |
| `bearer_methods_supported` | OPTIONAL | MCP query'yi yasakladığı için pratikte `["header"]` |
| `resource_signing_alg_values_supported` | OPTIONAL | `none` MUST NOT. Access: MD-3 allowlist'i |
| `resource_name` | RECOMMENDED | Son kullanıcıya gösterilir. Authority-opaque'tır |
| `resource_documentation`, `resource_policy_uri`, `resource_tos_uri` | OPTIONAL | — |
| `tls_client_certificate_bound_access_tokens` | OPTIONAL, varsayılan `false` | RFC 8705 |
| `authorization_details_types_supported` | OPTIONAL | RFC 9396. Access: kabul edilen SPP'lerin RAR type görünümü (§9.13.8 madde 8) |
| `dpop_signing_alg_values_supported` | OPTIONAL | Yol haritasında DPoP var. Access: ilan edilir (RFC 9864 adlarıyla) |
| `dpop_bound_access_tokens_required` | OPTIONAL, varsayılan `false` | **Access PEP profili: `true`** (AG-9). `cnf` zorunludur (P48); mTLS kullanan RS için `tls_client_certificate_bound_access_tokens: true` alternatiftir |
| `signed_metadata` | OPTIONAL (§2.2) | JWS imzalı metadata. Access: imza MD-3'e göre |

- `resource_name`, `resource_documentation`, `resource_policy_uri`, `resource_tos_uri` BCP 47 etiketiyle çoğullanabilir (`resource_name#tr-TR`).
- **Well-known URI.** Well-known dizgisi host ile path arasına eklenir:

  | Kaynak tanımlayıcısı | Metadata URL'i |
  |---|---|
  | `https://mcp.example.com` | `https://mcp.example.com/.well-known/oauth-protected-resource` |
  | `https://mcp.example.com/mcp` | `https://mcp.example.com/.well-known/oauth-protected-resource/mcp` |
  | `https://example.com/public/mcp` | `https://example.com/.well-known/oauth-protected-resource/public/mcp` |

  - Host'tan sonraki sonlandırıcı eğik çizgi eklemeden önce kaldırılır (MUST). Sorgu HTTP GET'tir (MUST). Başarılı yanıt 200 + `application/json`.
  - Bu kullanım RFC 8615'ten farklıdır: host başına birden fazla kaynağı (çok kiracılı) destekler.
  - İstemci yedekleme sırası: `WWW-Authenticate`'teki `resource_metadata` → alt path well-known → kök well-known.
- **RFC 9728 güvenlik notları.**
  - §7.3: istemci `resource`'un kullandığı tanımlayıcıyla tam eşleştiğini doğrular (MUST).
  - §7.4: audience kısıtlı token + RFC 8707. Aksi hâlde kötü niyetli RS1 istemciyi RS2 scope'lu token almaya ikna edip token'ı RS2'de yeniden kullanır.
  - §7.6: PRM `authorization_servers` ile AS metadata'sındaki kaynak listesi çapraz kontrol edilir.
  - §7.7: istemciler iç IP aralıklarına istek göndermez (SSRF).
  - §7.10: `Cache-Control: max-age` önerilir.
- **Access kuralı (AG-10).**
  - PRM, domain'in yayınladığı bir PEP yapılandırmasıdır. `authorization_servers` listesi ve `resource` değeri MD-14 kapsamındaki config'tir.
  - PRM bir Claim kaynağı veya authority belgesi değildir. Domain Metadata ile karıştırılmaz (P60).
  - PRM'deki AS'in güvenilir sayılması istemcinin işidir. RS tarafında güven, AS'in issuer anahtarlarının Domain Metadata / Acceptance zinciriyle doğrulanmasıdır (§9.10, §9.13).

#### 11.5.3 Stateless çekirdek (SEP-2575, SEP-2567)

- `initialize` ve `notifications/initialized` kaldırıldı.
- `Mcp-Session-Id` kaldırıldı. Modern sunucu eski trafikte "ignore it, and do not mint or echo session IDs". HTTP GET/DELETE → 405. `Last-Event-ID` yok sayılır; stream'ler devam ettirilemez.
- Her istek `_meta` içinde şunları taşır: `io.modelcontextprotocol/protocolVersion` (zorunlu), `io.modelcontextprotocol/clientCapabilities` (zorunlu), `io.modelcontextprotocol/clientInfo` (opsiyonel).
- `server/discover` eklendi; sunucular implemente eder (MUST).
- "Servers MUST NOT rely on prior requests over the same connection to establish context (e.g., capabilities, protocol version, client identity)."
- Yetkilendirme metni 2025-11-25'te "…even if they are part of the same logical session" idi. 2026-07-28'de "authorization MUST be included in every HTTP request from client to server" oldu. Aynı mantıksal oturum kaçış kapısı silindi.
- `clientInfo` ve `serverInfo` "self-reported… SHOULD NOT rely on them for security decisions". `clientCapabilities` bir özellik pazarlığı girdisidir, kimlik doğrulama girdisi değildir.
- **Access eşlemesi (AG-11).**
  - Stateless çekirdek Access'in tasarımıyla uyumludur: her POST bağımsız bir karar birimidir.
  - Uzun süren iş continuation'ı MCP oturumunda değil, ADP'de yaşar: ValidityContract horizon'u, `continue` kararı ve A-8.
  - `clientInfo`, `clientCapabilities` ve `serverInfo` hiçbir zaman Claim değildir ve ADP `context`'ine karar girdisi olarak konmaz. Bunlar PEP'in yerel parse girdisidir (P37, Acceptance'sız olgu).

#### 11.5.4 `ttlMs` ve `cacheScope`: gizli bir disclosure kararı (SEP-2549)

- SEP-2549 "TTL for List Results": Final, Standards Track, 9 Nisan 2026.
- `CacheableResult` şu sonuçlarda zorunludur: `server/discover`, `tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`, `resources/read`. MRTR yeniden denemeleri önbelleklenmez (MUST NOT).
- `ttlMs`: milisaniye cinsinden tamsayı (`max-age` benzeri). 0 = hemen bayat. Yoksa 0. Negatifse 0. Sunucu ≥ 0 verir (MUST). `no-store` ve `must-revalidate` karşılığı yoktur; tek yol `ttlMs: 0`'dır ve o da bir ipucudur, yasak değildir.
- `cacheScope` yalnız iki değer alır:

  | Değer | Spesifikasyon metni |
  |---|---|
  | `"public"` | "The response does not contain user-specific data. Any client, shared gateway, or caching proxy MAY store and serve the cached response to any user." |
  | `"private"` | "Cached responses MAY be reused for the same authorization context. Caches MUST NOT be shared across authorization contexts (e.g. a different access token requires a different cache)." |

- İzolasyon birimi yetkilendirme bağlamıdır, yani access token. Kullanıcı başına veya oturum başına bir değer yoktur.
- Spesifikasyon uyarısı: "`public`" yanıtlar kimliği doğrulanmış bir endpoint'ten gelse bile çağıranlar arasında paylaşılabilir. Sunucular "MUST apply appropriate per-primitive access controls, and MUST NOT rely on `cacheScope` alone". Ayrıca "Servers MUST apply the same `cacheScope` to all response pages for a given list request".
- `tools/list` yetkilendirmeye göre değişebilir ("The set MAY vary by the authorization presented on the request… credentials are per-request input, not connection state"), ama "MUST NOT vary per-connection".
- Kesin kural: liste scope, hak veya kiracıya göre filtreleniyorsa `cacheScope: "private"` zorunludur. Tek bir yanlış `"public"` protokolce onaylanmış çapraz kiracı ifşasıdır. Spesifikasyonun kendi örneği `server/discover`'ı `"public"` işaretler; yetenek ilanı token'a göre değişiyorsa o örnek yanlıştır.

**Access kuralı (AG-12, AGI-5 adayı).**
- `tools/list`, `resources/list` ve benzeri listeler **viewer-scoped DERIVED search** sonucudur (§9.7, P41–P43). Liste içeriği bir **disclosure** kararıdır (E26).
- `cacheScope: "public"` yalnız şu durumda yayınlanabilir: listenin her öğesi bir **Public Grant**'tan türemiş ve görünürlüğü requester'dan bağımsızsa. Bu, liste viewer'dan bağımsız olarak aynıysa demektir (çıkarım: "kullanıcıya özgü veri yok" koşulunun Access karşılığı).
- Diğer bütün durumlarda `"private"` yayınlanır. Şüphede `"private"` (fail-closed).
- `"private"` önbellek izolasyon birimi MCP'de access token'dır. Access PEP SDK'sında anahtar en az `(Instance, capacity, aud, applied_pos)` içerir (çıkarım; §9.7A.4 anahtar kuralının MCP uyarlaması). Böylece aynı token'ı farklı capacity ile kullanan bir istek önbelleği paylaşmaz.
- Önbellekte bulunan liste öğesi hiçbir zaman tool çağrısının yetkisi değildir. `tools/call` her seferinde kendi kararını ister (RS-M17, A-10).
- §13'e aday: guarantee — "`cacheScope` yanlış etiketlemesiyle çapraz kiracı liste ifşası: Access PEP SDK'sında yalnız Public-Grant-türevli listeler `public` olabilir (UDC; koşul: Access PEP SDK'sını kullanan, conformance vektörünü geçen PEP, TI-RT12); PEP kendi kodunu yazarsa NG".

#### 11.5.5 State handle, MRTR ve `requestState`

**State Handle Hijacking.**
- Bu saldırı sınıfı spesifikasyonda Session Hijacking'in yerini aldı. Akış:
  1. Sunucu kimliği doğrulanmış kullanıcı için handle üretir ve tool sonucunda döner.
  2. Saldırgan handle'ı ele geçirir veya tahmin eder.
  3. Saldırgan handle'ı tool argümanı olarak geçer.
  4. Sunucu sahipliği kontrol etmezse yetkisiz erişim olur.
- Azaltmalar:
  - Tüm gelen istekler doğrulanır (MUST).
  - Handle'a sahip olmak kimlik doğrulaması sayılmaz (MUST NOT).
  - Handle'lar CSPRNG ile, deterministik olmayan biçimde üretilir (SHOULD).
  - Handle'lar sunucu tarafında `<user_id>:<handle>` ile token'dan türetilen kullanıcıya bağlanır.
- "a handle is a name, not a capability."
- Vahşi doğadaki örnekler: CVE-2026-67431 (MCP Ruby SDK, oturum sahibi bağlaması eksik) ve CVE-2026-67430 (sınırsız oturum tutma, DoS). Toplayıcı kaynaklıdır, **NVD'de doğrulanmadı**.

**MRTR (SEP-2322, Final, 3 Şubat 2026).**
- Sunucu istemciye JSON-RPC isteği gönderemez: "Servers MUST send server-to-client requests (such as `roots/list`, `sampling/createMessage`, or `elicitation/create`) using the MRTR pattern… This is a breaking change."
- Sunucu `resultType: "input_required"` ile `InputRequiredResult` döner. İçinde `inputRequests` (anahtar → `ElicitRequest` / `CreateMessageRequest` / `ListRootsRequest`) ve opak `requestState` bulunur.
- İstemci girdiyi toplar ve orijinal isteği yeni bir JSON-RPC kimliğiyle `inputResponses` + `requestState` ekleyerek yeniden POST eder.
- Yalnız `prompts/get`, `resources/read` ve `tools/call` üzerinde izinlidir.
- "servers MUST treat `requestState` as an attacker-controlled input. If `requestState` influences authorization, resource access, or business logic, servers MUST protect its integrity (e.g. HMAC or AEAD) and MUST reject state that fails verification."
- Temel bağlama: `requestState` imzalı veya AEAD korumalıdır; `(sub, client_id, resource, original_request_hash)`'e bağlanır, kısa TTL taşır ve tek kullanımlık takip edilir.

**Access kuralı (AG-13, AGI-6 adayı).**
- State handle ve `requestState` **authority taşımaz**. Bunlar Access protocol nesnesi değildir: ne Grant, ne projection, ne ExerciseID (§9.3A protocol nesnesi → ontology tablosunda yer almaz).
- `requestState` bağlaması Access'te bu dörtlünün üst kümesidir: `(actor Instance, capacity, aud, original intent digest)`. `sub` yerine actor Instance kullanılır, çünkü aynı `sub` altında farklı Instance'lar çalışabilir (Entra replikaları, §11.9.3). `client_id` aynı CIMD'yi paylaşan Instance'ları ayırmaz.
- MRTR ile yeniden POST edilen `tools/call` yeni bir istektir. Bir ALLOW önceki POST'tan devralınmaz.
- Önceki POST REQUIRE_ACTION aldıysa, `requestState` yalnız aynı **nonce**'u taşıyabilir. Karar aynı nonce + eklenen proof ile yeniden verilir (§9.9.5, P54). `requestState`'in içeriği karar girdisi değildir; yalnız nonce referansıdır.
- `elicitation/create` ile toplanan cevap approval değildir (A-5, EI-18). Approval Surface adresi elicitation ile iletilebilir (§9.9.5 MCP satırı).

#### 11.5.6 RS davranış listesi (27 madde)

| Endpoint | Zorunluluk |
|---|---|
| `POST /mcp` | MUST |
| `GET /.well-known/oauth-protected-resource` (ve varsa `/{path}`) | MUST, ya da `WWW-Authenticate` yolu |

Yalnız modern protokolü destekleyen sunucuda MCP endpoint'ine `GET` veya `DELETE` → 405.

PRM asgari biçimi:
```json
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": ["https://as.example.com"],
  "scopes_supported": ["mcp:tools-basic"],
  "bearer_methods_supported": ["header"],
  "resource_name": "Example MCP Server"
}
```
- `resource` kullanıcının girdiği MCP sunucu URL'iyle path dahil tam eşleşir. `authorization_servers` çoklu ise Claude yalnız ilkini kullanır. `scopes_supported` minimaldir. `offline_access` buraya konmaz.
- Access profili PRM'ye ayrıca `dpop_bound_access_tokens_required: true` ve `dpop_signing_alg_values_supported` ekler (AG-9).

Davranış (Access notu `→` ile):
1. Token yok/geçersiz → 401 + `WWW-Authenticate: Bearer resource_metadata="…"`; mümkünse `scope="…"`. → DPoP'lu profilde `WWW-Authenticate: DPoP` challenge'ı da verilir (RFC 9449).
2. 200 yanıtındaki `WWW-Authenticate` işe yaramaz; Claude onurlandırmaz.
3. `resource_metadata` URL'i MCP sunucusunun origin'inde olmak zorunda değildir. `/.well-known/*` sunamayan platformlar (Supabase Edge Functions, Cloudflare Workers, Lambda URL) için en güvenilir yoldur.
4. İmza ve `iss` JWKS üzerinden doğrulanır. → MD-3 allowlist'i; `alg: EdDSA` reddi; anahtar Domain Metadata'dan (P51, P60).
5. `exp` ve `nbf` doğrulanır. → + ValidityContract horizon'u (§9.11).
6. `aud`/`resource` bizi göstermiyorsa 401.
7. Yetersiz scope → 403 + `insufficient_scope`, `scope`, `resource_metadata`. → Bounds yetersizse bu; contribution gerekiyorsa REQUIRE_ACTION satırı (§9.9.5).
8. Scope hiyerarşisi uygulanır.
9. Bir operasyonun bütün scope'ları tek challenge'da.
10. Upstream API için ayrı token; istemci token'ı asla iletilmez. → §11.13.
11. Önceki isteklerden bağlam çıkarılmaz; `Mcp-Session-Id` yok sayılır.
12. `clientInfo` ve `clientCapabilities` güvenlik kararında kullanılmaz.
13. State handle'lar CSPRNG, opak, sınırlı ömürlü ve `<user_id>:<handle>` bağlı. → AG-13'e göre `<instance_id>` bağlaması.
14. `requestState` imzalı/AEAD, kısa TTL, tek kullanımlık. → AG-13.
15. Token'a göre değişen listelerde `cacheScope: "private"`. → AG-12.
16. `server/discover` token'a göre değişiyorsa `"private"`.
17. Sayfalı listede tüm sayfalara aynı `cacheScope`.
18. `ttlMs` ≥ 0.
19. `cacheScope`'a güvenilmez; primitif başına erişim kontrolü ayrıca uygulanır.
20. `Origin` varsa ve geçersizse 403 (DNS rebinding).
21. Yerelde çalışıyorsa yalnız `127.0.0.1`'e bağlanılır.
22. Başlık/gövde uyuşmazlığında 400 + `-32020`; base64 sentinel çözülüp karşılaştırılır.
23. Başlık değerlerinde CR/LF yasaktır.
24. `Mcp-Param-*` alanlarına sır düşürülmez.
25. Metadata endpoint yanıtları < 5 s.
26. SSE yanıtlarında `X-Accel-Buffering: no`.
27. `subscriptions/listen` token süresi davranışına sunucu karar verir (spesifikasyon sessiz). → AG-15.

#### 11.5.7 `server/discover` ve `subscriptions/listen`

**`server/discover`.**
- `server/discover.md`'de yetkilendirme veya 401 hakkında normatif ifade yoktur. Metot sıradan bir JSON-RPC metodudur ve "authorization MUST be included in every HTTP request" kuralına tabidir. Kimlik doğrulamasız bootstrap olarak muaf tutulmaz. Bu yorum bir **çıkarımdır**.
- Pratik bootstrap: kimlik doğrulamasız RPC → 401 + `WWW-Authenticate: Bearer resource_metadata="…"` → PRM → AS keşfi.
- **Access kuralı (AG-14):**
  - Varsayılan olarak `server/discover` de yetkilendirme ister.
  - Kimlik doğrulamasız yetenek yoklaması yalnız şu durumda açılır: domain bunu bir **Public Grant** (public selector'lı; `Anonymous(context)` actor'ün kullanabildiği, INV-11) ile açıkça verir **ve** sonuç token'dan bağımsızdır. Bu durumda sonuç `cacheScope: "public"`'tir.
  - Yetenek ilanı token'a göre değişiyorsa `"private"`'tır ve kimlik doğrulama gerekir.

**`subscriptions/listen`.**
- Yanıtı açık bir SSE stream'i olan tek uzun ömürlü istektir. `basic/patterns/subscriptions.md`'de "token", "auth", "expire" ve "401" kelimelerinin hiçbiri geçmez (sıfır eşleşme). Spesifikasyon sessizdir.
- Önerilen davranış: token süresi dolunca stream kapatılır, istemci yeniden bağlanır ("the server holds no subscription state across reconnections").
- **Access kuralı (AG-15).** Uzun ömürlü dinleme, bir **long-running exercise**'tır:
  1. Stream açılışı bir ADP kararıdır (`check` değil, `resources/read` / `subscribe` action'ının kararı). Kararın ValidityContract'ı bir `horizon` taşır.
  2. Stream, `min(token exp, ValidityContract horizon)` anında sunucu tarafından kapatılır. İstemci yeni token ve yeni kararla yeniden bağlanır. Aynı stream üzerinde token yenileme yoktur. Bu, önerilen davranışın Access'teki kesinleşmiş hâlidir.
  3. Horizon'dan önce PEP beyan edilmiş checkpoint'lerde `continue` kararı isteyebilir (A-8, E31). `continue` DENY ise stream hemen kapanır ve yeni olay gönderilmez.
  4. SSF/CAEP veya Access event'i (ör. `authority-revoked`) gelirse PEP yeniden sorar. Sinyal hızlandırıcıdır; garanti horizon'dadır (§9.16.2).
  5. Bu kurallar SEP-2643/2848 veya spesifikasyonun gelecekteki bir metnine kadar Access'in yerel kararıdır. Upstream'e taşınması §9.17 backlog'undadır.
- §13'e aday: guarantee — "`subscriptions/listen` stream'i horizon sonrasında olay taşımaz (UDC: Access PEP SDK'lı, conformant PEP; PEP kendi kodunu yazarsa NG)".

### 11.6 Onay (consent) ↔ Grant: confused deputy

- Temel tespit: "Onay problemi RFC 8707 ile çözülmemektedir. Confused deputy'nin çözümü istemci başına onay kaydıdır. Gerçek dünyada en çok istismar edilen açık budur".
- Access'te çözüm iki katmanlıdır (§9.14.5 madde 3, P58):
  - **Yetki:** kullanıcının AAS-imzalı `grant.issue`'su (gerekirse `mandate.bind`). Holder = istemci Instance'ı değil, actor Party/Instance'ıdır. İstemci `client_id`'si Grant'ın AgencyTerms'üne bir **kısıt** olarak girebilir (ör. "yalnız bu CIMD URL'iyle kimliği doğrulanan Instance'lar"; çıkarım: istemci kimliğinin Access'te yalnız actor-binding kısıtı olabilmesi).
  - **UI kaydı:** `(user_id, client_id, resource, scopes, source, metadata_hash, grant_ref)`. Tekrar sormayı engeller; authority değildir.

**Uygulama kuralları (Access notu `→`).**
1. Onay kaydı her upstream yönlendirmesinden önce kontrol edilir. → Kontrol = `grant_ref`'in hâlâ geçerli olması. Kayıt var ama Grant yoksa → DENY ve yeniden onay.
2. Onay çerezi veya oturumu, kullanıcı onaya tıklamadan önce asla kurulmaz. "Bu tek sıralama hatası confused deputy saldırısının tamamıdır."
3. `state` CSPRNG ile üretilir, yalnız onaydan sonra sunucu tarafında saklanır, callback'te tam eşleşir, doğrulamadan sonra silinir. TTL ≤ 10 dk.
4. Onay çerezi `__Host-` önekli, `Secure`, `HttpOnly`, `SameSite=Lax`; imzalı ve belirli bir `client_id`'ye bağlıdır.
5. Onay anonim tarayıcı oturumuna değil kimliği doğrulanmış kullanıcıya bağlanır (Obsidian'ın çerez enjeksiyonu atlatması bu yüzden mümkün oldu).

**Proxy AS (AS-M15).**
- Statik istemci kimliğiyle üçüncü taraf AS'e giden bir MCP proxy'si, her dinamik kayıtlı istemci için kullanıcı onayı alır.
- Access'te bu proxy bir **credential broker** durumudur (§11.13). Upstream AS'ten alınan token Access'in kararı + projection'ıyla ajana verilir. Proxy'nin statik upstream kimliği hiçbir zaman ajanın authority'si değildir (MD-13: possession ≠ authority).
- `GET`/`POST /consent` bu senaryoda MUST'tır (§11.4.5); ekran Approval Surface'tir.

**Onay iptali.**
- Onay iptali = bağlı Grant'ın `grant.revoke`'u. Onay kaydı ve refresh ailesi temizlenir (P50).
- Canlı access token'lar horizon'a kadar yaşayabilir. "Onay iptali canlı token'ları geçersiz kılar" maddesi (§11.4.5 #29) Access'te UDC'dir: introspection `active=false` ve SSF hızlandırıcıdır (§9.11.2).

### 11.7 Güvenlik tuzakları ve vahşi doğadaki olaylar

- Sıralama, gerçek dünyada en çok zarar veren tuzaklara göredir.
- Onay tuzakları §11.6'da, istemci kimliği tuzakları §11.3–11.4'te, stateless dönem tuzakları §11.5'tedir.
- Bu bölüm token tuzaklarını ve olay kaydını taşır.

**Token tuzakları.**
15. `resource` onurlandırılır, tek ve doğru `aud` damgalanır, kayıtsız `resource` reddedilir (AG-8).
16. Audience'sız veya çoklu audience'lı token verilmez. Upstream token asla kendi token'ımız gibi kabul edilmez (RS-M8).
17. RFC 9207 `iss` yayınlanır (AG-7).
18. PKCE S256 zorunlu; `code_challenge_methods_supported` ilan edilir; PKCE kod yolu seviyesinde atlanamaz (CVE-2025-4144).
19. Kısa ömürlü access token; public istemcilerde refresh rotasyonu.
20. Authorization code takası atomik ve tek kullanımlık (CAS). Stateless yeniden denemeler çift takası rutinleştirir; oradaki yarış bir kod yeniden oynatma açığıdır.

**Stateless dönem ek tuzakları.**
- Ağ geçidi arkasındaysa gövde otoritedir:
  - başlık/gövde uyuşmazlığı reddedilir;
  - protokol sürüm başlığı istenir ve doğrulanır;
  - `Mcp-Param-*`'ta sır tutulmaz;
  - başlıkta CR/LF yasaktır;
  - base64 sentinel karşılaştırmadan önce çözülür.
- Çok kiracılıkta Asana olayı egzotik bir saldırı değil düz bir izolasyon mantık hatasıydı. Çapraz kiracı okumaları açıkça test edilir.

**Vahşi doğadaki CVE'ler.**
- Tablo **toplayıcı kaynaklıdır**. NVD ve CVE.org detay sayfaları doğrudan doğrulanamamıştır. Alıntılamadan önce NVD JSON API ile teyit edilir. Bu spec'te hepsi **doğrulanmadı** statüsündedir.
- Access'in hangi kuralının hangi sınıfı kapattığı:

| CVE | Bileşen | Kusur sınıfı | Access/MCP profili kuralı |
|---|---|---|---|
| CVE-2026-27124 | `fastmcp < 3.2.0` | Proxy callback'te onay doğrulaması eksik, confused deputy (CWE-441) | §11.6 kural 1–2; AS-M15 |
| CVE-2026-31944 | LibreChat | MCP OAuth callback ile hesap ele geçirme | §11.6; `state` kuralları |
| CVE-2026-42073 | OpenClaude | Callback'te CSRF ile `state` atlatması | §11.6 kural 3 |
| CVE-2026-62800 | FastMCP | Callback'te yansıtılmış XSS | Approval Surface conformance (§9.14) |
| CVE-2026-42230 | n8n | MCP OAuth açık yönlendirme | AS-M6/M7 |
| CVE-2026-46549 | NocoDB MCP | Token scope atlatması | RS-M17; ALLOW envelope'a bağlı (INV-19) |
| CVE-2026-49291 | mcp-memory-service | Okuma scope'uyla `tools/call` | Scope etikettir; `tools/call` kendi kararını ister (§11.2, L24) |
| CVE-2026-25536 | MCP TypeScript SDK | Transport yeniden kullanımından çapraz istemci sızıntısı | RS-M19; AG-12 önbellek izolasyonu |
| CVE-2026-67430 / -67431 | MCP Ruby SDK | Sınırsız oturum (DoS); oturum sahibi bağlaması eksik | AG-13 |
| CVE-2026-12112 | foreman-mcp-server | Gizli olmayan oturum kimliğiyle ele geçirme | AG-13 ("isim, yetenek değil") |
| CVE-2026-77822 / -18905 | IBM ContextForge MCP Gateway | DNS rebinding | RS-M15; §11.5.6 #20–21 |
| CVE-2026-81315 | ash_ai MCP HTTP transport | DNS rebinding; `X-Forwarded-Proto` origin doğrulaması eksik | RS-M15 |
| CVE-2026-24052 | `@anthropic-ai/claude-code` | WebFetch güvenilir alan adı atlatması | Kapsam dışı istemci kusuru; tool çıktısı authority-opaque (A-7) |
| CVE-2026-32625 | LibreChat | MCP URL interpolasyonu ile sır sızıntısı | AGI-3 (LLM ve istemci sırları ayrımı, §11.13) |

- Toplu istatistikler de toplayıcı kaynaklıdır ve doğrulanmadı:
  - `mcp-security-project/mcp-cve-project` 570'ten fazla MCP CVE'si iddia eder.
  - Temmuz 2025 taramasında 1.862 herkese açık MCP örneği kimlik doğrulamasız yanıt veriyordu; yalnız %8,5'i OAuth kullanıyordu.
- arXiv 2605.22333 (21 Mayıs 2026, Fudan) 7.973 canlı uzak MCP sunucusunu inceledi:
  - %40,55'i hiçbir kimlik doğrulaması olmadan tool açıyor;
  - OAuth kullanan 119 sunucunun %100'ünde en az bir kusur var, toplam 325 kusur;
  - %96,6'sında DCR kusuru var.
  - Tam PDF ayrıştırılamadı, özet kullanıldı.
- **Asana olayı (CVE değil).**
  - Özellik 1 Mayıs 2025'te yayımlandı; hata 4 Haziran 2025'te bulundu; erişim 17 Haziran 2025'te geri verildi.
  - Deneysel MCP sunucusundaki bir kiracı izolasyon mantık hatası yaklaşık 1.000 organizasyon arasında görev verisini, proje metadata'sını, ekip ayrıntılarını, yorumları ve dosyaları ifşa etti.
  - İhlal ya da prompt enjeksiyonu değildi; düz bir çok kiracılık yetkilendirme hatasıydı.
- §13'e aday: HL — "MCP sunucusunda kiracı izolasyon mantık hatası (Asana sınıfı): karar domain'i AIS'ten gelmezse (P38) veya liste önbelleği `public` işaretlenirse (AG-12) çapraz kiracı ifşası".
- §13'e aday: RR — "Toplayıcı kaynaklı MCP CVE tablosu doğrulanmadan tehdit modeli girdisi yapılıyor; NVD teyidi bekliyor".

**Güvenlik araştırmaları.**

| Kaynak | Bulgu | Access'teki karşılığı |
|---|---|---|
| Doyensec, "The MCP AuthN/Z Nightmare" (5 Mart 2026) | ID-JAG kurumsal model analizi: (1) erişim geçersizleştirme/iptal mekanizması yok; (2) "The IdP issues an ID Token with no scopes embedded", yüksek riskli scope'lar için onay penceresi tetiklenmiyor; (3) `audience`'ın `resource`'a bağlandığı doğrulanmıyor (scope ad alanı çakışması, kaynak tanımlayıcı enjeksiyonu); (4) ID-JAG yeniden oynatma amplifikasyonu: tek JAG ile çok access token, tek kullanımlık `jti` zorunlu | §11.11.4 (dört bulgunun dördü de kural) |
| Trail of Bits | Line jumping saldırısı (21 Nisan 2025), `mcp-context-protector` | Tool açıklaması authority-opaque (A-7); §11.20 |
| Invariant Labs | Tool zehirlenmesi PoC, GitHub MCP istismarı, Toxic Flow Analysis (yetkili tool çağrılarının kompozisyonu), `mcp-scan` | Kompozisyon riski: lineage budget + RestrictionPolicy (A-9); bilgi akışı kontrolü WATCH (§11.20) |
| Obsidian Security | Square'de tek tıkla hesap ele geçirme, token geçirme, anonim oturumun state'e bağlanması, çerez enjeksiyonu | §11.6 kural 2, 5; AS #35 |
| Cloudflare (14 Ağustos 2026) | `MCP-Protocol-Version` ile protokol tespiti, gölge MCP tespiti; DCR kalktığı için MCP Portals'a ön kayıtlı istemci | §11.3.8 sıra 1 |
| NSA/CISA "MCP: Security Design" (2 Haziran 2026 tarihli PDF) | PDF açılamadı | **Doğrulanmadı**; okunmalı (§11.23) |

### 11.8 Ekosistem, interop ve yol haritası

#### 11.8.1 SDK'lar ve Rust boşluğu

- **TypeScript.**
  - `@modelcontextprotocol/sdk` 1.30.0, `LATEST_PROTOCOL_VERSION = '2025-11-25'`; `main` 2.0.0-alpha.0.
  - AS implementasyonu `packages/server-legacy/`'ye taşındı. `protocolEras.ts` `'legacy'` ve `'modern'` çekirdeklerini ayırır.
  - RFC 9207 istemci tarafında tam (`IssuerMismatchError`). CIMD için `OAuthClientProvider.clientMetadataUrl` var.
- **Python.**
  - `mcp` 2.2.0. AS implementasyonunu korur.
  - `TokenVerifier` çıplak bir `Protocol`'dür. Yerleşik JWT/introspection doğrulayıcısı yoktur. Audience zorlaması isteğe bağlıdır. DPoP yalnız bildirimseldir.
- Her iki resmî SDK da PAR uygulamaz ve DPoP zorlamaz.
- **Rust.**
  - `rmcp` v3.2.0 (31 Ağustos 2026) OAuth desteği **yalnız istemci tarafıdır**: `TokenVerifier`, bearer middleware, PRM sunumu ve `WWW-Authenticate` yayını yoktur. PAR, DPoP ve RAR yoktur.
  - `rust-mcp-sdk` v2.0.0 (üçüncü taraf) tam RS desteği taşır. Keycloak sağlayıcısı öğreticidir: MCP sunucusu kendi PRM'sini sunar ve `aud`'ı kendisi doğrular; `disable_audience_validation` "strongly discouraged" bir kaçış kapısıdır. Keycloak yalnız token üreticisidir.
  - %100 conformance iddiası kendi beyanıdır (**doğrulanmadı**).
- **Rust OAuth sunucu yapı taşları.**
  - `oxide-auth` 0.6.1, iki buçuk yıl bayat, OAuth 2.0 dönemi; üzerine inşa edilmez.
  - `oauth2` 5.0.0 ve `openidconnect` 4.0.1 yalnız istemci tarafıdır.
  - `jsonwebtoken` 11.0.0 ve `aws-lc-rs` 1.18.1 aktiftir.
  - `jwt-authorizer` 0.15.0 bayattır.
  - `dpop-verifier` 4.4.0 en inandırıcı DPoP yapı taşıdır.
  - Vargı: "Rust'ta olgun ve genel amaçlı bir OAuth 2.1 Authorization Server crate'i yoktur."
- **Access notu.**
  - Bu tablo bir crate seçimi değildir. Kripto ve bağımlılık seçimi §15/§16'dadır (MD-3: `rsa` crate'i kullanılmaz).
  - Access PEP SDK'sının MCP RS desteği (PRM sunumu, `WWW-Authenticate`, DPoP doğrulaması, `Authorized<R,A>`, P40) bu boşluğu doldurur. Bu bir ürün kararıdır ve WATCH değildir (AG-16; statü PD, karşılığın yeterliliği EA).

#### 11.8.2 Conformance

- `github.com/modelcontextprotocol/conformance` resmî çatıdır; istemci ve sunucuyu kapsar.
  - Doğrulanmış yetkilendirme senaryoları: `auth/basic-dcr`, `auth/basic-metadata-var1`, `auth/basic-cimd`. Tam liste **sayılamadı** (GitHub API hız sınırı).
  - `--spec-version` 2025-11-25 ve 2026-07-28'i destekler. SEP-1730 katmanlaması ve `tier-check` vardır.
- Örnek komutlar:
  ```bash
  npx @modelcontextprotocol/conformance server --url http://localhost:3000/mcp
  npx @modelcontextprotocol/conformance client --command "…" --suite auth
  npx @modelcontextprotocol/conformance list
  ```
- **Karar (AG-17).** MCP conformance `auth` süiti, OIDF conformance süiti (§10) ve Access conformance vektörleri (T12) **birlikte** CI'dadır. Biri diğerinin yerine geçmez. MCP süiti Access semantiğini (Grant, REQUIRE_ACTION, ValidityContract) test etmez; Access vektörleri MCP wire biçimini test etmez. Test stratejisi §14'tedir.

#### 11.8.3 Sağlayıcılar ve istemci interop gerçekleri

**Sağlayıcılar.**

| Sağlayıcı | CIMD | DCR | RFC 9728 | RFC 8707 | Not |
|---|---|---|---|---|---|
| WorkOS AuthKit | Var (panelden, varsayılan kapalı) | Var | Var | Var | En güçlü doğrulanabilir MCP hikâyesi; Cross App Access erken erişimde |
| Cloudflare `workers-oauth-provider` | Var | Var | Her zaman | Var | Amaca özel en eksiksiz açık kaynak MCP AS'i |
| Keycloak | Deneysel (26.6.0) | Var | Muhtemelen yok | Bilinmiyor | Son sürüm 26.7.3 |
| Clerk | Beta (5 Ağustos 2026) | Bilinmiyor | Bilinmiyor | Bilinmiyor | — |
| Auth0 | "Yakında" | Bilinmiyor | Bilinmiyor | Bilinmiyor | Sayfalar erişilemedi |
| Stytch, Descope, Scalekit | oauth.net listesine göre var | Bilinmiyor | Bilinmiyor | Bilinmiyor | Doğrulanmadı |
| Okta, Entra ID | Kanıt yok | Var | Bilinmiyor | Entra `resource` destekler; MCP URL'i Application ID URI olmalı, yoksa `AADSTS9010010` | — |

- Değerlendirilmeyenler: Ory Hydra, Zitadel, Logto, Authentik, SuperTokens, node `oidc-provider`, MCP ağ geçitleri.

**Anthropic/Claude.** Bağlantı türleri: `oauth_dcr` ve `oauth_cimd` hazır; `oauth_anthropic_creds` ve `custom_connection` istekle; `static_headers` beta; `none`. Kritik ayrıntılar:
- Saf `client_credentials` desteklenmez ("Every connection requires user consent").
- Her istekte `code_challenge_method=S256` gönderilir.
- CIMD seçimi iki koşula bağlıdır: `client_id_metadata_document_supported: true` **ve** `token_endpoint_auth_methods_supported` içinde `"none"`. Biri yoksa DCR'a düşülür.
- Scope kontrolü için 401 `WWW-Authenticate`'inde `scope` verilir. Verilmezse PRM `scopes_supported` istenir. AS metadata'sında `offline_access` varsa o da eklenir.
- 401 şarttır: "Claude does not honor a `WWW-Authenticate` header on a `200` response."
- Çoklu `authorization_servers`'ta yalnız ilki kullanılır.
- Zaman aşımları: keşif/kayıt/token 10 s, yenileme 30 s.
- Token endpoint form kodlu, `/register` JSON kullanır.
- Yenileme 401'de tepkisel, süre dolmadan 5 dk önce öngörücüdür.
- Çıkış aralığı `160.79.104.0/21`'dir; WAF akışı bozabilir.
- Callback'ler: barındırılan yüzeyler `https://claude.ai/api/mcp/auth_callback`; Claude Code RFC 8252 loopback, geçici port (AG-6).
- Anthropic dokümantasyonu hâlâ 2025-11-25 sayfalarına bağlanır.

**OpenAI Apps SDK.**
- PKCE S256 zorunlu; `code_challenge_methods_supported` yoksa sunucu desteklenmez.
- CIMD tercih edilir: `token_endpoint_auth_method` `none` veya `private_key_jwt`; DCR yedektir.
- ChatGPT `resource` gönderir; AS bunu `aud`'a kopyalar.
- RFC 9207 sert gereksinimdir: "Clients use exact string comparison and do not normalize trailing slashes, paths, ports, or casing."
- OpenAI tarafından yönetilen mTLS sertifikası veya yayımlanan çıkış IP'leri.
- "ChatGPT does not support machine-to-machine OAuth grants such as client credentials."
- Yeniden yetkilendirme için `id_token_hint` onurlandırılır. Kurumsal alan adı kısıtı için OIDC metadata'sı, `openid`/`email` ve UserInfo gerekir.
- ChatGPT CIMD'si (8 Eylül 2026'da çekildi): `token_endpoint_auth_method: private_key_jwt`, `token_endpoint_auth_signing_alg: RS256`, `jwks_uri`. → MD-3: RS256 doğrulaması identity plane'de istemci başına opt-in.
- `token_endpoint_auth_methods_supported` bir RFC 7591 istemci alanı değildir; AS bilinmeyen alanlara toleranslı olmalıdır.
- OpenAI'nin tool başına `securitySchemes` dizisi MCP çekirdeğinde yoktur; OpenAI'ye özgüdür.

**Interop sonucu (beyan).**
- Bugünkü Claude ve ChatGPT MCP bağlayıcılarının DPoP/mTLS ile sender-constrained token kullandığına ve Access AIS ürettiğine dair kanıt yoktur. DPoP yol haritasında "ileride"dir; resmî SDK'lar DPoP zorlamaz (§11.8.1). **doğrulanmadı.**
- PI-11 ve PI-7 gereği bu istemciler Access MCP PEP profilinde yalnız `Anonymous` actor olarak Public Grant'ları kullanabilir. Kullanıcı adına (FOR(P)) Access authority'si bu istemcilere bearer token ile **verilmez**.
- Yollar:
  - (a) istemcinin DPoP desteği (SEP-1932, WATCH);
  - (b) kullanıcının kendi cihazındaki conformant istemci/Instance;
  - (c) PEP'in, authority taşımayan eski profilde (TN-27) yalnız Public kapsamı sunması.
- Bir proxy veya gateway'in holder olması çözüm değildir: PEP actor olamaz (E17, PI-7).
- §13'e aday: RR — "Ana akım MCP istemcilerinin sender-constraint/AIS desteği gelene kadar Access-korumalı MCP sunucuları bu istemcilere yalnız Public kapsam sunar (benimseme riski; PI-11 bilinçli olarak korunur)". (§12.10 ile ortak aday.)

**Karar (AG-18).**
- Satıcıya özgü kurallar (Claude, OpenAI) normatif profil değildir. Ayrı bir **interop eki**nde tutulur (§11.8.3 bu ekin çekirdeğidir) ve tarih damgalıdır.
- Normatif olan, bu kuralların türetildiği standart maddeleridir: RFC 9207 bayt eşleşmesi, PKCE ilanı, form kodlu token endpoint, 401 zorunluluğu.
- Satıcı davranışı değişirse ek güncellenir, profil değişmez.

#### 11.8.4 Yol haritası ve SEP'ler

- MCP yol haritası (22 Ağustos 2026, Soria Parra & Delimarsky): üçüncü öncelik ajan kimliği ve kurumsal güvenliktir. "MCP authorization today is built around a person approving access in a browser… more and more of the callers are agents running as cloud workloads with their own identity."
- İş akışları: DPoP, Workload Identity Federation, Enterprise-Managed Authorization'ın ID-JAG grant'ı, standart token takası. Ayrıca Server Card WG ("so a server can be discovered and reasoned over without connecting to it").

| SEP / PR | Başlık | Son güncelleme | Access statüsü ve eşleme |
|---|---|---|---|
| SEP-1932 | DPoP Profile for MCP | 7 Eylül 2026 | WATCH. Access PEP profili DPoP'u şimdiden zorunlu tutar (AG-9) |
| SEP-1933 | Workload Identity Federation | 7 Eylül 2026 | WATCH → §11.12 |
| SEP-2752 | HTTP Message Signing for MCP Client Authentication | 7 Eylül 2026 | WATCH. RFC 9421 imzası bir KeyBinding proof'udur, actor proof (AIS) değildir (L21) |
| SEP-2643 | Structured Authorization Denials | 6 Eylül 2026 | WATCH. REQUIRE_ACTION/DENY eşlemesi §9.9.5 |
| SEP-2848 | Asynchronous Approval for Tool Calls | 7 Eylül 2026 | WATCH. Bekleyen nesne = nonce (P54); §11.14 |
| SEP-2817 | AI Invocation Audit Context in Request `_meta` | 24 Ağustos 2026 | WATCH. `_meta` audit bağlamı PEP'in iddiasıdır, Claim değildir. Exercise kaydı esastır (çıkarım) |
| SEP-3149 | Require Token Endpoint Auth Methods Supported in CIMD | 17 Ağustos 2026 | WATCH; §11.3.1 |
| PR #3235 | Use updated CIMD RFC | 12 Ağustos 2026 | WATCH; -02 zaten uygulanıyor |
| PR #3191 | Authorization guide around CIMD | 3 Ağustos 2026 | Bilgi |

- Karar: DPoP ve RFC 8693 için mimaride bugünden yer bırakılır; `dpop_signing_alg_values_supported` metadata'ya şimdiden eklenir. Access bunu benimser (§11.4.5).

### 11.9 Ajan modeli: ajan = Instance

#### 11.9.1 Authority plane'de ajan

- **Kural (AG-19, FROZEN semantik).** Authority plane'de bir ajan, bir Party'nin altındaki **Instance**'tır. Party, ajanın operatörü, kullanıcının kendi ajan Party'si (`operated-by`) veya kurumdur.
  - Instance'ın kimliği InstanceID'dir. Güncel proof materyali KeyBinding'dir (DPoP / mTLS / WIT `cnf`). Çalışma ortamı iddiası Attestation Claim'idir (L21).
  - Ajanın authority'si yalnız Grant'tan gelir (MD-4). Capacity, basis Grant'ın AgencyTerms'üyle belirlenir: OWN veya Grant'ı veren principal Q için FOR(Q) (INV-4 agency continuity). Mandate authority kaynağı değildir. Ajan Instance'ının **kendi** holder Party'sinin (operatör veya ajan Party'si) o Instance'a bağladığı zarftır ve yalnız exercisability'yi daraltır (C14, INV-11). Bir principal başka bir Party'nin Instance'ına Mandate bağlayamaz; başkasının Instance'ına `mandate.bind` protocol rejection'dır. Ajanın FOR(P) eylemi FOR(P) AgencyTerms'lü Grant olmadan DENY'dır (`capacity-mismatch`). Ajan, kullanıcının kendi Instance'ıysa (`agent-kind = local`, §11.19) zarf kullanıcının kendi `mandate.bind`'idir.
  - LLM sağlayıcısı kendiliğinden authority sahibi değildir (EI-6; §11.19 ortak kuralı).
- "Principal" Access'te bir entity değildir (C5 ontology kararı). `enum Principal { User, ServiceAccount, Agent }` gibi bir tip authority plane'de yoktur.
- Ajana özgü ayrı bir authority primitive'i **yoktur** (F15). Ajanın farkı şablonlardadır:
  - agent Grant şablonunda zorunlu budget;
  - delegasyon derinliği ≤ 1;
  - `downstreamHolderClass` = aynı operatörün ajanları;
  - eşik-bitişik tekrar ve mass-selection guard'ları (§13.7.6, "Structuring, laundering ve abuse desenleri", POLICY DEFAULT).

#### 11.9.2 Identity plane'de ajan kaydı: `IdentitySubject`

- Identity plane'in iç kaydında ajan, kimlik doğrulama yöntemi ve yaşam döngüsü farklı olduğu için ayrı bir kayıt tipi olabilir. Ad **`IdentitySubject`**'tir; "Principal" kullanılmaz.
- Kayıt authority plane'e yalnız Claim olarak çıkar:
  - `party-kind=agent` (veya Instance'ın `agent-kind = cloud | local | enterprise | robot`, §11.19);
  - InstanceID Claim'i;
  - operatör/sponsor ilişki Claim'leri.
- Tipli bir ajan kaydının (`AgentIdentity`) alanlarının Access karşılığı (AG-20):

| `AgentIdentity` alanı | Access karşılığı | Not |
|---|---|---|
| `id`, `identifier: WorkloadUri` (`spiffe://`/`wimse://`, opak UUID değil) | InstanceID + `identity-binding.workload` Claim'i | Hiyerarşik URI politika seçicisi olarak kullanılabilir. Seçici bir rule-shaped Grant'ın selector'ıdır (MD-4), joker karakter yetki vermez |
| `blueprint_id` | Ajan Grant **şablonu** (Template, C15) + operatör Party'si | Entra blueprint ≈ Access şablonu + ortak KeyBinding politikası (çıkarım) |
| `owner_user_id`, `sponsor_user_id` | **İlişki** Claim'leri: `operated-by`, `sponsored-by` (Party → Party) | Bu bağlar ilişki olarak modellenir, kolon olarak değil. Çok sahipli ve devredilen ajan şema değişikliği gerektirmez |
| `tenant_id` | AuthorityDomain (AIS'te imzalı `domain`, P38) | Token'daki `tenant` karar girdisi değildir |
| `agent_type`, `protocols` | Instance metadata Claim'i | Karar girdisi ancak Acceptance'lı predicate-input olarak |
| `status: Active / Suspended / Disabled` | Instance lifecycle (`instance.create` / `instance.terminate`) + identity plane hesap durumu | Askıya alma = Instance terminate veya Grant restriction; ayrı "suspended" authority durumu yok |
| `trusted_instance_issuers`, `x509_spiffe_ids`, `jwks_uri` | Acceptance (`actor-binding` use'u) + KeyBinding | Attester modeli §11.12.4 |
| `inheritable_scopes`, `direct_scopes`, `authorization_details` | Grant (şablondan türeyen) + RAR projection'ı | Scope authority değildir (L24) |
| `max_delegation_depth: u8 // varsayılan 4` | Grant DelegationTerms `depth` (şablon varsayılanı ≤ 1) | §11.10.4. Politika varsayılanı 4 reddedilir (AG-25); birim farkı: toplam ↔ kalan |
| `default_token_ttl` ("insan token'larından ÇOK kısa") | ValidityContract horizon şablon varsayılanı | §11.9.4 |

- **FusionAuth karşılaştırması.** Entity/grant grafiğinde yeni aktör tipi eklemek veridir. Tipli bir ajan modelinde şema değişikliği gerekir; buna karşılık altı ajan değişmezi derleme zamanında zorlanabilir.
- **Access'in yeri (çıkarım).** Access iki yaklaşımın üçüncü bir yolunu kullanır:
  - Ajan tipi veridir (Claim).
  - Değişmezler tipte değil, Grant cebrindedir: attenuation ⊆, lineage budget, depth ve Mandate kesişimi (INV ailesi, §6).
  - Böylece "değişmezler genel grafikte ifade edilemez" itirazı Access'te geçerli değildir. Değişmezler genel grafikte değil, Grant lineage'ında ifade edilir.

#### 11.9.3 Ölçek: replika, oturum ve görev (Entra Agent ID dersleri)

- **Entra modeli.**
  - Agent identity kendi kimlik bilgisi olmayan özel bir service principal'dır.
  - Blueprint kimlik bilgilerini tutar; blueprint principal token alır ve audit'te görünür.
  - Sponsor sorumlu insandır.
  - "The subject of the token is a user, while the actor is the agent identity."
- **Entra'nın tasarım dersleri:**
  - Ölçeklenen replikalar ayrı ajan kimliği gerektirmez ("…adds directory objects and management overhead without any audit, access control, or accountability benefit").
  - Bellek ve bağlam yönetimi oturum kimliğiyle filtrelenir.
  - Yüksek hacimde "use shared agent identities and rely on session or context identifiers at the application layer".
- **Access kuralı (AG-21).** Access'te bu üç seviye ayrıdır ve her biri modelde vardır:

| Seviye | Access nesnesi | Kural |
|---|---|---|
| Ajan "ürünü" / blueprint | Operatör Party'si + Grant şablonu | Authority burada değil, Grant'larda |
| Çalışan kopya / replika / oturum | **Instance** | Audit atfı ve iptal birimi Instance'tır. Replika başına ayrı Instance zorunlu değildir: aynı KeyBinding'i paylaşan replikalar tek Instance'tır. Ancak o zaman iptal ve audit de birlikte olur. Görev başına Instance önerilir (§11.19 cloud agent satırı: "her oturum/görev bir Instance") |
| Tek eylem | Exercise (ExerciseID, nonce) | `agent_instance_id` Instance'ı, ExerciseID eylemi tanımlar |

- McGuinness'in problem tanımı ("every agent session collapses into one identity, defeating per-agent authorization, audit attribution, incident response, and abuse containment") Access'te Instance seviyesiyle çözülür. `agent_instance_id` claim'i InstanceID'nin projection'ıdır (§11.17).
- Toplu iptal: bir ajanın bütün Instance'larının sonlandırılması `instance.terminate` kümesidir. `POST /agents/{id}/revoke-all` uç noktası bu kümenin kolaylık yüzeyidir (§9.16.2, P59).

#### 11.9.4 Ajan projection'ının varsayılan horizon'u

- Ajan token'larının varsayılan ömrü (`default_token_ttl`) insan token'larından çok kısadır. Teleport notu: çok kısa ömür yenileme trafiğini ve yük profilini belirler; ikisi birlikte tasarlanır.
- Singapur CSA: "time-bound or one-time-use credentials".
- **Karar (AG-22, PD).** Ajan Instance'ına verilen projection'larda:
  - **exact-intent token** (RAR `kind=intent`): ömür = intent validity'si. Tek kullanımlıktır; `jti` / nonce tüketilir.
  - **bounds token**: varsayılan horizon ≤ 15 dk. Bu bir POLICY DEFAULT önerisidir; sayı bir dış kaynaktan alınmamıştır. Üst sınır insan projection'ındaki P49 sınırıdır (yönetimde ≤ 60 dk).
  - Refresh ömrü ≤ Grant/Mandate bitişi (`draft-ietf-oauth-refresh-token-expiration-03`'ün "The refresh token MUST NOT expire later than the user authorization expires" kuralıyla aynı yön, P50).
  - Consumption-bearing action'lar bounds token'la yapılamaz (§9.9.1).
- 15 dk değeri ENGINEERING ASSUMPTION'dır. Yük profili (§17) ile doğrulanır.

### 11.10 Delegasyon zinciri: `act`'in zayıflığı ve Access lineage'ı

#### 11.10.1 `act` bir denetim izidir, yetki kanıtı değildir

- RFC 8693 §4.1: tüketiciler yalnız üst düzey claim'lere ve `act` ile tanımlanan **mevcut** aktöre bakar. Önceki aktörler yalnız bilgilendiricidir ve erişim kontrolü kararlarında dikkate alınmamalıdır.
- `act` bir denetim izidir, yetki kanıtı değildir; bu tasarım gereğidir.
- Çelişki: neredeyse tüm ajan taslakları `act`'i delegasyon kanıtı gibi kullanır; bu bir standart ihlali riskidir.
- Access zaten aynı yerdedir: L22 ("Prior actor'ler token'dan değil Access lineage'ından doğrulanır") ve §9.9.4 kural 3.

#### 11.10.2 Delegation Chain Splicing

- **Kaynak.** IETF OAuth posta listesi, "Security Consideration: Delegation Chain Splicing in RFC 8693 Token Exchange", `cbchhaya`, 27 Şubat 2026. Birincil mesaj gövdesine erişilemedi; mekanizma açıklaması ikincildir (WorkOS, 27 Nisan 2026). **Doğrulama kısmi.**
- **Mekanizma.** Ele geçirilmiş bir aracı, farklı delegasyon bağlamlarından bir `subject_token` ve bir `actor_token` sunar. STS ikisini bağımsız doğrular ve hiç gerçekleşmemiş bir zinciri iddia eden, usulüne uygun imzalı bir token üretir.
- **Kök neden.** RFC 8693 iki token arasında çapraz doğrulama zorunlu kılmaz. ID-JAG da `actor_token`'a izin verir ama "this specification does not define normative processing requirements" der ve aynı riski uyarır.
- **Posta listesi azaltması.** `aud[N] == sub[N+1]` kriptografik eşleşmesi, kısa TTL, arka kanal iptali.
- **Access'te splicing yapısal olarak imkânsızdır (AG-23, AGI-1 adayı).**
  - Token exchange (RFC 8693) Access'te actor'ün kendi `projection.issue` Exercise'ıdır.
  - Çıkan token'daki iç içe `act` zinciri **yalnız Access lineage kaydından** üretilir. Gelen `subject_token`/`actor_token`'dan kopyalanmaz (§9.9.4, P53).
  - `subject_token` ve `actor_token` en fazla Claim girdisidir. Actor'ün FOR(P) Grant'ı lineage'da yoksa çıkış DENY'dır. Bu, `aud[N]==sub[N+1]` kontrolünden daha güçlüdür, çünkü eşleşme token çiftinde değil kayıtlı lineage'da aranır (çıkarım).
- §13'e aday: guarantee — "Splicing: iki geçerli token'dan sahte zincir üretilemez (BS; lineage kaydı tek kaynak)".

#### 11.10.3 Yedi rakip taslak

| Taslak | Rev./tarih | Yaklaşım | Access statüsü |
|---|---|---|---|
| `draft-liu-oauth-chain-delegation` | 00, 8 Haziran 2026 | `delegation_chain` claim'i; çift imza (`as_signature`, `delegator_signature`), ayrık JWS + JCS (RFC 8785); `record[i].delegator_id == record[i-1].delegatee_id`; ≤ 5 sıçrama | WATCH; biçimi `delegation_chain` PROFILE seçeneğinde (AG-24) |
| `draft-mcguinness-oauth-actor-profile` | 00, 30 Nisan 2026 | `sub` yetkilendiren; en dış `act.sub` doğrudan aktör; kanonik aktör `(act.iss, act.sub)`; asgari derinlik 4; continuation ve rebind modları | Üç değişmez benimsenir (§9.9.4) |
| `draft-asor-wimse-agent-delegation-chain` | 01, 3 Eylül 2026 | Ed25519/ES256/ML-DSA; `del_depth`, `del_max_depth`, `par_hash`, `cnf`; 8 adımlı çevrimdışı doğrulama | WATCH. Çevrimdışı doğrulama Access'te PAP ile yapılır (§9.10) |
| `draft-niyikiza-oauth-attenuating-agent-tokens` | 01, 15 Haziran 2026 | Macaroon/biscuit ilhamlı, asimetrik; 6 değişmez, 8 kısıt tipi, kapalı dünya | WATCH (L27; Biscuit REJECT, §9.4) |
| `draft-hamr-oauth-agent-delegation` | 01, 2 Eylül 2026 | `Agent-Delegation` HTTP başlığı; scope kapsaması, taban gevşetmeme, süre uzatmama; RFC 9421 zorunlu | WATCH |
| `draft-li-oauth-delegated-authorization` | 03, 24 Temmuz 2026 | `cnf.jkt` bağlama; istemci çocuk token'ı kendi anahtarıyla imzalar, AS'e gitmez; DPoP zorunlu | REJECT (yerel türetme). AS'siz türetilen token bir projection değildir; Access'te attenuation PAP alt-dilimiyle yapılır |
| `draft-mcguinness-oauth-mission` | 00, 6 Temmuz 2026 | Mission: onaylanmış göreve bağlı dayanıklı artefakt; `intent_hash`, `authority_hash` | WATCH. Kavramsal karşılığı Mandate + intent digest'tir |

- Değerlendirme: bu sağlıklı bir standartlaşma değildir; aynı problemin yedi rakip çözümüdür. En güçlü adaylar actor-profile ve liu'dur.

#### 11.10.4 Kanonik zincir, `delegation_chain` ve derinlik

- **Karar (AG-24).**
  - Kanonik delegasyon zinciri Access **lineage kaydıdır** (MD-4).
  - Token'a interop için iç içe `act` yazılır (projection, L22).
  - `delegation_chain` claim'i yalnız bir **PROFILE seçeneği** olarak üretilebilir. İçeriği Grant lineage'ının imzalı excerpt'idir: imza MD-3, anahtar projection imza anahtarı (P51). Verifier'a ipucu değeri taşır. Çevrimdışı doğrulama Access artefaktıyla (PAP) yapılır.
  - Rakip taslakların "güvenli üst kümesi" ihtiyacını Access'te zaten lineage karşılar. Yeni bir token formatı icat edilmez (L20).
- **Derinlik (AG-25).** Ekosistemde "4" iki ayrı anlamda geçer; Access'te üç ayrı sayı vardır:
  - **Ayrıştırıcı ≥ 4 seviye `act`** destekler (interop asgarisi; actor-profile). **Tutulur.**
  - `AgentIdentity.max_delegation_depth` varsayılanı 4 (toplam zincir tavanı, politika) **reddedilir:** ajan Grant şablonu varsayılanı DelegationTerms `depth` ≤ 1'dir. Bu kalan hop sayısıdır, yani kullanıcı → ajan → bir alt-ajan; `downstreamHolderClass` = aynı operatörün ajanları. Gerekçe: ajan zincirlerinde her ek hop prompt-enjeksiyon yüzeyidir; derinlik ihtiyacı açık şablonla genişletilir (CT3, INV-9).
  - Lineage'ın genel tavanı ≤ 16'dır (§13.7.4, SI-20).
  - Kanonik sınır Grant DelegationTerms'tedir. Token'daki `del_max_depth` gibi alanlar yalnız projection'dır.
- **Altı delegasyon değişmezinin Access karşılığı (AG-26):**

| # | Delegasyon değişmezi | Access karşılığı |
|---|---|---|
| 1 | Tek yönlü daraltma `child.scopes ⊆ parent.scopes` | Attenuation: alt Grant ⊆ üst Grant (INV ailesi, §6) |
| 2 | TTL monotonluğu `child.exp ≤ parent.exp` | Alt Grant ve projection ValidityContract'ı üst lineage'ın bitişini aşamaz |
| 3 | Derinlik monotonluğu | DelegationTerms `depth` |
| 4 | Zincir sürekliliği `record[i].delegator_id == record[i-1].delegatee_id` | Lineage kaydının yapısal özelliği (her Grant'ın grantor'u üst Grant'ın holder'ı) |
| 5 | Kesişim semantiği (downstream = kendi ∩ çağıranın) | Effective = AuthoritySet ∩ Mandate ∩ lineage budget'ları; WEF ACAP: "An orchestrating agent cannot delegate authority it does not itself hold" |
| 6 | Sahiplik kanıtı: yaprak token'ı sunan özel anahtarı kontrol eder | `cnf` zorunlu (P48) + AIS (actor proof) |

- Not: Bu değişmezler taslaklarda token/kod seviyesindedir. Access'te bunlar kayıt seviyesinde INV'lerdir. Bu yüzden yeni invariant gerekmez; eşleme bir conformance test listesidir (§14).

### 11.11 ID-JAG, MCP Enterprise-Managed Authorization ve Identity Chaining (MD-18)

- **Karar (AG-27, MD-18).** Identity plane ID-JAG'ı hem **üretir** (IdP AS rolü) hem **tüketir** (Resource AS rolü).
- Semantik:
  - ID-JAG bir **Claim/assertion taşıyıcısıdır**, authorization grant değildir.
  - Resource AS rolünde verilen access token `projection.issue` çıktısıdır. Dayanağı Acceptance + Grant'tır.
  - IdP hiçbir zaman grantor değildir (L6, E18).
- ID-JAG bugün ajan delegasyonunu çözmez; kullanıcı çoklu oturum açmasının uygulamalar arası taşınmasını çözer.

#### 11.11.1 Yapı ve akış (birincil metinden)

- `draft-ietf-oauth-identity-assertion-authz-grant-04`: 21 Mayıs 2026, süre bitişi 22 Kasım 2026. Yazarlar A. Parecki (Okta), K. McGuinness, B. Campbell (Ping). `draft-ietf-oauth-identity-chaining`'in bir profilidir.
- Token yapısı:

```
Header: { "typ": "oauth-id-jag+jwt" }        ← ZORUNLU, tip karışıklığına karşı
Payload:
  iss        IdP AS'in issuer identifier'ı            ZORUNLU
  sub        Kullanıcının IdP namespace'indeki id'si  ZORUNLU
  aud        Resource AS'in issuer identifier'ı        ZORUNLU
  client_id  Resource AS'teki client identifier'ı      ZORUNLU
  jti        Benzersiz id (replay)                     ZORUNLU
  exp, iat                                             ZORUNLU
  resource   RFC 8707 Resource Identifier              OPSİYONEL (MCP profilinde MUST)
  scope                                                OPSİYONEL
  email / aud_sub  JIT provisioning için               ÖNERİLEN
```

- Akış:
  1. IdP token endpoint'ine `POST /token`: `grant_type=…token-exchange`, `requested_token_type=urn:ietf:params:oauth:token-type:id-jag`, `audience=<Resource AS issuer>`, `subject_token=<ID Token | SAML | Refresh Token>`.
  2. Yanıt `{"issued_token_type":"…id-jag","access_token":"<JWT>","token_type":"N_A","expires_in":300}`. `token_type` `N_A`'dır, çünkü bu bir bearer token değil bir grant'tır.
  3. Resource AS token endpoint'ine `POST /token`: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `assertion=<ID-JAG>`.
  4. Resource AS audience kısıtlı access token verir.
- Keşif metadata'sı:
  - IdP AS: `identity_chaining_requested_token_types_supported` ∋ `urn:ietf:params:oauth:token-type:id-jag`.
  - Resource AS: `authorization_grant_profiles_supported` ∋ `urn:ietf:params:oauth:grant-profile:id-jag`.

#### 11.11.2 Access'te üretim (IdP AS rolü)

- ID-JAG üretimi, kullanıcının (veya ajanın FOR(P) Instance'ının) **`projection.issue` Exercise'ıdır** (identity assertion projection'ı; authority taşımaz). Dayanağı şablondan türetilmiş bir Grant'tır: ID-JAG'ın verilip verilmeyeceğini Grant şablonu belirler.
- **Ontology sınıfı.** Access'in ürettiği ID-JAG, authority taşımayan bir **kimlik iddiası projection'ıdır**. Authority scope içermez. Authority, RS tarafında (Resource AS) Access Grant'ından gelir: Resource AS Access ise §11.11.3'teki Grant'tan; Access dışı bir Resource AS ise oradaki yetki o AS'in kendi kararıdır (dış owner). Ürün holder-bound authority projection'ı olmadığı için PI-11 ve P48'in `cnf` kuralının kapsamı dışındadır (`token_type=N_A`). Sızan bir ID-JAG senaryosunda Access'in hiçbir BS iddiası dış AS davranışına bağlı değildir: ID-JAG Access authority'si iddia etmez.
- "Uygulamalar arası bağlantı politikası" tuple'ı `(requesting_client_id, resource_as_issuer, resource_identifier, allowed_scopes, subject_policy)` ve `CrossAppConnection` veri modeli **bir Grant şablonuna + Acceptance'a derlenir** (AG-28):

| Bağlantı politikası alanı | Access karşılığı |
|---|---|
| `requesting_client_id` | Grant AgencyTerms'ünde istemci kısıtı (actor-binding koşulu) |
| `resource_as_issuer`, `resource_identifier` | Projection hedefi: `aud` = Resource AS issuer; `resource` = MCP kanonik URI |
| `allowed_scopes` | Bağlantı politikasının filtresi: hangi scope'ların Resource AS'ten istenebileceği. ID-JAG'a Grant-türetilmiş authority olarak yazılmaz; taşınan `scope` varsa → ID-JAG'da `scope` ipucu (R3), authority değil |
| `subject_policy` | Rule-shaped Grant selector'ı (kimler) + RestrictionPolicy |
| `subject_mapper` (`idp_user_id` → resource app'in `sub`'ı) | Pairwise PartyRef takma adı (MD-10, P52; her projection'da domain-pairwise, §9.9.3 k.8) |

- Yönetici ayarı ayrı bir authority kaynağı değildir. Bağlantının eklenmesi/değişmesi bir domain action'ıdır (MD-14).
- Üretim kuralları:
  - (a) `typ: oauth-id-jag+jwt` header'ı zorunludur.
  - (b) İmza MD-3'e göre JOSE ES256'dır. Kimlik iddiası olduğu için realm JOSE anahtarıyla imzalanır (§9.9.3 k.7); authority taşımaz.
  - (c) `exp` kısa tutulur (örnek 300 s). Ömür ValidityContract horizon'una tabidir.
  - (d) MCP profilinde `resource` zorunludur.
  - (e) Token exchange'te istemci kimlik doğrulaması SSO'daki kadar sıkıdır (MCP EMA profil kısıtı).
  - (f) `actor_token` gelirse Access iç içe `act`'i lineage'dan üretir ve `actor_token`'ı yalnız actor-binding Claim'i olarak kullanır. Normatif işleme taslakta tanımsızdır (§11.10.2).

#### 11.11.3 Access'te tüketim (Resource AS rolü)

- Inbound ID-JAG bir **Claim taşıyıcısıdır**. Eşlemesi §9.13.8 madde 2'dedir: claim identity = `jti`, issuer = `iss`, subject = `sub` (+`iss`) → PartyRef, validity = `exp`, attribution evidence = imza.
- Karara yalnız aktif bir `actor-binding` veya `predicate-input` Acceptance'ının use'u için girer (Ingest kural 1).
- Doğrulama adımları (beş adım; Atlassian/Okta üretim kanıtı; AG-29):
  1. İmza ve issuer JWKS'ten doğrulanır. Issuer, `actor-binding` Acceptance'ı olan bir IdP olmalıdır (§9.13). Allowlist MD-3'tür.
  2. `typ == oauth-id-jag+jwt` (tip karışıklığına karşı).
  3. `aud` bu Resource AS'in issuer'ını gösterir.
  4. **İstemci sürekliliği.** ID-JAG'daki `client_id`, token endpoint'inde kimliği doğrulanan istemciyle eşleşir. Bunu atlayan implementasyonlar vardır.
  5. `exp`, `iat` ve `jti` tekilliği kontrol edilir. `jti` yeniden oynatma önbelleğinin TTL'i = `exp`'tir.
- Sonra Access kararı gelir:
  - `sub` → PartyRef çözümü;
  - aktif bir Grant (şablondan, rule-shaped) aranır;
  - karar ALLOW ise projection üretilir. Projection tek `aud` = MCP kanonik URI ve `cnf` taşır (P48). Authority, gelen ID-JAG'dan değil bu Access Grant'ından gelir.
  - Grant yoksa → `invalid_grant` (DENY) veya REQUIRE_ACTION eşlemesi (§9.9.5).
- `jti` önbelleği kaybolursa (ör. failover) ID-JAG kabulü fail-closed'dur. Önbellek tazeliği kanıtlanamıyorsa yeni ID-JAG istenir (çıkarım; MD-7 "never seen" fail-closed kuralının uyarlaması).

#### 11.11.4 Doyensec bulgularının kapatılması

| Doyensec bulgusu | Access kuralı |
|---|---|
| Erişim geçersizleştirme / token iptali yok | Projection ValidityContract horizon'una tabidir. Dayanak Grant revoke edilince yeni projection çıkmaz. SSF/`session_epoch` hızlandırıcıdır (§9.11, §9.16.2) |
| IdP ID Token'da scope yok; yüksek riskli scope'ta onay penceresi tetiklenmiyor | ID-JAG authority taşımaz. Yüksek riskli action için Grant şablonu RequirementTerm (contribution) taşır ve REQUIRE_ACTION döner (§9.9.5). Onay Approval Surface + AAS'tir |
| `audience`'ın `resource`'a bağlandığı doğrulanmıyor (scope ad alanı çakışması, kaynak tanımlayıcı enjeksiyonu) | `resource` kayıtlı kaynağa karşı doğrulanır (AG-8). Projection'da authority RAR'daki ActionRef'tir; ActionRef namespace'i SPP'den gelir, scope adı çakışması authority üretmez (L24) |
| ID-JAG yeniden oynatma amplifikasyonu (tek JAG → çok token) | `jti` tek kullanımlık (AG-29 adım 5). Her ID-JAG en fazla bir `projection.issue` girdisidir (PD) |

#### 11.11.5 MCP Enterprise-Managed Authorization

- Statü stabil; MCP `ext-auth` deposunda. "This document defines an application of the 'Identity Assertion JWT Authorization Grant' for use within enterprise deployments of the Model Context Protocol (MCP)."
- Rol eşlemesi:
  - Client = MCP istemcisi;
  - RS = MCP sunucusu;
  - Resource AS = PRM'de ilan edilen AS;
  - IdP AS = kurumsal SSO IdP (Access identity plane).
- Profil kısıtları:
  - `audience` = Resource AS issuer'ı (MUST);
  - `resource` verilirse MCP sunucusunun RFC 9728 tanımlayıcısıdır (MUST);
  - IdP token exchange'te istemci kimlik doğrulamasını SSO'daki kadar sıkı uygular;
  - ön kayıtlı değilse istemci CIMD'sini `client_id` olarak kullanabilir.
- Spesifikasyondan örnek payload:

```json
{ "jti":"9e43f81b64a33f20116179", "iss":"https://acme.idp.example",
  "sub":"U019488227", "email":"user@example.com",
  "aud":"https://auth.chat.example/", "resource":"https://mcp.chat.example/",
  "client_id":"f53f191f9311af35", "exp":1311281970, "iat":1311280970,
  "scope":"chat.read chat.history" }
```

- Ekosistem kanıtı:
  - IdP: Okta, Ping, Descope, Keycloak (devam ediyor).
  - İstemci: Claude, VS Code, WorkOS.
  - Kaynak: Slack, Notion, Figma, Linear, Asana, Datadog, Atlassian.
  - Keycloak 26.5 ID-JAG'ı önizleme olarak tüketir ama üretemez (keycloak#43971, hedef 26.7.0; ikincil kaynak, **doğrulanmadı**).
- Access notu: EMA'da `email` alanı JIT provisioning içindir. Minimize edilir (E26) ve yalnız `identity-binding` Claim'i olarak kullanılır; PartyRef birincil anahtarı `sub`'dır.

#### 11.11.6 Identity Chaining ve FiPA

- **Identity Chaining** (`draft-ietf-oauth-identity-chaining-17`).
  - IESG'den geçti, RFC Editor kuyruğunda; Proposed Standard, 19 Temmuz 2026.
  - RFC 8693 + RFC 7523 ile güven alanları arasında kimlik ve yetki taşır; ID-JAG'ın üst kümesidir.
  - **Access statüsü: ADOPT (taşıyıcı).** Alanlar arası zincirde dayanak §9.15A'dır: Foreign Authority Proof, bridging Grant veya cross-domain delegation. Identity chaining yalnız kimlik iddiasını taşır. Workload/identity federation authority federation değildir (L25).
- **FiPA** (`draft-ietf-oauth-first-party-apps-04`).
  - WG uzlaşısında; Authorization Challenge Endpoint; `auth_session` (cihaza bağlı, DPoP'la bağlanabilir); hata kodları `invalid_session`, `insufficient_authorization`, `redirect_to_web`.
  - Tarayıcısız/başsız istemci için resmî OAuth desenidir. SPA'da XSS nedeniyle önerilmez.
  - Uygulama ayrıntısı §10'dadır. REQUIRE_ACTION eşlemesindeki `insufficient_authorization` kullanımı §9.9.5'tedir.

### 11.12 Workload taşıyıcıları: SPIFFE, WIMSE, Transaction Tokens, attestation

**Ortak kural (L21, L25; AG-30).**
- Workload kimliği ("bu süreç kim") bir **actor-binding Claim'i ve KeyBinding**'dir.
- Authority ("kimin adına, ne yetkiyle") Grant/Mandate'tir.
- SPIFFE trust domain ≠ Access identity domain ≠ AuthorityDomain.
- Katmanlama: SPIFFE birinci katmandır ve sürecin kim olduğunu söyler; Access ikinci katmandır ve kimin adına, ne yetkiyle sorusunu cevaplar.

#### 11.12.1 SPIFFE / SPIRE ve SPIFFE istemci kimlik doğrulaması

- **JWT-SVID kuralları.**
  - `sub` = SPIFFE ID.
  - `aud` zorunlu; doğrulayıcı kendi tanımlayıcısını bulamazsa reddeder.
  - `exp` zorunlu.
  - Anahtar SPIFFE bundle'daki JWK (`use: jwt-svid`).
- WIT-SVID kuluçkada ve JWT-SVID'in aday halefidir:

  | | JWT-SVID | WIT-SVID |
  |---|---|---|
  | Tip | Bearer | Sahiplik kanıtı |
  | `cnf` | Yok | Zorunlu |
  | `aud` | Zorunlu | Yasak |

- **SPIFFE'in ajanlar için dört sınırı:**
  - SPIRE adanmış altyapı ister;
  - X.509 üretim gecikmesi geçici ajan yaratımıyla uyumsuzdur;
  - protokoller arası kimlik akışı yoktur;
  - delegasyonu hiç modellemez ("bu süreç nedir" sorusunu çözer, "kimin adına" sorusunu çözmez).
- **SPIFFE istemci kimlik doğrulaması** (`draft-ietf-oauth-spiffe-client-auth-02`).
  - Üç yöntem:
    - JWT-SVID (`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe`);
    - X.509-SVID mTLS (SPIFFE ID SAN URI'de);
    - WIT-SVID + Client Attestation PoP.
  - SPIFFE Bundle Endpoint zorunludur.
  - Yazarlar arasında Stian Thorgersen (Keycloak) vardır; implementasyon durumunda Keycloak listelenir.
- **Access statüsü.**
  - SPIFFE kimliği: ADOPT (actor-binding girdisi, §9.4).
  - SPIFFE istemci kimlik doğrulaması identity plane'de ADOPT edilir ve bugün implemente edilir.
  - Taslak durumu korunur (WG Doc). Bu bir istemci kimlik doğrulama yöntemidir, authority değildir.
- Hiyerarşik tanımlayıcı (`spiffe://acme.example/agent/finance/*`) bir Grant selector'ı olabilir. Joker kalıp yetki vermez, Grant'ın kapsadığı holder kümesini tanımlar (MD-4, rule-shaped Grant).

#### 11.12.2 WIMSE: WIT, WPT, tanımlayıcı ve mimari

- WIMSE'den henüz hiç RFC çıkmamıştır. WG dokümanları:
  - `wimse-arch-08`, `http-signature-06`, `identifier-03`, `mutual-tls-02`, `workload-creds-02`, `wpt-02`;
  - `workload-identity-practices-06` Informational RFC yolundadır.
- **WIT** (`typ: wit+jwt`): "MUST prove possession of the corresponding private key… MUST NOT be used as a bearer token and is not intended for use in the Authorization header."
  - Claim'ler: `sub` (iş yükü URI'si), `exp`, `cnf` (`jwk` içinde `alg` zorunlu), `iss`, `jti`. Ayrı HTTP başlıkları kullanılır.
  - Bearer geçiş uyarısı: "the decision which token to prefer is made when the caller's identity has still not been authenticated, and needs to be revalidated following the authentication step."
- **WPT** (`typ: application/wpt+jwt`, 27 Ağustos 2026):
  - `alg` WIT `cnf`'iyle eşleşir;
  - claim'ler `aud` (HTTP hedef URI), `exp`, `jti`, `wth` (WIT hash), `tth` (Txn token hash), `oth`;
  - `WPT` kimlik doğrulama şeması; hata `401` + `WWW-Authenticate: WPT`.
- **Tanımlayıcı**: `spiffe://…` veya `wimse://<trust-domain>/<path>`. Query/fragment/userinfo/port yasak; ≤ 2048 bayt; tam URI karşılaştırması. "Identifiers require cryptographic credential context to be considered authenticated."
- **Mimari §3.4.11**: AI aracıları delegasyonlu iş yüklerinin özel hâlidir. Upstream güvenlik bağlamı açıkça yetkilendirilmedikçe yayılır. Otonom eylemler delegasyonlu olanlardan ayrı kimliklerle ayrılır ("cryptographic binding of delegation tokens or attestation"). Çok ajanlı zincirde her sıçramada bağlam yeniden bağlanır.
- **Access statüsü.**
  - WIT/WPT bir **taşıma ve KeyBinding kanıtıdır**, actor kanıtı (AIS) değildir.
  - WIT `cnf`'i Instance KeyBinding olabilir.
  - "Otonom eylem ayrı kimlik" kuralı Access'te capacity ayrımıdır: OWN ile FOR(P) aynı Instance'tan farklı beyanla yapılır (A-1).
  - Access projection'larında bearer varsayılan değildir (`cnf` zorunlu, P48).
- WIMSE ajan delegasyon taslakları WATCH'tır:
  - `draft-reece-wimse-cross-org-delegation-02`: 7 problem, 10 gereksinim;
  - `draft-asor-…`;
  - `draft-sweeney-wimse-credential-delegation-00` (içerik incelenmedi);
  - `draft-rampalli-…`.
  - IETF 126'da "SOOS: Mandate JWT & Cross-Principal Transaction ID (XPID)" sunuldu. Adı Access Mandate'iyle örtüşür; içerik doğrulanmadı.

#### 11.12.3 Transaction Tokens (`draft-ietf-oauth-transaction-tokens-11`)

- WG uzlaşısında; üçüncü WGLC planlı.
- `typ: txntoken+jwt`. Claim'ler `txn`, `sub`, `aud` (güven alanı; alanlar arası kullanımı engeller), `scope`, `tctx` (değişmez işlem bağlamı), `rctx` (istek bağlamı), `req_wl` (isteyen iş yükü).
- RFC 8693 ile `requested_token_type=urn:ietf:params:oauth:token-type:txn_token` kullanılır. HTTP başlığı `Txn-Token`.
- **Access statüsü (PROFILE, §9.4):**
  - Txn-Token PEP'ler arası bağlamı taşır ve `causal: audit-only`'dir (§11.19 enterprise agent satırı).
  - Bir mikroservis zincirinde her consequential effect kendi ALLOW'unu veya exact-intent projection'ını ister. Txn-Token tek başına ALLOW değildir (INV-19).
  - `tctx` içine Access ExerciseID/intent digest konabilir (PD, çıkarım).

#### 11.12.4 Attestation tabanlı istemci kimlik doğrulaması ve "attester'ı kim yapar"

- `draft-ietf-oauth-attestation-based-client-auth-11` (3 Eylül 2026):
  - Client Attestation JWT (Client Attester'dan, örneğin anahtarına bağlı) ve Client Attestation PoP JWT;
  - başlıklar `OAuth-Client-Attestation`, `OAuth-Client-Attestation-PoP`, `OAuth-Client-Attestation-Challenge`.
- DPoP ortak anahtar modu: "the Client Instance Key and the DPoP Key are the same asymmetric key pair". Tek DPoP kanıtı hem attestation hem gönderici kısıtlamasıdır.
- Doğru mimari desen: donanım attestation'ı kayıt anında bir kez anahtarın donanımda yaşadığını kanıtlar; her istekte DPoP o anahtarın kullanıldığını kanıtlar.
- **Teleport sorusu.** İlk kanıtı kim toplar? İki cevap farklı güven modeli üretir:
  1. **Access delili kendisi toplar** (TPM quote, Android KeyDescription, Apple App Attest). Güven kökü donanım üreticisidir. Platform formatlarını bilmek maliyetlidir.
  2. **Access bir attester'ın imzaladığı iddiaya güvenir** (`tbot` modeli). Güven kökü attester'ın kendisidir; attester ele geçirilirse her iş yükü taklit edilebilir.
- **Karar (AG-31, Access modeliyle cevap).** Access'te iki model de aynı yapıdır: **Attestation bir Claim'dir** ve issuer'ı bir Acceptance ile kabul edilir (L21, §9.13).
  - Model 1'de issuer donanım üreticisinin kök anahtarıdır. Acceptance'ın issuer identification yöntemi pinned key / sertifika zinciridir.
  - Model 2'de issuer attester'dır. Acceptance attester'ı ve **hangi Claim class'ını imzalamaya yetkili olduğunu** kaydeder. Bu, controller'ın issuer yetkilendirmesidir (§9.13.1).
  - `trusted_instance_issuers` listesi yeterli değildir; hangi attester'ın hangi iddia tipini imzalamaya yetkili olduğu modellenmelidir. Bu, Acceptance'ın class kısıtıyla zaten karşılanır.
  - Seçim domain'in Acceptance kararıdır; ürün düzeyinde tek model dayatılmaz.
  - Attester ele geçirilmesi bir Acceptance revoke'u / lapse'idir (INV-23 ingest cutoff).
- §13'e aday: HL — "Attester (model 2) ele geçirilmesi: o attester'ın Acceptance'ı altındaki bütün actor-binding'ler taklit edilebilir; sınır Acceptance class kısıtı + KeyBinding".
- **AIMS** (`draft-klrc-aiagent-auth-03`, 6 Temmuz 2026). Bireysel taslak; yazarlar Kasselman, Lombardo, Rosomakho, Campbell, Steele (OpenAI), Parecki.
  - Yeni protokol icat etmez; WIMSE + OAuth + SPIFFE'i birleştirir.
  - Yedi bileşen: tanımlayıcılar, kimlik bilgileri, sağlama, kimlik doğrulama, yetkilendirme, gözlemlenebilirlik, düzeltme ve uyum ölçümü. "Sekiz katman" iddiası doğrulanmadı; ham metinde yedi bileşen var.
  - **Access statüsü: WATCH** (§9.4 korunur). Alıntıları gerekçe olarak alınır:
    - "The Large Language Model MUST NOT have access to an agent's credentials or to credentials that may be needed to access tools and services." (§8) → AGI-3, §11.13.
    - "An identifier alone is insufficient unless it can be verified to be controlled by the communicating agent through a cryptographic binding." → L21; `cnf` zorunlu.
    - "Such interactions do not by themselves constitute authorization and MUST be bound to a verifiable authorization grant issued by the authorization server… the agent MUST NOT treat local UI confirmation alone as sufficient authorization." (§10.7) → A-5, EI-18; §11.14.
    - Mission → yetkilendirme gereksinimlerine çeviri AIMS kapsamı dışındadır (§10.1). Access'te bu çeviri Approval Surface'te insanın onayladığı **typed intent**'tir (A-6), modelin değil.
- **Atıf notu.** İkili kimlik ve üç delegasyon akışı AIMS'te değil, `draft-ni-wimse-ai-agent-identity-02`'dedir (Huawei, süresi 1 Eylül 2026'da doldu; ham metinde grep ile doğrulandı) (§11.14.3).

### 11.13 Ajan credential broker'ı / token vault (MD-13)

- **Plane (MD-13).** Ajan credential broker'ı / token vault bir **identity plane capability**'sidir.
- **Kural (AG-32, AGI-2 adayı).** Upstream (üçüncü taraf) token'ın bir ajana verilmesi veya ajan adına kullanılması **bir Access kararıdır** (release Exercise'ı). Possession ≠ authority (MD-13).
  - MD-13'ün "karar + projection" ifadesi şöyle okunur: Access'in kararıyla verilen token için **release kararı** bir Exercise'tır ve projection, Exercise'a bağlı **release kaydıdır**. Upstream token'ın kendisi Access projection'ı **değildir**; içeriğinin ve semantiğinin sahibi upstream AS'dir.
  - §7 E36/EI-26 ile aynı ifade: "Exercise'sız release yetkisizdir" kuralı ve release kaydı BY SEMANTICS; broker'ın verme kararı ve vault'un her release yolunda bunu zorlaması UNDER DECLARED CAPABILITY; upstream token içeriği NOT GUARANTEED (G2 uygulanmaz; risk release Exercise'ında beyan edilir); token `exp` ≤ kararın ValidityContract horizon'u; CT2+ sınıflarda broker-as-PEP varsayılandır. Kanonik metin §7 E36'dır.
  - Vault'ta bir refresh token'ın bulunması hiçbir ajana o upstream servisi kullanma yetkisi vermez.
  - Her kullanım, ajanın FOR(P) capacity'li Grant'ına dayanan ve ajan Instance'ının Mandate zarfı içinde kalan bir `projection.issue` (veya `commit`) kararıdır.
- **Endüstri modelleri.**
  - **Auth0 Token Vault.** RFC 8693 tabanlıdır ama tescilli URN'ler kullanır (`urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token`). Saklama birimi tokenset'tir (kullanıcı × bağlantı). Ajan üçüncü taraf refresh token'a hiç dokunmaz. 35'ten fazla sağlayıcı desteklenir.
  - **Descope Agentic Identity Hub 2.0** (Ocak 2026) iki eksenlidir. **Resources** (gelen: korunan API ve MCP sunucuları; audience + scope; kısa ömürlü token) ve **Connections** (giden: downstream kimlik bilgisi kasası, uzun ömürlü üçüncü taraf kimlik bilgileri). Önerilen desen ajan → Resource → Connection kasası; ajan kasaya doğrudan erişmez.
- **Access eşlemesi (broker/vault veri modeli):**

| Veri modeli nesnesi | Access karşılığı |
|---|---|
| `Resource` (inbound; `audience_uri`, `scopes`, `allowed_clients`, `policy_ref`, `prm_document`) | Domain'in PEP'i + PRM (§11.5.2) + SPP ActionRef'leri. `policy_ref` ayrı bir policy kaynağı değildir; Grant ve RestrictionPolicy'dir |
| `Connection` (outbound; sağlayıcı OAuth config'i, `scope_mapping`) | Identity plane yapılandırması (MD-14 commit'i). `scope_mapping` bir claim/scope mapper'dır ve authority üretemez (§9.9.6) |
| `TokenSet` (`user × connection` → şifreli access/refresh; kiracı başına DEK ile zarf şifreleme) | Identity plane gizli deposu (PII/secret vault bileşeni, §16). Anahtar hiyerarşisi §15 |
| Ajanın kasaya erişimi | Yok. Ajan ya broker'ın kendi yaptığı çağrının sonucunu alır (a), ya da broker'ın **Access kararıyla teslim ettiği** kısa ömürlü, tek audience'lı upstream token'ı alır (b). (b)'deki token Access projection'ı **değildir**. Teslimi bir `projection.issue` Exercise'ıdır, ama artefaktın semantiği upstream AS'nindir |

- **LLM kimlik bilgisi izolasyonu (AGI-3 adayı; AIMS §8; Singapur CSA "Do not share credentials with the agent").**
  - Ajanın **modeli** (LLM bağlamı) hiçbir kimlik bilgisini görmez: upstream token, refresh token, istemci sırrı, DPoP özel anahtarı.
  - Kimlik bilgisi yalnız ajan **runtime**'ının deterministik katmanında bulunur (Instance KeyBinding, broker istemcisi).
  - Access bunu doğrudan zorlayamaz, çünkü runtime içi ayrımdır. Access'in katkısı şunlardır:
    - (a) projection'ların `cnf`'li olması: sızan token anahtar olmadan kullanılamaz;
    - (b) upstream token'ın tek-audience, kısa ömürlü ve intent'e bağlı olması;
    - (c) Instance attestation Claim'inde runtime'ın bu ayrımı beyan etmesi (Acceptance'lı predicate-input).
  - Garanti sınıfı:
    - (a) Access projection'larının `cnf`'li olması: BS.
    - "Exercise'sız release yetkisizdir": BS. Vault'un/broker'ın her release yolunda bunu zorlaması ve broker'ın verme kararı: UDC (conformance; E34 ile aynı yapı).
    - (b) upstream token'ın kısa ömrü ve tek audience'ı: UDC (koşul: upstream AS'nin beyanı ve aşağıdaki adım 3 kuralı).
    - Upstream token **içeriğinin** Grant'ı aşmaması: NG. G2 (projection ⊆ source) upstream token içeriğine uygulanmaz; bu risk release Exercise'ında beyan edilir.
    - (c) runtime beyanı: UDC.
    - `cnf`'siz upstream token sızıntısı: horizon içinde NG.
- §13'e aday: guarantee — "Ajan modeli prompt enjeksiyonuyla bir Access projection'ını sızdırırsa, `cnf` olmadan kullanılamaz (BS); `cnf`'siz upstream token (sağlayıcı DPoP desteklemiyorsa) sızıntısı horizon içinde NG; `exp` ≤ ValidityContract horizon'u UDC".
- §13'e aday: NG — "Upstream token içeriğinin Grant'ı aşmaması garanti edilmez (G2 upstream içeriğe uygulanmaz); release Exercise'ında beyanlı risk".
- §13'e aday: RR — "Upstream sağlayıcıların çoğu DPoP desteklemiyor (incelenen 15 issuer'dan hiçbiri); broker'ın verdiği upstream token'lar bearer kalabilir".
- **Upstream token alma akışı (çıkarım; MD-13 cümlesinin işlemsel hâli):**
  1. Ajan Instance'ı ADP'ye intent gönderir: `action = <upstream SPP ActionRef>`, capacity FOR(P).
  2. Karar ALLOW ise broker:
     - (a) ya upstream token'ı yalnız bu iş için kayıtlı bir yürütücüye verir; çağrıyı yürütücü yapar, ajan sonucu alır (AG-40);
     - (b) ya tokenset'ten kısa ömürlü, dar scope'lu bir upstream access token türetip ajanın koduna verir. Upstream AS desteklerse RFC 8693 ile daraltılır.
  3. (a) varsayılandır; CT2+ sınıflarda (a) zorunludur ve yürütücü her çağrıyı intent ⊑ Grant olarak denetler. (b) yalnız CT0–CT1'de, realm/domain açıkça açarsa ve şu koşulların hepsi sağlanırsa kullanılır: upstream token'ın `exp`'i kararın ValidityContract horizon'unu aşmaz; token ömrü ≤ 1 saattir **veya** upstream iptal adresi yayımlar. Bilgi eksikse (süre bilgisi yok, iptal adresi bilinmiyor, upstream tanımsız) broker (b)'yi reddeder ve (a)'ya düşer (L17, MD-8). **PD** (1 saat eşiği); kural FROZEN (AG-40).
  4. Her iki durumda kullanım bir Exercise olarak kaydedilir. Upstream tokenset'in kendisi Exercise değildir.

### 11.14 Çalıştırma ortasında insan onayı (HITL)

#### 11.14.1 Problem

- AIMS §10.7 bunu resmen kabul eder: "CIBA itself only accounts for client initiation, which doesn't map well to cases that envision the need for User confirmation to occur mid-execution."
- Açık problem tablosu: CIBA `binding_message` serbest metindir. "Çalıştırma ortasında ve işleme kriptografik bağlı insan onayı" açıktır; dört aday vardır ve hepsi bireyseldir.
- A2A'da `TASK_STATE_INPUT_REQUIRED` ve `TASK_STATE_AUTH_REQUIRED` vardır, ancak onayın nasıl toplanacağı ve işleme nasıl bağlanacağı tanımsızdır.

#### 11.14.2 Dört rakip mekanizma ve Access'in tek soyutlaması

- İlke: iç mimaride tek bir bekleyen yetkilendirme soyutlaması kurulur ve dört yüzey de ona bağlanır.
- **Access'te bu soyutlama zaten vardır:** REQUIRE_ACTION almış **nonce** (P54, §9.9.5). Ayrı bir "pending authorization" nesnesi yoktur.

| Mekanizma | Wire biçimi | Access eşlemesi | Statü |
|---|---|---|---|
| `draft-parecki-oauth-jwt-grant-interaction-response-00` | `{"error":"interaction_required","interaction_uri":"https://…","interval":5,"expires_in":600}`; yoklama veya sinyal yönlendirmesi ("No authorization code or other parameters are included") | `interaction_uri` = Approval Surface adresi; `expires_in` = intent validity; tamamlanınca aynı nonce + contribution proof ile `commit` | Bireysel → WATCH; eşleme PD (§9.9.5) |
| `draft-gerber-oauth-deferred-token-response-00` | `completion_mode=deferred` → `400 authorization_pending` + `deferral_code` (saatler/günler süren `expires_in`; göndericiye kısıtlı) | `deferral_code` = `exercise_ref (DomainID, nonce)`'un taşıyıcısı; göndericiye kısıt = actor Instance KeyBinding | Bireysel → WATCH |
| `draft-rosomakho-oauth-txn-challenge-00` | RS imzalı JWT challenge üretir; istemci AS'e taşır; AS onay alıp o işleme bağlı kapsamlı token verir | Challenge = RS'nin ADP REQUIRE_ACTION'ının taşıyıcısı; sonuç token = exact-intent projection (RAR `kind=intent`) | Bireysel → WATCH; Access semantiğine en yakın aday (çıkarım: intent'e bağlı token üretir) |
| AuthZEN AARP (Draft 1, Eylül 2026) | Reddederken `access_request` nesnesi; opak, asenkron görev tutamağı ("survives PEP restart, replacement, or handoff"); onay sonrası taze değerlendirme; "Reddedilmiş bir karar reddedilmiş kalmalıdır" | Görev tutamağı = `exercise_ref`; taze değerlendirme = aynı nonce ile yeniden `commit`; DENY nonce terminal (C30) | OIDF WG taslağı → WATCH; Final olursa PROFILE (§9.9.5) |
| CIBA (Final) | `/bc-authorize`, `binding_message`, `authorization_pending`, `slow_down` | **Yalnız davet**: kullanıcıyı Approval Surface'e çağırır. `binding_message` onay içeriği değildir | ADOPT (taşıma, §10) |
| MCP SEP-2848 (Asynchronous Approval for Tool Calls) | Açık | Final olursa aynı nonce eşlemesi | WATCH (§11.8.4) |

- **Kural (AG-33).**
  - Hangi yüzey kullanılırsa kullanılsın, onay **Approval Surface + AAS** ile, kullanıcının kendi Instance'ından gelir (A-5, §9.14). AAS'in `target`'ı intent digest'tir. WYSIWYS kuralı geçerlidir (§9.14.5 madde 1).
  - Yüzeyin döndürdüğü hiçbir token veya kod onayın kanıtı değildir; kanıt AAS ve DecisionRecord'dur.
  - Auth0'ın CIBA + RAR örneği: onaydan sonra `authorization_details` token'da aynen taşınır; "kaynak sunucusu neyin onaylandığını token'dan doğrulayabilir". Access'te bu cümle **reddedilir**: neyin onaylandığı token'dan değil AAS'ten doğrulanır (§9.14.5 madde 2). Token'daki RAR projection'dır.

#### 11.14.3 Üç bağlama modeli (`draft-ni-wimse-ai-agent-identity-02`)

- Dual-Identity Credential ajanın kimliğini sahibinin kimliğine kriptografik olarak bağlar. Taslağın süresi doldu; akademik eleştiri: çok sıçramalı delegasyonu çözmez.
- Eşleme: ajan aracılı model sahip beyanıdır; sahip aracılı model yönetim konsolu ile politika motorudur; sunucu aracılı model tam olarak CIBA'dır. Bunlar ayrı akışlar olarak desteklenir.
- Access karşılığı:

| Model | Mekanizma | Saldırı yüzeyi | Access karşılığı |
|---|---|---|---|
| Ajan aracılı, sahip önceden imzalı | Sahip isteği yerel olarak önceden imzalar (FIDO/HSM) | Ele geçirilmiş imza anahtarı | Sahibin önceden verdiği FOR(sahip) capacity'li Grant'ı (AAS ile `grant.issue`). Ajan sahibin kendi Instance'ıysa sahibin `mandate.bind` zarfı. Ya da `local_requirements`'ta önceden alınmış contribution (ValidityContract; §11.19 robot satırı) |
| Sahip aracılı, ağ geçidi | Sahip vekil ile sunucu arasında denetleyici aracıdır | Tek hata noktası, DoS | Coordinator → Approval Surface → AAS zinciri (§8.18.4, §11.16). Ağ geçidi PEP'tir, actor değildir (E17) |
| Sunucu aracılı, challenge-response | Kimlik sunucusu sahibi bant dışı kanalla arar | Bant dışı kanal güvenliği, replay | REQUIRE_ACTION + CIBA daveti + AAS. Replay'e karşı AAS nonce'a ve intent digest'e bağlıdır |

- Atıf notu: bu modeller AIMS'te değil, bu taslaktadır (§11.12.4).

### 11.15 A2A (Agent2Agent)

- **Durum.**
  - Linux Foundation yönetiminde; 27 Ağustos 2026'da Agentic AI Foundation'a katıldığı bilgisi var.
  - v1.0 tarihi çelişkilidir: site Ağustos 2026, blog 12 Mart 2026 der. **Doğrulanmadı.**
- **Agent Card** (`/.well-known/agent-card.json`):
  - zorunlu `id`, `name`, `interfaces[]`;
  - `securitySchemes: map<string, SecurityScheme>` (OpenAPI 3 ile birebir); `security` beceri başına granülerlik;
  - `signature` = `AgentCardSignature`: JCS (RFC 8785) ile kanonikleştirilmiş kart üzerinde JWS.
- **SecurityScheme tipleri:** `apiKey`, `http`, `oauth2`, `openIdConnect`, `mutualTls`. OAuth akışları `authorizationCode`, `clientCredentials`, `deviceCode`; `implicit` ve `password` yok (OAuth 2.1 uyumlu).
- RFC 9728, RFC 8707 ve OAuth metadata keşfinden bahsetmez. "Servers MUST reject requests with invalid or missing authentication credentials."
- **Kritik boşluk:** A2A'da SPIFFE/SPIRE geçmez. `mutualTls` vardır ama sertifikadaki SPIFFE kimliğinin ajan kimliğine bağlanmasına dair normatif kural yoktur.
- **MCP ile fark:** A2A yetkilendirme şemasını kartta bildirimsel tanımlar; MCP OAuth keşif zincirini zorunlu kılar ve audience bağlamayı normatif yapar. Yakınsama sinyali yoktur.
- **Access statüsü (§9.4 A2A satırı: EXTEND; AG-34).**
  - **Agent Card bir Claim'dir.** Kartın imzası bir issuer imzasıdır. Karttaki `securitySchemes`, beceri listesi ve açıklamalar authority-opaque'tır (A-7).
  - Kartı imzalayan anahtarın güvenilmesi bir Acceptance'tır (`actor-binding` veya `predicate-input`).
  - "Agent Card imzalama servisi" (`POST /agent-cards/sign`) identity plane capability'si olarak benimsenebilir (WATCH). İmza MD-3'e göre JOSE ES256'dır. İmza kartın beyanını doğrular, ajanın authority'sini değil.
  - Identity plane A2A'nın `securitySchemes`'inde görünür: `openIdConnectUrl` keşfi, `authorizationCode`, `clientCredentials`, `deviceCode`, RFC 8705 mTLS'e bağlı token.
  - mTLS'te SAN URI'deki SPIFFE ID actor-binding Claim'i olarak çıkarılır (ekosistemde kimsenin kapatmadığı boşluk). Bu bir actor-binding Acceptance kuralıdır.
  - A2A görev durumlarının REQUIRE_ACTION eşlemesi §9.9.5'tedir.
  - Bir A2A görev devri, devreden ajanın **kendi Grant'ının alt-delegasyonudur** (`grant.issue`, depth ≤ 1 şablonu) veya devralanın kendi Grant'ıyla yaptığı ayrı Exercise'tır. Görev mesajı authority taşımaz (çıkarım; WEF ACAP kesişim kuralı, §11.10.4 #5).
- A2A kayıt defteri tartışması bir yıldan uzun süredir sonuçsuzdur (issue #741, 80'den fazla yorum) → §11.17.

### 11.16 Ajan sözleşmesi (MD-19 #2)

- MD-19 #2: A-1, A-7, A-8, A-10 agent sözleşmesi normları spec'te normatiftir (§8.18.2).
- Tablonun tam metni kanonik olarak §8.18'dedir (MD-19.2). Bu bölüm yalnız MCP/OAuth/PEP eşlemesini taşır.
- §11.16.3–§11.16.4 metninin kanonik kopyası §8.18.3–§8.18.4'tür; çelişkide §8.18 kazanır.

#### 11.16.1 Karar cevabının içeriği

**Kanonik metin §8.18.1'dedir** (MD-19.2). Karar cevabı içeriği tablosu burada tekrarlanmaz; bu alt bölüm yalnız MCP/PEP eşlemesini verir.

- Not: bu tablonun wire karşılığı §9.5–§9.6'dadır (ADP yanıtı, reason/remediation kodları, P41). Çelişki hâlinde §9 metni geçerlidir.

#### 11.16.2 Agent davranış normları (agent-facing contract)

**Kanonik metin §8.18.2'dedir** (MD-19.2). A-1…A-12 normları burada tekrarlanmaz; MD-19'un saydığı dört norm (A-1, A-7, A-8, A-10) orada işaretlidir. Bu alt bölüm yalnız MCP/PEP eşlemesini verir:

**MCP/OAuth yüzeylerine uygulanış.**
- **A-1** → PEP SDK ve MCP istemcisi capacity'siz `tools/call` kuramaz. Token'da capacity §9.9.4'e göre `sub`/`act` ile görünür. Eksik capacity protocol hatasıdır (§9.5 kural 4).
- **A-7** → MCP tool açıklaması, `server/discover` sonucu, PRM `resource_name`, CIMD `client_name`, A2A Agent Card açıklaması, RAR `locations` ve hata gövdeleri instruction kaynağı değildir. Tool zehirlenmesi ve line jumping (§11.7) bu normun ihlal sınıfıdır. AIMS'in LLM-kimlik bilgisi kuralı aynı ailedendir (AGI-3).
- **A-8** → `subscriptions/listen` ve uzun MCP görevleri için AG-15. Horizon'da stream kapanır.
- **A-10** → `tools/list` / `check` / search sonuçları ve `cacheScope` önbelleği bir yetki değildir (AG-12). `authz_epoch` advisory cache'i yalnız advisory'dir (§9.11.1).
- **A-12** → AB Yapay Zekâ Yasası m. 50 ifşa yükümlülüğü (2 Ağustos 2026'dan itibaren, §11.18) bu normla karşılanır (çıkarım).

#### 11.16.3 İnsan gerektiren requirement'lar

Actor bir agent Instance'ı iken requirement insan varlığı veya insan step-up'ı istiyorsa (ör. `authentication` binding = actor Instance, humanPresence = true), agent bunu karşılayamaz. Cevap `REQUIRE_ACTION` + `not-satisfiable-by-actor`'dür. Coordinator bunu iki yoldan birine çevirir: (a) requirement contribution kabul ediyorsa principal'ın onayı (§8.17.6), (b) etmiyorsa eylemin principal'ın kendi Instance'ından yapılması gerektiği ("This must be done by you"). Hangi yolun açık olduğu requirement'ın kendisinden okunur; UI uydurmaz.

- Not (AGI-4 adayı): Ajan Instance'ı insan varlığı (UV/`humanPresence`) gerektiren bir requirement'ı hiçbir taşıyıcıyla karşılayamaz. CIBA, elicitation, `interaction_required`, platform biyometrisinin ajan cihazında taklidi ve sahip önceden imzalı akış bu kapsamdadır. Bu yüzden `not-satisfiable-by-actor` hiçbir yüzeyde `interaction_required`'a çevrilmez (§9.9.5 ek kural 1).

#### 11.16.4 Agent ↔ coordinator ↔ insan zinciri

```text
Agent ──typed intent + reason/remediation──► Coordinator (Work / third-party)
                                                │ places Gate / Condition (Work kararı)
                                                ▼
                                       Needs Attention (insan)
                                                │ opens
                                                ▼
                                Approval Surface / Delegation sheet (trusted)
                                                │ user act
                                                ▼
                                 Access Exercise (+ Work Declaration)
                                                │
Agent ◄──────── re-request (same/new nonce) ────┘
```

Access bu zincirde yalnız iki noktada konuşur: agent'ın isteğine karar verirken ve insanın eylemini kaydederken. Zincirin geri kalanı (yönlendirme, hatırlatma, sıra) coordinator'ındır (X5).

### 11.17 Ajan claim'leri ve ajan kaydı

| Taslak | İçerik | Access statüsü |
|---|---|---|
| `draft-mora-oauth-entity-profiles-01` | `client_profile`, `sub_profile` (7 değer: `user`, `device`, `native_app`, `web_app`, `browser_app`, `service`, `ai_agent`); `entity_profiles_supported` | WATCH; **arayüz hazır**. `sub_profile` Instance'ın `party-kind`/`agent-kind` Claim'inin projection'ıdır |
| `draft-mcguinness-oauth-ai-agent-instance-00` | `agent_instance_id` (zorunlu), `agent_platform`, `agent_model`, EAT biçiminde `agent_runtime`; `sub_profile: ["ai_agent","client_instance"]` | WATCH; **arayüz hazır**. `agent_instance_id` = InstanceID'nin (pairwise) projection'ı. `agent_runtime` = Attestation Claim'i |
| `draft-mcguinness-oauth-client-instance-assertion-01` | Somut çalışma zamanı örneğini tanımlayan imzalı JWT | WATCH; Instance actor-binding Claim'i taşıyıcısı |
| `draft-mcguinness-oauth-id-continuation-assertion-01` | Kullanıcı gittikten sonra kimlik yayılımı; ≤ 300 s, DPoP, tek kullanımlık | WATCH. Kullanıcı yokken devam Access'te Mandate + ValidityContract'tır; continuation assertion yalnız taşıyıcıdır |
| `draft-mcguinness-oauth-token-exchange-cnf-00` | Token exchange için `cnf` yanıt parametresi | WATCH; P48 ile uyumlu |
| `draft-mcguinness-oauth-rfc9728bis-01` | PRM kaynak tanımlayıcısı doğrulaması | WATCH; §11.5.2 |
| `draft-sharif-openid-agent-identity-01` | `agent_trust_score` (0–100), `agent_trust_level` (L0–L4), `agent_spend_limit` vb.; tek yazarlı, spekülatif | REJECT (authority olarak). Trust score yalnız Claim olabilir; asla Grant olmaz. `agent_spend_limit` bir BudgetTerm'ün projection'ı olabilir, kaynağı olamaz |
| `draft-drake-agent-identity-registry-03` | Donanıma çapalı federe kayıt; kalıcı ve iptal edilemez kimlik; tek yazarlı | REJECT. İptal edilemez kimlik Access lifecycle'ıyla (Instance terminate, Acceptance revoke) çelişir |
| `draft-abbey-scim-agent-extension-00` | SCIM `/Agents`, `/AgenticApplications`; `agentType`, `owners`, `roles`, `protocols`, `x509Certificates`, `subject` | WATCH; SCIM taşıyıcısı (§9.13.8 madde 7). `owners` → ilişki Claim'i (§11.9.2). `roles` Grant yazmaz (MD-4) |

- **Ajan kaydı.** Ajan kaydı konusunda tam kaos vardır: A2A registry tartışmada, MCP Registry önizlemede, SCIM `/Agents` taslak, Entra/Agent 365 tescilli, `urn:aid:` spekülatif, AgentDNS/ANS/NANDA akademik.
  - **Access kuralı:** kayıt bir **keşif** ve Claim kaynağıdır, authority kaynağı değildir. Bir registry'nin issuer'ı ancak Acceptance ile kabul edilir.
  - Singapur CSA'nın "trusted registry of agents" kontrolü (§11.18) Access'te Party/Instance kaydı + Acceptance'lı registry Claim'iyle karşılanır.
- **Trust score kuralı.** Herhangi bir risk/güven skoru (`agent_trust_score`, adaptif risk) yalnız Claim'dir. Karara Acceptance'lı predicate-input olarak girer ve **yalnız daraltır** (CI-2). Hiçbir skor bir Grant'ı ikame etmez veya onay atlatmaz.

### 11.18 Düzenleyici durum ve ortak gereksinimler

- Net cevap: "bugün bir IdP'yi AI ajanlarına ayrı kimlik vermeye hukuken zorlayan bağlayıcı bir düzenleme yoktur." Baskı tedarik ve ihaleden, OWASP/CSA taban çizgisinden gelir.

| Kaynak | Bağlayıcı mı | Ajan kimliği istiyor mu | Ne zaman |
|---|---|---|---|
| AB Yapay Zekâ Yasası m. 50 | Evet, 2 Ağustos 2026'dan beri | Hayır; yalnız YZ olduğunun ifşası | Şimdi |
| AB Yapay Zekâ Yasası yüksek risk | Evet, 2 Aralık 2027'ye ertelendi (Reg. EU 2026/1744, 27 Temmuz 2026) | Dolaylı | Aralık 2027 |
| Singapur CSA Securing Agentic AI eki (17 Haziran 2026) | Hayır ("not mandatory, prescriptive nor exhaustive") | Evet, çok spesifik | Tedarik/denetim baskısı |
| NIST NCCoE "Software and AI Agent Identity and Authorization" (5 Şubat 2026) | Hayır | Evet; MCP, OAuth 2.0/2.1, OIDC, SPIFFE/SPIRE, SCIM, NGAC | 2027 federal tedariki |
| OWASP Agentic Top 10 (2026) | Hayır | Evet; ASI03 kimlik ve ayrıcalık istismarı | Şimdi; fiilî taban çizgisi |
| FIDO Agentic Authentication WG (28 Nisan 2026) | Hayır | Evet; doğrulanabilir kullanıcı talimatı, ticarette güvenilir delegasyon | 2027+ |

- Singapur CSA'nın nihai metnindeki kimlik kontrolleri doğrulanmadı. PSD3/PSR'de ajansal YZ'ye özgü hüküm bulunamadı.
- **Dört kaynağın (CSA, NIST, OWASP, WEF) ortak 8 gereksinimi ve Access karşılığı (AG-35):**

| # | Ortak gereksinim | Access karşılığı | Garanti |
|---|---|---|---|
| 1 | Her ajana benzersiz ve ayrı kimlik; servis hesabı paylaşımı yok | Ajan = Instance (InstanceID); audit/iptal birimi Instance (§11.9.3) | BS (model) |
| 2 | Kısa ömürlü, kapsamlı, zaman sınırlı kimlik bilgisi | Projection: holder-bound, tek `aud`, ValidityContract; ajan varsayılanı AG-22 | BS (sınıflandırma), UDC (horizon kapanışı) |
| 3 | Güvenilir ajan kaydı ve doğrulanabilir kimlik bilgisi | Party/Instance kaydı + Acceptance'lı actor-binding (§11.17) | BS |
| 4 | Delegasyonda kesişim, toplama değil | Attenuation + Mandate kesişimi + lineage budget (§11.10.4 #5) | BS |
| 5 | Her adımda yeniden yetkilendirme; tek token'ı zincir boyunca kullanmak anti-desendir | Her effect kendi ALLOW'u (INV-19); passthrough yok (L24); Txn-Token audit-only (§11.12.3) | BS |
| 6 | İnkâr edilemezlik ve denetlenebilirlik | AIS (actor imzası), Decision Receipt, Exercise kaydı, witness (§9, §16–§17) | BS |
| 7 | Merkezî uygulama düzlemi | ADP + PEP profili; ancak Access merkezî **karar kaydı**dır, merkezî PEP dayatmaz | — (mimari) |
| 8 | Kullanıcı başlatmalı ile ajan başlatmalı eylemlerin ayrılması | Capacity OWN/FOR(P) beyanı (A-1) + `sub`/`act` eşlemesi (§9.9.4) | BS |

- WEF "AI Agents in Action" (Mayıs 2026) ACAP kuralı: "a downstream agent operates under the intersection of its own ACAP permissions and those of the agent that invoked it. An orchestrating agent cannot delegate authority it does not itself hold." Bu Access attenuation invariant'ıdır (§11.10.4).
- Uyum eşlemesinin bütünü §13'tedir. Bu tablo §13'e girdi önerisidir.

### 11.19 Üçüncü taraf entegrasyon walkthrough'ları

- **Amaç.** Tablo, ajan ve dış sistemlerin Access'e nasıl bağlandığının tek uçtan uca anlatımıdır ve PEP ≠ actor kuralını somutlaştırır.

Her senaryo aynı beş soruyu cevaplar: **Party/Instance kurulumu · authority kaynağı · karar yolu · approval tetikleyicisi · revocation'ı nasıl öğrenir.** Vendor ürünlerinin bugünkü özellikleri (ör. belirli bir agent platformunun MCP/A2A/OAuth desteği) **doğrulanmadı**; senaryolar generic agent sınıfları için yazılmıştır ve yalnız açık standartlara dayanır.

| Senaryo | Party / Instance | Authority | Karar yolu | Approval tetikleyicisi | Revocation öğrenimi |
|---|---|---|---|---|---|
| **Cloud agent** (OpenAI/Claude/Gemini/Grok benzeri hosted agent) | Agent operatörü Party (veya kullanıcının agent Party'si, `operated-by`); her oturum/görev bir Instance (`instance.create`, actor-binding = workload attestation / operatör IdP Claim'i; Instance KeyBinding'i Actor Intent Statement'ı imzalar, projection `cnf`'i için DPoP) | Kullanıcı → agent Grant (OWN) veya kullanıcı adına Mandate (FOR(P)) | Agent → (MCP tool / A2A görev / doğrudan API) → RS'nin PEP'i → ADP (PEP agent'ın Actor Intent Statement'ını `context`'te iletir; kendi transport kimliği yalnız `pep`); veya agent önce `projection.issue` ile exact-intent token alır (RFC 8693 + RAR `kind=intent`) | `REQUIRE_ACTION` (`unmet`: contribute:approve) → kullanıcıya CIBA/push davet → Approval Surface → AAS (`act = contribution`, §9.14) → agent `commit(aynı nonce, + contribution proof)` → ALLOW | Kısa ömürlü exact-intent token; ilgili SSF event → re-query; agent oturumu kapanınca Instance terminate |
| **Local agent** (kullanıcı cihazında) | Kullanıcı Party'sinin cihaz-bağlı Instance'ı (agent-kind = local) veya ayrı agent Party | Grant / Mandate | Doğrudan ADP; offline ise `revalidate-on-reconnect` bounds token | Aynı cihazda platform authenticator ile AAS | Reconnect'te yeni karar; horizon |
| **Enterprise agent** (şirket içi, kendi IdP'si) | Şirket domain'inde workload Party (SPIFFE / SCIM `identity-binding.workload`) + Instance | Şirket domain'inin Grant'ları (rule-shaped: rol/grup Claim'i selector) | Şirketin PEP'leri ADP; Txn-Token zinciri (informative) PEP'ler arası bağlamı taşır, `causal: audit-only` | Policy: yüksek sonuçlu action'larda yönetici `approve` | SSF/CAEP + Access event'leri; SCIM deprovision → `identity-binding` geçersiz → actor-binding fail closed |
| **External system / PEP** (SaaS, API gateway, eski sistem) | PEP bir Party değil, verifier'dır (Verifier Profile Claim); eylemi yapan actor ayrıdır (PEP ≠ actor, §9.5): PEP actor'ün Actor Intent Statement'ını iletir, üretemez; PEP'in transport kimliği hiçbir zaman actor olmaz | — | AuthZEN istemcisi olarak ADP (actor statement'ı `context`'te); veya OAuth RS olarak RAR'lı exact-intent token'ı (`cnf` = actor binding) doğrular | PEP ADP response'unu kullanıcıya/agent'a iletir | Status list / SSF; authority-state ack (§9.12.3) |
| **Robot / offline cihaz** | Cihaz Party'si + Instance (attestation evidence), Verifier Profile | Operatör Grant'ı veya ayrı yerel AuthorityDomain + bridging Grant (§9.15A.4) | Offline: PAP + ValidityContract + offline slice; yerel verifier | Yerel UV veya önceden alınmış contribution (ValidityContract `local_requirements`) | Horizon/Δ; reconnect'te offline report + yeni contract |
| **Başka organizasyon** | Kendi domain'inde kendi Party/Instance'ları | Kendi domain'inde Grant; bizim domain'de ya bridging Grant (`ForeignAuthority` holder + `foreign-authority` Acceptance, §9.15A.2) ya da foreign Party'ye bizim kökümüzden yerel extensional Grant (cross-domain delegation, `actor-binding` ile; §9.15A.3) | Bizim ADP: bridging'de PAP'ı §9.15A.2 kontrolleriyle doğrular + bridging Grant ceiling'i; consumption-bearing action'da home'un önceden draw ettiği slice veya home'da online exercise (§9.15A.3); yerel Grant'ta normal ADP | Bizim policy'mize göre; approver bizim domain'den veya foreign Claim'le | PAP status + horizon; Acceptance revoke |

**Ortak kurallar:** Hiçbir senaryo Suiss'e özel SDK, endpoint, Claim class'ı veya trust anchor gerektirmez (PI-13). Bir agent'ın model sağlayıcısı (LLM vendor) kendiliğinden authority sahibi değildir; agent'ın authority'si Grant'tan gelir (EI-6). Prompt/tool açıklaması/RAR `locations` gibi alanlar authority girdisi değildir (PI-2).

**Walkthrough'ların MCP/ajan bölümüyle bağlantısı:**
- *Cloud agent*:
  - "CIBA/push davet" yalnız davettir (§11.14.2).
  - Cloud agent satırındaki "kullanıcı adına Mandate (FOR(P))" ifadesi INV-4 ve C14'e göre şöyle okunur: kullanıcının ajan Party'sine verdiği FOR(P) capacity'li Grant, artı ajan Party'sinin kendi Instance'ına bağladığı Mandate zarfı. Kullanıcının Mandate'i yalnız kendi Instance'ına bağlanır.
  - DPoP nonce'u uzun ömürlü paylaşılan nonce'tur; replay cache TTL = kanıt ömrü + 2× saat kayması (MD-18; §10).
  - MCP üzerinden gelirse `tools/call` → §11.2 eşlemesi.
  - Upstream servis token'ı gerekiyorsa §11.13.
- *Enterprise agent*:
  - Kurumsal IdP ID-JAG ile gelirse §11.11.3 tüketim adımları uygulanır.
  - "SCIM deprovision → actor-binding fail closed" ingest-time cutoff'tur (INV-23).
- *External system / PEP*: MCP sunucusu bu satırdır (§11.5). PRM ve `WWW-Authenticate` PEP'in yayınıdır.
- *Başka organizasyon*: Identity chaining yalnız kimlik iddiasını taşır; authority §9.15A'dır (§11.11.6).
- Ek senaryo — **MCP proxy / credential broker**:

| Senaryo | Party / Instance | Authority | Karar yolu | Approval tetikleyicisi | Revocation öğrenimi |
|---|---|---|---|---|---|
| **MCP proxy / credential broker** (statik upstream istemci kimliğiyle üçüncü taraf AS'e giden aracı) | Proxy operatörünün PEP'i (actor değil); ajan kendi Instance'ı | Kullanıcının ajan Party'sine FOR(P) capacity'li Grant'ı (+ ajan Instance'ının kendi Mandate zarfı); upstream tokenset possession ≠ authority (MD-13) | Ajan → proxy (PEP) → ADP (upstream ActionRef, FOR(P)) → ALLOW → proxy upstream çağrıyı kendisi yapar veya kısa ömürlü upstream token türetir (§11.13) | İlk bağlantıda AS-M15 onayı = Approval Surface + AAS (`grant.issue`); sonraki yüksek sonuçlu action'larda REQUIRE_ACTION | Grant revoke → yeni karar yok; tokenset identity plane'de silinir; (b) yolunda teslim edilmiş canlı upstream token upstream `exp`'e kadar yaşar; `exp` ≤ kararın ValidityContract horizon'u (UDC); `cnf`'siz sızıntı horizon içinde NG |

### 11.20 Açık problemler ve Access konumu

| Problem | Ekosistem durumu | Access konumu |
|---|---|---|
| Alanlar arası kimlik zinciri | Neredeyse çözüldü (identity-chaining-17 RFC kuyruğunda) | Taşıyıcı ADOPT; authority §9.15A |
| Uygulamalar arası SSO taşıma | Çözüldü (ID-JAG-04 + MCP EMA) | §11.11 |
| Göndericiye kısıtlı token | Çözüldü (RFC 9449, RFC 8705) | `cnf` zorunlu (P48) |
| Sinyal/olay dağıtımı | Çözüldü (SSF 1.0, CAEP 1.0 Final) | Taşıma; güvenlik sinyale dayanmaz (§9.16.2). Final tarihi doğrulanmadı (MD-18) |
| Bant dışı kullanıcı onayı | Kısmen (CIBA Final, çalıştırma ortasına uymuyor) | CIBA = davet; onay = AAS (§11.14) |
| Ölçeklenebilir iptal | Neredeyse çözüldü (status-list-21; `VALID`/`INVALID`/`SUSPENDED`) | Status list projection taşıyıcısıdır; authority iptali kayıttadır (§9.11) |
| Delegasyon zincirinin kriptografik doğrulanabilirliği | Açık (7 rakip taslak) | **Access'te çözülü:** lineage kaydı + PAP (§11.10). Açık olan yalnız wire biçimi |
| Ajan kaydı ve keşfi | Açık | Keşif/Claim kaynağı; authority değil (§11.17) |
| Yetki daraltmanın OAuth'a entegrasyonu | Açık (Biscuit v3.3, UCAN 1.0 OAuth'la konuşmuyor; scope operatör düzeyinde, operand düzeyinde değil; arXiv 2603.17170) | RAR `kind=intent` operand düzeyindedir (exact-intent); attenuation Grant'tadır |
| Çalıştırma ortasında işleme bağlı insan onayı | Açık (CIBA `binding_message` serbest metin; 4 aday) | **Access'te çözülü:** AAS `target` = intent digest + WYSIWYS (§9.14). Açık olan wire biçimi (§11.14.2) |
| Ajana özgü CAEP olayları | Açık | Access semantic event'leri (`authority-revoked`, `instance-terminated` …; §9.16.2) outbound CAEP'e yaklaşık eşlenir |
| Toplu/kitlesel iptal | Açık (`draft-chen` boşluğu) | `instance.terminate` kümesi, Party compromise, Acceptance revoke (§9.16.2, P59) |
| Ajan denetlenebilirliği (inkâr edilemezlik) | Açık (AUDIT BoF reddedildi) | AIS + Decision Receipt + witness; Access'in kendi kaydı (§9, §12) |
| İş yükü kimliği standardı | Açık (WIMSE RFC yok) | Taşıyıcı-bağımsız actor-binding (L21) |
| Prompt enjeksiyonunun yetkilendirmeye etkisi | Yetkilendirme katmanında çözülemez | Kabul edilir. Access ele geçirilmiş ajanın etkisini Grant ∩ Mandate ∩ budget ile sınırlar; açıklama/talimat ayrımı A-7 |

**Prompt enjeksiyonu: dürüst değerlendirme.**
- Ölümcül üçlü (Simon Willison, 16 Haziran 2025): özel veriye erişim, güvenilmeyen içeriğe maruziyet ve dışarı iletişim. "we still don't know how to 100% reliably prevent this from happening."
- arXiv 2609.00267 (31 Ağustos 2026): LangGraph, CrewAI, AutoGen ve MCP'nin hiçbiri yerleşik sınırlama sağlamıyor. Yazarların yetkilendirme aracısı dört tehdidi de engelliyor ve ele geçirilmiş alt ajanın erişimini 8.100 olası eylemden ortalama 1,5'e düşürüyor.
- Makaledeki ≈ 2,6 µs/karar rakamı 160 satır Python'da HMAC caveat doğrulamasıdır, ReBAC graf çözümlemesi değildir. Access'in hedefi olarak alınamaz (§9.7A.6 sıcak yol hedefleri ayrıdır).
- Doğru okuma: yetki token'a gömülüyse doğrulama neredeyse bedavadır. Access'te karşılığı exact-intent projection'dır (§9.9.1).
- Invariant Labs'in Toxic Flow Analysis'i (kompozisyon) Access'te kısmen lineage budget ve RestrictionPolicy ile karşılanır. Bilgi akışı (taint) kontrolü Access'in karar semantiğinde yoktur → WATCH, §9.17 backlog.
- §13'e aday: RR — "Prompt enjeksiyonu ile ajanın Grant sınırları içinde zararlı ama yetkili eylem yapması; Access yalnız sınırlar, önlemez (NG)".

### 11.21 Identity plane'in ajan yüzeyi: sınıflandırma, endpoint'ler, token tipleri, metadata

**Plane.**
- Bu alt bölüm identity plane'in ajan yüzeyinin envanteridir.
- Genel OAuth/OIDC endpoint'lerinin uygulama ayrıntısı §10'dadır. Burada her öğenin Access statüsü ve authority eşlemesi verilir.

#### 11.21.1 Ekosistem sınıflandırması → Access statüsü

| "Bugün" (1–17) | Access statüsü |
|---|---|
| 1 OAuth 2.1 çekirdeği (PKCE S256, `plain` red, implicit/password yok) | ADOPT (§10) |
| 2 RFC 8414 + OIDC Discovery | ADOPT; Domain Metadata'dan türetilir (P60) |
| 3 RFC 9728 PRM | ADOPT (§11.5.2) |
| 4 RFC 8707 + kanonik URI + `aud` | ADOPT; AG-8 |
| 5 RFC 9207 `iss` (hata dahil, normalizasyonsuz) | ADOPT; MUST (AG-7) |
| 6 CIMD tam (+`client_id_metadata_document_supported`) | ADOPT -02 (AG-3) |
| 7 RFC 7591 DCR (legacy; `application_type`, issuer'a bağlı kimlik bilgisi) | PROFILE (geriye uyumluluk) |
| 8 RFC 8693 (`act`, `may_act`) | PROFILE; §9.9.4 |
| 9 ID-JAG üretim + tüketim | PROFILE (assertion taşıyıcı); AG-27 |
| 10 SPIFFE istemci kimlik doğrulaması | ADOPT (identity plane; taslak etiketiyle) |
| 11 DPoP `cnf.jkt` + mTLS `cnf.x5t#S256` | ADOPT; `cnf` zorunlu |
| 12 RAR (istek + token claim; tip başına JSON şeması; onayda insan okunur gösterim) | EXTEND (§9.13.5); onay gösterimi = AAS render (WYSIWYS) |
| 13 CIBA (`/bc-authorize`, `binding_message`, `authorization_pending`, `slow_down`) | PROFILE: yalnız davet |
| 14 Scope challenge motoru (403 `insufficient_scope`) | ADOPT; REQUIRE_ACTION ayrımı §9.9.5 |
| 15 Hiyerarşik tanımlayıcılar (`spiffe://`, `wimse://`) | ADOPT (Claim/selector) |
| 16 RFC 7009, RFC 7662, JWKS rotasyonu | ADOPT; introspection MD-8 |
| 17 SSF/CAEP vericisi (Final'in sekiz olayı) | ADOPT (identity plane); best effort. CAEP URL tuzağı: `openid-caep-specification-1_0.html` hâlâ 2021 draft-02'yi döndürür; Final `openid-caep-1_0-final.html`'dedir |

| "Arayüz hazırla" (18–35) | Access statüsü |
|---|---|
| 18 `delegation_chain` (sıçrama başına imza) | PROFILE seçeneği; lineage excerpt'i (AG-24) |
| 19 Actor Profile değişmezleri | Benimsenir (§9.9.4) |
| 20 `sub_profile` / `client_profile` | WATCH, arayüz hazır (§11.17) |
| 21 `agent_instance_id`, `agent_platform`, `agent_model`, `agent_runtime` | WATCH, arayüz hazır; InstanceID/Attestation projection'ı |
| 22 Attestation tabanlı istemci kimlik doğrulaması | WATCH; AG-31 |
| 23 Transaction Tokens | PROFILE (audit-only bağlam) |
| 24 Çalıştırma ortası onay uzantı noktası | Access soyutlaması = nonce (AG-33) |
| 25 AuthZEN PDP: SARC, `x-authzen-mapping`, CEL, AARP görev tutamağı | ADP = AuthZEN PROFILE+EXTEND (§9.5). COAZ-MCP **REJECT**: "The human user is represented as the AuthZEN Subject; the AI agent appears in the Context" modeli Access'te actor'ün AIS'ten türetilmesiyle yer değiştirir (L23, P38). AARP → WATCH (§11.14.2) |
| 26 Delegasyonlu refresh token (mutlak son tarih, göreve kapsamlı iptal; `draft-zhu-oauth-async-delegation-05`) | Mandate bitişi + Grant revoke ile karşılanır; refresh ≤ Grant (P50) |
| 27 `refresh_token_timeout`, `authorization_expires_in` | ADOPT-WATCH (WG Doc; §9.4.2) |
| 28 RAR metadata keşfi ve düzeltme | WATCH; `insufficient_authorization` eşlemesi §9.9.5 |
| 29 FiPA (`authorize-challenge`, `auth_session`) | §10 (varsayılan kapalı) |
| 30 SCIM `/Agents` | WATCH (§11.17) |
| 31 Üç bağlama modeli akış olarak | §11.14.3 |
| 32 WIT/WPT | WATCH; KeyBinding kanıtı (§11.12.2) |
| 33 Agent Card imzalama servisi | WATCH; Claim imzası (§11.15) |
| 34 Federe kimlik bilgisi kasası (Connection; zarf şifreleme, otomatik yenileme) | Identity plane capability (MD-13); kullanım = Access kararı (AG-32) |
| 35 Bulut iş yükü federasyonu (AWS/GCP OIDC → `jwt-bearer`) | ADOPT (actor-binding Claim'i; authority değil, L25) |

- "Henüz erken" listesi WATCH'tır (L27):
  - yetki daraltan token'lar (dört rakip);
  - ajan kayıt protokolleri (NANDA, ANS, AgentDNS, `agent://`, `urn:aid:`);
  - donanıma çapalı ajan kimliği;
  - `agent_trust_score` tarzı claim'ler;
  - Rego–OAuth bağlama;
  - göreve bağlı yetkilendirme;
  - ajana özgü CAEP olayları;
  - küresel/toplu iptal standardı;
  - SD-JWT ile Agent Card seçici ifşası;
  - agentproto'nun getireceği her şey.
- Diğer bireysel taslaklar da WATCH'tır:
  - `draft-chen-oauth-agent-authz-use-cases-03`: 11 senaryo; 3 boşluk: yetkilendirme bağlamı, delegasyon zinciri, toplu iptal.
  - `draft-carleton-workload-authz-grant-00` (Paul Carleton, Anthropic): AIMS profili; "Trust in the platform's issuer is established once, by reference, and thereafter agents are accepted on first presentation with no per-agent registration step". Access'te bu, platform issuer'ı için bir `actor-binding` Acceptance'ıdır. Ajanlar Instance olarak ilk sunumda oluşur; Grant yine ayrıca gerekir.
  - `draft-liu-ai-agent-authorization-integration-00`.
  - `draft-jia-oauth-scope-aggregation-01`: riskleri artık ayrıcalık ve kör imzalama. Access'te scope toplama exact-intent yerine bounds token'dır ve consumption-bearing action'ları kapsamaz.
  - `draft-gazitt-oauth-authzen-token-exchange-01`: iki ayrı değerlendirme (özne kapısı, isteyen taraf kapısı). Access'te `projection.issue` kararı tek bir ADP kararıdır; actor ve basis birlikte değerlendirilir.
  - `draft-mishra-oauth-agent-grants-02` (DAAP): PAR zorunlu, S256, kimliği doğrulanmış insan onayı "politika motoruyla ikame edilemez", DPoP/mTLS. Access'te insan onayı RequirementTerm'dir; politika yerine geçemez, A-5.

#### 11.21.2 Endpoint'ler ve Access karşılığı

| Endpoint | Standart | Access karşılığı |
|---|---|---|
| `GET /.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, `/.well-known/jwks.json` | OIDC Discovery, RFC 8414 | Domain Metadata türevi (P60) |
| `GET /authorize` (+`iss`), `POST /token`, `POST /par`, `POST /revoke`, `POST /introspect`, `POST /register` (legacy), `GET /userinfo` | OAuth/OIDC | §10; token = `projection.issue` |
| `POST /bc-authorize`, `POST /token` (`grant_type=…:ciba`) | CIBA | Davet |
| `POST /authorize-challenge` | FiPA | §10 |
| `GET /.well-known/authorization-details-types` | RAR metadata (taslak) | SPP RAR type görünümü (§9.13.8 madde 8) |
| `POST /access-requests`, `GET /access-requests/{task_handle}` | AuthZEN AARP | `exercise_ref` (nonce) yüzeyi; WATCH |
| `POST /agents/{id}/revoke-all` | Standart yok | `instance.terminate` kümesinin kolaylık yüzeyi (P59) |
| `GET /ssf/.well-known/sse-configuration` | SSF | Identity plane vericisi (§9.16.2) |
| `POST /agent-cards/sign` | A2A | Claim imzası; WATCH (§11.15) |
| SCIM `/Agents`, `/AgenticApplications` | Taslak | WATCH (§11.17) |

**Grant tipleri**. Hepsi `projection.issue` yoludur:
- `authorization_code` (PKCE S256), `refresh_token`, `client_credentials`;
- `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693);
- `urn:ietf:params:oauth:grant-type:jwt-bearer` (ID-JAG tüketimi);
- `urn:openid:params:grant-type:ciba`;
- `urn:ietf:params:oauth:grant-type:device_code` (RFC 8628, A2A `deviceCode`).
- Not: Claude ve ChatGPT saf `client_credentials`'ı MCP için desteklemez (§11.8.3). `client_credentials` ajanın OWN capacity'li kendi Grant'ına dayanır.

**`requested_token_type` değerleri:**
- `…:access_token`, `…:id_token`, `…:refresh_token`, `…:jwt`;
- `…:id-jag` (ID-JAG üretimi);
- `…:txn_token`.

**İstemci kimlik doğrulama metotları:**
- `private_key_jwt` (CIMD ile önerilen);
- `tls_client_auth` / `self_signed_tls_client_auth` (RFC 8705);
- `client_secret_basic` / `client_secret_post` (legacy; CIMD'de yasak);
- `urn:ietf:params:oauth:client-assertion-type:jwt-spiffe`;
- `attest_jwt_client_auth`.

#### 11.21.3 Token tipleri (`typ`)

| `typ` | Ne | Öncelik | Access |
|---|---|---|---|
| `at+jwt` | Access token (RFC 9068) | Bugün | Projection taşıyıcısı; JOSE ES256 (MD-3) |
| `oauth-id-jag+jwt` | ID-JAG | Bugün | Tüketilen: Claim taşıyıcısı (MD-18). Üretilen: authority taşımayan kimlik iddiası projection'ı; authority scope yok |
| `dpop+jwt` | DPoP kanıtı | Bugün | KeyBinding proof (L21); `alg: EdDSA` reddi, `Ed25519` adı (MD-3) |
| `txntoken+jwt` | Transaction Token | Arayüz | Audit-only bağlam |
| `wit+jwt` | WIMSE WIT | Arayüz | KeyBinding/actor-binding girdisi |
| `application/wpt+jwt` | WIMSE WPT | Arayüz | Taşıma kanıtı |
| `oauth-client-attestation+jwt`, `…-pop+jwt` | İstemci attestation'ı | Arayüz | Attestation Claim'i (AG-31) |

- Destek erişimi (MD-9) için **ayrı bir token tipi yoktur**. Projection, RFC 8693 delegation biçiminde standart `at+jwt`'dir: `sub` = kullanıcı, `act` = operatör; authority RAR'dadır (TN-70, TNI-13).

#### 11.21.4 Ajan access token'ının hedef şekli

- Ekosistemdeki hedef claim seti (özet):
  - `iss`, `sub` (yetkilendiren insan), `sub_profile`, `aud` (RFC 8707), `client_id` (CIMD URL), `jti`/`iat`/`exp`;
  - `act` (ajan; `sub` = `spiffe://…`, `sub_profile: ["ai_agent","client_instance"]`, `agent_instance_id`, `agent_platform`, `agent_model`; iç içe, min depth 4);
  - `delegation_chain` (`as_signature`, `delegator_signature`), `del_depth`, `del_max_depth`;
  - `scope`, `authorization_details`;
  - `cnf.jkt`, `txn`, `tenant`.
- Ekosistem kuralı: "`sub` insandır, `act` ajandır. Otonom, yani kullanıcısız ajan durumunda `sub` ajandır ve `act` yoktur."
- Access karşılığı (§9.9.4'ün ajan özeti; AG-26 ile tutarlı):

| Alan | Access kuralı |
|---|---|
| `sub` | FOR(P): P'nin pairwise PartyRef'i. OWN: basis holder Party (operatör veya ajanın kendi Party'si). "Otonom ajan = `sub` ajan" kuralı OWN satırına denk düşer |
| `act` | FOR(P)'de actor Party (pairwise) + `act.iss`; iç içe `act` yalnız lineage'dan (AG-23). Ayrıştırıcı ≥ 4 seviye |
| `sub_profile`, `agent_instance_id`, `agent_*` | Opsiyonel projection; InstanceID ve Attestation Claim'lerinden. Authority girdisi değil |
| `delegation_chain`, `del_depth`, `del_max_depth` | Opsiyonel PROFILE; lineage excerpt'i. Doğrulama PAP'la |
| `scope` | Etiket (L24) |
| `authorization_details` | **Authority'nin tek yeri**: Access RAR üyesi (`kind=bounds`/`intent`, `validity` = ValidityContract) (§9.13.5) |
| `cnf` | Zorunlu (P48) |
| `txn` | Opsiyonel; ExerciseID ile karıştırılmaz |
| `tenant` | **Karar girdisi değil** (P38). Yalnız görüntüleme; rezerve ad kiracıya kapalı (§9.9.4 kural 1) |
| `client_id` | OAuth client; actor değil (PI-7) |

#### 11.21.5 AS metadata'sının ajan alanları

```json
{
  "authorization_response_iss_parameter_supported": true,
  "client_id_metadata_document_supported": true,
  "identity_chaining_requested_token_types_supported": ["urn:ietf:params:oauth:token-type:id-jag"],
  "authorization_grant_profiles_supported": ["urn:ietf:params:oauth:grant-profile:id-jag"],
  "grant_types_supported": ["authorization_code","refresh_token","client_credentials",
    "urn:ietf:params:oauth:grant-type:token-exchange",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "urn:openid:params:grant-type:ciba",
    "urn:ietf:params:oauth:grant-type:device_code"],
  "token_endpoint_auth_methods_supported": ["private_key_jwt","tls_client_auth",
    "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe","client_secret_basic"],
  "dpop_signing_alg_values_supported": ["ES256","Ed25519"],
  "authorization_details_types_supported": ["..."],
  "entity_profiles_supported": ["user","service","ai_agent"],
  "backchannel_token_delivery_modes_supported": ["poll","ping","push"],
  "backchannel_authentication_endpoint": "https://.../bc-authorize",
  "authorization_challenge_endpoint": "https://.../authorize-challenge"
}
```

- `dpop_signing_alg_values_supported` RFC 9864 fully-specified `Ed25519` adını kullanır, `EdDSA`'yı değil. JWS doğrulamada `alg: EdDSA` reddedilir.
- `entity_profiles_supported` WATCH taslağıdır; ilan edilmesi opsiyoneldir.
- Bu belge Domain Metadata'dan türetilir; ayrı bir authority belgesi değildir (P60).

### 11.22 Karar kaydı (AG-1…AG-43) ve invariant adayları (AGI-1…AGI-8)

#### 11.22.1 AG kararları

Statü: FROZEN / PD (POLICY DEFAULT) / EA (ENGINEERING ASSUMPTION) / HYPOTHESIS / WATCH. Garanti: BS / UDC / NG (§13 sınıfları; kesinleştirme §13'tedir).

| ID | Seçim | Statü | Garanti | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| **AG-1** | MCP AS, ajan kimlik kaydı, credential broker/vault ve SSF/CAEP identity plane'dedir; ajanın authority'si authority plane'dedir; MCP RS domain'in PEP'idir | FROZEN (plane ataması) | — | L28; MD-13 plane ataması | MD-13; §11.0 |
| **AG-2** | MCP ontology eşlemesi: client = Instance, tool = ActionRef, `tools/call` = Exercise / exact-intent, liste = DERIVED disclosure, token = projection, elicitation ≠ approval, handle ≠ protocol nesnesi | FROZEN (semantik), wire PD | BS | PI-1/PI-7/EI-18 | §11.2 |
| **AG-3** | CIMD -02 implemente edilir, -00 uyumluluğu belgelenir; `client_id_metadata_document_supported` yokluğu = desteklenmiyor | PD | — | -02 MUST'ları katı üst küme | — |
| **AG-4** | CIMD `client_id` actor değildir; istemci kabulü/politikası MD-14 commit'idir; getirme başarısızlığında istek iptal (SHOULD → MUST) | FROZEN (actor ayrımı), PD (iptal) | BS | PI-7; fail-closed (R2) | §11.3; MD-14 |
| **AG-5** | CIMD'de authority-etkili alan değişirse onay kaydı geçersiz ve AAS'li yeniden onay; Grant revoke edilmez; görsel alan değişikliğinde uyarı | PD | UDC (canlı projection horizon'a kadar) | Spesifikasyon "AS seçebilir" der | §11.3.6 |
| **AG-6** | Loopback redirect: şema+host+path tam; host `localhost`/`127.0.0.1`/`[::1]` ise port yok sayılır; başka gevşetme yok; yalnız-loopback istemciye ek uyarı | PD | — | Claude Code interop; RFC 8252 §7.3 | — |
| **AG-7** | RFC 9207 `iss` her authorization yanıtında (hata dahil) MUST; metadata `issuer`'ıyla bayt bayt özdeş | PD | UDC (koşul: istemci RFC 9207 §2.4 doğrulaması yapar; TN-11 ile aynı) | SEP-2468; OpenAI sert gereksinim | — |
| **AG-8** | `resource` kayıtlı kaynağa karşı doğrulanır, bilinmeyene `invalid_target`; tek `aud`; MCP profilinde `resource` zorunlu | PD (P48'in MCP uygulaması) | BS | Audience oracle'ını önleme | P48 |
| **AG-9** | Access MCP PEP profili `dpop_bound_access_tokens_required: true` (veya mTLS bağlı token) ilan eder; bearer varsayılan değildir | PD | BS (sızan token anahtarsız kullanılamaz); RS'nin `cnf` doğrulaması UDC (RS-M4) | `cnf` zorunlu (P48); interop sonucu §11.8.3 beyanı | §11.5.2; SEP-1932 |
| **AG-10** | PRM PEP yapılandırmasıdır (MD-14); Claim kaynağı veya authority belgesi değildir; Domain Metadata'yla karışmaz | FROZEN | — | P60; L23 | §11.5.2 |
| **AG-11** | Stateless çekirdek: continuation ADP'de yaşar; `clientInfo`/`clientCapabilities`/`serverInfo` hiçbir zaman Claim veya karar girdisi değildir | FROZEN | BS | MCP metni "self-reported"; P37 | §11.5.3 |
| **AG-12** | Liste sonuçları viewer-scoped disclosure'dır; `cacheScope: "public"` yalnız tamamı Public-Grant-türevli ve viewer'dan bağımsız listede; aksi `"private"`; SDK önbellek anahtarı `(Instance, capacity, aud, applied_pos)` | PD | UDC (koşul: Access PEP SDK'sını kullanan, conformance vektörünü geçen PEP; TI-RT12), NG (kendi kodu) | Çapraz kiracı ifşası; E26 | — |
| **AG-13** | State handle ve `requestState` authority taşımaz; `requestState` HMAC/AEAD, kısa TTL, tek kullanım, `(actor Instance, capacity, aud, intent digest)`'e bağlı; REQUIRE_ACTION'da yalnız nonce referansı | PD | BS | "A handle is a name, not a capability"; RS-M12–13 | — |
| **AG-14** | `server/discover` varsayılan yetkilendirme ister; kimlik doğrulamasız yoklama yalnız Public Grant (public selector'lı; `Anonymous(context)` actor'ün kullanabildiği, INV-11) + token-bağımsız sonuçla, `public` | PD | — | Spesifikasyon sessiz; çıkarım | — |
| **AG-15** | `subscriptions/listen` long-running exercise'tır: `min(token exp, horizon)`'da sunucu kapatır; aynı stream'de token yenileme yok; checkpoint'te `continue`; sinyal hızlandırıcı | PD | UDC (SDK'lı, conformant PEP), NG (kendi kodu) | A-8, E31; spesifikasyon sessiz | — |
| **AG-16** | Access PEP SDK MCP RS desteği sunar (PRM, `WWW-Authenticate`, DPoP doğrulama, `Authorized<R,A>`) | PD (ürün kararı); karşılığın yeterliliği EA | — | Rust'ta RS/AS boşluğu | P40 |
| **AG-17** | MCP conformance `auth` süiti + OIDF süiti + Access vektörleri birlikte CI'da; biri diğerinin yerine geçmez | PD | — | Farklı katmanları test ederler | — |
| **AG-18** | Satıcıya özgü interop kuralları (Claude, OpenAI) tarih damgalı interop ekidir, normatif profil değildir. Interop sonucu: DPoP/AIS üretmeyen bugünkü istemciler Access PEP profilinde yalnız `Anonymous`/Public Grant kullanır (§11.8.3) | PD | — | Satıcı davranışı değişkendir | — |
| **AG-19** | Ajan = bir Party altında Instance; ajana özgü authority primitive yok; fark şablonlarda. Authority yalnız Grant'tan, capacity basis Grant'ın AgencyTerms'ünden gelir; Mandate yalnız daraltır ve yalnız holder Party'nin kendi Instance'ına bağlanır | FROZEN | BS | F15; MD-4, C14, INV-4 | §11.9.1 |
| **AG-20** | Identity plane'de ajan kaydı `IdentitySubject`; authority plane'e yalnız Claim olarak çıkar; owner/sponsor ilişki Claim'idir | PD | — | İlişki modeli (kolon değil) | §11.9.2 |
| **AG-21** | Audit ve iptal birimi Instance'tır; replika başına Instance zorunlu değil, görev başına önerilir; ExerciseID eylemi tanımlar | PD | BS (Instance düzeyinde atıf) | Entra dersleri + McGuinness problemi | §11.9.3 |
| **AG-22** | Ajan projection horizon'u: exact-intent = intent validity (tek kullanım); bounds ≤ 15 dk varsayılan; üst sınır P49; refresh ≤ Grant/Mandate bitişi | PD (15 dk EA) | UDC (horizon kapanışı) | "İnsan token'larından çok kısa"; CSA | §11.9.4 |
| **AG-23** | Token exchange çıktısındaki iç içe `act` yalnız lineage'dan üretilir; gelen token'lar yalnız Claim girdisi; splicing yapısal olarak imkânsız | FROZEN | BS | L22; RFC 8693 §4.1; splicing | §11.10.2; P53 |
| **AG-24** | Kanonik zincir = lineage; token'da `act`; `delegation_chain` yalnız PROFILE seçeneği (imzalı lineage excerpt'i); yeni format icat edilmez | FROZEN (kanonik), PD (PROFILE) | BS | L20 | §11.10.4 |
| **AG-25** | Ayrıştırıcı ≥ 4 seviye `act`; ajan şablonu depth ≤ 1 (kalan hop); politika varsayılanı 4 (toplam zincir) reddedilir; lineage tavanı ≤ 16 (§13.7.4); kanonik sınır DelegationTerms | PD | BS | Ayrıştırıcı asgarisi interop içindir; her ek hop prompt-enjeksiyon yüzeyidir | §11.10.4 |
| **AG-26** | Altı delegasyon değişmezi Access INV'lerine eşlenir; yeni invariant gerekmez; eşleme conformance test listesidir | FROZEN (eşleme) | BS | Değişmezler kayıt seviyesinde zaten var | §11.10.4 |
| **AG-27** | Identity plane ID-JAG üretir ve tüketir; ID-JAG Claim/assertion taşıyıcısıdır, authorization grant değildir; Resource AS token'ı `projection.issue`. Üretilen ID-JAG authority taşımayan kimlik iddiası projection'ıdır, authority scope içermez; authority RS tarafında Access Grant'ından gelir | FROZEN (semantik), PD (yetenek) | BS | MD-18 | §11.11 |
| **AG-28** | Uygulamalar arası bağlantı politikası tuple'ı Grant şablonu + Acceptance'a derlenir; `allowed_scopes` ID-JAG'da yalnız ipucudur (R3), authority değildir; `subject_mapper` = pairwise PartyRef; değişiklik MD-14 commit'i | PD | — | Yönetici ayarı ayrı kaynak değildir | §11.11.2 |
| **AG-29** | ID-JAG tüketiminde beş adım (imza/issuer, `typ`, `aud`, istemci sürekliliği, `exp`/`iat`/`jti`); `jti` tek kullanım, TTL = `exp`; önbellek tazeliği yoksa fail-closed | PD | BS | Doyensec replay; Atlassian üretim kanıtı | §11.11.3–4 |
| **AG-30** | Workload kimliği (SPIFFE, WIMSE, bulut OIDC) actor-binding Claim'i/KeyBinding'dir; trust domain ≠ AuthorityDomain; Txn-Token audit-only | FROZEN | BS | L21, L25 | §11.12 |
| **AG-31** | Attestation bir Claim'dir; donanım kökü veya attester modeli domain'in Acceptance seçimidir; attester'ın imzalayabileceği Claim class'ı Acceptance'ta kayıtlıdır | PD | BS (class kısıtı), NG (attester ele geçirilirse kapsamı içinde) | Teleport sorusu | §11.12.4 |
| **AG-32** | Credential broker/token vault identity plane'dedir; upstream token'ın ajana verilmesi/kullanılması Access kararıdır (release Exercise'ı; release kaydı projection'dır, upstream token projection değildir); broker'ın çağrıyı kendisi yapması varsayılandır (CT2+ broker-as-PEP); (b) yolunda token `exp` ≤ ValidityContract horizon | FROZEN (kural), PD (tercih) | BS (karar ve kayıt); UDC (broker'ın verme kararının zorlanması; upstream `exp`/`aud`); NG (upstream token içeriği; (b)'de `cnf`'siz sızıntı, horizon içinde) | MD-13 | §11.13 |
| **AG-33** | Çalıştırma ortası onay: tek soyutlama REQUIRE_ACTION nonce'u; dört yüzey (`interaction_required`, deferred, txn-challenge, AARP) + CIBA daveti ona eşlenir; onay AAS'tir, token değil | FROZEN (soyutlama), WATCH (yüzeyler) | BS | AIMS §10.7 | §11.14; P54 |
| **AG-34** | A2A Agent Card bir Claim'dir; kart imzası authority vermez; mTLS SAN'daki SPIFFE ID actor-binding Claim'i; görev devri alt-delegasyon veya ayrı Exercise | PD | BS | A2A boşluğu; A-7 | §11.15 |
| **AG-35** | Dört kaynağın 8 ortak gereksinimi Access mekanizmalarına eşlenir; §13'e girdi | PD | Satır başına (tablo) | Tedarik baskısı | §11.18 |
| **AG-36** | Ajan claim taslakları WATCH (arayüz hazır); trust score yalnız Claim, yalnız daraltır; iptal edilemez ajan kimliği REJECT; kayıt = keşif/Claim kaynağı | PD | BS (skor authority üretmez) | CI-2 | §11.17 |
| **AG-37** | §8.18.1–§8.18.4 (A-1…A-12 dahil) normatiftir; kanonik tam metin §8.18'dedir, §11.16 atıf + MCP/OAuth uygulanış notlarıdır | FROZEN (§8.18 metni) | — | MD-19 #2 | §11.16; §8.18 |
| **AG-38** | Identity plane ajan yüzeyi envanteri Access statüleriyle sınıflandırılır; COAZ-MCP REJECT; `Ed25519` adı (`EdDSA` değil) | PD | — | L27; MD-3 | §11.21 |
| **AG-39** | **Token vault upstream kataloğu.** En yaygın 20–30 servis (ör. Google, Microsoft, GitHub, Slack, Notion, Salesforce, Atlassian) için küratörlü upstream tanımları hazır gelir: OAuth/OIDC metadata, scope kataloğu, token yenileme ve iptal kuralları. Tanım veridir (F23). Upstream eklemek realm config değişikliğidir (`idp.*` domain action, MD-14). Release kararı her zaman bir Access Exercise'ıdır; hazır tanım hiçbir ajana authority vermez (E36, EI-26) | FROZEN (katalog var, release kuralı); PD (servis listesi) | BS (release kaydı) / NG (upstream token içeriği) | Ajan kullanım alanlarının çoğu yaygın SaaS'lara bağlanır; hazır tanım entegrasyon süresini kısaltır | E36; EI-26; MD-14 |
| **AG-40** | **Ajan bağlayıcısı ve yürütücü sınırı.** (1) Access bağlayıcının bağlantı ve yetki kısmıdır: upstream token'ların saklanması (token vault), hazır upstream tanımları (AG-39) ve "bu ajan bunu şimdi yapabilir mi" kararı (release Exercise'ı). (2) Araç tanımları (ajana sunulan araç şemaları) ve yürütme (upstream API'yi çağırma, yeniden deneme, sonucu döndürme) Executor'dadır. Executor Access'in çekirdeğinde değildir ve karar vermez; Access'in sunduğu bir servistir (**Access Executor servisi**), ayrı süreç ve ayrı proje olarak geliştirilir, Access ile birlikte teslim edilir (B21). Access çağrıyı kendisi yapmaz (F7). (3) CT2–CT3: upstream token hiçbir zaman ajana verilmez; yalnız kayıtlı ve kimliği doğrulanmış bir yürütücüye (Access Executor servisi veya müşterinin kendi kayıtlı yürütücüsü) yalnız o iş için verilir. Token kalıcı olarak vault'ta kalır; yürütücü iş başına kullanım alır. (4) CT0–CT1: token ajanın koduna yalnız ömrü ≤ 1 saatse veya upstream iptal adresi yayımlıyorsa verilebilir; aksi hâlde ya da bilgi eksikse iş yürütücüye gider. Hakkında bilgi olmayan, müşterinin eklediği upstream'ler varsayılan olarak yürütücüye gider. (5) Token ömrü ve iptal desteği token cevabındaki `expires_in`, upstream'in OAuth metadata'sındaki `revocation_endpoint` ve AG-39 tanımlarından öğrenilir. (6) Sınıflandırılmamış action CT2 sayılır. (7) Upstream token ajan modelinin bağlamına (prompt/sohbet içeriği) konamaz | FROZEN (sınır, 1–3, 5–7); PD (4'teki 1 saat eşiği) | BS (karar ve release kaydı) / UDC (yürütücünün intent ⊑ Grant denetimi) / NG (araç sonucu, ajana verilen token'ın kullanımı) | Access karar verir, işi yapmaz; token'ın ajana gitmemesi prompt enjeksiyonu ve token sızıntısı riskini kapatır | F7; E36; AG-39; MD-8; L24 |
| **AG-41** | **Ajan kaydı (registry) ve insan sorumlusu.** Ajan kaydı mevcut modelin (ajan Party + Instance, Grant, Mandate, bağlı hesaplar) üstünde bir yüzey ve API'dir; yeni primitive değildir. Her ajan için: sorumlu(lar), yetkiler, bağlı hesaplar (AG-39), son çalışma, durum. Her ajan Party'sinin **en az bir aktif insan sorumlusu** zorunludur. Sorumlu ayrılırsa (hesap devre dışı, SCIM sağlama kaldırma) ve başka aktif sorumlu yoksa ajanın Mandate'leri ve Instance'ları otomatik **askıya alınır** (daraltma; silme değil) ve yeni sorumlu atanana kadar ajan exercise edemez; askı ve atama Changes'ta görünür (SI-21) | FROZEN (zorunlu sorumlu, askıya alma); PD (yüzey ayrıntısı) | BY SEMANTICS (askı sonrası exercise yok); UNDER DECLARED CAPABILITY (ayrılma sinyalinin zamanında gelmesi) | Sahipsiz ajan, sahipsiz servis hesabı gibi kalıcı açık üretir | X13; SI-21; TN-95 |
| **AG-42** | **MCP gateway = Access Proxy MCP modu.** Access Proxy'nin (IDP-30, B22) MCP modu, Access'e entegre olmayan MCP sunucularının önünde PEP olarak çalışır: MCP trafiğini ayrıştırır, her araç çağrısında Access'e karar sorar (ajan, araç, parametreler, intent), kararı uygular ve çağrıyı kaydeder. Araç listesi ve tanımları için sabitleme (pin) ve değişiklik tespiti uygular (tool poisoning). Ayrı bir gateway ürünü yazılmaz | FROZEN (karar = Access kararı); PD (araç sabitleme politikası) | BS (karar kaydı) / UDC (proxy'nin uygulaması) / NG (proxy atlatılarak doğrudan erişilen MCP sunucusu) | Mevcut proxy genişletilerek MCP gateway elde edilir; her araç çağrısı yetki kararına bağlanır | IDP-30; B22; §11.7 |
| **AG-43** | **Gölge ajan ve NHI keşfi, iki aşamalı.** Aşama 1 (gün-1): Access'in kendi gördükleri raporlanır: kayıtsız istemciler, Instance'ı belirsiz token'lar, kullanılmayan bağlantılar ve Grant'lar; dış keşif araçlarından gelen sinyaller SSF ile kabul edilir (gelen sinyal yalnız daraltır, E38). Aşama 2: AG-39 bağlayıcılarıyla bağlı servislerin (Google, Microsoft, GitHub vb.) üçüncü taraf uygulama izinleri taranır ve kayıtsız ajanlar raporlanır. Keşif authority üretmez; bulguya göre aksiyon (askı, iptal) ayrı bir Exercise'tır | FROZEN (keşif authority üretmez); PD (aşama 2 zamanlaması) | NG (keşfin eksiksizliği) | Kayıtsız ajanlar en büyük görünmezlik açığıdır; tam keşif ürünü ayrı uzmanlık alanıdır | E38; AG-39; §4.4 |

#### 11.22.2 AGI invariant adayları

Numaralama ve kabul §6'nın işidir. Burada aday olarak önerilir.

| ID | Aday invariant | Gerekçe / bağlı karar |
|---|---|---|
| **AGI-1** | Bir projection'daki önceki aktörler (iç içe `act`, `delegation_chain`) yalnız Access lineage kaydından üretilir; gelen herhangi bir token'dan kopyalanmaz | Splicing (AG-23); L22'nin üretim yönü |
| **AGI-2** | Bir kimlik bilgisine sahip olmak (vault'taki upstream token, state handle, `requestState`, consent kaydı, CIMD kaydı) hiçbir zaman authority değildir | MD-13; AG-13; AG-32 |
| **AGI-3** | Access'in ajan Instance'ına verdiği her **Access projection'ı** `cnf`-bağlıdır. Sahiplik anahtarı olmayan bir taraf (ör. LLM bağlamı) Access projection'ını kullanamaz. Upstream token teslimi (§11.13 (b)) bu invariant'ın dışındadır, varsayılan kapalıdır ve NG satırıyla beyan edilir | AIMS §8; CSA; AG-9 |
| **AGI-4** | Ajan Instance'ı insan varlığı gerektiren bir RequirementTerm'ü hiçbir taşıyıcıyla karşılayamaz; `not-satisfiable-by-actor` hiçbir yüzeyde etkileşime dönüştürülmez | §8.18.3; §9.9.5 ek kural 1 |
| **AGI-5** | Viewer'a göre değişen bir liste/disclosure sonucu, viewer'lar arasında paylaşılan bir önbellek kapsamıyla (`public`) işaretlenmez | AG-12; E26 |
| **AGI-6** | Bir istemci tarafından geri getirilen opak durum (`requestState`, state handle, `deferral_code`, AARP görev tutamağı) en fazla bir nonce referansıdır ve karar girdisi değildir | AG-13; AG-33 |
| **AGI-7** | Inbound ID-JAG, token `act` zinciri, A2A Agent Card ve ajan güven skoru karara yalnız aktif bir Acceptance'ın use'u olarak girer; hiçbiri Grant ikame etmez | MD-18; AG-27; AG-34; AG-36; INV-15 |
| **AGI-8** | Bir ajanın kendi isteğine yönelik contribution'ı, kullanıcının kendi Instance'ından gelen AAS dışında hiçbir kanalla (sohbet, elicitation, CIBA yanıtı, token) oluşamaz | A-5; EI-18; AG-33 |

### 11.23 Doğrulanamayanlar (bu bölümde kullanılan)

**Spesifikasyon ve standart.**
1. MCP'nin CIMD -00 atfı ile -02 farkı doğrulanmıştır. PR #3235'in merge tarihi bilinmiyor.
2. CIMD -02 §6 "MUST include" ile IANA OPTIONAL çelişkisi muhtemelen editoryaldir; yazarlara doğrulatılmadı.
3. CIMD -02'de `application/json` içerik türü şartı yok; muğlak.
4. `server/discover`'ın kimlik doğrulamasız olup olamayacağı tanımsız; AG-14 Access'in kararıdır, spesifikasyon yorumu değildir.
5. `subscriptions/listen` token süresi davranışı tanımsız; AG-15 Access'in kararıdır.
6. SEP-837'nin statüsü (Final mi, merged mi) doğrulanamadı.
7. Delegation chain splicing'in birincil posta listesi mesajı okunamadı; mekanizma ikincil kaynaktan.
8. `draft-ni-wimse-ai-agent-identity` için -03 olup olmadığı; -02'nin süresi doldu.
9. AIMS'in "sekiz katmanı"; ham metinde yedi bileşen var.
10. ID-JAG'ın hedeflenen statüsü: Datatracker "None", metin "Standards Track" diyor.
11. `draft-parecki-oauth-global-token-revocation-06` revizyon/süre çelişkisi.
12. SSF 1.0 / CAEP 1.0 Final tarihi: kaynaklarda "2 Eylül 2025" ve "29 Ağustos 2025" (MD-18: doğrulanmadı).
13. A2A v1.0'ın kesin genel kullanım tarihi (Mart mı Ağustos 2026 mı).

**Güvenlik.**
14. MCP CVE tablosunun tamamı toplayıcı kaynaklıdır; NVD JSON API ile teyit edilmedi. CVE-2026-24052 ve CVE-2026-25536 birincil advisory'lerle doğrulanamadı. CVE-2025-54136 CVSS'i 7,2 / 8,8 çelişkili.
15. `mcp-cve-project` 570+ CVE iddiası, 1.862 açık örnek ve %8,5 OAuth istatistikleri.
16. NSA/CISA "MCP: Security Design" PDF'i açılamadı.
17. arXiv 2605.22333 tam PDF'i ayrıştırılamadı; özet kullanıldı.
18. Obsidian taramasının 660/27 ve 78/3 sayıları ikincil kaynaktandır.

**Ekosistem.**
19. Keycloak'ın RFC 9728/8707/9207/PAR/DPoP durumu; ID-JAG üretim issue'su keycloak#43971.
20. Auth0 MCP teklifi ve RFC 9728 implementasyonu; Clerk, Okta MCP verisi; Stytch/Descope yalnız genel bakış düzeyinde.
21. `rust-mcp-sdk`'nın %100 conformance iddiası; MCP conformance çatısının tam yetkilendirme senaryo listesi (üç ad doğrulandı).
22. Entra Agent ID'nin açık standart (ID-JAG, MCP EMA, WIMSE) desteği.
23. Okta Agent SSO genel kullanım tarihi (24 Ağustos 2026 birincil; Mayıs 2026 ikincil).
24. Singapur CSA ekinin nihai metnindeki kimlik kontrolleri; PSD3/PSR'de ajansal YZ hükmü bulunamadı; NIST SP 800-63 insan olmayan kimlik güncellemesi takvimi.
25. `draft-sweeney-wimse-credential-delegation-00` ve IETF 126 "SOOS: Mandate JWT" sunumunun içeriği incelenmedi.

**Bu bölümün kendi varsayımları (çıkarım veya EA olarak işaretli).**
- AG-22'deki 15 dk bounds horizon'u (EA).
- AG-12'deki önbellek anahtarı bileşimi (çıkarım).
- AG-13'teki `requestState` bağlama dörtlüsü (çıkarım).
- §11.13 upstream token akışındaki (a)/(b) tercihi (PD).
- §11.12.3'teki `tctx` içine ExerciseID konması (PD, çıkarım).
