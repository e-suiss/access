## 14. Güvenlik Güvencesi, Sertleştirme, Test ve Uyum

> **Bölüm notu.** §13 *ne* garanti edildiğini (sınıf ve koşul) söyler; bu bölüm o iddiaların *nasıl* ayakta tutulduğunu söyler: iddia disiplini, tehdit modeli, red team, açık yönetimi ve dış güvence, binary/runtime sertleştirme, parser/DoS, tedarik zinciri, test/doğrulama ve uyum. Red-team verdict (K/CL; §16.8), HL (§16.9) ve RT1–RT30 (§16.11) kararlarının kendisi §16'dadır; burada yalnız referans verilir. Kriptografik algoritma, anahtar yönetimi, yan kanal ölçümünün kriptografik tarafı ve formel doğrulamanın kripto kısmı §15'tedir; veri/HA/denetim log'u/operasyon §17'dedir. Bu bölüm onlara çapraz referans verir, tekrar etmez.
>
> **Karar satırı biçimi.** Her SA-n satırı: *Karar* · *Statü* (FROZEN / PD / EA / HYPOTHESIS / WATCH) · *Sınıf* (BS / UDC / NG / PU — §3.3) · *Gerekçe* · *Kaynak*. Invariant adayları SAI-n olarak yazılır; §6 yalnız işaret eder. Fail-closed (MD-8) her kararın üst kuralıdır; hiçbir SA kararı yeni authority primitive'i getirmez.

### 14.1 İddia disiplini

**Kural.** Her güvenlik iddiası §3.3 sınıflarından tam birindedir (SEC2) ve §13.4'te bir satıra bağlıdır; bir yüzeyde (UI, doküman, sözleşme, pazarlama, satış sunumu, API açıklaması) geçen güvenlik cümlesi o satırın sınıfından daha güçlü olamaz. §13.8'deki ifadeler hiçbir yüzeyde kullanılmaz. Sayı taşıyan her iddia kaynak etiketi taşır (ölçüm / kaynak §x / tahmin); ölçülmemiş performans ve gecikme değerleri EA'dır; doğrulanmamış dış iddialar "doğrulanmadı" ile işaretlenir.

**Formel doğrulama dili.** İzin verilen biçim: "Kernel'in *P* özelliği *M* modelinde *T* aracıyla, *K* sınırları içinde doğrulandı; kapsam dışı: HTTP/async katmanı, derleyici, donanım." Yasak biçim: "Access formel olarak doğrulanmıştır", "kiracı izolasyonunu derleyici garanti eder". Gerekçe: formel kapsam kernel/semantik ile sınırlıdır (HTTP/async kapsam dışı — HL-15); doğrulanmış kütüphanelerde bile açık bulunur (Kobeissi ePrint 2026/192: 13 açık; "%58.4" oranı küçük örneklemdir — doğrulanmadı) (N-47).

**Kapatılamayan boşluklar — RR olarak sahiplenilmiştir.**

| Boşluk | §13 satırı | RR |
|---|---|---|
| Argon2'nin doğrulanmış implementasyonu yok | — | RR-16 |
| RS256'nın doğrulanmış implementasyonu yok; `rsa` crate'inde Marvin yamasız | G46 (authority artefaktı, kabı ne olursa olsun, RSA veya realm anahtarıyla imzalı değildir) | RR-17 |
| LLVM constant-time garanti etmez | HL-16, U45, N-35 | RR-26 |
| Async/HTTP formel kapsam dışı | HL-29 (HL-15), N-36 | RR-27 |
| crates.io yayıncı imzası yok | HL-24, N-44 | RR-21 |

| ID | Karar | Statü | Sınıf | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| SA-1 | Her güvenlik iddiası tam bir sınıfta ve bir §13.4 satırına bağlı; yüzey metni satırdan güçlü olamaz; §13.8 listesi niteliksiz "formel olarak doğrulanmış", "kiracı izolasyonunu derleyici garanti eder", "çevrimdışı token'lar tek işlemde iptal edildi" ve MD-10/17 ifadelerini kapsar | FROZEN | BS (dil kuralı) | Niteliksiz "formel doğrulanmış" ve "anında iptal" dili XI-12 disiplinini bozar | SEC2; XI-12 |
| SA-2 | Kural: "doğrulanmış/denetlenmiş" bir bağımlılık güvenlik iddiasının kanıtı değil, girdisidir; iddia yalnız kendi test/vektör/ölçüm kanıtıyla | FROZEN | NG (N-47) | Doğrulanmış kütüphanelerde 13 açık (Kobeissi ePrint 2026/192) | — |
| SA-3 | Sayısal iddialar kaynak etiketli; ölçülmemiş hedef EA; doğrulanmamış dış sayı "doğrulanmadı"; sahte/şişirilmiş güvenlik verisi (14,140 vs 1,815) karar girdisi olamaz | FROZEN | — | LLM/SEO kaynaklı sayı kirliliği | RR-34 |
| SA-4 | Kapatılamayan beş boşluk RR-16/17/21/26/27 olarak sahiplenilir; pazarlama metninde "boşluk yok" ima edilmez | FROZEN | NG | Dürüst sınır beyanı | — |

**SAI-1 (aday).** §13.4'teki her G/U/N satırının en az bir izlenebilir test, vektör, proof veya (NG/PU için) dürüst-ifade testi (UI metni §13.8 karşılığına uyar) vardır; CI bu eşlemeyi doğrular ve eşlemesiz satır release'i bloklar (threat-model-as-code; MD-15b).

### 14.2 Tehdit modeli ve LINDDUN

**Yöntem.** Tehdit sınıfları TH-1–TH-32'dir (traceability-only ID'ler); her TH satırı bir STRIDE ve gerekiyorsa bir LINDDUN etiketi taşır. LINDDUN (Linking, Identifying, Non-repudiation, Detecting, Data disclosure, Unawareness, Non-compliance) identity plane ile birlikte zorunlu hâle gelir, çünkü kimlik verisi Access'in authority verisinden farklı olarak doğrudan kişisel veridir (MD-10). PASTA ve attack tree'ler yüksek etkili akışlar (recovery, admin, support erişimi, federation) için kullanılır; araç seçimi (Threat Dragon, Threagile, pytm, IriusRisk, MS TMT) uygulama kararıdır (WATCH).

**TH etiket tablosu (özet).**

| TH | Sınıf | STRIDE | LINDDUN | Birincil §13 satırı |
|---|---|---|---|---|
| TH-1 | Malicious user | E | — | G1–G3 (non-amplification) |
| TH-2 | Compromised user (AiTM) | S | — | §13.7.3; N-41, N-45 |
| TH-3 / TH-4 | Malicious / compromised agent | S, E | — | DL-6; PI-11 |
| TH-5 / TH-6 | Hallucinating model / prompt injection | T, E | — | RR-12 |
| TH-7 / TH-8 | Malicious executor / PEP / verifier | T, R | — | U1, U2, N-3 |
| TH-31 / TH-32 | Malicious surface / forged event | S, T | Unawareness | DL-2, N-2, N-38 |
| TH-9 | Malicious operator | T, I, E | Detecting, Data disclosure | DL-1, DL-4, §13.2 custody ≠ root |
| TH-10 | Peer domain / federation abuse | E | Linking | INV-17; G52 |
| TH-11 / TH-12 / TH-13 | Party / Instance / provider key theft | S | — | U14, U25, U41, G47 |
| TH-14 / TH-15 / TH-16 | Approval fatigue, push bombing, consent phishing | S, E | Unawareness | SEC17, SEC28 |
| TH-17 / TH-18 | Confused deputy / collusion | E | — | PI-7; DL-6 |
| TH-19 / TH-20 | Explanation probing / audit export exfiltration | I | Identifying, Data disclosure | DL-7, SEC24, SEC29 |
| TH-21 / TH-22 / TH-23 | Publisher / IdP / HR issuer compromise | S, T | — | SEC9, SEC16, G45 |
| TH-24 / TH-25 / TH-26 | Equivocation / lost suffix / forced migration abuse | T, R | — | DL-4, DL-5, §13.6 |
| TH-27 / TH-28 / TH-29 | Clock / replay / downgrade | T, S | — | K-2; PI-7; §13.7.8 |
| TH-30 | DoS on decision path | D | — | SI-20; §14.6 |
| (identity plane) | AiTM kitleri, infostealer, device code phishing, oturum hijack | S, I | Linking, Identifying | N-41, N-45, HL-23 |
| (identity plane) | Golden SAML (MITRE T1606.002), Modify Authentication Process (T1556), Alternate Authentication Material (T1550), MFA Request Generation (T1621) — teknik ayrıntılar doğrulanmadı | S, E | — | §13.2 realm imza anahtarı satırı; SEC28 |
| (identity plane) | Enumeration, credential stuffing | I, D | Identifying | U44, U46, N-46 |
| (identity plane) | Çapraz-RP korelasyon | — | Linking, Identifying | DL-9, U40, N-31 |
| (barındırma) | Co-tenant yan kanal | I | Data disclosure | DL-10, U54, N-32 |

**Dış referans çerçeveleri.** RFC 9700 (OAuth 2.0 Security BCP, BCP 240, Ocak 2025), RFC 6819 (OAuth tehdit modeli), NIST SP 800-63C (federasyon; FAL, PPII), MITRE ATT&CK teknikleri yukarıdaki gibi. Teknik ayrıntılar ve alt-teknik numaraları **doğrulanmadı**.

**Abuse case'ler (AB-1–AB-10).** AB-1 agent'ın insanı yorarak onay toplaması; AB-2 budget splitting; AB-3 rule-shaped selection'a sızma (HR feed manipülasyonu); AB-4 bootstrap/admission abuse; AB-5 revocation race; AB-6 offline slice abuse; AB-7 schema mapping manipülasyonu; AB-8 delegation chain laundering; AB-9 capacity spoofing (FOR(P) iddiası); AB-10 cross-product confused deputy. Karşılıkları §13.7.6 (structuring), §13.7.4 (rate) ve SEC16/SEC13/SEC28'dedir.

**Bilgi akışı (IFC).** IFC Option B (disclose / declassify authority; label = data owner'ın Claim'i) geçerlidir; SEC30 bağlayıcıdır. Identity plane'den gelen kişisel veri (e-posta, telefon, ulusal kimlik) `disclose` sınıfındadır; RP'ye ilk disclose CT2'dir (SEC30) ve korelasyon riski DL-9'dur.

| ID | Karar | Statü | Sınıf | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| SA-5 | TH-1–TH-32 STRIDE + LINDDUN etiketleri taşır; identity plane tehditleri (AiTM, infostealer, device code phishing, oturum hijack, Golden SAML, enumeration, korelasyon, co-tenant) aynı tablodadır; yeni tehdit ID ailesi açılmaz | FROZEN | — | Tek tehdit dili; LINDDUN gizlilik boşluğunu kapatır | — |
| SA-6 | Threat-model-as-code: tehdit modeli depoda makine-okur biçimde tutulur; CI her TH satırının en az bir §13 satırına ve her §13 satırının en az bir teste bağlı olduğunu doğrular (SAI-1) | PD (araç), FROZEN (eşleme kuralı) | UDC | Spec ↔ test sürüklenmesini önler | — |
| SA-7 | Trust model (§13.2) realm JOSE/SAML imza anahtarı (Golden SAML), operasyonel/binding anahtarı, LDAP/Kerberos/RADIUS/WS-Fed gateway, SCIM istemcisi, parser worker, co-tenant ve destek personeli satırlarını içerir | FROZEN | BS ("Asla" sütunu) | Identity plane bileşenlerinin blast radius'u beyan edilir | MD-1; MD-6; MD-9; MD-17; MD-18 |

### 14.3 Saldırı kataloğu ve red team

**Yöntem.** Red team iki eksenlidir: teknik (scale, concurrency, partition, clock, region/DB/log failure, replay, duplication/out-of-order, migration, offline, revocation, redaction, extreme workload) ve semantik (iki doğruluk kaynağı oluşabilir mi; derived canonical'ı ezebilir mi; authority bypass edilebilir mi; özel bilgi örtük geçebilir mi; kimlik sessizce değişebilir mi; sorumluluk kaybolabilir mi; implementasyon ayrıntısı canonical olabilir mi; ürün fiziksel olarak imkânsızı vaat edebilir mi). Her bulgu ya bir frozen sınıfın kendi satırına (§13.4) ya bir düzeltmeye (TI-RT / RT; §16) ya da beyanlı bir HL'ye bağlanır; "kısmen dayanır" sonucu kabul edilmez.

**Red-team sonucu — referans.** Verdict: **HOLDS AFTER CORRECTIONS**. Hiçbir saldırı bir frozen invariant'ın semantiğinin yanlış olduğunu göstermedi; 13 kırılma + 2 cross-layer bulgusu düzeltildi. Düzeltmelerin kararları (TI-RT1–TI-RT12, RT1–RT30) §16'dadır; aşağıdaki tablo yalnız bulgu ↔ §13 satırı izlenebilirliğidir.

| Bulgu | Konu | Canonical düzeltme (§16) | §13 satırı |
|---|---|---|---|
| K-1 | Yeniden değerlendirme farkının handover/recovery'yi durdurması; implementasyonun spec yerine geçmesi | Record-fold; doğrulama kapı değil; divergence quarantine; normatif = L0/L2 + vektörler (TI-RT1, TI-RT12, RT3) | G32, HL-12; §13.6 |
| K-2 | Fark edilmemiş saat sıçraması | İki bağımsız zaman kaynağı + sınırlı ilerleme + witness çapraz kontrolü (TI-RT2) | U29, N-28, HL-6 |
| K-3 | Kayıp suffix'teki AIS'in yeni lineage'da tekrar Exercise açması | İlk-commit AIS yaşı ≤ intent validity tavanı + SEC22 R1 (TI-RT3, RT6, RT7) | U28, U31 |
| K-4 | Derived snapshot'ın SYNC-DERIVED'ı ezmesi | Yalnız canonical-taraf kaynak; rebuild-diff (TI-RT4) | §16 (TI-RT4) |
| K-5 | Kendi beyanlı metadata tazeliği | Bağımsız witness cosign tazeliği + heartbeat (TI-RT5) | U12, N-30 |
| K-6 | Operasyonel anahtar excerpt'inde DomainID yokluğu | Excerpt'e DomainID; domain-başı operasyonel anahtar (TI-RT6); MD-6 ile must-understand | G47, HL-8 |
| K-7 | Handover sonrası eski anahtar statüsü | `superseded-at C_{h+1}` + predicate + drain (U27, RT13) | U27 |
| K-8 | Varış sırasıyla Claim güncelliği | Issuer sırası (TI-RT7) | G36 (TI-RT7); AS-18'de (SCIM) yeniden denenecek |
| K-9 | Release'in draw'u aşması | Σrelease ≤ draw (TI-RT8) | §16 (TI-RT8) |
| K-10 | Toplu meta-Exercise'ın domain'i kilitlemesi | O(1) işaret + tembel episode (TI-RT9) | U34 |
| K-11 | Sessiz depolama bozulması | Kayıt kimliği = commitment; FA-14 (TI-RT11) | G34, U30, N-29 |
| K-12 | Pozisyon ve event id sızıntısı | Opaque token + HMAC (TI-RT10) | G37 (TI-RT10); kalan sınır HL-10 |
| K-13 | Normatif kuralların kodda kalması | L0/L2 + vektör kapsamı (TI-RT12, RT22) | HL-12; §14.8 |
| CL-1 | UI'ın timeout'ta sonucu bilir gibi konuşması | "Not confirmed — checking" + aynı-nonce retry (RT23) | G39, N-27, §13.8 |
| CL-2 | Ack edilmemiş durumun ack edilmiş gibi gösterilmesi | `witnessed_through` + "confirming (witness pending)" (RT24) | §13.8 |

**Saldırı yüzeyi haritası.** AS-1–AS-15 geçerlidir (Protocol Gateway + Request Verifier; Domain Sequencer; Canonical Store; Derived Store; Claim Ingest; Projection Issuer/Signer + Key Mgmt; Offline Verifier SDK; Domain Metadata + discovery; Checkpointer + witness + replica; Handover/recovery; Identity plane + custody; Experience + hub; Events/outbox/SSF; zaman kaynakları; Spec ↔ Access Core ↔ üçüncü taraf implementasyon). Identity plane yüzeyi için dört satır daha vardır. **Sonuç sütunu boştur: bu yüzeyler henüz red team turundan geçmemiştir**; aşağıdaki "denenecek" listesi plandır, sonuç değildir.

| # | Yüzey | Güven sınırı / saldırgan | Denenecek test aileleri | Sonuç |
|---|---|---|---|---|
| AS-16 | SAML / XML (SP ve IdP rolleri; parser worker; c14n; imza doğrulama) | İnternet; kötü niyetli IdP/SP; imzalı assertion'ı ele geçiren saldırgan | 8 klasik XSW + 3 yeni sınıf, DocType/entity, c14n differential, imza sarmalama, yorum enjeksiyonu, Golden SAML senaryosu | AÇIK — red team bekliyor |
| AS-17 | LDAP gateway (bind, search, BER) | Ağ; anonim istemci; ele geçirilmiş servis hesabı | İç içe filtre (Kanidm GHSA-qcxq, GHSA-qcrp sınıfı), BER uzunluk/derinlik, LDAP injection, bind parola yolu (gateway açık metin görür) | AÇIK |
| AS-18 | SCIM (gelen provisioning; filter; bulk) | Ele geçirilmiş/hatalı SCIM istemcisi; sırasız teslim | Filter derinliği (GHSA-r5fr, GHSA-2pm5 sınıfı), bulk boyutu, K-8 sırasızlık, attribute ile authority genişletme girişimi (INV-16) | AÇIK |
| AS-19 | Parola / login / recovery / MFA | İnternet; credential stuffing; AiTM; MFA bombing; hesap kurtarma sosyal mühendisliği | Enumeration (status/body/header/redirect/zaman), stuffing, Argon2 DoS, push bombing, AiTM/BitM lab (Evilginx sınıfı), recovery'nin korunan seviyeden zayıf olması | AÇIK |

**Bilinen failure-mode tekrarları (FM-1–FM-24).** FM-1 Zanzibar new-enemy; FM-2 dual-write; FM-3 token theft/replay; FM-4 confused deputy; FM-5 consent phishing; FM-6 MFA bombing; FM-7 actor-token / tenant crossing (CVE-2025-55241); FM-8 Storm-0558; FM-9 Golden SAML; FM-10 cache poisoning; FM-11 TOCTOU; FM-12 split-brain; FM-13 equivocation; FM-14 OCSP soft-fail; FM-15 CAE gecikmesi; FM-16 SolarWinds; FM-17 Bybit (signer UI); FM-18 Kerberos ticket uzun ömrü; FM-19 Okta HAR / session token sızıntısı; FM-20 Salesloft-Drift; FM-21 replay across recovery; FM-22 clock attacks; FM-23 silent data corruption; FM-24 out-of-order SCIM/SSF. K-6/K-1/K-3/K-2/K-11/K-8 bağlantıları yukarıdaki tablodadır.

**CVE ve advisory kataloğu → regresyon gereksinimi.** Rakip ve bağımlılık advisory'leri birer "bu sınıf bizde regresyon testiyle kapalıdır" gereksinimine dönüşür (§14.8 bilinen saldırı regresyonu). Yeni ID ailesi açılmaz; satır anahtarı advisory kimliğidir.

| Advisory | Sınıf | Access karşılığı |
|---|---|---|
| Kanidm GHSA-r5fr-9gmv-jggh (CVE-2026-46689; CVSS 8.7 / GHSA'da 7.5) ve GHSA-2pm5-6m23-h692 | SCIM filter özyineleme → stack tükenmesi; derinlik limiti kurala inildikten sonra kontrol ediliyordu | Derinlik ≤ 32 **özyinelemeden önce** (MD-2; SAI-2); SCIM filter fuzz hedefi |
| Kanidm GHSA-qcxq-75wr-5cm8 ve GHSA-qcrp-p3rq-pffr | LDAP filter / BER decoding özyinelemesi (`lber`), kimlik doğrulamasız | BER derinlik/uzunluk limiti; LDAP BER fuzz; gateway ayrı süreç |
| Kanidm GHSA-xxwr-vvr3-2g9f (Critical 9.3) | `Modify::Set` küme mantığı → kimliği doğrulanmış keyfi yazma; crash üretmez | Durumlu PBT + metamorfik ilişki (rol atama permütasyonu; MR4); fuzz bu sınıfı bulmaz |
| Kanidm GHSA-84jc-3hj2-hwc7 | Görsel doğrulayıcıların yetkilendirmeden önce çalışması; PNG panic | "Auth before expensive extractor"; panic yasağı (MD-2) |
| Kanidm GHSA-53hj-r94p-8c8f; RAUTHY-005 | `client_secret` constant-time olmayan karşılaştırma | U45; `==` lint yasağı; dudect |
| Kanidm GHSA-gpxg-fx2g-qxj2; RAUTHY-007 | Saklanan HTML/SVG enjeksiyonu (displayname, profil resmi) | Tip seviyesinde şablon kaçışı; SVG yükleme yok/sanitize; CSP; DAST yalnız UI (ZAP) |
| Kanidm GHSA-x8cg-3c8h-gw55 | `login_hint`'in kimlik kanıtı sanılması; `sub` karşılaştırılmaması | Federation'da `sub` + `iss` eşleşmesi zorunlu; Tamarin/ProVerif modeli |
| Kanidm GHSA-j4gj-f54h-56j5 | RADIUS modülünün parolaları loglaması | Secret<T> (Debug yok); log redaksiyon testi |
| Kanidm GHSA-hh34-7jqq-3f73 (OAuch) | Authorization code tek kullanım değil; kısa PKCE verifier kabulü (RFC 9700) | OAuch + OIDF suite CI'da (§14.8) |
| Keycloak CVE-2026-4633 / GHSA-rhgq-f8x5-j2jc | Identity-first login + Organizations → farklı hata mesajı (enumeration) | Identity-first akışı varlık sızdırmaz biçimde kurulur veya kullanılmaz (SA-11; → §12 giriş UX) |
| RAUTHY-006 | Erişilebilir `unwrap` → DoS | Panic yasağı request path'te (MD-2) |
| RAUTHY-009 | Depoda özel anahtar | Secret scanning CI; anahtar kurulumda üretilir |
| RAUTHY-004 | `page_size=0` → sıfıra bölme | Checked arithmetic (MD-2), sınır vektörleri |
| RAUTHY-008 | Geliştirme portlarının `0.0.0.0`'da dinlemesi | Varsayılan loopback; yapılandırma lint'i |
| RAUTHY-001; `rsa` GHSA-9c48-w39g-hm26 (CVE-2026-21895); Marvin (CVE-2023-49092) | RSA implementasyon açıkları | `rsa` crate kullanılmaz; RS256 aws-lc-rs ile opt-in (MD-3; RR-17) |
| `jsonwebtoken` GHSA-h395-gr6q-cpjc (CVE-2026-25537) | JOSE doğrulama hatası (identity plane için en önemli tek bulgu) | JOSE 18 sınıf tablosu (§14.6) regresyonu; kendi doğrulayıcı + Wycheproof |
| `cmov` RUSTSEC-2026-0003 (CVE-2026-23519) | Constant-time primitif hatası | U45, asm snapshot; HL-16 |
| `biscuit-auth` GHSA-75rw-34q6-72cr; GHSA-p9w4-585h-g3c7 | İmza sahteciliği; third-party block anahtar karışıklığı | Capability token tasarımında alg ve anahtar bağlamı imzalı içerikte (PI-21) — referans |
| `protobuf` RUSTSEC-2024-0437 (CVE-2025-53605); `quick-xml` RUSTSEC-2026-0195 | Kontrolsüz özyineleme / XML | Derinlik limiti; quick-xml ≥ 0.41 |

**AiTM / BitM laboratuvarı ve purple team.** Evilginx sınıfı AiTM kitleri ve BitM (CuddlePhish) ile periyodik lab: TOTP ve push faktörlerinin kırıldığı, passkey'in phishing'i durdurduğu ama oturum token'ı hırsızlığını durdurmadığı beklenir ve her turda yeniden doğrulanır. DBSC (Chrome 146'da Windows'ta GA — doğrulanmadı) ve DPoP oturum bağlamayı daraltır (HL-23, N-41).

| ID | Karar | Statü | Sınıf | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| SA-8 | Red team yöntemi teknik + semantik eksenlidir (§14.3); identity plane için AS-16 SAML/XML, AS-17 LDAP, AS-18 SCIM, AS-19 parola/login/recovery yüzeyleri eklenir ve ilk açık release'ten önce bir red team turundan geçer | FROZEN (yöntem), EA (takvim) | — | Identity plane red team görmedi | — |
| SA-9 | K-1–K-13, CL-1–CL-2 ve FM-1–FM-24 geçerlidir; düzeltme kararları §16'dadır | FROZEN | — | Tek kanonik yer | §16 |
| SA-10 | Rakip/bağımlılık advisory'lerinin her sınıfı bir regresyon testine dönüşür ve CI'da koşar | FROZEN | UDC | "Rakipte olan bizde regresyonla kapalı" | — |
| SA-11 | Login akışı hesap varlığını hiçbir kanalda (mesaj, status, redirect, zaman) farklılaştırmaz; identity-first akış yalnız bu koşulla kullanılır | FROZEN | UDC (U44) | Keycloak CVE-2026-4633 | → §12 |
| SA-12 | AiTM/BitM purple-team lab'ı periyodiktir; pazarlama dili "passkey token hırsızlığını önler" demez | PD | NG (N-41) | Gerçek tehdit modeli | — |
| SA-13 | HL-15 (async/HTTP formel kapsam dışı; → HL-29) ve HL-16 (derleyici ct garantisi yok) HL listesindedir | FROZEN | NG | Dürüst sınır | §13.5 |

### 14.4 Açık yönetimi ve dış güvence

**Normatif kurallar.**

1. **security.txt ve SECURITY.md.** `/.well-known/security.txt` RFC 9116'ya uygun yayınlanır: `Contact` ve `Expires` zorunlu, `Encryption` (PGP), `Policy`, `Preferred-Languages` önerilir; depo kökünde SECURITY.md GitHub Security Advisories (GHSA) private reporting'e yönlendirir.
2. **Koordineli açıklama.** GHSA üzerinden CVD; varsayılan embargo 90 gündür. 90 gün genel sektör normudur, IdP'ye özgü bir standart değildir (**doğrulanmadı**). Aktif sömürüde süre kısalır. RustSec embargo desteklemez; yayın düzeltme sonrasıdır.
3. **CVE ataması.** İlk aşamada GitHub CNA; hacim gerektirdiğinde kendi CNA (≥ 4 hafta süreç, iki iletişim kişisi, kapsam beyanı). Rust bileşenleri için RustSec advisory'si; TS istemci paketleri için npm/GitHub advisory. Go vuln DB yalnız MD-1 Go süreç profili etkinleşirse kanala eklenir.
4. **PSIRT ve CRA Art.14 (MD-12).** PSIRT runbook'u şimdi kurulur: triage, şiddet (CVSS v4), düzeltme, advisory, kullanıcı bildirimi, aktif sömürülen açık ve ciddi olay için ENISA/CSIRT bildirim akışı. CRA Art.14 bildirim süreleri (24 saat erken uyarı / 72 saat bildirim) **doğrulanmadı**; runbook bu değerleri parametre olarak tutar.
5. **Dış güvence (MD-16).** Custodial hizmet (D6) için SOC 2 Type II; ek olarak identity plane, Kernel, verifier'lar ve kripto katmanının periyodik **crystal-box** (kaynak kodlu) güvenlik denetimi. İlk crystal-box denetimi ilk açık release'ten önce tamamlanır. Denetim raporları (bulgu + düzeltme durumu) yayınlanır (Rauthy ROS raporu örnek alınır). Denetim maliyeti aralıkları **doğrulanmadı**.
6. **Fonlar.** NGI Zero Commons (2026-06Z çağrısı; toplam 6.1 M€, hibe basamakları ≤ 50k / 150k / 500k €), OSTIF, Alpha-Omega, Sovereign Tech Fund, GitHub Secure Open Source Fund aday kaynaklardır. Ticari bir şirket olarak Suiss'in uygunluğu **doğrulanmadı**; başvuru öncesi teyit gerekir.
7. **Replay agent.** Provider kararı yeniden değerlendirmesi CT3 %100, CT2 %1 örneklemle bağımsız tarafça yapılır (§13.7.7; U13); uyuşmazlık divergence quarantine'e gider (§13.6).
8. **Bug bounty.** İlk açık sürümle birlikte başlar (SA-57). Kapsam, ödül tablosu ve platform seçimi uygulama kararıdır; bounty CVD sürecinin yerine geçmez.

| ID | Karar | Statü | Sınıf | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| SA-14 | security.txt (RFC 9116) + SECURITY.md + GHSA private reporting; 90 gün varsayılan embargo (genel norm) | PD | — | Standart CVD | — |
| SA-15 | CVE: önce GitHub CNA, sonra kendi CNA; RustSec + npm advisory kanalları; `govulncheck` / Go vuln DB yalnız MD-1 Go süreç profili etkinleşirse eklenir | PD | — | MD-1 dil kararıyla uyum | — |
| SA-16 | PSIRT runbook ve CRA Art.14 bildirim akışı şimdi kurulur (MD-12: Adem kararı bekleniyor; varsayılan bu) | FROZEN (runbook), PD (süre parametreleri) | — | 11 Eylül 2026 üretici raporlama yükümlülüğü | MD-12 |
| SA-17 | SOC 2 Type II (custodial hizmet) + periyodik crystal-box denetimi (identity plane, Kernel, verifier'lar, kripto); ilki ilk açık release'ten önce; raporlar yayınlanır | FROZEN | — | İkisi farklı soruları cevaplar | MD-16 |
| SA-18 | Açık kaynak güvenlik fonlarına başvuru; uygunluk teyidiyle | HYPOTHESIS | — | Ticari uygunluk doğrulanmadı | — |
| SA-19 | Bağımsız replay agent: CT3 %100, CT2 %1 | PD | UDC (U13) | DL-4 tespiti | §13.7.7 |

### 14.5 Binary ve runtime sertleştirme; dil profilleri

**Dilden bağımsız kurallar (MD-2) — her profilde bağlayıcı.**

| # | Kural | Uygulanış | Sınıf / satır |
|---|---|---|---|
| R-1 | Checked arithmetic; taşma = DENY | Rust: release'te `overflow-checks = true` + `checked_*`/`saturating_*` yalnız gerekçeli; clippy `arithmetic_side_effects`; TS: `bigint` veya doğrulanmış tamsayı aralığı; C FFI: sınır kontrolü sarmalayıcıda | G56 |
| R-2 | Allowlist dışında `unsafe` / FFI yok | Workspace `#![forbid(unsafe_code)]`; izinli crate'ler (HSM/PKCS#11, sandbox, aws-lc bağlaması) listelenir; toplam izinli `unsafe` < 500 satır; `cargo geiger --forbid-only` gate; Miri izinli crate'lerde | — |
| R-3 | Request path'te panic yok | clippy `unwrap_used`, `expect_used`, `indexing_slicing`, `panic` deny; ağ süreçlerinde `panic = "unwind"` ve görev sınırında yakalama → 500/DENY, süreç ayakta; `abort` ağ süreçlerinde yasak, `no_std` kernel ile izole signer/parser worker'larda serbest (çökme izolasyon sınırında kalır) | G48 |
| R-4 | Özyinelemeden önce derinlik kontrolü | Derinlik ≤ 32 sayaç parametresi özyinelemeden **önce**; SCIM/LDAP için iteratif parser tercih; `stacker` güvence değil | U48; SAI-2 |
| R-5 | Açık HTTP limitleri | hyper/axum varsayılanına güvenilmez; §14.6 değerleri yapılandırmada açık yazılır ve testle doğrulanır | U48 |
| R-6 | DST'ye uygun saf sequencer durum makinesi | I/O, saat ve rastgelelik enjekte edilir; DST (madsim/turmoil/Shuttle) aynı çekirdeği koşar | §14.8 |
| R-7 | Domain/tenant scope'suz sorgu derlenmez | Tipli sorgu katmanı (scope parametresiz sorgu tipi yok) + RLS FORCE (MD-5) | U59 |

> **Panic ve Go profili.** Ağ süreçlerinde `panic = "abort"` kullanılmaz; reproducible build tarifinde de bu kural geçerlidir (MD-2). Abort yalnız `no_std` kernel ve izole worker'larda kalır. Go'ya özgü sertleştirme kuralları **MD-1 reconsider tetiklenirse yazılacak Go süreç profili** olarak tutulur (AS çekirdeği için Go/Fosite süreç hibriti). Profil o durumda yazılır ve etkinleşir; MD-2 kuralları R-1…R-7 o süreçte de bağlayıcıdır ve `govulncheck` / Go vuln DB SA-15 kanallarına eklenir.

**Rust ana profili (identity plane, Access Core, gateway'ler).**

| Alan | Kural | Kaynak |
|---|---|---|
| Binary mitigasyonları | PIE, full RELRO, NX, BIND_NOW; CI'da `checksec` assert | — |
| Stack protector / CFI | Rust stable'da stack protector ve CFI nightly'dir (PR #146369 bloklu); **kullanılmaz**. ASan/LSan/TSan haftalık job; MSan atlanır; CET/BTI notu ölçülecek (doğrulanmadı) | — |
| Çalışma zamanı kilitleme sırası | `PR_SET_DUMPABLE=0` → soket bind → `no_new_privs` → bounding/capability temizliği → setgroups/setgid/setuid → Landlock → seccomp; Landlock ve seccomp **runtime başlamadan ana thread'de**, TSYNC ile; Landlock `HardRequirement`, minimum ABI `/healthz`'de loglanır; seccomp iki fazlı (başlangıç → daraltılmış); `io_uring` yasak (seccomp'u bypass eder) | — |
| Süreç ayrımı | Signer süreci: UDS + SCM_CREDENTIALS, ağ syscall'ı yok, salt-okur anahtar deposu, `memfd_secret`; parser worker: ayrı süreç, ağ yok; plane ayrımı T31 (MD-6, MD-18). IPC maliyeti 10–50 µs (ölçülmedi — EA) | U42; U43 |
| Konteyner | Kubernetes PSS `restricted`, `readOnlyRootFilesystem`, `drop: [ALL]`, `runAsUser: 65532`, bellek limiti (ör. 2Gi), `automountServiceAccountToken: false`; distroless glibc `cc:nonroot`; musl yalnız mimalloc ile (musl allocator 7×–700× yavaş); gVisor varsayılan değil, Kata opsiyonel | — |
| İmaj doğrulama | cosign `--certificate-identity-regexp` + `--certificate-oidc-issuer`; admission'da policy-controller veya Kyverno | U49 |
| Barındırma ve yan kanal | Dedicated seçeneğinde `mitigations=auto,nosmt`; paylaşımlıda co-tenant yan kanalı HL-17 (MD-17) | U54; N-32 |
| Sır tipleri | `Secret<T>`: Debug/Display yok, constant-time eşitlik, drop'ta zeroize; token'lar DB'de SHA-256 özetiyle; `==` ile sır karşılaştırma lint'le yasak; `*_vartime` API'leri yalnız açık veri için | U45; N-34 |

**`no_std` kernel ve izole worker'lar.** Kernel crate `no_std`'dir, I/O içermez, Kani hedeflerini taşır (MD-15); panic stratejisi abort'tur ve çağıran süreç kernel çağrısını izole eder. Signer ve parser worker'ları ayrı binary'lerdir; seccomp profilleri ana süreçten daha dardır.

**TS profili (istemciler, konsol, SDK).** npm lockfile zorunlu ve CI'da `npm ci`; bağımlılık eklemede ≥ 7 gün cooldown; `npm audit` + advisory izleme; yayın npm Trusted Publishing + provenance ile; `postinstall` script'leri allowlist dışında kapalı; Shai-Hulud sınıfı solucan riski RR-21. Tarayıcı tarafı: CSP, Trusted Types, tip seviyesinde şablon kaçışı (GHSA-gpxg sınıfı).

**C FFI profili.** Kerberos (MIT krb5 vb.) ayrı gateway sürecinde, ana süreçten ve signer'dan izole (MD-1); PKCS#11 ve aws-lc'nin C kısımları bağlama crate'lerinde allowlist'li `unsafe` ile; ASan job'ı ve opsiyonel CFI (clang) C bileşenlerinin derlemesinde; fuzz hedefi Kerberos ASN.1 girişine (RR-28).

| ID | Karar | Statü | Sınıf | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| SA-20 | Dil profilleri: Rust ana (kernel `no_std`, signer/parser worker'lar dahil), TS (istemci/konsol), C FFI (Kerberos izole süreç, PKCS#11/aws-lc C kısımları); MD-2 kuralları R-1–R-7 her profilde; Go süreç profili: MD-1 reconsider tetiklenirse yazılacak profil (AS çekirdeği) | FROZEN | — | MD-1/MD-2 | MD-1; MD-2 |
| SA-21 | Panic: request path'te yok; ağ süreçlerinde unwind + yakalama, abort yalnız kernel ve izole worker'larda; ağ süreçlerinde `panic="abort"` kullanılmaz | FROZEN | UDC (conformant implementasyon); kural G48 (BS) | Panic tek isteği değil süreci düşürmemeli | MD-2 |
| SA-22 | Landlock + iki fazlı seccomp + caps drop + `no_new_privs` + `PR_SET_DUMPABLE=0`, runtime öncesi ana thread'de, `HardRequirement`; `io_uring` yasak | FROZEN | UDC (U42) | io_uring seccomp bypass | — |
| SA-23 | Stack protector/CFI nightly kullanılmaz; sanitizer'lar haftalık; checksec CI gate | FROZEN | — | Nightly bağımlılığı kabul edilmez | — |
| SA-24 | PSS restricted + distroless glibc nonroot; musl yalnız mimalloc ile; gVisor varsayılan değil | PD | — | Performans ve saldırı yüzeyi | — |
| SA-25 | Dedicated compute B4 opsiyonu; signer ayrımı ve HSM ücretsiz taban; co-tenant yan kanalı HL-17 | FROZEN (HL), HYPOTHESIS (fiyat) | NG / UDC | MD-17 | MD-17 |
| SA-26 | Secret<T> disiplini ve token'ların DB'de özetle saklanması | FROZEN | UDC | Kanidm/Rauthy bulguları | — |

### 14.6 Parser ve DoS

**Katman sırası.** Bağlantı limiti → IP rate limit → body boyut limiti → timeout (10 s) → load shedding → eşzamanlılık limiti (~2× çekirdek) → trace → **kimlik doğrulama** → pahalı extractor/handler (Argon2 semaphore dahil). Kimlik doğrulama, pahalı parse/doğrulama işinden önce gelir (GHSA-84jc sınıfı).

**Limit tablosu (SI-20 ile birlikte).** Aşım protocol rejection'dır (SEC28); limit hatası hiçbir zaman ALLOW değildir (G48).

| Yüzey | Limit | Kaynak |
|---|---|---|
| ADP/Access istekleri | §13.7.4 (lineage ≤ 16, proof ≤ 64, selector ≤ 32 conjunct, istek ≤ 256 KB) | SI-20 |
| JSON | Boyut parse'tan önce; derinlik ≤ 32; serde_json `unbounded_depth` kapalı ve CI assert (varsayılan 128 yeterli değil) | — |
| CBOR (L2 profili; COSE, WebAuthn) | İç içelik, eleman sayısı, string uzunluğu sınırlı; duplicate key red; indefinite-length red; tag allowlist; canonical yeniden kodlama karşılaştırması; WebAuthn CBOR ~8 KB | — |
| JOSE | 18 saldırı sınıfı tablosu (alg confusion, `none`, `jwk`/`jku`/`x5u` header enjeksiyonu, `kid` enjeksiyonu, `crit` ihmali, b64=false, vb. — örnekler çıkarımdır) regresyonla kapalı; alg allowlist metadata'dan; `alg: EdDSA` JWS'te red (MD-3) | G55 |
| XML / SAML | quick-xml ≥ 0.41; DocType red; yalnız 5 önceden tanımlı entity; `max_declarations ≤ 32`; 8 XSW + 3 yeni sınıf regresyon; imza doğrulama yalnız c14n sonrası referansı çözülmüş elemana; izole parser worker; `saml-rs` typosquat kümesi yasak (MD-18) | — |
| x509 / DER | ≤ 8 KB; derinlik sınırlı | — |
| LDAP BER / SCIM filter | BER uzunluk ve derinlik limiti; filter derinliği ≤ 32 özyinelemeden önce; iteratif parser | Kanidm advisory'leri |
| Kanaldan gelen sayı | `Vec::with_capacity(n)` kanaldaki `n` ile yapılmaz; kapasite yalnız metrik olarak | — |
| HTTP/1.1 | Header okuma timeout 5–10 s (slowloris); header boyutu açık | — |
| HTTP/2 | `max_concurrent_streams` 100; `max_header_list_size` 8 KB; `max_frame_size` 16 KB; pencere 64 KB / 1 MB; send buffer 256 KB; `max_pending_accept_reset_streams` 20; `max_local_error_reset_streams` 256; keepalive 20 s / 10 s (Rapid Reset, CONTINUATION flood) | — |
| TLS | Handshake semaphore; 0-RTT kapalı | — |
| Regex (ReDoS) | Yalnız lineer zamanlı motor (`regex` crate); backtracking motorları yasak; desen ≤ 256; `size_limit` ayarlı | — |

**Parser kontrol listesi (12 madde) — özet.** Derinlik özyinelemeden önce; aşımda `Err` (panic değil); boyut parse'tan önce; kimlik doğrulama pahalı extractor'dan önce; kanaldan gelen sayıyla ön-tahsis yok; sınırlı streaming decoder; duplicate key red; bilinmeyen kritik alan red; canonical yeniden kodlama; her parser'a fuzz hedefi; advisory izleme; regresyon korpusu.

**Rate limiting.** Yerel (governor) + global (Redis sınıfı) iki katman; anahtarlar IP, kullanıcı, IP+kullanıcı; `X-Forwarded-For` sağdan güvenilir proxy sayısı kadar okunur. Global store düşerse **yerel strict limiter** devreye girer; fail-open seçeneği yoktur (MD-8).

**Argon2.** Semaphore N = floor(bellek·0.5 / m); acquire timeout 500 ms → 503; `spawn_blocking`. Yük örneği PD (m = 7 MiB, t = 5; CR-36) ile 10 çekirdekte ≈ 539 hash/sn ve ≈ 17,9 eşzamanlı × 7 MiB ≈ 125 MiB'dır (M4 ölçümü, EA). RFC 9106 parametresiyle (64 MiB) hesaplanan örnek — 500 login/s × 300 ms = 150 eşzamanlı × 64 MiB ≈ 9.6 GiB — PD için geçerli değildir. Kapasite planlaması §17'dedir.

**Enumeration (MD-18).** Dummy Argon2 hash **yapılmaz** (yanlış sabit maliyet, kaynak israfı); yerine adaptive delay + varlıktan bağımsız semaphore. Login, kayıt, parola sıfırlama ve recovery yanıtları status/body/header/redirect'te özdeş; "e-posta zaten kayıtlı" bilgisi yalnız e-posta kanalıyla iletilir; regresyon suite'i p50–p95 karşılaştırır (U44). Kademeli kilitleme Rauthy örneği (7 → 60 s, 10 → 600 s, 15 → 900 s, 20 → 3,600 s, 25 → 24 saat) bir PD adayıdır; NIST 800-63B-4 tavanı (≤ 100 ardışık başarısız) bağlayıcıdır (§13.7.9).

**Policy oracle.** DL-7 ve SEC24/SEC31 geçerlidir; identity plane'de karşılığı enumeration'dır. **Burst.** K-10 düzeltmesi (O(1) işaret + tembel episode) ve G44 (kota üstü Claim episode açmaz) geçerlidir.

| ID | Karar | Statü | Sınıf | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| SA-27 | Katman sırası: bağlantı → IP rate → body → timeout → shed → eşzamanlılık → trace → auth → pahalı handler | FROZEN | UDC | Kimlik doğrulamasız pahalı iş DoS'tur | — |
| SA-28 | Limit tablosu (§14.6) yapılandırmada açık ve testle doğrulanır; derinlik ≤ 32 özyinelemeden önce | PD (değerler), FROZEN (kural) | UDC (U48) | Kanidm 2026 advisory'leri | MD-2 |
| SA-29 | CBOR L2 profili ve JOSE 18 sınıf regresyonu; XML'de DocType red, izole worker | FROZEN | UDC | Parser differential en büyük identity saldırı yüzeyi | MD-18 |
| SA-30 | Rate limiter fail-open yok; global store düşerse yerel strict limiter | FROZEN | UDC (U46); kural G48 (BS) | MD-8 | — |
| SA-31 | Enumeration: dummy Argon2 yok; adaptive delay + varlıktan bağımsız semaphore; özdeş yanıt | FROZEN | UDC (U44) / NG (N-46) | Dummy hash yanlış sabit maliyet ve kaynak israfıdır | MD-18 |
| SA-32 | ReDoS: yalnız lineer regex motoru; desen ≤ 256 | FROZEN | UDC | Kontrolsüz kullanıcı deseni | — |
| SA-33 | HTTP/2 ve TLS parametreleri açık; 0-RTT kapalı | PD | UDC | Rapid Reset/CONTINUATION | — |

### 14.7 Tedarik zinciri

**Durum.** Tipik Rust IdP yığını ~243 crate, ~1.75 M satır, 26 `build.rs` taşır; `default-features = false` ile ~170 crate'e iner (−%30). cargo-vet'in gerçek kapsamı 1,815 crate / 5,576 denetimdir (yığının %51'i / ağırlıklı %91'i) — 14,140 gibi daha yüksek dolaşımdaki sayılar ölçümle uyuşmaz (RR-34). crates.io yayıncı imzası yoktur (TOFU; HL-24). 2026 olayları: `arrayref` (20 Ağustos 2026; lockfile kullananların ~%90'ı korunmuş), PolinRider RUSTSEC-2026-0280 (`.vscode/tasks.json` üzerinden), kötü niyetli crate sayıları 28/0/14/32.

**Normatif kurallar.**

| # | Kural | Ayrıntı | Kaynak |
|---|---|---|---|
| F-1 | Politika kapısı | `cargo-deny`: bans (openssl ve yinelenen ağır crate'ler), licenses (GPL'siz allowlist), sources `allow-git = []`; `cargo-audit` ayrı günlük job; `cargo vet` zorunlu; TS: lockfile + audit | — |
| F-2 | Kilitli ve gecikmeli tüketim | `--locked`; yeni sürüm/bağımlılık için ≥ 7 gün cooldown; vendor ile offline build; yeni `build.rs` alarmı (allowlist diff); vendored `.vscode/`, `.devcontainer/`, `.githooks/` taraması; GitHub Actions SHA pin; yayın token'ı keychain/OIDC'de | — |
| F-3 | Minimizasyon | `default-features = false`; yinelenen crate temizliği; `no_std` çekirdek; `argon2`, `sqlx` ve ASN.1 crate'leri manuel denetim | — |
| F-4 | Reproducible build | Toolchain pin (1.98.1 örnek), path remap, digest-pinli base imaj, vendor offline, çift build gate, OCI; gerekçe A3/B12 (bağımsız doğrulanabilirlik) | U50 |
| F-5 | SBOM ve VEX | CycloneDX birincil, SPDX ikincil; `cargo-auditable` ile binary içi bağımlılık listesi; VEX ile "etkilenmiyor" beyanı | — |
| F-6 | Provenance | SLSA v1.2 Build L3 **hedefi**: GitHub hosted runner + `actions/attest-build-provenance` (slsa-github-generator bakımsız); L3 seviyesi **doğrulanmadı** ve pazarlamada kullanılmaz; Source L4 hedefi: iki kişilik inceleme | U49 |
| F-7 | İmza ve şeffaflık | Sigstore (cosign keyless); release checkpoint'i Access witness'ları tarafından co-sign edilir (release'in kendisi bir log girdisidir) | §13.3 |
| F-8 | Attestation kümesi | Provenance, SBOM, VEX, test sonucu, imaj imzası (5'li küme) | — |
| F-9 | FM-16 (SolarWinds) | Önleme NG (HL-24); tespit UDC: reproducible build + bağımsız replay agent + differential; ele geçirilmiş sürüm divergence ile ortaya çıkar (K-1 yolu) | FM-16 |
| F-10 | Registry güveni | crates.io imzasız (TOFU); npm Trusted Publishing + provenance; kötü niyetli paket riski RR-21 | — |
| F-11 | Evaluator arşivi | Open reference evaluator'ın her sürümü ve vektörleri imzalı ve arşivlidir; replay eski sürümle yapılabilir | A3 |
| F-12 | Güvenlik verisi hijyeni | Tedarik zinciri kararlarında kullanılan sayılar ölçümle veya kaynakla; SEO/LLM kaynaklı sayılar reddedilir | RR-34 |

**Depo ve geliştirme güvenliği (SA-60).**

| # | Kural | Ayrıntı |
|---|---|---|
| F-13 | Sır sızıntısı önleme | `gitleaks` commit öncesi kancası ve CI taraması; GitHub push protection açık; yerel geliştirmede gerçek sır yoktur, `.env` dosyaları git'e giremez. Sızan sır önce iptal edilir veya değiştirilir, sonra geçmiş temizlenir; geçmiş temizliği tek başına yeterli değildir |
| F-14 | Statik analiz | CodeQL (Rust, TypeScript) ve Semgrep; spec'e özgü kurallar Semgrep ile yazılır (ör. `store` dışında SQL yok, `Secret` tipi biçimlendirilemez); yüksek önemli bulgu birleştirmeyi durdurur |
| F-15 | Bağımlılık güncellemesi | Renovate; F-2'deki 7 günlük bekleme uygulanır; bilinen bir güvenlik açığını kapatan güncelleme beklemez; her güncelleme testlerden ve `cargo-vet`'ten geçer |
| F-16 | Depo koruması | `main`'e doğrudan push yok; her değişiklik PR ve geçen CI ile girer; imzalı commit zorunlu; `main`'de force-push ve geçmiş yeniden yazımı yasak |
| F-17 | İnceleme | Claude'un yazdığı her değişikliği Adem inceler ve birleştirir. Yapay zekâ incelemesi SLSA Source L4'ün ikinci insan incelemesi sayılmaz; ekibe ikinci bir insan katılana kadar Source L4 iddia edilmez (SA-38) |
| F-18 | Hassas değişiklikler | Kripto, Kernel, imza, kimlik doğrulama akışları, RLS politikaları ve SQL'e dokunan PR'larda kısa tehdit değerlendirmesi zorunludur; bu yollar `CODEOWNERS`'ta hassas olarak işaretlenir |

**xz dersi.** Tek maintainer'a bağımlı kritik bileşenler RR-19 olarak izlenir; build-time kod (build.rs, proc-macro) çalışma zamanı kodundan daha sıkı incelenir.

| ID | Karar | Statü | Sınıf | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| SA-34 | cargo-deny/audit/vet + `--locked` + ≥ 7 gün cooldown + vendor offline + build.rs/IDE dosyası taraması + Actions SHA pin | FROZEN | UDC | 2026 tedarik zinciri olayları | — |
| SA-35 | `default-features = false` ve kritik crate'lerin manuel denetimi | PD | — | Yüzey −%30 | — |
| SA-36 | Reproducible build zorunlu; release gate | FROZEN | UDC (U50) | Replay ve bağımsız doğrulanabilirlik | A3/B12 |
| SA-37 | CycloneDX + SPDX + cargo-auditable + VEX; SBOM/VEX/provenance ücretsiz | FROZEN | — | CRA hazırlığı; B3 | — |
| SA-38 | SLSA Build L3 hedefi attest-build-provenance ile; seviye pazarlamada kullanılmaz; Source L4 iki kişilik inceleme | EA | UDC (U49) | L3 doğrulanmadı | — |
| SA-39 | Release checkpoint Access witness'larıyla co-sign | FROZEN | UDC | Kendi şeffaflık mekanizmasını kendi release'ine uygular | — |
| SA-40 | FM-16: tespit + önleme birlikte (önleme: imza, provenance, cooldown; tespit: reproducible + replay) | FROZEN | NG (önleme) / UDC (tespit) | — | F-9 |
| SA-60 | Depo ve geliştirme güvenliği: sır taraması ve push protection, sızan sırda önce iptal; CodeQL + Semgrep (spec'e özgü kurallar); Renovate 7 gün bekleme ve güvenlik istisnası; korunan `main`, imzalı commit; Adem'in incelemesi zorunlu, Source L4 ikinci insan katılana kadar iddia edilmez; hassas yollarda tehdit değerlendirmesi (F-13…F-18) | FROZEN | UDC | Açık kaynak depoda sızıntı anında herkese açıktır; iki kişilik ekipte inceleme kuralı dürüstçe tanımlanır | F-2; SA-38 |

### 14.8 Test ve doğrulama stratejisi

**Hakem kuralı.** Spec hakemdir: test hedefleri Access modeline bağlanır. "Epoch propagation" test hedefi "ValidityContract Δ/horizon penceresi + status-list tazeliği" invariant'ıdır (§13.11). Keycloak bir oracle değildir; differential uyuşmazlıkta karar spec'tedir.

**İki katmanlı güvence (MD-15).** (a) Frozen semantiği yalnız model karşı-örneği yeniden açabilir; (b) normatif vektörler, DRT ve proof'lar geçmeden release yoktur (U56). Kani hedefleri `no_std` kernel'dedir.

**Katmanlar.** Katman etiketleri SA-T1…SA-T18'dir.

| Katman | İçerik | Bütçe / sıklık | Kaynak |
|---|---|---|---|
| Normatif vektörler (SA-T1) | L0/L2 semantik vektörleri; her §13.4 satırı için en az bir vektör/test (SAI-1); çapraz-implementasyon determinizmi vektör kapsamı kadar (HL-12) | Her PR | TI-RT12 |
| Dış suite'ler (SA-T2) | OIDF OIDC / FAPI 2.0 / CIBA / Federation; OAuch; MCP conformance; SCIM; SAML; FIDO; beklenen-hata baseline'ı versiyonlu (sertifikasyon ücreti üye $700 / diğer $3,500) | Nightly; release öncesi tam | — |
| Interop matrisi (SA-T3) | 630 kombinasyondan riske göre 200'e indirilmiş matris | Haftalık | — |
| DRT (SA-T4) | Differential random testing: Rust kernel ↔ Lean (veya bağımsız) model; gecede 6 saat, ~100 M vaka/gün; Lean tarafı ~5 µs/vaka (EA); Cedar örneği: 25 bug'ın 4'ü proof, 21'i DRT ile | Nightly | — |
| Model checking (SA-T5) | TLA+ (sequencer, recovery, handover), stateright (Rust içi), Tamarin/ProVerif (OIDC/OAuth/SAML/DPoP protokol modelleri; GHSA-x8cg sınıfı) | Değişiklikte | — |
| Kani (SA-T6) | Kernel hedefleri (MD-15); aday liste — çıkarım, bağlayıcı liste §15/§16: checked arithmetic, budget toplamı, Σrelease ≤ draw, lineage derinliği, parser derinlik sayacı; constant-time erken dönüş yokluğu | PR'da hedefli | MD-15 |
| PBT (SA-T7) | proptest + proptest-state-machine; 23 IdP invariant'ı Access modeline bağlanarak | Her PR | — |
| Metamorfik (SA-T8) | MR1–MR8 (aşağıda) | Her PR (küçük), nightly (büyük) | — |
| Fuzz (SA-T9) | Identity plane'in 10–12 hedefi (öncelik: XML c14n → JOSE → LDAP BER → SCIM filter → CBOR) + authority plane hedefleri: CBOR Authority Record/AIS/AAS/PAP, COSE, SD-JWT, CEL/Cedar restriction dili, inclusion proof bundle; PR'da 10 dk, nightly 6 saat; fuzz'ın bulgu sınıflarının ~%40'ını yakalaması iddiası küçük örneklem (doğrulanmadı) | PR + nightly | — |
| Differential (SA-T10) | ory/hydra, node-oidc-provider ile protokol çıktısı; Rust kernel ↔ TS/Wasm doğrulayıcı | Nightly | — |
| Wycheproof (SA-T11) | C2SP Wycheproof vektörleri (wycheproof-rs 0.6.0) bütün imza/AEAD/ECDH yollarında | Her PR | → §15 |
| Bilinen saldırı regresyonu (SA-T12) | §14.3 advisory tablosu + enumeration suite (status/body/header/redirect/p50–p95) + XSW korpusu | Her PR | — |
| Constant-time (SA-T13) | dudect (\|t\| > 5 → fail), ctgrind, asm snapshot (fark → inceleme), aarch64 DIT notu | Nightly | → §15 |
| DST (SA-T14) | madsim / turmoil / Shuttle; saf sequencer (R-6) | Nightly | — |
| Jepsen/Elle (SA-T15) | PostgreSQL yalıtım ve failover; Elle anomali kontrolü | Release öncesi | — |
| Split-brain (SA-T16) | Senaryo: ~99 s çift primary, 1,472 ack'li yazmadan 619'u sağlam kaldı (ölçüm); kural: grace 0 + failover 30 s; security event'leri `synchronous_commit=on` (U51) | Release öncesi | — |
| Yük (SA-T17) | k6 constant-arrival-rate veya wrk2; ayrı makine; dropped iteration = fail (coordinated omission); Keycloak 26.4 sayıları (500/1,000/2,000 login/s; login ≈ 8× refresh; 1 vCPU ≈ 15 login/s veya ≈ 120 refresh/s) yalnız kıyas, hedef değil (EA) | Haftalık | — |
| Altyapı (SA-T18) | testcontainers, insta snapshot, Zipf dağılımlı veri; ZAP yalnız UI | — | — |
| Hata enjeksiyonu | DB kaybı → introspection `active=false` (503 değil); tek kural: primary'ye veya tazelik kaynağına ulaşılamıyorsa her token için, cache-hit dahil, `active=false`, 503 dönmez; refresh 503 + Retry-After; HSM down → DENY/503; signer süreci çökmesi → imza yok, ALLOW yok | Nightly | U37; G50 |

**Metamorfik ilişkiler.**

| MR | Dönüşüm | Beklenen ilişki |
|---|---|---|
| MR1 | Aynı istek başka kullanıcının token'ıyla | Yetkisizse 403/404, asla 200 |
| MR2 | Token scope'u daraltılır | İzin kümesi alt küme olur |
| MR3 | Kullanıcıya ilgisiz rol eklenir | İlgili kaynaktaki karar değişmez |
| MR4 | Politika/rol atama sırası permüte edilir | Karar aynı (GHSA-xxwr sınıfı) |
| MR5 | JWT başlığında boşluk/alan sırası değişir | İkisi de kabul veya ikisi de ret; asla ayrışma |
| MR6 | `redirect_uri` kayıtlıdan farklı ama "anlamsal eşdeğer" biçimde gönderilir | Exact string matching (RFC 9700) gereği **ret**; "aynı karar" ilişkisi yalnız kayıtlı değerle birebir eşleşen iki temsil için geçerlidir |
| MR7a | Domain A'da rastgele mutasyon (Grant, Restriction, revoke) | Domain B'nin karar vektörü bit bit aynı (authority plane izolasyonu, INV-17) |
| MR7b | Realm/tenant A'da rastgele mutasyon (kullanıcı, faktör, client, anahtar) | Realm/tenant B'nin authentication ve token kararları bit bit aynı (identity plane izolasyonu, MD-5) |
| MR8 | Zaman `exp`'in 1 s ötesine | Geçerliden geçersize; asla tersi |

**CI bütçesi.** PR hızlı yol < 2 dk; PR tam < 15 dk; merge sonrası ~45 dk; nightly (fuzz 6 saat, DRT 6 saat, DST, differential); haftalık (sanitizer'lar, interop, yük).

| ID | Karar | Statü | Sınıf | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| SA-41 | Spec hakemdir; test hedefleri Access modeline bağlanır; epoch testleri ValidityContract Δ/horizon invariant'ını sınar | FROZEN | — | — | MD-7 |
| SA-42 | İki katmanlı güvence: frozen semantiği yalnız model karşı-örneği açar; release gate vektör + DRT + proof | FROZEN | UDC (U56) | MD-15 | — |
| SA-43 | Dış suite'ler (OIDF, OAuch, MCP, SCIM, SAML, FIDO) beklenen-hata baseline'ıyla CI'da | FROZEN | UDC | GHSA-hh34 OAuch ile bulundu | — |
| SA-44 | Fuzz hedefleri identity + authority plane ortak listesi; öncelik XML c14n | FROZEN | UDC | MD-18 | — |
| SA-45 | MR7 iki ilişkidir (domain ve realm/tenant); MR6 RFC 9700 exact matching'e göre tanımlıdır | FROZEN (MR7), PD (MR6 — çıkarım, teyit gerekir) | UDC | İki izolasyon ekseni (MD-5) | — |
| SA-46 | Yük testi coordinated-omission'sız; Keycloak sayıları yalnız kıyas | EA | — | Ölçüm doğruluğu | — |
| SA-47 | Split-brain kuralı: grace 0 + failover 30 s; security event'leri senkron commit | PD | UDC (U51) | Split-brain ölçümü (SA-T16) | — |

#### 14.8.1 SA-59 Test katmanlarının aşamaları ve test disiplini

**Statü: FROZEN (aşama sırası, kural kapsaması, flaky kuralı); PD (süre bütçesi, araçlar).** SA-T1…SA-T18 katmanları aynen geçerlidir; bu bölüm hangisinin ne zaman zorunlu olduğunu belirler.

**Aşamalar.**

| Aşama | Zorunlu katmanlar |
|---|---|
| 0 — ilk satır koddan itibaren | Birim testleri; gerçek Postgres ile entegrasyon testleri; normatif vektörler (SA-T1); property-based testler (SA-T7); bilinen saldırı regresyonu (SA-T12); Wycheproof (SA-T11); şema güvenlik testleri (OP-66) |
| 1 — ilk açık sürümden önce | Dış conformance süitleri, önce OIDF (SA-T2); fuzz, en riskli ayrıştırıcılar önce (SA-T9); karşılaştırmalı testler (SA-T10, T42); metamorfik testler (SA-T8); sabit zaman testleri (SA-T13); yük testi (SA-T17); bağımsız denetim (SA-17) |
| 2 — ilk sürümden sonra | Deterministik simülasyon (SA-T14); uyumluluk matrisi (SA-T3); Kani (SA-T6); Jepsen/Elle ve split-brain (SA-T15, SA-T16) |
| 3 — uzmanlık gerektirenler | Lean karşılaştırması (SA-T4); TLA+, Tamarin, ProVerif modelleri (SA-T5) |

Bir katmanın aşaması geldiğinde o katman birleştirme veya sürüm kapısı olur; önceki aşamalar gevşetilmez.

**Testlerin yeri.** Birim testleri kodun yanında (`#[cfg(test)]`); crate entegrasyon testleri crate'in `tests/` klasöründe; uçtan uca testler ayrı `e2e` crate'inde; conformance, karşılaştırmalı test ve uyumluluk laboratuvarı `conformance/`, fuzz hedefleri `fuzz/`, yük testleri `load/` altında (OP-62).

**Yeterlilik ölçüsü.**
- Satır kapsama yüzdesi hedef değildir.
- **Kural kapsaması:** her normatif kuralın (INV, SI, TI, PI, CI, EI) en az bir testi vardır (SAI-1); test kural ID'sini adında veya yorumunda taşır (ör. `inv_2_single_write_path`); CI testi olmayan kuralları raporlar.
- **Mutation testing:** Kernel ve karar çekirdeği (CMP-24, CMP-4) için `cargo-mutants`; yakalanmayan mutant birleştirme kapısıdır (Aşama 1'den itibaren).

**Disiplin.**
- Her PR'da çalışan testler ≤ 10 dakika (PD); uzun katmanlar gece çalışır.
- Kararsız (flaky) test 24 saat içinde karantinaya alınır ve issue açılır; otomatik yeniden deneme ile geçirme yapılmaz.
- Test adları davranışı anlatır (ör. `deny_when_grant_expired`).
- Snapshot testleri (`insta`) yalnız büyük çıktılar içindir (hata yanıtları, OpenAPI belgesi, explain çıktısı); snapshot değişikliği PR'da açıkça incelenir.

### 14.9 Uyum

**İlke.** Uyum, §13 guarantee satırlarının yeniden etiketlenmesidir; uyum için yeni bir güvenlik iddiası icat edilmez. Hukuki nitelendirmeler (sınıf, kapsam, süre) aksi belirtilmedikçe ikincil kaynaklara dayanır ve **hukuki teyit gerektirir**.

**CRA — Cyber Resilience Act (MD-12). Adem kararı bekleniyor; varsayılan bu (D-10).**

| Öğe | Varsayılan karar | Kaynak / durum |
|---|---|---|
| Üretici rolü | Suiss; self-host binary, SDK'lar ve mobil uygulama için üreticidir. Saf SaaS (Suiss-hosted) bileşenlerin CRA kapsamı ayrıca değerlendirilir | MD-12; kapsam ayrıntısı doğrulanmadı |
| Sınıf | Varsayılan **Class I** "important product" (kimlik yönetimi yazılımı) | Doğrulanmadı |
| 11 Eylül 2026 | Art.14: aktif sömürülen açık ve ciddi olay bildirimi üreticiler için başlar → PSIRT runbook (SA-16) şimdi | 24 / 72 saat süreleri doğrulanmadı |
| 11 Aralık 2027 | Tam uygulama: Annex I temel gereksinimler, SBOM, CVD politikası, beyanlı destek süresi, Annex VII teknik dosya, uygunluk değerlendirmesi, CE; açık kaynak steward yükümlülükleri (Art.24(3)) | — |
| Şimdi kurulanlar | Art.14 PSIRT runbook; CRA-C1 security.txt + SECURITY.md; CRA-C2 CVD/GHSA; CRA-C3 CNA/RustSec (§14.4) | MD-12 |
| SBOM / VEX / provenance | Ücretsiz ve her sürümde (B3) | SA-37 |
| Destek süresi | Her major sürüm için yayınlanmış güvenlik desteği süresi (değer Adem kararıyla) | Açık soru |

**GDPR / KVKK ve saklama.**

1. **Minimizasyon ve pseudonymity.** Pairwise `sub` ve domain-pairwise PartyRef varsayılandır (MD-10); authority-relevant kişisel parametreler mümkünse opaque ref'tir (SEC32); LINDDUN etiketleri §14.2'dedir.
2. **Silme hakkı (GDPR Art.17).** Identity plane hesap silme akışı kişisel alanları siler veya crypto-shred eder; Authority Record append-only'dir ve redaksiyon uygular (C34; redaksiyon ≠ erase, HL-9, N-11). Crypto-shredding hukuki anlamda silme sayılmaz (EDPB 01/2025 yorumu; N-42); bu nedenle crypto-shred yalnız "erişilemez kılma" olarak anlatılır (§13.8).
3. **Saklama.** Exercise/audit body saklama 400 gün PD'dir ve daraltılabilir; digest'ler süresizdir. Süresiz digest'in gerekçesi: kişisel veri içermeyen pseudonymous iskelettir ve hesap verebilirlik amacıyla sınırlıdır (GDPR Art.5 saklama sınırlaması ile dengeleme; hukuki teyit gerekir). PII alanları ≤ 6 ay sonra crypto-shred edilir, Merkle özeti ciphertext üzerindedir. Saklama süresi kiracı kararıdır (PCI 12 ay, CNIL 6–12 ay gibi; tedarikçilerde 30–90 gün + streaming export).
4. **KVKK.** Periyodik imha ≤ 6 ay aralıkla; pasif hesaplar 45/90 gün kademeli deaktivasyon — PD.
5. **Audit erişimi.** Audit örneklenmez; audit okuması sorgu başına loglanır; imzalı checkpoint; alan kümesi PII etiketli.

**Denetim log'u ve non-repudiation.** NIST 800-53 AU ailesi ve PCI DSS Req.10 için **operasyonel erişim log'u** (yönetici, destek, operatör eylemleri) append-only ve tamper-evident tutulur; bu log **canonical değildir ve karar girdisi değildir** (TI-18). Authority Record'un kendisi canonical kayıttır. AU-10 non-repudiation yalnız teknik anlamdadır (imza ile attribution); hukuki non-repudiation iddia edilmez (EI-24). PCI DSS 4.0.1 metni doğrulanmadı.

**Sektörel eşleme.**

| Rejim | İlgili gereksinim (özet) | Access karşılığı | Durum |
|---|---|---|---|
| PCI DSS (Req.8, Req.10) | Güçlü kimlik doğrulama, MFA; log ve gözden geçirme | §13.7.3 phishing-resistant; operasyonel erişim log'u | PCI 4.0.1 ayrıntısı doğrulanmadı |
| HIPAA | Erişim kontrolü, audit | Grant + audit; BAA ticari karar | Doğrulanmadı |
| FedRAMP / OMB M-22-09 | Phishing-resistant MFA, zero trust | §13.7.3; passkey | FIPS 140-3 profili düşük öncelik (MD-3 FIPS profili ES256/ESP256) |
| SOC 2 / ISO 27001 | Kontrol çerçevesi | SOC 2 Type II custodial hizmet (SA-17) | — |
| NIS2 | Müşteri (essential/important entity) tedarik zinciri güvenliği; olay bildirimi | Kanıt paketi: SBOM, denetim raporları, PSIRT, SLA | Suiss'in kendi NIS2 kapsamı **doğrulanmadı** |
| DORA | Finansal kuruluşların ICT üçüncü taraf riski | Kanıt paketi + çıkış (G32) | Doğrulanmadı |
| eIDAS 2.0 / EUDI Wallet | Wallet ve nitelikli hizmetler | Identity plane federasyon (§10); Access'te Claim | WATCH |
| PSD2 SCA | Dinamik bağlama: tutar + alıcı | AAS intent digest (WYSIWYS); CT2 yeni alıcı; CIBA | — |
| TR ödeme (MD-11) | Uygulama-kontrollü faktör (PIN + cihaz anahtar çifti); SMS sınırları; SIM değişikliği kontrolü | "Uygulama-kontrollü faktör" assurance sınıfı ve TR ödeme şablonu (MD-11) → §10 | RG 33360 ve SPK VII-128.10 atıfları doğrulanmadı |
| OWASP ASVS 5.0 / Top 10:2025 | ~350 gereksinim, 17 bölüm; Top 10'da tedarik zinciri ve istisnai durum yönetimi | Kontrol listesi olarak; hedef seviye L3 identity plane, L2 diğer (çıkarım) | — |
| WCAG 2.2 | 3.3.8 Accessible Authentication: paste/autofill engelleme fail | Login UI paste/autofill'i engellemez; passkey birincil (→ §12) | EAA (European Accessibility Act) kapsamı kaynakta yok → açık soru |
| Ajan regülasyonu | AI ajanlarına ilişkin düzenlemeler | Agent = Party/Instance; Mandate; audit | WATCH |
| Residency | Veri yerleşimi | Cell ekseni (MD-5) → §17 | — |

| ID | Karar | Statü | Sınıf | Gerekçe | Kaynak |
|---|---|---|---|---|---|
| SA-48 | CRA: Suiss üretici (self-host binary, SDK, mobil); varsayılan Class I; Art.14 PSIRT ve CRA-C1…CRA-C3 şimdi; tam uyum 11 Aralık 2027'ye kadar — **Adem kararı bekleniyor (D-10); varsayılan bu** | PD (Adem kararına kadar) | — | Takvim riski (11 Eylül 2026) | MD-12 |
| SA-49 | SBOM, VEX ve provenance ücretsiz ve her sürümde | FROZEN | — | B3; CRA | — |
| SA-50 | Crypto-shredding ≠ silme; yüzeylerde "silindi" denmez | FROZEN | NG (N-42) | EDPB 01/2025 yorumu | — |
| SA-51 | Operasyonel erişim log'u append-only, tamper-evident, canonical değil, karar girdisi değil | FROZEN | UDC | TI-18 | — |
| SA-52 | Saklama: 400 gün PD daraltılabilir; digest süresiz (pseudonymous iskelet); PII ≤ 6 ay crypto-shred; kiracı süreyi seçer | PD | — | Hesap verebilirlik ile saklama sınırlaması dengesi | SEC32 |
| SA-53 | Sektörel eşleme tablosu yeni iddia üretmez; her satır §13 satırına bağlanır | FROZEN | — | İddia disiplini | — |
| SA-54 | PSD2 dinamik bağlama AAS intent digest ile; TR ödeme uygulama-kontrollü faktör sınıfı (MD-11) | FROZEN | UDC | Mevzuat uyumu | MD-11 |
| SA-55 | ASVS 5.0 kontrol listesi; WCAG 2.2 3.3.8 zorunlu | PD | — | Erişilebilir kimlik doğrulama | — |
| SA-56 | **Sertifika başvuru listesi; şu an odak değildir.** Aşağıdaki sertifikalar hedef listesidir, zaman taahhüdü yoktur ve talep/pazar ihtiyacına göre sıralanır: OpenID Certified (OP Basic, Config, Dynamic, Form Post, oturum kapatma), FAPI 2.0 OP sertifikası (IDP-12), ISO 27001 + 27017 + 27018, SOC 2 Type I/II, Türkiye'deki bankalar için BDDK dış hizmet uyum belgeleri ve Türkiye bölgesinde veri yerleşimi (§17.4), HIPAA, FedRAMP. Mevcut taahhütler değişmez: OIDF conformance süiti CI'dadır (B9, AG-17); SA-17 (custodial hizmet için SOC 2 Type II, ilk açık sürümden önce crystal-box denetimi) | WATCH (liste); SA-17 FROZEN kalır | — | Ürün öncelikleri sertifikadan önce gelir; liste kurumsal satış sorularına hazırlık içindir | SA-17; IDP-12; B9 |
| SA-57 | **Güvenlik güveni: bug bounty ve açık güvenlik sayfası.** Bug bounty ilk açık sürümle başlar. Herkese açık güvenlik sayfası bütün güvenlik duyurularını (GHSA), bağımsız denetim raporlarını (SA-17), CVD politikasını ve düzeltme sürelerini tek yerde yayınlar. SA-14, SA-16, SA-17 ve B20 aynen geçerlidir | FROZEN (başlangıç zamanı, açık sayfa); PD (ödül tablosu, platform) | — | Yeni ürünün güvenlik geçmişi yoktur; güven dış araştırma ve şeffaflıkla kazanılır | SA-14; SA-16; SA-17; B20 |
| SA-58 | **Açık kaynak SAML IdP test süiti.** Pazarda olgun bir IdP tarafı SAML conformance süiti olmadığı için Access, herhangi bir SAML IdP'yi test eden bağımsız bir süit yazar ve açık kaynak yayınlar (D4). İçerik: (1) standart uyum testleri (imza yeri ve c14n, NameID, binding'ler, `SubjectConfirmation` ve zaman alanları, metadata); (2) bilinen saldırıların regresyon testleri (XML imza sarmalama/XSW, yorum enjeksiyonu, imzasız assertion kabulü, imzalı çıktının authN olmadan üretilmesi; §10.6.1 CVE listesi); (3) gerçek SP profilleri (§10.6.1 profil tablosu). Access süiti her derlemede CI'da koşar (T42, IDP-40). Süit Access'ten bağımsızdır ve tarafsız tasarlanır: Access'e özel davranış ödüllendirilmez (E24); diğer IdP'ler (Keycloak, authentik vb.) kullanabilir | FROZEN (süitin varlığı, açıklık, tarafsızlık, CI kapısı); PD (kapsam ve yayın zamanı) | — | IdP tarafı SAML doğrulamasının pazardaki boşluğu kapanır; bağımsız süiti geçmek yeni ürün için kanıttır; topluluk katkısıdır (B24) | T42; IDP-40; D4; B24 |
| SA-59 | Test katmanları dört aşamada zorunlu olur (0: ilk koddan; 1: ilk açık sürümden önce; 2: sonra; 3: uzmanlık gerektirenler); testlerin yeri; satır kapsama hedef değil, kural kapsaması ve Kernel/karar çekirdeği için mutation testing; PR ≤ 10 dk, flaky karantina ve otomatik tekrar yasağı, davranışı anlatan test adları, sınırlı snapshot (§14.8.1) | FROZEN (aşama sırası, kural kapsaması, flaky kuralı); PD (süreler, araçlar) | — | İki kişilik ekip için 18 katman sıralanmadan uygulanamaz; en ucuz ve en çok hata yakalayan katmanlar önce gelir | SA-T1…SA-T18; SAI-1; OP-62; OP-66 |

### 14.10 Açık sorular

1. **CRA (D-10).** Üretici kapsamı, Class I sınıflandırması ve beyanlı destek süresi Adem kararını bekler; Suiss-hosted SaaS bileşenlerinin CRA kapsamı hukuki teyit ister.
2. **CRA Art.14 süreleri** (24/72 saat) ve 90 günlük embargo normunun IdP'ye uygulanabilirliği doğrulanmadı.
3. **EAA (European Accessibility Act)** identity plane UI'ına uygulanır mı — kaynakta yok.
4. **NIS2 / DORA** kapsamında Suiss'in kendi rolü (yönetilen hizmet sağlayıcı mı) doğrulanmadı.
5. **Fon uygunluğu** (NGI Zero Commons, OSTIF, Alpha-Omega, STF, GitHub SOSF) ticari bir şirket için doğrulanmadı.
6. **SLSA Build L3** seviyesinin GitHub hosted runner + attest-build-provenance ile fiilen karşılanıp karşılanmadığı doğrulanmadı.
7. **MR6** (redirect_uri) ilişkisinin RFC 9700 exact matching'e göre yeniden yazımı çıkarımdır; §10 (OAuth AS) ile teyit gerekir.
8. **§13.7.9 gevşetme CT değerleri** çıkarımdır; §16 policy tablosu ve MD-14 ile teyit gerekir.
9. **Identity-first login** (SA-11) §12 giriş UX kararıyla uyumlu mu — varlık sızdırmama koşulu bağlayıcıdır.
10. **SSF/CAEP tarihleri, WebAuthn L3 statüsü, CTAP sürümü** doğrulanmadı (MD-18); N-38 ve HL-19 bunlardan bağımsız yazılmıştır.
11. **OQ-MD2** (Cedar forbid-only alt kümesi spike; yedek CEL) fuzz hedefini etkiler (SA-44).

### 14.11 Invariant adayları (SAI-n)

| ID | Aday invariant | Dayanak | Doğrulama |
|---|---|---|---|
| SAI-1 | Her §13.4 G/U/N satırı ↔ en az bir test/vektör/proof veya dürüst-ifade testi; eşlemesiz satır release'i bloklar | MD-15b | CI eşleme kontrolü |
| SAI-2 | Her özyinelemeli parser derinlik kontrolünü özyinelemeden **önce** yapar; aşım `Err`'dir, panic değildir | MD-2; Kanidm GHSA-r5fr, GHSA-2pm5 | Fuzz + Kani (sayaç) |
| SAI-3 | Hiçbir altyapı hatası (limiter, cache, risk, introspection backend, HSM, signer) ALLOW / `active=true` / yeni token üretmez | MD-8; G48 | Hata enjeksiyonu testleri |
| SAI-4 | Cache'in hiç görmediği subject için yanıt yalnız canonical kaynaktan veya fail-closed'dur | MD-7; G49 | DST + hata enjeksiyonu |
| SAI-5 | Login/kayıt/sıfırlama/recovery yanıtları hesap varlığından bağımsız olarak status/body/header/redirect'te özdeştir | MD-18; U44 | Enumeration regresyon suite'i |
| SAI-6 | Domain A'daki mutasyon domain B'nin karar vektörünü değiştirmez; realm A'daki mutasyon realm B'nin authentication/token kararlarını değiştirmez (MR7a/b) | INV-17; MD-5 | Metamorfik PBT |
| SAI-7 | Yayınlanan her artefakt bağımsız olarak aynı digest'le yeniden üretilebilir ve provenance'ı Access witness'larınca co-signed release checkpoint'inde yer alır | F-4, F-7 | Çift build gate |
| SAI-8 | Sır taşıyan tipler Debug/Display/serialize edilemez ve yalnız constant-time karşılaştırılır | SA-26 | Derleme zamanı tip kısıtı + lint + dudect |
| SAI-9 | Authority artefaktı, kabından (COSE/JWS) bağımsız olarak yalnız domain-scoped ve excerpt'le bağlı anahtarla geçerlidir; realm JOSE/SAML anahtarı ve RSA asla; DomainID must-understand | MD-3, MD-6, T24; G46–G47 | Vektörler (her iki kap için) |

SAI aralıkları: SAI-1…SAI-39 §14'e (kullanılan SAI-1…SAI-9), SAI-40…SAI-59 §15'e ayrılmıştır; boşluklar rezervdir, yeniden numaralandırma yapılmaz.
