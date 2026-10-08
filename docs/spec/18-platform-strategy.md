## 18. Platform / Business Strategy

### 18.0 Statüler ve okuma notu

Bu bölümde iki ayrı statü vardır ve karıştırılmaz: **FROZEN STRATEGY DECISION (B1–B24)** frozen kararlardan türeyen ticari kurallardır; **CURRENT STRATEGIC HYPOTHESIS (H1–H17, H13a/H13b dahil)** pazar varsayımlarıdır ve kanıtla değişir. D1–D9 ile D-10 (MD-12) **Adem kararlarıdır**. D-11 adaydır. Recommended default'ları freeze edilmez. Hiçbir H, D veya fiyat kararı bir CANONICAL INVARIANT'ı veya FROZEN kararı değiştiremez (B1).

Okuma notu: Aşağıdaki kurallar aksi açıkça yazılmadıkça authority plane'e ve identity plane'e aynen uygulanır. Bu şu demektir:
- Z1–Z3 ve B1–B18 tam IdP için de geçerlidir.
- B5'in semantik sayaç yasağı MAU'ya da uygulanır (MD-17).
- B11'in identity hostage yasağı Access'in kendi identity plane'ini de bağlar.

### 18.1 Verdict (hipotez)

**Verdict (CURRENT STRATEGIC HYPOTHESIS): open-protocol authority layer, monetized as operated infrastructure + experience — wedge = agent delegation for consequential actions.** Ticari strateji ürün kurulumunun sonucudur, onu yeniden yazmaz. Frozen kararlar iş modelinin üç şeyini zaten belirler:

| # | Frozen kararlardan zorunlu olarak çıkan | Neden zorunlu | B |
|---|---|---|---|
| Z1 | **Suiss protocol'den para kazanamaz; operasyondan ve deneyimden kazanır.** | Protocol açık ve vendor-neutral; Suiss onun sahibi değil, bir implementasyonu (P1, P2) | B2 |
| Z2 | **Müşteriyi kayıt, kimlik, format veya güvenlikle tutamaz.** | DomainID provider'dan bağımsız, tam export ve handover/recovery protocol'de, non-custodial geçiş her zaman açık, normatif tanım spec + vektör (SEC17, SEC20, RT8, T4) | B3, B10, B11 |
| Z3 | **Ücret, kaydı, sormayı, daraltmayı veya ayırmayı pahalılaştıramaz.** | Access'in değeri kayıtlı, fail-closed, attributable kullanımdır; bunu azaltmaya iten fiyat güvenliği bozar (C30, E28, INV-26, DL-3, C8/PI-7, T27) | B5 |

Z1–Z3 identity plane için de geçerlidir. Z2'nin identity plane karşılıkları şunlardır:
- Parola hash'i ve TOTP sırrı self-servis ve ücretsiz export edilir. Pre-hash ve pepper import desteklenir (B19).
- PartyID ve key-event taşınabilirliği ile non-custodial geçiş ücretsizdir (B7).
- WebAuthn passkey'i RP ID'ye bağlıdır; RP ID **değişirse** kayıtlar silinmez ama kullanılamaz hâle gelir (NG, fiziksel; XI-12). RP ID müşterinin alan adında olduğundan provider değişimi RP ID'yi değiştirmez ve passkey'ler yeni provider'da çalışır (çıkarım; RP ID'nin kontrolü DNS'tedir). Suiss passkey'li realm'i kendi alan adında RP ID ile açmaz (§12.1.2). Çıkışta taşınamayan tek şey authenticator'ın kendisi değil, RP ID'nin değiştirilmesi hâlidir; bu hâl çıkış belgelerinde açıkça yazılır. Özel alan adının varlığı ücretlendirilemez (§18.6). CXF/CXP durumu → §10.

Bu üç zorunluluğun içinde kalan serbest alan hipotezdir:

> **H-çekirdek (CURRENT STRATEGIC HYPOTHESIS):** Organizasyonlar, birden çok vendor'ın agent'larına **para harcayan, bir şeyi değiştiren veya dışarıya bir şey gönderen** eylemler için yetki vermeye başladıkça, IdP'lerin verdiği kimlik ve OAuth scope'ları yetmez; "bu agent, kimin adına, hangi kaynaktan, hangi sınırla, bu exact işi şimdi yapabilir mi — ve sonra bunu kanıtlayabilir miyim" sorusuna cevap veren, vendor-neutral bir **authority layer** için ödeme yaparlar. İlk benimseyen bu agent'ları entegre eden platform/developer ekibidir, ödeyen organizasyondur (domain controller'ı), kullananlar ise principal'lar, approver'lar, admin'ler, auditor'lar ve agent'lardır.

H-çekirdek değişmez. Wedge hipotezi (H6) de değişmek zorunda değildir. Access'in tam IdP olarak ayrıca satılabileceği ayrı bir hipotezdir (H13b). H-çekirdeğin yerine geçmez.

**Tek cümlelik sonuç:**

> **Suiss Access protocol olarak herkese, ürün olarak domain'ini Suiss'e emanet edenlere aittir; Suiss para kazanır çünkü authority'yi en güvenilir işleten ve en anlaşılır gösteren taraftır — müşteriyi tuttuğu için değil; ve hiçbir fiyat, birinin yetkiyi kaydetmeden, sormadan veya geniş bırakarak daha ucuza kullanmasını ödüllendiremez.**

### 18.2 Positioning (hipotez)

**One-liner (H1'in sales dili; semantik tanım §1.1'dir).**

> **"Agent'larınıza ve ekiplerinize, neyi kimin adına ve hangi sınırla yapabileceklerini verin; istisnaları onaylayın, her an geri alın ve her kullanımı sonradan kanıtlayın — hangi vendor'ın agent'ı olursa olsun, Suiss'e bağlı kalmadan."**

Kısa biçim (H): *"The authority layer for humans and agents."*

**Ürün cümlesi**:

> **"Access tam bir IdP'dir (identity plane) ve onun üstünde authority plane'i olan tek üründür."**

"Tek ürün" kısmı CURRENT STRATEGIC HYPOTHESIS'tir. Kanıt seviyesi reviewed landscape'tir (§4.6, §4.7). "Örnek bulunamadı ≠ ilk biz" kuralına tabidir (§3.4). Satış dilinde ancak beyanlı karşılaştırma kümesi ve tarihle kullanılır (B15). Karşı örnek: tam IdP ile provenance + attenuation + budget + exercise record taşıyan authority katmanını tek üründe sunan bir rakip (L2 notu). Karşı örnek bulunursa yalnız bu cümle değişir; ürün tanımı (§1.1) değişmez.

Bu cümleler **CURRENT STRATEGIC HYPOTHESIS**'tir (H1). Semantik tanım (one-sentence definition) değişmez; one-liner onun ticari kısaltmasıdır ve forbidden claims'e tabidir: "stops agents", "revoked everywhere instantly", "guaranteed", "trusted agent" gibi ifadeler sales dilinde de kullanılamaz (**B15**).

**Commercial IS / IS NOT (§2.4–§2.5'in ticari karşılığı).**

| Suiss Access IS (ticari) | Dayanak |
|---|---|
| Agent'lara ve insanlara **sınırlı, bütçeli, süreli, geri alınabilir** yetki vermenin ve bunun her kullanımını kaydetmenin yeri | C27, X10 |
| Consequential bir eylemden önce sorulan **tek "evet / hayır / şu eksik"** kaynağı (her vendor'ın agent'ı için aynı sözleşme) | P6, P10, E24, X19 |
| Onayın **exact intent'e** bağlı, sonradan kanıtlanabilir bir yetki eylemi olduğu yer | E7, P29, L14 |
| "Kim benim adıma neyi yapabilir?" sorusunun tek envanteri ve tek iptal noktası | X6, X12 |
| Denetçiye "bu kullanım kökten bugüne nasıl meşruydu" kanıtını **Suiss'e sormadan** verebilen kayıt | P32, T12, RT8 |
| Kendi IdP'nizle (Entra, Okta, Google, Keycloak, SPIFFE …) çalışan; Access'in kendi identity plane'ini (tam IdP) **isteğe bağlı** sunan | F3, E18, E24, B7 |
| Açık bir protocol'ün en iyi işletilen implementasyonu; domain'inizi istediğiniz an başka provider'a taşıyabilirsiniz | P1–P4 |
| **Tam bir IdP**: OIDC/OAuth 2.1 AS, SAML, SCIM, LDAP, Kerberos, RADIUS, WS-Fed, OpenID Federation, passkey, oturum, hesap yaşam döngüsü, MCP ve ajan kimliği. Self-host edilebilir veya Suiss-hosted alınabilir | F21, §2.2.1, H13b |
| Identity verinizi (parola hash'i, TOTP sırrı dahil) ücretsiz ve self-servis dışa aktarabileceğiniz IdP | B19, B10 |

| Suiss Access IS NOT (ticari) | Neden söylenmez | Dayanak |
|---|---|---|
| IdP değiştirmeyi şart koşan bir ürün | Authority plane external IdP'lerle aynı Acceptance koşullarıyla çalışır. Enterprise girişte external IdP varsayılan kalır, çünkü IdP'yi değiştirmek wedge'i ağırlaştırır (H13a). Access'in tam IdP olması bu satırı değil, satışın sırasını etkiler | H13a, E18, B7 |
| Agent platformu, orchestrator, agent marketplace | Owner One/Executor; Access hiçbir vendor'ı tercih etmez | §2.5, E24 |
| "Agent'ları durduran" kill switch | Revocation ≠ stop | HL-13, EI-11, X13 |
| Ödeme / harcama limiti ürünü | Authority budget ≠ financial limit; para Pay/Money'nin | E21, X15 |
| Risk skoru / fraud motoru, DLP, SIEM, PAM oturum kaydı ürünü | Ayrı ürün katmanları. Access bunların authority kısmına karar verir, olay ve sinyal üretir. Risk tabanlı step-up ve ajan token vault identity plane'dedir | E22, L28, §2.5 |
| Workflow / onay kuyruğu | Access'in request queue'su yok | X5 |
| "Suiss tarafından sertifikalı" bir ekosistem kapısı | Conformance ≠ endorsement | P2, B9 |
| Zorunlu Suiss bağımlılığı (Work, One, Pay için) | No mandatory Suiss Access | §2.5 |
| Dikey / uyum ürünü veya "hafif" IdP konumlandırması | Konumlandırma hipotezidir (H17), yetenek dışlaması değildir. Uyum gereksinimleri (CRA, PSD2 SCA, PCI audit penceresi) karşılanır ama ürün "uyum ürünü" olarak konumlanmaz | H17, MKT-7 |

### 18.3 Platform rolleri

Access birden fazla roldedir; her rolün dayanağı farklı statüdedir:

| Rol | Access'te ne | Var olması | Ticari ağırlığı |
|---|---|---|---|
| **Protocol** | L0 Core Semantic Spec, L1 Interop Profiles, L2 Access-native parts, L3 Conformance | **FROZEN** (P1) — B16 | Gelir yok (B2); güvenilirlik ve ağ kaynağı (H10, H16) |
| **Infrastructure** (hosted provider) | Suiss-hosted AuthorityDomain operasyonu: cell, sequencer, HSM anahtar hiyerarşisi, witness/replica orkestrasyonu, handover/recovery, status/projection hattı. Suiss-hosted identity realm operasyonu: issuer, realm JOSE anahtar setleri (MD-6), oturum ve token hizmeti, SCIM/SAML/LDAP uç noktaları, yedekleme | **FROZEN** (E20, T27) — B16 | **Birincil gelir** (H9) |
| **Product** | Access = Identity plane (tam IdP) + hosted Authority plane + Experience yüzeyleri S1–S10 | **FROZEN** (F3, F21, X3) | Gelirin taşıyıcısı; deneyim farkı (H11); tam IdP olarak ayrı satış (H13b) |
| **Developer service** | PEP SDK'ları, decision lab, schema publishing, Offline Verifier SDK, Replay CLI; IdP SDK'ları (RP/OIDC client, SAML SP yardımcıları, MCP client/server profili), Kernel'in Wasm paketi (MD-1), sandbox realm | **FROZEN** (X21, T25, T34) | Ücretsiz; benimseme kapısı (H8) |
| **Enterprise control plane** | S7 org authority admin, S9 audit & security, residency/DR sınıfı, dedicated cell, SLA | **FROZEN** yüzeyler (X20, X22); paketleme H | Gelirin enterprise kısmı (H9; B4 sınırı) |
| **Consumer surface** | Authority hub (S2), S10 sign-ins & instances, end-customer profili — **tek Suiss kabuğunda gömülü** | **FROZEN** (X4, X6, X30) | Doğrudan gelir yok (H5) |
| **Platform** (ekosistemin üzerine kurduğu) | Schema Publication ekosistemi, conformant PEP/Approval Surface/Verifier ekosistemi, third-party provider'lar | **FROZEN** sözleşmeler (P2) | Integration yoğunluğu (H11) |
| **Self-host dağıtımı** | İki plane'in sunucu binary'leri; small-provider profili ≈ tek binary / tek komut (→ §16, §17); single-node profili beyanlıdır, FA-1 karşılanmaz (OP-48) | T36 (→ §16) | Destek/SLA aboneliği (H14, D4); kod tamamen açık kaynak; güvenlik düzeltmeleri her zaman açık sürümde (B20) |

**B16:** Bu rol yapısı (protocol ≠ ürün; Suiss-hosted = bir implementasyon; consumer yüzeyi gömülü) frozen kararlardan türer ve ticari tercihle değiştirilemez. **Hangi rolün önde satıldığı** (infrastructure + enterprise control plane önde, protocol arkada) **H1/H9**'dur.

**Developer-facing, enterprise-facing ve protocol infrastructure.**

| Yüz | İçerik | Fiyat ilkesi |
|---|---|---|
| **Developer-facing** | PEP SDK'ları (fail-open yok), decision lab (advisory + replay + conformance), sandbox domain (ayrı AuthorityDomain, X21), schema publishing, explain (structured), Offline Verifier SDK, Replay CLI; IdP SDK'ları, sandbox realm, hosted login, OIDF conformance sonuçları | **Ücretsiz** — SDK'lar, conformance, explain, Replay CLI B3; hosted sandbox domain/realm H8/D7 (fiziksel fair-use; fair-use aşımında daraltma/çıkış yolları açık, B18) |
| **Enterprise-facing** | S7 (rol sürümleme, change-impact, Acceptance blast radius, offboarding), S9 (audit, replay, export, containment), residency/DR sınıfı, dedicated cell/HSM partition, SLA, destek, enterprise connector'ları, policy authoring araçları | **Ücretli** — ama güvenlik/doğrulanabilirlik/çıkış özellikleri hariç (B3, B4, B19) |
| **Protocol infrastructure** | L0–L3, reference evaluator/verifier, conformance suite + vektörler, Witness profile (Work ile ortak), Approval Surface profile | **Açık** (B2, B9; lisans biçimi D4) |

Not (B4 sınırı): S7'nin **change-impact preview**'u ve "Full access" yasağı, S9'un **audit-scope explain/replay/export**'u enterprise yüzeyinde dursa bile güvenlik özelliğidir (X20, X22, SEC24); hiçbir pakette kapatılamaz. Ücretli olan, bunların **ölçek, otomasyon ve konfor** katmanıdır (ör. toplu simülasyon raporları, entegrasyonlu iş akışları, uzun retention), varlığı değil.

### 18.4 Value metric

**Value metric = Authority Exercise** (F5). C30'a göre kesin anlamı: bir intent nonce'u için **ilk committed ALLOW ile doğan** canonical entity; DENY ve REQUIRE_ACTION evaluation sonuçlarıdır, Exercise değildir. Access'in müşteriye ürettiği değer, **kaydedilmiş, attributable, provenance'ı bilinen bir Authority Exercise**'tır (C30/INV-22 kümesinin tamamı: effect'ten önce kaydedilen kullanım Exercise'ları ve authority state'i değiştiren meta-Exercise'lar; B17). Value raporlamasının consequential (CT2+) effect'leri destekleyen alt kümeye odaklanması bir hipotezdir (H).

Value metric'in **kullanım yeri**: müşteriye değer raporu, ürün başarı ölçüsü, ROI anlatısı, kapasite planlaması. Önerilen ürün metrikleri (H; hepsi derived, hiçbiri fatura girdisi değil):

| Metrik | Ne ölçer | Neden count değil oran |
|---|---|---|
| **Governed consequential coverage** = CT2+ effect'lerin Exercise'la desteklenen oranı (PEP'lerin raporladığı/attestation'lı effect'lere göre) | Access'in gerçekten sorulup sorulmadığı | Exercise sayısını artırmak hedef değil; **sorulmayan effect'i** azaltmak hedef |
| Revocation-to-effective penceresi (beyanlı Δ/horizon içinde kalma oranı) | Geri almanın beyan edildiği gibi çalışması | XI-12 dürüstlüğü |
| Time-to-delegate / time-to-approve | Sürtünme | Fatigue |
| Approval fatigue göstergeleri (onay/red oranı, ortalama inceleme süresi) | İnsan dikkatinin sağlığı | SEC26, X23 |
| Over-delegation göstergesi (kullanılmayan geniş Grant oranı, süresiz delegation oranı) | Least privilege | X10 |
| Kurtarma ve onboarding yeniden tetikleme oranı | Hesap ele geçirme ve sosyal mühendislik baskısı (Unit 42 tavsiyesi; birincil kaynaktan doğrulanmadı) | Mutlak sayı değil, oran ve eğilim |
| Phishing-resistant kimlik doğrulama oranı | Passkey / donanım anahtarı ile yapılan login'lerin payı | Kullanıcı sayısı değil, yöntem dağılımı |
| Sender-constrained token oranı | Bearer opt-in'in ne kadar yaygın kaldığı | Oran; hedef bearer payını azaltmak |
| Hesap efektif güvenlik dağılımı | Hesabın efektif güvenliği = bütün kurtarma yollarının AAL minimumu | Dağılım; admin konsolunda gösterilir (→ §12) |

B17 korunur. Identity plane metrikleri türetilmiş ürün metrikleridir. Unit of value veya fatura birimi değildir (MD-17).

### 18.5 Billing unit adayları ve Goodhart testi

Test sorusu: *Bu birim için fatura düşürmenin en ucuz yolu, müşteriyi daha az kayıt, daha az sorma, daha geniş/uzun yetki, daha az ayrım veya daha az doğrulamaya itiyor mu — ya da daraltmanın (revoke/narrow/suspend/terminate) veya çıkışın (export/handover/recover) kendisini birimin tavanına takabiliyor mu?* Evet ise birim **güvenliği bozar** ve B5 tarafından reddedilir. Bir satır ancak test sonucu "Hayır" (veya yalnız beyanlı, POLICY DEFAULT ile sınırlanmış bir residual) olduğunda ALLOW alır.

| Aday birim | Faturayı düşürmenin en ucuz yolu | Güvenlik / semantik etkisi | Karar |
|---|---|---|---|
| **Authority Exercise sayısı** (committed ALLOW) | (a) PEP'in Access'e sormaması / cache'lemesi; (b) uzun ömürlü, geniş bounds token ve büyük ValidityContract horizon'larıyla birçok effect'i tek Exercise'a yığmak; (c) consequential effect'i "advisory check"e çekmek | (a) E28/INV-26 fail-closed'u ekonomik baskıyla aşındırır; (b) revocation penceresini genişletir (DL-3, HL-3); (c) C30 kaydını kaybettirir | **REJECT** (B5) |
| Decision / evaluation API çağrısı (check + commit + explain) | Explain ve advisory check'i azaltmak; PEP'te yerel karar cache'i | Açıklama ve ön-kontrol güvenlik/UX aracıdır (X18); cache = stale ALLOW riski (T10 bunu önler ama baskı yaratır) | **REJECT** (B5) |
| Grant sayısı | Az ama geniş, süresiz, yeniden delege edilebilir Grant'lar | Over-delegation; X10 varsayılanlarına karşı baskı | **REJECT** (B5) |
| Agent / Instance sayısı | Birden çok agent'ı / workload'u tek Instance altında çalıştırmak | Attribution kaybı: Instance kimliği authority-binding sürekliliğidir (C8); AIS actor'ü Instance'tır (PI-7); compromise blast radius büyür | **REJECT** (B5; agents are not seats) |
| Human Party / "governed identity" sayısı | Paylaşılan hesaplar; insanları domain dışında tutup org'un OWN authority'siyle servis hesabı üzerinden işlem | Attribution ve SoD kaybı; CT3 quorum'u ≥ 2 eligible principal ister (SEC10, SEC26) | **REJECT** (B5) |
| AuthorityDomain sayısı | Ayrı domain'leri tek domain'de birleştirmek | Domain = izolasyon, shard ve blast radius birimi (T27, RT11, SI-3 radius) | **REJECT** (B5) |
| Approval / contribution sayısı | Requirement'ları gevşetmek, CT eşiğini yükseltmek, batch'i büyütmek | SEC10, SEC26 varsayılanlarına karşı baskı | **REJECT** (B5) |
| Claim ingest / Acceptance sayısı | Narrowing Claim'lerini (compromise, cutoff) geciktirmek | Narrowing ingest önceliği güvenliktir (T23) | **REJECT** (B5) |
| Revocation / narrowing / export / verify işlemi | Geri almamak, export almamak, doğrulamamak | Güvenlik ve çıkış özelliği | **REJECT** (B3, B5) |
| Projection issuance sayısı | Daha az ama daha uzun/geniş projection | DL-3 penceresi genişler | **REJECT** (B5) |
| **MAU / aktif kullanıcı** (identity plane) | Paylaşılan hesaplar; kullanıcıları IdP dışında veya tek servis hesabının arkasında tutmak; ayrılan kullanıcıyı deprovision etmeden "pasif" bırakmak | Attribution ve SoD kaybı (B5'in Party gerekçesiyle aynı); paylaşılan hesap = Instance attribution'ının kaybı | **REJECT** (B5; MD-17). Pazar normu MAU'dur; bu nedenle karar H9'un identity kısmıdır ve HYPOTHESIS olarak test edilir |
| Realm / tenant sayısı (identity plane) | Ayrı realm'leri tek realm'de birleştirmek | İzolasyon, issuer ve anahtar ayrımı kaybı (MD-5, MD-6) | **REJECT** (B5) |
| Kurumsal SSO / federasyon bağlantısı başına (WorkOS modeli) | Kurumsal federasyonu kurmamak; kullanıcıları parola ile bırakmak; bağlantıyı organizasyonlar arasında paylaştırmak | Phishing-resistant kurumsal kimlik doğrulama ve merkezi deprovisioning kaybı | **REJECT** (B5 gerekçesi; SSO'nun hiçbir pakette ücretli olmaması D-11 aday kuralıdır, §18.9) |
| Login / token issuance / refresh / introspection sayısı | Uzun ömürlü ve bearer token'a geçmek; introspection'dan kaçınmak | Revocation penceresi genişler (MD-7; ≤ 60 dk yönetim token'ı PD'si); sender-constrained varsayılana baskı (I3) | **REJECT** (B5) |
| MFA / passkey kullanıcı başına eklenti | MFA'yı kapatmak | Güvenlik paywall'u | **REJECT** (B3) |
| MCP client / CIMD client / ajan kaydı sayısı | Ajanları tek client altında çalıştırmak | Agents are not seats (Instance satırı) | **REJECT** (B5) |
| **Hosted operasyon sınıfı** (paylaşılan / dedicated cell; residency/DR sınıfı; SLA) | Daha düşük availability/residency sınıfı seçmek | Availability NG zaten (DL-8, N-20); integrity ve guarantee sınıfı aynı kalır (B4) | **ALLOW** — H9 ana eksen. Identity realm hosting'i dahil |
| **Fiziksel kapasite** (rezerve commit throughput / ingest kapasitesi; yalnız genişletici veya nötr commit'ler — daraltma sınıfı Exercise'lar (`*.revoke`, `instance.terminate`, restriction ekleyen `policy.set`, Acceptance daraltma; SEC23 listesi) ve suspend (X11), narrowing sınıfı Claim ingest'i (T23) ve export/handover/recover yolları kapasite sayacına girmez ve ticari tavan nedeniyle reddedilmez; bunlar yalnız SI-20 güvenlik sınırlarına (POLICY DEFAULT) tabidir — B18) | Kapasiteyi düşük rezerve etmek | Rezervasyon içinde sormak/kaydetmek marjinal olarak bedavadır (sayaç değil); aşım yalnız yeni genişletici/nötr commit'leri protocol rejection'la reddeder — **genişletici yönde fail-closed** (SEC28/SI-20 sınıfı rejection), availability bedeli; daraltma ve çıkış hiçbir zaman tavana takılmaz. Goodhart testi: **Hayır** — kalan tek baskı (daha uzun ValidityContract) POLICY DEFAULT Δ/horizon tavanlarıyla sınırlı, beyanlı residual | **ALLOW (rezervasyon olarak, sayaç olarak değil; daraltma/çıkış kapsam dışı)** — H9; B5 koşulları; residual |
| **Fiziksel kapasite — identity plane** (rezerve login/sn, Argon2 işçi kapasitesi) | Kapasiteyi düşük rezerve etmek | Aşımda yük atma 503'tür, fail-closed. Logout, oturum iptali, deprovisioning ve hesap kilitleme kapasite sayacına girmez (B18 analojisi) | **ALLOW (rezervasyon)** — H9; sayaç değil |
| **Fiziksel depolama / retention** (policy minimumunun üstü) | Retention'ı policy minimumuna indirmek | Digest'ler süresiz; redaksiyon audit bütünlüğünü bozmaz (T39, SEC32); minimum POLICY DEFAULT'un altına inilemez | **ALLOW** — H9 |
| Dedicated fiziksel izolasyon (dedicated cell, dedicated HSM partition; identity plane için dedicated compute) | Paylaşılanda kalmak | Paylaşılan partition korelasyonu **beyanlıdır** (HL-8, RT12) ve baseline'da müşteriye bildirilir; guarantee sınıfı değişmez. Co-tenant yan kanal riski HL-17, N-32, RR-23 (DL-10) olarak beyan edilir (MD-17). Signer ayrımı ve HSM herkes için ücretsizdir (B3) | **ALLOW** — H9; B4 testi |
| Enterprise tooling / experience konforu (policy authoring, analitik, toplu simülasyon raporları, connector'lar) | Kullanmamak | Güvenlik özelliğinin varlığı değil, konforu (B3/B4 sınırı) | **ALLOW** — H9 |
| Destek / SLA / profesyonel hizmet | — | Yok | **ALLOW** |
| Self-host destek / SLA aboneliği | Desteksiz ücretsiz kullanım (kod tamamen açık kaynak, D4) | Güvenlik düzeltmeleri her zaman açık sürümdedir (B20); export/handover/replay hiçbir lisansla kısıtlanamaz (B10) | **ALLOW** — H14, D4 |
| Admin/audit console koltuğu (yalnız S7/S9 **konfor/otomasyon** tooling'ine erişim; Party'nin domain'deki varlığı değil) | Daha az admin/auditor | Daha az admin genelde least-privilege'e uygun; ama auditor azaltma denetim kapasitesini düşürür. Koşullar: approver'lar ve quorum katılımcıları Approval Surface'ten koltuksuz katılır; B3 güvenlik yüzeyleri (audit-scope explain/replay, export, change-impact, revoke) koltuğa bağlanamaz | **ALTERNATİF (H9'un yedeği)** — recommended değil; H9 "what changes if false" |

**Pazar fiyat modelleri (bilgi).** Pazarda dört model gözlenir: MAU başına (Auth0, Clerk, Entra, Logto, FusionAuth Cloud), bağlantı başına (WorkOS 125 USD, Stytch beş bağlantı sonrası), self-host (altyapı ve operasyon: Keycloak, Ory, Authentik, SuperTokens) ve kademeli/eklentili (SuperTokens). Rakamlar eskir (MKT-3). Access'in MAU ve bağlantı başı modelleri reddetmesi B5'in sonucudur. Pazar normuna aykırı olması bir risktir. Bu risk H9'da falsifier olarak yazılır ve OQ-3'e eklenir (→ §20).

### 18.6 B4 testi: security paywall ile fiziksel fark

Bir özellik **ücretlendirilemez** eğer aşağıdakilerden biridir (B3):

1. Bir frozen guarantee'nin (G/U satırları) koşulu veya Suiss-hosted şablonun zorunlu POLICY DEFAULT'u (SEC17–SEC23, T21),
2. Bir güvenlik düzeltmesi (ör. domain-başı operasyonel anahtar RT11, witness-tazelik RT10, opaque `basis_ref` RT21),
3. Doğrulanabilirlik, export, replay, handover/recovery, conformance (P2, P4, P32, RT8),
4. Dürüstlük/güvenlik yüzeyi: revoke/narrow/suspend (X11), impact preview ve aftermath (X12), change-impact preview (X20), audit-scope explain/replay (X22, SEC24), honest status (X14), passkey/step-up, user-gated custody ve non-custodial geçiş (SEC17), CT3 bağımsız render yolu.
5. Identity plane güvenlik ve çıkış yüzeyi:
   - MFA, passkey ve step-up
   - özel alan adının varlığı (passkey RP ID'sinin müşterinin alan adında olması; sınır vakaları tablosu)
   - sender-constrained token (DPoP, mTLS)
   - oturum iptali, logout ve deprovisioning (SCIM deprovisioning dahil)
   - parola hash'i ve TOTP sırrı export'u; pre-hash import
   - signer süreç ayrımı ve HSM (MD-17)
   - OIDF conformance süitini koşmak (B9)
   - SBOM, VEX ve provenance

Bir özellik **ücretlendirilebilir** eğer yalnız şunları değiştirir (B4): availability, performans, kapasite, residency yeri, policy minimumunun üstündeki retention, fiziksel izolasyon (guarantee sınıfı aynı kalarak), destek/SLA, konfor ve otomasyon.

Sınır vakaları:

| Vaka | Karar | Neden |
|---|---|---|
| Multi-region sync DR sınıfı vs regional | Ücretlendirilebilir | Regional sınıfta bölge kaybı fence + son head kanıtı yoksa `domain.recover`'a kadar **fail-closed**'dur (T28): kayıp güvenlik değil availability'dir; her iki sınıf dürüstçe beyan edilir (XI-12) |
| Dedicated HSM partition | Ücretlendirilebilir | Paylaşılan partition'daki korelasyonlu donanım riski HL-8'dir ve RT12 ile **baseline'da beyan edilir**; domain-başı operasyonel anahtar (RT11) baseline'dadır. Dedicated partition beyanlı bir fiziksel sınırı müşteriye özel kılar, frozen bir guarantee satın aldırmaz |
| CT2 %1 / CT3 %100 provider kararı yeniden değerlendirme örneklemi | **Ücretlendirilemez** (yapabilme); kimin çalıştırdığı domain'in seçimidir | Yeniden değerlendirme tespit mekanizmasıdır; open Replay CLI ücretsiz. Suiss'in bunu yönetilen hizmet olarak sunması H olabilir ama domain'in kendi doğrulamasını hiçbir koşul engelleyemez |
| SIEM'e hazır connector | Ücretlendirilebilir (konfor) | SSF semantic event akışı (P33) ve Record Export (P32) ücretsiz; vendor-özel connector konfordur |
| Uzun audit retention | Ücretlendirilebilir (policy minimumunun üstü) | Minimum POLICY DEFAULT (SEC32: 400 gün redaksiyon uygunluğu; digest'ler süresiz) ücretsiz baseline |
| SCIM deprovisioning | **Ücretlendirilemez** | Deprovisioning daraltma sınıfıdır. Reddi authority'yi geniş bırakır (B18 gerekçesi) |
| Kurumsal SSO bağlantısı (SAML/OIDC upstream) | Aday kural: **ücretlendirilemez** ("SSO tax" reddi). Adem kararı D-11 | Phishing-resistant kurumsal kimlik doğrulama ve merkezi deprovisioning güvenlik yüzeyidir. Bağlantı başına fiyat Goodhart testinde REJECT almıştır (§18.5). Self-servis kurulum portalı ücretsizdir (TN-134); yalnız yönetilen onboarding (insan desteği) ücretlendirilebilir |
| Parola hash'i / TOTP sırrı self-servis export, pre-hash import | **Ücretlendirilemez** | Çıkış özelliği; identity hostage yasağı (B10, B11, B19) |
| Özel alan adı (realm issuer'ı ve WebAuthn RP ID'nin müşterinin alan adında olması) | **Ücretlendirilemez** (varlığı) | Passkey (B3) özel alan adı olmadan açılamaz (§12.1.2 RP ID kuralı), ve RP ID'nin müşteride olması passkey'li çıkışın tek yoludur (B11, B19). Sertifika ve DNS otomasyonu konforu ücretlendirilebilir (B4). Kural B3'ten türetilmiştir; Adem'in görmesi için §20'de not edilir |
| Uzun sıcak identity audit penceresi (PCI 12 ay) | Ücretlendirilebilir (policy minimumunun üstü) | Policy minimumu ücretsiz baseline'dır. Minimumun sıcak (sorgulanabilir) kısmının uzunluğu §17'de PD olarak yazılır |
| OIDF conformance sonuçları ve resmî sertifikasyon | Süiti koşmak ve sonuçları yayınlamak ücretsiz (B9); OIDF listeleme ücreti OIDF'nindir (üye 700 USD, üye olmayan 3.500 USD / dağıtım; birincil kaynaktan doğrulanmadı) | Conformance ≠ endorsement |
| Dedicated compute (identity plane) | Ücretlendirilebilir (B4 opsiyonu) | Guarantee sınıfını değiştirmediği sürece. Co-tenant yan kanal riski HL-17, N-32, RR-23 (DL-10) olarak baseline'da beyan edilir; dedicated varyant U54 |
| Signer süreç ayrımı, HSM | **Ücretlendirilemez** | Güvenlik kontrolüdür ve herkes için baseline'dır (MD-6, MD-17) |
| SBOM, VEX, provenance | **Ücretlendirilemez** | CRA Ek I zorunluluğu ve doğrulanabilirlik (→ §14) |

### 18.7 Frozen strategy decisions (B1–B24)

- **B1** Pazar, fiyat, satış kolaylığı veya bir H'nin çürümesi; ürün sınırını, ownership'i, protocol açıklığını, güvenlik guarantee'sini veya mimariyi geriye dönük değiştiremez.
- **B2** Access protocol'ü (L0–L3) açık, telifsiz ve vendor-neutral'dır; Suiss protocol'den gelir elde etmez (lisans/telif/katılım ücreti yok); gelir hosted operasyon, Experience, enterprise tooling ve destekten gelir.
- **B3** Hiçbir pakette ücretlendirilemez veya kapatılamaz: verification (reference verifier, PAP/receipt/checkpoint/inclusion proof), tam export ve replay, handover/recovery, conformance suite ve vektörler, SSF semantic event akışı, Suiss-hosted şablonun bütün güvenlik POLICY DEFAULT'ları (witness/replica-before-ack, user-gated custody, non-custodial geçiş, recovery anahtar ayrımı, CT3 bağımsız render yolu), güvenlik düzeltmeleri (ör. domain-başı operasyonel anahtar), passkey/step-up, revoke/narrow/suspend, impact preview/aftermath, change-impact preview, audit-scope explain, honest status, açık SDK'lar (PEP/verifier SDK) ve conformance runner. (Hosted developer sandbox domain'inin ücretsizliği B değil, H8/D7'dir.) Identity plane için listede ayrıca şunlar vardır:
  - identity plane'in MFA'sı ve sender-constrained token desteği
  - oturum iptali, logout ve deprovisioning
  - signer süreç ayrımı ve HSM
  - SBOM, VEX ve provenance
  - OIDF conformance süitinin koşulması
- **B4** Fiyat yalnız availability, performans/kapasite (B5 koşullarıyla: rezervasyon, sayaç değil; daraltma sınıfı ve çıkış yolları hariç — B18), residency yeri, policy minimumu üstü retention, beyanlı fiziksel izolasyon (guarantee sınıfı değişmeden), destek/SLA ve konfor/otomasyon üzerinden farklılaşabilir; integrity, authority güvenliği, doğrulanabilirlik, çıkış veya guarantee sınıfı üzerinden asla.
- **B5** Hiçbir fatura birimi şunları marjinal olarak pahalılaştıramaz: karar sormak (check/commit/explain), kaydetmek, daraltmak/geri almak, doğrulamak, export etmek; ayrı AuthorityDomain, ayrı Party (domain'e kabul edilmiş, authority tutan, kullanan veya onay veren), ayrı Instance kullanmak; dar/kısa Grant ve kısa horizon kullanmak; approval/quorum requirement'ları; Claim ingest ve Acceptance. Dolayısıyla Authority Exercise, evaluation çağrısı, Grant, Instance/agent, Party, AuthorityDomain, contribution, Claim, projection ve revocation sayıları fatura birimi değildir. Fiziksel kapasite rezervasyonu (B4, H9) ancak şu koşullarla fatura eksenidir: (i) sayaç değil rezervasyondur — rezervasyon içinde sormak/kaydetmek marjinal olarak ücretsizdir; (ii) Exercise veya başka bir semantik nesne cinsinden ifade edilmez; (iii) daraltma sınıfı (revocation sınıfı Exercise'lar, suspend, narrowing Claim ingest'i) ve export/handover/recover kapasite sayacına girmez ve ticari tavan nedeniyle reddedilmez (B18). Türetim notu: Access approval/contribution katılımı hiçbir zaman ücretli bir Work koltuğu gerektirmez; bundle'daki Access bileşeninin fiyatı Party veya approver sayısına endekslenemez. **Identity plane'de de aynı kural geçerlidir**: MAU/aktif kullanıcı, realm, kurumsal SSO bağlantısı, login/token/introspection, MFA kullanıcısı ve MCP/ajan client'ı sayıları fatura birimi değildir. Gerekçe paylaşılan hesaplara itme ve attribution kaybıdır. Identity fiyatı H9 ekseniyle kurulur: operasyon sınıfı, kapasite rezervasyonu, tooling. Pazar normu MAU olduğu için bu eksenin ticari tutması HYPOTHESIS'tir (H9).
- **B6** Protocol katılımı Suiss'e ödeme doğurmaz: requester/PEP/agent vendor'ı, verifier, karşı taraf/end customer, schema publisher ve Claim issuer protocol'e katılım için ödemez ve Suiss satın almaya zorlanmaz. (Gelirin hangi ilişkiden — hosting, Experience/tooling, destek — doğduğu H4/H9'dur.)
- **B7** Identity plane bundle'ı opsiyoneldir: Authority plane'in hiçbir özelliği veya fiyatı Suiss Identity kullanımına bağlanamaz; external IdP aynı Acceptance koşullarıyla girer; PartyID/key-event taşınabilirliği ve non-custodial geçiş ücretsiz ve her zaman açıktır.
  - "Suiss Identity" Access'in identity plane'idir (tam IdP). B7 aynen korunur. Identity plane'in tam IdP olması authority plane'i ona bağlamaz.
- **B8** Ticari koşullar first-party neutrality'yi bozamaz: Access ile Work/One/Pay arasında zorunlu bundle yoktur; her biri compatible provider/coordinator ile kullanılabilir; paket indirimi standalone erişilebilirliği ve semantik eşitliği koruduğu sürece serbesttir; third-party provider'ların (rakipler dahil) Access domain'i host etmesi ticari olarak kısıtlanmaz.
- **B9** Conformance suite ve vektörler açık ve ücretsizdir; conformance'ı geçmek Suiss onayı veya Suiss ile ticari ilişki gerektirmez; conformance ≠ endorsement; Suiss-hosted provider aynı suite'e tabidir. (Conformance markasının sahipliği ve Suiss'in sertifika/assessment hizmeti satıp satmayacağı D3'tür.) Identity plane'de OIDF (OIDC OP, FAPI 2, FAPI-CIBA) conformance süiti CI'da açık ve ücretsiz koşulur ve sonuçlar yayınlanır. Resmî OIDF sertifikasyonu OIDF'nin sürecidir. Ücreti Suiss'in ticari ilişkisine bağlanmaz.
- **B10** Çıkış protocol özelliğidir, sözleşme özelliği değildir: export, handover ve recovery ödeme durumuna, sözleşme süresine veya ücrete bağlanamaz; ticari sonlandırma (non-payment dahil) beyanlı bir wind-down ile yapılır: okuma/export/handover penceresi açık kalır, recovery yolu Suiss'e bağlı değildir; hiçbir lisans (self-host dahil) export/handover/replay'i kısıtlayamaz.
- **B11** Savunulabilirlik yalnız healthy kaynaklardan kurulur; data hostage, identity hostage, proprietary canonical format, security paywall, forced ecosystem dependency, exit friction, governance capture, trust-anchor capture, müşteri verisini eğitim/analitik moat'ı yapmak ve availability'yi pazarlık aracı yapmak reddedilir.
- **B12** Doğrulanabilirlik Suiss'in ticari sürekliliğine bağlanamaz: Suiss'in production'da kullandığı her semantik sürümün evaluator'ı açık reference'ta yayınlanır ve korunur; domain kayıtlarının decommission'ı önce export/handover penceresi, sonra crypto-shredding'dir.
- **B13** Suiss, kendi host ettiği domain'ler için ne "bağımsız witness" ne de "provider-dışı replica" olarak sayılabilir ve böyle satılamaz. (Kendi domain'inde bağımsız sayılmayan ek witness olması yasak değildir; başka provider'lardaki domain'lere bağımsız witness/replica hizmeti sunması H10'dur.)
- **B14** Custodial anahtar hizmeti yalnız user-gated sunulur; CT3 tutanlar varsayılan olarak non-custodial'dır (SEC17; Suiss'in CT3 tutanlara custodial hizmeti hiç sunmaması D6'daki ticari tercihtir); recovery entry anahtarları provider'da custody edilemez (SEC20); custodial mod non-custodial'dan ucuz fiyatlandırılamaz ve non-custodial'a geçiş ücretsizdir.
- **B15** Sales, marketing ve SLA dili forbidden claims'e ve beyanlı hard limit'lere tabidir: "anında her yerde iptal", "agent'ı durdurur", "domain başına throughput garantisi", "kayıpsız" (koşulsuz), "trusted agent" gibi iddialar yapılamaz; SLA servis availability'sini kapsar, fiziksel guarantee'leri değil. Yasak ifade listesi ayrıca şunları içerir:
  - "formel olarak doğrulanmış" (niteliksiz)
  - "kiracı izolasyonunu derleyici garanti eder"
  - realm başına veya login/sn throughput garantisi
  - "Keycloak'tan / X'ten hızlı" (performans hedefi EA'dır, §4.10)
  - "oturum her yerde anında kapandı"
  - "passkey ile hesap ele geçirilemez"
  - "authority plane'i olan tek ürün" (ancak beyanlı karşılaştırma kümesi ve tarihle, H olarak; §18.2)

  İzin verilen karşılıklar §3.3a'dadır.
- **B16** Access'in Suiss içindeki rol yapısı: protocol (L0–L3) + hosted infrastructure/provider + product (Identity plane — tam IdP — + Authority plane + S1–S10) + developer service + enterprise control plane; consumer yüzeyi tek Suiss kabuğunda gömülüdür. Suiss-hosted provider protocol'ün bir implementasyonudur.
- **B17** Value metric Authority Exercise'tır (C30 anlamıyla: ilk committed ALLOW ile doğan, kayıtlı, attributable kullanım); value raporlaması Exercise ve onun kayıtlarından türetilir, billing unit'ten ayrıdır (B5).
- **B18** Ücretsiz katılım sınırsız ücretsiz hosting değildir: protocol katılımı her zaman ücretsizdir (B6); bir domain'i Suiss'te host ettirmek ise (bireysel veya organizasyon) fiziksel fair-use veya abonelik ilişkisine tabidir. Bu ilişkinin ticari sınırı (kapasite rezervasyonu, fair-use, paket) aşıldığında yalnız yeni genişletici/nötr commit'ler protocol rejection alır — genişletici yönde fail-closed, sessiz degrade değil; revocation sınıfı Exercise'lar (*.revoke, instance.terminate, restriction ekleyen policy.set, Acceptance daraltma; SEC23 listesi) ve suspend, narrowing sınıfı Claim ingest'i ve export/handover/recover hiçbir ticari sayaca girmez ve ticari tavan nedeniyle reddedilmez; bunlar yalnız SI-20 güvenlik sınırlarına (değerler POLICY DEFAULT) tabidir (bunların reddi authority'yi geniş bırakırdı: authority yönünde fail-open).
- **B19** **Identity plane çıkış ve daraltma yolları ücretsizdir ve hiçbir ticari tavana takılmaz.** Kapsam:
  - Daraltma: logout, oturum iptali, hesap kilitleme, SCIM ve diğer deprovisioning yolları. Bunlar B18 anlamında daraltma sınıfıdır; ticari sayaca girmez ve fair-use aşımında da çalışır.
  - Çıkış: parola hash'lerinin ve TOTP sırlarının self-servis export'u (format ve koruma → §12, §15); pre-hash ve pepper import; PartyID ve key-event taşınabilirliği.
  - Passkey'in RP ID bağlılığı yalnız RP ID **değişirse** taşınamazlık sınırıdır (NG, fiziksel; §18.1 notu). RP ID müşterinin alan adında olduğu için provider değişimi passkey kaybı olarak NG beyan edilmez. Özel alan adının (realm issuer'ı ve WebAuthn RP ID'nin müşterinin alan adında olması) varlığı ücretlendirilemez (§18.6).

  Gerekçe: identity hostage yasağı (B11) ve Z2.
- **B20** **Güvenlik düzeltmeleri her zaman açık sürümde yayınlanır.** Self-host binary'ler dahil hiçbir güvenlik yaması, güvenlik sürümü veya hizmet seviyeli güvenlik düzeltmesi yalnız ticari veya enterprise katmana kilitlenemez. Ücretli destek, düzeltmenin *erken bildirimini veya uygulama yardımını* içerebilir. Erken bildirim CVD ambargosuyla sınırlıdır (→ §14). Düzeltmenin kendisini içeremez. Gerekçe: B3'ün "güvenlik düzeltmeleri ücretlendirilemez" kuralının self-host dağıtımına uzanması. CRA'nın ücretsiz güvenlik güncellemesi şartıyla uyumludur (§18.11).

- **B21** **Access Executor servisi Access ile birlikte sunulur.** Executor Access'in çekirdeği değildir; Access'in sunduğu bir servistir ve ayrı proje olarak geliştirilir (AG-40). Müşteri Access'i alırken hazır servis yürütücülerini (AG-39 kataloğundaki servisler) de alır; müşterinin gözünde tek kurulumdur. Yürütücüler, resmî MCP sunucusu olan servislerde o sunucuyu kullanır; olmayanlar için yürütücü Suiss tarafından yazılır. Müşteri kendi yürütücüsünü aynı kurallarla (kayıt, kimlik doğrulama, iş başına token) bağlayabilir; Access Executor servisi protocol'de ayrıcalıklı bir yol taşımaz.
  Gerekçe: Bağlantıyı sunmayan bir yetki ürünü değerlendirmeye alınmaz; yürütmenin ayrı tutulması Access'in karar mercii rolünü korur.

- **B22** **Access Proxy servisi Access ile birlikte sunulur.** Executor servisi gibi (B21) Access'in çekirdeği değildir; Access'in sunduğu ayrı bir servistir. Envoy ve Caddy motorlarıyla hazır paketlenir (IDP-30). Protocol'de ayrıcalıklı bir yol taşımaz: kiracının kendi proxy'si aynı forward-auth uç noktasıyla aynı kararları alır.
  Gerekçe: Proxy'si olmayan kiracı için "kur, çalışsın" yolu; proxy'nin kendisi yazılmaz, olgun motorlar paketlenir.

- **B23** **İYS entegrasyonu Relay'dedir; Access'in İYS servisi yoktur.** Access pazarlama iznini ve geçmişini kaydeder (IDP-37) ve her değişiklikte bir izin olayı yayınlar (İYS'nin istediği alanlar eksiksiz: izin tarihi, kaynak, kanal, alıcı, alıcı türü). Relay bağlıysa bu olayı alır ve İleti Yönetim Sistemi'ne kendisi yazar; İYS'ye bir marka için tek yazıcı Relay'dir (okuma, yazma, ret senkronu, kota tek yerde). Relay yoksa kiracı olayı kendi İYS entegratörüne iletir. Access İYS'ye hiçbir koşulda doğrudan yazmaz.
  Gerekçe: İYS ticari mesajlaşma işidir. Tek yazıcı çakışmayı ve ortak kota tüketimini önler; 250 bin adresin altındaki markalar zaten yetkili entegratör kullanmak zorundadır. Access İYS olmadan eksiksiz çalışır; pazarlama iletisi göndermez (E40).

- **B24** **Referans ve topluluk.** (1) Suiss ürünleri (Work, Pay, One, Commerce, Serve) Access'in ilk üretim müşterileridir; dış müşterilerle aynı sözleşmeyi kullanır, semantik ayrıcalık yoktur (E24). (2) İlk açık sürümden önce 5–10 dış tasarım ortağı; Türkiye pazarı önceliklidir; erken erişim karşılığında geri bildirim ve referans izni. (3) Başarılı kurulumlar vaka çalışmasına dönüşür; ölçüm verisi OP-61 ile ortaktır. (4) Topluluk: açık yol haritası, protocol için açık öneri (RFC) süreci, forum, katkıcı rehberi (D4 tamamen açık kaynak).
  Gerekçe: Topluluk, referans ve güvenlik geçmişi zamanla kazanılır; kendi ürünlerinde üretim kullanımı ve açık kaynak bu süreyi kısaltır.

B19 ve B20'nin statüsü: FROZEN STRATEGY DECISION (türetilmiş). B21, B22, B23, B24: FROZEN STRATEGY DECISION. Reopen koşulu türetildiği kararların koşuludur.

### 18.8 Current strategic hypotheses (H1–H17)

Her hipotez beş alanlıdır (iddia, neden inanıyoruz, onu ne çürütür, çürürse ne değişir, nasıl test edilir); aşağıda önce tek satırlık özetleri, sonra tam kayıtları vardır. "If false" alanı hiçbir zaman ontology, ownership, protocol, security veya mimari değişikliği içermez (B1).

- **H1** Access IAM-bitişik "authorization / delegated authority for AI agents" alt kategorisinde satın alınır; önde hosted infrastructure + enterprise control plane satılır
- **H2** Primary first adopter: çok-vendor agent'ları consequential işlere bağlayan mid/large org agent/AI platform ekibi
- **H3** Secondary first adopter: son kullanıcı adına eylem yapan agent ürünleri geliştiren AI-native şirketler (end-customer delegation)
- **H4** Ödeyen: domain'i Suiss'e host ettiren organizasyon; bütçe AI platform veya security/IAM
- **H5** Consumer, gömülü yüzeyler üzerinden ve ücretsiz benimser; wedge değildir
- **H6** Primary wedge: bütçeli, süreli, geri alınabilir agent delegation + eşik üstü exact-intent onayı + kayıt (CT2+)
- **H7** En hızlı yol Work ile co-wedge; standalone da satılır
- **H8** Distribution: developer-led benimseme + enterprise sales dönüşümü; PLG ikincil
- **H9** Fiyat: operasyon sınıfı + coarse fiziksel kullanım + opsiyonel tooling; semantik sayaç yok; identity plane'de de MAU, realm, SSO bağlantısı ve login sayısı fatura birimi değildir
- **H10** Ağ etkisi protocol düzeyinde iki taraflı, erken dönemde zayıf; Suiss'e tahakkuku operatör kalitesine bağlı
- **H11** Kalıcı savunma: güvenilirlik, trust, deneyim, integration; semantik öncelik geçici
- **H12** Incumbent'lar yakın vadede vendor-neutral bounded delegated authority sunmaz; Access onların üzerinde **veya yerine** çalışır
- **H13** İkiye ayrılır:
  - **H13a**: Identity bundle consumer/SMB'de değerli; enterprise girişte external IdP varsayılan.
  - **H13b**: Access'in identity plane'i tek başına tam IdP olarak (authority plane'i kullanmadan da) satılabilir. Tam IdP ile authority plane'in tek üründe sunulması ayrıştırıcıdır.
- **H14** Self-host/third-party provider'lar benimsemeyi ve regüle erişimi artırır, yamyamlaştırmaz
- **H15** Cross-org portable authority ve offline/edge genişlemedir, wedge değil
- **H16** Açıklık + neutral governance + ücretsiz conformance benimsemeyi hızlandırır
- **H17** Access dikey/uyum ürünü veya "hafif IdP" olarak konumlanmaz; dikey/uyum ürünü, "hafif IdP" ve yalnız geliştirici aracı konumlandırmalarının dışarıda kalması yetenek dışlaması değil konumlandırma tercihidir

#### 18.8.1 Tam kayıtlar

##### H1 — Kategori ve rol önceliği
- **Hypothesis:** Access kısa vadede IAM-bitişik "authorization / delegated authority for AI agents" alt kategorisi altında satın alınır; Suiss içinde önde satılan roller **hosted infrastructure + enterprise control plane**'dir, protocol arka planda güvence olarak anlatılır.
- **Why:** Incumbent'lar identity'yi çözüyor, bounded delegated authority'yi çözmüyor (L2); Work aynı disiplini uyguluyor (§27.5); yeni kategori yaratmak wedge kanıtından önce pahalı.
- **Supporting evidence:** Pilot alıcılarının bütçeyi IAM/security/AI platform kalemlerinden ayırması; RFP'lerde "agent authorization", "delegation", "approval evidence" gereksinimleri.
- **Falsifier:** Alıcıların ≥ çoğunluğu Access'i yalnız mevcut IdP vendor'ının özelliği olarak satın almayı kabul edip ayrı tedarikçiyi reddetmesi.
- **If false:** Access, IdP'lerin arkasında **AuthZEN PDP / authority provider** olarak OEM/partner kanalından dağıtılır; protocol ve hosted provider değişmez, yalnız kanal ve mesaj değişir.

##### H2 — Primary first adopter
- **Hypothesis:** İlk benimseyen, birden çok vendor'ın agent'larını consequential işlere (harcama, dış sisteme yazma, prod değişikliği) bağlayan **mid/large organizasyonun agent/AI platform ekibi**dir.
- **Why:** Work §24.3 aynı buyer'ı tanımladı; agent'a eylem yetkisi verme kararı platform ekibinde toplanıyor; Access'in değeri PEP sorduğunda doğar (E28) ve PEP'i bu ekip kurar.
- **Supporting evidence:** Tasarım ortaklarında ilk 90 günde ≥ 1 production PEP; REQUIRE_ACTION/budget kullanımı; platform ekibinin security'yi sürece kendisinin çekmesi.
- **Falsifier:** Platform ekiplerinin authority'yi "security'nin işi" sayıp benimsememesi ve ilk temasın sürekli CISO/IAM ekibinden gelmesi.
- **If false:** Primary buyer IAM/security ekibi olur; wedge mesajı "agent'ların yaptığı her şeyin kanıtlanabilir yetkisi" (S9/S6 önde) olur; ürün aynı.

##### H3 — Secondary first adopter (AI-native, B2B2C)
- **Hypothesis:** Son kullanıcı adına eylem yapan agent ürünleri geliştiren AI-native şirketler, **end-customer delegation**'ı (X30: tek seferlik vs kalıcı yetki, iptal edilebilir merchant yetkileri) kendileri yazmak yerine Access'ten alır.
- **Why:** Bu şirketlerin kendi kullanıcılarına "agent'ın neyi yapabileceğini" güvenle sunması gerekir; Ödeme alanındaki precedent'ler (AP2, SPT) bu ihtiyacın gerçek olduğunu gösterir.
- **Supporting evidence:** Developer sandbox → production dönüşümü; end-customer onay/iptal akışlarının kullanılması.
- **Falsifier:** Bu şirketlerin ödeme ağlarının kendi mandate mekanizmalarıyla yetinmesi.
- **If false:** B2B2C wedge'i Pay ile birlikte, ödeme dışı consequential action'lara (rezervasyon, veri paylaşımı, hesap değişikliği) daraltılır.

##### H4 — Payer ve bütçe
- **Hypothesis:** Ödeyen, domain'i Suiss'e host ettiren organizasyondur; bütçe ilk aşamada AI platform veya security/IAM kaleminden gelir.
- **Why:** B6 kim ödemeyeceğini belirler; geriye domain controller'ı kalır. Bütçe kalemi H1'e bağlıdır.
- **Supporting evidence:** Satın alma onaylarının kaynağı; deal başına imza atan fonksiyon.
- **Falsifier:** Organizasyonların hosted provider yerine **self-host**'u ezici çoğunlukla seçmesi (Suiss'e hosting geliri doğmaması).
- **If false:** Gelir merkezi destek/SLA aboneliğine ve yönetilen hizmetlere kayar (H14, D4); protocol ve self-host hakkı değişmez.

##### H5 — Consumer adoption yolu
- **Hypothesis:** Bireysel principal Access'i kendi başına aramaz; gömülü yüzeyler (One, Work, Pay; third-party agent uygulamalarının delegation sayfaları) üzerinden benimser ve ücretsiz kalır.
- **Why:** X4 IA kararı (tek kabuk, Access gömülü bileşen); consumer ödeme isteği kanıtlanmadı; Work'ün "free participation" ilkesi.
- **Supporting evidence:** Gömülü delegation yüzeylerinden gelen aktif principal sayısı; kişisel domain'lerde revoke/inventory kullanımı.
- **Falsifier:** Bireylerin bağımsız bir "my agents' authority" uygulamasını aktif olarak araması ve ödemeye istekli olması.
- **If false:** Consumer abonelik katmanı (konfor/kapasite; güvenlik değil — B3) eklenir; ontology ve B5 aynı.

##### H6 — Primary wedge
- **Hypothesis:** Wedge "agent'a bütçeli, süreli, geri alınabilir yetki + eşik üstünde exact-intent onayı + her kullanımın kaydı"dır (CT2+ consequential action'lar).
- **Why:** Incumbent'lar kimliği çözüyor, bounded delegated authority'yi değil (L2); delegation'ı first-class taşıyan tek deploy edilmiş örnekler ödeme alanında (L15) — ihtiyaç gerçek, genel çözüm yok.
- **Supporting evidence:** Pilotlarda BudgetTerm ve RequirementTerm kullanımı; REQUIRE_ACTION → onay → ALLOW döngüsünün haftalık kullanımı; revoke/narrow kullanımı.
- **Falsifier:** Pilotlarda organizasyonların OAuth scope + IdP agent özellikleriyle yetinmesi; budget/approval kullanılmaması.
- **If false:** Wedge denetim/kanıt (S6/S9) tarafına kayar veya IdP arkasında PDP konumu (H1 alternatifi) seçilir; ürün aynı.

##### H7 — Work ile co-wedge, standalone erişilebilirlik
- **Hypothesis:** En hızlı ticari yol Work'le birlikte satıştır; Access standalone da satılabilir.
- **Why:** Work wedge'inin authority yarısı Access'tir (E7; Work §24.4); aynı buyer (H2).
- **Supporting evidence:** Work deal'lerinde Access eki oranı; Work kullanmayan third-party coordinator'larla Access deal'leri.
- **Falsifier:** Access'in standalone satışlarının ihmal edilebilir kalması.
- **If false:** Access ticari olarak Work'ün bileşeni gibi paketlenir; **standalone erişilebilirlik, protocol açıklığı ve no-mandatory kuralı aynen kalır** (B8).

##### H8 — Distribution
- **Hypothesis:** Developer-led benimseme (açık SDK, sandbox, decision lab, MCP/A2A profilleri) + enterprise sales dönüşümü; PLG ikincil.
- **Why:** Access'in değeri PEP entegrasyonunda doğar; Work §24.5 enterprise sales primary, developer ecosystem supporting motion.
- **Supporting evidence:** Sandbox'tan production'a dönüşüm; SDK indirme → production domain oranı; MCP server'larda Access profile'ı benimsemesi.
- **Falsifier:** Developer benimsemesinin enterprise anlaşmalarına dönüşmemesi (yalnız hobi/sandbox kullanımı).
- **If false:** Satış öncelikli, tasarım-ortaklı kurumsal motion; developer araçları ücretsiz kalır (B3).

##### H9 — Fiyat yapısı
- **Hypothesis:** Organizasyon aboneliği = hosted operasyon sınıfı + coarse fiziksel kullanım (rezerve kapasite — yalnız genişletici/nötr commit'ler için, B5 koşullarıyla; policy minimumu üstü retention) + opsiyonel enterprise tooling; sayısal semantik nesne başına ücret yok.
- **Why:** B5 semantik sayaçları reddeder; Work §24.1 "usage charges reflect physical infrastructure consumption rather than semantic object count"; IAM alıcıları abonelik modeline alışkın [doğrulanmadı].
- **Supporting evidence:** Pilotlarda willingness-to-pay; tahmin edilebilirlik itirazlarının düşük olması; kapasite rezervasyonunun ValidityContract sürelerini uzatma baskısı yaratmaması (§9.4 residual); rezervasyon aşımlarının yalnız genişletici/nötr commit'lerde, nadir ve müşteriye görünür availability sinyali olarak kalması.
- **Falsifier:** Alıcıların fiyatı tahmin edememesi (fiziksel kapasite soyut gelir), kapasite rezervasyonu nedeniyle PEP'lerin horizon'ları uzatmaya zorlanması veya rezervasyon aşımlarının consequential iş akışlarında sık availability kesintisi üretmesi.
- **If false:** İkincil eksen olarak **admin/audit console koltuğu** veya org büyüklüğü bandı (yalnız raporlama/tahmin için; semantik sayaç değil) eklenir; B5'in reddettiği birimler hiçbir koşulda girmez.

##### H10 — Network effects
- **Hypothesis:** Ağ etkisi protocol düzeyinde iki taraflıdır (issuer domain'ler ↔ verifier'lar; schema publisher'lar ↔ domain'ler) ve erken dönemde zayıftır; Suiss'e tahakkuku operatör kalitesine bağlıdır.
- **Why:** Doğrulama açık ve ücretsiz (P32); schema yayını governance'sızdır.
- **Supporting evidence:** Suiss dışı verifier sayısı; birden çok domain tarafından kabul edilen schema sayısı; Suiss dışı provider'larda host edilen domain'ler.
- **Falsifier:** Verifier ve publisher'ların yalnız Suiss-hosted domain'lerle etkileşmesi (ağın fiilen tek-vendor kalması).
- **If false:** Protocol benimsemesine (ikinci implementasyon, governance, upstream profile'lar) yatırım artırılır; Suiss-özel ağ kurmaya **dönülmez** (B11).

##### H11 — Defensibility kaynakları
- **Hypothesis:** Kalıcı savunma operasyonel güvenilirlik, trust, deneyim ve integration yoğunluğundan gelir; semantik öncelik geçicidir.
- **Why:** Spec açık (P1); exit protocol'de (P4); framework §10.2.
- **Supporting evidence:** Kayıp müşteri nedenlerinde "fiyat/özellik" yerine "güvenilirlik/deneyim" lehine kalış; handover yapabildiği hâlde kalan müşteri oranı.
- **Falsifier:** Müşterilerin aynı spec'i uygulayan daha ucuz provider'a hızla geçmesi.
- **If false:** Operasyon maliyeti ve deneyim yatırımı yeniden önceliklendirilir; kilitlenme mekanizmasına **başvurulmaz** (B11).

##### H12 — Rekabet konumu
- **Hypothesis:** Incumbent IAM ve agent identity ürünleri yakın vadede bounded delegated authority'yi (provenance + attenuation + budget + exercise record) vendor-neutral biçimde sunmaz; Access onların **üzerinde** çalışarak kazanır.
- **Why:** §2.3 vendor paketleri; incumbent'ların kendi ekosistemine kilitli olması (Entra/M365, AWS) [doğrulanmadı].
- **Supporting evidence:** Rakip ürün duyurularında provenance/attenuation eksikliği; çok-vendor alıcıların tarafsız katman talebi.
- **Falsifier:** Bir incumbent'ın aynı semantiği (özellikle cascade revocation, lineage budget, exact-intent approval, exportable exercise record) çok-vendor ve açık biçimde sunması.
- **If false:** Access o incumbent'la **protocol uyumu** arar (aynı profile'ları konuşmak, H16), Suiss'in farkı operasyon ve deneyime çekilir; ontology değişmez.

##### H13 — Identity plane bundling'in ticari değeri
- **Hypothesis:** Identity plane bundle'ı consumer ve küçük işletmede değerlidir (passkey, user-gated custody, tek kurulum); enterprise girişte IdP'yi değiştirmek wedge'i ağırlaştırır, bu yüzden enterprise'da external IdP varsayılandır.
- **Why:** Bundling gerekçeleri (assurance, instance binding, recovery); E18 external IdP eşit; enterprise'larda IdP yerleşik [doğrulanmadı].
- **Supporting evidence:** Consumer/SMB'de Suiss Identity seçme oranı; enterprise pilotlarında IdP değişimi talebinin olmaması.
- **Falsifier:** Enterprise alıcıların tek-vendor identity + authority istemesi (Suiss Identity'yi workforce IdP olarak talep etmesi).
- **If false:** Enterprise için Suiss Identity workforce paketi konumlandırılır — **identity hostage koruması aynen** (B7: non-custodial geçiş, PartyID taşınabilirliği, external IdP eşitliği).

##### H14 — Self-host ve third-party provider'lar
- **Hypothesis:** Self-host ve third-party provider'lar Suiss gelirini yamyamlaştırmaktan çok benimsemeyi ve regüle sektör erişimini artırır.
- **Why:** Regüle kurumlar (finans, kamu) veri yerleşimi ve operasyonel kontrol ister; açık protocol güven yaratır (H16).
- **Supporting evidence:** Self-host kurulumlarının sonradan destek/SLA aboneliğine veya hybrid'e (bazı domain'ler hosted) dönüşmesi.
- **Falsifier:** Self-host'un hosted talebini belirgin biçimde ikame etmesi ve destek gelirinin bunu karşılamaması.
- **If false:** Hosted değer önerisi (operasyon, SLA, witness/replica orkestrasyonu, deneyim) güçlendirilir; self-host hakkı ve açık çekirdek **daraltılmaz** (B2, B10).

##### H15 — Cross-org ve offline genişleme
- **Hypothesis:** Cross-org portable authority ve offline/edge, wedge değil genişlemedir; ağ yoğunluğu oluştukça değer kazanır.
- **Why:** N1/N4 iki tarafın da protocol konuşmasını gerektirir; offline donanım entegrasyonu ister (T25).
- **Supporting evidence:** Wedge müşterileri arasında ilk iki-taraflı Grant/PAP akışları; edge dikeyinde tasarım ortağı.
- **Falsifier:** Tek başına cross-org (ör. merchant mandate) veya offline (ör. POS) kullanımının wedge'den hızlı büyümesi.
- **If false:** Sıra değişir (cross-org veya offline öne alınır); ürün ve protocol aynı.

##### H16 — Açıklık ve conformance benimsemeyi hızlandırır
- **Hypothesis:** Açık protocol + neutral governance + ücretsiz conformance, regüle alıcıları ve rakip vendor'ları benimsemeye ikna eder.
- **Why:** Work §21.2 aynı strateji; Suiss protocol'ü tek başına değiştiremez.
- **Supporting evidence:** Bağımsız ikinci implementasyon; upstream'e kabul edilen profile üyeleri (AuthZEN, SSF); RFP'lerde "open protocol / exit" kriteri.
- **Falsifier:** Açıklığın alıcı kararında ölçülebilir etkisi olmaması.
- **If false:** Açıklık **değişmez** (P1 frozen); yalnız ona yapılan pazarlama/standart yatırımı azaltılır.

---

#### 18.8.2 Identity plane ekleri ve ek hipotezler

**H9 — identity plane eki**:
- **Ek hipotez:** Identity plane de aynı eksenle fiyatlanır. Eksen hosted realm operasyon sınıfı, login/Argon2 kapasite rezervasyonu, policy minimumu üstü retention ve tooling'dir. MAU, realm, SSO bağlantısı veya login sayısı fatura birimi değildir (B5).
- **Why (ek):** Paylaşılan hesaplar ve attribution kaybı (MD-17). MAU fiyatı, ayrılan kullanıcıyı deprovision etmeme yönünde ekonomik baskı yaratır (çıkarım).
- **Supporting evidence (ek):** MAU modeline alışkın alıcıların operasyon sınıfı modelini tahmin edilebilir bulması.
- **Falsifier (ek):** Identity alıcılarının MAU dışı modeli karşılaştırılamaz bulup reddetmesi. Bir diğer falsifier: kapasite rezervasyonunun login zirvelerinde (kampanya, Black Friday) sık 503 üretmesi.
- **If false (ek):** Yalnız raporlama ve tahmin için MAU bandı gösterilir. Fatura birimi yapılmaz (B5). İkinci eksen olarak admin/audit console koltuğu kullanılır (§18.5 ALTERNATİF satırı).

**H12 sınama notu**: H12'nin falsifier'ı iki yönlüdür:
- (i) Bir incumbent aynı authority semantiğini sunarsa §18.8.1'deki falsifier geçerlidir.
- (ii) Bir **IdP projesi** (açık kaynak dahil; §4.6 envanteri) authority plane semantiğini tam IdP ile tek üründe sunarsa, H13b ve §18.2'deki "tek ürün" cümlesi düşer.

Envanterdeki projelerin hiçbirinde provenance + attenuation + budget + exportable exercise record birleşimi bulunamamıştır (reviewed landscape; §4.7). Bu "ilk biz" anlamına gelmez (§3.4). OQ-2'de (→ §20) yeniden sınanır.

**H13a** — §18.8.1'deki H13 kaydıdır. Bu kayıttaki "Suiss Identity" Access'in identity plane'idir.

**H13b — Tam IdP olarak ayrı değer**
- **Hypothesis:** Access'in identity plane'i, authority plane'e geçmeden de tek başına satın alınabilir tam bir IdP'dir. Bir kez kurulduğunda authority plane'e geçiş, ayrı bir authority ürünü benimsemekten ucuzdur.
- **Why:** MD-13 kapsamı daraltmaz. IdP envanteri, açık kaynak ve self-host IdP pazarının büyük ve parçalı olduğunu gösterir (§4.6). Identity plane admin config'inin ADP üzerinden `idp.*` domain action Exercise'ı olarak yetkilendirilmesi (MD-14) authority plane'i IdP'nin kendi yönetiminde zaten kullandırır (çıkarım: geçiş sürtünmesini azaltır).
- **Supporting evidence:**
  - Yalnız identity plane ile başlayan kurulumların authority plane'e (PEP, Grant, REQUIRE_ACTION) geçiş oranı.
  - Keycloak/Auth0/Zitadel'den göç taleplerinde hash/TOTP export ve import yolunun (B19) belirleyici olması.
- **Falsifier:**
  - Alıcıların tam IdP'yi yalnız olgun incumbent'lardan almayı sürdürmesi.
  - Identity plane'in bakım ve uyum maliyetinin (OIDF conformance, CRA, crystal-box denetim) authority wedge'ine ayrılacak kapasiteyi yemesi.
- **If false:** Identity plane ürünün parçası kalır (F21 FROZEN; MD-13). Satış ve yol haritası önceliği authority wedge'ine (H6) çekilir. Tam IdP özellikleri daraltılmaz; yalnız tanıtım ve yatırım sırası değişir.

**H17 — Konumlandırma: dikey/uyum ürünü değil**
- **Hypothesis:** Dikey uyum ürünü, "hafif IdP" ve yalnız geliştirici aracı konumlandırmalarının dışarıda kalması yetenek dışlaması değildir. Bunlar Access'in genel amaçlı identity + authority plane olarak konumlanmasının sonucudur. Uyum gereksinimleri (CRA, PSD2 SCA, PCI audit penceresi) karşılanır ama ürün bunlar üzerinden satılmaz.
- **Why:** MD-13 "kapsam daraltma yok" der. Access'in farklılaşma maddeleri dikey değil, yatay güvenlik özellikleridir (§4.7).
- **Supporting evidence:** RFP'lerde Access'in genel IAM veya agent authorization kalemi altında değerlendirilmesi.
- **Falsifier:** İlk ödeyen müşterilerin çoğunluğunun Access'i belirli bir uyum gereksinimi için (ör. yalnız PSD2 SCA) satın alması.
- **If false:** Bir dikey paket (şablon + rapor) konfor/tooling olarak sunulabilir (B4). Ürün sınırı ve plane ataması değişmez (B1).

### 18.9 Decisions requiring Adem (D1–D9, D-10, D-11 aday)

Belgelerde dayanağı olmayan ticari tercihlerdir. Her birinin recommended default'u bir H gibi okunur; hiçbiri freeze edilmez ve her default B1–B20 içinde kalır.

| D | Karar | Recommended default | Neden bu default | Neyle değişir |
|---|---|---|---|---|
| **D1** | Fiyat düzeyleri ve paket adları | Rakam yok. Yapı H9 (operasyon sınıfı + fiziksel kapasite + opsiyonel tooling); ilk pilotlarda tasarım-ortağı fiyatı + ölçüm | Willingness-to-pay kanıtı yok | Pilot WTP, kazanılan/kaybedilen deal'ler (OQ-3) |
| **D2** | İlk pazar (ülke/bölge) ve ilk dikey | Ülke seçilmez; ilk tasarım ortakları H2 profiline göre seçilir; residency sınıfı ortağın ihtiyacına göre açılır | Coğrafya dayanağı yok | Tasarım ortaklarının yerleşimi ve regülasyon |
| **D3** | Protocol governance kuruluşu, conformance markası ve kullanım koşulları, Suiss'in sertifika/assessment hizmeti satıp satmayacağı, upstream zamanlaması | L0/L2/L3 ve Witness / Approval Surface / Party regime profile'ları Work Protocol ile ortak, **mevcut neutral bir vakıf/SDO** altında (PI-18); L1 üyeleri ilgili upstream WG'lere (AuthZEN, SSF/CAEP, OAuth RAR); conformance markası governance kuruluşunundur; Suiss sertifika/assessment hizmeti satmaz (B9'un frozen kısmı her durumda geçerlidir); ilk yayın wedge pilotlarından sonra, ikinci implementasyon hedefiyle | Suiss'in tek başına değiştirememesini şart koşar; yeni kuruluş kurmak pahalıdır | Ortak katılımcıların tercihi; patent politikası (OQ-5) |
| **D4** | Lisanslar: Access'in bütün bileşenleri | **KARAR (Adem): Access tamamen açık kaynaktır.** Kapsam: Access Core, Kernel, identity plane ve authority plane sunucuları, kenar gateway'ler, konsol, Experience backend, analitik ve policy araçları, SDK'lar (T41), Offline Verifier Core, reference evaluator/verifier, conformance suite, replica agent ve Access'in sunduğu servisler (Executor, Access Proxy; B21, B22). Kapalı kaynak sürüm veya kapalı "enterprise" özelliği yoktur. Ticari gelir hizmetten gelir: Suiss-hosted işletim, destek ve SLA aboneliği, yönetilen onboarding, ayrılmış altyapı (B4). Lisans: **Apache License 2.0** (izin verici + açık patent hakkı); depo kökündeki `LICENSE` dosyası. Hiçbir lisans export / handover / replay / protocol kullanımını kısıtlayamaz (B10); protocol yolu Suiss binary'si gerektirmez (TI-17) | Açık bileşenler açık kaynaktır (T12); protocol telifsiz uygulanabilir | Hukuk; topluluk geri bildirimi |
| **D5** | Suiss-hosted domain'lerde ≥ 1 Suiss-dışı witness ve root-kontrollü replica'nın pratik temini, özellikle consumer | Org: domain root'u witness operatörünü ve replica depolamasını seçer; Suiss açık replica agent + witness listesi sunar. Consumer: Suiss, provider'dan ve operatöründen bağımsız (SI-12) ≥ 1 witness operatörü ve ≥ 1 provider-dışı replica operatörü **önerir** ve maliyetini üstlenebilir. Koşullar: (i) witness/replica tanımı root'un Genesis / Domain Metadata beyanıdır (P32, SEC23); Suiss default'u yalnız önerir, root kabul eder veya başka operatör seçer; (ii) Suiss beyan edilmiş witness/replica'yı tek taraflı değiştiremez veya sonlandıramaz; **Suiss'in witness/replica ödemesini kesmesi sonlandırma sayılır ve yalnız B10 wind-down ile yapılabilir** (root'a yeni operatör seçme penceresi); (iii) ödeme ilişkisi beyanlıdır; (iv) bu düzenlemenin SI-12'yi fiilen karşıladığı OQ-4 kanıtıyla gösterilene kadar yüzeyler U9/U10 dilini yalnız XI-12 koşullarıyla kullanır. **Fallback** (OQ-4 olumsuz çıkarsa): root'un Suiss'ten bağımsız seçip ödediği operatör, dağıtım ortağının witness'ı veya Work Witness profile ağı; bu D5/D7/H5'i değiştirir, SI-12/SEC23/P32'yi değil | T21/SEC23 zorunluluğu; SI-12; P32 (witness seçimi domain'indir); consumer'ın kendi altyapısı yoktur. Not: Suiss'in ödediği düzenleme SI-12 ve P32 ile yapısal olarak uyumludur (koşul (i)–(ii)); fiilî bağımsızlık OQ-4'tedir | Witness ağının olgunluğu; düzenlemenin SI-12'yi karşılayıp karşılamadığı (OQ-4) |
| **D6** | Custodial anahtar hizmetinin sorumluluk, sigorta ve denetim çerçevesi | SOC 2 Type II benzeri bağımsız denetim + görev ayrılığı (SEC19) beyanı; DL-1 her sözleşmede açık; sorumluluk sınırı hukuk tavsiyesiyle. **CT3 tutanlara custodial hizmet sunulmaz** (ticari tercih; SEC17 varsayılanının ötesinde) | SEC17–SEC19; DL-1 | Hukuk/sigorta piyasası |
| **D7** | Ücretsiz katmanların sınırları (kişisel domain, developer sandbox) | Kişisel domain ve hosted developer sandbox domain'i **ücretsiz**, yalnız fiziksel fair-use (kapasite/depolama) sınırıyla; aşımda yalnız yeni genişletici/nötr commit'ler protocol rejection alır, sessiz degrade yoktur; revoke/narrow/suspend/terminate, narrowing Claim ingest'i, export ve handover/recovery fair-use aşımında da çalışır (yalnız SI-20 güvenlik sınırları; B18) | B3, B5, B18 | Consumer maliyet profili (D5 dahil) |
| **D8** | Lansmanda Access standalone mı, yalnız Work ile mi satılır | **İkisi de**; satış eforu Work co-wedge'inde (H7); standalone fiyat listesi yayınlanır | B8: zorunlu bundle yok; standalone erişilebilirlik B'dir, efor dağılımı H'dir | H7 kanıtı |
| **D9** | Suiss'in OIDF trust anchor veya schema katalog görünümü işletip işletmeyeceği | İşletir ama **opsiyonel**, ücretsiz ve hiçbir domain'in kabul zorunluluğu olmadan; katalog registry değil, keşif görünümüdür | Anti-hostage kuralları (§9.17) izin verir, zorunlu kılmaz | Ekosistem talebi |

---

**D4 kapsam notu**:
- D4 identity plane sunucu binary'sini, IdP SDK'larını (RP, MCP client/server profili) ve Kernel Wasm paketini (MD-1) de kapsar.
- Karar: Access tamamen açık kaynaktır (yukarıdaki D4 satırı). Self-host kullanımı tamamen ücretsizdir; ücretli olan destek/SLA aboneliği ve Suiss-hosted hizmettir.
- Lisans biçimi **Apache License 2.0**'dır (Adem kararı): benimsemeyi kolaylaştırır, açık patent hakkı verir; gelir kodu kapatmaya değil hizmete dayandığı için izin verici lisans iş modeliyle uyumludur. Çift lisans (kapalı ticari sürümle) tamamen açık kaynak kararıyla dışlanır. Bu bölüm lisansları iyi/kötü diye yargılamaz. Pazardaki seçenekler yalnız bilgi olarak §18.10'dadır.
- Her seçenek şu kısıtlar içinde kalır: B2, B8, B10, B12, B20, TI-17.

**D-10 — CRA rolü**

| Karar | Recommended default (MD-12) | Neden bu default | Neyle değişir |
|---|---|---|---|
| Suiss'in CRA kapsamındaki rolü (manufacturer / open-source steward / kapsam dışı) ve ürün sınıfı | Self-host binary, SDK ve mobil bileşenlerde Suiss **manufacturer** kabul edilir. Varsayılan sınıf **Class I**'dir. Art.14 PSIRT runbook'u ve CRA-C1…CRA-C3 hemen kurulur: CRA-C1 açık zafiyet kabul kanalı (security.txt, SECURITY.md); CRA-C2 CVD süreci ve GHSA; CRA-C3 CNA (GitHub CNA yeterli, kendi CNA'sı gerekmez). MD-12'deki "C1–C3" = CRA-C1…CRA-C3; ontology C1–C3 ile karışmaz. Hukuki görüş paralel yürür | Ücretli destek/SLA aboneliği (D4) ve hosted hizmet ticarileşme sayılabilir (çıkarım). Paraya çevrilmeyen FOSS muafiyeti bu durumda dayanak olmayabilir. Spec "Adem kararı bekleniyor; varsayılan bu" diye yazar | Hukuki görüş; Class I/II sınıflandırması (IdP'nin "identity management" ürün kategorisine düşüp düşmediği → §14); ayrı steward tüzel kişisi kurulup kurulmaması |

**D-11 (aday) — Kurumsal SSO fiyatlaması**

| Karar | Recommended default | Neden bu default | Neyle değişir |
|---|---|---|---|
| Kurumsal SSO (SAML/OIDC upstream federasyonu) hiçbir pakette ücretli olmayacak mı ("SSO tax" reddi) | **Ücretsiz.** Bağlantının *varlığı* ücretlendirilmez. Self-servis kurulum portalı da ücretsizdir (TN-134). Yalnız yönetilen onboarding (insan desteği) konfor olarak ücretlendirilebilir (B4) | Bağlantı başına fiyat Goodhart testinde REJECT'tir (§18.5). Phishing-resistant kurumsal kimlik doğrulama ve merkezi deprovisioning güvenlik yüzeyidir (B3 gerekçesi) | Pilotlarda SSO'nun enterprise paket kararındaki ağırlığı. Bu karar B5'in reddettiği birimleri geri getiremez |

Statü notu: D-11 merkezi kararlarda (MD-1…MD-20) yoktur; B3/B5'ten türetilmiş **aday**dır ve Adem kararı bekler. D-10 CRA rolüne ayrılmıştır (MD-12, MD-20); identity paywall yasağı ayrı bir D kararı değil, B19 türetimidir.

### 18.10 Lisans seçenekleri — yalnız bilgi

Adem kuralı: bu tablo lisansları iyi veya kötü diye yargılamaz. Yalnız pazarda gözlenen seçimleri listeler. Karar D4'tür.

| Proje | Lisans | Gözlenen hareket |
|---|---|---|
| Keycloak | Apache 2.0 | Değişmemiş; uzun dönem destek ayrı ticari ürün üzerinden |
| Zitadel | Apache 2.0 → AGPL 3.0 (v3, 31 Mart 2025 yürürlüklü) | Yalnız yeni katkılar yeni lisansta; önceki sürümler eski lisansta; SDK'lar mevcut lisansını korur; ticari lisans mevcut |
| Ory | Apache 2.0 + kurumsal lisans | Hizmet seviyeli güvenlik sürümleri, havuzlama ve bazı veritabanı destekleri kurumsal lisansta |
| SuperTokens | Çekirdek Apache 2.0 + lisans anahtarlı premium | — |
| Casdoor | Apache 2.0 | — |
| Kanidm | MPL 2.0 | Dosya bazlı karşılıklı paylaşım |
| Pocket ID | BSD 2-clause | — |

Pazar gözlemi (bilgi; birincil kaynaktan doğrulanmadı): IdP alanında iki baskın strateji vardır. Biri AGPL + ticari çift lisans, diğeri Apache 2.0 + kapalı kurumsal katmandır. Bu gözlem Access için bağlayıcı değildir.

**Hangi seçenek olursa olsun geçerli kısıtlar (FROZEN):**
- B2: protocol telifsizdir.
- B8: third-party provider'lar ticari olarak kısıtlanmaz.
- B10: hiçbir lisans export/handover/replay'i kısıtlayamaz.
- B12: production'daki her semantik sürümün evaluator'ı açık reference'tadır.
- B20: güvenlik düzeltmeleri açık sürümdedir. Not: Ory'deki "hizmet seviyeli güvenlik sürümleri kurumsal lisansta" modeli Access için B20 ile dışlanır. Bu, lisans hakkında bir yargı değil, B3'ten türeyen bir kuraldır.
- TI-17: protocol yolu Suiss binary'si gerektirmez.

### 18.11 CRA

- **Rol:** D-10 (Adem kararı bekler; varsayılan manufacturer, Class I).
- **Tarihler** (birincil kaynaktan doğrulanmadı):
  - Bölüm IV: 11 Haziran 2026.
  - Art.14 bildirim yükümlülüğü (manufacturer): 11 Eylül 2026.
  - Tam uygulama: 11 Aralık 2027. Steward'ların raporlaması da bu tarihte başlar (Art.24(3) üzerinden).
  - Bugün (2026-10-06) itibarıyla, manufacturer varsayımı altında, Art.14 yükümlülüğü piyasaya sürülmüş ürün için **zaten yürürlüktedir** (çıkarım). Bu yüzden PSIRT runbook'u ve CRA-C1…CRA-C3 "hemen" kurulur (MD-12).
- **Bildirim süreleri:**
  - Erken uyarı: 24 saat.
  - Bildirim: 72 saat.
  - Nihai rapor: düzeltici önlemden sonra 14 gün (aktif istismar edilen zafiyet) veya bildirimden sonra 1 ay (ciddi olay).
- **Ticari sonuçlar:**
  - SBOM, VEX ve provenance ücretsizdir (B3).
  - Güvenlik güncellemeleri açık sürümdedir (B20).
  - CRA uyumu ürünün konumlandırması değildir (H17).

### 18.12 Bağımsız denetim ve fonlar

- **Karar (MD-16):**
  - Custodial hizmet için SOC 2 Type II kalır (D6).
  - Identity plane, Kernel, verifier'lar ve kripto için periyodik **crystal-box** kod denetimi yapılır. İlki ilk açık sürümden önce.
- **Model (bilgi):** Rauthy denetimi (Radically Open Security; NGI Zero Core fonlu; crystal-box; rapor v1.0, 15 Eylül 2025). Bulgular mimari kripto kırılması değil, klasik web ve implementasyon hatalarıdır: SVG XSS, sabit zamanlı olmayan karşılaştırma, `unwrap` panic, depoda gömülü anahtar, bağımlılık CVE'si. Bu desenler regresyon test setine girer (→ §14).
- **Fon ve program seçenekleri (bilgi; tarihler ve tutarlar birincil kaynaktan doğrulanmadı):**

| Program | Bilgi | Not |
|---|---|---|
| NGI Zero Commons Fund (NLnet) | Çağrı 2026-06Z; son başvuru 1 Haziran 2026; toplam 6,1 M EUR; ilk başvuru ≤ 50 k EUR, sonrakiler ≤ 150 k EUR; ROS denetimi ayni destek olarak | **Son tarih geçmiştir** (bugün 2026-10-06). Sonraki çağrı doğrulanmadı |
| OSTIF | Kâr amacı gütmeyen; denetim koordinasyonu ve lojistik | Dolar rakamı doğrulanamadı |
| Alpha-Omega (OpenSSF/LF) | > 70 hibe, > 20 M USD; Mart 2026'da 12,5 M USD ek fon | Rust ekosistemini fonlamış (rustls, crates.io Trusted Publishing) |
| Sovereign Tech Agency / Fund (DE) | 2026'da aktif; Fund, Fellowship, Standards, EU-STF pilotu | — |

- **Ticari ilke:** Denetim raporları yayınlanır (çıkarım: B9/B12 doğrulanabilirlik ruhuyla). Denetim "Suiss sertifikası" olarak satılmaz (B15).
- **OIDF sertifikasyon ücreti (bilgi):**
  - Üye: 700 USD/dağıtım.
  - Üye olmayan: 3.500 USD/dağıtım.
  - FAPI-CIBA üye toplamı: 1.000 USD. Pilot profiller ücretsizdir.

  Aynı kaynağa göre "sertifika talep eden OIDF üyesi olmalıdır". Bu iki bilgi birbiriyle gerilimdedir ve doğrulanmamıştır.

### 18.13 Yol haritası ve efor

- **Sıralama ilkesi:**
  - Wedge sırası H6/H7'dir.
  - ADP (identity plane admin config = ADP üzerinden `idp.*` domain action; MD-14) **Faz 1'e girer** (L23 notu). Identity plane'in ilk sürümü authority plane'in ADP'si olmadan yayınlanmaz, çünkü ayrı bir "admin token" sınıfı yoktur (MD-14).
- **Faz içerikleri:** Bileşen bazında → §16 ve §17. Bu bölüm yalnız ticari sırayı verir:
  - Faz 1: identity plane çekirdeği (OIDC/OAuth 2.1 AS, passkey, oturum, SCIM, export/import) + ADP + PEP SDK + exercise record.
  - Faz 2: wedge (bütçeli agent delegation, REQUIRE_ACTION, revoke; MCP profili).
  - Sonrası: enterprise protokolleri (SAML, LDAP, Kerberos, RADIUS, WS-Fed), cross-org, offline (H15).

  Not: Bu faz listesi ticari bir çıkarımdır ve yapım sırasını belirlemez. **Bağlayıcı yapım sırası Ek B'deki aşamalardır** (Aşama 0–14); ayrı bir "ilk sürüm" kesimi yapılmaz, aşamalar sırayla tamamlanır. Kurumsal protokoller Aşama 10'dadır; §10.6'daki protokol faz tablosu protokoller arası iç sırayı verir.
- **Efor (HYPOTHESIS / tahmin, ölçüm değil; doğrulanmadı):**
  - Tam IdP: Rust 46–73 dev-ay; Go 31–49 dev-ay (karşılaştırma bilgisi; dil kararı MD-1 → §16).
  - Yalnız OAuth/OIDC AS: 12–18 geliştirici-ayı (tahmin, ölçüm değil; birim §16.4.0 ile aynı).

  Bu rakamlar planlama varsayımıdır, taahhüt değildir. B15 gereği satış dilinde tarih vaadi olarak kullanılmaz.
- **Ticari bağımlılıklar:**
  - D-10 (CRA) Faz 1 yayınından önce kapanmalıdır.
  - MD-16'nın ilk crystal-box denetimi ilk açık sürümden önce yapılır.
  - OIDF conformance CI'da Faz 1'den itibaren koşar (B9).

### 18.14 Açık sorular `[→ §20]`

Strateji yapısı (B1–B24) açık değildir. Ampirik ve pazar soruları açık soru register'ındadır (→ §20). Bunlar:
- pazar ve strateji kanıtı soruları (OQ-3, OQ-4);
- MAU-dışı fiyatın kabulü (H9 identity falsifier'ı);
- H13b geçiş oranı;
- H12'nin iki yönlü yeniden sınanması;
- D-10 hukuki görüşü;
- NGI sonraki çağrısı.

Hiçbiri bir B'yi değiştiremez.
