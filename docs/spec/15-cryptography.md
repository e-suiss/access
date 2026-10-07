## 15. Kriptografi, Anahtarlar, Sır Yönetimi, Yan Kanal, PQC ve Formel Doğrulama

**Bu bölümün yeri ve kapsamı.** Bu bölüm Access'in kriptografi, anahtar ve sır yönetimi, yan kanal, PQC, performans ve formel doğrulama (formel doğrulanmış kripto dahil) kararlarını toplar. Kriptografik gereksinim tablosu §13.2'de, POLICY DEFAULT satırları §13.7.7 ve §13.7.8'de, FA-5/FA-6 §16.2'de, HL-8/HL-12 §16.9'da, T4, T5, T16, T19, T20, T24, T38 §16.10'dadır; bu bölüm onların kripto açıklamasını verir.

- Bağlayıcı merkezi kararlar: MD-1 (Rust, aws-lc-rs, tek `no_std` Access Kernel crate), MD-2 (dilden bağımsız sertleştirme), MD-3 (imza tablosu), MD-4 (Cedar teoremleri Access algebra'sını kapsamaz), MD-6 (anahtar hiyerarşisi ve signer), MD-15 (formal model iki katman), MD-17 (co-tenant HL), MD-18, MD-19.3/19.4 (PQ notu ve re-anchor mekaniği bu bölümdedir).
- Bu bölümün kararları `CR-n` ailesindedir (CR-1…CR-52). Karar kaydı §15.21'dedir. Bu bölümün Hard Limit'leri HL-27 ve HL-29, residual risk'leri RR-35…RR-38, invariant adayları SAI-40…SAI-46'dır. Guarantee satırı (G/U/N) bu bölümde açılmaz; ilgili satırlar §15.20'de listelenir, §13.4 ID'leri §13.13'tedir.
- **HL numaraları**: HL-25, HL-26 ve HL-28 kullanılmaz (ID yeniden kullanılmaz); bu sınırlar HL-20, HL-19 ve HL-16 + HL-21'dir (co-tenant kısmı HL-17 / DL-10, MD-17). HL-27 ve HL-29 bu bölümde tanımlıdır (HL-15 → HL-29). Bütün HL ve RR ID'leri §13.5 / §13.9 listelerinde yer alır.
- Plane etiketleri: **[AU]** authority plane, **[ID]** identity plane, **[PL]** iki plane'in ortak platform altyapısı.
- T-kararlarının (T4, T5, T16, T19, T20, T24, T38) kripto içeriği bu bölümde açıklanır. **T-kararlarının kanonik metni §16.10'dadır**: bu bölüm onlara "→ §16.10 Tn" ile atıf yapar ve yalnız bölüme özgü açıklamayı verir; T5 ve T12'nin bu bölümdeki ekleri §16.10 metnine dahildir. Bu bölümdeki diğer "(aynen)" alıntılar (SEC, SI, PI, TI, F, FA, G/U/N, HL, RR) yalnız okuma kolaylığı içindir. Kanonik yerleri: SEC §13.10; G/U/N §13.4; HL §13.5; RR §13.9; FA §16.2; SI/PI/TI §6; F §1–§4. Çelişkide kanonik metin kazanır.

**Bölüm ilkesi (§13.2).** Kriptografi bir authority kaynağı değildir. signed ≠ true, authenticated ≠ authorized, possession ≠ authority. Bu bölümdeki hiçbir mekanizma yeni bir authority primitive'i üretmez. Anahtarlar, imzalar, kaplar ve doğrulama araçları; record, value, projection veya OPERATIONAL sınıflarından birine düşer.

---

### 15.1 İlkeler, kriptografik gereksinimler ve garanti sınıfları

#### 15.1.1 Kriptografik gereksinimler

**Kanonik yer §13.2'dir**. Kriptografik gereksinimler tablosu (SEC4) yalnız §13.2'de yaşar; bu bölüm tabloyu tekrar etmez. Bu bölümdeki "forward secrecy", "confidentiality at rest" ve "uzun süreli doğrulanabilirlik" atıfları §13.2 tablosunu gösterir.

"Uzun süreli doğrulanabilirlik / crypto agility" satırının tek metni (§13.2 ve §13.12'deki MD-19.4 satırı bu metni kullanır):

> Algoritma kimliği imzalı içeriğin parçası (PI-21); yeniden sabitleme mekaniği: algoritma geçişi için §15.18 (PQ re-anchoring) ve §15.16 (agility); provider/binding değişimi için §16.6 ve §16.6.1 (recovery re-anchor T17)

**Identity plane satırları (MD-13).** Access tam bir IdP de olduğu için (MD-13) şu dört satır §13.2 tablosunun parçasıdır; kripto bölümüyle bağlantıları için burada da listelenir:

| Gereksinim | Gerekli mi | Nerede | Not |
|---|---|---|---|
| **İçerik gizliliği (JWE / SAML EncryptedAssertion)** [ID] | İstemci veya SP talep ederse evet | ID Token, UserInfo, JAR/JARM, SAML assertion | §15.3.3. Authority plane'de JWE kullanılmaz; [AU]'da gizlilik semantik garanti değildir (yukarıdaki satır korunur) |
| **Parola ve bearer sırrın tek yönlü saklanması** [ID] | Evet | Parola hash'i, client secret, API anahtarı, refresh/reset/magic-link/device code | §15.14. Veritabanı sızıntısında sırrın yeniden kullanılamaması; UNDER DECLARED POLICY |
| **Sabit zamanlı sır karşılaştırması** [PL] | Evet | Her sır karşılaştırması | §15.15. Platform ve derleyici varsayımına bağlıdır (UNDER DECLARED CAPABILITY); HL-16 |
| **Bellek-içi anahtar koruması** [PL] | Evet, best-effort | Signer, custody signer, verifier'ın sır tutan bileşenleri | §15.13. Kapsamadığı vektörler HL-21'de (co-tenant HL-17) beyan edilir |

SEC4 (§13.10, aynen): "**SEC4** Kriptografik gereksinimler: tamper-evidence ve teknik non-repudiation zorunlu; forward secrecy yalnız transport için; uzun süreli doğrulanabilirlik + algoritma kimliği imzalı içerikte; algoritma seçimi T5'tedir." Algoritma seçimi T5 + MD-3 + §15.2'dedir.

#### 15.1.2 Garanti sınıfları ve kriptografik iddia dili

- Garanti sınıfları değişmez: BY SEMANTICS, UNDER DECLARED CAPABILITY/POLICY, NOT GUARANTEED, PHYSICALLY UNSATISFIABLE.
- Kriptografik mekanizmalar semantik garanti vermez. Bir garantinin **gerçeklemesini** sağlar. Örnek: G35 ("Başka domain'in operasyonel anahtarıyla imzalanmış artefakt kabul edilmez") BY SEMANTICS'tir, çünkü kural verifier'ın must-understand denetimidir. İmzanın kendisi yalnız bu denetimin girdisidir.
- Fail-closed geçerlidir (MD-8). Doğrulanamayan imza, bilinmeyen algoritma, kanonik olmayan kodlama, parser sınır aşımı ve tazeliği kanıtlanamayan anahtar beyanı hiçbir zaman ALLOW veya "geçerli" sonucu üretmez.
- **İddia dili (MD-15).** Niteliksiz "formally verified", "proven secure", "constant-time guaranteed" ifadeleri yasaktır. İzin verilen biçim, kapsamı adıyla söyleyen biçimdir (§15.19.6, CR-50).

---

### 15.2 Algoritmalar ve varsayılanlar: plane ayrımı

#### 15.2.1 T5

**T5 → §16.10 T5** (kanonik metin). Bölüme özgü açıklama aşağıdadır.

T5'in gerekçesi ve reddedilen seçenekler:
- Gerekçe: SEC4 gereksinimleri; Work baseline (COSE/Ed25519); ES256 olmadan passkey ve çoğu HSM dışarıda kalır; algoritma kimliği imzalı içerikte → agility (PI-21).
- Reddedilen: yalnız Ed25519 (WebAuthn/HSM uyumsuzluğu); RSA varsayılan (boyut; yalnız ingest'te issuer algoritması olarak kabul edilir); kendi kripto.

**T5 metni:**

> **T5** Kripto suite: digest SHA-256, algoritma etiketli (CR-1). İmza tablosu MD-3'tür (aşağıda). Access'in ürettiği tanımlayıcılar RFC 9864 fully-specified biçimindedir; doğrulamada ES256 (−7) zorunludur ve WebAuthn assertion algoritmaları WebAuthn kurallarına göre kabul edilir; JWS'te `alg: EdDSA` reddedilir (CR-5). Kaplar COSE_Sign1 / JWS'tir (T24). TLS 1.3 kullanılır ve X25519MLKEM768 hibrit anahtar değişimi tercih edilir (CR-12). Kripto kütüphanesi aws-lc-rs'tir (MD-1, CR-13). HSM erişimi PKCS#11 üzerindendir (`cryptoki`); KMIP WATCH statüsündedir (CR-28). FIPS profili domain veya realm başına seçilir (CR-15). **PQ notu:** ML-DSA (RFC 9964, Mayıs 2026) için JOSE/COSE kayıtları yayımlanmıştır; Access ML-DSA-65'i opt-in profil olarak sunar ve JWKS'te `AKP` gün-1'de modellenir (MD-3). Ayrıntılar §15.17 PQC notu'ndadır. Ekleme her durumda CT3'tür (CR-8). Composite ve SLH-DSA taslak statüsündedir.

ML-DSA kayıt durumu: RFC 9964 Mayıs 2026'da yayımlandı. IANA JOSE kaydında `ML-DSA-44/65/87`, COSE kaydında −48/−49/−50, JWK ve COSE Key Types'ta `AKP` kayıtlıdır (8 Eylül 2026 durumu). Composite (`draft-ietf-jose-pq-composite-sigs-03`) ve SLH-DSA (`draft-ietf-cose-sphincs-plus-10`) için "kayıt statüsü doğrulanmadı" etiketi geçerlidir.

#### 15.2.2 İmza algoritmaları tablosu (MD-3, bağlayıcı)

| Bağlam | Plane | Varsayılan imza | Ayrıca | Kaynak |
|---|---|---|---|---|
| COSE authority kayıtları: receipt, PAP, checkpoint, AIS, AAS, Domain Metadata, status list | [AU] | Ed25519 | ES256/ESP256 zorunlu doğrulama | MD-3; T5 |
| JOSE projection'ları: ID token, access token, JAR/JARM, logout token | [ID] (ve [AU] token projection'ları, RFC 9068) | ES256 | Ed25519 seçmeli (client/realm metadata) | MD-3 |
| FIPS profili (domain veya realm başına) | [AU]+[ID] | Her yerde ES256 / ESP256 | — | MD-3 |
| RS256 | Yalnız [ID] | Client başına opt-in imza, yalnız aws-lc-rs ile | Authority artefaktları asla RSA ile imzalanmaz; `rsa` crate'i kullanılmaz | MD-3 |
| RSA doğrulaması (ingest) | [AU] ingest | Harici issuer algoritması olarak yalnız doğrulama (aws-lc-rs) | RSA anahtar boyutu ≥ 2048 | T5 ("yalnız ingest'te issuer algoritması olarak kabul edilir") |
| SAML | [ID] | rsa-sha256 (ekosistem istisnası) | ECDSA tercih edilir; `xmlenc#rsa-1_5` kapalı | MD-3 |
| PQ | [AU]+[ID] | ML-DSA-65 opt-in profil | ML-DSA-44 boyut-kısıtlı varyant; ML-DSA-87 CNSA profili (CR-41) | MD-3 |

**Ed25519 seçiminin kanıtı (ölçüm).** Ortam: Apple M4, tek çekirdek, Rust 1.98.1, `opt-level=3`, `lto="fat"`. Ölçüm tek makinededir ve hedef sunucu donanımında doğrulanmadı (mutlak rakamlar değil, oranlar ve eğilimler esas alınır). Statü: ENGINEERING ASSUMPTION.

| İşlem (aws-lc-rs) | µs/işlem | işlem/sn/çekirdek |
|---|---|---|
| Ed25519 imzalama | 4,10 | 243.804 |
| Ed25519 doğrulama | 18,32 | 54.597 |
| ES256 (P-256) imzalama | 11,05 | 90.483 |
| ES256 doğrulama | 27,30 | 36.632 |
| RSA-2048 imzalama (RustCrypto `rsa`) | 710,46 | 1.408 |
| RSA-2048 doğrulama (RustCrypto `rsa`) | 88,80 | 11.262 |
| HMAC-SHA256 | 0,66 | 1.522.689 |

Ed25519 imzalamada 2,6 kat, doğrulamada 1,5 kat hızlıdır. RSA-2048 imzalama aws-lc-rs Ed25519'un 173 katı sürer. Saf Rust `p256` crate'i aws-lc-rs'ten imzalamada 7,6 kat, doğrulamada 4,9 kat yavaştır ve üretim imza yolunda kullanılmaz. Ölçüm T5'in Ed25519 kararıyla aynı sonuca varır.

**CR-2 — İmza varsayılanları ve plane ayrımı.** MD-3 tablosu, yukarıdaki ingest ve SAML satırlarıyla birlikte normatiftir. Statü: FROZEN (MD-3'ün uygulanması). Gerekçe: COSE authority kayıtlarında Ed25519 hem Work hizasından hem ölçümden destek alır. JOSE'de ES256, OIDC/FAPI ve passkey ekosistemi gereğidir. FIPS gereksinimi global varsayılanı belirlemez; profil olarak seçilir. Kaynak: MD-3.

#### 15.2.3 Digest

**CR-1 — Digest algoritması.** Bütün Access digest'leri (leaf, intent, alan commitment, record, checkpoint, artefakt, `proof_commit`, DomainID = genesis digest) SHA-256 ile hesaplanır ve algoritma etiketi taşır (TI-11). SHA-256 Grover altında yaklaşık 128 bit güvenlik verir ve PQ geçişinde Merkle yapısının yeniden hesaplanmasını gerektirmez. Bu, §15.18'in temelidir. CNSA 2.0 profili SHA-384 ister (**ikincil kaynak, doğrulanmadı**). Bu bir profil notu olarak kalır: CNSA profili seçen domain için SHA-384 etiketli digest bir **gelecek profil sürümü** adayıdır. Bugün tek digest tabanı SHA-256'dır, çünkü iki digest tabanı iki source of truth riski taşır (T4). Statü: FROZEN; CNSA SHA-384 notu WATCH.

#### 15.2.4 HMAC ve simetrik MAC'ler

**CR-3 — HMAC kullanımı.** HMAC yalnız iki yerde kullanılır:
- (a) Anahtarlı türetim: TI-RT10 opaque `basis_ref` token'ı ve HMAC event id (T26), PII pairwise türetimleri (MD-10), double-HMAC karşılaştırması.
- (b) Tek taraflı, dahili ve aynı anahtarı tutan tek bir bileşenin hem ürettiği hem doğruladığı token'lar.

Çok taraflı token'da (birden çok bağımsız doğrulayıcı) simetrik MAC (`HS256/384/512`) kullanılmaz; anahtar paylaşımı gerektirdiği için çok taraflı bir IdP'de kullanılamaz. [ID] client'larının `client_secret_jwt` gibi HMAC'li istemci kimlik doğrulaması bu kuralın kapsamı dışındadır: anahtar AS ile tek bir client arasındadır, yani iki taraflıdır. Statü: FROZEN. Garanti: BY SEMANTICS (çok taraflı doğrulayıcı tek taraflı sırra dayanmaz).

---

### 15.3 JOSE ve COSE: tanımlayıcılar, kaplar, şifreleme

#### 15.3.1 Kaplar (T24, T16, R6)

**T24 → §16.10 T24**. Bölüme özgü özet: receipt COSE/JWS; token RFC 9068 + RAR; PAP COSE/CWT kanonik + SD-JWT profili; Token Status List derived'dan (`iat`/`as_of` = yansıtılan pozisyonun `recorded_at`'i).

**T16 → §16.10 T16**. Bölüme özgü özet (T16 metni): "**T16** Checkpoint = (domain, size, Merkle root, head leaf, recorded_at, version vector digest), operasyonel anahtarla COSE; cadence 60 s / 1,000 kayıt + out-of-cycle; state commitment yok. Cadence checkpoint'i (60 s, POLICY DEFAULT) değişiklik olmasa da üretilir (heartbeat), log'a kayıt olarak ingest edilir ve witness'lara gönderilir (log pozisyonu ve `recorded_at` ilerler; handover freeze'inde askıda); TI-RT5 tazeliğinin ve sessiz domain'de status list `iat` tazelenmesinin kaynağıdır."

Projection biçim tablosu:

| Projection (P17) | Biçim | Not |
|---|---|---|
| Decision Receipt | COSE_Sign1 (CBOR) ve JWS (JSON) — PEP'in profile'ına göre | İkisi de aynı kaydın `artifacts[]`'ında |
| Exact-intent token, bounds token | OAuth JWT AT (RFC 9068) + RAR `kind=intent\|bounds`; `cnf` zorunlu (DPoP/mTLS) | PI-11, P25 |
| Portable Authority Proof | **COSE/CWT kanonik** (cihazlar, offline, kompakt); **SD-JWT (RFC 9901) profili** (web, cross-domain JSON); içerik alanları iki biçimde aynı | Seçici açıklama: `lineage_commitment` halkaları |
| ValidityContract | PAP/token içinde gömülü; DecisionRecord'da value | P26 |
| Status | Token Status List — domain başına, operasyonel anahtarla imzalı, derived'dan üretilir; `iat` = yansıttığı `applied_pos`'un `recorded_at`'i (yayın anı değil) + `as_of` pozisyonu | Verifier Δ'yı `iat`'ten ölçer → derived gecikmesi Δ'yı tüketir, uzatmaz (SI-7); derived kesintisinde yeni liste yok, eski içerik taze `iat` ile imzalanmaz (fail closed); revocation sınıfı commit'te öncelikli yeniden yayın |
| Domain Metadata excerpt | Artefakta gömülü `kid` + binding key imzalı operasyonel anahtar beyanı `{kid, alg, validFrom, validUntil, usage}` (T20) | Offline verifier güncel metadata'ya erişmeden imza zincirini kurar; pencere **imza zamanını** (`iat`) sınırlar, kabul süresi verifier'ın yerel tavanıyla belirlenir (§9.10, §9.12) |

Excerpt ayrıca `jwk_thumbprint` alanını taşır (CR-18).

**Kap semantik değildir (T4, PI-2).** Aynı kayıttan üretilen COSE ve JWS projection'ları aynı `artifacts[]` digest kümesine bağlıdır. Kanıt imzaya değil payload digest'ine bağlıdır; imza deterministik olmayabilir (ES256). **Authority artefaktının geçerliliği kaba değil anahtar kapsamına bağlıdır**: authority artefaktı (COSE veya JWS/JWT/SD-JWT kabında, T24) yalnız o domain'in binding-imzalı excerpt'iyle bağlı operasyonel anahtarı veya binding anahtarıyla imzalıysa geçerlidir. Realm JOSE/SAML anahtarıyla veya RSA ile imzalı bir nesne, kabı ne olursa olsun, authority artefaktı değildir (G46, SAI-9; MD-3, MD-6, TI-RT6).

**CR-6 — Kap profili.** T24, T16 ve R6 kap seçimleri geçerlidir. Ekler:
- (a) JWKS ve COSE_KeySet, `kty: "AKP"` (COSE `kty` 7) anahtarlarını gün-1'den taşıyabilir. Bu anahtarlar `alg` zorunlu, `priv` = 32 baytlık seed kurallarıyla modellenir (MD-3).
- (b) Kap boyutu bütçesi PQ için ayrıca test edilir (CR-43).
- (c) **Doğrulama yolu tektir ve Kernel'dedir**. JWS compact/JSON ve SD-JWT doğrulaması (yalnız doğrulama; T24 receipt ve PAP profilleri), RFC 9864 tanımlayıcıları, `alg: EdDSA` reddi ve metadata allowlist'i (CR-5, CR-7; MD-3) Access Kernel'in (CMP-24, OP-1) parçasıdır. İmza **üretimi** ve identity plane'e özgü JOSE (JWE, JAR/JARM) `access-crypto`'dadır. Gerekçe: T25 [MD-1] Offline Verifier Core = Kernel ve MD-1 gerekçe 2 (verifier ile sunucu aynı kodu çalıştırır). Aksi hâlde Wasm/edge/mobil verifier SD-JWT PAP'ı veya JWS receipt'i doğrulamak için JOSE'yi ikinci kez yazar; bu HL-12 riskidir. Kernel listesine ekleme §16.4.1 OP-1 / §16.4.5 OP-5 / CMP-24'te yapılır.

Statü: FROZEN.

#### 15.3.2 Algoritma tanımlayıcıları ve yasaklar

**CR-5 — Fully-specified tanımlayıcılar (üretim); `none`, `RSA1_5` ve JWS `EdDSA` yasağı.**
1. Access yeni bir protokoldür ve legacy yükü yoktur. Access'in **ürettiği** bütün imzalar ve yeni artefaktlar RFC 9864 fully-specified tanımlayıcı kullanır: JOSE'de `Ed25519` (ve `Ed448`), COSE'de `ESP256/ESP384/ESP512` ve RFC 9864'ün Ed25519 kod noktası. Access'in kendi COSE artefaktında −7 yerine ESP256 yazılır (MD-3 "ES256/ESP256"). **Doğrulama kümesi:** COSE ES256 (−7) MD-3 gereği zorunlu doğrulanır. WebAuthn/CTAP assertion algoritmaları WebAuthn kurallarına göre kabul edilir (ör. −7 ES256; −8 EdDSA yalnız COSE_Key `crv` = Ed25519 ise; çıkarım, WebAuthn değerleri doğrulanmadı). Harici issuer imzaları ve client JWT'lerinde kabul kümesi o protokolün tanımlayıcısıyla ve MD-3 tablosuyla belirlenir. JWS'te `alg: EdDSA` her yerde reddedilir (MD-3). Kabul kümesi fully-specified tanımlayıcılarla sınırlanmaz; aksi hâlde passkey (ES256/−7) assertion'ı reddedilir ve bu MD-3 ile T5'e aykırıdır. RFC 9864 `EdDSA` değerini kullanımdan kaldırır. RFC 9864'ün COSE sayısal kod noktaları implementasyon öncesi IANA kaydından teyit edilir (doğrulanmadı).
2. JWS doğrulamada `alg: EdDSA` reddedilir (MD-3). Legacy `EdDSA`'nın ingest'te kabulü seçilmez: MD-3 bağlayıcıdır ve istisna tanımlamaz, bu yüzden ret JWS ingest dahil her JWS doğrulamasında geçerlidir (COSE/WebAuthn'daki −8 için madde 1). `EdDSA` ile imzalayan harici bir issuer, carrier adapter'da fully-specified `Ed25519` tanımlayıcısına geçene kadar `source-not-accepted` sınıfında kalır (fail closed). Bu bir kapsam daraltması değildir: Ed25519 imzası kabul edilir, yalnız belirsiz tanımlayıcı kabul edilmez.
3. `alg: none` hiçbir yerde desteklenmez. JWE `RSA1_5` hiç implemente edilmez. Gerekçe: `draft-ietf-jose-deprecate-none-rsa15-05` (Publication Requested, Haziran 2026, **henüz RFC değil**) uygulamaların bu algoritmaları varsayılan olarak kapatmasını zorunlu kılar. Hiç desteklememek downgrade yüzeyini sıfırlar. Marvin saldırısı PKCS#1 v1.5 şifre çözmeyi pratik olarak kırar; Kario'nun birincil önerisi tamamen kapatmaktır.
4. RS256 imzalamada (yalnız [ID], opt-in) `rsa` crate'i kullanılmaz (CR-14). RSASSA-PKCS1-v1_5 imzası taslağın kapsamı dışındadır ve kullanılabilir.

Statü: FROZEN. Garanti: BY SEMANTICS (kabul kümesinde olmayan tanımlayıcı reddedilir; kabul kümesi madde 1'deki üretim + MD-3 + protokol kümesidir).

#### 15.3.3 JWE ve SAML şifreleme (yalnız [ID])

**CR-4 — İçerik şifreleme algoritmaları.**
- JWE yalnız identity plane'de kullanılır: şifreli ID Token, UserInfo, JAR/JARM ve SAML EncryptedAssertion. Authority plane'de JWE kullanılmaz. [AU]'da gizlilik semantik garanti değildir (§13.2); bu durum korunur.
- Birincil: `ECDH-ES+A256KW` + `A256GCM`. `RSA-OAEP-256` yalnız legacy client için client başına açık opt-in'dir. `RSA1_5` yoktur (CR-5).
- ChaCha20-Poly1305 lehine gerekçe, aws-lc-rs'in AES-GCM doğrulamasının sınırlı olmasıdır: yalnız 12 B IV, 16 B tag, tam blok; AAD doğrulanmamış. Ancak ChaCha20-Poly1305'in JWE `enc` kaydı teyit edilmediği için JOSE birincili A256GCM kalır. ChaCha20-Poly1305 COSE ve iç (non-JOSE) şifrelemede seçilebilir. JWE kayıt durumu **doğrulanmadı**.
- AES-GCM tag karşılaştırması sabit zamanlı olmalıdır. libcrux-aes Temmuz 2026'ya kadar sabit zamanlı değildi (RUSTSEC-2026-0211). Bu yüzden JWE yolu libcrux kullanmaz, aws-lc-rs kullanır (CR-14).
- SAML'de `http://www.w3.org/2001/04/xmlenc#rsa-1_5` kapalıdır. SAML parser izole worker'da çalışır (MD-18). Sertleştirme §14'tedir.
- **PQ JWE yoktur:** `draft-ietf-jose-pqc-kem-06` yalnız COSE'u kapsar. JOSE HPKE'de ML-KEM yoktur. Şifreli [ID] token'ları bugün klasik kalır (RR-36).

Statü: FROZEN (algoritma kümesi PD).

---

### 15.4 Algoritma allowlist'i ve downgrade

Bağlı kurallar:
- SI-18 (aynen): "**SI-18** Downgrade is expansion. Domain minimum sürümünü, kabul edilen algoritma kümesini, Acceptance assurance floor'unu, ValidityContract tavanlarını veya bir RequirementTerm'in assurance/freshness/independence'ını gevşetmek genişletme sınıfında bir meta-Exercise'tır *[BY SEMANTICS]*"
- PI-21 (aynen): "**PI-21** Sürüm ve profile kimliği imzalı içeriğin parçasıdır; domain minimum sürümünü düşürmek genişletme sınıfıdır"
- §13.7.8 downgrade saldırı modeli (aynen): "(i) zorunlu alanın/extension'ın çıkarılması → imzalı içerik + must-understand (PI-12); (ii) eski sürümlü artefaktın eski verifier'a sunulması → Domain Metadata minimum sürümü, verifier freshness ≤ Δ; (iii) PEP ile eski profile pazarlığı → PEP minimumu Domain Metadata'dan alır, discovery'den değil; (iv) assurance downgrade (passkey yerine OTP) → RequirementTerm floor'u (SI-18); (v) algoritma downgrade → accepted algorithm kümesi Domain Metadata'da, imzalı içerikte algoritma kimliği."

§13.7.8 tablosu:

| Parametre | Değer |
|---|---|
| Domain minimum core spec / profile sürümü | Domain'in benimsediği en son sürüm; benimsemeden sonra 90 gün geçiş penceresi, sonra minimum = en son |
| Minimum'u düşürmek / algoritma eklemek (her algoritma, güçlü veya zayıf; PQ ve composite dahil) | CT3 (reserved + CT3 satırı: quorum varsa 2 contribution, Sole scope'ta donanım-bağlı UV assertion; her durumda 24 saat gecikme) |
| Minimum'u yükseltmek / algoritma çıkarmak | Narrowing (CT1) |
| Bilinmeyen sürümlü artefakt | Red (fail closed) + sayaç (telemetri) |

**CR-7 — Allowlist'in kaynağı.**
- [AU]: Kabul edilen algoritma kümesi yalnız Domain Metadata'dan (ve Verifier Profile'dan) okunur. Artefaktın veya mesajın header'ındaki `alg` yalnız kümede **seçilmiş** bir değeri adlandırır. Kümede olmayan değer reddedilir.
- [ID]: Kabul kümesi kayıtlı client metadata'sından (`id_token_signed_response_alg`, `request_object_signing_alg`, `token_endpoint_auth_signing_alg`, JWE `*_encrypted_response_alg/enc` vb.) ve realm politikasından gelir. Client metadata değişikliği bir domain action'dır (MD-14), yani aynı gevşetme kuralına tabidir.
- Header'daki `alg` hiçbir zaman kabul kümesini genişletmez (alg downgrade riski).
- Downgrade testi conformance'a girer.

Gerekçe: CT3 + 24 saat + imzalı içerik modeli, "client metadata'dan allowlist" kuralını kapsar ve ondan daha güçlüdür. Statü: FROZEN. Garanti: BY SEMANTICS. Kaynak: SI-18; PI-21.

**CR-8 — Algoritma ekleme sınıfı.** Kabul kümesine **her** algoritma eklenmesi CT3'tür; çıkarma CT1'dir. Gerekçe: Her yeni algoritma, güçlü veya zayıf, yeni bir implementasyon yüzeyidir. V8/V9 sınıfı ML-DSA doğrulayıcı hataları, "güçlü" bir algoritmanın hatalı doğrulayıcısının sahte imza kabul edebileceğini gösterir. Statü: FROZEN.

**SAI-40 (invariant adayı) — Allowlist header'dan gelmez.** Hiçbir doğrulayıcı (kernel, PEP SDK, verifier, identity plane), kabul edilen algoritma kümesini doğrulanan nesnenin kendi alanlarından türetemez. Küme yalnız Domain Metadata / Verifier Profile / kayıtlı client metadata'dan okunur. *[BY SEMANTICS]*

---

### 15.5 Doğrulama sıkılığı, deterministik CBOR ve parser sınırları

#### 15.5.1 Bağlı kurallar

- **T4 → §16.10 T4**. Bölüme özgü özet: deterministic CBOR + CDDL kanonik tek kodlama; wire'da standart biçimler; imzalı baytlar aynen.
- T4 kararı, gerekçesi ve reddedilen seçenekleri: Karar "**Kanonik tek kodlama + projection:** canonical kayıtlar ve Access'in hesapladığı her digest deterministic CBOR (RFC 8949 §4.2) + CDDL; wire'da standart taşıyıcıların kendi biçimi (AuthZEN/SSF JSON, JWT/SD-JWT, COSE); dışarıda imzalı bayt'lar aynen saklanır". Gerekçe "Tek digest tabanı → replay ve inclusion proof tek biçime bağlı (INV-27, P18); Work ile ortak aile; JSON standartlarını bozmadan taşıma (PI-2)". Reddedilen "Çift kanonik kodlama (iki digest tabanı = iki source of truth riski); JSON+JCS kanonik (sayı/Unicode belirsizliği, Work'ten ayrılma); Protobuf kanonik (deterministik serileştirme garanti değil)". Yeniden değerlendirme koşulu "Ortak governance Work ile birlikte kodlamayı değiştirirse (PI-18)".
- TI-11 (aynen): "**TI-11** Verbatim signatures, Access-computed digests. Dışarıda imzalı bayt'lar zarfın dışında (proof / body store) aynen saklanır, onlar üzerinde doğrulanır ve leaf'e yalnız digest'leriyle bağlıdır; intent, alan commitment'ı, record, checkpoint ve artefakt digest'lerini yalnız Access deterministic CBOR'dan hesaplar; caller'ın digest'i girdi değildir. AIS digest'i yalnız `proof_commit` içinde taahhüt edilir."
- SI-20 (aynen): "**SI-20** Bounded evaluation. Lineage derinliği, proof sayısı, selector karmaşıklığı, istek boyutu ve oranı sınırlıdır; aşım gerekçeli protocol rejection'dır (outcome değil, kayıt yok, nonce tüketilmez, effect yok) *[BY SEMANTICS (sınırın varlığı); değerler POLICY DEFAULT]*"
- HL-12 (aynen): "| HL-12 | Çapraz-implementasyon determinizmi vektör kapsamı kadar | G17 (provider yükümlülüğü); L0/L2 + vektörler (TI-RT12) | NG (kapsam dışı) |"

#### 15.5.2 İmza doğrulama sıkılık profili

**Sorun.** İmza baytları `proof_commit` digest'ine girer (TI-11). İki durum determinizmi ve conformance'ı bozar:
- ECDSA'da (r, s) ve (r, n−s) aynı mesaj için geçerlidir (malleability). Aynı intent iki farklı `proof_commit` digest'i üretebilir.
- İki doğrulama yolu Ed25519 kabul kümesinde ayrışırsa (RFC 8032 strict ↔ ZIP-215 tarzı gevşek doğrulama), aynı AIS bir yolda kabul edilir, öbüründe reddedilir.

MD-1'den sonra sunucu ve verifier aynı kernel'i çalıştırır, dolayısıyla dil ekseni kapanır. Kernel'in farklı kripto sağlayıcıları (CR-13) ve CPU hedefleri arasında ise ayrışma riski sürer.

**CR-9 — Sıkılık profili (L0 normatif metni ve conformance vektörleri).**
1. **Ed25519 (kabul):** Kanonik olmayan R ve S kodlaması ile S ≥ L reddedilir. Kanonik olmayan public key kodlaması ve küçük mertebeli public key reddedilir. Doğrulama denklemi bütün sağlayıcılarda aynıdır ve vektörlerle sabitlenir. ZIP-215 tarzı gevşek kabul seçilmez (gerekçe: tek kabul kümesi). Hangi kesin denklemin (cofactored/cofactorless) seçildiği L0 metninde ve vektörlerde sabitlenir. Bu bir **açık uygulama kalemidir** (OQ-CR1, §15.23).
2. **ECDSA P-256 (üretim):** Access'in ürettiği her ECDSA imzası low-S'ye normalize edilir.
3. **ECDSA (kabul), Access-native artefaktlar:** Access'in kendi ürettiği artefaktlar (receipt, PAP, checkpoint, Domain Metadata, status list, ES256/ESP256 profilinde) doğrulanırken high-S reddedilir.
4. **ECDSA (kabul), harici imzalar:** WebAuthn assertion'ları, harici issuer JWS'leri ve client JWT'leri için high-S kabul edilir. Harici imzacıların low-S'ye normalize ettiği varsayılamaz (**çıkarım**; authenticator davranışı doğrulanmadı). Malleability'ye karşı koruma imzaya değil şunlara dayanır: tek kullanımlık challenge/nonce, payload digest bağı (§15.3.1) ve kayıtta yalnız ilk sunulan imza baytlarının `proof_commit`'e girmesi (TI-11). Aynı payload'ın ikinci bir imza varyantıyla sunulması nonce tüketildiği için reddedilir.
5. **RSA (yalnız [ID] ve ingest doğrulaması):** PKCS#1 v1.5 imza doğrulamasında DER encoding birebir karşılaştırılır. Modül 2048–8192 bit aralığındadır.
6. **ML-DSA:** FIPS 204 norm ve hint sınırları vektörlerle sınanır (V8/V9 sınıfı). Crucible ve ACVP vektörleri koşulur (CR-51).
7. Bu kuralların hepsi TI-RT12 gereği L0/L2 metnine ve conformance vektörlerine girer. Vektörlere Wycheproof edge-case'leri eklenir.

Statü: FROZEN (kural); kesin Ed25519 denklemi OQ-CR1. Garanti: BY SEMANTICS (tek kabul kümesi spec'tir), vektör kapsamı kadar (HL-12).

**SAI-41 (invariant adayı) — Kanonik tek kabul.** Aynı semantik değer için kabul edilen tek bir bayt kodlaması vardır (deterministik CBOR, kanonik imza kodlaması). Kanonik olmayan girdi, imza veya kodlama sıkılık profilinin dışında kalan girdi gerekçeli protocol rejection'dır. Kabul kararı kripto sağlayıcısından ve CPU hedefinden bağımsızdır. *[BY SEMANTICS; implementasyon eşitliği vektör kapsamı kadar (HL-12)]*

#### 15.5.3 Deterministik CBOR doğrulaması ve yapısal parser sınırları

**CR-10 — Deterministik CBOR doğrulaması ve yapısal sınırlar.**
1. **Kodlama kararı Access'indir** (T4: RFC 8949 §4.2 deterministic CBOR + CDDL). Decoder kanonik olmayan girdiyi reddeder: preferred olmayan integer/float kodlaması, sırasız map anahtarları, indefinite length ve duplicate map key. Aksi hâlde aynı değer iki digest üretir.
2. **Round-trip:** `decode(encode(x)) == x` ve `encode(decode(b)) == b` (kanonik b için) özellikleri fuzz ve property testleriyle sınanır. Kernel decoder'ı için Kani ile N ≤ 32 bayt girdi üzerinde panic yokluğu, sınır aşımı yokluğu ve round-trip ispatlanır. Ayrıntı CR-47'dedir.
3. **Yapısal sınırlar (POLICY DEFAULT).** Bunlar SI-20'nin semantik sınırlarının (lineage ≤ 16, proof ≤ 64, istek ≤ 256 KB; §13.7.4) yapısal tamamlayıcısıdır.

| Sınır | Değer (PD) | Gerekçe |
|---|---|---|
| CBOR iç içe derinlik | ≤ 16 | Deterministic CBOR + CDDL ile bu kadarı yeter |
| JSON, SCIM filter, LDAP filter, XML ve diğer özyinelemeli parser derinliği | ≤ 32 | Kanidm CVE-2026-46689 / GHSA-qcxq-75wr-5cm8 (CVSS 8,7, kimliği doğrulanmamış istekle tüm IdP'yi kapatan stack taşması). `serde_json` `unbounded_depth` özelliğinin hiçbir bağımlılıkta açık olmadığı CI'da assert edilir |
| Map/array öğe sayısı | ≤ 256 | — |
| Tek string/bstr | ≤ 64 KB | — |
| Indefinite length | Yasak | T4 kanoniklik |
| Duplicate map key | Red | T4 kanoniklik |
| CBOR tag | Allowlist (CDDL'de tanımlı tag'ler) | — |
| Toplam ayırma | Sabit arena / üst sınır (`no_std` kernel) | MD-1 |
| x509/DER | ≤ 8 KB, fuzz ile doğrulanır | — |
| WebAuthn CBOR (attestation/authenticatorData) | Boyut ve derinlik kontrolü; kimliği doğrulanmamış kayıt yoludur | — |
| XML (SAML) | `Event::DocType` görülünce red (XXE ve billion laughs yapısal olarak kapanır) | — |

4. Sınır aşımı SI-20 anlamında gerekçeli protocol rejection'dır: outcome değildir, kayıt yoktur, nonce tüketilmez. Panic ve abort kullanılmaz; `Result::Err` döner (MD-2).
5. Derinlik kontrolü özyinelemeden **önce** yapılır (MD-2). Pahalı extractor'lardan önce kimlik doğrulama middleware'i çalışır.

Statü: FROZEN (kural); değerler POLICY DEFAULT. Garanti: BY SEMANTICS (sınırın varlığı). Kaynak: T4; SI-20.

#### 15.5.4 Batch imza doğrulaması

**CR-11 — Batch doğrulama kapalı.** Kernel, verifier ve identity plane batch imza doğrulaması (ör. ed25519 `verify_batch`) kullanmaz. Gerekçeler:
- (a) Kazanç sınırlıdır: batch 64'te imza başına 2,09 kat. Batch başarısızlığında hangi imzanın bozuk olduğunu bulmak için tekil doğrulama gerekir (M4 ölçümü, EA).
- (b) Tekil ve batch doğrulamanın kabul kümesi farklı olabilir. Bu da SAI-41'i bozar. Bu bir **hipotezdir** ve doğrulanmadı. Hipotez çürütülse bile (a) kararı tek başına taşır.

Statü: FROZEN.

---

### 15.6 TLS ve hibrit anahtar değişimi

**CR-12 — TLS 1.3 ve hibrit KEX.**
1. Bütün dış ve iç kanallar TLS 1.3 kullanır (T5). TLS 1.3 RFC 9846 (Temmuz 2026) ile yeniden yayımlanmıştır ve RFC 8446'yı geçersiz kılar.
2. **Hibrit anahtar değişimi bugün açılır:** `X25519MLKEM768` (RFC 10024, Ağustos 2026; IANA'da "Önerilen" olarak işaretli tek PQ grubu). rustls 0.23.27'den beri `prefer-post-quantum` varsayılan özelliktir; aws-lc-rs sağlayıcısı X25519MLKEM768'i destekler. Gerekçe: harvest-now-decrypt-later riski transport gizliliği içindir. Maliyeti sıfıra yakındır. EO 14412'de anahtar tesisi 31 Aralık 2030 kovasındadır. Forward secrecy gereksinimi (§13.2) yalnız transport içindir; bu karar o gereksinimin PQ'ye taşınmasıdır.
3. **Bilinen sorun:** X25519MLKEM768 istemci anahtar payı 1.216 bayttır, ClientHello tek segmente sığmaz. Ara kutu kırılması ölçülmüştür: iyimser anahtar payı bağlantıların %0,05'ini kırar; "grubu ilan et, payı gönderme" yaklaşımı evrensel olarak tolere edilir (Cloudflare ölçümü). Access istemci SDK'ları ve iç kanallarda iyimser gönderim varsayılandır. Kırılma telemetrisi alarm üretir; güvenli yaklaşıma düşüş domain veya realm politikasıdır (PD).
4. **İç mTLS'te ML-DSA kimlik doğrulaması:** Özel PKI'da mümkündür (RFC 9881, rustls 0.23.44 aws-lc-rs sağlayıcısında varsayılan açık). Servis kimliği SPIFFE/SPIRE'dır (T36). SPIRE KeyManager anahtar tipleri `rsa-2048`, `rsa-4096`, `ec-p256`, `ec-p384`'tür; ML-DSA SVID desteği belgelenmemiştir. Bu yüzden iç ML-DSA mTLS WATCH'tır (OQ-MD1 ile birlikte izlenir).
5. Kamuya açık web PKI'da ML-DSA sertifikası yoktur. CA/B Forum oylaması geçmemiştir; Chrome Merkle ağacı sertifikalarına yönelmiştir. Tarayıcıya dönük TLS sertifikaları klasik kalır.

Statü: FROZEN (TLS 1.3 + hibrit KEX); iç ML-DSA mTLS WATCH. Garanti: transport gizliliği UNDER DECLARED CAPABILITY (karşı tarafın hibrit grubu desteklemesine bağlı).

---

### 15.7 Kripto kütüphanesi, FIPS profili, kod disiplini ve performans

#### 15.7.1 Tek kripto sağlayıcısı

**CR-13 — aws-lc-rs tek üretim kripto sağlayıcısıdır.** Access Kernel, signer, verifier ve identity plane'in bütün imza, doğrulama, AEAD, KEM, HMAC ve KDF işlemleri aws-lc-rs üzerinden yapılır (MD-1). rustls da aws-lc-rs sağlayıcısıyla derlenir (CR-12).

Gerekçe:
- aws-lc-rs 1.18.1 tek sağlayıcıda klasik algoritmalar (Ed25519, P-256/384/521, RSA, X25519, AES-GCM, ChaCha20-Poly1305), ML-KEM ve ML-DSA'yı birlikte sunar.
- s2n-bignum üzerinden RSA, P-256/384/521, X25519 ve Ed25519 için HOL Light fonksiyonel doğruluk ve sabit zaman ispatları vardır. Kapsam sınırları §15.19.7'dedir (26 adlandırılmış SAW caveat'i).
- `no_std` kernel'in kripto sınırı ayrı ele alınır (çıkarım, uygulama kalemi): aws-lc-rs bir C/assembly kütüphanesidir ve `no_std`/Wasm hedefinde aynı biçimde derlenemeyebilir. Kernel'in Wasm/FFI hedeflerindeki doğrulama yolu için seçenekler OQ-MD4 kapsamında ölçülür. Kabul kümesinin sağlayıcıdan bağımsız olması SAI-41 ve CR-9 vektörleriyle sabitlenir. aws-lc-rs'in Wasm desteği **doğrulanmadı** (OQ-CR2).

Statü: FROZEN. Kaynak: MD-1.

#### 15.7.2 Yasaklı ve sınırlı kütüphaneler

**CR-14 — Kütüphane yasakları ve CI kapıları.**

| Kütüphane | Karar | Gerekçe | CI kapısı |
|---|---|---|---|
| RustCrypto `rsa` | **Yasak** (doğrudan veya transitif hiçbir yolda) | RUSTSEC-2023-0071 (Marvin, CVSS 5,9): `patched = []`, düzeltilmiş sürüm yok; RustCrypto/RSA issue #626 (sabit zamanlı bigint geçişi) **açık** | `cargo tree -i rsa` boş olmalı; `cargo deny` advisory kapısı |
| `ring` | Kullanılmaz | 18 ay sürüm yok; PQ yok | `cargo deny` bans |
| `libcrux` | Üretimde kullanılmaz | Sürüm < 0.1; RUSTSEC-2026-0211 (AES tag karşılaştırması sabit zamanlı değildi), 2026-0212; hax/F* ispatları yalnız ML-KEM/ML-DSA çekirdeğini kapsar | `cargo deny` bans |
| RustCrypto `ml-dsa`, `ml-kem` | Üretimde kullanılmaz | Crate README'leri "never been independently audited" der; RUSTSEC-2025-0144 (ml-dsa UDIV zamanlama sızıntısı) | `cargo deny` bans |
| `jsonwebtoken` | Kullanılabilir, ancak imza anahtarı önbelleklenir (CR-17) | Her imzada PKCS#8 yeniden ayrıştırma 1,91 kat kayıp | — |
| `subtle` | Yalnız aws-lc-rs'in sunmadığı karşılaştırmalar için | Best-effort; derleyici garantisi yok | asm snapshot (CR-39) |

Statü: FROZEN. Garanti: NOT GUARANTEED (kütüphane hatalarının yokluğu); kapılar UNDER DECLARED POLICY.

#### 15.7.3 FIPS profili

**CR-15 — FIPS profili (domain veya realm başına seçilir).** FIPS uyumunu bir müşteri (kamu, finans, FedRAMP) gerektirdiğinde domain (authority plane) veya realm (identity plane) "FIPS profili" seçer. Profil şunları getirir:

| Konu | FIPS profilinde | Varsayılan profilde |
|---|---|---|
| İmza | Her yerde ES256 / ESP256 (P-256); FIPS'te Ed25519 HSM desteği tutarsızdır (CloudHSM HashEdDSA yalnız hsm2m.medium'da ve FIPS dışı modda) | MD-3 tablosu |
| Parola hash'i | PBKDF2-HMAC-SHA256, 600.000 iterasyon (OWASP) | Argon2id (CR-36) |
| Modül sınırı | aws-lc-rs `fips` özelliği (AWS-LC FIPS modülü) | aws-lc-rs varsayılan |
| Operasyonel anahtar | HSM içinde kalır; KMS RAW-mod veya HSM başına işlem maliyeti kabul edilir (MD-6) | Signer süreci (CR-21) |
| PQC | **Mümkün değil** (HL-27): bugünkü sertifikalarda (5298/5314) ML-KEM var, ML-DSA yok; 5429'da ikisi de yok; FIPS 4.0 modülü sertifikasız | ML-DSA-65 opt-in |

FIPS profili bir **güvenlik garantisi değildir**, bir uyum profilidir. Garanti sınıfı değişmez. Profil değişikliği PI-21 / SI-18 kapsamındadır: profilden çıkış kabul kümesine algoritma eklemektir, dolayısıyla CT3'tür (CR-8). Sertifika numaraları ve kapsamları 8 Eylül 2026 durumudur. CMVP listesi değişkendir; **doğrulanmadı** (implementasyon öncesi yeniden kontrol edilir).

Statü: FROZEN (profilin varlığı); içerik PD. Kaynak: MD-3; MD-6.

#### 15.7.4 Kod disiplini (MD-2'nin kripto kodu için uygulanması)

**CR-16 — Kripto ve kernel kod disiplini.**
- Access Kernel crate'inde `#![forbid(unsafe_code)]` ve `#![no_std]` kullanılır; `deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)` açıktır. Overflow DENY'dir (checked arithmetic; MD-2).
- `unsafe` ve FFI yalnız allowlist'teki crate'lerde bulunur: aws-lc-rs, `cryptoki`, `memfd_secret` sarmalayıcısı. Allowlist CI'da `cargo geiger` veya eşdeğeri ile denetlenir. Araç adı bir çıkarımdır.
- İstek yolunda panic yoktur. Ağ süreçlerinde `abort` yasaktır; `no_std` kernel, signer ve parser worker'larında izinlidir (MD-2).
- Sır tutan tipler §15.13'teki tip disiplinine tabidir.
- Panic fuzz'ı ve çapraz platform determinizm testi (x86-64 / ARM64 / `-C target-feature=-avx2`) CI'dadır (CR-51).

Statü: FROZEN. Kaynak: MD-2.

#### 15.7.5 Performans

**CR-17 — Performans kararları ve imza anahtarı önbelleği.**
1. CMP-7 Projection Signer ve identity plane token imzacısı, ayrıştırılmış imza anahtarı nesnesini önbellekler. `jsonwebtoken`'ın her imzada PKCS#8 yeniden ayrıştırması aws-lc-rs ham API'sine göre 1,91 kat kayıptır (M4 ölçümü).
2. Bütün sayılar Apple M4 ölçümleridir (§15.2.2). Sunucu (x86-64 / Graviton) ölçümü yapılmadan kapasite planına girmez. Statü: ENGINEERING ASSUMPTION.
3. Kernel ↔ Wasm/FFI sınırının maliyeti OQ-MD4'tür ve henüz ölçülmedi.
4. İmza işlemi KMS/HSM'e gidiyorsa darboğaz CPU değil, KMS/HSM kotasıdır (§15.9, HL-20).

Statü: PD/EA.

---

### 15.8 Anahtar hiyerarşisi

#### 15.8.1 T20

**T20 → §16.10 T20**. Bölüme özgü açıklama için T20 metni (kanonik yeri §16.10): "**T20** Provider anahtar hiyerarşisi: HSM'de quorum'lu binding key, ≤ 24 saat domain-başı operasyonel anahtarlar, artefakta gömülü binding-imzalı excerpt {DomainID, kid, alg, validFrom, validUntil, usage} (verifier DomainID eşleşmesi ister; TI-RT6); pencere imza zamanını (`iat`) sınırlar ve verifier'da must-understand'dir; yeni operasyonel anahtarın validity başlangıcı aktivasyondan en az status-list derived gecikme tavanı kadar önce beyan edilir; kabul süresi min(horizon, iat + yerel tavan), tavanlar yalnız Domain Metadata / Verifier Profile'dan (`cap_horizon`: CT gerçekleştirilen intent'ten, class/variant Verifier Profile'dan; artefaktın beyanı kullanılmaz); HSM partition paylaşımı beyan edilir (FA-8 eki); binding değişimi yalnız `domain.handover` / `domain.recover`."

TI-RT6 (aynen): "**TI-RT6** Operasyonel anahtar excerpt'i DomainID'ye bağlıdır; verifier eşleşme ister; operasyonel anahtarlar domain başınadır"

T20 anahtar diyagramı ve maddeleri:

```text
Provider binding key  (Genesis / domain.* kayıtlarıyla bağlı; HSM; kullanımı k-of-n operatör quorum'u)
   └─ imzalar ─► Domain Metadata  (operasyonel anahtar listesi: kid, alg, validFrom, validUntil ≤ 24 s, usage)
                    └─ artefakta gömülü excerpt: {kid, alg, validFrom, validUntil, usage} imzası binding key'den
Operasyonel anahtarlar (HSM/KMS; günlük rotasyon): receipt, PAP, token, checkpoint, SET, status list
```

- "**Pencerenin anlamı:** `[validFrom, validUntil]` (≤ 24 saat; POLICY DEFAULT) **imza zamanını** (`iat`) sınırlar ve verifier tarafından must-understand uygulanır; artefaktın kabul süresi `min(horizon, iat + yerel tavan)`'dır ve yerel tavan artefakttan değil Domain Metadata / Verifier Profile'dan okunur (§9.10, §9.12). Bu, ≤ 24 saatlik anahtar ömrünü 72 saatlik offline horizon'larla uyumlu kılar ve blast radius'u verifier tarafında sınırlar: çalınmış anahtarla geri tarihli (`iat` pencere içine çekilmiş) bir artefakt en geç `validUntil + en büyük yerel tavan`'a kadar ve yerel horizon/slice tavanları içinde kabul edilebilir (U25); bu pencere içindeki sahte kabulün önlenmesi NG'dir (N-26, RR-14)."
- "Compromise tespitinde yol `domain.recover`'dır (SEC21) ve sonrası SI-11 inclusion kuralıdır."
- "Binding key değişimi yalnız `domain.handover` / `domain.recover` ile (P3); rutin binding key rotasyonu yoktur (rotasyon ihtiyacı = handover/recover Exercise'ı)."
- "Algoritma kimliği her imzalı içeriğin parçasıdır; kabul edilen algoritma kümesi Domain Metadata'dadır; zayıf algoritma eklemek genişletme sınıfıdır (SI-18, PI-21)."

Bağlı satırlar (aynen):
- G35: "Başka domain'in operasyonel anahtarıyla imzalanmış artefakt kabul edilmez (excerpt DomainID) (TI-RT6)"
- G42: "İmzasız artefakt yayınlanmaz (HSM kesintisinde artefakt gecikir) (TI-12)"
- U25: "Çalınmış provider imza anahtarıyla basılmış PAP/receipt/token'ın etkisinin her verifier'ın yerel kabul tavanıyla (horizon, slice, operasyonel anahtar penceresi, bridging ceiling/terms) sınırlı kalması | Verifier'ın Domain Metadata / Verifier Profile'da ilan edilen tavanları must-understand uygulaması (`cap_horizon`: CT gerçekleştirilen intent'ten, class/variant Verifier Profile'dan; artefaktın beyanı kullanılmaz) + Domain Metadata tazeliği TI-RT5 anlamında ≤ Δ; status-list anahtar penceresi örtüşmesi (T20)"
- N-26: "Provider imza anahtarı çalınmasının tespit/recovery öncesi penceresinde, verifier'ın yerel tavanları içindeki sahte PAP/receipt kabulünün önlenmesi (offline slice'lar merkezde draw edilmemiş olabilir); kurala uymayan verifier'da handover sonrası pencere de bu sınıftadır"
- RR-14: "Provider imza anahtarı çalınmasının tespit öncesi penceresi: verifier'ların yerel tavanları içinde sahte PAP/receipt kabulü (N-26) | Provider operatörü (anahtar custody'si); domain (yerel tavanların ilanı, recovery); verifier operatörleri | Anahtar evaluator değildir; containment ancak verifier tarafında mümkündür | Merkezde `projection.issue` karşılığı olmayan PAP sunumu (ack / offline report); witness çatallanması"
- FA-6: "HSM anahtarları extract edilemez; binding key kullanımı quorum'lu | HSM sertifikasyonu, operasyon | SEC21 yolu"
- SEC21 aynen §13.10'dadır; recovery prosedürü §13.6 ve §16.6'dadır. Bu bölüm yalnız anahtar boyutuna atıf yapar: "Eski anahtar `superseded-at checkpoint N`; compromise penceresindeki sahte artefaktlar exact-content inclusion kuralıyla reddedilir (SEC25)."
- Trust model "Provider imza anahtarı" satırı (aynen): "| **Provider imza anahtarı** | Receipt/PAP/checkpoint/metadata imzası | Authority (custody attestation) | Recovery kaydı verifier'a ulaşana kadar **güncel tarihli**, keyfi holder/bounds/horizon/slice/audience'lı PAP/receipt/token — her verifier'ın **yerel** kabul tavanı içinde (offline: Domain Metadata / Verifier Profile'da ilan edilmiş horizon/slice tavanları + operasyonel anahtar geçerlilik penceresi; foreign: bridging Grant ceiling'i ve terms'i); offline slice'lar lineage budget'ından draw edilmemiş olabilir; sahte checkpoint (witness'ta çatallanma olarak görünür; kökü hiçbir kayıt kümesinin record-fold'uyla yeniden üretilemez) | Online ADP kararı (anahtar evaluator değildir); merkezde budget draw'u veya Exercise kaydı; recovery sonrası exact-content inclusion proof'suz kabul (P18) | Verifier-side yerel tavanlar + metadata freshness ≤ Δ: conformant verifier'da yerel tavanı aşan kabul yok (→ U25, UDC); `domain.recover`, N = en son doğrulanmış checkpoint (SEC21) |"

#### 15.8.2 Anahtar hiyerarşisi

**CR-18 — Anahtar hiyerarşisi (T20 + MD-6).** T20 geçerlidir. Ekler:

```text
[AU] Provider binding key          (HSM, non-extractable, quorum'lu aktivasyon; domain başına veya beyanlı kapsam)
        └─ imzalar ─► Domain Metadata (operasyonel anahtar listesi + kabul kümesi + binding kapsamı)
        └─ imzalar ─► excerpt {DomainID, kid, alg, jwk_thumbprint, validFrom, validUntil, usage}
[AU] Operasyonel anahtarlar         (domain başına; signer süreci veya FIPS profilinde HSM; PD 1 s, tavan 24 s)
        └─ imzalar ─► receipt, PAP, token, checkpoint, SET, status list
[ID] Realm JOSE anahtar seti        (realm başına; 1 aktif + N pasif; publish-before-use; ayrı KMS anahtarı, T31)
        └─ imzalar ─► ID token, access token (identity plane), JARM, logout token, SAML assertion
[PL] KEK (domain başına, KMS/HSM) ─► DEK (body başına, T27/T39);   [ID] PII KEK (realm başına, T31)
[PL] basis_ref / event-id anahtarı (domain başına secret, TI-RT10)
[ID] Custody signer anahtarları     (TEE + HSM KEK, T32; user-gated, SEC17)
[ID] Parola pepper'ı (opsiyonel, EA; CR-37)
```

- **Excerpt `jwk_thumbprint` taşır**. Bu alan operasyonel public key'in RFC 7638 JWK thumbprint'idir (CR-24). Excerpt public key'i adlandırır, dolayısıyla bir verifier, operasyonel anahtarı Domain Metadata'nın tam listesine erişmeden excerpt'ten doğrular. Alan imzalı içerikte olduğu için must-understand'dir (PI-12).
- **Binding key kapsamı Domain Metadata'da beyan edilir** (MD-6). Seçenekler: domain başına binding key veya provider-genel binding key + domain başına beyan. Varsayılan domain başınadır (çıkarım: T20 "domain-başı operasyonel" der; binding key kapsamı T20'de açık değildir, MD-6 beyanı zorunlu kılar). Provider-genel binding key seçilirse paylaşımın blast radius'u HL-8 ve HL-20 kapsamında beyan edilir.
- **Storm-0558 sınıfı (MD-6):** Bir imza anahtarının kabul kapsamı dışında (başka tenant, başka domain, başka plane) kabul edilmesi sınıfıdır. 2023 Microsoft olayında tüketici MSA anahtarıyla kurumsal token'lar kabul edilmişti; bu ayrıntı genel bilgidir, birincil kaynaktan teyit edilmedi. Bu sınıf HL-8 kapsamındadır (tek metin §13.5; aşağıda atıf). Verifier excerpt'in `DomainID`'sini must-understand olarak eşler (TI-RT6, G35). Identity plane'de `iss`, realm ve `kid` eşleşmesi aynı kuraldır (§10).

**HL-8 → metni §13.5'tedir**. Bu bölüm ayrı bir HL-8 metni taşımaz. HL-8'in tek metni (§13.5): paylaşılan HSM partition'ında korelasyonlu ihlal; paylaşılan veya kapsam dışı imza anahtarının başka domain/tüketici/plane'de kabulü (Storm-0558 sınıfı). Kural BS'dir (G35, G47: DomainID must-understand); koruma yalnız conformant verifier'da etkilidir (UDC, U25); paylaşılan KMS kotası → HL-20. Bağlı: U25 / N-26 (beyanlı HSM partition paylaşımı, FA-8 eki); G35, G47; HL-20. Sınıf: NG (kural BS, etki UDC).

Statü: FROZEN. Garanti: G35 BY SEMANTICS; containment U25 UDC; tespit öncesi pencere N-26 NG. Kaynak: T20; MD-5; MD-6.

#### 15.8.3 Anahtar ömrü ve kapsam

**Plane farkı.** [AU] operasyonel anahtar ömrü hedefi "≤ 24 saat"tir (POLICY DEFAULT, §13.7.7). Identity plane imza anahtarları aylarca yaşayan JWKS anahtarlarıdır ("90 gün" sınıfı rotasyon; sayı satır satır teyit edilmedi). İki model farklı nesneleri anlatır:
- [AU] operasyonel anahtar: excerpt'li, `iat` pencereli, kısa ömürlü. Verifier'ın offline doğrulaması pencereye dayanır.
- [ID] JOSE imza anahtarı: OIDC RP'lerinin JWKS önbelleğine dayanır. Kısa ömür, JWKS yayılım gecikmesi yüzünden kırılgandır.

**CR-19 — Plane başına anahtar ömrü.**

| Anahtar | Ömür (PD) | Tavan | Gerekçe |
|---|---|---|---|
| [AU] operasyonel | **1 saat** | 24 saat (§13.7.7 hedefi, T20) | MD-6. Kısa pencere U25 blast radius'unu küçültür; signer süreci + publish-before-use (CR-25) yüksek rotasyonu ucuzlatır |
| [ID] JOSE imza | Realm politikası (PD 90 gün, **doğrulanmadı**: kaynak sayısı teyit edilmedi) | Realm politikası | JWKS önbellek ekosistemi; `T_token < T_sign` koşulu (CR-26) |
| [AU] binding | Rutin rotasyon yok | `domain.handover` / `domain.recover` | T20 |
| KEK | KMS politikası (yıllık rotasyon, çıkarım) | — | KMS'te rotasyon eski sürümleri korur |

**§13.7.7 satırı geçerlidir**. Operasyonel imza anahtarı ömrü satırının tek metni §13.7.7'dedir (MD-6: PD 1 saat, tavan ≤ 24 saat; domain-scoped; ayrı signer süreci). [ID] JOSE anahtar ömrü §13.7.9 / CR-19'dadır. Bu bölüm ayrı bir satır metni önermez.

**CR-20 — Anahtar kapsamı.** [AU] operasyonel anahtarlar domain başınadır (TI-RT6). [ID] JOSE anahtar seti realm başınadır (MD-5, MD-6). "Node başına imza anahtarı" yaklaşımı yalnız iç servis kimliği (SPIFFE SVID) ve signer sürecinin kendi mTLS kimliği için geçerlidir. Token imza anahtarı node başına çoğaltılmaz: node başına anahtar, RP'nin JWKS'inde N anahtar ve Storm-0558 benzeri kapsam karmaşası demektir (çıkarım). Statü: FROZEN. Kaynak: MD-5; MD-6.

---

### 15.9 Signer süreci ve KMS/HSM sınırı

**Sorun.** T20 operasyonel anahtarı "HSM/KMS" içinde tutar. Ölçümler bunun kapasite sınırını gösterir. Sayılar (satıcı belgeleri ve kota tablosu; ölçüm ortamları farklıdır):

| İmza noktası | ~ imza/sn | Not |
|---|---|---|
| Bellek içi (aws-lc-rs, tek çekirdek) | ~44.000 | §15.2.2'de M4'te Ed25519 imzalama 243.804/sn/çekirdek; iki sayı farklı ölçümlerden gelir ve ölçüm ortamları farklıdır |
| AWS CloudHSM | 3.000–7.000 | Örnek tipi ve algoritmaya göre |
| AWS KMS | 1.000 — hesap/bölge başına ECC/RSA/ML-DSA **paylaşımlı** kota | CloudHSM key store 1.800 sabit; kaynaklarda 300–500 tutarsızlığı var (**doğrulanmadı**) |
| Azure Managed HSM | ~990 | |
| Azure Key Vault | ~200 | |
| GCP Cloud KMS | ~50 | Kaynak sayısı; **doğrulanmadı** |
| YubiHSM 2 | ~14 | |

KMS'te Ed25519 yalnız RAW modda imzalanır, ML-DSA desteklenir. 1.000 imza/sn'de KMS maliyeti yaklaşık 38.880 USD/ay'dır.

**CR-21 — Operasyonel anahtar ayrı bir signer sürecindedir.**
1. [AU] operasyonel anahtarlar ve [ID] realm JOSE anahtarları, istek işleyen süreçlerden ayrı bir **signer sürecinde** tutulur ve kullanılır. Signer aws-lc-rs kullanır (MD-6).
2. Signer süreci sertleştirilir:
   - ağ syscall'ları yoktur (seccomp);
   - Landlock ile yalnız anahtar deposunu okur;
   - anahtarlar `memfd_secret` bölgesindedir (§15.13);
   - çağıranlarla yalnız yerel IPC (Unix domain socket) üzerinden konuşur;
   - core dump ve ptrace kapalıdır (CR-34).
3. Operasyonel anahtar KMS/HSM'de üretilir ve şifreli (KEK ile sarılı) olarak signer'a yüklenir. Unwrap yalnız signer içinde olur. Hiçbir zaman çözülmüş olarak diske veya log'a yazılmaz.
   - **FA-6 kapsamı:** FA-6 "HSM anahtarları extract edilemez" der. Bu varsayım binding key için korunur. Operasyonel anahtar varsayılan profilde HSM-dışıdır. FA-6'nın kapsamı "binding key, KEK ve FIPS profilindeki operasyonel anahtar" olarak netleşir.
4. **FIPS profilinde** operasyonel anahtar HSM içinde kalır. KMS RAW-mod veya HSM işlem maliyeti kabul edilir (MD-6, CR-15).
5. Signer süreci ve HSM her müşteriye ücretsizdir (MD-17, B3). Dedicated HSM partition ücretli paket öğesi olabilir (paketleme). Paylaşımlı partition'ın riski HL-8 / HL-20'de beyan edilir.

**Gerekçe.** Kısa ömürlü (PD 1 saat) operasyonel anahtar + signer süreci, hibrit modeldir. Binding key HSM'de, sık imzalayan kısa ömürlü anahtar bellek içindedir. KMS kota tavanını ve maliyetini aşar, blast radius'u CR-19 ile sınırlar. `max_age` / `max_signatures` eşikleri (ör. 5M imza) uygulanır: hangisi önce dolarsa rotasyon tetiklenir (PD).

Statü: FROZEN. Garanti: anahtarın signer dışına çıkmaması UNDER DECLARED CAPABILITY (OS izolasyonu; HL-21). Kaynak: MD-6; MD-17.

**SAI-45 (invariant adayı) — Signer izolasyonu.** Bir operasyonel veya realm imza anahtarının açık (unwrapped) materyali yalnız signer sürecinin korumalı belleğinde (veya FIPS profilinde HSM içinde) bulunur. Signer'ın dışarı verdiği tek çıktı imzadır. *[UNDER DECLARED CAPABILITY: OS izolasyonu, `memfd_secret`; HL-21]*

**CR-22 — KMS/HSM throughput tavanı beyanı.** Provider, kullandığı KMS/HSM'in imza kotasını ve paylaşım durumunu Domain Metadata / operasyon beyanında açıklar. Gerekçe: AWS KMS kotası hesap ve bölge başına paylaşımlıdır. Signer modeli kotayı imza başına değil anahtar üretimi ve unwrap başına kullanır. FIPS profili ise kotayı imza başına kullanır.

**HL-20 (paylaşımlı KMS/HSM kotası).** Paylaşımlı KMS/HSM kotası ve partition korelasyonu sınırı §13.5'teki HL-20'dir ("HSM/KMS throughput tavanı ve paylaşılan kotanın korelasyonlu tükenmesi"). HL-20 şunu da kapsar: paylaşımlı KMS kotası veya HSM partition'ı kullanan domain'lerin imza throughput'u **ve HSM kaynaklı kesintisi** birbirine bağlıdır; bir domain'in yükü veya bir HSM kesintisi diğerlerinin artefakt yayınını geciktirir (FIPS profilinde imza başına; signer profilinde anahtar rotasyonu başına). Bağlı: HL-1, HL-8, G42, B15. Sınıf: NG (availability). HL-25 kullanılmaz.

Statü: FROZEN.

**CR-23 — Kesinti modları: signer ≠ HSM.**

§16.7 hata modu satırı (aynen): "| HSM kesintisi | Kayıt commit, imza gecikir | Imzasız artefakt (BS, TI-12) | Artefakt gecikir |"

Signer/HSM ayrımıyla satırlar:

| Hata | Davranış | Asla | Kullanıcıya etki |
|---|---|---|---|
| Signer süreci kesintisi | Kayıt commit edilir, imza gecikir; signer yeniden başlar ve sarılı anahtarı tekrar yükler (KMS unwrap) | İmzasız artefakt (BS, TI-12; G42); signer dışında imza | Artefakt gecikir |
| HSM/KMS kesintisi (signer profili) | Mevcut operasyonel anahtarla imzalama tavan (24 saat) dolana kadar sürer. Yeni anahtar üretilemez; rotasyon ertelenir; PD 1 saat aşılır ve telemetri alarmı üretir | Tavanı aşan anahtar kullanımı; excerpt'siz imza | Yok, tavan içinde |
| HSM/KMS kesintisi (FIPS profili) | Kayıt commit edilir, imza gecikir | İmzasız artefakt (G42) | Artefakt gecikir |
| Binding key HSM kesintisi | Yeni operasyonel anahtar beyanı (excerpt) yapılamaz; mevcut excerpt'ler geçerli kalır | Binding imzasız excerpt | Tavan dolarsa artefakt gecikir |

Rotasyon jitter'ı (±%20) uygulanır: rotasyon zamanları domain'ler arasında dağıtılır, böylece KMS kotası tek anda tüketilmez. Statü: FROZEN.

---

### 15.10 `kid`, publish-before-use, düşürme ve rotasyon durum makinesi

**CR-24 — `kid` = RFC 7638 JWK thumbprint.** [AU] ve [ID] bütün yayımlanan imza anahtarlarının `kid`'i, public key'in RFC 7638 JWK thumbprint'idir (SHA-256, base64url). Gerekçe: `kid` deterministik ve içerik-bağlı olur; iki anahtar aynı `kid`'i taşıyamaz; `kid` bir anahtarı "adlandırarak" çakışma yaratamaz. `AKP` (ML-DSA) anahtarlarının thumbprint'inde hangi alanların kullanılacağı RFC 9964'e göre teyit edilir; **doğrulanmadı**. COSE tarafında `kid` aynı değerin bayt hâlidir (çıkarım). Statü: FROZEN.

**CR-25 — Publish-before-use.** Yeni bir imza anahtarı, kullanımdan önce yayımlanır:

```text
T_publish_lead ≥ T_cache + T_client + T_safety
```

- `T_cache`: yayın noktasının (JWKS / Domain Metadata) HTTP cache süresi. PD başlıklar `Cache-Control: max-age=300, stale-while-revalidate=600, stale-if-error=86400`.
- `T_client`: RP/verifier'ın kendi önbelleği. [ID]'de beyan edilmez ve tahmin edilir. [AU]'da Domain Metadata tazeliği ≤ Δ (TI-RT5).
- `T_safety`: güvenlik marjı (PD).

[AU] için T20'nin şartı aynen korunur: "yeni operasyonel anahtarın validity başlangıcı aktivasyondan en az status-list derived gecikme tavanı kadar önce beyan edilir". Kural ikisinin **büyüğü**dür: `T_publish_lead_AU ≥ max(status-list derived gecikme tavanı, Δ + T_safety)`.

Statü: FROZEN (kural); değerler PD. Kaynak: T20.

**SAI-46 (invariant adayı) — Yayımlanmamış anahtarla imza yok.** Hiçbir artefakt, imza anında yayın noktasında (Domain Metadata veya realm JWKS) en az `T_publish_lead` süredir bulunan bir anahtar dışında bir anahtarla imzalanmaz. *[BY SEMANTICS: signer durum makinesi kuralı; yayının verifier'a ulaşması UNDER DECLARED POLICY]*

**CR-26 — Düşürme ve saklama.**

```text
[ID]  T_drop ≥ son imza zamanı + T_token_max + T_safety       (koşul: T_token < T_sign)
[AU]  public key yayında kalır ≥ validUntil + max yerel kabul tavanı (Verifier Profile'lardaki en büyük horizon)
```

- [ID]: Bir JOSE anahtarı, onunla imzalanmış en uzun ömürlü token sona erene kadar JWKS'te kalır. Token ömrü anahtarın imza süresinden kısa olmalıdır (`T_token < T_sign`).
- [AU]: Artefaktın kabul süresi `min(horizon, iat + yerel tavan)`'dır (T20). Bu yüzden public key bu sürenin sonuna kadar doğrulanabilir kalmalıdır. Ayrıca **uzun süreli doğrulanabilirlik** (§13.2) gereği eski operasyonel anahtarların public kısımları ve excerpt'leri arşivde **süresiz** tutulur (Record Export, offline doğrulama). "Düşürme" yalnız aktif yayın listesinden çıkarmaktır. Private materyal DROPPED'ta yok edilir.

Statü: FROZEN. Kaynak: T20.

**CR-27 — Rotasyon durum makinesi.**

```text
PENDING ──publish──► PUBLISHED ──(T_publish_lead geçti)──► ACTIVE ──(rotasyon / max_age / max_signatures)──► RETIRING ──(T_drop)──► DROPPED
   │                                                                                                                │
   └─(iptal)──────────────────────────────────────────────────────────────────────────────────────────────────────► DROPPED
```

- Yalnız ACTIVE durumundaki anahtar imzalar. PUBLISHED ve RETIRING anahtarlar yalnız doğrulamada kullanılır.
- DROPPED'ta private materyal zeroize edilir (CR-33); public materyal arşivde kalır (CR-26).
- Her geçiş denetlenir. [AU]'da anahtar beyanı Domain Metadata'nın binding imzalı içeriğidir; bu bir Authority Record değil, Domain Metadata yayınıdır (derived yayın). Geçişler OPERATIONAL audit akışına yazılır (§17). [ID]'de geçişler realm audit olayıdır.
- Compromise'da: [AU]'da durum makinesi değil `domain.recover` çalışır (SEC21). [ID]'de anahtar acil DROPPED'a geçer ve RP'lere SSF/CAEP veya logout ile bildirilir (§10). Pre-publish edilmiş yedek anahtar yoksa geçiş `T_publish_lead` kadar kesinti yaratır, bu yüzden her realm'de 1 aktif + en az 1 PUBLISHED yedek tutulur (MD-6 "1 aktif + N pasif").
- SPIRE'ın budama disiplini (48 saat / 6 saat / 2 hafta) iç SVID'ler için referanstır.

Statü: FROZEN. Kaynak: MD-6.

---

### 15.11 Tören, quorum, binding key DR, PKCS#11 ve recovery anahtarları

**CR-28 — HSM erişim katmanı.** HSM erişimi PKCS#11 üzerinden yapılır: `cryptoki` 0.12 + `r2d2-cryptoki` oturum havuzu. PKCS#11 çağrıları bloklayıcıdır ve async runtime'da ayrı blocking thread havuzunda çalışır. Tek bir HSM oturumu kilitlenirse istek yolu bloklanmaz. KMIP WATCH statüsündedir: olgun bir Rust KMIP istemcisi yoktur ve KMS sağlayıcıları kendi API'lerini kullanır (çıkarım). T5'teki HSM erişimi "PKCS#11 (KMIP WATCH)"tır. Statü: FROZEN (PKCS#11), WATCH (KMIP).

**CR-29 — Anahtar töreni ve quorum'un anlamı.**
1. **Tören:** Binding key üretimi ve HSM partition kurulumu M-of-N operatör tarafından yapılır. Tören videoya kaydedilir, tanıklı tutanak tutulur ve script'li adımlarla ilerler. Let's Encrypt "boulder ceremony" sınıfı uygulama örnektir. Tutanağın digest'i Domain Metadata'da beyan edilir (çıkarım: bağlama yöntemi kaynakta yok).
2. **Quorum'un anlamı:** FA-6 "binding key kullanımı quorum'lu" der. Bu ifade **imza başına** quorum değildir. Quorum, binding key'in **aktivasyonunu** (HSM'de anahtarın kullanılabilir kılınması) ve **politikasını** (hangi operasyonel anahtarların excerpt'lerinin imzalanacağı) korur. Binding key yalnız excerpt ve Domain Metadata imzalar; bu imzalar operasyonel anahtar rotasyonu sıklığında (PD saatlik) olur. Her excerpt için k-of-n insan onayı operasyonel olarak mümkün değildir (çıkarım). Bu yüzden quorum, HSM'in M-of-N kimlik doğrulamasıyla anahtar oturumunu açar ve rotasyon otomasyonu bu oturum içinde imzalar. Oturumun ömrü ve kapsamı politika ile sınırlıdır (PD).
3. Binding key'in kendisinin değişimi yalnız `domain.handover` / `domain.recover`'dır (T20). Bu Exercise'lar rootTerms quorum'unu ister (§13.7.7).

FA-6'nın anlamı: "HSM anahtarları extract edilemez; binding key'in aktivasyonu ve politikası quorum'lu (imza başına değil)".

Statü: FROZEN. Kaynak: FA-6.

**CR-30 — Binding key DR ve paylaşımlı partition.**
1. Binding key'in felaket kurtarması yalnız HSM-içi klonlama (aynı üreticinin wrapped backup / cluster klonlama mekanizması) ile ve quorum altında yapılır. Binding key HSM dışına açık olarak çıkmaz (FA-6).
2. Binding key kaybedilirse (bütün HSM klonları yok) "yeni binding key üret" diye bir yol yoktur. Tek yol `domain.recover`'dır: root/rootTerms quorum'u, yeni provider anahtarları, N = SEC21 tanımı (FA bağı). Rutin binding key rotasyonu yoktur (T20).
3. Paylaşımlı HSM partition'ı beyan edilir (T20, RT12: "K-6: HSM partition paylaşımı FA-8 eki olarak beyan"). Paylaşım iki korelasyon getirir: ihlal korelasyonu (HL-8) ve throughput / kesinti korelasyonu (HL-20).

Statü: FROZEN. Kaynak: T20; RT12; FA-6.

**CR-31 — Recovery anahtarları ve custody signer.**
- SEC20 (aynen): "**SEC20** rootTerms domain.recover entry'sinin anahtarları (root Party Instance KeyBinding'leri) provider veya provider operatörü tarafından custody edilemez; Suiss-hosted domain oluşturma bunu zorunlu kılar (PI-15 ile)."
- §13.7.7 `domain.recover` satırı: 3-of-5 (org) / 2-of-3 (küçük); ≥ 2 donanım-bağlı; hiçbiri provider/operatör custody'sinde değil. Tam metin §13.7.7'dedir; prosedür §13.6 ve §16.6. Bu bölüm yalnız anahtar boyutuna atıf yapar.
- **T32 → §16.10 T32**. Bölüme özgü özet: user-gated custody = attested TEE custody signer + HSM KEK; assertion challenge imzalanacak payload digest'idir.
- SEC17 (aynen): "**SEC17** Custodial anahtarlar user-gated'dir (her kullanım Party'nin cihaz-bağlı authenticator assertion'ını ister); non-custodial controller'a geçiş her zaman açıktır; CT3 tutanlar varsayılan olarak non-custodial'dır. Custodial ve user-gated olmayan mod NOT GUARANTEED olarak beyan edilir."
- SEC19 (aynen): "**SEC19** Identity plane custody anahtarları Access provider rolünde kullanılmaz; görev ayrılığı beyan edilir (UDC)."
- FA-8 (aynen): "| FA-8 | TEE ölçümü ve attestation'ı dürüsttür | TEE üreticisi | User-gated custody NG'ye düşer (DL-1) |"

Custody signer süreci CR-21'in sertleştirmesini ve §15.13 bellek hijyenini aynen uygular (çıkarım: aynı sınıf sır). Statü: FROZEN.

---

### 15.12 KEK/DEK, crypto-shredding ve `basis_ref` anahtarı

Bağlı kurallar:
- **T27 → §16.10 T27** (MD-5). Bölüme özgü özet: domain başına KEK, body başına DEK.
- **T39 → §16.10 T39**. Bölüme özgü özet: body başına DEK, crypto-shredding; leaf hash ve digest'ler süresiz.
- **T31 → §16.10 T31**. Bölüme özgü özet: identity plane ayrı KMS ve operatör rolleri; PII crypto-shredding.
- TI-RT10 (aynen): "**TI-RT10** Audit altı viewer'a giden pozisyon taşıyan tanımlayıcılar (`basis_ref` dahil) domain başına anahtarla türetilmiş opaque token'dır; event id anahtarlı MAC'tir (HMAC); anahtar domain dışına çıkmaz."
- Ownership tablosu `basis_ref` satırı (aynen): "| `basis_ref` / event-id anahtarı | AuthorityDomain (domain başına) | Secret | Opaque `basis_ref` token'ı ve HMAC event id bu anahtardan türer; anahtar domain'in authoritative provider'ı dışına çıkmaz; kooperatif handover'da Record Export Package içinde yalnız yeni provider'a açık biçimde taşınır; forced recovery'de anahtar yoksa eski token'lar çözülmez ve fail closed olur | TI-RT10, T11 |"

**CR-32 — KEK/DEK ve sır deposu.**
1. KEK domain başınadır ([AU], T27) veya realm başınadır ([ID] PII, T31; MD-5). KEK KMS/HSM'de tutulur ve dışarı çıkmaz. DEK body başınadır (T39). Crypto-shredding = DEK'in yok edilmesi. Leaf hash ve digest'ler süresiz kalır (T39).
2. **Data-key önbelleği:** Çözülmüş DEK'ler kısa süreli bellek önbelleğinde tutulabilir. Sınırlar: üst süre (PD 5 dakika, çıkarım; kaynak sayısı teyit edilmedi), mesaj ve bayt sayısı. Önbellek §15.13 tip disiplinine tabidir. Gerekçe KMS kotası ve gecikmesidir.
3. **Crypto-shredding'in sınırı:** Önbellekteki, yedeklerdeki veya replica'lardaki DEK kopyaları shredding'i geciktirir. Shredding, bütün DEK kopyalarının tavan süresi (önbellek TTL + yedek saklama penceresi) dolunca tamamlanmış sayılır. "Anında silme" iddia edilmez (NG; B15 dili).
4. **Sır deposu:** Vault / OpenBao **zorunlu değildir**. Altyapı sırları (DB parolaları, harici API anahtarları) bulut KMS + workload identity (CR-35) ile yönetilir. Müşteri kendi Vault/OpenBao'sunu kullanıyorsa KEK sağlayıcısı olarak bağlanabilir (UDC). Bu seçim §16'dadır.
5. **`basis_ref` / event-id anahtarı** domain başına bir secret'tır (TI-RT10). Yalnız authoritative provider'ın signer veya KMS sınırında tutulur. Kooperatif handover'da Record Export Package içinde yalnız yeni provider'a açık biçimde (yeni provider'ın KEK'ine sarılı) taşınır. Bu, CR-35'in "yedekte ve dump'ta sır yok" kuralının **tek istisnasıdır**. Forced recovery'de anahtar yoksa eski token'lar fail closed olur.

Statü: FROZEN. Garanti: confidentiality at rest semantik değildir (§13.2); shredding'in tamamlanması UNDER DECLARED POLICY (tavanlar beyan edilir). Kaynak: T27; T31; T39; TI-RT10.

---

### 15.13 Sır yönetimi ve bellek hijyeni

Bu bölüm signer (CR-21), custody signer (T32), DEK önbelleği (CR-32), verifier'ın sır tutan bileşenleri ve identity plane'in bütün sırları için geçerlidir.

**CR-33 — Sır tipleri ve sıfırlama.**
1. Her sır tipi `zeroize` (1.9.x) ile `ZeroizeOnDrop` taşır. API sınırlarında `secrecy` 0.10.x (`SecretBox<T>`, `SecretString`, `ExposeSecret`) kullanılır. Elle sıfırlama kodu yazılmaz: CipherStash'in assembly incelemesinde naif `Drop` sıfırlaması `[u8; 4]` için tamamen silinmiştir.
2. Sırlar heap'te tutulur (`SecretBox`), `Copy` implement etmez ve referansla geçirilir; move semantiğinin stack kopyası bırakmasını önler. `Vec` / `String` büyümesi yasaktır: sabit kapasite veya sabit boyutlu dizi kullanılır.
3. `secrecy` 0.10, `cryptoki`'nin PIN tipiyle aynı sürümde tutulur.
4. Access'e özgü tip disiplini (`Secret<N>` sabit uzunluklu newtype, `*_vartime` adlandırması) yan kanal kuralıdır ve §15.15'tedir (CR-39).
5. **Sınır (14 vektör).** `zeroize` ve `secrecy` şu vektörleri **kapsamaz**. Her vektörün karşılığı ve garanti sınıfı:

| # | Vektör | Access'teki karşılık | Garanti |
|---|---|---|---|
| 1–2 | Derleyici kopyası / move kopyası | Heap indirection, `Copy` yok | UDC (derleyici davranışı) |
| 3–4 | `Vec` / `String` yeniden tahsisi | Sabit kapasite; büyüme yasak | UDC |
| 5 | `mem::forget` / leak | Kod incelemesi; lint (araç doğrulanmadı) | NG |
| 6 | Panic/unwind; `panic = "abort"` | Ağ süreçlerinde abort yok (MD-2). Signer ve kernel worker'da abort izinlidir, bu durumda Drop çalışmaz; koruma OS katmanıdır (#7) | UDC |
| 7 | SIGKILL / abort | `memfd_secret` veya `mlock` (CR-34) | UDC |
| 8 | Core dump | `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `MADV_DONTDUMP` (CR-34) | UDC |
| 9 | Swap | `mlock` / `memfd_secret` | UDC |
| 10 | Hibernation | `memfd_secret` aktifken hibernation engellenir | UDC |
| 11 | DMA / cold boot | IOMMU, bellek şifreleme (SME/SEV, TME/TDX); barındırma beyanı | NG (Access tarafından) |
| 12 | Hipervizör snapshot'ı / canlı göç | Confidential computing (SEV-SNP, TDX, Nitro); barındırma beyanı | NG (Access tarafından) |
| 13 | Spectre/Meltdown sınıfı | Mikrokod ve kernel azaltmaları; barındırma (CR-40) | NG |
| 14 | CPU register'ları | Karşılık yok; kabul edilmiş risk | NG |

**Panic profili ve sır temizliği.** Panic profili MD-2'dir: `abort` ağ süreçlerinde yasaktır; kernel, signer ve parser worker'larında izinlidir. Signer'da abort'un Drop'u atlaması, sırrın OS-korumalı bellekte (`memfd_secret`) olmasıyla telafi edilir: süreç ölünce sayfa sistemden kalkar (çıkarım). Sabit zamanlı imza için `ed25519-dalek` / `p256` kullanılmaz; sağlayıcı aws-lc-rs'tir (MD-1).

Statü: FROZEN.

**CR-34 — İşletim sistemi seviyesi koruma ve sertleştirme modları.**
1. **`memfd_secret(2)`:** Signer, custody signer ve DEK önbelleği anahtarları önce `memfd_secret` ile ayrılır. Mekanizma Linux 5.14'te eklendi; 6.5 öncesinde `secretmem.enable=y` gerekir. `ENOSYS` dönerse `mlock`'a düşülür. Arka uç metrikle raporlanır: `access_secret_memory_backend{type="memfd_secret|mlock|none"}`. Man sayfası %100 garanti vermez ve kernel'den okunabildiğine dair kanıt vardır (nosecmem). Bu nedenle garanti UDC'dir. Yönetilen Kubernetes node'larında çalışıp çalışmadığı doğrulanmadı.
2. **`mlock`:** Başlangıçta `getrlimit(RLIMIT_MEMLOCK)` okunur, log'lanır ve yetersizse uyarı verilir. Dağıtım dokümanı `IPC_LOCK` gerektirir. Container varsayılan memlock değeri doğrulanmadı.
3. **Guard page'ler:** `secrets` crate'i (guard page, canary, mlock) yalnız signer'ın uzun ömürlü anahtarları için kullanılabilir. Benimsenmesi düşüktür (90 günde ~9.661 indirme), bu yüzden kaynağı incelenmeden kullanılmaz.
4. **Core dump ve ptrace:** `prctl(PR_SET_DUMPABLE, 0)`, `setrlimit(RLIMIT_CORE, 0)` ve sır sayfalarında `madvise(MADV_DONTDUMP)` kullanılır. `PR_SET_DUMPABLE=0`, `/proc/<pid>/mem|environ|maps` erişimini ve `PTRACE_ATTACH`'ı kapatır. `core_pattern` pipe'a yönleniyorsa `RLIMIT_CORE` bypass edilebilir, bu yüzden `PR_SET_DUMPABLE` esastır.
5. **Sertleştirme modları:**

```text
ACCESS_HARDENING=paranoid  → PR_SET_DUMPABLE=0 + RLIMIT_CORE=0 + mlock + memfd_secret   (signer, custody signer: ZORUNLU)
ACCESS_HARDENING=balanced  → MADV_DONTDUMP (sır sayfaları) + RLIMIT_CORE=0 + mlock      (diğer üretim süreçleri: varsayılan)
ACCESS_HARDENING=dev       → hiçbiri; başlangıçta uyarı log'u + metrik                      (yalnız geliştirme)
```

Varsayılan `balanced`'tır. Signer ve custody signer süreçlerinde `paranoid` zorunludur, çünkü bu süreçler debuggability'ye değil izolasyona göre tasarlanmıştır (CR-21). Üretimde `dev` modu başlatma hatasıdır (fail closed, MD-8). Debuggability maliyeti (gdb/strace yok) tracing span'leri ve yapılandırılmış backtrace ile telafi edilir.

Statü: FROZEN (modlar); arka uç seçimi PD.

**CR-35 — Sırların başlatılması, log redaksiyonu, yedekler.**
1. **Bootstrap:** Sırlar ortam değişkeninden veya Kubernetes Secret'ından okunmaz. Süreç kendi workload identity'siyle (SPIFFE SVID / bulut IAM rolü; T36) KMS'ten kendi sarılı anahtarını açar. Gerekçe: ortam değişkenleri `/proc/<pid>/environ` üzerinden ve K8s Secret'lar etcd'de base64 olarak sızar. Bootstrap'ın kendi tavuk-yumurta kaynağı workload identity'dir; bu UDC'dir (platform IAM'ine güven).
2. **Log ve `Debug` redaksiyonu:** Sır içeren hiçbir tip `#[derive(Debug)]` taşımaz. Redakte eden `Debug` (secrecy) kullanılır. `tracing`'de `?` sigil'iyle sır tipi log'lanamaz. CI testi, bilinen test sırrının (canary değeri) hiçbir log, hata mesajı, panic çıktısı veya telemetri kanalında görünmediğini doğrular. Bu kural §17 log politikası ve DLP owner'ı ile çelişmez: Access kendi sırlarından sorumludur (SEC3).
3. **Yedekler, dump'lar, replikasyon:** Açık sır içermez. Yalnız KEK'e sarılı materyal içerebilir. **Tek istisna** `basis_ref` / event-id anahtarıdır: kooperatif handover'da Record Export Package içinde yalnız yeni provider'a açık biçimde taşınır (CR-32; §16.6 HO-4). Bu istisna "açık" ifadesini "yeni provider'ın KEK'ine sarılı" olarak yorumlar (çıkarım; HO-4 "yalnız yeni provider'a açık biçimde" der, yani yalnız yeni provider'ın açabildiği biçim).

Statü: FROZEN.

---

### 15.14 Parola ve token saklama (yalnız [ID] ve [PL])

**CR-36 — Parola hash'i: Argon2id, kalibre edilmiş; DoS korumalı.**
1. **Algoritma:** Argon2id. FIPS profilinde PBKDF2-HMAC-SHA256 600.000 iterasyon (CR-15).
2. **Parametreler (POLICY DEFAULT, kalibre edilir).** OWASP eşdeğer setlerinden biri seçilir ve hedef donanımda kalibre edilir. Ölçüm (Apple M4, tek makine, EA):

| Set | Süre/hash | 4 thread ölçeklenme | Not |
|---|---|---|---|
| m = 7 MiB, t = 5, p = 1 (Keycloak varsayılanı; OWASP eşdeğeri) | 8,95 ms | %87 | Düşük bellek → DoS yüzeyi küçük, ölçeklenme iyi |
| m = 19 MiB, t = 2, p = 1 (OWASP ilk seçenek) | 10,65 ms | %69 | Bellek bant genişliği darboğazı |
| m = 64 MiB, t = 3 | 66 ms | — | IdP için ağır |

   Access varsayılanı **m = 7 MiB, t = 5, p = 1**'dir (PD). Gerekçe: süre benzerdir, ölçeklenme ve DoS yüzeyi daha iyidir. Bu değer bu spec'in **kanonik** Argon2id değeridir; §10.2.1, IDP-3 ve §14.6 kapasite örneği buna atıf yapar (OWASP'ın m=19 MiB, t=2 seti kalibrasyon aralığıdır, varsayılan değildir). RFC 9106'nın GiB mertebesindeki "önerilen" ayarları IdP bağlamında reddedilir (DoS matematiği). Kalibrasyon hedefi bir süre değil, semaforla birlikte throughput/p99 hedefidir (PD, implementasyonda belirlenir).
3. **Semafor ve yük atma:** Eşzamanlı hash sayısı semaforla sınırlıdır: `N = floor(bellek_bütçesi × 0,5 / m_cost)`; `cpu-cores` ile de sınırlanır. Kuyrukta 500 ms bekleyen istek `503 + Retry-After` ile reddedilir. Ölçüm (M4): semafor = 10 iken 403,9 hash/sn ve p99 4,77 ms; sınırsızda p99 119 ms (25 kat kötü). Semafor varoluştan bağımsızdır: var olan ve olmayan kullanıcı aynı semaforu aynı biçimde kullanır ya da hiç kullanmaz (MD-18).
4. **Dummy Argon2 yok (MD-18).** Kullanıcı yokken sahte Argon2 hesaplanmaz. Gerekçe: saldırgana ücretsiz memory-hard iş verir (DoS) ve parametre veya algoritma göçünde zamanı eşitleyemez. Django CVE-2024-39329, dummy hash'e rağmen 11 yıl sonra çıkmıştır. Yerine: **adaptif gecikme** kullanılır. Başarısız yanıt, koşan başarı ortalamasına doldurulur (Rauthy `login_delay.rs` deseni). Bunun üzerine rate limit ve IP/hesap başına artan ceza eklenir; ceza, var olan ve olmayan hesap için aynı davranır. Garanti: enumeration direnci UNDER DECLARED POLICY; tam eşitlik NG (ortalama istatistikseldir).
5. Enumeration'ın protokol tarafı (aynı gövde/status/yönlendirme) CR-40'tadır.

Statü: FROZEN (algoritma, semafor, dummy yok); parametreler PD. Kaynak: MD-18.

**CR-37 — Pepper ve rehash göçü.**
1. **Pepper (opsiyonel, ENGINEERING ASSUMPTION):** Realm, parola hash'ine KMS/HSM'de tutulan bir pepper ekleyebilir (HMAC ön-işlemi veya Argon2 `secret` parametresi). Değeri "yalnız DB sızıntısı, uygulama belleği sızmadan" senaryosundadır. Pepper bellekte bulunduğu için bellek sızıntısında koruma vermez (**doğrulanmadı**). Pepper rotasyonu yalnız bir sonraki başarılı girişte yeniden hash'leme ile yapılabilir. Bu yüzden pepper sürümü hash kaydında saklanır.
2. **Rehash göçü:** Hash kaydı PHC string biçimindedir (algoritma + parametreler + salt + pepper sürümü). Başarılı girişte kayıtlı parametre güncel politikadan zayıfsa parola yeniden hash'lenir. Legacy algoritmalar (bcrypt, PBKDF2, scrypt) yalnız ingest edilmiş hesaplar için doğrulanır ve ilk başarılı girişte Argon2id'ye göç ettirilir. Göç bekleyen hesap sayısı telemetridir.

Statü: PD (pepper EA).

**CR-38 — Client secret, API anahtarı ve opak token saklama.**
1. **Client secret ve API anahtarı:** Sunucuda üretilir, ≥ 256 bit entropi taşır ve sabit uzunluktadır. Kullanıcı seçimli client secret kabul edilmez. Saklama: `SHA-256(secret)` veya realm anahtarlı `HMAC-SHA256(k, secret)`. Argon2 kullanılmaz, çünkü yüksek entropili sır için gerekmez ve her token isteğinde DoS yüzeyi yaratır. Doğrulama: gelen değerin hash'i hesaplanır ve sabit zamanlı karşılaştırılır.
2. **Opak token'lar:** Refresh token, şifre sıfırlama token'ı, magic link, device code, authorization code ve opak session id sunucuda üretilir, ≥ 128 bit (PD 256 bit) ve sabit uzunluktadır. Veritabanına yalnız `SHA-256(token)` yazılır; arama hash üzerinden yapılır; dönen kayıt sabit zamanlı doğrulanır. Böylece B-tree prefix zamanlaması ve DB dump'ının yeniden kullanılması kapanır. Sıfırlama ve magic link tokenları tek kullanımlıktır ve süreleri dolar (OWASP).
3. **TOTP seed'i:** Hash'lenemez, çünkü doğrulama için açık seed gerekir. Realm PII KEK'i ile sarılı saklanır (T31). TOTP kodu sabit zamanlı karşılaştırılır (RUSTSEC-2022-0018).

Statü: FROZEN. Garanti: DB sızıntısında token yeniden kullanılamaması UNDER DECLARED POLICY.

---

### 15.15 Yan kanallar

İlgili kayıtlar DL-7 (policy oracle) ve SEC31'dir. DL-7: "| DL-7 | **Policy oracle.** Karar yüzeyinin kendisi bir oracle'dır; tekrar eden sorgulardan eşik çıkarımı tamamen önlenemez | NOT GUARANTEED (disclosure scope, rate ve tespit ile sınırlanır) | Determinism (INV-27) rastgele gürültüyü yasaklar |"

SEC31: "**SEC31** Advisory check ve explain çağrıları canonical kayıt değildir ama operasyonel telemetri olarak sayılabilir; determinism gereği rastgele cevap savunması yoktur."

**Tehdit modeli.** Timeless Timing Attacks (Van Goethem ve diğ., USENIX Security 2020): HTTP/2 üzerinden yaklaşık 40.000 istek çiftiyle yanıt sırasından 100 ns'lik fark çıkarılabilir; ağ jitter'ı elenir. Bu yüzden "nanosaniyeler uzaktan ölçülemez" argümanı geçersizdir. Bütün sır karşılaştırmaları sabit zamanlıdır.

**CR-39 — Sabit zaman disiplini, tip ve doğrulama araçları.**
1. **Sabit zamanlı karşılaştırma zorunlu noktalar.** [ID] (10 nokta): opak token araması (önce hash), HMAC/JWS doğrulama, TOTP, client secret, API anahtarı, CSRF/state, sıfırlama/magic link, PKCE verifier, device/user code (asıl savunma rate limit), WebAuthn challenge. [AU] ekleri (çıkarım): nonce/`jti` eşleşmesi, `basis_ref` token çözümleme, HMAC event id doğrulaması, status list bit indeksinin gizli olduğu durumlar dışında bit okuma (indeks gizli değildir; kural yalnız sır içerikli karşılaştırmaya uygulanır), `proof_commit` digest eşleşmesi (digest gizli değildir, ancak maliyet sıfırdır).
2. **Tip disiplini:** Sır karşılaştırması yalnız `Secret<N>` sabit uzunluklu newtype üzerinden ve yalnız sabit zamanlı `ct_eq` ile yapılır. `Secret<N>` `PartialEq`, `Debug`, `Display` ve `Hash` implement etmez. Değişken zamanlı (verinin değerine göre dallanan) fonksiyonlar `*_vartime` sonekini taşır ve sır tipiyle çağrılamaz. Bu kurallar Clippy lint'i veya özel lint ile CI'da zorlanır (lint'in adı ve implementasyonu uygulama kalemi).
3. **Uzunluk sızıntısı:** `ct_eq` eşit uzunluk ister; token'lar sabit uzunluktadır.
4. **Hash-then-compare:** Mümkün olan her yerde (token, API anahtarı) karşılaştırma hash üzerinden yapılır. Bu, derleyici kaynaklı sızıntıya karşı ikinci savunmadır.
5. **Derleyici riski ve doğrulama araçları:** Rust `std::hint::black_box` hiçbir garanti vermez. Gerçek CVE'ler: RUSTSEC-2026-0003 (`cmov`: derleyicinin sabit zamanlı seçimi dallanmaya çevirmesi), RUSTSEC-2025-0144 (`ml-dsa` UDIV), RUSTSEC-2026-0211 ve 2026-0212 (`libcrux`), RUSTSEC-2024-0354. CI'da şu üç araç çalışır:
   - **dudect** istatistik testi: |t| > 5 sızıntı sayılır ve CI'ı kırar;
   - **ctgrind** / Valgrind tabanlı gizli-bağımlı dallanma denetimi;
   - kritik fonksiyonların **assembly snapshot**'ı: derleyici sürümü değişince diff incelenir.
6. **CPU özellikleri:** ARM64'te kriptografik ve karşılaştırma kodu DIT (`PSTATE.DIT`) açıkken çalışır (`aarch64-dit` RAII guard). x86'da DOITM global açılmaz (Intel önermiyor); kritik kod DOIT listesindeki komutlara dayanır. GoFetch (DMP) M1/M2'de sabit zamanlı kodu kırar. Bu yüzden üretim signer'ı Apple Silicon'da çalışmaz.

Statü: FROZEN. Garanti: sabit zamanlılık UNDER DECLARED CAPABILITY (derleyici ve CPU; HL-16).

**SAI-42 (invariant adayı) — Sır karşılaştırması sabit zamanlıdır.** Bir sır, sır türevi veya kullanıcının sunduğu kimlik bilgisi ile depolanmış değer arasındaki her eşitlik kontrolü, girdinin değerinden bağımsız sürede ve sabit uzunlukta yapılır. Mümkünse önce hash'lenir. *[UNDER DECLARED CAPABILITY: derleyici ve CPU; dudect/ctgrind kapısı]*

**CR-40 — Enumeration eşdeğerliği, dolgu ve barındırma.**
1. **[ID] enumeration (15 kanal):** Hata metni, HTTP status, gövde uzunluğu, URL hata parametresi, URI probing, yönlendirme hedefi, rate limit davranışı, sıfırlama akışı, kayıt akışı ("email already in use" e-postayla bildirilir), WebAuthn `allowCredentials` (discoverable credential tercih edilir), SCIM filter (yetkisiz sorgu reddi), OIDC hata kodları, `prompt=none`, sosyal login mesajı ve tahmin edilebilir kullanıcı adı. Var olan ve olmayan hesap için hepsinde aynı gövde, aynı status, aynı yönlendirme ve doldurulmuş süre kullanılır (CR-36 adaptif gecikme). Login akışı kullanıcı adı ve parolayı birlikte alır, MFA sonra gelir. Identity-first akış kullanılıyorsa parola formu her zaman gösterilir. Her yeni akış için enumeration regresyon testi zorunludur (Keycloak CVE-2026-4633 dersi). Kanidm'in "enumeration'ı önlememe" seçimi reddedilir. Gerekçe: Access'in hesap varlığı da DL-7 sınıfı bir oracle'dır ve en azından tutarlılık verilebilir.
2. **[AU] enumeration.** Authority plane'de bir karar isteğinin yanıtı "basis yok" ile "basis var ama çağıran görme yetkisinde değil" ayrımını sızdırmaz. Disclosure scope dışındaki bir basis için yanıt, var olmayan basis'in yanıtıyla aynı sınıftadır: aynı outcome kodu, aynı yapı, aynı uzunluk sınıfı. Bu, SI-14 (disclosure monotonluğu) ve DL-7'nin zamanlama ve uzunluk boyutudur.
3. **Dolgu ↔ INV-27.** INV-27 (determinism) ve SEC31 rastgele cevap savunmasını yasaklar. Zamanlama dolgusu ve rastgele gecikme (~1,73 ms ortalama jitter) bununla şöyle bağdaşır: **Dolgu serbesttir, içerik rastgeleliği yasaktır.** Yanıt süresinin ve yanıt boyutunun (sabit boyut sınıflarına) doldurulması semantik çıktıyı değiştirmez; yanıt içeriği (outcome, kayıt, digest) deterministik kalır. Rastgele gecikme yalnız zaman ekseninde uygulanabilir, ama saldırıyı yok etmez, yalnız sıralı saldırı seviyesine indirir. Bu yüzden birincil savunma sabit zaman ve adaptif dolgudur.
4. **Barındırma**: Signer ve custody signer, dedicated host veya en az çekirdek izolasyonu varsa orada çalışır (PD). Paylaşımlı barındırmada bulut co-tenant mikromimari riski (Spectre sınıfı, DMP) DL-10 / HL-17 olarak beyanlıdır (MD-17). Dedicated compute B4 opsiyonudur; ücretsiz değildir (MD-17 yalnız signer ayrımını ve HSM'i ücretsiz kılar).

Statü: FROZEN. Garanti: [AU] eşdeğerlik BY SEMANTICS (yanıt yapısı); zamanlama eşdeğerliği UNDER DECLARED POLICY; tam zamanlama eşitliği NG (DL-7). Kaynak: INV-27; SEC31; DL-7.

**SAI-43 (invariant adayı) — Yetkisiz ≡ var olmayan.** Çağıranın disclosure scope'u dışındaki bir nesne (basis, Grant, Party, hesap) için verilen yanıt, var olmayan nesne için verilen yanıttan outcome, yapı ve boyut sınıfı bakımından ayırt edilemez. *[BY SEMANTICS (içerik); zamanlama UNDER DECLARED POLICY; DL-7 sınırı]*

**HL-28 (emekli) → HL-16 + HL-21 (co-tenant: HL-17 / DL-10)**. Platform sabit zamanlılığı §13.5'teki HL-16'dır ("Derleyici (LLVM) constant-time garanti etmez"); bellek-içi sır koruması HL-21'dir ("Bellekteki sır: zeroize'ın kapsamadığı vektörler"); co-tenant SMT riski HL-17 / DL-10'dur (MD-17). Bu bölümün eklediği ayrıntı o satırlara katlanır: sabit zamanlı yürütme ve bellek-içi sır koruması derleyiciye, CPU'ya ve barındırmaya bağlıdır; mikromimari kanallar (Spectre sınıfı, DMP/GoFetch), co-tenant SMT, hipervizör snapshot'ı, DMA/cold boot ve CPU register kalıntısı Access tarafından kapatılamaz. Bağlı: CR-33, CR-34, CR-39, CR-40; MD-17; DL-7. Sınıf: NG. HL-28 ID'si yeniden kullanılmaz.

---

### 15.16 Crypto-agility

**İlgili ilkeler.** PI-21 (imzalı içerikte sürüm ve profil kimliği), SI-18 (downgrade = genişletme), §13.2 "uzun süreli doğrulanabilirlik / crypto agility" satırı, FA-5 ve U21:
- FA-5: kanonik metni §16.2'dedir ve §15.18'deki koşulu taşır.
- U21: "| U21 | "Existed by T" | Witness zaman sabitlemesi |"

**Agility kuralları (dayanak: PI-21, SI-18, CR-5, CR-7, CR-8):**
1. Her imzalı içerik algoritma kimliğini taşır. Her digest algoritma etiketi taşır (CR-1).
2. Kabul kümesi Domain Metadata / realm metadata'dadır. Ekleme CT3 + 24 saattir, çıkarma CT1'dir (CR-8).
3. Bir algoritmanın emekliye ayrılması üç adımdır: (a) yeni artefaktlar yeni algoritmayla imzalanır; (b) eski algoritma kabul kümesinden CT1 ile çıkarılır, yani yeni gelen eski-algoritmalı artefakt reddedilir; (c) **geçmiş** kayıtların doğrulanabilirliği re-anchor ile korunur (§15.18). Kayıtlar yeniden imzalanmaz.
4. Algoritma "kırıldı" kararı bir domain kararıdır (SI-18 gereği domain'in kendi meta-Exercise'ı). Provider yalnız önerir. Provider-genel bir kırılmada (ör. CRQC duyurusu) her domain'in kendi CT1'i gerekir. Bu operasyonel bir koordinasyon yüküdür (çıkarım; §17 runbook).
5. Kernel'de algoritma eklemek, bir semantik sürüm yayımı sayılır ve MD-15(b) sürüm kapısına girer: vektörler, DRT ve ispatlar geçmeden yayımlanmaz (CR-49).

Statü: FROZEN. Kaynak: PI-21; SI-18.

---

### 15.17 PQC notu

Bu alt bölüm MD-19.3'ün gerektirdiği "T5 PQ notu"dur. Şu öğeler invariant dilinde yazılmaz: landscape'teki standart statüleri ("kayıt statüsü doğrulanmadı" etiketleri korunur), T5'teki post-quantum notu, §13.7 POLICY DEFAULT değerleri, ENGINEERING ASSUMPTION sayıları, H1–H16 ve D1–D9. Bu yüzden bu not **invariant değildir**; standart statüleri, takvimler ve sürüm bilgileri WATCH/EA etiketlidir.

#### 15.17.1 Standart ve ekosistem durumu (8 Eylül 2026 okuması)

| Konu | Durum |
|---|---|
| ML-DSA (FIPS 204) JOSE/COSE | **RFC 9964 yayımlandı** (Mayıs 2026). `ML-DSA-44/65/87`; COSE −48/−49/−50; `kty: AKP` (COSE `kty` 7); `priv` = 32 baytlık seed; HashML-DSA tanımlanmaz; `alg` zorunlu |
| Composite ML-DSA (JOSE/COSE) | `draft-ietf-jose-pq-composite-sigs-03`, **RFC değil**. Taslaktaki geçici kod noktaları (−54…−59) başka kayıtlarla çakışır; sabit kodlanmaz |
| SLH-DSA COSE | `draft-ietf-cose-sphincs-plus-10`, IESG aşamasında, **RFC değil** |
| PQ KEM JWE | Yok: `draft-ietf-jose-pqc-kem-06` yalnız COSE'u kapsar; JOSE HPKE'de ML-KEM yok |
| Hibrit TLS KEX | RFC 10024 (X25519MLKEM768, önerilen) |
| Web PKI ML-DSA sertifikası | Yok (CA/B Forum oylaması geçmedi) |
| WebAuthn / passkey PQC | WebAuthn L3'te PQC yok; CTAP 2.3'te yok; donanım 2028+ beklentisi |
| aws-lc-rs | 1.18: ML-DSA ve ML-KEM kararlı API. FIPS: sertifika 5298/5314'te ML-KEM var, ML-DSA yok; 5429'da ikisi de yok; FIPS 4.0 modülü sertifikasız |
| Rust alternatifleri | RustCrypto `ml-dsa`/`ml-kem` "never audited" (RUSTSEC-2025-0144); libcrux < 0.1 |
| Rust JOSE kütüphaneleri | ML-DSA desteği olgun değil (jwt-simple / jose-rs) |
| ABD takvimi | EO 14412 (22 Haziran 2026): anahtar tesisi 31 Aralık 2030, imza/kimlik doğrulama 31 Aralık 2031. NIST IR 8547 **hâlâ taslak**. CNSA 2.0 (ML-DSA-87, ML-KEM-1024, SHA-384) **ikincil kaynak, doğrulanmadı** |

#### 15.17.2 Kararlar

**CR-41 — ML-DSA profilleri (MD-3 PQ satırının uygulanması).**
1. **ML-DSA-65 opt-in profil**dir: domain ([AU]) veya realm ([ID]) seçer. Seçim CT3'tür (CR-8).
2. **ML-DSA-44** boyut kısıtlı profildir: QR/NFC offline PAP ve header bütçesi aşılan projection'lar için (CR-43). **ML-DSA-87** CNSA profilidir (+ SHA-384 notu, CR-1).
3. JWKS ve COSE_KeySet `AKP` anahtarlarını gün-1'den taşıyabilir (MD-3). `alg` alanı zorunludur. `priv` yalnız seed biçimindedir ve signer dışına çıkmaz (CR-21).
4. **Kütüphane:** ML-DSA primitive'i aws-lc-rs'tir (CR-13). Rust JOSE/COSE kütüphanelerinde olgun ML-DSA desteği olmadığı için Access, ML-DSA için kendi ince COSE_Sign1 / JWS katmanını aws-lc-rs üzerine yazar (Hat3). Bu katman Kernel'in kap kodunun parçasıdır; CR-9 sıkılık profili ve CR-51 vektörleri ona da uygulanır.
5. PQ profili seçmek, klasik algoritmayı kabul kümesinden **çıkarmaz**. Çıkarma ayrı bir CT1 kararıdır ve ancak bütün verifier'lar PQ'yu doğrulayabildiğinde anlamlıdır (§15.16 madde 3).

Statü: FROZEN (MD-3).

**CR-42 — Composite ve hibrit imza kuralı.**
1. Bir composite algoritma (ör. ML-DSA-65 + Ed25519), kabul kümesine **tek bir algoritma kimliği** olarak girer. Doğrulama **iki bileşenin de** geçerli olmasını ister.
2. Bileşenlerin ayrı ayrı kabul edilmesi yasaktır. Composite imzadan klasik bileşeni ayırıp tek başına sunmak (stripping, RFC 9955 sınıfı tartışma) aksi hâlde downgrade'dir (SI-18).
3. Composite bugün taslaktır (CR-41 tablosu). Kod noktaları sabit kodlanmaz. Composite yalnız RFC olduktan sonra CT3 ile eklenebilir; o zamana kadar WATCH'tır.
4. Composite yerine bugün kullanılabilen hibrit desen: aynı payload üzerinde **iki ayrı** COSE_Sign1 (biri klasik, biri ML-DSA). Verifier politikası hangisini zorunlu kılacağını Domain Metadata'dan okur (çıkarım). Payload digest'i tektir, dolayısıyla INV-27 ve T4 etkilenmez.

Statü: FROZEN (kural); composite WATCH.

**SAI-44 (invariant adayı) — Composite bütünlüğü.** Composite bir algoritma kimliğiyle imzalanmış artefakt yalnız bütün bileşen imzaları geçerliyse kabul edilir. Hiçbir bileşen, composite kimliği altında olmadan, composite'in yerine kabul edilmez. *[BY SEMANTICS]*

**CR-43 — Boyut bütçesi.** ML-DSA-44 imzası yaklaşık 2.420 bayttır. Public key yaklaşık 1,3 KB'tır. ML-DSA-65 için FIPS 204 değerleri imza 3.309 B ve public key 1.952 B'dir (genel bilgi; teyit edilmedi). Bir PAP; artefakt imzası, binding-imzalı excerpt (CR-18) ve PoP taşır, dolayısıyla PQ profilinde ≥ 6 KB'a çıkar. Bütçe testleri conformance'a girer:
- HTTP header ≤ 8 KB (token'ın `Authorization` / DPoP başlığında taşınması);
- cookie ≤ 4 KB (session cookie'ye token konmaz; [ID] cookie opak session id taşır, CR-38);
- QR / NFC offline PAP: bayt bütçesi ve ML-DSA-44 profili;
- WebAuthn / CTAP mesajları: PQ yok (HL-19; HL-26 emekli).

Bütçeyi aşan projection, PQ profilinde **referans taşıma** (artefakt yerine digest + fetch) ile sunulur. Bu yeni bir primitive değildir; mevcut projection'ın taşıma profilidir (çıkarım; uygulama §9 protocol). Statü: PD.

**CR-44 — PQC geçiş takvimi ve FIPS sınırı.**
1. **Bugün:** hibrit TLS KEX açık (CR-12); `AKP` modellenmiş; ML-DSA-65 opt-in; re-anchor mekaniği tanımlı (§15.18).
2. **Takvim bağlayıcı değildir.** EO 14412'nin 2030 (anahtar tesisi) ve 2031 (imza) kovaları, Access'in iç planı için hedef referanstır (WATCH). Bir domain'in PQ'ya geçiş tarihi o domain'in kararıdır (SI-18).
3. **FIPS + PQC bugün birlikte mümkün değildir**: FIPS profilinde ML-DSA yoktur (CR-15). Bir domain ya FIPS profilini ya PQ profilini seçer. İkisini birden isteyen müşteri için bu bir hard limittir (HL-27). Sertifika durumu değişince yeniden değerlendirilir (WATCH).

Statü: WATCH (takvim), FROZEN (FIPS sınırının beyanı).

**HL-26 (emekli) → HL-19**. Aktör imzalarının PQ boşluğu §13.5'teki HL-19'dur ("WebAuthn/passkey'de PQC yok"). Bu bölümün eklediği ayrıntı HL-19 metnine katlanır: Passkey/WebAuthn **ve CTAP**'te PQC yoktur (donanım 2028+ beklentisi). CRQC sonrası, klasik passkey ile imzalanmış **yeni** Actor Intent Statement'lar ve authentication assertion'lar sahtelenebilir. Re-anchor edilmiş geçmiş kayıtlar Merkle yapısıyla korunur (§15.18), yeni commit'ler korunmaz. Bağlı: PI-7, P29, FA-5, §15.18. Sınıf: NG (PQ donanım yokken). HL-26 ID'si yeniden kullanılmaz.

**HL-27 — FIPS ve PQC'nin birlikte sağlanamaması.**

| ID | Hard limit | Bağlı | Sınıf |
|---|---|---|---|
| HL-27 | FIPS doğrulanmış bir modülde ML-DSA imzası bugün mevcut değildir (aws-lc-rs FIPS sertifikalarında ML-DSA yok). Bir domain FIPS profili ile PQ profilini aynı anda seçemez | CR-15, CR-44; MD-3 | PU (bugün) / WATCH |

**RR-36 — Şifreli identity token'ların harvest-now-decrypt-later riski.**

| ID | Risk | Sahip | Neden kalıyor | Tespit |
|---|---|---|---|---|
| RR-36 | JWE şifreli ID Token / UserInfo ve SAML EncryptedAssertion içerikleri bugün klasik anahtar anlaşmasıyla (ECDH-ES / RSA-OAEP) şifrelenir; kaydedilmiş trafik CRQC sonrası açılabilir. Transport katmanı hibrit KEX ile korunur (CR-12), ama içerik şifrelemesi korunmaz | Realm (JWE kullanımı), RP | JOSE için PQ KEM standardı yok | Yok (pasif kayıt); azaltma: JWE yerine TLS + minimizasyon |

**RR-37 — ML-DSA implementasyon olgunluğu.**

| ID | Risk | Sahip | Neden kalıyor | Tespit |
|---|---|---|---|---|
| RR-37 | ML-DSA doğrulayıcı implementasyonları yenidir. Doğrulayıcı hataları sahte imza kabulüne yol açabilir (V8/V9 sınıfı norm/hint hataları); aws-lc-rs'in ML-DSA'sı FIPS sertifikasız ve s2n-bignum ispat kapsamı dışında; Kobeissi ePrint 2026/192 doğrulanmış PQ kriptoda 13 açık bildirir | Provider (kütüphane seçimi), domain (PQ profilini seçme) | Olgunluk zaman ister | Crucible/ACVP/Wycheproof vektörleri (CR-51); çapraz implementasyon DRT'si |

---

### 15.18 PQ re-anchoring mekaniği

Bu alt bölüm MD-19.4'ün gerektirdiği yerdir; §13.2 tablosundaki "yeniden sabitleme mekaniği" atfı buraya işaret eder. **Ayrım:** T17'deki "recovery re-anchor" (`domain.recover` sonrası cite edilen C_N → recovery kaydını kapsayan checkpoint) farklı bir mekanizmadır. Bu alt bölüm **algoritma geçişi** içindir ve T17'yi değiştirmez. **Terim ayrımı**: *recovery re-anchor* (T17, `domain.recover`), *PQ re-anchor checkpoint'i* (CR-45, algoritma geçişi) ve *binding re-anchor* (OP-60, aynı provider içinde binding değişimi; §16.6.1) üç ayrı mekanizmadır. CR-45 RA-1b, OP-60 ile yapılır. RA-n etiketi yalnız bu alt bölümdedir; OP-60 adımları RB-n'dir.

**Sorun (FA-5 döngüselliği).** FA-5, algoritma kırılınca "witness zaman sabitlemesi 'existed by T' verir" der. Ancak witness cosign'ları da klasik imzadır (C2SP tlog-witness, büyük ihtimalle Ed25519; doğrulanmadı). CRQC Ed25519'u kırarsa sahte cosign da üretilebilir. "Existed by T" ancak kırılmadan **önce** PQ ile sabitlenmiş checkpoint'ler için geçerlidir. Öte yandan SHA-256 Grover altında yaklaşık 128 bit verir, dolayısıyla Merkle yapısı ve digest'ler kurtarılabilir: her kaydı yeniden imzalamak gerekmez.

**CR-45 — PQ re-anchoring mekaniği.**

```text
RA-1  Hazırlık (kırılmadan ÖNCE, domain kararı):
      a) ML-DSA-65 (CNSA: ML-DSA-87) kabul kümesine CT3 ile eklenir (CR-8, CR-41).
      b) Provider için ML-DSA binding key bağlanır: aynı provider içinde binding re-anchor, yani
         domain.handover'ın self-handover profili (OP-60, §16.6.1; OQ-CR3 kapandı).
      c) ≥ 1 bağımsız witness ML-DSA cosign anahtarını beyan eder (witness beyanı Genesis / Domain
         Metadata'da, §13.7.7 "≥ 2 witness, ≥ 1 provider'dan bağımsız"). Bu, OP-60
         self-handover'ının ön koşuludur (RB-0): witness ML-DSA doğrulayamıyorsa self-handover başlamaz.
RA-2  Re-anchor checkpoint: provider, log'un o anki tamamını (size = head) kapsayan bir T16 checkpoint'ini
      ML-DSA operasyonel anahtarla COSE_Sign1 imzalar (excerpt ML-DSA binding key'den). Payload T16'nın
      aynısıdır; yalnız algoritma kimliği farklıdır. Aynı payload'ın klasik imzalı kopyası ayrıca üretilebilir
      (CR-42 madde 4).
RA-3  ≥ 1 bağımsız witness checkpoint'i ML-DSA ile cosign eder. Cosign, mevcut T16 akışıyla log'a checkpoint
      Claim'i olarak ingest edilir.
RA-4  Önceki kayıtlar: daha önceki her checkpoint'ten re-anchor checkpoint'ine consistency proof'u kurulur.
      Kayıt gövdeleri, leaf'ler ve digest'ler (SHA-256) DEĞİŞMEZ; kayıt başına yeniden imza YOKTUR.
RA-5  Dışarıda tutulan artefaktlar (PAP, receipt, token, export): yeni imza gerekmez. T19 inclusion bundle'ı
      PQ checkpoint'e karşı üretilir; artefaktın payload digest'inin size ≤ N_PQ olan log'da bulunduğunu
      PQ-doğrulanabilir biçimde kanıtlar (SI-11 "inclusion over assertion" deseninin algoritma geçişine taşınması).
RA-6  Kadans: PQ profili seçildikten sonra re-anchor checkpoint'i düzenli üretilir (PD; ör. her cadence
      checkpoint'inin PQ kopyası veya günlük — değer implementasyonda belirlenir) ve klasik algoritmayı
      kabul kümesinden çıkarmadan (CT1) önce mutlaka üretilir.
RA-7  Kırılma ilanı sonrası: domain klasik algoritmaları CT1 ile çıkarır. Klasik imzalı artefakt yalnız PQ
      inclusion bundle'ıyla (RA-5) kabul edilir; bundle'sız klasik artefakt reddedilir (fail closed).
```

**RA-5 ↔ OP-60 zaman çizelgesi (CR-45 semantiği kanoniktir)**. Binding re-anchor (OP-60), eski (klasik) anahtarı yalnız **yeni üretim** için "superseded" yapar: C_{h+1}'den sonra eski binding/operasyonel anahtarla yeni artefakt imzalanmaz. Re-anchor'dan önce eski binding excerpt'iyle issue edilmiş ve inclusion bundle'ı olmayan klasik artefakt, **kırılma ilanına (RA-7) kadar** kabul edilir; reddedilmesi ancak kırılma ilanıyla başlar. Bu, prospektif revocation ile tutarlıdır: re-anchor geçmişe dönük iptal değildir. OP-60 bu semantiği izler (§16.6.1). "superseded-at anında handover predicate'i uygulanır" yorumu bu profilde geçerli değildir. Çevrimdışı filoda bundle üretimi ve drain'i (HO-9, RT14) kırılma ilanından önce planlanır.

**Verifier tarafı koşulu.** Verifier'ın PQ checkpoint'i doğrulayabilmesi için ML-DSA binding ve witness anahtarlarına kırılmadan önce, klasik imzaya dayanmayan bir yoldan güvenmiş olması gerekir. Örnekler: kırılmadan önce PQ checkpoint'i pin'lemiş olmak veya Verifier Profile'a PQ anahtarları gömülmüş olmak. Kırılmadan sonra yalnız DomainID'den (Genesis digest) başlayarak klasik imzalı zincirle PQ anahtarlarına ulaşmak güvenli değildir: saldırgan klasik imzaları sahteleyip alternatif anahtar beyanı üretebilir (çıkarım). Bu koşul FA-5'e eklenir.

**FA-5 (kanonik metin §16.2):** "| FA-5 | Kayıtlar ve imzalar uzun süre doğrulanabilir; algoritma kırılırsa witness zaman sabitlemesi "existed by T" verir — **yalnız kırılmadan önce PQ algoritmayla imzalanmış ve en az bir bağımsız witness'ın PQ cosign'ını almış bir re-anchor checkpoint'inin kapsadığı kayıtlar için ve verifier o PQ anahtarlarına kırılmadan önce güvenmişse** (§15.18) | Witness cosign (PQ) | U21 |"

**Garanti.**
- Re-anchor checkpoint'inin kapsadığı kayıtlar ve artefaktlar için "existed by T_reanchor": **UNDER DECLARED CAPABILITY** (ML-DSA güvenliği, witness bağımsızlığı, verifier'ın önceden PQ anchor'ı tutması, SHA-256'nın ikinci ön-görüntü direnci).
- Son re-anchor ile kırılma arasında kalan kayıtlar ve PQ re-anchor hiç yapılmamış domain'ler: **NOT GUARANTEED** (§15.20'de §13'e aday satır).
- Kırılma sonrası klasik passkey ile yeni AIS: HL-19 (HL-26 emekli).

Yeni primitive yoktur: checkpoint, cosign Claim'i, inclusion bundle ve handover mevcut yapılardır. Statü: FROZEN (mekanik); kadans PD; RA-1b → OP-60 (§16.6.1; OQ-CR3 kapandı). Kaynak: FA-5; T16, T17, T19.

**RR-35 — Re-anchor öncesi pencere.**

| ID | Risk | Sahip | Neden kalıyor | Tespit |
|---|---|---|---|---|
| RR-35 | Son PQ re-anchor checkpoint'i ile klasik algoritmanın kırıldığı an arasındaki kayıtlar ve artefaktlar PQ-doğrulanabilir "existed by T" kazanmaz. PQ profilini hiç seçmemiş domain'in bütün geçmişi bu sınıftadır | Domain (PQ profili ve kadans seçimi); provider (re-anchor üretimi) | CRQC zamanlaması bilinmez; re-anchor sürekli değil periyodiktir | Domain Metadata'da son re-anchor checkpoint'inin boyutu ve zamanı yayımlanır. Bağlı sınır: HL-34 (kırılma sonrası re-anchor sürekliliği kanıtlamaz; kırılmadan sonra klasik cosign da sahtelenebilir; §16.9.1) |

---

### 15.19 Formel doğrulama

#### 15.19.1 Statü

- "**F20** Freeze ve reopen kuralı §3.2'dir. Formal verification bir assurance yöntemidir (SECURITY CONTROL, NOT PRODUCT PRIMITIVE); product primitive üretmez ve reopen kapısı değildir."
- "Formal model bir counterexample bulursa bu, reopen koşulu (1) veya (2) için kanıttır (§3.2); formal model kendisi bir freeze veya reopen kuralı değildir."
- **T38 → §16.10 T38**. Bölüme özgü özet: formal verification planı (TLA+, Lean, differential test) assurance pratiğidir; freeze veya reopen kuralı değildir.
- Formel doğrulamanın statüsü **assurance pratiği**dir (F20). Hiçbir model freeze kuralı veya reopen kapısı değildir; bir modelin bulduğu counterexample, frozen kararı ancak §3.2 reopen koşullarından biri olarak (gerçek contradiction/impossibility kanıtı) etkileyebilir.
- MD-15 (bağlayıcı): (a) model counterexample'ı frozen semantiği yalnız §3.2 reopen koşuluyla yeniden açar; (b) vektörleri, DRT'si ve ispatları geçmeyen semantik sürüm yayımlanmaz (sürüm kapısı, freeze kuralı değil). F20 ve T38 ile çelişmez.
- **T12** (kanonik yer §16.10 T12): "**T12** Normatif tanım L0/L2 spec + conformance vektörleridir (RT8, TI-RT12). Access Kernel open-source bir Rust `no_std` crate'idir (MD-1); Suiss production onu kullanır. Differential oracle, Lean yürütülebilir modeli (**planlı**; henüz yazılmadı) ve o hazır olana kadar naif F0 reference evaluator'dır (CR-49). Yayınlanmış her semantik sürümün evaluator'ı korunur (RT8; sürüm emekliliği yok); B12 ayrı bir ticari taahhüttür."
- **FA-2** (§16.2): ihlal sonucunda anılan TLA+ modeli **planlıdır** ("TLA+ modelinin — planlı — varsayımı").
- **"Mekanik doğrulanır" ifadeleri** (TI-14, T13): kastedilen çalışma zamanı kontrolüdür (statik polarite analizi), ispat değildir. Bu ifadeler §14'te "çalışma zamanında mekanik olarak denetlenir (ispat değil)" diye okunur.
- **Mevcut durum (dürüst beyan):** Bu spec'in hiçbir parçası bugün makineyle doğrulanmış değildir. Mevcut 27 Lean modülü taslağı (~6,8K satır, 80 teorem gövdesi, 277 executable örnek, 129 R8 senaryosu) hiç derlenmedi ve güncel modele uymaz.

**CR-46 — Formel artefakt statü alanı ve katmanlı plan.** Her formel hedef, semantik sürüm başına bir statü taşır: `planned | modelled | proved | DRT-linked`. Statüler makine-okunur manifestoda tutulur (CR-50). Plan tek dillidir (MD-1): Kani, Flux ve Verus Kernel'e doğrudan uygulanır. Statü: FROZEN (statü alanı, plan yapısı); efor tahminleri HYPOTHESIS (tahmin, ölçüm değil; birim geliştirici-ayı; §18.13 ve MD-1 ile hizalı).

#### 15.19.2 Katmanlı plan

| Katman | Hedef | Araç | Doğrulanan özellik | Kapsam | Efor (HYPOTHESIS) |
|---|---|---|---|---|---|
| 0 Taban | Kernel'in bütün parser ve decoder'ları (CBOR, COSE, JWS, base64, DER, SAML worker XML) | cargo-fuzz + OSS-Fuzz, proptest/bolero, gecelik Miri, `forbid(unsafe_code)` | Round-trip; kanonik olmayan girdi reddi; panic yok; derinlik sınırı (CR-10) | — | 2–3 hafta |
| 1 Kani | Kernel aritmetiği ve kabul kuralı (CR-47) | Kani (+ `#[kani::stub]` saat/RNG), autoharness | Taşma yok, monotonluk, bütçe aşımı yok | — | 2–4 hafta |
| 1 Kani küçük N | Kernel CBOR/COSE decoder | Kani N ≤ 32 B + fuzz | Panic/OOB yok; `decode(encode(x)) == x` | — | 1–2 hafta |
| 1 Flux | Merkle path, buffer slicing | Flux | İndeks < len; path uzunluğu ≤ log2(size)+1 | — | 1 hafta |
| 1 Loom/Shuttle | Status list / iptal önbelleği, token cache | Loom (`LOOM_MAX_PREEMPTIONS=3`), Shuttle, TSan | İptal ↔ doğrulama yarışı yok | — | 1–2 hafta |
| 2 Lean | Canonical algebra | Lean 4 | ⊑ karar verilebilir ve sound; ∩ = glb; normalize idempotent; non-amplification; cascade monotonluğu | INV-3, INV-5, INV-8 | 2–3 geliştirici-ayı |
| 2 Lean | Decision Combinator + Restriction Engine | Lean 4 | Cedar teoremlerinin Access karşılıkları (CR-48) | MD-4 | 2–3 geliştirici-ayı |
| 2 Lean | Holding episode | Lean 4 | INV-31, TI-RT9, SI-10 özellikleri (CR-48) | — | 1–1,5 geliştirici-ayı |
| 2 DRT | Lean yürütülebilir model / naif F0 ↔ Access Kernel | CBOR vektör köprüsü (FFI gerekmez), gecelik ≥ 10⁷ | Aynı girdi ⇒ aynı outcome / blocker / digest | — | 4–6 hafta + sürekli CI |
| 3 TLA+ | Commit protokolü; handover/recovery/witness; witness/replica-before-ack | TLC / Apalache | Aşağıdaki TLA+ satırlarının tamamı | §5.1, §6.5, §13, §17.1, SEC23 | 1–2 geliştirici-ayı |
| 3 Stateright | Kernel'in aktör protokol modelleri ([ID] OAuth/OIDC akış durum makineleri; device code; PKCE) | Stateright (Rust içinde actor model checking) | Yetkilendirme kodu iki kez kullanılmaz; state eşleşmeden token yok; PKCE verifier'sız kod değişimi yok | — | 2–3 hafta |
| 3 Web modeli | OAuth/OIDC protokol seviyesi güvenlik | Fett–Küsters–Schmitz web modeli (referans; CCS 2016) | Protokol saldırı sınıfları | Makineyle denetlenmiş statüsü **doğrulanmadı** | Referans; uygulama yok |
| — | Restriction profile | CEL tip denetimi + statik maliyet; property testleri | Determinism; forbid-only; `policy.set` polarite analizi | — | — |
| — | Disclosure monotonluğu | Property testleri | SI-14 | — | — |
| — | Deterministic encoding | Test vektörleri (Kernel ↔ bağımsız referans encoder; TS SDK Wasm üzerinden aynı Kernel) | Aynı değer → aynı bayt → aynı digest; alan commitment'lı leaf'in tam / redakte / disclosure-scoped export'tan aynı hesaplanması; inclusion bundle'ın yalnız `artifacts` alanını açması; recovery conjunct vektörleri | — | — |
| — | Verifier yerel kabul kuralı | Conformance vektörleri | Anahtar penceresi = imza zamanı; kabul = min(horizon, iat + yerel tavan); tavanlar artefakttan okunmaz; N_cited bağı | T20, T25, T29 | — |

TLA+ satırları:
- "| Commit protokolü | TLA+ (TLC/Apalache) | Bir tüketilebilir birim için toplam tüketim ≤ kapasite; ack edilmiş kayıt ⇒ log'da; iki leader ⇒ en fazla birinin append'i (epoch CAS); retry idempotent | §5.1, §6.5 S1–S7 |"
- "| Handover / recovery / witness | TLA+ | Tek authoritative lineage (EI-20); cross-cell fencing: planlı taşımada HANDOFF/ACCEPTANCE mührü, plansız failover'da fence kanıtı veya eski head kapsamı yoksa promote yok (iki yazar yok, pozisyon yeniden kullanımı yok, dürüst failover'da witness çatallanması yok); handover cutover'ı döngüsüz ve pozisyon aritmetiği tek anlamlı (C_k → handover batch'i pos k..h, h = k+m → C_{h+1}; freeze'de beyan dışı kayıt ve checkpoint Claim'i yok; devam h+1); recovery batch'i pos N'den, domain.recover pos N+w (boşluk yok); safety: witness fencing sonrası eski anahtarla size > N cosign yok; liveness: kol (ii) / çatallanma sonrası recovery re-anchor ile yeni lineage'da cosign mümkün ve sonraki recovery'nin "witness en yüksek"i yeni lineage'dandır; mirror-before-witness ⇒ R\* = witness en yüksek; rollback guard: requester-subset senaryosu (değerlendirici-tarafı sorgu ⇒ DENY), kol (ii) REQUIRE_ACTION, çatallanma senaryoları (kayıtla desteklenen dal / son ortak checkpoint) | §13, §17.1, §6.5 S12 |"
- "| Witness/replica-before-ack | TLA+ | Ack edilmiş revocation/CT3 ⇒ bağımsız witness'lı checkpoint'te ve kapsayan önek replica'da | SEC23 |"
- PQ re-anchor (§15.18) TLA+ modeline bir senaryo olarak girer: re-anchor checkpoint'i ile recovery re-anchor'un (T17) etkileşimi; çatallanmada PQ cosign'ın hangi dalı izlediği.

Kademe: TLA+ modelleri tasarım freeze'inden önce (Stage 9 Red-Team girdisi); Lean algebra modeli ilk conformance sürümünden önce; differential test CI'da sürekli. Katman 0 ve Kani hedefleri Kernel'in ilk kod satırıyla birlikte başlar.

**Toplam efor (HYPOTHESIS):** İlk yıl yaklaşık 9–13 geliştirici-ayı; Lean'de deneyimli en az bir mühendis gerekir. Referans noktaları: Cedar validator ispatı 18 kişi-gün; SymCert yaklaşık 663 saat; ispat CI'ı ~3 dakika. Bunlar mühendislik yargısıdır.

#### 15.19.3 Kani hedefleri (kernel'de)

**CR-47 — Kani hedefleri Access Kernel'dedir (MD-15).** Kernel `no_std` ve I/O'suzdur. Bu, Kani'nin en iyi uyduğu sınıftır (saat aritmetiği, kripto yapıştırma, oran sınırlayıcı; Hifitime ve Firecracker örnekleri). Hedefler:

| # | Hedef | Özellik | Dayanak |
|---|---|---|---|
| CR-K1 | Yerel kabul aritmetiği `min(horizon, iat + cap)` | Taşma yok (checked ⇒ DENY), monoton; `iat ∉ [validFrom, validUntil]` ⇒ red | T20 |
| CR-K2 | ValidityContract aritmetiği | Taşma yok; daraltma monoton; Δ tüketilir, uzamaz | MD-7; SI-7 |
| CR-K3 | Slice muhasebesi | Yerel draw ≤ slice; Σrelease ≤ draw (TI-RT8) | — |
| CR-K4 | `recorded_at` monotonluğu | TI-RT2 aritmetiği | — |
| CR-K5 | N_cited karşılaştırması | Bundle'ın N_cited'a bağlılığı; N < R* ⇒ DENY | T19; SEC21 |
| CR-K6 | CBOR/COSE decoder (N ≤ 32 B) | Panic yok, OOB yok, round-trip, derinlik sınırı | CR-10 |
| CR-K7 | Algoritma seçimi | Kabul kümesinde olmayan `alg` ⇒ red; `alg` asla `none`'a düşmez | CR-5, CR-7 |
| CR-K8 | Rate limit / semafor sayacı | Pencerede izin verilen ≤ bütçe | CR-36 |
| CR-K9 | Delegasyon zinciri (lineage yürüyüşü) | Derinlik ≤ 16'da sonlanma; panic yok | SI-20 |

- **Autoharness:** `cargo kani autoharness` Kernel'in bütün saf fonksiyonlarına uygulanır. Generic fonksiyonlarda tek monomorfizasyon doğrulandığı için bu bir alt yaklaşımdır.
- **Saf çekirdek CI kuralı:** Kernel I/O yapmaz. Bu, `no_std` + bağımlılık allowlist'i ile CI'da zorlanır.

Statü: FROZEN (hedef listesi); efor HYPOTHESIS. Kaynak: MD-15.

#### 15.19.4 Lean modeli ve model checking

**CR-48 — Lean Grant-algebra modeli, Decision Combinator teoremleri ve model checking.**
1. **Lean algebra modeli (MD-4, INV-8):** Cedar teoremleri Access'in pozitif algebra'sını kapsamaz (RestrictionPolicy yalnız Cedar'ın forbid-only alt kümesidir). Bu yüzden ayrı bir Lean modeli yazılır: ⊑ karar verilebilir ve sound; ∩ = glb; normalize idempotent; non-amplification (child ⊆ parent ⇒ exercisable ⊆); cascade monotonluğu (INV-3, INV-5, INV-8). Algebra Cedar gibi kapalı ve karar verilebilirdir.
2. **Decision Combinator + Restriction Engine teoremleri (Cedar 7 özelliğinin uyarlanması):**

| Cedar teoremi | Access karşılığı (Lean hedefi) |
|---|---|
| `forbid_trumps_permit` | Tetiklenen restriction ALLOW'u ezer (MD-4) |
| `default_deny` | Hata, eksik girdi veya belirsizlik ⇒ ¬ALLOW (SI-6, TI-9, MD-8) |
| `allowed_only_if_explicitly_permitted` | ALLOW ⇒ covering basis ∧ ¬restriction ∧ requirements met |
| `order_and_dup_independent` | Proof ve restriction sırasından ve tekrarından bağımsızlık (T14'ün en erken pozisyon kuralı dışında); INV-27 test hedefi |
| Sound slicing (`PolicySlice`) | İndeks ve önbellek dilimlemesi kararı değiştirmez (önbellek şeffaflığı) |
| Validation soundness | Restriction profile tip denetimi geçtiyse değerlendirme yalnız beyanlı hata sınıflarına düşer; o hatalar ⇒ ¬ALLOW. Cedar'ın uyarısı geçerlidir: tip denetimi `entityDoesNotExist`, `extensionError`, `arithBoundsError` sınıflarını önlemez |
| Termination | Lean'de bütün fonksiyonlar total olduğu için otomatik gelir; Kernel tarafında SI-20 sınırları + CR-K9 |

   Ek Access hedefi: disclosure monotonluğu (SI-14).
3. **Holding episode (INV-31, TI-RT9, SI-10):** `since` = son false→true geçişi; staleness episode kapatmaz; affirmative kapatma terminaldir; cutoff kaldırılınca kapanmış episode canlanmaz; tembel hesap = istekli hesap.
4. **Mevcut formal taslaklar:** Derivation.lean, Meter.lean, Evidence.lean ve Requirement.lean güncel modele uyarlanabilir aday kaynaklardır. Hiçbiri derlenmedi ve güncel ontolojiye uymaz; doğrudan otorite değildir.
5. **Model checking:** TLA+ (TLC/Apalache) dağıtık protokoller için kullanılır (§15.19.2). Stateright, Kernel ile aynı dilde actor protokol modelleri için kullanılır (liveness desteği deneysel). İkisi birbirinin yerine geçmez: TLA+ tasarım modelidir, Stateright koda yakın modeldir (çıkarım).

Statü: FROZEN (hedefler); hepsi `planned`. Kaynak: MD-4.

#### 15.19.5 DRT, referans oracle ve vektör korpusları

**CR-49 — Differential test, naif F0 oracle, vektör korpusları ve sürüm kapısı.**
1. **Zincir:** Lean modeli → ispat (kesin) → özellikler. Kernel ↔ Lean yürütülebilir modeli → **DRT (olasılıksal, ispat değil)**. Cedar'ın kendi deneyimi: DRT ile 10 hata kaçırıldı; üretilen koşulların %35,5'i önemsiz sabitti; toplam 25 hatanın 4'ü ispat sırasında, 21'i DRT/PBT ile bulundu. Bu yüzden "Kernel formally verified" denmez (CR-50).
2. **Naif F0 referans evaluator:** Lean modeli hazır olana kadar oracle, optimizasyonsuz ve doğrudan spec'ten yazılmış bir referans evaluator'dır (U13 open reference evaluator). Her geliştirme fazında Kernel ile diferansiyel koşulur. Lean modeli geldiğinde F0 ikinci oracle olarak kalır.
3. **Property invariant'ları:** determinizm; monotonluk (±); Check/List uyumu; List/Search uyumu; önbellek şeffaflığı; batch = tekil (batch'teki her öğenin kararı tekil çağrıyla aynıdır; kısa devre yalnız `check`'te); domain izolasyonu; sonlanma; revizyon (zookie) monotonluğu. Her biri property testi ve conformance vektörüdür.
4. **Açık sınıfı korpusu:** Beş sınıf: (i) önbellek anahtarı hataları, (ii) model hataları, (iii) kimlik karışıklığı ve kiracı sızıntısı, (iv) uygulama noktası boşluğu / TOCTOU, (v) şaşkın vekil. OpenFGA, SpiceDB, Keycloak, Zitadel ve GitLab CVE'lerinden türetilir. Her vaka SEM / POL / YOK sınıflı regresyon vektörüdür (SEM: semantik olarak imkânsız; POL: politika ile önlenir; YOK: Access kapsamı dışı).
5. **R8 korpusu:** Mevcut 129 R8 adversarial senaryosu güncel ID'lere eşlenip conformance vektörlerine port edilir. Bu, en ucuz ve en yüksek değerli ilk adımdır. F.6 (mandate snapshot) senaryosu eşlemede açıkça "**bilinçli gevşetildi**" diye işaretlenir (C14).
6. **Kripto vektörleri:** CR-9 sıkılık profili, CR-10 CBOR kanoniklik, CR-43 boyut bütçesi ve §15.18 re-anchor bundle vektörleri.
7. **Sürüm kapısı (MD-15(b)):** Bir semantik sürüm, (a) vektörleri, (b) DRT'si (≥ 10⁷ gecelik, sıfır uyuşmazlık) ve (c) o sürüm için `proved` statüsündeki ispatları geçmeden yayımlanmaz. Bu bir freeze kuralı değildir, sürüm kapısıdır (F20 ile uyumlu). İlk conformance sürümünden önce `proved` olması gereken minimum küme Lean algebra'dır (§15.19.2 kademesi). Diğerleri statüleriyle beyan edilir.

Statü: FROZEN. Kaynak: MD-15.

#### 15.19.6 Manifesto ve iddia dili

**CR-50 — Doğrulama manifestosu ve iddia dili (R1–R5).**
- **R1 Makine-okunur manifesto:** Her sürüm için hangi hedefin hangi araçla, hangi teoremle, hangi kod yolunda, hangi statüde olduğu ve hangi varsayımlarla (ör. aws-lc-rs SAW caveat'leri) doğrulandığı yazılır. Desen: SOUNDNESS.md.
- **R2 Her commit'te CI:** İspatlar ve Kani harness'ları her commit'te koşulur. Kırılan ispat merge'i engeller.
- **R3 Gevşek kaçış yok:** Lean'de `sorry` / `axiom` sayısı 0'dır (manifestoda raporlanır). Kani'de `#[kani::unwind]` sınırları ve stub'lar manifestoda beyan edilir.
- **R4 Niteliksiz iddia yok:** "formally verified", "proven secure", "constant-time guaranteed", "quantum-safe" niteliksiz kullanılmaz. İzin verilen biçim: "Access Kernel'in ⊑ ve ∩ fonksiyonlarının Lean modeli, [sürüm]'de INV-3/INV-8 için ispatlıdır; Rust implementasyonu bu modelle differential test edilir (ispat değil)". Bu kural B15 yasaklı ifadelerine eklenir.
- **R5 Derinlemesine savunma:** İspat; fuzz, vektör, sabit zaman testi ve crystal-box audit'in (MD-16) yerine geçmez.

Statü: FROZEN. Kaynak: B15; MD-16.

#### 15.19.7 Doğrulanmış kripto, KAT ve çapraz platform

**CR-51 — Kripto doğrulama ve test vektörleri.**
1. **Ne doğrulanmış, ne değil:** aws-lc-rs 1.18.1'de RSA, P-256/384/521, X25519 ve Ed25519 için s2n-bignum HOL Light fonksiyonel ve sabit zaman ispatları vardır. aws-lc-verification SAW ispatları 26 adlandırılmış caveat taşır. AES-GCM doğrulaması sınırlıdır: 12 B IV, 16 B tag, tam blok, AAD doğrulanmamış. ML-DSA ve ML-KEM bu ispat kapsamı dışındadır (HL-29). Argon2'nin doğrulanmış bir implementasyonu yoktur. `subtle` best-effort'tur. Kobeissi ePrint 2026/192 doğrulanmış PQ kripto implementasyonlarında 13 açık bildirir ve ML-KEM ispatının yalnız %58,4'ü gerçekten SMT ile denetlenmiştir.
2. **CI test listesi (V1–V9):**
   - V1 çapraz platform determinizmi: x86-64 / ARM64 / `-C target-feature=-avx2`; Kernel'in Wasm ve FFI hedefleri eklenir (MD-1);
   - V2 backend durum uyumluluğu (sağlayıcı/sürüm değişiminde kabul kümesi eşitliği; SAI-41);
   - V3 X25519 sıfır paylaşılan sır reddi;
   - V4 nonce/sayaç taşması;
   - V5 imza sıkılığı (CR-9);
   - V7 panic fuzz ve `deny(clippy::unwrap_used)` (CR-16);
   - V8/V9 Wycheproof, NIST CAVP/ACVP ve ML-DSA için Crucible vektörleri;
   - artı ctgrind (CR-39).
   - V6'nın içeriği henüz tanımlanmadı; implementasyon sırasında belirlenir (OQ-CR4).
3. **KAT:** Bütün algoritmalar için Known Answer Test başlangıçta (FIPS profilinde modülün kendi self-test'i) ve CI'da koşulur.

Statü: FROZEN.

**CR-52 — Derleme zamanı ve conformance kapıları.**
1. **Tek yazma yolu:** INV-2 / PI-4 gereği bütün authority verme yolları tek merkezi fonksiyondan geçer. Authority verme yollarının listesi (rol atama, grup, taşıma, scope mapping, protocol mapper, token exchange) conformance kapsam listesidir. Her yol için "tek fonksiyon dışında yazma yok" testi vardır.
2. **`Authorized<R,A>`:** PEP SDK'da (Rust ve Wasm üzerinden TS) bir effect fonksiyonu yalnız `Authorized<R,A>` kanıt değeriyle çağrılabilir. Kanıt yalnız Kernel'in ALLOW kararından üretilir (derleme zamanı kanıt tipi). Bu bir PEP SDK tipidir, authority primitive'i değildir. TOCTOU tespiti ve tek transaction semantiği Access'tedir (INV-19, TI-3, TI-7).
3. **Uç nokta başına izin testi:** Her yönetim ve protokol uç noktası bir izin bildirimi taşır. Bildirimsiz uç nokta derlemeyi kırar; 403 testi otomatik üretilir.
4. **Determinizm testi:** Cedar `order_and_dup_independent` özelliği, INV-27'nin test hedefidir (CR-48 tablosu).
5. **Protokol web modeli:** OAuth/OIDC/FAPI akışları için Fett–Küsters–Schmitz modelinin saldırı sınıfları conformance senaryosu olur. Modelin makineyle denetlenmiş statüsü doğrulanmadı.

Statü: FROZEN. Kaynak: INV-2; PI-4.

**HL-29 — Formel güvencenin kapsamı.**

| ID | Hard limit | Bağlı | Sınıf |
|---|---|---|---|
| HL-29 (kanonik; §13.5'teki HL-15 "async runtime / HTTP katmanı" bu satırın özel hâlidir ve → HL-29 atfı taşır) | Formel güvence yalnız ispatın kapsamı kadardır: Lean modeli Kernel'in kendisi değildir (bağ DRT'dir, olasılıksaldır); Kani sınırlı model checking'dir (unwind ve N sınırları); kripto ispatları adlandırılmış caveat'lerle sınırlıdır (aws-lc SAW 26 caveat; ML-DSA/ML-KEM kapsam dışı); async HTTP katmanı hiçbir aracın kapsamında değildir. Kapsam dışında kalan hata sınıfları ispatla dışlanmaz | CR-46…CR-51; HL-12; B15 | NG (kapsam dışı) |

---

### 15.20 Guarantee matrix bağı: §13'e aday satırlar, yeni HL ve RR

Bu bölüm G/U/N satırı **açmaz**. Mevcut satırlar değişmeden geçerlidir: G35, G42, U21, U25, N-26, RR-14, HL-1, HL-8 (tek metin §13.5), HL-12, DL-1, DL-7. Aşağıdakiler §13 için **aday satırlardır**. Numara §13.4'te verilir (G60+/U60+/N-50+).

| Aday | Satır metni | Önerilen sınıf | Dayanak |
|---|---|---|---|
| §13'e aday satır A | Kabul kümesinde olmayan algoritma, `alg: none` veya JWS'te `alg: EdDSA` tanımlayıcısıyla imzalanmış artefakt kabul edilmez; kabul kümesi doğrulanan nesnenin kendisinden okunmaz; ES256 (−7) ve WebAuthn algoritmaları CR-5 madde 1'e göre doğrulanır | G (BY SEMANTICS) | CR-5, CR-7, SAI-40 |
| §13'e aday satır B | Kanonik olmayan CBOR, kanonik olmayan imza kodlaması veya yapısal sınırı aşan girdi kabul edilmez (gerekçeli protocol rejection) | G (BY SEMANTICS); implementasyonlar arası eşitlik HL-12 kadar | CR-9, CR-10, SAI-41 |
| §13'e aday satır C | Yayımlanmamış (publish-before-use süresini doldurmamış) anahtarla imzalanmış artefakt üretilmez | G (BY SEMANTICS) | CR-25, SAI-46 |
| §13'e aday satır D | Bellek-içi operasyonel anahtar çalınmasının etkisi, U25'in yerel kabul tavanlarıyla ve anahtar ömrüyle (PD 1 s, tavan 24 s) sınırlıdır | U (UDC) | CR-19, CR-21 |
| §13'e aday satır E | Bellek-içi anahtar çalınmasının önlenmesi (signer izolasyonu aşıldığında) | N (NG) | HL-21 (HL-28 emekli); SAI-45 |
| §13'e aday satır F | Sır karşılaştırmalarının sabit zamanlılığı | U (UDC: derleyici ve CPU) | CR-39, SAI-42, HL-16 (HL-28 emekli) |
| §13'e aday satır G | Var olan ve olmayan hesap / basis için yanıt içeriği eşdeğerliği | G (BY SEMANTICS) içerik; süre kanalı U (UDC) | CR-40, SAI-43; DL-7 |
| §13'e aday satır H | Algoritma kırılması sonrası "existed by T": PQ re-anchor checkpoint'inin kapsadığı kayıtlar için | U (UDC) | CR-45; FA-5; U21 |
| §13'e aday satır I | Son PQ re-anchor ile kırılma arasındaki kayıtlar ve PQ profilsiz domain'ler için "existed by T" | N (NG) | RR-35 |
| §13'e aday satır J | Kırılma sonrası klasik passkey ile yeni AIS sahteciliğinin önlenmesi | N (NG) | HL-19 (HL-26 emekli) |
| §13'e aday satır K | DB sızıntısında parola, client secret ve opak token'ların doğrudan yeniden kullanılamaması | U (UDC) | CR-36, CR-38 |
| §13'e aday satır L | Crypto-shredding'in tamamlanması (beyanlı tavan sonrasında) | U (UDC); "anında silme" N | CR-32 |

**Bu bölümün açtığı Hard Limit'ler (HL-25…HL-29) — özet.**

| ID | Kısa ad | Sınıf | Tanım yeri |
|---|---|---|---|
| HL-25 | **Emekli → HL-20** (paylaşımlı KMS/HSM kotası ve partition korelasyonu) | NG | §13.5 (HL-20); §15.9 atıf |
| HL-26 | **Emekli → HL-19** (WebAuthn/CTAP PQC yok) | NG | §13.5 (HL-19); §15.17 atıf |
| HL-27 | FIPS ve PQC'nin birlikte sağlanamaması (kalır; §13.5 listesine eklenir) | PU (bugün) / WATCH | §15.17 |
| HL-28 | **Emekli → HL-16 + HL-21** (co-tenant HL-17 / DL-10) | NG | §13.5; §15.15 atıf |
| HL-29 | Formel güvencenin kapsamı (kalır; HL-15 → HL-29; §13.5 listesine eklenir) | NG | §15.19 |
| HL-8 (genişletme) | + Storm-0558 sınıfı kapsam dışı kabul; tek metin §13.5 | NG (kural BS, etki UDC) | §13.5; §15.8.2 atıf |

**Bu bölümün açtığı Residual Risk'ler (RR-35…RR-38).** numaralarıyla §13.9 listesine eklenir. RR-39 kullanılmadı.

| ID | Kısa ad | Tanım yeri |
|---|---|---|
| RR-35 | Re-anchor öncesi pencere | §15.18 |
| RR-36 | Şifreli identity token'ların HNDL riski | §15.17 |
| RR-37 | ML-DSA implementasyon olgunluğu | §15.17 |
| RR-38 | Yönetilen platformda sertleştirme düşüşü (aşağıda) | §15.20 |

**RR-38 — Sertleştirme arka ucunun düşmesi.**

| ID | Risk | Sahip | Neden kalıyor | Tespit |
|---|---|---|---|---|
| RR-38 | Yönetilen Kubernetes node'larında `memfd_secret` kullanılamayabilir (kernel komut satırı erişimi yok; doğrulanmadı). Container memlock limiti düşük olabilir. Bu durumda signer `mlock`'a veya (izin verilmemişse başlamaz) daha zayıf arka uca düşer | Provider / self-host operatörü | Platform kısıtı | `access_secret_memory_backend` metriği; signer'da `none` başlatma hatasıdır (CR-34) |

---

### 15.21 Karar kaydı: CR-1 … CR-52

Garanti sütununda: BS = BY SEMANTICS, UDC = UNDER DECLARED CAPABILITY/POLICY, NG = NOT GUARANTEED, — = garanti iddiası yok (mühendislik kararı).

| ID | Karar (kısa) | Statü | Garanti | Gerekçe (kısa) | Kaynak |
|---|---|---|---|---|---|
| CR-1 | SHA-256 algoritma etiketli digest; CNSA SHA-384 profil notu | FROZEN / not WATCH | BS (etiket) | Tek digest tabanı; PQ'da Merkle kurtarılabilir | — |
| CR-2 | İmza varsayılanları ve plane ayrımı (MD-3 + ingest + SAML) | FROZEN | — | Ed25519 hız; ES256 ekosistem | MD-3 |
| CR-3 | HMAC yalnız anahtarlı türetim ve tek taraflı token | FROZEN | BS | Çok taraflı doğrulayıcı paylaşılan sırra dayanamaz | — |
| CR-4 | JWE yalnız [ID]; ECDH-ES+A256KW/A256GCM; RSA-OAEP-256 opt-in; RSA1_5 yok | FROZEN / küme PD | — | Marvin; JOSE kaydı | — |
| CR-5 | Üretimde fully-specified tanımlayıcılar; doğrulamada ES256 (−7) zorunlu, WebAuthn algoritmaları WebAuthn kurallarına göre; `none`, `RSA1_5` reddi; JWS `EdDSA` reddi (JWS ingest dahil) | FROZEN | BS | Downgrade yüzeyi sıfır; passkey kabulü | RFC 9864 |
| CR-6 | Kaplar T24/T16/R6 + AKP + boyut testi | FROZEN | — | Mevcut model doğru | — |
| CR-7 | Allowlist yalnız metadata'dan | FROZEN | BS | SI-18/PI-21 ile uyumlu | — |
| CR-8 | Her algoritma eklemesi CT3, çıkarma CT1 | FROZEN | BS | Yeni implementasyon yüzeyi | — |
| CR-9 | İmza sıkılık profili (Ed25519 strict, low-S, harici imza kuralı) | FROZEN / denklem OQ-CR1 | BS; HL-12 | `proof_commit` determinizmi | — |
| CR-10 | Deterministik CBOR doğrulaması + yapısal sınırlar | FROZEN / değerler PD | BS (sınırın varlığı) | Kanidm CVE; T4 | — |
| CR-11 | Batch imza doğrulaması kapalı | FROZEN | — | Sınırlı kazanç; kabul kümesi hipotezi | — |
| CR-12 | TLS 1.3 + X25519MLKEM768; iç ML-DSA mTLS WATCH | FROZEN / WATCH | UDC | HNDL, sıfıra yakın maliyet | — |
| CR-13 | aws-lc-rs tek sağlayıcı | FROZEN | — | Klasik + PQ + ispat | — |
| CR-14 | `rsa` crate yasağı + `cargo tree -i rsa`; ring/libcrux/RustCrypto PQ yok | FROZEN | UDC (kapılar) | RUSTSEC-2023-0071 patched=[] | — |
| CR-15 | FIPS profili (ES256, PBKDF2 600k, HSM'de operasyonel anahtar, PQC yok) | FROZEN / içerik PD | — (uyum profili) | Kamu/finans müşterisi | — |
| CR-16 | Kernel kod disiplini (`forbid(unsafe_code)`, `no_std`, lint'ler, unsafe allowlist) | FROZEN | — | MD-2 | — |
| CR-17 | İmza anahtarı önbelleği; performans EA; OQ-MD4 | PD / EA | — | 1,91 kat kayıp | — |
| CR-18 | Anahtar hiyerarşisi; excerpt'e `jwk_thumbprint`; binding kapsamı beyanı; HL-8 genişlemesi | FROZEN | G35 BS; U25 UDC; N-26 NG | T20 + MD-6 | — |
| CR-19 | Plane başına anahtar ömrü ([AU] PD 1 s / tavan 24 s; [ID] realm) | FROZEN / değerler PD | — | Farklı nesneler | MD-6 |
| CR-20 | Anahtar kapsamı: [AU] domain, [ID] realm; node başına yalnız iç kimlik | FROZEN | BS (TI-RT6) | Kapsam karmaşasını önler | MD-5 |
| CR-21 | Signer süreci (seccomp, Landlock, memfd_secret, IPC); FIPS'te HSM | FROZEN | UDC (HL-21) | KMS kota ve maliyet | MD-6 |
| CR-22 | KMS/HSM throughput ve paylaşım beyanı | FROZEN | — | Paylaşımlı kota | — |
| CR-23 | Kesinti modları: signer ≠ HSM; jitter ±%20 | FROZEN | G42 BS | Signer ve HSM kesintisinin ayrılması | — |
| CR-24 | `kid` = RFC 7638 thumbprint | FROZEN | — | Deterministik, içerik-bağlı | — |
| CR-25 | Publish-before-use: `T_publish_lead ≥ max(T20 şartı, T_cache + T_client + T_safety)` | FROZEN / değerler PD | BS (signer kuralı) | Önbellek yayılımı | — |
| CR-26 | Düşürme ve saklama; [AU] public key arşivi süresiz | FROZEN | — | Uzun süreli doğrulanabilirlik | — |
| CR-27 | Rotasyon durum makinesi; 1 aktif + ≥ 1 yedek | FROZEN | — | Denetlenebilir geçiş | — |
| CR-28 | PKCS#11 (`cryptoki` 0.12, havuz, blocking thread); KMIP WATCH | FROZEN / WATCH | — | Rust uygulama yolu | — |
| CR-29 | Anahtar töreni; quorum = aktivasyon ve politika (imza başına değil) | FROZEN | — | Saatlik excerpt'e insan onayı imkânsız | FA-6 |
| CR-30 | Binding key DR = HSM-içi klon; kayıpta yalnız `domain.recover`; partition beyanı | FROZEN | HL-8, HL-20 | FA-6, T20 | — |
| CR-31 | Recovery anahtarları ve custody signer (SEC17/19/20, T32) | FROZEN | Mevcut sınıflar | SEC17/19/20 ve T32 modeli | — |
| CR-32 | KEK/DEK, DEK önbelleği, shredding tavanı, Vault/OpenBao opsiyonel, `basis_ref` anahtarı | FROZEN | UDC (shredding); at-rest semantik değil | T27/T39/TI-RT10 | — |
| CR-33 | `zeroize` + `secrecy`; heap, `Copy` yok; 14 vektör tablosu | FROZEN | UDC / NG (vektöre göre) | Dürüst sınır | — |
| CR-34 | `memfd_secret`→`mlock` düşüşü; core dump/ptrace; `ACCESS_HARDENING`; signer'da paranoid zorunlu | FROZEN / arka uç PD | UDC | Core dump, ptrace ve swap sızıntısı | — |
| CR-35 | Workload identity bootstrap; log redaksiyonu + CI canary; yedekte sır yok (tek istisna `basis_ref`) | FROZEN | UDC | Ortam değişkeni ve etcd sızıntısı | — |
| CR-36 | Argon2id m=7 MiB/t=5/p=1 (PD); semafor; 503; dummy Argon2 yok; adaptif gecikme | FROZEN / parametre PD | UDC; tam eşitlik NG | DoS ve CVE-2024-39329 | — |
| CR-37 | Pepper opsiyonel (EA); PHC string; rehash göçü | PD / EA | — | Yalnız DB-sızıntısı senaryosu | — |
| CR-38 | Client secret/API anahtarı ≥ 256 bit, SHA-256/HMAC + CT; opak token'lar hash'li | FROZEN | UDC | B-tree ve dump riski | — |
| CR-39 | CT noktaları ([ID] + [AU]); `Secret<N>`, `*_vartime`; dudect/ctgrind/asm; DIT | FROZEN | UDC (HL-16) | Timeless Timing | — |
| CR-40 | Enumeration eşdeğerliği ([ID] 15 kanal, [AU] yetkisiz ≡ yok); dolgu serbest / içerik rastgeleliği yasak; barındırma | FROZEN | BS içerik; UDC süre; NG tam eşitlik | DL-7, INV-27 | — |
| CR-41 | ML-DSA-65 opt-in, -44 boyut, -87 CNSA; AKP; aws-lc-rs üzerinde ince COSE/JWS katmanı | FROZEN | — | MD-3 | — |
| CR-42 | Composite = tek alg kimliği, iki bileşen zorunlu; composite WATCH; çift COSE_Sign1 deseni | FROZEN / WATCH | BS (SAI-44) | Stripping | — |
| CR-43 | PQ boyut bütçesi testleri; referans taşıma | PD | — | ≥ 6 KB artefakt | — |
| CR-44 | PQC takvimi (WATCH); FIPS+PQC bugün yok | WATCH / FROZEN (beyan) | HL-27 | EO 14412; CMVP | — |
| CR-45 | PQ re-anchoring mekaniği (RA-1…RA-7); FA-5 koşulu; kanonik semantik | FROZEN / kadans PD (RA-1b → OP-60) | UDC; NG (RR-35) | FA-5 döngüselliği | — |
| CR-46 | Formel statü alanı (`planned/modelled/proved/DRT-linked`); tek dilli katmanlı plan | FROZEN | — | Formel statünün dürüst beyanı | — |
| CR-47 | Kani hedefleri CR-K1…CR-K9 Kernel'de; autoharness; saf çekirdek CI | FROZEN | HL-29 | MD-15 | — |
| CR-48 | Lean algebra + Decision Combinator (Cedar teorem şablonları) + episode; TLA+ + Stateright | FROZEN (hedef) / `planned` | HL-29 | MD-4; INV-8 | — |
| CR-49 | DRT; naif F0 oracle; property invariant'ları; CVE ve R8 korpusları; sürüm kapısı | FROZEN | HL-12, HL-29 | MD-15(b) | — |
| CR-50 | Manifesto R1–R5; niteliksiz iddia yasağı (B15'e ek) | FROZEN | — | Epistemik dürüstlük | — |
| CR-51 | Doğrulanmış kripto kapsamı; V1–V9; Wycheproof/CAVP/ACVP/Crucible; KAT | FROZEN | HL-29 | Verification theatre dersi | — |
| CR-52 | Tek yazma yolu testi; `Authorized<R,A>`; uç nokta başına izin; determinizm testi; web modeli senaryoları | FROZEN | — | INV-2 / PI-4 | — |

---

### 15.22 Invariant adayları ve doğrulanamayan iddialar

#### 15.22.1 Invariant adayları (SAI-n)

| ID | Ad | Metin (kısa) | Sınıf | Tanım |
|---|---|---|---|---|
| SAI-40 | Allowlist header'dan gelmez | Kabul kümesi yalnız Domain Metadata / Verifier Profile / client metadata'dan okunur | BS | §15.4 |
| SAI-41 | Kanonik tek kabul | Tek bayt kodlaması; kanonik olmayan ⇒ protocol rejection; sağlayıcıdan bağımsız | BS (HL-12 kadar) | §15.5.2 |
| SAI-42 | Sır karşılaştırması sabit zamanlı | Değerden bağımsız süre, sabit uzunluk, mümkünse hash | UDC | §15.15 |
| SAI-43 | Yetkisiz ≡ var olmayan | Scope dışı nesne yanıtı var olmayanınkinden ayırt edilemez | BS (içerik) / UDC (süre) | §15.15 |
| SAI-44 | Composite bütünlüğü | Bütün bileşenler geçerli olmadan kabul yok | BS | §15.17 |
| SAI-45 | Signer izolasyonu | Açık anahtar materyali yalnız signer'da (veya HSM'de) | UDC | §15.9 |
| SAI-46 | Yayımlanmamış anahtarla imza yok | `T_publish_lead` dolmadan imza yok | BS | §15.10 |

SAI aralıkları: SAI-1…SAI-39 §14'e (kullanılan SAI-1…9), SAI-40…SAI-59 §15'e ayrılmıştır; boşluklar rezervdir. Yeniden numaralandırma yapılmaz (ID istikrarı).

#### 15.22.2 Doğrulanamayan veya doğrulanmamış iddialar

1. RFC 9864'ün COSE sayısal kod noktaları (Ed25519 vb.): IANA'dan teyit edilecek.
2. `AKP` anahtarının RFC 7638 thumbprint alanları (RFC 9964'e göre teyit edilecek).
3. `draft-ietf-jose-deprecate-none-rsa15` "Publication Requested" statüsü: RFC değil.
4. ChaCha20-Poly1305 için JWE `enc` kaydı: kaynaklarda yok.
5. Batch ve tekil doğrulamanın farklı kabul kümeleri: hipotez (CR-11).
6. Argon2 ve imza performans sayıları: Apple M4, tek makine; sunucu donanımında doğrulanmadı.
7. KMS/HSM throughput sayıları (özellikle GCP ~50/sn) ve KMS CloudHSM key store 1.800 ↔ 300–500 tutarsızlığı.
8. KMS/HSM maliyet tahmini (~38.880 USD/ay): hesap yöntemi doğrulanmadı.
9. [ID] JOSE anahtar ömrü PD 90 gün: dayanak sayı satır satır teyit edilmedi.
10. DEK önbellek TTL'i PD 5 dakika: çıkarım.
11. `memfd_secret`'ın yönetilen Kubernetes'te çalışması; container memlock varsayılanı.
12. Pepper'ın değeri ("pepper bellekten"; doğrulanmamış).
13. aws-lc-rs'in `no_std` / Wasm hedeflerinde derlenebilirliği (OQ-CR2).
14. CMVP sertifika numaraları ve kapsamları (5298/5314/5429; FIPS 4.0): değişken liste.
15. CNSA 2.0 gereksinimleri: ikincil kaynak.
16. NIST IR 8547 statüsü (taslak), EO 14412 tarihleri: 8 Eylül 2026 okuması.
17. ML-DSA-65 boyutları (3.309 B / 1.952 B): FIPS 204 genel bilgisi, teyit edilmedi.
18. Fett–Küsters–Schmitz web modelinin makineyle denetlenmiş statüsü.
19. Efor tahminleri (geliştirici-ayı, hafta; HYPOTHESIS): mühendislik yargısı.
20. Storm-0558 olay ayrıntıları: satır satır teyit edilmedi; genel bilgi.
21. SPIRE KeyManager'da ML-DSA desteği yokluğu (çıkarım).
22. KMIP için olgun Rust istemcisinin yokluğu: çıkarım.
23. V6 testinin içeriği (bu bölümde adıyla kullanılmadı).
24. Witness cosign'ının Ed25519 olduğu (doğrulanmadı).

---

### 15.23 Açık sorular

**Açık sorular (OQ-CR; §20'ye aday):**

| ID | Soru | Neden açık | Etkisi |
|---|---|---|---|
| OQ-CR1 | Ed25519 doğrulama denklemi (cofactored / cofactorless) L0'da hangisi? | Seçim henüz yapılmadı; vektör ve sağlayıcı davranışıyla birlikte seçilmeli | CR-9, SAI-41 |
| OQ-CR2 | Kernel'in Wasm/FFI hedeflerinde kripto sağlayıcısı aws-lc-rs mi, yoksa aynı kabul kümesini veren başka bir sağlayıcı mı? | aws-lc-rs'in `no_std`/Wasm desteği doğrulanmadı | CR-13; OQ-MD4 ile birlikte |
| OQ-CR3 | ~~ML-DSA binding key'i aynı provider'a `domain.handover` ile bağlamak mümkün mü (self-handover), yoksa ayrı bir `domain.*` kaydı mı gerekir?~~ **KAPANDI → OP-60 (§16.6.1)** | Karar: aynı provider içinde binding re-anchor = `domain.handover`'ın self-handover profili (OP-60, FROZEN TECHNICAL). Ön koşul: witness'ın ML-DSA doğrulayabilmesi (RA-1c / RB-0). Semantik CR-45'e göredir. Yeni primitive yok | CR-45 RA-1b |
| OQ-CR4 | V6 testinin içeriği ve CR-51 listesine girişi | V6 adıyla tanımlanmadı | CR-51 |
