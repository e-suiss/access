## 0. Okuma rehberi

### 0.1 Bu belge nedir
Bu belge Access'in kanonik spec'idir. Access tek bir üründür ve iki plane'den oluşur:
- **Identity plane:** tam bir IdP. İçinde parola, passkey, OAuth/OIDC AS, SAML, SCIM, LDAP, Kerberos, OpenID Federation, oturum, hesap yaşam döngüsü, yönetim API'si ve ajan kimliği vardır.
- **Authority plane:** Access'in yetki semantiği. İçinde Grant, Mandate, Authority Exercise ve ValidityContract vardır.

Kararlar şu ölçütlerle verilir:
- kanıt kalitesi: ölçüm, birincil kaynak, CVE doğrulaması
- semantik doğruluk
- garanti sınıflarının dürüstlüğü
- uygulanabilirlik
- eksiksizlik

### 0.2 Merkezi kararlar (MD-1…MD-20)
Merkezi kararlar bütün bölümleri bağlayan mimari kararlardır. Spec'in geri kalanı bunlara atıf verir. Özet:

| MD | Karar |
|---|---|
| MD-1 | Backend dili **Rust**; tek `no_std` **Access Kernel** crate'i sunucu ve bütün verifier'larda aynı; aws-lc-rs; kenar protokol gateway'leri ayrı süreç (T12, T25, T35, T38) |
| MD-2 | Dilden bağımsız sertleştirme kuralları + dil profilleri |
| MD-3 | İmza: COSE authority kayıtları Ed25519, JOSE projection'ları ES256, FIPS profili, RS256 yalnız identity plane opt-in, RFC 9864, `alg: EdDSA` reddi, ML-DSA opt-in |
| MD-4 | Pozitif yetki yalnız Grant'tan; ReBAC/Zanzibar türetilmiş index; restriction dili Cedar forbid-only alt kümesi (spike koşullu) |
| MD-5 | Dört eksen: Tenant / AuthorityDomain / Identity Realm / Cell; RLS FORCE |
| MD-6 | Anahtar hiyerarşisi: HSM binding key + izole signer süreci; realm başına JOSE anahtarları |
| MD-7 | Revocation: ValidityContract semantiktir, epoch'lar mekanizmadır; 28 saatlik token reddedilir |
| MD-8 | Her yerde fail-closed |
| MD-9 | Impersonation yok; destek erişimi Grant'tır |
| MD-10 | Linkability: pairwise `sub` ve domain-pairwise PartyRef |
| MD-11 | Uygulama-kontrollü faktör assurance sınıfı (TR ödeme) |
| MD-12 | CRA: Suiss manufacturer, Class I (**Adem kararı bekleniyor, D-10**) |
| MD-13 | Plane ataması: identity yetenekleri identity plane'e, authority semantiği authority plane'e atanır (§2.5, §7.6) |
| MD-14 | Identity plane yapılandırması ADP commit ile yetkilendirilir |
| MD-15 | Formel model iki katmanlıdır; Kani hedefleri release kapısıdır (TI-RT12, §15) |
| MD-16 | Bağımsız dış denetim (crystal-box audit) (§14) |
| MD-17 | Fiyat ekseni MAU değildir; dedicated compute maliyet seçeneğidir, signer ayrımı ve HSM ücretsiz taban güvencedir (§18) |
| MD-18 | Teknik ayrıntı kararları: UUIDv7 iç ID ve opak dış ID; ID-JAG yalnız assertion/Claim taşıyıcısıdır; DPoP nonce ve replay kuralı; birincil kaynakta doğrulanmamış standart tarih ve statüleri "doğrulanmadı" olarak işaretlenir |
| MD-19 | Bileşen etiketleri (`CMP-n`), RLS ve tutarlılık kararları (§16.3, §17) |
| MD-20 | Açık sorular disiplini (§20) |

### 0.3 Etiketler
- **Statüler** §3'tedir: FROZEN, POLICY DEFAULT, ENGINEERING ASSUMPTION, HYPOTHESIS, WATCH, MERKEZİ KARAR, OPEN — COMPONENT-BLOCKING. Garanti sınıfları: BY SEMANTICS, UNDER DECLARED CAPABILITY/POLICY, NOT GUARANTEED.
- **"doğrulanmadı":** İddia birincil kaynakta teyit edilmemiştir.
- **"çıkarım":** Türetmedir; birincil kaynakta yoktur.

### 0.4 ID aileleri

| Aile | Bölüm | Aile | Bölüm |
|---|---|---|---|
| MD-n | §0.2 Merkezi kararlar | F, must-never | §2 |
| L, MKT-n, LFP-n | §4 Landscape | C | §5 Ontology |
| CI, INV, EI, XI, PI, SI, TI, TI-RT | §6 Invariant'lar | E | §7 Ecosystem |
| X, A | §8 Ürün deneyimi | P | §9 Protocol |
| IDP-n / IDI-n | §10 Identity plane | AG-n / AGI-n | §11 MCP ve ajan |
| TN-n / TNI-n | §12 Kiracılık, oturum, hesap, yönetim | G, U, N, DL, HL, RR, SEC | §13 Güvenlik matrisi |
| SA-n / SAI-n | §14 Güvence | CR-n | §15 Kripto |
| CMP-n, FA, T, RT, OP-n / OPI-n | §16–§17 Mimari ve operasyon | B, H, D | §18 Strateji |

Bileşen kimlikleri `CMP-n` biçimindedir (§16.3); `C-n` ontology kararlarına aittir (§5.15).

### 0.5 Bölüm haritası

| § | Bölüm |
|---|---|
| 1–4 | Tanım, tez, statü sistemi, landscape |
| 5–6 | Ontology, invariant'lar |
| 7–8 | Ecosystem/ownership, ürün deneyimi |
| 9 | Protocol |
| 10 | Identity Plane |
| 11 | MCP ve ajan kimliği |
| 12 | Kiracılık, oturum, hesap yaşam döngüsü, giriş UX, yönetim API'si |
| 13 | Security / Trust / Guarantee Matrix |
| 14 | Güvenlik güvencesi, sertleştirme, test, uyum |
| 15 | Kriptografi, anahtarlar, PQC, formel doğrulama |
| 16 | Technical Architecture |
| 17 | Veri, HA, denetim, gözlemlenebilirlik, dağıtım, operasyon |
| 18 | Platform / Business Strategy |
| 19 | Canonical Decision Register |
| 20 | Açık sorular, Adem kararları |
| Ek A | ID aileleri |

### 0.6 Okuma sırası
- Ürünü anlamak için: önce "Kısaca Access", sonra §1, §2, §5.1–5.7, §7.6, §10.0, §13.4.
- Uygulayıcılar için: §5, §6, §9, §10, §12, §15, §16, §17.
- Güvenlik için: §13, §14, §15.
