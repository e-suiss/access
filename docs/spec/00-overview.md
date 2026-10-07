## Kısaca Access

Bu bölüm spec'in özetidir. Normatif metin aşağıdaki numaralı bölümlerdedir; çelişkide onlar kazanır.

### Access nedir?

Access, Suiss'in **kimlik ve yetki ürünüdür**. Tek bir ürün olarak iki katmandan (plane) oluşur:

- **Identity plane: tam bir kimlik sağlayıcısı (IdP).** İnsanları (müşteri, çalışan, geliştirici, yönetici), servisleri, cihazları ve yapay zekâ ajanlarını doğrular. Hesapları, parolaları, passkey'leri ve oturumları yönetir. Standart protokollerin hepsini konuşur: OIDC/OAuth 2.1, SAML, SCIM, LDAP, Kerberos, RADIUS, WS-Fed, OpenID Federation, MCP. Keycloak, Okta, Auth0 veya Clerk'in yaptığı işi yapar. (§10–§12)
- **Authority plane: yetki katmanı.** Bir yetkinin nereden geldiğini, kimden kime nasıl devredildiğini, hangi sınırlar içinde olduğunu tutar. Bir işlem yapılmak istendiğinde **ALLOW**, **DENY** ya da eksikleri söyleyen **REQUIRE_ACTION** kararını verir ve bu kararın değiştirilemez, doğrulanabilir kaydını üretir. (§5–§9)

Access'in cevapladığı tek soru şudur (§1.6):

> **"Bu aktör, bu yetkiyle, tam olarak bunu, şimdi yapabilir mi?"**
> *(May this actor, on this authority, do this exact thing now?)*

### Hangi problemi çözer?

**Temel problem: yetki kullanımının meşruiyeti** (§1.3). Bir aktörün (kendi adına veya başkası adına) bir yetkiyi kullanmasının meşru olup olmadığını, yetkinin kaynağından bu kullanıma kadar açık ve doğrulanabilir bir zincirle belirlemek.

Bu problem beş soruya ayrılır:

| # | Soru | Access'in cevabı |
|---|---|---|
| 1 | **Kim hareket ediyor?** | Somut çalışan örnek (Instance) ve doğrulama güvencesi. Identity plane bu soruyu tam bir IdP olarak cevaplar |
| 2 | **Kimin yetkisiyle?** | Yetkinin kökü (root), devir zinciri ve kimin adına hareket edildiği (kendi adına / başkası adına) |
| 3 | **Hangi sınırlar içinde?** | Kapsam, tutar, süre, amaç, bütçe. Sınırlar zincir boyunca **yalnız daralır**, hiçbir zaman genişlemez |
| 4 | **Şu an, tam olarak bu iş için kullanılabilir mi?** | Gerekli onaylar, kanıtlar, iptal durumu ve kısıtlar kontrol edilerek verilen karar |
| 5 | **Ne kullanıldı?** | Hangi yetkinin hangi iş için kullanıldığının değiştirilemez kaydı |

**Neden şimdi?** Yapay zekâ ajanları neredeyse her işi **başkası adına** yapar. Bugünkü IdP'ler "bu kişi kim?" sorusunu iyi cevaplar, ama "bu ajan kimin yetkisiyle, hangi sınırla, şu an bunu yapabilir mi, ve bunu sonradan nasıl kanıtlarız?" sorusunu cevaplamaz. Herkes yalnız kendi adına hareket etseydi Access bir IdP + erişim listesinden ibaret olurdu. Ajan dünyasında öyle değil; Access'in var olma nedeni bu.

Access'i kullanan bir ürün yedi şeyi güvenilir biçimde alır (§1.4): **aktör** (kim), **temsil ve köken** (kimin adına, yetki nereden), **sınırlar**, **karar**, **süreklilik** (iptal anından itibaren geçerli), **kayıt** (ne kullanıldı) ve **taşınabilirlik** (kayıtlar Access'e sormadan, şirketler arasında doğrulanabilir).

### Ne değildir?

| Access ... değildir | Bu işin sahibi | Access'in o işteki rolü |
|---|---|---|
| İşi yürüten sistem (ödemeyi yapan, mesajı gönderen) | Executor ve domain ürünleri | İşin sınırını tanımlar ve "yapılabilir mi?" kararını verir (F7) |
| İş verisinin ve iş kurallarının sahibi ("bu sipariş geçerli mi?") | Domain ürünleri (Commerce, Serve…) | Domain'in iddialarını girdi olarak kullanır |
| İş koordinasyonu ve onay toplama sistemi | Work | Onay yetkisine karar verir |
| Ödeme ve para sistemi | Pay, Money | Ödeme yetkisine ve bütçesine karar verir |
| Bildirim ve teslim sistemi | Relay | Neyin bildirilmesi gerektiğini tanımlar |
| Ajan çalıştırıcı ve orkestratör | One, Executor Runtime | Ajanın kimliğini ve yetkisini yönetir |
| KYC / uzaktan kimlik tespiti uygulaması | Dış KYC sağlayıcıları | Tespit sonucunu iddia (Claim) olarak kabul eder (IDP-34) |
| Active Directory'nin yerine geçen Windows domain sunucusu | AD, Samba AD | AD ile birlikte çalışır (IDP-38) |
| PAM kasası, fraud motoru, SIEM, DLP | Ayrı ürün katmanları | Bunların yetki kısmına karar verir, olay ve sinyal üretir (IDP-39) |
| Küresel güven / itibar puanı sistemi | Hiç kimse (yasak) | — |

Ayrıca Access'te hiçbir zaman olmayacak şeyler (§2.8, must-never):

- **Giriş yapmak yetki vermez.** Hiçbir login, token, grup üyeliği, oturum veya risk skoru tek başına yetki üretmez (INV-12).
- **Kimliğe bürünme (impersonation) yoktur.** Destek personeli kullanıcının yerine geçemez; kullanıcının izniyle, kendi kimliğiyle ve kayıtlı olarak çalışır (MD-9).
- **Müşteri kodu Access içinde çalışmaz.** Özelleştirme veri, şablon ve müşterinin kendi sunucusundaki çağrı noktalarıyla yapılır (F23).
- **Şüphede ret.** Bir şey doğrulanamıyorsa cevap ALLOW değildir (fail-closed, MD-8).

### En temel kavramlar

**Herkesin bilmesi gereken kavramlar:**

| Kavram | Ne demek | Örnek |
|---|---|---|
| **Party** | Hak ve sorumluluk sahibi kişi veya kurum: insan, şirket, ajan, servis | Ayşe; Acme A.Ş.; Acme'nin satın alma ajanı |
| **Instance** | Bir Party'nin şu an hareket eden somut örneği: belirli bir cihazdaki oturum, çalışan bir ajan süreci | Ayşe'nin iş bilgisayarındaki oturumu; ajanın bugün başlayan çalışması |
| **Claim** | Birinin bir şey hakkındaki **iddiası**; gerçeğin kendisi değil, kimin neyi söylediğinin kaydı | İK: "Ayşe finans departmanında"; IdP: "Ayşe passkey ile giriş yaptı" |
| **Acceptance** | Hangi kaynağın iddiasına, hangi amaçla güvenildiğinin açık ve geri alınabilir kararı. "Güven"in Access'teki tek anlamı | "İK sisteminin departman bilgisini yetki seçiminde kullanırız" |
| **Grant** | Bir yetkinin açıkça verilmesi; yetkinin **tek** kaynağı. Devir de bir Grant'tır | Finans müdürü, satın alma ajanına "ayda 100.000 EUR'ya kadar tedarikçi siparişi" yetkisi verir |
| **Mandate** | Bir Party'nin sahip olduğu yetkinin, belirli bir Instance'ta kullanılabilecek alt kümesi. Yetkiye sahip olmak, her yerde kullanabilmek demek değildir | Ajanın yetkisi var, ama bu çalışmasında yalnız 10.000 EUR'ya kadar kullanabilir |
| **Authority Exercise** | Yetkinin belirli bir iş için, belirli bir anda kullanılması ve bunun kararı + kaydı. Access'in **değer birimi** | Ajanın saat 14:02'de B şirketine 50.000 EUR'luk sipariş vermesi |
| **Decision** | Access'in kararı: **ALLOW**, **DENY** ya da eksikleri söyleyen **REQUIRE_ACTION** | REQUIRE_ACTION: "Bu tutar için finans müdürünün onayı gerekiyor" |

**Yetki modelinin diğer kavramları:**

| Kavram | Ne demek |
|---|---|
| **AuthorityDomain** | Yetki kayıtlarının tutulduğu, tek bir doğruluk kaynağı olan alan; genelde bir kurum |
| **AuthorityAnchor ve root** | Bir kaynak üzerindeki yetkinin başladığı nokta ve o yetkinin asıl sahibi |
| **RestrictionPolicy** | Yetki vermeyen, yalnız yasaklayan veya ek şart koyan kural ("hafta sonu ödeme yok") |
| **Intent / IntentEnvelope** | Yapılmak istenen işin tam tanımı: ne, hangi kaynakta, hangi parametrelerle, hangi amaçla |
| **ValidityContract** | Bir kararın veya belgenin ne kadar süre, hangi koşullarla geçerli sayılacağı; iptalin ne kadar sürede etkili olacağı |
| **Projection** | Yetkinin dışarıya taşınan, kısa ömürlü, kişiye bağlı belgesi: token, SSH sertifikası, imzalı karar belgesi. Yetkinin kendisi değil, kanıtıdır |
| **Consequence Tier (CT0–CT3)** | İşlemin risk sınıfı: okumadan (CT0) geri alınamaz ve kritik işlemlere (CT3) kadar. Gereken güvence buna göre artar |

**Identity plane kavramları:** **Tenant** (ticari müşteri), **Identity Realm** (bir müşterinin kullanıcılarının yaşadığı izole kimlik alanı), kullanıcı kaydı, kimlik bilgisi (parola, passkey), oturum, uygulama (client) ve bağlı dış IdP. Bunlar authority plane'e yalnız Claim olarak geçer (§5.16, §5.17).

**Temel ilkeler:**

1. **Yetki yalnız Grant'tan gelir.** Rol, grup veya token yetki değildir; en fazla bir Grant'ın kime uygulanacağını seçen girdidir (MD-4).
2. **Yetki zincir boyunca yalnız daralır.** Devreden kişi sahip olduğundan fazlasını veremez.
3. **Sahip olmak ≠ kullanabilmek.** Yetkiye sahip olan bir Party'nin her Instance'ı onu kullanamaz (Mandate).
4. **Her değişiklik tek yoldan geçer.** Yetki verme, değiştirme ve iptal de bir Authority Exercise'tır; kararı ve kaydı vardır (INV-2).
5. **İptal ileriye dönük ve kesindir.** İptal edildiği andan itibaren, devam eden kullanım dahil, geçerlidir.
6. **Kayıtlar dışarıda doğrulanabilir.** Bir karşı taraf veya denetçi, Access'e sormadan bir kararın gerçek ve geçerli olduğunu kontrol edebilir (§1.4, vaat 7).
