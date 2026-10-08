## 8. Product Experience

Experience katmanı ontology'yi değiştirmez; onu insanlara ve agent'lara dürüstçe gösterir. Bağlayıcı kurallar: bir canonical kavram tek UI terimidir (§8.8); her gösterilen gerçek owner'ından gelir, gelmiyorsa UNKNOWN'dur (§8.13); hiçbir yüzey ack edilmemiş durumu ack edilmiş gibi göstermez (§8.7).

**Identity plane.** Access tam bir identity plane'e sahiptir. Hosted giriş sayfaları, hesap self-servis yüzeyleri, oturum ve cihaz listesi, kurtarma akışları, yönetim konsolu ve destek erişimi identity plane yüzeyleridir. **Identity plane mesajları da bu bölümün sözlük ve forbidden-claims kurallarına (§8.8–§8.12) ve degraded-state kurallarına (§8.13) tabidir.**
- Identity plane yüzeylerinin akış mekaniği (identifier-first, passkey/koşullu arayüz, MFA, hosted/embedded, markalama, erişilebilirlik) §12'dedir (TN-G1–TN-G3). Bu bölüm o yüzeylerin **dili ve dürüstlük kurallarını** koyar.
- Giriş UX ürün dili kuralları ve bu bölümün kurallarıyla ilişkileri §8.15'tedir.
- Destek erişiminin deneyimi §8.16'dadır (MD-9).
- Deneyim ayrıntıları §8.17'dedir; agent sözleşmesinin tam metni (A-1…A-12) §8.18'dedir (MD-19.2).
- Ek experience kararları X32–X41 §8.19'dadır.

### 8.1 Canonical mental model

> **Yetki bir kaynaktan doğar, yalnız daralarak başkasına verilir ve her kullanımı kaydedilir. Access bu zinciri gösterir: kim neyi, kimin adına, hangi sınırla ve neye dayanarak yapabilir. Verdiğimi görürüm, daraltırım ve geri alırım; geri alma bundan sonrası içindir. İşin kendisi, para, kimlik ve dünyada olan etki başkalarınındır — Access onları sahiplerinin ağzından söyler.**

Bu modelin kullanıcıya öğrettiği beş kalıcı fikir (her biri frozen bir karara dayanır):

| # | Kullanıcının aklında kalan fikir | Dayandığı karar |
|---|---|---|
| 1 | **Yetki bir zincirdir.** Her yetkinin bir kaynağı var; her halka öncekinden dar veya eşit | INV-1, INV-3, INV-4 |
| 2 | **"Kimin adına" ayrı bir sorudur.** Benden gelen yetki her zaman benim adıma kullanılmaz | XI-10, C12 |
| 3 | **Vermek zor, almak kolay.** Genişletmek dikkat ister; daraltmak her an mümkündür | INV-10, L11 |
| 4 | **İzin ≠ yapıldı ≠ durdu.** Access neyin *yapılabileceğini* söyler; yapılıp yapılmadığını ve durup durmadığını sahibi söyler | INV-18, EI-11, E25 |
| 5 | **Onay yetki değildir.** Bir isteği onaylamak o isteği tamamlar; kimseye yeni yetki vermez | CI-14, INV-20, E7 |

### 8.2 Tek model, beş mercek

Organizasyon ve developer için ayrı bir mental model gerekip gerekmediği test edildi. **Karar: ayrı model yok, ayrı mercek var.** Ayrı model, aynı fact'e iki farklı anlam yüklerdi (ör. admin için "rol = yetki", kullanıcı için "rol = etiket"); bu iki source of truth'un dildeki karşılığıdır. Her mercek aynı zincirin farklı bir kesitine bakar:

| Mercek | Zincirin hangi kesiti | Merceğin cümlesi | Aynı modelden ne ekler |
|---|---|---|---|
| **Principal** | Benden çıkan ve bana gelen halkalar | "Benden kim ne kullanıyor, kim benim adıma ne yapabilir, ben neyi nereden tutuyorum" | Budget, süre, aftermath |
| **Approver** | Tek bir intent ve benim `approve` halkam | "Kendi yetkimle, tam olarak bunu, şu sıfatla onaylıyorum" | Exact intent, independence, assurance |
| **Admin / authority owner** | Kökler, rol halkaları, seçim kaynakları | "Kurumun yetki anayasası: kökler, roller, kabul edilen kaynaklar, korunan eylemler" | Rule-shaped seçim, Acceptance blast radius, change impact |
| **Developer / operator** | Karar sözleşmesi | "Her consequential effect'ten önce soruyorum; cevap ALLOW, DENY veya *neyin eksik olduğu*; schema'mı ben yayınlarım, yetki yaratmam" | Schema, PEP, verifier profile, advisory evaluation |
| **Auditor** | Kayıtlar ve dayandıkları state | "Her kullanım kökten bugüne izlenebilir ve o anki state'e göre yeniden üretilebilir" | StateBasis, cited claims, replay, redaction |

Mercekler arasında dil değişmez: "Delegation", "Approve", "Revoke", "Suspend", "Limit" her mercekte aynı canonical şeyi adlandırır; derinlik değişir.

### 8.3 Anti-modeller

| Yanlış model | Neden tehlikeli | Hangi tasarım kararı önler |
|---|---|---|
| "Access'e giriş yaptım, demek ki yetkim var" | Identity ≠ Authority (F3, INV-12): giriş yapmak (sign-in) yetki vermez | S10 sign-in yüzeyi yetki göstermez; "Signed in" hiçbir zaman "allowed" ile yan yana sunulmaz (X29) |
| "Çıkış yaptım, artık hiçbir şey benim adıma çalışamaz" | Sign-out identity plane oturumunu ve o cihazdaki bağlı insan Instance'ını bitirir (temizlik); verilmiş Grant'lar (agent'lara ve uygulamalara delegation'lar) kalır. Revocation ayrı bir Exercise'tır (Identity ≠ Authority) | "Sign out" ≠ "Revoke". Sign-out ekranı bağlı uygulama ve agent delegation'larının sürdüğünü yazar ve S2'ye link verir (X36) |
| "Destek ekibi benim hesabımla giriş yapıyor" | Impersonation yoktur. Destek operatörü kendi Instance'ıyla, kullanıcının verdiği Grant'ın kapsamında ve FOR(kullanıcı) capacity'siyle hareket eder | Destek erişimi S1'de bir delegation'dır; S2'de "Acting for you" satırında görünür ve iptal edilebilir (§8.16, X37) |
| "Organizasyonumun hesabı = yetki alanım" | Tenant ticari hesaptır. Authority AuthorityDomain'dedir. Organizasyon realm içinde bir Party'dir | UI ticari aboneliği (Tenant) ve yetki yapısını (Domain/roles) ayrı yerlerde gösterir; "Admin of subscription" ≠ "Authority root" (§8.11) |
| "Onaylar Access'te yaşar" | Approval toplama Work'ündür; Access'in kuyruğu yoktur | X5, XI-7; onay isteği yalnız Needs Attention'dan gelir |
| "Access agent'ı durdurur" | Stop Executor'ındır (E31); revocation ≠ stop | Aftermath paneli, "Suspend" ≠ "Pause" (X13) |
| "Ayarlar sayfasındaki bir izin" | Statik izin modeli provenance'ı ve zamanı saklar | Envanter her satırda kaynak, capacity ve süre gösterir |
| "Agent'ımın ödeme limiti bankamın limitidir" | Authority budget ≠ financial limit ≠ financial hold (E21, F9) | Limit etiketleri ayrı; iki limit iki satır (XI-14) |
| "Admin her şeyi yapabilir" | "admin: *" reserved action'ları kapsamaz (INV-9, E11) | "Full access" yasak; admin Grant'ı neyi kapsadığını ve neyi kapsamadığını gösterir (X20) |
| "Bir kez onayladım, artık izin verdim" | Contribution tek intent'e bağlı ve single-use'tur (INV-20) | "Approve" ≠ "Give access" ≠ "Allowed"; tekrar eden onaylar explicit delegation önerisine dönüşür (X8, XI-19) |
| "Erişim verdim, artık yapabilir" | Grant holding yaratır; exercisable kullanım Mandate, restriction ve requirement'lardan da geçer; "Allowed" yalnız Access'in ALLOW kararıdır (CI-5) | "Give access" metni kullanım vaat etmez; kalan engeller önceden görünür (X8) |
| "HR beni çıkardıysa her şeyim gitti / geri geldi" | Yalnız rule-shaped holding'ler HR'a bağlıdır; doğrudan verilen Grant'lar kalır; geri dönmek eski türevleri canlandırmaz (INV-31) | Offboarding'de kanal kanal disposition; rejoin açıklaması |
| "İmzalı = doğru" | Claim ≠ Truth (INV-14) | Claim'ler "X says (signed)" olarak gösterilir; "verified fact" yasak |

### 8.4 Epistemik statü

Mental model ve mercekler FROZEN PRODUCT DECISION'dır (X1, X2). Şunlar **CURRENT UX HYPOTHESIS**'tir ve kullanıcı araştırması ile pilotlarla doğrulanır (OQ-6): kullanıcıların provenance/capacity ayrımını iki grup hâlinde anlayacağı; asimetrik sürtünmenin güvenlik-kullanılabilirlik dengesini koruyacağı; "Approve" / "Give access" / "Allowed" terim ayrımının öğrenilebileceği. Hipotez çürürse değişen şey kelime ve gruplamadır; semantik ayrımlar ve forbidden claims (§8.10) değişmez.

### 8.5 Yüzeyler (S1–S11; X32)

| # | Yüzey | Cevapladığı soru | Kimin için | Canonical kaynak | Asla |
|---|---|---|---|---|---|
| **S1** | **Delegation** (yetki verme / düzenleme sayfası) | "Kime, neyi, kimin adına, hangi sınırla, ne zamana kadar veriyorum — ve neyi vermiyorum?" | Principal, admin, approver'ın "Give access" yolu, end customer (merchant yetkisi) | Kullanıcının holding'i (derived effective authority), kabul edilmiş action schema'ları, named AuthoritySet sürümleri; sonuç `grant.issue` / `grant.amend` Exercise'ı | NL cümlesini kayıt gibi göstermek; kullanıcının tutmadığından fazlasını önermek; reserved action'ları veya gelecekteki action'ları "dahil" göstermek; varsayılan olarak yeniden delege edilebilirlik |
| **S2** | **Authority inventory** ("Authority" hub) | "Benim yetkimden kim ne kullanıyor, kim benim adıma ne yapabilir, ben neyi nereden tutuyorum?" | Principal (birincil), admin (org adına), end customer | Derived: holder set, effective authority, budget remaining, Commitment-scoped bağ (Work ref), revocation impact; cross-domain read federation projection'ları (owner + freshness etiketli) | Bakiye veya finansal limit; execution durumu (authority durumu gibi); başka domain'in güncel durumunu "teyitli" diye; başkalarının graph'ı |
| **S3** | **Approval Surface** (trusted; Work Gate ile ortak) | "Kendi yetkimle, hangi sıfatla, tam olarak neyi onaylıyorum ve bunun sonucu ne olacak/olmayacak?" | Approver, admin (quorum), end customer (ödeme onayı) | Exact intent (kabul edilmiş schema ile render), Work Gate canonical payload (Work), eligible set ve requirement'lar (Access); sonuç `contribute(approve, digest)` Exercise'ı + Work Declaration | Agent prose'unu özet olarak; "Approve anyway"; DENY'ı aşan onay; Gate satisfied'ı "allowed" olarak; render edilemeyen intent için onay düğmesi |
| **S4** | **Revoke / Suspend / Narrow + Aftermath** | "Bunu şimdi bitirirsem/daraltırsam neler etkilenir — ve bitirdikten sonra gerçekte ne durumda?" | Principal, admin, auditor (containment) | `grant.revoke` / `grant.amend` / `policy.set` / `instance.terminate` Exercise'ları; revocation impact ve staleness exposure (derived); Executor control durumu (Executor/Work) ve verifier ack'leri (Claim) | "Agent stopped" (Executor teyidi olmadan); "Revoked everywhere instantly"; açık ValidityContract/projection varken "can't use this anymore"; beyan edilmiş pencere içindeki conformant kullanımı "outside authority" diye etiketlemek; "Undo"; commit olmadan "Revoked" |
| **S5** | **Explanation** ("Why?" paneli; her yüzeyde) | "Neden izin verildi / reddedildi / ne gerekiyor — ve bu hayırın sahibi kim?" | Herkes, viewer'ın authority'si kadar derinlikte | DecisionRecord (geçmiş karar için) veya advisory evaluation (varsayımsal için); cited Claim/Acceptance/policy; diğer owner'ların kendi cevapları (Work autonomy, domain eligibility, Pay limiti) | Viewer'ın göremeyeceği graph parçaları; özel bağlam (One memory, Work içeriği); advisory sonucu "garanti" gibi; serbest metin talimat (agent'a) |
| **S6** | **Activity** (yetki kullanımları) | "Benim yetkimle veya benim adıma ne zaman, kim tarafından, neye dayanarak ne yapıldı — ve sonucu bildirildi mi?" | Principal, admin, auditor, developer | Exercise/DecisionRecord'lar; outcome state (unattested / attested-conforming / attested-nonconforming, derived); effect attestation Claim'leri (issuer etiketli) | Effect'i Access'in beyanı gibi "done"; attestation yokluğunu başarı veya başarısızlık olarak; DENY/REQUIRE değerlendirmelerini "kullanım" olarak |
| **S7** | **Organization authority admin** | "Kurumun yetki yapısı ne: kökler, roller, seçim kaynakları, korunan eylemler, kısıtlar — ve bu değişiklik kimi nasıl etkiler?" | Admin / authority owner | Anchor'lar ve rootTerms, rule-shaped Grant'lar, named AuthoritySet sürümleri, Acceptance'lar, RestrictionPolicy sürümleri, meta-Exercise geçmişi; change-impact (derived) | "Full access"; sessiz toplu sürüm geçişi; disposition'sız offboarding; Acceptance etkisini (blast radius) göstermeden kabul; impersonation |
| **S8** | **Developer console** | "Schema'm hangi domain'lerde nasıl kabul edildi, PEP'im doğru soruyor mu, bu karar neden böyle çıktı?" | Developer / operator | Publisher'ın schema yayınları (publisher'ın), domain Acceptance'ları (Access), advisory evaluation, DecisionRecord replay (yetki kadar), verifier conformance Claim'leri | Domain adına schema kabulü; fail-open ayarı; prod authority'nin test domain'ine sızması; başka tenant'ların kararları |
| **S9** | **Audit & security** | "Bu kullanım kökten bugüne nasıl meşru oldu, o anki state neydi, revocation nereye kadar yayıldı, neyin sonucu bilinmiyor?" | Auditor, security, admin | Append-only kayıtlar (Genesis, Exercise/DecisionRecord, Claim ingest), AuthorityStateBasis, revocation impact, outcome state; SIEM'e export edilen projection | Kaydın düzenlenmesi; redakte body'nin "yok" gibi; SIEM kopyasının kaynak gibi |
| **S10** | **Sign-ins & instances** (Identity plane + Instance) | "Hangi cihaz girişi/çalışan kopya benim (veya agent'ımın) adına doğrulanmış durumda ve onları nasıl kapatırım?" | Principal, developer/operator, security | Identity plane Claim'leri (authentication, authenticator-binding), Instance lifecycle Exercise'ları, Mandate sınırları (uzman görünümünde) | "Signed in = allowed"; "trusted device" ifadesinin yetki çağrıştırması; Party recovery'yi Instance recovery gibi |
| **S10** | (S10'un identity plane genişlemesi) | Ek: identity plane oturumlarının (login session) render'ı. Satır birimi "*device* üzerinde giriş"tir: bir cihazdaki identity plane oturumu tam olarak bir insan Instance'ına bağlıdır. Satır iki alt durumu ayrı gösterir: **identity** ("signed in until …" / "signed out"; son etkinlik, boşta kalma + mutlak ömür, cihaz/tarayıcı, bağ (DBSC/DPoP) durumu) ve **authority** ("active" / "ended"). "Sign out" (bu cihazda: oturumu bitirir ve bağlı Instance'ı sonlandırır; temizlik) ve "End this sign-in" (başka bir cihaz satırı için `instance.terminate`; identity plane o oturumu `session_epoch` ile kapatır) ayrı eylemlerdir; tek düğme olarak birleştirilmez ve hiçbiri Revoke değildir (X36) | — | Identity plane oturum kayıtları (identity plane), Instance lifecycle Exercise'ları (authority plane) | Oturum satırını Instance'tan bağımsız ikinci bir "session" nesnesi olarak göstermek; "Signed out everywhere instantly"; sign-out'u revoke gibi göstermek |
| **S11** | **Account & sign-in methods** (identity plane self-servis) | "Hangi yöntemlerle giriş yapabilirim, hesabımı nasıl kurtarırım, verilerimi nasıl alır veya silerim, hangi hesaplar bağlı?" | Her insan Party (kendi hesabı için); admin yalnız kendi realm'inin politika görünümünde | Identity plane: credential/authenticator kayıtları (passkey, parola, TOTP, kurtarma kodları), bağlı hesaplar (IdentityBinding), kurtarma durumu, hesap durumu, veri taşınabilirlik/silme talepleri; SEC18 soğuma durumu (authority plane politikası) | Credential'ın "trusted device" diye sunulması; kurtarma sonrası "you're all set" (SEC18 varken); silmenin "everything erased" diye sunulması (tombstone/saklama varken); passkey'in RP ID değişiminden sonra çalışacağını ima etmek; hesap var/yok bilgisini kimliği doğrulanmamış viewer'a sızdırmak (X34) |

Step-up (taze kimlik doğrulama) bir yüzey değil, etkileşimdir; Identity plane'in ceremony'si olarak S1, S3 veya domain akışı içinde açılır. Step-up ekranı hangi exact eylem için istendiğini ve neden istendiğini söyler (X29). Gerekçe (RFC 9470): nedeni söylemeyen yeniden doğrulama ekranı kimlik avından ayırt edilemez ve kullanıcıyı düşünmeden kimlik bilgisi girmeye alıştırır. `acr_values` tavsiye, `max_age` zorunludur; mekanizma §12 TN-O3'tedir. Login sırasındaki kimlik doğrulama (S11/hosted giriş) da bir ceremony'dir ve yetki vermez.

**Yüzeyler hakkında taşıyıcı kararlar**

1. **Approval Surface ortak bir yüzeydir, Access'in değil.** Plane ataması (§2.5/§7.6) gereği trusted approval surface Experience/Work Approval Surface conformance profile'ıdır. Access onun içindeki authority-relevant kısmı (kim, hangi digest, hangi assurance, hangi independence) tanımlar; Work Gate'in nedenini; yüzey sadık render'ı ve kullanıcı eylemini (E32).
2. **S2 ve Work'ün "Commitments" yüzeyi ayrı sorulara cevap verir.** Commitments: "kim benim için ne üstlendi" (Work). S2: "kim benim adıma ne *yapabilir*" (Access). Bir agent ikisinde de görünebilir; iki satır iki fact'tir ve birbirine referansla bağlanır (E8: work delegation ≠ authority delegation).
3. **S5 her yerde aynı bileşendir.** Work Live, Needs Attention, Pay limit ekranı, Commerce personel ekranı ve developer console aynı "Why?" panelini kullanır; panel her "hayır"ı owner'ıyla gösterir.
4. **Hiçbir yüzey optimistic UI kullanmaz.** Authority değiştiren bir eylem, authoritative domain commit'i dönene kadar "submitted" (gönderildi) durumundadır; "Revoked", "Delegation created", "Approved" ancak commit sonrası yazılır (X14, XI-3).

### 8.6 Attention: ne otomatik, ne insan, ne asla otomatik

| Olay / eylem | Otomatik mi | İnsan dikkati nerede | Asla otomatik değil çünkü | Owner |
|---|---|---|---|---|
| Exercisable ∩ autonomy içindeki istek | **Evet** (ALLOW; Work "proceed") | — (Briefing'de özet olabilir) | — | Access + Work |
| Autonomy "require-Gate" | Hayır | Needs Attention (Gate) | — | Work |
| Approval requirement (contribution) | Hayır | Needs Attention → S3 | Approval exact digest'e bağlı insan eylemidir (EI-18) | Work + Access |
| Authority eksik (DENY) | Hayır | Needs Attention (Condition) → S1 | Authority genişletmesi | Work + Access |
| Step-up | Hayır (insan) | Inline, eylem anında | Assurance kanıtı | Identity plane |
| Yeni cihazdan giriş, yeni credential eklenmesi, kurtarma başlatılması/tamamlanması, birincil e-posta veya telefon değişimi | Bildirim **evet** (Relay, anlık); eylem gerektirmez | "If this wasn't you: Secure your account" linki (S11). **"Action required" etiketi yok** | Güvenlik açısından önemli bilgi sınıfıdır (aşağıdaki tablo). Key-event bildirimi Party Identity Regime yükümlülüğüdür (SEC18) | Identity plane |
| Login push onayı (MFA) | Hayır (insan) | Push; sayı eşleştirme zorunlu (aynı cihaz istisnası) → §12 TN-G1 | Login push bir authority onayı değildir. Authority onayının bildirim içi yapılması ayrı kurala (CT1 + H(AAS)) tabidir | Identity plane |
| Olay tabanlı oturum iptali (parola değişimi, MFA yöntemi değişimi, cihaz uyumsuzluğu, yönetici iptali, `instance.terminate`) | **Evet** (identity plane mekanizması) | Bilgi: S10 satırında "Signed out because …" | — | Identity plane |
| Destek erişimi talebi | **Asla** otomatik değil | S1 (kullanıcının kendi delegation'ı) veya break-glass Grant'ının requirement'ları (quorum) | Authority genişletmesi (INV-10). Destek talebi requester inisiyatifli bir authority talebidir; trusted sheet doğrudan açılmaz (XI-7) | Access |
| Grant issue / genişletme / delegability açma / süre uzatma | **Asla** | S1 (trusted) | Authority genişletmesi (INV-10) | Access |
| Template/rol sürüm geçişi | **Asla** (toplu da olsa explicit) | S7 change-impact | Canlı dolaylılık yok (C28) | Access |
| Acceptance establish/expand | **Asla** | S7 (+ quorum Gate) | Reserved, blast radius | Access |
| Restriction kaldırma (unsuspend, policy gevşetme) | **Asla** | S4/S7 (trusted) | Genişletme sınıfı (INV-6) | Access |
| Mandate rebind (widen) | **Asla** | Holder'ın kendi Instance'ı | Fresh ceremony | Access |
| Departure disposition, root transfer disposition | **Asla** | S7 Offboarding / Domain | Varsayılan yok (C10, E6) | Access |
| Delegation yenileme | **Asla** | Envanter / Briefing | Validity uzatma = genişletme | Access |
| Expiry | **Evet** (derived) | Briefing (kullanılıyorsa) | — | Access |
| Commitment-scoped bitiş | **Evet** (Work Claim'i ile) | Briefing (Work) | — | Work → Access |
| HR'ın seçimi değiştirmesi | **Evet** (kabul edilmiş kaynak) | Changes / Briefing | Kanal önceden explicit kurulmuştur (C13) | HR → Access |
| Revocation, narrowing, containment | Kişi veya yetkili Party'nin (SOC dahil) attributable Exercise'ı; otomasyon ancak attributable bir Party'nin önceden verilmiş Grant'ıyla | Aftermath; execution unknown ise Needs Attention | — (daraltma güvenli yöndedir) | Access |
| Budget release | Grounded Claim geldiğinde actor/lineage holder Exercise'ı (otomasyon olabilir) | — | Grounded olmayan release imkânsız | Access |
| Revocation sonrası execution unknown | Hayır | Needs Attention / Live | Fiziksel stop teyidi yoktur | Work + Executor |
| Semantic event teslimi | **Evet** | — | — | Relay |

**Access-only olayların dikkat yeri**

Work'e bağlı olmayan authority olayları (biri size yetki verdi, bir merchant yetkisi sona erdi, bir agent'ınız alt delegation yaptı, bir kaynak kabulü değişti) için kural:

| Olay sınıfı | Varsayılan | Neden |
|---|---|---|
| Bilgi (değişti, sona erdi, verildi) | Authority hub ▸ Changes (pull); Relay ile özet teslimi kullanıcının tercihine göre | Görev değildir |
| Güvenlik açısından önemli bilgi (sizin adınıza yeni bir alt delegation; sizin adınıza yeni bir domain'e kabul; sizin Instance'ınızın sonlandırılması) | Relay ile anlık teslim varsayılan açık; **"action required" etiketi yok**; içerik "If you didn't expect this: Revoke / Review" linki taşır | Daraltma her zaman bir dokunuş uzaklıktadır (XI-5) ama sistem görev yaratmaz |
| İnsan kararı gerektiren her şey | **Asla buradan değil** — coordinator'ın Gate/Condition'ı | X5 |

### 8.7 Honest status ladder

Bir authority kullanımının yaşam yolu her yüzeyde aynı basamaklarla, her basamak kendi owner rozetiyle gösterilir. Basamaklar birleştirilemez; atlanan basamak "—" veya "unknown" olarak görünür, tahmin edilmez.

| Basamak | UI (EN / TR) | Owner | Kaynak fact | Asla bununla eşitlenmez |
|---|---|---|---|---|
| Requested | Requested / İstendi | Requester (agent/PEP) → Access | Exercise opening (pending) | Approved |
| Approval recorded | Approved by *X* / *X* onayladı | Access | contribution Exercise | Gate satisfied, Allowed |
| Gate satisfied | Gate cleared / Onay adımı tamam | Work | Work Declaration (ExerciseID'li) | Allowed |
| Allowed | Allowed / İzin verildi | Access | ALLOW DecisionRecord (Exercise doğar) | Started, Done |
| Not allowed | Not allowed / İzin verilmedi | Access | DENY (evaluation) | Failed (effect) |
| Started | Started (reported by *runtime/Pay*) | Executor / domain | Execution state, Act report | Done |
| Reported done | Done (reported by *Pay*) | Effect issuer | `effect.attestation` Claim | Access'in teyidi; "true" |
| Reported not done | Not done (reported by *Pay*) | Effect issuer | `effect.non-execution` Claim | Revoked |
| Unknown | Result unknown | — (owner'dan bilgi yok) | Attestation yok | Failed veya Succeeded (EI-22) |
| Differs | Reported result differs from what was allowed | Access (derived) | attested-nonconforming | "Outside authority" kesin hükmü (inceleme gerekir) |

**Commit ve ack görünürlüğü (`witnessed_through` kuralı).** Derived okuma cevapları `witnessed_through` alanını taşır (mevcut checkpoint verisi; yeni nesne değildir). Witness/replica-before-ack sınıfındaki (SEC23) bir kayıt — revocation, scope-narrowing amend, delegation — `witnessed_through` pozisyonunun ötesindeyse UI niteliksiz durum göstermez:

| Durum | UI (EN) | UI (TR) | Ne zaman kalkar |
|---|---|---|---|
| Commit edildi, witness/replica ack bekliyor | **Revoked — confirming (witness pending)** / **Delegation created — confirming (witness pending)** | Geri alındı — teyit ediliyor (witness bekleniyor) | Kayıt `witnessed_through` içine girince nitelik kalkar |
| Commit edildi ve ack'lendi | **Revoked** / **Delegation created** | Geri alındı / Yetki verildi | — |
| İstek gönderildi, sonuç bilinmiyor (timeout) | **Not confirmed — checking** | Teyit edilmedi — kontrol ediliyor | Aynı nonce'la retry/sonuç sorgusu cevap verince (§8.13) |

Diğer kayıt sınıflarında ladder değişmez. S2 ve S10'daki "Revoked" / "Delegation created" satırları bu kurala tabidir.

"Allowed" basamağı yalnız Access'in ALLOW DecisionRecord'undan gelir. Kullanıcının "Give access" / "Delegate" eylemi bu ladder'ın bir basamağı değildir; envanterde ve Activity'de "Delegation created" olarak, ayrı bir satırda görünür (XI-13).

### 8.8 Canonical → UI eşlemesi

Kural: **bir canonical kavram → bir UI terimi**; bir UI terimi → tek canonical kavram. Bağlama göre değişen yalnız render'dır (ör. Instance'ın cihaz adı), terim değil.

| Canonical | UI (EN) | UI (TR) | Görünürlük | Not |
|---|---|---|---|---|
| Grant (verdiğim) | **Delegation** | Yetki verme / verilen yetki | Default | "Transfer/devir" asla: grantor yetkisini kaybetmez |
| Grant (tuttuğum) | **Your authority** (from *X*) | Yetkim (*X*'ten) | Default | Kaynak her zaman yanında |
| Rule-shaped Grant | **Role delegation** ("everyone HR lists in Finance") | Rol yetkisi | Default (admin), Expert (kullanıcı) | Seçici + kaynak |
| Named AuthoritySet | **Role** / **Template** (vN) | Rol / Şablon (sürüm) | Default | Sürüm görünür |
| AgencyTerms / capacity | **On your behalf** · **On behalf of *Acme*** · **For their own use** · **As yourself** | Sizin adınıza · *Acme* adına · Kendi kullanımı için · Kendi adınıza | **Default** | Provenance'tan ayrı (XI-10) |
| Provenance / lineage | **Given by** / **Comes from** (chain) | Veren / Kaynağı (zincir) | Default (tek halka), Expert (zincir) | |
| DelegationTerms | **Can pass on** (up to N steps / only to …) | Başkasına verebilir | Default | Varsayılan No |
| Reserved action | **Protected action** | Korunan eylem | Default | "Only included when named" |
| BudgetTerm / remaining | **Limit** / **left** ("1,200 TRY left today") | Limit / kalan | Default | "Held/balance" asla |
| RequirementTerm | **Needs** ("needs 1 approval", "needs a fresh sign-in") | Gerekli | Default | |
| contribution (approve) | **Approve** / **Approval** | Onayla / onay | Default | Yalnız contribution için |
| contribution (co-authorize, consent) | **Co-sign** / **Consent** | Birlikte imzala / Rıza | Default | Sınıfa göre tek terim |
| grant.issue (insan talebiyle) | **Give access…** / **Give access once** / **Delegate**; commit sonrası **Delegation created** | Erişim ver / Bir kez erişim ver / Yetki ver; commit sonrası "Yetki verildi" | Default | "Approve", "Allow", "Allowed", "Granted" asla (Allowed yalnız ALLOW'dur); onay metni kullanım vaat etmez ("Access will still check the request") |
| grant.revoke | **Revoke** | Yetkiyi kaldır | Default | "Undo", "Geri al", "Delete" asla |
| grant.amend (narrow) | **Narrow** | Daralt | Default | |
| grant.renounce | **Give back** | İade et | Default | Yalnız extensional |
| Restriction overlay (suspend) | **Suspend** / **Suspended** | Askıya al / askıda | Default | "Pause" asla |
| RestrictionPolicy | **Restriction** ("Acme restriction: …") | Kısıt | Default (sınıf), Expert (içerik, yetki varsa) | |
| Acceptance | **Accepted source** (for *sign-in / facts / membership / partner authority / action definitions*) | Kabul edilen kaynak (… için) | Admin default; kullanıcı Expert | "Trusted" asla |
| Claim | **Statement** ("HR says …, 3 Oct") | Beyan ("HR'a göre …") | Default (özet) | "Verified/true" asla |
| Authority Exercise | **Use** (of authority) | Yetki kullanımı | Default (Activity) | |
| DENY / REQUIRE_ACTION / advisory | **Not allowed** · **Needs …** · **Check** ("would be allowed now") | İzin verilmedi · … gerekli · Kontrol | Default | DENY "kullanım" değildir |
| ALLOW | **Allowed** | İzin verildi | Default | "Done/Completed/Paid" asla; kullanıcının grant.issue eylemi için asla |
| Outcome state | **Reported done / Reported not done / Result unknown / Differs from allowed** | Bildirildi: yapıldı / yapılmadı / sonuç bilinmiyor / izinden farklı | Default | Reporter adıyla |
| Instance | **Instance** — render: "Sign-in on *device*" (insan), "Running copy" (agent) | Giriş (cihaz) / çalışan kopya (render) | Default (S10) | Terim tek; yalnız render Party türüne göre değişir; "session"/"oturum" Instance için asla |
| Mandate | **Instance limits** ("this copy's limits") | Çalışan kopya sınırları | Expert | "Mandate" kelimesi asla; genişletme yalnız agent'ın Party'sinden, operatörden değil |
| AuthorityAnchor / root | **Authority root** ("Root: Acme board, 2 of 3") | Yetki kökü | Admin | "Owner" değil (hukuki sahiplik Money/domain'in) |
| AuthorityDomain | **Domain** (çok domain varsa) | Alan | Gizli / çok domain'de görünür | Tenant/org/workspace değil |
| Projection (offline) | **Offline pass** ("valid offline until 18:00") | Çevrimdışı izin | Default (POS), Expert | "Token" yalnız developer |
| ValidityContract | **Valid until … / next check by …** | … tarihine kadar geçerli / sonraki kontrol | Default | Adı asla |
| Commitment-scoped while-condition | **Ends with Work commitment *X*** | *X* taahhüdüyle biter | Default | |
| Bridging Grant / foreign authority | **Partner authority** (up to …) | Ortak kurum yetkisi (… tavanına kadar) | Admin | |
| Semantic event | (görünmez; Changes satırı olarak) | — | — | |
| Exercise ↔ Gate | **Approval recorded** (Access) · **Gate cleared** (Work) | Onay kaydedildi · Onay adımı tamam | Default | İki satır |
| Identity plane oturumu (login session) | Ayrı terim yok: Instance satırının nitelikleri ("Signed in on *device* · active 5 min ago · stays signed in until 12 Oct"). Eylem: **Sign out** | Ayrı terim yok: "*cihaz* üzerinde giriş" satırının nitelikleri. Eylem: **Çıkış yap** | Default (S10) | "Session"/"oturum" kelimesi Access UI'ında kullanılmaz (§8.11). "Sign out" ≠ "Revoke". Satır birimi "*device* üzerinde giriş"tir; identity ve authority alt durumları ayrı gösterilir. Bir cihazdaki identity plane oturumu tam olarak bir insan Instance'ına bağlıdır; aynı UI terimi iki canonical nesneyi adlandırmaz, oturum yalnız satırın identity alt durumudur (XI-13) |
| "Beni hatırla" (oturum sürekliliği) | **Keep me signed in on this device** | Bu cihazda girişim açık kalsın | Default (giriş) | Yalnız identity plane oturum ömrüdür. "Remember this decision", "Trust this device" asla (§8.10) |
| Credential / authenticator | **Sign-in method** (Passkey · Password · Authenticator app · Recovery codes) | Giriş yöntemi (Geçiş anahtarı · Parola · Doğrulama uygulaması · Kurtarma kodları) | Default (S11) | "Trusted"/"verified device" asla |
| Hesap (user record) | **Account** | Hesap | Default (S11) | Tenant için kullanılmaz (§8.11) |
| Tenant | **Subscription** / **Billing account** (yalnız fatura ve plan yüzeylerinde) | Abonelik / Fatura hesabı | Yalnız ticari yüzeyler | "Organization"/"Domain"/"Account" değil. Authority içermez |
| Identity Realm | Son kullanıcıda görünmez; giriş sayfasında yalnız realm'in marka adı ("Sign in to *Acme*"). Admin/Developer: **Realm** | Görünmez / Admin: Realm | Admin, Developer | "Tenant" değil |
| Cell | Hiçbir UI'da görünmez | — | — | — |
| Organizasyon (B2B; Party + Anchor) | **Organization** (*Acme*) | Organizasyon | Default | "Tenant" değil. Authority root'u ayrı gösterilir |
| Client / RP | **App** (*Acme Payroll*) · Developer: **Client** | Uygulama · Developer: Client | Default / Developer | "Verified app" asla (X27 consent phishing dersi) |
| Üçüncü taraf uygulamaya kaynak erişimi (OAuth consent → Grant) | **Connect *App*…** → S1 exact preview → commit sonrası **Delegation created** | *Uygulama* bağla… → Yetki verildi | Default | Scope listesi asla (X27). "Allow"/"Authorize" asla (§8.11) |
| Protokol scope'u consent'i (claim release: e-posta, profil) | **Share with *App*: your email address, your name** | *Uygulama* ile paylaş: e-posta adresiniz, adınız | Default (giriş) | Authority dili kullanılmaz ("Give access" değil): kimlik verisi paylaşımıdır |
| Upstream IdP | **Sign in with *Provider*** | *Sağlayıcı* ile giriş yap | Default (giriş) | "Trusted provider" asla |
| IdentityBinding (bağlı hesap) | **Linked sign-in** (*Google account a…@…*) | Bağlı giriş | Default (S11) | "Merged" asla; bağlama açık eylemdir |
| Hesap durumu: disabled | Admin: **Sign-in disabled**. Kullanıcıya (kimliği doğrulanmışsa): **Your account's sign-in is turned off by *Acme*** | Admin: Giriş kapalı | Admin / kimliği doğrulanmış kullanıcı | Kimliği doğrulanmamış viewer'a gösterilmez (X34) |
| Destek erişimi Grant'ı | **Support access** (*Acme Support*, case #…, until 15:30) | Destek erişimi | Default | "Impersonation", "Log in as", "View as" asla |
| Token vault'taki upstream bağlantı | **Connected account for agents** (*GitHub* · used by Agent A under your delegation) | Ajanlar için bağlı hesap | Default (S2/S11) | "Agent has your GitHub password/token" değil: possession ≠ authority; satır hangi delegation'la kullanıldığını gösterir |

### 8.9 UI'a asla ulaşmayan canonical terimler

`HoldingRef` · holding episode · `AuthorityStateBasis` (Audit'te "state at decision time" olarak içerik görünür, adı görünmez) · `ValidityContract` · nonce · `PartyRef` / PartyID · `Genesis` (Admin'de "domain setup") · `AnchorRoot` · Acceptance use adları (`actor-binding`, `predicate-input`, `subject-selection`, `foreign-authority`, `schema-definition`) · `IntentEnvelope` · `DecisionRecord` (Audit'te "decision record" serbest) · `ActorContext` / `Anonymous(context)` · `consumption` · `projection.issue` · `meta-Exercise` · `RestrictionPolicy` (adıyla) · `RequirementTerm` · `SubjectSelector` · `Mandate` (adıyla) · digest (Audit'te "fingerprint") · `KeyBinding` · `ExerciseCapacity` / `OWN` / `FOR(P)` (yalnız sade dil karşılıkları).

Identity plane ve kiracılık için ek liste: `tenant_id` · `realm_id` · `placement_id` / Cell · `session_epoch` / `key_epoch` · `acr` / `amr` / `aal` ham değerleri (sade dil: "passkey", "password + code") · `client_id` (Developer hariç) · `sub` (pairwise dahil) · AIS (Actor Intent Statement) · DPoP / DBSC (sade dil: "this sign-in is tied to this device") · `jti`, nonce · `act` claim'i (sade dil: "acting for *X*") · SCIM, JIT provisioning (Admin hariç) · token vault (sade dil: "connected account").

### 8.10 Forbidden UI claims ve dürüst karşılıkları

| Yasak ifade | Neden yanlış | Dürüst ifade | Guarantee sınıfı |
|---|---|---|---|
| "Agent stopped" / "Ajan durduruldu" (revoke sonrası) | Revocation ≠ stop (EI-11) | "Authority revoked. Agent: still running / paused (confirmed by runtime) / status unknown" | Revocation: GUARANTEED BY SEMANTICS (commit anında, yeni isteklere); stop: UNDER DECLARED CAPABILITY (Executor teyidi) |
| "Revoked everywhere instantly" | Propagation ≠ semantic; offline staleness (CI-9) | "Effective now for new requests; offline devices may honor until 18:00 if they follow their profile; running tasks may continue steps already allowed until their next authority check (14:30)" | UNDER DECLARED CAPABILITY |
| "Agent A can't use this anymore" / "From now on, Agent A can't use this" (açık ValidityContract veya projection varken) | Açık reusable Decision horizon'una kadar envelope içi kullanım beyan edilmiş staleness penceresidir (CI-9, INV-24, E31) | "New requests are refused from now on. Steps already allowed may continue until 14:30 (next authority check), if its runtime follows its declared contract." (Açık contract/projection yoksa "can't use this" yazılabilir) | UNDER DECLARED CAPABILITY |
| "Outside authority" (beyan edilmiş pencere içindeki, envelope içi conformant kullanım için) | Pencere içi kullanım bir ALLOW'un envelope'una bağlıdır (INV-19, E31) | "Within the declared window (until 14:30)"; "outside authority" yalnız pencere sonrası, envelope dışı veya hiçbir Exercise'a bağlanamayan effect için | GUARANTEED BY SEMANTICS (sınıflandırma); pencere: UNDER DECLARED CAPABILITY |
| "Gives the agent one use" / "Allowed" / "Granted" (kullanıcının grant.issue eylemi için) | Grant yalnız holding yaratır; kullanım Mandate, restriction ve requirement'lardan da geçer (CI-5); "Allowed" yalnız ALLOW DecisionRecord'dur (XI-13) | "Gives Agent A authority for one use with exactly these details, until 15:30. Access will still check the request." · commit sonrası "Delegation created" | — |
| "Permission granted forever" / "Sonsuza kadar" | Validity açık; expiry tek her-zaman-çalışan revocation (F19) | "Until you revoke it" (yalnız explicit seçimle) veya tarih | — |
| "Approved" (Gate cleared anlamında, allowed sanılacak biçimde) | Gate satisfied ≠ ALLOW (EI-4) | "Your approval is recorded · Gate cleared · Payment: not yet allowed" | — |
| "Done" / "Paid" (ALLOW anlamında) | Decision ≠ Effect (INV-18) | "Allowed · Payment: reported done by Pay / result unknown" | Effect truth: issuer'ın Claim'i; NOT GUARANTEED by Access |
| "Failed" (attestation yok) | Absence ≠ outcome (EI-22) | "Result unknown" | — |
| "Verified" (Claim için) | Signed ≠ true (INV-14) | "HR says (signed)" | Claim truth: NOT GUARANTEED (Access iddianın kaydını tutar) |
| "Trusted source / trusted device" | Trust = scoped acceptance; device ≠ authority | "Accepted for sign-in" / "Compliant per Acme MDM (statement)" | — |
| "Full access" / "All permissions" / "Admin can do everything" | Reserved action'lar wildcard'la kapsanmaz (INV-9) | "All non-protected actions in *X* as of catalog vN" | GUARANTEED BY SEMANTICS (kapsam) |
| "Includes future actions" | No live inheritance (E11) | "Future actions not included" | GUARANTEED BY SEMANTICS |
| "Approve anyway" / "Override" | Approval DENY'ı aşamaz (E7) | "Approving can't raise a limit. *X* can give access once or raise the limit." | — |
| "Undo" (revoke için) | Geçmiş kullanımlar geçerli tarih (INV-23) | "Revoke (from now on)" | — |
| "Pause authority" | Pause = Executor control | "Suspend" | — |
| "Transfer to agent" / "devret" | Grant transfer değildir | "Delegate" / "Yetki ver" | — |
| "Pending revocation" / "Revoke queued" | Kuyruklu revocation yoktur; commit yoksa revocation yok; timeout'ta istemci commit'i bilemez (HL-5) | Gönderilmiş istekte: "Not confirmed — checking" → aynı nonce'la retry/sonuç sorgusu → "Revoked", "Revoked — confirming (witness pending)" veya (nonce devam eden lineage'da, arşiv dahil, yoksa) "Not recorded — try again". "Couldn't revoke — *domain* unreachable; not recorded" yalnız bu nonce için hiçbir deneme gönderilmemişse (ilk deneme, transport bağlantısı kurulmadan, aracı yok) | Sonucun sabitlenmesi UDC; sonucun istemcide öğrenilmesi NOT GUARANTEED |
| "Your balance" (authority budget için) / "held" | Budget ≠ balance ≠ hold (E21, F9) | "Limit left" / "counted, result unknown" | — |
| "Signed in — you're all set" (yetki çağrışımıyla) | Identity ≠ Authority | "Signed in on *device*" | — |
| "Remember this decision" / "Always allow" (tek dokunuşla) | Decision ≠ Credential; implicit autonomy birikimi (Work) | "Create a delegation for similar requests…" (S1, exact preview) | — |
| "This mapping is safe / equivalent" (schema) | Etiket doğruluğu publisher trust (E10) | "Publisher declares it narrows v2; Access can't verify meaning" | NOT GUARANTEED |
| "Nothing was lost" (forced migration) | Kayıp suffix riski (E20) | "Changes after 11:02 may be lost; repeat revocations made after then" | NOT GUARANTEED (yalnız UNDER DECLARED CAPABILITY korunur) |
| "Independent approvers" | Bağımsızlık kanıtlanamaz | "Different people, different devices" | UNDER DECLARED POLICY (kontrol edilebilir şartlar) |
| "Human" rozeti agent için | Work | "AI agent · acting for *X* · operated by *Y*" | — |
| "This agent can't do X" (advisory'den) | Advisory ≠ guarantee | "Wouldn't be allowed now" | — |
| "Formally verified" / "Formel olarak doğrulanmış" (ürün veya bileşen için genel iddia) | Formel model belirli bir modelin belirli özelliklerini kanıtlar; implementasyonun tamamını değil (MD-15) | "Property *P* of model *M* is machine-checked (Lean/Kani/TLA+); see scope" | Kapsamlı ifadesi BY SEMANTICS değildir; kapsam beyanı zorunlu |
| "Tenant isolation is guaranteed by the compiler" / "Kiracı izolasyonunu derleyici garanti eder" | Tip düzeyi kapsam belirli yanlış kullanımları önler. Asıl savunma RLS + bileşik anahtar + testtir (MD-5) | "Queries without a tenant/domain scope don't compile; isolation is additionally enforced by row-level security" | UNDER DECLARED CAPABILITY |
| "Wrong password" / "This account is locked" / "No account with this email" (kimliği doğrulanmamış viewer'a) | Enumeration oracle'ı. Ayrıca kilitli hesapta "wrong password" yanlış bir iddiadır | "We couldn't sign you in with these details." + kurtarma yolu. Durum bilgisi hesabın doğrulanmış kanalına gönderilir ("If an account exists for this address, we've sent instructions") | — (açıklama kapsamı: viewer'ın authority'si kadar, E26) |
| "Trust this device" / "Remember this device" (MFA atlama için) | Device ≠ authority; "trusted" yasak terim | "Don't ask for a second step on this device for 30 days" | — |
| "Signed out everywhere" / "All access removed" (sign-out veya disable sonrası) | Sign-out identity plane oturumlarını ve o cihazlardaki bağlı insan Instance'larını bitirir (temizlik); delegation'lar kalır. Hesap devre dışı bırakmada mevcut Instance'ların daraltması `account.status` DENY overlay'iyle gelir. Offline projection'lar beyan edilmiş pencerede kalabilir | "Signed out on all devices. Apps and agents you connected keep their access until you revoke it (Acting for you). Offline passes may work until 18:00." | Oturum sonlandırma UNDER DECLARED CAPABILITY (`session_epoch` yayılması); Instance sonlandırması ve overlay commit anında BY SEMANTICS; offline NOT GUARANTEED |
| "You're all set" / "Full access restored" (kurtarma sonrası) | SEC18: yeni authenticator 24 saat CT2+ requirement'larını karşılamaz. Instance'lar yeni, Mandate'ler yeniden kurulmalı (INV-13) | "You're signed in. Your delegations remain. Some sensitive actions (e.g. payments over 1,000 TRY) will be available after 14:00 tomorrow. Your devices need to sign in again; instance limits must be set again." | SEC18: POLICY DEFAULT |
| "Account deleted — all your data is gone" | Tombstone ve saklama süreleri; audit kayıtları silinmez, redakte edilir (INV-30) | "Your account is deleted. Some records are kept until *date* for legal reasons; history entries are redacted, not removed." | Redaksiyon BY SEMANTICS (INV-30); saklama POLICY DEFAULT |
| "Email verified" / "Verified identity" | Signed ≠ true (INV-14). Doğrulama yalnız kanal kontrolüdür | "Confirmed you can receive email at a…@… (3 Oct)" | — |
| "View as user" / "Log in as" / "Impersonate" | Impersonation yoktur | "Request support access" (kullanıcının delegation'ı) / "Emergency access (break-glass)" | Model BY SEMANTICS |
| "Your passkeys will keep working" (RP ID / özel alan adı değişikliğinde) | RP ID değişince eski passkey'ler tarayıcıda sunulmaz; kullanıcı yeniden kaydolmak zorundadır | Admin uyarısı: "Changing the sign-in domain can't be undone for passkeys: users must create new passkeys." | NOT GUARANTEED (geri dönülemez) |
| Ham OAuth hata kodu kullanıcıya (`invalid_scope`, `unsupported_response_type`) | Geliştirici hatasıdır; kullanıcıya anlamsızdır | "*App* isn't set up correctly for sign-in. Reference: 7F3K-2Q (for *App*'s support)". Geçersiz `redirect_uri` veya `client_id`'de yönlendirme yapılmaz (RFC 6749 §4.1.2.1) | — (owner: client geliştiricisi) |

### 8.11 Terim çakışmaları

Ödeme dünyasında "mandate" (SEPA DD mandate, UPI mandate, AP2 mandate, recurring card mandate) Pay/scheme artifact'ıdır; Access Mandate ise bir Instance'ın exercisability zarfıdır (E21). **Karar: "mandate" kelimesi Access UI'ında hiç kullanılmaz.** Access Mandate kullanıcıya "Instance limits" olarak (yalnız uzman görünümünde) görünür. Pay UI'ı "mandate" kelimesini yalnız scheme artifact'ları için kullanır ve her birinin altında dayandığı Access delegation'ını link olarak gösterir: "SEPA mandate MR-221 · based on your delegation to *M* (≤ 500 EUR/month)". İki kayıt birleştirilmez; scheme artifact iptali ile Access revocation'ı ayrı eylemlerdir ve ekran ikisinin durumunu ayrı satırlarda gösterir.

**Diğer çakışmalar**

| Kelime | Çakışma | Karar |
|---|---|---|
| **Session** / **Oturum** | Work: ephemeral Experience session (Executor instance'ından ayrı, Work); Access: Instance | Instance için "session"/"oturum" kullanılmaz: insan Instance'ı "sign-in / giriş (cihaz)", agent Instance'ı "running copy / çalışan kopya"; "session"/"oturum" yalnız Experience oturumu |
| **Session** / **Oturum** (identity plane dahil) | Üç anlam vardır: (1) Work'ün Experience oturumu; (2) Access Instance'ı; (3) identity plane login oturumu | **Spec dili:** nitelemesiz "oturum/session" kullanılmaz. Her zaman "identity plane oturumu", "Experience oturumu" veya "Instance" yazılır. **UI:** Access yüzeylerinde "session/oturum" kelimesi hiçbir anlamda kullanılmaz. İnsan Instance'ı "Sign-in on *device*" / "*cihaz* üzerinde giriş" olarak render edilir. Identity plane oturumu ayrı bir UI nesnesi değildir, o satırın nitelikleridir. Eylemler "Sign out" / "Çıkış yap" ve "End this sign-in" olarak ayrıdır. Agent Instance'ı "Running copy" kalır. Boşta kalma ve mutlak süre authentication Claim tazeliği olarak ifade edilir. "Session" kelimesi yalnız Work yüzeylerinde ve Work anlamında kalır. Ayrıca (4) **PAM oturumu** (ayrı ürün katmanının privileged session'ı; Access yalnız açma kararı verir) ve (5) **RP uygulama oturumu** ile **upstream IdP oturumu** (dış owner'ların kayıtları) vardır; spec'te bunlar da her zaman nitelenerek yazılır. Bir identity plane oturumu cihaz başına tam olarak bir insan Instance'ına bağlanır; "Sign out" oturumu bitirir ve o Instance'ı sonlandırır (temizlik), "End this sign-in" başka cihazdaki satır için `instance.terminate`'tir |
| **Tenant / Account / Organization** | IdP anlamında "kiracı" = realm. Ticari "account" = Tenant. Kullanıcı "account" = user record. "Organization" = B2B Party | UI: user record → "Account"; Tenant → "Subscription/Billing account"; B2B Party → "Organization". "Tenant" ve "realm" son kullanıcı UI'ında kullanılmaz |
| **Grant / Authorization (OAuth)** | OAuth "authorization grant" ve "authorize" ≠ Access Grant ve ALLOW | Access UI'ında "grant" kelimesi görünmez (zaten "Delegation"). OAuth "Authorize *App*" düğmesi kullanılmaz; "Connect *App*…" + S1 exact preview kullanılır. Developer konsolunda OAuth terimleri yalnız protokol bağlamında, "OAuth grant type" gibi nitelenmiş olarak geçer |
| **Scope** | OAuth scope ≠ Access authority (L24) | Son kullanıcı UI'ında scope adları gösterilmez. Developer'da "OAuth scope" nitelenmiş yazılır |
| **Admin** | Realm/konsol yöneticisi (identity plane yüzeyi), Tenant aboneliği yöneticisi (ticari), authority yönetimi (Grant) | "Admin" bir rol etiketi değil, bir Grant'tır (IA-5). UI "Billing admin" (ticari), "Sign-in settings" (realm config, MD-14 Exercise'ı) ve "Authority admin" (S7) bölümlerini ayrı gösterir. Hiçbiri "Full access" değildir |
| **Credential** | Identity plane authenticator ↔ "Decision ≠ Credential" ilkesindeki bearer anlamı | UI "Sign-in method". Spec'te nitelemesiz "credential" identity plane authenticator'ıdır (§7.2) |
| **Token** | Identity plane token'ı ↔ Access projection'ı | Son kullanıcı UI'ında "token" yok ("Token" yalnız developer UI'ında, §8.8). Offline pass, connected account gibi render'lar kullanılır |
| **Owner** | Hukuki sahiplik (Money/domain) vs Anchor root (Access) vs Work owner/obligor | Access UI "Authority root"; "owner" kullanılmaz |
| **Principal** | Work: on-behalf-of rolü; Access'te entity değil | UI "on behalf of *X*"; "principal" kelimesi yalnız Work yüzeylerinde ve aynı anlamda |
| **Authorization** | Pay authorization (hold) vs Access ALLOW | Access UI "Allowed"; "authorized" kelimesi Pay'e bırakılır |
| **Unauthorized** | Pay "Authorized (hold)" ile yan yana çakışma | Access UI hiçbir Exercise'a/envelope'a bağlanamayan effect için "Outside authority" (TR "Yetki dışı") der; "unauthorized/authorized" Access UI'ında kullanılmaz |
| **Consent** | PSD2/OB consent (scheme artifact) vs Access contribution sınıfı | Access UI "Consent" yalnız contribution sınıfı için; scheme consent Pay UI'ında, Grant'a link ile |
| **Policy** | Work Practice policy, autonomy policy, RestrictionPolicy | Access UI "Restriction"; "policy" Work'e bırakılır |
| **Trust** | Work'te Trust = contextual Claim (Work); Access'te acceptance | Access UI "accepted source"; "trust score" hiçbir yerde (yasak) |

### 8.12 Progressive disclosure

Üç derinlik; her derinlik bir öncekinin **açıklamasıdır**, farklı bir gerçek değildir. Derinlik viewer'ın tercihi *ve* authority'si ile sınırlıdır: kişi Audit derinliğini ancak ilgili kayıtları görme authority'si varsa açar (E26).

| Öğe | Default | Expert | Audit |
|---|---|---|---|
| Kim / ne / limit / süre | ● | ● | ● |
| **Capacity** ("on your behalf" / "for their own use") | ● (her zaman; XI-10) | ● | ● |
| Provenance | Tek halka ("Given by *X*") | Tam zincir root'a kadar, delegability, depth | Zincir + her halkanın created-by Exercise'ı |
| Rule-shaped seçim | "Because HR says you're in Finance" | Kaynak, Acceptance kapsamı, beyan zamanı, freshness | Cited Claim ID'leri, Acceptance sürümü, holding başlangıcı ("since") |
| Instance limits (Mandate) | — (yalnız "Why?" içinde sonuç olarak) | ● | ● + sürüm |
| Requirements / restrictions | "Needs 1 approval" | Requirement terimleri, kısıt sınıfları | Policy sürümleri, rootTerms |
| Budget | Kalan + reset | Halka halka draw'lar | Draw/release kayıtları |
| Decision state (StateBasis) | — | "Checked at 14:02 against current state" | Okunan nesneler ve sürümleri, trusted time, replay |
| Digest / fingerprint | — | Approval'da kısa fingerprint (isteğe bağlı) | Tam digest, redaksiyon doğrulaması |
| Outcome | Status ladder | Reporter ve zaman | Attestation Claim'leri, conformance hesabı |
| Domain / provider | Yalnız çok domain'de | Domain + provider | Handover/recovery geçmişi |
| Redaksiyon | "Some details removed" | Hangi alanlar | "Redacted — fingerprint verifiable" (INV-30) |
| Giriş/oturum (S10) | Cihaz, son etkinlik, "signed in until" | Kimlik doğrulama yöntemi sınıfı, bağ (device-bound / not bound), boşta kalma ve mutlak ömür | Authentication Claim'leri, `session_epoch` olayları (sade dille), ilgili Instance Exercise'ları |
| Hesap güvenliği (S11) | Giriş yöntemleri listesi, son değişiklik | Her yöntemin eklendiği zaman ve cihaz, SEC18 soğuma durumu | Authenticator-binding Claim'leri ve zamanları |
| Destek erişimi | "Support access by *Acme Support* until 15:30" | Kapsam, PurposeRef (vaka), kalan süre, operatörün adı | Operatörün her Exercise'ı (FOR(kullanıcı)), başlangıç ve bitiş kayıtları |

Kurallar: (1) Default görünüm hiçbir zaman Expert'in çeliştiği bir şey söylemez (sadeleştirme ≠ farklı iddia). (2) Status ladder ve capacity hiçbir derinlikte gizlenmez. (3) Audit derinliği bir kopya değil, canonical kayıtların render'ıdır; export edilen SIEM projection'ı "copy — not the record" etiketi taşır.

### 8.13 Degraded-state UX

Kural (E25, EI-21): kullanıcıya gösterilen her gerçek owner'ından gelir; owner'a ulaşılamıyorsa gösterilen şey **UNKNOWN**'dur ve güvenli varsayılan (fail closed) açıkça yazılır. Access'in kendi kararı hiçbir zaman "unknown" değildir: belirsizlik DENY veya REQUIRE_ACTION'dır.

| Durum | Kullanıcıya gösterilen gerçek | Owner | Güvenli varsayılan (görünür) | Asla |
|---|---|---|---|---|
| **Access unavailable** | "Can't check authority right now (*Acme Access* unreachable)." Revoke/Delegate denemesi: istek hiç gönderilmediyse (ilk deneme, bağlantı kurulmadan, aracı yok) "Couldn't revoke — *Acme Access* unreachable; not recorded"; istek gönderildi ve cevap gelmediyse "Not confirmed — checking" ve aynı nonce'la retry (timeout kuralı aşağıda). | PEP/Work UNKNOWN raporlar; Access geri gelince karar | Online consequential effect yok; geçerli ValidityContract/offline slice içindekiler contract sonuna kadar ("POS-7 can continue offline until 18:00") | "Allowed (offline)" diye uydurmak; revoke'u "queued" göstermek |
| **Access unavailable + acil durdurma ihtiyacı** | "Authority can't be changed right now. You can still ask the runtime to pause (Work control), if it supports it." | Executor (fiziksel), Work (control) | Executor control | Access kesintisinde "agent disabled" |
| **Relay delayed** | Bildirim gecikmesi durumu (Work'te); authority değişikliğinin kendisi etkilenmez: "Revoked 14:03 — notifications delayed." | Relay (teslim), Access (commit) | Güvenlik teslimata dayanmaz (INV-24) | Teslim edilmedi diye revocation'ı "pending" göstermek |
| **Effect receipt lost** | "Allowed 14:02 · Result unknown (no report from Pay yet)." Budget: "300 TRY counted — released only if Pay reports it didn't happen." | Executor/domain (outcome); Access (draw) | Aynı nonce tekrar ALLOW almaz; yeni deneme yeni istek | "Failed" veya "Done" |
| **Executor ignores revocation** | Aftermath, horizon'dan önce: "Authority revoked 14:03. Runtime still active and hasn't confirmed pause. Steps within what was already allowed are within the declared window until 14:30 (next authority check)." Horizon'dan sonra (continuation istenmedi veya DENY'a rağmen devam): "Runtime is ignoring the revocation: any effect after 14:30, outside what was allowed, or not tied to an allowed use is outside authority." Security: containment seçenekleri yalnız ikinci durumda önerilir | Executor + Work (control durumu); Access ("authority yok"; pencere derived) | Horizon'daki continuation ve her yeni istek DENY; containment Exercise'ları | "Stopped"; Access'in fiziksel durdurduğunu ima etmek; pencere içindeki conformant executor'ı "outside authority"/"ignoring revocation" diye etiketlemek |
| **Foreign provider unreachable** | "Can't confirm Partner Co.'s authority now. Partner actions that need fresh proof are not allowed by Access until fresh proof arrives." Yerel taraf: "You can still revoke the partner bridge here (takes effect locally now)." | Foreign domain (kendi state'i); yerel Access | REQUIRE_ACTION/DENY (profile'a göre) | Foreign durumu "valid" varsaymak |
| **IdP stale** | "Your sign-in source hasn't confirmed you recently — please sign in again." Rule-shaped: "Needs refresh — not removed." | IdP / Identity plane (giriş); Access (yeniden değerlendirme) | REQUIRE_ACTION; staleness episode'u kapatmaz | Staleness'ı rol kaybı gibi göstermek |
| **Domain product unavailable** | "Commerce couldn't confirm the order is refundable right now." | Domain | Access predicate'i uydurmaz → REQUIRE_ACTION | "Not refundable" (owner söylemedi) |
| **Forced provider migration** | Admin ve etkilenen kullanıcılar: "*Acme* moved to a new provider after the old one became unreachable. Changes after 11:02 may be lost. If you revoked anything after 11:02, revoke it again." | AuthorityDomain root (recovery Exercise'ı, beyan edilen risk) | Eski provider'ın sonraki pass'ları/kararları geçersiz (fail closed) | "No data lost"; eski provider kayıtlarını güncel göstermek |
| **Work ↔ Access uyuşmazlığı** | Work: "Waiting — authority couldn't be confirmed for this step." Envanter: Access'in durumu; Work'te Commitment durumu; ikisi ayrı satır | Her biri kendi fact'i | Work, Access'in doğrulamadığı basis'le ilerlemez | Birinin durumunu diğerinden türetmek |
| **Approval: contribution var, Declaration yok** | "Approval recorded (Access); gate not updated yet (Work)." | Access / Work | Gate açık | "Approved and proceeding" |
| **Approval: render edilemiyor** | "This request can't be displayed faithfully here (unknown or unaccepted action definition). It can't be approved from this surface." | Domain Acceptance (schema) | Onay kapalı | Agent prose'uyla onay |
| **Inventory projection stale** | "As of 14:05 — couldn't refresh *domain*." | Domain | Eylemler domain'e gider; sonuç commit'ten | Stale satırı güncel gibi |
| **Offline verifier saati/profili belirsiz** | Admin: "POS-7's clock/profile report is missing; exposure window unknown beyond declared 18:00." | Verifier operatörü | Contract sonu sonrası DENY (conformant verifier) | "Offline devices are safe" |
| **Clock / future-dated statement** | "A statement from *X* is dated in the future and can't be used." | Issuer | Kullanılmaz (C33) | Sessizce yok saymak |
| **Identity plane unavailable** (authority plane erişilebilir) | "Sign-in isn't available right now. Things already allowed keep working within their limits." Yeni giriş ve step-up yapılamaz | Identity plane | Step-up gerektiren REQUIRE_ACTION'lar karşılanamaz → DENY/REQUIRE kalır. Mevcut ValidityContract'lar contract sonuna kadar geçerlidir | "Signed in" (doğrulanmadan); step-up'ı atlayarak "allowed" |
| **Upstream IdP unreachable** (federation) | "*Provider* isn't responding. Try another sign-in method if you've set one up." | Upstream IdP | Upstream'e bağlı girişler açılmaz. Hesap durumu değişmez | "Your account was removed"; başka hesaba otomatik bağlama |
| **Gelen sinyal (CAEP/SSF) gecikti veya alıcı arızalı** | Admin: "Signals from *Provider* delayed since 14:02 — decisions use declared validity windows." | Sinyal issuer'ı / alıcı | Güvenlik sinyale dayanmaz. Risk motoru veya cache arızası ALLOW'a dönmez | "No risk detected" (sinyal yokken) |
| **Hesap devre dışı, offline token/projection var** | Admin: "Sign-in disabled 14:03. Sign-in sessions ended (identity). Devices' sign-ins are blocked from 14:03 by *Acme*'s account policy. Offline passes may work until 18:00 if devices follow their profile. Agents' delegations from this person are listed below." | Identity plane (hesap); Access (overlay, pencere derived) | Yeni giriş ve token yok. Mevcut Instance'lar `account.status` Claim'inin ingest'inden itibaren domain'in varsayılan DENY overlay'iyle DENY (`restricted`) alır. Offline pencere sonrası DENY | "Revoked everywhere instantly"; "all access removed" |
| **Kurtarma sonrası soğuma** | "You're signed in. Some sensitive actions will be available after 14:00 tomorrow." Eylem anında: "Needs: a sign-in method added more than 24 h ago (available 14:00 tomorrow)" | Access (SEC18 policy), identity plane (binding zamanı) | CT2+ requirement'ları REQUIRE_ACTION. SEC18'i gevşetmek CT3 genişletmesidir (SI-18) | "All set"; soğumayı gizleyip DENY'ı açıklamasız bırakmak |
| **Identity plane access token süresi doldu, yenileme başarısız** | App: "Please sign in again to continue." | Identity plane | Yeniden giriş; authority kararları etkilenmez | Kullanıcının "logged out by Access because of a risk" gibi doğrulanmamış neden söylemesi |

**Timeout kuralı (Revoke/Delegate ve diğer authority-changing istekler).** Timeout'ta istemci commit'in olup olmadığını bilemez (HL-5). Bu yüzden:

| Adım | Davranış |
|---|---|
| 1 | UI "**Not confirmed — checking**" gösterir; başarı da başarısızlık da iddia edilmez. |
| 2 | İstemci aynı nonce'la retry eder (TI-8). Commit edebilen retry yalnız AIS'in intent validity penceresi içindedir; etkileşimli revoke kısa validity seçer (değer ENGINEERING ASSUMPTION; ≤ intent validity tavanı, POLICY DEFAULT, §13.7.3). |
| 3 | Pencereden sonra aynı-nonce isteği yalnız sonuç sorgusudur; kuyruklu revoke oluşmaz. |
| 4 | Sonuç: "Revoked", "Revoked — confirming (witness pending)" veya — yalnız nonce devam eden lineage'da (arşiv dahil) yoksa — "Not recorded — try again". |
| 5 | Aracılı yolda (ör. istemci adına Suiss Experience backend'i) veya daha önce gönderilmiş bir denemenin retry'ında "Couldn't revoke … not recorded" kısayolu kullanılmaz; adım 1–4 uygulanır. |

Sınıflar: sonucun sabitlenmesi UDC; sonucun istemcide öğrenilmesi NOT GUARANTEED (§13.4).

### 8.14 Frozen experience decisions (X1–X31)

- **X1** Mental model. Access kullanıcıya "kaynaktan doğan, yalnız daralarak verilen ve her kullanımı kaydedilen yetki zinciri" olarak sunulur; verilen yetki görülür, daraltılır ve geri alınır; geri alma ileriye dönüktür ve durdurma değildir; iş, para, kimlik ve effect sahiplerinin ağzından söylenir.
- **X2** One model, five lenses. Principal, approver, admin, developer ve auditor için ayrı mental model yoktur; aynı model farklı kesit ve derinlikte gösterilir; terimler mercekler arasında değişmez.
- **X3** Surface set. Access kaynaklı yüzeyler S1–S11'dir; her biri tanımlı soruyu, kullanıcıyı, canonical kaynağı ve "asla" listesini taşır. Approval Surface Access'in değil, Work Approval Contract + Access contribution şartlarının ortak conformant yüzeyidir. S10 identity plane oturum render'ını da kapsar; S11 Account & sign-in methods yüzeyidir. Hosted giriş yüzeyleri (§12 TN-G1) identity plane yüzeyleridir ve §8.8–§8.13'e tabidir.
- **X4** Information architecture. Tek Suiss kabuğu; Work'ün Needs Attention/Briefing/Live yüzeyleri günlük ev; Access bir Authority hub, yetkiye göre görünen Admin/Developer/Audit bölümleri ve her yerde açılan gömülü bileşenlerdir (S1, S3, S5, status ladder, step-up). Ürün sınırı owner rozetinde görünür; içerik kopyalanmaz, referansla bağlanır. "Tek Suiss kabuğu" first-party Suiss hesapları ve Suiss Experience yüzeyleri içindir: tek kabuk, tek RP. Müşteri realm'lerinin hosted giriş ve hesap yüzeyleri realm'in kendi (alt) alan adında ve kendi markasıyla sunulur. Suiss kabuğu müşteri realm'ine dayatılmaz. Sözlük ve forbidden-claims kuralları iki durumda da aynıdır.
- **X5** Access has no request queue. İnsan eylemi gerektiren her authority talebi coordinator'ın dikkat yüzeyine (Suiss'te Work Gate/Condition → Needs Attention; third-party'de compatible coordinator) girer. Authority hub'ında "Requests" yoktur; "Changes" yalnız bilgidir. Governance quorum'ları da Work Gate veya IGA ile koordine edilir.
- **X6** Cross-product authority görünürlüğü = Authority hub ("Acting for you", "Shared from you", "Your authority"; cross-domain, owner ve freshness etiketli; One ve first-party ürünler ayrıcalıksız) + Needs Attention (bekleyen contribution'lar). İkisi referansla bağlanır. "Shared from you", viewer'ın holding'inden/root'undan türeyen ve agency'si FOR(viewer) olmayan her Grant'tır (OWN ve FOR(P ≠ viewer)), capacity etiketiyle; viewer'ın verdiği her Grant en az bir grupta görünür ve iki adımda iptal edilebilir.
- **X7** Approval = one ceremony, two records. Trusted Approval Surface'te tek kullanıcı eylemi önce Access contribution Exercise'ını, sonra onu cite eden Work Declaration'ını üretir; iki kayıt ayrı durum satırlarında gösterilir; kısmi başarısızlık dürüstçe yazılır; Decline yalnız Work Declaration'ıdır. Tek eylemin iki kaydı yetkilendirme biçimi Protocol'dedir.
- **X8** Approve ≠ Give access ≠ Allowed. "Approve" yalnız contribution; "Give access…/Delegate" yalnız grant.issue/amend (commit etiketi "Delegation created"); "Allowed" yalnız Access'in ALLOW DecisionRecord'u. "Give access once" = count=1, parametreleri sabit, kısa süreli Grant; altında ne verildiği ve kullanım vaat edilmediği yazılır ("Gives Agent A authority for one use with exactly these details, until 15:30. Access will still check the request."). Seçenekler DENY'ın reason class kümesinden ve her engelin zincirdeki seviyesinden hesaplanır: viewer'ın seviyesinde veya üstündeki her engel (sınıfı ne olursa olsun, ör. viewer'ın kendi tükenmiş budget'ı) viewer'ın çözemediği engeldir; böyle bir engel kalıyorsa tek seferlik seçenek ya sunulmaz ya da "Would still be blocked by: …" satırıyla sunulur. Authority eksikken "Approve" sunulmaz; hiçbir yüzey "Approve anyway" sunmaz.
- **X9** Three entries, one confirmation. Template, NL ve hassas editör yalnız taslak üretir; kayda giren tek şey exact typed preview'den sonra yapılan Exercise'tır. NL'den Grant'a geçişte exact preview zorunludur ve yorum farkları ayrı satırlarda gösterilir; kayda cümle değil typed içerik girer. One veya bir agent taslak hazırlayabilir; trusted sheet yalnız kullanıcının başlattığı bağlamda (kendi navigasyonu, One'a kendi komutu, kendi tıkladığı "Connect") doğrudan açılır; requester inisiyatifli talep coordinator'a typed authority request olarak gider ve yalnız Needs Attention item'ından açılır.
- **X10** Delegation defaults. Yeniden delege etme varsayılan kapalı; capacity seçimi zorunlu ve kullanıcının kendi agency'sinden türetilir; agent'a verilen delegation'da bitiş zorunlu alandır ("until you revoke" yalnız explicit seçim, "forever" asla); preview "Not included" bloğunu (protected ve gelecekteki action'lar) daima gösterir. Bunlar ürün varsayılanıdır, ontology kuralı değildir.
- **X11** Asymmetric friction. Genişleten eylemler trusted surface'te, exact preview ve gereken assurance ile; daraltan eylemler kullanıcının herhangi bir authenticated yüzeyinden en kısa yolla yapılır.
- **X12** Revoke = impact preview + honest aftermath. Revoke öncesi derived impact (cascade, instance kullanımı, açık reusable Decision'ların ValidityContract pencereleri, offline pass'lar, değişmeyenler); sonrası owner'lı aftermath satırları (Access — açık pencere dahil, Executor, verifier, Relay, history) gösterilir. Açık ValidityContract/projection varken "can't use this" yazılmaz; pencere içi envelope içi kullanım "within the declared window"dır, "outside authority" değildir. Preview başka owner'ın fact'ini beyan etmez (Work satırı: "Work shows their status").
- **X13** Suspend, not pause. Access'in geri alınabilir daraltması "Suspend"dir ve yalnız viewer restriction koyma yetkisine sahipse sunulur; "Pause/Cancel/Take control" Work/Executor'ındır. Ortak "Stop" etkileşimi iki fact'i ayrı satırlarda gösterir.
- **X14** Honest status ladder, no optimistic UI. §8.7 basamakları her yüzeyde aynıdır ve birleştirilmez; authority değiştiren eylemler commit'ten önce "submitted"dır. Derived okuma cevapları `witnessed_through` taşır; witness/replica-before-ack sınıfındaki (revocation sınıfı, CT3) bir kayıt `witnessed_through` değerinin ötesindeyse "Revoked — confirming (witness pending)" gösterilir ve nitelik ack ile kalkar; diğer sınıflarda ladder değişmez.
- **X15** Budget display. Effective remaining (zincirin en darı), sonucu bilinmeyen draw'ların "counted" olarak ayrılması, reset zamanı ve tükenme seçenekleri gösterilir; "balance/held" kullanılmaz; tükenme onayla aşılmaz.
- **X16** Rule-shaped explanation. Authority yolu + seçim beyanı; stale ("needs refresh") ve removed ayrı durumlardır; yeniden katılımda eski türevlerin geri gelmediği açıkça söylenir; intensional rolde "Leave" yerine "Turn off for me" sunulur.
- **X17** Offline honesty. POS/edge ve long-running yüzeyleri offline pencereyi, offline limiti ve sonraki kontrol zamanını gösterir; revocation exposure "en geç T — beyan edilen profile uyulursa" koşuluyla yazılır. Aynı semantik online reusable Decision'lara (long-running executor, intermittent projection) da uygulanır: "may continue steps already allowed until 14:30 (next authority check), if its runtime follows its declared contract" (UNDER DECLARED CAPABILITY).
- **X18** Explanation model. Why / why not / what is needed; derived; past vs hypothetical etiketli; her "hayır" owner'ıyla; viewer'ın authority'si kadar; Default/Expert/Audit derinlikleri.
- **X19** Agent-facing contract. Outcome + reason class'lar (kapalı on sınıflık kümeden; DENY başarısız olan tüm sınıfları döner, tekil değil) + unmet terms + typed remediation; capacity beyanı zorunlu; DENY nonce'u terminal; prose approval değildir; açıklama talimat değildir; insan-gerektiren requirement not-satisfiable-by-actor olarak döner.
- **X20** Admin experience. Rol sürümleme ve change-impact preview; "Full access" yok; Acceptance ekranı use'u sade dille ve blast radius'uyla gösterir; reserved değişiklikler quorum Gate'iyle koordine edilir; offboarding her kanal için explicit seçim ister; impersonation yok; toplu işlemler attributable Exercise kümeleridir. "Impersonation yok" kuralının modeli §8.16 ve E37'dedir: destek erişimi kullanıcının Grant'ı veya reserved break-glass Grant'ıdır. Destek erişiminin 12 değişmezi (§8.16) POLICY DEFAULT'tur. Devredilmiş yönetimin CVE dersleri (hiyerarşi taşıma, rol atama, mapper yükseltme) §12 TN-Y2'dedir.
- **X21** Developer experience. Publisher yayınlar, domain kabul eder (console kabul düğmesi sunmaz); PEP SDK actor-instance proof'u ile kurulur, fail-open yoktur; decision lab advisory (söz değil) + replay + conformance; sandbox ayrı AuthorityDomain'dir.
- **X22** Audit views. Audit yüzeyleri canonical kayıtların render'ıdır: provenance, capacity, StateBasis, cited proofs, replay, redaksiyon doğrulaması; SIEM export'u "copy — not the record" etiketi taşır.
- **X23** Attention model. §8.6 tablosu bağlayıcıdır: autonomy içi ALLOW, expiry, Commitment-scoped bitiş, kabul edilmiş kaynaktan seçim değişikliği ve teslim otomatiktir; genişletme, kabul, yenileme, rol geçişi, disposition ve approval asla otomatik değildir; insan dikkati yalnız coordinator'ın consequence-ranked yüzeyinden girer; requester aciliyet beyan edemez; sessizlik onay değildir.
- **X24** Vocabulary. §8.8 eşlemesi, §8.9 yasak terimler ve §8.10 forbidden claims bağlayıcıdır; "mandate" Access UI'ında kullanılmaz.
- **X25** Progressive disclosure. §8.12 tablosu bağlayıcıdır; capacity ve status ladder hiçbir derinlikte gizlenmez; Default Expert'le çelişmez.
- **X26** Degraded-state UX. §8.13 tablosu bağlayıcıdır; her arızada owner, UNKNOWN ve güvenli varsayılan görünür. Authority değiştiren bir istekte timeout'ta "Not confirmed — checking" gösterilir ve aynı nonce'la retry yapılır; sonuç "Revoked", "Revoked — confirming (witness pending)" veya — yalnız nonce devam eden lineage'da (arşiv dahil) yoksa — "Not recorded — try again" olarak yazılır (§8.13 timeout kuralı). "Couldn't revoke — *domain* unreachable; not recorded" yalnız bu nonce için hiçbir deneme gönderilmemişse (ilk deneme, transport bağlantısı kurulmadan, aracı yok) yazılır. Kuyruklu veya pending authority değişikliği gösterilmez.
- **X27** Best-of-breed adaptations. JIT istek, exact preview, tek envanter, dynamic linking ve change-impact ADOPT/ADAPT; scope listeleri, süper roller, örtük auto-approve ve activity-feed-as-attention REJECT.
- **X28** Embedded authority surfaces are renderers. Pay limit ekranı, Commerce/Serve personel ekranları, POS, One sohbeti ve third-party uygulamalar Access verisini render eder ve Access'e Exercise talebi gönderir; kopya tutmaz, karar vermez; aynı sözleşme third-party yüzeyler için de geçerlidir.
- **X29** Identity honesty. Sign-in yüzeyleri yetki iddia etmez; step-up hangi exact eylem için olduğunu söyler ve yetki vermez; recovery mesajları Instance ve Party recovery'sini ayırır ("Your delegations remain; your devices need to sign in again; instance limits must be set again"). Kural identity plane'in bütün mesajlarına uzanır: giriş, hata, kurtarma, hesap durumu, sign-out ve destek mesajları da yetki iddia etmez. Kimliği doğrulanmamış viewer'a hesap durumu ifşa etmez (X34). Kurtarma mesajı SEC18 soğumasını açıkça yazar (X38).
- **X30** End-customer experience. Merchant agent'ı her zaman "AI agent · acting for *M*" olarak görünür; müşterinin authority'si yalnız trusted ödeme/izin yüzeyinde exact intent ile kullanılır; tek seferlik ve kalıcı (merchant'a Grant) ayrı fiil ve preview'lerle sunulur; kalıcı merchant yetkileri görülebilir ve iptal edilebilir; agent cümlesi effect gerçeği sayılmaz.
- **X31** Default visibility. Bir Party varsayılan olarak (a) kendi holding'lerini, (b) verdiği Grant'ları (capacity'si ne olursa olsun; tamlık kuralı) ve onların alt ağacını, (c) FOR(kendisi) capacity'siyle veya kendi verdiği Grant'lar üzerinden yapılmış kullanımları görür; ötesi explicit authority gerektirir. Bu bir ürün varsayılanıdır; daha sıkı varsayılanlar Security'de belirlenebilir.

### 8.15 Identity plane ürün dili ve giriş UX kuralları

**Kapsam.** Bu alt bölüm identity plane yüzeylerinin (hosted giriş, S10, S11, hata ve kurtarma ekranları, login push, yönetici konsolu, destek banner'ı) **dil ve dürüstlük kurallarını** verir. Akışların mekanizması, eşikleri ve platform ayrıntıları §12'dedir (TN-G1 giriş akışları, TN-G2 markalama, TN-G3 erişilebilirlik ve yerelleştirme, TN-H1–TN-H8 hesap yaşam döngüsü, TN-O1–TN-O4 oturum ve sinyaller). Satırlar orada tekrar normatifleştirilmez, buradan atıfla bağlanır.

**İlke.** Giriş UX ürün kuralları ile §8'in dürüstlük kuralları çoğunlukla aynı yöne bakar. İkisi de kullanıcıyı yanlış güvene ve kimlik avına alıştırmamayı hedefler. Gerilim taşıyan üç yer vardır:
- (a) **Sızdırmama ↔ dürüst durum:** enumeration direnci ile E25/XI-1'in "owner'ı ve UNKNOWN'u göster" kuralı.
- (b) **Hatırlama ↔ "remember" yasağı:** "beni hatırla" ile §8.10'daki "Remember this decision" yasağı.
- (c) **Tek kabuk ↔ kiracı markası:** X4 ile kiracı başı özel alan adı ve marka kuralı.

Çözümlerin hepsi mevcut bir Access ilkesinden türetilir. Yeni primitive yoktur.

#### 8.15.1 Giriş UX kuralları ve çözümleri

> Bu tablonun satır etiketleri X-L1…X-L18'dir; landscape kararları L1–L28 ile karışmaz. Tablodaki "§8.17.8.1 E-n" atıfları açıklama ilkeleridir, ecosystem kararları E1–E40 değildir.

| # | Giriş UX kuralı | Dürüstlük kuralı (§8) | Gerilim | Çözüm (bağlayıcı) | Gerekçe |
|---|---|---|---|---|---|
| X-L1 | Tanımlayıcı adımında sabit çıktı: aynı HTTP kodu, gövde boyutu, gecikme. Kilitli/devre dışı dahil tek mesaj | E25/XI-1: gösterilen her gerçek owner'ından gelir, owner yoksa UNKNOWN. §8.13: degraded durum dürüstçe yazılır | Var (görünüşte). Tek mesaj durumu gizler. Keycloak'ın "invalid username or password" mesajı kilitli hesapta yanlış bir iddiadır | **X34.** Kimliği doğrulanmamış viewer'ın hesap varlığını veya durumunu öğrenme authority'si yoktur. Açıklama viewer'ın authority'si kadardır (E26, §8.17.8.1 E-4 ilkesinin identity plane'e uzanması). Bu yüzden tek mesaj dürüstlük ihlali değildir. **Ama mesaj yanlış bir iddia taşıyamaz:** "Wrong password", "No account" ve "Account locked" yasaktır. İzinli biçim nötrdür: "We couldn't sign you in with these details." Durumun kendisi hesabın doğrulanmış kanalına iletilir ("If an account exists for this address, we've sent instructions"). Kimliği doğrulandıktan sonra tam dürüstlük geçerlidir | Access'in "UI wording never exceeds its guarantee class" (XI-12) ve "explanation scoped by authority" (XI-9) ilkeleri. OWASP sızıntı kanıtı |
| X-L2 | "Beni hatırla" iki katmanlı: boşta kalma + mutlak ömür + olay tabanlı iptal | §8.10: "Remember this decision" / "Always allow" yasak (Decision ≠ Credential) | Var (kelime düzeyinde) | **X33.** "Keep me signed in on this device" yalnız identity plane oturum ömrüdür ve izinlidir. Hiçbir authority kararını hatırlamaz. "Remember this decision" ve "Always allow" yasağı aynen kalır. "Remember/Trust this device" (MFA atlama) yerine nötr süre ifadesi kullanılır: "Don't ask for a second step on this device for 30 days" | Identity ≠ Authority. "trusted" yasak terimdir (§8.10) |
| X-L3 | Agresif yeniden doğrulamadan kaçın; sık istem kimlik avına alıştırır | Step-up RequirementTerm'den gelir; exact eylemi söyler (X29) | Yok (tamamlayıcı) | Yeniden doğrulama istemi yalnız iki kaynaktan gelir: (i) bir RequirementTerm (authority plane), (ii) identity plane oturum politikası olayı. Her istem nedenini ve hangi eylem için olduğunu söyler ("Confirm it's you to send 3,000 TRY to Ayşe K."). Genel "Re-enter your password" yasaktır (§8.5, §8.17.5.4) | Microsoft'un belgelediği risk + CIBA binding_message dersi |
| X-L4 | RFC 9470 step-up ekranı nedenini açıklamalı | X29 | Yok | Aynı kural. `acr_values` tavsiye, `max_age` zorunludur → §12 TN-O3 | — |
| X-L5 | Gömülü bileşenler (varsayılan) ve barındırılan sayfalar birlikte sunulur (TN-133); platformun kendi giriş sayfası ve gömülü bileşenler kiracının istemcisiyle aynı düğüm sözleşmesini kullanır; üçüncü taraf izni, CT3 onayları ve yönetim konsolu her zaman barındırılandır | X4 tek Suiss kabuğu; XI-18 first-party ayrıcalık yok | Kısmi | **X40.** First-party Suiss hesapları: tek kabuk, tek RP. Müşteri realm'leri: gömülü bileşenler veya realm'in (alt) alan adında hosted giriş, realm markasıyla. Suiss'in kendi hosted girişi de aynı düğüm sözleşmesinin tüketicisidir. Bu, XI-18/E24'ün identity plane karşılığıdır | — |
| X-L6 | Kiracı markalaması betiksiz şablon + CSP; kiracı metin ezmesi | §8.8 sözlük ve §8.10 forbidden claims bağlayıcıdır (X24) | Var: kiracı metin ezmesi yasak ifade sokabilir ("Trusted device", "Account locked") | **X35.** Mesaj anahtarları iki sınıftır. **Korunan anahtarlar** kiracı tarafından ezilemez; çevirileri canonical anahtardan üretilir ve forbidden-claims denetiminden geçer. Bunlar: enumeration'a duyarlı mesajlar, guarantee taşıyan mesajlar (sign-out, disable, recovery, revoke, step-up nedeni), owner atıfları. **Serbest anahtarlar:** ton, marka, yardım metni. Çeviri denetimi §8.10 tablosunun makine-okunur hâlini kullanır (UNDER DECLARED CAPABILITY) | XI-12, XI-13; şablon kaynaklı RCE/XSS kanıtı |
| X-L7 | Login push'ta sayı eşleştirme zorunlu; aynı cihaz istisnası | Bildirim içi authority onayı yalnız CT1 + H(AAS); yüksek sonuçlu onay bildirimden yapılamaz (§13.7.3, §8.17.6.3) | Yok (farklı nesneler) | Login push identity plane ceremony'sidir ve authority onayı değildir. Metni: "Sign-in request to *Acme* from *browser, city?*. Enter the number shown." Authority onayının bildirim içi yapılması ayrı kuraldır. İkisi aynı bildirim şablonunu paylaşmaz | — |
| X-L8 | OAuth hataları: geçersiz `redirect_uri`/`client_id`'de yönlendirme yok; geliştirici hatasında korelasyon kimlikli nazik mesaj | §8.17.8.1 E-3 / E25: her "hayır"ın owner'ı vardır | Yok | Hata ekranı owner'ı adlandırır: "*App* isn't set up correctly for sign-in (the app's developer can fix this). Reference: …". Kullanıcının kendi kararı (`access_denied`) "You chose not to continue" olarak yazılır. Geçici arıza (`temporarily_unavailable`) §8.13 identity plane satırına bağlanır | RFC 6749 §4.1.2.1 |
| X-L9 | Kurtarma sonrası GRACE → "tam oturum" | X29 recovery mesajları; SEC18; INV-13 | Görünüşte | **X38.** Giriş identity plane kurtarma akışına göre açılır. Authority tarafında Party Grant'ları kalır, Instance yenilenir, Mandate yeniden bağlanır, CT2+ requirement'ları 24 saat bekler. Mesaj bunların hepsini söyler. "Full access restored" yasaktır | — |
| X-L10 | Devre dışı bırakma tek işlemde: durum, oturumlar, refresh ve çevrimdışı token'lar | E29; §8.10 "Revoked everywhere instantly" yasak | Var | Identity plane kayıtları tek işlemde değişir. UI offline pencereyi ayrıca yazar (§8.13 satırı). "Offline tokens revoked" yazılmaz | — |
| X-L11 | Silme: tombstone, SCIM 404 | INV-30 redaksiyon; XI-21 geçmiş yeniden yazılmaz | Yok | Silme mesajı saklama ve redaksiyonu söyler (§8.10 satırı). Silinmiş hesap kimliği doğrulanmamış viewer'a "var olmayan hesap"tan ayırt edilemez (X34 ile tutarlı) | — |
| X-L12 | Kiracı özel alan adı passkey'den önce; RP ID geri dönülemez | X4; T31 "WebAuthn RP" | Kısmi | Admin ekranı RP ID / alan adı değişikliğini "geri dönülemez" olarak işaretler ve sonucu yazar (§8.10 satırı). Mekanizma §12 TN-K2'dedir | §12 |
| X-L13 | Ev alanı keşfi kapalı; `domain_hint` politikayı ezmez; hedef kiracı kullanıcıya onaylatılır | E26; XI-17 (agent/ürün kimliği görünür) | Yok | Giriş sayfası hedef organizasyonu açıkça yazar: "You're signing in to *Acme* (acme.example)". İpucu parametreleri bu satırı değiştirmez | §12 TN-G1 |
| X-L14 | Erişilebilirlik: WCAG 2.2 AA, yapıştırma ve otomatik doldurma serbest, CAPTCHA yerine etkileşimsiz bot savunması, ekran okuyucu duyuruları | Status ladder ve owner rozetleri (§8.7, XI-1, XI-2) | Yok (tamamlayıcı) | **X39.** Dürüstlük taşıyan her öğenin metin karşılığı vardır ve ekran okuyucuya okunur. Bunlar: status ladder basamağı, owner rozeti, "confirming (witness pending)", UNKNOWN, offline pencere, SEC18 soğuması. Yalnız renk veya ikonla durum gösterilmez | §12 TN-G3 |
| X-L15 | Yerelleştirme: çok kademeli yedek zinciri, kiracı metin ezmesi, RTL baştan | §8.8 EN/TR eşlemesi canonical | Kısmi | **X39.** Çeviriler canonical terim anahtarından üretilir, serbest çeviri yapılmaz. Bir dilde "bir canonical kavram → bir UI terimi" kuralı korunur. Yeni dil eklemek §8.8'e o dilin sütununu eklemektir. Korunan anahtarlar (X35) her dilde korunur. RTL baştandır → §12 TN-G3 | — |
| X-L16 | IdP dilinde "oturum" = login oturumu | §8.11: "oturum" yalnız Experience oturumu | Var | **X33** ve §8.11 "Session / Oturum (identity plane dahil)" satırı | — |
| X-L17 | Kimliğe bürünme "ayrı ve açık kapsam" ↔ "hiç uygulanmayacak, yalnız devretme" | X20 "impersonation yok" | Var: iki kural birbirini dışlar | **X37** ve §8.16 (MD-9) | MD-9 |
| X-L18 | Yasak ifadeler: "formel olarak doğrulanmış", "kiracı izolasyonunu derleyici garanti eder" | §8.10, B15 | Yok | §8.10'da yasak ifade satırlarıdır | — |

#### 8.15.2 Identity plane mesaj sınıfları ve owner'ları

| Mesaj sınıfı | Owner (E25) | Kimliği doğrulanmamış viewer'a | Kimliği doğrulanmış viewer'a | Yasak |
|---|---|---|---|---|
| Kimlik doğrulama başarısız | Identity plane | Nötr tek mesaj (X34) | Neden: "That passkey isn't registered for this account" | Hesap varlığını ima eden her şey |
| Hesap kilitli / devre dışı / silinmiş | Identity plane (kilit), realm admin (disable) | Nötr tek mesaj; ayrıntı doğrulanmış kanala | "Your account's sign-in is turned off by *Acme*. Contact: …" | "Locked" (pre-auth) |
| Step-up | Access (requirement) + identity plane (ceremony) | — | Exact eylem + neden (X29, X-L3) | "Re-enter your password" (bağlamsız) |
| Sign-out / oturum sonu | Identity plane | — | Hangi oturumlar bitti; delegation'ların sürdüğü (X36) | "All access removed" |
| Kurtarma | Identity plane (giriş), Access (SEC18, INV-13) | Nötr ("If an account exists…") | X38 mesajı | "Full access restored" |
| OAuth / federation hatası | Client geliştiricisi veya upstream IdP | Owner atıflı nazik mesaj + referans (X-L8) | Aynı | Ham hata kodu |
| Yeni cihaz / yeni yöntem bildirimi | Identity plane (Relay ile teslim) | — | "If this wasn't you: Secure your account" | "Action required" etiketi (§8.6 kuralı) |
| Destek erişimi | Access (Grant) | — | §8.16 metinleri | "Impersonation", "View as" |

### 8.16 Destek erişimi deneyimi (MD-9)

**Model.**
- Kimliğe bürünme (impersonation, "log in as", "view as user") yoktur (X20, §8.17.9.8).
- Destek erişimi iki yoldan biriyle kurulur:
  - (a) Kullanıcının kendi Grant Exercise'ı: kullanıcı destek operatörüne süreli, dar bir delegation verir. Delegation iptal edilebilir ve kaskad eder.
  - (b) Reserved break-glass Grant'ı (INV-28): önceden verilmiş, requirement'lı, zaman sınırlı. Hesap kaynaklarında break-glass yalnız kullanıcının self-anchor rootTerms'ünde admission sırasında (E6) beyan edilmiş reserved istisnai Grant olarak vardır (CI-13, INV-28).
- Destek erişiminin hedefi, identity plane hesap kaynakları üzerindeki `idp.account.*` domain action'larıdır (E34). Kaynakların root'u kullanıcının self-anchor'ıdır (`scope = Party(P)`, §7.9.2.3). Grant'ın holder'ı destek operatörü Party'si (veya destek ekibinin rule-shaped seçicisi) olur; operatör kendi Instance'ından exercise eder.
- Operatör kendi Instance'ıyla, FOR(kullanıcı) capacity'siyle hareket eder. Her Exercise'ın actor'ü operatördür (C12, PI-7).
- `OrgPolicy` yolu yalnız organizasyonun kendi kaynaklarında geçerlidir. Organizasyonun oradaki authority'si kendi Grant'ıdır. Kullanıcının kişisel kaynaklarına bu yoldan girilmez.
- Serbest metin gerekçe destek vakasında veya Work'te kalır. Authority taşıyan alan typed PurposeRef'tir (vaka referansı). PurposeRef'te serbest metin yoktur.

**Destek erişiminin 12 değişmezi.** Statü ve guarantee satır satır aşağıdadır. MD-9'daki "PD" ifadesi şablon değerleri için okunur. #1, #2, #6, #10, #11 modelden gelir. §12.3.4 TN-71 aynı statü ve guarantee'yi gösterir.

| # | Değişmez | Access karşılığı | Statü / guarantee |
|---|---|---|---|
| 1 | Token daima özneyi ve eylemde bulunanı taşır; impersonation modu yok | Identity plane projection'ı `act` taşır (operatör) ve `sub` (kullanıcı). `act` bir projection ipucudur; lineage kayıtlardadır (L22). Impersonation modu yoktur | Model BY SEMANTICS; `act`'in aşağı akışta doğru okunması NOT GUARANTEED (dış RS) |
| 2 | Ayrıcalık kesişimi; operatörün admin hakları askıda | Destek Grant'ı ⊆ kullanıcının holding'i (INV-3). Her Exercise tek basis ve tek capacity adlandırır (C12). Operatörün kendi OWN authority'si bu Exercise'larda basis olamaz | BY SEMANTICS |
| 3 | Yasak işlem listesi motor seviyesinde | Yasak liste = `idp.account.*` namespace'inde reserved bayraklı action'lar (INV-9, E34). Destek şablonu bunları adlandıramaz; destek sınıfı Grant'lara RestrictionPolicy uygulanır. Liste: credential/MFA değişimi, birincil e-posta/telefon, hesap silme, ödeme, toplu export, rol yükseltme, davet, yeni API anahtarı veya uzun ömürlü token | Reserved bayrağı BY SEMANTICS (wildcard ile kapsanamaz, E11). Şablonda dışlama PD. Yasaklayan RestrictionPolicy UNDER DECLARED POLICY |
| 4 | Gerekçe boş olamaz | PurposeRef zorunlu (typed vaka referansı). Serbest metin vaka sisteminde | PD (şablon zorunluluğu); PurposeRef'in typed alan olması TN-73 FROZEN |
| 5 | Mutlak tavan 60 dk; uzatma yeni rıza | Validity ≤ 60 dk. Uzatma genişletmedir ve yeni Grant Exercise'ı ister (X10, §8.17.7.7) | PD (≤ 60 dk); "uzatma = genişletme" BY SEMANTICS |
| 6 | Başlangıç, bitiş ve eylem başına denetim; operatöre atıf | Grant issue/expiry/revoke ve her Exercise kayıtlıdır; actor operatörün Instance'ıdır | BY SEMANTICS |
| 7 | Özneye bildirim zorunlu | SI-21: kendisi hakkındaki genişletme Changes'ta görünür ve Relay ile iletilir. PD: anlık teslim açık | Destek Grant'ının verilmesinin (genişletme) görünürlüğü BY SEMANTICS (SI-21). Break-glass **kullanımı** meta-Exercise değildir: kullanım kaydı BY SEMANTICS (Exercise kaydı); özneye görünürlüğü break-glass şablonunun zorunlu `notify-subject` requirement'ıyla UNDER DECLARED POLICY. Teslim NOT GUARANTEED (N-2) |
| 8 | Kullanıcı kendisine bürünülmesini yasaklayabilir | Rıza yolunda varsayılan "yok"tur: Grant verilmezse erişim yoktur. Kullanıcının self-restriction'ı destek Grant'ını daraltır (kaldırma kendi Exercise'ı). Break-glass yolu yalnız self-anchor rootTerms'ünde admission'da beyan edilmiş reserved istisnai Grant olarak vardır; self-restriction'a karşı muafiyeti ancak o policy'de beyanlıysa geçerlidir (§12 row 91), beyan yoksa self-restriction break-glass'ı da daraltır. Her kullanımı Exercise kaydıdır. Özneye bildirimi `notify-subject` requirement'ıyladır | Rıza yolu BY SEMANTICS; self-restriction PD; break-glass muafiyeti UNDER DECLARED POLICY; kullanım kaydı BY SEMANTICS; bildirim UNDER DECLARED POLICY, teslim NOT GUARANTEED |
| 9 | Özyinelemeli devretme yasak; derinlik 1 | Destek Grant'ında DelegationTerms "Can pass on: No" sabittir (depth 0) | PD (şablon); DelegationTerms'ün uygulanması BY SEMANTICS |
| 10 | `may_act` iddiası veya organizasyon politikası yoksa red | Grant yoksa DENY (`no-covering-authority`) | BY SEMANTICS |
| 11 | Devredilmiş oturum öznenin oturumlarını etkilemez; iptal ayrı yayılır | Operatörün Instance'ı kullanıcının Instance'larından ayrıdır. Destek Grant'ının revoke'u kullanıcının identity plane oturumlarına ve Instance'larına dokunmaz | BY SEMANTICS |
| 12 | Destek artefaktları ayrı ayrıcalık sınıfı; token içerenler otomatik redakte | Redaksiyon profili (INV-30 mekanizması); token içeren artefaktlar identity plane'de otomatik redakte edilir | Otomatik tespit ve redaksiyon PD; UNDER DECLARED CAPABILITY. Redakte edilmiş kaydın digest doğrulanabilirliği BY SEMANTICS (INV-30), ayrı bir garanti |

**Deneyim.**

| An | Kullanıcının gördüğü | Operatörün gördüğü | Owner | Asla |
|---|---|---|---|---|
| Talep | Needs Attention item'ı (coordinator) veya destek akışında kullanıcının kendi başlattığı S1: "Give *Acme Support* access: view your account settings · case #4411 · for 60 minutes · can't change sign-in methods, payments or email · can't pass on" | "Waiting for Ayşe K. to give support access (case #4411)" | Access (S1), coordinator (item) | Operatörün trusted sheet'i kendi inisiyatifiyle açması (XI-7); "Approve" fiili (bu bir delegation'dır: "Give access") |
| Aktif | S2 ▸ Acting for you: "*Acme Support* (Mehmet Y.) · support access · until 15:30 · Revoke". Anlık bildirim (SI-21) | Kalıcı banner: "Acting for Ayşe K. with her support access (case #4411) · read-only · ends 15:30 · every action is recorded under your name" | Access | Banner'sız destek görünümü; "Logged in as Ayşe" |
| Kullanım | S6 Activity: "Viewed sign-in settings — by Mehmet Y. (Acme Support) on your behalf, 15:02" | Her eylem için olağan karar sözleşmesi; reserved eylemler "Protected action — not included in support access" | Access | Eylemin kullanıcıya atfedilmesi |
| Bitiş | "Support access ended 15:30" (expiry) veya "You revoked support access 15:10" | "Support access ended" | Access | Sessiz uzatma; "pending end" |
| Break-glass | Changes + anlık bildirim: "*Acme Security* used emergency access on your account (incident #…) · 2 approvals · until 16:00" | Quorum ve requirement'lar | Access (INV-28; kullanım kaydı BY SEMANTICS, bildirim `notify-subject` ile UNDER DECLARED POLICY) | Bildirimsiz kullanım; beyansız muafiyetle self-restriction'ı aşmak |

### 8.17 Deneyim ayrıntıları (normatif ayrıntı metni)

**Statü ve okuma kuralı.**
- Bu bölüm deneyim kararlarının (§8.1–§8.14) normatif ayrıntı metnidir (PRODUCT EXPERIENCE — FROZEN): roller, IA, etkileşim desenleri, approval deneyimi, envanter ve revocation, açıklama, admin, developer, dikkat ilkeleri, best-of-breed uyarlamaları, backlog ve açık sorular.
- İlgili bölümler:
  - Agent-facing contract §8.18'dedir.
  - Canonical model, mercekler, anti-modeller, yüzeyler, dikkat tablosu, status ladder, sözlük, progressive disclosure ve degraded-state kuralları §8.1–§8.13'tedir.
  - Experience invariant'ları (XI-1–XI-22) §6.4'tedir.
  - X1–X31 §8.14'tedir.
- Metin içindeki "Work §n" atıfları Work spec'inin numaralandırmasıdır. §8.17.14'teki OQ1/OQ2/OQ3 soruları ilgili katmanlarda cevaplanır: Protocol → §9; Security → §13–§14; Technical → §16–§17. Açık kalanlar §20'dedir.
- Bu bölümle §8.1–§8.14 arasında fark varsa §8.1–§8.14 geçerlidir (ör. X26 timeout kuralı, `witnessed_through`). Bilinen tek fark aşağıda notuyla işaretlenmiştir.

#### 8.17.1 Executive Experience Verdict

**Verdict: COHERENT WITH REFINEMENTS**

Frozen model kullanıcıya dürüst, öğrenilebilir ve tek bir zihinsel modelle sunulabiliyor. Hiçbir yüzey için ikinci bir source of truth, yeni bir primitive veya gizli bir authority yolu gerekmedi. **EXPERIENCE CONTRADICTS MODEL** sonucunu gerektirecek bir yer bulunmadı: her kullanıcı ihtiyacı ya mevcut bir Exercise'la (issue, amend, revoke, renounce, contribute, policy.set, instance.*), ya mevcut bir derived state'le (holder set, effective/exercisable authority, budget remaining, revocation impact, outcome state, eligible set), ya da başka bir ürünün fact'iyle (Work Gate, Executor stop state, Pay hold) karşılanıyor.

Refinement'lar, aday modeli ve yerleşik UX alışkanlıklarını frozen modele göre düzelten kararlardır:

| # | Refinement | Neden contradiction değil |
|---|---|---|
| R1 | **Aday mental model düzeltildi.** "Benim adıma kim, neyi, hangi sınırla yapabilir — ve ben bunu görür, değiştirir, geri alırım" üç yerde yanlış vaat ediyor: (a) *benim adıma* yalnız `FOR(me)` capacity'sidir; benden türeyip kendi adına (Alice → Bob, OWN) veya başka bir principal adına (Alice → Agent A, FOR(Acme)) kullanılan authority de kullanıcının görmesi gereken şeydir (provenance ≠ capacity); (b) *değiştiririm* simetrik değildir: daraltma her zaman, genişletme daha sıkı yoldan (INV-10); (c) *geri alırım* yalnız kendi authority'm izin verdiği kadardır (Work S20) ve **geri almak durdurmak değildir** (EI-11). Canonical model §8.1'dedir | Model değişmiyor; yalnız dili frozen ayrımlara hizalanıyor |
| R2 | **"Approve", "Give access" ve "Allowed" üç ayrı terimdir.** Approve = contribution Exercise'ı (bir requirement'ı karşılar, authority yaratmaz); Give access/Delegate = `grant.issue`/`grant.amend` (holding yaratır; exercisable kullanım vaat etmez); Allowed = yalnız Access'in ALLOW DecisionRecord'u. Aynı terim iki canonical kavrama verilmez; "Approve anyway" bir DENY'ı aşamaz (§8.17.5.2, §8.17.6, §8.8) | E7, EI-4, INV-20, CI-14'ün UI karşılığı |
| R3 | **Access'in istek/onay kuyruğu yoktur.** İnsan dikkati gerektiren her authority talebi coordinator'ın dikkat yüzeyine girer (Suiss'te Work Needs Attention, Gate/Condition olarak; third-party'de compatible coordinator). Access yalnız semantic event içeriği, eligible set ve trusted act'i sağlar (§8.17.11) | ("toplama, hatırlatma, sıra, timeout: Work + Relay"), §7.9.5.3, E30; ikinci bildirim evreni yasağı |
| R4 | **"Pause" kelimesi Access'e ait değildir.** Pause/cancel/takeover Executor control'üdür (Work §15). Access'in geri alınabilir daraltması **Suspend**'dir (restriction overlay). Tek düğmeli "Stop" etkileşimi iki fact'i ayrı satırlarda gösterir (§8.17.7.5) | Authority ≠ Control ≠ Execution (Work §15.1), INV-6 |
| R5 | **Cross-product görünürlük sorusu kapandı (§8.17.6.5):** cross-product authority görünürlüğü = Access kaynaklı tek bir **Authority** hub (cross-domain projection, owner ve freshness etiketli) + Work kaynaklı tek bir **Needs Attention**; ikisi referansla bağlanır, birbirini kopyalamaz. Gate + contribution aynı kullanıcı eylemiyse trusted Approval Surface'te **tek tören, iki kayıt, ayrı durum satırları**dır (§8.17.6, §8.17.7.1) | E7 ve E32'nin deneyim karşılığı; yeni nesne yok |
| R6 | **Honest status ladder.** requested → approved → allowed → started → reported → (done / not done / unknown) adımları hiçbir yüzeyde birleştirilmez; her basamak kendi owner'ının fact'idir (§8.7) | E25, EI-21/22 |
| R7 | **Asimetrik sürtünme.** Authority'yi genişleten her eylem trusted surface'te, exact typed preview ve gereken assurance ile yapılır; daraltan her eylem kullanıcının herhangi bir authenticated yüzeyinden, en kısa yoldan yapılabilir (§8.17.5.1, §8.17.7) | INV-10 / L11 asimetrisinin deneyime yansıması |
| R8 | **"Allow once" ihtiyacı iki canonical eyleme düşer** ve UI bunu saklamaz: agent'ın authority'si var ama bir approval requirement'ı karşılanmamışsa "Approve this request" (contribution, digest'e bağlı); agent'ın authority'si yoksa "Give access once" (count=1 BudgetTerm'lü, parametreleri eşitlikle sabitlenmiş, kısa validity'li bir Grant). İkincisi kullanım vaat etmez: Access isteği yeniden değerlendirir ve kalan engeller (instance limits, restriction) önceden gösterilir (§8.17.5.2) | One-shot Grant, holding ≠ exercisable ve RequirementTerm; yeni mekanizma yok |

**Tek cümlelik sonuç:**

> **Kullanıcı Access'i, kendisinden kaynaklanan ve kendisine verilen yetkinin görünür, sınırlı ve geri alınabilir zinciri olarak algılar; Access ona kimin, neyi, kimin adına, hangi sınırla ve neye dayanarak yapabildiğini ve her kullanımın kaydını gösterir — işin kendisini, parayı, etkinin gerçekleştiğini ve çalışan bir sürecin durduğunu ise sahiplerinin ağzından ve dürüstçe "bilinmiyor" diyebilen bir dille gösterir.**

Freeze criterion cevapları (ayrıntı ilgili bölümlerde):

| Soru | Cevap |
|---|---|
| What does each user think Access is? | Tek model, beş mercek: principal için "benden çıkan ve bana gelen yetkinin zinciri"; approver için "kendi yetkimle tam olarak neyi onayladığım yer"; admin için "kurumun yetki anayasası"; developer için "her consequential effect'ten önce sorduğum ve neyin eksik olduğunu söyleyen authority provider"; auditor için "her yetki kullanımının kökten bugüne değiştirilemez kaydı" (§8.2, §8.17.3) |
| Primary surfaces and their questions? | S1 Delegation · S2 Authority inventory · S3 Approval Surface (Work ile ortak) · S4 Revoke/Suspend/Narrow + Aftermath · S5 Explanation · S6 Activity · S7 Org authority admin · S8 Developer console · S9 Audit & security · S10 Sign-ins & instances (§8.5) |
| What do users repeatedly do? | Delegate (genellikle agent'a), approve (Gate içinde), check "who can act for me", narrow/revoke, ask "why/why not", step-up; admin: role değişikliği, source kabulü, offboarding; developer: test/explain decision (§8.17.2, §8.17.5) |
| What happens automatically, and what must never be automatic? | Otomatik: autonomy içindeki ALLOW'lar, expiry, Commitment-scoped bitiş, HR kaynaklı seçim değişikliği, event teslimi. Asla otomatik değil: authority'yi genişleten veya kabulü değiştiren her şey, her approval, her yenileme, her template/role sürüm geçişi (§8.6) |
| Where must human attention enter? | Approval, eksik authority, genişletme, kabul (Acceptance) değişikliği, departure disposition, revocation sonrası bilinmeyen execution; hepsi coordinator'ın dikkat yüzeyinden, consequence sıralamasıyla (§8.17.11) |
| Which canonical terms never reach the UI? | HoldingRef, AuthorityStateBasis, ValidityContract (adıyla), nonce, Acceptance use adları, PartyRef, Genesis, AnchorRoot, holding episode, projection, Mandate (adıyla) ve diğerleri (§8.9) |
| Can any UI wording imply a guarantee the system cannot give? | **NO** (§8.10, XI-12, X24) |
| Can any surface become a second source of truth? | **NO** (XI-3, XI-16, X4, X28) |
| Can any convenience create a hidden authority path? | **NO** (XI-4, XI-18, X11, §8.17.9.8) |

#### 8.17.2 Users / Roles and Jobs

Access'in insan kullanıcıları altı role ayrılır; aynı kişi birden çok rolde olabilir (bir çalışan hem principal, hem approver, hem de bir agent'ın operatörü olabilir). Rol bir hesap türü değildir; o anki işin merceğidir. Yedinci kullanıcı, agent'tır: UI kullanıcısı değildir ama Access'in en sık "konuştuğu" taraftır (§8.18).

##### 8.17.2.1 Rol tablosu

| Rol | Ne düşünüyor | Tekrar tekrar ne yapıyor | Ne korkuyor | Access'te esas gördüğü | Asla görmemesi gereken |
|---|---|---|---|---|---|
| **Individual principal** (kendi adına agent'lar çalıştıran kişi) | "Agent'larım ve bağladığım uygulamalar benim adıma bir şeyler yapıyor; neyi yapabildiklerini ben belirliyorum" | Agent'a/uygulamaya yetki verir; sınır koyar (tutar, alıcı, süre); "kim benim adıma ne yapabilir" diye bakar; daraltır, iptal eder; bir talebi tek seferlik erişim vererek ("Give access once") karşılar | Agent'ın sınırı aşması; unutulmuş, süresiz yetkiler; iptal ettiği hâlde bir şeyin devam etmesi; anlamadan onay vermek; para limiti ile yetki limitinin karışması | S2 Authority inventory, S1 Delegation, S6 Activity, S5 "Why?" | Başkalarının authority graph'ı; One'ın hafızası; "agent durduruldu" gibi Executor teyidi olmayan cümle |
| **Approver** (kendisinden onay istenen kişi) | "Benden belirli bir şeyi onaylamam isteniyor; kendi yetkimle bunun tam olarak ne olduğunu görüp karar vermeliyim" | Needs Attention'dan gelen bir isteği açar; exact intent'i inceler; onaylar veya reddeder; gerekirse güçlü kimlik doğrulama yapar | Yanlış bir şeyi onaylamak (blind signing); onayının başka bir şeye kullanılması; sürekli onay bombardımanı; onay vermesinin "iş tamamlandı" sanılması | S3 Approval Surface (Work Gate bağlamıyla), S5 | Agent'ın yazdığı özet (canonical render yerine); "Approve anyway" ile DENY'ı aşma seçeneği |
| **Organization admin / authority owner** | "Kurumun yetki yapısını ben tasarlıyorum: kim hangi rolle ne yapabilir, hangi kaynağa (HR, IdP) güveniyoruz, korunan eylemler kimde" | Rol (named AuthoritySet) tanımlar ve sürümler; rule-shaped Grant'ları yönetir; kaynak kabul eder (Acceptance); offboarding yapar; break-glass tanımlar; değişiklik etkisine bakar | "Admin her şeyi yapabilir" sanılması; bir rol değişikliğinin sessizce yüzlerce kişiyi genişletmesi; HR/IdP compromise'ının yetki basması; ayrılan çalışanın bir kanaldan yetki tutmaya devam etmesi | S7 Org authority admin, S9, S5 | "Full access" etiketi; disposition seçilmeden tamamlanan offboarding; impersonation ("view as") |
| **Agent operator / developer** | "Benim servisim/agent'ım Access'e sorar; ben action schema'larımı yayınlarım ama authority yaratmam" | Schema yayınlar; PEP'i entegre eder; decision'ı test eder ve açıklar; verifier profile beyan eder; agent'ın Instance'larını yönetir | Belirsiz DENY'lar; Access erişilemezken ne olacağı; schema sürüm geçişinde her şeyin bozulması; yanlışlıkla servis kimliğiyle kullanıcı adına işlem yapmak | S8 Developer console, S5 (structured), S9 (kendi domain'inde) | "fail open" seçeneği; kendi schema'sını kendi domain'inde kabul etme kısayolu (Acceptance domain admin'inindir) |
| **Security / audit reviewer** | "Her yetki kullanımının nereden geldiğini, kimin adına yapıldığını ve neye dayandığını kanıtlayabilmeliyim" | Exercise kayıtlarını sorgular; bir kararı geriye dönük açıklar/yeniden üretir; revocation etkisini ölçer; containment uygular; export alır | Kaydın eksik/yeniden yazılmış olması; executor'ın kendi kaydını yazması; offline pencerede ne olduğunun bilinmemesi; SIEM kopyasının kaynak sanılması | S9 Audit & security, S5 (tam derinlik) | Silinmiş geçmiş; "effect gerçekleşti" ifadesi attestation olmadan |
| **End customer** (bir merchant'ın agent'ıyla etkileşen kişi) | "Bir şirketin asistanıyla konuşuyorum; benden ödeme veya bilgi isterse ne verdiğimi bilmeliyim" | Agent'la konuşur; gerekirse ödeme onaylar veya merchant'a (tek seferlik/kalıcı) ödeme yetkisi verir; sonradan kayıtlı yetkileri görür ve iptal eder | Bir insanla konuştuğunu sanmak; tek seferlik sandığı onayın kalıcı olması; agent'ın "tamam" demesinin işlemin yapıldığı sanılması | Trusted ödeme/izin yüzeyi (S3/S1'in end-customer profili), S2'nin "Merchants that can charge you" bölümü | Merchant'ın iç authority graph'ı; agent prose'unun authority veya sonuç gerçeği gibi sunulması |

> Identity plane'in rolleri de aynı mercek modeline yerleşir. Ayrı bir mental model yoktur (X2):
> - **Tüketici / çalışan (son kullanıcı):** S10–S11'de principal merceğidir.
> - **RP / uygulama geliştiricisi:** OIDC/SAML client kaydı, developer merceğidir (S8, identity plane developer yüzeyi → §10, §12).
> - **Tenant admin:** iki ayrı Grant'tır. Ticari abonelik yöneticiliği "Billing admin" olarak authority içermez. Realm/authority yöneticiliği admin merceğidir (S7 ve realm "Sign-in settings", MD-14).
> - **Platform admin:** Suiss operasyonudur. Kiracı domain'inde authority'si yoktur (INV-29, "Hosted by Suiss Access — the host holds no authority here").
> - **Destek operatörü:** §8.16.

##### 8.17.2.2 Agent: UI'sız kullanıcı

| Soru | Cevap |
|---|---|
| Ne "düşünür"? | Agent bir Party'dir (F15: ayrı security universe değil); Access ona "bu Instance, bu basis ile, bu capacity'de, bu exact intent için şimdi exercise edebilir mi?" sorusunun cevabını verir |
| Tekrar tekrar ne yapar? | Intent kurar ve karar ister; continuation ister; REQUIRE_ACTION'ı coordinator'ına iletir; advisory evaluation ile planlar; effect attestation'ı (executor/domain üzerinden) bağlar |
| Ne riskler taşır? | Confused deputy (kendi authority'sini principal işine kullanmak), prose'u approval sanmak/sundurmak, DENY'dan sonra aynı şeyi döngüyle denemek, açıklamayı talimat sanmak (prompt injection), intent'i limit altına bölmek |
| Deneyimi nerede tanımlı? | §8.18 (structured decision contract, reason classes, remediation types, nonce kuralları) |

##### 8.17.2.3 Rol × yüzey yoğunluğu

| Yüzey | Principal | Approver | Admin | Developer | Auditor | End customer |
|---|---|---|---|---|---|---|
| S1 Delegation | ●●● | ○ | ●● | ● | — | ● (profil) |
| S2 Inventory | ●●● | ● | ●● | ● | ● | ● (profil) |
| S3 Approval Surface | ● | ●●● | ●● | — | — | ●● (profil) |
| S4 Revoke/Suspend/Narrow | ●● | — | ●● | ● | ●● (containment) | ● |
| S5 Explanation | ●● | ●● | ●●● | ●●● | ●●● | ● |
| S6 Activity | ●● | ● | ●● | ●● | ●●● | ● |
| S7 Org admin | — | — | ●●● | ● | ●● | — |
| S8 Developer console | — | — | ● | ●●● | ● | — |
| S9 Audit & security | — | — | ●● | ● | ●●● | — |
| S10 Sign-ins & instances | ●● | ● | ●● | ●● | ●● | ● |

(●●● birincil iş, ●● sık, ● ara sıra, — kullanmaz, ○ yalnız kendisi grantor ise.)

#### 8.17.3 Mental Model(s)

##### 8.17.3.1 Aday modelin testi

Aday model: *"Benim adıma kim, neyi, hangi sınırla yapabilir — ve ben bunu görür, değiştirir, geri alırım."* Dört iddiaya bölündü ve her biri frozen modele karşı sınandı.

| Adayın parçası | Test | Sonuç | Düzeltme |
|---|---|---|---|
| "Benim **adıma**" | Alice'in Bob'a dokümanını okuma izni (agency OWN): Bob Alice adına değil kendi adına okur, ama authority Alice'ten türer | **Eksik.** "Adıma" yalnız `FOR(me)` capacity'sini kapsar; benden türeyen OWN delegation'lar ve başka bir principal adına verdiklerim (ör. Acme adına bir agent'a) listeden düşer, kullanıcı en tehlikeli paylaşımları göremez | İki soru: *"Kim benim adıma hareket edebilir?"* (capacity) ve *"Benim yetkimden kim ne kullanıyor?"* (provenance). Envanter ikisini ayrı gruplar; provenance kesiti capacity'den bağımsız olarak **tamdır** (§8.17.7.1) |
| "**neyi, hangi sınırla**" | AuthoritySet + ConstraintSet + Mandate + RestrictionPolicy + RequirementSet | **Doğru ama tek katmanlı değil.** Grant'ın sınırı ile bir Instance'ın o an kullanabileceği (Mandate, restriction) farklıdır (CI-5) | Varsayılan görünüm Grant sınırını gösterir; "şu an neden yapamıyor" sorusu S5'e gider (exercisable ≠ held) |
| "**değiştiririm**" | Daraltma consent gerektirmez; genişletme daha sıkı requirement taşır (INV-10); expired/revoked Grant uzatılamaz | **Yanlış simetri vaat ediyor** | "Daraltırım ve yeniden veririm"; genişletme ayrı ve daha dikkatli bir eylemdir |
| "**geri alırım**" | Kullanıcı yalnız kendi authority'sinin izin verdiği revocation'ı yapabilir (Work S20; `grant.revoke` sahipleri); revocation fiziksel durdurma değildir (EI-11); geçmiş kullanımlar geçerli tarih olarak kalır (INV-23) | **İki yanlış vaat:** her şeyi geri alabileceği ve geri almanın durdurmak olduğu | "Verdiğimi ve benden türeyeni geri alırım; geri alma bundan sonrası içindir; çalışan bir işin durması ayrı bir şeydir ve onu bana sahibi söyler" |

Sonuç: aday **REFRAME** edildi. Özü (görünürlük, sınır, geri alınabilirlik) korunur, üç yanlış vaadi kaldırılır.

#### 8.17.4 Information Architecture

##### 8.17.4.1 Tek kabuk, sahiplik rozetli

Şart: Work ve Access yüzeyleri aynı kullanıcıya iki uygulama gibi görünmemeli, ama iki source of truth da birleşmemeli. **Karar: Suiss Experience tek bir kabuktur; ürün sınırı navigasyonda değil, her durum satırındaki owner rozetinde görünür.** Kullanıcının günlük evi Work'ün dikkat yüzeyleridir; Access'in yüzeyleri aynı kabukta bir hub ve her yerde açılan gömülü bileşenlerdir.

```text
SUISS (tek kabuk)
├── Needs Attention............ Work (tek aksiyon kuyruğu; Gate/Condition)        ← authority talepleri BURAYA girer
├── Briefing................... Work (ne değişti; Work'ü etkileyen authority değişiklikleri dahil)
├── My Work / Commitments / Work View / Live / Chat..... Work
│
├── Authority  (hub)........... Access kaynaklı
│   ├── Acting for you......... FOR(me) holder'lar: agent'lar, kişiler, uygulamalar, merchant'lar
│   ├── Shared from you........ benden (holding'imden veya root'umdan) türeyen, agency'si FOR(me) olmayan her delegation;
│   │                            satırda capacity etiketi: "for their own use" / "on behalf of Acme"
│   ├── Your authority......... tuttuklarım: kaynak, neden, sıfat, süre, limit
│   ├── Activity............... yetki kullanımları (S6)
│   ├── Sign-ins & instances... S10
│   └── Changes................ authority değişikliklerinin akışı (salt bilgi; görev değil)
│
├── Admin (org, yetkiye göre görünür)..... S7
│   ├── Roles & templates · People & agents · Sources · Restrictions & requirements
│   ├── Protected actions & break-glass · Offboarding · Domain (constitution, provider) · Changes
├── Developer (yetkiye göre görünür)...... S8: Namespaces & schemas · Integrations · Decision lab · Logs
└── Audit (yetkiye göre görünür).......... S9: Records · Replay · Revocation impact · Unknown outcomes · Export

Gömülü bileşenler (her ürünün içinde açılır, aynı sözleşme):
  [Delegation sheet S1]  [Approval Surface S3]  [Why? panel S5]  [Status ladder]  [Step-up ceremony]
```

> Identity plane eklemeleri:
> - Kabuk ağacına "Account & sign-in methods" (S11) eklenir.
> - Admin bölümüne "Sign-in settings" eklenir: realm config, client'lar, upstream IdP, marka, giriş politikası. Bu ayarların her değişikliği bir domain action Exercise'ıdır (E34).
> - Müşteri realm'lerinin hosted giriş ve hesap yüzeyleri Suiss kabuğunun dışında, realm alan adında ve realm markasıyla sunulur (X40). Gömülü bileşen sözleşmesi (S1, S3, S5, status ladder, step-up) orada da aynıdır.

##### 8.17.4.2 Yerleşim kuralları

| Kural | İçerik | Gerekçe |
|---|---|---|
| **IA-1 Tek aksiyon kuyruğu** | İnsan eylemi gerektiren her authority talebi (approval, eksik authority, genişletme talebi, quorum katkısı) Needs Attention'da Work item'ı olarak görünür; Authority hub'ında "Requests" sekmesi **yoktur**. Requester'ın (agent'ın veya uygulamanın) kendi inisiyatifiyle başlattığı talep trusted bir sheet'i (S1/S3) doğrudan açamaz: taslak hazırlayıp coordinator'a typed "authority request" gönderir ve sheet yalnız o Needs Attention item'ından açılır (Work ranking, dedup ve attention budget'a tabi). Doğrudan açılış yalnız kullanıcının başlattığı, kullanıcının hazır bulunduğu bağlamdadır (kendi navigasyonu, One'a kendi verdiği komut, uygulamada kendi tıkladığı "Connect"; §8.17.4.3) | Access'in request queue'su yok (X5); Work §14.2 "Commitment/Gate olmadan approval gösterilmez"; Work §14.1 "must not become approval spam", S12 |
| **IA-2 Changes ≠ Needs Attention** | Authority hub'ındaki "Changes" yalnız bilgi akışıdır (biri size yetki verdi, bir yetki sona erdi, bir kaynak değişti); hiçbir item "action required" iddia etmez | İkinci bildirim evreni yasağı |
| **IA-3 Referansla bağlanma** | Bir Needs Attention item'ı ilgili GrantID/ExerciseID'ye, bir envanter satırı ilgili CommitmentRef/GateRef'e **link** verir; içerik kopyalanmaz, her taraf kendi owner'ından okunur | E27 references ≠ ownership |
| **IA-4 Gömülü yüzey = renderer + Exercise talep eden** | Pay'in "agent spending limit" ekranı, Commerce personel ekranı, POS, One sohbeti, third-party uygulama: Access verisini gösterebilir ve Access'e Exercise talebi gönderebilir; kendi kopyasını tutamaz ve kendi kararını veremez | §7.9.9.2 ("Pay ekranı yalnız Access'e `grant.amend`/`policy.set` isteyen bir yüzeydir"), X28 |
| **IA-5 Yetkiye göre görünürlük** | Admin, Developer, Audit bölümleri bir rol etiketiyle değil, viewer'ın ilgili authority'sine göre görünür; görünen her eylem viewer'ın gerçekten exercise edebileceği eylemdir | XI-11; "admin" bir Grant'tır |
| **IA-6 Domain ve provider görünürlüğü** | Tek domain kullanan kullanıcı domain kavramını görmez; birden çok domain'de yetkisi olan kullanıcı her satırda domain (ve uzman görünümünde provider) etiketini görür | AuthorityDomain ≠ tenant ≠ org (L25); E20 |
| **IA-7 Composition, privilege değil** | Kullanıcı Work'ü third-party bir authority provider ile veya Access'i third-party bir coordinator ile kullanıyorsa aynı bileşenler (S3, S5, status ladder) aynı protocol sözleşmesiyle çalışır; Suiss-only kısayol yoktur | E24, Work §25.2, XI-18 |

##### 8.17.4.3 Giriş noktaları

| Kullanıcı nereden gelir | Başlatan | Hangi yüzey açılır | Not |
|---|---|---|---|
| Needs Attention'daki bir approval item'ı | Requester → coordinator | S3 (Gate bağlamı + exact intent) | Bildirim yalnız davettir; onay S3'te yapılır |
| Needs Attention'daki "authority missing" / "authority request" item'ı | Requester → coordinator | S1 (agent'ın talep ettiği typed intent'ten taslak) | §8.17.5.2 |
| Agent'ın veya uygulamanın kendi inisiyatifiyle authority istemesi | Requester | **Hiçbir trusted sheet doğrudan açılmaz** → coordinator'a typed authority request → Needs Attention item'ı (yukarıdaki satır) | IA-1; Work ranking/dedup/attention budget, S12; push-bombing koruması (§8.17.11.4) |
| One sohbeti ("Ajanıma alışveriş yetkisi ver") | Kullanıcı | S1 (One'ın kullanıcı isteğiyle hazırladığı taslak, kullanıcı onaylar) | One hazırlar, tetiklemez (E23) |
| Third-party uygulamanın "Connect your Suiss authority" akışı (kullanıcının tıklamasıyla) | Kullanıcı | S1 (uygulamanın istediği typed bounds ile) | OAuth consent'in yerine geçen, exact preview'lü delegation (§8.17.12) |
| Authority hub / kendi navigasyonu | Kullanıcı | S1, S2, S4 | Daraltma iki adımda (XI-5) |
| Work Live'da çalışan bir agent | Kullanıcı | S2 satırı + S4 + Executor control (Work) | "Stop" etkileşimi §8.17.7.5 |
| Bir DENY/REQUIRE_ACTION mesajı (her üründe) | — (bilgi) | S5 | Owner-attributed açıklama |
| Ödeme/checkout | Kullanıcı (checkout eylemi) | S3 end-customer profili veya S1 (merchant'a kalıcı yetki) | §8.17.5.11 |
| Güvenlik olayı | Kullanıcı (security) | S9 → S4 (containment) | §8.17.9.7 |

#### 8.17.5 Interaction Patterns

Her desen: kullanıcı ne yapar · hangi canonical eyleme düşer · ne otomatik · ne asla · dürüst durum.

##### 8.17.5.1 Delegation creation (template / natural language / precise editor)

**Karar: üç giriş, tek onay.** Template, doğal dil ve hassas editör yalnız *taslak* üretir. Kayda geçen tek şey, kullanıcının kendi Instance'ından, trusted surface'te, typed Grant içeriğinin **exact preview**'ünü gördükten sonra yaptığı `grant.issue` (veya `grant.amend`) Exercise'ıdır. **NL'den Grant'a geçişte exact preview zorunludur** ve preview NL cümlesini değil, typed içeriği gösterir.

```text
Template ─┐
NL (One / LLM taslağı) ─┼──► typed draft ──► EXACT PREVIEW (S1) ──► user act (trusted surface,
Precise editor ─┘                             • ne verilir                gerekiyorsa step-up)
                                              • kimin adına                     │
                                              • yeniden verilebilir mi          ▼
                                              • sınırlar, süre, limit     grant.issue Exercise (Access)
                                              • ne VERİLMEZ                     │
                                              • NL yorum farkları               ▼
                                                                         commit → "Delegation created" + GrantID
```

Commit etiketi §8.8'deki delegation terimine bağlıdır ("Delegation created" / "Yetki verildi"). "Granted" ve "Allowed" kullanıcının bu eylemi için kullanılmaz: delegation holding yaratır; holder'ın bir isteğinin izinli olup olmadığı ayrı bir Access kararıdır (ALLOW, §8.7).

Preview'ün zorunlu blokları (wording değil, içerik zorunluluğu):

| Blok | İçerik | Kaynak |
|---|---|---|
| **To** | Holder: kişi / agent / uygulama / merchant (agent ise "AI agent", operatörü ile; Work §11.5) veya rule-shaped seçici ("Finance ekibindeki herkes — HR'ın beyanına göre") | SubjectSelector + Claim'ler |
| **Can do** | Action'lar (schema'nın insan-okunur adıyla), resource'lar, typed parametre sınırları (tutar ≤, alıcı =, adet ≤, zaman aralığı ⊆, amaç ∈) | AuthoritySet (closed type system, E12) |
| **Acting as** | "On your behalf" / "On behalf of Acme" / "For their own use" — kullanıcının *kendi* holding'inin agency'sinden türetilir; kullanıcı Acme adına tutuyorsa "on your behalf" seçeneği hiç görünmez | AgencyTerms + agency continuity (INV-4) |
| **Can pass on** | Varsayılan **No**. Açılırsa: "up to N more steps", "only to: …" | DelegationTerms (C15) |
| **Limits** | Budget (adet/tutar/pencere), "this counts against *your* limit too" notu | BudgetTerm; lineage draw (C27) |
| **Requires** | Ek requirement'lar (ör. "each payment over 1,000 TRY needs your approval") | RequirementSet |
| **Valid** | Başlangıç–bitiş; Commitment-scoped ise "ends when Work commitment *X* ends" | Validity, while-condition (E8) |
| **Not included** | Reserved/protected action'lar; namespace'e gelecekte eklenecek action'lar; kullanıcının kendisinin tutmadığı her şey | INV-9, E11, INV-3 |
| **Interpretation** (yalnız NL girişte) | "'Küçük alışverişler' → her alışveriş ≤ 500 TRY olarak yorumlandı" gibi her yorum ayrı satır; kullanıcı değiştirmeden onaylarsa yorum *typed içerik* olarak kayda girer, cümle girmez | One/LLM taslağı (authority değil, E23) |

Kurallar:

- **Kullanıcının tutmadığı verilemez.** Preview, kullanıcının effective authority'si dışındaki her alanı daha taslakta işaretler ("You can approve up to 2,000 TRY; you can't give 5,000"). Bu bir UX kolaylığıdır; asıl garanti `grant.issue`'nun `Child ⊆ Parent` kontrolüdür (INV-3).
- **Template = sürümü pin'li named AuthoritySet.** Template'in yeni sürümü mevcut delegation'ları değiştirmez; S2 "Template v3 available — 4 delegations still on v2" gösterir ve geçiş diff'li, explicit bir `grant.amend`'dir (C28).
- **Agent'a verilen delegation'da bitiş zorunlu alandır.** Ürün varsayılanı bir süre önerir; "until you revoke" ancak explicit seçimle ve tam bu kelimelerle yazılır ("forever" asla). Gerekçe: unutulmuş, süresiz delegation landscape'in en sık başarısızlığıdır. Bu bir ürün varsayılanıdır, ontology kuralı değildir (X10).
- **One hazırlar, kullanıcı imzalar; sheet'i kim açar ayrı bir sorudur.** One veya herhangi bir agent taslağı doldurabilir; onay eylemi her zaman kullanıcının kendi Instance'ındandır (E23). Agent'ın "taslağı onaylı" diye göstermesi mümkün değildir. S1'in (ve S3'ün) açılması iki ayrı durumdur:
  - **Kullanıcının başlattığı, kullanıcının hazır bulunduğu bağlam** (kendi navigasyonu, One'a kendi verdiği komut — "Ajanıma alışveriş yetkisi ver" —, bir uygulamada kendi tıkladığı "Connect"): S1 doğrudan açılabilir.
  - **Requester'ın başlattığı talep** (agent veya uygulama kendi inisiyatifiyle authority ister): agent/uygulama trusted bir sheet'i kendi inisiyatifiyle **açamaz**; yalnız taslak hazırlayıp coordinator'a typed "authority request" gönderebilir. Talep Needs Attention'a girer, Work ranking/dedup/attention budget'ına tabidir ve S1 yalnız o item'dan açılır (IA-1, §8.17.4.3, X5). Gerekçe: exact preview içeriği korur ama dikkati korumaz; requester inisiyatifli açılış push-bombing'in delegation versiyonudur (§8.17.11.1).

##### 8.17.5.2 Just-in-time authority request (agent REQUIRE_ACTION / DENY → kullanıcı)

```text
t0  Agent Instance → Access: intent        → DENY({başarısız reason class'ların kümesi}: no-covering-authority,
                                                   budget-exhausted, outside-instance-limits, restricted …)
                                              veya REQUIRE_ACTION(unmet terms, eligible set*)
t1  Agent → coordinator (Work): typed intent + structured reason          (prose truth değildir)
t2  Work: Condition "authority missing" veya intent-bound Gate → Needs Attention (consequence-ranked)
t3  Kullanıcı item'ı açar; seçenekler typed veriden (reason class kümesinin tamamı + her engelin zincirdeki seviyesi) render edilir:
       a) "Approve this request"      → yalnız REQUIRE_ACTION(contribution) ise; contribute(approve, digest)
       b) "Give access once"          → yalnız authority eksikse; count=1, parametreleri sabit, kısa süreli grant.issue;
                                        viewer'ın çözemediği bir engel varsa (başka sınıf veya sınıfı ne olursa
                                        olsun viewer'ın seviyesinde/üstündeki engel) ya sunulmaz ya da
                                        "Would still be blocked by: …" satırıyla sunulur
       c) "Give access for similar…"  → S1, bounded delegation taslağı (exact preview)
       d) "Decline"                   → Work Declaration (Access'te kayıt yok)
t4  Trusted surface'te kullanıcı eylemi → Access Exercise (+ Gate varsa Work Declaration, ExerciseID ile)
t5  Agent yeniden ister: REQUIRE_ACTION ise aynı nonce; DENY ise yeni nonce (DENY o nonce için terminaldir, C30)
t6  Access: ALLOW / DENY  →  status ladder (§8.7)
(* eligible set requester'ın görmeye yetkili olduğu kadar, E26)
```

Karar noktaları:

| Durum | Sunulan seçenekler | Sunulmayan | Neden |
|---|---|---|---|
| Agent'ın authority'si var, approval requirement'ı karşılanmamış | Approve this request · Decline · (Give access for similar: requirement'ı kaldıran/gevşeten bir amend; genişletme sınıfı — **yalnız requirement viewer'ın kendi verdiği Grant'ta ise**; üst seviyeden (ör. Acme'nin terms'ü/policy'si) geliyorsa sunulmaz, yerine "Set by Acme. Who can: …") | Give access once | Authority eksik değil; eksik olan contribution'dır |
| Agent'ın authority'si yok (hiçbir basis kapsamıyor) ve kümede başka sınıf yok | Give access once · Give access for similar · Decline | **Approve** | Onay authority yaratmaz (CI-14, INV-20); "approve" bu durumda yanlış vaattir |
| Authority yok **ve** kümede viewer'ın çözemediği bir engel var (başka sınıf veya viewer'ın seviyesinde/üstündeki aynı sınıf) (`outside-instance-limits`, `restricted` …) | Ya "Give access once" hiç sunulmaz, ya da altında "Would still be blocked by: instance limits / Acme restriction" satırıyla sunulur; ayrıca her kalan engel için "Who can: …" | Kalan engeli gizleyen tek seferlik seçenek | Grant yalnız holding yaratır; exercisable = holding ∩ instance limits − restrictions, requirement'lara tabi (CI-5); XI-11 |
| Budget tükendi — tükenen budget viewer'ın verdiği Grant'ta (viewer'ın kendi seviyesinin altında) | Give access for similar (limit artırma = amend, genişletme) · Give access once (ayrı, count=1 Grant; o da kullanıcının kendi budget'ından düşer) · "Wait until 00:00 (limit resets)" · Decline | "Approve over limit" | Budget aşımı onayla aşılamaz; lineage budget'ları her draw'da uygulanır (C27) |
| Budget tükendi — tükenen budget viewer'ın kendi seviyesinde veya üstünde (ör. Alice'in kendi 2,000 TRY/gün limiti, Acme'nin limiti) | "Your own limit (or Acme's) is used up; resets at 00:00. Who can raise it: …" · Wait · Decline | Give access once / for similar (yeni Grant aynı tükenmiş budget'tan çekeceği için yine DENY olur) | **Çözülebilirlik reason class'ına göre değil, engelin zincirin hangi seviyesinde olduğuna göre** belirlenir; seviye başına kalan budget zaten derived'dır (§8.17.5.6, C27) |
| Instance sınırı dışında (Mandate) | "This needs Agent A's own account (the agent's Party) to widen this copy's limits, with a fresh confirmation" (yalnız bilgi + link; §8.11 gereği "owner" kelimesi kullanılmaz; agent'ın Party'si kullanıcının kendisiyse kendi Instance'ından fresh confirmation ile) | Kullanıcının başka bir Party'nin Mandate'ini doğrudan genişletmesi; operatöre yönlendirme | `mandate.rebind`'ı yalnız Instance'ın Party'si kendi Instance'ı üzerinden, fresh ceremony ile yapar (C14); operatör ≠ actor (§7.9.7.1) |
| Kullanıcının kendisi tutmuyor | "You can't give access for this. Who can: …" (görmeye yetkiliyse) | Herhangi bir erişim verme düğmesi | INV-3 |
| Requirement kullanıcının değil, başka birinin katkısını istiyor (independence) | "Needs approval from someone other than you" | Approve | Independence `contributor ≠ actor principal` |

**İki canonical eylem, iki fiil; karar üçüncü bir terim:** "Approve" yalnız contribution'dır; "Give access…" yalnız Grant'tır; "Allowed" yalnız Access'in ALLOW DecisionRecord'udur ve kullanıcı eylemi için hiçbir yüzeyde kullanılmaz. "Give access once" metninin altında her zaman ne verildiği ve neyin vaat edilmediği yazar: *"Gives Agent A authority for one use with exactly these details, until 15:30. Access will still check the request."* (X8). Kullanıcının eylemi commit olduğunda "Delegation created" yazılır; isteğin sonucu status ladder'da ayrı basamaktır (t6; §8.7).

##### 8.17.5.3 Approval

Ayrıntı §8.17.6'da. Desen düzeyinde: exact intent render, digest bağlama, assurance, independence, tek tören → iki kayıt, Decline yalnız Work.

##### 8.17.5.4 Step-up

| Adım | Ne olur | Owner |
|---|---|---|
| Access REQUIRE_ACTION döner: `authentication` Claim, binding = actor Instance (gerekirse intent digest), assurance ≥ X, freshness ≤ N dk | — | Access (requirement) |
| Yüzey inline sorar: *"Confirm it's you to send 3,000 TRY to Ayşe K."* — neden ve neye bağlı olduğu yazar | Identity plane ceremony (passkey vb.) | Identity plane (Claim issuer) |
| Yeni `authentication` Claim → aynı nonce yeniden değerlendirilir | ALLOW / DENY | Access |

Kurallar: step-up yalnız kullanıcının *kendi* Instance'ında karşılanabilir; agent'ın Instance'ı insan-varlığı gerektiren bir requirement'ı karşılayamaz ve agent'a "requirement not satisfiable by your instance — needs your principal's own action" döner (§8.18.3); bu durumda coordinator onu contribution veya kullanıcının kendi eylemi olarak yönlendirir. Step-up mesajı genel "Re-enter your password" değildir; hangi exact eylem için olduğunu söyler (CIBA binding_message zayıflığı dersi). Step-up yetki vermez; yalnız requirement'ı karşılar ("Signed in again" ≠ "allowed").

> Ceremony identity plane'dedir. RFC 9470 eşlemesi (`acr_values` tavsiye, `max_age` zorunlu) ve oturum politikası olaylarıyla tetiklenen yeniden doğrulama §12 TN-O3'tedir. Agresif ve bağlamsız yeniden doğrulama yasaktır.

##### 8.17.5.5 Revoke ve dürüst sonrası

Ayrıntı §8.17.7.3–§8.17.7.5. Desen: **impact preview → user act (narrowing; herhangi bir authenticated yüzey) → commit → aftermath paneli** (Access: revoked since T; açık reusable Decision'lar: izinli adımlar en geç hangi sonraki authority kontrolüne kadar devam edebilir; Executor: running/paused/stopped/unknown; offline: en geç ne zamana kadar onurlandırılabilir; geçmiş kullanımlar: geçerli tarih). Revocation commit anında semantik olarak etkilidir; ama açık bir ValidityContract horizon'una veya offline pass sonuna kadar envelope içindeki conformant kullanım **beyan edilmiş bir staleness penceresidir**, outside authority değildir (CI-9, INV-24, E31). "Outside authority" yalnız envelope dışı effect, pencere sonrası effect ve hiçbir Exercise'a bağlanamayan effect için yazılır (INV-19). Guarantee sınıfı: UNDER DECLARED CAPABILITY.

##### 8.17.5.6 Budget visibility ve tükenme

| Gösterilen | Nasıl | Canonical karşılık |
|---|---|---|
| **Effective remaining** | "1,200 TRY left today (of 2,000)" — zincirdeki tüm limitlerin en darı; uzman görünümünde halka halka ("your limit 5,000 → agent 2,000 → sub-agent 1,000") | Lineage draw: her exercise tüm budget'lardan düşer (C27) |
| **Counted, result unknown** | "Includes 300 TRY counted for a payment whose result hasn't been reported" | Draw = rezervasyon; release yalnız grounded non-execution Claim'iyle (INV-21) |
| **Reset** | "Resets at 00:00 (Europe/Istanbul)" | BudgetTerm window kuralı |
| **Exhausted** | "Limit reached — new payments by this agent will be refused until 00:00" | Sonraki draw DENY |
| **Financial limit** (varsa) | Ayrı satır, Pay/Money rozetli: "Card daily limit (your bank): 10,000 TRY" | E21; Access'te değil |

**Asla:** "held" kelimesi authority budget için (financial hold ile çakışır, F9); "balance" kelimesi; budget'ın para gibi toplanması; release'in "refund" diye gösterilmesi. Tükenme bir Commitment'ı bloke ediyorsa dikkat Work'e aittir (Condition → Needs Attention); Access yalnız `budget-exhausted` semantic event içeriğini üretir.

##### 8.17.5.7 Rule-shaped authority: "Neden bu yetkim var / yok?"

Cevap her zaman **iki parçalıdır** (INV-16): *authority yolu* (kim bu rolü kime verdi) + *seçim beyanı* (hangi kaynağın hangi beyanı sizi seçiyor, ne zamandan beri).

| Durum | Kullanıcının gördüğü | Canonical karşılık |
|---|---|---|
| Seçili | "You can approve expenses ≤ 10,000 TRY **as a Finance approver for Acme**. Given by: Acme CFO (role *Finance Approver v4*). You're included because **HR says** you're in Finance (statement of 3 Oct, accepted source: Acme HR)." | Rule-shaped Grant + subject-selection Acceptance + Claim; capacity FOR(Acme) |
| Beyan bayat | "**Needs refresh** — HR's statement about your team is older than this action allows. Your role is not removed." | Staleness ≠ lapse; REQUIRE_ACTION (C13) |
| HR çıkardı | "Not included since 6 Oct — HR says you're no longer in Finance. Delegations you made from this role ended at the same time." | Affirmative disqualify → episode kapanışı ve cascade (INV-31) |
| Geri döndü | "Included again since 9 Oct. **Delegations you made before 6 Oct are not restored**; create them again if needed." | Yeni episode, eski türevler canlanmaz (INV-31) |
| Kişisel dışlama | "Acme excluded you from this role on 7 Oct (Finance Approver v4)." | Selector'ın conjunctive daraltılması |
| Kendi isteğiyle kullanmamak | "Turn off on my devices" (self-restriction; kendiniz geri açabilirsiniz) — **"Leave role" yok** | Intensional Grant'ta renounce yoktur; Mandate daraltma veya self-restriction (C13) |

"Bayat" (stale) ve "çıkarıldı" (removed) hiçbir yüzeyde aynı görsel/dil durumunu paylaşmaz (XI-15).

##### 8.17.5.8 Offline / intermittent authority (POS, edge, uzun süren executor)

| Kim | Ne görür | Guarantee etiketi |
|---|---|---|
| **Kasiyer (POS)** | "Offline since 14:02 · can act offline until 18:00 · offline limit left: 3 voids, 2,000 TRY" | Projection + offline slice; verifier'ın beyan ettiği profile uyması *UNDER DECLARED CAPABILITY* |
| **Manager (S4'te revoke ederken)** | "Effective now for online systems. **Terminal POS-7 is offline**; it may still honor this until **18:00** at the latest *if it follows its declared offline profile*. Uses it reports later will be shown against this change." | Revocation commit anında; staleness exposure derived; Δ issuance Exercise'ında beyanlı (E13) |
| **Admin (S7/S9)** | "Revocation exposure: 3 terminals, max window 18:00 · 2 confirmed applied (terminal reports) · 1 unknown" | Delivery ack ≠ authority-state ack (E30) |
| **Uzun süren agent işi** | "Authority re-checked every 15 min; next check by 14:30" | ValidityContract horizon + continuation (E31) |
| **Principal (S4'te revoke ederken, açık reusable Decision varken)** | "Agent A's running task may continue steps already allowed until **14:30** (its next authority check), *if its runtime follows its declared contract*; after that, new steps are refused." | Revocation commit anında; açık reusable Decision'lar revocation impact'in parçası; *UNDER DECLARED CAPABILITY* |

**Asla:** "Revoked instantly everywhere", "Offline devices updated", "Terminal blocked" (terminalin kendi raporu yoksa). Offline pencere bir sözdür ve sahibi (domain'in issuance kararı) ile birlikte gösterilir (CI-9, INV-24).

##### 8.17.5.9 Holder tarafı: "Bu yetkiyi istemiyorum"

| Grant türü | Eylem | Canonical |
|---|---|---|
| Size doğrudan verilmiş (extensional) | "Give back" (iade et) — kalıcı | `grant.renounce` (terminal) |
| Rol üzerinden (intensional) | "Turn off for me" (geri açılabilir) veya "Ask Acme to exclude me" | Self-restriction / Mandate daraltma; dışlama yalnız authority source'tan |
| Kendi verdiğiniz alt delegation | Revoke | `grant.revoke` (grantor) |

> Honest status ladder §8.7'dedir.

##### 8.17.5.11 End customer akışları

| Akış | Deneyim | Canonical |
|---|---|---|
| Merchant'ın agent'ıyla sohbet | Her zaman "AI agent · acting for *Merchant M*" rozeti; insan olarak gösterilmez | Work §11.5; capacity FOR(M) |
| Tek seferlik ödeme | Trusted ödeme yüzeyi exact tutar/alıcı/amaç gösterir: "Pay 300 TRY to M, once" | Müşterinin kendi Exercise'ı (kendi ödeme aracı authority'siyle ödeme intent'i). Digest'e bağlı contribution **yalnız** merchant müşteriden zaten bir Grant tutuyorsa (ör. "Kartımı kaydet" Grant'ı + per-order approval requirement) geçerli bir yoldur; aksi hâlde onay authority yaratamaz (R8, X8, INV-20). Pay effect ayrı |
| "Kartımı kaydet / sonraki siparişlerde çek" | S1 end-customer profili: "Let *M* charge your card: up to 500 TRY per order, until 31 Dec 2026, only for orders you place" | Müşterinin ödeme aracı Anchor'ından merchant'a Grant (§7.9.9.3); scheme artifact (Pay) ayrıca |
| Sonradan görmek/iptal | S2 "Merchants that can charge you" (Suiss kimliği varsa) veya merchant/Pay yüzeyinde aynı Access verisinin render'ı | Projection; revoke = `grant.revoke` |
| Agent "iade yapıldı" der | Müşteriye güvenilir gerçek yalnız canonical kayıtları render eden yüzeyden (makbuz, Pay/Commerce durumu) gelir; agent cümlesi bilgi amaçlıdır | Agent prose ≠ effect truth (EI-10, Work S1) |

Müşteri, merchant'ın iç kararlarının açıklamasını (ör. "neden iade 500 TRY ile sınırlı") Access'ten almaz; açıklama requester'ın (agent'ın) authority'si kadardır ve müşteriye ne gösterileceği merchant'ın kararıdır (E26).

#### 8.17.6 Approval Experience (Work Gate + Access contribution)

##### 8.17.6.1 Karar: tek tören, iki kayıt, ayrı durum satırları

Approver açısından onay **tek bir etkileşimdir**. Sistem açısından **iki fact**'tir ve iki owner'ı vardır (E7):

```text
            Approval Surface (trusted, conformant; first- veya third-party)
┌──────────────────────────────────────────────────────────────────────────┐
│ WHY (Work)        Gate: "Release supplier payment for PO-1182"           │ ← Work canonical Gate payload
│                   Commitment: Supplier onboarding · requested by Agent A  │
│ EXACTLY WHAT      Pay 48,500.00 TRY → Kaya Tekstil A.Ş. (IBAN …41)        │ ← IntentEnvelope, kabul edilmiş
│ (Access-bound)    purpose: PO-1182 · once · valid until 17:00            │   schema ile render; digest'e bağlı
│ YOU APPROVE AS    Finance approver for Acme (role v4)                     │ ← approve Grant, capacity FOR(Acme)
│ STILL NEEDED      1 more approval · not the requester · not this device  │ ← RequirementTerm count/independence
│ WHAT THIS DOES    Records your approval. Access then re-checks the        │
│                   payment; the payment itself is made by Pay.            │
│            [ Approve ]  (passkey)                [ Decline ]              │
└──────────────────────────────────────────────────────────────────────────┘
        │ one user act (fresh, human-present authentication)
        ├──► Access: contribute(approve, digest) Exercise  ──► "Your approval: recorded 14:02"   (Access)
        └──► Work:   Gate Declaration citing ExerciseID    ──► "Gate: 1 of 2 approvals"          (Work)
```

| Konu | Karar | Dayanak |
|---|---|---|
| **Sıra** | Önce Access contribution commit; sonra Work Declaration, ExerciseID'yi cite eder ve Work referansı doğrular | §7.9.5.3 uyumsuzluk kuralları |
| **Tek user act → iki kayıt** | Approval Surface tek bir authenticating user act toplar; bu act'in iki kaydı nasıl yetkilendirdiği (ör. tek imzanın iki digest'i bağlaması veya iki ardışık imza) **DEFER TO PROTOCOL** (§8.17.14 OQ1). Deneyim kararı: kullanıcı bir kez eylem yapar; iki kayıt ayrı durum satırlarında görünür | E32; Work Approval Contract (Work §21.10) |
| **Kısmi başarısızlık** | Contribution commit oldu, Declaration olmadı → "Your approval is recorded (Access). Work hasn't registered it on the gate yet — retrying." Gate açık kalır; contribution yalnız Access requirement'ı için kullanılabilir. **"Approved and proceeding" yazılmaz** | §7.9.5.3; E29 (cross-product atomicity yok) |
| **Contribution DENY** | Approver'ın kendi authority'si yok/yetersiz/requirement'ı karşılanmadı → onay kaydedilmez; Declaration gönderilmez; açıklama S5 | INV-20 |
| **Decline** | Yalnız Work Declaration (Gate reddi). Access'te negatif contribution kaydı yoktur; reddetmek authority exercise'ı değildir | Contribution sınıfları |
| **Approve sonrası** | Approver'ın gördüğü durum ladder'ı: "Your approval: recorded" → "Gate: cleared" → "Payment: allowed / not allowed (Access)" → "Payment: reported done / unknown (Pay)". Gate cleared ≠ allowed | EI-4, §8.7 |
| **Pure coordination Gate** ("tasarımı onayla") | Aynı tören; digest = Work'ün canonical Gate payload digest'i, ActionRef `work.gate.satisfy` (Work publisher). "WHAT THIS DOES" satırı: "Records your approval of this design; it doesn't give anyone new authority" | E7 |
| **Eligible set** | Approve düğmesi yalnız kullanıcı eligible set'teyse görünür; değilse "You can't approve this. Eligible: Finance approvers (3)" — liste viewer'ın görmeye yetkili olduğu kadar | §7.9.5.3 (eligible set Access'ten), E26 |

##### 8.17.6.2 Exact intent rendering

| Kural | İçerik |
|---|---|
| **Kaynak** | Render yalnız domain'de `schema-definition` Acceptance'ı ile kabul edilmiş schema sürümünün typed alanlarından yapılır. Kabul edilmemiş schema/sürüm → "This request can't be displayed faithfully here; it can't be approved from this surface" (fail closed; E10) |
| **Agent prose** | Agent'ın açıklaması yalnız "Requester's note" başlığı altında, ayrı ve ikincil gösterilebilir; canonical özetin yerini alamaz (Work S11, Work §21.9) |
| **Authority-opaque içerik** | Approver'ın görmesi gereken ama Access'in tutmadığı gövde (ör. gönderilecek e-posta metni) coordinator/domain'den gelir ve yüzey onu intent digest'ine karşı doğrular; eşleşmezse onay kapalı. Access gövdeyi istemez (E26) |
| **Malzeme alanları** | Hedef, tutar/resource, alıcı, geri alınabilirlik, principal/agent bağlamı, malzeme değişiklikleri (Work §17.6) ve Access'e özgü: approver'ın sıfatı (capacity), kalan requirement'lar, geçerlilik süresi |
| **Değişiklik** | Intent değişirse (tek parametre bile) önceki contribution'lar geçersizdir ve yüzey "The request changed after you approved; your approval no longer applies" gösterir (L14) |

##### 8.17.6.3 Assurance ve independence

- Gereken assurance (human presence, phishing-resistant, freshness) RequirementTerm'den gelir; yüzey bunu "Confirm with your passkey" gibi somut eyleme çevirir.
- Independence (Bybit dersi, L13/F13): "not the requester", "not someone who approved from the same device", "a different approval app" gibi şartlar **görünür** ve karşılanıp karşılanmadığı contribution kanıtlarından derived gösterilir. Bağımsızlığın *gerçekten* bağımsız insanlar olduğunu sistem kanıtlayamaz (Work §18.3 #9); yüzey "independent" kelimesini değil "different person / different device" gibi kontrol edilebilir ifadeleri kullanır.
- **Notification ile onay.** Yüksek sonuçlu sınıflarda Relay bildirimi yalnız davettir; onay her zaman trusted surface'te açılan exact render üzerinden yapılır (Work §21.9). Düşük sonuçlu sınıflarda bildirim içi hızlı onay ancak (a) bildirim yüzeyi conformant render yapıyorsa ve (b) RequirementTerm'in assurance'ı bunu karşılıyorsa mümkündür; sınıf eşikleri Security'dedir (§8.17.14 OQ2).
- **Batch.** Yüksek sonuçlu sınıflarda toplu onay yoktur. Düşük sonuçlu sınıflarda toplu görünüm olabilir, ama her item kendi render'ıyla listelenir ve her biri kendi digest'ine bağlı ayrı bir contribution üretir; "Approve all" etiketi kullanılmaz ("Approve these 4 requests" ve dördü görünür).

##### 8.17.6.4 Quorum deneyimi

```text
Request: Transfer 1,000,000 EUR  ·  needs 2 of {CFO, Treasurer, CEO} · not the requester · different devices
├─ CFO     approved 10:14 (passkey, phone)            Access
├─ Treasurer  waiting  — in Needs Attention since 10:15   Work
└─ Payment: not yet allowed (1 of 2)                  Access
```

Toplama, hatırlatma, sıra ve deadline Work'tür (Gate + Relay); "1 of 2" sayımı ve geçerliliği Access'tir (C26). Aynı Party'nin iki onayı bir sayılır; tek aggregate kimlik gösteren threshold tek onaydır (L13) ve yüzey bunu "counts as one approval" diye yazar.

##### 8.17.6.5 Cross-product authority görünürlüğü — CLOSED

| Sorunun parçası | Karar |
|---|---|
| Birden çok üründe kendi adına hareket eden Party'leri tek yerde görmek | **Authority hub → "Acting for you"** (§8.17.7.1): cross-domain, cross-product, Access kaynaklı tek envanter; One, Work agent'ları, third-party uygulamalar ve merchant'lar ayrıcalıksız aynı listede (E24) |
| Verdiği Grant'ları görmek | "Acting for you" + "Shared from you" (provenance ≠ capacity). "Shared from you", viewer'ın holding'inden/root'undan türeyen ve agency'si `FOR(viewer)` olmayan **her** Grant'ı kapsar (OWN ve `FOR(P ≠ viewer)`, ör. Acme adına bir agent'a verilen); satır capacity etiketi taşır. Tamlık kuralı: viewer'ın grantor olduğu her Grant en az bir grupta görünür ve Revoke/Narrow iki adım içindedir (§8.17.7.1, XI-10) |
| Commitment-scoped authority'leri görmek | Envanter satırında "Ends with Work commitment *X*" bağı (CommitmentRef link; içerik Work'ten) |
| Bekleyen contribution taleplerini görmek | **Needs Attention** (Work) — tek aksiyon kuyruğu; Authority hub'ında kopyası yok, yalnız "N approvals waiting for you →" linki (sayım Work'ten) |
| İptal etmek | Her envanter satırından S4; sonuç ve aftermath dürüst (§8.17.7.3–§8.17.7.5) |
| Gate + contribution tek kullanıcı eylemi | Trusted Approval Surface'te tek tören, iki kayıt, ayrı durum satırları (§8.17.6.1) |

#### 8.17.7 Authority Inventory & Revocation Experience

##### 8.17.7.1 Envanterin yapısı

**Authority** hub'ının ilk ekranı üç gruptan oluşur; gruplama doğrudan frozen ayrımlardan gelir:

| Grup | Soru | Canonical tanım | Satır içeriği (varsayılan görünüm) |
|---|---|---|---|
| **Acting for you** | "Kim benim adıma hareket edebilir?" | Agency'si `FOR(me)` içeren ve viewer'ın lineage'ından türeyen (veya viewer adına hareket eden birinin verdiği) Grant'ların holder'ları | Kim (tür rozeti: AI agent / person / app / merchant), ne yapabilir (insan-okunur özet), limit ve kalan, süre, son kullanım, kaynak domain (birden çok ise), Commitment bağı (varsa) |
| **Shared from you** | "Benim yetkimden kim, benim adıma olmadan, ne kullanıyor?" | Viewer'ın holding'inden (veya root'undan) türeyen ve agency'si `FOR(viewer)` olmayan **her** Grant: `OWN` ve `FOR(P ≠ viewer)` (ör. Alice'in Acme rolünü exercise ederek Agent A'ya verdiği `FOR(Acme)` delegation) — ve onların alt ağacı | Kim, ne, süre, son kullanım; capacity etiketi: "for their own use" / "on behalf of *Acme*" |
| **Your authority** | "Ben neyi, kimden, hangi sıfatla tutuyorum?" | Viewer'ın holding'leri (extensional ve rule-shaped), effective authority | Ne, kimden (grantor/rol), sıfat ("as yourself" / "on behalf of Acme"), seçim nedeni (rule-shaped ise), süre, limit |

Her satırın **eylemleri viewer'ın authority'sinden türetilir** (XI-11): grantor için Revoke/Narrow/Edit (genişletme ayrı); kök (self-anchor root) için ek olarak Suspend (restriction overlay'i koyma yetkisi varsa) ve "End this agent's running copies" (agent'ın self-anchor root'u viewer ise); holder için Give back / Turn off for me. Viewer'ın yapamadığı eylem gizlenmez, "Who can: …" olarak gösterilir.

**Tamlık kuralı.** "Benim verdiklerim" kesiti provenance'a göre **tamdır**: viewer'ın grantor olduğu (veya kendi holding'inden/root'undan türeyen) her Grant, capacity'si ne olursa olsun, en az bir grupta görünür ve Revoke/Narrow iki adım içindedir (XI-5). Capacity her satırın etiketidir (XI-10); gruplama bu tamlığı bozamaz. Bu yalnız lineage + AgencyTerms sorgusudur; yeni derived state yoktur. Aynı Grant admin'in org merceğinde ("Acting for Acme", §8.17.7.6) de görünebilir: bu iki ayrı fact değil, aynı satırın iki görünümüdür.

**Alt ağaç.** Bir satır açıldığında viewer'ın verdiği Grant'tan türeyen alt delegation'lar görünür ("Agent A passed part of this to Sub-agent B: ≤ 1,000 TRY"). Gerekçe: grantor cascade ile alt ağacı zaten etkiler (INV-5) ve principal kendi adına hareket edenleri görebilmelidir (Work S20). Bu varsayılan görünürlük bir ürün kararıdır (X31); daha sıkı varsayılanlar Security'de belirlenebilir.

**One ayrıcalıksızdır.** One listede bir agent olarak görünür; Grant'ları, limitleri ve son kullanımı diğer agent'larla aynı biçimde gösterilir. Sabitlenmiş/üstte gösterilmesi bir deneyim tercihidir; görünürlükten muaf olması değildir (E23, E24).

##### 8.17.7.2 Cross-product ve cross-domain envanter

| Konu | Karar |
|---|---|
| **Kaynak** | Her satır, Grant'ın bulunduğu AuthorityDomain'in authoritative kaydından türeyen bir projection'dır. Envanter bir source of truth değildir; çelişkide domain kazanır (C2, EI-1) |
| **Freshness** | Uzak domain'den gelen satırlar "as of 14:05" taşır; stale ise "may have changed — couldn't reach *domain*" |
| **Erişilemeyen domain** | Satır UNKNOWN durumuna geçer: "Current status unknown (*Acme Access* unreachable)". Bu durumda revoke düğmesi çalışmaz ve "Couldn't revoke — *Acme Access* is unreachable. Your request was not recorded." yazar; revoke **kuyruğa alınıp "pending" gösterilmez** (E25, XI-16) |
| **Domain/provider etiketi** | Tek domain'li kullanıcıda gizli; çok domain'de satır başına ("Personal", "Acme", "Shop M") |
| **Discovery** | Kullanıcının hangi domain'lerde ilgili kayıtları olduğunu global bir Party registry olmadan nasıl bulacağımız Technical/Protocol sorusudur (§8.17.14 OQ3). Deneyim kararı: envanter, bilinen domain'leri listeler ve "Not shown: domains you haven't connected" uyarısını taşır; tam olduğunu iddia etmez |
| **Work bağı** | Commitment-scoped Grant satırı CommitmentRef'e link verir ve Work'ten Commitment'ın durumunu (Work rozetiyle) gösterir; Access Commitment state'i tutmaz (E8) |
| **Payment scheme artifact'ları** | "Merchants that can charge you" satırı Access Grant'ıdır; scheme mandate/consent (SEPA/UPI/PSD2) Pay'in ekranında ayrı bir nesne olarak, Grant'a link ile gösterilir; iki kayıt birleştirilmez (E21) |

> Tablodaki "Erişilemeyen domain" satırındaki "Couldn't revoke … not recorded" metni yalnız bu nonce için hiçbir deneme gönderilmemişse kullanılır: ilk deneme, transport bağlantısı kurulmadan, aracı yok. İstek gönderilmiş ve cevap gelmemişse "Not confirmed — checking" gösterilir ve aynı nonce'la retry/sonuç sorgusu yapılır (§8.13). Kuyruklu veya pending revoke yoktur.

##### 8.17.7.3 Revoke: impact preview

Revoke bir narrowing eylemidir: kullanıcının herhangi bir authenticated yüzeyinden, en fazla iki adımda yapılabilir (XI-5). Önce derived impact gösterilir ("What does revoking G affect?"):

```text
Revoke "Agent A — payments up to 2,000 TRY/day, on your behalf"?
  From now on, new requests by Agent A using this are refused.          (Access, at commit)
  Also ends:  1 delegation Agent A passed on (Sub-agent B, ≤1,000 TRY)    (cascade, derived)
              New requests from 2 running copies using this authority    (exercisability)
  Open tasks: Agent A's running task may continue steps already allowed  (if its runtime follows
              until 14:30 (its next authority check); after that, new     its declared contract)
              steps are refused.
  Offline:    1 offline pass may be honored until 18:00 at the latest    (if the device follows
                                                                          its declared profile)
  Not changed: 14 past uses stay in your history as valid at their time.
               This doesn't change Work commitments; Work shows their status.
  [ Revoke ]   [ Narrow instead ]   [ Suspend instead ]*
  * yalnız viewer restriction koyma yetkisine sahipse
```

"Open tasks" satırı, mevcut derived state'in (revocation impact + staleness exposure) açık reusable Decision'ları da kapsayan render'ıdır: G'yi basis'inde taşıyan her açık ALLOW'un ValidityContract horizon'u en geç kontrol zamanıyla gösterilir (CI-9, E31). **"Can't use this" ifadesi yalnız açık ValidityContract veya projection yoksa yazılabilir** ("From now on, Agent A can't use this."). Work satırı Work'ün fact'ini beyan etmez; Commitment durumu Work rozetiyle Work'ten okunur (E25).

##### 8.17.7.4 Aftermath paneli

Commit sonrası panel, her satırı kendi owner'ından gösterir:

| Satır | Örnek | Owner | Asla |
|---|---|---|---|
| Authority | "Revoked 14:03:12. New requests by Agent A using this authority will be refused." Açık reusable Decision varsa: "Steps already allowed may continue until 14:30 (next authority check), if its runtime follows its declared contract." | Access (derived exposure; UNDER DECLARED CAPABILITY) | "Agent stopped"; açık horizon varken "can't use this anymore" |
| Running work | "Agent A is still running a task (reported by its runtime)." / "Paused (confirmed by runtime 14:03:40)." / "Runtime hasn't reported — status unknown." | Executor (Work Live üzerinden) | Executor teyidi olmadan "stopped" |
| Next step | Horizon'dan önce: "Steps within what was already allowed are within the declared window until 14:30." Horizon'da ve sonra: "Its next authority check (14:30) will be refused. Any effect after that, outside what was allowed, or not tied to an allowed use is outside authority; Access can't physically prevent it." | Access (semantik) | "Agent can no longer do anything"; pencere içindeki conformant kullanımı "outside authority" diye etiketlemek |
| Offline | "POS-7: confirmed applied 14:05 (terminal report)." / "Unknown — honored at most until 18:00 if profile is followed." | Verifier Claim / derived exposure | "Updated everywhere" |
| Delivery | "Notified 3 systems (Relay)." | Relay | Delivery'nin "applied" sayılması (E30) |
| History | "Past uses remain valid history." | Access | Geçmişin silinmesi/geri alınması (INV-23) |

Executor durumu bilinmiyorsa ve iş bir Work Commitment'ına bağlıysa, Work bunu Needs Attention'a "Agent may still be running after you revoked its authority" olarak alabilir; dikkat kararı Work'ündür, içerik Access ve Executor fact'lerindendir.

##### 8.17.7.5 Suspend, Narrow ve "Stop" düğmesi

| Eylem | UI (EN / TR) | Canonical | Geri alınabilir mi | Kim yapabilir |
|---|---|---|---|---|
| **Revoke** | Revoke / Yetkiyi kaldır | `grant.revoke` (terminal, cascade) | **Hayır** — yeniden yetki = yeni delegation (C17) | Grantor, lineage üst holder'ları, root, `grant.revoke` Grant'ı olan |
| **Narrow** | Narrow / Daralt (ör. limit 2,000 → 500) | `grant.amend` narrowing (consent yok) | Geri genişletmek = genişletme eylemi (trusted surface, daha sıkı) | Grantor lineage'ı, root |
| **Suspend** | Suspend / Askıya al | RestrictionPolicy veya Instance restriction overlay (INV-6) | Evet; kaldırmak genişletme sınıfıdır (trusted surface) | Restriction koyma yetkisi olan (scope root, `policy.set` / `instance.*` Grant'ı); yoksa seçenek görünmez |
| **End instances** | End this agent's running copies / Çalışan kopyaları kapat | `instance.terminate` | Hayır | Instance'ın Party'si, Party'nin self-anchor root'u, `instance.terminate` Grant'ı olan |
| **Pause / Cancel / Take control** | **Work/Executor'ındır** | Executor control (Work §15) | Executor'a göre | Work control akışı |

**"Pause" kelimesi Access eylemleri için kullanılmaz** (X13). Work Live'daki bir agent için tek "Stop" düğmesi sunulabilir; bu, iki ayrı eylemin ortak *etkileşimi*dir ve sonuç iki ayrı satırla gösterilir:

```text
[ Stop Agent A ]  →  1) Work/Executor: pause request        → "Pause requested… confirmed 14:03:40" | "not supported by this runtime" | "unknown"
                     2) Access: suspend or revoke (seçim)   → "Authority suspended 14:03:12 (Access)"
```

Executor pause desteklemiyorsa bu açıkça yazar (Work §15.2); ortak düğme hiçbir zaman tek bir "Stopped" durumu üretmez.

##### 8.17.7.6 Rule-shaped holding'ler ve org adına envanter

- Bir organizasyon Instance'a sahip değildir; org adına envanter, org'un authority'sini yönetme yetkisi olan admin'lere S2'nin org merceği olarak gösterilir: "Acting for Acme" (FOR(Acme) holder'ları), "Acme's roots", "Roles". Bir çalışanın Acme adına verdiği bir delegation hem bu mercekte hem çalışanın kendi "Shared from you" grubunda ("on behalf of Acme") görünür; bu aynı satırın iki görünümüdür, iki fact değil (§8.17.7.1 tamlık kuralı).
- Rule-shaped bir Grant'ın satırı holder'ları liste olarak değil seçici olarak gösterir ("Everyone HR lists in Finance — currently 14"); kişi listesi derived ve "as of" etiketlidir.

##### 8.17.7.7 Yenileme ve sona erme

- Süresi yaklaşan ve kullanılan bir delegation envanterde "Ends in 3 days — used 12 times this week" olarak işaretlenir; bir Commitment ona bağlıysa Work bunu Briefing/Needs Attention'a alabilir.
- **Otomatik yenileme yoktur.** Validity uzatma genişletmedir; "Renew" S1'i mevcut içerikle ve yeni bitişle açar, kullanıcı exact preview'ü onaylar. Expired bir Grant uzatılamaz; "Renew" orada "Create again" olur.

#### 8.17.8 Explanation Experience (why / why not / what is needed)

##### 8.17.8.1 İlkeler

> Bu tablodaki E-1…E-7 yerel açıklama ilkesi etiketleridir. Ecosystem kararları E1–E40 ve §13.11 epoch satırlarıyla (EP-n) karışmaması için başka bölümlerden "§8.17.8.1 E-n" diye atıf yapılır.

| # | İlke | Dayanak |
|---|---|---|
| E-1 | **Açıklama derived'dır.** Geçmiş bir karar için DecisionRecord'dan (cited proofs + StateBasis), varsayımsal bir soru için advisory evaluation'dan üretilir; ikisi etiketle ayrılır: "Why this was allowed (at 14:02)" vs "Would this be allowed now?" | C30, C31, INV-22 |
| E-2 | **Advisory sonuç söz değildir.** "Would be allowed now" bir sonraki isteğin ALLOW alacağını garanti etmez; state, budget ve claim'ler değişebilir. UI "will be allowed" yazmaz | Decision ≠ Credential (L17) |
| E-3 | **Her "hayır"ın owner'ı vardır.** Bir eylemin yapılamaması Access DENY'ından, Work autonomy'sinden (require-Gate/deny), domain eligibility'sinden (ör. "order not refundable"), Pay/Money finansal limitinden veya Executor capability eksikliğinden gelebilir. "Why?" paneli bunları ayrı satırlarda, owner rozetiyle gösterir; birini diğerinin ağzından söylemez | E25 |
| E-4 | **Viewer'ın authority'si kadar.** Açıklama, viewer'ın görmeye yetkili olmadığı Party'leri, Grant'ları, policy içeriğini veya Claim gövdelerini göstermez; yerine "a restriction set by your organization" gibi sınıf düzeyinde ifade kullanır | E26 |
| E-5 | **İki parçalı neden.** Rule-shaped veya foreign authority'de "neden" her zaman authority yolu + seçim beyanı olarak ayrı gösterilir | INV-16, L6 |
| E-6 | **Eksik olan yapılandırılmıştır.** REQUIRE_ACTION her zaman "ne gerekiyor + kim/ne karşılayabilir + nerede yapılır" olarak gösterilir; DENY "kim değiştirebilir" olarak | RequirementTerm |
| E-7 | **Agent'lara açıklama veridir, talimat değildir.** Agent'a dönen açıklama typed reason ve remediation kodlarıdır; serbest metin agent için instruction kaynağı olamaz | Work §17.4, S2 |

##### 8.17.8.2 Kategoriler

| Kategori | Decision | Kullanıcının gördüğü (örnek) | "What is needed" | Kim çözebilir |
|---|---|---|---|---|
| Kapsayan authority yok | DENY | "Agent A has no authority to send payments to new recipients." | Yeni veya genişletilmiş delegation | Kaynağı tutan (grantor/root) |
| Instance sınırı dışında | DENY | "This running copy of Agent A isn't set up to make payments." | Instance limits'in genişletilmesi (`mandate.rebind`, fresh confirmation) | Agent'ın Party'si, kendi Instance'ı üzerinden (C14); operatör yalnız iletişim/konfigürasyon tarafıdır, actor değildir (§7.9.7.1) |
| Restriction | DENY / REQUIRE | "Blocked by an Acme restriction: payments outside business hours." | Kısıtın kaldırılması (genişletme) veya bekleme | Restriction'ın sahibi |
| Requirement eksik: approval | REQUIRE_ACTION | "Needs 1 approval from a Finance approver (not the requester)." | Contribution | Eligible set (Needs Attention'da) |
| Requirement eksik: step-up | REQUIRE_ACTION | "Confirm it's you (passkey) — needed within 5 minutes for this payment." | Fresh authentication Claim | Actor'ün kendisi |
| Requirement eksik: claim/posture | REQUIRE_ACTION | "Your device's compliance statement (from Acme MDM) is older than 24h." | Fresh Claim | Issuer / cihaz |
| Beyan bayat (rule-shaped) | REQUIRE_ACTION | "HR's statement about your team needs refresh. Your role is not removed." | Fresh selection Claim | Issuer |
| Budget tükendi | DENY | "Agent A reached its 2,000 TRY daily limit; resets at 00:00." | Bekleme veya limit artırma | Grantor |
| Revoked / expired / ended | DENY | "Your delegation to Agent A was revoked on 6 Oct, 14:03, by you." | Yeni delegation | Grantor |
| Source not accepted | DENY | "Statements from *X* aren't accepted here for selecting members." | Acceptance (reserved) | Domain admin(ler) |
| Schema version not accepted | DENY | "This app uses a newer version of 'refund' that Acme hasn't accepted yet." | `acceptance.amend` (exact digest) | Domain admin |
| Foreign status unknown | REQUIRE / DENY | "Can't confirm Partner Co.'s authority right now." | Fresh foreign proof | Foreign domain |
| Capacity uyuşmazlığı | DENY | "Agent A tried to act on your behalf using authority it holds for itself." | Doğru basis/capacity ile yeni istek | Agent |

##### 8.17.8.3 Owner composition: "Why can't the agent do this?"

```text
Why can't Agent A refund order #8812 (600 TRY)?
  Access   ✗ Over its refund limit: Agent A may refund ≤ 500 TRY per order (given by Store Manager, role Support v2)
  Commerce ✓ Order is refundable (Commerce says, 14:01)
  Work     — Commitment "Resolve complaint #331" is active; refunds over 250 TRY need a Gate (team policy)
  Pay      — not reached
  What could change this: approving can't raise a limit.
                          A store manager can give access once for a refund up to 600 TRY, or raise the limit.
                          (Access will still check the refund.)
```

Panel üç kural uygular: (1) her satır kendi owner'ının cevabıdır; (2) satırların sırası kullanıcı için "en yakın çözüm" sırasıdır, owner önceliği değildir; (3) "what could change this" yalnız gerçekten mümkün canonical eylemleri sayar (§8.17.5.2 tablosu).

##### 8.17.8.4 Derinlik

| Seviye | İçerik |
|---|---|
| **Default** | Tek cümlelik karar + en yakın çözüm + kim çözebilir |
| **Expert** | Authority yolu (root → rol/delegation zinciri), capacity, seçim beyanı ve kaynağı, uygulanan requirement'lar ve kısıtlar, budget halkaları, instance limits |
| **Audit** | DecisionRecord: StateBasis (okunan nesneler ve sürümleri), cited Claim/Acceptance/policy sürümleri, trusted evaluation time, consumption effects, digest'ler; replay (aynı girdi → aynı karar, INV-27) |

##### 8.17.8.5 Ne açıklanmaz

- Başka Party'lerin holding'leri ve graph'ı (viewer'ın authority'si dışında).
- Policy'nin eşik değerleri, viewer'ın onları görme authority'si yoksa (ör. "fraud restriction" sınıf düzeyinde kalır). Açıklamanın bir policy keşif oracle'ına dönüşmemesi için rate ve detay sınırları Security'dedir (§8.17.14 OQ2).
- Claim gövdeleri (yalnız issuer, sınıf, zaman ve gereken değer/özet; E26).
- One memory, Work içeriği, sohbet (EI-15).

#### 8.17.9 Organization Admin Experience

##### 8.17.9.1 Admin'in modeli

Admin bir "süper kullanıcı" değildir; kurumun authority yapısını yöneten, kendisi de aynı modele tabi bir holder'dır. Admin konsolu (S7) kurumun **yetki anayasasını** gösterir: kökler (Anchor'lar ve root kompozisyonu), roller (named AuthoritySet sürümleri), rol delegation'ları (rule-shaped Grant'lar), seçim kaynakları (Acceptance'lar), kısıtlar ve requirement'lar (RestrictionPolicy, rootTerms), korunan eylemler (reserved action'lar ve break-glass Grant'ları) ve tüm değişikliklerin geçmişi (meta-Exercise'lar).

##### 8.17.9.2 Roles & templates

| Etkileşim | Deneyim | Canonical |
|---|---|---|
| Rol tanımlamak | Rol editörü = typed AuthoritySet editörü; "Not included" bloğu reserved action'ları ve gelecekteki action'ları açıkça listeler | Named AuthoritySet (C28), E11 |
| Rolü bir kitleye vermek | "Give *Finance Approver v4* to: everyone HR lists in Finance" — seçim kaynağı ve kabul durumu görünür | Rule-shaped Grant + subject-selection Acceptance (C13) |
| Rolü değiştirmek | Yeni sürüm oluşturulur; mevcut Grant'lar eski sürümde kalır; **change-impact preview**: "Moving 3 role delegations to v5 gives 41 people a new ability: *refund > 5,000 TRY*; removes 1 ability from 12 people." Geçiş explicit, toplu `grant.amend`; genişletme içeren geçiş genişletme requirement'larını taşır (quorum/assurance) | C28, INV-10; Cedar change-analysis ilkesi |
| "Admin" rolü | Admin Grant'ı kapsadığı meta-action'ları tek tek gösterir; reserved meta-action'lar (`acceptance.*`, `anchor.*`) ayrı, pin'li Grant'lar ve quorum ister | — |

**Yasak etiketler:** "Full access", "All permissions", "Owner (can do anything)", "Global admin". Doğru biçim: "All non-protected actions in *commerce* as of catalog v12 — future actions not included."

##### 8.17.9.3 Sources (Acceptance)

Kaynak kabul ekranı, Acceptance'ın **use** boyutunu sade dille ve **blast radius**'u ile gösterir:

| Use (canonical) | UI etiketi | Ekranda gösterilen sonuç |
|---|---|---|
| `actor-binding` | "Sign-in source" | "People in *corp-x* can sign in with Acme IdP. If this source is compromised, someone could act as those people — within what they already hold." |
| `predicate-input` | "Fact source" | "Statements from Commerce can be used as conditions and restrictions. They can't give anyone authority." |
| `subject-selection` | "Membership source" (**protected**) | "HR's statements will decide who is in 12 role delegations (ceilings: …). Requires 2 admins." |
| `foreign-authority` | "Partner authority source" (**protected**) | "Partner Co.'s authority will be recognized up to these ceilings: …" |
| `schema-definition` | "Action definitions" (**protected**) | "Accept *refund v3* (fingerprint …). The publisher declares it narrows v2; Access can't verify the meaning — this relies on trusting the publisher." |

Aynı kaynağın bir use için kabulü başka bir use için kabul değildir ve ekran bunu "This doesn't make Acme IdP a membership source" diye yazar (INV-15). "Trusted source" ifadesi kullanılmaz; "accepted for *use*" kullanılır.

> Access'in kendi realm'i de bu ekranda bir "Sign-in source" olarak görünür. Kendi realm'i için de use-typed Acceptance gerekir; realm'in grup/SCIM claim'leri "Membership source" için ayrı ve korunan bir kabul ister.

##### 8.17.9.4 Korunan eylemler ve break-glass

- Reserved action'lar "Protected action" rozetiyle gösterilir: "Only delegations that name this action explicitly can include it."
- Break-glass bir Grant'tır (önceden verilmiş, reserved, requirement'lı, zaman sınırlı; INV-28): "Emergency access: Security on-call can terminate any instance for 4 hours after 2 approvals; every use is reviewed." Exercise dışı "kill switch" yoktur (§7.9.12.1).

##### 8.17.9.5 Governance değişikliklerinin koordinasyonu

Reserved bir değişiklik (ör. yeni membership source) quorum istediğinde, ilk admin'in isteği REQUIRE_ACTION döner. **Diğer admin'lerin katkısını toplamak Access'in değil coordinator'ındır**: Suiss'te bir Work Gate (ör. "authority change request" Commitment'ı; Practice ile şablonlanabilir) veya kurumun IGA aracı. Admin konsolu bu Gate'i gömülü gösterebilir (packaging ≠ ownership, L3); onay töreni S3'tür. Access'te "pending change" kuyruğu yoktur (X5, X20).

##### 8.17.9.6 Offboarding (departure) ve JML

| Adım | Deneyim | Canonical |
|---|---|---|
| HR çalışanı çıkarır | Rule-shaped holding'ler otomatik kapanır (affirmative); admin Changes'da görür: "E's Finance role ended (HR, 6 Oct)" | Episode kapanışı (INV-31) |
| Kalan kanallar | **Offboarding sayfası** E'nin bütün kanallarını listeler ve her biri için explicit seçim ister — varsayılan yok: doğrudan Grant'lar (keep / revoke), Instance'lar (terminate), rule-shaped holding'ler (retain / exclude from selector / restrict), self-anchor (retire / transfer), yeniden giriş (allowed / blocked) | E6, EI-8 |
| Uyarı | "3 delegations given directly to E survive HR's change. Decide for each." | Extensional Grant HR'a bağlı değildir |
| E'nin verdikleri | "E gave 2 delegations to agents; they end with E's role (derived) / they stay (E's direct grant) — see each." | Cascade derived |

Offboarding tamamlanmadan "Offboarded" etiketi gösterilmez; tamamlanmış hâli, departure Exercise'ının commit'idir.

##### 8.17.9.7 Domain, provider ve containment

- **Domain sayfası**: constitution özeti (meta-anchor root kompozisyonu, rootTerms), provider (custody, root değil: "Hosted by Suiss Access — the host holds no authority here", INV-29), handover/recovery geçmişi.
- **Forced migration sonrası**: "Recovered from previous provider at record position N (6 Oct 11:02). Changes after that point may be lost. Revocations made after 11:02 must be repeated." Root'un recovery Exercise'ında beyan ettiği risk aynen gösterilir; "nothing was lost" denmez (E20).
- **Containment (security)**: SOC'un `instance.*`/`grant.revoke`/restriction Exercise'ları S9'dan S4'e gider; aftermath paneli aynıdır.

##### 8.17.9.8 Gizli yol yok

- **Impersonation / "view as user" yoktur.** Destek erişimi, kullanıcının kendi verdiği zaman sınırlı bir delegation veya reserved break-glass Grant'ıdır; her ikisi de kullanıcının envanterinde görünür.
- **Toplu işlemler** (bulk revoke, bulk amend) tek bir eylem değil, her biri attributable Exercise olan bir kümedir; preview her birinin etkisini toplar.
- **"Sync from HR"** bir kısayol değil, kabul edilmiş bir membership source'un normal etkisidir ve rol satırında kaynağıyla görünür.

> - Destek erişiminin modeli ve deneyimi §8.16'dadır: 12 değişmez POLICY DEFAULT'tur.
> - Identity plane yönetimi (client, upstream IdP, realm config) de gizli yol değildir; her değişiklik bir Exercise'tır (E34).
> - Devredilmiş yönetimin dersleri §12 TN-Y2'dedir: hiyerarşi taşıma iki uçta izin ister, credential sahip alanı değişmez, mapper'lar yükseltme yüzeyidir, kiracı başı FGAP bayrağı vardır.
> - Yönetim API'sinde kullanıcının credential'ını doğrudan yazan uç nokta yoktur (§12).

#### 8.17.10 Developer Experience

##### 8.17.10.1 Developer'ın modeli

"Benim ürünüm kendi effect'inin PEP'idir; her consequential effect'ten önce actor'ün kendi Exercise'ı için karar ister veya doğrular. Ben action vocabulary'mi ve typed parametrelerimi yayınlarım; domain'ler onları kabul eder. Authority yaratmam, kimsenin yerine istekte bulunmam." (E16, E17)

> Identity plane'in developer merceği şunları ekler: OIDC/SAML client kaydı, redirect URI, imza algoritması seçimi (MD-3), pairwise/public `sub` seçimi (MD-10). Bunlar realm config değişiklikleridir (E34) ve developer konsolunda aynı "advisory ≠ promise" ve "fail-open yok" kurallarına tabidir. Protokol ayrıntısı §10'da, yönetim API'si §12'dedir.

##### 8.17.10.2 Schema publishing → domain acceptance

```text
Developer (publisher)                         Domain admin
  publish namespace + typed schema v3          sees in Sources ▸ Action definitions:
  • her authority-relevant parametre             • diff v2 → v3 (typed)
    closed type'a eşlenir (E12)                   • parametre sınıfları (relevant / opaque)
  • parametre sınıfı: relevant | opaque          • reserved bayrakları
  • reserved bayrakları                          • publisher'ın compatibility beyanı (Claim)
  • compatibility beyanı (narrowing …)           • "Access can't verify meaning: publisher trust"
                                               accept (reserved acceptance.amend, exact fingerprint)
```

| Kural | Deneyim |
|---|---|
| Publisher kendi schema'sını hiçbir domain'de kendisi kabul edemez (o domain'in admin authority'si yoksa) | Console "Pending acceptance in: Acme, Shop M" gösterir; kabul düğmesi yoktur |
| Authority-relevant ama tipe eşlenemeyen parametre | Console yayın öncesi uyarır: "`note` affects who receives money — map it to a recipient type or it will be rejected" (E12) |
| Yeni sürüm mevcut Grant'ları değiştirmez | "Existing delegations stay on v2 in each domain until the domain accepts a mapping or delegations are updated" (E10) |
| Namespace'e yeni action | "Not included in existing delegations that use `commerce.*` (catalog pinned at issue)" (E11) |

##### 8.17.10.3 PEP entegrasyonu

| Kural | Neden | Deneyim |
|---|---|---|
| **Actor = basis holder'ın Instance'ı; PEP actor değildir** | E17 | SDK isteği actor Instance'ın proof'uyla kurar; PEP'in kendi servis kimliğiyle kullanıcı adına istek kurma yolu yoktur |
| **Zincirleme effect'ler** | E17, §7.9.7.4 | Downstream intent upstream ExerciseID'yi taşır; console, causal-bound allowance ve upstream RestrictionPolicy kurulmamışsa "Chain link is audit-only in this domain (not enforced)" uyarısını gösterir |
| **Fail closed** | E25, INV-26 | SDK'de Access erişilemezken "allow" seçeneği yoktur; geçerli ValidityContract/offline slice içinde yerel karar ancak domain projection çıkarmışsa |
| **Verifier profile** | E13 | Developer verifier'ının profilini beyan eder (conformance Claim); hangi profile ile projection çıkarılacağı domain'in kararıdır; console bunu "requested: offline 4h · domain granted: intermittent 15 min" diye gösterir |
| **Effect attestation** | EI-10 | SDK attestation'ı ExerciseID'ye bağlar; "unknown" bir sonuç değeridir, hata değil |

##### 8.17.10.4 Decision lab

| Araç | Ne yapar | Etiket |
|---|---|---|
| **Check** | Advisory evaluation: "Would this intent be allowed for this actor now?" | "Advisory — not recorded, not a promise" |
| **Explain** | S5'in developer derinliği: reason class, unmet terms, authority yolu (developer'ın görme yetkisi kadar) | — |
| **Replay** | Geçmiş bir DecisionRecord'u kendi StateBasis'iyle yeniden değerlendirir; aynı sonucu üretmesi beklenir (INV-27); farklıysa evaluator uyumsuzluğu bulgusu | Audit yetkisi gerekir |
| **Sandbox** | Test, ayrı bir AuthorityDomain'de (kendi genesis'i) yapılır; "test mode" bayrağı yoktur, prod authority sandbox'a veya tersine akamaz | Sandbox = ayrı domain (L25) |
| **Conformance** | PEP / verifier / Approval Surface conformance testleri | Conformance ≠ endorsement (Work §21.8) |

##### 8.17.10.5 Developer'a asla

- "fail open", "bypass for testing", "service account acts for user" seçenekleri.
- Başka tenant/domain kararlarının görünürlüğü (yetki yoksa).
- Advisory sonucun cache'lenip token gibi kullanılmasını öneren örnekler.

#### 8.17.11 Attention Model

##### 8.17.11.1 İlkeler

1. **Approval fatigue bir güvenlik problemidir.** Her gereksiz onay, gerekli onayın değerini düşürür (MFA bombing, Bybit). Hedef onay sayısını azaltmak değil, her onayı *anlamlı* kılmaktır: yalnız bir requirement veya Gate gerçekten varsa, consequence'a göre sıralı, exact render ile.
2. **Tek dikkat evreni.** İnsan eylemi gerektiren her şey Work'ün Needs Attention'ına girer (veya compatible coordinator'ın eşdeğerine); teslimat Relay'indir. Access semantic event *içeriği* üretir (ne değişti, hangi Grant/Exercise, kime authority açısından ilgili) ve bu içerik bir görev değildir (E30, X5).
3. **Ranking Work'ündür.** Consequence of waiting, risk/impact radius, irreversibility, deadline, evidence weakness, accountability position (Work §14.2). Access'in ranking'e katkısı yalnız fact'tir: intent'in sınıfı, tutarı, reserved olup olmadığı, budget'a yakınlığı.
4. **Requester aciliyet beyan edemez.** Agent veya requester bir authority talebini "urgent/unshelvable" yapamaz (Work S12).
5. **Sessizlik onay değildir.** Veto penceresi ancak önceden verilmiş bounded autonomy olarak vardır; sessizlik sonradan authority yaratmaz (Work §9.4, S10).
6. **Tekrar, politikaya dönüşür — sessizce değil.** Aynı sınıfta tekrar eden onaylar bir *öneri* doğurur: "You approved 6 similar refunds ≤ 200 TRY this week. Give Agent A access to do these without asking?" Kabul, S1'de exact preview'lü bir delegation (Access) ve/veya Work autonomy Declaration'ıdır (Work principle 13). Öneri hiçbir zaman kendiliğinden yürürlüğe girmez (XI-19).

##### 8.17.11.4 Fatigue kontrolleri (deneyim düzeyi)

| Kontrol | Sahibi | Not |
|---|---|---|
| Consequence-ranked tek kuyruk, root-cause grouping, attention budget | Work | Work §14.2 |
| Aynı intent için tekrar tekrar istek → tek item; DENY'dan sonra aynı nonce yok | Work (dedup) + Access (C30) | A-3 |
| Tekrar → explicit delegation/autonomy önerisi | Experience (öneri), Access/Work (kabul) | XI-19 |
| Yüksek sonuçlu onay bildirimden yapılamaz; batch yok | Experience + Access requirement | §8.17.6.3 |
| Onay ekranında "what this does / doesn't do" satırı | Experience | Blind approval'ı azaltır |
| Requester başına istek oranı, push-bombing koruması | Work + Security | Eşikler §8.17.14 OQ2 |
| Login push'ta sayı eşleştirme zorunlu (aynı cihaz istisnası); login push ile authority onayı ayrı şablonlar | Identity plane | Kanıt: Lapsus$/Uber olayları, Microsoft zorunlu sayı eşleştirmesi. Etkinliğin sayısal kanıtı doğrulanamadı |

#### 8.17.12 Best-of-Breed Experience Adaptations

Rakibin yüzeyi kopyalanmaz; underlying need bulunur. **Epistemik not:** Primary kaynakla doğrulanmış sistemler: AuthZEN, PSD2 Art. 5, SPC, CIBA, Entra PIM/Teleport, UK OB/Berlin Group, AP2, Stripe SPT, Bybit, MFA bombing. Diğer ürün desenleri (OS permission prompt'ları, Google/Apple third-party access sayfaları, GitHub fine-grained token'lar, Slack uygulama izinleri, agent platformlarının tool approval'ı, 1Password paylaşım UX'i) **yaygın bilinen desen** olarak anılır ve primary kaynakla yeniden doğrulanmadı; karar desenin kendisine aittir, vendor'ın bugünkü implementasyonuna değil.

| Kaynak desen | Underlying need | Karar | Suiss uyarlaması | Reddedilen kısım |
|---|---|---|---|---|
| **OS permission prompt'ları** (just-in-time, "allow once / while using / always", precision narrowing ör. yaklaşık konum) | İzni ihtiyaç anında ve bağlamında istemek; daha dar alternatif sunmak | **ADAPT** | JIT authority request (§8.17.5.2): "Approve this request" / "Give access once" / "Give access for similar…" — her biri canonical eyleme eşli, hiçbiri Access'in ALLOW'unu vaat etmez; dar alternatif (bu sipariş için, bu tutara kadar) varsayılan öneri | Uygulamanın yazdığı purpose metninin bağlayıcı içerik sayılması; "always" tek dokunuşu (→ exact preview'lü delegation) |
| **OAuth consent ekranları** | Bir uygulamaya bağlanırken neyin verildiğini görmek | **ADAPT** (ihtiyaç) / **REJECT** (scope listesi) | S1 exact preview: typed bounds, capacity, süre, "not included"; requester kimliği "accepted source says …" ile | Akıl yürütülemeyen scope listeleri (F9), süresiz consent (F19), consent phishing'e açık "verified app" rozeti |
| **Google/Apple "third-party access" sayfaları** | Kime ne verdiğimi tek yerde görmek ve iptal etmek | **ADOPT** (ihtiyaç) | Authority hub: "Acting for you" + "Shared from you" (capacity'den bağımsız tam "given by you" kesiti; "on behalf of *Acme*" satırları dahil), son kullanım, iki adımda revoke + dürüst aftermath + alt ağaç | Provenance/capacity'siz düz liste; "removed access" deyip çalışan işi gizlemek |
| **Entra / Okta admin konsolları, PIM/Teleport access requests** | Effective access ve "neden"; eligible ≠ active; JIT elevation | **ADAPT** | S7 people/roles + S5 iki parçalı neden; JIT = requirement'lı standing Grant + Gate | Süper roller ("Global Administrator"), rol patlaması, PIM aktivasyonunun rutinleşmesi (F18) |
| **IGA access review / certification** | Periyodik yeniden doğrulama | **WRONG LAYER** (kampanya) / **ADAPT** (veri) | Access "who/why/revoke impact" sorgularını sağlar; reviewer'ın kararı Exercise'tır | Kampanya UX'inin Access'te olması (E22) |
| **1Password / vault paylaşım UX'i** | "Bu kasaya/öğeye kim erişiyor" ve hijyen uyarıları | **ADAPT** (hijyen) / **WRONG LAYER** (custody) | Envanter hijyeni: kullanılmayan, süresi yaklaşan, geniş delegation'lar Briefing/Changes'da | Secret custody (E22) |
| **Payment SCA / PSD2 dynamic linking / W3C SPC** | Gösterilen tutar ve alıcıya bağlı onay | **ADOPT** | S3: exact intent render + digest binding; intent değişirse onay geçersiz | Genel "Confirm?" metni |
| **CIBA / number matching / push bombing dersleri** | Decoupled onay; yorgunluk saldırısına direnç | **ADAPT** | Bildirim yalnız davet; yüksek sonuçlu onay trusted surface'te; requester aciliyet beyan edemez | Bildirime tek dokunuşla yüksek sonuçlu onay |
| **GitHub fine-grained tokens** (resource ve action seçimi, zorunlu süre, org onayı) | Dar, süreli, kaynak bazlı yetki; org'un kabul kontrolü | **ADAPT** | S1'de resource/action seçimi, agent delegation'ında zorunlu bitiş (X10); org kısıtları RestrictionPolicy/downstreamHolderClass ile | Klasik geniş token'lar; token = authority (Decision ≠ Credential) |
| **Slack/Teams uygulama izinleri** (kurulumda geniş izin; admin onaylı uygulamalar) | Kurum, hangi uygulamalara yetki verilebileceğini belirlemek ister | **ADAPT** / **REJECT** | Kurum kısıtı: "Members can delegate to apps in this list only" (RestrictionPolicy/downstreamHolderClass) | Kurulum anında geniş, süresiz izin |
| **Agent platformlarının tool approval'ı** ("allow once", "always allow this command", auto-approve modları) | Agent'ın her adımında sormadan güvenli ilerleme | **ADAPT** / **REJECT** | "Allow once" ihtiyacı → "Approve this request" veya "Give access once" (canonical eşli; Access'in kararı ayrı); "always allow" → bounded delegation + Work autonomy önerisi (XI-19) | Örtük auto-approve modları (Work §23.3 "always approve/auto implicit autonomy accumulation"); vendor-session onayının source of truth olması |
| **UK OB / Berlin Group consent nesneleri, bankaların "standing orders / direct debits" listeleri** | Kalıcı ödeme yetkilerini nesne olarak görmek | **ADOPT** | "Merchants that can charge you" (Access Grant) + Pay'de scheme artifact'ı, linkli | Scheme artifact'ını Access Grant'ıyla birleştirmek (E21) |
| **AP2 open/closed mandate, Stripe SPT** | Açık zarf → kapalı exercise; limitli, alıcıya bağlı yetki | **ADAPT** | Delegation (zarf) + exact intent onayı; "mandate" kelimesi Pay'e bırakılır (§8.11) | Ödeme-spesifik ontoloji |
| **Bybit (blind signing, ortak kompromize UI)** | Bağımsız ve sadık render | **ADOPT (ders)** (F13) | Independence şartlarının görünür olması; render yalnız kabul edilmiş schema'dan | Agent/uygulama özetine dayanan onay |
| **Oso Explain / Cedar change analysis** | "Neden?" bir kanıt olmalı; değişiklik etkisi önceden görülmeli | **ADOPT** | S5 proof-tabanlı açıklama; S7 change-impact preview | — |
| **Incident-management attention** (severity ≠ urgency, dedup, escalation) | Dikkati sonuca göre harcamak | **ADOPT via Work** | Work Needs Attention ranking; Access yalnız fact sağlar | Ayrı Access bildirim merkezi |
| **Activity feed'ler** | Okunabilirlik | **REJECT** (feed) / **ADAPT** (ihtiyaç) | Activity (S6) kullanım kaydıdır, gürültü akışı değil; özet Work Briefing'de | Ham olay akışı dikkat yüzeyi olarak |

> Tablodaki "WRONG LAYER (kampanya/custody)" etiketleri "ayrı ürün katmanı" olarak okunur (E22, E33): Access bunların authority kısmına karar verir, olay ve sinyal üretir.

> Bu tablodaki desenlerin bir kısmı birincil kaynakla yeniden doğrulanmamıştır (yukarıdaki epistemik not). MFA yorgunluğu ve sayı eşleştirme için birincil kaynaklı kanıt vardır (Microsoft 13 Şubat 2026 güncellemesi, CISA notu). Uyarı: sayı eşleştirmenin yorgunluk saldırılarını ortadan kaldırdığına dair sayısal kanıt bulunamamıştır.

#### 8.17.13 Cross-Product Experience Backlog

Diğer ürünler için freeze yoktur; yalnız deneyim seam gereksinimleri kaydedilir. Hepsi **Candidate**.

| Idea | Why valuable | Correct owner | Access relationship |
|---|---|---|---|
| REQUIRE_ACTION(contribution) ve "authority missing" DENY'larının varsayılan olarak intent-bound Gate / Condition'a çevrilmesi | Access'in kuyruğu olmadan insan dikkatinin tek yerden girmesi (X5) | Work (Gate policy, Practice) | Unmet terms, eligible set, reason class sağlar |
| Needs Attention item türleri: "approval", "authority missing", "agent may still be running after revocation", "authority expiring for active commitment" | Authority olaylarının consequence-ranked dikkate girmesi | Work | Semantic event içeriği |
| Briefing'de "authority changes affecting this Work" bölümü | Briefing'in authority değişikliklerini göstermesi | Work | Derived events; GrantID linkleri |
| Live'da üç şerit: Authority · Control · Execution | Work §15.1'in görsel karşılığı; "Stop" etkileşimi (§8.17.7.5) | Work + Executor | Authority şeridinin içeriği |
| Approval Surface profile'ının genişletilmesi: tek ceremony → contribution + Work Declaration; ayrıca `grant.issue`/`amend` gibi kullanıcı authority act'lerini kapsaması | Tek tören, iki kayıt; delegation'da da sadık render | Protocol (Work Approval Contract + Access) | Digest/assurance/independence şartları (§8.17.14 OQ1) |
| Tekrar eden onaylardan delegation/autonomy önerisi | Fatigue azaltma (XI-19) | Experience + One (taslak) + Work (autonomy) | S1 exact preview; kabul Access Exercise'ı |
| One'ın NL → typed delegation taslağı ve yorum farkları listesi | Doğal dilde yetki verme, exact preview ile | One (taslak) / Experience | S1; One tetiklemez (E23) |
| Executor: "confirmed paused/stopped" Claim'leri ve control capability beyanının UI'a taşınması | Aftermath panelinde dürüst execution satırı | Executor Contract | Claim olarak tüketir |
| Verifier (POS/edge) "applied" raporları ve saat/profil sağlığı | Revocation exposure'ın ölçülmesi | Domain / Executor / Protocol | Authority-state ack Claim'leri (E30) |
| Pay: "agent spending limit" ekranının Access renderer'ı olması; scheme mandate sayfalarında GrantID linki | Tek limit kaynağı; mandate çakışması | Pay | X28, §8.11 |
| Commerce/Serve personel ekranlarında "Why can't I…?" paneli ve POS offline penceresi | Mağaza personelinin dürüst açıklaması | Commerce / Serve | S5, §8.17.5.8 |
| Identity plane: intent'e bağlı step-up mesajı; recovery mesajları (Instance vs Party) | Step-up ve recovery dürüstlüğü | Access Identity plane | §8.17.5.4, X29 |
| IGA: review UX'inin Access "who/why/impact" sorgularını tüketmesi | Governance'ın pratikte yapılması | IGA / governance uygulaması | Derived sorgular; kararlar Exercise |
| Security tooling: revocation exposure ve unknown-outcome dashboard'ları; açıklama oracle'ına karşı rate/detay sınırları | Güvenlik operasyonu | Security tooling | Derived; Claim'ler |
| Developer platform: actor-instance proof'u zorunlu kılan PEP SDK, sandbox domain kurulumu, decision replay aracı | DX hatalarının önlenmesi | Developer platform / Protocol | X21 |
| Kullanıcı araştırması: provenance/capacity gruplaması, "Approve" / "Give access" / "Allowed" terim ayrımı, asimetrik sürtünme | §8.4 hipotezlerinin doğrulanması | Experience research | Değişirse yalnız kelime/gruplama |

> "Identity plane" satırı backlog değildir; normatif karşılığı §8.15 (X33–X39) ve §12'dir.

#### 8.17.14 Open Questions (en fazla 3)

Product Experience'ın kendi açık sorusu yoktur. Aşağıdaki üç soru yalnız sonraki aşamalara aittir.

1. **Protocol — deneyim sözleşmelerinin encoding'i.** (a) Approval Surface conformance profile'ında tek bir authenticating user act'in hem Access contribution'ını (intent veya Gate payload digest'i) hem Work Declaration'ını nasıl yetkilendirdiği ve aynı profile'ın `grant.issue`/`amend` gibi kullanıcı authority act'lerini nasıl kapsadığı; (b) agent-facing reason class ve typed remediation kodlarının, unmet RequirementTerm'lerin ve viewer-scoped açıklama derinliklerinin wire biçimi; (c) Approval Surface'in authority-opaque gövdeyi intent digest'ine karşı doğrulama biçimi. Deneyim kararları X7, X8, X18, X19'da kapalıdır; açık olan yalnız biçimdir.

2. **Security — dikkat ve açıklama parametreleri.** Bildirim içi hızlı onayın ve düşük sonuçlu toplu onayın izinli olduğu action sınıfları ile assurance eşikleri; requester başına istek oranı ve push-bombing korumaları; eşik altı bölmeye (structuring) karşı varsayılan RestrictionPolicy desenleri; açıklama ve advisory evaluation'ın policy-keşif oracle'ına dönüşmemesi için detay/rate sınırları; X31 varsayılan görünürlüğünün (özellikle alt ağaç ve "Shared from you" kullanım geçmişi) gizlilik açısından sıkılaştırılması gereken durumlar.

3. **Technical Architecture — cross-domain envanter keşfi ve tazeliği.** Global bir Party registry olmadan (E4, EI-7) bir kullanıcının ilgili kayıtları olan AuthorityDomain'lerin nasıl keşfedileceği ve Authority hub'ının bu domain'lerden read federation projection'larını hangi tazelik ve gizlilik sınırlarıyla toplayacağı; projection'ın hiçbir zaman source of truth'a dönüşmeden (XI-3, XI-16) ölçeklenmesi.

### 8.18 Agent-facing contract: karar cevabı ve agent davranış normları A-1…A-12 (tam metin)

**Neden ayrı bölüm.** MD-19.2 gereği agent-facing contract'ın (8.18.1–8.18.4) tam metni burada normatif olarak yer alır. A-1…A-12'nin canonical tanımı bu bölümdür. §9 (Protocol) ve §11 (MCP ve Ajan Kimliği) bu ID'lere buradan atıf yapar: §9.4 MCP satırı (A-7), §9 karar sözleşmesi (A-1, A-7, A-10) ve continuation kuralı (A-8).

**Statü.** FROZEN PRODUCT DECISION (X19'un açılımı). Wire biçimi (reason class encoding, alt kodlar, remediation alanı) Protocol'dedir (§9.5–§9.7). Burada semantik içerik ve davranış normu sabitlenir.

Agent Access'in UI'sız kullanıcısıdır. "Deneyim"i, karar sözleşmesinin biçimi ve agent'tan beklenen davranıştır. Wire formatı ve API Protocol'dedir; burada semantik içerik ve davranış normları sabitlenir.

#### 8.18.1 Karar cevabının içeriği

| Alan | İçerik | Not |
|---|---|---|
| **Outcome** | ALLOW · DENY · REQUIRE_ACTION | UNKNOWN Access'in kendi kararı için yoktur (EI-21) |
| **Exercise referansı** | ALLOW'da ExerciseID; ValidityContract (reusable ise): horizon, next re-check | Decision ≠ Credential; ALLOW yalnız bu envelope için (INV-19) |
| **Reason classes** (DENY) | Başarısız olan **tüm** sınıfların kümesi (tekil değil); semantik sınıflar (§8.17.8.2 ile birebir): `no-covering-authority`, `outside-instance-limits`, `restricted`, `budget-exhausted`, `ended` (revoked/expired/lapsed), `capacity-mismatch`, `source-not-accepted`, `schema-not-accepted`, `nonce-closed`, `foreign-status-unavailable` | Sınıf kümesi sabitlenir; DENY birden çok engel varsa hepsini döner, böylece §8.17.5.2 seçenekleri ve "Would still be blocked by" satırı kümenin tamamından **ve her engelin zincirdeki seviyesinden** (viewer'ın altında / viewer'ın seviyesinde veya üstünde; seviye başına kalan budget ve requirement kaynağı derived'dır, C27) hesaplanır. Requester'a görünürlük E26'ya tabidir (sınıf düzeyinde). Encoding ve alt kodlar Protocol'dedir (§9) |
| **Unmet requirements** (REQUIRE_ACTION) | Her RequirementTerm için: tür (contribution / claim), sınıf, count, binding, freshness, independence; contribution için eligible set (requester'ın görme yetkisi kadar) | — |
| **Remediation type** | Typed, talimat değil: `route-to-coordinator` (contribution/genişletme insan gerektirir), `refresh-claim` (issuer'dan), `self-authenticate` (actor Instance'ın karşılayabileceği), `wait-until(T)` (budget penceresi), `not-satisfiable-by-actor` (ör. insan-varlığı), `new-request-required` | Agent bunlara göre yönlendirir; serbest metin yok |
| **Explanation depth** | Requester'ın authority'si kadar | E26 |

#### 8.18.2 Agent davranış normları (agent-facing contract)

| # | Norm | Gerekçe |
|---|---|---|
| A-1 | **Basis ve capacity açık beyan edilir.** Agent principal işi için `FOR(P)` ile ister; kendi kurumsal authority'sini kullanacaksa `OWN` beyan eder. SDK capacity'siz istek kurmaz | Confused deputy (Work §17.3), INV-4, E9 |
| A-2 | **ALLOW envelope'a bağlıdır.** Herhangi bir parametre değişirse yeni intent, yeni istek | INV-19 |
| A-3 | **DENY o nonce için terminaldir.** Aynı nonce tekrar denenmez; yeni nonce ancak bir state değişikliğinden (yeni Grant, budget reset, fresh Claim) sonra anlamlıdır. Döngüsel yeniden deneme yoktur | C30 |
| A-4 | **REQUIRE_ACTION bir DENY değildir.** Aynı nonce, proof eklenince yeniden değerlendirilir; agent bekler ve coordinator'a typed talebi iletir | — |
| A-5 | **Prose approval değildir.** Agent kullanıcıya "onaylıyor musun?" diye sorup sohbet cevabını approval sayamaz ve sunamaz; contribution yalnız kullanıcının kendi Instance'ından, trusted surface'te olur | E23, EI-18, Work S11 |
| A-6 | **Agent canonical özeti yazmaz.** Coordinator'a typed intent'i gönderir; insanın göreceği render schema'dan gelir. Agent'ın notu "Requester's note" olarak ayrı kalır | Work §21.9 |
| A-7 | **Açıklama talimat değildir.** Reason/remediation kodları planlama verisidir; içinde gömülü metin (ör. schema'dan gelen etiket) agent için instruction kaynağı olamaz | Work §17.4 |
| A-8 | **Long-running iş continuation ister.** ValidityContract horizon'undan önce, beyan edilmiş checkpoint'lerde ve pause/takeover sonrası; continuation DENY'da yeni consequential effect başlatılmaz | E31 |
| A-9 | **Bölme yolu yoktur.** Bir intent'i limit/requirement eşiği altına bölmek bir exploit'tir; lineage budget'ları bölmeyi faydasız kılar (C27), eşik bazlı requirement'ların bölmeye karşı pencere/kümülatif kuralları RestrictionPolicy ile ifade edilir; varsayılanlar Security'dedir (§13–§14) | INV-3; landscape structuring dersi |
| A-10 | **Advisory evaluation planlama içindir.** "Would this be allowed?" sonucu cache'lenip credential gibi kullanılmaz | L17 |
| A-11 | **Kendi durumunu sorabilir.** Agent kendi Instance'ının exercisable özetini, kalan budget'ını ve horizon'unu advisory olarak öğrenebilir; principal'ın diğer delegation'larını göremez | E26 |
| A-12 | **İnsanlara kendini agent olarak tanıtır.** Kullanıcıya dönük her yüzeyde agent rozeti, principal'ı (capacity) ve operatörü görünür; agent insan olarak sunulmaz | Work §11.5 |

#### 8.18.3 İnsan gerektiren requirement'lar

Actor bir agent Instance'ı iken requirement insan varlığı veya insan step-up'ı istiyorsa (ör. `authentication` binding = actor Instance, humanPresence = true), agent bunu karşılayamaz. Cevap `REQUIRE_ACTION` + `not-satisfiable-by-actor`'dür. Coordinator bunu iki yoldan birine çevirir: (a) requirement contribution kabul ediyorsa principal'ın onayı (§8.17.6), (b) etmiyorsa eylemin principal'ın kendi Instance'ından yapılması gerektiği ("This must be done by you"). Hangi yolun açık olduğu requirement'ın kendisinden okunur; UI uydurmaz.

#### 8.18.4 Agent ↔ coordinator ↔ insan zinciri

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

#### 8.18.5 Spec içi bağlar

| Norm | Spec içindeki bağları |
|---|---|
| A-1 | Protokolde, `commit` modunda basis/capacity eksikse istek protocol hatasıdır (§9.5 kural 4). Ajan kimliği ve Instance'ı §11'dedir. §11.16 bu bölüme atıf yapar; A-1…A-12'nin kanonik metni burasıdır. |
| A-5, A-6 | MCP'nin kendi consent/elicitation akışı approval değildir (EI-18). Ajan platformlarının "always allow" modları reddedilir (§8.17.12). |
| A-7 | MCP tool description'ı authority-opaque'tır ve talimat değildir (§9.4 MCP satırı, §11). `remediation` kodları planlama verisidir, serbest metin alanı yoktur (§9.6). |
| A-8 | Continuation hook'u Executor Contract'tadır. DENY Exercise'ı ileriye dönük kapatır (§9.7 continuation). |
| A-10 | `mode = check` advisory'dir ve kaydedilmez. Cevap credential değildir, cache'lenip izin olarak kullanılamaz (§9.7; L17). |
| A-12 | XI-17 (§6) ile aynı kuraldır. Merchant agent'ı için X30 geçerlidir. |
| Token vault (MD-13, E36) | Ajanın upstream API token'ı istemesi bir Access kararıdır. Token ancak bir Exercise'a bağlı olarak serbest bırakılır: release kararı Exercise'tır, upstream token Access projection'ı değildir ve içeriği NOT GUARANTEED'dır; `exp` ≤ ValidityContract horizon; CT2+ sınıflarda varsayılan broker-as-PEP'tir (§11.13). Ajan token'ı "kendi yetkisi" sayamaz; A-1 (basis ve capacity beyanı) burada da geçerlidir. |
| ID-JAG (MD-18) | Ajanın taşıdığı ID-JAG bir assertion/Claim taşıyıcısıdır, authorization grant değildir. Access'in ürettiği ID-JAG authority taşımayan bir kimlik iddiası projection'ıdır ve authority scope içermez; authority RS tarafında Access Grant'ından gelir. |

### 8.19 Ek experience kararları (X32–X41) ve invariant adayları

Statü: **PROPOSED FOR FREEZE**; onaylandığında FROZEN PRODUCT DECISION olur. Reopen koşulu X1–X31 ile aynıdır: gerçek contradiction, semantik/fiziksel imkânsızlık, materially stronger evidence veya sonraki layer'da zorunlu model açığı. Kullanıcı araştırmasıyla değişebilecek olan yalnız kelime ve gruplamadır (§8.4). Pixel tasarım, ekran akışı, API ve wire format freeze edilmez.

| ID | Karar | Statü | Guarantee | Dayanak |
|---|---|---|---|---|
| **X32** | **Yüzey kümesi S1–S11.** S10 identity plane oturumlarının render'ıyla genişler. S11 "Account & sign-in methods" eklenir. Hosted giriş, kurtarma ve hata ekranları identity plane yüzeyleridir ve §8.8–§8.13 ile X24–X26'ya tabidir. [PATCHES X3] | PROPOSED FOR FREEZE | — | MD-13. Hesap self-servis yüzeyi (FIDO zorunlu desenleri dahil) Access yüzey disiplinine girer |
| **X33** | **Oturum sözlüğü.** Spec dilinde nitelemesiz "oturum/session" yoktur: "identity plane oturumu", "Experience oturumu" veya "Instance" yazılır. Access UI'ında "session/oturum" kelimesi kullanılmaz. İnsan Instance'ı "Sign-in on *device*" olarak render edilir; identity plane oturumu o satırın nitelikleridir. "Keep me signed in on this device" izinlidir; "Remember this decision", "Always allow" ve "Trust this device" yasaktır. Oturum ömrü iki katmanlıdır | PROPOSED FOR FREEZE | — | §8.11 |
| **X34** | **Kimliği doğrulanmamış viewer'a hesap durumu ifşa edilmez, yanlış iddia da edilmez.** Pre-auth mesajları nötr ve tek tiptir. Durum hesabın doğrulanmış kanalına iletilir. Kimlik doğrulandıktan sonra tam dürüstlük (owner + neden) geçerlidir. Silinmiş hesap, var olmayan hesaptan ayırt edilemez | PROPOSED FOR FREEZE | Sabit çıktı (kod, boyut, gecikme) UNDER DECLARED CAPABILITY (§12 TN-G1, §14 yan kanal); mesaj içeriği kuralı BY SEMANTICS (UI kuralı) | §8.15 X-L1, X-L11; E26 |
| **X35** | **Korunan mesaj anahtarları.** Enumeration'a duyarlı, guarantee taşıyan ve owner atfeden mesaj anahtarları kiracı tarafından **ezilemez**. Çeviriler canonical anahtardan üretilir ve makine-okunur §8.10 forbidden-claims denetiminden geçer. Serbest metnin yasak iddia içermediğini bir string doğrulayıcı kanıtlayamayacağı için "ezme + doğrulayıcı" seçeneği yoktur | PROPOSED FOR FREEZE | Ezme yasağı BY SEMANTICS (ürün kuralı); çeviri denetimi UNDER DECLARED CAPABILITY | §8.15 X-L6; XI-12, XI-13 |
| **X36** | **Sign-out ≠ End this sign-in ≠ Revoke.** Bir identity plane oturumu cihaz başına tam olarak bir insan Instance'ına bağlanır. "Sign out" bu cihazdaki identity plane oturumunu bitirir ve bağlı Instance'ı sonlandırır (`instance.terminate`; temizlik, başka Instance'ların authority'si etkilenmez). "End this sign-in" başka bir cihaz satırı için `instance.terminate`'tir; identity plane o oturumu `session_epoch` ile kapatır. Agent'lara ve uygulamalara verilmiş delegation'lar her iki durumda da kalır ve ekran bunu söyler. "Sign out everywhere" metni offline penceresini, sürmekte olan delegation'ları ve sonlandırılan Instance'ları yazar. Hesap devre dışı bırakmada authority daraltması `account.status` DENY overlay'iyle gelir; Instance sonlandırması temizliktir | PROPOSED FOR FREEZE | Oturum sonlandırma UNDER DECLARED CAPABILITY (`session_epoch` yayılması); Instance sonlandırması ve overlay commit anında BY SEMANTICS; offline NOT GUARANTEED | Identity ≠ Authority; E29; §8.10 |
| **X37** | **Destek erişimi deneyimi.** Destek erişimi S1'de bir delegation (veya break-glass Grant'ı), S2'de "Acting for you" satırı, operatör tarafında kalıcı banner'dır. "View as", "Log in as" ve "Impersonate" hiçbir yüzeyde bulunmaz. Destek erişiminin 12 değişmezi PD'dir (§8.16) | PROPOSED FOR FREEZE | Model BY SEMANTICS; değişmezlerin çoğu PD (§8.16 tablosu) | MD-9, E37 |
| **X38** | **Kurtarma ve yaşam döngüsü dürüstlüğü.** Kurtarma mesajı Party Grant'larının kaldığını, cihazların yeniden giriş yapacağını (kurtarma her zaman yeni bir successor Instance doğurur), Instance limitlerinin yeniden kurulacağını ve SEC18 soğumasını (bitiş zamanıyla) söyler. Devre dışı bırakma ve silme mesajları offline penceresini, saklama süresini ve redaksiyonu söyler | PROPOSED FOR FREEZE | SEC18 PD; INV-13 ve INV-30 BY SEMANTICS | X29 |
| **X39** | **Dürüstlük metinleri erişilebilir ve çevrilebilir.** Status ladder basamağı, owner rozeti, UNKNOWN, "confirming (witness pending)", offline pencere ve SEC18 soğumasının her birinin metin karşılığı vardır ve ekran okuyucuya okunur. Durum yalnız renkle gösterilmez. Çeviriler canonical terim anahtarından üretilir; her dilde "bir canonical kavram → bir UI terimi" korunur. RTL baştandır | PROPOSED FOR FREEZE | — | §8.8 |
| **X40** | **Kabuk ve realm.** Tek Suiss kabuğu ve tek RP first-party Suiss hesapları içindir. Müşteri realm'lerinin hosted yüzeyleri realm alan adında ve realm markasıyla sunulur. Suiss'in kendi hosted girişi de aynı düğüm sözleşmesinin tüketicisidir (first-party ayrıcalık yok). [PATCHES X4] | PROPOSED FOR FREEZE | — | XI-18, E24 |
| **X41** | **Identity plane mesajlarının owner'ı ve yasak ifadeleri.** §8.10'daki identity plane satırları ve §8.15.2 mesaj sınıfı tablosu bağlayıcıdır. OAuth ve federation hataları owner'ı (client geliştiricisi, upstream IdP) adlandırır ve korelasyon referansı taşır. Geçersiz `redirect_uri`/`client_id`'de yönlendirme yapılmaz. "Formally verified" ve "tenant isolation guaranteed by the compiler" yasaktır | PROPOSED FOR FREEZE | — | E25 |

**Experience invariant adayları.** Statü: aday (PROPOSED FOR FREEZE); §6.10 satırı adayı.

- **XI-23 (aday)** Sign-in is never authority; sign-out is never revocation. Hiçbir yüzey giriş durumunu yetki olarak, çıkış veya oturum sonunu da delegation iptali olarak sunmaz. İkisi ayrı eylem ve ayrı satırdır. Sign-out'un bağlı Instance'ı sonlandırması temizliktir; başka Instance'ların authority'si etkilenmez. (Identity ≠ Authority, X29, X36) *[BY SEMANTICS (ürün kuralı)]*
- **XI-24 (aday)** Unauthenticated surfaces assert nothing about an account. Kimliği doğrulanmamış viewer'a gösterilen hiçbir mesaj hesabın varlığını, durumunu veya kimlik bilgisinin doğruluğunu iddia etmez ya da ima etmez. (X34, E26) *[BY SEMANTICS (ürün kuralı)]*
- **XI-25 (aday)** Protected strings survive branding and translation. Korunan mesaj anahtarları (guarantee taşıyan, owner atfeden, enumeration'a duyarlı) kiracı tarafından **ezilemez**. Çeviriler canonical anahtardan üretilir ve forbidden-claims denetiminden geçer. (X35, X39, XI-12) *[UNDER DECLARED CAPABILITY (çeviri denetimi)]*
- **XI-26 (aday)** Support access is always a visible delegation. Bir Party adına destek amaçlı her eylem, o Party'nin envanterinde görünen bir Grant'a (veya self-anchor rootTerms'ünde beyanlı, kullanımı kayıtlı bir break-glass Grant'ına) dayanır. Impersonation yolu yoktur. (MD-9, X37, SI-21, INV-28) *[Model ve kullanım kaydı BY SEMANTICS; özneye bildirim UNDER DECLARED POLICY, teslim NOT GUARANTEED]*

### 8.20 Doğrulanmamış iddialar ve açık noktalar

**Etiketli / doğrulanmamış iddialar.**
- Giriş UX'ine ilişkin şu iddialar doğrulanmadı: FIDO/Corbado anket rakamları, koşullu arayüz dönüşümü, EAA tarih ve eşikleri, sayı eşleştirme etkinliği, MFA hatırlama 90 gün, Okta CSP limitleri. Bu spec hiçbirini garanti veya ölçüm olarak kullanmaz.
- Ürün karşılaştırması ("hiçbir ürün on ikisinin hepsini yapmamaktadır") doğrulanmadı; normatif dayanak olarak kullanılmaz.
- Keycloak impersonation en iyi uygulamaları blog kaynaklıdır, doğrulanmadı.
- §8.17.12 desenleri birincil kaynakla yeniden doğrulanmadı.
- §8.4 UX hipotezleri (OQ-6) doğrulanmadı. X33–X39 terimleri de aynı hipotez statüsündedir: kelime ve gruplama araştırmayla değişebilir, semantik ayrımlar değişmez.
- DBSC desteği ve etkinliği doğrulanmadı. §7.6'da sender-constraint UNDER DECLARED CAPABILITY olarak yazılır.
- §7.6'daki "identity plane'in kendi giriş-risk sinyalleri" satırı bir **çıkarımdır**. MD-13 risk tabanlı step-up'ı identity plane'e atar; genel risk skorlaması ayrı bir katmandır.

**Açık noktalar (→ §20 adayı).**
- EI-25–EI-27 ve XI-23–XI-26 invariant adaylarıdır.
- **Açık soru.** X36'ya göre bir identity plane oturumu cihaz başına tam olarak bir insan Instance'ına bağlanır. Instance domain kapsamlıdır ve bir realm 1 yönetişim + N tüketen domain'e bağlanabilir. Bu bağ yönetişim domain'indeki Instance olarak okunmaz; metin X36'nın lafzıyla kalır. Tüketen domain'lerdeki Instance'ların kardinalitesi ve sign-out'un onlara etkisi netleştirilmelidir.
