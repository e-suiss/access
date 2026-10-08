# Ek C. Saklama ve silme kuralları

Bu ek, OP-73 (fiziksel silme yok; kişisel veri silme = crypto-shredding) ve OP-74 (saklama ve silme modeli) için **veri tablosudur**. Motor kural içermez; kuralları bu tablodan okur. Tablo Access, Relay ve diğer Suiss ürünlerinde ortaktır.

Kullanım kuralları:

1. **Birim.** Kural, anahtar kişi × saklama sınıfı başınadır (OP-74). Her satır bir saklama sınıfını bir bölgeye ve sektöre bağlar.
2. **Kiracı.** Kiracı bölgesini ve sektör şablonunu (C.3) seçer. Şablondaki süreleri **yalnız uzatabilir**; kısaltamaz. Azami sınırı olan satırda uzatma azami sınırı aşamaz.
3. **İki saklama türü** (OP-74). *Kanuni saklama*: dayanak + süre + başlangıç olayı + varsa azami süre; süre sonunda otomatik imha. *Dava/regülatör saklaması*: talep kaydedilince otomatik başlar, açıkça kaldırılana kadar imhayı durdurur; kanuni saklamanın süresi veya azami sınırı dolsa bile imha olmaz.
4. **Başlangıç olayı.** Süre, başlangıç olayı kaydedilene kadar işlemez (ör. hesap kapanışı gerçekleşmeden KYC süresi başlamaz).
5. **Çoklu dayanak.** Bir kayıt birden fazla satıra girerse imha, bütün satırların süresi dolduğunda ve hiçbir dava/regülatör saklaması kalmadığında yapılır. Azami sınırlı bir satır, daha uzun asgari süreli başka bir satırın dayanağıyla tutulan kaydı imha ettirmez.
6. **Belirsizlik.** Kaynakların çeliştiği ya da sustuğu yerde en kısıtlayıcı yorum seçilir: en uzun saklama, azami sınır varsa ona uyan değer. Seçilen yorum satırda veya C.5'te belirtilir.
7. **İşaret.** ⚠️ işareti, değeri birincil metinden doğrulanmamış satırı gösterir. ⚠️ satırları C.5 varsayılanıyla çalışır ve kaynak güncellendiğinde gözden geçirilir.

### C.0 Saklama sınıfları

| Sınıf | İçerik |
|---|---|
| `profile` | Hesap ve profil alanları; saklama yükümlülüğü yoksa silme talebinde hemen crypto-shred edilir |
| `kyc` | Kimlik tespiti, doğrulama belgeleri ve sonuçları, gerçek faydalanıcı |
| `transaction` | Ödeme, transfer ve ticari işlem kayıtları |
| `aml_report` | Şüpheli işlem bildirimi, iç değerlendirme ve destekleyici belgeler |
| `audit` | Kimlik doğrulama, yetki, erişim ve yönetim olayları |
| `traffic` | IP, port, oturum başlangıç/bitiş, veri miktarı gibi trafik bilgisi |
| `consent` | Ticari ileti onayı ve onayın kanıtı (metin, kanal, zaman, cihaz/IP) |
| `message_log` | Ticari ileti gönderim, teslim ve ret kayıtları |
| `contract` | Sözleşme, ön bilgilendirme, cayma ve teslimat kayıtları |
| `ledger` | Ticari defter, finansal tablo, ticari yazışma, muhasebe belgesi |
| `tax` | Vergi defter ve belgeleri |
| `dsr_log` | İlgili kişi taleplerinin ve yanıtlarının kaydı |
| `erasure_log` | Silme, imha, saklama başlatma/kaldırma ve okunabilir çıkarma kayıtları |
| `suppression` | Bastırma listesi (opt-out, aranmama); anahtarlı hash olarak tutulur |

## C.1 Silme talebi kuralları

### C.1.1 Ortak kurallar (bütün bölgeler)

1. **Alan bazında değerlendirme.** Silme talebi saklama sınıfı başına değerlendirilir. Saklama yükümlülüğü olmayan sınıflar hemen crypto-shred edilir; yükümlülüğü süren sınıflar kanuni saklamada kalır ve erişimi daraltılır. Talep bütünüyle reddedilmez; kısmi yanıt üretilir.
2. **Crypto-shredding koşulları.** Bir sınıfın crypto-shred edilmiş sayılması için hepsi sağlanır:
   1. Kişi × sınıf anahtarının **bütün kopyaları** imha edilir: KMS/HSM replikaları, anahtar yedekleri, DR bölgesi, escrow, sarmalanmış kopyalar, önbellekteki DEK'ler.
   2. Anahtar bir ana anahtardan deterministik türetilmez; her DEK rastgele üretilir. Türetilmiş anahtarın imhası imha sayılmaz.
   3. Kişiye bağlanabilen **düz metin meta veri kalmaz**: e-posta veya telefon hash'i, blind index, IP, cihaz kimliği, ad, alıcı adresi, kişiye özgü zaman damgası örüntüsü. Bu alanlar aynı anahtarla şifrelenir ya da shred anında tombstone değeriyle değiştirilir. Kalan özne kimliği yalnız rastgele takma kimliktir ve başka hiçbir depoda eşleme tablosu yoktur.
   4. Düz metin hiçbir kalıcı ortama yazılmamıştır: arama dizini, analitik kopya, kuyruk kalıcılığı, outbox, olay günlüğü, uygulama logu.
   5. Şifreleme AES-256-GCM sınıfında simetrik şifredir; kalıcı ciphertext RSA/ECC sarmalamasına dayanmaz; algoritma değişimi mümkündür (kripto çevikliği).
   6. Shred bir `erasure_log` kaydı üretir (kim, ne zaman, hangi anahtar kimliği, hangi sınıflar). Bu kayıt kişiyi tanımlayan veri içermez; takma kimlik kullanır.
3. **Alt işleyiciler.** Verinin aktarıldığı alıcılara (Relay'in e-posta/SMS sağlayıcıları dahil) silme bildirimi gönderilir. Crypto-shredding bu kopyaları kapsamaz; bildirim zinciri ayrıca işletilir.
4. **Kanuni saklamadaki verinin kullanımı.** Saklamadaki sınıf yalnız saklama amacıyla tutulur; uygulama, analitik ve pazarlama erişimi kapalıdır. Okunabilir çıkarma yalnız iki kişilik onayla yapılır (OP-74).
5. **Yumuşak silme ara durumdur.** Kişisel veri taşıyan kayıtta yumuşak silme tek başına silme sayılmaz. Yumuşak silinmiş kişisel alanlar, bölgenin yanıt süresi içinde crypto-shred edilir.
6. **Kullanıcı metni (bütün bölgeler).** Yüzey dili §13.8'e uyar:
   - Shred edilen sınıflar için "kişisel alanlar okunamaz hâle getirildi" denir; "kalıcı olarak silindi" denmez (N-42).
   - Saklamada kalan sınıflar için: sınıfın adı, genel dayanak ("kanuni saklama yükümlülüğü"), öngörülen bitiş tarihi veya başlangıç olayı, şikâyet yolu yazılır.
   - Şüpheli işlem bildirimi (TR 5549 m.4(2); AB AMLR; ABD 31 CFR §1020.320(e), §1022.320(d)) ya da dava/regülatör saklamasının varlığı, sebebi ve tarafı metinde yer almaz. Bu sınıflar için yalnız "kanuni saklama yükümlülüğü" yazılır ve bitiş tarihi yerine "yükümlülük süresince" denir.
   - Saklama kaydının gerekçesi (ŞİB, SAR, dava) yalnız uyum rolüne görünür.
7. **Bastırma listesi.** Silme talebinde bastırma kaydı (normalize e-posta/telefonun kiracı anahtarıyla HMAC'i + opt-out türü + tarih) crypto-shred edilmez; tekrar gönderimi önlemek için kalır (C.5).

### C.1.2 Türkiye

| Konu | Kural |
|---|---|
| Dayanak | 6698 m.4(2)(d), m.7, m.11(1)(e)-(f), m.13; Silme Yönetmeliği m.7–12 |
| Cevap süresi | **30 gün**, ücretsiz (m.13(2); Yön. m.12) |
| Kısmi ret | Kısıtlama hakkı yoktur. İşleme şartlarının tamamı kalkmamışsa talep **gerekçe açıklanarak reddedilir** (Yön. m.12(3)); veri m.5(2)(ç) veya (e) ile işlenmeye devam eder. Ret yazılı veya elektronik verilir. |
| İstisnalar | Kanuni saklama (m.5(2)(a), (ç)); hakkın tesisi ve korunması (m.5(2)(e)); suç soruşturması ve denetim (m.28(2)) |
| Üçüncü kişiler | İşlem, verinin aktarıldığı üçüncü kişilere bildirilir (m.11(1)(f); Yön. m.12) |
| Crypto-shredding niteliği | Anahtarın bütün kopyalarının imhası Kurul rehberinde **yok etme** yöntemi olarak sayılır (Yön. m.9). Anonimleştirme sayılmaz (Yön. m.10). Yumuşak silme, DBA ve uygulama rolleri dahil ilgili kullanıcıların erişimi kalkmışsa **silme**dir (Yön. m.8). |
| Periyodik imha | En geç **6 ay** arayla (Yön. m.11) |
| İmha kaydı | `erasure_log` **en az 3 yıl** (Yön. m.7) |
| Şikâyet yolu metni | "Kişisel Verileri Koruma Kurulu'na yanıttan itibaren 30 gün, her hâlde başvurudan itibaren 60 gün içinde şikâyet" (m.14) |

### C.1.3 Avrupa Birliği

| Konu | Kural |
|---|---|
| Dayanak | GDPR Art. 5(1)(e), 6(1)(c), 12, 17, 18, 19, 25 |
| Cevap süresi | **1 ay**; karmaşıklıkta **+2 ay**, uzatma ilk ay içinde gerekçesiyle bildirilir (Art. 12(3)) |
| Kısmi ret / kısıtlama | Art. 17(3)(b) hukuki yükümlülük ve (e) hukuki talepler istisnası yalnız gereken veri ve süre için uygulanır; kalan veri silinir. Saklanan veri Art. 18 uyarınca **kısıtlanır** ve sistemde açıkça işaretlenir (Recital 67). Kısıtlama kaldırılmadan önce kişiye bilgi verilir (Art. 18(3)). |
| Ret bildirimi | 1 ay içinde: işlem yapılmama sebebi, dayanak, öngörülen bitiş tarihi, DPA'ya şikâyet hakkı ve yargı yolu (Art. 12(4)) |
| Alıcılar | Silme ve kısıtlama alıcılara bildirilir (Art. 19); işleyici sözleşmesi Art. 28(3)(g) silme/iade içerir |
| Crypto-shredding niteliği | AB düzeyinde anahtar imhasını silme sayan açık kural yoktur. Kalan veri **fiilen anonim** ise Art. 17'yi karşılar (EDPB 02/2025 v2.0 ⚠️; C-413/23 P göreli yaklaşım). C.1.1 madde 2'nin bütün koşulları bu bölgede zorunludur. |
| DE notu | BDSG §35(3): sözleşme veya tüzükten doğan saklama süresi varsa silme yerine Art. 18 kısıtlaması uygulanır |
| IE notu | Data Protection Act 2018 s.60: suç soruşturması ve hukuki talepler için hak kısıtlaması |

### C.1.4 Amerika Birleşik Devletleri

| Konu | Kural |
|---|---|
| Dayanak | Genel federal silme hakkı yoktur. California: Cal. Civ. Code §1798.105, §1798.145; 11 CCR §7021, §7022, §7101. Diğer eyaletler: Virginia §59.1-577, Colorado §6-1-1306, Connecticut CTDPA ve benzerleri |
| Cevap süresi | Alındı teyidi **10 iş günü**; esas yanıt **45 gün**, gerekçeli bildirimle **+45 gün** (11 CCR §7021; diğer eyaletler 45 + 45) |
| Kısmi ret / kısıtlama | §1798.105(d) ve §1798.145(a) istisnaları (kanuni yükümlülük, subpoena, soruşturma, hukuki talepler, güvenlik). Ret gerekçelendirilir, istisna dışı kısım silinir, saklanan veri istisna amacı dışında kullanılmaz (11 CCR §7022(f)). |
| Finansal veri | GLBA kapsamındaki veri (KYC, işlem) CCPA'dan veri bazında muaftır (§1798.145(e)); aynı kiracının pazarlama, analitik ve B2B verisi kapsamdadır. Connecticut'ta kurum bazlı muafiyet 2026-07-01'den itibaren büyük ölçüde kalkmıştır. |
| Silme yöntemi | "Kalıcı ve tamamen silme, deidentify veya aggregate" (11 CCR §7022(b)(1)). Crypto-shredding kalıcı silmeye eşdeğer teknik yöntem olarak uygulanır; NIST SP 800-88 Rev. 2 §3.2 Cryptographic Erase koşulları (FIPS 140 doğrulamalı modül, düz metnin hiç yazılmamış olması) karşılanır. Yedeklerde uyum ertelenebilir (§7022(d)); anahtar imhası yedekteki kopyayı da okunamaz kılar. |
| Servis sağlayıcılar | Servis sağlayıcı ve üçüncü kişilere bildirim zinciri (§7022(b)(2)-(3), (c)) |
| Kolluk bildirimi | Kolluk bir tüketicinin verisini **90 gün** silinmemesini bildirebilir; yazılı bildirimle 90'ar gün uzar (§1798.145 ⚠️ alt bent). Bildirim dava/regülatör saklaması başlatır. |
| Talep kaydı | `dsr_log` **en az 24 ay**, başka amaçla kullanılmaz (11 CCR §7101 ⚠️) |
| Disposal ödevi | Saklama ihtiyacı biten veri imha edilir (FTC Safeguards §314.4(c)(6); FCRA Disposal Rule §682.3; Cal. Civ. Code §1798.81 "okunamaz veya deşifre edilemez") |

## C.2 Saklama süreleri

Sütunlar: **Bölge | Veri türü (sınıf) | Dayanak | Süre | Başlangıç olayı | Azami sınır | Regülatöre okunabilir verme.** "Okunabilir verme: Evet" satırlarında saklama süresi içinde anahtar imha edilmez ve iki kişilik çıkarma düz metin, bilinen formatta (CSV, JSON, PDF) çıktı üretir.

### C.2.1 Türkiye

| Bölge | Veri türü (sınıf) | Dayanak | Süre | Başlangıç olayı | Azami sınır | Okunabilir verme |
|---|---|---|---|---|---|---|
| TR | KYC belge ve kayıtları (`kyc`) | 5549 m.8; Tedbirler Yön. m.46(1) | 8 yıl | Son işlem tarihi; hesapla ilgili kimlik belgelerinde hesabın kapanışı | Yok | Evet; "okunabilir hâle getirmek için gerekli tüm bilgi ve şifreler" (5549 m.7) |
| TR | 5549 belge, defter, kayıtları; ŞİB ve iç bildirim (`aml_report`, `transaction`) | 5549 m.8; Tedbirler Yön. m.46(1)-(2) | 8 yıl | Belgede düzenleme tarihi; defter ve kayıtta son kayıt tarihi | Yok | Evet (5549 m.7) |
| TR | Ödeme hizmeti belge ve kayıtları (`transaction`) | 6493 m.23(1) | En az 10 yıl, yurt içinde | Kanunda yok; işlem tarihi, hesap/sözleşme belgelerinde ilişkinin sonu ⚠️ (C.5) | Yok | Evet (6493 m.21(5); TCMB BS Tebliği m.16(1)(h)) |
| TR | Ödeme/e-para kuruluşu denetim izleri, API sorgu izleri dahil (`audit`) | TCMB BS Tebliği m.13(2), (5), (6) | En az 10 yıl, yedekli, zaman damgalı; 24 saatte geri dönüş | Kayıt anı | Yok | Evet; "denetime hazır, taramaya imkân verecek" |
| TR | Ödeme kuruluşu güvenlik ihlali delilleri (`audit`) | TCMB BS Tebliği m.12(7) | En az 10 yıl | İhlal | Yok | Evet |
| TR | Banka faaliyet belgeleri (`transaction`, `ledger`) | 5411 m.42 | 10 yıl | Kanunda yok; belgenin takvim yılı sonu ⚠️ (C.5) | Yok | Evet; "tüm sistem ve şifreler" (5411 m.95, m.96) |
| TR | Banka iz kayıtları (`audit`) | BDDK BS Yön. m.13(3)-(4) | Asgari 5 yıl | Kayıt anı | Yok | Evet; talep anında kopya, "bilinen formatlara dönüştürerek"; kopyalar en az 2 yıl (m.27(5)) |
| TR | Ticari ileti onayı (`consent`) | 6563 m.11(3); Yön. m.13(2) | 10 yıl (Kanun 10 yıl, Yönetmelik 3 yıl; üst ve sonraki norm seçildi) | Onayın sona erdiği (ret) tarih | Yok | Evet; "noksansız ve gerçeğe uygun" |
| TR | Ticari ileti gönderim, ret ve içerik kayıtları (`message_log`) | 6563 m.11(3); Yön. m.13(2) | 10 yıl (aynı gerekçe) | İşlem tarihi | Yok | Evet |
| TR | 6563 kapsamındaki e-ticaret işlem kayıtları (`transaction`) | 6563 m.11(3) | 10 yıl | İşlem tarihi | Yok | Evet |
| TR | Mesafeli sözleşme bilgi ve belgeleri (`contract`) | Mesafeli Sözleşmeler Yön. m.20(1) | 3 yıl (6563 kapsamındaysa 10 yıl) | Yönetmelikte yok; işlem tarihi ⚠️ | Yok | Kısmen; aracı hizmet sağlayıcı istenirse verir (m.20(2)) |
| TR | Pazaryeri satıcı-tüketici işlem kayıtları (`transaction`) | Mesafeli Söz. Yön. m.20(2), m.12(5) | 3 yıl; 6563 kapsamında 10 yıl | İşlem tarihi | Yok | Evet |
| TR | Ticari defter, finansal tablo, ticari yazışma, muhasebe belgesi (`ledger`) | TTK m.82(1), (5), (6) | 10 yıl | Kaydın, belgenin veya yazışmanın takvim yılı sonu | Yok | Evet; "uygun sürede okunabilir hâle getirilebilir" (m.82(3)(b)) |
| TR | Vergi defter ve belgeleri (`tax`) | VUK m.253, m.256 | 5 yıl | İlgili yılı izleyen takvim yılı başı | Yok | Evet (ibraz) |
| TR | Yer sağlayıcı trafik bilgisi (`traffic`) | 5651 m.5(3), m.2(1)(j) | 2 yıl | Kayıt anı | **2 yıl** | Evet; mahkeme veya savcılık talebiyle. ⚠️ 2007 yönetmeliği 6 ay diyor; kanun aralığının üst ucu seçildi (C.5) |
| TR | Elektronik haberleşme erişim ve trafik verisi (`audit`, `traffic`) | 5809 m.51(10) | Erişim kayıtları 2 yıl; trafik verisi 1–2 yıl; rıza kayıtları abonelik süresince | Haberleşme tarihi | **2 yıl** (trafik) | Evet. Yalnız BTK yetkilendirmeli işletmeci kiracıda açılır ⚠️ |
| TR | Nitelikli e-sertifika arşivi | 5070 m.10(1)(g); E-İmza Yön. m.14(2) ⚠️ | En az 20 yıl | — | Yok | Evet. Yalnız ESHS kiracıda açılır; Access doğrulayan taraf olarak taşımaz |
| TR | Genel kimlik doğrulama ve güvenlik logları (`audit`) | 6698 m.12, m.4(2)(d) | 400 gün (C.5) | Kayıt anı | Yok | KVKK Kurulu incelemesi (m.15) |
| TR | Silme/imha kayıtları (`erasure_log`) | Silme Yön. m.7 | En az 3 yıl | İşlem | Yok | Kurul talebi |
| TR | İlgili kişi talepleri (`dsr_log`) | 6698 m.13, m.14 (ispat) | 3 yıl (C.5) | Yanıt tarihi | Yok | Kurul talebi |

### C.2.2 Avrupa Birliği (genel)

| Bölge | Veri türü (sınıf) | Dayanak | Süre | Başlangıç olayı | Azami sınır | Okunabilir verme |
|---|---|---|---|---|---|---|
| AB | KYC/CDD belgeleri, elektronik kimlik verisi (`kyc`) | AMLD Art. 40(1)(a) (10.7.2027'ye kadar); AMLR Art. 77(1)(a), (3) (10.7.2027'den) | 5 yıl; otorite vaka bazında +5 yıla kadar uzatır | İş ilişkisinin sonu veya arızi işlem tarihi | **10 yıl**; süre sonunda imha zorunlu | Evet; redakte edilmemiş, derhal, değiştirilemez (77(1)-(2)) |
| AB | AML iç değerlendirmeleri (`aml_report`) | AMLR Art. 77(1)(b) | 5 yıl (+5) | İş ilişkisinin sonu veya arızi işlem tarihi | **10 yıl** | Evet (FIU, denetim otoritesi) |
| AB | Bilgi paylaşım ortaklığı kayıtları (`aml_report`) | AMLR Art. 77(1)(d) | 5 yıl (+5) | Aynı | **10 yıl** | Evet |
| AB | AML işlem kayıtları (`transaction`) | AMLD Art. 40(1)(b); AMLR Art. 77(1)(c) | 5 yıl (+5) | İş ilişkisinin sonu; arızi işlemde işlem tarihi ⚠️ (C.5) | **10 yıl** | Evet; asıl kayıt veya yargıda delil olarak kabul edilebilir kopya |
| AB | Fon transferine eşlik eden bilgi, kripto dahil (`transaction`) | TFR (EU) 2023/1113 Art. 26 | 5 yıl ⚠️ (+5 ulusal) | İşlem | **10 yıl** ⚠️ | Evet |
| AB | Ödeme hizmeti kayıtları (`transaction`) | PSD2 Art. 21 | En az 5 yıl | Ulusal uygulama ⚠️; işlem tarihi (C.5) | Yok | Evet (PSD2 Art. 23) |
| AB | Yatırım hizmeti kayıtları ve ilgili elektronik iletişim (`transaction`, `message_log`) | MiFID II Art. 16(6)-(7); Del. Reg. 2017/565 Art. 72–76 | 5 yıl; otorite isterse 7 yıl | Kayıt tarihi | Yok | Evet. Yalnız yatırım şirketi kiracıda açılır |
| AB | Finans sektörü kimlik doğrulama, güvenlik ve denetim logları (`audit`) | DORA Art. 9–10, 17; RTS (EU) 2024/1774 Art. 12 | Sabit süre yok; kuruluş amaca göre belgeler. Şablon değeri 5 yıl (C.5) | Kayıt anı | Yok | Evet (DORA Art. 50) |
| AB | ICT olay kayıtları (`audit`) | DORA Art. 17(1)-(3), Art. 19 | Sabit süre yok ⚠️; şablon değeri 5 yıl (C.5) | Olay | Yok | Evet |
| AB | NIS2 kapsamındaki güvenlik logları (`audit`) | NIS2 Art. 21(2); CIR (EU) 2024/2690 Annex §3.2 ⚠️ | "Önceden belirlenmiş süre"; şablon değeri 400 gün (C.5) | Kayıt anı | Yok | Evet (NIS2 Art. 32–33) |
| AB | Güven hizmeti kayıtları (`audit`) | eIDAS Art. 24(2)(h) | Faaliyet sona erdikten sonra "gerektiği sürece"; ulusal süre (çoğu 10 yıl ⚠️) | Faaliyetin sonu | Yok | Evet. Yalnız güven hizmeti sağlayıcısı kiracıda açılır |
| AB | Pazaryeri tacir bilgileri (`kyc`) | DSA Art. 30(3) | 6 ay | Tacirle ilişkinin sonu | **6 ay**; sonra imha | Evet ⚠️ (madde no) |
| AB | Pazarlama onayı kanıtı (`consent`) | GDPR Art. 7(1); ePrivacy Art. 13 | Sabit süre yok; işleme sürdükçe + talep zamanaşımı (Art. 17(3)(e)). Şablon değeri: üye devlet değeri, yoksa 5 yıl (C.5) | Rıza tarihi | Yok | Evet (GDPR Art. 58(1)(a), (e)) |
| AB | Ticari ileti gönderim/teslim kayıtları (`message_log`) | GDPR Art. 5(1)(e), 17(3)(e) | Amaçla sınırlı; `consent` süresine eşlenir | Gönderim | Yok | Evet (DPA) |
| AB | Elektronik haberleşme trafik/konum verisi (`traffic`) | ePrivacy Art. 6, 15(1); C-203/15, C-511/18, C-470/21 | Genel ve ayrımsız saklama yasaktır; faturalama ihtiyacı bitince imha | — | Faturalama süresi | Yalnız yasal erişim düzenine göre. Yalnız ECS/NI-ICS kiracıda açılır ⚠️ |
| AB | Sözleşme/tüketici işlem kayıtları (`contract`) | Ulusal zamanaşımı + GDPR Art. 17(3)(e) | Üye devlet değeri (C.2.3) | Üye devlet değeri | Üye devlet değeri | Mahkeme |
| AB | Kimlik doğrulama ve güvenlik logları, sektör kuralı yok (`audit`) | GDPR Art. 5(1)(e), 6(1)(f), 32 | 400 gün (C.5) | Kayıt anı | Yok | Evet (DPA, Art. 58) |
| AB | Silme/imha kayıtları (`erasure_log`) | GDPR Art. 5(2), 12, 17 (hesap verebilirlik) | 3 yıl (C.5) | İşlem | Yok | Evet (DPA) |
| AB | İlgili kişi talepleri (`dsr_log`) | GDPR Art. 5(2), 12 | 3 yıl (C.5) | Yanıt tarihi | Yok | Evet (DPA) |

### C.2.3 AB üye devlet notları (örnek: Almanya, İrlanda)

Üye devlet satırı, aynı sınıftaki AB genel satırının yerine geçer; AB tüzüğüyle (AMLR) çelişirse AB tüzüğü uygulanır.

| Bölge | Veri türü (sınıf) | Dayanak | Süre | Başlangıç olayı | Azami sınır | Okunabilir verme |
|---|---|---|---|---|---|---|
| AB-DE | KYC kayıtları (`kyc`) | GwG §8(4) | 5 yıl, sonra derhal imha | İlişkinin sona erdiği takvim yılının sonu ⚠️ | **10 yıl** ⚠️ | Evet (BaFin, FIU) |
| AB-DE | Ödeme kuruluşu kayıtları (`transaction`) | ZAG §30 ⚠️ | 5 yıl | İşlem tarihi (C.5) | Yok | Evet (BaFin) |
| AB-DE | Ticari defter, bilanço (`ledger`) | HGB §257(1) Nr. 1, (4); AO §147(1), (3) | 10 yıl | Takvim yılı sonu (HGB §257(5)) | Yok | Evet; AO §147(6) makinece okunabilir erişim |
| AB-DE | Muhasebe fişi, fatura (`ledger`) | HGB §257(4); AO §147(3); UStG §14b (BEG IV) | 8 yıl; BaFin denetimindeki kuruluşta 10 yıl (kaynaklar çelişkili ⚠️; uzun değer seçildi) | Takvim yılı sonu | Yok | Evet |
| AB-DE | Ticari yazışma (`ledger`) | HGB §257(4); AO §147(3) | 6 yıl | Takvim yılı sonu | Yok | Evet |
| AB-DE | Pazarlama onayı kanıtı (`consent`) | UWG §7a | 5 yıl | Rızanın verilmesi ve **her kullanımı** (her gönderim süreyi yeniler); rıza geri alınınca son kullanım | Yok | Evet (Bundesnetzagentur) |
| AB-DE | Sözleşme kayıtları (`contract`) | BGB §§195, 199 | 3 yıl | Talebin doğup öğrenildiği yılın sonu | 10 yıl (BGB §199) | Mahkeme |
| AB-DE | Güvenlik amaçlı IP logu (`traffic`) | BGH III ZR 391/13 ⚠️ | 7 gün (içtihat örneği) | Kayıt anı | Yok | — |
| AB-IE | KYC ve işlem kayıtları (`kyc`, `transaction`) | Criminal Justice (ML & TF) Act 2010 s.55 ⚠️ | 5 yıl ⚠️ | İlişkinin sonu / işlem tarihi | **10 yıl** (AMLR) | Evet (CBI, Garda FIU) |
| AB-IE | Muhasebe ve vergi (`ledger`, `tax`) | Companies Act 2014 s.285 ⚠️; TCA 1997 s.886 | 6 yıl ⚠️ | Hesap döneminin sonu ⚠️ | Yok | Evet (Revenue) |
| AB-IE | Sözleşme kayıtları (`contract`) | Statute of Limitations 1957 | 6 yıl | Talebin doğduğu tarih | Yok | Mahkeme |
| AB-IE | Pazarlama onayı (`consent`) | S.I. 336/2011 Reg. 13 | Sabit süre yok ⚠️; AB şablon değeri 5 yıl (C.5) | Son kullanım | Yok | Evet (DPC, ComReg) |

### C.2.4 Amerika Birleşik Devletleri

| Bölge | Veri türü (sınıf) | Dayanak | Süre | Başlangıç olayı | Azami sınır | Okunabilir verme |
|---|---|---|---|---|---|---|
| ABD | CIP tanımlayıcı bilgiler, banka (`kyc`) | 31 CFR §1020.220(a)(3)(ii)(A) | 5 yıl | Hesabın kapanışı (kredi kartında kapanış veya hareketsizlik) | Yok | Evet; "makul sürede erişilebilir" (§1010.430(d)) |
| ABD | CIP doğrulama kayıtları (`kyc`) | 31 CFR §1020.220(a)(3)(ii)(B) | 5 yıl | Kaydın oluşturulması | Yok | Evet |
| ABD | Gerçek faydalanıcı (`kyc`) | 31 CFR §1010.230(i) ⚠️ (alt bent) | 5 yıl | Tanımlayıcıda hesap kapanışı; doğrulamada kayıt oluşturma | Yok | Evet |
| ABD | MSB müşteri tanıma (`kyc`) | 31 CFR §1022.210, §1010.410(e), §1010.415, §1010.430(d) | 5 yıl | Kaydın oluşturulması | Yok | Evet |
| ABD | BSA kayıtları, genel (`transaction`) | 31 CFR §1010.430(d) | 5 yıl | Kaydın oluşturulması | Yok | Evet |
| ABD | Fon transferi ≥ 3.000 USD (`transaction`) | 31 CFR §1010.410(a), (e)-(f) | 5 yıl | İşlem | Yok | Evet |
| ABD | CTR kopyaları (`aml_report`) | 31 CFR §1010.311, §1010.306(a)(2) | 5 yıl | Dosyalama | Yok | Evet |
| ABD | SAR kopyası ve destekleyici belgeler (`aml_report`) | 31 CFR §1020.320(d), §1022.320(c) | 5 yıl | Dosyalama tarihi | Yok | Evet; SAR'ın varlığı açıklanamaz (§1020.320(e), §1022.320(d)) |
| ABD | Banka kayıtları (`transaction`) | 31 CFR §1020.410 | 5 yıl | Kayıt | Yok | Evet |
| ABD | Reg E uyum kanıtı: EFT, ön ödemeli, havale (`transaction`) | 12 CFR §1005.13(b) | En az 2 yıl; soruşturma bildiriminde sonuçlanana kadar | Açıklama veya işlem tarihi | Yok | Evet (CFPB) |
| ABD | Reg Z uyum kanıtı (`transaction`) | 12 CFR §1026.25(a), (c) | 2 yıl; mortgage kapanış belgesi 5 yıl, diğer mortgage 3 yıl ⚠️ | Açıklamanın gerekli olduğu tarih | Yok | Evet (CFPB) |
| ABD | Reg B kredi başvuruları (`kyc`, `contract`) | 12 CFR §1002.12(b) | 25 ay tüketici; 12 ay ticari ⚠️ | Sonucun bildirimi | Yok | Evet. Yalnız kredi veren kiracıda açılır |
| ABD | Reg DD mevduat (`transaction`) | 12 CFR §1030.9(c) ⚠️ | 2 yıl ⚠️ | — | Yok | Evet. Yalnız banka |
| ABD | Eyalet para transferi lisansı kayıtları (`transaction`, `ledger`) | Ör. Iowa §533C.606; 205 ILCS 658/7-6; 32 MRSA §6100-E; Va. Code §6.2-1943 | En az 3 yıl; eyalete göre değişir | Kayıt | Yok | Evet (eyalet denetçisi) |
| ABD | Kart verisi: SAD (CVV, PIN, iz verisi) | PCI DSS v4.0.1 Req. 3.3 | Yetkilendirmeden sonra saklanmaz | Yetkilendirme | **0**; şifreli de olsa tutulmaz | — |
| ABD | PCI ortamı denetim logları (`audit`) | PCI DSS v4.0.1 Req. 10.5.1 | En az 12 ay; son 3 ay anında analiz edilebilir | Log olayı | Yok | Evet (QSA) |
| ABD | NY DFS kapsamındaki denetim izi (`audit`) | 23 NYCRR §500.6 | En az 5 yıl (güncel metin; 2017 metninde siber olay izleri 3 yıl ⚠️) | Kayıt | Yok | Evet (DFS) |
| ABD | Müşteri bilgisi, saklama yükümlülüğü dışındaki (`profile`) | FTC Safeguards 16 CFR §314.4(c)(6)(i) | — | Son kullanım | **2 yıl**; kanuni saklama veya hedefli imkânsızlık hariç | — |
| ABD | TCPA otomatik arama/SMS onayı (`consent`) | 47 U.S.C. §227; 47 CFR §64.1200(a)(2), (f)(9); 28 U.S.C. §1658(a) | 5 yıl (TCPA zamanaşımı 4 yıl, TSR 5 yıl; uzun değer seçildi) | Onaya dayanılan son mesajın gönderimi | Yok | Evet (FCC, FTC, mahkeme) |
| ABD | TSR kayıtları, onay dahil (`consent`, `message_log`) | 16 CFR §310.5 | 5 yıl | Kaydın oluşturulması | Yok | Evet (FTC) |
| ABD | Firma aranmama listesi (`suppression`) | 47 CFR §64.1200(d)(3), (d)(6) | Talep 5 yıl geçerli; 10 iş günü içinde uygulanır | Talep tarihi | Yok | Evet |
| ABD | E-posta opt-out (`suppression`) | 15 U.S.C. §7704(a)(3)-(4); 16 CFR Part 316 | Süresiz; 10 iş günü içinde uygulanır | Opt-out | Yok | Evet (FTC) |
| ABD | Genel vergi kayıtları (`tax`) | 26 U.S.C. §6001, §6501(a), (e); Treas. Reg. §1.6001-1(e) | 7 yıl (6 yıl zamanaşımı + beyan süresi; C.5) | Vergi yılının sonu | Yok | Evet; erişilebilir ve okunabilir (Rev. Proc. 98-25 ⚠️) |
| ABD | İstihdam vergisi kayıtları (`tax`) | Treas. Reg. §31.6001-1(e)(2) | En az 4 yıl | Verginin vadesi veya ödenmesi | Yok | Evet (IRS) |
| ABD | Broker-dealer kayıtları ve iletişimleri (`transaction`, `message_log`, `ledger`) | 17 CFR §240.17a-4 | 3 yıl çoğu kayıt; 6 yıl defterler | Kayıt | Yok | Evet; derhal, makul kullanılabilir biçimde. Yalnız broker-dealer kiracıda açılır |
| ABD | HIPAA dokümantasyonu (`audit`) | 45 CFR §164.316(b)(2)(i) | 6 yıl ⚠️ (loglara uygulanması tartışmalı) | Oluşturma veya son yürürlük | Yok | Evet (HHS). Yalnız sağlık kiracıda açılır |
| ABD | CSAM raporu içeriği | 18 U.S.C. §2258A(h) | 1 yıl | NCMEC raporu | Yok | Evet (NCMEC, kolluk) |
| ABD | Sözleşme kayıtları (`contract`) | Eyalet zamanaşımı: CA CCP §337 4 yıl; NY CPLR §213 6 yıl ⚠️ | 6 yıl (C.5) | Sözleşmenin sonu | Yok | Mahkeme (FRCP 34) |
| ABD | Kimlik doğrulama ve güvenlik logları, sektör kuralı yok (`audit`) | 16 CFR §314.4(c)(8) (süre yok); CCPA §1798.100(a)(3) | 400 gün (C.5) | Kayıt anı | Yok | Evet |
| ABD | İlgili kişi talepleri (`dsr_log`) | 11 CCR §7101(a) ⚠️ | 3 yıl (24 ay asgari; C.5) | Yanıt tarihi | Yok | Evet (CPPA) |
| ABD | Silme/imha kayıtları (`erasure_log`) | FRCP 37(e) savunması; 11 CCR §7022(e) | 3 yıl (C.5) | İşlem | Yok | Evet |

## C.3 Sektör şablonları

Şablon, bölge × sektör için hangi sınıfların hangi C.2 satırıyla açıldığını belirler. Şablonda yer almayan sınıf için kanuni saklama yoktur; silme talebinde hemen crypto-shred edilir. Bütün şablonlarda ortak açık olanlar: `erasure_log` (3 yıl), `dsr_log` (3 yıl), `suppression` (C.5), `audit` genel satırı (400 gün; sektör satırı daha uzunsa o).

### C.3.1 Ödeme / e-para kuruluşu

| Sınıf | TR | AB | ABD |
|---|---|---|---|
| `kyc` | 8 yıl, son işlem / hesap kapanışından (5549) | 5 yıl (+5), ilişki sonundan; azami 10 (AMLR 77) | 5 yıl (§1010.430, §1022.210) |
| `transaction` | 10 yıl, yurt içinde (6493 m.23) + 8 yıl (5549); uzun olan | 5 yıl (+5) AML; azami 10. PSD2 ≥ 5 yıl. TFR 5 yıl ⚠️ | 5 yıl BSA; Reg E ≥ 2 yıl; eyalet lisansı ≥ 3 yıl |
| `aml_report` | 8 yıl | 5 yıl (+5); azami 10 | 5 yıl (SAR, CTR) |
| `audit` | En az 10 yıl, yedekli, zaman damgalı, 24 saatte geri dönüş (TCMB Tebliği m.13) | 5 yıl şablon (DORA, C.5) | NY lisanslıysa 5 yıl (DFS 500.6); PCI ortamında ≥ 12 ay; diğer 400 gün |
| `consent`, `message_log` | 10 yıl (6563) | Üye devlet değeri, yoksa 5 yıl | 5 yıl (TCPA/TSR) |
| `ledger` | 10 yıl (TTK) | Üye devlet (DE: 10/10/6; BaFin denetimli fiş 10) | Eyalet lisansı ≥ 3 yıl |
| `tax` | 5 yıl (VUK) | Üye devlet | 7 yıl |
| `traffic` | 2 yıl, azami 2 (5651) | Açılmaz | Açılmaz |
| `profile` | Açılmaz | Açılmaz | Azami 2 yıl son kullanımdan (FTC Safeguards) |
| Yurt içinde tutma | **Zorunlu**: birincil ve ikincil sistemler, yedekler, dış hizmet sağlayıcı sistemleri ve kiracı anahtarlarının KMS/HSM'i ile yedekleri TR bölgesinde (6493 m.23; TCMB Tebliği m.21) | Yok; GDPR Bölüm V aktarım kuralları | Yok |

### C.3.2 Banka

| Sınıf | TR | AB | ABD |
|---|---|---|---|
| `kyc` | 8 yıl (5549) | 5 yıl (+5); azami 10 | CIP 5 yıl hesap kapanışından; doğrulama 5 yıl kayıttan; BO 5 yıl |
| `transaction` | 10 yıl (5411 m.42) + 8 yıl (5549); uzun olan | 5 yıl (+5) AML; azami 10. Ödeme hizmeti veriyorsa PSD2 ≥ 5. Yatırım hizmeti veriyorsa MiFID II 5–7 | 5 yıl (§1010.410, §1020.410); Reg E/Z/DD 2 yıl; Reg B 25 ay; mortgage 3–5 yıl |
| `aml_report` | 8 yıl | 5 yıl (+5); azami 10 | 5 yıl (SAR §1020.320) |
| `audit` | Asgari 5 yıl (BDDK BS Yön. m.13); talep kopyaları en az 2 yıl | 5 yıl şablon (DORA, C.5) | NY'de 5 yıl (DFS 500.6); PCI ortamında ≥ 12 ay; diğer 400 gün |
| `consent`, `message_log` | 10 yıl (6563) | Üye devlet değeri, yoksa 5 yıl | 5 yıl |
| `ledger` | 10 yıl (TTK, 5411 m.42) | Üye devlet (DE: BaFin denetimli fiş 10 yıl) | 6 yıl (C.5; 17a-4 açıksa ona göre) |
| `tax` | 5 yıl | Üye devlet | 7 yıl |
| `traffic` | 2 yıl, azami 2 | Açılmaz | Açılmaz |
| Yurt içinde tutma | **Zorunlu**: birincil ve ikincil sistemler TR'de (BDDK BS Yön. m.25); yurt dışı paylaşımda sır kısıtı (5411 m.73); kiracı anahtarlarının KMS/HSM'i TR'de (C.5) | Yok | Yok |

### C.3.3 E-ticaret / pazaryeri

| Sınıf | TR | AB | ABD |
|---|---|---|---|
| `kyc` | Açılmaz (MASAK yükümlüsü değilse); ödeme akışını kendisi yönetiyorsa ödeme şablonu ⚠️ | Pazaryeri tacir bilgisi 6 ay, azami 6 ay (DSA Art. 30) | Açılmaz; ödeme akışını kendisi yönetiyorsa ödeme şablonu ⚠️ |
| `transaction` | 10 yıl (6563 m.11(3)) | Sözleşme satırı (üye devlet) | Sözleşme satırı (6 yıl) |
| `contract` | 3 yıl (Mesafeli Söz. Yön. m.20); 6563 kapsamında 10 yıl | Üye devlet (DE 3 yıl + yıl sonu; IE 6 yıl) | 6 yıl |
| `audit` | 400 gün; 6563 kapsamındaki işlem logu 10 yıl ⚠️ | 400 gün | Kart kabul ediyorsa PCI ≥ 12 ay; diğer 400 gün |
| `consent`, `message_log` | 10 yıl (6563); ret sonrası gönderim 3 iş günü içinde durur (m.8(3)) | Üye devlet değeri, yoksa 5 yıl | 5 yıl; opt-out 10 iş günü içinde uygulanır |
| `ledger` | 10 yıl | Üye devlet | — |
| `tax` | 5 yıl | Üye devlet | 7 yıl |
| `traffic` | 2 yıl, azami 2 | Açılmaz | Açılmaz |
| Yurt içinde tutma | Yok; KVKK m.9 aktarım kuralları | Yok | Yok |

### C.3.4 Genel SaaS

| Sınıf | TR | AB | ABD |
|---|---|---|---|
| `transaction` | TTK ticari belge sayılıyorsa 10 yıl (`ledger`) | — | — |
| `contract` | — | Üye devlet | 6 yıl |
| `audit` | 400 gün | 400 gün (NIS2 kapsamında aynı) | 400 gün |
| `consent`, `message_log` | 10 yıl (6563) | Üye devlet değeri, yoksa 5 yıl | 5 yıl |
| `ledger` | 10 yıl | Üye devlet | — |
| `tax` | 5 yıl | Üye devlet | 7 yıl |
| `traffic` | 2 yıl, azami 2 (5651) | Açılmaz | Açılmaz |
| Yurt içinde tutma | Yok; KVKK m.9 | Yok | Yok |

### C.3.5 Sektöre özel ek sınıflar

Aşağıdaki satırlar şablona ek seçenek olarak açılır; varsayılan kapalıdır: AB yatırım hizmeti (MiFID II), AB güven hizmeti (eIDAS), AB ECS/NI-ICS trafik verisi, TR ESHS (5070), TR elektronik haberleşme işletmecisi (5809), ABD broker-dealer (17a-4), ABD sağlık (HIPAA), ABD kredi veren (Reg B/Z).

## C.4 Regülatör talepleri

Her talep kaydı ilgili kişi ve sınıflar için **otomatik dava/regülatör saklaması** başlatır ve anahtar imhasını durdurur. Teslim, iki kişilik onayla okunabilir çıkarmadır (OP-74); şifreli veri teslimi yeterli değildir. Teslim kanalı şifreli olabilir; çıktıya bütünlük kanıtı (imza, zaman damgası, hash zinciri) eklenir.

| Bölge | Otorite | Dayanak | İstenebilecek veri | Biçim | Süre |
|---|---|---|---|---|---|
| TR | MASAK | 5549 m.7, m.8; Tedbirler Yön. m.46 | Her türlü bilgi, belge, kayıt | Okunabilir; "gerekli tüm bilgi ve şifreler"; özel kanunla kaçınılamaz | Talepte belirtilen süre |
| TR | BDDK | 5411 m.95, m.96; BS Yön. m.27(5) | Bütün defter, kayıt, belge; sistemlere yerinde erişim | Okunabilir, bilinen formatta; talep anında kopya alınır, kopya en az 2 yıl saklanır | Talep anında kopya |
| TR | TCMB | 6493 m.21(5), m.23; BS Tebliği m.13, m.16(1)(h) | Ödeme hizmeti kayıtları, denetim izleri | Okunabilir | Denetim izi **24 saat** içinde geri yüklenir |
| TR | Ticaret Bakanlığı | 6563 m.11(3); Yön. m.13(2); Mesafeli Söz. Yön. m.20 | E-ticaret ve ticari ileti kayıtları, onaylar | Noksansız ve gerçeğe uygun elektronik kayıt | Talepte belirtilen süre |
| TR | Vergi idaresi | VUK m.256 | Defter ve belgeler | İbraz | Talepte belirtilen süre |
| TR | Mahkeme, savcılık | CMK m.134; 5651 m.5(3) | Bilgisayar kayıtlarının kopyası, çözülmüş metin, trafik bilgisi | Çözülmüş metin; çözülemeyen kayıtta el koyma (m.134(2)) | Kararda belirtilen süre |
| TR | KVKK Kurulu | 6698 m.15 | İnceleme kapsamında bilgi ve belge | Okunabilir | Talepte belirtilen süre |
| TR | Siber Güvenlik Başkanlığı | 7545 m.6(1)(ç)-(d); 5651 yetkileri (7590) | Bilgi, belge, veri, log | ⚠️ İkincil düzenleme bekleniyor | ⚠️ |
| AB | DPA | GDPR Art. 58(1)(a), (e), (f) | Bütün kişisel veri ve bilgi; tesislere erişim | Okunabilir | Talepte belirtilen süre |
| AB | AML denetim otoritesi, FIU, AMLA | AMLR Art. 69, 77(2); AMLD Art. 32–33, 40; Reg. (EU) 2024/1620 | CDD, işlem kayıtları, değerlendirmeler | Redakte edilmemiş, değiştirilemez | **Derhal** |
| AB | Ödeme otoritesi | PSD2 Art. 21, 23 | Uyum için gereken bütün kayıtlar | Okunabilir | Talepte belirtilen süre |
| AB | Finans otoritesi (DORA) | DORA Art. 50, Art. 30(3)(e) | Loglar, olay kayıtları, ICT sağlayıcı bilgisi | Okunabilir | Talepte belirtilen süre |
| AB | Yatırım otoritesi | MiFID II Art. 69 | Kayıtlar, iletişim kayıtları | Okunabilir | Talepte belirtilen süre |
| AB | NIS2 otoritesi | NIS2 Art. 32–33 | Güvenlik politikaları, loglar, denetim kanıtı | Okunabilir | Talepte belirtilen süre |
| AB-DE | Vergi otoritesi | AO §147(6) | Dijital veriye doğrudan/dolaylı erişim | Makinece okunabilir (GoBD) | Talepte belirtilen süre |
| AB | Ceza adaleti, sınır ötesi | e-Evidence Reg. (EU) 2023/1543 (18.8.2026'dan); Dir. 2023/1544 | Abone verisi, tanımlama amaçlı IP, trafik verisi, içerik | Okunabilir; emir önce kiracıya, ikincil olarak Suiss'e (Art. 5(6) ⚠️) | Üretim emri **10 gün**, acil **8 saat**; muhafaza emri 60 gün ⚠️ |
| ABD | FinCEN, IRS (BSA denetimi), banka regülatörleri | 31 U.S.C. §5318; 31 CFR §1010.430(d); 12 U.S.C. §481 | BSA kayıtları, KYC, işlem kayıtları | Makul sürede erişilebilir, okunabilir | Talepte belirtilen süre |
| ABD | FinCEN 314(a) | 31 CFR §1010.520(b)(3) | Belirli kişiyle eşleşen hesap/işlem | Eşleşme bildirimi | **14 gün** |
| ABD | CFPB | 12 U.S.C. §5562 | Tüketici finansmanı kayıtları | CID'de belirtilen biçim | CID'de belirtilen süre |
| ABD | SEC, FINRA | 17 CFR §240.17a-4(f), (j) | Broker-dealer kayıtları | Makul kullanılabilir elektronik biçim | **Derhal** |
| ABD | Federal hükümet (banka müşteri kaydı) | RFPA 12 U.S.C. §3401 vd. | Subpoena, celpname, arama emriyle kayıt | — | Belgede belirtilen süre |
| ABD | Kolluk (ECS/RCS) | 18 U.S.C. §2703; §2703(f) | Abone bilgisi (subpoena), içerik dışı kayıt (§2703(d) kararı), içerik (arama emri); koruma talebi | Mevcut kayıtlar | Koruma **90 gün + 90 gün** |
| ABD | Kolluk (CCPA bildirimi) | Cal. Civ. Code §1798.145 ⚠️ | Silmeme bildirimi | — | **90 gün**, 90'ar gün uzar |
| ABD | ABD sağlayıcıya yurt dışı veri talebi | CLOUD Act 18 U.S.C. §2713 | Zilyetlik, muhafaza veya kontroldeki veri | Okunabilir | Talepte belirtilen süre. Self-host'ta talep kiracıya yönelir |
| ABD | Hukuk davası | FRCP 26(b)(2)(B), 34, 45; 37(e) | Kontroldeki ESI | Olağan tutulduğu veya makul kullanılabilir biçime çevrilmiş | Talepte belirtilen süre; dava öngörüldüğü andan itibaren koruma |

## C.5 Varsayılan seçimler

| # | Konu | Varsayılan | Gerekçe |
|---|---|---|---|
| 1 | 6563 ticari ileti kayıtları | 10 yıl | Kanun m.11(3) hem üst norm hem Yönetmelik m.13(2)'den sonraki normdur. |
| 2 | 6563 onay kaydının başlangıcı | Onayın sona erdiği (ret) tarih | Yönetmeliğin başlangıç olayı ile Kanunun süresi birleştirildiğinde en uzun saklama budur. |
| 3 | Relay'in 6563 rolü | Relay aracı hizmet sağlayıcı yükümlülüklerini taşır | Taşımasa da kiracının 10 yıllık kayıtları Relay'de durur; destek zorunludur. |
| 4 | 5651 yer sağlayıcı kapsamı | Access ve Relay SaaS, TR bölgesinde yer sağlayıcı sayılır; `traffic` 2 yıl | Kapsam belirsizdir; kanun aralığının üst ucu (2 yıl) en uzun saklamadır ve azami sınırı aşmaz. 2007 yönetmeliğindeki 6 ay ⚠️ kanunun alt sınırının altındadır. |
| 5 | Azami sınır ve dava/regülatör saklaması | Azami sınır yalnız kanuni saklamaya uygulanır; dava/regülatör saklaması altındaki kayıt azami sınır dolsa da imha edilmez | 5809 m.51(10) soruşturma verisini "süreç tamamlanana kadar" tutar; FRCP 37(e) ve 18 U.S.C. §1519 imhayı yasaklar. |
| 6 | 6493 m.23 ve 5411 m.42 başlangıcı | 6493: işlem tarihi, hesap/sözleşme belgelerinde ilişkinin sonu. 5411: belgenin takvim yılı sonu | Kanunlar susar; seçilen olaylar en geç başlangıcı verir. |
| 7 | AMLR işlem kayıtlarının başlangıcı | Süren iş ilişkisinde ilişkinin sonu; arızi işlemde işlem tarihi | Art. 77(3) metni ("end of a business relationship or occasional transaction") ve en uzun saklama; azami 10 yıl aynı başlangıçtan sayılır. |
| 8 | DE muhasebe fişi, BaFin denetimli kuruluş | 10 yıl | Kaynaklar 8 ile 10 yıl arasında çelişir ⚠️; uzun değer seçildi. |
| 9 | Genel denetim logu | 400 gün | SEC32 POLICY DEFAULT ile aynı; PCI DSS 12 ay asgarisini karşılar; sektör kuralı yoksa amaçla sınırlı kalır. |
| 10 | DORA ve finansal ICT olay logu | 5 yıl | DORA süre vermez; AML 5 yıl ve NY DFS 5 yıl ile hizalanır, olay incelemesi ve denetim kapsar. |
| 11 | AB pazarlama onayı (üye devlet değeri yoksa) | 5 yıl, son kullanımdan | AB'de sabit süre yoktur; DE UWG §7a değeri en kısıtlayıcı örnektir. |
| 12 | ABD pazarlama onayı | 5 yıl, son mesajdan | TCPA zamanaşımı 4 yıl, TSR 5 yıl; uzun olan seçildi. |
| 13 | ABD vergi | 7 yıl, vergi yılı sonundan | §6501(e) 6 yıl beyandan işler; beyan tarihi kaydedilmediğinde yıl sonu + 1 yıl pay eklenir. |
| 14 | ABD sözleşme kayıtları | 6 yıl, sözleşmenin sonundan | Eyalet zamanaşımları 4–6 yıl ⚠️; uzun olan seçildi. |
| 15 | Bastırma listesi | Normalize e-posta/telefonun kiracı anahtarıyla HMAC'i + opt-out türü + tarih; opt-out geçerli olduğu sürece kalır; ABD aranmama talebi 5 yıl; kiracı kapanışında imha | CAN-SPAM opt-out süresizdir, TCPA aranmama 5 yıldır; tekrar gönderimi önlemek kanuni yükümlülüktür. Hash düz metin değildir; crypto-shred kapsamı dışında ayrı sınıftır. |
| 16 | `erasure_log` | 3 yıl, bütün bölgelerde; kişisel veri içermez | KVKK Yön. m.7 en az 3 yıl ister; ABD talep kaydı 24 ay ve AB hesap verebilirlik bununla karşılanır. |
| 17 | `dsr_log` | 3 yıl, bütün bölgelerde | 11 CCR §7101 24 ay asgarisini ve KVKK m.14 şikâyet süresini karşılar; `erasure_log` ile hizalıdır. |
| 18 | Silme yanıt hedefi | Bütün bölgelerde 30 gün; bölgenin yasal üst sınırı ayrıca uygulanır | En kısa yasal süre TR 30 gündür; tek hedef operasyonu sadeleştirir. |
| 19 | Periyodik imha işi | Günlük çalışır | KVKK Yön. m.11 en geç 6 ay ister; günlük çalışma azami sınırlı satırlarda aşımı önler. |
| 20 | Okunabilir çıkarma süresi | 24 saat üst sınır; AB e-Evidence acil üretim emrinde 8 saat; AMLR "derhal" taleplerinde aynı nöbet | TCMB 24 saat ister; e-Evidence acil emri 8 saattir. İki onaylayıcı 7/24 nöbetle bu sürelere yetişir. |
| 21 | ŞİB/SAR gizliliği | Kullanıcı metninde yalnız "kanuni saklama yükümlülüğü"; gerekçe yalnız uyum rolüne görünür | 5549 m.4(2) ve 31 CFR §1020.320(e) bildirimin varlığının açıklanmasını yasaklar. |
| 22 | Ödeme ve banka kiracısında anahtar konumu | Kiracı anahtarlarının KMS/HSM'i ve yedekleri TR bölgesinde | "Bilgi sistemleri ve yedekleri yurt içinde" kuralı anahtar sistemini de kapsar sayılır ⚠️; en kısıtlayıcı yorumdur. |
| 23 | Rol | SaaS'ta kiracı veri sorumlusu, Suiss veri işleyendir; kiracı şablonu seçer. Self-host'ta yükümlülükler operatördedir | Saklama yükümlülüğü kiracıya aittir; tablo varsayılan sunar. |
| 24 | ⚠️ satırlar | Tablodaki değerle çalışır; kaynak güncellendiğinde satır yeniden değerlendirilir | Değer en kısıtlayıcı yorumla seçilmiştir. |

## C.6 Kaynaklar

**Türkiye**
- 6698 KVKK: https://www.mevzuat.gov.tr/MevzuatMetin/1.5.6698.pdf
- Silme Yönetmeliği: https://www.kvkk.gov.tr/Icerik/5441/KISISEL-VERILERIN-SILINMESI-YOK-EDILMESI-VEYA-ANONIM-HALE-GETIRILMESI-HAKKINDA-YONETMELIK
- KVKK Silme, Yok Etme, Anonimleştirme Rehberi: https://ktun.edu.tr/Dosyalar/1255/files/Mevzuat_ve_Dokumanlar_HUKUKI_METINLER/Genel%20Politika%20ve%20Prosed%C3%BCrler/imha_rehberi_bc1cb353-ef85-4e58-bb99-3bba31258508.pdf
- Kurul kararı 2020/93: https://www.kvkk.gov.tr/Icerik/6875/2020-93
- 5549: https://www.mevzuat.gov.tr/MevzuatMetin/1.5.5549.pdf
- Tedbirler Yönetmeliği: https://cdn.egm.org.tr/sites/files/Suc-Gelirlerinin-Aklanmasinin-Ve-Terorun-Finansmaninin-Onlenmesine-Dair-Tedbirler-Hakkinda-Yonetmelik-2642.pdf
- 6493: https://www.mevzuat.gov.tr/MevzuatMetin/1.5.6493.pdf
- Ödeme Hizmetleri Yönetmeliği: https://www.resmigazete.gov.tr/eskiler/2021/12/20211201-1.htm
- TCMB Bilgi Sistemleri Tebliği: https://www.resmigazete.gov.tr/eskiler/2021/12/20211201-3.htm
- Tebliğ değişikliği (RG 7.10.2023): https://www.turmob.org.tr/arsiv/mbs/resmigazete/32332-8.pdf
- 5411: https://www.mevzuat.gov.tr/MevzuatMetin/1.5.5411.pdf
- BDDK BS ve Elektronik Bankacılık Yönetmeliği: https://www.resmigazete.gov.tr/eskiler/2020/03/20200315-10.htm
- 6563: https://www.mevzuat.gov.tr/MevzuatMetin/1.5.6563.pdf
- Ticari İletişim ve Ticari Elektronik İletiler Yönetmeliği: https://www.lexpera.com.tr/mevzuat/yonetmelikler/ticari-iletisim-ve-ticari-elektronik-iletiler-hakkinda-yonetmelik ; https://www.alomaliye.com/2015/07/15/ticari-iletisim-ve-ticari-elektronik-iletiler-hakkinda-yonetmelik/ ; 2020 değişikliği: https://www.alomaliye.com/2020/01/04/ticari-iletisim-ve-ticari-elektronik-iletiler/amp/
- 6102 TTK: https://www.mevzuat.gov.tr/MevzuatMetin/1.5.6102.pdf
- 213 VUK: https://www.mevzuat.gov.tr/MevzuatMetin/1.4.213.pdf
- 5651: https://www.mevzuat.gov.tr/MevzuatMetin/1.5.5651.pdf
- 5809: https://www.mevzuat.gov.tr/MevzuatMetin/1.5.5809.pdf
- Mesafeli Sözleşmeler Yönetmeliği: https://alomaliye.com/2014/11/27/mesafeli-sozlesmeler-yonetmeligi/
- 5070: https://www.mevzuat.gov.tr/MevzuatMetin/1.5.5070.pdf ; E-İmza Yönetmeliği: https://www.barobirlik.org.tr/dosyalar/belgeler/e-imza/mevzuat/e-imza-yonetmelik.pdf
- 5271 CMK: https://www.mevzuat.gov.tr/MevzuatMetin/1.5.5271.pdf
- 7545 Siber Güvenlik Kanunu: https://www.mevzuat.gov.tr/MevzuatMetin/1.5.7545.pdf
- 4857: https://www.mevzuat.gov.tr/MevzuatMetin/1.5.4857.pdf
- 5651 yönetmelik süreleri: https://www.erdem-erdem.av.tr/bilgi-bankasi/5651-sayili-kanun-kapsaminda-internet-aktorleri
- Mesafeli Sözleşmeler özeti: https://www.erdem-erdem.av.tr/bilgi-bankasi/mesafeli-sozlesmelere-dair-yonetmelik
- 5651 2026 değişiklikleri: https://oner.av.tr/yeni-sosyal-medya-uygulamalari/

**Avrupa Birliği**
- GDPR: https://eur-lex.europa.eu/eli/reg/2016/679/oj
- AMLR (EU) 2024/1624: https://eur-lex.europa.eu/eli/reg/2024/1624/oj ; Art. 77: https://www.springlex.eu/en/packages/aml/amlr-regulation/article-77/
- AMLD (EU) 2015/849: https://eur-lex.europa.eu/eli/dir/2015/849/oj
- TFR (EU) 2023/1113: https://eur-lex.europa.eu/eli/reg/2023/1113/oj
- PSD2: https://eur-lex.europa.eu/eli/dir/2015/2366/oj
- MiFID II: https://eur-lex.europa.eu/eli/dir/2014/65/oj ; Del. Reg. 2017/565: https://eur-lex.europa.eu/eli/reg_del/2017/565/oj
- DORA: https://eur-lex.europa.eu/eli/reg/2022/2554/oj ; RTS 2024/1774 Art. 12: https://www.springlex.eu/en/packages/dora/rts-rmf-regulation/article-12/
- NIS2: https://eur-lex.europa.eu/eli/dir/2022/2555/oj ; CIR 2024/2690: https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj
- eIDAS 2024/1183: https://eur-lex.europa.eu/eli/reg/2024/1183/oj ; Art. 24(2)(h): https://lawplayer.com/eu/act/32024R1183 ; CIR 2025/2530: https://eur-lex.europa.eu/eli/reg_impl/2025/2530/oj
- ePrivacy 2002/58: https://eur-lex.europa.eu/eli/dir/2002/58/oj
- DSA (EU) 2022/2065: https://eur-lex.europa.eu/eli/reg/2022/2065/oj
- Data Act (EU) 2023/2854: https://eur-lex.europa.eu/eli/reg/2023/2854/oj
- e-Evidence (EU) 2023/1543: https://eur-lex.europa.eu/eli/reg/2023/1543/oj
- KDV Direktifi 2006/112: https://eur-lex.europa.eu/eli/dir/2006/112/oj
- EDPB Guidelines 01/2025 Pseudonymisation: https://www.edpb.europa.eu/system/files/2025-01/edpb_guidelines_202501_pseudonymisation_en.pdf
- EDPB Guidelines 02/2026 Anonymisation (taslak): https://digitalpolicyalert.org/event/41477-european-data-protection-board-adopted-guidelines-022026-on-anonymisation-for-public-consultation ; https://privacymatters.dlapiper.com/2026/08/eu-edpb-publishes-draft-guidelines-on-anonymisation/ ; https://www.stephensonharwood.com/insights/the-edpbs-guidelines-on-anonymisation-one-legal-standard-two-approaches-three-criteria/
- EDPB Guidelines 02/2025 Blockchain v2.0: https://ppc.land/edpb-forces-blockchain-firms-to-avoid-storing-personal-data-on-chain/ ; https://www.edpb.europa.eu/our-work-tools/our-documents/publication-type/guidelines_en
- EDPB CEF 2025 silme hakkı raporu: https://www.edpb.europa.eu/documents/coordinated-enforcement-framework/coordinated-enforcement-action-implementation-of-the-0_en ; https://www.reedsmith.com/our-insights/blogs/viewpoints/102mm9l/edpb-report-on-the-right-to-erasure-key-takeaways-from-the-2025-coordinated-enfo/
- WP29 Opinion 05/2014: https://ec.europa.eu/justice/article-29/documentation/opinion-recommendation/files/2014/wp216_en.pdf
- C-413/23 P EDPS v SRB: https://curia.europa.eu/juris/liste.jsf?num=C-413/23 ; https://www.cliffordchance.com/insights/resources/blogs/talking-tech/en/articles/2025/09/pseudonymized-data-after-edps-v-srb.html ; https://cm.twobirds.com/en/insights/2025/eu-the-srb-decision-a-new-era-for-personal-data-and-data-processing-agreements
- C-293/12 Digital Rights Ireland: https://curia.europa.eu/juris/liste.jsf?num=C-293/12
- C-203/15 Tele2: https://curia.europa.eu/juris/liste.jsf?num=C-203/15
- C-511/18 La Quadrature du Net: https://curia.europa.eu/juris/liste.jsf?num=C-511/18
- C-140/20 G.D.: https://curia.europa.eu/juris/liste.jsf?num=C-140/20
- C-793/19 SpaceNet: https://curia.europa.eu/juris/liste.jsf?num=C-793/19
- C-470/21 LQDN II: https://fra.europa.eu/it/caselaw-reference/cjeu-case-c-47021-judgment ; https://eucrim.eu/news/ecj-ruled-on-data-retention-of-ip-addresses-in-piracy-cases/
- C-579/21 Pankki S: https://curia.europa.eu/juris/liste.jsf?num=C-579/21
- C-26/22 SCHUFA: https://curia.europa.eu/juris/liste.jsf?num=C-26/22
- C-582/14 Breyer: https://curia.europa.eu/juris/liste.jsf?num=C-582/14
- PSD3/PSR durumu: https://www.taylorwessing.com/en/insights-and-events/insights/2025/11/eu-lawmakers-strike-a-deal-on-payments-reforms ; https://www.mondaq.com/ireland/financial-services/1780752/psd3psr-final-compromise-texts-are-published ; https://www.openbankingtracker.com/guides/psd3-psr-readiness
- Digital Omnibus: https://iapp.org/news/a/eu-digital-omnibus-what-the-proposed-changes-to-the-concept-of-personal-data-mean-in-practice
- AB veri saklama girişimi: https://heise.de/-11101430 ; https://edri.org/our-work/mass-surveillance-of-telecommunications-document-pool/
- DE BDSG §35: https://www.gesetze-im-internet.de/bdsg_2018/__35.html
- DE GwG §8: https://www.gesetze-im-internet.de/gwg_2017/__8.html
- DE HGB §257: https://www.gesetze-im-internet.de/hgb/__257.html ; AO §147: https://www.gesetze-im-internet.de/ao_1977/__147.html
- DE BEG IV: https://www.haufe.de/steuern/gesetzgebung-politik/viertes-buerokratieentlastungsgesetz_168_613390.html ; https://www.lexware.de/wissen/buchhaltung-finanzen/buerokratieentlastungsgesetz/
- DE UWG §7a: https://www.gesetze-im-internet.de/uwg_2004/__7a.html
- DE ZAG §30: https://www.gesetze-im-internet.de/zag_2018/__30.html
- DE BGB §195: https://www.gesetze-im-internet.de/bgb/__195.html
- DE IP saklama tasarısı: https://www.beck-aktuell.de/heute-im-recht/rechtspolitik-gesetzgebung/regierung-gesetzentwurf-ip-speicherpflicht-2026-04-22 ; https://dserver.bundestag.de/btd/21/041/2104159.pdf
- IE Criminal Justice (ML & TF) Act 2010: https://www.irishstatutebook.ie/eli/2010/act/6/enacted/en/html
- IE Data Protection Act 2018: https://www.irishstatutebook.ie/eli/2018/act/7/enacted/en/html
- IE S.I. 336/2011: https://www.irishstatutebook.ie/eli/2011/si/336/made/en/print
- IE Communications (Retention of Data) (Amendment) Act 2022: https://www.irishstatutebook.ie/eli/2022/act/22/enacted/en/html

**Amerika Birleşik Devletleri**
- 11 CCR §7022: https://www.law.cornell.edu/regulations/california/11-CCR-7022
- Cal. Civ. Code §1798.105: https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.105
- CCPA düzenlemeleri: https://cppa.ca.gov/regulations/
- 16 CFR §314.4: https://www.law.cornell.edu/cfr/text/16/314.4
- 16 CFR Part 682: https://www.ecfr.gov/current/title-16/chapter-I/subchapter-F/part-682
- 31 CFR §1020.220: https://www.law.cornell.edu/cfr/text/31/1020.220
- 31 CFR §1010.430: https://www.ecfr.gov/current/title-31/subtitle-B/chapter-X/part-1010/subpart-D/section-1010.430
- 31 CFR Chapter X (§1010.410, §1010.230, §1022.320, §1020.320): https://www.ecfr.gov/current/title-31/subtitle-B/chapter-X
- 12 CFR §1005.13: https://www.ecfr.gov/current/title-12/chapter-X/part-1005/subpart-A/section-1005.13
- 12 CFR §1026.25: https://www.ecfr.gov/current/title-12/chapter-X/part-1026/subpart-D/section-1026.25
- 23 NYCRR §500.6: https://www.law.cornell.edu/regulations/new-york/23-NYCRR-500.6
- 47 CFR §64.1200: https://www.law.cornell.edu/cfr/text/47/64.1200
- TSR 2024 değişikliği: https://www.federalregister.gov/documents/2024/04/16/2024-07180/telemarketing-sales-rule
- REPORT Act, P.L. 118-59: https://www.congress.gov/118/plaws/publ59/PLAW-118publ59.htm
- NIST SP 800-88 Rev. 2: https://csrc.nist.gov/pubs/sp/800/88/r2/final ; https://csrc.nist.gov/files/pubs/sp/800/88/r2/final/docs/sp800-88r2-faq.pdf
- Iowa §533C.606: https://www.legis.iowa.gov/docs/code/2026/533C.606.pdf
- Illinois 205 ILCS 658/7-6: https://ilga.gov/legislation/ilcs/documents/020506580K7-6.htm
- Maine 32 MRSA §6100-E: https://legislature.maine.gov/statutes/32/title32sec6100-E.html
- FRCP 37: https://www.law.cornell.edu/rules/frcp/rule_37 ; FRCP 34: https://www.law.cornell.edu/rules/frcp/rule_34
- 18 U.S.C. §2703: https://www.law.cornell.edu/uscode/text/18/2703 ; §1519: https://www.law.cornell.edu/uscode/text/18/1519
- 15 U.S.C. §7001 (E-SIGN): https://www.law.cornell.edu/uscode/text/15/7001
- 15 U.S.C. §7704 (CAN-SPAM): https://www.law.cornell.edu/uscode/text/15/7704
- 45 CFR §164.316: https://www.law.cornell.edu/cfr/text/45/164.316
- 17 CFR §240.17a-4: https://www.law.cornell.edu/cfr/text/17/240.17a-4
- Treas. Reg. §1.6001-1: https://www.law.cornell.edu/cfr/text/26/1.6001-1
- TCPA revoke-all ertelemesi: https://www.consumerfinancialserviceslawmonitor.com/2026/01/fcc-further-extends-effective-date-for-tcpa-revoke-all-rule/ ; https://www.burr.com/telephone-consumer-protection-act/the-fcc-delays-effective-date-of-tcpa-revoke-all-rule-until-january-31-2027
- Connecticut SB 1295: https://perkinscoie.com/insights/blog/connecticut-pierces-glba-veil-overhauling-its-omnibus-privacy-law ; https://natlawreview.com/article/connecticut-overhauls-its-data-privacy-act
- FinCEN AML/CFT program NPRM (2026-04-07): https://www.mofo.com/pdf/resources/insights/260417-fincen-proposes-new-rule-aml-cft-programs
- FinCEN yatırım danışmanı AML ertelemesi: https://www.mofo.com/pdf/resources/insights/260108-fincen-hits-pause-no-aml-rule-for-investment-advisers-until-2028
- TSR 5 yıl: https://www.huschblackwell.com/newsandinsights/ftc-amends-telemarketing-sales-rule-to-increase-recordkeeping-requirements-and-cover-business-to-business-telemarketing-calls
- PCI DSS 10.5.1: https://myctrl.tools/frameworks/pci-dss-v4/10-5-1
- Colorado Privacy Act: https://privacy.gtlaw.com/colorado/
