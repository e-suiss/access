## 13. Security / Trust / Guarantee Matrix

> **Bölüm notu.** Sınıflar §3.3'tedir: BS = GUARANTEED BY SEMANTICS, UDC = GUARANTEED UNDER DECLARED CAPABILITY / POLICY (koşul satırda yazılı), NG = NOT GUARANTEED, PU = PHYSICALLY UNSATISFIABLE; ek etiketler PD (POLICY DEFAULT), EA (engineering assumption — ölçülmemiş hedef), HYPOTHESIS. Identity plane satırları (DL-9–DL-10, G45–G56, U35–U59, N-31–N-49, HL-15–HL-24, RR-16–RR-34, §13.7.9, §13.11–§13.13) identity plane'e ve MD-2/6/7/8/10/17/18'e dayanır. Diğer bölümlerden gelen satırlar şunlardır: G57–G64, U60–U71, N-50–N-59 (§13.4 alt tablosu), HL-35–HL-40 (§13.5), RR-43–RR-45 (§13.9); kaynak → ID eşlemesi §13.13 sonundaki tablodadır. HL/RR kanonik numaraları §13'tekilerdir; mükerrer ID'ler emeklidir (HL-25 → HL-20, HL-26 → HL-19, HL-28 → HL-16 + HL-21, HL-30 → HL-22, RR-40/41/42 → RR-18/19/20; HL-15 → HL-29). §13.5 ve §13.9 bu spec'in bütün HL ve RR'lerini listeler; §15, §16 ve §17 yalnız atıf yapar. §13.11 satır etiketleri EP-n'dir. MD-8 (fail-closed) bütün satırların üst kuralıdır: hiçbir satır "hata durumunda ALLOW" okunacak biçimde yorumlanamaz.

### 13.1 Verdict ve beyan edilmiş sınırlar

**Verdict: SECURE WITH DECLARED LIMITS.** Model saldırı altında semantik olarak dayanır; model-level vulnerability yoktur. Ele geçirilmiş hiçbir issuer, IdP, publisher, provider operatörü, executor veya verifier kendi **beyan edilmiş** blast radius'unun ötesinde positive authority basamaz: positive authority yalnız Anchor lineage'ında meta-Exercise ile doğar (INV-1, INV-2), her dış girdi use-typed Acceptance'tan geçer (INV-15) ve her actor attribution actor Instance'ının KeyBinding'iyle imzalı Actor Intent Statement'a bağlıdır (PI-7). Provider imza anahtarı için beyan edilmiş radius verifier'ların **yerel** kabul tavanlarıdır (U25, N-26). Kalan riskler gizli değil, beyan edilmiş sınırlardır; ürün bunları guarantee dilinde söylemez (XI-12).

**Beyan edilmiş sınırlar** (her biri §13.4'te sınıflı, §13.9'da residual risk olarak sahipli):

| # | Sınır | Sınıf | Neden kaçınılmaz |
|---|---|---|---|
| DL-1 | **Custodial anahtar.** Party/Instance anahtarlarını tutan custodian (Suiss-hosted'da Identity plane), user-gated custody beyan edilmedikçe o Party'yi taklit edebilir | NOT GUARANTEED (→ N-16; user-gated custody varyantı ayrı satır → U15) | Custody ≠ controller ≠ root (E4) semantiktir; anahtarı tutan tarafın anahtarı kullanmaması fizikseldir |
| DL-2 | **Approval Surface'i işleten taraf** (first-party dahil) kullanıcıya farklı render gösterip başka bir digest'e assertion toplatabilir | NOT GUARANTEED (→ N-7; conformant + bağımsız surface varyantı ayrı satır → U7) | Authenticator içerik göstermez (F12: WebAuthn txAuthSimple terk edildi); render'ı yalnız surface gösterir |
| DL-3 | **Offline/intermittent pencere.** Revocation sonrası beyan edilmiş horizon/Δ/slice içinde kullanım | UNDER DECLARED CAPABILITY (pencerenin fiilen kapanması → U2, U19; pencerenin sınıflandırılması ayrı satır → G25) | CI-9, INV-24 |
| DL-4 | **Provider değerlendirme doğruluğu ve equivocation'ı** önlenemez; yalnız yeniden değerlendirme (open reference evaluator) ve witness ile tespit edilir | NOT GUARANTEED (önleme → N-13; tespit ayrı satır → U9, U13) | Provider kararı fiziksel olarak onun elindedir; çıkış her zaman açıktır (G32) |
| DL-5 | **Forced recovery'de kayıp suffix** | NOT GUARANTEED (witness'sız veya provider-dışı kayıt replica'sız → N-14; witness/replica-before-ack + evaluator-side rollback guard varyantı ayrı satır → U10) | E20, PI-15; witness yalnız checkpoint commitment'ını co-sign eder, kaydı tutmaz — co-sign ≠ replica |
| DL-6 | **Yetkili ama kötü niyetli / ele geçirilmiş aktör** (insan, agent, root) kendi authority'si içinde zarar verebilir; colluding insanlar split authority'yi aşabilir | NOT GUARANTEED (zarar budget, Mandate, requirement ve pencere ile sınırlanır) | Approved ≠ wise |
| DL-7 | **Policy oracle.** Karar yüzeyinin kendisi bir oracle'dır; tekrar eden sorgulardan eşik çıkarımı tamamen önlenemez | NOT GUARANTEED (disclosure scope, rate ve tespit ile sınırlanır) | Determinism (INV-27) rastgele gürültüyü yasaklar |
| DL-8 | **Fail-closed'un availability bedeli.** Access erişilemezse beyan edilmiş contract dışındaki consequential effect durur | NOT GUARANTEED (availability → N-20; ValidityContract içi süreklilik ayrı satır → UDC) — bilinçli trade-off | INV-26, E25, X21 |
| DL-9 | **Artık çapraz-domain / çapraz-RP ilişkilendirilebilirlik (linkability).** Pairwise `sub` ve domain-pairwise PartyRef pseudonym'i tanımlayıcı düzeyinde korelasyonu kaldırır; ama aynı KeyBinding'in (aynı donanım anahtarı / aynı custodial anahtar) birden çok domain'de kullanımı, zamanlama, IP/cihaz parmak izi ve davranış korelasyonu kalır | NOT GUARANTEED (→ N-31; tanımlayıcı düzeyi pairwise varsayılanı ayrı satır → U40; authority düzeyinde korelasyonun yalnız bridging Grant / IdentityBinding ile olması ayrı satır → G52) | Kriptografik tanımlayıcı ayrımı yan bilgiyi (ağ, zaman, cihaz) silmez; LINDDUN "Linking/Identifying" tehditleri tanımlayıcı katmanının dışındadır. Not: pairwise ↔ LINDDUN eşlemesi çıkarımdır |
| DL-10 | **Paylaşılan hesaplama altyapısında co-tenant yan kanalı.** Aynı fiziksel host / çekirdek / önbellek paylaşan başka kiracı veya iş yükü mikromimari yan kanallarla (cache, SMT, Spectre sınıfı) gizli bilgi sızdırabilir | NOT GUARANTEED (→ N-32; dedicated compute (B4) varyantı ayrı satır → U54) | Paylaşılan donanımda mikromimari izolasyon yazılımla tam sağlanamaz; dedicated compute bir maliyet seçeneğidir, signer ayrımı ve HSM ise ücretsiz taban güvencedir (MD-17, B3) |

**Tek cümlelik sonuç:**

> **Access'in güvenlik çekirdeği şudur: positive authority yalnız kaydedilmiş, attributable ve imzalı bir meta-Exercise ile doğar; her dış girdi yalnız kendi use'unun beyan edilmiş blast radius'u kadar etkili olur; her belirsizlik DENY veya REQUIRE_ACTION üretir; her geri alma ileriye dönüktür ve en geç beyan edilmiş pencerede etkili olur — ve ürün bunun ötesinde hiçbir şeyi, özellikle fiziksel durdurmayı, dış gerçeği, insan muhakemesini ve unutturmayı, guarantee olarak söylemez.**

### 13.2 Security ownership ve trust model

E22: **security-important ≠ authority-plane-owned**. Access'in **authority plane** güvenlik sorumluluğu dört şeydir:

1. **Authority semantiğinin bütünlüğü** — non-amplification, use-scoped trust, lineage, consumption, revocation semantiği.
2. **Kendi kayıtlarının bütünlüğü** — append-only Authority Record, attribution, tamper-evidence, replay edilebilirlik, export.
3. **Karar yolunun fail-closed olması** — belirsizlik, hata, aşırı yük ve bilinmeyen sürüm hiçbir zaman ALLOW üretmez.
4. **Trust acceptance'ın blast radius'u** — her Acceptance'ın, her custody'nin, her provider binding'in ele geçirilmesinin ne kadar zarar verebileceğinin beyanı ve sınırlanması.

Diğer güvenlik concern'lerinin owner'ları §7.1 ve E22'dedir; Access onları yalnız Claim, requirement veya restriction girdisi olarak tüketir.

**Identity plane'in güvenlik sorumluluğu.** Identity plane (§10) Access'in **identity plane'idir**. Authority plane'den ayrı bir canonical depo, ayrı cell/KMS/operatör rolleri (T31) ve tek kanal Claim Ingest (TI-15) ile ayrılır. Ayrı bir ürün veya E22 anlamında ayrı bir owner değildir. Sorumlulukları: (a) authentication ceremony bütünlüğü (credential doğrulama, phishing-resistant faktör, MFA, recovery ≥ korunan seviye); (b) session ve token (OIDC/OAuth/SAML) üretimi, rotasyonu ve `session_epoch` fast revoke; (c) credential deposu (parola hash'i, passkey kayıtları, TOTP sırları — Secret<T> disiplini, §14.5); (d) federation protokol uyumu (OIDC, SAML, SCIM, LDAP/Kerberos/RADIUS/WS-Fed gateway'leri — ayrı süreçler, MD-1); (e) enumeration ve brute-force direnci (§14.6). Identity plane'in her çıktısı Access'e yalnız `authentication` / `authenticator-binding` / `identity-binding` Claim'i olarak, kabul edildiği use kadar girer (INV-12, INV-15; G45). Identity plane yapılandırma değişiklikleri domain action'ıdır (MD-14) ve dolayısıyla tek yazma yolundan geçer (G54). Statü: FROZEN · sınıf: BS (ayrım) · kaynak: MD-13, MD-14.

**Kriptografik gereksinimler (yalnız gereksinim; algoritma seçimi T5 → §15, MD-3):**

| Gereksinim | Gerekli mi | Nerede | Not |
|---|---|---|---|
| **Tamper-evidence** | **Evet** | Authority Record (hash chain / Merkle commitment), checkpoint, offline report chain, Record Export | C2 |
| **Non-repudiation** (teknik anlamda: imza ile issuer/actor attribution'ı) | **Evet** | Actor Intent Statement, AAS + authentication assertion, Claim, checkpoint, receipt, PAP | PI-7, P29. *Hukuki* non-repudiation iddia edilmez (EI-24) |
| **Forward secrecy** | **Yalnız transport gizliliği için evet**; imzalı kayıtlar için **hayır** (anlamsız: imzalar uzun süre doğrulanabilir kalmalıdır) | ADP, ingest, export kanalları | Anahtar ele geçirildiğinde geçmiş imzalar geçersiz olmaz; ele geçirme sonrası imzaların ayrılması **witness'lı zaman sabitlemesi** ile yapılır ("existed by T", Work) |
| **Uzun süreli doğrulanabilirlik / crypto agility** | **Evet** | Kayıtlar, checkpoint'ler | Algoritma kimliği imzalı içeriğin parçası (PI-21); yeniden sabitleme mekaniği: algoritma geçişi için §15.18 (PQ re-anchoring) ve §15.16 (agility); provider/binding değişimi için §16.6 ve §16.6.1 (recovery re-anchor T17) |
| **Confidentiality at rest** | Evet, ama **semantik guarantee değil** | Claim değerleri, intent parametreleri | Operatörün okuyamaması iddia edilmez; minimizasyon (E26) ve redaksiyon (C34) birincil kontroldür |
| **Algoritma kümesi ve PQ geçişi** | **Evet** (gereksinim burada, seçim §15) | COSE authority kayıtları, JOSE projeksiyonları, JWKS, SAML | COSE authority: Ed25519 varsayılan, ES256/ESP256 doğrulaması zorunlu; JOSE projeksiyonu ES256; FIPS profili her yerde ES256/ESP256; RS256 yalnız identity plane'de istemci başına opt-in, authority artefaktı asla RSA imzalı değil, `rsa` crate kullanılmaz (Marvin); SAML rsa-sha256 istisnası; JWS'te `alg: EdDSA` reddedilir; alg allowlist metadata'dan. PQ: ML-DSA-65 opt-in, JWKS'te `AKP` 1. günden modellenir; PQ re-anchor §15 |
| **Constant-time ve sır hijyeni** | **Evet** (UDC) | Token/MAC/hash karşılaştırma, imza, sır taşıyan tipler | Derleyici constant-time garanti etmez (HL-16); ct yalnız ölçümle (dudect, asm snapshot) UDC'dir (U45); Secret<T>: Debug yok, ct-eq, zeroize — zeroize her kopyayı silmez (N-34). Kapsam ("Sabit zamanlı sır karşılaştırması [PL]"): her sır karşılaştırması; platform ve derleyici varsayımına bağlı UDC (§15.15); HL-28 → HL-16 + HL-21 |
| **İçerik gizliliği (JWE / SAML EncryptedAssertion)** [ID] | İstemci veya SP talep ederse evet | ID Token, UserInfo, JAR/JARM, SAML assertion | §15.3.3. Authority plane'de JWE kullanılmaz; [AU]'da gizlilik semantik garanti değildir ("Confidentiality at rest" satırı korunur); içerik şifrelemesinin HNDL riski RR-36 |
| **Parola ve bearer sırrın tek yönlü saklanması** [ID] | Evet | Parola hash'i, client secret, API anahtarı, refresh/reset/magic-link/device code | §15.14. Veritabanı sızıntısında sırrın yeniden kullanılamaması UNDER DECLARED POLICY (U69; CR-36, CR-38) |
| **Bellek-içi anahtar koruması** [PL] | Evet, best-effort | Signer, custody signer, verifier'ın sır tutan bileşenleri | §15.13. Kapsamadığı vektörler HL-21'de beyan edilir (HL-28 katlandı); etki sınırı U41, önleme NG (N-33) |

Bu tablo kriptografik gereksinimlerin tek kanonik kopyasıdır (SEC4). §15.1.1 tabloyu tekrar etmez, buna atıf yapar; [ID]/[PL] satırları bu tablodadır.

**Blast radius tablosu (trust model).**

"Blast radius" = bileşen tamamen kötü niyetli olduğunda **semantik olarak** ulaşabileceği en geniş sonuç. "Asla" sütunu GUARANTEED BY SEMANTICS sınırıdır; "Containment lever" o bileşeni durduran attributable Exercise'tır.

| Bileşen | Neye güvenilir | Neye asla güvenilmez | Ele geçirilirse blast radius | Asla (semantik sınır) | Containment lever |
|---|---|---|---|---|---|
| **Anchor root** (Sole/Joint) | Kendi Anchor scope'unda authority kaynağı olmaya | Başka Anchor'ın / domain'in authority'sine | Kendi scope'undaki her şey, rootTerms requirement'ları içinde | Kapsamadığı scope; reserved action'ı rootTerms requirement'ı olmadan; geçmişi silmek | Joint root (k-of-n) + delay; Sole root'ta yalnız covering root veya yeniden genesis |
| **rootTerms `domain.recover` entry'si** (Genesis'te beyan edilmiş; actor'ler entry'nin KeyBinding'lerine sahip root Party Instance'ları) | Provider binding'i forced recovery ile değiştirmeye | Grant/Acceptance/policy yazmaya | Provider binding'i değiştirmek; eski bir checkpoint'i cite ederek rollback denemesi (replica'dan yeniden üretilen en yüksek witness'lı checkpoint R*'ın altındaki N her durumda evaluator-side guard'a takılır (DENY); witness quorum'u erişilemezken, replica yok/sorgulanamaz iken veya kesilmiş replica ile yalnız meta-anchor genel threshold'uyla ve StateBasis'te beyanlı kayıp suffix'le — DL-6) | Authority state yazmak (yalnız `domain.recover`, basis = AnchorRoot(meta-anchor), scope `Domain(D)`); Anonymous istek | Evaluator-side witness + replica checkpoint guard'ı (girdi requester seçimi değil; SEC22); witness/replica-before-ack (SEC23); custody ayrılığı (SEC20) |
| **Access provider (evaluator)** | Kararları spec'e göre üretmeye, kayıtları tutmaya | Authority sahibi olmaya (INV-29) | Yanlış ALLOW/DENY; hizmet reddi; equivocation; kayıp suffix | Actor adına Exercise üretmek (AIS yok; PI-7); authority sahibi olmak; geçmişi tespit edilemez biçimde yeniden yazmak (witness varsa) | `domain.handover` / `domain.recover`; yeniden değerlendirme ile tespit |
| **Provider operatörü** (Suiss-hosted dahil) | Provider'ı işletmeye | Root, custodian veya surface sahibi sayılmaya | Provider'ınki + (aynı operatör ayrıca custodian ise) DL-1 + (surface'i de sunuyorsa) DL-2 | Genesis'te verilmemiş authority (INV-29); custody'siz Party'leri taklit | Görev ayrılığı + user-gated custody (SEC17–SEC19) |
| **Provider imza anahtarı** | Receipt/PAP/checkpoint/metadata imzası | Authority (custody attestation) | Recovery kaydı verifier'a ulaşana kadar **güncel tarihli**, keyfi holder/bounds/horizon/slice/audience'lı PAP/receipt/token — her verifier'ın **yerel** kabul tavanı içinde (offline: Domain Metadata / Verifier Profile'da ilan edilmiş horizon/slice tavanları + operasyonel anahtar geçerlilik penceresi; foreign: bridging Grant ceiling'i ve terms'i); offline slice'lar lineage budget'ından draw edilmemiş olabilir; sahte checkpoint (witness'ta çatallanma olarak görünür; kökü hiçbir kayıt kümesinin record-fold'uyla yeniden üretilemez) | Online ADP kararı (anahtar evaluator değildir); merkezde budget draw'u veya Exercise kaydı; recovery sonrası exact-content inclusion proof'suz kabul (P18) | Verifier-side yerel tavanlar + metadata freshness ≤ Δ: conformant verifier'da yerel tavanı aşan kabul yok (→ U25, UDC); `domain.recover`, N = en son doğrulanmış checkpoint (SEC21) |
| **Identity plane** (issuer + custodian) | `authentication` / `authenticator-binding` / `identity-binding` Claim'leri yayınlamaya, kabul edildiği use kadar | Authority yaratmaya (INV-12) | `actor-binding` kabul edildiği subjectClass'taki Party'lerin **zaten tuttuğu** authority kadar impersonation; custodial ise ayrıca designation değiştirme | Yeni Grant, Acceptance, ceiling üstü authority, reserved action (E18) | Acceptance narrowing + ingest-time cutoff; non-custodial controller (P21 conjunction) |
| **External IdP** | Kabul edildiği use kadar | Başka use'a (INV-15) | `actor-binding`: subjectClass impersonation; `subject-selection` ise mevcut rule-shaped Grant ceiling'leri içinde seçim | Yeni Grant/Acceptance/meta-action (E18) | `acceptance.amend` cutoff |
| **HR / claim issuer** (`subject-selection`) | Seçim fact'lerine | Grantor olmaya (INV-16) | Önceden var olan rule-shaped Grant'ların holder kümesi, ceiling'leri içinde | Grant ceiling'ini, reserved action'ları, budget'ı aşmak | Cutoff = affirmative disqualify (SEC9) |
| **Schema publisher** | Namespace'inin anlamına, kabul edilmiş exact digest kadar | Kabul edilmemiş sürüm/mapping'e (E10) | Kabul edilmiş digest'in render/anlamı; pin'li mapping'in yanlış etiketlenmesi | Kabul edilmemiş digest'le kapsam değiştirmek; reserved bayrağını sessizce kaldırmak (EI-16) | `schema-definition` Acceptance revoke → `schema-not-accepted` (fail closed) |
| **Foreign domain** | `foreign-authority` Acceptance kapsamında authority kanıtına | Yerel authority'ye (INV-17) | Bridging Grant ceiling'i kadar | Ceiling dışı; yerel kayda yazmak (PI-24) | Bridging Grant / Acceptance revoke (yerelde kesin) |
| **PEP** | Kararı effect'ten önce uygulamaya (beyan) | Actor olmaya (E17) | Kendi fiziksel olarak kontrol ettiği effect'ler (Access'siz de yapabileceği şey) | ALLOW almak için actor imzası üretmek; receipt'i başka intent'e taşımak (PI-8) | Verifier/PEP Acceptance revoke; domain operasyonu |
| **Offline verifier** | Contract'a uymaya (beyan) | Rapor doğruluğuna (NOT GUARANTEED) | Kendi audience'ındaki contract'lar; horizon ve slice kadar (SEC13 kuralıyla) | Merkezde slice'ı ikinci kez harcatmak; yeni contract almak (profile Acceptance revoke sonrası) | `predicate-input` Acceptance revoke; issuer-side red (PI-12) |
| **Executor** | Continuation'da sormaya, stop beyanına (beyan) | Effect truth'una (Claim) | Çalışan işin devamı; yanlış attestation | Continuation'ı kendi adına istemek (E31); release'i kendi başına yapmak (P27) | Instance restriction/terminate; attestation issuer Acceptance revoke |
| **Approval Surface** | Sadık render + user act toplamaya (beyan) | Render'ın doğruluğunun kayıttan tespitine | Kendi kullanıcılarından farklı intent'e assertion toplamak (DL-2) | Approver'ın AIS'i ve assertion'ı olmadan contribution; DENY'ı aşan onay (XI-6) | Surface conformance Acceptance'ı; bağımsız surface şartı |
| **Relay / SSF transmitter** | Teslim etmeye (best effort) | Hiçbir güvenlik kararına (INV-24) | Event gecikmesi/kaybı/sahte event | Authority genişletmek (PI-9) | Receiver re-query; event imzası |
| **Work / coordinator** | Gate ve dikkat yönetimine | Access requirement'ını karşılamaya (EI-4) | Onay isteklerini yanlış yönlendirmek, approver'ı bombalamak | Authority yaratmak; Gate ile DENY aşmak | Work'ün kendi kontrolleri; Access request rate policy |
| **One / agent / model** | Kendi Instance'ı ve Mandate'i içinde exercise'a | Talimat kaynağı olmaya (A-7) | Grant ∩ Mandate ∩ budget içinde her şey | Grant/genişletme/approval'ı kullanıcının Instance'ı olmadan (E23) | Mandate revoke, instance.terminate, suspend |
| **Witness** | Checkpoint'leri sadakatle co-sign etmeye | Authority'ye | Sahte co-sign; equivocation'ı gizlemek (tek witness'ta) | Authority state değiştirmek | Witness çeşitliliği (≥ 2); domain witness değiştirir |
| **Protocol governance** | Core spec / meta-schema yayınlamaya | Domain'de kendiliğinden yürürlüğe | Kötü bir core sürüm yayınlamak | Benimsemeyen domain'i etkilemek | Domain benimsemez (sürüm benimseme reserved bir root meta-Exercise'ıdır) |
| **Party controller** | Party'nin key-state'ini ve issuer designation'ını yönetmeye | Authority'ye (Controller ≠ Authority) | Party'nin Instance kurulumunu ve issuer designation'ını | Grant yazmak | Regime recovery (Party'nin) |
| **Realm JOSE / SAML imza anahtarı** (identity plane; OIDC ID token, SAML assertion) | Kendi realm'inin RP'leri için kimlik doğrulama sonucunu imzalamaya | Authority artefaktı imzalamaya (authority artefaktı, kabı COSE veya JWS/JWT/SD-JWT olsun, yalnız o domain'in binding-imzalı excerpt'iyle bağlı operasyonel veya binding anahtarıyla geçerlidir; MD-3, MD-6, T24, G46); başka realm'e | **Golden SAML / sahte ID token**: realm'in bütün RP'lerinde, anahtar rotasyonuna kadar herhangi bir kullanıcı adına sahte authentication (MITRE T1606.002 — ayrıntı doğrulanmadı). Access tarafında yalnız `authentication` use'u kadar (INV-15), issuer radius (SI-3), cooling (SEC18), cutoff (SEC9) | Authority yaratmak; Grant/Acceptance yazmak; başka realm'in RP'sinde geçerli olmak | Anahtar rotasyonu + JWKS'ten çıkarma (`key_epoch` artışı) + issuer cutoff (SEC9); HSM/signer süreci (MD-6) |
| **Operasyonel imza anahtarı** (domain-scoped; ayrı signer süreci) | Kendi domain'inin PAP/receipt/checkpoint excerpt'lerini PD ömrü içinde imzalamaya | Başka domain'e (DomainID must-understand; G47); binding'i değiştirmeye | Kendi domain'inde, anahtar ömrü (PD 1 saat, tavan 24 saat) ve her verifier'ın yerel tavanı (U25, U41) içinde sahte PAP/receipt | Başka domain'de kabul edilmek (Storm-0558 / CVE-2025-55241 sınıfı; K-6 → G47); binding anahtarı yerine geçmek | `key_epoch` artışı; `domain.recover` (SEC21); signer süreci yeniden kurulum |
| **Binding anahtarı** (HSM, quorum) | Domain Metadata binding'ini ve operasyonel anahtar delegasyonunu imzalamaya | Gündelik imzaya | Provider imza anahtarı satırı (U25, N-26) + operasyonel anahtar yetkilendirme | Quorum'suz kullanım (HSM politikası, UDC) | `domain.recover`; HSM quorum değişikliği |
| **LDAP / Kerberos / RADIUS / WS-Fed gateway süreci** | Eski protokol bind'ini identity plane authentication olayına çevirmeye | Authority'ye; parola dışı credential'a | O gateway'den bind eden kullanıcıların parolaları (gateway açık metin görür); o realm için sahte authentication | Realm dışına çıkmak; signer anahtarına erişmek (ayrı süreç, ayrı seccomp/Landlock profili); Kerberos C FFI'nin ana süreç belleğine erişmesi | Gateway'i kapatma; etkilenen kullanıcılar için credential reset; realm cutoff |
| **SCIM istemcisi** (gelen provisioning) | Acceptance'ta beyan edilen `subject-selection` / `identity-binding` attribute'larına | Grantor olmaya (INV-16) | HR / claim issuer satırı ile aynı: mevcut rule-shaped Grant ceiling'leri içinde seçim; sırasız/eski pozitif Claim (K-8) | Grant ceiling'ini aşmak | SCIM token revoke; Acceptance cutoff (SEC9) |
| **Parser worker** (SAML/XML, gerekirse BER/CBOR; izole süreç) | Girdiyi normalize edilmiş yapıya çevirmeye | İmza doğrulama sonucunu tek başına belirlemeye; anahtar materyaline | Hizmet ettiği realm'de XSW-sınıfı yanlış ayrıştırma ile sahte assertion kabulü; worker çökmesi (DoS) | Signer'a / ana süreç belleğine ulaşmak (ayrı süreç, network syscall yok) | Worker yeniden başlatma; XSW regresyon korpusu; parser sürüm geri alma |
| **Co-tenant** (aynı fiziksel host'taki başka kiracı / iş yükü) | Hiçbir şeye | Her şeye | Mikromimari yan kanalla sır sızıntısı (DL-10) | Authority, kayıt veya karar değiştirmek (yan kanal yalnız gizlilik) | Dedicated compute (B4), `mitigations=auto,nosmt` (U54) |
| **Destek personeli (support access)** | Kullanıcının verdiği support Grant'ı kapsamında okumaya/işleme | Kullanıcı adına AIS üretmeye (impersonation yok) | Support Grant'ı kapsamı ve süresi | Kullanıcı olarak oturum açmak; Grant dışına çıkmak (G53) | Support Grant revoke; süre sonu |

**Freeze sorusu:** Tablonun "Asla" sütunundaki her satır bir GUARANTEED BY SEMANTICS sınırıdır ve INV-1/INV-2 (tek kaynak, tek yazma yolu), INV-15 (use-scoped acceptance), PI-7 (actor yalnız AIS'ten) ve INV-29 (custody ≠ root) ile kapanır. Hiçbir bileşen kendi satırının ötesine geçemez → **NO**.

**Suiss-hosted provider operatörü: custody ≠ root.**

Operatörün authority **yaratamaması** iki bağımsız semantik bariyere ve bir tespit mekanizmasına dayanır: (1) ve (2) semantiktir ve her biri tek başına yaratımı engeller (BY SEMANTICS); (3) önleme değil **tespittir** (UNDER DECLARED CAPABILITY — birisi replay yaparsa):

1. **Tek yazma yolu** (INV-2, PI-4): authority state yalnız meta-Exercise ALLOW'u ile değişir; "admin API" bir meta-Exercise Request'e indirgenir; operatörün Genesis'te verilmiş bir Grant'ı yoktur (INV-29).
2. **Actor attribution** (PI-7): her `commit`/`continue` kaydı actor Instance'ının KeyBinding'iyle imzalı AIS taşır ve Record Export'ta korunur; operatör AIS üretemez.
3. **Replay — tespit** (INV-27, PI-6): export'u open reference evaluator ile replay eden herkes, AIS'siz veya lineage'sız bir meta-Exercise'ı ve yanlış bir ALLOW'u tespit eder.

**Garanti olmayanlar** (aynı dürüstlükle): (a) operatör **custodian** ise (2) kırılır → DL-1; (b) operatör **surface'i** de sunuyorsa kullanıcı act'i yanıltılabilir → DL-2; (c) (3) yalnız birisi replay yaparsa tespit eder (UNDER DECLARED CAPABILITY); (d) operatör hizmeti reddedebilir (availability) ve equivocation yapabilir (witness yoksa tespit edilemez). Bu yüzden Suiss-hosted domain'lerde varsayılanlar (SEC17–SEC20): domain root'ları ve reserved Grant tutanlar **non-custodial** controller + cihaz-bağlı passkey kullanır; custodial mod **user-gated**'dir; `domain.recover` entry'sinin anahtarları Suiss'te değildir; en az bir witness Suiss'ten bağımsızdır; revocation sınıfı ve CT3 commit'leri ack'ten önce kapsayan checkpoint'e kadar bütün kayıtlarıyla (önek) root kontrolündeki provider-dışı replica'ya ulaşır (SEC23); CT3 Approval Surface için bağımsız (Suiss dışı veya platform-trusted) bir render yolu sunulur.

### 13.3 Witness, replica ve inclusion proof

Witness yalnız checkpoint commitment'ını (kök + pozisyon) co-sign eder; kaydı tutmaz. Forced recovery kayıtları ister. Bu yüzden iki ayrı capability vardır: **co-sign ≠ replica**.

| Gereksinim | POLICY DEFAULT | Neden |
|---|---|---|
| Witness sayısı ve bağımsızlığı | ≥ 2 witness; en az biri provider'dan ve provider operatöründen **bağımsız** (SI-12); Suiss-hosted domain'de en az biri Suiss dışı | Tek witness provider'la birlikte equivocate edebilir |
| Checkpoint sıklığı | Her 60 saniyede veya her 1,000 kayıtta (hangisi önce) bir checkpoint witness'a; değişiklik olmasa da cadence (heartbeat) checkpoint'i üretilir ve log'a `checkpoint` Claim kaydı olarak ingest edilir | Kayıp suffix üst sınırı; sessiz domain'de metadata ve status `iat` tazeliği |
| **Witness/replica-before-ack** (SEC23) | Revocation sınıfı Exercise'lar (`*.revoke`, `instance.terminate`, restriction ekleyen `policy.set`, Acceptance daraltma) ve CT3 commit'leri, kapsayan checkpoint en az bir bağımsız witness tarafından co-sign edilmeden **ve** o checkpoint pozisyonuna kadar **bütün kayıtlar** (önek — yalnız revocation/CT3 kaydının kendisi değil; mevcut Record Export akışı; root kontrolünde) domain'in beyan ettiği provider-dışı replica'ya ulaşmadan **acknowledge edilmez**. Diğer kayıtlar için ayrı ack şartı yoktur; önek şartı onları revocation/CT3 ack'lerinde zaten taşır. Replica capability'si Genesis / Domain Metadata'da beyan edilir; Suiss-hosted şablonda zorunludur | E20'nin tam "witness/replica'ya ulaşmadan acknowledge etmeme" capability'si: witness yalnız commitment'ı (kök + pozisyon) co-sign eder, kaydı tutmaz; forced recovery "N'den devam" için kayıtları ister (INV-27) — **co-sign ≠ replica**; checkpoint hash chain/Merkle kökü olduğundan kökü yeniden üretmek o pozisyona kadar bütün önek'i ister — **replica'daki tek kayıt ≠ replica'dan yeniden üretilebilen checkpoint**; en önemli kayıp (revocation) yalnız provider'da kalmaz |
| Verifier tarafı | CT1 offline/intermittent contract'larda verifier'ın Domain Metadata tazeliği ≤ contract Δ, bağımsız witness cosign'ıyla ölçülür (TI-RT5); recovery/handover koşulunda `N_cited` witness co-signed olmalı | P18 capability'si |

Witness/replica-before-ack (önek) + evaluator-side guard (N ≥ R*) + witness quorum'u ve replica erişilebilir iken ack edilmiş revocation/CT3'ün kaybolmaması **UDC**'dir (→ U10); witness yoksa, replica yoksa, replica erişilemezken veya kesilmiş replica ile **NG** (replica'sız witness'lı domain forced recovery yapabilir, ama (N, witness en yüksek] aralığı beyanlı kayıp suffix'tir; N-14). Son revocation/CT3 ack'inden sonraki diğer kayıtların (ör. CT1 consumption) kaybı checkpoint sıklığıyla sınırlı risk olarak beyan edilir.

**Inclusion proof gereksinimleri.** `superseded-at` eski provider anahtarıyla imzalı bir artefakt (PAP, ValidityContract, reusable Decision, Decision Receipt, exact-intent token) için kabul edilebilir kanıt (P18, SEC25):

1. **Exact içerik bağı:** artefaktın exact içeriği (digest veya authority-relevant alanları: bounds, holder, horizon, slice, target digest …) `N_cited`'de commit edilmiş `projection.issue` / DecisionRecord içeriğiyle eşleşir; ExerciseID / `projection_exercise` yalnız adrestir. DecisionRecord ürettiği artefaktın digest'ini value içeriği olarak taşır.
2. **Commitment'a dahil olma:** o kaydın `N_cited`'deki Authority Record commitment'ına dahil olduğunun kanıtı (Merkle yolu; biçim §16.6).
3. **Checkpoint'in kendisi** en az bir bağımsız witness tarafından co-sign edilmiştir (aksi hâlde eski provider onu da equivocate edebilir). Recovery'de `N_cited` = N; handover'da inclusion C_k'ye karşıdır ve C_{h+1}'e consistency path ile bağlanır (U27).
4. Work'ün Gate receipt doğrulaması aynı kuralı uygular: target digest `N_cited`'deki kayıtla eşleşmeyen eski-anahtarlı receipt Gate'i karşılamaz.

**Equivocation.** Önleme NG (fiziksel, N-13). Tespit UDC: en az bir bağımsız witness + checkpoint karşılaştırması (gossip; U9). Eski provider'ın yazmaya devam etmesi: bu yazılar devam eden lineage'da authoritative değildir (BS, G21); client'ların bunu fark etmesi Domain Metadata tazeliğine bağlıdır (UDC, TI-RT5).

**Provider değerlendirme doğruluğu.** Provider yanlış ALLOW üretebilir (önleme NG, N-13). Tespit için POLICY DEFAULT: Suiss-hosted domain'lerde domain'in seçtiği bir taraf CT3 kararlarının tamamını ve rastgele %1 CT2 kararını open reference evaluator ile yeniden değerlendirir (INV-27, PI-6); uyuşmazlık kanıttır ve `domain.handover` / `domain.recover` gerekçesidir, çıkışı durdurmaz (G32). Yeniden değerlendirme yapılmazsa tespit garantisi yoktur (U13).

### 13.4 Guarantee matrix

Her satır tam olarak bir sınıftadır (§3.3); iki yönlü iddialar iki satır olarak yazılır. G = GUARANTEED BY SEMANTICS (BS), U = GUARANTEED UNDER DECLARED CAPABILITY / POLICY (UDC), N = NOT GUARANTEED / PHYSICALLY UNSATISFIABLE (NG/PU). G32–G44, U28–U34 ve N-27–N-30 red-team sırasında frozen sınıfların kendi satırlarıdır; yeni guarantee değildir. Sessiz depolama bozulması iki satırdır: tespit öncesi NG (N-29), tespit sonrası UDC (U30); kayıt kimliği commitment olduğu için bozulma log içeriğini değiştirmez (G34, BS).

| # | İddia | Koşul (yalnız UDC) |
|---|---|---|
| | **GUARANTEED BY SEMANTICS (BS)** | |
| G1 | Positive authority yalnız Anchor lineage'ında meta-Exercise ile doğar; başka hiçbir sistem authority yaratamaz |  |
| G2 | Non-amplification: child ⊆ parent; Exercisable = Holding ∩ Mandate; projection ⊆ source |  |
| G3 | Her exercise lineage'daki bütün BudgetTerm'lerden draw eder; tüketilebilir birim at-most-once; merkezde offline slice ikinci kez harcanamaz; bir Exercise için Σrelease ≤ draw (TI-RT8) |  |
| G4 | Revocation commit anından itibaren sonraki her online commit/continue/projection.issue için DENY'dır |  |
| G5 | Invalidity terminal ve cascade'dir; hiçbir şey canlanmaz; re-qualification yeni episode'dur |  |
| G6 | Restriction yalnız daraltır; kaldırılması genişletmedir; gevşetme mevcut requirement'ı karşılamayı ister |  |
| G7 | Bir Claim yalnız kendi Acceptance use'unda karar girdisidir; ingest ≠ acceptance |  |
| G8 | Issuer compromise'ı yalnız use'unun beyan edilmiş etkisini üretir; Grant/Acceptance/reserved/meta yetkisi üretmez |  |
| G9 | Ingest-time cutoff narrowing'dir ve dayanan episode'ları terminal kapatır |  |
| G10 | Foreign authority yalnız foreign-authority Acceptance + bridging ceiling ile; domain'ler arası yazma yok |  |
| G11 | Kabul edilmemiş schema sürümü/mapping hiçbir Grant'ın kapsamını değiştiremez; prefix pin'li; reserved express-only |  |
| G12 | Approval yalnız exact digest'e bağlı contribution Exercise'ıdır; DENY/budget/ceiling'i aşamaz; single-use |  |
| G13 | Onaylanan digest = Exercise'ın intent digest'i; intent digest yüzey-bağımsız |  |
| G14 | Actor attribution yalnız actor Instance KeyBinding'li AIS ile; PEP/transport kimliği actor değil; statement'sız istek Anonymous |  |
| G15 | Capacity ∈ basis Grant agency; Anonymous hiçbir şey tutamaz/veremez/katkı yapamaz |  |
| G16 | Access kararı hiçbir zaman UNKNOWN değildir; protocol hatası/rejection effect üretmez |  |
| G17 | Aynı kayıtlar + girdiler → aynı karar ve consumption (provider yükümlülüğü). Normatif hakem L0/L2 metni + conformance vektörleridir (RT8); yeniden değerlendirme farkı kanıttır ve divergence quarantine'e gider, çıkış kapısı değildir |  |
| G18 | Decision ≠ credential; receipt tek Exercise/intent/audience'a bağlı; projection holder-bound (bearer yok) |  |
| G19 | Hiçbir event, event kaybı veya sıra farkı authority genişletmez |  |
| G20 | Must-understand fail closed; downgrade genişletme sınıfıdır |  |
| G21 | Domain'de tek authoritative lineage; recovery sonrası N (SEC21) dışı eski-provider kayıtları ve exact-content inclusion proof'suz eski-anahtarlı artefaktlar semantik olarak geçersizdir; handover sonrası için U27 |  |
| G22 | Authority backdate edilemez; occurredAt yalnız daraltmayı seçer |  |
| G23 | Kayıtların existence/attribution/lineage/digest/zamanı silinemez |  |
| G24 | First-party/hosting/custody/operator hiçbir semantik ayrıcalık veya authority taşımaz |  |
| G25 | Açık ValidityContract penceresi içindeki envelope içi kullanımın "authority içi" sınıflanması |  |
| G26 | Batch atomik değil; her öğe kendi Exercise'ı |  |
| G27 | Açıklama/advisory/search/event viewer authority'sini aşmaz; `undisclosed` restriction requester'a ve policy authority'si olmayan viewer'a yalnız sınıf olarak görünür; audit scope policy içeriğini görür |  |
| G28 | Audit export, portable/reusable artefakt üreten ve consequential okumalar kayıtlı, attributable Exercise'tır; diğer okumalar (explain, search, S2/S6, check) PI-4 contract'ından geçer ama canonical kayıt değildir |  |
| G29 | Break-glass ve containment yalnız önceden verilmiş reserved Grant'ların Exercise'ıdır |  |
| G30 | Gate satisfied ≠ ALLOW; Work Access requirement'ını karşılayamaz |  |
| G31 | Revocation ≠ stop: Access stop iddia etmez; continuation DENY'ı semantiktir |  |
| G32 | Replay divergence handover'ı / recovery'yi (çıkışı) durdurmaz; çıkışın kendisi UDC'dir (U24 / handover işbirliği) (TI-RT1) |  |
| G33 | Derived katman veya rebuild-diff hakemi canonical log'u ve kayıtlı DecisionRecord effect'ini ezmez (TI-RT1, TI-RT4) |  |
| G34 | Kayıt bozulması log içeriğini değiştirmez; kayıt kimliği commitment'tır (TI-RT11) |  |
| G35 | Başka domain'in operasyonel anahtarıyla imzalanmış artefakt kabul edilmez (excerpt DomainID) (TI-RT6) |  |
| G36 | Issuer sırası belirsizse disqualifying kazanır; eski / sırasız Claim episode açmaz (TI-RT7) |  |
| G37 | Örtük bilgi sızmaz: audit kapsamı altındaki viewer'a pozisyon taşıyan tanımlayıcılar opaque token, event id HMAC (TI-RT10) |  |
| G38 | Spec ↔ implementasyon ayrışmasında spec kazanır (vektör kapsamı HL-12) (TI-RT12) |  |
| G39 | UI bilinemeyeni bildirmez: Access cevabına kadar "Not confirmed — checking"; ack'siz "confirmed" yok ("witness pending"); "Not recorded" yalnız nonce devam eden lineage'da yoksa (SEC23, RT23, RT24) |  |
| G40 | Aynı nonce'la retry çift Exercise üretmez (TI-8) |  |
| G41 | Commit'siz ALLOW yoktur (hot domain / hot key'de retry veya rejection) (TI-9) |  |
| G42 | İmzasız artefakt yayınlanmaz (HSM kesintisinde artefakt gecikir) (TI-12) |  |
| G43 | Derived kesintisinde taze imzalı stale status yayınlanmaz (SI-7, T24; bileşen CMP-7) |  |
| G44 | Claim burst'ünde kota üstü Claim episode açmaz; narrowing öncelikli (P19, SI-20) |  |
| | **Identity plane eklemeleri (BS)** | |
| G45 | Identity plane'in her çıktısı (ID token, SAML assertion, session, SCIM/LDAP sonucu) Access'te yalnız kabul edildiği use'ta bir Claim'dir; authority yaratmaz. Grant tek pozitif kaynaktır (INV-12, INV-15, MD-4) |  |
| G46 | Geçerli bir authority artefaktı (receipt, PAP, exact-intent/bounds token, checkpoint, status list, Domain Metadata; kap COSE veya JWS/JWT/SD-JWT, T24) yalnız o domain'in binding-imzalı excerpt'iyle bağlı operasyonel anahtarı veya binding anahtarıyla imzalıdır. Realm JOSE/SAML anahtarıyla veya RSA ile imzalı bir nesne, kabı ne olursa olsun, authority artefaktı değildir (MD-3, MD-6, T24, TI-RT6) |  |
| G47 | DomainID must-understand'dir: başka domain'in (veya domain'siz) anahtarıyla imzalı excerpt/PAP bu domain'de geçerli değildir — Storm-0558 / CVE-2025-55241 sınıfı (K-6) semantik olarak kapanır (MD-6). Kural BS'dir; etkisi conformant verifier'dadır (U25); sınırın tek metni HL-8'dedir |  |
| G48 | Karar ve doğrulama yolunda hiçbir hata durumu ALLOW / `active=true` / yeni token üretmez: rate limiter, risk motoru, cache, introspection backend'i, policy motoru, parser hatası → DENY, `active=false`, 503 veya protocol rejection (MD-8, INV-26). Introspection hiçbir durumda 503 dönmez: primary'ye veya tazelik kaynağına ulaşılamıyorsa her token için, cache-hit dahil, `active=false` döner |  |
| G49 | Cache'in **hiç görmediği** kullanıcı/oturum/token için cevap "geçerli" değildir: ya canonical kaynağa gidilir ya fail-closed; zaman tabanlı degraded pencere yalnız "cache bayat" durumuna uygulanabilir (MD-7) |  |
| G50 | Identity plane login ve refresh yolları backend erişilemezken 503 (+ refresh'te `Retry-After`) döner; refresh asla `invalid_grant` döndürmez (oturumu yanlışlıkla yok etmez) ve asla yeni token basmaz (MD-8) |  |
| G51 | `authz_epoch` cache'i advisory'dir; authority kararının girdisi AuthorityStateBasis / `applied_pos`'tur; epoch artışı hiçbir zaman genişletme kaynağı değildir (MD-4, MD-7) |  |
| G52 | Authority düzeyinde çapraz-domain korelasyon (aynı Party'nin iki domain'deki pseudonym'lerinin bağlanması) yalnız kayıtlı bir bridging Grant / IdentityBinding ile oluşur; projeksiyon ve PAP'ta PartyRef domain-pairwise pseudonym'dir (MD-10, INV-17, E4, PI-8) |  |
| G53 | Destek erişimi bir Grant'tır; impersonation yoktur: destek personeli kullanıcının KeyBinding'iyle AIS üretemez, her destek eylemi kendi Instance'ına attribute edilir (MD-9, PI-7) |  |
| G54 | Identity plane yapılandırma değişiklikleri (IdP ekleme, faktör politikası, client kaydı, realm anahtar politikası) domain action'ıdır; tek yazma yolundan (meta-Exercise) geçer (MD-14, INV-2) |  |
| G55 | Alg allowlist Domain/Realm Metadata'dandır; `none`, allowlist dışı alg ve JWS'te `alg: EdDSA` reddedilir; bilinmeyen alg/sürüm fail-closed'dur (MD-3, §13.7.8) |  |
| G56 | Authority değerlendirmesinde aritmetik taşma (budget, count, window toplamı) DENY'dır; taşmış değer hiçbir zaman kısmi ALLOW üretmez (MD-2 checked arithmetic) |  |
| | **GUARANTEED UNDER DECLARED CAPABILITY / POLICY (UDC)** | |
| U1 | PEP kararı effect'ten önce uygular | Conformant PEP |
| U2 | Verifier horizon/Δ/status/slice'a uyar; revocation penceresi fiilen kapanır | Verifier profile (secure clock, tamper-evident sayaç) |
| U3 | Grup audience'lı slice toplamı ≤ slice | Ortak tamper-evident sayaç beyanı |
| U4 | Offline report chain'inde gizleme/sıra değişikliği tespiti | Verifier imza/sayaç capability'si |
| U5 | Executor checkpoint'te sorar; stop teyidi | Executor control capability + teyit |
| U6 | İcra edilen body = onaylanan digest | Conformant Surface + PEP |
| U7 | Kullanıcının gördüğü render = AAS'deki render | Conformant ve (CT3'te) bağımsız surface |
| U8 | PEP zinciri upstream bağı | Declared RestrictionPolicy + causal-bound allowance |
| U9 | Equivocation tespiti | ≥ 1 bağımsız witness + karşılaştırma. Consumer dili OQ-4 kanıtına kadar yalnız XI-12 koşullarıyla |
| U10 | Forced recovery'de ack edilmiş (witness'lı ve replica'lı) revocation/CT3 kaybı yok (rollback ve çalınmış anahtarla üretilen çatallanma dahil) | Witness/replica-before-ack (SEC23: bağımsız witness co-sign'ı **ve** kapsayan checkpoint'e kadar bütün önek'in root kontrolündeki provider-dışı replica'ya ulaşması) + evaluator-side rollback guard: değerlendirici beyan edilmiş her witness'ın en yeni checkpoint'ini ve replica'yı kendisi sorgular, N ≥ R* (SEC22) + N = SEC21 tanımı, çatallanmada kayıtlarla yeniden üretilebilen dal; witness quorum'u ve replica erişilebilir |
| U11 | Eski provider'ın yazmayı fiilen kesmesi | Fencing/witness |
| U12 | Recovery sonrası eski-anahtarlı artefaktın fiilen reddi | Domain Metadata tazeliği = verifier'ın pinli kümesinden bağımsız bir witness'ın ≤ Δ (yoksa ≤ 1 saat) cosign'ı (TI-RT5; heartbeat checkpoint'i sessiz domain'de de tazeler) + witness'lı checkpoint + exact-content inclusion kanıtı |
| U13 | Provider yanlış kararının tespiti | Export + open reference evaluator ile yeniden değerlendirme yapan taraf; çıkışı durdurmama iddiası G32'dir (BS) |
| U14 | Actor anahtarının yalnız actor tarafından kullanılması | Non-custodial veya user-gated custody |
| U15 | Custodian'ın kullanıcı act'i olmadan impersonation yapamaması | User-gated custody + attestation |
| U16 | Provider operatörünün recovery yapamaması | Recovery entry anahtarlarının provider dışı custody'si (SEC20) |
| U17 | Approver'ların "farklı kişi / farklı cihaz / farklı surface" olması | Independence term'leri (policy) |
| U18 | Rate, throttling, oracle ve structuring kontrolleri | Domain policy (§13.7) |
| U19 | Intermittent revocation propagation ≤ Δ | Verifier status freshness |
| U20 | Agent'ın gerçek dünya kimliği / runtime config'i | Identity Binding / attestation |
| U21 | "Existed by T" | Witness zaman sabitlemesi |
| U22 | Redakte içeriğin geri getirilemezliği | Bütün kopyaların redaksiyonu uygulaması |
| U23 | Merkezde PEP replay'inin tek effect üretmesi | PEP/Executor idempotency |
| U24 | Forced recovery yapılabilmesi (kayıtlar provider dışında olsun olmasın; kilit yok) | Genesis rootTerms'te domain'in principal yapısında karşılanabilir bir recovery entry'si beyanı (Sole root: ayrı donanım-bağlı recovery Instance'ları); replica yok/sorgulanamaz veya R* < witness en yüksek ise rollback guard REQUIRE_ACTION + N = R* + beyanlı kayıp suffix (SEC22) + recovery re-anchor: kol (ii) sonrası witness/replica-before-ack yeni lineage'da çalışır (§16.6) |
| U25 | Çalınmış provider imza anahtarıyla basılmış PAP/receipt/token'ın etkisinin her verifier'ın yerel kabul tavanıyla (horizon, slice, operasyonel anahtar penceresi, bridging ceiling/terms) sınırlı kalması | Verifier'ın Domain Metadata / Verifier Profile'da ilan edilen tavanları must-understand uygulaması (`cap_horizon`: CT gerçekleştirilen intent'ten, class/variant Verifier Profile'dan; artefaktın beyanı kullanılmaz) + Domain Metadata tazeliği TI-RT5 anlamında ≤ Δ; status-list anahtar penceresi örtüşmesi (T20) |
| U26 | Custodian'ın imzaladığı regime key-event'lerinin Access'e ingest edilip Party'nin Changes görünümünde görünmesi | Party Identity Regime / issuer conformance (key-event'lerin Claim olarak yayınlanması + Acceptance) |
| U27 | Kooperatif handover sonrası lineage dışı eski-anahtarlı artefaktın reddi | `superseded-at C_{h+1}` + handover predicate'i (§9.10); `N_cited` lineage değiştiren kayıttan; handover drain (RT14); verifier kurala uyar. Aynı-provider self-handover (binding re-anchor, OP-60) profilinde eski anahtar yalnız yeni üretim için `superseded` olur; bundle'sız eski klasik artefakt handover predicate'ine yalnız kırılma ilanından sonra takılır (CR-45 semantiği kanoniktir; U71, HL-34) |
| U28 | Forced recovery kayıp suffix'indeki AIS'in yeni lineage'da ikinci Exercise açmaması (RT6) | `nonce-closed/pre-recovery`: SEC22 R1 quarantine policy'si yürürlükte (kaldırma CT3) + ilk değerlendirmede AIS yaşı ≤ intent validity tavanı (profile kuralı; tavan POLICY DEFAULT = hot-path nonce ufku) + trusted time (TI-RT2) |
| U29 | Zaman-bağlı terimlerin (horizon, time-lock, cooling) saat sıçramasıyla kaymaması (TI-RT2) | ≥ 2 bağımsız zaman kaynağı + sınırlı ilerleme + witness çapraz kontrolü (TI-RT2, FA-3); ihlalde kayma ≤ sapma |
| U30 | Sessiz depolama bozulması **tespit edildikten sonra** bozuk satıra dayalı karar verilmemesi (tespitte commit durur; hakem Genesis'ten fold) (TI-RT11) | FA-14 tespiti (page checksum, ECC, okumada leaf/body commitment doğrulaması); kayıt kimliği = commitment (TI-RT11). Tespit öncesi N-29 |
| U31 | Timeout sonrası sonucun intent validity penceresi sonunda sabitlenmesi; kuyruklu / pending revoke olmaması (RT23) | Commit edebilen retry ≤ AIS'in intent validity'si (etkileşimli revoke'ta kısa değer, ENGINEERING ASSUMPTION; her durumda ≤ POLICY DEFAULT tavanı) + trusted time (TI-RT2) |
| U32 | DB primary failover'da ack'li kaydın kaybolmaması (FA-1); identity plane'in ack edilmiş güvenlik yazmaları (kimlik bilgisi, MFA, iptal, kilit, refresh rotasyonu) dahil — AZ kaybında kaybolmaz (OPI-4; §17.13) | Sync standby (FA-1); identity plane: ≥ 2 sync standby, `ANY 1`, dürüst fsync (OP-24). Single-node profilinde bu satır geçerli değildir (HL-40, N-59) |
| U33 | Region kaybında iki yazar olmaması (FA-13) | Cross-cell fence (FA-13) |
| U34 | Toplu meta-Exercise'ın domain'i kilitlememesi (TI-RT9) | O(1) işaret + commit başı iş sınırı (ENGINEERING) |
| | **Identity plane eklemeleri (UDC)** | |
| U35 | `session_epoch` fast revoke yayılımı: aynı düğüm 0; aynı cluster p99 < 250 ms; cluster'lar arası < 500 ms (§13.11 satır EP-3); identity plane iptalinin Access yüzeylerinde (login/refresh/introspection) polling aralığı içinde uygulanması bu satırdır (§17.13; OP-21) | Strict profil; node cache + outbox polling 100–250 ms; cache miss → DB; ölçüm EA (MD-7). Veritabanı erişilemezken bu süre **verilmez** (geçersiz kılma koşulu) |
| U36 | Salt-JWT doğrulayan RS'de iptal edilmiş oturumun/token'ın kabul süresi ≤ access token ömrü + clock skew | RS `exp` ve audience'ı doğrular; token ömrü PD: admin/yüksek etkili client'ta ≤ 60 dk, hızlı profilde 5 dk; 28 saatlik token reddedilir (MD-7) |
| U37 | Introspection (strict profil): tazelik kanıtlanabiliyorsa güncel sonuç; kanıtlanamıyorsa `active=false`; RS 5xx'i DENY sayar. Tek kural: primary'ye veya tazelik kaynağına ulaşılamıyorsa her token için `active=false` döner; cache-hit dahildir; 503 dönmez (OPI-3) | Conformant RS; introspection tazelik hedefi 250 ms (EA) (MD-8) |
| U38 | Sinyal tüketen RS (SSF/CAEP alıcısı) teslim edilmiş bir session-revoked / credential-change olayından sonra beyan ettiği işlem süresi içinde oturumu sonlandırır | Alıcı conformance'ı ve teslim; teslimin kendisi NG (N-38); garanti tavanı yine U36'dır (sinyal hızlandırıcıdır, sınır değildir) |
| U39 | Önceden imzalanmış ve beyanlı ömürlü self-contained identity token'ları backend erişilemezken RS'in yerel doğrulamasında ömürleri içinde kabul edilmeye devam eder (identity degraded window = ValidityContract horizon'u; fail-open değildir); bu sırada yeni token basılmaz | Yalnız identity plane'in önceden imzalı self-contained token'ları ve yalnız RS'te yerel doğrulama. Introspection DB erişilemezken `active=false`'tur (EP-3, U37). 60–300 s fail-open pencereleri hiçbir token sınıfı ve hiçbir plane için kabul edilmez (MD-8). Authority-bearing token/PAP için ayrı degraded window yoktur; SEC27 continuity envelope'u geçerlidir |
| U40 | Pairwise `sub` (OIDC/SAML) ile iki RP aynı kullanıcıyı tanımlayıcı üzerinden ilişkilendiremez | Client public `sub`'a opt-in yapmamıştır (MD-10); RP'lere korelasyon attribute'u (e-posta, telefon, ulusal kimlik) disclose edilmez; RP'ler aynı sector identifier'ı paylaşmaz (MD-10). E-posta/telefon/ad claim'lerinin disclose edildiği RP'ler arası korelasyon kalan yüzeydir (RR-22, N-31; §10.12) |
| U41 | Çalınmış operasyonel anahtarın etki penceresi ≤ anahtar ömrü (PD 1 saat, tavan 24 saat) ∩ verifier yerel tavanı | Signer süreci ayrımı; `key_epoch`; verifier'ların anahtar penceresini uygulaması (MD-6; U25 uzantısı) |
| U42 | Signer sürecinden anahtar materyali sızmaz (ağ çağrısı yok, salt-okur anahtar deposu, `memfd_secret`) | Linux Landlock ABI ≥ beyanlı minimum (HardRequirement; `/healthz`'de loglanır), iki fazlı seccomp, `PR_SET_DUMPABLE=0`, `no_new_privs`; çekirdek/host ele geçirilmesi kapsam dışı (N-33) (MD-6) |
| U43 | Parser worker'daki bellek bozulması / panic signer'a ve ana süreç belleğine ulaşmaz | Ayrı süreç, ağ syscall'ı yok, şemalı IPC (UDS + SCM_CREDENTIALS), kaynak limitleri (MD-18) |
| U44 | Hesap varlığına bağlı fark status/body/header/redirect'te yoktur; zamanlama farkı ölçüm eşiği altındadır | Adaptive delay + varlıktan bağımsız Argon2 semaphore (dummy Argon2 yok — MD-18); p50–p95 regresyon suite'i; ağ jitter'ı (HTTP/2 ~1.73 ms) ölçüm sınırıdır — sıfır sızıntı NG (N-46) |
| U45 | Sır karşılaştırması (token, MAC, hash, OTP) constant-time'dır | Platform/derleyici varsayımı: LLVM ct garanti etmez (HL-16); dudect \|t\| > 5 fail, ctgrind, asm snapshot CI'da |
| U46 | Brute-force tavanı (NIST 800-63B-4: ≤ 100 ardışık başarısız deneme) global rate store düşse bile korunur | Global store düşerse yerel strict limiter devreye girer; fail-open yoktur (MD-8) |
| U47 | Parola hash'leme (Argon2) yükü diğer endpoint'leri aç bırakmaz | Semaphore N = floor(bellek·0.5 / m), acquire timeout 500 ms → 503, `spawn_blocking` |
| U48 | Parser kaynak tüketimi (bellek, derinlik, süre) girdi boyutuyla sınırlıdır | §14.6 limit tablosu: boyut parse'tan önce, derinlik ≤ 32 recursion'dan önce, kanaldan gelen `n` ile `with_capacity(n)` yok; fuzz kapsamı (MD-2) |
| U49 | Yayınlanan binary/imajın provenance'ı doğrulanabilir | Sigstore/cosign `certificate-identity-regexp` + issuer doğrulaması; attest-build-provenance; release checkpoint Access witness'larıyla co-signed; SLSA Build L3 seviyesi **doğrulanmadı** |
| U50 | Bağımsız taraf aynı kaynaktan aynı digest'i üretir (reproducible build) | Pinli toolchain, path remap, digest-pinli base imaj, vendor offline, çift build gate |
| U51 | Ack edilmiş security event'i (login, faktör değişimi, revoke, admin eylemi) kaybolmaz | `synchronous_commit=on`; failover grace 0 (split-brain senaryosu §14.8) |
| U52 | Identity audit kaydı tamper-evident checkpoint'e ≤ 1 s içinde girer | Hedef EA; witness co-sign ile |
| U53 | Audit kaydı örneklenmez; audit okuması da loglanır | Audit pipeline kapasitesi; okuma logu sorgu başınadır |
| U54 | Dedicated compute (B4) seçen tenant'ta co-tenant mikromimari yan kanal yüzeyi kaldırılır | Dedicated host/çekirdek, `mitigations=auto,nosmt`; hosting sağlayıcı beyanı (MD-17) |
| U55 | DPoP proof'u replay edilemez | Replay cache TTL = proof ömrü + 2× clock skew; uzun ömürlü paylaşılan nonce; clock skew beyanlı (MD-18) |
| U56 | Release normatif vektörleri, DRT'yi ve proof'ları geçmeden yayınlanmaz | CI bütünlüğü; MD-15(b) release gate; Kani hedefleri kernel'de (§14.8) |
| U57 | Destek Grant'ı süreli, kayıtlı ve kullanıcıya görünürdür | 12 destek değişmezi PD olarak (MD-9) |
| U58 | Crypto-shredding: PII alanları anahtar imhasından sonra okunamaz | Anahtarın yedekte/başka kopyada olmaması; Merkle hash'i ciphertext üzerinde; hukuki "silme" değildir (N-42) |
| U59 | Domain/tenant scope'u olmayan veritabanı sorgusu derlenmez / çalışmaz | Tipli sorgu katmanı (MD-2) + RLS FORCE (MD-5); uygulama ve servis rolleri NOBYPASSRLS ve tablo sahibi değildir; superuser / `BYPASSRLS` / sahip rolleri bu koşulun dışındadır (HL-33) |
| | **NOT GUARANTEED / PHYSICALLY UNSATISFIABLE (NG/PU)** | |
| N-1 | İmzalı bir Claim'in (HR, IdP, KYC, attestation, effect, offline report, Agent Card) doğru olduğu |  |
| N-2 | Event/sinyalin zamanında teslimi |  |
| N-3 | Revocation'ın çalışan executor'ı teyitsiz durdurduğu |  |
| N-4 | Offline verifier'da anında revocation |  |
| N-5 | Effect'in gerçekleştiği, doğru olduğu veya exactly-once olduğu |  |
| N-6 | Kabul edilmiş compatibility mapping'in anlam doğruluğu |  |
| N-7 | Conformant olmayan surface'in sadık render'ı |  |
| N-8 | Onaylayan insanın okuduğu/anladığı/bilgece karar verdiği |  |
| N-9 | Görünüşte bağımsız insanların bağımsızlığı; colluding insanların split authority'yi aşmaması |  |
| N-10 | Modelin prompt injection'a dayanıklılığı; ele geçirilmiş ama yetkili agent'ın tespit öncesi ayırt edilmesi |  |
| N-11 | Alıcının açıklanan veriyi unutması; redaksiyonun dağıtılmış kopyaları silmesi |  |
| N-12 | Karar yüzeyinden policy çıkarımının tamamen önlenmesi |  |
| N-13 | Provider yanlış kararının önlenmesi; equivocation'ın fiziksel önlenmesi |  |
| N-14 | Witness'sız forced recovery'de kayıpsızlık; replica'sız, replica erişilemezken veya kesilmiş replica ile witness'lı domain'de genel threshold'la yapılan rollback'te (DL-6) (N, witness en yüksek] beyanlı kayıp suffix'indeki revocation'ların korunması; son revocation/CT3 ack'inden sonraki (R*, witness en yüksek] aralığındaki diğer kayıtların (ör. CT1 consumption) korunması; hiçbir dalı kayıtlarla desteklenmeyen çatallanmada (provider equivocation'ı + replica yok) çatallanma sonrası kayıpsızlık; witness quorum'u erişilemezken genel threshold'la yapılan recovery'de rollback'in önlenmesi; recovery entry'si beyan edilmemiş ("Recovery not available") domain'de recovery. Bu kolda N = R* |  |
| N-15 | Kötü niyetli verifier raporunun doğruluğu; kaybolan cihazın raporu |  |
| N-16 | Custodial (user-gated olmayan) modda custodian'ın impersonation yapmaması |  |
| N-17 | Kişi tekilliği (Sybil direnci) |  |
| N-18 | Sole root compromise'ının domain içinde kurtarılması |  |
| N-19 | Genesis'in meşruiyeti ("doğru kişiler kurdu") |  |
| N-20 | Access'in availability'si (outage'ın olmaması) |  |
| N-21 | Hukuki non-repudiation / liability |  |
| N-22 | Operatörün body içeriğini okuyamaması |  |
| N-23 | Agent'ın açıklama/remediation'a uyması |  |
| N-24 | Dış sistemde ambient session'ın kullanıcıdan ayırt edilmesi |  |
| N-25 | Compromise penceresinde gerçekleşmiş effect'lerin geri alınması |  |
| N-26 | Provider imza anahtarı çalınmasının tespit/recovery öncesi penceresinde, verifier'ın yerel tavanları içindeki sahte PAP/receipt kabulünün önlenmesi (offline slice'lar merkezde draw edilmemiş olabilir); kurala uymayan verifier'da handover sonrası pencere de bu sınıftadır |  |
| N-27 | İstemcinin timeout'ta commit sonucunu Access'ten bir cevap ulaşmadan bilmesi (HL-5) | — |
| N-28 | Bütün zaman kaynakları ve witness'lar birlikte yalan söylediğinde zaman-bağlı terimlerin doğruluğu (HL-6) | — |
| N-29 | Tespit öncesi sessiz depolama bozulmasının yol açtığı yanlış kararın önlenmesi (HL-2 alt sınıfı; tespit sonrası U30) | — |
| N-30 | Bütün witness'lar kötü niyetliyken lineage dışı imzanın reddi (TI-RT5) | — |
| | **Identity plane eklemeleri (NG/PU)** | |
| N-31 | Aynı KeyBinding, zamanlama, IP/cihaz veya davranış üzerinden çapraz-domain/çapraz-RP ilişkilendirmenin olmaması (DL-9, HL-18; MD-10) | — |
| N-32 | Paylaşılan donanımda co-tenant mikromimari yan kanalının olmaması (DL-10, HL-17; MD-17) | — |
| N-33 | Host/çekirdek ele geçirildiğinde süreç belleğindeki operasyonel anahtarın çalınmaması; sınır U25/U41 penceresidir | — |
| N-34 | `zeroize`'ın sırrın her kopyasını (register, stack spill, swap, core dump, kopyalanmış buffer vb. kapsanmayan 14 vektör) silmesi (HL-21) | — |
| N-35 | Derleyicinin/CPU'nun constant-time kodu koruması (HL-16) — ct yalnız ölçümle UDC (U45) | — |
| N-36 | Async runtime ve HTTP katmanının formel olarak doğrulanmış olması (HL-15 → HL-29); formel kapsam kernel/semantik ile sınırlıdır (§14.8) | — |
| N-37 | WebAuthn/passkey ceremony'sinin post-quantum güvenli olması; CRQC sonrası klasik passkey ile yeni AIS / authentication assertion sahteciliğinin önlenmesi (HL-19; §15.20 J) | — |
| N-38 | SSF/CAEP sinyalinin zamanında ve sıralı teslimi; gelen CAEP yalnız "yeniden sor" tetikleyicisidir, best effort (N-2'nin identity plane uzantısı) | — |
| N-39 | Salt-JWT doğrulayan RS'de iptalin token ömründen önce etkili olması (HL-22) | — |
| N-40 | "Çevrimdışı token'ların tek işlemde iptali" — çevrimdışı tutulan token ömrü dolana kadar geçerlidir | — |
| N-41 | Passkey'in authentication sonrası oturum/token hırsızlığını (infostealer, BitM, AiTM sonrası cookie) önlemesi — "passkey phishing'i durdurur, token hırsızlığını değil" (HL-23) | — |
| N-42 | Crypto-shredding'in GDPR anlamında "silme" sayılması (EDPB 01/2025 yorumu — hukuki nitelik doğrulanmadı) | — |
| N-43 | HSM/KMS imza throughput'unun beyanlı tavan üstünde sürdürülmesi; paylaşılan KMS kotasının korelasyonlu tükenmemesi (AWS ECC ~1,000/s, YubiHSM ~14/s — doğrulanmadı) (HL-20) | — |
| N-44 | crates.io / npm'den gelen paketin yayıncı kimliğinin kriptografik olarak doğrulanması (registry publisher imzası yok, TOFU) (HL-24) | — |
| N-45 | TOTP, push ve SMS OTP'nin AiTM/phishing'e dayanması (SIM swap dahil) | — |
| N-46 | Hesap varlığının ağ üzerinden sıfır zamanlama sızıntısıyla gizlenmesi (U44'ün ölçüm eşiği ötesi) | — |
| N-47 | "Denetlenmiş" veya "formel doğrulanmış" bağımlılığın hatasız olması (Kobeissi ePrint 2026/192: doğrulanmış kütüphanelerde 13 açık) | — |
| N-48 | Aynı RP içinde, kullanıcının kendi açtığı public `sub` / paylaşılan attribute sonrasında unlinkability (opt-in sonrası) | — |
| N-49 | Bilinmeyen bağımlılık açığının (0-day) yayın öncesi tespiti; fuzz yalnız bulgu sınıflarının bir kısmını yakalar (~%40 iddiası — küçük örneklem, doğrulanmadı) | — |
| | **Diğer bölümlerden gelen satırlar — BS (G57–G64)** | |
| G57 | Identity plane oturumu sonlandırıldıktan sonra (logout, `session.revoke`, `session_epoch` artışı) o oturum için yeni token veya kimlik iddiası (ID token, SAML assertion, refresh sonucu) üretilmez; refresh canonical oturum durumunu okur (EP-2). RP tarafındaki kapanma N-51'dir (§10.12; §9 kimlik-iddiası profili) |  |
| G58 | Splicing yoktur: iki geçerli token'dan sahte bir delegasyon zinciri üretilemez; zincirin tek kaynağı lineage kaydıdır (AG-23; §11) |  |
| G59 | Token vault / credential broker'ın upstream token release'i yalnız ALLOW almış bir Exercise'a bağlıdır; Exercise'sız release yetkisizdir. Release kaydı Access projection'ıdır; upstream token içeriği değildir — G2 (projection ⊆ source) upstream token içeriğine uygulanmaz (→ N-54) (E36, EI-26; §11.13) |  |
| G60 | Kanonik olmayan CBOR, kanonik olmayan imza kodlaması veya yapısal sınırı aşan girdi kabul edilmez (gerekçeli protocol rejection); implementasyonlar arası eşitlik HL-12 kadardır (CR-9, CR-10, SAI-41; §15.20 B) |  |
| G61 | Yayımlanmamış (publish-before-use süresini doldurmamış) anahtarla imzalı artefakt üretilmez (CR-25, SAI-46; §15.20 C) |  |
| G62 | Yetkisiz requester'a var olan ile var olmayan hesap / basis / kaynak için cevap **içeriği** aynıdır (yetkisiz ≡ var olmayan); süre kanalı U44 / N-46, policy oracle DL-7 (CR-40, SAI-43; §15.20 G) |  |
| G63 | Operasyonel break-glass yolu (OP-46) ayrı bir kod yoludur ve authority kararı üretmez; authority düzeyinde break-glass yalnız G29 yoluyladır (SI-22; §17.13) |  |
| G64 | Karışık sürümlü rolling upgrade'de hiçbir commit farklı semantikle yapılmaz (sürüm kapısı + activation record; OP-56; §17.13) |  |
| | **Diğer bölümlerden gelen satırlar — UDC (U60–U71)** | |
| U60 | "Yeni içerik + bayat projection" penceresinin kapanması: kaynak q'dan sonra yazılmış içerik için `as_of < q` olan projection reddedilir ve online karar istenir | İçerik pozisyonunu saklayan ve kontrolü yapan PEP (§9.7A.3; PAP verifier opsiyonel sekizinci kontrol, §9.10.1). Saklamayan PEP'te kalan pencere ValidityContract'ın beyan ettiği penceredir (sınıflandırma G25) |
| U61 | Advisory önbellek / türetilmiş indeks cevabının bayatlığı beyanlı sınır içindedir; cevap commit girdisi değildir ve ALLOW üretmez (G51, G27) | `applied_pos` anahtarlı; olumsuz TTL ≤ 1 s; hiç görülmemiş → fail-closed (G49) (§9.11.2; EP-10) |
| U62 | Domain'in mevzuat şablonunun (PSD2 SCA, TR GKD / TR ödeme) kurallarının karar yolunda uygulanması | Şablon domain'de kurulu ve kabul edilmiş (MD-11); conformant surface ve PEP. Mevzuata uygunluğun kendisi N-52'dir (§10.3.4, §10.12) |
| U63 | MCP liste önbelleği (`cacheScope`) çapraz kiracı ifşası üretmez: yalnız Public-Grant-türevli listeler `public` işaretlenir | Access PEP SDK'sını kullanan ve conformance vektörlerini geçen PEP (TI-RT12; AG-12; sınıf UDC). Kendi kodunu yazan PEP N-53 (§11.5.4) |
| U64 | `subscriptions/listen` stream'i ValidityContract horizon'u sonrasında olay taşımaz | Access PEP SDK'sını kullanan, conformant PEP (AG-15). Kendi kodu N-53 (§11.5.7) |
| U65 | Broker'ın Access kararıyla teslim ettiği (`cnf`'siz) upstream token kısa ömürlü ve tek audience'lıdır; `exp` ≤ kararın ValidityContract horizon'u | Upstream AS'nin `exp`/`aud` beyanı + broker kuralı: upstream `exp` horizon'u aşarsa teslim reddedilir ve broker-as-PEP moduna düşülür; CT2+ için varsayılan broker-as-PEP'tir (AG-32; §11.13). Sızıntı NG: N-54 |
| U66 | Vault / broker her release yolunda G59'u (Exercise'sız release yok) zorlar | Vault conformance'ı (E34/E36 yapısı; TI-RT12) |
| U67 | Hesap kurtarma soğuması (cooling) meşru sahibe itiraz penceresi sağlar | Meşru sahip bildirimi alır ve pencere içinde itiraz eder; bildirim teslimi N-2 sınıfındadır; bildirim görülmezse koruma yoktur (§12.10; TN-55, TN-61) |
| U68 | Algoritma kırılması sonrası "existed by T": PQ re-anchor checkpoint'inin kapsadığı kayıtlar için | Re-anchor checkpoint'i kırılmadan önce ML-DSA ile imzalanmış ve PQ witness cosign'ı almıştır; verifier o PQ anahtarlarına kırılmadan önce güvenmiştir (CR-45, FA-5 yamalı, HL-34; U21'in PQ uzantısı) (§15.20 H) |
| U69 | Veritabanı sızıntısında parola, client secret ve opak token'lar doğrudan yeniden kullanılamaz | Argon2id PD (CR-36: m = 7 MiB, t = 5, p = 1) ve token/secret'ların özetle saklanması (CR-38, SA-26) (§15.20 K) |
| U70 | Identity denetim log'unda yayımlanmış bir checkpoint'ten önceki değişikliğin tespiti | ≥ 1 bağımsız yayın hedefi (OP-37); checkpoint aralığı U52. Checkpoint öncesi pencere N-56 (HL-33) (§17.13) |
| U71 | Binding re-anchor (OP-60) sonrası eski binding anahtarının **yeni üretim** için kabul edilmemesi (`superseded`) | ≥ 1 dürüst witness (PQ re-anchor için ML-DSA doğrulayabilen witness ön koşuldur); re-anchor eski anahtar kırılmadan / ele geçirilmeden önce yapılmıştır; verifier `superseded` kuralına uyar. CR-45 semantiği kanoniktir: bundle'sız klasik artefakt yalnız kırılma ilanıyla reddedilir (HL-34) (§17.13) |
| | **Diğer bölümlerden gelen satırlar — NG/PU (N-50–N-59)** | |
| N-50 | Ele geçirilmiş istemci cihazında DPoP/DBSC sahiplik bağının koruma sağlaması: saldırgan cihazdaki anahtarla geçerli kanıt ve taze token üretebilir; holder-binding yalnız çalınmış token'ın başka yerde kullanılmasını kapatır (RR-30; §10.12, §12.10) | — |
| N-51 | Logout sonrası RP'nin kendi oturumunu kapatması (front/back-channel logout teslimi ve RP uyumu); Access tarafı G57'dir (§10.12) | — |
| N-52 | Mevzuata (PSD2 SCA, TR GKD) uygunluk; şablon kurallarının uygulanması U62'dir (§10.12) | — |
| N-53 | Access PEP SDK'sını kullanmayan veya conformance beyanı olmayan PEP kodunun MCP liste önbelleği kapsamını ve stream horizon'unu doğru uygulaması (U63, U64; HL-37) | — |
| N-54 | Broker'ın teslim ettiği `cnf`'siz upstream token sızdığında horizon içinde kullanılmaması; upstream token içeriğinin Grant'ı aşmaması (G2 upstream içeriğe uygulanmaz; risk release Exercise'ında beyan edilir) (AGI-3; RR-43) | — |
| N-55 | Son PQ re-anchor ile kırılma arasındaki kayıtlar ve PQ profilini hiç seçmemiş domain'ler için PQ-doğrulanabilir "existed by T" (RR-35, HL-34; §15.18, §15.20 I) | — |
| N-56 | Identity denetim log'unda Merkle checkpoint yayınından önceki pencerede DB düzeyi değişikliğin tespiti (HL-33; U70) | — |
| N-57 | Identity plane async DR profilinde veri kaybı olmaması (RPO > 0; HL-31, OP-29) | — |
| N-58 | Identity plane'de kiracı veya realm bazında satır düzeyinde geri yükleme (vaat edilmez; HL-32) | — |
| N-59 | Single-node (small-provider) profilinde ack edilmiş yazmanın node/disk kaybında korunması: FA-1 bu profilde yoktur; authority plane'de SEC23 witness/replica-before-ack yine zorunludur (HL-40) | — |

### 13.5 Known Hard Limits → guarantee satırları

Hiçbir hard limit ürün vaadine giremez (RT28). Bu tablo bu spec'in **bütün** HL'lerini listeler (HL-1…HL-40); HL ID'si yalnız burada tanımlanır, diğer bölümler (§15, §16.9, §17) atıf yapar. Emekli ID'ler "Emekli → HL-x" satırıyla kalır ve yeniden kullanılmaz.

| HL | Sınır | Guarantee satırı | Sınıf |
|---|---|---|---|
| HL-1 | Domain başına throughput tek sequencer'la sınırlı | N-20 (availability), B15 (throughput garantisi yok) | NG |
| HL-2 | Provider veya operatörün yanlış kararı önlenemez | N-13, N-29 (tespit öncesi depolama bozulması); tespit U13, U30; çıkış G32 | NG (tespit UDC) |
| HL-3 | Offline pencerede revocation etkisi gecikir | N-4; U2, U19 | NG (pencere UDC) |
| HL-4 | Forced recovery'de kayıp suffix (slice çift harcaması dahil) | N-14; U10, U28 | NG (ack'liler UDC) |
| HL-5 | İstemci timeout'ta sonucu bilemez | N-27; sabitlenme U31 (UDC); metin G39 (BS) | NG |
| HL-6 | Bütün zaman kaynakları ve witness'lar birlikte yalan söylerse kayma | N-28; U29 | NG |
| HL-7 | Equivocation önlenemez, yalnız tespit edilir | N-13; U9 | PU (önleme) / UDC (tespit) |
| HL-8 | Paylaşılan HSM partition'ında korelasyonlu ihlal; paylaşılan veya kapsam dışı imza anahtarının başka domain/tüketici/plane'de kabulü (Storm-0558 sınıfı; realm/consumer anahtarı ile kurumsal token'ın karışması dahil — §12.10). Kural BS'dir (G35, G47: DomainID must-understand); koruma yalnız conformant verifier'da etkilidir (UDC, U25); paylaşılan KMS kotası → HL-20. HL-8'in tek metni budur; §15.8.2 ve §16.9.1 buna atıf yapar | U25 / N-26 (beyanlı HSM partition paylaşımı, FA-8 eki); G35, G47; HL-20 | NG (kural BS, etki UDC) |
| HL-9 | Fiziksel silme (redaksiyon ≠ erase) | N-11; U22 | NG |
| HL-10 | Merkle index pozisyonu gösterir | — (gizlilik sınırı; TI-RT10 kapsamı dışı) | NG |
| HL-11 | Status list herd privacy liste boyutuyla sınırlı | — | NG |
| HL-12 | Çapraz-implementasyon determinizmi vektör kapsamı kadar | G17 (provider yükümlülüğü); L0/L2 + vektörler (TI-RT12) | NG (kapsam dışı) |
| HL-13 | Revocation çalışan effect'i durdurmaz | G31, N-3 | PU |
| HL-14 | TEE / SE yan kanalları; donanımın secure clock hakkında yalan söylemesi | N-15; U14 | NG |
| HL-15 | Async runtime / HTTP katmanı formel doğrulama kapsamı dışındadır → **HL-29** (genel metin; bu satır onun async/HTTP özel hâlidir) | N-36; fuzz + DST + differential test (§14.8); HL-29 | NG |
| HL-16 | Derleyici (LLVM) constant-time garanti etmez; `black_box` garanti değildir. HL-28 buraya katlandı: sabit zamanlı yürütme derleyiciye, CPU'ya ve barındırmaya bağlıdır; mikromimari kanallar (Spectre sınıfı, DMP/GoFetch) Access tarafından kapatılamaz; co-tenant SMT kısmı HL-17'dir (§15.15) | N-35; U45 (ölçüm); CR-39, CR-40 | NG (ölçümle UDC) |
| HL-17 | Paylaşılan donanımda co-tenant yan kanalı; paylaşılan PostgreSQL / önbellek üzerinde zamanlama veya istatistik yan kanalı dahil — RLS bunu kapatmaz (§12.10) | N-32; DL-10; U54 (dedicated) | NG (dedicated UDC) |
| HL-18 | Artık çapraz-domain linkability (aynı KeyBinding, zamanlama, ağ) | N-31; DL-9; U40, G52 | NG (tanımlayıcı UDC, authority BS) |
| HL-19 | WebAuthn/passkey'de PQC yok. HL-26 buraya katlandı: passkey/WebAuthn ve CTAP'te PQC yoktur (donanım 2028+ beklentisi); CRQC sonrası klasik passkey ile imzalanmış **yeni** AIS ve authentication assertion'lar sahtelenebilir; re-anchor edilmiş geçmiş kayıtlar Merkle yapısıyla korunur, yeni commit'ler korunmaz (§15.17, §15.18) | N-37; PI-7, P29, FA-5 | NG |
| HL-20 | HSM/KMS throughput tavanı ve paylaşılan kotanın korelasyonlu tükenmesi (HL-8 uzantısı). HL-25 buraya katlandı: paylaşımlı KMS kotası veya HSM partition'ı kullanan domain'lerin imza throughput'u ve HSM kaynaklı kesintisi birbirine bağlıdır; bir domain'in yükü veya bir HSM kesintisi diğerlerinin artefakt yayınını geciktirir (FIPS profilinde imza başına; signer profilinde anahtar rotasyonu başına) (§15.9) | N-43; DL-8 (availability); HL-1, G42, B15 | NG |
| HL-21 | Bellekteki sır: zeroize'ın kapsamadığı vektörler, host ele geçirilmesinde bellekten anahtar okunması. HL-28'in bellek kısmı buraya katlandı: hipervizör snapshot'ı, DMA/cold boot ve CPU register kalıntısı Access tarafından kapatılamaz (§15.13, §15.15) | N-33, N-34; U41, U42; CR-33, CR-34 | NG |
| HL-22 | Bearer/self-contained identity token'ı ömrü boyunca durumsuz doğrulanır; iptal o RS'de ömürden önce etkili değildir. HL-30 buraya katlandı: identity plane'in self-contained JWT access token'ı introspection yapmayan RS'te ömrü boyunca geçerli kalabilir; session/epoch iptali o RS'e token ömrü dolana kadar ulaşmaz (OP-21, OP-29, OP-32, OP-45 atıfları bu satıradır) | N-39; U36, U37, U38, U39 | NG (ömür UDC) |
| HL-23 | Phishing-resistant authentication oturum/token hırsızlığını önlemez | N-41; DPoP/DBSC ile daraltma (U55) | NG |
| HL-24 | Paket registry'lerinde yayıncı imzası yok; tedarik zinciri saldırısı önlenemez, yalnız tespit ve sınırlama | N-44; U49, U50; FM-16 (tespit UDC) | NG (tespit UDC) |
| HL-25 | **Emekli → HL-20** (birleştirildi; ID yeniden kullanılmaz) | HL-20 | — |
| HL-26 | **Emekli → HL-19** (birleştirildi; ID yeniden kullanılmaz) | HL-19 | — |
| HL-27 | FIPS doğrulanmış bir modülde ML-DSA imzası bugün yoktur (aws-lc-rs FIPS sertifikalarında ML-DSA yok); bir domain FIPS profili ile PQ profilini aynı anda seçemez (tanım §15.17) | CR-15, CR-44; MD-3 | PU (bugün) / WATCH |
| HL-28 | **Emekli → HL-16 + HL-21** (sabit zamanlılık HL-16'ya, bellek-içi sır koruması HL-21'e; co-tenant SMT HL-17) (ID yeniden kullanılmaz) | HL-16, HL-21 | — |
| HL-29 | Formel güvence yalnız ispatın kapsamı kadardır: Lean modeli Kernel'in kendisi değildir (bağ DRT'dir, olasılıksaldır); Kani sınırlı model checking'dir (unwind ve N sınırları); kripto ispatları adlandırılmış caveat'lerle sınırlıdır (aws-lc SAW caveat'leri; ML-DSA/ML-KEM kapsam dışı); async runtime / HTTP katmanı hiçbir aracın kapsamında değildir (HL-15 bu sınırın async/HTTP özel hâlidir). Kapsam dışında kalan hata sınıfları ispatla dışlanmaz (tanım §15.19) | N-36; CR-46…CR-51; HL-12; B15; RR-27 | NG (kapsam dışı) |
| HL-30 | **Emekli → HL-22** (birleştirildi; ID yeniden kullanılmaz) | HL-22 | — |
| HL-31 | Identity plane'in async DR profilinde (tek bölge + async kopya) RPO > 0'dır; promote sonrası kayıp penceresindeki login, kayıt ve kimlik bilgisi değişiklikleri kaybolabilir; epoch artırımı oturumları güvenli tarafa çeker, kayıp veriyi geri getirmez (tanım §16.9.1; OP-29) | N-57 | NG |
| HL-32 | Identity plane'de kiracı veya realm bazında satır düzeyinde geri yükleme yoktur; kurtarma cluster PITR'i ile ayrı ortama yapılıp seçici veri aktarımıyla olur; authority plane'de domain düzeyinde yeniden kurma vardır (tanım §16.9.1; OP-59) | N-58 | NG |
| HL-33 | PostgreSQL superuser'ı, `BYPASSRLS` rolü veya tablo sahibi DB düzeyindeki koruma katmanlarını (RLS, append-only trigger'ları) atlatabilir; authority log'unda zincir, Merkle, witness ve replica karşılaştırmasıyla tespit edilir (G34, FA-14); identity denetim log'unda Merkle checkpoint yayınından önceki pencerede tespit edilmeyebilir (tanım §16.9.1; OP-37, OP-38) | U59 (koşul dışı roller), U70, N-56; G34 | NG (önleme UDC: operatör rol ayrımı; tespit dış tanığa bağlı) |
| HL-34 | Aynı provider içinde binding re-anchor (OP-60, §16.6.1) eski binding key kırılmadan veya ele geçirilmeden önce yapılmalıdır. Kırılmadan sonra eski anahtarın çift imzası sürekliliği kanıtlamaz ve kırılmadan sonra klasik witness cosign'ı da sahtelenebilir; süreklilik yalnız kırılmadan önce alınmış **PQ** witness cosign'lı bir re-anchor checkpoint'ine (CR-45) ve verifier'ın o PQ anahtarlarına kırılmadan önce güvenmiş olmasına dayanır (FA-5 yamalı, U21); aksi NG (RR-35, N-55). PQ geçişinin zamanlaması bu sınıra tabidir (tanım §16.9.1; §15.17, §15.18) | U71, U68, N-55, RR-35; FA-5 | NG |
| HL-35 | Realm imza anahtarının (SAML veya JOSE) sızması o realm'in bütün RP/SP'lerinde, anahtar rotasyonuna kadar herhangi bir kullanıcı adına sahte authentication sağlar (Golden SAML — MITRE T1606.002, sahte ID token). Etki RP/SP'lerin kendi authority'si kadardır; Access authority plane'ine yalnız `authentication` / actor-binding Acceptance'ının kapsamı kadar girer (§10.12; §10.6.1) | §13.2 realm imza anahtarı satırı; G8, G45, G46; N-1 | NG (radius BS) |
| HL-36 | CIMD alan adının süresinin dolması veya yeniden satılmasıyla istemci kimliğinin devralınması; onay kaydı ve canlı projection'lar horizon'a kadar etkilenir (§11) | G18; U2, U19 (horizon); N-1 | NG |
| HL-37 | MCP sunucusunda kiracı izolasyon mantık hatası (Asana sınıfı): karar domain'i AIS'ten gelmezse (P38) veya liste önbelleği `public` işaretlenirse (AG-12) çapraz kiracı ifşası (§11) | U63, U64, N-53; G14 | NG (SDK'lı conformant PEP'te UDC) |
| HL-38 | Yardım masası / kanal kaybı (Scattered Spider sınıfı): niyet belirteci yardım masası riskini kaldırır, kayıtlı iletişim kanalının kaybını kaldırmaz (TN-61; §12.10) | U67, N-2; DL-6 | NG |
| HL-39 | Zehirli kiracı / SAML ele geçirme: ürünün kendi davet postasının kimlik avı kanalı olarak kullanılması (TN-89, TN-95; §12.10) | N-45; HL-23; SEC18 | NG |
| HL-40 | Single-node (small-provider) profilinde ack edilmiş yazma node/disk kaybında kaybolabilir: FA-1 bu profilde karşılanmaz; U32/U51 bu profilde HL olarak beyan edilir ve ≥ 2 sync standby şartı kalkar; profil Domain Metadata ve realm DR beyanında `durability: single-node` olarak yayımlanır. Authority plane'de SEC23 witness/replica-before-ack yine zorunludur, kayıp suffix `domain.recover` ile ele alınır (U24). Authority plane deposu için T8/OP-7 geçerlidir; SQLite yalnız T8'in izin verdiği yerde (§17.9; OP-48) | N-59; U32, U51 (bu profilde değil); U24 | NG |

### 13.6 Forced recovery prosedürü ve kayıp revocation'ların yeniden yapılması

**Recovery assurance (SEC20–SEC23).**

| Öğe | Kural |
|---|---|
| Exercise | `domain.recover` root'un kendi meta-Exercise'ıdır: basis = AnchorRoot(meta-anchor), capacity OWN, requirement = Genesis'te beyan edilmiş rootTerms recovery entry'si. Actor'ler entry'nin tanımladığı KeyBinding'lere sahip root Party Instance'larıdır (AIS ile; Anonymous yapamaz); provider imzası gerekmez |
| Entry içeriği (POLICY DEFAULT) | k-of-n offline recovery anahtarı (organizasyon 3-of-5, küçük domain 2-of-3), her biri ayrı root Party Instance'ında, en az ikisi donanım-bağlı; hiçbiri provider'da veya provider operatöründe custody edilmez (SEC20); her katkı human presence + UV + phishing-resistant assertion. Joint root'ta independence = distinct Party/controller; Sole root'ta aynı Party'nin ayrı donanım-bağlı recovery Instance'ları (2-of-3, en az biri offline). Kurulamıyorsa domain oluşturma S7'de "Recovery not available" beyan eder (NG, N-14) |
| N (SEC21) | Bağımsız witness co-signed **ve** kökü recovery tarafındaki kayıtlarla (provider-dışı replica veya dürüst provider'ın Record Export'u) yeniden üretilebilen en yüksek checkpoint. Yeni provider N'den record-fold ile devam eder. Anahtar compromise'ında bile N geri çekilmez: çalınmış anahtarla imzalı artefaktlar exact-content inclusion kuralıyla reddedilir; N'ye dahil şüpheli kayıtlar prospective revoke Exercise'larıyla ele alınır (SI-9) |
| Rollback guard (SEC22) | Değerlendirici beyan edilmiş **her** witness'ın en yeni imzalı checkpoint Claim'ini (freshness ≤ 1 saat) ve provider-dışı replica'dan yeniden üretilebilen en yüksek witness'lı checkpoint'i (R*) kendisi sorgular, recovery kararıyla aynı batch'te ingest eder ve StateBasis'te cite eder; requester'ın sunduğu alt küme girdi değildir. Cite edilen N < R* → DENY |
| Kol (i) | Replica beyanlı, sorgulanabilir ve R* = witness en yüksek: N = R* ile guard geçer |
| Kol (ii) | Replica yok, sorgulanamıyor veya R* < witness en yüksek (dürüst gecikme ile kesilmiş replica ayırt edilemez): ek REQUIRE_ACTION (meta-anchor root'un genel threshold'u); N = R* ve (N, witness en yüksek] StateBasis'te beyanlı kayıp suffix. SEC23 önek şartı sayesinde (R*, witness en yüksek] ack edilmiş revocation/CT3 içermez. Domain kilitlenmez (U24) |
| Witness quorum'u | POLICY DEFAULT: bütün beyan edilmiş witness'lar. Taze Claim alınamazsa REQUIRE_ACTION (genel threshold) |
| Çatallanma | Aynı pozisyon için iki farklı checkpoint varsa recovery çatallanma pozisyonunu ve çelişen Claim'leri beyan eder; N kayıtlarla kökü yeniden üretilebilen dalın en yüksek bağımsız witness'lı checkpoint'idir; guard o dalda uygulanır. Çalınmış anahtarla imzalı sahte dalın kökünü hiçbir kayıt kümesi üretmez. Hiçbir dal kayıtlarla desteklenmiyorsa (gerçek provider equivocation'ı + replica yok) çatallanma öncesi en yüksek ortak bağımsız witness'lı checkpoint kullanılır ve kayıp NG olarak beyan edilir (N-14) |
| Bildirim | `domain-recovered` event'i bütün root katılımcılarına ve domain admin'lerine |

**Post-recovery adımları.**

| Adım | İçerik |
|---|---|
| PR-0 | `domain.recover` commit (N, varsa beyanlı kayıp suffix ve çelişen dallar cite edilir); Domain Metadata: yeni provider binding, eski anahtarlar `superseded-at checkpoint N` |
| PR-1 | Post-recovery quarantine policy'si (SEC22 R1) aynı Exercise kümesinde `policy.set` ile kurulur: (a) N'den önce issue edilmiş projection'lar yalnız exact-content inclusion proof'la veya re-issue ile; (b) CT2+ exercise'lar REQUIRE_ACTION (grantor veya root contribution); (c) `nonce-closed/pre-recovery`: recovery'den önce zamanlı ve nonce'u devam eden lineage'da bulunmayan AIS istekleri devam eden lineage'da Exercise açamaz (ilk değerlendirmede AIS yaşı ≤ intent validity tavanı; aynı-nonce re-commit etkilenmez; U28). SEC22 R1 deseninde, **ayrı** bir quarantine policy'si olarak: divergence quarantine (TI-RT1, RT3) — divergent kaydın genişletici effect'leri (ve alt ağaçları) DENY overlay'i altında, daraltıcı/consumption effect'leri kayıtlı hâliyle uygulanır; `domain.handover` / `domain.recover` ile aynı Exercise kümesinde veya rebuild-diff bildiriminden sonra root/Security Party `policy.set`'iyle kurulur; kaldırılması ayrı bir CT3'tür |
| PR-2 | Kayıp revocation keşfi: (a) revoke eden Party'lerin elindeki Decision Receipt'leri; (b) witness log'ları (witness/replica-before-ack varsa ack edilmiş revocation'lar zaten N'dedir; replica'sız domain'de witness log'u beyanlı kayıp suffix'in yalnız varlığını ve kökünü gösterir); (c) eski provider'ın kısmi export'u (audit girdisi); (d) PEP/verifier authority-state ack Claim'leri |
| PR-3 | Her kayıp revocation yeni bir revoke Exercise'ıyla prospective yeniden yapılır (P4, E20); revoke'u o Grant'ı revoke etme yetkisi olan herhangi bir Party yapar (grantor, lineage üstü, root) |
| PR-4 | Kayıp draw'lar: Pay/domain attestation'larından bilinen tüketim için ilgili BudgetTerm'ler `grant.amend` ile daraltılır; single-use birimler için Grant'lar revoke + yeniden issue |
| PR-5 | İlgili quarantine policy'sinin kaldırılması: root'un veya Security Party'nin CT3 Exercise'ı (genişletme). Post-recovery quarantine (SEC22 R1) ile divergence quarantine ayrı policy'lerdir; birinin kaldırılması diğerini kaldırmaz |

**Guarantee.** N sonrası eski-provider kayıtlarının devam eden lineage'da authoritative olmaması BS (G21); ack edilmiş revocation'ın kaybolmaması UDC (U10); beyanlı kayıp suffix'teki revocation'ların kaybı NG (N-14); recovery'nin tamamlanabilmesi UDC (U24); kayıp suffix'teki AIS'in tekrar Exercise açmaması UDC (U28); PR-2'nin tamlığı NG. Adım etiketleri (PR-0–PR-5) register ID'si değildir.

**Divergence quarantine'in kapsamı (TI-RT1).** Divergence, record-fold sırasında kayıtlı bir DecisionRecord'un yeniden değerlendirmesinin farklı sonuç vermesidir. Divergence quarantine SEC22 R1 kümesinin parçası değildir; onun deseninde ayrı bir policy'dir ve yalnız recovery'de değil, kooperatif handover'da ve rebuild-diff'te bulunan yeniden değerlendirme farkında da aynı biçimde kurulur: provider kanıtı domain'e bildirir; quarantine root'un veya Security Party'nin narrowing `policy.set`'idir (handover / recover ile aynı Exercise kümesinde veya rebuild-diff bildiriminden sonra); provider commit'i durdurabilir ama restriction yazamaz; kaldırma CT3'tür (TI-RT3).

### 13.7 Policy defaults

**Hepsi POLICY DEFAULT'tur:** semantik invariant değildir; Suiss-hosted domain şablonlarının başlangıç içeriğidir (Genesis rootTerms, başlangıç RestrictionPolicy'leri, Grant template'leri, `projection.issue` politikası). Domain sıkılaştırabilir (narrowing); gevşetmek genişletme sınıfında bir meta-Exercise'tır (SI-18). Değerler kalibrasyon başlangıcıdır ve pilot ölçümleriyle ayarlanır (OQ-2).

#### 13.7.1 Consequence Tier (CT) sınıflandırması — POLICY DEFAULT

| Tier | Tanım (schema alanlarından ve meta-action sınıfından türetilir) | Örnek |
|---|---|---|
| **CT0** | Okuma veya authority-state'e/dış dünyaya etkisiz; consumption-bearing değil; `effect_class` reversible; disclosure yok | Kendi kaydını okuma, advisory check |
| **CT1** | Reversible veya düşük değerli consumption-bearing; tutar ≤ domain eşiği (varsayılan 1,000 EUR eşdeğeri); bilinen alıcı | Küçük refund, ticket güncelleme |
| **CT2** | Irreversible `effect_class`; dış Party'ye effect; tutar > CT1 eşiği; **yeni alıcı**; yeni alıcıya `disclose`; authority-narrowing olmayan meta-action'lar (`grant.issue` genişletmesiz, `mandate.bind`) | Ödeme, sözleşme imzası, dış e-posta, delegation verme |
| **CT3** | `reserved` action'lar; genişletme sınıfı meta-action'lar (`grant.amend` expand, delegability açma, restriction kaldırma, `acceptance.establish/expand`, `policy.set` gevşetme, `anchor.*`, `domain.*`, minimum sürüm düşürme, `declassify`); break-glass kullanımı; tutar > CT3 eşiği (varsayılan 100,000 EUR eşdeğeri) | Yeni HR kaynağı kabulü, root değişimi, provider handover; kalıcı silme, realm imza anahtarı rotasyonu, yönetici göç dışa aktarımı (reserved ilan edildi → CT3; TN-86, TN-118). IdP bağlantısı, SCIM `subject-selection` Acceptance'ı (`acceptance.establish`), break-glass muafiyetini beyan eden `policy.set`, SEC18 gevşetmesi ve soğuma kısaltma zaten bu tanımdadır (§12.10) |

Narrowing meta-action'ları (revoke, restriction ekleme, Acceptance daraltma, `instance.terminate`) tier'dan bağımsız olarak **CT1 assurance** ile yapılabilir (SI-4, X11).

**Karşılanabilirlik kuralı.** CT bir policy sınıflandırmasıdır (SEC7); eşlendiği RequirementTerm şablonu domain'in eligible principal yapısında **karşılanabilir** olmalıdır — bir POLICY DEFAULT frozen bir semantik yetkiyi fiilen silemez. Buna göre: (a) bir Party'nin **kendi koyduğu** actor-side self-restriction'ı (ör. Suspend) kaldırması o Party'nin kendi Exercise'ıdır (X13): genişletme sınıfı requirement'ı (taze H(AAS)-bağlı, phishing-resistant UV assertion) ile, quorum'suz; başkasının koyduğu restriction'ın kaldırılması CT3 kalır. (b) Kullanıcının kendi `grant.issue`'su (X8) ve kendi ödemesi CT2'dir ve kendi assertion'ıyla karşılanır (SEC10). (c) CT3 quorum'u yalnız ≥ 2 eligible principal olan scope'ta varsayılandır. (d) Tam export ve `domain.recover` entry'si Sole root için karşılanabilir biçim taşır.

#### 13.7.2 Connectivity tavanları — POLICY DEFAULT

| Class / variant | CT0 | CT1 | CT2 | CT3 |
|---|---|---|---|---|
| `online` / `online-strict` | izinli | izinli | **zorunlu** (veya exact-intent token, horizon ≤ 5 dk, count = 1) | **zorunlu**; projection yok |
| `intermittent` / `bounded-staleness` | Δ ≤ 15 dk, horizon ≤ 24 saat | Δ ≤ 5 dk, horizon ≤ 8 saat | yok | yok |
| `intermittent` / `revalidate-on-reconnect` | horizon ≤ 24 saat | horizon ≤ 8 saat | yok | yok |
| `offline` / `checkpointed-offline` | horizon ≤ 72 saat | horizon ≤ 24 saat; slice ≤ en dar lineage BudgetTerm penceresinin %10'u ve ≤ 1 pencere; **verifier profile:** tamper-evident sayaç + secure clock class (monotonic + imzalı zaman) + donanım attestation; grup audience'ı yalnız ortak sayaç beyanıyla (SEC13) | yok (domain explicit genişletmesiyle, ≤ 4 saat, tek verifier) | yok |
| `long-running` / `checkpoint-continuation` | checkpoint ≤ 60 dk, horizon ≤ 24 saat | checkpoint ≤ 15 dk, horizon ≤ 8 saat | her consequential adım yeni `continue`; horizon ≤ 2 saat | yok |
| Offline report teslim tavanı | horizon + 24 saat; aşan verifier'a yeni contract yok (SEC14; girdi `derived.unreported_contracts`, §16.5.1) | aynı | — | — |
| Domain Metadata freshness (verifier) | ≤ contract Δ (yoksa ≤ 1 saat) | aynı | — | — |
| Clock skew toleransı (Claim, C33) | 2 dk | 2 dk | 1 dk | 1 dk |

**Verifier-side tavan notu.** Yukarıdaki horizon/slice tavanları yalnız issuer (`projection.issue`) politikası değildir: domain bunları Domain Metadata / Verifier Profile üzerinden verifier'ın **yerel kabul tavanı** olarak da ilan eder ve conformant verifier tavanı aşan artefaktı (ve operasyonel anahtar penceresi dışındaki imzayı, T20) yerel DENY ile reddeder. Çalınmış provider imza anahtarıyla basılmış bir artefakt issuer tarafındaki kontrollerden hiç geçmediği için containment buradadır (U25). Foreign tarafta eşdeğer yerel daraltma bridging Grant'ın ceiling'i ve terms'idir.

#### 13.7.3 Authentication & approval assurance — POLICY DEFAULT

| Alan | CT1 | CT2 | CT3 |
|---|---|---|---|
| Step-up freshness (actor) | ≤ 15 dk | ≤ 5 dk, binding = intent digest (H(AAS) üzerinden) | ≤ 5 dk, binding = H(AAS) |
| Authenticator class | Phishing-resistant (WebAuthn/passkey; ödeme: SPC) | Aynı + UV | Aynı + UV + **donanım-bağlı, non-custodial** |
| Authenticator class — identity plane eşlemesi | Identity plane faktörlerinin (AAL, uygulama-kontrollü faktör, parola/OTP/push) bu satıra eşlenmesi ve ek kurallar: bkz. §10.3, IDP-8. Bu tablo (§13.7.3) kanoniktir; §10.3.3 buna atıf yapar ve §10.3.3'teki IDP-8 tablosu bu tabloyu daraltır, değiştirmez. Uygulama-kontrollü faktör (MD-11) §13.7.3'ün phishing-resistant sınıfını tek başına karşılamaz; TR ödeme şablonunda CT2 için phishing-resistant authenticator **ve** uygulama-kontrollü faktör birlikte istenir (şablon daraltmasıdır) | aynı | aynı |
| Human presence | Approval için evet | Evet | Evet |
| Contribution / assertion (SEC10) | Requirement'a göre | Varsayılan: actor'ün principal'ının taze, H(AAS)-bağlı, phishing-resistant human-presence assertion'ı **veya** bir insan contribution'ı (actor agent ise insan contribution'ı; X19). Başka principal'dan contribution (`contributor ≠ actor principal`) yalnız domain SoD beyan ettiğinde (org şablonu: `approve:<class>` Grant'ları) | **≥ 2 eligible principal olan scope'ta** (Joint root, org şablonu): ≥ 2 contribution (quorum), independence: distinct Party, distinct controller, **distinct surface path**, ≠ actor principal. **Tek-principal (Sole) scope'ta:** principal'ın donanım-bağlı, non-custodial UV assertion'ı + yürürlük gecikmesi (time-lock) |
| Approval Surface | Conformant (Acceptance'lı) | Conformant, tam render | Conformant, tam render; quorum varsa en az bir contribution bağımsız surface'ten |
| Bildirim içi hızlı onay | İzinli (conformant tam render + H(AAS)) | **Yok** | **Yok** |
| Batch | ≤ 10 item, aynı requester + action class, item başına ayrı AAS + assertion | **Yok** | **Yok** |
| AAS `expires_at` | ≤ 15 dk | ≤ 5 dk | ≤ 5 dk |
| REQUIRE_ACTION nonce validity = intent validity tavanı (ilk-commit AIS yaşı tavanı; = hot-path nonce saklama ufku) | ≤ 24 saat | ≤ 24 saat | ≤ 72 saat |
| Yürürlük gecikmesi (genişletmeler) | — | — | ≥ 24 saat (break-glass hariç: kendi zaman sınırı + zorunlu sonradan inceleme) |
| Yeni authenticator / designation cooling | — | 24 saat (SEC18) | 24 saat |
| Agent Instance'ın requirement'ı karşılaması | Domain kararı | Actor-side term'ler yalnız `attestation.runtime` + donanım-bağlı KeyBinding ile; insan term'lerini karşılayamaz; `approve` eligible set'ine agent girmesi domain'in explicit genişletme kararıdır (CT3) | Hiçbir insan term'ini karşılayamaz |
| Yeni alıcı (ödeme, `disclose`, ilk delegation) | CT2'ye yükseltilir | — | — |

CT0 için CT1 değerleri uygulanır (daraltma; ayrı bir CT0 değeri yoktur). Intent validity tavanı bir POLICY DEFAULT'tur, semantik invariant değildir; domain daha kısa tavan seçebilir (narrowing). Etkileşimli revoke kısa validity seçer (değer ENGINEERING ASSUMPTION, OQ-1; ≤ intent validity tavanı, POLICY DEFAULT).

**CT0 dipnotunun kapsamı.** "CT0 için CT1 değerleri uygulanır" kuralı tablonun **bütün satırlarını**, authenticator class satırı dahil, kapsar. Sonuç: bir Access exercise'ı için actor'ün authentication Claim'i en az phishing-resistant bir authenticator'dan (WebAuthn/passkey; ödemede SPC) gelmelidir; parola, OTP (TOTP/SMS) veya push **tek başına hiçbir CT'yi (CT0 dahil) karşılamaz** — bu faktörler N-45'e göre AiTM'e dayanmaz. Bu kural yalnız Access karar yolundaki requirement'ı bağlar; identity plane'in kendi oturum açma politikası (hangi faktörle oturum açılabileceği, AAL düzeyi, MD-11 uygulama-kontrollü faktör sınıfı) §10.3 / IDP-8'dedir. Parola + phishing-resistant olmayan ikinci faktörle açılmış bir identity oturumu var olabilir, ama o oturumdan türeyen `authentication` Claim'i bu tablonun CT requirement'larını karşılamaz; Access step-up (REQUIRE_ACTION) ister. Domain bu varsayılanı genişletmek (ör. CT0 için daha zayıf authenticator kabulü) isterse bu bir gevşetmedir (SEC8) ve CT3 sınıfıdır (çıkarım — §13.7.8 analojisi). Statü: PD · sınıf: UDC · kaynak: SEC10, SEC26, N-45.

#### 13.7.4 Rate limit'ler ve kaynak sınırları — POLICY DEFAULT

Aşım **protocol rejection**'dır (outcome değil; kayıt yok; nonce tüketilmez; effect yok — SI-20), istisna: requester throttling bir **RestrictionPolicy** DENY'ıdır çünkü girdisi kayıtlı değerlendirmelerdir — bu, throttling'i kullanan domain şablonunun insan contribution'ı gerektiren REQUIRE_ACTION evaluation'larını **auditable (kayıtlı)** olarak beyan etmesini gerektirir (C30'un auditable dalı; SI-8, INV-27).

| Sınır | Değer | Biçim |
|---|---|---|
| ADP `commit` per actor Instance | 20/s sürekli, 100 burst | Protocol rejection |
| `check` (advisory) per actor Instance | 60/dk, 2,000/gün | Protocol rejection + telemetri |
| Explain (viewer-scoped) per viewer | 30/dk, 500/gün | Protocol rejection |
| Search per viewer | 10/dk; sayfa ≤ 100 | Protocol rejection |
| **Requester throttling**: insan contribution'ı gerektiren açık REQUIRE_ACTION per requester Instance | ≤ 20/saat, ≤ 100/gün; aynı intent digest tek sayılır; girdi: şablonla auditable beyan edilmiş REQUIRE_ACTION kayıtları | RestrictionPolicy → DENY `restricted/policy:request-rate` + security event |
| `projection.issue` per Instance × action class | ≤ 30/saat; açık offline PAP ≤ 3 (girdi: `derived.*` whitelist sayaçları, §16.5; key'ler §16.5.2) | RestrictionPolicy DENY |
| Bootstrap Grant'ları (`party.register`, `instance.create(self)`) per context (ör. IP/attestation sınıfı) | ≤ 10/saat | BudgetTerm (count/window) |
| Claim ingest per issuer | Acceptance'ta beyan edilen kotanın 2×'i; aşan ingest quarantine **yalnız qualifying (genişletici) etkiye** uygulanır; narrowing sınıfı Claim kota nedeniyle reddedilmez veya quarantine'e alınmaz, yalnız SI-20 sınırlarına tabidir | P19 kural 3 |
| Lineage derinliği | ≤ 16 | Protocol rejection |
| Proof sayısı per request | ≤ 64 | Protocol rejection |
| Selector karmaşıklığı | ≤ 32 conjunct | `grant.issue` DENY |
| Request boyutu | ≤ 256 KB (opaque body'ler digest) | Protocol rejection |

#### 13.7.5 Explanation derinliği ve görünürlük — POLICY DEFAULT

| Kapsam | Varsayılan | Not |
|---|---|---|
| Requester (agent dahil) | Default derinlik: class + position + resolver class + remediation; `undisclosed` restriction'da yalnız class | P14–P16, SEC24 |
| Viewer | Expert derinlik kendi lineage'ı ve verdiği Grant'lar için; alt ağaç derinlik ≥ 2 kimlikleri pseudonymous | X31 sıkılaştırması |
| Audit | Ayrı `access.audit.export` / audit-read Grant'ı; tam Claim değerleri reserved — ≥ 2 eligible principal olan domain'de + 2 contribution, Sole root domain'de root'un donanım-bağlı UV assertion'ı; `undisclosed` policy'lerin tam içeriği audit scope'ta görünür | |
| `undisclosed` varsayılanı | Fraud, velocity, risk-tabanlı restriction'lar; kapsam yalnız `requester` ve policy authority'si olmayan `viewer` (restriction-owner ve audit tam içerik görür) | SEC24, SI-14 |

#### 13.7.6 Structuring, laundering ve abuse desenleri — POLICY DEFAULT

| Desen | Mekanizma | Değer |
|---|---|---|
| Agent Grant'ında budget | Consumption-bearing her agent Grant'ı: per-intent cap + günlük window BudgetTerm + count/window | Template zorunlu alanı (X10 ile hizalı) |
| Party-düzeyi toplam | Actor-side RestrictionPolicy (Party'nin derived consumption'ı, bütün lineage'lar) | Domain tanımlar; şablon mevcut |
| Eşik-bitişik tekrar | Pencere (24 saat) içinde aynı ResourceRef/recipient'a ≥ 3 exercise, her biri requirement eşiğinin ≥ %80'i → REQUIRE_ACTION (contribution) | RestrictionPolicy |
| Mass-selection guard | Selector holder kümesinde 24 saatte > %10 veya > 5 yeni Party → yeni holder'ların CT2+ exercise'ları REQUIRE_ACTION | RestrictionPolicy |
| Delegation zinciri | Agent'a delegable Grant: depth ≤ 1, `downstreamHolderClass` = aynı operatörün agent'ları | Template (C15) |
| Mapping probation (SEC16) | Pin'den sonra 14 gün mapping üzerinden CT2+ → REQUIRE_ACTION | RestrictionPolicy |
| Yeni alıcı | İlk ödeme / ilk `disclose` → CT2 | |

#### 13.7.7 Custody, witness ve recovery — POLICY DEFAULT

| Parametre | Değer |
|---|---|
| Meta-anchor root (organizasyon) | `Joint(k ≥ 2)`, independence: distinct Party + controller (kişisel domain: `Sole`; risk RR-10'da beyanlı) |
| rootTerms `domain.recover` entry'si | 3-of-5 (org) / 2-of-3 (küçük); ≥ 2 donanım-bağlı; **hiçbiri provider/operatör custody'sinde değil**; independence: Joint root'ta distinct Party/controller, Sole root'ta aynı Party'nin ayrı donanım-bağlı recovery Instance'ları (distinct device/assurance path) — kurulamıyorsa S7'de "Recovery not available" (NG); rollback guard: değerlendirici beyan edilmiş her witness'ın en yeni checkpoint Claim'ini ve beyan edilmiş replica'dan yeniden üretilen en yüksek witness'lı checkpoint'i (R*) kendisi sorgular (freshness ≤ 1 saat; quorum = bütün beyan edilmiş witness'lar); N < R* her durumda DENY; replica yok/sorgulanamaz veya R* < witness en yüksek ise ayrıca REQUIRE_ACTION (meta-anchor genel threshold'u) + N = R* + beyanlı kayıp suffix; quorum alınamazsa meta-anchor genel threshold'u (REQUIRE_ACTION); çatallanmada N kayıtlarla yeniden üretilebilen dalı izler (SEC22) |
| Witness ve replica | ≥ 2 witness, ≥ 1 provider'dan bağımsız; checkpoint her 60 s / 1,000 kayıt; witness/replica-before-ack revocation + CT3 için (SEC23): bağımsız witness co-sign'ı **ve** kapsayan checkpoint'e kadar bütün kayıtların (önek) root kontrolündeki provider-dışı replica'ya (Record Export akışı) ulaşması; replica beyanı Genesis / Domain Metadata'da; Suiss-hosted şablonda zorunlu |
| Custody | CT3 tutanlar non-custodial; custodial mod user-gated (SEC17) |
| Cooling | Yeni authenticator-binding / designation: 24 saat CT2+ için kullanılamaz (SEC18) |
| Quarantine policy'leri (post-recovery SEC22 R1; divergence, ayrı policy) | Root / Security Party'nin narrowing `policy.set`'i; kaldırma CT3 |
| `party.compromise` occurredAt bilinmiyorsa | Overlay beyan zamanından 72 saat geriye |
| Issuer cutoff marjı | t_c − 24 saat; t_c bilinmiyorsa t_d − 7 gün |
| Operasyonel imza anahtarı ömrü | 1 saat (PD), tavan ≤ 24 saat; domain-scoped; ayrı signer süreci (mekanizma T20 → §15/§16); [ID] JOSE anahtarları realm politikası (CR-19; §13.7.9). Bu satır kanoniktir; §15.8.3 atıf yapar |
| Provider kararı yeniden değerlendirme örneklemi | CT3 %100, CT2 %1 (domain'in seçtiği taraf) |

#### 13.7.8 Sürüm ve downgrade — POLICY DEFAULT

**Downgrade saldırı modeli:** (i) zorunlu alanın/extension'ın çıkarılması → imzalı içerik + must-understand (PI-12); (ii) eski sürümlü artefaktın eski verifier'a sunulması → Domain Metadata minimum sürümü, verifier freshness ≤ Δ; (iii) PEP ile eski profile pazarlığı → PEP minimumu Domain Metadata'dan alır, discovery'den değil; (iv) assurance downgrade (passkey yerine OTP) → RequirementTerm floor'u (SI-18); (v) algoritma downgrade → accepted algorithm kümesi Domain Metadata'da, imzalı içerikte algoritma kimliği.

| Parametre | Değer |
|---|---|
| Domain minimum core spec / profile sürümü | Domain'in benimsediği en son sürüm; benimsemeden sonra 90 gün geçiş penceresi, sonra minimum = en son |
| Minimum'u düşürmek / zayıf algoritma eklemek | CT3 (reserved + CT3 satırı: quorum varsa 2 contribution, Sole scope'ta donanım-bağlı UV assertion; her durumda 24 saat gecikme) |
| Minimum'u yükseltmek / algoritma çıkarmak | Narrowing (CT1) |
| Bilinmeyen sürümlü artefakt | Red (fail closed) + sayaç (telemetri) |

#### 13.7.9 Identity plane ve çalışma zamanı — POLICY DEFAULT

Aşağıdakiler de POLICY DEFAULT'tur (semantik invariant değildir); sıkılaştırma narrowing, gevşetme genişletme sınıfıdır (SEC8). Gevşetmenin hangi CT'de olduğu §13.7.1 ve MD-14'e göre belirlenir; aşağıda "gevşetme" sütunundaki CT değerleri **çıkarım**dır (§13.7.8 analojisi) ve §16 policy tablosuyla teyit edilmelidir.

| Parametre | Varsayılan | Gevşetme | Kaynak |
|---|---|---|---|
| Identity access token ömrü | Admin ve yüksek etkili client: ≤ 60 dk; hızlı profil (yüksek hacimli RS): 5 dk; > 60 dk varsayılan olarak reddedilir; 28 saatlik token her durumda reddedilir (MD-7). Ömür bir **üst sınırdır**: authority taşıyan token'ın horizon'u = min(ömür PD'si, §13.7.2 tavanı); tavan token bounds'undaki en yüksek CT'den gelir; CT2+ action için bounds token verilmez, yalnız exact-intent token (≤ 5 dk, count = 1); CT3 için projection yok. Yönetim yüzeyindeki ≤ 60 dk yalnız CT0 okuma/gezinme içindir; meta-Exercise'lar AIS + ADP `commit` ile yapılır (MD-14) | Gevşetme genişletme sınıfıdır (CT3, çıkarım) | MD-7 |
| Revocation profili | Strict (introspection zorunlu, 250 ms hedef) admin/finans RS'lerinde; diğerlerinde hızlı profil (JWT 5 dk) | Strict → hızlı: CT3 (çıkarım) | MD-7 |
| `session_epoch` yayılım bütçesi (EA) | Aynı düğüm 0; aynı cluster p99 < 250 ms; cluster arası < 500 ms | — (ölçüm hedefi) | U35 |
| Witness co-sign gecikmesi (EA) | p99 ≤ 750 ms | — | — |
| Identity audit checkpoint aralığı | ≤ 1 s (EA); log başına yayınlanır | Genişletme CT2 (çıkarım) | U52 |
| Operasyonel imza anahtarı ömrü | 1 saat (PD), tavan 24 saat | 24 saat üstü yok (tavan) | MD-6 |
| DPoP | Uzun ömürlü paylaşılan nonce; replay cache TTL = proof ömrü + 2× clock skew | — | MD-18 |
| `sub` biçimi | Pairwise (OIDC/SAML); PartyRef domain-pairwise | Public `sub` opt-in: client başına, CT2 (çıkarım) | MD-10 |
| Rate limit anahtarları | IP, kullanıcı, IP+kullanıcı; `X-Forwarded-For` sağdan güvenilir proxy sayısı kadar | — | — |
| Başarısız login tavanı | ≤ 100 ardışık başarısız deneme (NIST 800-63B-4); kademeli gecikme; global store düşerse yerel strict limiter | Fail-open asla (tavan değil kural) | U46 |
| Argon2 eşzamanlılığı | Semaphore N = floor(bellek·0.5/m); acquire timeout 500 ms → 503 | — | U47 |
| Enumeration | Adaptive delay + varlıktan bağımsız semaphore; dummy Argon2 yok; aynı status/body/header/redirect | — | MD-18 |
| Security event yazımı | `synchronous_commit=on` | — | U51 |
| Exercise / audit body saklama | Genel varsayılan 400 gün (SEC32); sektör şablonu uzatır (ör. ödeme kuruluşu denetim izi 10 yıl, Ek C.3); kısaltma yok (OP-74); digest'ler süresiz (pseudonymous iskelet, GDPR Art.5 gerekçesi §14.9); PII alanları saklama sınıfının Ek C kuralına göre crypto-shred | Kiracı yalnız uzatır | SEC32; OP-74 |
| HTTP sınırları | Header/slowloris timeout 5–10 s; HTTP/2 `max_concurrent_streams` 100, `max_header_list_size` 8 KB; 0-RTT kapalı | Daraltma serbest | — |
| Parser sınırları | Derinlik ≤ 32; JSON/CBOR boyut önce; x509/DER ≤ 8 KB; WebAuthn CBOR ~8 KB; regex desen ≤ 256 | Daraltma serbest | §14.6 |
| Provider kararı yeniden değerlendirme (replay agent) | CT3 %100, CT2 %1 (= §13.7.7) | — | §13.7.7 |
| Hesap durumunun authority etkisi (`account.status`) | Her domain'in varsayılan güvenlik politikası (Genesis şablonu): realm issuer'ının kabul edilmiş `account.status ∈ {suspended, deactivated, tombstone}` Claim'i, ilgili PartyRef'in o realm üzerinden actor-binding'le kurulmuş Instance'larına DENY overlay'idir (E5 restriction kanalı; Claim'in ingest pozisyonundan itibaren; actor gerektirmez). `instance.terminate` ve departure temizlik Exercise'larıdır; güvenlik bunlara dayanmaz. Overlay'in uygulanması politika kurulu ve Claim ingest edilmişse BS; offline yayılma NG (pencere UDC) | Overlay'in kaldırılması genişletmedir (SI-4) | E5, SEC12 deseni |

### 13.8 Unsatisfiable guarantees (ürün asla vaat etmez)

Ürün (UI, docs, sözleşme metni, API açıklaması) aşağıdakileri **hiçbir yüzeyde** vaat etmez; dürüst karşılıklar aşağıdadır (UI karşılıkları §8.10) ve XI-12 bağlayıcıdır.

| Asla vaat edilmez | Dürüst ifade |
|---|---|
| "Revoked everywhere instantly" | "Effective now for new requests; offline devices may honor until T if they follow their profile" |
| "Agent stopped" (teyitsiz) | "Authority revoked. Agent: running / paused (confirmed) / unknown" |
| "Verified" / "true" (Claim) | "*Issuer* says (signed)" |
| "Done / Paid" (ALLOW için) | "Allowed · *Owner*: reported done / unknown" |
| "Nothing was lost" (forced recovery) | "Changes after *time of N* may be lost; repeat revocations made after then" |
| "Independent approvers" | "Different people, different devices" |
| "Two people must approve" (tek sahipli kişisel domain'de) | "Confirm with your hardware key; takes effect after 24 h — you can cancel until then" |
| "You'll be notified of every change to your keys" | "Key changes Access has received appear in Changes; your identity provider notifies you of key changes" |
| "A signature from Suiss's key means it's valid" | "Accepted only within the limits each verifier enforces; after a key compromise, only items matching the recovered record" |
| "Approval guarantees correctness" | "Records your approval. Access then re-checks…" |
| "Deleted" (redaksiyon için) | "Redacted — fingerprint verifiable; copies shared earlier are not recalled" |
| "Suiss can't access your keys" (custodial modda) | "Keys held by Suiss for you — you can move them to your own device" |
| "Suiss can't see your data" | Söylenmez; minimizasyon anlatılır |
| "Tamper-proof" | "Tamper-evident (checked against independent witnesses)" — yalnız witness varsa |
| "Secure against AI misuse" / "prompt-injection-proof" | "Agent can only use what you delegated, within limits" |
| "Unique person" (Sybil) | Issuer'ın iddiası olarak gösterilir |
| "Always available" | Offline/continuity pencereleri koşullarıyla |
| "Legally binding approval" | Söylenmez (EI-24) |
| "Revoke queued" / "Pending revocation" | "Not confirmed — checking" (timeout); sonuç gelince "Revoked", "Revoked — confirming (witness pending)" veya (nonce lineage'da yoksa) "Not recorded — try again" |
| "Formel olarak doğrulanmış" (niteliksiz) | "Kernel'in şu özellikleri şu modelde şu araçla doğrulandı (kapsam: …); HTTP/async katmanı formel kapsam dışında" |
| "Kiracı izolasyonunu derleyici garanti eder" | "Tenant scope'suz sorgu derlenmez; veritabanında RLS FORCE ayrıca uygulanır" |
| "Çevrimdışı token'lar tek işlemde iptal edildi" | "Yeni istekler için iptal edildi; çevrimdışı token'lar en geç *T*'de sona erer" |
| "Logged out everywhere" (anında) | "Sessions ended; apps that already hold a token may keep access until *T* (≤ token lifetime)" |
| "Passkey ile hesabınız çalınamaz" | "Passkey phishing'e dayanır; oturum çalınmasına karşı cihaz bağlama ayrıca uygulanır" |
| "Kullanıcılarınız uygulamalar arasında ilişkilendirilemez" | "Her uygulama farklı bir kullanıcı numarası görür; zaman, ağ ve cihaz bilgisi yine de ilişkilendirmeye izin verebilir" |
| "Tamamen izole altyapı" (paylaşılan hosting'de) | "Mantıksal izolasyon; donanım izolasyonu dedicated seçenekle" |
| "Constant-time / zamanlama saldırılarına karşı kanıtlanmış" | "Constant-time olarak ölçüldü (dudect/asm snapshot); derleyici garantisi yoktur" |
| "Denetlendi = güvenli" / "SLSA L3 sertifikalı" | "Bağımsız denetim *tarih*'te yapıldı, rapor burada"; SLSA seviyesi yalnız doğrulanmış provenance ile ve pazarlamada kullanılmadan |
| "CRA uyumlu" (uygunluk değerlendirmesi tamamlanmadan) | "CRA hazırlığı: SBOM, CVD süreci, destek süresi yayınlandı" |
| "Verileriniz silindi" (crypto-shredding için) | "Kişisel alanlar okunamaz hâle getirildi; denetim iskeleti (pseudonymous) saklanır" |
| "Quantum-safe records" / "kayıtlarınız kuantum sonrası doğrulanabilir" (niteliksiz) | "Re-anchor edilmiş kayıtlar, PQ anchor'ına kırılmadan önce güvenen verifier'da doğrulanabilir; son re-anchor'dan sonraki kayıtlar bu kapsamda değildir" (U68, N-55) |
| "Anında silindi" (crypto-shredding için) | "Kişisel alanlar beyanlı süre içinde okunamaz hâle getirilir" (U58; tamamlanma beyanlı tavandan sonra; anında silme NG, N-42) |

### 13.9 Residual risks (RR-1–RR-45)

| ID | Risk | Owner | Neden kabul | İzleme sinyali |
|---|---|---|---|---|
| RR-1 | Custodial modda custodian impersonation (DL-1) | Identity plane (custodian) + domain | Kullanılabilirlik; non-custodial seçenek her zaman açık | Ingest edilmiş custodial key-event'leri (SI-13); regime bildirimleri |
| RR-2 | Sadakatsiz/ele geçirilmiş surface (DL-2); ele geçirilmiş istemci ekranında gösterilen metin ile H(AAS)'nin farklı olması ve aynı kökende konsol XSS'iyle imza ekranının manipülasyonu dahil (§10.12, §12.10; TN-131) | Surface operatörü; domain (Acceptance) | Authenticator içerik gösteremez | CT3 bağımsız surface uyuşmazlıkları |
| RR-3 | Offline/intermittent pencere içi kötüye kullanım (DL-3) | Domain (contract issuer), verifier operatörü | Connectivity gerçeği | Offline report gap'leri, ack eksikleri |
| RR-4 | Provider yanlış kararı / equivocation (DL-4) | Provider; domain (witness, yeniden değerlendirme) | Fiziksel | Yeniden değerlendirme uyuşmazlığı, witness çatışması |
| RR-5 | Witness'sız veya replica'sız kayıp suffix (DL-5) | Domain root | Witness ve provider-dışı replica opsiyonel (Suiss-hosted şablonda zorunlu) | Witness/replica yokluğu veya replica gecikmesi S7'de görünür; recovery StateBasis'inde R* ve beyanlı kayıp suffix (replica-before-ack önek'i sayesinde ack edilmiş revocation/CT3 içermez) |
| RR-6 | Yetkili kötü aktör / collusion (DL-6) | Domain governance; Work accountability | İnsan gerçeği | Structuring/abuse desenleri |
| RR-7 | Policy oracle (DL-7) | Domain (policy tasarımı); security tooling | Determinism | `check`/explain telemetrisi |
| RR-8 | Fail-closed availability (DL-8) | Domain (continuity planı); provider | Güvenlik önceliği | Rejection oranları |
| RR-9 | Publisher mapping anlamı | Publisher; domain admin'leri | Access anlamı doğrulayamaz | Probation REQUIRE_ACTION oranı |
| RR-10 | Sole root compromise | Root Party | Kişisel domain sadeliği | Root key-event'leri |
| RR-11 | Narrowing ile DoS | Domain (restriction scope'u) | SI-4'ün bilinçli bedeli | Containment overlay olayları |
| RR-12 | Prompt injection / model hatası Grant ∩ Mandate içinde (ajanın Grant sınırları içinde zararlı ama yetkili eylemi; Access yalnız sınırlar, önlemez — §11) | Agent operatörü; One/Executor | Model gerçeği | Effect attestation uyuşmazlığı |
| RR-13 | Compromise penceresindeki effect'ler | Effect owner'ları (Pay/domain/Executor) | Prospective recovery (SI-9) | Compromise impact sorgusu |
| RR-14 | Provider imza anahtarı çalınmasının tespit öncesi penceresi: verifier'ların yerel tavanları içinde sahte PAP/receipt kabulü (N-26) | Provider operatörü (anahtar custody'si); domain (yerel tavanların ilanı, recovery); verifier operatörleri | Anahtar evaluator değildir; containment ancak verifier tarafında mümkündür | Merkezde `projection.issue` karşılığı olmayan PAP sunumu (ack / offline report); witness çatallanması |
| RR-15 | Access'e ingest edilmemiş regime key-event'lerinin Party tarafından görülmemesi | Party Identity Regime (Work + Access governance) | Key-event history regime'indir (E4) | Regime bildirimleri; key-event Claim ingest gecikmesi |
| RR-16 | Argon2'nin formel doğrulanmış implementasyonu yok | Identity plane (credential deposu); güvenlik ekibi | Endüstri standardı parola hash'i; alternatif yok; passkey birincil faktör | Wycheproof/KAT vektörleri, RustSec advisory'leri |
| RR-17 | RS256 için doğrulanmış implementasyon yok; `rsa` crate'inde Marvin açığı yamasız | Identity plane | Yalnız istemci başına opt-in, aws-lc-rs üzerinden; authority artefaktı asla RSA değil | Opt-in client sayısı; aws-lc-rs advisory'leri |
| RR-18 | OAuth/OIDC AS'nin Rust'ta sıfırdan yazılması (olgun referans yok) | Identity plane mühendisliği | MD-1 tek backend kararı; differential test ile telafi | OIDF suite sonuçları, differential uyuşmazlıkları (hydra, oidc-provider); RR-40 buraya katlandı — azaltma: OIDF süiti CI'da ilk günden, PKCE S256 zorunlu, implicit/ROPC yok, refresh reuse tespiti baştan (§16.4.10) |
| RR-19 | Kritik bağımlılıklarda korelasyonlu tek maintainer (bus factor) | Tedarik zinciri sahibi | Rust ekosistem gerçeği; vendor + fork hazırlığı | cargo-vet kapsamı, maintainer aktivitesi; RR-41 buraya katlandı — webauthn-rs/ldap3_proto/concread aynı ekipten, bergshamra ailesi tek kişiden; azaltma: `cargo vendor`, fork kapasitesi, CI'da bloklayıcı `cargo-audit`/`cargo-deny` (§16.4.10) |
| RR-20 | SAML/XML (c14n, imza sarmalama — XSW) karmaşıklığı; libxml2 sınıfı açıklar | Identity plane (SAML gateway) | SAML kapsamda; izole parser worker; DocType reddi | XSW regresyon korpusu; c14n fuzz (öncelik 1) bulguları; RR-42 buraya katlandı — libxml2 C yığını (samael yolu) veya genç saf-Rust yığın (bergshamra yolu); izole parser worker (§16.4.10) |
| RR-21 | crates.io/npm yayıncı imzası yok; kötü niyetli paket (PolinRider, Shai-Hulud sınıfı) | Tedarik zinciri sahibi | Registry gerçeği; tespit + sınırlama | cargo-deny/audit/vet, ≥ 7 gün cooldown, yeni build.rs alarmı |
| RR-22 | Artık linkability (DL-9); pairwise `sub`'a rağmen e-posta, telefon ve ad claim'lerinin RP'ler arası korelasyonu dahil (claim minimizasyonu kiracı politikası; §10.12); aynı `cnf` anahtarı veya zamanlama ile domain'ler arası korelasyon dahil (§9.9.3, P52) | Identity plane; domain (attribute disclosure politikası) | Ağ/zaman bilgisi kriptografiyle silinemez | Public `sub` opt-in sayısı; korelasyon attribute disclose'ları |
| RR-23 | Co-tenant yan kanalı (DL-10) | Hosting operatörü; tenant (dedicated seçimi) | Maliyet; dedicated seçenek açık | Hosting mikrokod/mitigation durumu |
| RR-24 | Enumeration zamanlama kanalı (U44, N-46) | Identity plane | Ağ jitter'ı altında ölçüm eşiği | Enumeration regresyon suite'i p50–p95 farkı |
| RR-25 | Identity degraded window: backend erişilemezken önceden imzalı token'ların ömür sonuna kadar kabulü (U39). Degraded window = beyanlı token ömrü (RS'te yerel doğrulama); fail-open yok: Access yüzeyleri (introspection, userinfo, oturum kontrolü) `active=false` / 503 (login, refresh) ile fail-closed'dur; OP-45 bozulmuş modu buraya bağlanır | Identity plane; RS operatörü | Availability; pencere = beyanlı token ömrü | Degraded mode süresi, açık token sayısı |
| RR-26 | Derleyici constant-time kırması (HL-16) | Güvenlik ekibi | Platform gerçeği | asm snapshot farkları, dudect |
| RR-27 | Async/HTTP katmanında formel kapsam dışı hata (HL-15 → HL-29) | Mühendislik | Araç olgunluğu | Fuzz/DST bulguları, hyper advisory'leri |
| RR-28 | Kerberos C FFI (bellek güvenliği olmayan kod) | Gateway sahibi | Kerberos uyumluluğu; izole süreç | ASan/fuzz job'ı, MIT krb5 advisory'leri |
| RR-29 | Phishing'e açık faktörler (TOTP, push, SMS; TR ödeme şablonundaki uygulama-kontrollü faktör) | Domain (faktör politikası); identity plane | Mevzuat/kullanıcı gerçeği; CT2+ phishing-resistant ister (§13.7.3) | Faktör dağılımı; AiTM tespit sinyalleri |
| RR-30 | Authentication sonrası token/oturum hırsızlığı (infostealer, BitM) (HL-23); DPoP/DBSC anahtarının aynı cihazdaki malware ile kötüye kullanılması — ele geçirilmiş cihazda sahiplik bağı koruma sağlamaz (N-50; §10.12, §12.10) | Identity plane; RS | Passkey kapsam dışı; DPoP/DBSC daraltır | Oturum anomalileri (hijack imzası) |
| RR-31 | HSM/KMS throughput ve kota korelasyonu (HL-20) | Provider operatörü | Donanım/bulut gerçeği | İmza kuyruk gecikmesi, kota alarmı |
| RR-32 | WebAuthn PQ eksikliği (HL-19) | Standart kuruluşları; identity plane (izleme) | Standart yok | WebAuthn/FIDO PQ çalışmaları (WATCH) |
| RR-33 | CRA sınıflandırması ve üretici kapsamı belirsizliği (D-10, Adem kararı bekleniyor) | Suiss yönetimi | Karar bekleniyor; varsayılan Class I ile hazırlık | 11 Eylül 2026 Art.14 yükümlülükleri; resmî rehberler |
| RR-34 | Sahte/şişirilmiş güvenlik verisi (SEO/LLM kaynaklı; ör. 14,140 iddia vs 1,815 ölçülen cargo-vet kapsamı) karar girdisi olarak; toplayıcı kaynaklı MCP CVE tablosunun NVD teyidi olmadan tehdit modeli girdisi yapılması dahil (§11) | Güvenlik ekibi | Tüm sayılar kaynak etiketli; doğrulanmayanlar işaretli | "doğrulanmadı" etiketli sayıların periyodik doğrulanması |
| RR-35 | Re-anchor öncesi pencere: son PQ re-anchor checkpoint'i ile klasik algoritmanın kırıldığı an arasındaki kayıtlar ve artefaktlar PQ-doğrulanabilir "existed by T" kazanmaz; PQ profilini hiç seçmemiş domain'in bütün geçmişi bu sınıftadır (tanım §15.18; N-55, HL-34) | Domain (PQ profili ve kadans seçimi); provider (re-anchor üretimi) | CRQC zamanlaması bilinmez; re-anchor periyodiktir | Domain Metadata'da son re-anchor checkpoint'inin boyutu ve zamanı |
| RR-36 | Şifreli identity token'ların harvest-now-decrypt-later riski: JWE şifreli ID Token / UserInfo ve SAML EncryptedAssertion içerikleri klasik anahtar anlaşmasıyla şifrelenir; transport hibrit KEX ile korunur (CR-12), içerik şifrelemesi korunmaz (tanım §15.17) | Realm (JWE kullanımı), RP | JOSE için PQ KEM standardı yok | Yok (pasif kayıt); azaltma: JWE yerine TLS + minimizasyon |
| RR-37 | ML-DSA implementasyon olgunluğu: doğrulayıcı hataları sahte imza kabulüne yol açabilir; aws-lc-rs ML-DSA FIPS sertifikasız ve ispat kapsamı dışında (tanım §15.17) | Provider (kütüphane seçimi), domain (PQ profili) | Olgunluk zaman ister | Crucible/ACVP/Wycheproof vektörleri (CR-51); çapraz implementasyon DRT'si |
| RR-38 | Yönetilen platformda sertleştirme arka ucunun düşmesi: `memfd_secret` kullanılamayabilir (doğrulanmadı), container memlock limiti düşük olabilir; signer `mlock`'a düşer veya başlamaz (tanım §15.20) | Provider / self-host operatörü | Platform kısıtı | `access_secret_memory_backend` metriği; signer'da `none` başlatma hatasıdır (CR-34) |
| RR-39 | Kullanılmadı (rezerv, yeniden kullanılmaz) | — | — | — |
| RR-40 | **Emekli → RR-18** (azaltma maddeleri RR-18'e eklendi) | — | — | — |
| RR-41 | **Emekli → RR-19** | — | — | — |
| RR-42 | **Emekli → RR-20** | — | — | — |
| RR-43 | Upstream sağlayıcıların çoğu DPoP desteklemiyor (incelenen 15 issuer'dan hiçbiri); broker'ın teslim ettiği upstream token'lar bearer kalabilir (U65, N-54; §11) | Identity plane (broker); domain (upstream bağlantı seçimi) | Upstream ekosistem gerçeği; CT2+ varsayılanı broker-as-PEP | DPoP destekleyen upstream sayısı; upstream token teslim sayısı |
| RR-44 | Ana akım MCP istemcilerinin (Claude, ChatGPT bağlayıcıları) sender-constraint / AIS desteği gelene kadar Access-korumalı MCP sunucuları bu istemcilere yalnız Public kapsam sunar; PI-11 ve PI-7 bilinçli olarak korunur (benimseme riski; istemci desteği doğrulanmadı) (§11.8.3, §12.10) | Ürün; MCP PEP sahibi | PI-11 FROZEN; bearer authority verilmez | SEP-1932 (WATCH); istemci DPoP desteği |
| RR-45 | RP ID / alan adı değişimi passkey'leri geçersiz kılar ve bütün kullanıcıları aynı anda en zayıf kurtarma yoluna iter (TN-17, TN-63; özel alan adı RP ID'si ücretlendirilmez) (§12.10) | Kiracı (alan adı kararı); identity plane | WebAuthn RP ID bağı | RP ID değişiklik talepleri; kurtarma yolu kullanımında sıçrama |

### 13.10 Frozen security decisions (SEC1–SEC32)

- **SEC1** Security verdict'i SECURE WITH DECLARED LIMITS'tir; DL-1–DL-8 beyan edilmiş sınırlardır; model-level vulnerability yoktur.
- **SEC2** Her güvenlik iddiası §3.3'teki guarantee sınıflarından tam olarak birindedir; iki yönlü iddialar iki satırdır; ürün yüzeyleri §13.8'deki ifadeleri vaat etmez.
- **SEC3** Access'in güvenlik sorumluluğu dört şeydir (authority semantiği, kendi kayıtları, fail-closed karar yolu, trust acceptance blast radius'u); diğer güvenlik concern'leri E22'deki owner'lardadır.
- **SEC4** Kriptografik gereksinimler: tamper-evidence ve teknik non-repudiation zorunlu; forward secrecy yalnız transport için; uzun süreli doğrulanabilirlik + algoritma kimliği imzalı içerikte; algoritma seçimi T5'tedir.
- **SEC5** Trust model §13.2 tablosudur; her bileşenin "Asla" sütunu GUARANTEED BY SEMANTICS sınırıdır.
- **SEC6** Güvenlik invariant'ları SI-1–SI-22'dir.
- **SEC7** Consequence Tier (CT0–CT3) bir policy sınıflandırmasıdır, ontology değildir; schema alanlarından ve meta-action sınıfından türetilir.
- **SEC8** Policy default'lar Genesis/template içeriğidir; sıkılaştırma narrowing, gevşetme genişletme sınıfıdır (SI-18).
- **SEC9** Issuer compromise prosedürü cutoff → ingest quarantine → closure → reconcile'dır; subject-selection/foreign-authority Acceptance'ına cutoff affirmative disqualify'dır ve dayanan episode'ları terminal kapatır (SI-10).
- **SEC10** CT2+ action'lar için en az bir insan contribution'ı veya actor'ün principal'ının taze, H(AAS)'ye bağlı, phishing-resistant human-presence assertion'ı varsayılandır (actor agent ise insan contribution'ı; X19); başka principal'dan contribution (contributor ≠ actor principal) yalnız domain SoD beyan ettiğinde; CT3 quorum'u yalnız ≥ 2 eligible principal olan scope'ta, tek-principal (Sole) scope'ta donanım-bağlı UV assertion + time-lock; bir Party'nin kendi self-restriction'ını kaldırması quorum'suz kendi Exercise'ıdır; yeni alıcı CT2'dir. Her POLICY DEFAULT requirement şablonu domain'in principal yapısında karşılanabilir olmalı veya karşılanamazlığı beyan edilmelidir.
- **SEC11** Hedef Exercise'ı commit edilmeden önce actor Instance'ı terminate edilmiş contribution'ı cite eden değerlendirme varsayılan olarak REQUIRE_ACTION'dır (RestrictionPolicy).
- **SEC12** party.compromise overlay'i occurredAt'tan (bilinmiyorsa beyandan 72 saat geriye) sonra kurulan Instance'lara uygulanır; occurredAt yalnız daraltır.
- **SEC13** Consumption-bearing offline slice'ın audience'ı tek verifier'dır veya ortak tamper-evident sayaç beyan eden verifier grubudur; aksi projection.issue DENY (PI-12'nin uygulanması).
- **SEC14** Horizon + 24 saat içinde raporlanmamış offline contract'ı olan verifier'a yeni contract issue edilmez.
- **SEC15** Compromise impact sorgusu (bir Instance/issuer/key için pencere içindeki Exercise, Grant, contribution, projection listesi) derived bir sorgudur; yeni nesne değildir.
- **SEC16** Compatibility mapping pin'inden sonra 14 gün mapping üzerinden değerlendirilen CT2+ intent'ler REQUIRE_ACTION'dır (mapping probation).
- **SEC17** Custodial anahtarlar user-gated'dir (her kullanım Party'nin cihaz-bağlı authenticator assertion'ını ister); non-custodial controller'a geçiş her zaman açıktır; CT3 tutanlar varsayılan olarak non-custodial'dır. Custodial ve user-gated olmayan mod NOT GUARANTEED olarak beyan edilir.
- **SEC18** Yeni authenticator-binding veya issuer designation 24 saat boyunca CT2+ requirement'larını karşılamaz; ingest edildiğinde Party'nin Changes görünümünde görünür (SI-13); key-event'lerin Party'ye bildirimi Party Identity Regime yükümlülüğüdür.
- **SEC19** Identity plane custody anahtarları Access provider rolünde kullanılmaz; görev ayrılığı beyan edilir (UDC).
- **SEC20** rootTerms domain.recover entry'sinin anahtarları (root Party Instance KeyBinding'leri) provider veya provider operatörü tarafından custody edilemez; Suiss-hosted domain oluşturma bunu zorunlu kılar (PI-15 ile).
- **SEC21** Provider imza anahtarı compromise'ı `domain.recover` ile ele alınır (cooperative `domain.handover` değil). N = bağımsız witness co-signed ve kökü recovery tarafındaki kayıtlarla (provider-dışı replica veya dürüst provider'ın Record Export'u) yeniden üretilebilen en yüksek checkpoint. Değerlendirici R*'ı kendisi sorgular; N < R* → DENY. Replica yoksa, sorgulanamıyorsa veya R* < witness en yüksek ise REQUIRE_ACTION, N = R* ve (N, witness en yüksek] beyanlı kayıp suffix'tir (SEC22). Yeni provider N'den record-fold ile devam eder; co-sign ≠ replica; kökü yeniden üretmek N'ye kadar bütün öneki ister (SEC23 replica-before-ack bu öneki taşır). Eski anahtar `superseded-at checkpoint N`; compromise penceresindeki sahte artefaktlar exact-content inclusion kuralıyla reddedilir (SEC25); N'ye dahil şüpheli kayıtlar recovery sonrası prospective revoke Exercise'larıyla ele alınır. Blast radius verifier'ların yerel kabul tavanlarıdır (U25, N-26). Bütün "N" kullanımları bu tanıma atıf yapar.
- **SEC22** Rollback guard: değerlendirici beyan edilmiş her witness'ın en yeni imzalı checkpoint Claim'ini ve domain'in beyan ettiği provider-dışı replica'nın kayıtlarıyla kökü yeniden üretilebilen en yüksek witness'lı checkpoint'i (R*) kendisi sorgular ve StateBasis'te cite eder (requester'ın sunduğu alt küme girdi değildir). Cite edilen N < R* her iki kolda DENY'dır. Replica beyanı yoksa, replica sorgulanamıyorsa veya R* < witness en yüksek ise guard ayrıca REQUIRE_ACTION'dır (meta-anchor genel threshold'u; dürüst gecikme ile kesilmiş replica ayırt edilemez): N = R* (replica yoksa kayıtları recovery tarafında bulunan en yüksek doğrulanmış checkpoint) ve (N, witness en yüksek] StateBasis'te beyanlı kayıp suffix'tir — SEC23 önek şartı sayesinde (R*, witness en yüksek] ack edilmiş revocation/CT3 içermez; recovery yolu beyanlı domain kilitlenmez. Witness quorum'unun Claim'i alınamazsa REQUIRE_ACTION (meta-anchor genel threshold'u). Witness'ta çatallanma varsa N, kayıtlarla kökü yeniden üretilebilen dalın en yüksek bağımsız witness'lı checkpoint'idir ve çelişen dal(lar) beyan edilir; "çatallanma öncesi son ortak checkpoint" yalnız hiçbir dal kayıtlarla desteklenmediğinde kullanılır ve o kayıp NG olarak beyan edilir (N-14). Sınıf: witness/replica-before-ack (önek) + N ≥ R* + witness quorum'u ve replica erişilebilir iken UDC (U10); witness'sız, replica'sız, replica erişilemezken veya kesilmiş replica ile genel threshold'la NG (N-14). Recovery ile aynı Exercise kümesinde post-recovery quarantine policy'si (R1) kurulur. R1 kümesi: (a) N'den önce issue edilmiş projection'lar yalnız exact-content inclusion proof'la veya re-issue ile; (b) CT2+ exercise'lar REQUIRE_ACTION; (c) `nonce-closed/pre-recovery`: recovery'den önce zamanlı ve nonce'u devam eden lineage'da bulunmayan AIS istekleri devam eden lineage'da Exercise açamaz — ilk değerlendirmede AIS yaşı ≤ intent validity tavanı (= hot-path nonce saklama ufku; arşiv nonce lookup'ında kalır), aynı-nonce re-commit etkilenmez (U28). Post-recovery quarantine policy'si root'un veya Security Party'nin narrowing `policy.set`'idir; kaldırılması CT3'tür. SEC22 R1 deseninde, ayrı bir quarantine policy'si olarak: divergence quarantine (TI-RT1, RT3) — divergent kaydın genişletici effect'leri (ve alt ağaçları) DENY overlay'i altında, daraltıcı/consumption effect'leri kayıtlı hâliyle uygulanır; `domain.handover` / `domain.recover` ile aynı Exercise kümesinde veya rebuild-diff bildiriminden sonra root/Security Party `policy.set`'iyle kurulur; kaldırılması ayrı bir CT3'tür. Kayıp revocation'lar PR-2–PR-4 ile yeniden yapılır (§13.6).
- **SEC23** Revocation sınıfı Exercise'lar ve CT3 commit'leri, kapsayan checkpoint en az bir bağımsız witness tarafından co-sign edilmeden ve o checkpoint pozisyonuna kadar bütün kayıtlar (önek; yalnız revocation/CT3 kaydı değil — mevcut Record Export akışı; root kontrolünde) domain'in beyan ettiği provider-dışı replica'ya ulaşmadan acknowledge edilmez; diğer kayıtlar için ayrı ack şartı yoktur (witness/replica-before-ack; E20'nin tam capability'si; co-sign ≠ replica); ≥ 2 witness, ≥ 1 bağımsız; replica capability'si Genesis / Domain Metadata'da beyan edilir — POLICY DEFAULT, Suiss-hosted şablonda zorunlu.
- **SEC24** RestrictionPolicy'ler undisclosed işaretlenebilir; requester scope'una ve policy authority'si olmayan viewer'a açıklama yalnız sınıf döner; restriction-owner, policy authority'si olan viewer ve audit scope tam içeriği görür ve Record Export policy içeriğini taşır (replay korunur; PI-6); fraud/velocity/risk restriction'ları varsayılan undisclosed'dır.
- **SEC25** Inclusion proof gereksinimleri §13.3'tedir: exact içerik eşleşmesi + commitment'a dahil olma + witness'lı checkpoint N (handover'da C_k → C_{h+1}); Work receipt doğrulaması dahil.
- **SEC26** Assurance tablosu §13.7.3'tür: bildirim içi onay ve batch yalnız CT1; batch ≤ 10, item başına ayrı AAS ve assertion; CT2 varsayılanı SEC10'dur (assertion veya contribution; SoD beyanlıysa başka principal); CT3 ≥ 2 eligible principal olan scope'ta ≥ 2 contribution + bağımsız surface yolu, tek-principal scope'ta donanım-bağlı UV assertion; her iki durumda ≥ 24 saat yürürlük gecikmesi.
- **SEC27** Availability fail-open ile değil, önceden issue edilmiş continuity envelope'larıyla (küçük slice'lı, kısa horizon'lu projection'lar; break-glass için offline PAP) sağlanır.
- **SEC28** Rate ve kaynak aşımı protocol rejection'dır (outcome değil); requester throttling kayıtlı değerlendirmelere dayanan RestrictionPolicy DENY'ıdır (şablon insan-contribution'lı REQUIRE_ACTION evaluation'larını auditable beyan eder; C30).
- **SEC29** X31 korunur; §13.7.5'teki iki sıkılaştırma (alt ağaç derinlik ≥ 2 kimliklerin pseudonymous olması, audit okumasının ayrı Grant istemesi) varsayılandır.
- **SEC30** Yeni alıcıya ilk disclose CT2, declassify CT3'tür; label data owner'ın Claim'idir (IFC Option B).
- **SEC31** Advisory check ve explain çağrıları canonical kayıt değildir ama operasyonel telemetri olarak sayılabilir; determinism gereği rastgele cevap savunması yoktur.
- **SEC32** Exercise body redaksiyon uygunluğu varsayılan 400 gün (canlı derivation yoksa); digest'ler süresiz; kişisel veri taşıyan authority-relevant parametreler mümkünse opaque ref.

**SEC eki.** SEC4'teki "algoritma seçimi T5'tedir" ifadesi §15'i (MD-3 kriptografik profil, PQ satırı) gösterir; T5 karar kimliğidir. SEC19'daki görev ayrılığı MD-6 signer süreci ayrımıyla somutlaşır (U42). SEC27'deki "availability fail-open ile değil" kuralı identity plane'e MD-8 ile uygulanır: identity degraded window yalnız U39 koşuluyla vardır. Yeni güvenlik süreç kararları §14'te SA-n olarak yazılır. SEC3'teki "Access'in güvenlik sorumluluğu" "Access'in authority plane güvenlik sorumluluğu" olarak okunur; identity plane'in sorumluluğu §13.2'deki identity plane paragrafıdır (MD-13). SEC1'deki beyan edilmiş sınırlar kümesi DL-1–DL-10'dur (DL-9 MD-10, DL-10 MD-17). SEC27'deki identity degraded window RS'te yerel doğrulamanın ValidityContract horizon'udur, fail-open değildir; introspection'da primary'ye veya tazelik kaynağına ulaşılamıyorsa her token için, cache-hit dahil, `active=false` döner, 503 dönmez.

### 13.11 ValidityContract Δ/horizon ↔ epoch mekanizması: doğrulama yollarının guarantee satırları (MD-7)

**Kural (MD-7).** Semantik ValidityContract'tır; epoch'lar mekanizmadır. `session_epoch` identity plane oturum/token fast revoke'u, `key_epoch` anahtar penceresidir; `authz_epoch` yerine AuthorityStateBasis / `applied_pos` kullanılır (G51). Her doğrulama yolu aşağıdaki tabloda bir satırdır (satır etiketleri EP-n'dir; ecosystem E-n ile çakışmaz); her satır bir guarantee satırına (G/U/N) bağlıdır ve azami bayatlığı (Δ) veya horizon'u açıkça beyan eder. Geçersiz kılma koşulu bağlayıcıdır: "veritabanı düşse dahi doğrulama sürer" ile "iptal ≤ 250 ms" aynı yolda birlikte verilemez; aşağıdaki hiçbir satır ikisini birlikte vaat etmez. Epoch commit sonrası garanti vermez: epoch artışı yalnız commit edilmiş durum değişikliğini yayar. Statü: FROZEN (semantik), PD (sayılar), EA (gecikme hedefleri) · dayanak: MD-7, MD-8.

| # | Doğrulama yolu | İptal bilgisi cache miss | Partition / DB erişilemez | Restart | Azami bayatlık (Δ / horizon) | Sınıf / satır |
|---|---|---|---|---|---|---|
| EP-1 | Identity plane — login | Canonical kaynağa gidilir | 503; kimlik doğrulama yapılmaz, oturum açılmaz | Cache boş başlar; her istek canonical kaynağa | Δ = 0 (karar canonical durumdan) | G48, G50 (BS) |
| EP-2 | Identity plane — refresh | Canonical kaynağa gidilir | 503 + `Retry-After`; asla `invalid_grant`, asla yeni token | Aynı | Δ = 0; mevcut access token kendi ömrüyle sınırlı (EP-4) | G50 (BS) |
| EP-3 | Identity plane — introspection (strict profil) | "Hiç görülmedi" → canonical; canonical'a ulaşılamazsa `active=false`. Primary'ye veya tazelik kaynağına ulaşılamıyorsa her token için, cache-hit dahil, `active=false`; 503 dönmez | `active=false`; RS 5xx'i DENY sayar | `active=false` cache dolana kadar canonical'dan | Δ_same-node = 0; Δ_cluster p99 < 250 ms; Δ_cross-cluster < 500 ms (EA) | G49 (BS); U35, U37 (UDC) |
| EP-4 | Salt-JWT doğrulayan RS (sinyal tüketmez) | Uygulanamaz: RS'te iptal cache'i yoktur, yalnız JWKS anahtar cache'i (anahtar tazeliği ≠ iptal tazeliği) | Token ömrü içinde kabul; JWKS yenilenemezse bilinen anahtarlarla, `key_epoch` penceresi içinde | Aynı | Horizon = access token ömrü + clock skew (PD: ≤ 60 dk admin, 5 dk hızlı profil) | U36 (UDC); N-39, HL-22 (NG) |
| EP-5 | Sinyal tüketen RS (SSF/CAEP) | Sinyal yoksa EP-4 davranışı | Sinyal kaybı → EP-4'e düşer | Aynı | Sinyal teslim edilirse alıcının beyanlı işlem süresi; garanti tavanı EP-4 horizon'u | U38 (UDC); N-38 (NG) |
| EP-6 | Identity token degraded window (backend erişilemez) | — | Önceden imzalı token'lar ömrü içinde kabul; yeni token yok | — | Horizon = beyanlı token ömrü (yalnız RS'in self-contained token'ı yerel doğrulaması; EP-4 ile aynı sınır). 60–300 s'lik degraded pencereler (introspection'da `active:true` / "düşük güven") **reddedilir** (MD-8): introspection, login ve refresh DB erişilemezken EP-1…EP-3 davranışını izler | U39 (UDC); RR-25 |
| EP-7 | Authority-bearing artefakt (PAP, receipt, exact-intent token) | Verifier Domain Metadata/status tazeliği ≤ contract Δ (yoksa ≤ 1 saat) | Contract'ın connectivity class'ına göre (§13.7.2); online-strict'te DENY | Verifier sayaç/secure clock profiline göre | Δ / horizon / slice ValidityContract'ta (CT2 exact-intent horizon ≤ 5 dk; CT3 projection yok) | G25, U2, U19, U25 (mevcut satırlar); degraded window yok (SEC27) |
| EP-8 | `key_epoch` (anahtar penceresi) | Verifier eski anahtarı yalnız kendi pinli penceresinde kabul eder | Yeni metadata alınamazsa pencere dolunca fail-closed | Pinli küme korunur | Operasyonel anahtar: 1 saat PD, 24 saat tavan; recovery sonrası Domain Metadata tazeliği ≤ Δ | U12, U41 (UDC); G47 (BS) |
| EP-9 | Authority karar girdisi (`authz_epoch` yerine) | `applied_pos` ≥ istenen basis değilse canonical'a sor veya REQUIRE/DENY | DENY (fail-closed) | Basis yeniden kurulur | Δ = 0 commit-mode'da (karar commit head'de) | G51 (BS); FM-1 |
| EP-10 | Advisory önbellek / türetilmiş indeks (§9.11.2) | `applied_pos` anahtarlı; hiç görülmemiş → fail-closed | Commit-mode karara girmez (G51); advisory cevap ALLOW üretmez | Cache boş başlar; `applied_pos` yeniden kurulur | Olumsuz TTL ≤ 1 s; advisory tazelik beyanlı | G51 (BS); U61 (UDC) |

**Not (çıkarım).** EP-3'teki 250/500 ms değerleri hedeftir ve ölçülmemiştir (EA; UDC parametreleri). Veritabanı erişilemezken EP-3 yolunda bu bütçe değil `active=false` geçerlidir; dolayısıyla "DB düştüğünde de 250 ms içinde iptal" ifadesi hiçbir yüzeyde kullanılmaz (§13.8).

### 13.12 Kripto tablosu çapraz referansları (MD-19.3, MD-19.4)

| Karar | §13.2 kripto tablosu satırı | Metin |
|---|---|---|
| MD-19.4 | "Uzun süreli doğrulanabilirlik" | "Yeniden sabitleme mekaniği: algoritma geçişi için §15.18 (PQ re-anchoring) ve §15.16 (agility); provider/binding değişimi için §16.6 ve §16.6.1 (recovery re-anchor T17)" |
| MD-19.3 | "Algoritma kümesi ve PQ geçişi" | "Post-quantum: §15 PQC bölümü ve MD-3 PQ satırı (ML-DSA-65 opt-in; JWKS `AKP` 1. günden)". §3.4 aynı referansı kullanır |

### 13.13 Diğer bölümlerdeki adayların §13 ID'leri

Diğer bölümlerde adı geçen güvence, risk ve sınır adayları aşağıdaki §13 ID'lerine bağlıdır; bölümler bu ID'lere atıf yapar.

| Bölüm | Aday | §13 ID |
|---|---|---|
| §9.7A.3 | "yeni içerik + bayat projection" penceresi (UDC) | U60 (pencere sınıflandırması → G25) |
| §9.9.3 m.8, §9.18 P52 | kalan korelasyon yüzeyi: aynı `cnf` / zamanlama (HL/RR) | → HL-18, N-31, RR-22 (DL-9) |
| §9.10.1 m.2 | kapsam dışı anahtar kabulü, Storm-0558 (HL) | → HL-8 (tek metin) |
| §9.11.2 login | login yolunda DB kaybı: fail-closed, Claim üretilmez | → G48, G50; EP-1 |
| §9.11.2 refresh | refresh yolunda StateBasis kaybı: projection üretilmez | → G50; EP-2 |
| §9.11.2 introspection | tazelik kanıtlanamazsa `active=false` | → G48, G49, U37 (cache-hit dahil); EP-3 |
| §9.11.2 salt-JWT RS | bayatlık ≤ horizon | → U36, N-39, HL-22; EP-4 |
| §9.11.2 SSF/CAEP RS | sinyal best effort, pencere horizon'la sınırlı | → U38, N-38; EP-5 |
| §9.11.2 advisory önbellek | ALLOW üretmez, bayatlık beyanlı | U61 (+ G51); EP-10 (§13.11 satırı) |
| §9 | kimlik iddiası: RP'de iptal NG; Access'te yeni iddia üretmeme BS | G57 (BS); NG kısmı → N-39, N-51 |
| §10.12 #1 (+ §10.2.1) | enumeration yan kanalı (RR) | → RR-24 (U44, N-46) |
| §10.12 #2 (+ §10.4.3) | DPoP/DBSC anahtarı aynı cihazda malware (RR) | → RR-30 + N-50 |
| §10.12 #3 (+ §10.4.6) | pairwise `sub`'a rağmen claim korelasyonu (RR) | → RR-22, U40, N-31 |
| §10.12 #4 (+ §10.5.4) | ele geçirilmiş ekran ≠ H(AAS) (RR) | → RR-2, DL-2, N-7, U7 |
| §10.12 #5 (+ §10.6.1) | Golden SAML (HL) | HL-35 |
| §10.12 #6 | realm JOSE anahtarı sızması (HL) | HL-35 (#5 ile aynı satır) |
| §10.12 #7 | upstream IdP authentication doğruluğu NG / Acceptance dışı kullanmama BS | → N-1; G7, G45 |
| §10.12 #8 | logout sonrası RP oturumu NG / yeni token yok BS | N-51; G57 |
| §10.12 #9 | mevzuata uygunluk NG / şablon kuralları UDC | N-52; U62 |
| §11.3 | CIMD alan adı devralma (HL) | HL-36 |
| §11.5.4 | `cacheScope` çapraz kiracı liste ifşası | U63 (SDK'lı conformant PEP; UDC); kendi kod N-53 |
| §11.5.7 | `subscriptions/listen` horizon sonrası olay yok | U64; kendi kod N-53 |
| §11 | MCP sunucusu kiracı izolasyon hatası, Asana sınıfı (HL) | HL-37 |
| §11 | doğrulanmamış MCP CVE tablosu girdi (RR) | → RR-34 |
| §11 | splicing yok (BS) | G58 |
| §11 | attester (model 2) ele geçirilmesi (HL) | → G8 (radius BS), N-1; §13.2 External IdP satırı |
| §11.13 | `cnf`'li token sızıntısı kullanılamaz BS / `cnf`'siz upstream sızıntısı horizon'la sınırlı UDC | → G18 (BS); U65 (UDC); N-54 (horizon içi sızıntı NG) |
| §11.13 | upstream sağlayıcılar DPoP desteklemiyor (RR) | RR-43 |
| §11.19 | prompt enjeksiyonuyla yetkili zararlı eylem (RR) | → RR-12, N-10 |
| §11.13 | NG adayı: upstream token sızıntısı / içerik Grant'ı aşabilir | N-54 |
| §11.13 / E36 | Exercise'sız release yetkisiz BS; vault zorlaması UDC | G59; U66 |
| §11.8.3 | ana akım MCP istemcileri yalnız Public kapsam (RR) | RR-44 |
| §11.18 AG-35 tablo | 8 ortak gereksinim (CSA/NIST/OWASP/WEF) | → #1 G14; #2 G18, G25, U2/U19; #3 G7, G45; #4 G2, G3; #5 G18, G12; #6 G14, G23; #7 — (mimari); #8 G15; uyum: §14.9 Ajan regülasyonu satırı |
| §12.10 #1 | realm/consumer anahtarı ile kurumsal token karışması (HL) | → HL-8 |
| §12.10 #2 | ortak kiracı yan kanalı, paylaşılan PG/önbellek (HL) | → HL-17, N-32 |
| §12.10 #3 | DPoP taze-token saldırısını durdurmaz (NG) | N-50 |
| §12.10 #4 | RP ID değişimi passkey'leri öldürür (RR) | RR-45 |
| §12.10 #5 | sinyal teslimi (NG) | → N-2, N-38 |
| §12.10 #6 | BitB / gerçek zamanlı kimlik avı proxy'leri (HL) | → HL-23, N-45, RR-29 |
| §12.10 #7 | yardım masası / kanal kaybı (HL) | HL-38 |
| §12.10 #8 | konsol XSS ile imza ekranı manipülasyonu (HL) | → DL-2, N-7, RR-2 |
| §12.10 #9 | seçim yoluyla yükseltme (HL) | → §13.2 HR/claim issuer satırı, G8, N-1 |
| §12.10 #10 | zehirli kiracı / davet postası (HL) | HL-39 |
| §12.10 #11 | kurtarma soğuması itiraz penceresi (UDC) | U67 |
| §12.10 #12 | CT3 listesi eklemeleri | → §13.7.1 CT3 tanımı ve Örnek sütunu |
| §15.20 A | alg allowlist / `none` / `EdDSA` reddi | → G55 |
| §15.20 B | kanonik olmayan CBOR / imza kodlaması | G60 |
| §15.20 C | yayımlanmamış anahtarla imza yok | G61 |
| §15.20 D | bellek-içi anahtar çalınmasının etkisi sınırlı (UDC) | → U41 |
| §15.20 E | bellek-içi anahtar çalınmasının önlenmesi (NG) | → N-33 (HL-21) |
| §15.20 F | sır karşılaştırması sabit zamanlı (UDC) | → U45 (N-35, HL-16) |
| §15.20 G | var olan / olmayan için yanıt içeriği eşdeğer | G62 (içerik BS); süre kanalı → U44, N-46 |
| §15.20 H | PQ re-anchor kapsamında existed by T (UDC) | U68 |
| §15.20 I | re-anchor öncesi pencere / PQ profilsiz domain (NG) | N-55 |
| §15.20 J | kırılma sonrası klasik passkey ile AIS sahteciliği (NG) | → N-37, HL-19 |
| §15.20 K | DB sızıntısında sır yeniden kullanılamaz (UDC) | U69 |
| §15.20 L | crypto-shredding tamamlanması (UDC); anında silme N | → U58; N-42; §13.8 satırı |
| §15.18 Garanti | re-anchor öncesi kayıtlar NG | N-55 |
| §17.13 #1 | identity ack edilmiş güvenlik yazması AZ kaybında kaybolmaz (UDC) | → U32 |
| §17.13 #2 | identity iptali Access yüzeylerinde polling aralığında (UDC) | → U35 |
| §17.13 #3 | introspection yapmayan RS'te iptal (NG) | → N-39, HL-22 |
| §17.13 #4 | identity denetim log checkpoint öncesi tespit (UDC / NG) | U70; N-56 |
| §17.13 #5 | async DR identity veri kaybı (NG) | N-57 (HL-31) |
| §17.13 #6 | satır düzeyinde realm restore (NG) | N-58 (HL-32) |
| §17.13 #7 | binding re-anchor sonrası eski binding kabul edilmez (UDC) | U71 |
| §17.13 #8 | break-glass yolu authority kararı üretmez (BS) | G63 |
| §17.13 #9 | karışık sürüm rolling upgrade'de farklı semantikle commit yok (BS) | G64 |
| §17.9 OP-48 | single-node profilinde ack'li yazma kaybı (HL) | HL-40; N-59 |
| §17.7.2 OP-45 | identity degraded window | → U39, RR-25 |
