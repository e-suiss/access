# Ek B. Özellik envanteri ve yapım sırası

Bu ek, spec'te tanımlı **bütün ürün özelliklerinin yapım sırasına göre** listesidir. Proje bu sırayla yapıldığında hiçbir özellik atlanmamış olur. **Normatif değildir:** her maddenin kaynağı numaralı bölümlerdedir; çelişkide onlar kazanır.

## Nasıl kullanılır

- Aşamalar sırayla yapılır; her aşama öncekilerin üstüne kurulur.
- Her madde bir onay kutusudur (`- [ ]`). Bir madde şu üç koşul sağlanınca işaretlenir (`- [x]`): kodu yazılmıştır; kaynak gösterdiği spec kurallarının testleri vardır ve geçer (SA-59 kural kapsaması); gerekiyorsa dokümanı yazılmıştır.
- Her aşamanın başında **spec dışı ön koşullar** vardır: spec'te özellik olarak yazmayan ama o aşamayı yapabilmek için gereken kararlar ve altyapı. Aşamaya başlamadan önce kapatılır.
- Her aşamanın sonunda **doğrulanacak sınırlar** vardır: o aşamada geçerli olan yasaklar ("bilinçli olarak olmayanlar"). Her biri, ihlal edildiğinde kırılan bir negatif testle doğrulanınca işaretlenir.
- Bir aşama, bütün maddeleri ve sınırları işaretlenince tamamlanmış sayılır.

**Kapsam.** 2371 özellik, 302 sınır, 50 spec dışı ön koşul. Envanter spec'in bütün bölümleri baştan sona okunarak çıkarılmış, tekrarlar kaynakları korunarak birleştirilmiştir. Özellik taşıyan karar ailelerinin (IDP, TN, AG, X, A, P, CR, SA, OP, T, B, E, F) her ID'si ya bir maddede kaynak olarak geçer ya da özellik olmadığı için dışarıda bırakılmıştır (iç implementasyon ayrıntısı, meta kural, yalnız atıf yapan satır, tarihçe, rakip bilgisi, açık soru, HL/RR risk satırı).

**Durum değerleri.** gün-1 / Faz n: spec'teki zamanlama. WATCH: talep üzerine. PD: değiştirilebilir varsayılan. EA: ölçülmemiş tahmin. HYPOTHESIS: doğrulanmamış strateji varsayımı. yol haritası: sonraya bırakılan. belirtilmemiş (FROZEN): kesin karar, zamanlaması yazılmamış. "Durum" alanındaki faz bilgisi spec'in kendi faz tablolarından gelir; bu ekteki aşama sırası yapım bağımlılığına göredir ve ikisi farklı olabilir.

## Aşamalar

| Aşama | İçerik | Özellik | Sınır | Ön koşul |
|---|---|---|---|---|
| 0 | [Proje temeli](#aşama-0--proje-temeli) | 58 | 20 | 13 |
| 1 | [Kernel](#aşama-1--kernel) | 63 | 12 | 4 |
| 2 | [Depo ve kayıt](#aşama-2--depo-ve-kayıt) | 94 | 19 | 5 |
| 3 | [Authority plane çekirdeği](#aşama-3--authority-plane-çekirdeği) | 317 | 67 | 1 |
| 4 | [Anahtar yönetimi ve signer](#aşama-4--anahtar-yönetimi-ve-signer) | 49 | 0 | 0 |
| 5 | [Identity plane çekirdeği](#aşama-5--identity-plane-çekirdeği) | 235 | 48 | 9 |
| 6 | [İki plane'in bağlanması](#aşama-6--iki-planein-bağlanması) | 225 | 28 | 3 |
| 7 | [Yönetim ve geliştirici yüzeyi](#aşama-7--yönetim-ve-geliştirici-yüzeyi) | 175 | 14 | 3 |
| 8 | [Hesap, B2B ve deneyim](#aşama-8--hesap-b2b-ve-deneyim) | 308 | 24 | 4 |
| 9 | [Ajanlar ve MCP](#aşama-9--ajanlar-ve-mcp) | 245 | 21 | 0 |
| 10 | [Kurumsal protokoller](#aşama-10--kurumsal-protokoller) | 180 | 18 | 3 |
| 11 | [Entegrasyonlar ve servisler](#aşama-11--entegrasyonlar-ve-servisler) | 91 | 7 | 0 |
| 12 | [Yönetişim](#aşama-12--yönetişim) | 94 | 5 | 1 |
| 13 | [Dayanıklılık, ölçek ve şeffaflık](#aşama-13--dayanıklılık-ölçek-ve-şeffaflık) | 173 | 11 | 2 |
| 14 | [İleri güvence](#aşama-14--ileri-güvence) | 64 | 8 | 2 |

## Aşama 0 — Proje temeli

Depo iskeleti, Rust workspace, CI aşamaları, lint ve biçim, geliştirme ortamı, test altyapısı, tedarik zinciri, süreç ve dokümantasyon altyapısı. Sonraki her aşama bunun üstüne kurulur.

### Spec dışı ön koşullar

- [x] **Lisans biçimi kararı ve `LICENSE` dosyası** — Apache License 2.0 seçildi; `LICENSE` depo kökünde. Kaynak: D4.
- [x] **İlk sürüm kapsamı kararı** — Ayrı bir ilk sürüm kesimi yapılmaz; aşamalar bu ekteki sırayla tamamlanır (§18.13 notu).
- [ ] **GitHub ayarları** — `main` koruması, imzalı commit (imza anahtarı + yerel ayar), secret scanning ve push protection, yalnız squash merge, özel güvenlik bildirimi, `gh` CLI. Kaynak: OP-71, SA-60.
- [x] **Spec gerilimlerinin çözülmesi** — Giriş akışı identifier-first (TN-96; §10.2.1 ve CR-40 düzeltildi); value metric ≠ fatura birimi (§1.5); pairwise değer yalnız rastgele tablo, HMAC yok (IDP-24, §10.6.1); yapım sırası Ek B (§18.13 notu).
- [ ] **§20.3 editoryal işleri** — 8 tutarlılık kalemi (§13 numara atıfları, §10.2.1 düzeltmesi, PI-15/U27 notu, SYNC-DERIVED anahtarlama, CT3 örnekleri, T-kararlarının taşınması, kopya metinlerin atfa indirilmesi, Ek A emekli ID listesi).
- [ ] **Rust kütüphane olgunluğu değerlendirmesi** — witness, NATS ve SPIFFE istemcileri. Kaynak: OQ-MD1.
- [ ] **Linux CI koşucusu** — seccomp, Landlock, `memfd_secret` ve `checksec` testleri macOS'ta yapılamaz.
- [ ] **Kernel çapraz derleme hedefleri CI'da** — wasm32, iOS ve Android; her hedef aynı test vektörlerini geçer (CMP-24, MD-1, T41).
- [ ] **Frontend / TypeScript araç zinciri ve test altyapısı** — derleme, lint, Wasm paketleme, tarayıcıda uçtan uca ve görsel regresyon testleri (konsol, gömülü bileşenler, Web SDK).
- [ ] **Erişilebilirlik otomatik denetimi** — WCAG 2.2 AA için araç (ör. axe) ve CI kapısı.
- [ ] **Yasak (must-never) regresyon test kataloğu** — her yasağın onu doğrulayan otomatik negatif testle izlenebilir eşlemesi.
- [ ] **Yasak terim ve ürün iddiası taraması** — UI dizgileri ve doküman metninde yasak terimlerin ve yasak iddiaların CI'da taranması.
- [ ] **Ayrılmış benchmark makinesi** — gece çalışan gerçek süre benchmark'ları için gürültüsüz ortam (OP-72).

### K11 Yönetim API'si, konsol, SDK'lar ve geliştirici araçları

#### SDK'lar

- [ ] **Yayın kanalları** — İmajlar GHCR (amd64/arm64, imzalı); Kernel ve doğrulama paketi crates.io; SDK'lar npm, PyPI, Maven Central, NuGet, Go modules, SwiftPM. _Kaynak:_ OP-68 madde 5. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).

#### Komut satırı ve operasyon araçları

- [ ] **Tek komutluk yerel ortam (`just dev`)** — Postgres, NATS, SoftHSM, KMS taklidi, Mailpit, izleme; 15 dakikalık ilk gün. _Kaynak:_ OP-69. _Durum:_ belirtilmemiş.

### K15 Güvenlik ve kriptografi

#### Veri şifreleme ve sır yönetimi

- [ ] **Sır tipleri (`Secret<T>`, `secrecy`, `zeroize`) ve bellek hijyeni** — Sır/PII tiplerinde Debug/Display/serialize yok, constant-time eşitlik, drop'ta zeroize; `==` ile sır karşılaştırma lint'le yasak. _Kaynak:_ §14.5; §17.8.1; CR-33; OP-47; OP-64; SA-26; SAI-8. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Log ve `Debug` redaksiyonu + CI canary testi** — Parola loglanmaz; `Secret<T>` ve log redaksiyon testi. _Kaynak:_ §14.3 (Kanidm GHSA-j4gj); CR-35; OP-64. _Durum:_ belirtilmemiş (FROZEN).

#### Süreç izolasyonu ve signer

- [ ] **Süreç içi ayrıcalık ayrımı** — Mühendislik kuralı; patlama yarıçapını azaltır (§16'ya atıf). _Kaynak:_ §5.12; §6.2 kanıt notu. _Durum:_ belirtilmemiş.

#### Platform ve çalışma zamanı sertleştirmesi

- [ ] **Dilden bağımsız sertleştirme kuralları + dil profilleri** — _Kaynak:_ MD-2. _Durum:_ belirtilmemiş.
- [ ] **Çalışma zamanı kilitleme; `io_uring` yasak** — _Kaynak:_ §14.5; SA-22. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Binary mitigasyonları** — PIE, full RELRO, NX, BIND_NOW; CI'da `checksec`. _Kaynak:_ §14.5; SA-23. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Overflow checks ve panic profili** — Release'de `overflow-checks = true`; istek yolunda panic yok (unwind + görev sınırında yakalama → 500/DENY); ağ süreçlerinde abort yasak. _Kaynak:_ §14.5 R-3; CR-16; MD-2; OP-4; SA-21. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **Konteyner sertleştirme** — PSS `restricted`, `readOnlyRootFilesystem`, `drop: [ALL]`, nonroot, distroless glibc, digest pin; musl yalnız mimalloc ile; gVisor varsayılan değil, Kata opsiyonel. _Kaynak:_ §14.5; §17.9.2; OP-49; SA-24. _Durum:_ PD.
- [ ] **İmzalı yayın: cosign keyless, SLSA L2, amd64/arm64 imzalı imajlar, trusted publishing** — _Kaynak:_ §17.9.2; OP-68. _Durum:_ PD.
- [ ] **SBOM, VEX ve provenance (ücretsiz)** — _Kaynak:_ §18.6; §18.7; §18.11; B3. _Durum:_ belirtilmemiş.
- [ ] **Geliştirme portları varsayılan loopback** — _Kaynak:_ §14.3 (RAUTHY-008). _Durum:_ belirtilmemiş.

#### Güvence, denetim ve tehdit modeli

- [ ] **Tehdit modeli, açık yönetimi, tedarik zinciri güvencesi** — Tehdit modeli, açık (vulnerability) yönetimi, sertleştirme ve tedarik zinciri güvencesi. _Kaynak:_ §2.2.1 (Güvence satırı). _Durum:_ belirtilmemiş.
- [ ] **Tehdit modeli (STRIDE + LINDDUN, TH-1…TH-32)** — Identity plane tehditleri aynı tabloda; PASTA ve attack tree yüksek etkili akışlarda; abuse case'ler AB-1…AB-10. _Kaynak:_ §14.2; SA-5. _Durum:_ belirtilmemiş (FROZEN); araç seçimi WATCH.
- [ ] **Threat-model-as-code** — Makine-okur tehdit modeli; CI her TH ↔ §13 satırı ↔ test eşlemesini doğrular. _Kaynak:_ SA-6; SAI-1. _Durum:_ PD (araç), eşleme FROZEN.
- [ ] **Advisory → regresyon testi** — Rakip/bağımlılık advisory'lerinin her sınıfı CI'da regresyon testine dönüşür. _Kaynak:_ §14.3; SA-10. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Güvenlik bildirimi özel kanaldan** — _Kaynak:_ OP-71. _Durum:_ belirtilmemiş.

### K16 Gizlilik, rıza ve uyum

#### Mevzuat ve standart eşlemeleri

- [ ] **Niteliksiz güvenlik iddiası yasağı** — "formally verified", "quantum-safe" vb. niteliksiz kullanılmaz; hard limit'ler ürün vaadine giremez. _Kaynak:_ B15; CR-50; RT28. _Durum:_ belirtilmemiş (FROZEN).

### K17 Dağıtım, operasyon, yüksek erişilebilirlik ve felaket kurtarma

#### Dağıtım biçimleri ve profiller

- [ ] **Tek binary, tek mod** — Dev/prod kod yolu yok; fark yalnız config. _Kaynak:_ §17.9.1; OP-48; T36. _Durum:_ belirtilmemiş (FROZEN).

#### Sürüm, yükseltme ve göç

- [ ] **İmzalı, tekrarlanabilir sürüm artefaktları** — Çift tekrarlanabilir build, SBOM, provenance, Sigstore. _Kaynak:_ F-4…F-7; OP-68. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).

#### Operasyon yönetimi

- [ ] **Kırmızı çizgiler listesi** — Bkz. "Bilinçli olarak olmayanlar". _Kaynak:_ §17.9.8; OP-54. _Durum:_ belirtilmemiş (FROZEN).

### K18 Açık kaynak, ticari model ve paketleme

#### Açık protokol ve yönetişim

- [ ] **Açık, telifsiz, vendor-neutral protocol (L0–L3)** — Katmanlar: L0 Core Semantic Spec, L1 Interop Profiles, L2 Access-native parts, L3 Conformance. L0–L3 metni ve conformance vektörleri normatiftir; protokol telifsizdir. _Kaynak:_ §7.1, §9.1, §18.7 B2; D3, P1. _Durum:_ belirtilmemiş (FROZEN; §18.7'de FROZEN STRATEGY).
- [ ] **Spec kazanır** — Kod ile spec ayrışırsa spec kazanır; normatif tanım L0/L2 + vektörlerdir. _Kaynak:_ §9.1; G38, RT8, TI-RT12. _Durum:_ belirtilmemiş.
- [ ] **Ayrı sürüm izleri** — İzler: Core Semantic Spec, core meta-schema, interop profilleri, action schema'ları, connectivity profilleri. _Kaynak:_ §9.17.2; P34. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Benimsenmemiş sürüm etkisiz; tek yönlü geriye uyumluluk** — Standart sürüm değişimi yalnız profile sürümünü değiştirir. _Kaynak:_ §9.17 compat k.2, k.5, k.6. _Durum:_ belirtilmemiş.

#### Açık kaynak bileşenler

- [ ] **Access tamamen açık kaynak** — Core, Kernel, iki plane sunucusu, gateway'ler, konsol, Experience backend, analitik, SDK'lar, verifier, conformance suite, replica agent, Executor/Proxy açıktır; kapalı enterprise özelliği yoktur. _Kaynak:_ §18.9 D4. _Durum:_ belirtilmemiş (Adem kararı; lisans biçimi açık).
- [ ] **Self-host tamamen ücretsiz** — _Kaynak:_ §18.9 D4 notu. _Durum:_ belirtilmemiş.
- [ ] **Tek bakımcılı bağımlılıkların açık kaynak fork'u** — 6 ay yanıtsızlıkta fork. _Kaynak:_ T42 madde 5. _Durum:_ PD (eşik).

#### Suiss bağımsızlığı ve kilitlenmeme (anti-hostage)

- [ ] **Lisans protocol kullanımını kısıtlayamaz** — Hiçbir lisans export, handover, replay veya protocol kullanımını kısıtlayamaz. _Kaynak:_ §9.1; B10, D4, T36. _Durum:_ belirtilmemiş (FROZEN).

#### Ücretlendirilemez güvenlik ve temel yüzeyler

- [ ] **Güvenlik özelliği paywall arkasına konmaz** — Güvenlik özellikleri ücretli pakete bağlanmaz. _Kaynak:_ §7.3; B3. _Durum:_ belirtilmemiş.
- [ ] **Ücretlendirilemez özellikler listesi (B3 yüzeyleri)** — Verification, export/replay, handover/recovery, conformance, SSF akışı, güvenlik POLICY DEFAULT'ları/PD'leri, passkey/step-up, revoke/narrow/suspend, impact preview, change-impact, audit-scope explain, honest status, açık SDK'lar; identity'de MFA, sender-constrained token, logout/deprovisioning, signer/HSM, SBOM/VEX, OIDF suite. _Kaynak:_ §9.17, §18.6, §18.7 B3. _Durum:_ belirtilmemiş (FROZEN STRATEGY).
- [ ] **SBOM, VEX ve provenance ücretsiz ve her sürümde** — CycloneDX birincil, SPDX ikincil, `cargo-auditable`. _Kaynak:_ §14.7 F-5; B3, SA-37, SA-49. _Durum:_ belirtilmemiş (FROZEN).

#### Güvenlik açığı yönetimi ve yayın şeffaflığı

- [ ] **security.txt (RFC 9116) + SECURITY.md + GHSA private reporting; 90 gün embargo** — _Kaynak:_ §14.4; SA-14. _Durum:_ PD.
- [ ] **Reproducible build** — Bağımsız taraf aynı digest'i üretir; pinli toolchain, path remap, digest-pinli imaj, vendor offline, çift build gate. _Kaynak:_ F-4, SA-36, SAI-7, U50. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Provenance ve imza (Sigstore/cosign, SLSA Build L3 hedefi)** — attest-build-provenance; L3 doğrulanmadı ve pazarlamada kullanılmaz; 5'li attestation kümesi (provenance, SBOM, VEX, test sonucu, imaj imzası). _Kaynak:_ F-6, F-7, F-8, SA-38, U49. _Durum:_ EA.

### K19 Geliştirme ve kalite güvencesi

#### Kalite ilkeleri ve iddia disiplini

- [ ] **Güvenlik iddiası disiplini (SA-1…SA-4)** — Her güvenlik iddiası tek sınıfta ve §13.4 satırına bağlı; sayılar kaynak etiketli; formel doğrulama dili kalıbı; kapatılamayan beş boşluk RR olarak sahiplenilir. _Kaynak:_ §14.1. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **SAI-1 eşleme kontrolü** — Her §13.4 satırı ↔ test/vektör/proof veya dürüst-ifade testi; eşlemesiz satır release'i bloklar. _Kaynak:_ SAI-1. _Durum:_ belirtilmemiş (aday).
- [ ] **Benchmark alt koşulu ("yeniden üretim bekliyor")** — Performans sayıları kod, ham çıktı ve komut repoda olana kadar "yeniden üretim bekliyor" etiketi taşır. _Kaynak:_ §3.1d. _Durum:_ belirtilmemiş.
- [ ] **Karar kaydı alanları (kabul testi, karşı örnek)** — Her teknik kararda kabul testi ve geçersiz kılacak karşı örnek alanları zorunludur. _Kaynak:_ §3.1c. _Durum:_ belirtilmemiş.

#### Test stratejisi ve CI

- [ ] **Test katmanları SA-T1…SA-T18** — Normatif vektörler, dış suite'ler (OIDF/FAPI/CIBA/Federation, OAuch, MCP, SCIM, SAML, FIDO), interop matrisi, DRT (Lean), TLA+/stateright/Tamarin/ProVerif, Kani, PBT, metamorfik (MR1–MR8), fuzz, differential (hydra, oidc-provider), Wycheproof, bilinen saldırı regresyonu, constant-time, DST, Jepsen/Elle, split-brain, yük, altyapı. _Kaynak:_ §14.8; SA-41…SA-46. _Durum:_ belirtilmemiş.
- [ ] **SA-59 test aşamaları ve disiplin** — Aşama 0–3; kural kapsaması; mutation testing (`cargo-mutants`); PR ≤ 10 dk; flaky 24 saatte karantina; davranışı anlatan test adları; sınırlı snapshot. _Kaynak:_ §14.8.1; SA-59. _Durum:_ belirtilmemiş (FROZEN; süreler PD).
- [ ] **CI bütçesi** — PR hızlı < 2 dk, tam < 15 dk; merge sonrası ~45 dk; nightly ve haftalık işler. _Kaynak:_ §14.8. _Durum:_ belirtilmemiş.
- [ ] **OP-3 CI kapıları** — cargo geiger, cargo-vet/deny/auditable, golden vector, OIDF, clippy deny. _Kaynak:_ CR-14, CR-16, OP-3. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **Sanitizer'lar haftalık; stack protector/CFI nightly kullanılmaz** — _Kaynak:_ SA-23. _Durum:_ belirtilmemiş (FROZEN).

#### Dil, bağımlılık ve tedarik zinciri güvenliği

- [ ] **Dil profilleri ve MD-2 kuralları (R-1…R-7)** — Rust ana (kernel `no_std`), TS, C FFI; `unsafe` allowlist (< 500 satır, `cargo geiger`, Miri); DST'ye uygun saf sequencer; Go profili yalnız MD-1 reconsider'da. _Kaynak:_ §14.5; SA-20. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Kütüphane yasakları (rsa, ring, libcrux, RustCrypto PQ) ve bağımlılık yığını** — _Kaynak:_ CR-14, OP-5. _Durum:_ belirtilmemiş (FROZEN; sürümler PD).
- [ ] **Tedarik zinciri kapısı** — cargo-deny/audit/vet, `--locked`, ≥ 7 gün cooldown, vendor offline, build.rs/IDE dosyası taraması, Actions SHA pin; `default-features = false`; kritik crate manuel denetimi; güvenlik verisi hijyeni. _Kaynak:_ §14.7 F-1…F-3, F-12; SA-34, SA-35. _Durum:_ belirtilmemiş (SA-34 FROZEN, SA-35 PD).
- [ ] **SolarWinds sınıfı (FM-16) tespit + önleme** — _Kaynak:_ F-9, SA-40. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Depo ve geliştirme güvenliği (SA-60)** — gitleaks + push protection; CodeQL + Semgrep; Renovate; korunan `main`, imzalı commit; Adem incelemesi; hassas yollarda tehdit değerlendirmesi ve CODEOWNERS. _Kaynak:_ §14.7 F-13…F-18; SA-60. _Durum:_ belirtilmemiş (FROZEN).

#### Mühendislik standartları (OP-62…OP-74)

- [ ] **OP-62 Monorepo ve klasör yapısı, bağımlılık yönü kuralları** — Tek depo; bağımlılık yönü kuralları CI'da zorlanır. _Kaynak:_ OP-62. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **OP-63 Kod içi mimari** — Saf çekirdek / ports-adapters, sans-I/O, UnitOfWork, outbox, idempotency, yapılandırma ayrımı. _Kaynak:_ OP-63. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **OP-64 Kod kalitesi** — İngilizce kod, rustfmt, workspace lint'leri, tipli kimlik/hata (thiserror), RFC 9457, tracing, SAFETY yorumu. _Kaynak:_ OP-64. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **OP-68 Sürümleme ve CI** — SemVer, CHANGELOG, imzalı imajlar; CI aşamaları (PR ≤ 10 dk, gece, sürüm); Conventional Commits; trusted publishing. _Kaynak:_ OP-68, SA-59. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **OP-69 Geliştirici deneyimi** — `just dev`, docker compose, SoftHSM, Mailpit, geliştirme modu yok, `just gen`. _Kaynak:_ OP-69. _Durum:_ belirtilmemiş (FROZEN TECHNICAL; araçlar PD).
- [ ] **OP-70 Dokümantasyon** — Spec yeri, karar kayıt tabloları, Mermaid/C4, rustdoc, runbook. _Kaynak:_ OP-70. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **OP-71 Süreç ve katkı** — Trunk-based, squash, Adem birleştirir, SECURITY.md, CODEOWNERS. _Kaynak:_ OP-71, SA-60. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **OP-72 Performans disiplini** — criterion/divan, iai-callgrind, benchmark gerileme kapısı; ölçümsüz optimizasyon yok. _Kaynak:_ OP-72. _Durum:_ belirtilmemiş (FROZEN TECHNICAL; eşikler PD; bütçeler EA).

### Bu aşamada doğrulanacak sınırlar

#### Ürün kapsamı

- [ ] **Access değildir (genel tablo)** — Agent platformu/orchestrator/marketplace, "agent'ları durduran" kill switch, ödeme/harcama limiti ürünü, risk/fraud motoru, DLP, SIEM, PAM oturum kaydı, workflow/onay kuyruğu, sertifikalı ekosistem kapısı, zorunlu Suiss bağımlılığı, dikey/uyum ürünü veya "hafif IdP" değildir. _Kaynak:_ §18.2 IS NOT tablosu. _Durum:_ belirtilmemiş.

#### Kimlik ve protokol

- [ ] **Taslaklara normatif bağımlılık yok** — _Kaynak:_ §9.4.2; §11.0 #6; L27. _Durum:_ belirtilmemiş.

#### Karar ve tutarlılık

- [ ] **Test/geliştirme modu ve güvenliği gevşeten bayrak yok** — "Bypass for testing" ve "test mode" bayrağı yoktur (sandbox ayrı domain'dir); dev/prod kod yolu ayrımı yapılmaz. _Kaynak:_ §8.17.10.4; §8.17.10.5; CR-34; OP-48; OP-63; OP-69; TI-9; X21. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).

#### Güvenlik sertleştirme ve geliştirme süreci

- [ ] **Ağ süreçlerinde `panic="abort"` yok; request path'te panic yok** — _Kaynak:_ SA-21. _Durum:_ belirtilmemiş.
- [ ] **Stack protector/CFI nightly yok; gVisor varsayılan değil** — _Kaynak:_ SA-22; SA-24. _Durum:_ belirtilmemiş.
- [ ] **`io_uring` yok** — _Kaynak:_ OP-4; SA-23. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **Backtracking regex motorları yok** — _Kaynak:_ SA-32. _Durum:_ belirtilmemiş.
- [ ] **Satır kapsama yüzdesi hedef değil; flaky testte otomatik tekrar yok** — _Kaynak:_ SA-59. _Durum:_ belirtilmemiş.
- [ ] **`main`'e doğrudan push / force-push yok** — _Kaynak:_ F-16. _Durum:_ belirtilmemiş.
- [ ] **Yeniden üretilebilir build taahhüt edilmez** — _Kaynak:_ OP-49. _Durum:_ belirtilmemiş.
- [ ] **Üçüncü taraf imaj katalog bağımlılığı yok** — _Kaynak:_ OP-49. _Durum:_ belirtilmemiş.
- [ ] **Ayrı ADR klasörü yok** — _Kaynak:_ OP-70. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).

#### Ürün iddiaları ve vaat edilmeyenler

- [ ] **Yasak ürün iddiaları** — "Formel olarak doğrulanmış", "proven secure", "constant-time guaranteed", "quantum-safe" (niteliksiz), "izolasyonu derleyici garanti eder", "Keycloak'tan hızlı", "oturum her yerde anında kapandı", "passkey ile ele geçirilemez" denmez. _Kaynak:_ §1.4; §3.3a; §15.1.2; B15; CR-50. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **SLSA L3 ve Source L4 pazarlamada iddia edilmez** — _Kaynak:_ F-17; SA-38. _Durum:_ belirtilmemiş.
- [ ] **NG/PU sınıfı vaat edilmeyenler** — Claim doğruluğu (N-1), sinyal zamanlı teslimi (N-2, N-38), effect exactly-once (N-5), Sybil direnci (N-17), availability (N-20), prompt injection direnci (N-10), passkey ile token hırsızlığı önleme (N-41), PQ WebAuthn (N-37), sıfır zamanlama sızıntısı (N-46), co-tenant yan kanal yokluğu (N-32), çapraz-RP tam unlinkability (N-31) vb. _Kaynak:_ §13.4; §13.8; N-1…N-59. _Durum:_ NG/PU.

#### İş modeli ve lisans

- [ ] **Kapalı kaynak / enterprise sürüm ve çift lisans yok** — _Kaynak:_ D4. _Durum:_ belirtilmemiş.
- [ ] **Güvenlik yamaları ücretli katmana kilitlenmez** — _Kaynak:_ B20. _Durum:_ belirtilmemiş.
- [ ] **Protocol'den gelir (lisans/telif/katılım ücreti) yok** — _Kaynak:_ B2. _Durum:_ belirtilmemiş.
- [ ] **Semantik sayaç fatura birimi yok** — MAU, SSO bağlantısı, login, Exercise, Grant, agent vb. fatura birimi değildir. _Kaynak:_ B5. _Durum:_ belirtilmemiş.

#### Ekosistem sınırından gelen kurallar

- [ ] **“Kapsam dışı” yerine plane ataması** — Her yetenek identity plane'e, authority plane'e veya ayrı bir ürün katmanına atanır; “kapsam dışı” yalnız gerçek dış sahipler için kullanılır. Ayrı katmanlarda Access yetki kısmına karar verir, olay ve sinyal üretir. _Kaynak:_ §7.6, §7.8; E33, MD-13. _Durum:_ PROPOSED FOR FREEZE.

## Aşama 1 — Kernel

`no_std` çekirdek: deterministik CBOR, digest, ⊑/∩/normalize ve constraint cebiri, ValidityContract aritmetiği, imza ve kanıt doğrulama, restriction motoru, saf durum makineleri ve test vektörleri.

### Spec dışı ön koşullar

- [ ] **Cedar forbid-only spike'ı ve CEL karar kapısı** — başarı ölçütü ve karar tarihi; restriction dili buna bağlı. Kaynak: MD-4, OQ-MD2.
- [ ] **SMT çözücü seçimi ve bağlanması** — `policy.set` polarite ve eşdeğerlik analizi için.
- [ ] **Ed25519 doğrulama denklemi kararı** — cofactored mı cofactorless mı. Kaynak: OQ-CR1.
- [ ] **aws-lc-rs'in `no_std`/Wasm derlenebilirliği** — Kernel'in kripto arka ucu için. Kaynak: OQ-CR2.

### K02 Kimlik protokolleri ve federasyon

#### Doğrulanabilir kimlik bilgileri ve dijital cüzdan

- [ ] **SD-JWT (RFC 9901)** — Seçici açıklama ve PAP kabı olarak kullanılır. _Kaynak:_ §9.4 D, §9.10, §9.13 k.5. _Durum:_ belirtilmemiş (ADOPT).

### K07 Yetki modeli

#### Temel ilkeler ve primitive'ler

- [ ] **Non-monotonic granting yasağı** — "Allow unless X" kuralları positive grant + restriction olarak ifade edilmek zorundadır. _Kaynak:_ L7. _Durum:_ belirtilmemiş

#### AuthoritySet, kısıt cebiri ve tip sistemi

- [ ] **AuthoritySet boyutları** — actions (reserved dahil), resource selector, typed parameter bounds, recipient selector ve purpose set. _Kaynak:_ §5.3, §5.8. _Durum:_ belirtilmemiş
- [ ] **ConstraintSet** — Validity window, while-conditions (ör. Instance yaşadığı sürece) ve budget terms. _Kaynak:_ §5.3, §5.8. _Durum:_ belirtilmemiş
- [ ] **Purpose boyutu** — Typed PurposeRef yalnız küme/eşitlik semantiği taşır; serbest metin authority sınırı olamaz. _Kaynak:_ §5.3, §5.8; C23. _Durum:_ belirtilmemiş
- [ ] **Karar verilebilir kanonik constraint cebiri (⊑ / ∩ / normalize)** — Intersection, subsumption ve normalization sonlanır; child ⊆ parent mekaniktir; positive authority'de negation yoktur (HRU gerekçesi). Kernel'de tek implementasyonu vardır. _Kaynak:_ §5.8; CMP-24, INV-7, INV-8, L9, OP-1. _Durum:_ belirtilmemiş (FROZEN, kernel)
- [ ] **Kapalı attenuation tip sistemi** — Dokuz tip: Enum/set, Equality, Ordered numeric+unit, Count, Time interval, ResourceRef/prefix/selector, SubjectSelector, PurposeRef set, Boolean; yalnız conjunction kullanılır. Tipe eşlenemeyen parametre Acceptance'ta reddedilir. _Kaynak:_ §5.8, §7.9.3.4, §9.13.3; E12, INV-8. _Durum:_ belirtilmemiş

#### Budget ve consumption

- [ ] **Checked arithmetic: taşma = DENY** — Budget/count/window toplamında taşma DENY'dır, kısmi ALLOW üretmez. _Kaynak:_ §13.4 G56; §14.5 R-1; MD-2. _Durum:_ belirtilmemiş

#### Restriction ve politika dili

- [ ] **RestrictionPolicy dili: Cedar forbid-only alt kümesi (CEL yedeği)** — Sabit taban `permit`, kullanıcı politikaları yalnız `forbid` yazar; REQUIRE, forbid'e bağlı bir RequirementSet referansıdır; SMT eşdeğerlik analizi yapılır. Cedar spike'ı başarısız olursa CEL profili + SMT eşdeğerlik yedeği kullanılır. _Kaynak:_ §4.3; §5.8; §16.5; INV-36, MD-4, OQ-MD2, T13, TI-14. _Durum:_ FROZEN (§16.5); CEL yedeği spike'a bağlı

#### Schema ve katalog yönetimi

- [ ] **Must-understand fail closed; downgrade genişletmedir** — Authority'yi sınırlayan alanı tanımayan verifier/evaluator onu "kapsanmıyor" sayar (DENY). _Kaynak:_ §9.1 R7, §9.17; §13.4 G20; P34, PI-12. _Durum:_ belirtilmemiş (FROZEN)

#### Exercise protokolü

- [ ] **Intent digest'ini Access hesaplar** — Digest Access canonical içerikten hesaplanır; caller hash seçemez. _Kaynak:_ §9.5. _Durum:_ belirtilmemiş
- [ ] **Deterministik karar** — Aynı kayıtlar + girdiler → aynı karar ve consumption; normatif hakem L0/L2 metni + conformance vektörleri. _Kaynak:_ §13.4 G17; INV-27, RT8. _Durum:_ belirtilmemiş

#### Çalışma zamanı, log ve atomiklik

- [ ] **Access Core** — Algebra, Requirement Resolver, Restriction Engine, Decision Combinator, Explain, Federation verifier ve record-fold; L0 semantiğinin open-source implementasyonu, versioned StateView üzerinden saf fonksiyon. _Kaynak:_ CMP-4. _Durum:_ belirtilmemiş
- [ ] **Requirement Resolver: en erken pozisyonlu proof seçimi** — Birden çok tatmin eden proof kümesinde en erken pozisyon seçilir. _Kaynak:_ T14. _Durum:_ belirtilmemiş (FROZEN)

### K08 Karar, uygulama ve doğrulama

#### Karar sonuçları ve semantiği

- [ ] **Semantik determinizm ve saf değerlendirme fonksiyonu** — Aynı girdiler iki compliant evaluator'da aynı Decision'ı verir; değerlendirme saf ve deterministik bir fonksiyondur, veri getirme ayrı katmandır. _Kaynak:_ §6.2; §9.7A.7; INV-27; P47. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Restriction dili: Cedar forbid-only alt kümesi** — _Kaynak:_ §9.7A.7; MD-4. _Durum:_ belirtilmemiş.
- [ ] **Sınırlı evaluation ve zorunlu kotalar** — Lineage derinliği, proof sayısı ve istek boyutu sınırlıdır; aşım protokol rejection'ıdır. Kotalar: derinlik 25, genişlik 10, check 100 ms, search 1 s/1000, yazma başına 1000 demet, depo başına 200 tip; kotaya takılan sorgu "cevap yok" döner. _Kaynak:_ §5.8; §9.7A.5; P46; SI-20. _Durum:_ PD (§5.8); EA (§9.7A.5).

#### Envelope bağı ve intent

- [ ] **Intent envelope ve Access-hesaplı digest** — Typed schema'lı, hash-bound bir değerdir. Digest'i deterministic CBOR ile Access hesaplar; caller'ın digest'i girdi değildir. _Kaynak:_ §5.3, §5.10; C29, TI-11. _Durum:_ belirtilmemiş.

#### Projection'lar ve yetki artefaktları

- [ ] **ValidityContract gömülü** — PAP/token içinde gömülü; checked aritmetik, taşma = DENY. _Kaynak:_ §15.3.1; CR-K2; OP-1. _Durum:_ belirtilmemiş (FROZEN).

#### Kernel ve referans bileşenler

- [ ] **Access Kernel (OP-1)** — Normatif değerlendirme çekirdeği; CI kapısı + diferansiyel vektörler. _Kaynak:_ §17.14; OP-1. _Durum:_ belirtilmemiş (FROZEN, PD arayüz).
- [ ] **Sunucu ve verifier aynı Kernel kodunu çalıştırır** — Sunucu, offline verifier, edge/Wasm, mobil FFI. _Kaynak:_ CMP-24; MD-1; T12; T25. _Durum:_ belirtilmemiş (FROZEN).

### K11 Yönetim API'si, konsol, SDK'lar ve geliştirici araçları

#### Doğrulama ve replay araçları

- [ ] **Open reference evaluator (naif F0, imzalı, arşivli)** — Optimizasyonsuz, spec'ten yazılmış referans evaluator ve diferansiyel oracle; replay için Suiss olmadan çalışır. Her sürümü ve vektörleri imzalı ve arşivlidir, replay eski sürümle yapılabilir. _Kaynak:_ §9.16, §9.17; §14.7 F-11; A3; CR-49; T12; U13. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Her semantik sürümün evaluator'ı korunur** — Sürüm emekliliği yok. _Kaynak:_ RT8; T12. _Durum:_ belirtilmemiş (FROZEN).

### K13 Denetim, kayıt, şeffaflık ve dışa aktarım

#### Kayıt formatı ve seçici açıklama

- [ ] **Kayıt zarfı: deterministic CBOR + CDDL** — Normatif CDDL open spec'te yayınlanır. _Kaynak:_ §17.6.1; T4. _Durum:_ belirtilmemiş.
- [ ] **Alan başına salt'lı commitment ile seçici açıklama** — Bir alanı açmadan leaf ve Merkle kökü doğrulanabilir. _Kaynak:_ §17.6.1 kural 1. _Durum:_ belirtilmemiş.

### K15 Güvenlik ve kriptografi

#### Kripto sağlayıcısı ve doğrulama çekirdeği

- [ ] **aws-lc-rs tek kripto sağlayıcısı** — Tüm kripto aws-lc-rs ile yapılır; Ed25519/P-256 için s2n-bignum ispatlı implementasyonlar kullanılır. _Kaynak:_ §2.2.1; §3.3a; §4.9; CR-13; MD-1. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Access Kernel (tek `no_std` crate, sunucu ve tüm verifier'larda aynı)** — Aynı karar mantığı her verifier'da çalışır. _Kaynak:_ MD-1. _Durum:_ belirtilmemiş.
- [ ] **Kernel'de tek doğrulama yolu (JWS/SD-JWT/COSE)** — Bütün imza biçimleri Kernel'deki tek yoldan doğrulanır. _Kaynak:_ CR-6; OP-1. _Durum:_ belirtilmemiş (FROZEN).

#### İmza algoritmaları ve hash

- [ ] **COSE authority imzası: Ed25519 varsayılan** — Receipt, PAP, checkpoint, AIS, AAS, Domain Metadata ve status list COSE + Ed25519 ile imzalanır; ES256/ESP256 doğrulaması zorunludur. FIPS profilinde ES256/ESP256, ML-DSA-65 opt-in. _Kaynak:_ §9.10.1 k.1; §13.2 kripto tablosu; CR-2; CR-5; MD-3; P51; RR-17. _Durum:_ belirtilmemiş (FROZEN MD-3).
- [ ] **Authority artefaktı / authority taşıyan token asla RSA** — Access'in imzaladığı authority artefaktları ve authority taşıyan token'lar RSA kullanmaz. _Kaynak:_ §10.4.5; §11.4.5 düzeltme (a); §13.2; MD-3. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **Yasak JOSE algoritmaları** — `none`, `HS*`, `alg: EdDSA` ve RSA1_5 asla kabul edilmez. _Kaynak:_ §10.4.5; §13.4 G55; IDP-10; MD-3. _Durum:_ belirtilmemiş (alg FROZEN).
- [ ] **RFC 9864 fully-specified algoritmalar ve `alg: EdDSA` reddi** — Üretimde RFC 9864 tam belirtilmiş tanımlayıcılar kullanılır; polimorfik `EdDSA` değeri JWS'te reddedilir. _Kaynak:_ §9.9.3 k.7; §9.15.1; §10.8.3; §12.1.2; §13.2; CR-5; MD-3; P51; RR-17; TN-13. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Algoritma allowlist'i yalnız client/Domain/Realm metadata'dan** — Header `alg` kümeyi genişletmez; allowlist dışı alg reddedilir, bilinmeyen alg/sürüm fail-closed; downgrade testi conformance'ta. _Kaynak:_ §9.9.3 k.7; §9.10.1; §9.15.1; §10.4.5; §11.4.5 düzeltme (d); §12.1.2; §13.4 G55; CR-7; IDI-6; P51; SAI-40; TN-13. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **İmza sıkılık profili** — Ed25519 strict, ECDSA low-S üretim, Access-native'de high-S reddi, RSA DER birebir, ML-DSA norm/hint vektörleri. _Kaynak:_ CR-9; SAI-41. _Durum:_ belirtilmemiş (FROZEN; Ed25519 denklemi açık).
- [ ] **HMAC kullanım kuralı** — HMAC yalnız anahtarlı türetim ve tek taraflı token için. _Kaynak:_ CR-3. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **SHA-256 algoritma etiketli digest** — Bütün digest'ler algoritma etiketli SHA-256; CNSA SHA-384 gelecek profil adayı. _Kaynak:_ CR-1; T5. _Durum:_ belirtilmemiş (FROZEN; SHA-384 WATCH).
- [ ] **Domain separation'lı hash (yaprak 0x00, iç düğüm 0x01, RFC 9162)** — _Kaynak:_ §17.6.1. _Durum:_ belirtilmemiş.

#### Kodlama, kanonikleştirme ve token doğrulama

- [ ] **Verbatim imzalar ve deterministic CBOR digest'leri** — Dış imzalı baytlar aynen saklanır; digest'leri Access hesaplar. _Kaynak:_ §6.7; TI-11. _Durum:_ belirtilmemiş.
- [ ] **Kanonik olmayan CBOR / imza kodlaması reddi** — Yapısal sınırı aşan girdi de reddedilir. _Kaynak:_ §13.4 G60; CR-9; CR-10. _Durum:_ belirtilmemiş.
- [ ] **I-JSON, UTF-8, birimli sayılar** — Authority sayısal parametreleri closed type'ta birimli tamsayı/ondalıktır; IEEE 754 float kullanılmaz. _Kaynak:_ §9.5.1 #11. _Durum:_ belirtilmemiş.
- [ ] **JWT doğrulama kuralları** — iss/aud/exp/nbf/iat kontrolü, ±60 s saat kayması toleransı, anahtar tipi–alg eşleşmesi. _Kaynak:_ §10.4.5. _Durum:_ PD (skew).
- [ ] **JOSE 18 saldırı sınıfı regresyonu** — Alg confusion, `none`, `jwk`/`jku`/`x5u` header enjeksiyonu, `kid` enjeksiyonu, `crit` ihmali, b64=false vb.; kendi doğrulayıcı + Wycheproof. _Kaynak:_ §14.6; SA-29. _Durum:_ belirtilmemiş (FROZEN).

#### Kripto çevikliği ve post-kuantum

- [ ] **Kripto çevikliği: algoritma kimliği imzalı içeriğin parçası** — `algorithm` alanı gün-1'den vardır; uzun süreli doğrulanabilirlik için algoritma kimliği imzalı içeriğe girer. _Kaynak:_ §3.1b; §4.8 eksen 11; §13.2; MD-3; PI-21; SEC4. _Durum:_ gün-1.
- [ ] **JWKS / COSE_KeySet'te `AKP` anahtar tipi** — ML-DSA anahtarları için `AKP` gün-1'den modellenir, varsayılan kapalıdır. _Kaynak:_ §3.1b; §4.8 eksen 11; §9.15.1 k.1; §10.4.5; §10.8.3; §13.2; §13.12; CR-6; CR-41; MD-3; MD-19.3; P60; T5. _Durum:_ gün-1 (modelleme; varsayılan kapalı).

#### Anahtar hiyerarşisi ve kapsamı

- [ ] **DomainID must-understand / binding key kapsamı (Storm-0558 sınıfı koruma)** — Verifier DomainID, iss, realm ve kid eşleşmesini denetler; excerpt DomainID'ye bağlıdır; başka domain'in veya kapsam dışı anahtarla imzalı excerpt/PAP/artefakt DENY edilir. _Kaynak:_ §6.8; §7.1; §9.10.1 k.2; §13.4 G35, G47; CR-18; HL-8; I4; K-6; LFP-26; MD-6; TI-RT6. _Durum:_ belirtilmemiş (FROZEN).

#### Sabit zaman ve yan kanal

- [ ] **Sabit zamanlı karşılaştırma disiplini** — Token/MAC/hash/OTP constant-time; [ID] 10 nokta + [AU] ekleri; `Secret<N>`, `*_vartime`; CI'da dudect (|t| > 5 fail), ctgrind, asm snapshot. _Kaynak:_ §14.8 SA-T13; CR-39; SAI-42; U45. _Durum:_ belirtilmemiş (FROZEN).

#### Girdi, parser ve DoS sınırları

- [ ] **Parser ve DoS limitleri** — Yük boyutu, istek sayısı, bellek sınırları; JSON derinlik ≤ 32 ve boyut parse'tan önce; CBOR derinlik ≤ 16, öğe ≤ 256, string ≤ 64 KB, indefinite-length/duplicate key red, tag allowlist, canonical yeniden kodlama, WebAuthn ~8 KB; x509/DER ≤ 8 KB; SAML DocType red; LDAP BER/SCIM filter limitleri; `with_capacity(n)` yasağı. _Kaynak:_ §9.5.1 #12; §14.6; CR-10; OP-4; SA-28; SA-29; SI-20; U48. _Durum:_ PD (değerler), kural FROZEN.
- [ ] **ReDoS koruması** — Yalnız lineer zamanlı regex motoru; desen ≤ 256. _Kaynak:_ §14.6; SA-32. _Durum:_ belirtilmemiş (FROZEN).

#### Güvenlik ilkeleri: fail-closed, downgrade, compromise

- [ ] **Fail-closed her yerde; kodda fail-open yolu yok** — Belirsizlik, erişilemeyen girdi, rate limiter, risk motoru veya cache arızası ALLOW üretmez; degraded-allow veya bypass konfigürasyonu kodda tanımlı değildir. _Kaynak:_ §6.2; §6.6; §6.7; INV-26; MD-8; SI-6; TI-9. _Durum:_ belirtilmemiş.

#### Zaman güvenliği

- [ ] **Semantik timer yok** — Zamana bağlı semantik evaluation anında trusted time'a göre hesaplanır. _Kaynak:_ §6.7; TI-10. _Durum:_ belirtilmemiş.

### K17 Dağıtım, operasyon, yüksek erişilebilirlik ve felaket kurtarma

#### Dağıtım biçimleri ve profiller

- [ ] **Provider-neutrality** — Protocol yolu yalnız açık spec + Kernel + standart altyapıyla gerçeklenebilir. _Kaynak:_ §17.9.1; TI-17. _Durum:_ belirtilmemiş.

### K18 Açık kaynak, ticari model ve paketleme

#### Açık kaynak bileşenler

- [ ] **Access Core ve Access Kernel açık kaynak** — Access Core, L0 semantiğinin open-source implementasyonudur (normatif değildir); Kernel open-source `no_std` crate'tir. Suiss production bunları kullanır. _Kaynak:_ §7.2, §9.1, §16.1; CMP-24, T12, TI-RT12. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Açık reference evaluator ve Reference Verifier; evaluator retention taahhüdü** — Production'daki her semantik sürümün evaluator'ı açık reference'ta tutulur (ticari taahhüt B12); Reference Verifier sunulur. _Kaynak:_ §6.7, §7.1; B12, T12, TI-17. _Durum:_ belirtilmemiş.
- [ ] **Conformance suite ve vektörler açık ve ücretsiz** — _Kaynak:_ B9. _Durum:_ belirtilmemiş.

### K19 Geliştirme ve kalite güvencesi

#### Release kapısı ve formel doğrulama

- [ ] **Dil/sürüm değişikliği release kapısından geçer** — RestrictionPolicy dil sürümü değişikliği MD-15(b) kapısına tabidir. _Kaynak:_ §6.9; INV-36. _Durum:_ belirtilmemiş.
- [ ] **DRT, property invariant'ları, CVE ve R8 korpusları, sürüm kapısı** — _Kaynak:_ CR-49; MD-15(b). _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Cedar REQUIRE eşlemesi spike'ı** — Açık spike'tır. _Kaynak:_ §5.8; OQ-MD2. _Durum:_ belirtilmemiş.
- [ ] **I/O'suz çekirdek, CI'da zorlanır** — Çekirdek I/O içermez; bu CI'da zorlanır. _Kaynak:_ §3.1b #15. _Durum:_ gün-1.

#### Access conformance ve test vektörleri

- [ ] **Conformance vektör kapsamı** — Semantik sonuç değiştiren her kural L0/L2 metnine ve vektörlere girer. _Kaynak:_ §9.18 P34; TI-RT12. _Durum:_ belirtilmemiş.
- [ ] **Golden vector CI kapısı** — CBOR, Merkle, leaf hash, COSE bayt düzeyinde. _Kaynak:_ §17.6.1, §17.10.2; OP-56, RT8. _Durum:_ belirtilmemiş.
- [ ] **CVE regresyon vektörleri** — §6.2 kanıt notlarındaki vakalar regresyon vektörü olur. _Kaynak:_ §6.2. _Durum:_ belirtilmemiş.
- [ ] **Kripto test vektörleri (V1–V9, Wycheproof, CAVP/ACVP, Crucible, KAT)** — _Kaynak:_ CR-51. _Durum:_ belirtilmemiş (FROZEN).

#### Protokol, kiracı ve bileşen güvenlik testleri

- [ ] **JOSE downgrade testi; `cargo tree -i rsa` CI kontrolü** — _Kaynak:_ §10.4.5. _Durum:_ belirtilmemiş.

### Bu aşamada doğrulanacak sınırlar

#### Yetki modeli

- [ ] **Restriction pozitif yetki üretemez** — _Kaynak:_ INV-6; TI-14; must-never #2. _Durum:_ belirtilmemiş.
- [ ] **ReBAC tuple canonical edge değil; Cedar permit modeli ve pozitif yetki için Cedar yok** — _Kaynak:_ §5.8; L4; L8; MD-4. _Durum:_ belirtilmemiş.
- [ ] **Positive authority'de negation, serbest predicate, Turing-complete ifade ve dış çağrı yok** — _Kaynak:_ §5.8; INV-7; INV-8. _Durum:_ belirtilmemiş.
- [ ] **Wildcard-subject delegation yok; reserved action'lar wildcard/prefix ile kapsanmaz** — _Kaynak:_ INV-9; L10. _Durum:_ belirtilmemiş.
- [ ] **Semantik timer yok** — _Kaynak:_ T15; TI-10. _Durum:_ belirtilmemiş (FROZEN).

#### Karar ve tutarlılık

- [ ] **Harici yetki motoru bağımlılığı yok** — OpenFGA, SpiceDB, Keto, casbin, oso ve regorus kullanılmaz. _Kaynak:_ §9.7A.7. _Durum:_ belirtilmemiş.

#### Kriptografi

- [ ] **Authority artefaktları asla RSA veya realm JOSE/SAML anahtarıyla imzalanmaz; `rsa` crate kullanılmaz** — Realm anahtarı authority projection'ı imzalamaz. _Kaynak:_ §9.9.3 k.7; §11.4.5; §13.2; G46; MD-3; P51; RR-17; T5. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **JWS'te `alg: EdDSA` ilan edilmez ve reddedilir (ingest dahil)** — _Kaynak:_ §9.9.3 k.7; §11.4.5; CR-5; G55; MD-3; P51. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **`alg: none` hiçbir yerde yok** — _Kaynak:_ CR-5; G55. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Authority plane'de JWE yok** — _Kaynak:_ §13.2 kripto tablosu; CR-4. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Çok taraflı token'da simetrik MAC (HS256/384/512) yok** — _Kaynak:_ CR-3. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Batch imza doğrulaması yok** — _Kaynak:_ CR-11. _Durum:_ belirtilmemiş (FROZEN).

## Aşama 2 — Depo ve kayıt

PostgreSQL şeması, kiracılık eksenleri ve RLS, domain log, sequencer, outbox, Genesis, Exercise/DecisionRecord/Claim kayıtları, idempotency, temel denetim kaydı, göç altyapısı.

### Spec dışı ön koşullar

- [ ] **Güvenilir zaman kaynakları** — en az iki bağımsız kaynak (ör. NTS, Roughtime), doğrulanması ve testte taklit edilmesi.
- [ ] **Zamanlanmış / ertelenmiş iş altyapısı** — soğuma süreleri, davet ve alan adı doğrulama süreleri, imha işleri, ileri tarihli İK kayıtları için kalıcı zamanlayıcı.
- [ ] **Sır yükleme mekanizması kararı** — ortam değişkeni ve K8s Secret yasak; dosya bağlama, KMS sarmalı vb. hangisi.
- [ ] **Identity plane outbox algoritması** — Kaynak: OQ-MD3.
- [ ] **Paylaşımlı sayaç ve önbellek deposu kararı** — hız sınırı ve kota sayaçları, replay/nonce önbellekleri (DPoP, `jti`) çok düğümde fail-closed; PostgreSQL mi ayrı depo mu.

### K03 Oturum ve token yönetimi

#### Epoch'lar ve hızlı iptal

- [ ] **Aynı nonce ile retry çift Exercise üretmez** — İdempotent retry. _Kaynak:_ §13.4 G40; TI-8. _Durum:_ belirtilmemiş.

### K04 Hesap yaşam döngüsü ve kurtarma

#### Tanımlayıcılar ve e-posta

- [ ] **Tanımlayıcılar asla yeniden kullanılmaz; mezar taşı (tombstone)** — PartyID, realm-yerel `sub`, kullanıcı kimliği, InstanceID ve ResourceRef koşulsuz yeniden atanmaz; silme bir tombstone'dur ve tekillik kısıtı canlı kayıtlarla birlikte tombstone'u da kapsar. SCIM DELETE sonrası 404 (asla 410); riske katmanlı emeklilik. E-posta hiçbir zaman kimlik/anahtar değildir. _Kaynak:_ §3.1b #14, §5.6, §5.16, §12.3.5; INV-32, TN-76, TNI-10. _Durum:_ gün-1 (§3.1b); FROZEN (§12.3.5)

### K05 Kiracılık, realm ve B2B organizasyonlar

#### Kiracılık eksenleri ve kardinalite

- [ ] **Dört kiracılık ekseni: Tenant / AuthorityDomain / Identity Realm / Cell** — Tenant ticari hesaptır (fatura, kota, sözleşme, destek); AuthorityDomain authority semantiğinin, yerleşimin, izolasyonun ve shard'ın birimidir; Identity Realm identity ad alanı (IdP kiracısı); Cell fiziksel yerleşimdir. _Kaynak:_ §2.2.2 #6; §5.1, §5.14, §5.16, §7.2; §12.1.1; §16.10 T27; E35; MD-5; TN-1. _Durum:_ belirtilmemiş (FROZEN, §12.1.1/T27); E35'e göre PROPOSED FOR FREEZE.
- [ ] **Kardinalite: tenant → 0..n domain, 1..n realm** — Bir domain hiçbir zaman iki tenant'a yayılmaz; varsayılan eşleme 1 realm ↔ 1 domain'dir. _Kaynak:_ §5.16, §7.1; §12.1.1; TN-1. _Durum:_ belirtilmemiş (FROZEN, TN-1).
- [ ] **Düz hiyerarşi** — İç içe tenant/realm yok; iç yapı Grant lineage ile ifade edilir (derinlik ≤16). _Kaynak:_ §12.1.1; TN-6. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Sandbox domain ve tesis domain'i** — Bir kiracı birden çok domain barındırabilir (ör. X21 sandbox domain'i). _Kaynak:_ §5.16; X21. _Durum:_ belirtilmemiş.
- [ ] **B2C ve B2B'nin birlikte desteği** — Müşteri (B2C) ve kurumsal (B2B) senaryolar aynı modelde desteklenir. _Kaynak:_ §4.8 eksen 4. _Durum:_ belirtilmemiş.

#### Authority log anahtarlama ve yerleşim

- [ ] **Authority log'unun `domain_id` ile anahtarlanması; değişebilir tenant ↔ domain eşlemesi** — Authority canonical log ve kayıtları `domain_id` ile anahtarlanır; tenant ↔ domain eşlemesi placement directory ve ticari tablolarda tutulur ve değişebilir. _Kaynak:_ §3.1b; §5.1, §5.16, §7.1; I4; OP-12; OP-17; T27. _Durum:_ gün-1 (§3.1b); T27'ye göre FROZEN.

#### Fiziksel izolasyon ve tipli kapsam

- [ ] **Şema düzeyinde kiracı izolasyonu: kapsam önekli PK, bileşik FK, RLS FORCE, NOBYPASSRLS, SET LOCAL** — Identity plane, derived, PII vault ve operasyon tablolarında PK'de `tenant_id` (+ `domain_id`/`realm_id`), kapsam önekli UNIQUE, bileşik FK, `RESTRICTIVE` RLS FORCE ve `NOBYPASSRLS` uygulama rolü; kapsam ayarsızsa fail-closed. _Kaynak:_ §3.1b #1–3; §5.1, §5.16; §10.1.1; §16.1.1; §17.2.2; I4; MD-5; OP-12; T27. _Durum:_ gün-1; §17.2.2'ye göre FROZEN (MD-5).
- [ ] **Kapsamsız sorgu derlenmez (tipte kiracı/domain/realm kapsamı)** — `access-store` tipli sorgu katmanı domain/tenant kapsamı olmayan sorguyu derlemez (branded lifetime); RLS ikincil katmandır; uygulama ve servis rolleri NOBYPASSRLS ve tablo sahibi değildir. _Kaynak:_ §5.16; §13.4 U59; §14.5 R-7; §17.2.2; HL-33; MD-2, MD-5; OP-3, OP-8, OP-12. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **Branded lifetime ile derleme zamanı izolasyon iddiası** — Belirli yanlış kullanımları derlemede engellediğine dair izin verilen dil §3.3a'ya bağlıdır. _Kaynak:_ §3.3a; MKT-D5. _Durum:_ HYPOTHESIS.

#### Realm ve tenant başına operasyonel ayarlar

- [ ] **Realm/tenant başına denetim saklama ayarı** — Sıcak katman 30–90 gün arasında ayarlanabilir. _Kaynak:_ §17.6.7; OP-40. _Durum:_ POLICY DEFAULT.

### K07 Yetki modeli

#### Kayıtlar, corpus ve tek yazma yolu

- [ ] **Kayıtlar kanonik, graf türetilmiş** — Genesis, Exercise ve Claim kayıtları append-only ve attributable'dır; güncel graf bunların deterministik projection'ıdır. _Kaynak:_ §5.2; C2, TI-1. _Durum:_ belirtilmemiş
- [ ] **İki corpus** — Authority state corpus'u yalnız meta-Exercise ALLOW ile yazılır; Claim corpus'u dış ingest ile veya `claim.issue` ile yazılır. _Kaynak:_ §5.2; INV-2. _Durum:_ belirtilmemiş

#### AuthorityDomain, Genesis ve Anchor

- [ ] **AuthorityDomain ve Genesis** — DomainID genesis digest'idir ve provider'dan bağımsızdır. Genesis domain başına tek, imzalı kayıttır; kurucu root'ları, bootstrap Grant'larını, ilk Acceptance'ları, reserved power'ları ve meta-action requirement'larını içerir. _Kaynak:_ §5.1, §5.2; C4, T27. _Durum:_ belirtilmemiş
- [ ] **İlk yönetici yalnız Genesis'ten yetkilenir** — Genesis tek unconditioned kayıttır; ayrı bootstrap admin yolu yoktur. İlk realm yöneticisi Genesis bootstrap Grant'ı veya kurucu root'un Exercise'ıyla yetkilenir. _Kaynak:_ §5.2; §12.5.1; INV-2, MD-14, TN-111. _Durum:_ belirtilmemiş (FROZEN)

#### Claim, Acceptance ve ingest

- [ ] **Claim corpus domain log'unda** — Claim'ler aynı total order'dadır; HoldingRef `since` ingest pozisyonudur. _Kaynak:_ §17.1.4. _Durum:_ belirtilmemiş

#### Exercise protokolü

- [ ] **Nonce tabanlı idempotency** — Aynı nonce + aynı intent digest + aynı actor aynı DecisionRecord'u döndürür ve ikinci consumption yapılmaz; farklı intent/digest protocol hatasıyla reddedilir. _Kaynak:_ §9.5 k.5; §17.1.1; INV-21, OP-S2–OP-S5, OP-S8, P7, TI-8. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Nonce ve AIS yaşı kuralı** — Nonce lookup arşiv dahil yapılır; AIS yaşı ≤ intent validity tavanı; aynı-nonce retry idempotenttir. _Kaynak:_ §16.5; RT7, TI-RT3. _Durum:_ belirtilmemiş (FROZEN; tavan PD)

#### Çalışma zamanı, log ve atomiklik

- [ ] **Domain başına append-only, Merkle-commitment'lı log** — Her AuthorityDomain için tek total order'lı log; prev hash chain + Merkle ağacı; DomainID = genesis digest. _Kaynak:_ §16.1; T3. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **AuthorityDomain başına tek sequencer (head CAS)** — Domain başına tek leader/yazar; optimistic read-set validation yapılır ve head CAS (`pos`, `epoch`) ikinci leader'ın append'ini DB'de reddeder. _Kaynak:_ §16.1 A1; §17.1.1; CMP-3, T6, T7, TI-2. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Atomik batch commit** — Kayıtlar ∪ sync-derived ∪ outbox ∪ head CAS tek transaction'dır; bir DecisionRecord'un bütün effect'leri birlikte görünür. _Kaynak:_ §16.1 A1; §17.1.1; T7, TI-7. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Meta-Exercise ile state değişikliği tek tx** — Her meta-Exercise ALLOW + state change tek transaction'dır. _Kaynak:_ §17.1.1; INV-2. _Durum:_ belirtilmemiş
- [ ] **Stale state ALLOW üretemez** — Commit-mode kararlar yalnız leader'da, q−1 state'ine karşı verilir; replica/index/cache yalnız advisory'dir. _Kaynak:_ §16.1 A2; INV-26, T10. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Record-fold ile state kurma** — State, kayıtlı DecisionRecord effect'leri + Claim'lerden L0 türetimle kurulur; cold-start yalnız Genesis'ten veya fold-doğrulanmış snapshot'tan. _Kaynak:_ §16.5; TI-RT1, TI-RT4. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **SYNC-DERIVED yapılar** — Budget sayaçları, nonce/single-use, güncel authority state, holding episode'ları, rolling aggregate'ler, release toplamları, Claim güncelliği, per-verifier contract durumu ve issuer kota sayaçları commit tx'inde güncellenir. _Kaynak:_ §16.5.1; T9. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Koleksiyon key'leriyle read-set tamlığı** — Negatif okumalar koleksiyon key'leriyle yakalanır; kaçırılmış çakışma olmaz. _Kaynak:_ §16.5.2; TI-4. _Durum:_ belirtilmemiş (FROZEN)

### K08 Karar, uygulama ve doğrulama

#### Envelope bağı ve intent

- [ ] **Idempotent nonce ve aynı-nonce retry** — (domain, nonce) tekildir; retry ikinci consumption üretmez, PEP replay'i merkezde tek effect üretir; aynı nonce + farklı intent protokol hatasıdır. İstemci timeout'unda aynı nonce'la retry yapılır; pencere sonrası aynı-nonce isteği yalnız sonuç sorgusudur. _Kaynak:_ §5.10; §13.4 U23; §16.7; RT23; TI-8. _Durum:_ belirtilmemiş.
- [ ] **Effect receipt lost: aynı nonce tekrar ALLOW almaz** — _Kaynak:_ §8.13. _Durum:_ belirtilmemiş.

#### Ürün kapsamı ve yol haritası

- [ ] **Exercise record** — _Kaynak:_ §18.13. _Durum:_ Faz 1 (§18.13 çıkarım).

### K11 Yönetim API'si, konsol, SDK'lar ve geliştirici araçları

#### Erişim filtresi ve kimlikler

- [ ] **Veri katmanında tipli yetki filtresi + uç nokta izin manifesti** — Domain/tenant kapsamı olmayan sorgu derlenemez, handler başına filtre unutulamaz; manifestsiz yol CI'da kırılır, uç nokta başına otomatik 403/404 testi vardır, kaynak gizleme varsayılandır. _Kaynak:_ §3.1b #22; §12.5.1; CR-52 madde 3; LFP-28; TN-113. _Durum:_ gün-1; belirtilmemiş (FROZEN).
- [ ] **Opak kimlik tabanlı yetkilendirme; UUIDv7 iç / önekli opak dış ID** — Yetkilendirme isim yerine opak kimlikle yapılır; iç ID UUIDv7, dış ID önekli opak (`grt_…`, `rlm_…`). _Kaynak:_ §3.1b #11; LFP-27; MD-18; OP-65. _Durum:_ gün-1.

### K12 Entegrasyonlar ve yardımcı servisler

#### SSF/CAEP, olay yayını ve Relay

- [ ] **Transactional outbox** — Her dış etki (webhook, SSF/CAEP, e-posta, Relay) aynı transaction'da outbox'a yazılır. _Kaynak:_ §16.1.1; OP-63 madde 3. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).

### K13 Denetim, kayıt, şeffaflık ve dışa aktarım

#### Exercise ve karar kayıtları

- [ ] **Authority Exercise kaydı (attributable exercise record)** — Hangi authority'nin hangi envelope için kullanıldığının değiştirilemez kaydı; kaydı Access üretir, receipt executor'ındır. _Kaynak:_ §1.4 vaat 6; F5; F7; LFP-22. _Durum:_ belirtilmemiş.
- [ ] **Append-only, silinemez kayıt defteri** — Existence, attribution, lineage, digest ve zaman silinemez; Genesis, Exercise/DecisionRecord, Claim ingest kayıtları düzenlenemez. _Kaynak:_ §5.2; §8.5 S9; §13.4 G23; C34; INV-30. _Durum:_ belirtilmemiş.
- [ ] **DecisionRecord** — Outcome, cited proofs, AuthorityStateBasis, trusted time, ValidityContract ve consumption effects içerir. _Kaynak:_ §5.2; INV-22. _Durum:_ belirtilmemiş.
- [ ] **DecisionRecord sürüm alıntısı** — Her karar core spec/meta-schema/schema/profile sürümlerini kaydeder; replay aynı sürümlerle yapılır. _Kaynak:_ §9.5 `versions`; §9.17 compat k.1. _Durum:_ belirtilmemiş.
- [ ] **DENY / REQUIRE_ACTION kaydı** — Commit-mode DENY kanonik DecisionRecord olarak kayıtlıdır; auditable veya güvenlik açısından önemliyse evaluation DecisionRecord'u olarak da kaydedilebilir. _Kaynak:_ §5.2; §17.6.6; OP-39. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **Karar log'u kapsamı** — Advisory/search/explain kaydedilmez; identity plane denetim olayı iş değişikliğiyle atomik yazılır, Merkle, imza ve egress arka planda yapılır. _Kaynak:_ §9.16.3; C30. _Durum:_ belirtilmemiş.

#### Atıf ve inkâr edilemezlik

- [ ] **İmzalı bayt'ların aynen saklanması (proof store)** — AIS, AAS, WebAuthn assertion, ID token, SET alındığı bayt'larla saklanır. _Kaynak:_ §17.6.1 kural 2; SI-1; TI-11. _Durum:_ belirtilmemiş.

#### Authority log bütünlüğü

- [ ] **Authority domain log'u (CANONICAL, tamper-evident)** — Domain başına append-only hash zinciri + Merkle commitment; header'lar süresiz; checkpoint, offline report chain ve Record Export tamper-evident; redaksiyon T39'a göre. _Kaynak:_ §12.1.3, §12.3.5; §13.2 kripto tablosu; §17.1.4; §17.6; INV-30; SEC4; T3; TN-77. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Authority log: tek sequencer, batch içinde amortize hash zinciri** — _Kaynak:_ §4.3; T3; T16. _Durum:_ belirtilmemiş.
- [ ] **DB'de üç katmanlı append-only savunması** — GRANT, satır trigger'ı, TRUNCATE trigger'ı; pgaudit ikincil. _Kaynak:_ §17.2.7; OP-17. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **Kayıt kimliği = commitment; sessiz bozulma tespiti** — Bozulma log içeriğini değiştirmez; tespit sonrası bozuk satıra dayalı karar verilmez; rebuild-diff farkı sev-1. _Kaynak:_ §13.4 G34, U30; §17.6.12; FA-14; RT9; TI-16. _Durum:_ belirtilmemiş.
- [ ] **Ack edilmiş security event kaybolmaz** — `synchronous_commit=on`; failover grace 0. _Kaynak:_ §13.4 U51; SA-47. _Durum:_ PD.

#### Identity plane denetim log'u

- [ ] **Tamper-evident identity plane audit** — Düz append-only log + periyodik (~1 sn) Merkle checkpoint + imza; ekleme yolu imza beklemez; checkpoint'ler dış tanığa (witness), müşteri hook'una, nesne kilitli S3'e yayımlanır, SIEM'e projection üretilir. Yayımlanmış checkpoint öncesi değişiklik ≥ 1 bağımsız yayın hedefiyle tespit edilir (DB erişimi olanın satır değiştirmesi dahil). _Kaynak:_ §2.2.1; §4.3; §7.1; §13.4 U70; §17.6.2; MKT-D14; OP-37. _Durum:_ belirtilmemiş (FROZEN TECHNICAL); farklılaşma HYPOTHESIS.
- [ ] **Atomik denetim outbox'ı (identity) + Merkle checkpointer** — Her güvenlik değişikliği minimal denetim satırını iş değişikliğiyle aynı tx'te outbox üzerinden yazar. _Kaynak:_ §3.1b #23; §16.1.1; §17.1.3; CMP-27; OP-10, OP-13; OPI-6. _Durum:_ gün-1; FROZEN TECHNICAL.
- [ ] **Denetim logunun request path dışında olması** — Login isteği audit insert'ini beklemez. _Kaynak:_ MKT-D17. _Durum:_ belirtilmemiş (farklılaşma HYPOTHESIS).
- [ ] **Partition'lı identity denetim günlüğü** — Tenant + zaman bölümlü, yüzlerde bölüm; sıcak pencere 30–90 gün + tenant başına dışa aktarım hedefi; GDPR silmesi bölüm DETACH+DROP. _Kaynak:_ §3.1b #10; §12.1.3; TN-25. _Durum:_ gün-1 (partition); PD (pencere).
- [ ] **Protocol rejection'ların operasyonel denetim akışı** — Örneklemesiz, OPERATIONAL. _Kaynak:_ §17.6.6; OP-39, OP-44. _Durum:_ belirtilmemiş.

### K14 Sinyaller, gözlemlenebilirlik ve analitik

#### Authority semantic event'leri

- [ ] **Olay id realm/domain başına HMAC** — Dedup için domain başına anahtarlı HMAC. _Kaynak:_ §12.2.2; §17.3.1; T26. _Durum:_ belirtilmemiş.

#### Olay dağıtımı

- [ ] **Authority event dağıtımı (outbox → NATS JetStream)** — Event id domain başına HMAC (dedup); durability fence; her event `basis` taşır. _Kaynak:_ §17.3.1; E30; T26; TI-6. _Durum:_ belirtilmemiş.
- [ ] **Olay sıralama kuralı** — Sıra garantisi yok; monoton sürüm alanı; "şüphede yeniden sorgula". _Kaynak:_ §17.3.5; OP-22. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **NATS opsiyonel (self-host)** — Relay ve SSF transmitter doğrudan outbox polling ile çalışabilir. _Kaynak:_ §17.3.6; OP-23. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Identity outbox polling** — Varsayılan 100 ms; teslim algoritması açık (OQ-MD3). _Kaynak:_ §17.3.3; OP-20; OPI-1. _Durum:_ belirtilmemiş (algoritma açık).

### K15 Güvenlik ve kriptografi

#### Transport ve servis kimliği

- [ ] **TLS 1.3 her kanalda** — _Kaynak:_ §10.8.3; CR-12; T5. _Durum:_ belirtilmemiş (FROZEN).

#### Veri şifreleme ve sır yönetimi

- [ ] **KEK/DEK zarf şifreleme ve DEK önbelleği** — _Kaynak:_ CR-32; T27; T39. _Durum:_ belirtilmemiş (FROZEN; TTL PD).
- [ ] **Domain KEK'i; body başına DEK** — AuthorityDomain kapsamlı KEK; body'ler domain KEK'i altında body başına DEK ile şifrelenir. _Kaynak:_ §5.16; §7.2; §12.1.3; MD-19.6. _Durum:_ belirtilmemiş.
- [ ] **Her KEK rotasyonla değiştirilebilir** — _Kaynak:_ §17.10.4. _Durum:_ belirtilmemiş.
- [ ] **Authority kayıtları sır içermez** — _Kaynak:_ §7.1; §7.9.12.4. _Durum:_ belirtilmemiş.
- [ ] **Dosya tabanlı sırlar ve rotasyonda yeniden yükleme** — _Kaynak:_ §17.9.5; CR-35; OP-52. _Durum:_ PD.

#### Platform ve çalışma zamanı sertleştirmesi

- [ ] **Fail-fast güvenli yapılandırma** — Güvensiz config ile başlatma reddedilir (issuer, TLS, admin adresi, sync standby sayısı, signer, JWKS). _Kaynak:_ §17.9.5; OP-52. _Durum:_ belirtilmemiş (FROZEN).

#### Kiracı izolasyonu ve kimlik tanımlayıcıları

- [ ] **Veri izolasyonu (RLS)** — PK'de tenant_id, bileşik FK, RLS ENABLE+FORCE, RESTRICTIVE fail-closed, NOBYPASSRLS, `SET LOCAL`. _Kaynak:_ §12.1.3; TN-19; TNI-3. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Tip sisteminde kiracı kapsamı ve dürüst izolasyon ifadesi** — Kapsamsız sorgu derlenmez (markalı kapsam, opak kimlik tipleri, tek `begin`); ürün ifadesi: "Queries without a tenant/domain scope don't compile; isolation is additionally enforced by row-level security". _Kaynak:_ §8.10; §12.1.3; MD-5; TN-22. _Durum:_ FROZEN (kural), EA (crate).
- [ ] **Kapsamlı benzersizlik (gizli kanal savunması)** — Küresel benzersizlik yalnız `client_id`, `kid`, hostname, slug. _Kaynak:_ §12.1.3; TN-20. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **PostgreSQL sertleştirme** — `SECURITY DEFINER` + `search_path`, `security_invoker` view'lar, `(SELECT…)` sarılı indeksli RLS fonksiyonları, `SET ROLE` yok, asgari sürüm sabitleme, havuzda `RESET ALL`. _Kaynak:_ §12.1.3; TN-26. _Durum:_ PD.
- [ ] **Çapraz kiracı okuma testleri** — _Kaynak:_ §11.4.5 #36; §11.7. _Durum:_ belirtilmemiş.
- [ ] **İç kimlikler UUIDv7, dış kimlikler opak** — Dış kimlikler zaman/sıra sızdırmaz (HMAC/opaque). _Kaynak:_ §5.3; §12.1.3; §17.2.1; MD-18; OP-11; TI-RT10. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).

#### Güvenlik ilkeleri: fail-closed, downgrade, compromise

- [ ] **Replay koruması (AIS)** — Nonce + digest bağlama ile forward edilen statement başka intent/nonce'a bağlanamaz. _Kaynak:_ §9.5 k.3. _Durum:_ belirtilmemiş.

#### Zaman güvenliği

- [ ] **Trusted time / zaman bütünlüğü** — En az 2 bağımsız zaman kaynağı, sınırlı ilerleme, witness çapraz kontrolü, monoton `recorded_at`; uyuşmazlık commit'i durdurur, saat sapması beyanı aşılırsa leader sağlıksız sayılır. _Kaynak:_ §5.11; §6.7; §6.8; §17.4.11; FA-3; RT4; TI-19; TI-RT2; U29. _Durum:_ belirtilmemiş; sapma eşiği EA (≤ 250 ms).

### K16 Gizlilik, rıza ve uyum

#### Takma adlar ve bağlanamazlık

- [ ] **HMAC event id** — Event id domain başına anahtarlı HMAC'tir, subject hash'i değildir. _Kaynak:_ §9.16; TI-RT10. _Durum:_ belirtilmemiş.
- [ ] **Idempotency-Key'de kişisel veri yok** — _Kaynak:_ §9.5.2 k.5. _Durum:_ PD.

### K17 Dağıtım, operasyon, yüksek erişilebilirlik ve felaket kurtarma

#### Dağıtım biçimleri ve profiller

- [ ] **PostgreSQL ≥ 18 asgari sürüm** — Canonical + derived cluster cell başına. _Kaynak:_ §3.1b #27; §17.9.1; §17.14; OP-7; T8. _Durum:_ gün-1; FROZEN TECHNICAL.

#### Cell topolojisi ve altyapı

- [ ] **Cell (fiziksel yerleşim) ekseni** — Fiziksel yerleşim birimi kiracılık eksenlerinden ayrıdır. _Kaynak:_ §2.2.2 #6; MD-5. _Durum:_ belirtilmemiş.
- [ ] **Satır tabanlı çok kiracılık; Citus sonradan** — Kiracı başına şema/DB reddedilir. _Kaynak:_ §12.1.3; TN-21. _Durum:_ PD.
- [ ] **Bağlantı havuzu ve ayrı havuzlar** — Kritik, admin, replica, sequencer havuzları; kuyruk derinliği metrik. _Kaynak:_ §17.9.7; OP-53. _Durum:_ PD.

#### Commit ve dayanıklılık

- [ ] **Storage-tabanlı tek writer** — domain_head üzerinde CAS; pozisyon yeniden kullanılmaz. _Kaynak:_ §6.7; TI-2. _Durum:_ belirtilmemiş.
- [ ] **Saat bağımsız commit** — Commit head CAS + pozisyon üzerine kuruludur; derived depo arka ucu seçiminde saat kayması dikkate alınır. _Kaynak:_ §9.7A.2 k.4. _Durum:_ belirtilmemiş.
- [ ] **Tek commit, tüm effect'ler + outbox** — Effect'ler tek transaction'da yazılır; paylaşım yazımı outbox + aynı-nonce retry ile. _Kaynak:_ §5.17, §6.7; TI-7, TI-8. _Durum:_ belirtilmemiş.
- [ ] **Outbox tabanlı yayın (derived ≠ canonical)** — Dağıtık cache doğruluk kaynağı değildir; outbox kullanılır (identity plane outbox algoritması OQ-MD3 açık). _Kaynak:_ §3.1; §4.3; OQ-MD3. _Durum:_ belirtilmemiş.
- [ ] **Durability fence** — Durable commit olmadan ack, event veya artefakt çıkmaz. _Kaynak:_ §6.7; TI-6. _Durum:_ belirtilmemiş.

#### Provider bağımsızlığı ve keşif

- [ ] **DomainID provider'dan bağımsız; conformant provider'da hosting** — DomainID genesis digest'inden türetilir ve provider değişiminde korunur. _Kaynak:_ §7.9.11.2; §9.15, §9.17; CI-15; E20; P3. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Domain'de tek provider binding** — Eşzamanlı iki provider imkânsızdır; alt Anchor binding değiştiremez. _Kaynak:_ §9.13.7, §9.15; PI-15. _Durum:_ belirtilmemiş.

#### Sürüm, yükseltme ve göç

- [ ] **Şema göçü ayrı job, expand/contract, `CONCURRENTLY` indeks** — Şema göçü uygulama başlangıcında değil ayrı job olarak çalışır. _Kaynak:_ §2.2.1; §3.1b #26; §16.1.1; §17.10.1; OP-55. _Durum:_ gün-1; FROZEN TECHNICAL.

### K18 Açık kaynak, ticari model ve paketleme

#### Suiss bağımsızlığı ve kilitlenmeme (anti-hostage)

- [ ] **Anti-hostage kuralları** — Kurallar: DomainID bağımsız, tam export her zaman, Suiss registry/trust anchor değil, handover/recovery protocol'de, conformance ≠ endorsement. _Kaynak:_ §9.17. _Durum:_ belirtilmemiş.

#### Ticari model ve fiyat ekseni

- [ ] **Ticari abonelik (Tenant) yalnız fatura/plan yüzeylerinde** — "Subscription / Billing account"; authority içermez. _Kaynak:_ §8.8, §8.11. _Durum:_ belirtilmemiş.
- [ ] **Ticari value metric = Authority Exercise** — Ticari değer metriği Authority Exercise'tır (login/oturum fatura birimi değildir). _Kaynak:_ §1.5; B17. _Durum:_ belirtilmemiş.
- [ ] **Semantik sayaç fatura birimi yok (fiyat ekseni MAU değil)** — Exercise, Grant, Instance, Party, Domain, MAU, realm, SSO bağlantısı, login, MFA kullanıcısı, MCP client vb. fatura birimi değildir. _Kaynak:_ §4.8 eksen 6, §18.5; B5, MD-17. _Durum:_ belirtilmemiş (FROZEN STRATEGY); identity ticari tutması HYPOTHESIS (H9).

#### Ücretlendirilemez güvenlik ve temel yüzeyler

- [ ] **12 aylık audit penceresi policy minimumunun ücretsiz baseline olması** — PCI'ın 12 aylık sıcak audit gereksinimini karşılayan policy minimumu ücretsiz baseline'dır. _Kaynak:_ MKT-D16, SEC32. _Durum:_ belirtilmemiş.

### K19 Geliştirme ve kalite güvencesi

#### Release kapısı ve formel doğrulama

- [ ] **DST'ye uygun saf sequencer durum makinesi** — _Kaynak:_ OP-8. _Durum:_ belirtilmemiş (FROZEN).

#### Access conformance ve test vektörleri

- [ ] **Fuzz, deterministik concurrency testi, sınırlı model kontrolü, conformance süiti** — HTTP ve depolama katmanları fuzz ve deterministik concurrency testine, protokol durum makinesi sınırlı model kontrolüne ve conformance süitine tabidir. _Kaynak:_ §3.3a. _Durum:_ belirtilmemiş.
- [ ] **Conformance: tek yazma yolu testi, determinizm testi, web modeli senaryoları** — INV-2'nin kapsadığı yüzeyler tek yazma yolu conformance kapsam listesiyle test edilir. _Kaynak:_ §6.2; CR-52, INV-2. _Durum:_ belirtilmemiş (FROZEN).

#### Protokol, kiracı ve bileşen güvenlik testleri

- [ ] **Altı çapraz kiracı izolasyon testi CI'da zorunlu** — Şema değişmezi CI, ikiz kiracı diferansiyel, proptest, token karışıklığı fuzzer (+ DomainID vektörü), gizli kanal, ayarlanmamış GUC. _Kaynak:_ §12.1.3; TN-23. _Durum:_ PD.

#### Mühendislik standartları (OP-62…OP-74)

- [ ] **OP-66 Veri katmanı** — ORM yok, `sqlx::query!`, şema güvenlik testleri, gerçek Postgres testleri. _Kaynak:_ OP-66. _Durum:_ belirtilmemiş.
- [ ] **OP-73 Fiziksel silme yok** — Uygulama rolünde `DELETE`/`TRUNCATE` yetkisi yok, CI SQL lint'i; yumuşak silme (durum + `deleted_at` + tombstone); kişisel veri silme = crypto-shredding; saklama sonu = soğuk arşiv. _Kaynak:_ OP-73. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **OP-74 Saklama ve silme modeli** — Kişi × saklama sınıfı DEK'i, kanuni saklama kuralları (Ek C), dava/regülatör saklaması, silme talebi akışı, iki kişilik okunabilir çıkarma (≤ 24 saat), bastırma kayıtları. _Kaynak:_ OP-74; Ek C. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).

### Bu aşamada doğrulanacak sınırlar

#### Yetki modeli

- [ ] **Ayrı Acceptance store'u ve ayrı decision store yok** — _Kaynak:_ §7.9.1.1. _Durum:_ belirtilmemiş.
- [ ] **Tek global epoch yok** — _Kaynak:_ L17. _Durum:_ belirtilmemiş.
- [ ] **`authz_epoch` authority plane'de yok** — Yerini AuthorityStateBasis ve `applied_pos` alır. _Kaynak:_ §5.11; §9.11.1; P56. _Durum:_ belirtilmemiş.
- [ ] **Tuple deposuna log dışında yazma yolu yok** — _Kaynak:_ §5.17; INV-33. _Durum:_ belirtilmemiş.
- [ ] **Spec yeni event türü eklemez** — Ek event türü governance yoluyla eklenir. _Kaynak:_ SI-21. _Durum:_ belirtilmemiş.

#### Yönetim, operatör ve destek erişimi

- [ ] **Bootstrap yazma/admin yolu yok** — Genesis tektir. _Kaynak:_ §5.2; INV-2; TN-130. _Durum:_ belirtilmemiş.

#### Kiracı ve hesap modeli

- [ ] **İç içe tenant/realm ve örtük miras yok** — _Kaynak:_ TN-6. _Durum:_ belirtilmemiş.
- [ ] **Kiracı izolasyonunda `SET ROLE` geçişi, `gen_random_uuid()` varsayılanı ve kiracı başına şema/DB yok** — _Kaynak:_ §12.1.3; OP-12; TN-21; TN-26. _Durum:_ belirtilmemiş.

#### Kriptografi

- [ ] **Sırlar ortam değişkeninden / K8s Secret'tan okunmaz** — _Kaynak:_ CR-35; OP-63. _Durum:_ belirtilmemiş (FROZEN).

#### Veri, depolama ve yüksek erişilebilirlik

- [ ] **CockroachDB/Spanner sınıfı dağıtık SQL ve global tablolar yok** — _Kaynak:_ OP-28; OP-30. _Durum:_ belirtilmemiş.
- [ ] **Gömülü dağıtık cache (Infinispan/Hazelcast) yok** — _Kaynak:_ OP-54. _Durum:_ belirtilmemiş.
- [ ] **Global search index / global registry yok** — _Kaynak:_ T30; T40. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Authority için SQLite yok; HA'da SQLite yok** — _Kaynak:_ OP-48. _Durum:_ belirtilmemiş.
- [ ] **Üretimde down migration yok** — _Kaynak:_ OP-55. _Durum:_ belirtilmemiş.

#### Denetim, saklama ve gözlemlenebilirlik

- [ ] **Identity plane audit log'unda olay başına hash zinciri yok; yönetilen defter (QLDB) yok** — _Kaynak:_ §4.3; OP-5; OP-37. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Denetimde örnekleme yok** — _Kaynak:_ OP-44. _Durum:_ belirtilmemiş.
- [ ] **OCSF kanonik iç şema değildir** — _Kaynak:_ OP-41. _Durum:_ belirtilmemiş.
- [ ] **Authority log header'larına saklama kısaltması uygulanmaz** — _Kaynak:_ INV-30; OP-40. _Durum:_ belirtilmemiş.

#### Güvenlik sertleştirme ve geliştirme süreci

- [ ] **Zarf 200 dönüp içi 429 yok; Idempotency-Key ile sessiz yutma yok** — _Kaynak:_ TN-125; TN-126. _Durum:_ belirtilmemiş.

## Aşama 3 — Authority plane çekirdeği

Anchor, Grant, Mandate, Instance, Acceptance, RestrictionPolicy, requirement ve onay, consumption ve bütçe, karar ve explain, iptal ve kaskad, ADP/AuthZEN karar API'si.

### Spec dışı ön koşullar

- [ ] **AuthZEN PDP uyum test takımı** — ADP'nin AuthZEN uyumunu otomatik doğrulayan koşum aracı.

### K01 Kimlik doğrulama yöntemleri

#### Step-up ve yeniden doğrulama

- [ ] **Stronger authentication requirement** — RequirementTerm biçimi: Claim · authentication · binding = Instance · assurance floor · freshness. _Kaynak:_ §5.9; C24. _Durum:_ belirtilmemiş.

### K02 Kimlik protokolleri ve federasyon

#### İstemci kaydı ve istemci kimliği

- [ ] **"Güven seviyesi" Acceptance parametresi** — Güven seviyesi birinci sınıf bir alandır ve Acceptance'ın parametresidir. _Kaynak:_ §9.13.8 k.5. _Durum:_ belirtilmemiş.

#### Authority federasyonu (domain'ler arası)

- [ ] **Bridging Grant** — `ForeignAuthority(domain, class)` holder'lı rule-shaped Grant'tır; effective = Ceiling ∩ Map(foreign chain) ∩ Mandate. _Kaynak:_ §9.15A.2, §9.15A.4; P31. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Cross-domain delegation** — Yerel holder, `actor-binding` ile tanınan foreign Party'ye yerel extensional Grant verir; vendor erişimi ve ortaklıklar için varsayılan yoldur. _Kaynak:_ §9.15A.3; P31. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Read federation** — Başka domain'in kayıtlarını görmek `access.read` / `access.audit.export` action'ları ile aynı Exercise contract'ından geçer; dış okuyucu yerel/bridging Grant ile yetkilendirilir. _Kaynak:_ §9.15A.5. _Durum:_ belirtilmemiş.

### K03 Oturum ve token yönetimi

#### Epoch'lar ve hızlı iptal

- [ ] **Pending/queued revoke yok; timeout'ta sonuç sabitlenir** — Timeout sonrası sonuç intent validity penceresinin sonunda sabitlenir; kuyruklu/pending revoke olmaz. _Kaynak:_ §13.4 U31; RT23. _Durum:_ belirtilmemiş.

### K04 Hesap yaşam döngüsü ve kurtarma

#### Party Identity Regime etkileri

- [ ] **Yeni PartyID hiçbir authority miras almaz** — `occurredAt` yalnız daraltmayı seçer. _Kaynak:_ §9.13; INV-23. _Durum:_ belirtilmemiş

### K05 Kiracılık, realm ve B2B organizasyonlar

#### Kiracılık eksenleri ve kardinalite

- [ ] **Tenant / Realm / Cell authority girdisi değildir** — `tenant_id`, `realm_id`, ticari paket ve `placement_id` hiçbir authority kararına, Acceptance'a veya ValidityContract'a girmez. _Kaynak:_ §2.2.2 #6; §5.16, §7.1; §16.10 T27; EI-27; INV-37; MD-5. _Durum:_ belirtilmemiş (aday; T27'ye göre FROZEN).
- [ ] **Kararın domain'i imzadan gelir** — Domain, actor'ün AIS'te imzaladığı `domain` alanıdır; token'daki `tenant` iddiası ve `tenant_id` karar girdisi değildir. _Kaynak:_ §9.5.2 k.3; MD-5; P38. _Durum:_ belirtilmemiş (FROZEN, türetilmiş).

#### Fiziksel izolasyon ve tipli kapsam

- [ ] **Domain'ler arası yazma yok / foreign authority** — Foreign authority yalnız `foreign-authority` Acceptance + bridging Grant ceiling ile kullanılır. _Kaynak:_ §13.2; §13.4 G10. _Durum:_ belirtilmemiş.

#### Realm yönetişimi

- [ ] **Varsayılan Acceptance şablonu** — Genesis'te yalnız `actor-binding` içeren varsayılan Acceptance şablonu. _Kaynak:_ §10.1.4 not 3. _Durum:_ belirtilmemiş.

#### Kiracılık kavramlarının UI ve yönetimde görünümü

- [ ] **Platform admin'in kiracı domain'inde authority'si yok** — "Hosted by Suiss Access — the host holds no authority here". _Kaynak:_ §8.17.2.1 notu, §8.17.9.7; INV-29. _Durum:_ belirtilmemiş.

### K06 Giriş deneyimi, UI bileşenleri ve markalama

#### Onay ve consent ekranları

- [ ] **Action Schema render tanımı** — Approval Surface/S1 için insan-okunur etiketler, alan sırası ve yerelleştirmeler; render schema digest'ine dahildir ve authority-opaque'tır. _Kaynak:_ §9.13.3; P23; XI-8. _Durum:_ belirtilmemiş (FROZEN).

### K07 Yetki modeli

#### Temel ilkeler ve primitive'ler

- [ ] **Grant: pozitif yetkinin tek kaynağı** — Pozitif yetki yalnız Grant'tan gelir ve yalnız Anchor lineage'ında meta-Exercise ile doğar. Rol, grup ve token yetki değildir; başka hiçbir sistem (IdP, issuer, provider) authority yaratamaz. _Kaynak:_ §Kısaca ilkeler; §2.2.2 #1; §13.4 G1, G45; MD-4; INV-1, INV-12. _Durum:_ belirtilmemiş
- [ ] **Yedi authority primitive + bir policy construct** — AuthorityDomain, AuthorityAnchor, Grant, Mandate, Instance, Acceptance ve Authority Exercise primitive'dir; RestrictionPolicy policy construct'tır. _Kaynak:_ §5.1; C1. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Authority değişikliği de Exercise'tır** — Authority değişikliği daha sıkı requirement'lı bir Exercise'tır; ayrı bir universe yoktur. _Kaynak:_ L11; INV-2. _Durum:_ belirtilmemiş
- [ ] **Meta-authority asimetrisi** — Genişletme daha sıkı requirement taşıyabilir; gevşetme mevcut (daha sıkı) requirement'ı karşılamayı gerektirir. _Kaynak:_ §5.7; INV-10. _Durum:_ belirtilmemiş
- [ ] **Composition rule: domain predicate'lerinin tüketimi** — Hem domain hem authority içeren kararlarda domain predicate'i hesaplar, Access tüketir ve authority'yi değerlendirir. _Kaynak:_ §2.6 Test C; F6. _Durum:_ belirtilmemiş
- [ ] **Domain predicate'leri** — Schema ve truth domain'indir; Acceptance (genellikle predicate-input) AuthorityDomain'indir. Predicate authority yaratmaz. _Kaynak:_ §7.9.10.5; E15. _Durum:_ belirtilmemiş
- [ ] **Compatible authority provider modeli** — Domain başına tek authoritative kaynak vardır; global tek Suiss provider yoktur. _Kaynak:_ §1.3; F16. _Durum:_ belirtilmemiş
- [ ] **Normatif zaman = domain trusted time; backdate yok** — Authority backdate edilemez; `occurredAt` yalnız daraltmayı seçer. _Kaynak:_ §5.11; §13.4 G22; C33, INV-23. _Durum:_ belirtilmemiş

#### Kayıtlar, corpus ve tek yazma yolu

- [ ] **Tek yazma yolu: meta-Exercise'lar** — Authority state yalnız meta-Exercise'larla değişir: `grant.issue/amend/revoke/renounce`, `mandate.*`, `acceptance.*`, `policy.set`, `anchor.*`, `domain.handover/recover`, `instance.*`, `claim.issue`, `contribute`, `consumption.release`, `projection.issue`. Rol atama, grup, taşıma, scope mapping, protocol mapper ve token exchange dahil bütün authority verme yolları tek merkezi fonksiyondan geçer. _Kaynak:_ §9.7; AP-3, CR-52, INV-2, P11, PI-4. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Core meta-action'lar ve cross-domain class'lar** — `grant.*`, `mandate.*`, `acceptance.*`, `anchor.*`, `instance.*`, `party.register`, `claim.issue`, `contribute`, `consumption.release`, `projection.issue`, `policy.set`; cross-domain class'lar `approve`, `disclose`, `declassify`. _Kaynak:_ §7.9.3.1. _Durum:_ belirtilmemiş

#### AuthorityDomain, Genesis ve Anchor

- [ ] **AuthorityDomain, AuthorityAnchor ve root** — AuthorityDomain yetki kayıtlarının tek doğruluk kaynağıdır; Anchor kaynak üzerindeki yetkinin başlangıç noktası, root asıl sahibidir. Root `Sole(Party)` veya `Joint(Parties, k, independence)` olur; scope'lar ayrık veya iç içedir, kaynak en özel Anchor'a düşer, kapsanmayan kaynakta authority yoktur. _Kaynak:_ §Kısaca; §2.6; §5.1, §5.7; C9. _Durum:_ belirtilmemiş
- [ ] **Anchor create / transfer / retire** — Root transfer, dayanan Grant'ların akıbetini açık disposition ile belirtir; varsayılan yoktur. _Kaynak:_ §5.1, §5.7; C10. _Durum:_ belirtilmemiş
- [ ] **Sahiplik Anchor ile** — Kaynak, sahibinin Anchor'ı altında doğar; sahipsiz Anchor ifade edilemez. Ayrı sahip için ayrı Anchor kurulur. _Kaynak:_ §5.7, §5.17. _Durum:_ belirtilmemiş
- [ ] **Domain admission (`party.register` + self-anchor)** — Self-anchor root'u açıkça yazılır (insan: kendisi; agent: org). Aynı Party'nin farklı domain'lerde farklı root'u olabilir. _Kaynak:_ §7.9.2.3, §7.9.2.5; E6, EI-8. _Durum:_ belirtilmemiş
- [ ] **Domain departure** — Bütün holding kanallarını ve yeniden giriş kapısını varsayılansız kapsayan explicit bir meta-Exercise'tır. _Kaynak:_ §7.9.2.3; E6, EI-8. _Durum:_ belirtilmemiş
- [ ] **Custody ≠ root (operatör authority yaratamaz)** — Operatörün Genesis'te Grant'ı yoktur; tek yazma yolu ve actor attribution iki semantik bariyerdir; ihlal replay ile tespit edilir. _Kaynak:_ §13.2; INV-2, INV-29, PI-7. _Durum:_ belirtilmemiş
- [ ] **First-party ayrıcalığı yok** — First-party, hosting, custody veya operator hiçbir semantik ayrıcalık ya da authority taşımaz; Suiss Identity'nin de ayrıcalığı yoktur. _Kaynak:_ §10.1.4 not 2; §13.4 G24. _Durum:_ belirtilmemiş

#### Party, Instance ve actor modeli

- [ ] **Party / Instance / actor-capable Party üç katmanlı actor modeli** — Authority sahibi Party, doğrulanabilir actor-capable Party ve somut çalışan Instance ayrı katmanlardır; users/clients bunlara eşlenir. _Kaynak:_ F18. _Durum:_ belirtilmemiş
- [ ] **Instance yaşam döngüsü** — Genesis ceremony, rekey (continuity korunur), recover (tek successor) ve terminate geçişleri vardır; UI'da terminate "End this agent's running copies" olarak sunulur. _Kaynak:_ §5.1, §5.6; §8.17.7.1, §8.17.7.5; C8, INV-13. _Durum:_ belirtilmemiş
- [ ] **Askıya alma = Instance terminate veya Grant restriction** — Ayrı bir "suspended" authority durumu yoktur. _Kaynak:_ §11.9.2. _Durum:_ belirtilmemiş
- [ ] **`party.compromise` overlay** — occurredAt'tan (bilinmiyorsa beyandan 72 saat geriye) sonra kurulan Instance'lara uygulanır. _Kaynak:_ §13.7.7; SEC12. _Durum:_ PD

#### Grant ve delegasyon

- [ ] **Grant (extensional) ve delegasyon** — Grant, basis'ten holder'a provenance taşıyan derivation'dır ve delegasyonun tek temsilidir (core primitive; delegator + delegate + scope). Grantor yetkisini kaybetmez. _Kaynak:_ §5.1, §5.7; C11, F13, LFP-1. _Durum:_ belirtilmemiş
- [ ] **Rule-shaped (intensional) Grant** — Kural biçimli subject/resource taşır; issuer ve basis içerir. Selector `Pred(φ)`, `Public` veya `ForeignAuthority` olabilir; Claim değişince aynı Grant farklı bir küme seçer. _Kaynak:_ §5.3, §5.7; C13, L5. _Durum:_ belirtilmemiş
- [ ] **Grant yaşam döngüsü** — issue → (pending) → active ⇄ restricted → amended → revoked / expired / renounced. Renounce yalnız extensional Grant'tadır. _Kaynak:_ §5.1, §5.4; C13. _Durum:_ belirtilmemiş
- [ ] **Grant revizyonları** — Grant aynı kimlikte revizyon tutar. Holder veya basis değişikliği yeni Grant'tır; budget ledger revizyonlar boyunca süreklidir. _Kaynak:_ §5.7; C16. _Durum:_ belirtilmemiş
- [ ] **Holding episode'ları ve HoldingRef** — Affirmative değişiklik episode'u kapatır; staleness kapatmaz (REQUIRE_ACTION döner). Re-qualification (ör. yeniden katılım) yeni episode açar ve eski türevleri canlandırmaz. _Kaynak:_ §5.3, §5.4; §8.17.5.7; INV-31. _Durum:_ belirtilmemiş
- [ ] **Attenuation ve non-amplification** — Devreden sahip olduğundan fazlasını veremez; kapsam, tutar, süre, amaç ve bütçe zincir boyunca yalnız daralır (child ⊆ parent; Exercisable = Holding ∩ Mandate; projection ⊆ source). İki katmanlıdır: issue anında `Child ⊆ Parent` kontrol edilir, evaluation'da lineage boyunca intersection alınır; kullanıcı kendi etkin izninin üstünde izin veremez (INV-10 + Exercise başına tek basis). _Kaynak:_ §1.4 vaat 3; §Kısaca; §5.8; §8.17.5.1, §8.17.5.2; §12.5.1, §12.5.2; §13.4 G2; INV-3, TNI-7. _Durum:_ belirtilmemiş (FROZEN, §12.5)
- [ ] **Delegability (DelegationTerms)** — `delegable`, bounded `depth`, `downstreamHolderClass` ve reserved sınıflar; delegasyon yalnız delegable ve depth > 0 iken mümkündür, wildcard-subject delegation ifade edilemez. UI'da "Can pass on" olarak görünür (varsayılan No; "up to N more steps", "only to: …"). _Kaynak:_ §5.3, §5.8; §8.8, §8.17.5.1; C15, INV-9, L10, LFP-20. _Durum:_ belirtilmemiş; UI varsayılanı PD
- [ ] **Delegasyon derinlik sınırları** — Ajan şablonu depth ≤ 1 (kalan hop); lineage genel tavanı ≤ 16; açık şablonla genişletilebilir. _Kaynak:_ §11.10.4; AG-25. _Durum:_ PD
- [ ] **Kanonik delegasyon zinciri = lineage kaydı; splicing yok** — Zincirin tek kaynağı lineage kaydıdır; iki geçerli token'dan sahte delegasyon zinciri üretilemez. _Kaynak:_ §11.10.4; §13.4 G58; AG-23, AG-24, MD-4. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Altı delegasyon değişmezinin INV eşlemesi** — Daraltma, TTL monotonluğu, derinlik monotonluğu, zincir sürekliliği, kesişim semantiği, sahiplik kanıtı; conformance test listesi. _Kaynak:_ §11.10.4; AG-26. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Plan/step-bound authority (`PlanRef/StepRef/purpose`)** — Plan/adım referansına bağlı yetki; ilerleme state'i Access'te tutulmaz. _Kaynak:_ F10. _Durum:_ belirtilmemiş
- [ ] **Tek kullanımlık davet/niyet token'ları** — Single-use Claim veya one-shot Grant olarak modellenir. _Kaynak:_ §5.8, §6.2. _Durum:_ belirtilmemiş
- [ ] **Doğrudan paylaşım = extensional Grant** — UI'da "Give access" olarak görünür. _Kaynak:_ §5.17. _Durum:_ belirtilmemiş

#### Mandate ve kesişim

- [ ] **Mandate (instance-bounded exercise)** — Sahip olunan yetkinin bir Instance'ta kullanılabilir alt kümesi; Instance'a bağlı sabit exercisability zarfıdır: bind, rebind (genişletme), narrow, revoke. Delege edilemez; rebind ile genişletmeyi yalnız Instance'ın Party'si kendi Instance'ından fresh ceremony ile yapabilir, operatör yapamaz (UI: "Instance limits"). _Kaynak:_ §5.1, §5.7; §8.6, §8.8, §8.17.5.2; C14, F14, L15. _Durum:_ belirtilmemiş
- [ ] **Mandate HoldingRef pin'i** — Reserved sınıflar pin ister. CT2 ve üstü action sınıflarında Mandate varsayılan olarak pin ister. _Kaynak:_ §5.7; C14. _Durum:_ PD
- [ ] **Kesişim semantiği (Effective = AuthoritySet ∩ Mandate ∩ lineage budget)** — Ele geçirilmiş ajanın etkisi Grant ∩ Mandate ∩ budget ile sınırlanır. _Kaynak:_ §11.0 #8, §11.10.4 #5, §11.20. _Durum:_ belirtilmemiş

#### Capacity ve agency

- [ ] **AgencyTerms ve ExerciseCapacity (OWN / FOR)** — On-behalf-of yalnız basis Grant'ın beyan edilmiş agency'sinden türer; bir Grant yalnız OWN ve issuing principal için FOR verebilir. FOR(P) Grant'ı olmadan FOR(P) eylemi `capacity-mismatch` ile DENY olur; Anonymous hiçbir şey yapamaz. _Kaynak:_ §5.3, §5.7; §11.9.1; §13.4 G15; C12, INV-4. _Durum:_ belirtilmemiş (FROZEN, §11.9.1)

#### Roller, gruplar ve rule-shaped seçim

- [ ] **Named AuthoritySet (rol/şablon), sürümlü ve pin'li** — Sürümüyle pin'lenir; canlı dolaylılık yoktur. Yeni sürüm mevcut delegasyonları değiştirmez ("Template v3 available — 4 delegations still on v2"); geçiş Grant başına diff'li explicit `grant.amend`'dir. _Kaynak:_ §5.3, §5.8; §8.17.5.1; §12.3.8, §12.5.2; C28, TN-114. _Durum:_ belirtilmemiş (FROZEN, §12)
- [ ] **Rol ataması = Grant; rol claim'i onun projection'ı** — Rol ataması bir named AuthoritySet sürümünü pin'leyen Grant'tır; token'daki rol claim'i bu Grant'ın projection'ıdır (⊆ AuthoritySet ∩ Mandate). Grup üyeliği ise yalnız identity Claim'idir. _Kaynak:_ §2.2.2 #1; §5.3, §5.17. _Durum:_ belirtilmemiş
- [ ] **Grup → izin = rule-shaped Grant** — Holder `Pred(membership(g))`, basis ilgili Anchor root'udur. İç içe gruplar conjunction ile veya issuer'ın düzleştirdiği Claim ile ifade edilir. _Kaynak:_ §5.17. _Durum:_ belirtilmemiş
- [ ] **Authority-selecting claim class: seçim için `subject-selection` Acceptance** — Grup/rol Claim'i (upstream dahil) holder seçimine yalnız `subject-selection` Acceptance ile girer (Authority Selector Authority). _Kaynak:_ §10.1.4 not 1; INV-16, L6. _Durum:_ belirtilmemiş
- [ ] **Bir grup = bir üyelik issuer'ı** — Her grup tam bir üyelik issuer'ı beyan eder; domain-local ve upstream grup ayrımı vardır, selector issuer'ı adlandırır, aynı grup için ikinci yazma yolu reddedilir. _Kaynak:_ §5.17; §10.1.4 not 1; INV-33, L6 (i). _Durum:_ belirtilmemiş
- [ ] **Domain-local üyelik (`claim.issue`)** — Yerel davet veya üyelik bir `claim.issue` Exercise'ıdır. _Kaynak:_ §5.2, §5.17. _Durum:_ belirtilmemiş
- [ ] **Koşullu tuple / ABAC koşulu** — Pozitif koşul parametre sınırına veya while-condition'a çevrilir; daraltıcı koşul RestrictionPolicy'ye gider. _Kaynak:_ §5.8, §5.17. _Durum:_ belirtilmemiş

#### AuthoritySet, kısıt cebiri ve tip sistemi

- [ ] **Parametre sınıflandırması** — Authority-relevant parametreler Grant ile sınırlanabilir; authority-opaque parametreler yalnız digest'e girer. Eşlenemeyen relevant parametre schema kabulünde reddedilir. _Kaynak:_ §7.9.3.4; E12. _Durum:_ belirtilmemiş
- [ ] **Reserved action'lar** — Wildcard veya prefix ile hiçbir katalogda kapsanmaz, Mandate'e yalnız pin ile girer. Domain ek action'ları yerel olarak reserved işaretleyebilir (yalnız daha sıkı); UI: "Only delegations that name this action explicitly can include it." _Kaynak:_ §5.7, §7.9.3.3; §8.8, §8.17.9.4; §9.13, §9.13.3; E11, INV-9. _Durum:_ belirtilmemiş

#### Budget ve consumption

- [ ] **Authority budget (BudgetTerm) ve lineage draw** — Bir yetkinin ne kadar kullanılabileceğini count veya amount+unit ve pencereyle sınırlar (ör. 500 TRY/gün); finansal limit ve hold'dan ayrıdır. Her exercise lineage'daki tüm budget'lardan ve Mandate'ten draw eder ("this counts against *your* limit too"; uzman görünümde halka halka). _Kaynak:_ §2.6; §5.3, §5.8; §8.17.5.1, §8.17.5.6; C27, F9, INV-3. _Durum:_ belirtilmemiş
- [ ] **Consumption-bearing state'in at-most-once commit'i** — Consumption birimleri: intent nonce, single-use Claim, single-use contribution, BudgetTerm, one-shot Grant (count=1), step-bound allowance, recovery slot. ALLOW + consumption tek transaction'da commit edilir ve concurrency, retry, failover altında at-most-once korunur; eşzamanlı ikinci draw `budget-exhausted` DENY alır. _Kaynak:_ §2.6; §5.8; §13.4 G3; §16.1 A1; §17.1.1; F7, F10, INV-21, OP-S1, TI-2, TI-7, TI-8, TI-RT8. _Durum:_ belirtilmemiş (FROZEN, §16–17)
- [ ] **Grounded budget release (Σrelease ≤ draw)** — `consumption.release` yalnız orijinal exerciser veya lineage holder tarafından, grounded non-execution ya da daha düşük gerçek miktar Claim'iyle yapılır; sonucu bilinmeyen draw "counted" kalır. Grounding dedup uygulanır; aşım `budget-exhausted/release-exceeds-draw` verir; kullanılmayan offline slice da bu yolla iade edilir. _Kaynak:_ §5.2, §5.8; §8.13, §8.17.5.6; §9.12.2; §16.5; INV-21, P27, RT17, RT18, TI-RT8. _Durum:_ belirtilmemiş (FROZEN, §9.12.2/§16.5)
- [ ] **Budget tükenmesi onayla aşılamaz** — _Kaynak:_ §8.17.5.2; X15. _Durum:_ belirtilmemiş
- [ ] **Contract dışı kullanımın derived state olması** — Yaptırım yetkili Party'nin explicit Exercise'ıdır; otomatik authority değişikliği yoktur. _Kaynak:_ §9.12.2; E5, P27. _Durum:_ belirtilmemiş (FROZEN)

#### Restriction ve politika dili

- [ ] **Restriction overlay (suspend, containment) yalnız daraltır** — Suspend, containment ve RestrictionPolicy yalnız DENY/REQUIRE üretir ve lineage'ı kırmaz. Kaldırılmaları genişletmedir ve mevcut requirement'ı karşılamayı ister; UI'da "Suspend" yalnız restriction koyma yetkisi olana sunulur. _Kaynak:_ §5.11; §8.17.7.5; §13.4 G6; C17, INV-6, X13. _Durum:_ belirtilmemiş
- [ ] **Deny-overrides karar birleştirme** — Kapsayan basis yoksa DENY; aksi hâlde requirement'lar ve politika çıktıları birleştirilir. _Kaynak:_ §5.8. _Durum:_ belirtilmemiş
- [ ] **`policy.set` sınıflandırması ve polarite analizi** — Yapısal, muhafazakâr ve mekanik sınıflandırma; narrowing olduğu kanıtlanamayan değişiklik genişletme sayılır. _Kaynak:_ §5.8; §16.5; INV-36, T13, TI-14. _Durum:_ belirtilmemiş (FROZEN, §16.5)
- [ ] **Kapalı `derived.*` whitelist'i (11 fonksiyon)** — Restriction'ların okuyabileceği on bir deterministik türetilmiş fonksiyon (Party toplam tüketim, açık REQUIRE_ACTION sayısı, selector holder geçiş sayısı, cited contribution Instance durumu, mapping pin yaşı, Claim yaşı, raporlanmamış contract'lar, rollback guard girdisi, `projection.issue` sayısı, açık offline PAP sayısı, eşik-bitişik tekrar); dışı DENY. _Kaynak:_ §16.5; RT26, SI-8. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Policy default sıkılaştırma/gevşetme kuralı** — Policy default'lar Genesis/template içeriğidir; sıkılaştırma narrowing, gevşetme genişletme sınıfı meta-Exercise'tır. _Kaynak:_ §13.7; SEC8, SI-18. _Durum:_ PD

#### Requirement'lar, onay ve quorum

- [ ] **Requirement'lar ve RequirementTerm** — Karar için gereken kanıt, onay ve quorum koşulları; eksikse REQUIRE_ACTION döner. RequirementTerm alanları: proofKind (Claim / Contribution), class, source, count, binding, freshness, independence, consumption. _Kaynak:_ §4.4 katman tablosu; §5.9; C24. _Durum:_ belirtilmemiş
- [ ] **Fresh claim requirement'ı** — Claim · class · freshness biçimindedir. _Kaynak:_ §5.9. _Durum:_ belirtilmemiş
- [ ] **Device posture requirement'ı** — `posture.device` Claim'i Instance'a bağlıdır. _Kaynak:_ §5.9, §7.9.12.2. _Durum:_ belirtilmemiş
- [ ] **Foreign authority acceptance requirement'ı** — Foreign-authority proof holder'a bağlıdır. _Kaynak:_ §5.9. _Durum:_ belirtilmemiş
- [ ] **Korunan eylemler = RequirementTerm; reserved ilanları** — Kalıcı silme ve realm imza anahtarı rotasyonu (politika/acil) reserved → CT3. _Kaynak:_ §12.5.2; TN-118. _Durum:_ PD (reserved ilanı)
- [ ] **Exact-intent approval (intent digest'ine bağlı contribution)** — Onay, onaylanan exact intent digest'ine bağlı, single-use bir contribution Exercise'ıdır; onaylanan digest = intent digest ve yüzeyden bağımsızdır. Intent değişirse onay geçersizdir ("The request changed after you approved…"); onay DENY, budget veya ceiling'i aşamaz. _Kaynak:_ §8.3, §8.17.6.2; §13.4 G12, G13; INV-20, L14, LFP-12. _Durum:_ belirtilmemiş
- [ ] **Doğrulanabilir quorum / co-authority** — Quorum katkıları aynı intent digest'ine bağlı, bağımsız doğrulanabilir ve bağımsızlık sınıfı taşır; kripto threshold otomatik quorum sayılmaz. Başkasının meta-action'ını onaylamak (ikinci admin onayı) bir contribution Exercise'ıdır ve "ödeme için kullanıcı onayı" ile aynı protocol nesnesidir. _Kaynak:_ §2.6 Test B; §9.14, §9.14.3; L13, LFP-13. _Durum:_ belirtilmemiş
- [ ] **Contribution sınıfları** — Core sınıflar: `approve`, `co-sign`, `witness`, `disclose`, `declassify` (UI'da Co-sign / Consent); publisher namespaced `contribute:<ns>/<name>` ekleyebilir. _Kaynak:_ §8.8; §9.14, §9.17.1. _Durum:_ belirtilmemiş
- [ ] **Terminate edilmiş actor'ün contribution'ı** — Hedef Exercise commit edilmeden önce actor Instance'ı terminate edilmiş contribution'ı cite eden değerlendirme REQUIRE_ACTION döner. _Kaynak:_ SEC11. _Durum:_ belirtilmemiş (FROZEN)

#### Consequence Tier ve güvence eşikleri

- [ ] **Consequence Tier (CT0–CT3) sınıflandırması** — İşlemin risk sınıfı (okuma CT0 … geri alınamaz/kritik CT3), schema alanlarından ve meta-action sınıfından türetilir; gereken güvence buna göre artar. CT1 eşiği 1,000 EUR, CT3 eşiği 100,000 EUR; yeni alıcı CT2; reserved/genişletme meta-action'ları, kalıcı silme, realm imza anahtarı rotasyonu, yönetici göç dışa aktarımı CT3. _Kaynak:_ §Kısaca; §13.7.1; SEC7, TN-86, TN-118. _Durum:_ PD
- [ ] **Narrowing meta-action'ları CT1 assurance ile** — Revoke, restriction ekleme, Acceptance daraltma ve `instance.terminate` tier'dan bağımsız CT1'dir. _Kaynak:_ §13.7.1; SI-4, X11. _Durum:_ PD
- [ ] **Karşılanabilirlik kuralı** — Requirement şablonu domain'in principal yapısında karşılanabilir olmalı; kendi self-restriction'ını kaldırma quorum'suz kendi Exercise'ı; kullanıcının kendi `grant.issue`'su ve ödemesi CT2; CT3 quorum'u yalnız ≥ 2 eligible principal scope'ta. _Kaynak:_ §13.7.1; SEC10, X8, X13. _Durum:_ PD
- [ ] **CT3 quorum ve time-lock** — ≥ 2 eligible principal scope'ta ≥ 2 contribution (distinct Party/controller/surface path, ≠ actor principal); Sole scope'ta donanım-bağlı non-custodial UV assertion + time-lock; genişletmelerde ≥ 24 saat yürürlük gecikmesi (break-glass hariç). _Kaynak:_ §13.7.3; SEC26. _Durum:_ PD
- [ ] **AAS `expires_at` ve intent validity tavanları** — AAS CT1 ≤ 15 dk, CT2/CT3 ≤ 5 dk; REQUIRE_ACTION nonce validity CT1/CT2 ≤ 24 saat, CT3 ≤ 72 saat. _Kaynak:_ §13.7.3. _Durum:_ PD

#### İptal, kaskad ve geçerlilik

- [ ] **Terminal invalidity ve cascade revocation** — Revoke, expire, renounce, lapse ve termination terminaldir; bir lineage'ın geçersizliği türetilen tüm grant, mandate ve projection'ları ileriye dönük geçersiz kılar ve hiçbir şey canlanmaz (re-qualification yeni episode'dur). UI'da Revoke (`grant.revoke`) terminaldir; yeniden yetki yeni delegasyondur. _Kaynak:_ §5.11; §8.17.7.5; §13.4 G5; C17, INV-5, INV-23, L12. _Durum:_ belirtilmemiş
- [ ] **Prospektif revocation (commit anından itibaren)** — Revocation bir meta-Exercise'tır; commit anından itibaren devam eden kullanım dahil sonraki her online commit/continue/`projection.issue` için DENY üretir. Tamamlanmış Exercise'lar tarih olarak kalır. _Kaynak:_ §1.4 vaat 5; §5.2, §5.11; §13.4 G4; F12, INV-23. _Durum:_ belirtilmemiş
- [ ] **Revocation ≠ stop; continuation DENY** — Access stop iddia etmez; continuation DENY'ı semantiktir. _Kaynak:_ §13.4 G31. _Durum:_ belirtilmemiş
- [ ] **ValidityContract ve continuation** — Ayrı "lease" nesnesi yoktur; geçerlilik ValidityContract ve continuation DecisionRecord ile taşınır. `mode=continue` aynı Instance'ın AIS'i ile mevcut Exercise üzerinde yeni karardır; DENY Exercise'ı ileriye dönük kapatır, envelope değişirse yeni commit gerekir. _Kaynak:_ §9.7; AP-4, F12, L19, MD-7, P7. _Durum:_ belirtilmemiş (FROZEN, §9.7)
- [ ] **AuthorityStateBasis** — Her reusable/auditable karar değerlendirildiği state basis'i tanımlar. _Kaynak:_ F12, L17. _Durum:_ belirtilmemiş
- [ ] **Ingest-time cutoff** — Acceptance'a cutoff koymak narrowing'dir ve dayanan episode'ları terminal kapatır; subject-selection/foreign-authority'de affirmative disqualify uygulanır. Cutoff'u geri almak genişletmedir ve kapanan episode'ları canlandırmaz; issuer compromise prosedürü cutoff → quarantine → closure → reconcile. _Kaynak:_ §6.6; §13.4 G9; SEC9, SI-10. _Durum:_ belirtilmemiş
- [ ] **Issuer cutoff marjı** — t_c − 24 saat; t_c bilinmiyorsa t_d − 7 gün. _Kaynak:_ §13.7.7. _Durum:_ PD
- [ ] **Semantik timer yok** — Zaman-bağlı davranış zamanlayıcıyla değil değerlendirmeyle uygulanır. _Kaynak:_ T15; TI-10. _Durum:_ belirtilmemiş (FROZEN)

#### Claim, Acceptance ve ingest

- [ ] **Claim ve Acceptance (trust'ın tek anlamı)** — Acceptance bir trust nesnesidir: issuer × claim class × subject class × domain × assurance floor × validity × use. `acceptance.establish/amend/revoke` meta-Exercise'ları ile kurulur, daraltılır, genişletilir veya iptal edilir. _Kaynak:_ §2.3; §5.1; §9.13; C18, F4, INV-15, must-never #9. _Durum:_ belirtilmemiş
- [ ] **Beş Acceptance use'u** — actor-binding, predicate-input, subject-selection, foreign-authority, schema-definition; son üçü reserved'dır. _Kaynak:_ §5.15; §10.1.4; C18. _Durum:_ belirtilmemiş
- [ ] **Claim modeli** — Claim issuer, subject, class, değer veya digest, validity, attribution ve supersedes alanlarını taşır. İmza zorunlu değildir; issuer attribution zorunludur. _Kaynak:_ §5.2; C19, INV-14. _Durum:_ belirtilmemiş
- [ ] **Ingest ≠ Acceptance (use-scoped Claim kabulü)** — Bir Claim karara yalnız aktif bir Acceptance'ın kendi use'u için girer. _Kaynak:_ §9.13 k.1; §13.4 G7; INV-2, INV-15. _Durum:_ belirtilmemiş
- [ ] **Claim ingest kanalı (taşıyıcı-bağımsız)** — Ingest alanları: claim identity, issuer, subject, class, value|digest, issuedAt, validity, attribution evidence, ingest time, supersedes. OIDC, SET, VC, SCIM, SVID/WIT ve domain-signed Claim için tanımlıdır. _Kaynak:_ §9.13; AP-7, P19. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Claim Ingest Pipeline** — Carrier adapter'ları, issuer auth, normalize, minimize, dedup, kota, sequencer append; ingest disposition canonical header'dadır. _Kaynak:_ CMP-8; T23. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Claim ingest disposition'ları (admit / quarantine / reasoned reject)** — Kapsam dışı Claim sessizce düşürülmez: ya quarantine'de (`quarantine:<reason>`) kaydedilir ya gerekçeli reddedilir. _Kaynak:_ §7.2; §9.4 H, §9.13 k.3; P19. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Claim güncelliği issuer sırasıyla** — Sıra varış zamanına göre değil issuer sırasına göre belirlenir (açık `supersedes`, key-event pozisyonu, monoton alan); belirsizlikte disqualifying kazanır. _Kaynak:_ §5.5; §9.13 k.6; §16.5; G36, RT15, RT16, TI-RT7. _Durum:_ belirtilmemiş (FROZEN, §16.5)
- [ ] **Assurance floor** — Acceptance'ın assurance floor'u imza istiyorsa, imzasız ama authenticated Claim o use için kullanılmaz. _Kaynak:_ §9.13 k.2; C19. _Durum:_ belirtilmemiş
- [ ] **Gelecekten gelen Claim kullanılamaz** — `issuedAt` > trusted time (skew dışında) olan Claim kullanılamaz. _Kaynak:_ §9.13 k.4; C33, P19. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Ingest kotası ve narrowing önceliği** — Kota aşımında quarantine yalnız genişletici Claim'lere uygulanır; narrowing Claim'ler kota dışı, öncelikli ve ayrı izlenir; `quarantine:quota` yalnız qualifying etkiyi düşürür. _Kaynak:_ §9.13 k.7; §17.6.1, §17.8.2; G44, SI-20, T23. _Durum:_ belirtilmemiş
- [ ] **Issuer tanımlama yöntemleri** — PartyRef (varsayılan), OIDF entity identifier + chain kısıtı, SPIFFE trust domain + bundle ve pinned key set desteklenir. _Kaynak:_ §9.13; P22. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Issuer compromise blast radius sınırı** — Issuer compromise yalnız use'unun beyan edilmiş etkisini üretir; Grant/Acceptance/reserved/meta yetkisi üretmez. _Kaynak:_ §13.4 G8. _Durum:_ belirtilmemiş
- [ ] **Contextual tuple yok; PEP olgusu yalnız predicate-input** — PEP'in sunduğu olgu yalnız Acceptance'lı `predicate-input` Claim'idir; holder seçimine giremez. _Kaynak:_ §9.5.2 k.2; P37. _Durum:_ belirtilmemiş (FROZEN, türetilmiş)

#### Kaynak modeli ve yaşam döngüsü

- [ ] **Kaynak parametresi gün-1'den zorunlu** — Intent her zaman ActionRef + ResourceRef taşır; kaynaksız "rol kontrolü" ifade edilemez. _Kaynak:_ §9.5.2 k.4. _Durum:_ gün-1
- [ ] **Kaynak hiyerarşisi ve miras** — Hiyerarşi domain'in Claim'i veya ResourceRef selector'ıdır. Miras Anchor iç içeliği veya resource selector'lu Grant ile kurulur. _Kaynak:_ §5.5, §5.17. _Durum:_ belirtilmemiş
- [ ] **İki uçlu taşıma / yeni incarnation** — Taşıma, kaynak ve hedefi birlikte adlandıran tek bir Exercise ile veya yeni incarnation ile yapılır ve change-impact önizlemesinde gösterilir. Taşıma etkin izni artıramaz; hedef holder kazancı hedef uç onayına bağlıdır. _Kaynak:_ §6.9; §12.5.2; INV-35, TN-115. _Durum:_ belirtilmemiş (aday, §6.9); FROZEN (§12.5.2)
- [ ] **ResourceRef incarnation** — Yeniden yaratılan kaynak eski authority'yi miras almaz. _Kaynak:_ §5.3, §7.9.10.4; E14. _Durum:_ belirtilmemiş
- [ ] **Kaynak yaşam döngüsü seam'i** — Create işleminde otomatik en özel Anchor kullanılır. Delete, move, split/merge ve root transfer kuralları tanımlıdır. _Kaynak:_ §7.9.10.4; E14. _Durum:_ belirtilmemiş

#### Schema ve katalog yönetimi

- [ ] **Schema governance** — Core meta-action namespace'i Access protocol'ünündür. Domain ve third-party namespace'leri yalnız `schema-definition` Acceptance'ıyla anlam kazanır; global registry gerekmez. _Kaynak:_ §7.9.3.1–2; E10. _Durum:_ belirtilmemiş
- [ ] **Schema Publication Package (SPP)** — Publisher'ın imzalı yayınıdır; alanlar: publisher, namespace, catalog_version, catalog_digest, actions, compatibility, retirements, core_spec_min. Kullanım `schema-definition` Acceptance pin'iyle olur. _Kaynak:_ §9.13; AP-9, P23. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Action Schema** — Alanlar: name/version/digest, reserved, consumption_bearing, typed parametreler (authority-relevant closed type / authority-opaque body digest rule), resource_types, purpose_vocabulary, render, effect_class. _Kaynak:_ §9.13.3; P23. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Immutable schema sürümleri ve exact digest pin'i** — Yeni sürüm veya mapping reserved `acceptance.amend` ister. _Kaynak:_ §7.9.3.2; E10, EI-16, PI-19. _Durum:_ belirtilmemiş
- [ ] **Compatibility declaration ve mapping sınıfları** — representation-equivalent, narrowing, broadening, incompatible. Mapping closed algebra ile ifade edilir, digest ile pin'lenir ve yalnız non-broadening yönde otomatik uygulanır. _Kaynak:_ §7.9.3.2, §7.9.3.5; §9.13.4; E10, P24. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Mapping probation** — Compatibility mapping pin'inden sonra 14 gün mapping üzerinden CT2+ → REQUIRE_ACTION. _Kaynak:_ §13.7.6; SEC16. _Durum:_ PD
- [ ] **Katalog sürümü ve prefix pin'i; gelecekteki action'lar dahil değil** — Prefix'li Grant `(namespace, catalog_version, catalog_digest)` pin'ler; sonradan eklenen action'lar `grant.amend` olmadan kapsanmaz. UI "Full access" yerine "All non-protected actions in *X* as of catalog vN" ve "Future actions not included" der. _Kaynak:_ §7.9.3.3; §8.10, §8.17.9.2, §8.17.10.2; §9.13; E11. _Durum:_ belirtilmemiş
- [ ] **Schema sürüm/mapping kontrolü** — Kabul edilmemiş schema sürümü/mapping hiçbir Grant kapsamını değiştiremez; prefix pin'li, reserved express-only; `schema-definition` revoke → `schema-not-accepted`. _Kaynak:_ §13.2; §13.4 G11. _Durum:_ belirtilmemiş
- [ ] **Action retirement** — Publisher Claim'idir; retired sürüme gelen intent restriction ile DENY edilebilir. _Kaynak:_ §7.9.3.5. _Durum:_ belirtilmemiş
- [ ] **Core namespace meta-schema'ları** — Core meta-action'lar Access Core Semantic Spec'in SPP'sidir; domain yeni sürümü `anchor.amend(rootTerms)` ile benimser. _Kaynak:_ §9.13.7. _Durum:_ belirtilmemiş
- [ ] **Okuma action'ları `access.read` / `access.audit.export`** — Authority state değiştirmeyen Access-internal okuma action'larıdır. _Kaynak:_ §9.13.7. _Durum:_ belirtilmemiş
- [ ] **Domain sürüm ve downgrade kontrolü** — Domain minimum core spec/profile sürümü (benimsemeden 90 gün sonra minimum = en son); minimum düşürme/zayıf algoritma ekleme CT3; yükseltme narrowing (CT1); bilinmeyen sürümlü artefakt red + telemetri sayacı. _Kaynak:_ §13.7.8. _Durum:_ PD
- [ ] **Downgrade saldırı modeli savunmaları** — Zorunlu alan çıkarma, eski sürüm, PEP profil pazarlığı, assurance downgrade ve algoritma downgrade'e karşı must-understand, minimum sürüm, RequirementTerm floor'u ve imzalı algoritma kimliği. _Kaynak:_ §13.7.8. _Durum:_ PD
- [ ] **Semantik sürüm aktivasyonu (activation record)** — Yeni core spec/meta-schema/profile ancak domain log'una activation record yazıldıktan sonra kullanılır; kayıtta `versions` görünür. _Kaynak:_ §17.10.2; OP-56, PI-21. _Durum:_ belirtilmemiş (FROZEN TECHNICAL)

#### Cross-domain ve federasyon

- [ ] **Cross-domain / federated authority acceptance** — Yabancı organizasyonun authority artefaktları açık Acceptance ile kabul edilir; organizasyon sınırını aşan provenance. _Kaynak:_ §2.4; F16. _Durum:_ belirtilmemiş
- [ ] **Foreign authority evidence** — Foreign chain digest + issuer Claim'i olarak girer. _Kaynak:_ §7.9.11.3; E19. _Durum:_ belirtilmemiş
- [ ] **Local bridging Grant (partner authority)** — Yerel root'tan, `ForeignAuthority` selector'ı ve foreign-authority Acceptance'ıyla kurulur; ceiling içinde etkilidir. UI'da "Partner authority (up to …)" olarak görünür ve yerel bridge revoke edilebilir. _Kaynak:_ §5.13, §7.9.11.3; §8.8, §8.13; C21, INV-17. _Durum:_ belirtilmemiş
- [ ] **Cross-domain delegation** — Foreign Party'ye yerel extensional Grant verilir; budget home domain'den draw edilir. _Kaynak:_ §5.13, §7.9.11.3; PI-24. _Durum:_ belirtilmemiş
- [ ] **Anchor domain'ler arası taşınmaz** — Yeni domain'de yeni Anchor kurulur, eskisi retire edilir; gerekirse bridging Grant kullanılır. _Kaynak:_ §7.9.11.2. _Durum:_ belirtilmemiş

#### Özel yetki alanları

- [ ] **Disclosure / declassification authority (IFC Option B)** — Bilgi açıklama ve declassification yetkisi Access'tedir; sınıflandırma (label) data owner'ın Claim'idir. Yeni alıcıya ilk disclose CT2, declassify CT3; identity plane kişisel verisi `disclose` sınıfındadır. _Kaynak:_ §2.4; §14.2; F11, SEC30. _Durum:_ belirtilmemiş (FROZEN, SEC30)
- [ ] **Hukuki gerçeklik modelleme** — Vekâletname → `FOR(Alice)` Grant'ı; mahkeme kararı → reserved legal-process Grant'ı. _Kaynak:_ §7.9.12.7; CI-13. _Durum:_ belirtilmemiş
- [ ] **Hukuki sahiplik değişiminde koşullu reserved Grant** — `anchor.transfer`'ı yapan önceden tanımlı reserved Grant'tır (ör. `ownership.changed` Claim'i şartıyla). _Kaynak:_ §7.9.9.2. _Durum:_ belirtilmemiş

#### Exercise protokolü

- [ ] **IntentEnvelope** — Yapılmak istenen işin tam tanımı (ne, hangi kaynakta, hangi parametrelerle, hangi amaçla); kararın bağlandığı birim. _Kaynak:_ §Kısaca; §1.5. _Durum:_ belirtilmemiş
- [ ] **Authority Exercise ve yaşam döngüsü** — Exercise nonce'a bağlıdır ve ilk committed ALLOW ile doğar; consumption atomik commit edilir. Akış commit → REQUIRE_ACTION/DENY/ALLOW, ardından continue, outcome attestation ve `consumption.release`. _Kaynak:_ §5.1, §5.10; §9.7; C30. _Durum:_ belirtilmemiş
- [ ] **Tek Exercise girişi** — Domain action'ları ve meta-action'lar aynı Exercise Request / Decision sözleşmesinden geçer. _Kaynak:_ §9.1 R1, §9.7; P11, PI-4. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Dört mesaj türü** — Her mesaj bir Exercise talebi, projection, Claim veya derived bildirimdir; ayrı bir "komut" türü yoktur. _Kaynak:_ §9.3 k.2. _Durum:_ belirtilmemiş
- [ ] **Exercise Request alanları** — domain, mode (commit/continue/check), nonce, actor proof (AIS), basis, capacity, intent (IntentEnvelope), proofs, pep, reuse. _Kaynak:_ §9.5; AP-1, P7. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Actor Intent Statement (AIS) ile actor attribution** — Actor Instance'ın KeyBinding'iyle domain, nonce, intent digest, PEP audience, mode, capacity, basis ref ve zaman üzerine imzalanan message-level statement'tır. Actor attribution yalnız AIS ile olur; PEP iletir ama üretemez, PEP/transport kimliği actor değildir. _Kaynak:_ §9.3A, §9.5, §9.17 #6; §13.4 G14; P9, PI-7. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Statement'sız istek = Anonymous** — Statement yoksa ActorContext `Anonymous(context)` olur ve yalnız Public Grant'lar değerlendirilir; düz AuthZEN PEP bu sayede bağlanabilir ama yalnız Public authority'den yararlanır. _Kaynak:_ §9.5 k.2; INV-11, P9. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **PEP ≠ actor** — PEP kendi kimliğiyle actor yerine istek kuramaz; statement alanları eşleşmezse protocol hatası olur. _Kaynak:_ §9.5 k.3; E17, P9. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Açık basis ve capacity beyanı** — `commit` modunda basis/capacity eksikse protocol hatası olur; `check` modunda aday basis'ler advisory olarak döndürülebilir. _Kaynak:_ §9.5 k.4; INV-4, P8. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Protocol hatası semantiği** — Protocol hatasında değerlendirme, kayıt, nonce tüketimi ve Exercise yoktur; dördüncü bir outcome değildir ve effect üretmez. _Kaynak:_ §9.5 k.4; P8. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Üç outcome; UNKNOWN yok** — Outcome'lar ALLOW, DENY ve REQUIRE_ACTION'dır; kararlar hiçbir zaman UNKNOWN değildir. _Kaynak:_ §9.5; §13.4 G16; EI-21, INV-26, P10. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **DENY nonce'unun terminal olması** — DENY verilmiş nonce terminaldir; yeni deneme yeni nonce ister. _Kaynak:_ §9.5 k.5, §9.7; C30. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **REQUIRE_ACTION ile aynı nonce'la yeniden değerlendirme** — Nonce intent validity'sine kadar açık kalır; eksik proof eklenince aynı nonce ile yeniden commit edilir. _Kaynak:_ §9.5 k.5, §9.7; P7. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Decision Response alanları** — decision, outcome, advisory, exercise, validity, receipt, blockers (tümü), unmet, remediation, evaluation_record, basis_ref, causal_binding, witnessed_through, versions. _Kaynak:_ §9.5; P10. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Kaydedilen DENY/REQUIRE_ACTION evaluation kaydı** — Nonce'a bağlı bir evaluation DecisionRecord ref'i döner; bu bir Exercise değildir. _Kaynak:_ §9.5. _Durum:_ belirtilmemiş
- [ ] **Effect yalnız Claim olarak** — Access'e effect hakkında yalnız Claim (effect.attestation / effect.non-execution) gelir. _Kaynak:_ §9.3A, §9.7; INV-18. _Durum:_ belirtilmemiş
- [ ] **Batch atomik değil** — Her öğe kendi Exercise'ıdır. _Kaynak:_ §13.4 G26. _Durum:_ belirtilmemiş
- [ ] **Event'ler authority genişletmez** — Hiçbir event, event kaybı veya sıra farkı authority genişletmez. _Kaynak:_ §13.4 G19. _Durum:_ belirtilmemiş

#### Blocker ve remediation

- [ ] **Blocker yapısı** — 10 kapalı class, namespaced subcode, position, resolver class, 6 remediation kodu ve wait_until. _Kaynak:_ §9.6; P14, X19. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **10 blocker class'ı** — `no-covering-authority`, `outside-instance-limits`, `restricted`, `budget-exhausted`, `ended`, `capacity-mismatch`, `source-not-accepted`, `schema-not-accepted`, `nonce-closed`, `foreign-status-unavailable`. _Kaynak:_ §9.6; P14. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Bilinmeyen subcode → üst class** — Bilinmeyen subcode üst class olarak yorumlanır; bilinmeyen class yoktur. _Kaynak:_ §9.6; P15. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Yeni blocker sınıfı yok; recovery ve budget subcode'ları** — `nonce-closed/pre-recovery` ve `budget-exhausted/release-exceeds-draw` tanımlıdır; yeni üst-düzey sınıf eklenmez. _Kaynak:_ §9.6; P14, RT25, TI-RT8. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Blocker position** — `instance`, `hop(k)`, `anchor`, `domain-policy`, `foreign`, `actor-side`; halka kimliği görme yetkisi kadar açılır. _Kaynak:_ §9.6; E26. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Resolver sınıfı ("Who can")** — Engeli kimin kaldırabileceği sınıf olarak verilir (grantor-of-hop(k), root, restriction-owner, issuer, domain-admin, actor, actor-party, time); kişi listesi viewer-scoped explain'dedir. _Kaynak:_ §9.6; X8. _Durum:_ belirtilmemiş
- [ ] **Altı remediation kodu** — `route-to-coordinator`, `refresh-claim`, `self-authenticate`, `wait-until(T)`, `not-satisfiable-by-actor`, `new-request-required`; planlama verisidir, talimat değildir. _Kaynak:_ §9.6; A-7, P14. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Unmet RequirementTerm projeksiyonu** — proofKind, class, count, binding, freshness, independence, consumption, source, position, satisfiable_by_actor. _Kaynak:_ §9.6; P10. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Rule-shaped seçimin iki parçalı nedeni** — Authority yolu + seçim beyanı. _Kaynak:_ §8.17.5.7; E-5, INV-16. _Durum:_ belirtilmemiş

#### Approval Act Statement ve contribution akışı

- [ ] **Approval Act Statement (AAS)** — Tek kullanıcı fiili tek AAS ve tek assertion üretir; iki act türü vardır: `contribution` ve `authority-act`. AAS her zaman proof'tur, IntentEnvelope değildir. _Kaynak:_ §9.14; AP-6, P29, R5. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **AAS alanları** — act, approver, capacity, contribution_class, target, exercise_ref (DomainID, nonce), work_gate, surface, render_digest, material_fields, issued_at, expires_at. _Kaynak:_ §9.14. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Contribution akışı (act = contribution)** — Requester REQUIRE_ACTION alır, approver contribute Exercise'ını commit eder, requester aynı nonce ile yeniden commit eder. Access önce commit eder, Work sonra doğrular. _Kaynak:_ §9.14.1 A; P29. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Kullanıcının kendi authority act'i (act = authority-act)** — Kullanıcının kendi `grant.issue/amend/revoke`'u; actor kullanıcının Instance'ıdır ve contribution yoktur. _Kaynak:_ §9.14.1 B, §9.14.3; INV-16, P29. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Opaque body doğrulaması** — Opaque parametreler body digest rule ile intent'e bağlanır; surface digest eşleşmezse onay toplanmaz, PEP eşleşmezse effect üretmez (`intent-mismatch`). _Kaynak:_ §9.14.2; P30. _Durum:_ belirtilmemiş (FROZEN)

#### Tenant, göç ve devredilmiş yönetim

- [ ] **Tenant asla authority girdisi değil** — Ticari durum yalnız protocol rejection/identity plane kısıtı üretir; org adı, e-posta ve alan adı da ADP girdisi değildir. _Kaynak:_ §12.1.1; TN-1, TNI-1. _Durum:_ belirtilmemiş (FROZEN)

#### Çalışma zamanı, log ve atomiklik

- [ ] **`instance.create` + `mandate.bind`** — Mandate'siz Instance hiçbir şey exercise edemez (fail-closed ara durum). _Kaynak:_ §17.1.1; INV-11. _Durum:_ belirtilmemiş
- [ ] **`instance.recover` atomikliği** — Eski terminal + successor + recovery slot tek DecisionRecord'dur. _Kaynak:_ §17.1.1; INV-13. _Durum:_ belirtilmemiş
- [ ] **`anchor.transfer` + disposition** — Tek DecisionRecord'dur. _Kaynak:_ §17.1.1; E14. _Durum:_ belirtilmemiş
- [ ] **Holder değişikliği (issue + revoke)** — _Kaynak:_ §17.1.1; INV-4. _Durum:_ belirtilmemiş
- [ ] **Quorum contribution tüketimi** — Hedef ALLOW ile contribution single-use bayrakları aynı transaction'dadır. _Kaynak:_ §17.1.1; INV-20. _Durum:_ belirtilmemiş
- [ ] **Inline Claim proof** — Claim record'ları kararın önünde aynı batch'tedir. _Kaynak:_ §17.1.1 adım 7. _Durum:_ belirtilmemiş

#### Ekosistem sınırından gelen kurallar

- [ ] **Sessiz genişleme yok** — Hiçbir sistem başka bir sistemin authority'sini sessizce (veya kendi yetkisi dışında açıkça) genişletemez; positive authority yalnız AuthorityDomain'in yerel Anchor lineage'ında meta-Exercise ile doğar. _Kaynak:_ §7.4; E1. _Durum:_ belirtilmemiş (FROZEN).

### K08 Karar, uygulama ve doğrulama

#### Karar sonuçları ve semantiği

- [ ] **Üç karar sonucu: ALLOW / DENY / REQUIRE_ACTION** — Her intent için üç sonuçlu karar verilir; UNKNOWN yoktur ve belirsizlik DENY veya REQUIRE_ACTION olarak sonuçlanır, Access'in kendi kararı hiçbir zaman "unknown" değildir. `allowed: bool` yüzeyinde REQUIRE_ACTION asla `true` olmaz. _Kaynak:_ §1.4 vaat 4; §2.4; §5.10; §8.13; PI-5. _Durum:_ belirtilmemiş.
- [ ] **Fail-closed boolean eşlemesi** — `decision=true` ⇔ ALLOW'dur. REQUIRE_ACTION'ı anlamayan PEP onu DENY gibi uygular; ters yön yasaktır. _Kaynak:_ §9.5; R2. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Karar cevabı içeriği** — Outcome (ALLOW/DENY/REQUIRE_ACTION), ExerciseID, ValidityContract (horizon, next re-check). _Kaynak:_ §8.18.1; EI-21. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Decision Response `basis_ref`** — Karar yanıtı (D, q−1, version vector digest) taşır. _Kaynak:_ §17.1.1 adım 15. _Durum:_ belirtilmemiş.
- [ ] **DENY reason class kümesi (on sınıf, tümü döner)** — `no-covering-authority`, `outside-instance-limits`, `restricted`, `budget-exhausted`, `ended`, `capacity-mismatch`, `source-not-accepted`, `schema-not-accepted`, `nonce-closed`, `foreign-status-unavailable`. _Kaynak:_ §8.18.1; X19. _Durum:_ belirtilmemiş.
- [ ] **REQUIRE_ACTION yapılandırılmış eksikler** — Karşılanmamış her RequirementTerm için tür, sınıf, count, binding, freshness, independence ve eligible contributor kümesi döner; aynı nonce'la yeniden değerlendirilir. _Kaynak:_ §1.4 vaat 4; §5.9; §8.18.1. _Durum:_ belirtilmemiş.
- [ ] **Typed remediation kodları** — `route-to-coordinator`, `refresh-claim`, `self-authenticate`, `wait-until(T)`, `not-satisfiable-by-actor`, `new-request-required`; serbest metin yok. _Kaynak:_ §8.18.1. _Durum:_ belirtilmemiş.
- [ ] **AuthZEN Access Request & Approval profili** — REQUIRE_ACTION için taşıyıcı adayıdır; profilin onay statüsü doğrulanmadı. _Kaynak:_ §5.10; FDT-5. _Durum:_ belirtilmemiş.
- [ ] **Protocol rejection ≠ outcome** — Limit aşımı, bozuk istek, retry: kayıt yok, nonce tüketilmez. _Kaynak:_ §17.7.1; P8; SI-20. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Commit'siz ALLOW yok** — Hot domain/key'de retry veya rejection. _Kaynak:_ §13.4 G41; TI-9. _Durum:_ belirtilmemiş.
- [ ] **`authz_epoch` advisory; karar girdisi AuthorityStateBasis / `applied_pos`** — Epoch artışı genişletme kaynağı değil; `applied_pos` yetersizse canonical'a sor veya REQUIRE/DENY. _Kaynak:_ §13.4 G51; EP-9. _Durum:_ belirtilmemiş.
- [ ] **Risk ADP'de Claim olarak, yalnız daraltır** — _Kaynak:_ §12.2.4; TN-46. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **İzleme modu authority yolunda yok** — _Kaynak:_ §12.4.3; TN-108. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Senkron / asenkron sınıflandırma** — Consequential effect öncesi karar senkrondur; yayılma, rapor ve bildirim asenkrondur. _Kaynak:_ §7.9.13.1; E28. _Durum:_ belirtilmemiş.

#### Envelope bağı ve intent

- [ ] **ALLOW envelope-bound** — Bir ALLOW bağlandığı intent envelope'u dışında tekrar kullanılamaz; zarf dışı her effect unauthorized'dır ve Exercise kaydına karşı tespit edilebilir. _Kaynak:_ §6.2; INV-19; must-never #12. _Durum:_ belirtilmemiş.
- [ ] **Her consequential effect kendi ALLOW'u (Txn-Token tek başına ALLOW değil)** — _Kaynak:_ §11.12.3, §11.18 #5. _Durum:_ belirtilmemiş.
- [ ] **Proof binding** — Her proof (domain, nonce/ExerciseID, digest, audience) dörtlüsüne bağlıdır. _Kaynak:_ §6.6; SI-17. _Durum:_ belirtilmemiş.

#### Actor kimliği ve istek doğrulama

- [ ] **Actor Intent Statement (AIS)** — Actor Instance KeyBinding'iyle imzalanır; domain, nonce, digest ve audience'a bağlıdır. Statement'sız istek Anonymous sayılır. _Kaynak:_ §6.5, §6.6; PI-7, SI-1. _Durum:_ belirtilmemiş.
- [ ] **Request Verifier / AIS doğrulaması** — Boyut/derinlik limitleri, AIS imzası exact bayt üzerinde, domain/nonce/intent digest/PEP audience/mode eşleşmesi, kanonik CBOR; caller digest'ine güvenmez. _Kaynak:_ §17.1.1 adım 3; §17.6.1 kural 3; CMP-2; TI-11. _Durum:_ belirtilmemiş.
- [ ] **Anonymous actor** — Yalnız Public Grant kullanır; tutamaz, veremez, quorum'a sayılmaz. _Kaynak:_ §5.6; INV-11. _Durum:_ belirtilmemiş.
- [ ] **AuthZEN `subject` türetilir** — `subject` AIS'ten türetilir; PEP'in yazdığı `properties` authority girdisi değildir. _Kaynak:_ §9.5 k.1; L23, R2. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Transport PoP ≠ actor** — PEP→ADP DPoP/mTLS yalnız PEP'i kanıtlar; actor AIS'ten. _Kaynak:_ §12.2.1; PI-7. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **PEP kimlik doğrulaması (transport kimliği)** — PEP mTLS / OAuth client auth / DPoP / WIMSE WPT ile doğrulanır ve PEP audience'a bağlanır. API anahtarı yalnız Public-only PEP'lerde kabul edilir. _Kaynak:_ §9.5, §9.5.1 #10; §17.1.1 adım 1. _Durum:_ belirtilmemiş.
- [ ] **Çok kiracılıkta karar domain'i AIS'ten** — Domain kapsamı AIS'ten, realm Host'tan gelir ve token eşleşmesi denetlenir (`TenantMismatch`); token'daki `tenant` karar girdisi değildir. _Kaynak:_ §11.4.5 #36, §11.9.2, §11.21.4; §12.1.3; P38; TN-22. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **PEP contextual claim'leri** — PEP yalnız Acceptance'lı issuer olarak, predicate-input use'unda Claim sunabilir. _Kaynak:_ §5.10. _Durum:_ belirtilmemiş.

#### Karar protokolü (Access Decision Profile)

- [ ] **Access Decision Profile (ADP) — AuthZEN Authorization API 1.0 PEP yüzeyi** — Karar protocol'ü AuthZEN 1.0 üzerinde PROFILE + EXTEND'dir, yeni transport yoktur; Protocol Gateway tarafından sunulur. Doğrulanmış credential'dan subject/actor, require-action eşlemesi, authority context ve imzalı decision receipt sağlar; SARC, `x-authzen-mapping` ve CEL kullanır. _Kaynak:_ §4.3; §9.5; §11.21.1 #25; AP-1; CMP-1; L23; OP-6; OP-65; P6. _Durum:_ Faz 1 (§4.3); FROZEN (§9.5).
- [ ] **ADP commit / continue / projection.issue modları** — Commit-mode kararlar yalnız domain leader'ında canonical + SYNC-DERIVED state'e karşı verilir. _Kaynak:_ §5.10; TI-5. _Durum:_ belirtilmemiş.
- [ ] **Normatif 15 adımlı commit yolu** — TLS 1.3, limitler, AIS ön-doğrulama, intent digest, placement, nonce, değerlendirme, serial validation, batch tx, imza, witness, Decision Response. _Kaynak:_ §17.1.1. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Continuation DecisionRecord** — Uzun süren kullanımda aynı Exercise üzerinde yeni karar alınır; continuation DENY Exercise'ı kapatır. _Kaynak:_ §5.10; C30, C31. _Durum:_ belirtilmemiş.
- [ ] **AuthZEN 1.0 PDP uyum kontrol listesi (13 madde)** — ADP 13 maddeyi taşıyıcı yükümlülüğü olarak uygular. _Kaynak:_ §9.5.1; P35. _Durum:_ belirtilmemiş (FROZEN; taşıyıcı ayrıntısı PD).
- [ ] **`POST /access/v1/evaluation`** — commit/continue/check modlarının tek-öğe taşıyıcısıdır. _Kaynak:_ §9.5.1 #1. _Durum:_ belirtilmemiş.
- [ ] **`POST /access/v1/evaluations` (batch)** — Üç `evaluations_semantic` değeri desteklenir. _Kaynak:_ §9.5.1 #2. _Durum:_ belirtilmemiş.
- [ ] **`POST /access/v1/search/resource`** — "What can X reach?" sorusunu yanıtlar. _Kaynak:_ §9.5.1 #3. _Durum:_ belirtilmemiş.
- [ ] **`POST /access/v1/search/subject`** — "Who can do Y?" ve eligible set sorgularını yanıtlar; erişim incelemesi için gereklidir. _Kaynak:_ §9.5.1 #4. _Durum:_ belirtilmemiş.
- [ ] **`POST /access/v1/search/action`** — Viewer-scoped action listesi döndürür. _Kaynak:_ §9.5.1 #5. _Durum:_ belirtilmemiş.
- [ ] **`GET /.well-known/authzen-configuration`** — Domain Metadata'dan türetilir. `capabilities` ADP, explain ve consistency_token'ı ilan eder; `signed_metadata` sağlanır. _Kaynak:_ §9.5.1 #6, §9.15.1. _Durum:_ belirtilmemiş.
- [ ] **HTTP durum semantiği** — Ret = 200 + `decision=false`, protocol hatası = 400. 401/403 PEP erişim sorunudur, karar değildir. _Kaynak:_ §9.5.1 #7; P35. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **`X-Request-ID` yankısı** — İz korelasyonu için DecisionRecord context'ine yazılır. _Kaynak:_ §9.5.1 #8. _Durum:_ belirtilmemiş.
- [ ] **AuthZEN bilinmeyen alan kuralının sınırı** — "Bilinmeyen alanları yok say" kuralı yalnız taşıyıcı alanlarına uygulanır. Anlaşılmayan must-understand üye DENY'dır. _Kaynak:_ §9.5.1 #9; P35. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **HTTPS + JSON bağlaması, `v1` uç noktaları** — HTTPS + JSON normatiftir. gRPC/CoAP bağlamaları profilde tanımlanabilir. ADP CBOR biçimi vardır. _Kaynak:_ §9.5.1. _Durum:_ belirtilmemiş.
- [ ] **Tutarlılık belirteci `context.consistency_token`** — `at_least`/`as_of` için opak taşıyıcıdır ve yalnız check/search/explain'de anlamlıdır. _Kaynak:_ §9.5.2 k.1; P36. _Durum:_ PD (alan adı); FROZEN (kural).

#### Batch

- [ ] **Batch semantiği** — Öğeler bağımsızdır, atomicity yoktur; her öğe ayrı Exercise'tır. Commit'te yalnız `execute_all`; `deny_on_first_deny`/`permit_on_first_permit` kısa devresi yalnız check modunda kullanılabilir. _Kaynak:_ §5.10; §9.7, §9.7.1; P12, P42; PI-23. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Batch = tekil değişmezi** — Batch öğesinin sonucu tek başına `evaluation` çağrısının sonucuyla aynıdır; kısa devre yalnız `check`'te. _Kaynak:_ §9.7.1; CR-49 madde 3. _Durum:_ belirtilmemiş (FROZEN).

#### Advisory check ve önbellek

- [ ] **Advisory check (`mode=check`)** — "Would this be allowed now?" sorusunu replica/derived'dan, `as_of`/`at_least` ile yanıtlar; kaydedilmez, söz değildir, `advisory=true` döner. Cevap credential değildir, cache'lenemez ve effect yetkilendirmez; p99 ≤ 10 ms hedeflenir. _Kaynak:_ §5.4, §5.10; §8.8, §8.17.10.4; §9.7; §17.4.6, §17.5.1; A-10; AP-2; E-2; OP-27, OP-32. _Durum:_ belirtilmemiş; EA (p99 hedefi).
- [ ] **Advisory karar önbelleği** — Commit yolunda önbellek yoktur. Anahtar uzunluk önekli blake3 + `applied_pos`'tur; geçersizleştirme pozisyon, izleme akışı ve TTL ile yapılır; önbellek/türetilmiş indeks cevabı ALLOW üretmez. _Kaynak:_ §9.7A.4; §13.4 U61; EP-10; P45. _Durum:_ PD (anahtar); EA (TTL).
- [ ] **Olumsuz önbellek TTL ≤ 1 s, olumlu 10 s** — Yetki veren Exercise olumsuz girdileri senkron düşürür. _Kaynak:_ §9.7A.4; P45. _Durum:_ EA.
- [ ] **"Hiç görülmedi" fail-closed** — Bayat önbellek ile hiç görülmemiş durum ayrı ele alınır; hiç görülmemişe zaman penceresi uygulanmaz. _Kaynak:_ §9.7A.4, §9.11.1; MD-7. _Durum:_ belirtilmemiş (FROZEN).

#### Türetilmiş indeks, arama ve okuma tutarlılığı

- [ ] **Türetilmiş ReBAC graf indeksi (CMP-9) ve sorgu motoru (CMP-11)** — Zanzibar-benzeri; grup üyeliği, rule-shaped Grant, named AuthoritySet ve extensional Grant'tan türetilir. Yalnız check/search/explain/eligible set servis eder; commit-mode ALLOW üretmez. _Kaynak:_ §9.7A.1; CMP-9, CMP-11; L8; MD-4; P43; T13; TI-5. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Query Service: search ve explain** — `check`, `search_resources`, `search_subjects`, explain ve eligible set derived index + Query Service ile viewer-scoped okuma olarak sunulur; advisory cevap credential değildir. _Kaynak:_ §5.4, §5.17; CMP-9, CMP-11. _Durum:_ belirtilmemiş.
- [ ] **"Who can Y / what can X reach / why" sorguları** — Graf sorgusu + proof inşası (lineage path, cited Claim'ler, Acceptance'lar, politikalar). _Kaynak:_ §5.4. _Durum:_ belirtilmemiş.
- [ ] **Eligible approver / contributor kümesi** — Bir onay için yetkili onaylayıcı/katkıcı kümesinin hesaplanması (alıcıyı Work/Relay seçer). _Kaynak:_ §2.7 Relay; §16.5.1; L8. _Durum:_ belirtilmemiş.
- [ ] **Revocation impact ve staleness exposure önizlemesi** — _Kaynak:_ §16.5.1; CMP-9. _Durum:_ belirtilmemiş.
- [ ] **Search sınırları** — Search 1 s sert son tarih, ≤ 1000 sonuç/sayfa ve zorunlu sayfalama ile çalışır. Son tarih aşılırsa kısmi değil hata döner. _Kaynak:_ §9.7.1; P42. _Durum:_ EA.
- [ ] **Derived cevapların uyumu (Check/List tutarlılığı)** — check, search, önbellekli/önbelleksiz check ve batch aynı pozisyonda / aynı token altında aynı sonucu verir (UDC). _Kaynak:_ §6.9; §9.7.1; INV-34; P42. _Durum:_ belirtilmemiş (aday).
- [ ] **Okuma tutarlılık sınıfları** — `head`/strong (commit/continue/projection.issue için tek sınıf), `at_least(position)`, `as_of(position)` ve `minimize_latency` (yalnız advisory); ConsistencyToken, watch ve `witnessed_through` ile; derived cevaplar advisory'dir. _Kaynak:_ §5.4, §5.17; §9.7A.2; §16.5; CMP-11; P43; T11; TI-5. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Varsayılan bayat değil** — Check'te belirteç verilmezse `at_least(son görülen)` veya `head` kullanılır. _Kaynak:_ §9.7A.2 k.2; P43. _Durum:_ PD.
- [ ] **Snapshot süresi dolumu** — Eski `as_of` belirteci "anlık görüntü süresi doldu" hatası verir ve istemci `head`'e düşer. Önerilen pencere 24 saattir. _Kaynak:_ §9.7A.2 k.3. _Durum:_ EA.

#### Açıklama ve ifşa

- [ ] **Explain / "why can X do Y" (viewer-scoped)** — Bir actor'ün bir şeyi neden yapabildiğini/yapamadığını açıklar; geçmiş için DecisionRecord'dan, varsayımsal için advisory'den, etiketli olarak üretilir. _Kaynak:_ §2.2.2 #3; §2.4; §9.7, §9.7.1; AP-2. _Durum:_ belirtilmemiş.
- [ ] **Explain (geçmiş karar, q−1 rekonstrüksiyonu)** — State q−1'de kurulur, Kernel explain modunda aynı normatif değerlendirme + disclosure filtresiyle yeniden değerlendirir; eşleşmezse açıklama verilmez. _Kaynak:_ §17.6.13; T34; X25. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Explain (varsayımsal)** — `check` yolu, `advisory` etiketli. _Kaynak:_ §17.6.13. _Durum:_ belirtilmemiş.
- [ ] **Explanation derinliği = requester'ın authority'si kadar** — Requester: class + position + resolver class + remediation; viewer: kendi lineage'ı için expert derinlik, alt ağaç derinlik ≥ 2 kimlikleri pseudonymous; `undisclosed` varsayılanı fraud/velocity/risk restriction'ları. _Kaynak:_ §8.18.1; §13.7.5; E26; SEC24, SEC29. _Durum:_ PD.
- [ ] **Explain / advisory check / search sınırları** — Viewer authority'sini aşmaz; `undisclosed` restriction requester'a yalnız sınıf olarak görünür; audit scope içeriği görür; canonical kayıt değil, telemetri sayılabilir. _Kaynak:_ §13.4 G27, G28; SEC24, SEC31. _Durum:_ belirtilmemiş.
- [ ] **Disclosure filtresi** — Her okuma yolunun son aşaması. _Kaynak:_ §17.6.13; TI-20. _Durum:_ belirtilmemiş.
- [ ] **Yetkisiz ≡ var olmayan (görülemeyen kaynakta DENY = yokluk)** — DENY "kaynak yok" cevabından ayırt edilemez; disclosure scope dışı basis yanıtı var olmayanınkiyle aynı outcome, yapı ve uzunluk sınıfındadır. PEP SDK varsayılanı 403/404 ayrımını gizlemektir. _Kaynak:_ §9.5.2 k.7; CR-40; E26; P41; SAI-43. _Durum:_ belirtilmemiş (FROZEN).

#### Fail-closed ve kesinti davranışı

- [ ] **Fail-closed karar yolu** — Doğrulanamayan her durumda sonuç ALLOW değildir. Rate limiter, risk motoru, cache, introspection backend, policy motoru veya parser hatası hiçbir zaman ALLOW / `active=true` / yeni token üretmez; DENY, `active=false`, 503 veya protocol rejection döner. Tazeliği kanıtlanamayan token introspection'da `active=false`'tur. _Kaynak:_ §12.0.4; §13.4 G48; INV-26; MD-8; must-never #11; SAI-3. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Domain predicate uydurulmaz** — Domain ulaşılamazsa REQUIRE_ACTION ("Commerce couldn't confirm…"). _Kaynak:_ §8.13. _Durum:_ belirtilmemiş.
- [ ] **Future-dated statement reddi** — "A statement from *X* is dated in the future and can't be used." _Kaynak:_ §8.13; C33. _Durum:_ belirtilmemiş.
- [ ] **Clock skew toleransı** — Claim için CT0/CT1 2 dk, CT2/CT3 1 dk. _Kaynak:_ §13.7.2; C33. _Durum:_ PD.

#### Projection'lar ve yetki artefaktları

- [ ] **ValidityContract** — Alanlar: issuing_exercise, basis_ref, holder, audience, bounds, profile, horizon, max_staleness (Δ), freshness_sources, revalidation, offline_slice, local_requirements, verifier_profile_ref, clock, must_understand. _Kaynak:_ §9.12; P26. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Reusable Decision ve continuation** — Açık ValidityContract horizon'una kadar envelope içi kullanım beyan edilmiş staleness penceresidir; continuation DENY'da yeni effect yok. _Kaynak:_ §8.17.5.5; A-8; X17. _Durum:_ belirtilmemiş.

#### İptal, tazelik ve status

- [ ] **Revocation guarantee sınıfları** — Commit anında BS etkili; pencere içi kullanım BS (sınıflandırma) ve kapanma UDC; SSF teslimi NG; çalışan executor'ı durdurma NG. _Kaynak:_ §9.11; INV-23. _Durum:_ belirtilmemiş.

### K09 Ajanlar ve MCP

#### Ajan yetki sınırları ve delegasyon

- [ ] **Kendi exercise'ını onaylama engeli** — `independence` term'i (contributor ≠ actor principal, human presence) self-approval'ı engeller; yüksek sonuçlu sınıflarda domain varsayılanıdır. _Kaynak:_ §7.9.6.3. _Durum:_ belirtilmemiş

#### Ajan yaşam döngüsü, sorumluluk ve iptal

- [ ] **Toplu/kitlesel iptal (Party compromise, Acceptance revoke)** — _Kaynak:_ §11.20. _Durum:_ belirtilmemiş

### K10 Yönetişim

#### Onay, quorum ve görevler ayrılığı

- [ ] **Approval authority (kim onaylayabilir, proof geçerli mi)** — Kimin onaylayabileceği ve onay kanıtının geçerliliği Access'te; onay ihtiyacı Work/domain'de. _Kaynak:_ F8; §2.7 Work. _Durum:_ belirtilmemiş
- [ ] **Approval = contribution Exercise** — `approve:<class>` ordinary bir Grant'tır; approve ≠ execute. _Kaynak:_ §5.9; C25, INV-20. _Durum:_ belirtilmemiş
- [ ] **Co-authority** — Contribution · co-authorize, intent digest'e bağlı. _Kaynak:_ §5.9. _Durum:_ belirtilmemiş
- [ ] **Quorum** — `Joint(k)` veya count=k; threshold imza tek contribution sayılır; Public selector kaynak olamaz. Yönetişim akışlarının (ör. ikinci admin onayı) protocol nesnesidir (bkz. K07). _Kaynak:_ §5.9, §9.14.3; C26, INV-20. _Durum:_ belirtilmemiş
- [ ] **CT3 quorum ve bağımsız render yolu** — CT3 quorum ≥ 2 eligible principal; CT3 bağımsız render yolu baseline. _Kaynak:_ §18.5, §18.6; SEC10, SEC26. _Durum:_ belirtilmemiş
- [ ] **Okta çift onayı ve AWS çok kişili onay eşlemesi** — Her ikisi de RequirementTerm örneğine iner. _Kaynak:_ §5.9. _Durum:_ belirtilmemiş
- [ ] **Approver bağımsızlığı (independence kontrolü)** — Distinct Party, controller, surface veya assurance path üzerinden cited proof ile kontrol edilir (UDC); "farklı kişi / farklı cihaz / farklı surface" policy ile. _Kaynak:_ §6.6, §13.4 U17; SI-19. _Durum:_ belirtilmemiş
- [ ] **Approve hiçbir şeyi ezmez** — "Approve anyway / override" yoktur. _Kaynak:_ §6.4; XI-6. _Durum:_ belirtilmemiş
- [ ] **Eligible approver kümesi** — Approver'lar derived olarak hesaplanır ve Work Gate'e verilir. _Kaynak:_ §5.4, §7.9.5.3; E7. _Durum:_ belirtilmemiş

#### Kötüye kullanım korumaları

- [ ] **Structuring / abuse guard'ları** — Party-düzeyi toplam (actor-side RestrictionPolicy); eşik-bitişik tekrar (24 saatte ≥ 3 exercise, her biri eşiğin ≥ %80'i → REQUIRE_ACTION); mass-selection guard (24 saatte > %10 veya > 5 yeni Party → CT2+ REQUIRE_ACTION). _Kaynak:_ §13.7.6; AB-1…AB-10. _Durum:_ PD
- [ ] **Requester throttling** — İnsan contribution'ı gerektiren açık REQUIRE_ACTION per requester ≤ 20/saat, ≤ 100/gün → RestrictionPolicy DENY `restricted/policy:request-rate` + security event. _Kaynak:_ §13.7.4; SEC28. _Durum:_ PD

#### Erişim gözden geçirme ve IGA

- [ ] **Erişim incelemesi için subject search** — `search/subject` erişim incelemesi için gereklidir. _Kaynak:_ §9.5.1 #4. _Durum:_ belirtilmemiş

#### Ayrıcalıklı erişim ve süreli yetki

- [ ] **Time-bound delegation** — Süre sınırlı yetki devri. _Kaynak:_ §2.4. _Durum:_ belirtilmemiş
- [ ] **Org delegasyon kısıtı: "Members can delegate to apps in this list only"** — RestrictionPolicy / downstreamHolderClass ile (GitHub uyarlaması). _Kaynak:_ §8.17.12. _Durum:_ belirtilmemiş

#### Değişiklik etkisi ve yönetim yüzeyi

- [ ] **Change-impact / revocation impact önizlemesi (ücretsiz)** — "G'yi iptal etmek neyi etkiler?" sorusu cevaplanır; yetim (orphan) satırları önizlemededir: çözülmeyen kapsam, holder seçmeyen rule-shaped Grant, sahipsiz identity plane nesnesi. Hiçbir pakette kapatılamaz; "Full access" yasağı. _Kaynak:_ §5.4, §5.8, §12.5.2, §18.3, §18.6; B3, B4, TN-121, X20. _Durum:_ PD (§12.5.2)
- [ ] **Revoke / narrow / suspend, impact preview ve aftermath (ücretsiz)** — _Kaynak:_ §18.6, §18.7; B3, X11, X12. _Durum:_ belirtilmemiş

#### Olay müdahalesi ve containment

- [ ] **"Force-now" yönetici iptali** — _Kaynak:_ §12.2.4. _Durum:_ belirtilmemiş
- [ ] **Compromise impact sorgusu** — Bir Instance/issuer/key için pencere içindeki Exercise, Grant, contribution, projection listesi (derived sorgu). _Kaynak:_ RR-13, SEC15. _Durum:_ belirtilmemiş (FROZEN)

#### Anahtar custody ve kriptografik yönetişim

- [ ] **Meta-anchor root yapısı** — Organizasyon `Joint(k ≥ 2)` (distinct Party + controller); kişisel domain `Sole`. _Kaynak:_ §13.7.7. _Durum:_ PD

### K11 Yönetim API'si, konsol, SDK'lar ve geliştirici araçları

#### Yönetim yazma yolu ve yetki modeli

- [ ] **Yönetim API'si = ADP meta-Exercise (tek yazma yolu)** — REST/gRPC yönetim uç noktaları sunulabilir, ama Grant, Acceptance, policy, `claim.issue` değiştiren her çağrı, hangi yüzeyden gelirse gelsin ADP meta-Exercise'ına (AIS + ADP `commit`) derlenir; actor proof'suz çağrı state değiştiremez. Her realm config yazması `idp.*` domain action Exercise'ıdır; REST yanıtı `exercise_id`/`position` döner. _Kaynak:_ §2.2.2 #3; §7.6; §9.7; §12.5, §12.5.1; §13.2; §13.7.9; CMP-15.5; L11; MD-14; OP-6; OP-65; P11; PI-4; TN-110. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Tek merkezi yetki fonksiyonu** — Rol atama, grup→izin kuralı, hiyerarşi taşıma, scope mapping, token exchange politikası, admin API ve deklaratif yapılandırma uzlaştırıcısı aynı meta-Exercise yolundan geçer. _Kaynak:_ §6.2; INV-2, PI-4. _Durum:_ belirtilmemiş.

#### Hız ve yapı limitleri

- [ ] **ADP/API rate limit'leri** — `commit` 20/s, burst 100; `check` 60/dk, 2,000/gün; explain 30/dk, 500/gün; search 10/dk, sayfa ≤ 100; aşım protocol rejection'dır (kayıt yok, nonce tüketilmez). _Kaynak:_ §13.7.4; SEC28; SI-20. _Durum:_ PD.
- [ ] **İstek yapısal limitleri** — Lineage derinliği ≤ 16; proof ≤ 64; selector ≤ 32 conjunct; istek ≤ 256 KB. _Kaynak:_ §13.7.4; §14.6. _Durum:_ PD.

### K12 Entegrasyonlar ve yardımcı servisler

#### Ajan ve yürütücü entegrasyonları

- [ ] **AuthZEN AARP eşlemesi** — `access_request` = `exercise_ref`; onaydan sonra aynı nonce ile yeniden commit yapılır. _Kaynak:_ §9.4 B; §9.9.5. _Durum:_ WATCH (talep üzerine) + eşleme hazır.

### K13 Denetim, kayıt, şeffaflık ve dışa aktarım

#### Exercise ve karar kayıtları

- [ ] **Decision proof: lineage ve fact dependency ayrımı** — Karar kanıtı authority lineage'ını ve dış fact bağımlılığını ayrı gösterir. _Kaynak:_ L6. _Durum:_ belirtilmemiş.
- [ ] **Provenance sorgusu ("why can X do Y", "ne kullanıldı")** — Provenance ve exercise record sistemi olarak sorgulanabilir. _Kaynak:_ §2.4. _Durum:_ belirtilmemiş.

#### Atıf ve inkâr edilemezlik

- [ ] **Actor attribution** — Her commit/continue kaydı AIS taşır; provider/PEP actor adına istek üretemez (BS). _Kaynak:_ §9.16, §9.16.3. _Durum:_ belirtilmemiş.
- [ ] **Attribution kanıtı (accountability ayrı)** — Access kimin yaptığını kanıtlar; accountability Work regime'inin konusudur. _Kaynak:_ §7.9.5.6; E9; EI-24. _Durum:_ belirtilmemiş.

#### Denetime erişim ve disclosure

- [ ] **Audit scope (ayrı Grant)** — `access.audit.export` / audit-read Grant'ı; tam Claim değerleri reserved (≥ 2 contribution veya Sole root'ta donanım-bağlı UV). _Kaynak:_ §13.7.5; SEC29. _Durum:_ PD.
- [ ] **Audit disclosure scope (`reason_admin`)** — Audit kapsamı StateBasis ref'i, cited Claim/Acceptance/policy sürümleri ve consumption'ı gösterir. _Kaynak:_ §9.6, §9.6.1. _Durum:_ PD (eşleme).
- [ ] **Kapsamlı açıklama ve disclosure** — Explain, search ve event'ler viewer authority'sinden fazlasını açmaz; undisclosed restriction yalnız sınıf olarak görünür. _Kaynak:_ §6.5, §6.6, §6.7; PI-16; SI-14; TI-20. _Durum:_ belirtilmemiş.
- [ ] **Opaque `basis_ref` ve HMAC event id (örtük bilgi sızıntısı yok)** — Audit kapsamı altındaki viewer'a pozisyon taşıyan tanımlayıcılar opak token'dır; anahtar domain dışına çıkmaz. _Kaynak:_ §6.8; §7.1; §13.4 G37; CR-32; RT21; T11; TI-RT10. _Durum:_ belirtilmemiş (FROZEN).

### K14 Sinyaller, gözlemlenebilirlik ve analitik

#### Revocation ve sonuç görünürlüğü

- [ ] **UNKNOWN raporlama** — Tüketici başkasının fact'i hakkında UNKNOWN gösterir; Access kendi kararında UNKNOWN demez. _Kaynak:_ §7.9.14; E25; EI-21. _Durum:_ belirtilmemiş.

#### Açıklama ("Why?")

- [ ] **Explanation ilkeleri E-1…E-7** — Derived; advisory söz değil; her hayırın owner'ı; viewer authority'si kadar; iki parçalı neden; eksik olan yapılandırılmış; agent'a açıklama veri. _Kaynak:_ §8.17.8.1; X18. _Durum:_ belirtilmemiş.
- [ ] **Açıklama kategorileri** — Kapsayan authority yok, instance sınırı, restriction, approval/step-up/claim eksik, beyan bayat, budget, ended, source/schema not accepted, foreign unknown, capacity uyuşmazlığı. _Kaynak:_ §8.17.8.2. _Durum:_ belirtilmemiş.
- [ ] **Ne açıklanmaz** — Başkalarının graph'ı, yetkisiz policy eşikleri, Claim gövdeleri, One memory/Work içeriği. _Kaynak:_ §8.17.8.5. _Durum:_ belirtilmemiş.

#### Dikkat, bildirim ve onay yükü

- [ ] **Requester aciliyet beyan edemez; sessizlik onay değildir** — _Kaynak:_ §8.17.11.1; X23. _Durum:_ belirtilmemiş.

### K15 Güvenlik ve kriptografi

#### Transport ve servis kimliği

- [ ] **Hibrit PQ anahtar değişimi (X25519MLKEM768) ve forward secrecy** — "Bugün açılır"; ADP, ingest ve export kanallarında forward secrecy; istemci SDK ve iç kanallarda iyimser gönderim, güvenli yaklaşıma düşüş politikası. _Kaynak:_ §10.8.3; §13.2; CR-12; CR-44; RR-36. _Durum:_ belirtilmemiş (FROZEN; düşüş politikası PD).
- [ ] **Kenar/HTTP kimliğinin actor'e çevrilmemesi** — Transport kimliği actor değildir. _Kaynak:_ CMP-1; PI-7; T36. _Durum:_ belirtilmemiş.

#### Girdi, parser ve DoS sınırları

- [ ] **HTTP/1.1, HTTP/2, TLS sınırları** — Header timeout 5–10 s; HTTP/2 `max_concurrent_streams` 100, header list 8 KB, Rapid Reset/CONTINUATION ayarları; TLS handshake semaphore; 0-RTT kapalı. _Kaynak:_ §13.7.9; §14.6; OP-4; OP-8; SA-33. _Durum:_ PD.
- [ ] **İstek katman sırası; pahalı extractor'dan önce auth** — Bağlantı → IP rate → body → timeout → shed → eşzamanlılık → trace → auth → pahalı handler. _Kaynak:_ §14.3; §14.6; SA-27. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Önbellek anahtarı çakışma koruması** — Uzunluk önekli hash. _Kaynak:_ §9.7A.4; P45. _Durum:_ PD.

#### Hesap numaralandırma ve kimlik bilgisi saldırıları

- [ ] **Yetkisiz ≡ var olmayan (cevap içeriği aynı)** — _Kaynak:_ §13.4 G62; CR-40. _Durum:_ belirtilmemiş.

#### Güvenlik ilkeleri: fail-closed, downgrade, compromise

- [ ] **Downgrade = genişletme; downgrade saldırı modeli savunmaları** — Sürüm, algoritma, assurance floor veya tavanları gevşetmek genişletme sınıfıdır; Domain minimum sürümünün altı kabul edilmez, minimum'u düşürmek genişletme sınıfı meta-Exercise'tır; must-understand, PEP minimumu metadata'dan, algoritma kümesi. _Kaynak:_ §6.5; §6.6; §9.17 compat k.4; §13.7.8; §15.4; P34; PI-21; SI-18. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Compromise patlama yarıçapı = beyan edilen use** — Issuer compromise yalnız kabul edildiği use kadar etki üretir. _Kaynak:_ §6.6; §7.9.11.1; E18; SI-3. _Durum:_ belirtilmemiş.
- [ ] **Prospektif compromise işleme** — Geçmiş geçerli kayıtlar silinmez. _Kaynak:_ §6.6; SI-9. _Durum:_ belirtilmemiş.
- [ ] **Güvenlik girdileri kayıtlıdır** — Gizli veya nondeterministik savunma uygulanmaz. _Kaynak:_ §6.6; SI-8. _Durum:_ belirtilmemiş.
- [ ] **Post-revocation pencereleri önceden beyanlı** — Event kaybı veya saat kayması pencereyi uzatamaz. _Kaynak:_ §6.6; SI-7. _Durum:_ belirtilmemiş.
- [ ] **Intent validity tavanı** — Tavan, hot-path nonce saklama ufkuna eşittir. _Kaynak:_ §6.8; TI-RT3. _Durum:_ PD.

#### Onay ekranı güvenliği

- [ ] **Digest binding (dynamic linking)** — Onay exact digest'e bağlıdır; intent değişirse geçersiz olur. _Kaynak:_ §8.17.6.2; §8.17.12; EI-18. _Durum:_ belirtilmemiş.
- [ ] **Contribution DENY** — Approver'ın authority'si yoksa onay kaydedilmez. _Kaynak:_ §8.17.6.1. _Durum:_ belirtilmemiş.
- [ ] **Explanation / policy-keşif oracle sınırları** — Açıklama policy-keşif oracle'ına dönüşmez: rate ve detay sınırları; ham karar ağacı requester'a dönmez. _Kaynak:_ §8.17.8.5; §8.17.14 OQ2; §9.6; §9.7.1. _Durum:_ belirtilmemiş.

#### Revocation ve olay müdahalesi

- [ ] **Revocation otomasyonu yalnız attributable Party'nin önceden verilmiş Grant'ıyla** — _Kaynak:_ §8.6. _Durum:_ belirtilmemiş.
- [ ] **Kuyruklu/pending revocation yok** — _Kaynak:_ §8.10; §8.17.7.2; X26. _Durum:_ belirtilmemiş.

### K16 Gizlilik, rıza ve uyum

#### Takma adlar ve bağlanamazlık

- [ ] **Opaque `basis_ref`** — Audit altındaki taraflara pozisyon sızdırmayan opaque token verilir. _Kaynak:_ §9.5, §9.12; TI-RT10. _Durum:_ belirtilmemiş.

#### Veri minimizasyonu ve seçici açıklama

- [ ] **Karar için private context gerektirmeme** — One belleği veya Work içeriği gibi özel bağlam karar için istenmez. _Kaynak:_ §2.7 One; must-never #14. _Durum:_ belirtilmemiş.

#### İfşa kapsamı ve görünürlük

- [ ] **`disclose` / `declassify` core sınıfları** — Disclosure authority'si içindir. _Kaynak:_ §7.9.3.1, §7.9.10.3. _Durum:_ belirtilmemiş.
- [ ] **Disclosure scope (requester / viewer / audit)** — Viewer-scoped explain `relative_to_viewer` döner. _Kaynak:_ §9.6; P16. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Açıklama viewer'ın authority'si kadar** — Sınıf düzeyi ifade ("a restriction set by your organization"). _Kaynak:_ §8.12; E-4; E26. _Durum:_ belirtilmemiş.
- [ ] **`reason_user` / `reason_admin` eşlemesi** — `reason_user` serbest metinsiz requester kapsamıdır; `reason_admin` yalnız audit authority varsa vardır. _Kaynak:_ §9.6.1; P41. _Durum:_ PD (eşleme).
- [ ] **Eligible set requester'ın görme yetkisi kadar** — _Kaynak:_ §8.17.5.2, §8.18.1. _Durum:_ belirtilmemiş.

#### Mevzuat ve standart eşlemeleri

- [ ] **PSD2 dynamic linking ilkesi** — Onay exact intent'e bağlıdır (PSD2 Art. 5). _Kaynak:_ §4.3; L14. _Durum:_ belirtilmemiş.

### K17 Dağıtım, operasyon, yüksek erişilebilirlik ve felaket kurtarma

#### Commit ve dayanıklılık

- [ ] **Sınırlı commit işi; toplu meta-Exercise domain'i kilitlemez** — Toplu episode olayları O(1) işaret + tembel hesapla uygulanır. _Kaynak:_ §6.8; K-10; TI-RT9; U34. _Durum:_ EA.

### K18 Açık kaynak, ticari model ve paketleme

#### Açık protokol ve yönetişim

- [ ] **Conformance profilleri** — Profiller: Provider, Decision PEP, Offline Verifier, Approval Surface, Claim Issuer, Schema Publisher, Coordinator, Event Receiver. _Kaynak:_ §9.1, §9.17; P2. _Durum:_ belirtilmemiş (FROZEN).

#### Suiss bağımsızlığı ve kilitlenmeme (anti-hostage)

- [ ] **Protokol yolunda (gizli) Suiss bağımlılığı yok** — Suiss-hosted Access veya Suiss binary'si zorunlu değildir; compatible authority provider'lar ve third-party provider'lar aynı protokolü uygulayarak birlikte çalışır. Karar, doğrulama, claim, schema, approval, Work, audit, provider değişimi ve governance Suiss olmadan çalışır. _Kaynak:_ §1.2, §6.7, §7.3, §9.17.4, §16.1; F16, OP-7, PI-14, T36, TI-17. _Durum:_ belirtilmemiş (FROZEN).

#### Ticari model ve fiyat ekseni

- [ ] **Ticari paket semantiği değiştirmez** — Fiyat ve paket semantiği değiştiremez. _Kaynak:_ §7.1, §7.3; B1. _Durum:_ belirtilmemiş.

### K19 Geliştirme ve kalite güvencesi

#### Access conformance ve test vektörleri

- [ ] **Conformance negatif testi (fail-open yok)** — _Kaynak:_ §17.7.1; X21. _Durum:_ belirtilmemiş.
- [ ] **Check/List uyum vektörleri ve diferansiyel test** — INV-34'ü doğrular. _Kaynak:_ §6.9; INV-34. _Durum:_ belirtilmemiş.
- [ ] **Capacity ve REQUIRE_ACTION eşleme vektörleri** — _Kaynak:_ §9.17.5. _Durum:_ yol haritası.

#### Protokol, kiracı ve bileşen güvenlik testleri

- [ ] **İndeks diferansiyel testi** — Advisory doğruluğu F0 referansına karşı diferansiyel testle doğrulanır. _Kaynak:_ §9.7A.1. _Durum:_ belirtilmemiş.
- [ ] **Veri deposuz özellik testleri** — Saf karar fonksiyonu sayesinde özellik testleri veri deposu olmadan koşar. _Kaynak:_ §9.7A.7. _Durum:_ belirtilmemiş.

### Bu aşamada doğrulanacak sınırlar

#### Ürün kapsamı

- [ ] **Ödeme, para ve bildirim/teslim sistemi değil; ödeme-spesifik ontoloji yok** — _Kaynak:_ §Kısaca; §2.7; §8.17.12. _Durum:_ belirtilmemiş.
- [ ] **Workflow motoru / plan-adım ilerlemesi yok** — _Kaynak:_ F10; must-never #6. _Durum:_ belirtilmemiş.
- [ ] **Execution motoru, fencing veya dağıtık transaction koordinatörü değil** — _Kaynak:_ F7; must-never #7. _Durum:_ belirtilmemiş.
- [ ] **Domain truth ve iş state'i tutmaz; eligibility hesaplamaz** — Bakiye, hold, ledger, settlement; vardiya planlaması; refund window; Work Commitment ve Gate; One memory; execution/stop state Access'in değildir. _Kaynak:_ §2.6; §7.1; §7.3; §7.5; §7.9.10.2; must-never #5. _Durum:_ belirtilmemiş.
- [ ] **Access istek/onay kuyruğu ve inbox'ı yok** — Görev üretmez; Authority hub'ında "Requests" sekmesi yoktur. _Kaynak:_ IA-1; R3; X5; XI-7. _Durum:_ belirtilmemiş.

#### Kimlik ve protokol

- [ ] **Reddedilen standartlar** — Grant Management for OAuth, GNAP, Biscuit, UCAN, ZCAP, Macaroons, COAZ/COAZ-MCP (normatif), AuthZEN AARP (normatif bağımlılık), AP2 ve PSD2 consent (Access semantiği olarak), WIMSE AIMS (normatif bağımlılık). _Kaynak:_ §9.4; §9.4.2. _Durum:_ belirtilmemiş.
- [ ] **Zincirli bearer capability (Biscuit, UCAN, ZCAP) canonical değil** — _Kaynak:_ §4.3; L27. _Durum:_ belirtilmemiş.
- [ ] **Yeni karar transport'u yok** — _Kaynak:_ P6. _Durum:_ belirtilmemiş.

#### Token modeli

- [ ] **Token'daki `tenant` / `tenant_id` iddiası karar girdisi değil** — _Kaynak:_ §9.5.2 k.3; §11.21.4; P38. _Durum:_ belirtilmemiş.
- [ ] **Ayrı "pending authorization" nesnesi yok** — Bekleyen tek nesne nonce'tur. _Kaynak:_ §9.9.5; §11.14.2; P54. _Durum:_ belirtilmemiş.

#### Yetki modeli

- [ ] **Login, token, grup üyeliği, oturum, risk skoru veya posture yetki üretmez; identity plane authority üretmez** — Authority çekirdeği identity deposuna erişmez. _Kaynak:_ INV-12; OP-62; SEC19; must-never #1, #3. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Delegation, projection, federation veya offline taşıma ile yetki büyütme yok** — _Kaynak:_ must-never #4. _Durum:_ belirtilmemiş.
- [ ] **Hiçbir extension authority genişletemez** — Dördüncü outcome veya yeni connectivity class'ı governance'sız eklenemez. _Kaynak:_ §9.17; §9.17.1. _Durum:_ belirtilmemiş.
- [ ] **Ayrı authorization universe / ayrı evaluator yok** — _Kaynak:_ L11. _Durum:_ belirtilmemiş.
- [ ] **Contextual tuple yok** — _Kaynak:_ §9.5.2 k.2; P37. _Durum:_ belirtilmemiş.
- [ ] **Kaynaksız rol kontrolü ifade edilemez** — _Kaynak:_ §9.5.2 k.4. _Durum:_ belirtilmemiş.
- [ ] **Canlı action mirası (gelecekteki action'ların otomatik dahil edilmesi) ve otomatik semantic broadening yok** — _Kaynak:_ §8.10; E10; E11. _Durum:_ belirtilmemiş.
- [ ] **Canlı rol dolaylılığı yok** — Rol değişikliği Grant'ları sessizce değiştirmez. _Kaynak:_ C28. _Durum:_ belirtilmemiş.
- [ ] **Sessiz toplu rol/template sürüm geçişi yok** — _Kaynak:_ §8.5 S7; §8.6. _Durum:_ belirtilmemiş.
- [ ] **"Full access" / süper rol / "Global admin" yok** — _Kaynak:_ §8.17.9.2; X20. _Durum:_ belirtilmemiş.
- [ ] **Otomatik yenileme ve "forever" süre yok** — _Kaynak:_ §8.17.7.7; X10. _Durum:_ belirtilmemiş.
- [ ] **Intensional Grant'ta holder renounce ve "Leave role" yok** — _Kaynak:_ §8.17.5.7; INV-31. _Durum:_ belirtilmemiş.
- [ ] **Mandate delege edilemez, Instance değiştiremez** — _Kaynak:_ C14. _Durum:_ belirtilmemiş.
- [ ] **Org ve joint gruplar Instance'a sahip olmaz** — _Kaynak:_ C6. _Durum:_ belirtilmemiş.
- [ ] **Ayrı "suspended" authority durumu yok** — _Kaynak:_ §11.9.2. _Durum:_ belirtilmemiş.
- [ ] **`max_delegation_depth` varsayılanı 4 reddedilir** — _Kaynak:_ AG-25. _Durum:_ belirtilmemiş.
- [ ] **PAP'ta holder tarafı offline attenuation yok** — Alt-ajan delegasyonu çevrimiçi `grant.issue`'dur. _Kaynak:_ §9.4 F. _Durum:_ belirtilmemiş.
- [ ] **Global trust / reputation skoru hiçbir yerde yok** — _Kaynak:_ §8.11; F4; must-never #8. _Durum:_ belirtilmemiş.
- [ ] **Advisory/search/explain kaydedilmez ve credential değil** — _Kaynak:_ §9.7; §9.16.3; C30. _Durum:_ belirtilmemiş.
- [ ] **Access'te negatif contribution (Decline kaydı) yok** — Decline yalnız Work'tedir. _Kaynak:_ §8.17.6.1; §9.14.4. _Durum:_ belirtilmemiş.
- [ ] **Access slice release yapmaz; ayrı ihlal Claim'i issue etmez; otomatik authority değişikliği yok** — _Kaynak:_ §9.12.2; E5. _Durum:_ belirtilmemiş.
- [ ] **Ayrı reserve/finalize adımı ve ayrı bütçe nesnesi yok** — _Kaynak:_ §9.12; §9.3A. _Durum:_ belirtilmemiş.
- [ ] **Ayrı "lease" nesnesi yok** — _Kaynak:_ L19. _Durum:_ belirtilmemiş.
- [ ] **Semantik sürüm emekliliği yok** — _Kaynak:_ RT8; T12. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Global Party registry yok; Access Party yaratmaz** — İkinci Party registry tutulmaz. _Kaynak:_ §8.17.14 OQ3; §10.1.3; C5; E4; INV-12. _Durum:_ belirtilmemiş.

#### Karar ve tutarlılık

- [ ] **UNKNOWN / dördüncü karar sonucu yok** — Karar yalnız üç sonuçtan biridir; protocol hatası da outcome değildir. _Kaynak:_ §5.10; §9.5; EI-21; INV-26. _Durum:_ belirtilmemiş.
- [ ] **REQUIRE_ACTION'ın `true` olarak eşlenmesi yasak** — _Kaynak:_ §9.5; R2. _Durum:_ belirtilmemiş.
- [ ] **Fail-open yok** — Hiçbir hata durumu (rate limiter, risk motoru, cache arızası, timeout dahil) ALLOW/`active=true`/yeni token üretmez; degraded-allow, authority plane'de bozulmuş mod ve signer'sız imza yolu yoktur. _Kaynak:_ §6.6; §6.7; §9.5; §9.5.2 k.8; §16.7.1; §17.7.1; G48; MD-8; SA-30; SI-22; T33; TI-9; U39; X21; must-never #11. _Durum:_ belirtilmemiş.
- [ ] **Kill-switch API ve operatör override yok** — Exercise dışı kill switch bulunmaz. _Kaynak:_ §6.6; §6.7; §8.17.9.4; SI-22; TI-9. _Durum:_ belirtilmemiş.
- [ ] **İzleme modunda authority ALLOW yok** — _Kaynak:_ TN-108. _Durum:_ belirtilmemiş.
- [ ] **Replica / cache / derived index'ten ALLOW yok; commit'te tutarlılık seçeneği yok** — Commit daima head'den verilir; `minimize_latency` commit'te yoktur. _Kaynak:_ §5.4; §9.7A.2; INV-33; TI-5. _Durum:_ belirtilmemiş.
- [ ] **Commit yolunda karar önbelleği yok; commit derived indeksi okumaz** — _Kaynak:_ §9.7A.1; §9.7A.4; TI-5. _Durum:_ belirtilmemiş.
- [ ] **Batch atomikliği ve commit modunda kısa devre yok** — Toplu işlem atomik değildir. _Kaynak:_ §9.7.1; E29; P12; PI-23; TN-125. _Durum:_ belirtilmemiş.
- [ ] **Semantik cross-product / cross-domain atomiklik ve dağıtık transaction yok** — _Kaynak:_ §7.9.13.2; §17.1.1; E29; EI-23. _Durum:_ belirtilmemiş.
- [ ] **Kısmi search sonucu yok** — Son tarih aşılırsa hata döner. _Kaynak:_ §9.7.1. _Durum:_ belirtilmemiş.
- [ ] **Explain ham karar ağacını requester'a döndürmez** — _Kaynak:_ §9.7.1. _Durum:_ belirtilmemiş.
- [ ] **"Pending/queued" authority değişikliği, kuyruklu revoke ve optimistic UI yok** — _Kaynak:_ §8.10; §8.17.9.5; §13.8; U31; X14; X26; XI-3. _Durum:_ belirtilmemiş.
- [ ] **Domain'ler arası authority yazma yok; foreign authority doğrudan authority değil** — _Kaynak:_ §9.15A.2–3; PI-3. _Durum:_ belirtilmemiş.
- [ ] **Anchor'ın domain'ler arası taşınması ve Anchor reparent yok** — _Kaynak:_ §7.9.11.2; §12.5.2; INV-35. _Durum:_ belirtilmemiş.
- [ ] **Eşzamanlı iki provider yok; Anchor/`anchor.amend` provider binding değiştiremez** — _Kaynak:_ §9.13.7; §9.15. _Durum:_ belirtilmemiş.

#### Onay ve kanıt

- [ ] **Bildirim cevabı, relay ack'i, agent prose'u, MCP elicitation, CIBA yanıtı/`binding_message`, A2A mesajı, onay ekranı veya Gate approval sayılmaz** — Token da approval kanıtı değildir. _Kaynak:_ §7.9.8.4; §9.4 G; §9.9.5; §9.14.5; §11.2; A-5; AG-33; EI-18; SI-5. _Durum:_ belirtilmemiş.
- [ ] **Serbest metin onay geçerli approval evidence değil** — _Kaynak:_ L14. _Durum:_ belirtilmemiş.
- [ ] **Auth0 tarzı "onaylananı token'dan doğrulama" reddedilir** — Kanıt AAS'tir. _Kaynak:_ §11.14.2. _Durum:_ belirtilmemiş.
- [ ] **AAS Grant türü değil; iki ayrı imza yok; Access ile Work arasında onay relay'i yok** — _Kaynak:_ §9.14.4. _Durum:_ belirtilmemiş.
- [ ] **"Approve anyway" / "Override" yok; onay DENY'ı veya limiti aşamaz** — _Kaynak:_ §8.10; X8; XI-6. _Durum:_ belirtilmemiş.
- [ ] **"Remember this decision" / "Always allow" / "Trust this device" yok** — _Kaynak:_ §8.10; X33; XI-19. _Durum:_ belirtilmemiş.
- [ ] **Örtük auto-approve modları yok** — _Kaynak:_ §8.17.12; X27; XI-6; XI-19. _Durum:_ belirtilmemiş.
- [ ] **Yüksek sonuçlu (CT2+) onayda bildirim içi/push tek dokunuş ve "Approve all"/batch onay yok** — _Kaynak:_ §8.17.6.3; §13.7.3; §13.7.9; TN-100. _Durum:_ belirtilmemiş.

#### Yönetim, operatör ve destek erişimi

- [ ] **Hosting provider, operatör ve custodian root değildir; varsayılan authority'leri yok** — _Kaynak:_ C4; INV-29; SI-2; TN-119. _Durum:_ belirtilmemiş.
- [ ] **Tenant admin örtük domain root sayılmaz** — _Kaynak:_ §7.3. _Durum:_ belirtilmemiş.

#### Kriptografi

- [ ] **Rastgele cevap (policy oracle gürültüsü / içerik rastgeleliği) savunması yok** — _Kaynak:_ CR-40; DL-7; INV-27; SEC31. _Durum:_ belirtilmemiş (FROZEN).

#### Veri, depolama ve yüksek erişilebilirlik

- [ ] **Dağıtık cache doğruluk kaynağı değil; LISTEN/NOTIFY ve Redis pub/sub iptal taşıyıcısı değil** — Redis/Infinispan doğruluk kaynağı olmaz; Bloom filtresi iptal listesi yoktur. _Kaynak:_ §4.3; OP-5; OP-19; OP-54; T26. _Durum:_ belirtilmemiş (FROZEN).

#### Güvenlik sertleştirme ve geliştirme süreci

- [ ] **TLS 0-RTT yok** — _Kaynak:_ SA-33. _Durum:_ belirtilmemiş.

#### Kullanıcı arayüzü ve terminoloji

- [ ] **"Pause" Access eylemi değil; Access agent'ı fiziksel durdurmaz** — _Kaynak:_ R4; X13. _Durum:_ belirtilmemiş.

#### Ürün iddiaları ve vaat edilmeyenler

- [ ] **Effect'in gerçekleştiğini/doğru olduğunu/durduğunu vaat etmez ("Revoked ⇒ stopped" yok)** — Revocation çalışan executor'ı/effect'i durdurmaz, "Agent stopped" denmez; Access fiziksel durdurma yapmaz. _Kaynak:_ §1.4; §9.11; E31; EI-11; G31; HL-13; must-never #10. _Durum:_ NG.

#### Ekosistem sınırından gelen kurallar

- [ ] **Başka sistemin anlamsal gerçeğinin sahibi değil** — Her anlamsal gerçeğin tek sahibi vardır (§7.1 sahiplik matrisi); diğer kopyalar gözlenen, önbellekteki veya yansıtılan kopyalardır. _Kaynak:_ §7.4; E2. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Referans sahiplik değildir** — PartyRef, ResourceRef, WorkRef, ActionRef, ExerciseID, GrantID, ClaimID, AuthorityDomainID ve EffectRef sınır geçebilir, ama işaret ettikleri durumun kanonik kopyasını taşıma hakkı vermez. _Kaynak:_ §7.4; E27. _Durum:_ belirtilmemiş (FROZEN).

## Aşama 4 — Anahtar yönetimi ve signer

Anahtar hiyerarşisi, HSM/KMS, signer süreçleri, rotasyon ve anahtar DR'ı, imza algoritmaları. Kimlik çekirdeği token imzalayabilmeden önce kurulur; geçici anahtar çözümü kullanılmaz (TI-9).

### K02 Kimlik protokolleri ve federasyon

#### Issuer, discovery ve anahtar yayını

- [ ] **Realm başına OAuth/OIDC yetkilendirme sunucusu ve issuer** — Her realm ayrı AS/issuer'dır; varsayılan alt alan adı (joker sertifika). _Kaynak:_ §12.1.2; TN-10. _Durum:_ PD (biçim), FROZEN (köken izolasyonu).
- [ ] **Path tabanlı issuer + çift well-known** — Path issuer desteklenir (varsayılan değil); RFC 8414 ve OIDC Discovery well-known yollarının ikisi de servis edilir. _Kaynak:_ §12.1.2; TN-10. _Durum:_ PD.
- [ ] **Sabit issuer** — Issuer yapılandırmada sabittir, `Host` başlığından türetilmez. _Kaynak:_ §17.9.6. _Durum:_ belirtilmemiş.
- [ ] **OIDC Discovery ve RFC 8414 AS metadata** — `/.well-known/openid-configuration` ve RFC 8414 metadata realm issuer altında birlikte sunulur; path içeren issuer için tüm well-known varyantları; yalnız açılmış özellikler ilan edilir. Metadata Domain Metadata'dan türetilir (P60). _Kaynak:_ §2.2.1; §9.4.2, §9.15.1 k.2; §10.4.6; §11.4.1 AS-M2, §11.4.5, §11.21.1 #2, §11.21.2; CMP-1; CMP-15.1. _Durum:_ belirtilmemiş (ADOPT).
- [ ] **AS metadata (Access düzeltmeleriyle)** — `code_challenge_methods_supported: ["S256"]`, `authorization_response_iss_parameter_supported: true`, `client_id_metadata_document_supported: true`, `dpop_signing_alg_values_supported`, `token_endpoint_auth_signing_alg_values_supported` vb. _Kaynak:_ §11.4.5. _Durum:_ belirtilmemiş.
- [ ] **JWKS yayını (`GET /jwks.json`)** — Realm anahtarlarının JWKS ile yayını (`AKP` modellemesi dahil). _Kaynak:_ §2.2.1; §3.1b; §11.4.5, §11.21.2; CMP-1; CMP-15.1. _Durum:_ belirtilmemiş.
- [ ] **RFC 9207 `iss` authorization response parametresi (mix-up koruması)** — `iss` her authorization yanıtında, hata dahil, zorunlu döner ve metadata `issuer` ile bayt-özdeştir (SHOULD → MUST); subdomain issuer ile gün-1. _Kaynak:_ §2.2.1; §3.1b #8; §9.4 A; §10.4.3; §11.4.4, §11.4.5 #7; §12.1.2; AG-7; AS-S2; TN-11. _Durum:_ gün-1 (§3.1b; §12.1.2 FROZEN "birinci günden gerekir"); §11.4.4'e göre PD.
- [ ] **RFC 9728 Protected Resource Metadata (PRM)** — Korunan kaynak metadata'sı benimsenir; `resource_metadata` 403 challenge'ında kullanılır. _Kaynak:_ §2.2.1; §4.3; §9.4 A, §9.9.5; §10.4.3 (→ §11.5.2). _Durum:_ belirtilmemiş (ADOPT).

### K03 Oturum ve token yönetimi

#### İmza anahtarları ve token saklama

- [ ] **Token imza algoritmaları** — JOSE projection'ları (ID token, access token, JARM, logout token) varsayılan olarak ES256 ile imzalanır; Ed25519 desteklenir, RSA (RS256) yalnız opt-in'dir. _Kaynak:_ §17.5.3; CR-2, MD-3, OP-34, T5. _Durum:_ belirtilmemiş (FROZEN); EA (kapasite).
- [ ] **Identity JOSE anahtar rotasyonu (aktif/pasif/devre dışı)** — Pasif anahtar en uzun refresh ömrü + RP JWKS cache TTL'i kadar yaşar. _Kaynak:_ §17.10.4; OP-58. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **Opak token ve bearer sırların hash'li saklanması** — Client secret, API anahtarı, refresh, reset, magic link, device code, authorization code ve session id tek yönlü özetle saklanır. Opak token'lar ≥ 128 bit (PD 256) ve sabit uzunluktadır; DB'ye yalnız SHA-256 yazılır, arama hash üzerinden yapılır. _Kaynak:_ §13.2 kripto tablosu; §14.5; CR-38, SA-26. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Device code akışı (tehdit modeli)** — Device code sırrı tek yönlü saklanır; device code phishing tehdit tablosunda yer alır. _Kaynak:_ §13.2; §14.2. _Durum:_ belirtilmemiş.

### K10 Yönetişim

#### Anahtar custody ve kriptografik yönetişim

- [ ] **Custodial anahtarlar yalnız user-gated (custody signer)** — Attested TEE custody signer + HSM KEK; her kullanım cihaz-bağlı authenticator assertion'ı ister; non-custodial controller'a geçiş her zaman açık; CT3 tutanlar varsayılan non-custodial. _Kaynak:_ §18.7 B14; CMP-15.8, CR-31, SEC17, T32, U14, U15. _Durum:_ PD (SEC17); FROZEN (CR-31); FROZEN STRATEGY (B14)
- [ ] **Recovery anahtarları provider custody'sinde olamaz** — 3-of-5 / 2-of-3, ≥ 2 donanım-bağlı. _Kaynak:_ §18.7 B14; CR-31, SEC20. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Görev ayrılığı: identity custody anahtarları provider rolünde kullanılmaz** — _Kaynak:_ CR-31, MD-6, SEC19. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Algoritma "kırıldı" kararı domain'indir** — Provider yalnız önerir; her domain kendi CT1'ini alır. _Kaynak:_ §15.16 madde 4. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Downgrade = genişletme (CT3 + 24 saat)** — Algoritma ekleme/minimum düşürme CT3 + 24 saat gecikme; çıkarma/yükseltme CT1. _Kaynak:_ §15.4; CR-8, SI-18. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Domain minimum sürüm geçiş penceresi (90 gün)** — _Kaynak:_ §15.4 tablo. _Durum:_ PD

### K15 Güvenlik ve kriptografi

#### İmza algoritmaları ve hash

- [ ] **JOSE projection imzası: ES256 varsayılan, Ed25519 seçmeli** — Projection'lar JOSE + ES256 ile imzalanır; Ed25519 seçilebilir. _Kaynak:_ §9.9.3 k.7; §10.4.5; §12.1.2; §13.2; IDP-10; MD-3; P51; TN-13. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **RS256 yalnız identity plane'de, client başına opt-in** — RS256 yalnız kimlik iddiaları ve istemci assertion doğrulaması için client başına açılır; RSA anahtarı yalnız talep üzerine (tembel) ve ≥ 2048 bit üretilir. _Kaynak:_ §9.9.3 k.7; §10.1.7; §10.4.5; §11.4.5 düzeltme (a); §12.1.2; §13.2; MD-3; P51; TN-13. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **DPoP algoritmaları RFC 9864 adlarıyla (`ES256`, `Ed25519`)** — `EdDSA` ilan edilmez, JWS doğrulamada reddedilir. _Kaynak:_ §11.4.5 (b); §11.21.5; AG-38. _Durum:_ PD.
- [ ] **FIPS profili (domain/realm başına)** — Regüle müşteriler için: ES256/ESP256 her yerde, Ed25519 yok, PBKDF2, aws-lc-rs `fips`, operasyonel anahtar HSM'de; uyum profili, garanti değil. _Kaynak:_ §4.8 eksen 5; §10.4.5; CR-15; MD-3; T5. _Durum:_ belirtilmemiş (FROZEN; içerik PD).
- [ ] **JWE ID token şifreleme (opsiyonel)** — ECDH-ES+A256KW + A256GCM; RSA-OAEP-256 legacy. _Kaynak:_ §10.4.5. _Durum:_ belirtilmemiş (opsiyonel).

#### Anahtar hiyerarşisi ve kapsamı

- [ ] **Anahtar hiyerarşisi** — Binding key, operasyonel anahtar, realm JOSE, KEK/DEK, `basis_ref`, custody ve pepper anahtarları. _Kaynak:_ CR-18; MD-6; T20. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Binding anahtarı (HSM, quorum)** — Domain Metadata binding'ini ve operasyonel anahtar delegasyonunu imzalar; quorum'suz kullanılamaz, quorum aktivasyonu ve politikasını belirler. _Kaynak:_ §13.2; §17.10.4; CR-29; FA-6; MD-6; RT11; T20. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Domain-scoped operasyonel imza anahtarı ve plane başına ömür** — [AU] varsayılan 1 saat, tavan 24 saat; [ID] realm politikası (PD 90 gün); ayrı signer süreci, FIPS'te HSM; çalınmış anahtar etki penceresi ≤ ömür ∩ verifier yerel tavanı; `key_epoch`. _Kaynak:_ §9.11.1; §9.15.1; §12.1.2; §13.2; §13.7.7; CR-19; MD-6; T20; U41. _Durum:_ PD.
- [ ] **Anahtar kapsamı: [AU] domain, [ID] realm** — _Kaynak:_ CR-20. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Excerpt'te `jwk_thumbprint`** — _Kaynak:_ CR-18. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Anahtar ailesi ayrımı** — Authority taşıyan token domain operasyonel anahtarıyla ayrı signer sürecinde imzalanır; realm JOSE anahtarı authority projection imzalamaz, domain operasyonel anahtarı kimlik iddiası imzalamaz. Realm JOSE/SAML veya RSA imzalı nesne authority artefaktı sayılmaz. _Kaynak:_ §9.9.3 k.7; §12.1.2; §13.4 G46; MD-6; SAI-9; T20; TN-14; TNI-2. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Realm başına JOSE anahtar seti ve ayrı KMS anahtarı** — Kiracılar arası paylaşılan anahtar yok; realm başına 1 aktif + N pasif, publish→wait→use, emekli anahtar tutma, `kid` zorunlu (opak, küresel), `Cache-Control`; realm başına domain anahtarlarından ayrı KMS anahtarı; bağımsız rotasyon (3–6 ay). _Kaynak:_ §3.1b #4; §6.7; §10.1.7; §10.4.5; §12.1.2; I4; IDP-10; LFP-26; MD-6; T31; TN-12. _Durum:_ gün-1; FROZEN (yapı), PD (rotasyon aralığı).
- [ ] **`kid` = RFC 7638 thumbprint** — _Kaynak:_ CR-24. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Amaca göre ayrı anahtarlar** — OIDF entity statement / federasyon, Domain Metadata yayın, token/projection ve SAML imza anahtarları ayrıdır. _Kaynak:_ §9.13.8 k.6; §9.15; §10.1.7; §10.7.1; MD-6; T20. _Durum:_ belirtilmemiş.
- [ ] **Claim issuer ayrı anahtarla (COSE, Ed25519)** — _Kaynak:_ §10.1.7 alt bileşenler. _Durum:_ belirtilmemiş.
- [ ] **Custody signer ve görev ayrılığı** — Ayrı süreç, HSM, kiracı KEK; custody anahtarları provider rolünde kullanılmaz; custodial anahtar NOT GUARANTEED. _Kaynak:_ §5.12; §10.1.7; DL-1; SEC19. _Durum:_ belirtilmemiş.
- [ ] **Domain-pairwise takma ad anahtarı** — Domain dışına çıkmaz; handover'da Record Export Package içinde taşınır. _Kaynak:_ §7.1; MD-10. _Durum:_ belirtilmemiş.

#### Anahtar yaşam döngüsü, rotasyon ve felaket kurtarma

- [ ] **Anahtar rotasyonu: politika domain action, zamanlanmış yürütme operasyonel** — Realm JOSE, SAML metadata yeniden imzası, keytab rotasyonu. _Kaynak:_ §10.1.7; §10.6.1; §10.6.4. _Durum:_ belirtilmemiş.
- [ ] **Realm imza anahtarı rotasyonu** — Rotasyon + JWKS'ten çıkarma (`key_epoch`) + issuer cutoff; HSM/signer süreci; rotasyon CT3. _Kaynak:_ §13.2; §13.7.1. _Durum:_ belirtilmemiş.
- [ ] **Rotasyon durum makinesi; 1 aktif + ≥ 1 yedek** — PENDING→PUBLISHED→ACTIVE→RETIRING→DROPPED. _Kaynak:_ CR-27. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Publish-before-use** — Yayımlanma süresini doldurmamış anahtarla artefakt üretilmez. _Kaynak:_ §13.4 G61; CR-25; SAI-46. _Durum:_ belirtilmemiş (FROZEN; değerler PD).
- [ ] **`max_age` / `max_signatures` rotasyon tetikleyicileri** — _Kaynak:_ CR-21. _Durum:_ PD.
- [ ] **Rotasyon jitter'ı (±%20)** — _Kaynak:_ CR-23. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Anahtar düşürme ve saklama kuralları** — _Kaynak:_ CR-26. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Kesinti modları: signer ≠ HSM; imzasız artefakt yayınlanmaz** — HSM/KMS kesintisinde mevcut anahtarla tavan dolana kadar imza sürer; sonra artefakt gecikir, imzasız artefakt çıkmaz. _Kaynak:_ §13.4 G42; CR-23. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Derived kesintisinde taze imzalı stale status yok** — _Kaynak:_ §13.4 G43. _Durum:_ belirtilmemiş.
- [ ] **İmza anahtarları DB dışında, bağımsız yedek (DR)** — DB'den bağımsız yedek yaşam döngüsü; dışa aktarılamayan KMS'te çok bölgeli anahtar zorunlu. _Kaynak:_ §3.1b #25; §17.10.4; OP-58. _Durum:_ gün-1; FROZEN TECHNICAL.
- [ ] **HSM/KMS (PKCS#11/KMIP)** — Anahtar materyali HSM/KMS'te; `mlock` ile bellek koruması. _Kaynak:_ §17.9.5; CMP-13; OP-52. _Durum:_ belirtilmemiş.

#### Süreç izolasyonu ve signer

- [ ] **Ayrı signer süreci (commit sonrası imza)** — Ağ çağrısı yok (seccomp), salt-okur anahtar deposu, `memfd_secret`, UDS + `SCM_CREDENTIALS`, Landlock + iki fazlı seccomp, `PR_SET_DUMPABLE=0`, `no_new_privs`, core dump/ptrace kapalı; authority ve identity signer ayrı. Signer ayrımı ve HSM herkes için ücretsiz taban güvencedir. _Kaynak:_ §14.5; §17.1.1; §17.6.5; §18.6; CMP-22; CMP-22a; CR-21; MD-6; MD-17; OP-2; SA-22; U42. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Plane ayrımı (identity plane altyapı ayrımı)** — Ayrı cell/cluster, ayrı KMS, ayrı operatör rolleri; ortak tablo/DB rolü yok; identity plane'in Core'a ayrıcalıklı yolu yok. _Kaynak:_ §5.12; §10.1.1; §10.1.7; T31; TI-15. _Durum:_ belirtilmemiş.
- [ ] **Kiracı kodu IdP sürecinde asla** — Sunucu tarafı şablon, betik, eylem, ifade politikası yok. _Kaynak:_ §12.4.2; TN-106. _Durum:_ belirtilmemiş (FROZEN).

## Aşama 5 — Identity plane çekirdeği

Identity Realm, kullanıcı kaydı, parola, passkey ve temel yöntemler, login ve gereksinim modeli, oturum ve `session_epoch`, temel OIDC OP / OAuth 2.1 AS.

### Spec dışı ön koşullar

- [ ] **Realm alt alan adı yönlendirmesi ve TLS sertifika otomasyonu** — joker sertifika, özel alan adı, Frontend API'nin kiracı alan adında sunulması.
- [ ] **E-posta, SMS/ses ve posta teslim sağlayıcıları** — sağlayıcı seçimi, şablonlar, teslim ve bounce takibi, SPF/DKIM.
- [ ] **Push teslim kanalı (APNs/FCM) ve onaylayıcı uygulama** — push ile doğrulama ve number matching için.
- [ ] **FIDO MDS çekme ve doğrulama işi** — imzalı MDS blob'unun periyodik alınması ve önbelleklenmesi.
- [ ] **Sızdırılmış parola kontrolü (HIBP) kararı** — canlı API mi yerel ayna mı; servis erişilemezken davranış.
- [ ] **Argon2id kalibrasyonu** — hedef donanımda parametre ve semafor ölçümü (OP-5).
- [ ] **WebAuthn test düzeneği** — sanal authenticator ile passkey, conditional UI, BE/BS ve Signal API testleri.
- [ ] **Hesap varlığı sızdırmama (enumeration) ölçüm testi** — yanıt kodu, gövde, boyut ve süre karşılaştırması.
- [ ] **Çıkışta `instance.terminate`'i yapan aktör kararı** — kullanıcının Instance'ı mı, identity plane servis Party'si mi (§20.2).

### K01 Kimlik doğrulama yöntemleri

#### Genel model ve tipli sonuç

- [ ] **Tipli kimlik doğrulama durum makinesi** — Kimlik doğrulama, çalışma zamanında yorumlanan ve adımı silinebilen bir "flow" yerine tipli bir durum makinesidir. Güvenlik adım sırasına değil, yalnız gereksinim listesinin tamamlanmasına bağlıdır. _Kaynak:_ §3.1b #16; §4.3; LFP-23; TN-132. _Durum:_ gün-1.
- [ ] **Tipli kimlik doğrulama sonucu (assurance Claim)** — Yöntem, ulaşılan AAL/güvence, bağlanan authenticator ve realm bağlamı tek bir tipli değerde taşınır. Bu değer authority plane'e Claim olarak geçer ve token üretimi doğrulama yoluna erişemez. _Kaynak:_ §12.4.1; F17; TN-103. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Assurance modeli** — Assurance teknolojiden bağımsız semantik bir değerdir: method class (ör. phishing-resistant), human presence, binding strength, issuer assurance ve yaş. Passkey, WebAuthn ve OIDC bu değeri doldurmanın yollarıdır. _Kaynak:_ §5.3. _Durum:_ belirtilmemiş.
- [ ] **Platform biyometrisi tek başına güçlü unsur sayılmaz** — Assurance değerlendirmesinde platform biyometrisi tek başına güçlü kimlik doğrulama unsuru kabul edilmez. _Kaynak:_ §5.3; §9.14.5 k.1; MD-11. _Durum:_ belirtilmemiş.
- [ ] **Uygulama-kontrollü faktör (app PIN + uygulamaya bağlı anahtar çifti)** — Ayrı bir assurance method class'ıdır ve assurance vektörüne `app_controlled_factor` olarak girer. Tek başına phishing-resistant sınıfını karşılamaz. _Kaynak:_ §5.3; §10.1.6, §10.3.3, §10.3.4; IDP-9, MD-11. _Durum:_ PD.
- [ ] **Login yolunda fail-closed** — Backend/DB erişilemezse login 503 döner; kimlik doğrulama yapılmaz, oturum açılmaz ve önbellekte hiç görülmemiş kullanıcı fail-closed olur. Karar canonical durumdan verilir (Δ = 0); login'in sonucu authority değil, `authentication` Claim'idir. _Kaynak:_ §9.11.2; §13.11 EP-1; G48, G50. _Durum:_ belirtilmemiş (§13'e aday).
- [ ] **Identifier-first login akışı** — Login önce tanımlayıcıyı alır (TN-96); ikinci adım hesap var olsun olmasın aynıdır: passkey seçeneği ve parola formu her zaman gösterilir, MFA sonra gelir. _Kaynak:_ §10.2.1, §15.15; CR-40, TN-96. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Identity-first login yalnız varlık sızdırmama koşuluyla** — Login akışı hesap varlığını hiçbir kanalda farklılaştırmaz; identity-first akış yalnız bu koşul sağlanırsa kullanılır. _Kaynak:_ §14.3; SA-11. _Durum:_ belirtilmemiş (FROZEN).

#### Passkey / WebAuthn: yöntem ve güvence

- [ ] **Passkey / WebAuthn ile giriş** — Oltalamaya dayanıklı, origin'e bağlı passkey girişi; passkey müşterinin alan adındaki RP ID'ye bağlıdır. S11'de "Passkey / Geçiş anahtarı" giriş yöntemi olarak yönetilir. WebAuthn L2 üretimde, L3 kısmen desteklenir. _Kaynak:_ §1.4; §2.2.1; §3.3a; §4.11; §8.5 S11, §8.8; §18.1, §18.2, §18.13; B3, B19, XI-12. _Durum:_ Faz 1 (§18.13, çıkarım); X32 PROPOSED FOR FREEZE.
- [ ] **Passkey/WebAuthn birincil yöntem (phishing-resistant varsayılan)** — Passkey/WebAuthn birincil yöntemdir; parola, OTP ve push yalnız fallback'tir ve güvenceleri sınırlıdır. _Kaynak:_ §10.0 P-ID-6, §10.2. _Durum:_ belirtilmemiş (varsayılan açık).
- [ ] **WebAuthn RP ve authenticator registry (passkey credential'ı)** — Identity plane bir WebAuthn RP ve authenticator registry içerir; passkey public key'i realm'e yerel credential olarak tutulur. Authority etkisi yalnız `authentication` / `authenticator-binding` Claim'idir ve bu Claim'ler yalnız public materyal digest'i taşır; webauthn-rs 0.5 tabanlıdır. _Kaynak:_ §5.6, §7.1, §7.9.12.4; §16.3.1 CMP-15.7; MD-5, OP-5, T31. _Durum:_ belirtilmemiş.
- [ ] **Cihaza bağlı passkey / donanım anahtarı (AAL3, CT3)** — Donanım authenticator'larıyla doğrulama: cihaza bağlı passkey ve FIPS 140-3 donanım anahtarı AAL3'ü, UV + donanıma bağlı + non-custodial olduğunda CT3'e kadar karşılar. _Kaynak:_ §2.2.1; §10.2, §10.2.4. _Durum:_ belirtilmemiş (varsayılan açık).
- [ ] **Senkronize passkey (AAL2, CT2)** — Senkronize passkey AAL2 sayılır; CT2'ye kadar karşılar, CT3'ü karşılamaz. _Kaynak:_ §10.2, §10.3.3; IDP-8. _Durum:_ PD.
- [ ] **Passkey bağımsızlık grubu (`independence_group`)** — Aynı senkronizasyon dokusundaki passkey'ler (AAGUID + BE/BS) tek authenticator sayılır; senkron passkey tek başına "tam korumalı" gösterilmez. _Kaynak:_ §12.3.2; MKT-D7, TN-63. _Durum:_ PD (TN-63); MKT-D7'de HYPOTHESIS.
- [ ] **Donanım anahtarı: kullanıcı başına ≥2 kayıt** — Kullanıcı başına en az iki donanım anahtarı kaydı önerilir; break-glass için zorunludur. _Kaynak:_ §10.2.5. _Durum:_ belirtilmemiş.

#### Passkey / WebAuthn: RP ve alan adı

- [ ] **WebAuthn RP ID realm başına ve `user.id` kararı** — Her müşteri realm'i kendi WebAuthn RP ID'sini alır; first-party yüzeyler tek RP ID kullanır. RP ID ve WebAuthn `user.id` gün-1'de sabitlenir. _Kaynak:_ §3.1b #12, #13; §10.2.4; §12.1.2; IDP-5, MD-5, TN-17, TN-18. _Durum:_ gün-1 (karar FROZEN).
- [ ] **Özel alan adının passkey kaydından önce sabitlenmesi** — _Kaynak:_ §10.2.4; IDP-5. _Durum:_ belirtilmemiş (karar FROZEN).

#### Passkey / WebAuthn: ceremony ve kullanıcı deneyimi

- [ ] **"Passkey ile giriş" yolu her zaman sunulur** — Önce-tanımlayıcı akışını atlayan, boş `allowCredentials` ile keşfedilebilir credential kullanan passkey girişi her zaman mevcuttur; sunucuya tanımlayıcı sızdırmaz. _Kaynak:_ §12.4.1; TN-96. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Discoverable credential (`credProps.rk` kontrolü)** — _Kaynak:_ §10.2.4. _Durum:_ belirtilmemiş.
- [ ] **Conditional get / koşullu arayüz + açık passkey düğmesi** — Kullanıcı adı alanında passkey autofill desteklenir ama tek yol değildir; her zaman açık bir passkey düğmesi ve `AbortController` bulunur. _Kaynak:_ §10.2.4; §12.4.1; TN-99. _Durum:_ PD.
- [ ] **Conditional create (otomatik passkey yükseltme)** — Attestation istenmez, kullanıcı bilgilendirilir, `excludeCredentials` doldurulur. _Kaynak:_ §10.2.4. _Durum:_ belirtilmemiş.
- [ ] **Cihazlar arası QR (hybrid) son çare** — Platform tespit edilir; QR son çare olarak sunulur, asla tek yol olmaz. _Kaynak:_ §12.4.1, §12.4.3; TN-99, TN-107. _Durum:_ PD.
- [ ] **Hybrid / bilinmeyen transport toleransı** — Bilinmeyen transport değerleri kabul edilir. _Kaynak:_ §10.2.4. _Durum:_ belirtilmemiş.
- [ ] **WebAuthn Signal API** — `signalUnknownCredential` başarısız denemeden sonra, `signalAllAcceptedCredentials` yalnız doğrulanmış kullanıcı için tam listeyle, `signalCurrentUserDetails` isim değişikliğinde kullanılır. _Kaynak:_ §10.2.4; §12.4.1; TN-97. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **`uiMode: immediate` (L4)** — _Kaynak:_ §10.2.4. _Durum:_ WATCH.

#### Passkey / WebAuthn: doğrulama politikaları

- [ ] **WebAuthn UV politikası** — Varsayılan `preferred`; CT2+/AAL2+ için UV=1 zorunlu. _Kaynak:_ §10.2.4. _Durum:_ belirtilmemiş.
- [ ] **WebAuthn uzantıları: `credProps`, `credProtect` seviye 2** — _Kaynak:_ §10.2.4. _Durum:_ belirtilmemiş.
- [ ] **WebAuthn PRF desteği** — Salt alan ayrımı yapılır; sunucu yalnız salt ve `prf.enabled` saklar, çıktıyı asla saklamaz. first/second ile rotasyon yapılır, yedek yol şarttır. _Kaynak:_ §10.2.4. _Durum:_ belirtilmemiş.
- [ ] **BE/BS bayrak politikası** — BE değişirse ret; BS güncellenir, 1→0 değişiminde uyarı verilir; BE=0∧BS=1 geçersizdir. Kurumsal politika BE=0 şartı koyabilir. _Kaynak:_ §10.2.4; IDI-5. _Durum:_ belirtilmemiş.
- [ ] **Sign count politikası** — BE=0'da artış beklenir; ihlal sinyal Claim'i üretir ve kiracı politikasına göre ret yapılır. BE=1'de zorunlu değildir. _Kaynak:_ §10.2.4. _Durum:_ belirtilmemiş.
- [ ] **AAGUID + MDS 3.1.1 + topluluk listesi (ipucu)** — _Kaynak:_ §10.2.4. _Durum:_ belirtilmemiş.
- [ ] **Attestation politikası** — Tüketicide `none`; kurumsalda kiracı bayrağıyla `direct` + MDS + AAGUID allowlist ve enterprise attestation. _Kaynak:_ §10.2.4. _Durum:_ belirtilmemiş.
- [ ] **WebAuthn algoritmaları ve assertion kabulü** — ES256, ESP256, Ed25519 ve legacy RS256 desteklenir; `pubKeyCredParams` sırası ESP256/ES256 → Ed25519 → RS256'dır. EdDSA (−8) yalnız `crv` = Ed25519 ise kabul edilir; harici imzalarda high-S kabul edilir, koruma tek kullanımlık challenge'a dayanır. _Kaynak:_ §10.2.4, §10.8.1; §15.3.2, §15.5.2; CR-5, CR-9. _Durum:_ gün-1 (ESP256, Ed25519; §10.8.1); kabul kuralları FROZEN.
- [ ] **RS256 authenticator yalnız oturum girişi için** — RS256 authenticator AIS/AAS imzalayamaz ve hiçbir CT'yi karşılamaz. _Kaynak:_ §10.2.4. _Durum:_ belirtilmemiş.
- [ ] **WebAuthn CBOR girdi sınırları** — Kimliği doğrulanmamış kayıt yolundaki attestation/authenticatorData için boyut ve derinlik kontrolü. _Kaynak:_ §15.5.3; CR-10. _Durum:_ PD.

#### Parola

- [ ] **Parola ile giriş (fallback / ikincil yöntem)** — Parola S11'de bir "Sign-in method" olarak yönetilir; parola hash'i identity plane'de realm-yerel credential'dır ve authority kaydı sır içermez. AAL1'dir, CT0 dahil hiçbir CT'yi tek başına karşılamaz; varsayılan açık fallback'tir, gömülü modda passkey önceliklidir. _Kaynak:_ §2.2.1; §4.11; §5.1 eki, §5.6, §7.1; §8.5 S11, §8.8; §10.2, §10.2.1; §12.4.1; TN-101, TN-133. _Durum:_ PD (TN-101/133); varsayılan açık.
- [ ] **Parola hash'i Argon2id (kanonik parametreler)** — Parolalar Argon2id ile tek yönlü hash'lenir; kanonik varsayılan m = 7 MiB, t = 5, p = 1'dir ve hedef donanımda kalibre edilir. Parametreler realm başına yükseltilebilir, düşürülemez; DB sızıntısında hash doğrudan yeniden kullanılamaz. _Kaynak:_ §10.2.1; §13.2 kripto tablosu, §14.6; §15.1.1, §15.14; §17.5.2; CR-36, IDP-3, OP-33, U69. _Durum:_ PD (parametreler); kural FROZEN.
- [ ] **Argon2id yüksek bellek profili (RFC 9106)** — Opsiyonel profil. _Kaynak:_ §10.2.1. _Durum:_ belirtilmemiş (opsiyonel).
- [ ] **FIPS profilinde PBKDF2** — FIPS profili seçen realm'de parola hash'i PBKDF2-HMAC-SHA256, 600.000 iterasyondur. _Kaynak:_ §10.2.1; §15.7.3, §15.14; CR-15, CR-36, IDP-3. _Durum:_ PD (içerik); FROZEN (karar).
- [ ] **Parola rehash göçü ve legacy hash desteği** — Hash kaydı PHC string biçimindedir. Zayıf parametreli veya eski Argon2 parametreli hash'ler başarılı girişte yeniden hash'lenir (gerekirse süre farkı ölçülerek göç zorlanır). İngest edilmiş bcrypt/PBKDF2/scrypt hash'leri "sarmala ve sonraki girişte yeniden hash'le" (`PasswordNeedsRehash`) ile 60–90 günde tembel olarak Argon2id'ye göç eder. _Kaynak:_ §10.2.1; §15.14; CR-37. _Durum:_ PD.
- [ ] **Argon2 eşzamanlılık semaforu ve yük atma** — Hash `spawn_blocking` ile, bellek bütçesine ve çekirdek sayısına göre boyutlanan bir semafor arkasında çalışır (N = floor(bellek·0.5/m)). 500 ms bekleyen istek `503 + Retry-After` alır; semafor hesap varlığından bağımsızdır ve Argon2 yükü diğer endpoint'leri aç bırakmaz. _Kaynak:_ §13.7.9, §14.6; §15.14; §16.7.1; §17.5.2; CR-36, OP-33, U47. _Durum:_ PD (değerler); FROZEN TECHNICAL.
- [ ] **NIST 800-63B-4 parola politikası** — En az 8 (15 önerilir), en fazla ≥64 karakter; kompozisyon kuralı, rotasyon ve güvenlik sorusu yoktur. Yapıştırma ve Unicode serbesttir, NFKC uygulanır. _Kaynak:_ §10.2.1; IDP-3. _Durum:_ PD.
- [ ] **Sızıntı listesi kontrolü (HIBP k-anonymity)** — Zorunludur. _Kaynak:_ §10.2.1; IDP-3. _Durum:_ PD.
- [ ] **Parola → passkey geçiş kalıbı** — Parola 12–18 ay fallback olarak kalır; ~%60 passkey kaydına ulaşılınca kiracı politikasıyla emekliye ayrılabilir. _Kaynak:_ §10.2.1. _Durum:_ belirtilmemiş.

#### Kaba kuvvet ve enumeration koruması

- [ ] **Brute-force tavanı (NIST 800-63B-4)** — En fazla 100 ardışık başarısız deneme ve kademeli gecikme uygulanır. Global rate store düşse bile yerel strict limiter korur; fail-open yoktur. _Kaynak:_ §13.7.9, §14.6; SA-30, U46. _Durum:_ PD (kural FROZEN).
- [ ] **Parola / OTP / MFA challenge deneme sınırları** — Hesap başına parola, OTP ve MFA challenge denemeleri PG'de kesin (Katman B) sayaçla sınırlanır. _Kaynak:_ §17.5.5; OP-35. _Durum:_ FROZEN TECHNICAL / POLICY DEFAULT (değerler).
- [ ] **Hesap kilitleme** — Kaba kuvvet sonucu hesap kilitlenir; kilit sayaçları logged ve senkron replike tutulur, kilitleme kapasite sayacına girmez. Kademeli kilit adayı (Rauthy örneği): 7 → 60 s, 10 → 600 s, 15 → 900 s, 20 → 3.600 s, 25 → 24 saat. _Kaynak:_ §14.6; §17.2.6, §17.5.5; §18.5; B19, OP-16, OP-35. _Durum:_ belirtilmemiş (FROZEN TECHNICAL); kademeler PD (aday).
- [ ] **Hesap enumeration direnci** — Login, kayıt, parola sıfırlama ve recovery yanıtları status/body/header/redirect'te özdeştir. "E-posta zaten kayıtlı" bilgisi yalnız e-posta kanalıyla verilir; p50–p95 regresyon suite'i vardır. _Kaynak:_ §13.7.9, §14.6; MD-18, SA-31, SAI-5, U44. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Adaptif gecikme (dummy Argon2 yerine)** — Kullanıcı yokken sahte hash hesaplanmaz; başarısız yanıt koşan başarı ortalamasına doldurulur ve varlıktan bağımsız semafor kullanılır. Üstüne rate limit ve IP/hesap başına artan ceza eklenir. _Kaynak:_ §15.14; §17.5.2; CR-36, MD-18, OP-33. _Durum:_ belirtilmemiş (FROZEN).

#### OTP, TOTP ve kurtarma kodları

- [ ] **OTP** — Tek kullanımlık kodla kimlik doğrulama. _Kaynak:_ §2.2.1. _Durum:_ belirtilmemiş.
- [ ] **TOTP / doğrulama uygulaması (RFC 6238)** — S11'de "Authenticator app / Doğrulama uygulaması" giriş yöntemi. 30 s adım ve ±1 pencere kullanılır, kullanılmış kodun tekrarı reddedilir. Seed realm-yerel credential olarak realm PII KEK'iyle sarılı saklanır; kod sabit zamanlı karşılaştırılır. _Kaynak:_ §5.1 eki, §5.6, §7.1; §8.5 S11, §8.8; §10.2.2; §15.14; CR-38, CR-39. _Durum:_ belirtilmemiş (FROZEN; kiracı başına).
- [ ] **Kurtarma kodları** — Identity plane credential'ı ve S11'de giriş yöntemidir; TOTP ile zorunlu eşlikçidir. Tek kullanımlıktır ve Argon2id ile hash'lenir. _Kaynak:_ §7.1, §7.2; §8.5 S11, §8.8; §10.2.2. _Durum:_ belirtilmemiş.
- [ ] **SMS OTP (restricted, varsayılan kapalı)** — AAL2'de izinlidir ama önerilmez; TR ödeme şablonunda yalnız kurulum/aktivasyon için kullanılır. _Kaynak:_ §10.2.2; IDP-4. _Durum:_ PD (varsayılan kapalı).

#### Magic link ve askıya alınabilir akışlar

- [ ] **E-posta OTP ve magic link** — E-posta bağlantısı veya koduyla parolasız giriş (tüketici kullanıcılar için). AAL1'dir ve hiçbir CT'yi karşılamaz; ömür ≤15 dk ve tek kullanımlıktır. Token sunucuda üretilir, ≥128 bit (PD 256) olur ve DB'de yalnız SHA-256 hash'i tutulur. _Kaynak:_ §1.7; §2.2.1; §10.2, §10.2.2; §15.14; CR-38, CR-39. _Durum:_ belirtilmemiş (FROZEN; kiracı başına).
- [ ] **Magic link önizleme botu koruması** — Link'i tüketen istek GET değildir; link onay ekranı açar veya kod gösterir. _Kaynak:_ §10.2.2; IDP-4. _Durum:_ PD.
- [ ] **Magic link'i başlatan cihaza bağlama** — Link başka cihazda açılabilir ama oturum başlatan cihaza bağlanır; başka cihazda tamamlamak açık onay ister. _Kaynak:_ §10.2.2; IDP-4. _Durum:_ PD.
- [ ] **Askıya alınabilir akış (magic link, OTP, bant dışı onay, CIBA)** — Link/OTP beklemesi, bant dışı onay ve CIBA akışları askıya alınabilir/sürdürülebilir kimlik doğrulama olarak tipli durum makinesinde modellenir. _Kaynak:_ §10.2.2; §12.4.1; TN-102. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Askıya alınabilir kimlik doğrulamanın kuralları** — Sunucu tarafı durum ve opak tanıtıcı; tek kullanım ve tarayıcı bağlamına bağlama; mutlak askı ömrü; sürdürme güvenceyi yükseltmez. Adım atlanamaz, sürdürme/sona erme ayrı denetim olaylarıdır ve e-posta tarayıcısının tıklaması akışı tüketmez. _Kaynak:_ §12.4.1; TN-102, TNI-9. _Durum:_ belirtilmemiş (FROZEN 1–4), PD (ömür, 5–6).

#### Push ile doğrulama

- [ ] **Push ile doğrulama** — Push bildirimli kimlik doğrulama yöntemi. _Kaynak:_ §2.2.1. _Durum:_ belirtilmemiş.
- [ ] **Login push'ta zorunlu sayı eşleştirme** — Push onayında number matching zorunludur (aynı cihaz + bağlam istisnası); bildirimde uygulama, konum ve eylem bağlamı gösterilir ("Sign-in request to *Acme* from *browser, city?*. Enter the number shown."). Push tek başına hiçbir CT'yi karşılamaz. _Kaynak:_ §8.6, §8.15.1 X-L7, §8.17.11.4; §10.2.3; §12.4.1; IDP-4, TN-100, TN-G1. _Durum:_ PD (kiracı başına); §12.4.1'de FROZEN.
- [ ] **Push fatigue savunması** — Oran sınırı ve ret sonrası bekleme. _Kaynak:_ §10.2.3 (→ §12). _Durum:_ belirtilmemiş.

#### MFA

- [ ] **MFA** — Identity plane çok faktörlü doğrulama sunar; hiçbir pakette ücretli eklenti değildir. _Kaynak:_ §18.5, §18.6, §18.7; B3. _Durum:_ belirtilmemiş (FROZEN STRATEGY).
- [ ] **Çalışanlar için phishing-resistant MFA** — Çalışan kullanıcılar için oltalamaya dayanıklı çok faktörlü doğrulama. _Kaynak:_ §1.7. _Durum:_ belirtilmemiş.
- [ ] **Zorunlu MFA seçeneği** — Kiracı MFA zorunluluğu seçebilir; zorunlu MFA hiçbir sırayla atlanamaz. _Kaynak:_ §12.4.2; TN-132. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **MFA etkinleştirilince önceki oturumların geçersizleşmesi** — _Kaynak:_ §12.3.3; TN-64. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **"Don't ask for a second step on this device for 30 days"** — MFA'yı belirli süre o cihazda sormama seçeneği; nötr süre ifadesi kullanılır ("Trust/Remember this device" yasak). _Kaynak:_ §8.10; X33, X-L2. _Durum:_ belirtilmemiş.

#### Step-up ve yeniden doğrulama

- [ ] **Step-up kimlik doğrulama (her pakette)** — Passkey/step-up yüzeyi her pakette açıktır. _Kaynak:_ §18.6 madde 4–5; B3. _Durum:_ belirtilmemiş (FROZEN STRATEGY).

#### Sertifika, donanım ve cihaz anahtarları

- [ ] **Cihaz anahtarı kaydı** — `device_id, identity_subject_id, public_key, key_type, algorithm, attested_at, status, created_at, last_seen`; kayıt `authenticator-binding` Claim'i üretir. _Kaynak:_ §10.1.3. _Durum:_ belirtilmemiş.

#### Device code akışı

- [ ] **Device code akışı varsayılan kapalı** — Realm açarsa token DPoP'a bağlanır ve client adı/kapsam/IP-konum gösteren ayrı bir onay ekranı kullanılır. _Kaynak:_ §12.2.1; TN-35. _Durum:_ PD.
- [ ] **Device code / user code için rate limit** — Device/user code karşılaştırması sabit zamanlıdır; asıl savunma rate limit'tir. _Kaynak:_ §15.15; CR-39. _Durum:_ belirtilmemiş (FROZEN).

#### İstemci kimlik doğrulaması

- [ ] **`private_key_jwt` / client credentials** — API tüketicileri için client credentials ve `private_key_jwt`; CIMD istemcileri için önerilen confidential istemci yoludur. Yayımlanmış JWKS ile RFC 7523 §2.2 doğrulaması yapılır. _Kaynak:_ §1.7; §11.3.6 (§8.2), §11.3.7, §11.21.2. _Durum:_ belirtilmemiş.
- [ ] **`none` (public istemci)** — Metadata'da `token_endpoint_auth_methods_supported` içinde `"none"` ilan edilir; Claude'un CIMD seçmesi için kritiktir. _Kaynak:_ §11.4.5, §11.8.3. _Durum:_ belirtilmemiş.
- [ ] **`client_secret_basic` / `client_secret_post` (legacy)** — Yalnız ön kayıtlı confidential istemciler için; CIMD istemcilerinde yasaktır. _Kaynak:_ §11.4.5 düzeltme (c), §11.21.2. _Durum:_ belirtilmemiş.

### K02 Kimlik protokolleri ve federasyon

#### Genel kapsam ve identity plane sınırları

- [ ] **OIDC OP ve OAuth 2.1 Authorization Server (tam IdP)** — Identity plane tam bir OpenID Connect sağlayıcısı ve OAuth 2.1 AS'dir (2.1 draft olarak etiketlenir, PKCE ile); Rust'ta Access tarafından yazılır. Access tam bir IdP'dir (OAuth AS, OIDC OP, SAML IdP, SCIM server, LDAP yüzeyi, SPNEGO acceptor); identity bundle müşteri için opsiyoneldir, kenar gateway'ler ayrı süreçte çalışır. _Kaynak:_ §2.2.1; §4.11; §7 giriş, §7.6; §10.0 P-ID-2; §16.3.1 CMP-15.1; §18.2, §18.13; F21; I1; L24; MD-1, MD-13; T42. _Durum:_ Faz 1 (§18.13, çıkarım).
- [ ] **Standart protokol uçlarının birebir sunulması** — AuthZEN, OAuth, SSF, `.well-known`, OIDF standart bağlamalarla aynen sunulur; üçüncü taraf PEP Suiss'e özgü bir şey bilmeden bağlanır. _Kaynak:_ §16.4.6 OP-6; OP-65; TI-17. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **OAuth 2.0 RFC profili ve OAuth 2.1 bilgilendirici taban çizgisi** — RFC 6749/6750 ve RFC 9700 (BCP 240) profillenir; OAuth Grant Access Grant değildir, client registration authority vermez. OAuth 2.1 bilgilendiricidir; normatif bağımlılık RFC'lerdedir, 2.1 RFC olunca profil ona hizalanır. _Kaynak:_ §9.4 A; AP-5. _Durum:_ belirtilmemiş (PROFILE; 2.1 informative).
- [ ] **OAuth AS güvenlik tabanı (OAuth 2.1 / RFC 9700 güvenli varsayılanları)** — PKCE S256 zorunlu, implicit/ROPC yok, refresh reuse tespiti baştan; OIDF süiti CI'da ilk günden. _Kaynak:_ §10.4.1; §13.9 RR-18. _Durum:_ belirtilmemiş.
- [ ] **Identity plane token'ları yalnız kimlik iddiasıdır (OIDC Core 1.0)** — ID token / assertion authority değildir; token'lar yalnız identity Claim'leri ve authority plane'in onayladığı projection içeriğini taşır, rol claim'i Grant projection'ıdır. OIDC ID Token Claim taşıyıcısıdır; `groups` claim'i Acceptance'sız selection'a giremez. _Kaynak:_ §2.2.2 #1; §7.1, §7.3; §9.4 D, §9.13; E39; S-1. _Durum:_ belirtilmemiş (OIDC Core: ADOPT).
- [ ] **Rezerve protokol claim'lerinin korunması; claim eşleme yetki üretemez** — Kiracı/RP `iss`, `sub`, `aud`, `exp`, `act`, `cnf`, `scope`, `client_id` vb.'yi tanımlayamaz/gölgeleyemez; token içeriği önceden tanımlı kümeden seçilir. Scope mapping ve protocol mapper yetki üretmez. _Kaynak:_ must-never #18; §6.5, §7.3; E39; F23; PI-8. _Durum:_ belirtilmemiş.
- [ ] **OIDF conformance süitlerinin CI'da koşulması** — OIDF OIDC / FAPI 2.0 / FAPI-CIBA / CIBA / Federation süitleri CI'da açık ve ücretsiz koşulur, sonuçlar yayınlanır; protokol uygunluğu koşuludur. _Kaynak:_ I1; §4.5; §14.8 SA-T2; §18.7 B9, §18.13; B9. _Durum:_ Faz 1 (CI'da Faz 1'den itibaren).

#### Grant tipleri ve temel akışlar

- [ ] **Authorization Code + PKCE S256 (zorunlu, atlanamaz)** — Varsayılan akış; S256 confidential client dahil zorunlu, `plain` reddedilir, PKCE'nin atlanabildiği kod yolu yoktur. PKCE verifier sabit zamanlı karşılaştırılır. _Kaynak:_ §10.4.1; §11.4.5 #1, §11.7 #18, §11.21.1 #1, §11.21.2; §16.4.10 RR-18; AS-M9; CMP-15.1; CR-39; IDP-7. _Durum:_ belirtilmemiş (varsayılan; karar FROZEN; ADOPT).
- [ ] **Authorization code tek kullanım ve kısa PKCE verifier reddi** — OAuch + OIDF suite ile regresyonla kapalı. _Kaynak:_ §14.3 (Kanidm GHSA-hh34). _Durum:_ belirtilmemiş.
- [ ] **Refresh Token grant** — `refresh_token` grant tipi; public client'ta rotasyon + DPoP bağı. _Kaynak:_ §10.4.1, §10.4.3; §11.21.2. _Durum:_ belirtilmemiş (açık).
- [ ] **Refresh token rotasyonu ve reuse detection** — Yeniden sunulan refresh token tüm aileyi iptal eder ve `session_epoch` artırır; sunucuda tolerans yok. Refresh token DB'de yalnız hash olarak tutulur. _Kaynak:_ §12.2.1; CMP-15.1; CR-38; RR-18; TN-31. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Refresh token DPoP bağlama (`dpop_jkt`)** — Public client refresh token'ı DPoP anahtarına bağlıdır. _Kaynak:_ §12.2.1; TN-31. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Client Credentials grant** — Makine-makine için; yalnız confidential, `private_key_jwt`/mTLS tercih. Ajanın OWN capacity'li kendi Grant'ına dayanır. _Kaynak:_ §10.4.1; §11.21.2; CMP-15.1. _Durum:_ belirtilmemiş (açık).
- [ ] **Device Authorization grant (RFC 8628)** — Varsayılan kapalı, kiracı başına; açıksa DPoP bağlı, onay ekranında client/konum/kod bağlamı; device code hash'li saklanır. A2A `deviceCode` için de kullanılır. _Kaynak:_ §10.4.1; §11.21.2; CMP-15.1; CR-38; IDP-7. _Durum:_ belirtilmemiş (varsayılan kapalı).
- [ ] **JWT Bearer assertion (RFC 7523)** — `iss/sub/aud/exp/jti` zorunlu, `jti` replay cache. _Kaynak:_ §10.4.1. _Durum:_ belirtilmemiş (açık).
- [ ] **Örtük akış (implicit) yasağı** — _Kaynak:_ §12.2.1, §12.4.1; TN-34, TN-101. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Eski bearer client profili (istisna)** — Authority taşımayan, realm'in beyan ettiği eski profilde kısa ömürlü bearer; varsayılan kapalı, NOT GUARANTEED. _Kaynak:_ §12.2.1; TN-27. _Durum:_ PD.

#### Uç noktalar

- [ ] **Endpoint: `GET /authorize`** — PKCE, `resource`, `iss`, onay ekranı. _Kaynak:_ §11.4.5. _Durum:_ belirtilmemiş.
- [ ] **Endpoint: `POST /token` (form kodlu)** — `application/x-www-form-urlencoded` zorunlu; `/register` JSON. _Kaynak:_ §11.4.5 #19. _Durum:_ belirtilmemiş.
- [ ] **UserInfo uç noktası ve OIDC claims parametresi** — `GET /userinfo` pairwise `sub` döner (OpenAI kurumsal alan adı kısıtı için de gerekir); bozulmuş mod pencere yasağı userinfo'yu kapsar. _Kaynak:_ §10.4.6; §11.4.5; §17.7.2; OP-45. _Durum:_ belirtilmemiş.
- [ ] **Token introspection (RFC 7662, `POST /introspect`)** — Introspection projection'ın güncel durum sorgusudur; tazeliği kanıtlanamayan veya doğruluk kaynağına ulaşılamayan durumda (cache-hit dahil) `active=false` döner, 503 yok. Authority tarafında introspection `at_least = head`. _Kaynak:_ §9.9, §9.9.3 k.5; §10.4.3; §11.4.5, §11.21.1 #16; §17.3.4, §17.7.2; CMP-1; CMP-15.1; MD-8; OP-21, OP-45; P-ID-8; T24. _Durum:_ belirtilmemiş (ADOPT; §17 FROZEN).
- [ ] **Token revocation (RFC 7009, `POST /revoke`)** — Token revoke bir projection temizliğidir; `grant.revoke` değildir, tersi de geçerli değildir ve cascade etmez. _Kaynak:_ §6.5; §9.4 A, §9.9; §10.4.3; §11.4.5, §11.21.1 #16; CMP-15.1; PI-10. _Durum:_ belirtilmemiş (ADOPT).

#### Yetkilendirme isteği ve token uzantıları

- [ ] **PAR (RFC 9126, `POST /par`)** — Varsayılan açık; FAPI/yüksek sonuçta zorunlu (`require_pushed_authorization_requests`). Hem identity AS hem authority projection token AS'de; `request_uri` durumu DB'de tutulur (durumsuz süreçler). _Kaynak:_ §2.2.1; §4.11; §9.4 A; §10.4.3; §11.21.2; §17.1.3; CMP-1; CMP-15.1; OP-10. _Durum:_ belirtilmemiş (ADOPT; varsayılan açık).
- [ ] **RFC 8707 Resource Indicators, tek `aud` ve `invalid_target`** — Her OAuth access token projection'ı tek bir RS/PEP için verilir; AS `resource`'u kayıtlı korunan kaynaklara karşı doğrular, bilinmeyene `invalid_target` döner (keyfi audience oracle'ı önlenir). MCP profilinde `resource` zorunludur, varsayılan kaynak yoktur. _Kaynak:_ §2.2.1; §9.9.3 k.1; §10.4.3; §11.4.3, §11.4.5 #4, #21; AG-8; P48. _Durum:_ FROZEN (§9.9.3); `invalid_target` PD; §11.4.3'e göre PD.
- [ ] **Step-up challenge (RFC 9470)** — `max_age` zorunlu, `acr_values` tavsiye. _Kaynak:_ §10.3.3, §10.4.3; IDP-8. _Durum:_ PD.
- [ ] **JWT access token profili (RFC 9068)** — Access token RFC 9068 JWT veya opaque + introspection olabilir; RFC 9068 RS'leri `sub`'ı görüntüleyebilir ama authority'yi RAR + `cnf` + ValidityContract'tan okur. _Kaynak:_ §9.9, §9.9.4 k.2; §10.4.3. _Durum:_ belirtilmemiş (ADOPT).
- [ ] **Refresh token süre alanları (`refresh_token_timeout`, `authorization_expires_in`)** — `draft-ietf-oauth-refresh-token-expiration-03` için arayüz hazırdır; `authorization_expires_in` Grant validity'sinin projection'ıdır. _Kaynak:_ §9.4.2; §11.21.1 #27. _Durum:_ WATCH (talep üzerine) (ADOPT-WATCH).

#### Sender-constraint: DPoP ve mTLS

- [ ] **Access token holder binding zorunluluğu** — Her access token DPoP (`cnf.jkt`) veya mTLS (`cnf.x5t#S256`) ile holder-bound'dur; public client DPoP ile karşılanır. _Kaynak:_ §9.4 A, §9.9.3 k.2; PI-11. _Durum:_ belirtilmemiş (ADOPT).
- [ ] **DPoP (RFC 9449) sender-constrained token** — Identity plane access token'ı DPoP/mTLS'e bağlıdır; authority taşıyan her projection holder-bound, authority token'larında `cnf` zorunlu. DPoP doğrulama ≈21 µs. _Kaynak:_ §2.2.1; §4.11; §10.4.3; §12.2.1; §13.4 U55, §13.7.9; §15.3.1 projection tablosu; §17.2.3, §17.4.11, §17.5.3, §18.6; CMP-15.1; IDP-11; MD-18; PI-11; TN-27. _Durum:_ belirtilmemiş (ADOPT; §12.2.1 FROZEN); §13.4'e göre PD.
- [ ] **DPoP doğrulama profili** — RFC 9449 §4.3 kontrolleri birebir, `htu` RFC 3986 normalizasyonu, metadata'dan alg allowlist. _Kaynak:_ §12.2.1; TN-28. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **DPoP nonce (uzun ömürlü, paylaşılan, durumsuz)** — Paylaşımlı MAC'li nonce, kayan pencere, ≤5 dk bayat tolerans, her 200'de öngörülü `DPoP-Nonce`, AS/RS ayrı nonce; nonce verildikten sonra nonce'suz kanıt reddedilir. _Kaynak:_ §9.4 A; §12.2.1; §13.4 U55, §13.7.9; MD-18; TN-29. _Durum:_ PD (süreler), FROZEN (red kuralı).
- [ ] **DPoP replay cache** — Anahtar `BLAKE3(htm‖htu‖jti)`, TTL = kanıt ömrü + 2× saat kayması; cache arızası = red. _Kaynak:_ §9.4 A; §12.2.1; §13.4 U55, §13.7.9; §17.2.3, §17.4.11; MD-18; TN-30. _Durum:_ PD (değerler), FROZEN (fail-closed).
- [ ] **DBSC / DPoP ile oturum bağlama** — Çalınmış token'ın başka yerde kullanılmasını kapatır; ele geçirilmiş cihazda koruma sağlamaz. _Kaynak:_ §13.4 N-50; §14.3; HL-23. _Durum:_ belirtilmemiş.

#### İstemci kaydı ve istemci kimliği

- [ ] **Global benzersiz, sunucu üretimi `client_id` + ayrı `display_name`** — Client kimliği kiracılar arası çakışmayı önlemek için global benzersiz ve sunucu tarafından üretilir, zaman/sıra sızdırmaz; görünen ad ayrı alandır. _Kaynak:_ §3.1b #5, #30; §17.2.1; I4; LFP-26; OP-11; TI-RT10. _Durum:_ gün-1 (§17.2.1 FROZEN TECHNICAL).
- [ ] **İstemci kaydı: statik kayıt (domain action)** — _Kaynak:_ §10.4.6. _Durum:_ belirtilmemiş.
- [ ] **`redirect_uri` yalnız tam dizge eşleşmesi** — Kayıtlı redirect URI yalnız tam dizge karşılaştırmasıyla eşleşir (RFC 8252 loopback port istisnası); regex/joker/desen yok, "anlamsal eşdeğer" farklı URI reddedilir (RFC 9700). `/authorize` ve token takasında iki aşamalı doğrulanır, güvenilmeyen URI'ye yönlendirme yapılmaz. _Kaynak:_ must-never #16; §3.1b #24; §7.1 Client satırı; §10.4.1; §11.4.5 #2–3; §14.8 MR6; §17.9.6; AS-M5/M6/M7; E39; IDP-7; LFP-25; SA-45. _Durum:_ gün-1 (§3.1b); karar FROZEN (IDP-7); §14.8'e göre PD (çıkarım, teyit gerekir).
- [ ] **Loopback redirect port-agnostik eşleşme** — Şema+host+path tam eşleşir; host `localhost`/`127.0.0.1`/`[::1]` ise port yok sayılır; başka gevşetme yok (Claude Code interop). _Kaynak:_ §11.3.9, §11.4.5 #3; AG-6. _Durum:_ PD.
- [ ] **`client_secret_jwt` istemci kimlik doğrulaması** — HMAC'li iki taraflı istemci kimlik doğrulaması desteklenir. _Kaynak:_ §15.2.4; CR-3. _Durum:_ belirtilmemiş (FROZEN).

#### Algoritmalar, imza ve şifreleme

- [ ] **İmza algoritması allowlist'i client / Domain Metadata'dan gelir** — Algoritma header'dan değil, client kaydından veya Domain Metadata'dan alınır; `id_token_signed_response_alg`, `request_object_signing_alg`, `token_endpoint_auth_signing_alg`, JWE alanları ve realm politikası kabul kümesini belirler, değişiklik bir domain action'dır. _Kaynak:_ §7.1; §15.4; CR-7; MD-3, MD-14. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **İstemci başına RS256 imza opt-in** — Identity plane'de client başına RS256 imzalama (yalnız aws-lc-rs). _Kaynak:_ §15.2.2 MD-3; CR-2; T5. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **İstemci başına Ed25519 imza seçimi (JOSE)** — JOSE projection'larında Ed25519 client/realm metadata ile seçilebilir (varsayılan ES256). _Kaynak:_ MD-3 tablosu; T5. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Realm anahtarıyla kimlik iddiası imzalama** — Realm JOSE anahtarları ID token, logout token, userinfo JWT, SAML assertion ve SET'i imzalar. _Kaynak:_ §12.1.2; TN-14. _Durum:_ belirtilmemiş (FROZEN).

#### OIDC özellikleri ve oturum

- [ ] **Pairwise `sub` varsayılanı; public `sub` client başına opt-in** — OIDC/SAML'de `sub` varsayılan olarak pairwise'dır (NIST 800-63C PPII); iki RP aynı kullanıcıyı tanımlayıcı üzerinden ilişkilendiremez, dışa verilen kimlikler zaman/sıra sızdırmaz. `sector_identifier_uri` desteklenir; türetim §10.4.6'ya göre rastgele değer tablosu (HMAC değil), CR-3'e göre HMAC. Public `sub` client başına opt-in'dir (ADP commit; CT2, çıkarım). _Kaynak:_ §2.2.2 #5; §5.18, §7.1; §10.4.6; §13.4 U40, §13.7.9; §17.2.1; CMP-15.1; CR-3; E39; IDP-24; MD-10; OP-11; P-ID-10; TI-RT10. _Durum:_ PD (§10.4.6, §13.4); E39: PROPOSED FOR FREEZE; §17.2.1 FROZEN TECHNICAL.
- [ ] **OIDC RP-Initiated Logout 1.0** — `id_token_hint` ya da `client_id` + tam eşleşen `post_logout_redirect_uri`. _Kaynak:_ §10.4.6. _Durum:_ belirtilmemiş.
- [ ] **OIDC Back-Channel Logout 1.0 (varsayılan)** — Logout token ES256 ile imzalı, `events`, `sid`/`sub`, `nonce` yok. _Kaynak:_ §10.4.6; §15.2.2 MD-3; CMP-15.1; IDP-24. _Durum:_ PD.
- [ ] **OIDC Front-Channel Logout (legacy, opt-in)** — _Kaynak:_ §10.4.6; IDP-24. _Durum:_ PD (opt-in).
- [ ] **OIDC `prompt=create`, `prompt=login`, `max_age`, `acr_values`** — _Kaynak:_ §10.4.6. _Durum:_ belirtilmemiş.
- [ ] **`prompt=none` ve OIDC hata kodlarında enumeration eşdeğerliği** — Var olan/olmayan hesap için aynı yanıt. _Kaynak:_ CR-40. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Yerel uygulamalarda sistem tarayıcısı zorunluluğu (RFC 8252)** — _Kaynak:_ §12.4.1; TN-101. _Durum:_ PD.

#### Consent ve kullanıcı yüzeyi

- [ ] **Protokol scope consent'i (claim release)** — "Share with *App*: your email address, your name"; authority dili kullanılmaz. _Kaynak:_ §8.8. _Durum:_ belirtilmemiş.
- [ ] **Geçersiz `redirect_uri`/`client_id`'de yönlendirme yok** — RFC 6749 §4.1.2.1'e uygun; korelasyon ID'li nazik mesaj gösterilir. _Kaynak:_ §8.10; §12.4.1; TN-104; X-L8; X41. _Durum:_ belirtilmemiş (FROZEN).

### K03 Oturum ve token yönetimi

#### Login oturumu

- [ ] **Sunucu tarafı login oturumu** — Oturum durumu sunucu tarafında tutulur; login oturumunun açılması, sürdürülmesi ve yönetimi identity plane'dedir. _Kaynak:_ §2.2.1; §2.4; §2.5. _Durum:_ belirtilmemiş.
- [ ] **Login oturumu ve uçucu auth durumu DB'de** — Auth oturumu, authorization code, refresh ailesi, PAR `request_uri` ve kaba kuvvet sayacı senkron replike veritabanında tutulur; uçuştaki OAuth akışları node kapanışından etkilenmez. _Kaynak:_ §16.1.1; §17.1.3, §17.9.3; CMP-15.2, OP-10, OP-50. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **İki katmanlı oturum ömrü (boşta + mutlak)** — Boşta kalma süresi, mutlak ömür ve olay tabanlı iptal desteklenir; varsayılan boşta 7 gün (1 sa–30 g), mutlak 30 gün (1 sa–90 g). S10'da "signed in until …" gösterilir. _Kaynak:_ §7.1, §7.6; §8.5 S10; §12.2.1; MD-13, TN-36, X33, X-L2. _Durum:_ PD.
- [ ] **"Beni hatırla" / "Keep me signed in on this device"** — Yalnız identity plane oturum ömrünü ve login sürtünmesini etkiler; hiçbir authority kararını hatırlamaz ve CT2+ requirement'ı karşılamaz. Authority için "Remember this decision" yasaktır. _Kaynak:_ §7.1; §8.8; §12.2.1, §12.4.1; TN-36, X33, X-L2. _Durum:_ belirtilmemiş (FROZEN; §8.8'de PROPOSED FOR FREEZE).
- [ ] **Olay tabanlı zorunlu oturum iptali** — Parola/MFA değişimi, cihaz uyumsuzluğu, yönetici iptali, `instance.terminate` ve `party.compromise` oturumları otomatik iptal eder; S10'da "Signed out because …" gösterilir. _Kaynak:_ §8.6; §12.2.1; TN-36. _Durum:_ PD.

#### Oturum çerezi, BFF ve cihaza bağlama

- [ ] **Suiss yüzeylerinde session cookie** — Hosted login, admin konsolu ve S1–S10 identity plane session cookie kullanır; OAuth yalnız üçüncü taraflar içindir. _Kaynak:_ §2.2.2 #7; §3.1b #20. _Durum:_ gün-1.
- [ ] **Opak session cookie** — Cookie yalnız opak session id taşır; token cookie'ye konmaz (≤ 4 KB bütçe). _Kaynak:_ CR-38, CR-43. _Durum:_ belirtilmemiş.
- [ ] **DBSC (Device Bound Session Credentials)** — Oturum token hırsızlığına karşı cihaza bağlı oturum; kiracı başına opt-in ve progressive. Oturum çerezi TPM anahtarına bağlanır, kısa ömürlü çerez yenilemesi kanıt ister, hata `session_epoch` artışına yol açar. İskelet + özellik bayrağı: `Secure-Session-*`, `dbsc+jwt`, 403/4xx/429/404 semantiği, `/.well-known/device-bound-sessions`, bağlanmamış pencerede düşük ayrıcalık; destek "doğrulanmadı" etiketlidir. _Kaynak:_ §1.4; §2.2.1; §2.5; §7.6; §10.8.2; §12.2.1; IDP-22, TN-33. _Durum:_ WATCH (şartname) → PD; EA (iskelet).
- [ ] **DPoP ile oturum/token bağlama** — Oturum ve token'lar DPoP ile bağlanabilir; sender-constraint UNDER DECLARED CAPABILITY'dir. _Kaynak:_ §2.2.1; §7.1, §7.6. _Durum:_ belirtilmemiş.

#### Oturum yüzeyi ve çıkış

- [ ] **Logout sonrası yeni token yok** — Oturum sonlandırıldıktan sonra (logout, `session.revoke`, epoch artışı) o oturum için yeni token veya kimlik iddiası üretilmez; refresh canonical oturum durumunu okur. _Kaynak:_ §10.4.6; §13.4 G57; EP-2. _Durum:_ belirtilmemiş.

#### Epoch'lar ve hızlı iptal

- [ ] **Üç epoch modeli (`session_epoch`, `key_epoch`, `authz_epoch`)** — Oturum/token iptali, anahtar penceresi ve advisory karar cache'i için ayrı epoch'lar vardır, tek global epoch yoktur. `authz_epoch` yerine AuthorityStateBasis/`applied_pos` eşlenir. _Kaynak:_ §3.1b #18; §12.2.1; §16.1.1; F12, L17, MD-7, OP-21, TN-37. _Durum:_ gün-1 (eşleme FROZEN).
- [ ] **`session_epoch` ile hızlı iptal** — Instance veya Party başına monoton sayaçtır; `instance.terminate` ve `party.compromise` sonrası artar ve identity plane oturumlarını ve token'ları kapatır. Token `rev` claim'i taşır, doğrulama sayaç üzerinden yapılır; node-yerel cache yalnız pozitif hızlandırıcıdır, DB yoksa DENY. Yayılma UNDER DECLARED CAPABILITY'dir. _Kaynak:_ §5.11, §7.1, §7.7; §9.11.1; §11.3.6, §11.4.5 #29; §16.7.1; §17.3.4; CMP-15.2, MD-7, OP-21, P56. _Durum:_ belirtilmemiş (FROZEN MD-7).
- [ ] **Üç katmanlı epoch cache** — Node-yerel cache + outbox polling (100–250 ms) + PG primary doğruluk kaynağı; node açılışta son pencerenin iptal kümesini tek sorguda yükler. _Kaynak:_ §17.3.4, §17.9.7; OP-21, OP-53. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Identity continuity (oturum/token iptali)** — `session_epoch`, `instance.terminate` ve `party.compromise` beyanlı Δ/horizon içinde etkilidir. _Kaynak:_ I5; L12. _Durum:_ belirtilmemiş.
- [ ] **Identity plane iptal/bayatlık tablosu** — Login, refresh, introspection, salt-JWT RS ve sinyal tüketen RS doğrulama yolları için Δ/horizon satırları. _Kaynak:_ F12; I5; L16. _Durum:_ belirtilmemiş.
- [ ] **"Önbellek bu kullanıcıyı hiç görmedi" fail-closed** — Hiç görülmemiş kullanıcı/oturum/token için cevap "geçerli" değildir ve yetki üretmez; cache-miss her zaman primary'ye sorar, ulaşılamazsa istek reddedilir ("epoch = 0" varsayılmaz). _Kaynak:_ §5.11, §6.2, §7.7; §13.4 G49; §17.3.4, §17.13; MD-7, MD-8, OPI-3, SAI-4. _Durum:_ belirtilmemiş (FROZEN).

#### Token sınıfları ve karar modeli

- [ ] **Kimlik iddiası profili: `session_epoch` ile hızlı iptal** — Kimlik iddialarında horizon = `exp` / `NotOnOrAfter`. _Kaynak:_ §10.4. _Durum:_ belirtilmemiş.
- [ ] **Identity plane refresh token'ları** — Refresh token'lar identity plane kaydıdır, authority kaydı değildir. _Kaynak:_ §7.9.12.4. _Durum:_ belirtilmemiş.

#### Sender-constrained token ve DPoP

- [ ] **DPoP profili: 12 adımlı doğrulama** — typ, alg allowlist, jwk, imza, htm, normalize htu, iat, jti, nonce, ath, cnf.jkt. _Kaynak:_ §10.4.3; IDP-11. _Durum:_ belirtilmemiş (yapı FROZEN).
- [ ] **DPoP nonce yönetimi** — Uzun ömürlü, paylaşılan, durumsuz nonce; bayat-nonce toleransı ve öngörülü nonce. AS `400 use_dpop_nonce`, RS `401` döner; AS/RS nonce'ları ayrıdır. _Kaynak:_ §10.4.3; IDP-11. _Durum:_ PD (süreler).
- [ ] **DPoP replay cache** — TTL = kanıt ömrü + 2×skew, BLAKE3 anahtar. _Kaynak:_ §10.4.3; IDP-11. _Durum:_ PD (süreler).
- [ ] **DPoP refresh bağı (public client) ve `dpop_jkt` desteği** — _Kaynak:_ §10.4.3. _Durum:_ belirtilmemiş.

#### Token ömürleri ve ValidityContract

- [ ] **Access token ömrü sınırları** — Kısa ömürlü access token: tipik 5–15 dk (varsayılan 10 dk), hızlı profilde 5 dk. 60 dk'yı aşan ömür varsayılan reddedilir ve 28 saatlik token her durumda reddedilir; salt-JWT RS'de iptal edilmiş token kabul süresi ≤ ömür + clock skew. Horizon = min(ömür PD, §13.7.2 tavanı). _Kaynak:_ §9.9.3 k.4; §10.4.5; §11.4.5 #24; §13.4 U36; §13.7.9; AS-S3, IDP-10, LFP-10, MD-7, P49. _Durum:_ PD.
- [ ] **ID token ömrü ≤ 5 dk** — _Kaynak:_ §10.4.5. _Durum:_ PD.

#### Refresh token

- [ ] **Refresh token rotasyonu ve reuse detection (aile iptali)** — Refresh token her kullanımda rotate edilir (public istemcilerde zorunlu); rotasyon sync quorum ile yazılır. Harcanmış refresh token tekrar görülürse ailenin bütün projection'ları iptal edilir ve `projection-invalidated` event'i üretilir; refresh reuse Katman B ile sınırlanır. _Kaynak:_ §9.9.3 k.6; §11.4.5 #22; §17.1.3, §17.4.3, §17.5.5; AS-M8, OP-10, OP-24, OP-35, P50. _Durum:_ PD; FROZEN TECHNICAL (§17).
- [ ] **Tarayıcı refresh token kuralları** — Rotasyon veya sender-constraint zorunludur; ömür ilk verilme ömrüyle sınırlıdır. _Kaynak:_ §12.2.1. _Durum:_ belirtilmemiş.
- [ ] **Arızada 503 + `Retry-After` (asla `invalid_grant`)** — Geçersiz refresh `invalid_grant` alır; ancak StateBasis okunamazsa, PG failover'da veya backend erişilemezken token/refresh/login/kayıt uç noktaları 503 + `Retry-After` döner. Yeni projection üretilmez, client refresh token'ını atmaz ve kullanıcı yanlışlıkla çıkış yaptırılmaz. _Kaynak:_ §9.11.2; §11.4.5 #23; §13.4 G50; §16.7.1; §17.4.5; EP-2, OP-26. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Atomik, tek kullanımlık authorization code takası (CAS)** — _Kaynak:_ §11.4.5 #20, §11.7 #20. _Durum:_ belirtilmemiş.
- [ ] **Token endpoint yanıt süresi < 10 s** — _Kaynak:_ §11.4.5 #25. _Durum:_ belirtilmemiş.

#### Introspection ve RS doğrulaması

- [ ] **Fail-closed token introspection** — İptal durumu için introspection yolu sunulur. Tazelik kanıtlanabiliyorsa güncel sonuç verilir; primary'ye veya tazelik kaynağına ulaşılamıyorsa cache-hit dahil her token `active=false` alır, 503 dönmez ve fail-open penceresi yoktur. Tazelik hedefi 250 ms'dir. _Kaynak:_ §6.2, §7.7; §9.9.3 k.5, §9.11.2; §13.4 G48, U37; §16.7.1; §17.7.2; EP-3, I5, INV-26, MD-8, MD-18, OP-45, OPI-3, P49, P-ID-8. _Durum:_ belirtilmemiş (FROZEN); 250 ms hedefi EA.

#### Token içeriği ve claim'ler

- [ ] **Token tipleri (`typ`)** — `at+jwt` (ES256), `oauth-id-jag+jwt`, `dpop+jwt`; arayüz olarak `txntoken+jwt`, `wit+jwt`, `application/wpt+jwt` ve istemci attestation tipleri. _Kaynak:_ §11.21.3. _Durum:_ belirtilmemiş (bugün / arayüz).

### K04 Hesap yaşam döngüsü ve kurtarma

#### Genel çerçeve ve veri modeli

- [ ] **Hesap durum makinesi** — `staged → pending_user_action → active ↔ locked/suspended → deactivated → tombstone → purging` (özet hâli: active, disabled, locked, recovery, tombstone); locked (sistem) ≠ suspended (yönetici). Durum, `account.status` Claim'i olarak authority plane'e girer. _Kaynak:_ §5.6, §7.1, §12.3.1; TN-49. _Durum:_ PD (adlar), FROZEN (E5 etkisi)
- [ ] **`IdentitySubject` kullanıcı kaydı (opak ID, UUID v7, tombstone)** — E-posta PK değil; hard delete yerine durum + tombstone. _Kaynak:_ §10.1.3, §10.1.7 veri modeli; IDP-2. _Durum:_ belirtilmemiş (karar FROZEN)
- [ ] **Credential deposu** — Parola hash'i, passkey kayıtları, TOTP sırları Secret<T> disipliniyle tutulur. _Kaynak:_ §13.2 identity plane sorumluluğu. _Durum:_ belirtilmemiş
- [ ] **Kullanıcı başına DEK** — Identity plane'de kullanıcı başına DEK gün-1 mimari kararıdır. _Kaynak:_ §16.1.1 tablo; OP-42. _Durum:_ gün-1

#### Tanımlayıcılar ve e-posta

- [ ] **Büyük/küçük harf duyarsız login tanımlayıcısı (realm kapsamlı)** — `UNIQUE(realm_id, lower(identifier))`; e-posta anahtar değildir. _Kaynak:_ §17.2.2, §17.2.5; MD-5, OP-12, OP-15. _Durum:_ PD

#### Hesap durumları ve devre dışı bırakma

- [ ] **Devre dışı bırakmanın atomikliği (tek işlem)** — Hesap durumu, oturumlar, refresh aileleri ve `session_epoch` tek işlemde değişir (UDC). Offline projection'lar beyan edilmiş pencerede kalır; UI bu pencereyi ayrıca yazar, "Offline tokens revoked" garanti olarak yazılmaz. _Kaynak:_ §7.7, §8.13, §12.3.1; TN-50, X-L10. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Idempotent devre dışı bırakma** — Zaten sağlaması kaldırılmış hesapta etkisiz. _Kaynak:_ §12.3.1. _Durum:_ belirtilmemiş

#### Hesap kurtarma: yöntemler ve akış

- [ ] **Deneme sınırı ve artan bekleme** — Authenticator başına ≤100 ardışık başarısız deneme; 30 s → 1 s artan bekleme. _Kaynak:_ §12.3.2; TN-59. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Passkey risk sinyalleri** — BS 0→1, AAGUID değişimi, yeni cihazdan ilk doğrulama günlüğe yazılır; alan adı değişimi güvenlik olayıdır. _Kaynak:_ §12.3.2; TN-63. _Durum:_ PD

#### Credential sıfırlama ve yönetimi

- [ ] **Son kimlik doğrulama yönteminin korunması** — Hesaptaki son yöntem şema düzeyinde kaldırılamaz. _Kaynak:_ §12.3.3; MKT-D12, TN-68. _Durum:_ PD (§12.3.3); HYPOTHESIS (MKT-D12)

### K05 Kiracılık, realm ve B2B organizasyonlar

#### Fiziksel izolasyon ve tipli kapsam

- [ ] **Realm/tenant izolasyonu (metamorfik doğrulama)** — Realm A'daki mutasyon realm B'nin authentication/token kararlarını, domain A'daki mutasyon domain B'nin karar vektörünü değiştirmez. _Kaynak:_ §14.8 MR7a/b; SA-45; SAI-6. _Durum:_ belirtilmemiş (FROZEN).

#### Identity Realm

- [ ] **Identity Realm: izole identity ad alanı ve yapılandırması** — Her realm kendi issuer URL'i, JOSE anahtar seti, PII KEK'i, RP ID'si, login ad alanı, kullanıcıları, client'ları, marka/teması, giriş politikası ve enumeration moduna sahiptir; identity plane realm başına izoledir. _Kaynak:_ §2.2.2 #6; §5.14, §5.16, §7.1; §10.1.1; §16.1.1; CR-20; I4; MD-5; T31. _Durum:_ belirtilmemiş.
- [ ] **Realm imza anahtarının realm'e bağlılığı** — Realm JOSE/SAML anahtarı başka realm'in RP'sinde geçerli değildir. _Kaynak:_ §13.2. _Durum:_ belirtilmemiş.
- [ ] **AS metadata realm'e ait** — RFC 8414 AS metadata realm'indir ve Domain Metadata'ya çapraz atıf yapar. _Kaynak:_ §9.15.1 k.2; MD-5; P60. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Realm-yerel kullanıcı, credential ve benzersizlik** — Credential ve login tanımlayıcısı `UNIQUE(realm_id, …)` ile tutulur, küresel kullanıcı tablosu yoktur; iki realm'de aynı e-posta iki ayrı kullanıcıdır, realm'ler arası bağ yalnız `identity-binding` ile. _Kaynak:_ §3.1b #6; §5.6, §5.16, §7.7; §10.1.1; §12.1.1; §16.1.1 tablo; IDI-2; MD-5; TN-2. _Durum:_ gün-1 (§3.1b, §16.1.1); FROZEN (TN-2).
- [ ] **Değişmez realm slug, hostname ve issuer** — Regex'li, değişmez slug/hostname; realm slug/issuer ve `placement_id` gün-1 tablolarında. _Kaynak:_ §3.1b #7, #9; §12.1.2; §16.1.1 tablo; CMP-26; TN-16. _Durum:_ gün-1; FROZEN (TN-16).
- [ ] **Global benzersiz, sistem üretimi `client_id`** — _Kaynak:_ §16.1.1 tablo. _Durum:_ gün-1.
- [ ] **Realm başına politika, tek oturumda birleşmez** — Requirement hedef domain'de değerlendirilir; her realm kendi oturumuna sahiptir. _Kaynak:_ §12.1.1; TN-7. _Durum:_ belirtilmemiş (FROZEN).

#### Realm yönetişimi

- [ ] **Realm oluşturma Genesis'i kurar** — Yönetişim domain'i olmayan realm oluşturulamaz; yoksa realm oluşturma önce domain Genesis'ini kurar. _Kaynak:_ §5.16; §12.1.1 2a; TN-111. _Durum:_ belirtilmemiş (FROZEN).

#### Realm ve tenant başına operasyonel ayarlar

- [ ] **Realm başına Argon2 parametre yükseltme** — _Kaynak:_ §17.5.2; OP-33. _Durum:_ PD.

#### Alan adı ve RP ID

- [ ] **Özel alan adı kararı passkey'den önce; geri dönülemez RP ID uyarısı** — Onboarding ve admin ekranı RP ID / alan adı değişikliğini geri dönülemez olarak işaretler ("users must create new passkeys"). _Kaynak:_ §8.10; §12.1.2, §12.4.2; TN-17; TN-K2; X-L12. _Durum:_ belirtilmemiş (FROZEN, TN-17).
- [ ] **Related Origin Requests (`/.well-known/webauthn`)** — Birinci sınıf destek; 5 etiket limiti UI'da gösterilir. _Kaynak:_ §12.1.2; TN-18. _Durum:_ PD.

### K06 Giriş deneyimi, UI bileşenleri ve markalama

#### Barındırılan ve gömülü giriş yüzeyleri

- [ ] **Hosted login (barındırılan sayfalar)** — Suiss'in barındırdığı giriş, kayıt ve hesap ayarları sayfaları realm alan adında, session cookie ile; tek ayarla tüm akışlar veya uygulama başına mod seçilir. Identity plane yüzeyidir, §8.8–§8.13 kurallarına tabidir. _Kaynak:_ §2.2.2 #7; §8 giriş; §12.4.1; §18.3; CMP-15.6; TN-133; X3, X32. _Durum:_ belirtilmemiş (FROZEN iki mod, TN-133).
- [ ] **Hosted giriş aynı düğüm sözleşmesinin tüketicisi (first-party ayrıcalık yok)** — Suiss'in hosted giriş sayfası, kiracının yazabileceği bir istemciyle aynı düğüm sözleşmesini kullanır. _Kaynak:_ E24 (§12'ye atıf); X-L5, X40. _Durum:_ belirtilmemiş.

#### Düğüm sözleşmesi ve akış modeli

- [ ] **Düğüm sözleşmesi (UI node modeli)** — Sunucu tipli yapı döner, çizim istemcidedir; uydurulan alanlar reddedilir. _Kaynak:_ §12.4.2; TN-106. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Gereksinim modeli (sıra ve ekran kiracıda, kurallar sunucuda)** — Sunucu tamamlanması gereken listeyi ve bozulamaz kuralları tutar, her adımda eksikleri tipli durumla bildirir; kiracı sırayı ve ekranları belirler. _Kaynak:_ §12.4.2; TN-132. _Durum:_ belirtilmemiş (FROZEN).

#### Giriş akışı ve yöntemler

- [ ] **Identifier-first giriş** — Önce tanımlayıcı (kullanıcı adı/e-posta) alınıp yönteme göre yönlendiren akış. _Kaynak:_ §2.2.1; §12.4.1; TN-96. _Durum:_ belirtilmemiş.
- [ ] **Kullanıcı adı + parola birlikte, sonra MFA (identity-first yok)** — Enumeration savunması olarak tanımlayıcı ve parola birlikte alınır (parola akışı için; identifier-first maddesiyle ayrı tutuldu). _Kaynak:_ §10.2.1 madde 1. _Durum:_ belirtilmemiş.
- [ ] **Realm başına kullanıcı enumeration modu** — Realm config'inde toplu/katı koruma modu seçilir; katı modun kısıtları dokümantedir. _Kaynak:_ §7.1; §12.4.1; TN-96. _Durum:_ PD (mod).
- [ ] **Passkey UX** — Passkey kayıt ve giriş kullanıcı deneyimi. _Kaynak:_ §2.2.1. _Durum:_ belirtilmemiş.
- [ ] **Discoverable credential tercihi** — `allowCredentials` sızıntısını önlemek için discoverable credential tercih edilir. _Kaynak:_ CR-40. _Durum:_ belirtilmemiş.
- [ ] **MFA kaydı** — Kullanıcının MFA faktörlerini kaydetme akışı. _Kaynak:_ §2.2.1. _Durum:_ belirtilmemiş.

#### Enumeration direnci ve giriş mesajları

- [ ] **Sabit çıktı / enumeration-nötr giriş ekranı** — Giriş, kayıt ve sıfırlama uç noktaları var/yok/kilitli/devre dışı dallarında aynı HTTP kodu, gövde, boyut, yönlendirme ve doldurulmuş süreyle yanıt verir; tek nötr mesaj "We couldn't sign you in with these details." 15 sızıntı kanalı kapsanır (hata metni, status, uzunluk, URL parametresi, URI probing, yönlendirme, rate limit, sıfırlama, kayıt, `allowCredentials`, SCIM filter, OIDC hata kodu, `prompt=none`, sosyal login, tahmin edilebilir kullanıcı adı). _Kaynak:_ §8.10; §12.3.6, §12.4.1; CR-40; OP-64 madde 5; TN-82, TN-96; X-L1, X34. _Durum:_ belirtilmemiş (FROZEN); sabit çıktı UNDER DECLARED CAPABILITY (X34).
- [ ] **Kimlik doğrulandıktan sonra tam dürüstlük** — Neden gösterilir ("That passkey isn't registered for this account"). _Kaynak:_ §8.15.2; X34. _Durum:_ belirtilmemiş.

#### Markalama ve şablonlar

- [ ] **Tarayıcı tarafı sertleştirme** — CSP, Trusted Types, tip seviyesinde şablon kaçışı; SVG yükleme yok/sanitize (saklanan HTML/SVG enjeksiyonuna karşı). _Kaynak:_ §14.3 advisory tablosu; §14.5 TS profili. _Durum:_ belirtilmemiş.

### K07 Yetki modeli

#### Kayıtlar, corpus ve tek yazma yolu

- [ ] **Identity plane yapılandırması tek yazma yolundan** — IdP ekleme, faktör politikası, client kaydı ve realm anahtar politikası domain action'ıdır; kendi AuthorityDomain'inde ADP `commit` ile meta-Exercise olarak değişir. _Kaynak:_ §13.4 G54; §16.1.1; MD-14; OP-63 madde 4. _Durum:_ belirtilmemiş

#### Roller, gruplar ve rule-shaped seçim

- [ ] **Upstream mapping / mapper'ların reserved requirement (CT3) ile korunması** — Authority-selecting claim üyeliğini toplu değiştirebilen config action'ları (upstream mapping, protocol mapper, JIT/SCIM bağlama) CT3 reserved requirement taşır. Mapper ve scope authority kaynağı değildir, yalnız identity plane claim'i üretir. _Kaynak:_ §10.1.4 not 1; §12.5.2; L6 (ii), TN-117. _Durum:_ belirtilmemiş (FROZEN, §12.5.2)

#### Consequence Tier ve güvence eşikleri

- [ ] **CT karşılama koşulları (identity plane)** — CT1/2/3 phishing-resistant yolları; senkronize passkey ve upstream IdP CT3'ü varsayılan olarak karşılamaz. _Kaynak:_ §10.3.3; IDP-8. _Durum:_ PD

#### Identity plane ile sınır

- [ ] **Assurance vektörü** — `aal`, `loa_eidas`, `phishing_resistant`, `hardware_bound`, `non_custodial`, `uv`, `human_presence`, `app_controlled_factor`, `synced`, `auth_time`; karar vektör üzerinden verilir. _Kaynak:_ §10.1.6. _Durum:_ belirtilmemiş
- [ ] **`phishing_resistant` yalnız channel binding ya da verifier name binding ile** — _Kaynak:_ §10.3.1. _Durum:_ belirtilmemiş
- [ ] **NIST 800-63-4 IAL/AAL/FAL eşlemesi** — _Kaynak:_ §10.3.1. _Durum:_ belirtilmemiş
- [ ] **eIDAS LoA eşlemesi** — Access kendi yöntemleriyle "High" iddia etmez. _Kaynak:_ §10.3.2. _Durum:_ belirtilmemiş

#### Tenant, göç ve devredilmiş yönetim

- [ ] **E-posta/`hd`/`preferred_username`/`upn`/görünen adla yetkilendirme ve birleştirme yasağı** — _Kaynak:_ §12.1.1, §12.3.8; TN-3. _Durum:_ belirtilmemiş (FROZEN)

### K11 Yönetim API'si, konsol, SDK'lar ve geliştirici araçları

#### Yönetim yazma yolu ve yetki modeli

- [ ] **Identity plane yapılandırması yalnız ADP `commit` ile (`idp.*` domain action namespace'i)** — Client, redirect URI, upstream IdP/IdP bağlantısı, SAML SP, SCIM client, şablon, realm ayarı, markalama, anahtar/rotasyon politikası, RP ID değişiklikleri realm'in yönetişim domain'inde ADP commit ile yetkilendirilen `idp.*` action'larıdır (`idp.client.*`, `idp.upstream.*`, `idp.group.*`, `idp.realm.rehome`, `idp.account.*`). _Kaynak:_ §5.12, §5.17; §7.1; §10.1.7; §12.5; E34; F21; IDI-1; MD-14. _Durum:_ belirtilmemiş.
- [ ] **Config değerinin committed ALLOW digest'ine bağlanması** — Bağlı olmayan config yazımı fail-closed reddedilir. _Kaynak:_ §7.1; EI-25. _Durum:_ belirtilmemiş (aday).
- [ ] **İstemci/CIMD kabul politikası değişikliği = domain action (ADP `commit`)** — Yönetim değişiklikleri MD-14 commit'idir; `issuer` değişimi de. _Kaynak:_ §11.3, §11.4.4; AG-4. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Client kaydı (küresel benzersiz opak `client_id`)** — _Kaynak:_ §12.1.2; TN-15. _Durum:_ belirtilmemiş (FROZEN).

### K13 Denetim, kayıt, şeffaflık ve dışa aktarım

#### Identity plane denetim log'u

- [ ] **Başarısız login/MFA/token isteği kaydı** — Örneklemesiz, Katman B sayaç güncellemesiyle aynı tx. _Kaynak:_ §17.6.6; OP-39. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).

### K14 Sinyaller, gözlemlenebilirlik ve analitik

#### Risk ve tehdit sinyalleri

- [ ] **Sign count ihlali sinyal Claim'i; BS 1→0 uyarısı** — _Kaynak:_ §10.2.4. _Durum:_ belirtilmemiş.

#### Operasyon sinyalleri, metrikler ve alarmlar

- [ ] **Hash semaforu metriği (`max_hash_threads`, `hash_await_warn_time`)** — _Kaynak:_ §10.2.1. _Durum:_ belirtilmemiş.

### K15 Güvenlik ve kriptografi

#### Kodlama, kanonikleştirme ve token doğrulama

- [ ] **`private_key_jwt` korumaları** — jti replay cache, aud kontrolü, hata yanıtında `Date` header. _Kaynak:_ §10.4.5. _Durum:_ belirtilmemiş.

#### Veri şifreleme ve sır yönetimi

- [ ] **Credential store şifreli sütun (kiracı KEK)** — Parola hash, TOTP secret, recovery code, cihaz anahtarları. _Kaynak:_ §10.1.7. _Durum:_ belirtilmemiş.
- [ ] **Client secret / API anahtarı saklama** — ≥ 256 bit, sunucu üretimli, SHA-256 veya HMAC + sabit zamanlı karşılaştırma. _Kaynak:_ CR-38. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Argon2id parametreleri** — m=7 MiB, t=5, p=1 (CR-36). _Kaynak:_ §12.3.6; CR-36. _Durum:_ belirtilmemiş.

#### Platform ve çalışma zamanı sertleştirmesi

- [ ] **Proxy başlığı güveni varsayılan kapalı** — Açıksa güvenilir proxy listesi zorunlu. _Kaynak:_ §17.9.6. _Durum:_ belirtilmemiş.

#### Kiracı izolasyonu ve kimlik tanımlayıcıları

- [ ] **Köken izolasyonu (alt alan adı başına realm)** — Çerez/XSS izolasyonu. _Kaynak:_ §12.1.2; TN-10. _Durum:_ belirtilmemiş (FROZEN).

#### Hız sınırlama ve yük atma

- [ ] **İki katmanlı rate limiting (zorunlu)** — Katman A yaklaşık (governor/GCRA, gateway, yerel); Katman B kesin (Redis sınıfı / PostgreSQL atomik GCRA sayaç); anahtarlar IP, kullanıcı, IP+kullanıcı; `X-Forwarded-For` sağdan güvenilir proxy sayısı kadar; güvenlik ve hesap limitleri node-yerel uygulanmaz. _Kaynak:_ §10.2.1 (→ §12); §10.6; §13.7.9; §14.6; §17.5.5; OP-35; T33. _Durum:_ FROZEN TECHNICAL / POLICY DEFAULT.
- [ ] **Kota/hız sayaç boyutları; limiter arızası ALLOW'a dönmez** — Tenant, realm, domain boyutunda; identity uç noktalarında ek aktör/IP boyutu; limiter arızası fail-closed. _Kaynak:_ §12.1.3; §17.5.5; MD-8; TN-24. _Durum:_ PD (değerler), FROZEN (fail-closed).
- [ ] **Hesap + IP kapsamlı sınır** — _Kaynak:_ §12.3.6; TN-82. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **IP başına üstel kara liste (7→60 s … 25→24 saat)** — _Kaynak:_ §10.2.1 madde 4. _Durum:_ PD.

#### Hesap numaralandırma ve kimlik bilgisi saldırıları

- [ ] **Enumeration savunması: sahte Argon2 yerine ucuz kapı (Rauthy modeli)** — Kimlikten bağımsız IP/ASN token bucket + küresel semafor, sabit boyutlu hash işçi havuzu, adaptif gecikme/sabit taban, sıfırlamada hesap başı sınır. _Kaynak:_ §10.2.1; §12.3.6; IDP-3; TN-83. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **Enumeration regresyon süiti** — Login, kayıt, sıfırlama, MFA enroll, SCIM, device flow, OIDC hata yollarında durum kodu, gövde, header, redirect, p50/p95 karşılaştırması. _Kaynak:_ §10.2.1 madde 5. _Durum:_ belirtilmemiş.
- [ ] **Passkey numaralandırma koruması** — Boş `allowCredentials`, deterministik hayali credential ID. _Kaynak:_ §12.4.1; TN-97. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Davranışsal biyometri ve duygu çıkarımı yasağı (risk girdisi)** — _Kaynak:_ §12.2.4; TN-47. _Durum:_ belirtilmemiş (FROZEN).

#### Güvenlik ilkeleri: fail-closed, downgrade, compromise

- [ ] **İmzalı kimlik çıktısı yalnız tamamlanmış authN'den** — _Kaynak:_ §10.6.1 madde 10; IDI-7. _Durum:_ belirtilmemiş.

#### Kimlik protokolleri güvenliği

- [ ] **RP ID değişimi geri dönülemez CT3 domain action** — _Kaynak:_ §10.2.4; IDI-4; IDP-5. _Durum:_ belirtilmemiş (karar FROZEN).

### K16 Gizlilik, rıza ve uyum

#### Takma adlar ve bağlanamazlık

- [ ] **Minimizasyon ve pseudonymity (genel ilke)** — Pairwise `sub`, domain-pairwise PartyRef ve opaque ref ile. _Kaynak:_ §14.9; MD-10. _Durum:_ belirtilmemiş.
- [ ] **Varsayılan pairwise `sub` (OIDC `sub`, SAML persistent NameID)** — Gizlilik amaçlı bağlanamazlık (NIST 800-63C PPII); public `sub` client başına opt-in'dir. _Kaynak:_ §9.9.3 k.8; MD-10; P-ID-10. _Durum:_ PD.
- [ ] **E-posta asla anahtar değil** — _Kaynak:_ IDI-2; MD-5; P-ID-9. _Durum:_ belirtilmemiş.

#### Veri minimizasyonu ve seçici açıklama

- [ ] **RP'ye minimum veri** — Tam profil, iç PartyID ve diğer RP'lerdeki `sub` paylaşılmaz. _Kaynak:_ §7.9.15.2. _Durum:_ belirtilmemiş.

#### İfşa kapsamı ve görünürlük

- [ ] **Kimliği doğrulanmamış viewer'a hesap bilgisi sızdırılmaz** — _Kaynak:_ X34; XI-24. _Durum:_ belirtilmemiş.

#### Mevzuat ve standart eşlemeleri

- [ ] **Uygulama-kontrollü faktör assurance sınıfı (TR ödeme)** — Türkiye ödeme senaryoları için ayrı assurance sınıfı. _Kaynak:_ MD-11. _Durum:_ belirtilmemiş.

### K17 Dağıtım, operasyon, yüksek erişilebilirlik ve felaket kurtarma

#### Dağıtım biçimleri ve profiller

- [ ] **SQLite yalnız tek node identity kurulumu** — Identity plane, tek node, ≈1.000 kullanıcı altı; yalnız T8'in izin verdiği yerde; authority plane PostgreSQL ≥ 18. _Kaynak:_ §4.8 eksen 7; §17.9.1; OP-48; T8; T36. _Durum:_ PD (eşik).

#### Performans ve kapasite

- [ ] **Argon2 için `spawn_blocking` + çekirdek sayısı mertebesinde semafor** — _Kaynak:_ §4.10. _Durum:_ EA.

### K18 Açık kaynak, ticari model ve paketleme

#### Paketleme

- [ ] **Identity plane'in tek başına / tam IdP olarak satılabilmesi** — Identity plane authority plane olmadan da (tam IdP olarak) satılabilir; authority semantiği ve must-never'ler yine geçerlidir. _Kaynak:_ §1.3, §18.8, §18.8.2; H13b. _Durum:_ HYPOTHESIS.

### K19 Geliştirme ve kalite güvencesi

#### Dış conformance süitleri ve interop

- [ ] **OIDF conformance suite ilk günden CI'da** — OIDC Basic/Config/Dynamic, FAPI 2.0 SP + Message Signing, FAPI-CIBA, Logout. _Kaynak:_ §10.4.7, §16.4.0, §18.13; B9, OP-3. _Durum:_ gün-1 (§16.4.0); §18.13'e göre Faz 1.
- [ ] **Karşılaştırmalı (differential) protokol testi** — oidc-provider, openid-client, FIDO araçları, xmlsec/Shibboleth/SimpleSAMLphp, SCIM, OpenLDAP, Wycheproof. _Kaynak:_ T42. _Durum:_ belirtilmemiş (FROZEN; referans listesi PD).

#### Protokol, kiracı ve bileşen güvenlik testleri

- [ ] **Fosite hata sınıfları regresyon derlemi** — _Kaynak:_ §10.4.7; MD-1. _Durum:_ belirtilmemiş.
- [ ] **AS reconsider tetikleyicisi** — 6. ayda 2× gecikmede Go/Fosite değerlendirmesi. _Kaynak:_ §10.4.7; MD-1. _Durum:_ WATCH.
- [ ] **DPoP replay conformance testleri** — _Kaynak:_ §10.4.3. _Durum:_ belirtilmemiş.

### Bu aşamada doğrulanacak sınırlar

#### Ürün kapsamı

- [ ] **Headless kimlik altyapısı / uygulama içi kütüphane kategorileri hedeflenmez** — _Kaynak:_ §4.5. _Durum:_ belirtilmemiş.
- [ ] **Yönetilen broker kendi identity plane'i için kullanılmaz** — _Kaynak:_ §4.9. _Durum:_ belirtilmemiş.
- [ ] **Kiracının kendi AS'si gün-1'de ürün özelliği değil** — _Kaynak:_ TN-8. _Durum:_ gün-1'de yok.

#### Kimlik ve protokol

- [ ] **Yeni identity protokolü veya token formatı icat edilmez** — MCP, OAuth, ID-JAG, WIMSE, SPIFFE, A2A taşıyıcıdır. _Kaynak:_ §11.0 #3; AG-24; L20; P-ID-3. _Durum:_ belirtilmemiş.
- [ ] **Implicit grant yok** — _Kaynak:_ §10.4.1; §16.4.10; IDP-7; RR-18; TN-34; TN-101. _Durum:_ belirtilmemiş.
- [ ] **ROPC (password grant) yok, göç istisnası da yok** — _Kaynak:_ §10.4.1; §16.4.10; IDP-7; RR-18. _Durum:_ belirtilmemiş.
- [ ] **PKCE `plain` yok** — _Kaynak:_ §10.4.1. _Durum:_ belirtilmemiş.
- [ ] **Token Binding yok (ölü standart)** — _Kaynak:_ §10.4.3; §12.2.1. _Durum:_ belirtilmemiş.
- [ ] **OIDC Session Management (iframe) yok** — _Kaynak:_ §10.4.6; IDP-24. _Durum:_ belirtilmemiş.
- [ ] **Device code ve first-party apps varsayılan kapalı** — _Kaynak:_ TN-35; TN-101. _Durum:_ varsayılan kapalı.
- [ ] **Regex/wildcard/desen `redirect_uri` eşleşmesi yok** — Opt-in olarak bile yoktur; loopback dışında gevşetme yapılmaz. _Kaynak:_ §11.4.5 #3; §17.9.6; AG-6; must-never #16. _Durum:_ belirtilmemiş.
- [ ] **Issuer `Host` başlığından türetilmez** — _Kaynak:_ §17.9.6. _Durum:_ belirtilmemiş.
- [ ] **Kısa ömürlü (60 s) DPoP nonce modeli yok** — _Kaynak:_ §12.2.1; MD-18. _Durum:_ belirtilmemiş.
- [ ] **Refresh reuse'ta sunucu tarafı ardışık-kullanım toleransı yok** — _Kaynak:_ TN-31. _Durum:_ belirtilmemiş.

#### Token modeli

- [ ] **Uzun ömürlü token + sinyal güdümlü iptal modeli yok** — Örneğin 28 saatlik access token reddedildi. _Kaynak:_ §5.11; §9.9.3 k.4; MD-7; P49; TN-37. _Durum:_ belirtilmemiş.
- [ ] **Audience'sız veya çoklu audience'lı token yok** — `resource` yoksa varsayılan kaynak da yoktur. _Kaynak:_ §9.9.3 k.1; AG-8. _Durum:_ belirtilmemiş.
- [ ] **OAuth scope authority taşımaz** — Scope yalnız etikettir; authority-bearing scope üretilmez, RAR authority'nin tek yeridir. _Kaynak:_ §9.4 A; §11.21.4; L24; R3. _Durum:_ belirtilmemiş.
- [ ] **Session cookie'ye token konmaz** — _Kaynak:_ CR-43. _Durum:_ belirtilmemiş.
- [ ] **Kiracı token'ı Suiss realm issuer/anahtarıyla asla basılmaz** — _Kaynak:_ TN-8. _Durum:_ belirtilmemiş.
- [ ] **Offline token'lar tek işlemde/atomik iptal edilmez ve bu iddia edilmez** — "Active sign-ins ended" denmez. _Kaynak:_ N-40; TN-50. _Durum:_ belirtilmemiş.

#### Yetki modeli

- [ ] **Authority plane identity kaydı yazmaz, authenticator bağlayamaz, PartyID değiştiremez** — _Kaynak:_ §10.1.1. _Durum:_ belirtilmemiş.

#### Karar ve tutarlılık

- [ ] **60–300 s fail-open/bozulmuş mod penceresi yok; introspection 503 dönmez** — Erişilemezlikte `active=false` döner; `X-Access-Degraded` yoktur. _Kaynak:_ §6.2; §7.7; §9.9.3 k.5; G48; OP-45; OPI-3; P-ID-8; U37. _Durum:_ belirtilmemiş.
- [ ] **Backend kesintisinde/failover'da refresh `invalid_grant` dönmez** — _Kaynak:_ G50; OP-26. _Durum:_ belirtilmemiş.

#### Onay ve kanıt

- [ ] **OAuth/MCP consent kaydı authority değil** — _Kaynak:_ §9.14.5 k.3. _Durum:_ belirtilmemiş.

#### Yönetim, operatör ve destek erişimi

- [ ] **Master realm ("ana kiracıdan her şeyi yönet") modeli yok** — _Kaynak:_ TN-119. _Durum:_ belirtilmemiş.

#### Kiracı genişletilebilirliği

- [ ] **Kiracı kodu sunucuda/IdP sürecinde çalışmaz** — Şablon, betik, kural, hook, eylem, ifade politikası, token-claim ifadesi dahil Turing-tam kiracı kodu yoktur. _Kaynak:_ §16.1.1; F23; LFP-24; OP-6; TN-106; TN-135; must-never #15. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Çalışma zamanında yorumlanan auth flow konfigürasyonu yok** — _Kaynak:_ §4.3; LFP-23. _Durum:_ belirtilmemiş.
- [ ] **Akış kompozisyonu (sunucu tarafı adım dizme) kiracıya kapalı** — _Kaynak:_ TN-105. _Durum:_ belirtilmemiş.
- [ ] **Rezerve protokol claim'leri kiracı tarafından tanımlanamaz/gölgelenemez** — _Kaynak:_ must-never #18. _Durum:_ belirtilmemiş.

#### Kiracı ve hesap modeli

- [ ] **Küresel kullanıcı tablosu ve küresel `UNIQUE(email)` yok** — Hücreler arası kullanıcı verisi replikasyonu da yoktur. _Kaynak:_ OP-30; TN-2; TN-20. _Durum:_ belirtilmemiş.
- [ ] **Tek oturumda farklı realm politikalarının birleştirilmesi yok** — _Kaynak:_ TN-7. _Durum:_ belirtilmemiş.
- [ ] **Realm slug/hostname değiştirme yok** — _Kaynak:_ TN-16. _Durum:_ belirtilmemiş.
- [ ] **Tanımlayıcı yeniden kullanımı yok; SCIM DELETE sonrası 410 yok (yalnız 404)** — _Kaynak:_ INV-32; TN-76. _Durum:_ belirtilmemiş.
- [ ] **Suiss passkey'li realm'i kendi alan adında RP ID ile açmaz** — _Kaynak:_ §18.1. _Durum:_ belirtilmemiş.

#### Kimlik doğrulama yöntemleri

- [ ] **Dummy (sahte) Argon2 hash hesaplaması yok** — Var olmayan kullanıcı için de yapılmaz. _Kaynak:_ §10.2.1; CR-36; IDP-3; MD-18; OP-33; SA-31; TN-83. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Identity-first login yok** — _Kaynak:_ §10.2.1; IDP-3. _Durum:_ belirtilmemiş.
- [ ] **Parola kompozisyon kuralı, periyodik rotasyon ve güvenlik sorusu yok** — _Kaynak:_ §10.2.1. _Durum:_ belirtilmemiş.
- [ ] **Platform biyometrisi tek başına güçlü unsur değildir; anne kızlık soyadı/kimlik bilgisi doğrulama unsuru değil (TR)** — _Kaynak:_ §5.3; §10.3.4. _Durum:_ belirtilmemiş.
- [ ] **WebAuthn `devicePubKey` uzantısı kullanılmaz; largeBlob'a bağımlılık yok** — _Kaynak:_ §10.2.4; §12.2.1. _Durum:_ belirtilmemiş.
- [ ] **PRF çıktısı sunucuda saklanmaz** — _Kaynak:_ §10.2.4. _Durum:_ belirtilmemiş.
- [ ] **Davranışsal biyometri / duygu çıkarımı yok** — _Kaynak:_ TN-47. _Durum:_ belirtilmemiş.
- [ ] **reCAPTCHA yok; bulmaca CAPTCHA sert kapı değil** — _Kaynak:_ TN-81; TN-107. _Durum:_ belirtilmemiş.
- [ ] **Giriş/kayıt yüzeyinde üçüncü taraf takip kodu yok** — _Kaynak:_ IDP-36. _Durum:_ belirtilmemiş.
- [ ] **Kullanıcı seçimli client secret yok; client secret için Argon2 yok** — _Kaynak:_ CR-38. _Durum:_ belirtilmemiş (FROZEN).

#### Kriptografi

- [ ] **JWE `RSA1_5` / SAML `xmlenc#rsa-1_5` yok** — _Kaynak:_ §10.6.1; CR-4; CR-5. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Enumeration'ı önlememe (Kanidm seçimi) reddedildi** — _Kaynak:_ CR-40. _Durum:_ belirtilmemiş (FROZEN).

#### Veri, depolama ve yüksek erişilebilirlik

- [ ] **Node-yerel hesap bazlı limit yok** — _Kaynak:_ OP-35. _Durum:_ belirtilmemiş.

#### Kullanıcı arayüzü ve terminoloji

- [ ] **OAuth scope listesi ve "Authorize *App*" düğmesi son kullanıcı UI'ında yok** — _Kaynak:_ §8.11; X27. _Durum:_ belirtilmemiş.

## Aşama 6 — İki plane'in bağlanması

Identity→authority Claim geçişi, projection'lar, PEP SDK, Offline Verifier, status list, verifier profilleri, Frontend API'nin temeli.

### Spec dışı ön koşullar

- [ ] **PEP conformance test koşumu** — fail-open yokluğu, 5xx = DENY ve diğer PEP kurallarının otomatik testi.
- [ ] **Güvenilir saat ve sayaç emülatörü** — Offline Verifier'ın horizon, saat kayması ve sayaç adımlarını donanımsız test etmek için.
- [ ] **Kernel Wasm/FFI performans ölçümü** — Kaynak: OQ-MD4.

### K01 Kimlik doğrulama yöntemleri

#### Genel model ve tipli sonuç

- [ ] **Identity plane faktörlerinin Access assurance sınıfına eşlenmesi** — AAL, uygulama-kontrollü faktör ve parola/OTP/push §13.7.3 satırına eşlenir. Kanonik olan §13.7.3'tür; IDP-8 tablosu onu yalnız daraltır. _Kaynak:_ §13.7.3; IDP-8, MD-11. _Durum:_ PD.
- [ ] **CT'ye göre authenticator sınıfı** — CT1 için phishing-resistant (WebAuthn/passkey; ödemede SPC), CT2 için buna ek olarak UV, CT3 için UV ile birlikte donanıma bağlı ve non-custodial authenticator gerekir. _Kaynak:_ §13.7.3. _Durum:_ PD.
- [ ] **Phishing-resistant authenticator zorunluluğu (Access exercise'ları)** — CT0 dahil her Access exercise'ında actor'ün authentication Claim'i en az phishing-resistant bir authenticator'dan (WebAuthn/passkey; ödemede SPC) gelmelidir. Parola, TOTP/SMS OTP veya push tek başına hiçbir CT'yi karşılamaz; bu durumda Access step-up (REQUIRE_ACTION) ister. _Kaynak:_ §13.7.3 (CT0 dipnotu); N-45, SEC10, SEC26. _Durum:_ PD.
- [ ] **Human presence şartı** — Approval ile CT2/CT3 için insan varlığı (human presence) zorunludur. _Kaynak:_ §13.7.3. _Durum:_ PD.
- [ ] **Human presence binding'i** — Human presence isteyen bir contribution term'i, binding'i o contribute Exercise'ının AAS digest'i olan bir authentication Claim'i ister. _Kaynak:_ §6.6; SI-5. _Durum:_ belirtilmemiş.

#### Passkey / WebAuthn: yöntem ve güvence

- [ ] **Passkey/WebAuthn assertion ile onay** — Onay ve authority act'leri tek bir WebAuthn/passkey assertion ile verilir. Challenge H(AAS)'dir; sonuç, binding'i statement digest'i olan bir `authentication` Claim'idir. _Kaynak:_ §9.2 AP-6, §9.3A, §9.14.1. _Durum:_ belirtilmemiş (FROZEN, P29).

#### Parola

- [ ] **Parola pepper'ı** — KMS/HSM'de tutulan pepper bir AES-GCM katmanı olarak eklenebilir; salt ≥16 bayttır ve pepper kiracı KEK hiyerarşisine bağlıdır. Pepper sürümü hash kaydında saklanır; rotasyon sonraki başarılı girişte yeniden hash ile yapılır. _Kaynak:_ §10.2.1; §15.14; CR-18, CR-37, IDP-3. _Durum:_ PD (IDP-3); §15.14'e göre EA (opsiyonel).

#### Step-up ve yeniden doğrulama

- [ ] **Step-up (taze kimlik doğrulama) ceremony'si** — Bir yüzey değil etkileşimdir; S1, S3 veya domain akışı içinde inline açılır. RequirementTerm'den gelir (authentication Claim, binding = actor Instance / intent digest, assurance, freshness). _Kaynak:_ §8.5, §8.17.5.4; TN-O3, X29. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Korunan eylem (protected action) step-up'ı** — Korunan eylemler bir yetki değil, Claim · authentication · freshness requirement'ıdır. Aday liste (kalıcı silme, imza anahtarı rotasyonu, IdP bağlantı ayarı) CT3 sınıfındadır. _Kaynak:_ §5.9, §6.2; INV-10. _Durum:_ belirtilmemiş.
- [ ] **Step-up tazeliği (freshness)** — CT1 ≤ 15 dk; CT2 ≤ 5 dk ve intent digest'e (H(AAS)) bağlı; CT3 ≤ 5 dk ve H(AAS)'e bağlı. _Kaynak:_ §13.7.3. _Durum:_ PD.
- [ ] **RFC 9470 step-up köprüsü** — Yalnız authentication-strength eksikliğinde RS/MCP server `401 insufficient_user_authentication` döner; `max_age` zorunlu, `acr_values` tavsiyedir. Bu challenge authority değildir; CT2+ intent-bound term'ler REQUIRE_ACTION + AAS ile karşılanır. _Kaynak:_ §4.11; §8.5, §8.17.5.4; §9.4 A, §9.9.5; §12.2.3; TN-44, TN-O3, X-L4. _Durum:_ belirtilmemiş (ADOPT; FROZEN).
- [ ] **Step-up yetki vermez** — Step-up yalnız requirement'ı karşılar; "Signed in again" ≠ "allowed". _Kaynak:_ §8.17.5.4; §12.2.3; X29. _Durum:_ belirtilmemiş.
- [ ] **Yeniden doğrulama yalnız iki kaynaktan** — İstem yalnız bir RequirementTerm'den veya identity plane oturum politikası olayından gelir; agresif/bağlamsız yeniden doğrulama yasaktır. _Kaynak:_ §8.17.5.4; X-L3. _Durum:_ belirtilmemiş.
- [ ] **Risk tabanlı step-up (identity plane)** — Identity plane risk sinyaline göre ek doğrulama ister; gereklilik authority plane'de RequirementTerm'dir. Risk yalnız daraltır, yetki üretmez; kararı yine ADP verir ve risk motoru arızası ALLOW'a dönmez (fail-closed). Ayrı bir risk/fraud motoru ürünü değildir. _Kaynak:_ §2.4; §2.5; §7.6; §9.16.2 k.4; §18.2; CI-2, E22, L28, MD-8, MD-13. _Durum:_ belirtilmemiş.
- [ ] **Identity plane giriş-risk sinyalleri (bot, velocity, impossible travel)** — Bu sinyaller yalnız step-up, deny veya `risk.*` Claim üretir, authority vermez. _Kaynak:_ §7.6 (TN-O4), §7.9.12.1. _Durum:_ belirtilmemiş.
- [ ] **Actor-binding tazeliği oturum ömrüne bağlı** — Oturum ömrü (boşta kalma / mutlak süre) dolduğunda bağlı Instance actor-binding tazeliğini karşılayamaz. _Kaynak:_ §7.1. _Durum:_ PD.

#### Kurtarma ve yeni authenticator

- [ ] **Yeni authenticator / designation soğuması (SEC18 GRACE)** — Yeni bir authenticator-binding veya issuer designation (ör. kurtarma sonrası) ilk 24 saat CT2+ requirement'larını karşılamaz; Party'nin Changes görünümünde görünür. Eylemde "Needs: a sign-in method added more than 24 h ago (available 14:00 tomorrow)" gösterilir. _Kaynak:_ §7.7; §8.10, §8.13; §13.7.3, §13.7.7; SEC18, SI-13, X38, X-L9. _Durum:_ PD (SEC18 POLICY DEFAULT).

### K02 Kimlik protokolleri ve federasyon

#### Genel kapsam ve identity plane sınırları

- [ ] **Protokol scope'ları ile kaynak scope'larının ayrımı** — `openid`, `profile`, `offline_access` gibi scope'lar ve claim release consent'i identity plane semantiğidir. Kaynak erişimi ifade eden her scope/`authorization_details` `grant.issue` + `projection.issue` sonucudur. _Kaynak:_ §2.2.2 #2; §7.1; L24; S-1, S-2. _Durum:_ belirtilmemiş.

#### Token exchange ve delegasyon

- [ ] **AuthZEN OAuth 2.0 token verme profili** — Final olursa `projection.issue`'nun AuthZEN görünümü olarak PROFILE adayıdır. _Kaynak:_ §9.4.2. _Durum:_ WATCH (talep üzerine).

#### Yetkilendirme isteği ve token uzantıları

- [ ] **RAR (RFC 9396) — Access tipleri** — Authority yalnız RAR `authorization_details` içinde typed taşınır; RAR envelope'un taşıyıcısıdır, semantiği Access'tedir: `type` = ActionRef, `authorization_details` ↔ IntentEnvelope, schema digest ayrı zorunlu üye, `kind=intent|bounds`. Tip başına JSON şeması; onayda insan okunur gösterim (AAS render); encoding protokol aşamasına bırakılmıştır. _Kaynak:_ §2.2.1; §7.9.3.2; §9.4 A, §9.13.5; §10.4.3; §11.21.1 #12; E12; L24; P25; R3. _Durum:_ belirtilmemiş (EXTEND, FROZEN P25).
- [ ] **RAR ortak alanlarının yok sayılması** — `locations`, `actions`, `datatypes`, `identifier`, `privileges` Access sınırı ifade etmez; `locations` yalnız RFC 8707 `resource` ile tutarlı bir ipucudur. _Kaynak:_ §9.13.5; P25. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **RAR `authorization_details` ile authority taşıyan access token** — Domain operasyonel anahtarıyla imzalanır; `aud` tek RS (RFC 8707), `cnf` zorunlu. _Kaynak:_ §12.1.2, §12.2.1; TN-14, TN-27. _Durum:_ belirtilmemiş (FROZEN).

#### Algoritmalar, imza ve şifreleme

- [ ] **Harici issuer imzalarının ingest doğrulaması (RSA dahil)** — Harici issuer'ların RSA (≥ 2048, ≤ 8192) ve diğer imzaları yalnız doğrulama amacıyla kabul edilir; `EdDSA` tanımlayıcılı issuer `source-not-accepted` sınıfında kalır. _Kaynak:_ MD-3 tablosu; CR-5, CR-9. _Durum:_ belirtilmemiş (FROZEN).

#### MCP, ID-JAG ve ajan protokolleri

- [ ] **RFC 9200 ACE-OAuth** — Kısıtlı/edge verifier için opsiyonel binding olarak profillenir. _Kaynak:_ §9.4 E. _Durum:_ belirtilmemiş (PROFILE).

#### Upstream IdP ve kimlik federasyonu

- [ ] **External IdP ile authority plane kullanımı (use-scoped kabul)** — Authority plane harici IdP'ler ve external workload identity (Entra, Okta, Google, Keycloak, SPIFFE…) ile Access identity plane'iyle aynı Acceptance koşullarıyla çalışır; enterprise'da harici IdP varsayılandır. Dış IdP yalnız kabul edildiği use kadar güvenilir; `acceptance.amend` cutoff ile durdurulur. _Kaynak:_ §2.2; §13.2; §18.2; P-ID-2; B7; E18; F3; H13a. _Durum:_ belirtilmemiş (FROZEN, B7).
- [ ] **Use-typed IdP Acceptance'ları** — Authentication trust (actor-binding), identity claim acceptance (predicate-input), authority-selecting acceptance (subject-selection, reserved) ve foreign authority acceptance (reserved) ayrı Acceptance'lardır; biri diğerini ima etmez. _Kaynak:_ §7.9.11.1; C18; E18; INV-15. _Durum:_ belirtilmemiş (E18: FROZEN).
- [ ] **N:M realm ↔ domain eşlemesi (`realm_domain_binding`)** — Realm'in kimlik Claim'leri birden çok domain'de Acceptance ile tüketilir. _Kaynak:_ §12.1.1; TN-4. _Durum:_ PD (biçim), FROZEN (Acceptance zorunluluğu).
- [ ] **Claim Ingest — protokol başına taşıyıcı alan eşlemesi** — WebAuthn, OIDC, SAML, SCIM, SCIM SET, LDAP, SPNEGO, mTLS/PIV, cihaz attestation için Claim sınıfı/subject/issuer/zorunlu alan tablosu; eşleme dışı alan girmez. _Kaynak:_ §10.1.2; IDP-1. _Durum:_ belirtilmemiş (karar FROZEN).

#### Authority federasyonu (domain'ler arası)

- [ ] **Foreign Authority Proof** — B domain'i A'nın PAP'ını Claim olarak, yalnız `foreign-authority` Acceptance ile kullanır. Üç kontrol (kriptografik geçerlilik, kapsam için issuer güveni, semantik kapsama) + tazelik koşulu yapılır. _Kaynak:_ §9.15A.2; P31. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Home budget'ın home'da draw edilmesi** — Cross-domain consumption-bearing action için PAP `offline_slice` taşımak zorundadır; yoksa home'da online exercise gerekir. Target'ın BudgetTerm'i ek bir daraltmadır. _Kaynak:_ §9.15A.3; INV-21; P31. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Domain sınırında revocation zinciri** — A'daki revoke PAP status'u üzerinden B'de tazelik koşulunu bozar; B kendi bridging Grant'ını veya Acceptance'ını her an yerel olarak revoke edebilir. _Kaynak:_ §9.15A.3. _Durum:_ belirtilmemiş.

### K03 Oturum ve token yönetimi

#### Login oturumu

- [ ] **Agresif yeniden kimlik doğrulamadan kaçınma** — Yüksek CT tazeliği eylem anında step-up ile sağlanır. _Kaynak:_ §12.2.1; TN-36. _Durum:_ PD.
- [ ] **Oturum ↔ Instance bağı (kardinalite)** — Identity plane oturumu, aynı KeyBinding üzerinden cihaz ve domain başına en çok bir insan Instance'ına bağlanır. Oturum yenilemek yeni Instance değildir. _Kaynak:_ §5.1 eki, §5.6, §7.1, §7.2; §12.0.3, §12.12/7; INV-13. _Durum:_ belirtilmemiş.

#### Oturum yüzeyi ve çıkış

- [ ] **Logout / sign-out semantiği** — Sign-out identity plane oturumunu bitirir ve bağlı Instance'ları (tüm domain'lerde) `instance.terminate` ile sonlandırır; kesin iptal `session_epoch` artışıyladır. Bu temizliktir: başka cihazlar, Instance'lar ve delegation'lar etkilenmez ve ekran bunu söyler ("Sign out" bu cihaz için). _Kaynak:_ §2.2.1; §5.1 eki, §5.6, §7.1; §8.3, §8.5 S10; §10.4.6; §12.0.3; X36, XI-23. _Durum:_ belirtilmemiş.

#### Epoch'lar ve hızlı iptal

- [ ] **`key_epoch` anahtar penceresi** — Domain Metadata / realm JWKS rotasyonu ve operasyonel anahtar penceresidir (varsayılan 1 sa, üst sınır 24 sa). _Kaynak:_ §5.11, §7.2; §9.11.1; MD-6, MD-7, P56. _Durum:_ PD.
- [ ] **"Hızlı" ve "katı" (strict) iptal profilleri** — Strict profil (introspection zorunlu, 250 ms hedef) admin/finans RS'lerinde; diğerlerinde hızlı profil (JWT 5 dk) kullanılır ve introspection yapmayan RS'te iptal token ömrüyle sınırlıdır. Strict → hızlı geçiş CT3'tür (çıkarım). _Kaynak:_ §13.7.9; §17.5.1; HL-22, MD-7, OP-32. _Durum:_ PD; §17.5.1'e göre EA.
- [ ] **Ölçeklenebilir iptal: status list taşıyıcısı** — _Kaynak:_ §11.20. _Durum:_ belirtilmemiş.
- [ ] **Onay iptali = bağlı Grant'ın `grant.revoke`'u** — Onay kaydı ve refresh ailesi temizlenir; canlı access token'lar horizon'a kadar yaşayabilir, introspection/SSF hızlandırıcıdır (UDC). _Kaynak:_ §11.4.5 #29, §11.6. _Durum:_ belirtilmemiş.

#### Token sınıfları ve karar modeli

- [ ] **İki token sınıfı: authority taşıyan projection vs. kimlik iddiası** — Authority taşıyan her token (RAR'lı AT, refresh, exact-intent/bounds) `projection.issue` ürünüdür ve holder-bound'dur. Kimlik iddiası token'ları (ID token, SAML/WS-Fed assertion, logout token, LDAP/SPNEGO oturumu, protokol-scope-only AT) authority taşımaz ve kimlik-iddiası profiline tabidir. _Kaynak:_ §9 bölüm notu; §10.4; E39, MD-7. _Durum:_ belirtilmemiş.
- [ ] **İki katmanlı token modeli** — Kimlik iddiaları (Claim), bounds token (kaba authority) ve ince karar (ADP commit / exact-intent) ayrı katmanlardır. _Kaynak:_ §9.9.6; P55. _Durum:_ belirtilmemiş (FROZEN, türetilmiş).
- [ ] **Her token issuance bir karar** — Token endpoint ve RFC 8693 exchange birer `projection.issue` Exercise Request'idir; ALLOW yoksa token da yoktur. _Kaynak:_ §9.9. _Durum:_ belirtilmemiş (FROZEN P17).
- [ ] **Projection yenileme / refresh = yeni karar** — Projection yenilemek bir renewal değil, yeni bir `projection.issue` kararıdır (FAPI'de rotasyonsuz refresh dahil); revocation'dan sonra refresh DENY olur. _Kaynak:_ §6.5; §9.9, §9.9.3 k.6; §10.4.2, §10.5.1; L19, P17, PI-10. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Exact-intent token** — OAuth AT + RAR `kind=intent`: tek intent digest, kısa horizon, count = 1; authority yalnız `authorization_details`'tedir. Örnek kullanım MCP tool çağrısıdır. _Kaynak:_ §9.9.1; §11.2, §11.21.4; P17. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Bounds token** — OAuth AT + RAR `kind=bounds`: AuthoritySet ∩ Mandate projection'ı, kısa ValidityContract ve status ref taşır. Consumption-bearing action için yeterli değildir. _Kaynak:_ §9.9.1, §9.9.6; §11.2, §11.21.4; P17. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Token'daki rol claim'i bir Grant projection'ıdır** — Rol claim'i ⊆ (AuthoritySet ∩ Mandate) ve `projection.issue` ile üretilir. Grup/org üyeliği ise yalnız identity Claim'idir; RP'ye authority kanıtı olarak sunulmaz. _Kaynak:_ §5.3, §5.4, §5.17; INV-33, S-1. _Durum:_ belirtilmemiş.
- [ ] **Claim mapper kısıtları** — Mapper authority üretemez; kiracı yalnız önceden tanımlı Claim kümesinden seçer ve mapper değişikliği ADP `commit` gerektirir. _Kaynak:_ §9.9.6; MD-14, P55, PI-8. _Durum:_ belirtilmemiş (FROZEN, türetilmiş).

#### Sender-constrained token ve DPoP

- [ ] **Sender-constrained / holder-bound token varsayılanı (`cnf`)** — Authority taşıyan her projection (exact-intent / bounds dahil) DPoP `cnf.jkt`, mTLS `cnf.x5t#S256`, JWT-SVID veya PoP ile holder-bound'dur; bearer authority yoktur. Bearer yalnız beyanlı legacy RP opt-in'idir. _Kaynak:_ §6.5; §11.2, §11.21.1 #11; §15.3.1; AGI-3, I3, L21, MKT-D2, P25, P48, PI-11. _Durum:_ belirtilmemiş (ADOPT).
- [ ] **RS SDK/gateway'in kendi DPoP replay kontrolü** — _Kaynak:_ §10.4.3; IDP-11. _Durum:_ belirtilmemiş.

#### Token ömürleri ve ValidityContract

- [ ] **ValidityContract tüm token'ların sözleşmesi** — ID, access ve refresh token ile oturum çerezi dahil yeniden kullanılabilir her artefaktın semantik sözleşmesi ValidityContract'tır (horizon, freshness profili, re-validation koşulu). _Kaynak:_ §5.3, §5.11; INV-22, MD-7. _Durum:_ belirtilmemiş.
- [ ] **CT'ye göre token kısıtları (authority taşıyan token horizon'u)** — Horizon = min(ömür PD'si, connectivity tavanı). CT2+ action için bounds token verilmez, yalnız exact-intent token (≤ 5 dk, count = 1) verilir; CT3 için projection verilmez. _Kaynak:_ §9.9.3 k.4; §10.4.5; §13.7.9. _Durum:_ PD.
- [ ] **Uzun ömür yalnız beyanlı horizon ile** — Uzun ömürlü token yalnız beyanlı bir ValidityContract horizon'u olarak mümkündür (UDC). _Kaynak:_ §5.11; §9.9.3 k.4; MD-7. _Durum:_ belirtilmemiş.
- [ ] **Token ömrü < anahtar imza süresi** — `T_token < T_sign`; JOSE anahtarı en uzun ömürlü token sona erene kadar JWKS'te kalır. _Kaynak:_ CR-19, CR-26. _Durum:_ belirtilmemiş (FROZEN).

#### Refresh token

- [ ] **Refresh ömrü ≤ Grant/Mandate validity** — Refresh hareketsizlik ve mutlak tavanla sınırlıdır; Grant/Mandate bitişini aşamaz. _Kaynak:_ §9.9.3 k.6; §11.9.4; §11.21.1 #26; AG-22, P50. _Durum:_ PD.

#### Introspection ve RS doğrulaması

- [ ] **RS 5xx = DENY** — RS, introspection veya JWKS uç noktasından 5xx aldığında ya da `active=false` gördüğünde DENY uygular. _Kaynak:_ §9.9.3 k.5; §13.4 G48; §17.7.2; OP-45, P49. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Salt-JWT RS doğrulaması ve bayatlık sınırı** — RS `exp` ve audience'ı doğrular; JWKS yenilenemezse bilinen anahtarlarla `key_epoch` penceresi içinde doğrular. Sinyal tüketmeyen RS için azami bayatlık ≈ token ömrü = horizon'dur; JWKS önbelleği iptal durumu değildir. _Kaynak:_ §9.11.2; §13.11 EP-4; U36. _Durum:_ belirtilmemiş (§13'e aday).

#### Token içeriği ve claim'ler

- [ ] **Capacity → `sub`/`act`/`may_act` eşlemesi** — OWN'da `sub` = basis holder ve `act` yok; FOR(P)'de `sub` = P ve `act.sub` = actor; çok halkalı lineage'da iç içe `act` kullanılır. _Kaynak:_ §9.9.4; P53. _Durum:_ PD (wire biçimi).
- [ ] **Rezerve claim adları kiracıya kapalı** — `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `nbf`, `act`, `may_act`, `cnf`, `scope`, `client_id`. _Kaynak:_ §9.9.4 k.1, §9.9.6; P55. _Durum:_ PD (rezerve liste).
- [ ] **Token boyutu farkındalığı** — Token şişmesi sınırları dikkate alınır: çerez 4 KiB, başlık 8 KiB (değerler doğrulanmadı). _Kaynak:_ §9.9.6. _Durum:_ belirtilmemiş.

### K04 Hesap yaşam döngüsü ve kurtarma

#### Tanımlayıcılar ve e-posta

- [ ] **Realm'ler arası IdentityBinding** — Birden çok hücredeki kullanıcı global kullanıcı tablosu yerine açık IdentityBinding ile bağlanır. _Kaynak:_ §17.4.9; MD-5, OP-30. _Durum:_ belirtilmemiş (FROZEN)

#### Hesap bağlama ve birleştirme

- [ ] **IdentityBinding retraction / controller değişikliği** — Bu Claim'ler affirmative değişikliktir: episode kapanır; controller değişikliği yalnız ilgili selector'ları etkiler. _Kaynak:_ §7.9.2.4. _Durum:_ belirtilmemiş

#### Hesap durumları ve devre dışı bırakma

- [ ] **Hesap durumu → varsayılan DENY overlay** — Realm issuer'ının `account.status ∈ {suspended, deactivated, tombstone}` Claim'i, ilgili PartyRef'in o realm üzerinden kurulmuş Instance'larına ingest pozisyonundan itibaren domain'in varsayılan politikasıyla DENY overlay'i (`restricted`) olarak uygulanır. Actor gerektirmez (CT1 narrowing); overlay'in kaldırılması genişletmedir. _Kaynak:_ §5.6, §7.1, §7.7, §8.10, §8.13, §12.3.1, §12.10, §13.7.9; E5, E29, SEC12, SI-4, TN-49, TN-50, X36. _Durum:_ PD

#### Hesap kurtarma: ilkeler ve authority etkisi

- [ ] **Authenticator ekleme/silme, cihaz ve parola değişimi Instance'ı değiştirmez** — Yeni `authenticator-binding` Claim'i üretilir; SEC18 cooling uygulanır. _Kaynak:_ §10.1.3; IDP-2. _Durum:_ belirtilmemiş (karar FROZEN)

#### Party Identity Regime etkileri

- [ ] **Party Identity Regime Claim'lerinin tüketimi** — Access şu Claim'leri tüketir: `party.key-state`, `party.compromise`, `party.recovered`, `party.terminated`, `party.identity-break`, `controller-of`, `identity-binding.<kind>`, `authenticator-binding`. Etkileri yalnız restriction, actor-binding veya explicit Exercise yoluyladır. _Kaynak:_ §9.13; AP-8, P20. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Party key compromise beyanının etkisi** — Claim, varsayılan güvenlik politikasıyla compromise sonrası Instance'lara DENY overlay'i uygular. Terminal temizlik `instance.terminate` / `instance.recover` ile yapılır. _Kaynak:_ §7.9.2.4. _Durum:_ belirtilmemiş
- [ ] **Party recovery etkisi** — Party recovery yeni `instance.create` için actor-binding girdisidir; Grant'lar PartyRef'e bağlı olduğu için yaşar. Instance recovery ≠ Party recovery. _Kaynak:_ §7.9.2.3–4. _Durum:_ belirtilmemiş
- [ ] **Party termination etkisi** — Actor-binding fail-closed başarısız olur ve mevcut Instance'lar DENY overlay'i altına girer. Grant'ların akıbeti explicit Exercise ile belirlenir. _Kaynak:_ §7.9.2.4. _Durum:_ belirtilmemiş
- [ ] **Controller'ın issuer designation'ı** — Controller, key-event history'ye class başına issuer designation yazar. `authenticator-binding` Claim'i, Acceptance ve designation birlikte sağlanırsa kullanılır (conjunction). _Kaynak:_ §9.13.1; P21. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Designation iptalinin prospective olması** — Designation kaldırılınca issuer'ın sonraki Claim'leri geçmez, önceki Exercise'lar geçerli kalır. Compromise sonrası ingest-time cutoff aynı mekanizmayla uygulanır. _Kaynak:_ §9.13.1 k.4; P21. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Custodial anahtar modeli (beyanlı)** — Suiss Identity plane anahtarları custodial tutabilir; bu Suiss'i controller yapmaz. Custodian riski gizli değil, beyan edilmiş bir bağımlılıktır. _Kaynak:_ §9.13.1 k.3, §9.17.4. _Durum:_ belirtilmemiş

### K05 Kiracılık, realm ve B2B organizasyonlar

#### Fiziksel izolasyon ve tipli kapsam

- [ ] **Domain-pairwise PartyRef pseudonym'i** — Projeksiyon ve PAP'ta PartyRef domain-pairwise pseudonym'dir; authority düzeyinde çapraz-domain korelasyon yalnız bridging Grant / IdentityBinding ile. _Kaynak:_ §13.4 G52; MD-10. _Durum:_ belirtilmemiş.

#### Realm yönetişimi

- [ ] **Tek yönetişim domain'i (`realms.governing_domain_id`) + N tüketen domain** — Her realm'in NOT NULL tek bir yönetişim domain'i vardır; realm config yalnız orada ADP commit ile değişir. Realm Claim'lerini tüketen domain'ler yalnız kendi Acceptance'larını taşır ve `idp.*` commit'leri DENY alır. _Kaynak:_ §2.2.2 #6; §5.16, §7.1, §7.7; §9.15.1 k.3; §10.1.1; §12.1.1 2a; F21; INV-37; MD-5a; MD-14; TN-1. _Durum:_ belirtilmemiş (FROZEN, TN-1).
- [ ] **Identity plane yapılandırması = ADP commit** — Client, redirect URI, upstream IdP, şablon, CIMD alan adı güven politikası ve realm config değişiklikleri domain action'larıdır ve ADP `commit` ile yetkilendirilir. _Kaynak:_ §9.15.1 k.3; MD-14; P60. _Durum:_ belirtilmemiş (FROZEN).

### K06 Giriş deneyimi, UI bileşenleri ve markalama

#### Markalama ve şablonlar

- [ ] **Realm yönetimi ve markalama değişikliği `idp.*` Exercise'ı** — Realm yöneticisi client, tema, upstream IdP ve giriş politikasını yönetir; her değişiklik `idp.*` domain action Exercise'ıdır. _Kaynak:_ §1.7; §12.4.2; TN-106. _Durum:_ belirtilmemiş (FROZEN, TN-106).

### K07 Yetki modeli

#### Consequence Tier ve güvence eşikleri

- [ ] **CT2 contribution/assertion varsayılanı** — Actor'ün principal'ının taze, H(AAS)-bağlı, phishing-resistant human-presence assertion'ı veya insan contribution'ı (actor agent ise insan contribution'ı); başka principal'dan contribution yalnız SoD beyanlıysa. _Kaynak:_ §13.7.3; SEC10. _Durum:_ PD

#### Identity plane ile sınır

- [ ] **Identity ≠ Authority: identity plane yalnız Claim verir** — Identity plane authority üretmez; tek kanalı Claim Ingest API'dir ve Claim karara yalnız Acceptance kadar girer. _Kaynak:_ P-ID-1; CMP-15; E3, INV-12, T31, TI-15. _Durum:_ belirtilmemiş (FROZEN, CMP-15)
- [ ] **Seam: Authority → Identity yazma yok** — Yalnız derived event'ler ve Decision Response'lar. _Kaynak:_ §10.1.1. _Durum:_ belirtilmemiş
- [ ] **Party Identity Regime Claim sınıfları** — `party.key-state`, `party.compromise`, `party.recovered`, `party.terminated`, `party.identity-break`, `controller-of`, `identity-binding.<kind>`, `authenticator-binding`, `authentication`, `operated-by`/`agent-kind`/`sponsored-by`. _Kaynak:_ §10.1.5. _Durum:_ belirtilmemiş
- [ ] **Controller issuer designation** — Acceptance ∧ designation conjunction; iptal prospektiftir. _Kaynak:_ §10.1.5. _Durum:_ belirtilmemiş
- [ ] **Attestation/cihaz bütünlüğü/risk sinyal, kapı değil** — Yalnız Acceptance'lı `predicate-input` olarak girer. _Kaynak:_ P-ID-7, §10.1.3; IDI-3. _Durum:_ belirtilmemiş
- [ ] **Identity issuer'ın authority issuer rolü varsayılan engelli** — `foreign-authority` açık Acceptance ister. _Kaynak:_ §10.7.1; L26. _Durum:_ belirtilmemiş
- [ ] **Dış artefaktlar tek başına authority değil** — Scope, trust chain, trust mark, VC, ID-JAG, CIBA cevabı tek başına authority değildir. _Kaynak:_ §10.1.4, §10.7.1; IDI-9, PI-3. _Durum:_ belirtilmemiş

#### Kaynak modeli ve yaşam döngüsü

- [ ] **Sahip/holder alanı değişmezliği** — Credential/token sahip alanı yaratılışta sabittir. _Kaynak:_ §12.5.2; TN-116. _Durum:_ belirtilmemiş (FROZEN)

#### Exercise protokolü

- [ ] **Decision ≠ credential; holder-bound projection** — Receipt tek Exercise/intent/audience'a bağlıdır; projection holder-bound'dur (bearer yok). _Kaynak:_ §13.4 G18. _Durum:_ belirtilmemiş

### K08 Karar, uygulama ve doğrulama

#### Karar sonuçları ve semantiği

- [ ] **Her refresh yeni karar** — Revocation sonrası refresh DENY. _Kaynak:_ §12.2.1; L19, TN-31. _Durum:_ belirtilmemiş (FROZEN).

#### Envelope bağı ve intent

- [ ] **İcra edilen body = onaylanan digest** — Conformant Surface + PEP koşuluyla. _Kaynak:_ §13.4 U6. _Durum:_ belirtilmemiş.

#### Karar protokolü (Access Decision Profile)

- [ ] **Tek ADP kararıyla `projection.issue`** — Actor ve basis birlikte değerlendirilir (iki kapılı değerlendirme yerine). _Kaynak:_ §11.21.1 (gazitt notu). _Durum:_ belirtilmemiş.
- [ ] **Identity plane PEP'inin ADP'ye Decision çağrısı** — _Kaynak:_ §10.1.1; MD-14. _Durum:_ belirtilmemiş.
- [ ] **ADP ile identity plane admin config (`idp.*` domain action)** — Identity yönetimi ADP üzerinden Exercise olarak yetkilendirilir; ayrı "admin token" sınıfı yok. _Kaynak:_ §18.8.2 H13b, §18.13; MD-14. _Durum:_ Faz 1.

#### Türetilmiş indeks, arama ve okuma tutarlılığı

- [ ] **İçerik nedenselliği ("yeni düşman" koruması)** — Kaynak pozisyon q (`content_position`) biliniyorsa PEP ondan eski `as_of`/`basis_ref`'li projection'ı o içerik için reddeder ve online yolda `at_least ≥ q` karar ister (UDC). _Kaynak:_ §6.9; §9.7A.3; §13.4 U60; INV-41; P44. _Durum:_ belirtilmemiş (aday); PD (§9.7A.3).

#### Fail-closed ve kesinti davranışı

- [ ] **PEP tarafında HTTP fail-closed (5xx = DENY)** — 5xx, timeout veya ayrıştırılamayan yanıtta effect üretilmez; Access'in conformance profilini beyan eden RS 5xx'i DENY sayar (UDC). Rate limiter/risk motoru/cache arızası ALLOW'a dönmez. _Kaynak:_ §6.2; §9.5.2 k.8; INV-26; MD-8. _Durum:_ belirtilmemiş.
- [ ] **Access erişilemezken fail-closed** — Online consequential effect yok, "timeout ⇒ allow" seçeneği yoktur; effect yalnız geçerli ValidityContract/offline slice içinde contract sonuna kadar üretilebilir. _Kaynak:_ §8.13, §8.17.10.3; §9.5; E25, E28; X21. _Durum:_ belirtilmemiş.
- [ ] **Fail-open seçeneği/konfigürasyonu yok** — SDK'de fail-open seçeneği yoktur; "degraded allow / timeout ⇒ allow / bypass" bayrağı kodda yoktur ve conformance negatif testiyle denetlenir. _Kaynak:_ §8.17.10.3, §8.17.10.5; §17.7.1; CMP-17; OP-8; SI-22; TI-9; X21. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Continuity envelope'ları (fail-open yerine)** — Availability önceden issue edilmiş küçük slice'lı, kısa horizon'lu projection'larla ve break-glass için offline PAP ile sağlanır. _Kaynak:_ SEC27. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Identity plane kesintisinde authority davranışı** — Yeni `authentication` Claim'i yoksa REQUIRE_ACTION/DENY; mevcut KeyBinding'li cihaz-bağlı Instance'lar AIS imzalamaya devam eder. _Kaynak:_ §16.7.1; §17.7.1; E25. _Durum:_ belirtilmemiş.
- [ ] **IdP stale → REQUIRE_ACTION, rol kaybı değil** — "Needs refresh — not removed." _Kaynak:_ §8.13. _Durum:_ belirtilmemiş.
- [ ] **Foreign status unknown → REQUIRE/DENY** — Fresh foreign proof gelene kadar partner eylemlerine izin yok. _Kaynak:_ §8.13, §8.17.8.2. _Durum:_ belirtilmemiş.

#### PEP uygulaması ve SDK

- [ ] **PEP kararı effect'ten önce uygular** — Conformant PEP koşuluyla. _Kaynak:_ §13.4 U1. _Durum:_ belirtilmemiş.
- [ ] **PEP SDK'ları** — Fail-open içermeyen referans PEP SDK'ları. _Kaynak:_ §18.3, §18.13. _Durum:_ Faz 1 (§18.13 çıkarım).
- [ ] **PEP SDK actor-instance proof'u** — İstek actor Instance proof'uyla kurulur; PEP servis kimliğiyle kullanıcı adına istek kuramaz. _Kaynak:_ §8.17.10.3; E17; X21. _Durum:_ belirtilmemiş.
- [ ] **PEP SDK `Authorized<R, A>` kanıt tipi** — Rust SDK'sında derleme zamanı yetki kanıtıdır; private yapıcısı vardır, ExerciseID + intent digest taşır ve yalnız Kernel ALLOW'undan üretilir; effect fonksiyonu yalnız bu kanıtla çağrılır, effect öncesi INV-19 digest kontrolü yapılır. _Kaynak:_ §9.5.2 k.6; CR-52; MD-1; P40. _Durum:_ PD (§9.5.2); FROZEN (CR-52).
- [ ] **PEP'ler arası zincir ve causal binding** — Downstream PEP kendi Exercise'ını ister ve upstream (causal) ExerciseID taşır. Upstream bağ declared RestrictionPolicy + upstream ExerciseID'ye anahtarlı count=1 causal-bound allowance ile kurulur (GUARANTEED UNDER DECLARED POLICY); `causal_binding = enforced | audit-only` görünür kılınır, zorlanmıyorsa console "Chain link is audit-only in this domain (not enforced)" uyarır. _Kaynak:_ §7.9.7.4; §8.17.10.3; §9.9.2; §13.4 U8; E17; EI-17. _Durum:_ belirtilmemiş.
- [ ] **Authority-state acknowledgement** — PEP'in bir revoke/narrow'u uyguladığını beyan eden Claim'dir. Bir detection sinyalidir; revoke etkinliği ack'e bağlı değildir. _Kaynak:_ §9.12.3; E30; P28. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **External system / PEP entegrasyonu** — AuthZEN istemcisi olarak ADP veya OAuth RS olarak exact-intent token doğrulama; authority-state ack. _Kaynak:_ §11.19. _Durum:_ belirtilmemiş.
- [ ] **Gömülü Kernel / istemci içi karar noktası** — `intermittent`/`offline` profilidir; yalnız ValidityContract'lı projection'a karşı advisory/projected karar verir. ValidityContract + Verifier Profile Claim olmadan conformant değildir. _Kaynak:_ §5.10; §9.7A.7; P47. _Durum:_ belirtilmemiş (FROZEN, türetilmiş).
- [ ] **Projected exercise** — PEP, ValidityContract'lı bir projection'a karşı yerel karar verir. Consumption taşıyan sınıflar online Exercise veya offline slice ister. _Kaynak:_ §5.10. _Durum:_ belirtilmemiş.

#### İşlem imzalama ve onay ekranı

- [ ] **İşlem imzalama: WebAuthn challenge = H(AAS), SPC, cihaz anahtarı ile H(AAS) imzası** — 5 adımlı WYSIWYS; assertion `authentication` Claim'ine "binding = statement digest" ile girer. _Kaynak:_ §10.3.4, §10.5.4. _Durum:_ belirtilmemiş.

#### Projection'lar ve yetki artefaktları

- [ ] **Projection'lar (token, SSH sertifikası, imzalı karar belgesi)** — Holder-bound, audience-bound, kısa ömürlü; passthrough yok. _Kaynak:_ §Kısaca; L4; L24. _Durum:_ belirtilmemiş.
- [ ] **Projection ⊆ source** — Her projection ⊆ (AuthoritySet ∩ Mandate ∩ requirements) olur; Decision Receipt credential değildir. _Kaynak:_ §6.5; INV-3; PI-8. _Durum:_ belirtilmemiş.
- [ ] **Projection issuance (`projection.issue`) ve offline slice draw** — Tek reusable/portable artifact'tır. Bounds ⊆ Exercisable, profile ≤ policy ve Δ ≤ tavan kontrol edilir; offline slice projection commit'inde önceden draw edilir. _Kaynak:_ §9.9; §17.1.1; AP-5; OP-S9; P17, P27; PI-20. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Projection verme koşulu: yerelde doğrulanamayan requirement** — Yerelde doğrulanamayan requirement'ı olan action'lar bounds'a giremez (fail closed). _Kaynak:_ §9.10. _Durum:_ belirtilmemiş.
- [ ] **Projection türleri ve uzak PEP profilleri** — Türler: Receipt, exact-intent token, bounds token, Portable Authority Proof, continuation contract; uzak PEP'ler exact-intent token, bounds token veya PAP kullanır. _Kaynak:_ §9.9.1; §17.5.1; P17. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Exact-intent token ve bounds token** — RFC 9068 JWT AT + RAR `kind=intent|bounds`. _Kaynak:_ §15.3.1; T24. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Signed capability offline profili** — İmzalı capability token'ı ile offline doğrulama profili (projection; kaynak değil). _Kaynak:_ §4.4. _Durum:_ belirtilmemiş.
- [ ] **Decision Receipt** — Karar yanıtıyla verilen imzalı ALLOW kanıtıdır. Alanlar: issuer, ExerciseID, intent digest, actor, capacity/basis, audience, zaman, validity, consumption özeti. Credential değildir. _Kaynak:_ §4.4; §9.8; L23; P13; R4. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Decision Receipt biçimleri (COSE_Sign1 ve JWS)** — PEP profiline göre COSE veya JWS; ikisi aynı `artifacts[]` digest kümesine bağlı. _Kaynak:_ §15.3.1; T24. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Receipt offline doğrulama ve audit attribution** — Receipt yalnız o intent/PEP/nonce için geçerlidir. Zincirde upstream receipt yalnız causal ref'tir. _Kaynak:_ §9.8. _Durum:_ belirtilmemiş.
- [ ] **Portable Authority Proof (PAP)** — Domain dışında / offline doğrulanabilir authority kanıtıdır; Work dış authority'ye `DomainID + ExerciseID` ile atıf yapar. Alanlar: issuer, projection_exercise, holder, capacity, bounds, local_requirements, validity, offline_slice, status, lineage_commitment, audience, must_understand. _Kaynak:_ §7.9.11.2; §9.10; P18; R6; SI-11. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **PAP kapları: COSE/CWT ve SD-JWT** — Access-tanımlı içerik JWT/SD-JWT veya COSE kabında taşınır; cihaz/offline için COSE/CWT kanonik, web/cross-domain için SD-JWT profili; seçici açıklama. _Kaynak:_ §9.2 AP-5, §9.10; §15.3.1; R6; T24. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Lineage commitment (seçici açıklama)** — Basis lineage digest'i halkalar seçici açılabilecek şekilde taşınır; tam graph ifşa edilmez. _Kaynak:_ §9.10. _Durum:_ belirtilmemiş.
- [ ] **Kanıtlı imzalı artefaktlar** — PAP, ValidityContract, Decision Receipt gibi artefaktların digest'i imzadan önce DecisionRecord `artifacts` alanındadır; inclusion proof verilir. _Kaynak:_ §6.7; TI-12. _Durum:_ belirtilmemiş.
- [ ] **Authority taşıyan access token domain operasyonel anahtarıyla imzalanır** — Domain Metadata çapraz referansı; verifier DomainID eşleşmesini denetler. _Kaynak:_ §10.4.5. _Durum:_ belirtilmemiş.
- [ ] **Domain Metadata excerpt'i (offline imza zinciri)** — Artefakta gömülü binding-imzalı `{DomainID, kid, alg, jwk_thumbprint, validFrom, validUntil, usage}`; verifier güncel metadata'ya erişmeden doğrular. _Kaynak:_ §15.3.1; CR-18; T20. _Durum:_ belirtilmemiş (FROZEN).

#### Bağlantı profilleri ve ValidityContract varyantları

- [ ] **Dört connectivity profili** — `online`, `intermittent`, `offline` ve `long-running` (executor) class'ları frozen'dır; sınıf bazında sorumluluklar tanımlıdır. _Kaynak:_ §5.11, §7.9.4; §9.12; E13; L16; P26. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Profile variant: `online-strict`** — Receipt/exact-intent token kullanılır ve her action'da ADP çağrılır; revoke anında etkilidir. _Kaynak:_ §9.12. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Profile variant: `bounded-staleness`** — Bounds token + status kullanılır; Δ içinde tazeleme yapılır, aşılırsa online'a düşülür. _Kaynak:_ §9.12. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Profile variant: `revalidate-on-reconnect`** — Bağlantı gelince yeni karar alınır; kesintide horizon'a kadar kullanılabilir. _Kaynak:_ §9.12. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Profile variant: `checkpointed-offline`** — PAP + offline slice + rapor yükümlülüğü içerir. _Kaynak:_ §9.12. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Profile variant: `checkpoint-continuation`** — Long-running iş için Executor her checkpoint'te `continue` ister. _Kaynak:_ §9.9.1, §9.12. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Connectivity class tavanları** — Her class/variant için CT bazlı Δ/horizon/slice/checkpoint tavanları; CT2 online zorunlu veya exact-intent token (≤ 5 dk, count 1); CT3 online zorunlu, projection yok. _Kaynak:_ §13.7.2. _Durum:_ PD.
- [ ] **Robot / offline cihaz doğrulaması** — PAP + ValidityContract + offline slice; yerel verifier; `local_requirements` ile önceden alınmış contribution; reconnect'te offline report. _Kaynak:_ §11.19. _Durum:_ belirtilmemiş.
- [ ] **Staleness-window (Δ) risk beyanı** — `projection.issue` actor'ü Δ'yı attributable olarak beyan eder; tavanı lineage ve politika koyar. _Kaynak:_ §7.9.4.1; E13. _Durum:_ belirtilmemiş.

#### Offline doğrulama ve verifier

- [ ] **Offline / portable doğrulama** — Access'e sormadan, organizasyonlar arası doğrulama. _Kaynak:_ §1.4 vaat 7; F16. _Durum:_ belirtilmemiş.
- [ ] **Offline slice (önceden draw)** — `projection.issue` commit'inde draw tamamdır; merkezde slice içi double spend olmaz. Offline rapor remaining'i değiştirmez; kullanılmayan slice grounded release ile döner. _Kaynak:_ §6.5; §7.9.4.2; §9.12, §9.12.2; P27; PI-20. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Grup audience'lı offline slice** — Grup slice toplamı ≤ slice (ortak tamper-evident sayaç beyanıyla); consumption-bearing offline slice audience'ı tek verifier veya ortak sayaçlı grup, aksi projection.issue DENY. _Kaynak:_ §13.4 U3; SEC13. _Durum:_ belirtilmemiş.
- [ ] **Home/target domain draw** — Home'da tek draw; target yalnız ek daraltma. _Kaynak:_ OP-S11; PI-24. _Durum:_ belirtilmemiş.
- [ ] **Offline Verifier 7 adımlı kural (Kernel'de)** — Adımlar: imza zinciri/DomainID, horizon/clock, holder PoP, intent ⊑ bounds + local requirements, slice yeterliliği, status/metadata tazeliği (witness cosign), must-understand; Kernel'de uygulanır. _Kaynak:_ §9.10; CMP-24; OP-1; P18. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Verifier opsiyonel adım 8 (içerik nedenselliği)** — Verifier Profile'da "içerik pozisyonu kontrolü" olarak beyan edilir. _Kaynak:_ §9.10.1 k.4; §13.4 U60; P44. _Durum:_ PD.
- [ ] **Must-understand ve Verifier DomainID** — Verifier anlamadığı zorunlu özelliği reddeder; DomainID must-understand'dir, domain A projection'ı domain B verifier'ında DENY. _Kaynak:_ §6.5, §6.8; §12.1.2, §12.1.3; PI-12; TI-RT6; TN-14, TN-23. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Verifier Profile (Claim) beyanı** — Her verifier yeteneklerini ve freshness profilini beyan eder (profile'lar, sürümler, clock, tamper-evident sayaç, offline report, attestation, status erişimi, içerik pozisyonu kontrolü, tazeleme aralığı); iptal gecikmesi bununla sınırlıdır ve `cap_horizon` kaynağıdır. Profile uymayan/kapsanmayan contract issue edilmez; developer bunu conformance Claim ile beyan eder ve console "requested: offline 4h · domain granted: intermittent 15 min" gösterir. _Kaynak:_ §7.1, §7.9.4.1; §8.17.10.3; §9.12.1, §9.12.4; E13; L17; P26; PI-12; U25. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Verifier-side yerel kabul tavanları (`min(horizon, iat + yerel tavan)`)** — Domain horizon/slice tavanlarını Domain Metadata / Verifier Profile'da (`cap_horizon`) verifier'ın yerel tavanı olarak ilan eder; conformant verifier aşan artefaktı ve anahtar penceresi dışı imzayı yerel DENY ile reddeder (çalınmış provider anahtarı containment'ı). _Kaynak:_ §13.7.2 not; §16.5; CR-K1; T20; U25. _Durum:_ PD (§13.7.2); FROZEN (T20).
- [ ] **Offline verifier: horizon/Δ/status/slice uyumu** — Verifier profile (secure clock, tamper-evident sayaç) ile revocation penceresi fiilen kapanır; intermittent propagation ≤ Δ. _Kaynak:_ §13.4 U2, U19. _Durum:_ belirtilmemiş.
- [ ] **Offline Exercise Report** — Verifier'ın yeniden bağlanınca gönderdiği Claim'dir. Alanlar: verifier, projection, period, entries[], hash chain, slice_unused, profile_version. Remaining'i tek başına değiştirmez. _Kaynak:_ §9.12.2; P27. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Offline report chain** — Gizleme/sıra değişikliği tespiti (verifier imza/sayaç capability'si); horizon + 24 saat içinde raporlamayan verifier'a yeni contract yok. _Kaynak:_ §13.4 U4; §13.7.2; SEC14. _Durum:_ PD (24 saat).
- [ ] **Offline reconciliation (authority tarafı)** — Offline exercise raporları projection'a bağlanır; contract içi/dışı ayrımı derived'dır. _Kaynak:_ §7.9.4.1. _Durum:_ belirtilmemiş.
- [ ] **Offline Verifier Core / SDK** — Kernel + platform adaptörleri (FFI/Wasm); SE/TPM sayaç, imzalı zaman, chained report, grup sayaç servisi. _Kaynak:_ §18.3; CMP-17; T25. _Durum:_ belirtilmemiş (FROZEN).

#### İptal, tazelik ve status

- [ ] **Offline revocation: bounded staleness, offline budget, status list** — Offline doğrulamada iptal bounded staleness, offline budget, kısa ömür ve status list ile uygulanır. _Kaynak:_ F16; K14 (Token Status List); LFP-11. _Durum:_ belirtilmemiş.
- [ ] **Offline projection'lar beyanlı ValidityContract penceresinde** — "Offline atomik iptal" asla iddia edilmez. _Kaynak:_ §12.3.1; TN-50. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Kanallar: bilgi ve safety ayrımı** — Status list ve event'ler bilgi kanalıdır. Safety online ADP veya horizon + bounds + slice'tır; event kaybı authority genişletmez. _Kaynak:_ §9.12.4; PI-9. _Durum:_ belirtilmemiş.
- [ ] **Token Status List ve introspection tazeliği** — Domain başına, operasyonel anahtarla imzalı, `applied_pos`'lu; tazelik/`iat` yansıtılan canonical pozisyonun `recorded_at`'inden ölçülür, yayıncı eski içeriği taze `iat` ile imzalamaz. Derived gecikme beyanlı Δ'yı tüketir; derived kesintisinde yeni liste yok; revocation öncelikli yeniden yayın; heartbeat ile tazelenir. _Kaynak:_ §6.7; §15.3.1; §16.5.1; §17.1.4, §17.4.2; CMP-7; G43; T24; TI-5, TI-12. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Domain Metadata yayını ve freshness** — Verifier cache ≤ contract Δ (yoksa ≤ 1 saat); tazelik bağımsız witness cosign'ıyla ölçülür. _Kaynak:_ §7.1; §13.3; §13.7.2; T29; TI-RT5. _Durum:_ PD.
- [ ] **Authority artefaktı doğrulama yolu (EP-7)** — PAP/receipt/exact-intent token için Δ/horizon/slice ValidityContract'ta; online-strict'te DENY; degraded window yok. _Kaynak:_ §13.11 EP-7. _Durum:_ belirtilmemiş.

#### Kernel ve referans bileşenler

- [ ] **Kernel Wasm paketi** — _Kaynak:_ §18.3, §18.9 D4 notu; MD-1. _Durum:_ belirtilmemiş.
- [ ] **Reference verifier / PAP / receipt / checkpoint / inclusion proof doğrulaması (ücretsiz)** — _Kaynak:_ §18.7 B3. _Durum:_ belirtilmemiş (FROZEN STRATEGY).

#### Ürün kapsamı ve yol haritası

- [ ] **Cross-org portable authority** — _Kaynak:_ §18.8.1 H15, §18.13. _Durum:_ yol haritası ("Sonrası").
- [ ] **Offline / edge** — _Kaynak:_ §18.8.1 H15, §18.13. _Durum:_ yol haritası ("Sonrası").

### K11 Yönetim API'si, konsol, SDK'lar ve geliştirici araçları

#### Yönetim yazma yolu ve yetki modeli

- [ ] **Claim Ingest API** — Identity → Authority arasındaki tek kanaldır. _Kaynak:_ §5.12; TI-15. _Durum:_ belirtilmemiş.

#### API yüzeyleri ve ayrım

- [ ] **Frontend API** — Gömülü UI ve tarayıcı/mobil istemciler için; özel alan adında, kendi çerez/CORS/CSRF kurallarıyla. _Kaynak:_ OP-65. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).

#### Hız ve yapı limitleri

- [ ] **`projection.issue` ve bootstrap limitleri** — `projection.issue` ≤ 30/saat per Instance × action class, açık offline PAP ≤ 3; bootstrap Grant'ları (`party.register`, `instance.create(self)`) ≤ 10/saat per context. _Kaynak:_ §13.7.4. _Durum:_ PD.

#### Decision lab, sandbox ve conformance

- [ ] **Conformance test suite, test vektörleri ve runner** — PEP / verifier / Approval Surface için; conformance ≠ endorsement. _Kaynak:_ §8.17.10.4; §9.1 L3; §9.17; CMP-17; T34. _Durum:_ belirtilmemiş.

#### Doğrulama ve replay araçları

- [ ] **Reference Verifier** — PAP/receipt/checkpoint doğrulayıcısı. _Kaynak:_ §9.1, §9.17; CMP-17; T34. _Durum:_ belirtilmemiş.
- [ ] **Offline Verifier Core / ayrı doğrulama paketi** — Müşteri olmayan doğrulayıcılar için yalnız Offline Verifier Core'u içeren ayrı paket (Offline Verifier SDK); saldırı yüzeyi haritasında AS-1–AS-15 içinde. _Kaynak:_ §9.1; §14.3; T41 madde 2. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **TS/Wasm doğrulayıcı** — Rust kernel ↔ TS/Wasm doğrulayıcı differential test edilir. _Kaynak:_ §14.8 SA-T10. _Durum:_ belirtilmemiş.

#### SDK'lar

- [ ] **Access PEP SDK (Rust)** — Bkz. K08 `Authorized<R,A>`; conformance vektörlerini geçen PEP SDK'sı MCP cache/stream kurallarını doğru uygular. _Kaynak:_ §9.5.2 k.6; P40; U63, U64. _Durum:_ PD.

### K12 Entegrasyonlar ve yardımcı servisler

#### Güvenlik ekosistemi: PAM, sır kasası, HSM

- [ ] **Vault dinamik DB kimlik bilgileri, ESO/Vault Agent sır bağlama** — _Kaynak:_ §17.9.5; OP-52. _Durum:_ PD (araçlar).
- [ ] **Müşterinin Vault/OpenBao'sunu KEK sağlayıcısı olarak bağlama** — _Kaynak:_ CR-32 madde 4. _Durum:_ belirtilmemiş.
- [ ] **HSM erişimi PKCS#11 (`cryptoki`)** — Oturum havuzu, blocking thread havuzu. _Kaynak:_ CMP-13; CR-28; T5. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **KMIP** — _Kaynak:_ CR-28; T5. _Durum:_ WATCH.

#### Claim ingest kuralları

- [ ] **Claim ingest kotası** — Issuer başına Acceptance'ta beyanlı kotanın 2×'i; aşan ingest yalnız qualifying etkiye quarantine; narrowing Claim kota nedeniyle reddedilmez; kota üstü Claim episode açmaz. _Kaynak:_ §13.4 G44; §13.7.4; P19. _Durum:_ PD.
- [ ] **Issuer sırası (sırasız Claim)** — Issuer sırası belirsizse disqualifying kazanır; eski/sırasız Claim episode açmaz. _Kaynak:_ §13.4 G36; TI-RT7. _Durum:_ belirtilmemiş.
- [ ] **Regime key-event ingest'i** — Custodian'ın imzaladığı regime key-event'leri Access'e ingest edilir ve Party'nin Changes görünümünde görünür. _Kaynak:_ §13.4 U26. _Durum:_ belirtilmemiş.

#### Federasyon ve envanter görünümü

- [ ] **Cross-domain read federation projection'ları** — Envanter source of truth değildir; "as of 14:05", erişilemezse UNKNOWN. _Kaynak:_ §8.5 S2; §8.17.7.2. _Durum:_ belirtilmemiş.

### K13 Denetim, kayıt, şeffaflık ve dışa aktarım

#### Atıf ve inkâr edilemezlik

- [ ] **Teknik non-repudiation (AIS + Decision Receipt + Exercise kaydı + witness)** — AIS, AAS + assertion, Claim, checkpoint, receipt, PAP imzalıdır; hukuki non-repudiation iddia edilmez. _Kaynak:_ §11.18 #6; §11.20; §13.2; EI-24. _Durum:_ belirtilmemiş.
- [ ] **Decision receipt signing** — Karar makbuzlarının imzalanması (assurance aracı). _Kaynak:_ §4.4; L23. _Durum:_ belirtilmemiş.

#### Identity plane denetim log'u

- [ ] **Identity denetim checkpoint'lerinin cell başına denetim anahtarıyla imzası** — CMP-22b. _Kaynak:_ §17.6.5; CMP-22b. _Durum:_ PD (çıkarım).

#### Özel olay denetimleri

- [ ] **Anahtar rotasyon geçişlerinin denetimi** — [AU]'da OPERATIONAL audit akışına, [ID]'de realm audit olayına yazılır. _Kaynak:_ CR-27. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Anahtar töreni tutanağı** — M-of-N, video kayıtlı, tanıklı, script'li; tutanak digest'i Domain Metadata'da beyan. _Kaynak:_ CR-29. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Eski public key'lerin süresiz arşivi** — [AU] operasyonel anahtarların public kısmı ve excerpt'leri uzun süreli doğrulanabilirlik için süresiz tutulur. _Kaynak:_ CR-26. _Durum:_ belirtilmemiş (FROZEN).

#### Record Export ve bağımsız doğrulama

- [ ] **Access'e sormadan dışarıda doğrulanabilir kayıtlar** — Karşı taraf veya denetçi bir kararın gerçek ve geçerli olduğunu Access'e sormadan kontrol edebilir. _Kaynak:_ §Kısaca ilke 6; §1.4 vaat 7. _Durum:_ belirtilmemiş.

#### Provider beyanları ve şeffaflık yayınları

- [ ] **Domain Metadata Publisher** — `.well-known`, OIDF entity statement; kökü Genesis'teki provider binding. _Kaynak:_ CMP-14. _Durum:_ belirtilmemiş.
- [ ] **Custodial anahtar kullanımı beyanı** — Custodial mod non-custodial gibi sunulmaz. _Kaynak:_ §6.6; SI-13. _Durum:_ belirtilmemiş.
- [ ] **KMS/HSM throughput ve paylaşım beyanı** — Provider kota ve paylaşım durumunu açıklar. _Kaynak:_ CR-22. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Binding key kapsamı ve HSM partition paylaşımı beyanı** — _Kaynak:_ CR-18; CR-30; RT12. _Durum:_ belirtilmemiş (FROZEN).

### K14 Sinyaller, gözlemlenebilirlik ve analitik

#### Risk ve tehdit sinyalleri

- [ ] **Issuer kota bildirimi** — Claim burst'te issuer'a bildirim. _Kaynak:_ §16.7. _Durum:_ belirtilmemiş.

#### Operasyon sinyalleri, metrikler ve alarmlar

- [ ] **Gizli bellek arka uç metriği (`access_secret_memory_backend`)** — `{type=memfd_secret|mlock|none}`; signer sır bellek arka ucunu raporlar, `none` başlatma hatasıdır. _Kaynak:_ CR-34; RR-38. _Durum:_ belirtilmemiş.
- [ ] **HSM/KMS kesintisinde rotasyon gecikmesi alarmı** — _Kaynak:_ CR-23. _Durum:_ belirtilmemiş.
- [ ] **Bilinmeyen sürümlü artefakt sayacı** — _Kaynak:_ §15.4 tablo. _Durum:_ belirtilmemiş.

### K15 Güvenlik ve kriptografi

#### Kodlama, kanonikleştirme ve token doğrulama

- [ ] **Tek kanonikleştirme fonksiyonu + özellik testi (yol tabanlı yetkilendirme)** — _Kaynak:_ §12.5.1; TN-113. _Durum:_ belirtilmemiş (FROZEN).

#### Transport ve servis kimliği

- [ ] **SPIFFE/SPIRE servis kimliği** — _Kaynak:_ CR-12; T36. _Durum:_ belirtilmemiş.

#### Veri şifreleme ve sır yönetimi

- [ ] **Bellek-içi anahtar koruması (best-effort)** — Signer, custody signer ve verifier sır bileşenlerinde. _Kaynak:_ §13.2; §15.13. _Durum:_ belirtilmemiş.

#### Platform ve çalışma zamanı sertleştirmesi

- [ ] **OS seviyesi koruma ve `ACCESS_HARDENING` modları** — paranoid/balanced/dev; signer'da paranoid zorunlu; üretimde dev başlatma hatası verir. _Kaynak:_ CR-34. _Durum:_ belirtilmemiş (FROZEN; arka uç PD).

#### Güvenlik ilkeleri: fail-closed, downgrade, compromise

- [ ] **IdP compromise kurtarması** — Acceptance revoke, ingest-time cutoff ve episode kapanışı. _Kaynak:_ §7.9.11.1. _Durum:_ belirtilmemiş.
- [ ] **Güvenliğin sinyale / taşıyıcı teslimatına dayanmaması** — Güvenlik expiry, version ve checkpoint'e dayanır; event teslimi NOT GUARANTEED ve safety kanalı değildir; safety kanalı status list ve re-query'dir. _Kaynak:_ §6.2; §17.3.1; §17.3.2; FA-12; INV-24; OP-19. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **Holder-bound projection varsayılanı** — Authority projection'ları holder-bound'dur, bearer varsayılan değildir; garanti: sızan Access projection'ı anahtarsız kullanılamaz (BS). _Kaynak:_ §11.13; AG-9; AGI-3; L21; LFP-4; PI-11. _Durum:_ belirtilmemiş; garanti PD.

### K16 Gizlilik, rıza ve uyum

#### Takma adlar ve bağlanamazlık

- [ ] **Domain-pairwise PartyRef** — Domain dışına çıkan her projection, PAP, receipt ve audit altı export'ta `sub`, `act.sub` ve RAR PartyRef'leri domain-pairwise türetilmiş takma addır (subject_mapper). _Kaynak:_ §2.2.2 #5; §5.3; §5.18; §9.9.3 k.8; §9.10.1 k.3; §11.11.2; AG-28; INV-38; MD-10; P52. _Durum:_ belirtilmemiş (FROZEN MD-10; §5'te aday); PD (§11.11.2).
- [ ] **ID token/userinfo sector-pairwise, authority projection domain-pairwise** — _Kaynak:_ §9.10.1 k.3; §10.4.6. _Durum:_ belirtilmemiş.
- [ ] **Domain'ler arası korelasyon yalnız açık bağla** — Korelasyon yalnız bridging Grant veya IdentityBinding ile kurulur. _Kaynak:_ §5.3; §5.18; §9.10.1 k.3; §9.15A.5. _Durum:_ belirtilmemiş.
- [ ] **Kalan korelasyon yüzeyi beyanı** — Aynı KeyBinding, zamanlama ve Claim içeriği NOT GUARANTEED olarak beyan edilir. _Kaynak:_ §5.18. _Durum:_ belirtilmemiş.

#### Veri minimizasyonu ve seçici açıklama

- [ ] **Authority-relevance minimization** — Yalnız opaque ref, authority-relevant parametreler ve gereken Claim'ler alınır; seam başına tablo vardır. _Kaynak:_ §7.9.15; E26. _Durum:_ belirtilmemiş.
- [ ] **Claim minimizasyonu ve seçici açıklama** — Ingest hattında yalnız karar için gereken alınır; mümkünse değer yerine digest, SD-JWT tercih edilir. _Kaynak:_ §7.9.15.1; §9.13 k.5; CMP-8; E26; T23. _Durum:_ belirtilmemiş.
- [ ] **Claim corpus data lake değildir** — Redaction ve minimizasyon Claim'lere de uygulanır. _Kaynak:_ §7.9.15.2. _Durum:_ belirtilmemiş.
- [ ] **PAP seçici açıklama (SD-JWT, lineage halkaları)** — _Kaynak:_ §15.3.1; T19. _Durum:_ belirtilmemiş.

#### PII koruması ve redaksiyon

- [ ] **Identity plane ayrı KMS ve operatör rolleri** — _Kaynak:_ CR-32; T31. _Durum:_ belirtilmemiş (FROZEN).

#### Rıza ve izinler

- [ ] **Üçüncü taraf rızası = Grant (`grant.issue`)** — Üçüncü taraf RP consent'i S1 exact preview'den sonra verilen, iptal edilebilir bir Grant Exercise'ıdır; identity plane consent kaydı Grant'ın projection'ıdır ve çelişkide Grant kazanır. _Kaynak:_ §1.7; §2.2.2 #2; §7.1; L24; X9. _Durum:_ belirtilmemiş.
- [ ] **Consent ≠ authority** — Onay kaydı UI kaydıdır; kayıt var ama Grant yoksa DENY. _Kaynak:_ §9.14.5 k.3; P58. _Durum:_ belirtilmemiş (FROZEN).

### K17 Dağıtım, operasyon, yüksek erişilebilirlik ve felaket kurtarma

#### Cell topolojisi ve altyapı

- [ ] **Süreç topolojisi** — Authority core, derived/query, signer'lar, identity core, gateway'ler, parser worker'ları ayrı süreçlerdir. _Kaynak:_ OP-2. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Identity plane ayrı cell/cluster/KMS/operatör rolleri; tek kanal Claim Ingest API'si** — _Kaynak:_ §12.1.2, §12.4; T31; TI-15. _Durum:_ belirtilmemiş.
- [ ] **`mlock` / memlock dağıtım gereksinimi** — `IPC_LOCK`; RLIMIT_MEMLOCK log ve uyarı. _Kaynak:_ CR-34. _Durum:_ belirtilmemiş.
- [ ] **Zamanlanmış anahtar rotasyonu operasyonel** — Politika dahilinde yürütme ayrı Exercise gerektirmez. _Kaynak:_ §12.1.2; TN-12, TN-118. _Durum:_ belirtilmemiş.

#### Arıza davranışı ve bozulmuş mod

- [ ] **Signer erişilemezse token üretimi 503** — Signer'sız imza yolu yoktur. _Kaynak:_ §16.7.1. _Durum:_ belirtilmemiş.
- [ ] **Access erişilemezken davranış** — Geçerli contract/slice içindeki kararlar sınıra kadar devam eder, sonra DENY olur. _Kaynak:_ §7.9.14. _Durum:_ belirtilmemiş.
- [ ] **Identity plane bağımsız arıza toleransı** — Identity plane yokken mevcut ValidityContract'lar geçerli kalır. _Kaynak:_ §8.13. _Durum:_ belirtilmemiş.

#### Provider bağımsızlığı ve keşif

- [ ] **Domain Metadata (AP-15)** — Genesis/handover/Acceptance kayıtlarından türetilen imzalı PROJECTION; DomainID, provider binding, anahtarlar, superseded anahtar durumu, witness/replica kümesi, endpoint'ler, sürümler, minimum sürüm, status/event, export ve checkpoint kaynakları. _Kaynak:_ §9.15; P3. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Discovery: `.well-known` ve/veya OIDF entity statement** — OIDF kabında Domain Metadata ayrıca imzalı iç nesnedir. _Kaynak:_ §9.15; P3. _Durum:_ belirtilmemiş (ADOPT/PROFILE).
- [ ] **Üç ayrı discovery belgesi** — Domain Metadata, OIDC/RFC 8414 AS metadata ve `authzen-configuration` ayrı belgelerdir. _Kaynak:_ §9.15.1 k.2; P60. _Durum:_ belirtilmemiş (FROZEN).

### K18 Açık kaynak, ticari model ve paketleme

#### Açık kaynak bileşenler

- [ ] **Açık bileşenler (reference verifier, Offline Verifier Core, conformance suite, replica agent)** — D4 lisans kararıyla açıktır. _Kaynak:_ T36. _Durum:_ belirtilmemiş.

#### First-party nötrlüğü ve birlikte çalışabilirlik

- [ ] **First-party nötrlüğü** — Suiss'in kendi ürünleri (One dahil) third-party'lerle aynı sözleşmeyi kullanır ve envanterde onlarla aynıdır; ayrıcalıklı claim/Claim sınıfı, issuer yöntemi, endpoint, trust anchor veya örtük Acceptance yoktur. External IdP eşit girer. _Kaynak:_ §2.3, §6.1, §6.5, §7.4, §8.17.7.1, §9.13.2, §9.13.8 k.1; must-never #13; CI-15, E3, E24, INV-29, PI-13, X6, XI-18. _Durum:_ belirtilmemiş.
- [ ] **Third-party provider / executor / PEP birlikte çalışabilirliği** — Hepsi aynı sözleşmeyle çalışır. _Kaynak:_ §7.9.16. _Durum:_ belirtilmemiş.
- [ ] **Third-party provider'lar ticari olarak kısıtlanmaz** — _Kaynak:_ B8. _Durum:_ belirtilmemiş.
- [ ] **Plane'ler bağımsız kullanılabilir** — Identity plane third-party authority provider'la, authority plane third-party IdP ile kullanılabilir. _Kaynak:_ §7.9.1.3, §7.9.16; B7, E24. _Durum:_ belirtilmemiş.

#### Ticari model ve fiyat ekseni

- [ ] **Dedicated HSM partition (ücretli paket öğesi)** — _Kaynak:_ CR-21 madde 5. _Durum:_ belirtilmemiş.
- [ ] **Custodial mod non-custodial'dan ucuz değil; geçiş ücretsiz** — _Kaynak:_ B14. _Durum:_ belirtilmemiş.
- [ ] **Protocol katılımı ücretsiz** — PEP/agent vendor'ı, verifier, schema publisher, Claim issuer ödemez. _Kaynak:_ B6. _Durum:_ belirtilmemiş.

#### Ücretlendirilemez güvenlik ve temel yüzeyler

- [ ] **Signer ayrımı ve HSM her müşteriye ücretsiz taban güvence** — İzole signer süreci ve HSM ücretli ek değil, ücretsiz taban güvencedir. _Kaynak:_ B3, CR-21 madde 5, DL-10, MD-17, SA-25. _Durum:_ belirtilmemiş (FROZEN).

### K19 Geliştirme ve kalite güvencesi

#### Access conformance ve test vektörleri

- [ ] **Conformance test paketleri (PEP / verifier / Approval Surface)** — _Kaynak:_ §8.17.10.4. _Durum:_ belirtilmemiş.

#### Protokol, kiracı ve bileşen güvenlik testleri

- [ ] **Single-flight testi** — _Kaynak:_ §9.9.3 k.6. _Durum:_ PD.

### Bu aşamada doğrulanacak sınırlar

#### Ürün kapsamı

- [ ] **IdP değiştirmeyi şart koşmaz** — _Kaynak:_ §18.2; B7; H13a. _Durum:_ belirtilmemiş.
- [ ] **Merkezî PEP dayatılmaz** — _Kaynak:_ §11.18 #7. _Durum:_ belirtilmemiş.

#### Token modeli

- [ ] **Bearer authority yok** — Authority taşıyan projection holder-bound'dur; WIT de bearer olarak kullanılamaz; bugünkü bearer-only MCP istemcilerine FOR(P) authority verilmez (authority taşımayan eski profil istisnası hariç). _Kaynak:_ §9.9.3 k.2; §11.8.3; AG-18; G18; PI-11; RR-44; TN-27. _Durum:_ belirtilmemiş.
- [ ] **Token passthrough ve Exercise'sız token release yok** — RS başka token'ı kabul etmez/transit ettirmez; istemci token'ı upstream'e geçmez. _Kaynak:_ §7.3; §9.9.3 k.9; E36; L24; RS-M8; RS-M10. _Durum:_ belirtilmemiş.
- [ ] **CT3 için projection yok; CT2+ için bounds token yok** — _Kaynak:_ §9.9.3 k.4; §13.7.3; §13.7.9. _Durum:_ belirtilmemiş.
- [ ] **Hata gövdelerinde serbest metin yok; `not-satisfiable-by-actor` → `interaction_required` eşlemesi yok** — _Kaynak:_ §9.9.5. _Durum:_ belirtilmemiş.

#### Yetki modeli

- [ ] **PEP/proxy/gateway ve transport kimliği actor veya holder olamaz** — "Service account acts for user" yoktur. _Kaynak:_ §8.17.10.5; §9.5 k.2–3; §11.8.3; §11.14.3; E17; X21. _Durum:_ belirtilmemiş.
- [ ] **OAuth/CIMD client actor, Claim issuer, örtük issuer veya authority holder değil** — _Kaynak:_ §9.13.8 k.3; AG-4; PI-7. _Durum:_ belirtilmemiş.
- [ ] **Receipt credential değil** — _Kaynak:_ §9.8; R4. _Durum:_ belirtilmemiş.
- [ ] **Ayrı "migration" nesnesi yok** — _Kaynak:_ §9.13. _Durum:_ belirtilmemiş.
- [ ] **Grup üyeliğine ikinci issuer / ikinci yazma yolu yok** — Domain-local grup ile identity plane grubu aynı olamaz. _Kaynak:_ §5.17; TN-95. _Durum:_ belirtilmemiş.

#### Karar ve tutarlılık

- [ ] **Cache-miss'te "iptal edilmemiş" / epoch=0 varsayımı yok** — _Kaynak:_ OPI-3. _Durum:_ belirtilmemiş.
- [ ] **Beyansız istemci içi karar noktası conformant değil** — _Kaynak:_ §9.7A.7; P47. _Durum:_ belirtilmemiş.

#### Onay ve kanıt

- [ ] **Attestation/trust mark/VC/CIBA cevabı tek başına authority veya Grant üretmez; onay (AAS) atlanmaz** — _Kaynak:_ §10.7.1; IDI-3; IDI-9. _Durum:_ belirtilmemiş.

#### Kiracı genişletilebilirliği

- [ ] **Claim mapper authority üretemez; kiracıya serbest ifade veya şablon yok** — _Kaynak:_ §9.9.6; P55. _Durum:_ belirtilmemiş.

#### Kimlik doğrulama yöntemleri

- [ ] **Push/TOTP/OTP/parola hiçbir CT'yi tek başına karşılamaz** — _Kaynak:_ §10.3.3; IDP-4. _Durum:_ belirtilmemiş.

#### Federasyon, şema ve güven

- [ ] **Ayrı "trust configuration" mesajı yok** — Acceptance meta-Exercise'tır. _Kaynak:_ §9.13. _Durum:_ belirtilmemiş.
- [ ] **Suiss'e / Suiss Identity'ye özel Claim sınıfı ve örtük Acceptance yok** — _Kaynak:_ §9.13.2; §10.1.4. _Durum:_ belirtilmemiş.
- [ ] **Broadening/incompatible mapping otomatik kullanılmaz** — _Kaynak:_ §9.13.4. _Durum:_ belirtilmemiş.
- [ ] **Global schema registry yok** — _Kaynak:_ §9.13; T30. _Durum:_ belirtilmemiş.

#### Kriptografi

- [ ] **İmzalı kayıtlar için forward secrecy yok** — _Kaynak:_ §13.2. _Durum:_ belirtilmemiş.
- [ ] **Rutin binding key rotasyonu yok** — Yalnız handover/recover. _Kaynak:_ CR-19; CR-30; T20. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Node başına token imza anahtarı yok** — _Kaynak:_ CR-20. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Sonradan değiştirilemeyen ana anahtar yok** — _Kaynak:_ OP-58. _Durum:_ belirtilmemiş.
- [ ] **Vault/OpenBao zorunlu değil** — _Kaynak:_ CR-32. _Durum:_ belirtilmemiş.
- [ ] **Üretim signer'ı Apple Silicon'da çalışmaz** — _Kaynak:_ CR-39. _Durum:_ belirtilmemiş (FROZEN).

#### Ürün iddiaları ve vaat edilmeyenler

- [ ] **Hukuki non-repudiation iddia edilmez** — _Kaynak:_ EI-24. _Durum:_ belirtilmemiş.

#### İş modeli ve lisans

- [ ] **CT3 tutanlara custodial hizmet yok** — _Kaynak:_ B14; D6. _Durum:_ belirtilmemiş.

## Aşama 7 — Yönetim ve geliştirici yüzeyi

Yönetim API'si, konsol, CLI, SDK'lar, webhook ve dış çağrı noktaları, GitOps, analitik, gözlemlenebilirlik, SSF/CAEP.

### Spec dışı ön koşullar

- [ ] **Alarm yönlendirme ve nöbet altyapısı** — sev-1 alarmları ve runbook'lar için çağrı sistemi.
- [ ] **GeoIP/ASN veri kaynağı** — imkânsız seyahat, şüpheli IP ve ASN bağlama için; kaynak, lisans, güncelleme ve gizlilik değerlendirmesi.
- [ ] **Plan, fatura ve kota durumu altyapısı** — ticari hesap, fatura yüzeyi, kota ve kapasite rezervasyonu.

### K01 Kimlik doğrulama yöntemleri

#### Genel model ve tipli sonuç

- [ ] **Kiracının giriş yöntemlerini seçmesi** — Kiracı panelden hangi giriş yöntemlerinin açık olacağını seçer: e-posta, telefon, kullanıcı adı, sosyal sağlayıcı, passkey. _Kaynak:_ §12.4.2; TN-132. _Durum:_ belirtilmemiş (FROZEN).

#### Passkey / WebAuthn: yöntem ve güvence

- [ ] **Platform biyometrisi ve passkey (mobil SDK)** — Mobil SDK paketleri passkey ve platform biyometrisi desteği taşır. _Kaynak:_ §16.10 T41 madde 4. _Durum:_ gün-1.

### K02 Kimlik protokolleri ve federasyon

#### İstemci kaydı ve istemci kimliği

- [ ] **OIDC/SAML client kaydı (developer merceği)** — Redirect URI, imza algoritması seçimi (MD-3), pairwise/public `sub` seçimi (MD-10); realm config değişikliği olarak (E34). _Kaynak:_ §8.17.2.1 notu, §8.17.10.1. _Durum:_ belirtilmemiş.

#### OIDC özellikleri ve oturum

- [ ] **Native SSO for Mobile Apps** — `device_secret` cihaz anahtarına bağlı; aynı vendor uygulamaları arasında token exchange. _Kaynak:_ §10.4.6; IDP-24. _Durum:_ WATCH (PROFILE, varsayılan kapalı).
- [ ] **FiPA — First-Party Apps (`authorization_challenge_endpoint`, `auth_session`)** — Tarayıcısız first-party istemci için (SPA değil); istemci kanıtlaması zorunlu, sunucu her aşamada `redirect_to_web` ile tarayıcıya düşürebilir; taslak expire olursa kapalı. _Kaynak:_ §10.5.2; §11.11.6, §11.21.1 #29, §11.21.2; §12.4.1; IDP-13; TN-101. _Durum:_ WATCH (varsayılan kapalı); §12.4.1'e göre PD.
- [ ] **Tarayıcı redirect'i olmayan (mobil ana akış) kalıp** — Mobil ana akış için redirect'siz kalıp gereksinimi. _Kaynak:_ §4.8 eksen 9. _Durum:_ belirtilmemiş.

#### Upstream IdP ve kimlik federasyonu

- [ ] **SSF/CAEP sinyal alımı ve yayımı** — Sinyal tüketen RS teslim edilmiş session-revoked / credential-change olayından sonra oturumu beyanlı süre içinde sonlandırır; gelen CAEP "yeniden sor" tetikleyicisidir, best effort. _Kaynak:_ §13.4 U38, N-38; EP-5. _Durum:_ belirtilmemiş.
- [ ] **Back-channel logout ve CAEP ile RP sözleşmesi** — RP seam'inin parçasıdır. _Kaynak:_ §7.3 Identity plane ↔ RP. _Durum:_ belirtilmemiş.
- [ ] **CAEP/SSF gelen sinyal gecikmesi durumu** — Admin'e "Signals from *Provider* delayed since 14:02 — decisions use declared validity windows"; risk motoru/cache arızası ALLOW'a dönmez. _Kaynak:_ §8.13. _Durum:_ belirtilmemiş.

### K03 Oturum ve token yönetimi

#### Login oturumu

- [ ] **Yönetici konsol oturum politikası** — 12 saat mutlak, 15 dk boşta, ASN bağlama ve isteğe bağlı IP bağlama; tüm yönetim yüzeylerini kapsar. _Kaynak:_ §12.5.5; TN-129. _Durum:_ PD.

#### Oturum çerezi, BFF ve cihaza bağlama

- [ ] **BFF (Backend-for-Frontend)** — Konsol çerezi BFF ile yönetilir ve SPA müşterilerine BFF resmî olarak önerilir. BFF authority holder olamaz; BFF oturum deposu arızası fail-closed'dur. _Kaynak:_ §2.2.1; §2.2.2 #3; §12.2.1, §12.4.1; TN-34. _Durum:_ PD.

#### Epoch'lar ve hızlı iptal

- [ ] **Anahtar ele geçirilmesinde RP bildirimi (SSF/CAEP veya logout)** — [ID] imza anahtarı ele geçirilirse anahtar acil DROPPED'a geçer, RP'ler SSF/CAEP veya logout ile bilgilendirilir. _Kaynak:_ CR-27. _Durum:_ belirtilmemiş (FROZEN).

#### Token ömürleri ve ValidityContract

- [ ] **Yönetim / konsol token'ı ≤ 60 dk** — Yönetim yüzeyinde access token ömrü en fazla 60 dakikadır ve yalnız CT0 okuma/gezinmeyi kapsar, hiçbir meta-Exercise'ı yetkilendirmez. Token holder-bound ve iptal edilebilirdir. _Kaynak:_ §7.1; §9.9.3 k.4; §10.4.5; §12.2.1; §12.5.5; §18.5; TN-37, TN-130. _Durum:_ PD; §12.5.5'e göre FROZEN.

#### Refresh token

- [ ] **Mobil single-flight refresh** — Mobil SDK'lar eşzamanlı yenileme yarışını önlemek için token yenilemeyi single-flight yapar. _Kaynak:_ §12.2.1; T41 madde 4; TN-31. _Durum:_ gün-1; PD (TN-31).

### K05 Kiracılık, realm ve B2B organizasyonlar

#### Realm şablonları ve sandbox

- [ ] **Geliştirme/sandbox realm'i** — Geliştirici için hosted sandbox realm; ortak sosyal test anahtarlarıyla, fiziksel fair-use ile ücretsiz. _Kaynak:_ §18.3, §18.9 D7; H8; IDP-31. _Durum:_ HYPOTHESIS (H8/D7).

#### Kiracılık kavramlarının UI ve yönetimde görünümü

- [ ] **Billing admin / Sign-in settings / Authority admin ayrımı** — Ticari abonelik yöneticiliği authority içermez; realm config ve authority yönetimi ayrı bölümlerdir. _Kaynak:_ §8.11, §8.17.2.1 notu. _Durum:_ belirtilmemiş.
- [ ] **Platform-admin ve realm-admin API ayrımı** — Yönetim API'sinde iki ayrı yüzey (audience, scope, rate bütçesi). _Kaynak:_ CMP-15.5. _Durum:_ belirtilmemiş.

### K06 Giriş deneyimi, UI bileşenleri ve markalama

#### Giriş akışı ve yöntemler

- [ ] **Telemetri (passkey/koşullu UI)** — İstemci yetenek sonucu, odak olayı ve koşullu sözün çözülmesi ayrı ölçülür. _Kaynak:_ §12.4.1; TN-99. _Durum:_ PD.

#### Experience yüzeyleri (S1–S11)

- [ ] **S8 Developer console** — Schema kabulleri, PEP doğruluğu, karar açıklaması. _Kaynak:_ §8.5; X21. _Durum:_ belirtilmemiş.

#### Bilgi mimarisi

- [ ] **Admin bölümü** — Roles & templates, People & agents, Sources, Restrictions & requirements, Protected actions & break-glass, Offboarding, Domain, Changes; + "Sign-in settings". _Kaynak:_ §8.17.4.1. _Durum:_ belirtilmemiş.
- [ ] **Developer bölümü** — Namespaces & schemas, Integrations, Decision lab, Logs. _Kaynak:_ §8.17.4.1. _Durum:_ belirtilmemiş.
- [ ] **Audit bölümü** — Records, Replay, Revocation impact, Unknown outcomes, Export. _Kaynak:_ §8.17.4.1. _Durum:_ belirtilmemiş.
- [ ] **Yetkiye göre görünürlük (IA-5)** — Admin/Developer/Audit bölümleri viewer'ın authority'sine göre gösterilir; görünen her eylem gerçekten exercise edilebilir. _Kaynak:_ IA-5. _Durum:_ belirtilmemiş.

#### Experience altyapısı ve konsol

- [ ] **Konsol için çerez tabanlı BFF; çerez yalnız gezinti** — Konsol çerezi yalnız gezinti ve okumayı taşır, tek başına authority değişikliğini yetkilendiremez; her meta-Exercise CT tazeliğinde AIS ister, authority okuması AIS veya holder-bound projection ister. _Kaynak:_ §9.15.1 k.3; CMP-15.6; MD-14. _Durum:_ belirtilmemiş.
- [ ] **Causal binding konsol uyarısı** — `causal_binding = audit-only` işareti X21 konsol uyarısının kaynağıdır. _Kaynak:_ §9.9.2. _Durum:_ belirtilmemiş.

### K07 Yetki modeli

#### Kullanıcı arayüzü semantiği

- [ ] **Varsayılan görünürlük (X31) / operatör yetkisiz** — Party kendi holding'lerini, verdiği Grant'ları ve alt ağacını, FOR(kendisi) kullanımlarını görür; ötesi explicit authority ister. "Platform yöneticisi bile göremesin" varsayılandır. _Kaynak:_ §8.17.7.1; §12.5.2; TN-119, X31. _Durum:_ PD (ürün varsayılanı, §8); FROZEN (§12.5.2)

#### Değer metriği

- [ ] **Value metric: Authority Exercise** — İlk committed ALLOW ile doğan kayıtlı, attributable kullanım; değer raporlaması bundan türer. _Kaynak:_ §18.4; B17, C30, F5. _Durum:_ belirtilmemiş (FROZEN STRATEGY)

### K08 Karar, uygulama ve doğrulama

#### Offline doğrulama ve verifier

- [ ] **Offline verifier saat/profil sağlığı uyarısı** — "POS-7's clock/profile report is missing; exposure window unknown beyond declared 18:00." _Kaynak:_ §8.13. _Durum:_ belirtilmemiş.

### K09 Ajanlar ve MCP

#### Ajan kimliği ve modeli

- [ ] **Otomasyon (CLI/CI) = agent/servis Instance'ı** — _Kaynak:_ §12.5.5; TN-130. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **GitOps uzlaştırıcısı agent Party'si** — (bkz. K11) _Kaynak:_ §12.5.3; TN-122. _Durum:_ belirtilmemiş (FROZEN)

### K11 Yönetim API'si, konsol, SDK'lar ve geliştirici araçları

#### Yönetim yazma yolu ve yetki modeli

- [ ] **Yönetim API'sinde credential'ı doğrudan yazan uç nokta yok** — _Kaynak:_ §8.17.9.8 notu. _Durum:_ belirtilmemiş.
- [ ] **Ayrı admin token sınıfı yok** — Yönetim yüzeyindeki ≤ 60 dk token yalnız CT0 okuma/gezinme içindir; yetki taşıyan ayrı admin token yoktur. _Kaynak:_ §10.1.7; §12.5.5; §13.2; CMP-15.5; TN-130. _Durum:_ belirtilmemiş (FROZEN).

#### API yüzeyleri ve ayrım

- [ ] **Platform-admin ve realm-admin API'leri ayrı** — Ayrı audience, scope namespace ve rate bütçesi; master realm modeli yok. _Kaynak:_ §2.2.2 #3; §3.1b #21; §6.2; §12.5.2; INV-2; MD-14; TN-119. _Durum:_ gün-1 (§3.1b); FROZEN (§12.5.2).
- [ ] **Beş API ailesi** — Standart protokol, yönetim, karar, Frontend API, iç RPC. _Kaynak:_ §17.14; OP-65. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **Admin API ve konsolun ayrı hostname/port'ta sunulması** — _Kaynak:_ §17.9.6; CMP-15.5. _Durum:_ belirtilmemiş.

#### REST API kuralları

- [ ] **`Idempotency-Key` tüm değiştiren uç noktalarda (→ AIS nonce)** — Anahtar nonce'a eşlenir; eksik 400, aynı anahtar + aynı içerik ilk sonuç (başarılı kısa devre), farklı yük 422, eşzamanlı 409; doğrulama hatası yeniden çalışır. ≤ 255 karakter, kişisel veri içermez, saklama penceresi yayımlanır. _Kaynak:_ §2.2.1; §9.5.2 k.5; §12.5.4; MKT-D15; OP-63; OP-65; P39; TN-126. _Durum:_ gün-1 (FROZEN eşleme; saklama PD).
- [ ] **API sürümleme (`/v1`, yalnız eklemeli, Deprecation/Sunset)** — Ana sürüm adreste; RFC 9745 / RFC 8594 başlıkları. _Kaynak:_ OP-65. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **REST: kaynak başına sürüm** — `/admin/api/{realm}/clients/v2`. _Kaynak:_ §12.5.1; TN-112. _Durum:_ PD.
- [ ] **OpenAPI koddan üretilir, SDK'lar şartnameden** — CI eşitlik ve kırıcı değişiklik kapısı. _Kaynak:_ §12.5.1; OP-65; TN-112. _Durum:_ PD (TN-112); FROZEN TECHNICAL (OP-65).
- [ ] **REST: PUT/POST/PATCH (JSON Merge Patch)** — _Kaynak:_ §12.5.1; TN-112. _Durum:_ PD.
- [ ] **REST: 201 + tam temsil** — _Kaynak:_ §12.5.1; TN-112. _Durum:_ PD.
- [ ] **REST: doğal anahtarla adresleme** — _Kaynak:_ §12.5.1; TN-112. _Durum:_ PD.
- [ ] **REST: SCIM filtre alt kümesi, bilinmeyen alan → 400** — _Kaynak:_ §12.5.1; TN-112. _Durum:_ PD.
- [ ] **REST: tek istekte tam yaratma + genişletme** — _Kaynak:_ §12.5.1; TN-112. _Durum:_ PD.
- [ ] **Opak imleçli sayfalama + `Link` başlığı** — Offset/sayfa numarası yok. _Kaynak:_ §12.5.1; OP-65; TN-112. _Durum:_ PD.
- [ ] **ETag / If-Match iyimser eşzamanlılık (412)** — _Kaynak:_ OP-65. _Durum:_ belirtilmemiş.
- [ ] **RFC 9457 Problem Details hata biçimi, kalıcı hata kodları** — _Kaynak:_ OP-64; OP-65. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **Tipli hatalar, karar ≠ hata, numaralandırma-nötr hatalar** — _Kaynak:_ OP-64; TN-96. _Durum:_ belirtilmemiş.
- [ ] **API biçim kuralları** — `snake_case`, RFC 3339 UTC, büyük tamsayılar string. _Kaynak:_ OP-8; OP-65. _Durum:_ belirtilmemiş.
- [ ] **`Request-Id` ve standart `RateLimit` başlıkları** — _Kaynak:_ OP-65. _Durum:_ belirtilmemiş.

#### Hız ve yapı limitleri

- [ ] **Üç katmanlı yönetim API hız sınırı** — Kova, eşzamanlılık semaforu, aktör bazlı koruma. _Kaynak:_ §12.5.4; TN-127. _Durum:_ PD.

#### Toplu işlemler ve deklaratif yapılandırma

- [ ] **Toplu işlem (bulk) iş API'si** — Bulk revoke/amend attributable Exercise kümeleridir: her öğe ayrı Exercise, preview etkileri toplar; `202` + LRO yoklama, öğe başı hata dosyası, zarf içi kısıtlama zarfta görünür, sıralı-ya-paralel + 424. _Kaynak:_ §8.17.9.8; §12.5.4; TN-125; X20. _Durum:_ FROZEN (Exercise kümesi), PD (ergonomi).
- [ ] **Deklaratif yapılandırma / GitOps uzlaştırıcısı** — Kendi Instance/Grant'ı olan agent Party'dir ve yönetim API'sinin istemcisidir; değişiklikleri meta-Exercise'a indirir, her uygulama bir Exercise'tır, reserved değişiklikler yalnız önerilir. _Kaynak:_ §6.2; §12.5.3; INV-2; OP-65 tablo; TN-122. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Deterministik, fark alınabilir dışa aktarım (yapılandırma)** — Sırlar referansla; istenen/çalışma zamanı durumu ayrımı; tam CRUD + kayma uzlaştırması. _Kaynak:_ §12.5.3; TN-123. _Durum:_ PD.
- [ ] **Uzlaştırma yönü ve acil kaçış** — Yönetilen alanlar konsolda salt okunur; bant dışı yazma red; acil kaçış denetimli restriction Exercise'ı (CT1); uzlaştırıcı restriction'ı geri almaz. _Kaynak:_ §12.5.3; TN-124. _Durum:_ belirtilmemiş (FROZEN).

#### Yönetim konsolu: temel

- [ ] **Yönetim konsolu (BFF + çerez, DBSC'ye hazır)** — Konsol çerezi yalnız gezinmeyi ve authority taşımayan identity plane ekranlarını taşır; authority okuması ADP üzerinden, yazmalar istemcide üretilen AIS ile yapılır. _Kaynak:_ §2.2.2 #3, #7; §5.12; §7.7; §10.1.7; §10.4.5; §12.5.5; TN-128; TNI-12. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Authority grafiği ve audit okuması (envanter, explain, search, audit, export)** — Grant/Acceptance envanteri, explain, search, audit ve export okumaları AIS (CT0, step-up istemez) veya cihaz-bağlı, holder-bound bir okuma projection'ı ile ADP üzerinden yapılır; BFF holder olamaz. _Kaynak:_ §2.2.2 #3; §5.12; §7.7; §10.1.7; PI-4; PI-7. _Durum:_ belirtilmemiş.
- [ ] **Kendi profil ve kendi oturum listesi ekranları** — Konsol çereziyle, authority taşımayan ekranlar. _Kaynak:_ §2.2.2 #3. _Durum:_ belirtilmemiş.
- [ ] **Konsol teknolojisi (TypeScript, Kernel'e Wasm)** — _Kaynak:_ §12.5.1; MD-1; OP-62 `web/`; T35. _Durum:_ belirtilmemiş.
- [ ] **Genesis kurulum sihirbazı** — Cihaz-bağlı authenticator ile imzalı tek kayıt; `Joint(k≥2)` önerisi; Sole'de "Recovery not available" uyarısı. _Kaynak:_ §12.5.1; TN-111. _Durum:_ PD (UX).
- [ ] **Admin arama/listeleme ve raporlar (replica'dan)** — _Kaynak:_ §17.4.6; OP-27. _Durum:_ belirtilmemiş.
- [ ] **Konsol kiracı analitiği paneli** — Bkz. K14. _Kaynak:_ IDP-36. _Durum:_ PD.

#### Konsol: rol, kaynak ve domain ekranları

- [ ] **Rol editörü (typed AuthoritySet editörü)** — "Not included" bloğuyla. _Kaynak:_ §8.17.9.2. _Durum:_ belirtilmemiş.
- [ ] **Rol sürümleme ve change-impact preview** — "Moving 3 role delegations to v5 gives 41 people a new ability…"; geçiş explicit toplu `grant.amend`, genişletme requirement'ları ile. _Kaynak:_ §8.17.9.2; X20. _Durum:_ belirtilmemiş.
- [ ] **`policy.set` ve rol sürümü önizlemesinde SMT analizi** — Cedar eşdeğerlik/kapsama analiziyle "yetki değişti mi?" sorusu sorulur; CI'da yaklaşık 75 ms (doğrulanmadı). _Kaynak:_ §5.8. _Durum:_ belirtilmemiş.
- [ ] **Admin Grant'ının meta-action'larını tek tek göstermesi** — Reserved meta-action'lar (`acceptance.*`, `anchor.*`) ayrı, pin'li ve quorum'lu. _Kaynak:_ §8.17.9.2. _Durum:_ belirtilmemiş.

#### Geliştirici konsolu ve schema yayını

- [ ] **Schema publishing → domain acceptance akışı** — Developer namespace + typed schema yayınlar; domain admin diff, parametre sınıfları, reserved bayrakları, compatibility beyanı görür ve exact fingerprint ile kabul eder. _Kaynak:_ §8.17.10.2; §18.3; X21. _Durum:_ belirtilmemiş.
- [ ] **Console "Pending acceptance in: …" (kabul düğmesi yok)** — _Kaynak:_ §8.17.10.2; X21. _Durum:_ belirtilmemiş.
- [ ] **Tipe eşlenemeyen authority-relevant parametre uyarısı** — Console uyarı verir: "`note` affects who receives money — map it to a recipient type…". _Kaynak:_ §8.17.10.2; §9.13.3; E12. _Durum:_ belirtilmemiş.
- [ ] **Yeni schema sürümü mevcut Grant'ları değiştirmez mesajı** — _Kaynak:_ §8.17.10.2; E10. _Durum:_ belirtilmemiş.
- [ ] **Developer console Logs ve Integrations** — _Kaynak:_ §8.17.4.1. _Durum:_ belirtilmemiş.
- [ ] **Developer'a yalnız protokol bağlamında OAuth terimleri** — "OAuth grant type", "OAuth scope" nitelenmiş. _Kaynak:_ §8.11. _Durum:_ belirtilmemiş.
- [ ] **Policy authoring araçları, toplu simülasyon raporları** — Enterprise konfor (ücretli olabilir). _Kaynak:_ §18.3, §18.5. _Durum:_ belirtilmemiş.

#### Decision lab, sandbox ve conformance

- [ ] **Decision lab** — Advisory + replay + conformance. _Kaynak:_ §18.3. _Durum:_ belirtilmemiş.
- [ ] **Decision lab: Check** — Advisory, "not recorded, not a promise". _Kaynak:_ §8.17.10.4. _Durum:_ belirtilmemiş.
- [ ] **Decision lab: Explain (structured explain)** — Developer derinliğinde reason class, unmet terms, authority yolu. _Kaynak:_ §8.17.10.4; §18.3. _Durum:_ belirtilmemiş.
- [ ] **Sandbox = ayrı AuthorityDomain** — "Test mode" bayrağı yok; prod ↔ sandbox akış yok; fair-use ile ücretsiz. _Kaynak:_ §8.17.10.4; §18.3; D7; H8; X21. _Durum:_ belirtilmemiş; ücretsizlik HYPOTHESIS (H8/D7).

#### SDK'lar

- [ ] **SDK: dil başına tek paket (`auth` + `authorize`), Kernel'e bağlı** — `auth` identity, `authorize` PEP; modüller kod düzeyinde ayrı; sunucu Rust, konsol TypeScript. _Kaynak:_ §12.5.1; CMP-17; T35; T41 madde 1. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Kernel bağlamaları (uniffi, Wasm, C ABI)** — Karar/doğrulama/kodlama her dilde aynı Kernel'den; bağlamaların conformance vektörlerini geçmesi CI kapısı. _Kaynak:_ OP-62 `sdks/bindings`; T41 madde 6. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **İstemci / IdP SDK'ları (RP/OIDC client, SAML SP yardımcıları, MCP client/server)** — RP tarafını kapsar; headless kullanım yönetim API'si ve SDK'larla kısmen karşılanır. _Kaynak:_ §4.5; §18.3; T41. _Durum:_ belirtilmemiş.
- [ ] **İstemci SDK'sında refresh single-flight** — Eşzamanlı çağıranlar aynı sonucu bekler; davranış testle kapsanır. _Kaynak:_ §9.9.3 k.6; P50. _Durum:_ PD.
- [ ] **RS SDK (DPoP replay kontrolü dahil)** — _Kaynak:_ §10.4.3. _Durum:_ belirtilmemiş.
- [ ] **Backend SDK'ları: TypeScript/Node, Python, Go, Java, .NET** — _Kaynak:_ T41 madde 3. _Durum:_ gün-1 (liste PD).
- [ ] **Backend SDK'ları: PHP ve Ruby** — _Kaynak:_ T41 madde 3. _Durum:_ yol haritası.
- [ ] **Mobil SDK'ları: iOS (Swift), Android (Kotlin), React Native (Expo)** — _Kaynak:_ T41 madde 4. _Durum:_ gün-1 (liste PD).
- [ ] **Mobil SDK: Flutter** — _Kaynak:_ T41 madde 4. _Durum:_ yol haritası.
- [ ] **Web SDK: React + web components** — _Kaynak:_ T41 madde 5. _Durum:_ PD.
- [ ] **SDK SemVer ve uyumluluk tablosu; son iki minor için güvenlik desteği** — _Kaynak:_ OP-68. _Durum:_ PD (destek penceresi).

#### Komut satırı ve operasyon araçları

- [ ] **`access-cli`** — Yönetim, `access ssh login`, replay. _Kaynak:_ OP-62. _Durum:_ belirtilmemiş.

#### Genişletme noktaları ve entegrasyon yüzeyleri

- [ ] **Dış çağrı noktaları (inline hook)** — Kayıt öncesi, token üretimi, giriş sonrası kiracı HTTPS'ini imzalı istekle çağırır; yalnız reddetme veya yetkisiz claim ekleme; fail-closed (claim eklemede "cevap yoksa devam" seçeneği); kayıt `idp.*` domain action. _Kaynak:_ §12.4.2; TN-135. _Durum:_ FROZEN (kurallar), PD (çağrı noktası listesi).
- [ ] **Webhook'lar (Standard Webhooks)** — Kullanıcı, üyelik, oturum iptali, tercih/belge onayı, ajan askısı olayları; imzalı, en az bir kez, yeniden deneme, idempotency kimliği; outbox kaynaklı; bildirim ≠ authority. _Kaynak:_ §12.4.2; TN-136. _Durum:_ FROZEN (kurallar), PD (olay kataloğu).

### K12 Entegrasyonlar ve yardımcı servisler

#### Genel entegrasyon ilkeleri

- [ ] **Kiracının kendi sunucusundaki dış çağrı noktaları** — Özelleştirme, kiracının kendi sunucusunda çalışan dış çağrı noktalarıyla yapılır; kod Access sürecinde çalışmaz. _Kaynak:_ §Kısaca; F23; TN-135. _Durum:_ belirtilmemiş.

#### SSF/CAEP, olay yayını ve Relay

- [ ] **SSF/CAEP/RISC vericisi (Outbox Relay + SSF Transmitter)** — Identity plane kendi CAEP/RISC olaylarını ve Access semantic event'lerini yayınlar: outbox → NATS JetStream → SET imzası → push (RFC 8935) / poll (RFC 8936), receiver başına stream, disclosure scope receiver yetkisi kadar. Best effort teslimdir, güvenlik kararına girdi değildir (receiver re-query); event id domain başına HMAC, sıra garantisi yok. _Kaynak:_ §9.16.2 k.3; §13.2; §17.3.1; CMP-10; MD-13; P33; P59; T26. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Self-host küçük formda polling (NATS opsiyonel)** — _Kaynak:_ T26. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **SSF semantic event akışı ücretsiz** — _Kaynak:_ §18.6; §18.7 B3. _Durum:_ belirtilmemiş.
- [ ] **CAEP olayları (identity plane)** — _Kaynak:_ §17.3.3, §17.3.5; OP-20, OP-22. _Durum:_ belirtilmemiş.
- [ ] **"Expansion about you" event'leri** — Zorunlu event türü (teslim NG). _Kaynak:_ §17.3.1; SI-21. _Durum:_ belirtilmemiş.
- [ ] **SSF/CAEP/RISC alıcısı (inbound)** — Gelen SET bir Claim'dir; yalnız yeniden sor veya Acceptance'lı daraltma etkisi vardır; `session-revoked` actor-binding düşüşü ve `session_epoch` artışı yaratır. _Kaynak:_ §9.16.2 k.4; P59. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Google RISC adaptörü vb. SSF alıcı adaptörleri** — Alıcı arayüzü gün-1, adaptörler fazlı. _Kaynak:_ §12.2.2; TN-42. _Durum:_ PD (adaptör fazlı).
- [ ] **Identity audit sinyal adaptörleri (OCSF/SET/CAEP/CEF)** — İki yayın kanalı: CAEP akışı ve tam denetim akışı. _Kaynak:_ CMP-27; OP-37–OP-44. _Durum:_ belirtilmemiş.

### K13 Denetim, kayıt, şeffaflık ve dışa aktarım

#### Exercise ve karar kayıtları

- [ ] **Örneklenmiş debug izleri** — Explain/DecisionTrace ve Cedar Diagnostics benzeri izler operatör telemetrisidir, authority kaydı değildir. _Kaynak:_ §9.7.1; §9.16.3. _Durum:_ belirtilmemiş.

#### Denetime erişim ve disclosure

- [ ] **Denetime erişimin denetimi; örnekleme yok** — Audit örneklenmez; her denetim sorgusu bir denetim olayıdır ve loglanır; üst denetim ayrı zincirdedir, authority'de `access.audit.export` Exercise'ıdır. _Kaynak:_ §13.4 U53; §14.9; §17.6.11; OP-44; PI-4. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).

#### Dışa aktarım adaptörleri ve akışlar

- [ ] **İki yayın kanalı** — CAEP aksiyon akışı (8 tip) + tam taksonomili denetim akışı; ortak `txn`; üç zaman damgası (gerçekleşme, kayıt, checkpoint). _Kaynak:_ §17.6.8; OP-41. _Durum:_ belirtilmemiş.
- [ ] **Ham olay / izin değişikliği webhook'ları** — Analitik ham olayları ve tercih değişiklikleri webhook ile kiracıya. _Kaynak:_ IDP-36, IDP-37. _Durum:_ belirtilmemiş.

### K14 Sinyaller, gözlemlenebilirlik ve analitik

#### SSF/CAEP verici ve alıcı

- [ ] **SSF/CAEP vericisi (identity plane)** — İki plane'de ortak SSF vericisi identity plane'de çalışır; authority event içeriği Access'ten gelir. Final'in sekiz olayını best effort yayınlar; güvenlik teslimata/sinyale dayanmaz, sinyal yalnız hızlandırıcıdır. _Kaynak:_ §2.2.1; §2.4; §7.1; §7.6; §11.0; §11.21.1 #17; §11.21.2 (`/ssf/.well-known/sse-configuration`); AG-1; E38; L18. _Durum:_ belirtilmemiş (PROPOSED FOR FREEZE §7; ADOPT §11).
- [ ] **SSF/CAEP alıcısı** — Dış CAEP/SSF sinyalleri alınır; gelen olaylar `risk.*` / posture Claim'idir ve yalnız daraltır, narrowing kota dışıdır, authority yaratamaz. Sinyal kaybı veya arıza ALLOW'a dönmez. _Kaynak:_ §2.4; §2.5; §7.1; §7.6; §11.0; §12.2.2; E38; L18; TN-42. _Durum:_ gün-1 (alıcı arayüzü), FROZEN.
- [ ] **SSF keşfi `/.well-known/ssf-configuration`** — Path'li biçim dahil. _Kaynak:_ §12.2.2; TN-39. _Durum:_ PD.
- [ ] **SSF beş uç nokta** — Yapılandırma, durum, özne ekle/çıkar, doğrulama; ikinci stream 409 döner. _Kaynak:_ §12.2.2; TN-39. _Durum:_ PD.
- [ ] **SSF push (RFC 8935) ve poll (RFC 8936) teslimi** — `ssf.read`/`ssf.manage` kapsamlı, ≤60 dk ömürlü token ile. _Kaynak:_ §12.2.2; TN-39. _Durum:_ PD.
- [ ] **SET kuralları** — `sub_id`, `exp` yok, SET başına tek olay, `txn`, `secevent+jwt`. _Kaynak:_ §12.2.2; TN-39. _Durum:_ PD.
- [ ] **SET imza algoritması stream başına** — Varsayılan ES256; interop için RS256'da tembel RSA. _Kaynak:_ §12.2.2; TN-40. _Durum:_ PD.
- [ ] **CAEP olayları yayını (sekiz olay)** — `session-revoked`, `credential-change`, `assurance-level-change`, `token-claims-change`, `device-compliance-change`, `risk-level-change`, `session-established`, `session-presented`. _Kaynak:_ §12.2.2; TN-41. _Durum:_ PD.
- [ ] **RISC olayları yayını** — `account-disabled`, `account-purged`, `identifier-recycled`, `credential-compromise`. _Kaynak:_ §12.2.2; TN-41, TN-43. _Durum:_ PD.
- [ ] **Access olayı ↔ CAEP/RISC eşleme tablosu** — _Kaynak:_ §12.2.2; TN-41. _Durum:_ PD.
- [ ] **CAEP ile birlikte veya onun yerine yayın** — Access event'leri profile göre CAEP karşılıklarıyla birlikte veya onların yerine yayınlanır. _Kaynak:_ §9.16, §9.16.2. _Durum:_ belirtilmemiş.

#### Authority semantic event'leri

- [ ] **Access authority semantic event'leri (SSF/SET EXTEND)** — revoked, narrowed, expired, mandate-ended, instance-terminated, acceptance-changed, budget-exhausted, revalidation-required, projection-invalidated, domain-handover/recovered olayları SSF stream üzerinden SET olarak yayınlanır; derived bildirimlerdir. _Kaynak:_ §5.2; §7.9.8; §9.16; §12.2.2; AP-11; EI-9; F12; L18; P33; TN-39. _Durum:_ belirtilmemiş (FROZEN); §12.2.2'ye göre PD.
- [ ] **Event: `authority-revoked`** — _Kaynak:_ §5.2; §9.16; §12.2.2; L18. _Durum:_ belirtilmemiş; PD (§12.2.2).
- [ ] **Event: `authority-narrowed`** — _Kaynak:_ §5.2; §9.16; §12.2.2; L18. _Durum:_ belirtilmemiş; PD (§12.2.2).
- [ ] **Event: `authority-expired`** — _Kaynak:_ §9.16; §12.2.2; L18. _Durum:_ belirtilmemiş; PD (§12.2.2).
- [ ] **Event: `mandate-ended`** — _Kaynak:_ §5.2; §9.16; §12.2.2; L18. _Durum:_ belirtilmemiş; PD (§12.2.2).
- [ ] **Event: `instance-terminated`** — _Kaynak:_ §5.2; §9.16; §12.2.2. _Durum:_ belirtilmemiş; PD (§12.2.2).
- [ ] **Event: `acceptance-changed`** — _Kaynak:_ §5.2; §9.16; §12.2.2. _Durum:_ belirtilmemiş; PD (§12.2.2).
- [ ] **Event: `budget-exhausted`** — _Kaynak:_ §5.2; §9.16; §12.2.2; L18. _Durum:_ belirtilmemiş; PD (§12.2.2).
- [ ] **Event: `revalidation-required`** — _Kaynak:_ §5.2; §9.16, §9.16.2; §12.2.2. _Durum:_ belirtilmemiş; PD (§12.2.2).
- [ ] **Event: `projection-invalidated`** — _Kaynak:_ §9.9.3; §9.16; §12.2.2. _Durum:_ belirtilmemiş; PD (§12.2.2).
- [ ] **Event: `domain-handover` / `domain-recovered`** — _Kaynak:_ §9.16; §12.2.2. _Durum:_ belirtilmemiş; PD (§12.2.2).
- [ ] **Event alanları** — HMAC event id, domain, kaynak ExerciseID, subject, etkili zaman, basis referansı. _Kaynak:_ §9.16; TI-RT10. _Durum:_ belirtilmemiş.
- [ ] **Receiver kuralları (event = yalnız re-query sinyali)** — Event authority değildir; hiçbir event veya event kaybı authority genişletmez, kayıp event pencereyi aşamaz; sıra varsayılmaz, re-query yapılır; event'ler disclosure scope'a tabidir. _Kaynak:_ §6.5; §9.16; PI-9; P33. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Ack türleri** — Delivery ack, semantic ack ve authority-state ack ayrıdır; authority-state ack staleness exposure görünümünü besler. _Kaynak:_ §7.9.8.3; E30. _Durum:_ belirtilmemiş.

#### Olay taksonomisi ve log alanları

- [ ] **Kimlik olay taksonomisi ve OCSF/CAEP eşlemesi** — Gözlemlenebilirlik için kendi kimlik olay taksonomisi tanımlanır ve OCSF formatında olay üretimi / OCSF-CAEP eşlemesi sağlanır. _Kaynak:_ §2.2.1; §2.4; §2.5; §17.8.1; OP-47. _Durum:_ belirtilmemiş.
- [ ] **Kalıcı olay adları ve ortak log alanları** — `grant.issued`, `login.failed` vb. değiştirilmez. _Kaynak:_ OP-67. _Durum:_ belirtilmemiş.
- [ ] **Security event'leri (throttling, rejection telemetrisi)** — Requester throttling security event üretir; `check` aşımları ve bilinmeyen sürüm red sayacı telemetriye yazılır. _Kaynak:_ §13.7.4, §13.7.8. _Durum:_ PD.

#### Risk ve tehdit sinyalleri

- [ ] **Temel risk sinyalleri: imkânsız seyahat, sızdırılmış parola, şüpheli cihaz** — _Kaynak:_ IDP-39. _Durum:_ belirtilmemiş.
- [ ] **Risk katmanları SL0/SL1/SL2** — Kriptografik → deterministik politika → risk (step-up + CAEP + insan kuyruğu, kalıcı otomatik kilit yok). _Kaynak:_ §12.2.4; TN-46. _Durum:_ PD (parametreler), FROZEN.
- [ ] **Risk gölge (shadow) modu, öğrenme penceresi, FP bütçesi SLO'su, kademeli çıkış** — _Kaynak:_ §12.2.4; TN-46. _Durum:_ PD.
- [ ] **Saldırı korumalarında izleme modu** — Bot tespiti, şüpheli IP, kaba kuvvet, ihlal edilmiş parola engellemeden yalnız günlüğe yazabilir. _Kaynak:_ §12.2.4, §12.4.3; TN-46, TN-108. _Durum:_ PD.
- [ ] **Canary credentials** — Güvenlik aracı olarak tuzak credential'lar. _Kaynak:_ §4.4 katman testi. _Durum:_ belirtilmemiş.
- [ ] **Residual risk izleme sinyalleri** — Her RR'nin izleme sinyali (ör. rejection oranları, imza kuyruk gecikmesi/kota alarmı, degraded mode süresi, faktör dağılımı, AiTM tespit sinyalleri, oturum anomalileri, public `sub` opt-in sayısı). _Kaynak:_ §13.9. _Durum:_ belirtilmemiş.
- [ ] **Advisory check/explain oracle tespiti** — Security tooling'e export edilir. _Kaynak:_ §17.8.2; SEC31. _Durum:_ belirtilmemiş.
- [ ] **Compromise impact sorgusu** — Instance/issuer/key × zaman penceresi. _Kaynak:_ §16.5.1; CMP-9; SEC15. _Durum:_ belirtilmemiş.

#### Revocation ve sonuç görünürlüğü

- [ ] **Revocation impact ve staleness exposure görünümü** — Revocation zamanı ile projection contract'ları karşılaştırılır. _Kaynak:_ §5.4. _Durum:_ belirtilmemiş.
- [ ] **Revocation exposure ve unknown-outcome dashboard'ları (security tooling)** — _Kaynak:_ §8.17.13. _Durum:_ yol haritası (Candidate).
- [ ] **Yetim tuple sayacı** — Derived index metriği. _Kaynak:_ §5.4. _Durum:_ belirtilmemiş.

#### Telemetri ilkeleri ve altyapısı

- [ ] **Telemetri karar girdisi değildir** — Karar günlüğü ve izler operasyoneldir. _Kaynak:_ §5.2; TI-18. _Durum:_ belirtilmemiş.
- [ ] **OpenTelemetry telemetri** — Telemetri minimize ve pseudonymous'tur, karar girdisi değildir, body/PII taşımaz; VictoriaMetrics/Grafana/ClickHouse ile. _Kaynak:_ §17.8.1; OP-5; OP-47; T37. _Durum:_ belirtilmemiş (FROZEN); PD (araçlar).
- [ ] **Metriklerde tenant/realm/domain etiketi yok** — Kırılım analitik özet tablolarından yapılır. _Kaynak:_ §17.8.1; OP-47; T37. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **ClickHouse analitik katmanı (DERIVED)** — Envelope-level, pseudonymous. _Kaynak:_ §17.8.1; OP-47; T37; T40. _Durum:_ belirtilmemiş.
- [ ] **Derived search/analytics/realtime, viewer-rechecked** — Derived search (FTS) ve analitik/realtime görünümler viewer'a göre yeniden kontrol edilir; global index yok. _Kaynak:_ §17.1.4; §17.8.1; T40. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **W3C traceparent korelasyonu** — HTTP, iç RPC, outbox ve signer boyunca. _Kaynak:_ §17.8.3; OP-67. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **Protokoller arası ortak sağlık/metrik katmanı** — _Kaynak:_ §10.6 ortak altyapı. _Durum:_ belirtilmemiş.
- [ ] **Sağlık uçları `/livez`, `/readyz`, metrik (iç ağda)** — _Kaynak:_ §17.9.3; OP-67. _Durum:_ belirtilmemiş.
- [ ] **Landlock minimum ABI `/healthz`'de loglanır** — _Kaynak:_ §14.5; U42. _Durum:_ belirtilmemiş.
- [ ] **Advisory/explain telemetrisi saklama 90 gün** — _Kaynak:_ §17.6.7. _Durum:_ EA.

#### Operasyon sinyalleri, metrikler ve alarmlar

- [ ] **Operasyon sinyalleri tablosu** — Commit latency, epoch/CAS/fence, witness bekleme, mirror lag, `applied_pos` gecikmesi, ingest kuyruk yaşı, status list `iat` yaşı, rejection/DENY oranları, advisory/explain hacmi, replay uyuşmazlıkları, degraded_mode, epoch cache hit/miss, Argon2 kuyruk, 503/429, sync standby, checkpoint MMD, break-glass, havuz kuyrukları. _Kaynak:_ §17.8.2. _Durum:_ belirtilmemiş (normatif).
- [ ] **Her alarm için runbook** — _Kaynak:_ OP-67, OP-70. _Durum:_ belirtilmemiş.

#### Ürün metrikleri

- [ ] **Ürün metrikleri** — Governed consequential coverage, revocation-to-effective penceresi, time-to-delegate/approve, approval fatigue, over-delegation, kurtarma/onboarding yeniden tetikleme oranı (güvenlik metriği), phishing-resistant auth oranı, sender-constrained token oranı, hesap efektif güvenlik dağılımı. _Kaynak:_ §1.5; §18.4; MKT-D13. _Durum:_ HYPOTHESIS.

#### Kiracı analitiği

- [ ] **Analitik toplu ve kişisel verisiz; karar girdisi değil** — _Kaynak:_ IDP-36; TI-18. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **Kayıt/giriş hunisi** — Adım bazında vazgeçme. _Kaynak:_ IDP-36. _Durum:_ PD.
- [ ] **Giriş yöntemi dağılımı** — _Kaynak:_ IDP-36. _Durum:_ PD.
- [ ] **Passkey benimseme oranı zaman serisi** — _Kaynak:_ IDP-36. _Durum:_ PD.
- [ ] **MFA kurulum tamamlama** — _Kaynak:_ IDP-36. _Durum:_ PD.
- [ ] **Başarısız giriş artışı uyarısı (saldırı belirtisi)** — _Kaynak:_ IDP-36. _Durum:_ PD.

### K15 Güvenlik ve kriptografi

#### Kimlik protokolleri güvenliği

- [ ] **Webhook ve inline hook imzalama** — _Kaynak:_ §12.4.2; TN-135; TN-136. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Konsol güvenliği** — Ayrı köken, kiracı dizgileri güvenilmez, oturuma bağlı CSRF, sıkı CSP, Host'a güven yok, imza ekranı güvenilir yüzey. _Kaynak:_ §12.5.5; TN-131. _Durum:_ belirtilmemiş (FROZEN).

### K16 Gizlilik, rıza ve uyum

#### İfşa kapsamı ve görünürlük

- [ ] **Search sonuçlarında ifşa kontrolü** — `page.total` filtre dışı kayıtların varlığını sızdırmaz. _Kaynak:_ §9.7.1. _Durum:_ belirtilmemiş.

#### Otomatik karar ve üçüncü taraf araçlar

- [ ] **Kalıcı otomatik kilit yok + insan kuyruğu (GDPR m.22)** — _Kaynak:_ §12.2.4; TN-46. _Durum:_ belirtilmemiş (FROZEN).

### K17 Dağıtım, operasyon, yüksek erişilebilirlik ve felaket kurtarma

#### Operasyon yönetimi

- [ ] **Runbook'lar (alarm başına)** — _Kaynak:_ OP-67; OP-70 madde 5. _Durum:_ PD.

### K18 Açık kaynak, ticari model ve paketleme

#### Ticari model ve fiyat ekseni

- [ ] **MAU bandı yalnız raporlama/tahmin için** — _Kaynak:_ §18.8.2 H9 eki. _Durum:_ HYPOTHESIS.
- [ ] **Admin/audit konsol koltuğu (alternatif eksen)** — Yalnız konfor tooling'i; güvenlik yüzeyleri koltuğa bağlanamaz. _Kaynak:_ §18.5, §18.8.2. _Durum:_ HYPOTHESIS (H9 yedeği).
- [ ] **Ücretsiz kişisel domain ve developer sandbox** — _Kaynak:_ D7. _Durum:_ belirtilmemiş (D7 default).

#### Güvenlik açığı yönetimi ve yayın şeffaflığı

- [ ] **npm Trusted Publishing + provenance (TS paketleri)** — _Kaynak:_ §14.5 TS profili; F-10. _Durum:_ belirtilmemiş.

### K19 Geliştirme ve kalite güvencesi

#### Access conformance ve test vektörleri

- [ ] **Admin API conformance testi** — Actor proof'suz yönetim çağrısının authority state değiştiremediği test edilir. _Kaynak:_ §9.7, §12.5. _Durum:_ belirtilmemiş.

#### Protokol, kiracı ve bileşen güvenlik testleri

- [ ] **Uç nokta izin manifesti CI kontrolü + otomatik 403/404 testleri** — _Kaynak:_ §12.5.1; TN-113. _Durum:_ belirtilmemiş (FROZEN).

#### Mühendislik standartları (OP-62…OP-74)

- [ ] **OP-65 API aileleri ve şema zinciri** — API kuralları (bkz. K11). _Kaynak:_ OP-65. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **OP-67 Gözlemlenebilirlik kod kuralları** — _Kaynak:_ OP-67. _Durum:_ belirtilmemiş.

### Bu aşamada doğrulanacak sınırlar

#### Token modeli

- [ ] **Bearer yönetim token'ı yok** — Yönetim için bearer token kullanılmaz. _Kaynak:_ §7.7. _Durum:_ belirtilmemiş.

#### Yetki modeli

- [ ] **Analitik ve telemetri karar/restriction/derived authority girdisi değildir** — _Kaynak:_ IDP-36; OP-47; TI-18. _Durum:_ belirtilmemiş.
- [ ] **Event authority değil; event kaybı authority genişletmez** — _Kaynak:_ §9.12.4; §9.16; PI-9. _Durum:_ belirtilmemiş.
- [ ] **Gelen `session-revoked` Grant revocation'ı değil** — _Kaynak:_ §9.16.2 k.4. _Durum:_ belirtilmemiş.
- [ ] **Sinyal (SSF/CAEP) güvenlik mekanizması değildir; sıra garantisi yok** — _Kaynak:_ L18; TN-39. _Durum:_ belirtilmemiş.

#### Yönetim, operatör ve destek erişimi

- [ ] **Impersonation / "Log in as" / "View as user" yok** — Operatör, yönetici veya destek personeli kullanıcının yerine geçemez; destek erişimi Grant'tır. `act`'sız saf impersonation token'ı, destek için ayrı token tipi ve `DelegatedSession` yoktur. _Kaynak:_ §5.7; §8.3; §8.10; §8.16; §8.17.9.8; §9.9.4; §11.21.3; §12.0.3; §12.3.4; §12.5.5; §13.2; E37; G53; MD-9; P53; TN-70; TNI-13; X20; X37; XI-26; must-never #19. _Durum:_ belirtilmemiş.
- [ ] **Ayrı "admin token" sınıfı, ayrı admin yazma yolu ve süper admin kısayolu yok** — Yalnız Exercise yolu vardır. _Kaynak:_ §2.2.2 #3; §5.12; §7.3; §9.7; §9.9.3 k.4; §9.15.1; §10.1.7; §10.4.5; §18.13; CMP-15.5; E34; MD-14; TN-110; TN-111; TN-130. _Durum:_ belirtilmemiş.
- [ ] **Konsol çereziyle authority değişikliği veya okuması yok; BFF holder olamaz** — Çerez yalnız gezinmeyi taşır. _Kaynak:_ §2.2.2 #3; §5.12; §7.7; TN-128. _Durum:_ belirtilmemiş.
- [ ] **Yönetici başkasının credential'ını belirleyemez/yazamaz** — `credential.set` action'ı ve yönetim API'sinde credential'ı doğrudan yazan uç nokta yoktur. _Kaynak:_ §5.12; §8.17.9.8; CMP-15.3; TN-61; TNI-6; must-never #17. _Durum:_ belirtilmemiş.
- [ ] **Console'dan domain adına schema kabul düğmesi yok** — _Kaynak:_ §8.17.10.2; X21. _Durum:_ belirtilmemiş.

#### Denetim, saklama ve gözlemlenebilirlik

- [ ] **Metriklerde tenant/realm/domain etiketi yok** — _Kaynak:_ OP-47. _Durum:_ belirtilmemiş.

#### Kullanıcı arayüzü ve terminoloji

- [ ] **Yasak UI terimleri** — Access UI'ında "mandate", "pause" (authority için), "transfer/devir" (Grant için), "verified/trusted", "full access", "forever", "undo" ve Instance için "session" kullanılmaz. _Kaynak:_ §8.11; X24; XI-13. _Durum:_ belirtilmemiş.
- [ ] **Revoke için "Undo" yok** — _Kaynak:_ §8.10. _Durum:_ belirtilmemiş.
- [ ] **Toplu "Stopped" durumu üreten tek düğme yok** — _Kaynak:_ §8.17.7.5. _Durum:_ belirtilmemiş.

## Aşama 8 — Hesap, B2B ve deneyim

Hesap yaşam döngüsü ve kurtarma, B2B organizasyonlar, gömülü bileşenler ve barındırılan sayfalar, markalama ve erişilebilirlik, ürün yüzeyleri, rıza ve tercih merkezi, gizlilik, sosyal giriş.

### Spec dışı ön koşullar

- [ ] **Mesaj kataloğu ve i18n biçimi kararı** — katalog biçimi (ICU, Fluent vb.), yedek zinciri, korunan anahtarlar.
- [ ] **Etkileşimsiz bot savunması kararı** — CAPTCHA yasak; yerine kullanılacak sinyal veya sağlayıcı.
- [ ] **Kişisel veri işleme envanteri ve saklama-imha politikası** — ROPA/VERBİS, DPIA; KVKK imha ve taşınabilirlik işleri buna dayanır.
- [ ] **Ücretsiz e-posta, ISS ve üniversite alan adı listesi** — alan adına göre otomatik katılım yasağı için.

### K01 Kimlik doğrulama yöntemleri

#### Passkey / WebAuthn: RP ve alan adı

- [ ] **Related origins (`/.well-known/webauthn`)** — Yalnız kiracının kendi markaları için, en fazla 5 etiket. _Kaynak:_ §10.2.4; IDP-5. _Durum:_ belirtilmemiş (karar FROZEN).

#### Passkey / WebAuthn: ceremony ve kullanıcı deneyimi

- [ ] **FIDO'nun iki zorunlu deseni** — Hesap ayarlarında passkey oluşturma/görme/yönetme ile passkey girişi + zarif yedek yol ürün gereksinimidir. _Kaynak:_ §12.4.1; TN-99. _Durum:_ PD.

#### Step-up ve yeniden doğrulama

- [ ] **Step-up ekranı exact eylemi ve nedeni adlandırır** — Ekran eylemi ve nedeni söyler ("Confirm it's you to send 3,000 TRY to Ayşe K."); genel "Re-enter your password" yasaktır. _Kaynak:_ §8.5, §8.17.5.4; §12.2.3; TN-45, X29, X-L3, X-L4. _Durum:_ belirtilmemiş (FROZEN).

#### Kurtarma ve yeni authenticator

- [ ] **Hesap kurtarma soğuması (itiraz penceresi)** — Recovery cooling meşru sahibe bildirim ve itiraz penceresi sağlar; bildirim görülmezse koruma yoktur. _Kaynak:_ §13.4 U67; TN-55, TN-61. _Durum:_ belirtilmemiş.
- [ ] **Recovery ≥ korunan seviye** — Identity plane ceremony bütünlüğü: phishing-resistant faktör, MFA ve recovery korunan seviyeden zayıf olamaz. _Kaynak:_ §13.2; AS-19. _Durum:_ belirtilmemiş.

#### Sosyal giriş

- [ ] **Sosyal login** — Sosyal sağlayıcılarla giriş. _Kaynak:_ §1.7; §2.2.1. _Durum:_ belirtilmemiş.
- [ ] **Social login: backend token doğrulaması** — İmza, `iss`, `aud`, `exp`, `nonce` backend'de kontrol edilir; anahtar `(iss, sub)`'dır. _Kaynak:_ §10.2.6. _Durum:_ belirtilmemiş (kiracı başına).
- [ ] **Gün-1 sosyal sağlayıcılar** — Google, Apple, Microsoft (kişisel/iş), GitHub, LinkedIn, Facebook. _Kaynak:_ IDP-31. _Durum:_ gün-1.
- [ ] **Genel OIDC/OAuth2 sosyal bağlayıcı** — Her OIDC/OAuth2 sağlayıcısı için. _Kaynak:_ IDP-31. _Durum:_ gün-1.
- [ ] **İkinci dalga sosyal sağlayıcılar** — Discord, Slack, GitLab, X, Amazon, LINE, Kakao, Naver, WeChat; talebe göre. _Kaynak:_ IDP-31. _Durum:_ PD (talebe göre).
- [ ] **Sosyal sağlayıcı tanımı veridir (e-posta güvencesi dahil)** — Adresler, izinler, logo ve sağlayıcının e-posta doğrulama/yetkili alan bilgisi veri olarak tutulur. _Kaynak:_ F23; IDP-31. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **Sosyal giriş geliştirme anahtarları (sandbox)** — Geliştirme/sandbox realm'inde ortak test anahtarlarıyla sosyal giriş hemen çalışır; üretimde ortak anahtar reddedilir, kiracı anahtarı zorunludur. _Kaynak:_ IDP-31. _Durum:_ belirtilmemiş (karar FROZEN).

#### Federasyon ve kurumsal SSO

- [ ] **Domain doğrulama (DNS TXT) ve home realm discovery** — Doğrulanmamış alan adı için HRD yönlendirmesi yapılmaz. _Kaynak:_ §10.2.6. _Durum:_ belirtilmemiş.

### K02 Kimlik protokolleri ve federasyon

#### Issuer, discovery ve anahtar yayını

- [ ] **Özel alan adı issuer'ı** — Yükseltme olarak sunulur; varlığı ücretlendirilemez. _Kaynak:_ §12.1.2; TN-10. _Durum:_ PD.

#### OIDC özellikleri ve oturum

- [ ] **Sosyal login (enumeration-nötr mesaj)** — Sosyal login mesajı enumeration kanalları arasında tek biçimdedir. _Kaynak:_ CR-40. _Durum:_ belirtilmemiş.

#### Consent ve kullanıcı yüzeyi

- [ ] **Üçüncü taraf uygulamaya bağlanma: "Connect *App*…" (OAuth consent → Grant Exercise)** — Üçüncü taraf RP'nin consent'i bir Grant Exercise'ına derlenir: OAuth consent yerine S1 exact preview'lü delegation, commit sonrası "Delegation created". Scope listesi ve "Allow/Authorize" dili yasaktır. _Kaynak:_ §1.7; §2.2.2 #2; §8.8, §8.11, §8.17.4.3, §8.17.12; X27. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **"Connect your Suiss authority" akışı (third-party uygulama)** — Kullanıcının tıklamasıyla uygulamanın istediği typed bounds ile S1 açılır. _Kaynak:_ §8.17.4.3. _Durum:_ belirtilmemiş.
- [ ] **OAuth hata ekranları: owner atfı ve korelasyon referansı** — "*App* isn't set up correctly for sign-in (the app's developer can fix this). Reference: 7F3K-2Q"; ham hata kodu kullanıcıya gösterilmez. _Kaynak:_ §8.10, §8.15.2; X-L8; X41. _Durum:_ belirtilmemiş (PROPOSED FOR FREEZE).
- [ ] **`access_denied` ve `temporarily_unavailable` mesajları** — Kullanıcının kendi kararı "You chose not to continue"; geçici arıza §8.13 identity plane satırına bağlanır. _Kaynak:_ X-L8. _Durum:_ belirtilmemiş.
- [ ] **Ev alanı keşfi (HRD) varsayılan kapalı; ipuçları realm politikasını ezmez** — Hedef organizasyon açıkça yazılır ("You're signing in to *Acme* (acme.example)"); HRD açıksa hedef kiracı kullanıcıya onaylatılır. `domain_hint`/`login_hint` vb. ipucu parametreleri realm politikasını/satırı değiştirmez. _Kaynak:_ §7.3; §12.4.1; TN-98; TN-G1; X-L13. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Bağlı hesaplar (IdentityBinding) — "Linked sign-in"** — S11'de bağlı giriş hesapları; bağlama açık eylemdir, "Merged" yasak. _Kaynak:_ §8.5 S11, §8.8. _Durum:_ belirtilmemiş.

#### Upstream IdP ve kimlik federasyonu

- [ ] **Açık IdentityBinding ile hesap bağlama (realm'ler arası, iki yarılı)** — Realm'ler arası ve upstream hesap bağı yalnız açık bir IdentityBinding Claim'iyle kurulur. Her yarı kendi yönetişim domain'inde commit edilir; kanıt `invite_token`/`admin_exercise`/`verified_idp_subject`; tek taraflı bağ actor-binding üretmez. _Kaynak:_ §5.6, §5.16; §7.1, §7.9.11.1; §12.1.1, §12.1.3; C7; MD-5; TN-2, TN-65. _Durum:_ belirtilmemiş (FROZEN).

### K03 Oturum ve token yönetimi

#### Login oturumu

- [ ] **Kurtarma sonrası kısıtlı oturum (GRACE_PERIOD)** — E-posta/telefon değişimi, kurtarma kodu üretimi, MFA silme, IdP bağlama, rol yükseltme, dışa aktarım, ödeme, yeni API anahtarı/uzun ömürlü token ve hesap silme reddedilir veya ek doğrulama ister. _Kaynak:_ §12.3.2; TN-56. _Durum:_ PD.
- [ ] **Anonim / misafir oturum ve kayıtlı hesaba yükseltme** — Kayıtsız ziyaretçiye oturum kimliği verilir; sonradan kayıtlı hesaba yükseltilebilir. _Kaynak:_ §1.7. _Durum:_ belirtilmemiş.

#### Oturum çerezi, BFF ve cihaza bağlama

- [ ] **Oturum bağ durumu (DBSC/DPoP) gösterimi** — S10'da "this sign-in is tied to this device"; Expert görünümünde device-bound / not bound. _Kaynak:_ §8.5 S10, §8.9, §8.12. _Durum:_ belirtilmemiş (DBSC etkinliği doğrulanmadı, §8.20).

#### Oturum yüzeyi ve çıkış

- [ ] **"Sign-ins & instances" (S10) yüzeyi** — Identity plane oturumu = cihaz başına tek insan Instance'ı; satır birimi "Sign-in on *device*"'tır ve identity ile authority alt durumları ayrı gösterilir. _Kaynak:_ §8.5 S10, §8.8; §12.0.3, §12.2.1; X36. _Durum:_ belirtilmemiş.
- [ ] **"End this sign-in" (başka cihaz)** — Başka cihaz satırı için `instance.terminate`; identity plane oturumu `session_epoch` ile kapatır. "Sign out" ile tek düğmede birleştirilmez. _Kaynak:_ §8.5 S10; X36. _Durum:_ belirtilmemiş.
- [ ] **"Sign out everywhere" dürüst metni** — "Signed out on all devices. Apps and agents you connected keep their access until you revoke it (Acting for you). Offline passes may work until 18:00." _Kaynak:_ §8.10; X36. _Durum:_ belirtilmemiş.
- [ ] **Access token süresi doldu, yenileme başarısız mesajı** — Uygulamada "Please sign in again to continue." gösterilir; doğrulanmamış neden söylenmez. _Kaynak:_ §8.13. _Durum:_ belirtilmemiş.

#### Token ömürleri ve ValidityContract

- [ ] **ValidityContract gösterimi** — UI'da "Valid until … / next check by …" olarak gösterilir; adı görünmez. _Kaynak:_ §8.8, §8.9. _Durum:_ belirtilmemiş.
- [ ] **Offline pass (projection) gösterimi** — "Offline pass (valid offline until 18:00)"; "token" kelimesi yalnız developer UI'ında kullanılır. _Kaynak:_ §8.8, §8.11. _Durum:_ belirtilmemiş.

### K04 Hesap yaşam döngüsü ve kurtarma

#### Genel çerçeve ve veri modeli

- [ ] **Hesap yaşam döngüsü (identity plane bileşeni)** — Kayıt, kurtarma, bağlama, silme ve göç identity plane'e aittir ve identity plane'in hesap yaşam döngüsü bileşenini oluşturur. _Kaynak:_ §7.6; CMP-15.3; MD-13. _Durum:_ belirtilmemiş
- [ ] **Dış kimlik bağı `(provider, provider_subject_id)`, kimlik başına `verified_at`** — Dış sağlayıcı kimlikleri bu anahtarla bağlanır ve her kimliğin doğrulanma zamanı tutulur. _Kaynak:_ §10.1.7; P-ID-9. _Durum:_ belirtilmemiş
- [ ] **`idp.account.*` hesap action namespace'i** — `read`, `profile.update`, `credential.*`, `email.change`, `delete`, `export` action'larını içerir. Hesap kaynakları kullanıcının self-anchor kapsamındadır. _Kaynak:_ §7.1 Destek satırı; E34. _Durum:_ belirtilmemiş (PROPOSED FOR FREEZE)

#### Tanımlayıcılar ve e-posta

- [ ] **E-posta yeniden kullanım politikası** — Varsayılan asla; realm biberli özet veya "N gün tut" seçebilir (koşullu). _Kaynak:_ §12.3.5; TN-76. _Durum:_ PD
- [ ] **Birincil e-posta/telefon değişimi ve güvenlik bildirimi** — Değişiklik güvenlik bildirimi tetikler. _Kaynak:_ §8.6. _Durum:_ belirtilmemiş
- [ ] **E-posta değişimi ve posta kutusu devri koruması** — E-posta odak anahtarı olamaz; `mailbox_owner_since` + RFC 7293. _Kaynak:_ §12.3.3; TN-66, TN-69. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Realm slug değişimi = yeni realm + göç** — _Kaynak:_ §12.1.2; TN-16. _Durum:_ belirtilmemiş (FROZEN)

#### Kayıt

- [ ] **Kayıt (self-servis ve yönetimli)** — Kullanıcı kaydı self-servis veya yönetimli yapılır; kendi kendine kayıt uç noktası failover/bozulmuş modda 503 döner. _Kaynak:_ §2.2.1, §2.4, §17.4.5, §17.7.2. _Durum:_ belirtilmemiş
- [ ] **Kayıt (sign-up) akışı 8 adım** — Sözdizimi/teslim edilebilirlik, relay allowlist, ucuz kapı, PAT, Turnstile/Friendly Captcha skoru, suistimal skoru, bant dışı onay kodu, kod dönünce hesap + `party.register`. _Kaynak:_ §12.3.6; TN-80. _Durum:_ belirtilmemiş (FROZEN kısmen), PD
- [ ] **15 kayıt değişmezi** — Özdeş yanıt, ~250 ms taban, IP+hesap sınırı, sabit Argon2 havuzu, ham+kanonik e-posta, WebAuthn `user.id` 64 rastgele bayt vb. _Kaynak:_ §12.3.6; TN-80. _Durum:_ FROZEN (1,2,5,6,10,12), PD (diğer)
- [ ] **Kayıtta enumeration koruması** — "E-posta zaten kullanımda" bilgisi yanıtta değil, yalnız e-postayla bildirilir. _Kaynak:_ §10.2.1 madde 6; CR-40. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **`party.register` bootstrap Grant hız sınırı** — ≤10/saat. _Kaynak:_ §12.3.6; TN-80. _Durum:_ PD
- [ ] **Domain izin/engel listesi (kayıt)** — Kiracı kayıt için domain listesi seçer. _Kaynak:_ §12.4.2; TN-132. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Zorunlu profil alanları** — Kiracı panelden seçer. _Kaynak:_ §12.4.2; TN-132. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Doğrulama (e-posta vb.)** — Kayıt sırasında kimlik/iletişim bilgisinin doğrulanması. _Kaynak:_ §2.2.1. _Durum:_ belirtilmemiş
- [ ] **E-posta doğrulama dürüst ifadesi** — "Confirmed you can receive email at a…@… (3 Oct)"; "Email verified" yasak. _Kaynak:_ §8.10. _Durum:_ belirtilmemiş
- [ ] **Doğrulanmamış hesapların budanması** — _Kaynak:_ §12.3.3. _Durum:_ belirtilmemiş
- [ ] **Ön ele geçirme (pre-hijack) savunması** — Sahiplik kanıtı önceki credential'ları öldürür ve oturumları iptal eder; doğrulama öncesi hesap satırı yok. _Kaynak:_ §12.3.3; TN-64, TNI-5. _Durum:_ belirtilmemiş (FROZEN)

#### Hesap bağlama ve birleştirme

- [ ] **Hesap bağlama (account linking) ve yedi koşulu** — Birden fazla kimliğin/giriş yönteminin aynı hesaba bağlanması. Koşullar: doğrulanmış e-posta RP kayıtlarında, IdP allowlist (predicate-input Acceptance), bağlama anında kontrol kanıtı, diğer oturumların iptali, `(iss, sub)` anahtarı, otomatik bağlama yok. _Kaynak:_ §2.2.1, §12.3.3; TN-65. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Hesap birleştirme (merge)** — Bir identity-binding kaydı ve onun Claim'idir; geri alınamaz, bu yüzden bağlama tercih edilir. Birleştirmede anlık görüntü + denetim olayı alınır; lineage, holding, Mandate, budget ve authority birleşmez. _Kaynak:_ §5.6, §5.17, §12.3.3; INV-39, TN-67, TNI-11. _Durum:_ belirtilmemiş (aday; §12.3.3'e göre FROZEN)
- [ ] **Birleştirme yalnız açık kullanıcı eylemi + yeniden kimlik doğrulama** — Doğrulanmış e-posta otomatik birleştirme gerekçesi değildir; doğrulanmamış e-posta hiçbir zaman eşleme anahtarı olmaz (nOAuth). _Kaynak:_ §10.2.6; IDP-31. _Durum:_ belirtilmemiş (karar FROZEN)

#### Hesap durumları ve devre dışı bırakma

- [ ] **Hesap durumu: disabled mesajı** — Admin'e "Sign-in disabled"; doğrulanmış kullanıcıya "Your account's sign-in is turned off by *Acme*". _Kaynak:_ §8.8, §8.15.2. _Durum:_ belirtilmemiş
- [ ] **Atıl/pasif hesap süpürmesi ve deaktivasyonu** — Yerleşik hareketsizlik süpürmesi; eşik 45/90 gün kurumsal (KVKK kademeli deaktivasyon), 2 yıl tüketici; break-glass muaf; otomatik imha işi sürekli çalışır (KVKK 6 aylık periyot tavanının altında). _Kaynak:_ §12.3.1, §14.9; TN-51. _Durum:_ PD

#### Hesap kurtarma: ilkeler ve authority etkisi

- [ ] **Hesap kurtarma akışları** — Identity plane yüzeyi; kurtarma başlatma/tamamlama. _Kaynak:_ §2.2.1, §8 giriş, §8.5 S11, §8.6. _Durum:_ belirtilmemiş
- [ ] **Kurtarma ≥ korunan güvence (yapılandırma anında)** — Kurtarma yolunun güvencesi korunan hesabınkinden düşük olamaz; kurtarma yöntemleri güvence etiketi taşır ve zayıf yapılandırma yapılandırma anında reddedilir (durum-koşullu CHECK; `achieved_aal >= required_aal` şema kısıtı). _Kaynak:_ §2.2.1, §6.9, §12.3.2; INV-40, MKT-D6, TN-53, TNI-4. _Durum:_ FROZEN (§12.3.2); şema kısıtı HYPOTHESIS (MKT-D6)
- [ ] **`instance.recover` ≥ Mandate'lerin en sıkı term'i (INV-40)** — Successor'a bind/rebind veya yeni (CT3) Grant verilirken en zayıf kurtarma yolu sınıfı kontrol edilir; eşik karşılanmazsa REQUIRE_ACTION veya DENY. _Kaynak:_ §6.9, §12.3.2; INV-40, TN-53. _Durum:_ belirtilmemiş (aday; §12.3.2'ye göre FROZEN)
- [ ] **Hesabın efektif güvenliği / en zayıf giriş yolu metriği** — Hesabın efektif güvenliği kurtarma dahil bütün yolların AAL minimumudur; dağılımı admin konsolunda, S7 ve S10'da gösterilir. _Kaynak:_ §12.3.2, §18.4; TN-53. _Durum:_ FROZEN (§12.3.2); HYPOTHESIS (ürün metriği, §18.4)
- [ ] **Kurtarma her zaman yeni successor Instance doğurur** — Kurtarma authority plane'de yeni bir successor Instance (`instance.recover`) doğurur ve authority/Mandate miras bırakmaz; Party Grant'ları kalır, Mandate INV-40 kapısından yeniden bağlanır. _Kaynak:_ §5.6, §5.11, §7.7, §10.1.3, §12.3.2; C8, INV-13, TN-53, X29, X38, X-L9. _Durum:_ belirtilmemiş (FROZEN, §12.3.2)
- [ ] **Domain kurtarmayı sıkılaştırabilir** — Domain daha uzun cooling süresi veya rebind için ek requirement koyabilir; kurtarmayı gevşetemez. _Kaynak:_ §5.6, §5.11, §10.1.3; INV-40. _Durum:_ belirtilmemiş
- [ ] **`recovery-result` Claim'i** — Kurtarma sonucu ve kurtarma yolu sınıfı, successor'ın actor-binding'ine bağlı bir Claim'dir. _Kaynak:_ §6.9, §7.7; INV-40. _Durum:_ belirtilmemiş
- [ ] **"Cihaz ekleme" kurtarma değildir** — Eski Instance'ın authenticator'ıyla doğrulanmış cihaz ekleme bir kurtarma işlemi sayılmaz. _Kaynak:_ §5.6. _Durum:_ belirtilmemiş
- [ ] **Kurtarma dürüstlük mesajı (X38)** — "You're signed in. Your delegations remain. Some sensitive actions … after 14:00 tomorrow. Your devices need to sign in again; instance limits must be set again." "Full access restored" yasak. _Kaynak:_ §8.10, §8.13; X29, X38, X-L9. _Durum:_ belirtilmemiş (PROPOSED FOR FREEZE)

#### Hesap kurtarma: yöntemler ve akış

- [ ] **NIST SP 800-63B-4 kurtarma sınıfları** — Kayıtlı kurtarma kodları, gönderilen kodlar, kurtarma kişileri, kimlik tespiti tekrarı; destek temsilcisi alternatif yöntem. _Kaynak:_ §12.3.2; TN-52. _Durum:_ PD (izinli sınıflar)
- [ ] **Kayıtlı kurtarma kodları** — ≥64 bit, özetli, tek tek tek kullanımlık, kullanımda yeni kod, yeniden üretim bildirimli, "sakladım" onayı. _Kaynak:_ §12.3.2; TN-59. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Gönderilen kurtarma kodları** — ≥6 hane; posta 21/30 gün, SMS/ses 10 dk, e-posta 24 s ömür tavanı. _Kaynak:_ §12.3.2. _Durum:_ belirtilmemiş
- [ ] **Kurtarma kişileri** — 24 s uzatma, yönetim arayüzü, yıllık hatırlatma. _Kaynak:_ §12.3.2. _Durum:_ belirtilmemiş
- [ ] **Tipli kurtarma durum makinesi** — REQUESTED → EVIDENCE_MET → COOLING_DOWN → REBIND_OPEN → GRACE_PERIOD → CLOSED; THROTTLED/LOCKED/DENIED; adım silinemez; atomik kanıt tüketimi. _Kaynak:_ §12.3.2; TN-54. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Normal giriş devam eden kurtarmayı iptal eder** — _Kaynak:_ §12.3.2; TN-54. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Kurtarma engelleme (DoS) sınırı** — Yalnız e-postayı bilenin kurtarmayı kilitletmesini önleyen ayrı sınır. _Kaynak:_ §12.3.2; TN-54. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **İki katmanlı kurtarma soğuması** — Identity plane soğuma tablosu (ters orantılı, riske duyarlı, vaka başına kısaltılamaz) + SEC18 (kurtarma sonrası 24 saat CT2+ karşılanmaz); UI tarihi söyler. _Kaynak:_ §10.1.3, §12.3.2; SEC18, TN-55. _Durum:_ PD (tablo, 24 s süresi), FROZEN (SEC18, kısaltma yasağı)
- [ ] **Kurtarma bildirimleri** — ≥2 bildirim adresi; kurtarma kanalı ≠ bildirim kanalı (şema); itiraz talimatı; REQUESTED ve COOLING_DOWN'da bildirim. _Kaynak:_ §12.3.2; TN-57. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Asimetrik eşik: kayıp bildirimi tek faktörle** — Yeni authenticator ekleme tam kurtarma ister. _Kaynak:_ §12.3.2; TN-58. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Cihazlar arası bağlama kodu** — ≥40/112 bit, tek kullanımlık, ≤10 dk, e-postayla iletilmez; bağlama AAL kuralı. _Kaynak:_ §12.3.2; TN-59. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Asistanlı kurtarmayı kapatma** — Yüksek değerli hesap için Apple Recovery Key modeli; kalıcı kayıp onayı. _Kaynak:_ §12.3.2; TN-60. _Durum:_ PD
- [ ] **TAP eşdeğeri kurtarma yetkisi nesnesi** — Geçici erişim kodu (1 s, 10 dk–30 g, 8–48 uzunluk); yalnız realm seçerse; oturumu yalnız authenticator bağlar. _Kaynak:_ §12.3.2; TN-62. _Durum:_ PD
- [ ] **Kurtarma / onboarding yeniden tetiklenme oranı metriği** — Bkz. K14. _Kaynak:_ §12.3.2; MKT-D13, TN-63. _Durum:_ PD (§12.3.2); HYPOTHESIS (MKT-D13)

#### Credential sıfırlama ve yönetimi

- [ ] **Yönetici credential belirleyemez; yalnız tek kullanımlık reset intent** — Yönetim API'si / yardım masası kullanıcının (başkasının) credential'ını yazamaz; yalnız tek kullanımlık, kısa ömürlü (1 s / ≤24 s) kurulum/reset niyet belirteci üretir, farklı kayıtlı adrese gönderilir ve üretimi bir Exercise'tır; credential'ı kullanıcı kendisi kaydeder. Bu bir tavandır. _Kaynak:_ must-never #17; §5.12, §7.1, §12.3.2; CMP-15.3, LFP-29, TN-61, TNI-6. _Durum:_ belirtilmemiş (FROZEN, §12.3.2)
- [ ] **Parola sıfırlama (≠ kurtarma)** — Sıfırlamada diğer oturum/token'lar düşer, bekleyen e-posta değişimleri iptal, bağlı federe kimlikler gösterilir ve varsayılan bağ koparılır. _Kaynak:_ §12.3.2, §12.3.3; TN-52, TN-64. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Parola sıfırlama token'ı** — Sıfırlama token'ı tek kullanımlık, süreli, hash'li; sıfırlama akışı enumeration-nötr. _Kaynak:_ CR-38, CR-40. _Durum:_ belirtilmemiş (FROZEN)

#### Hesap silme ve veri hakları

- [ ] **Hesap silme** — Hesabın silinmesi; identity plane kişisel alanları siler veya crypto-shred eder, Authority Record redaksiyon uygular (GDPR Art.17). Tombstone, SCIM 404; dürüst mesaj: "Your account is deleted. Some records are kept until *date*…; history entries are redacted, not removed." _Kaynak:_ §2.2.1, §8.10, §14.9; X38, X-L11. _Durum:_ belirtilmemiş (saklama PD)
- [ ] **Silme = crypto-shredding** — Kişi × saklama sınıfı başına DEK imha edilerek PII okunamaz hâle getirilir; satır kalır. _Kaynak:_ CMP-15.9; CR-32, T31; OP-73; OP-74. _Durum:_ belirtilmemiş
- [ ] **Kendi hesabının self-servis yönetimi ve veri taşınabilirlik/silme talepleri (S11)** — Kullanıcı hangi yöntemlerle giriş yaptığını, kurtarma yollarını, bağlı hesapları yönetir; verilerini alır veya silme talep eder. _Kaynak:_ §8.5 S11. _Durum:_ belirtilmemiş

#### Göç, içe aktarım ve çıkış (taşınabilirlik)

- [ ] **Hash içe aktarımı (pre-hash / pepper, veri olarak tanımlı hash şeması)** — `bcrypt(sha256(pw))` ve peppered hash'ler kod yazmadan içe aktarılır; Kratos format listesi (bcrypt, Argon2, scrypt, Firebase scrypt, PBKDF2, crypt, biberli), PHC dizgisi, parametre tavanı yok, ön özet/biber eklentisi. _Kaynak:_ §2.2.1, §4.8 eksen 10, §12.3.7, §18.1, §18.7; B19, MKT-D10, TN-85. _Durum:_ PD (§12.3.7); Faz 1 (§18.13 çıkarım)
- [ ] **Tembel (lazy) göç** — Kademeli parola göçü: girişte senkron yeniden özetleme, ölümcül olmayan, sabit zamanlı; eski IdP çağrısı başarısızsa giriş başarısız. _Kaynak:_ §4.8 eksen 10, §12.3.7; TN-85. _Durum:_ PD
- [ ] **Eski özet sayacı metriği** — Yönetim panosunda birinci sınıf metrik. _Kaynak:_ §12.3.7; TN-85. _Durum:_ PD
- [ ] **CXF credential içe aktarımı** — İçe aktarım yeni `authenticator-binding` Claim'i (SEC18 cooling); sayaç sıfırlanır. _Kaynak:_ §10.8.1. _Durum:_ belirtilmemiş
- [ ] **Parola hash'i ve TOTP sırlarının ücretsiz self-servis dışa aktarımı** — Çıkış hakkı; hiçbir ticari tavana takılmaz. Yönetici göç dışa aktarımı `idp.*` domain action'ıdır: reserved, CT3, quorum/step-up/denetim, realm'e bağlı anahtarla şifreli bundle. _Kaynak:_ §4.8, §12.3.7, §18.1, §18.2, §18.6, §18.7; B10, B11, B19, MKT-D9, TN-86. _Durum:_ PD (§12.3.7); Faz 1 (§18.13 çıkarım); parite kalemi
- [ ] **Sosyal sağlayıcı istemci kimliği yeniden kullanımı + Apple transfer 60 gün sayacı** — Farklı kimlikte açık uyarı. _Kaynak:_ §12.3.7; TN-87. _Durum:_ belirtilmemiş (FROZEN anahtar), PD (uyarı)
- [ ] **Sıfır kesinti göç** — Token değişimi uç noktası eski token'ı eski JWKS ile doğrular; çift JWKS/`iss` en uzun RT ömrü boyunca; eski issuer açık Acceptance, süre sonunda kalkar. _Kaynak:_ §12.3.7; TN-88. _Durum:_ PD
- [ ] **PartyID ve key-event taşınabilirliği** — Ücretsiz ve her zaman açık; non-custodial geçiş. _Kaynak:_ §18.1, §18.7; B7, B19. _Durum:_ belirtilmemiş (FROZEN STRATEGY)
- [ ] **Passkey RP ID taşınabilirliği** — RP ID müşterinin alan adında olduğundan provider değişiminde passkey'ler çalışmaya devam eder; RP ID değişimi çıkış belgelerinde yazılır. _Kaynak:_ §18.1, §18.7; B19, XI-12. _Durum:_ belirtilmemiş

### K05 Kiracılık, realm ve B2B organizasyonlar

#### Realm şablonları ve sandbox

- [ ] **Realm şablonları** — B2C, B2B SaaS, workforce, finans, sağlık, kamu, e-ticaret, mobil, geliştirici platformu için realm politikası varsayılanları; ADP commit ile uygulanır. _Kaynak:_ §10.9.2. _Durum:_ belirtilmemiş.
- [ ] **TR ödeme realm şablonu (ÖHY/BS Tebliği GKD)** — Uygulama-kontrollü faktör, biyometri tek başına yetmez, SMS yalnız kurulumda, SIM 90 gün, işlem kodu müşteri anahtarıyla imzalı, anne kızlık soyadı/kimlik bilgisi unsur değil. _Kaynak:_ §10.3.4; IDP-9. _Durum:_ PD (şablon).

#### Alan adı ve RP ID

- [ ] **Müşteri realm'i hosted yüzeyleri kendi (alt) alan adında ve markasıyla** — Suiss kabuğu müşteri realm'ine dayatılmaz. _Kaynak:_ §8.17.4.1; X4, X40. _Durum:_ belirtilmemiş (X40 PROPOSED FOR FREEZE).
- [ ] **Tek Suiss kabuğu / tek RP (first-party)** — First-party Suiss hesapları için. _Kaynak:_ X4, X40. _Durum:_ belirtilmemiş.

#### Kiracılık kavramlarının UI ve yönetimde görünümü

- [ ] **Tenant / Organization / Account ayrımı UI'da** — Tenant "Subscription/Billing account" (yalnız ticari yüzeyler, authority içermez); B2B Party "Organization"; user record "Account"; "tenant"/"realm" son kullanıcıda görünmez. _Kaynak:_ §8.8, §8.11. _Durum:_ belirtilmemiş.
- [ ] **Realm yalnız admin/developer'da görünür** — Son kullanıcı yalnız realm marka adını görür ("Sign in to *Acme*"). _Kaynak:_ §8.8. _Durum:_ belirtilmemiş.
- [ ] **Cell hiçbir UI'da görünmez** — _Kaynak:_ §8.8, §8.9. _Durum:_ belirtilmemiş.
- [ ] **Domain görünürlüğü yalnız çok domain'de** — Tek domain'li kullanıcı domain kavramını görmez; çok domain'de satır başına etiket, Expert'te provider. _Kaynak:_ §8.8, §8.17.7.2; IA-6. _Durum:_ belirtilmemiş.

#### B2B organizasyon modeli

- [ ] **B2B organizasyon = realm içinde Party + Anchor** — Organizasyon ayrı domain değildir; root `Joint(k)` yöneticilerdir, org yetkisi FOR(org) ile kullanılır, organizasyonlar arası yetki bridging Grant'tır. _Kaynak:_ §2.2.1; §4.8 eksen 4; §5.16, §5.17, §7.1; §12.1.1; C6, C21; CMP-15.3; MD-5; TN-5. _Durum:_ belirtilmemiş (FROZEN, TN-5).
- [ ] **Organizasyon yönlendirmesi organizasyon kimliği üzerinden** — E-posta alan adı üzerinden değil. _Kaynak:_ §12.1.1, §12.4.1; TN-3. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Org adına envanter (S2 org merceği)** — Admin'e "Acting for Acme", "Acme's roots", "Roles". _Kaynak:_ §8.17.7.6. _Durum:_ belirtilmemiş.

#### Üyelik, davet ve grup

- [ ] **Organizasyon üyeliği (Membership)** — `source ∈ {Invite, Scim, Jit, DomainAutojoin}`; rol = sürümlü named AuthoritySet Grant'ı. _Kaynak:_ §12.3.8. _Durum:_ belirtilmemiş.
- [ ] **Grup üyeliği tek issuer** — Identity-plane-managed (`idp.group.*`), domain-local veya upstream; ikinci yazma yolu reddedilir. _Kaynak:_ §12.3.8; TN-95, TN-117. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Davet (invitation)** — Opak SHA-256 belirteç; rol satırdan; kabulde `grant.issue` davet edenin o anki yetkisiyle; NFKC, doğrulanmış tanımlayıcı eşleşmesi, atlanamaz kabul, `no-referrer` + sihirli kod, tarayıcı tıklaması tüketmez; 7/30 gün; ilk kabulde sahip/yönetici yok; farklı alan adında ara sayfa. _Kaynak:_ §12.3.8; TN-89. _Durum:_ FROZEN (1–3, 7, 10), PD (süre).
- [ ] **Kiracı oluşturma / toplu davet hız sınırı ve itibar kontrolü** — _Kaynak:_ §12.3.8; TN-89, TN-95. _Durum:_ belirtilmemiş.

#### Alan adı doğrulama ve otomatik katılım

- [ ] **Alan adı doğrulaması (DNS/HTTPS/IdP)** — Süreli Claim; yeniden doğrulama zorunlu; MX/tescil değişimi tetikler; çoklu organizasyon talep kilidi ve alarm. _Kaynak:_ §12.3.8; TN-90. _Durum:_ belirtilmemiş (FROZEN Claim modeli), PD (süreler).
- [ ] **Otomatik katılım (domain autojoin)** — Rule-shaped Grant; varsayılan kapalı; erişim talebi ara seçenek; tüketici/TR ücretsiz posta/ISS/üniversite alan adlarında yasak. _Kaynak:_ §12.3.8; TN-90. _Durum:_ belirtilmemiş (FROZEN tüketici yasağı), PD.
- [ ] **Seçimle yükseltmeye soğuma** — Reserved/CT3 içeren rule-shaped Grant'ta yeni holding episode için 24 s soğuma + SI-21 bildirimi. _Kaynak:_ §12.5.2; TN-109. _Durum:_ PD.

#### Sahiplik

- [ ] **Organizasyon sahiplik devri (`anchor.transfer`)** — CT3, ≥24 s gecikme, alıcı contribution'ı, tüm root'lara bildirim, gecikme içinde iptal; Grant akıbeti açık. _Kaynak:_ §12.3.8; TN-91. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Son sahip koruması** — Sahipsiz Anchor ifade edilemez; identity plane ≥1 aktif sahibi veri katmanında her yolda korur. _Kaynak:_ §12.3.8; TN-91. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Kendi rolünü genişletme yasağı, daraltma serbest** — _Kaynak:_ §12.3.8; TN-91. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Sahiplik ≠ faturalama** — _Kaynak:_ §12.3.8; TN-91. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **DNS ile sahiplik kurtarma (yalnız önceden beyanlıysa)** — Genesis rootTerms'te beyanlı entry; CT3, ≥24 s, bildirim. _Kaynak:_ §12.3.8; TN-92. _Durum:_ belirtilmemiş (FROZEN).

#### Kurumsal SSO ve SCIM

- [ ] **"Kurumsal bağlantı yöneticisi" şablon Grant'ı** — Müşteri BT sorumlusu için dar, süreli (7 g), delegable olmayan; yalnız taslak hazırlar, yürürlüğe alma CT3'tür. _Kaynak:_ §12.5.2; TN-120. _Durum:_ PD.

### K06 Giriş deneyimi, UI bileşenleri ve markalama

#### Barındırılan ve gömülü giriş yüzeyleri

- [ ] **Gömülü UI bileşenleri (varsayılan mod, web)** — Giriş/kayıt, kullanıcı menüsü, hesap ayarları, organizasyon seçici/ayarları, ajan bağlantıları; React ile başlanır, diğer çatılar web components ile; Frontend API kiracının özel alan adında. Barındırılan sayfalarla aynı düğüm sözleşmesini kullanır. _Kaynak:_ §12.4.1; OP-62 `web/`; OP-65; T41 madde 5; TN-101, TN-133; X-L5. _Durum:_ gün-1 (bileşen listesi PD); T41'e göre PD.
- [ ] **Mobil UI bileşenleri** — Mobil paketler TN-133 bileşenlerinin mobil karşılıklarını taşır. _Kaynak:_ T41 madde 4. _Durum:_ gün-1.
- [ ] **Gömülü mod güvenlik koşulları** — Özel alan adı zorunlu, passkey öncelikli, HttpOnly çerez realm alt alan adında. _Kaynak:_ §12.4.1; TN-133. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Gömülemeyen üç yüzey** — Üçüncü taraf izin ekranı, CT3 onayları/authority genişletme ve yönetim konsolu daima barındırılan sayfadadır. _Kaynak:_ §12.4.1; TN-133; X-L5. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Özel alan adı (realm issuer + WebAuthn RP ID müşteri alan adında)** — Varlığı ücretlendirilemez; sertifika/DNS otomasyonu konforu ücretlendirilebilir. _Kaynak:_ §18.6, §18.7, §20.1; B3, B19. _Durum:_ belirtilmemiş.

#### Düğüm sözleşmesi ve akış modeli

- [ ] **Görsel akış tasarımcısı (sürükle-bırak)** — Yalnız ekran sırası ve görünümü; sunucu kurallarına dokunmaz. _Kaynak:_ §12.4.2; TN-132. _Durum:_ yol haritası (WATCH).

#### Özel amaçlı bileşenler

- [ ] **"Tercihlerim" bileşeni (gömülü ve barındırılan)** — Kayıt ekranında, hesap ayarlarında veya ayrı bileşen olarak. _Kaynak:_ IDP-37; TN-133. _Durum:_ belirtilmemiş.

#### Giriş akışı ve yöntemler

- [ ] **Apple ile Giriş uyarısı (App Store kuralı)** — Konsol uyarır ve önerir. _Kaynak:_ §10.2.6; IDP-31. _Durum:_ belirtilmemiş.
- [ ] **Kurtarma sonrası UI tarih mesajı** — "Girişiniz açıldı; yüksek etkili işlemler ‹tarih›'ten itibaren". _Kaynak:_ §12.3.2; TN-55. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Yeni cihaz / yeni yöntem / kurtarma / e-posta değişimi anlık bildirimi** — Relay ile; "If this wasn't you: Secure your account"; "Action required" etiketi yok. _Kaynak:_ §8.6, §8.15.2; SEC18. _Durum:_ belirtilmemiş.

#### Enumeration direnci ve giriş mesajları

- [ ] **Durumun doğrulanmış kanala iletilmesi** — "If an account exists for this address, we've sent instructions". _Kaynak:_ §8.15.2; X-L1, X34. _Durum:_ belirtilmemiş.
- [ ] **Silinmiş hesap var olmayan hesaptan ayırt edilemez** — _Kaynak:_ X-L11, X34. _Durum:_ belirtilmemiş.
- [ ] **Identity plane mesaj sınıfları ve owner'ları tablosu** — Doğrulama başarısız, kilitli/devre dışı/silinmiş, step-up, sign-out, kurtarma, OAuth/federation hatası, yeni cihaz bildirimi, destek erişimi. _Kaynak:_ §8.15.2; X41. _Durum:_ belirtilmemiş.
- [ ] **Dürüst hata ve durum mesajları (identity plane)** — Kendi oturumundaki kullanıcıya kurtarma soğuma tarihi ve offline pencere dürüstçe söylenir; forbidden claims ve degraded-state kuralları identity plane metinlerine de uygulanır. _Kaynak:_ §12.4.1; TN-104. _Durum:_ belirtilmemiş (FROZEN).

#### Markalama ve şablonlar

- [ ] **Script çalıştırmayan şablon kabuğu + CSP** — Hosted UI şablonları script çalıştırmaz, fonksiyon çağrısı yoktur, tanımsız ada başvuru hatadır; özelleştirme betiksiz şablon + CSP allowlist ile (önce rapor, sonra zorlama). _Kaynak:_ §2.2.1; §3.1b #28; §12.4.2; CMP-15.6; F23; TN-106; X-L6. _Durum:_ gün-1; PD (CSP modu).
- [ ] **Tema kaydı: realm başına marka/tema (veri olarak markalama)** — Markalama kod değil veri (tema kaydı) olarak tanımlanır ve realm yapılandırmasının parçasıdır; realm başına marka ve giriş politikası. _Kaynak:_ §2.2.1; §3.1b #29; §5.14, §5.16, §7.1; §10.1.1; CMP-15.6; F23. _Durum:_ gün-1.
- [ ] **Korunan mesaj anahtarları (X35)** — Enumeration'a duyarlı, guarantee taşıyan ve owner atfeden anahtarlar kiracı tarafından ezilemez; serbest anahtarlar: ton, marka, yardım metni. _Kaynak:_ X-L6, X35; XI-25. _Durum:_ belirtilmemiş (PROPOSED FOR FREEZE).
- [ ] **Makine-okunur forbidden-claims çeviri denetimi** — Çeviriler canonical anahtardan üretilir ve §8.10'un makine-okunur hâliyle denetlenir. _Kaynak:_ X-L6, X35. _Durum:_ belirtilmemiş (UNDER DECLARED CAPABILITY).
- [ ] **Giriş/kayıt yüzeyinde üçüncü taraf takip kodu yasağı (CSP)** — _Kaynak:_ IDP-36; TN-106. _Durum:_ belirtilmemiş (karar FROZEN).

#### Erişilebilirlik ve yerelleştirme

- [ ] **WCAG 2.2 AA erişilebilir kimlik doğrulama** — Yapıştırma/otomatik doldurma engellenmez (3.3.8), tek alanlı yapıştırılabilir OTP, bilişsel test yok, ekran okuyucu duyurusu, QR tek yol değil; passkey birincil. _Kaynak:_ §12.4.3; §14.9; SA-55; TN-107; TN-G3; X-L14. _Durum:_ belirtilmemiş (FROZEN, TN-107); SA-55'e göre PD.
- [ ] **CAPTCHA yerine etkileşimsiz bot savunması** — _Kaynak:_ §12.4.3; TN-107; X-L14. _Durum:_ belirtilmemiş (FROZEN, TN-107).
- [ ] **Dürüstlük metinlerinin erişilebilirliği (X39)** — Ladder basamağı, owner rozeti, witness pending, UNKNOWN, offline pencere, SEC18 için metin karşılığı ve ekran okuyucu; yalnız renk/ikonla durum gösterilmez. _Kaynak:_ X-L14, X39. _Durum:_ belirtilmemiş.
- [ ] **Yerelleştirme: canonical anahtardan çeviri, çok kademeli yedek zinciri, realm metin ezme** — Yeni dil = §8.8'e yeni sütun; her dilde bir kavram = bir terim. _Kaynak:_ §12.4.3; TN-108; X-L15, X39. _Durum:_ PD (TN-108).
- [ ] **RTL desteği baştan** — _Kaynak:_ §12.4.3; TN-108; X-L15, X39. _Durum:_ PD (TN-108).
- [ ] **Login EN/TR terim eşlemesi ("‹cihaz› üzerinde giriş")** — Authority kavramları login metinlerine taşınmaz. _Kaynak:_ §12.4.3; TN-108. _Durum:_ PD.

#### Mental model ve mercekler

- [ ] **Canonical mental model** — "Yetki kaynaktan doğar, yalnız daralarak verilir, her kullanımı kaydedilir"; beş kalıcı fikir. _Kaynak:_ §8.1; X1. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Five lenses (tek model, beş mercek)** — Principal, Approver, Admin, Developer, Auditor için aynı model, farklı kesit/derinlik; terimler değişmez. _Kaynak:_ §8.2; X2. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Progressive disclosure: Default / Expert / Audit** — Her derinlik öncekinin açıklamasıdır ve onunla çelişemez; capacity ve status ladder hiçbir derinlikte gizlenmez; Audit derinliği authority gerektirir. Kademeler protocol'de disclosure scope'a karşılık gelir. _Kaynak:_ §8.12; §9.6; X25. _Durum:_ belirtilmemiş.
- [ ] **S10/S11/destek erişimi için disclosure satırları** — Default: cihaz, son etkinlik; Expert: yöntem sınıfı, bağ, SEC18 soğuma; Audit: authentication Claim'leri, `session_epoch` olayları. _Kaynak:_ §8.12. _Durum:_ belirtilmemiş.
- [ ] **UX hipotezlerinin araştırma ile doğrulanması** — Provenance/capacity gruplaması, asimetrik sürtünme, Approve/Give access/Allowed ayrımının öğrenilebilirliği; X33–X39 terimleri de hipotezdir. _Kaynak:_ §8.4, §8.20; OQ-6. _Durum:_ HYPOTHESIS.

#### Deneyim invariant'ları

- [ ] **Her durumun tek owner'ı** — Her durum satırı owner'ını gösterir (Expert derinlik); owner'a ulaşılamıyorsa UNKNOWN gösterilir. _Kaynak:_ §6.4; XI-1. _Durum:_ belirtilmemiş.
- [ ] **Honest status ladder (durum merdiveni çökmez)** — Requested → Approval recorded → Gate satisfied → Allowed / Not allowed → Started → Reported done / not done / Unknown / Differs; her basamak owner rozetlidir ve birleştirilmez (revoked ≠ stopped; delivered ≠ applied; unknown ≠ failed ≠ succeeded). Ücretlendirilemez dürüstlük yüzeyidir. _Kaynak:_ §6.4; §8.7; §18.6; B3; R6; X14; XI-2. _Durum:_ belirtilmemiş.
- [ ] **Optimistic UI yok** — Yüzeyler authority state tutmaz; authority değiştiren eylem commit'e kadar "submitted" görünür, "Revoked", "Delegation created", "Approved" ancak commit sonrası; "pending/queued" authority değişikliği yoktur. _Kaynak:_ §6.4; §8.5 karar 4; X14; XI-3. _Durum:_ belirtilmemiş.
- [ ] **Genişletme önizlemeli ve açık (asimetrik sürtünme)** — Her genişletme trusted surface'te exact typed preview ve assurance sonrası yapılan attributable bir Exercise'tır. _Kaynak:_ §6.4; R7; X11; XI-4. _Durum:_ belirtilmemiş (sürtünme dengesi HYPOTHESIS, §8.4).
- [ ] **Daraltma her zaman yakın** — İptal/daraltma herhangi authenticated yüzeyden en fazla iki adımdadır; önce etki, sonra sonuç gösterilir. _Kaynak:_ §6.4; R7; X11; XI-5. _Durum:_ belirtilmemiş.
- [ ] **Trusted sheet'ler (S1/S3) yalnız kullanıcı başlatınca açılır** — Kullanıcının başlattığı bağlamda doğrudan açılır; agent veya uygulama yalnız taslak hazırlayıp typed authority request gönderir, requester inisiyatifli talep yalnız Needs Attention item'ından açılır. _Kaynak:_ §6.4; §8.17.5.1; IA-1; X9; XI-7. _Durum:_ belirtilmemiş.
- [ ] **Açıklamalar türetilmiş, owner'lı, kapsamlı** — Açıklama DecisionRecord'dan mı advisory'den mi geldiğini etiketler, viewer yetkisi kadar derindir ve agent'a typed veri olarak döner. _Kaynak:_ §6.4; XI-9. _Durum:_ belirtilmemiş.
- [ ] **Capacity her zaman görünür ve tamlık kuralı** — "Kimin adına" etiketi provenance'tan ayrı gösterilir; viewer'ın grantor olduğu her Grant envanterde görünür. _Kaynak:_ §6.4; XI-10. _Durum:_ belirtilmemiş.
- [ ] **Sunulan eylemler = exercise edilebilir eylemler; "Who can: …"** — Viewer'ın yapamadığı eylem gizlenmez, "who can" ile yapabilecek kişi gösterilir (görmeye yetkiliyse). _Kaynak:_ §6.4; §8.17.5.2, §8.17.7.1; XI-11. _Durum:_ belirtilmemiş.
- [ ] **Dürüst UI dili: forbidden claims ve garanti sınıfı** — Yasak ifadeler ("Agent stopped", "Revoked everywhere instantly", "Full access", "Undo", "Verified", "Trusted device", "Tamper-proof", "Logged out everywhere", "Verileriniz silindi" vb.) asla kullanılmaz, her birinin dürüst karşılığı tanımlıdır; offline pencere, executor stop gibi konular guarantee koşuluyla yazılır. _Kaynak:_ §6.4; §8.10; §13.8; SA-1; SEC2; X24; XI-12. _Durum:_ belirtilmemiş (FROZEN, §13.8).
- [ ] **İki limit iki satır** — Authority limiti ile finansal limit ayrı satır ve ayrı owner rozetiyle gösterilir. _Kaynak:_ §6.4; XI-14. _Durum:_ belirtilmemiş.
- [ ] **Rule-shaped authority iki parçalı açıklama** — "Because HR says you're in Finance"; stale ("Needs refresh — not removed") ≠ removed; rejoin ≠ restore, yeniden katılımda eski türevler geri gelmez. _Kaynak:_ §6.4; §8.17.5.7; X16; XI-15. _Durum:_ belirtilmemiş.
- [ ] **Cross-domain satırlar "as of" taşır** — Uzak domain'den gelen satır tazelik bilgisi taşır, erişilemezse UNKNOWN gösterilir; envanter tamlık iddia etmez. _Kaynak:_ §6.4; XI-16. _Durum:_ belirtilmemiş.
- [ ] **First-party yüzey ayrıcalığı yok (composition, privilege değil)** — Suiss yüzeyleri conformant third-party yüzeyin yapamadığı hiçbir authority eylemini yapamaz; third-party Experience ve S1 aynı sözleşme ve conformance kuralıyla kurulabilir, intent digest yüzeyden bağımsızdır. _Kaynak:_ §6.4; §9.1, §9.14.3; E23; IA-7; XI-18. _Durum:_ belirtilmemiş.
- [ ] **Tekrar → yalnız öneri** — Tekrar eden onaylar yalnız öneri üretir; "Remember this", otomatik yenileme ve auto-approve yoktur. _Kaynak:_ §6.4; XI-19. _Durum:_ belirtilmemiş.
- [ ] **Tarih gösterilir, yeniden yazılmaz** — Redaksiyon "redacted — fingerprint verifiable" olarak görünür. _Kaynak:_ §6.4; XI-21. _Durum:_ belirtilmemiş.
- [ ] **Özel bağlam yüzeye çıkmaz** — One memory, Work içeriği ve başka Party'lerin grafiği gösterilmez. _Kaynak:_ §6.4; XI-22. _Durum:_ belirtilmemiş.
- [ ] **Sign-in yüzeyleri yetki iddia etmez (XI-23–XI-26 adayları)** — "Signed in" hiçbir zaman "allowed" ile yan yana sunulmaz; sign-in ≠ authority, sign-out ≠ revocation gibi aday invariant'lar (metin §8.19'da). _Kaynak:_ §6.10; §8.3; X29; XI-23. _Durum:_ belirtilmemiş (aday).

#### Ürün dili ve terimler

- [ ] **Canonical → UI terim eşlemesi (bir kavram = bir terim)** — Bağlayıcı EN/TR sözlük (Delegation, Your authority, Role, On your behalf, Can pass on, Protected action, Limit/left, Approve, Revoke, Narrow, Give back, Suspend, Allowed, Instance limits, Authority root, Offline pass vb.); Mandate için "Instance limits", insan Instance'ı "Sign-in on *device*", agent Instance'ı "Running copy"; "Give access"/"Delegate" ile "Allowed" ayrı tutulur. _Kaynak:_ §6.4, §7.2; §8.8; X24; XI-13. _Durum:_ belirtilmemiş.
- [ ] **UI'a ulaşmayan canonical terimler listesi** — HoldingRef, ValidityContract, nonce, Mandate, tenant_id, acr/amr ham değerleri, sub, DPoP/DBSC adları vb. _Kaynak:_ §8.9. _Durum:_ belirtilmemiş.
- [ ] **Terim çakışması kuralları** — "mandate" Access UI'ında hiç yok; session, tenant/account/org, grant/authorize, scope, admin, credential, token, owner, principal, authorization, unauthorized ("Outside authority"), consent, policy, trust için kurallar. _Kaynak:_ §8.11; X24. _Durum:_ belirtilmemiş.
- [ ] **"Session/oturum" kelimesi Access UI'ında kullanılmaz** — _Kaynak:_ §8.11; X33; X-L16. _Durum:_ belirtilmemiş.
- [ ] **"Give access…/Delegate" metni kullanım vaat etmez** — "…Access will still check the request."; commit etiketi "Delegation created". _Kaynak:_ §8.8; X8. _Durum:_ belirtilmemiş.
- [ ] **Remediation koddan metne çeviri** — Kullanıcı dilindeki metin Experience'ın kod → metin çevirisidir; protocol serbest metin taşımaz. _Kaynak:_ §9.6.1. _Durum:_ belirtilmemiş.
- [ ] **Claim gösterimi "Issuer says (signed)"** — Claim'ler "Verified" değil, issuer'ın imzalı iddiası olarak gösterilir. _Kaynak:_ §13.8. _Durum:_ belirtilmemiş.

#### Dürüst durum metinleri

- [ ] **"Not confirmed — checking" ve diğer dürüst durum metinleri** — UI bilinemeyeni bildirmez: Access cevabına (ör. authority failover sırasında) kadar "Not confirmed — checking"; ack'siz "confirmed" yok; "Not recorded — try again" yalnız nonce lineage'da yoksa; ayrıca "Unavailable — time check", "Busy — retry". _Kaynak:_ §13.4 G39; §13.8; §16.7; §17.4.5; CL-1, CL-2; RT23, RT24. _Durum:_ belirtilmemiş.
- [ ] **Sole root onay metni** — "Confirm with your hardware key; takes effect after 24 h — you can cancel until then". _Kaynak:_ §13.8. _Durum:_ belirtilmemiş.

#### Experience yüzeyleri (S1–S11)

- [ ] **Experience yüzeyleri S1–S10** — Ürün identity plane + authority plane + S1–S10'dur. _Kaynak:_ §18.3; B16; F3; X3. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **S1 Delegation (yetki verme / düzenleme sayfası)** — "Kime, neyi, kimin adına, hangi sınırla, ne zamana kadar — ve neyi vermiyorum?"; sonuç `grant.issue`/`grant.amend`. _Kaynak:_ §8.5; X3, X32. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **S2 Authority inventory ("Authority" hub)** — Kim benim yetkimden ne kullanıyor, kim benim adıma ne yapabilir, ben neyi nereden tutuyorum; cross-domain projection'lar owner+freshness etiketli; consumer yüzeyi, tek Suiss kabuğunda gömülü. _Kaynak:_ §8.5; §18.3; X4, X6. _Durum:_ belirtilmemiş (FROZEN, §18.3).
- [ ] **S4 Revoke / Suspend / Narrow + Aftermath** — Etki önizleme ve dürüst sonrası. _Kaynak:_ §8.5; X12. _Durum:_ belirtilmemiş.
- [ ] **S5 Explanation ("Why?" paneli, her yüzeyde aynı bileşen)** — Neden izin/ret/ne gerekiyor ve hayırın sahibi. _Kaynak:_ §8.5; X18. _Durum:_ belirtilmemiş.
- [ ] **S6 Activity (yetki kullanımları)** — Kim, ne zaman, neye dayanarak ne yaptı ve sonucu bildirildi mi; DENY/REQUIRE "kullanım" sayılmaz. _Kaynak:_ §8.5. _Durum:_ belirtilmemiş.
- [ ] **S7 Organization authority admin** — Kökler, roller, seçim kaynakları, korunan eylemler, kısıtlar ve change-impact. _Kaynak:_ §8.5; X20. _Durum:_ belirtilmemiş.
- [ ] **S9 Audit & security** — Kökten bugüne meşruiyet, o anki state, revocation yayılımı, bilinmeyen sonuçlar. _Kaynak:_ §8.5; X22. _Durum:_ belirtilmemiş.
- [ ] **S10 Sign-ins & instances** — Cihaz girişleri ve çalışan kopyalar; identity plane oturum render'ı genişlemesi; consumer kabukta gömülü. _Kaynak:_ §8.5; §18.3; X30, X32, X36. _Durum:_ belirtilmemiş (FROZEN, §18.3).
- [ ] **S11 Account & sign-in methods** — Identity plane self-servis yüzeyi. _Kaynak:_ §8.5; X32. _Durum:_ belirtilmemiş (PROPOSED FOR FREEZE).
- [ ] **Gömülü bileşen seti (authority)** — Delegation sheet S1, Approval Surface S3, Why? panel S5, Status ladder, Step-up ceremony; her üründe aynı sözleşme. _Kaynak:_ §8.17.4.1; X4. _Durum:_ belirtilmemiş.
- [ ] **Gömülü yüzeyler = renderer** — Pay limit ekranı, Commerce/Serve personel ekranı, POS, One sohbeti, third-party uygulamalar Access verisini render eder ve Exercise talebi gönderir; kopya tutmaz, karar vermez. _Kaynak:_ IA-4; X28. _Durum:_ belirtilmemiş.

#### Bilgi mimarisi

- [ ] **Tek Suiss kabuğu, sahiplik rozetli** — Ürün sınırı her durum satırındaki owner rozetinde görünür; içerik referansla bağlanır. _Kaynak:_ §8.17.4.1; IA-3; X4. _Durum:_ belirtilmemiş.
- [ ] **Authority hub alt bölümleri** — Acting for you, Shared from you, Your authority, Activity, Sign-ins & instances, Changes. _Kaynak:_ §8.17.4.1. _Durum:_ belirtilmemiş.
- [ ] **Authority hub ▸ Changes görünümü (yalnız bilgi akışı)** — Party'yi etkileyen genişletmeler (instance.create, onun adına grant.issue, acceptance.*) ve ingest edilmiş regime key-event'leri derived olarak görünür; hiçbir item "action required" iddia etmez. _Kaynak:_ §6.6; IA-2; SI-13, SI-21; X5. _Durum:_ belirtilmemiş.
- [ ] **Giriş noktaları tablosu** — Needs Attention approval → S3; authority missing → S1; One sohbeti → S1; Connect → S1; DENY mesajı → S5; checkout → S3/S1; güvenlik olayı → S9→S4. _Kaynak:_ §8.17.4.3. _Durum:_ belirtilmemiş.

#### Experience altyapısı ve konsol

- [ ] **Experience backend (authority hub, S1–S10, decision lab)** — Açık kaynak experience backend: authority hub aggregator, S1–S10 render verisi, decision lab; authority tutmaz/yazmaz. _Kaynak:_ CMP-16; XI-3. _Durum:_ belirtilmemiş.
- [ ] **Realtime UI (SSE/WebSocket)** — NATS'tan beslenen gateway; client sinyal alınca `at_least` ile yeniden okur. _Kaynak:_ §17.3.1; XI-3. _Durum:_ belirtilmemiş.

#### Delegation etkileşim desenleri

- [ ] **Delegation: üç giriş, tek onay** — Template, doğal dil (One/LLM) ve hassas editör yalnız taslak üretir; kayda yalnız exact typed preview sonrası Exercise girer. _Kaynak:_ §8.17.5.1; X9. _Durum:_ belirtilmemiş.
- [ ] **Exact preview zorunlu blokları** — To, Can do, Acting as, Can pass on, Limits, Requires, Valid, Not included, Interpretation (NL). _Kaynak:_ §8.17.5.1. _Durum:_ belirtilmemiş.
- [ ] **NL yorum farkları ayrı satırda** — "'Küçük alışverişler' → her alışveriş ≤ 500 TRY"; kayda typed içerik girer, cümle girmez. _Kaynak:_ §8.17.5.1; X9. _Durum:_ belirtilmemiş.
- [ ] **"Not included" bloğu daima** — Protected ve gelecekteki action'lar ile kullanıcının tutmadığı her şey. _Kaynak:_ §8.17.5.1; X10. _Durum:_ belirtilmemiş.
- [ ] **Taslakta effective authority dışı alanların işaretlenmesi** — "You can approve up to 2,000 TRY; you can't give 5,000". _Kaynak:_ §8.17.5.1. _Durum:_ belirtilmemiş.
- [ ] **Delegation varsayılanları** — Yeniden delege varsayılan kapalı; capacity seçimi zorunlu; agent delegation'ında bitiş zorunlu ("until you revoke" yalnız explicit, "forever" asla). _Kaynak:_ §8.17.5.1; X10. _Durum:_ PD (ürün varsayılanı).
- [ ] **Just-in-time authority request seçenekleri** — "Approve this request" / "Give access once" / "Give access for similar…" / "Decline"; seçenekler reason class kümesinden ve engelin zincirdeki seviyesinden hesaplanır. _Kaynak:_ §8.17.5.2; X8. _Durum:_ belirtilmemiş.
- [ ] **"Give access once" (tek seferlik Grant)** — count=1, parametreleri sabit, kısa süreli; viewer-scoped explain'deki `relative_to_viewer` alanından hesaplanır; çözülemeyen engel varsa sunulmaz veya "Would still be blocked by: …" ile sunulur. _Kaynak:_ §8.17.5.2; §9.6; R8; X8. _Durum:_ belirtilmemiş.
- [ ] **Budget görüntüleme** — Effective remaining (zincirin en darı), counted-result-unknown, reset zamanı, tükenme; financial limit ayrı satır, Pay/Money rozetli. _Kaynak:_ §8.17.5.6; X15. _Durum:_ belirtilmemiş.
- [ ] **"Turn off for me" (intensional rolde)** — "Leave role" yok; self-restriction, geri açılabilir; "Ask Acme to exclude me". _Kaynak:_ §8.17.5.7, §8.17.5.9; X16. _Durum:_ belirtilmemiş.
- [ ] **"Give back" (renounce)** — Doğrudan verilmiş Grant'ın kalıcı iadesi. _Kaynak:_ §8.8, §8.17.5.9. _Durum:_ belirtilmemiş.

#### Offline ve uzun süren iş gösterimi

- [ ] **Offline honesty (POS/edge/long-running)** — Offline pencere, offline limit, sonraki kontrol zamanı; "en geç T — profile uyulursa". _Kaynak:_ §8.17.5.8; X17. _Durum:_ belirtilmemiş.

#### Onay ve consent ekranları

- [ ] **S1 exact preview / OAuth consent ekranı** — Consent ekranı S1 exact preview'dır ("Connect"); meta-Exercise'ın typed preview'ı core meta-schema render'ından gösterilir. _Kaynak:_ §9.9, §9.14.1 B. _Durum:_ belirtilmemiş.

### K07 Yetki modeli

#### Party, Instance ve actor modeli

- [ ] **Party birleşmesi authority birleştirmez** — _Kaynak:_ §12.3.3; TN-67, TNI-11. _Durum:_ belirtilmemiş (FROZEN)

#### Schema ve katalog yönetimi

- [ ] **Schema benimseme akışı** — SPP ingest edilir, S7 Sources ▸ Action definitions'ta diff incelenir, ardından `acceptance.amend(schema-definition)` yapılır. _Kaynak:_ §9.13.6. _Durum:_ belirtilmemiş

#### Tenant, göç ve devredilmiş yönetim

- [ ] **Hesap yaşam döngüsü olayları yalnız Claim/Exercise ile etkiler** — _Kaynak:_ §12.3; E5, TNI-8. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Rıza/izinler göçte Grant olarak yeniden verilir** — _Kaynak:_ §12.3.7; TN-84. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **IdP göçü ≠ `domain.handover`** — _Kaynak:_ §12.3.7; TN-84. _Durum:_ belirtilmemiş (FROZEN)

#### Kullanıcı arayüzü semantiği

- [ ] **Approve ≠ Give access ≠ Allowed (üç terim, üç kavram)** — Approve = contribution, Give access = `grant.issue/amend`, Allowed = ALLOW DecisionRecord. _Kaynak:_ §8.8; R2, X8. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Provenance ≠ capacity** — "On your behalf / On behalf of *Acme* / For their own use / As yourself" capacity etiketi her satırda provenance'tan ayrı gösterilir. _Kaynak:_ §8.8; R1, XI-10. _Durum:_ belirtilmemiş
- [ ] **Capacity seçimi kullanıcının agency'sinden türetilir** — Kullanıcı Acme adına tutuyorsa "on your behalf" seçeneği görünmez. _Kaynak:_ §8.17.5.1; X10. _Durum:_ belirtilmemiş
- [ ] **Authority root gösterimi** — "Root: Acme board, 2 of 3"; "owner" kelimesi kullanılmaz. _Kaynak:_ §8.8, §8.11. _Durum:_ belirtilmemiş
- [ ] **Rule-shaped (role) delegation gösterimi** — "Give *Finance Approver v4* to: everyone HR lists in Finance"; satırda seçici + "currently 14". _Kaynak:_ §8.8, §8.17.7.6, §8.17.9.2. _Durum:_ belirtilmemiş
- [ ] **Kişisel dışlama (selector daraltma)** — "Acme excluded you from this role on 7 Oct". _Kaynak:_ §8.17.5.7. _Durum:_ belirtilmemiş
- [ ] **Narrow (`grant.amend` narrowing, consent yok)** — Geri genişletmek genişletme eylemidir. _Kaynak:_ §8.17.7.5. _Durum:_ belirtilmemiş
- [ ] **Otomatik yenileme yok** — "Renew" S1'i yeni bitişle açar; expired Grant için "Create again". _Kaynak:_ §8.6, §8.17.7.7. _Durum:_ belirtilmemiş
- [ ] **Süresi yaklaşan kullanılan delegation işareti** — "Ends in 3 days — used 12 times this week". _Kaynak:_ §8.17.7.7. _Durum:_ belirtilmemiş

### K10 Yönetişim

#### Değişiklik etkisi ve yönetim yüzeyi

- [ ] **S7 org authority admin** — Rol sürümleme, change-impact, Acceptance blast radius, offboarding. _Kaynak:_ §18.3. _Durum:_ belirtilmemiş (FROZEN yüzey)

### K11 Yönetim API'si, konsol, SDK'lar ve geliştirici araçları

#### Yönetim konsolu: temel

- [ ] **S9 audit & security konsolu** — Audit, replay, export, containment. _Kaynak:_ §18.3. _Durum:_ belirtilmemiş (FROZEN yüzey).

#### Konsol: rol, kaynak ve domain ekranları

- [ ] **Sources (Acceptance) ekranı** — Use'u sade dille (Sign-in source, Fact source, Membership source, Partner authority source, Action definitions) ve blast radius'uyla gösterir; bir use kabulü başka use değildir. _Kaynak:_ §8.17.9.3; INV-15; X20. _Durum:_ belirtilmemiş.
- [ ] **Access'in kendi realm'i "Sign-in source" olarak** — Realm grup/SCIM claim'leri ayrı korunan "Membership source" kabulü ister. _Kaynak:_ §8.17.9.3 notu. _Durum:_ belirtilmemiş.
- [ ] **S7 Sources ▸ Action definitions** — Schema diff, tipler ve reserved inceleme ekranı. _Kaynak:_ §9.13.6. _Durum:_ belirtilmemiş.
- [ ] **Domain sayfası** — Constitution özeti, provider (custody), handover/recovery geçmişi. _Kaynak:_ §8.17.9.7. _Durum:_ belirtilmemiş.
- [ ] **Sign-in settings (realm config) ekranı** — Client'lar, upstream IdP, marka, giriş politikası; her değişiklik domain action Exercise'ı. _Kaynak:_ §8.11; §8.17.4.1; E34; MD-14. _Durum:_ belirtilmemiş.
- [ ] **Admin konsolunda Gate'in gömülü gösterimi** — Packaging ≠ ownership. _Kaynak:_ §8.17.9.5. _Durum:_ belirtilmemiş.

### K12 Entegrasyonlar ve yardımcı servisler

#### SSF/CAEP, olay yayını ve Relay

- [ ] **Davet e-postası (işlemsel posta)** — _Kaynak:_ §12.3.8. _Durum:_ belirtilmemiş.

#### Bot ve kötüye kullanım savunması

- [ ] **Bot savunması: Turnstile / Friendly Captcha skoru, Privacy Pass (RFC 9577)** — Skor tabanlı; PAT yalnız pozitif sinyal. _Kaynak:_ §12.3.6; TN-81. _Durum:_ PD.
- [ ] **Gizlilik relay allowlist'i** — iCloud Hide My Email, Firefox Relay, DuckDuckGo tek kullanımlık sayılmaz. _Kaynak:_ §12.3.6; TN-81. _Durum:_ PD.
- [ ] **Tek kullanımlık e-posta skorlaması** — Bloklanmaz, skorlanır; artı etiketi kişi başı hak kontrolünde kanonikleştirilir. _Kaynak:_ §12.3.6; TN-81. _Durum:_ PD.

#### Federasyon ve envanter görünümü

- [ ] **"Not shown: domains you haven't connected" uyarısı** — Envanter tam olduğunu iddia etmez. _Kaynak:_ §8.17.7.2. _Durum:_ belirtilmemiş.

### K13 Denetim, kayıt, şeffaflık ve dışa aktarım

#### Özel olay denetimleri

- [ ] **Niyet belirteci üretim/kullanım ayrı denetim olayları** — _Kaynak:_ §12.3.2; TN-61. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Kurtarma ekleme-yalnız geçiş kaydı** — _Kaynak:_ §12.3.2. _Durum:_ belirtilmemiş.
- [ ] **Birleştirme öncesi anlık görüntü + denetim olayı** — _Kaynak:_ §12.3.3; TN-67. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Belge onay kaydı (tamper-evident)** — Metin, sürüm digest'i, zaman, yöntem; yeni sürümde yeniden onay istenebilir. _Kaynak:_ IDP-37; TN-132. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **Tercih değişiklik geçmişi** — _Kaynak:_ IDP-37. _Durum:_ belirtilmemiş.

#### Redaksiyon ve saklama

- [ ] **Redaksiyon: "Redacted — fingerprint verifiable"** — Audit kayıtları silinmez, redakte edilir (redaksiyon ≠ erase); body yalnız canlı derivation'a gerekmediğinde redakte edilir ve digest doğrulanabilir kalır. _Kaynak:_ §5.11; §8.10; §8.12; §13.8; C34; INV-30; U22; XI-21. _Durum:_ belirtilmemiş.
- [ ] **Redaksiyon mekanizması (T39, crypto-shredding)** — Salt'lı body commitment, body başına DEK; body + salt + DEK silinir, leaf hash/commitment ve digest süresiz kalır; 400 gün uygunluk. _Kaynak:_ §17.6.1, §17.6.9; C34; INV-30; OP-42; RT27; T39. _Durum:_ belirtilmemiş (FROZEN TECHNICAL); PD (400 gün).
- [ ] **Saklama politikası (authority saklama tablosu)** — Exercise/audit body genel varsayılan 400 gün sonra redaksiyon uygunluğu; sektör şablonu uzatır, kısaltma yok; header/commitment/digest süresiz; belirsizse redakte etme; PII saklama sınıfının Ek C kuralına göre crypto-shred. _Kaynak:_ §13.7.9; §14.9; §17.6.7; OP-40; OP-74; SA-52; SEC32; Ek C. _Durum:_ PD / POLICY DEFAULT (süreler).
- [ ] **Olay iskeleti uzun, PII kısa** — İskelet ≥ 12 ay; IP/UA/e-posta özne × saklama sınıfı anahtarıyla şifreli, sınıfın Ek C kuralına göre crypto-shred; alan başına PII ve saklama sınıfı etiketi. _Kaynak:_ §17.6.7; OP-40. _Durum:_ POLICY DEFAULT.
- [ ] **Kiracı saklama sınırının arayüzde açık yazılması** — "30 güne indir" header'lara uygulanamaz; arayüzde yazılır. _Kaynak:_ §17.6.7. _Durum:_ belirtilmemiş.
- [ ] **Opaque ref kişisel parametreler** — Kişisel veri taşıyan authority-relevant parametreler mümkünse opaque ref. _Kaynak:_ SEC32. _Durum:_ belirtilmemiş.

#### Kişi verisi dışa aktarımı

- [ ] **Kişi verisi dışa aktarımı (GDPR m.20)** — Tanımlayıcılar, profil, atamalar, rıza/yetki görünümü, federe kimlikler, MFA metadata'sı, giriş ve durum geçmişi dahil; hash/MFA sırrı/OTP/kurtarma kodu/WebAuthn özel materyali hariç; step-up, hız sınırı, denetim. _Kaynak:_ §12.3.5; TN-79. _Durum:_ PD (içerik), FROZEN (ayrım).
- [ ] **Hash/OTP göç dışa aktarımı** — Bkz. K04. _Kaynak:_ §12.3.7; TN-86. _Durum:_ PD.

#### Audit yüzeyleri ve kullanıcıya görünür geçmiş

- [ ] **Audit yüzeyleri canonical kayıtların render'ı** — Provenance, capacity, StateBasis, cited proofs, replay, redaksiyon doğrulaması. _Kaynak:_ §8.5 S9; X22. _Durum:_ belirtilmemiş.
- [ ] **Audit derinliği (DecisionRecord detayı)** — StateBasis, cited Claim/Acceptance/policy sürümleri, trusted evaluation time, consumption effects, digest'ler. _Kaynak:_ §8.12; §8.17.8.4. _Durum:_ belirtilmemiş.
- [ ] **Activity (S6) kullanım kaydı** — Feed değil, kayıt; DENY kullanım sayılmaz. _Kaynak:_ §8.5; §8.17.12. _Durum:_ belirtilmemiş.
- [ ] **Geçmiş kullanımlar geçerli tarih olarak kalır** — "Past uses remain valid history"; "Undo" yok. _Kaynak:_ §8.10; §8.17.7.4; INV-23. _Durum:_ belirtilmemiş.
- [ ] **Revocation impact / exposure görünümü** — "Revocation exposure: 3 terminals, max window 18:00 · 2 confirmed applied · 1 unknown". _Kaynak:_ §8.5 S9; §8.17.5.8. _Durum:_ belirtilmemiş.
- [ ] **Unknown outcomes görünümü** — Audit bölümünde. _Kaynak:_ §8.5 S9; §8.17.4.1. _Durum:_ belirtilmemiş.
- [ ] **Meta-Exercise geçmişi (S7)** — Tüm değişikliklerin geçmişi. _Kaynak:_ §8.5 S7; §8.17.9.1. _Durum:_ belirtilmemiş.
- [ ] **Claim'lerin "X says (signed)" gösterimi** — "Verified fact" yasak. _Kaynak:_ §8.3, §8.8, §8.10. _Durum:_ belirtilmemiş.
- [ ] **Changes akışı / SI-21 genişleme görünürlüğü** — Authority değişiklikleri pull ile görülür; Relay özet teslimi tercihe bağlı. _Kaynak:_ §8.6; §12.3.2; IA-2; SI-21. _Durum:_ belirtilmemiş.
- [ ] **Kullanıcıya görünen güvenlik geçmişi** — Login, MFA, anahtar, oturum, OAuth onayı; 30–90 gün; IP maskeli; risk skoru gösterilmez. _Kaynak:_ §17.6.10; OP-43. _Durum:_ PD (süre).

### K14 Sinyaller, gözlemlenebilirlik ve analitik

#### Revocation ve sonuç görünürlüğü

- [ ] **Revocation "nerede etkili oldu" görünürlüğü** — Ack'ler S4/S9 status'unda görünür; domain raporlama koşulu koyabilir. _Kaynak:_ §9.12.3. _Durum:_ belirtilmemiş.
- [ ] **Exercise outcome state ve offline kullanım görünümü** — Outcome attested/unknown; offline kullanılan/kullanılmayan/contract dışı derived state'i S4/S9'da görünür. _Kaynak:_ §9.12.2; §16.5.1. _Durum:_ belirtilmemiş.

#### Açıklama ("Why?")

- [ ] **Owner composition paneli** — Access/Commerce/Work/Pay satırları ayrı; "what could change this" yalnız mümkün canonical eylemler; en yakın çözüm sırası. _Kaynak:_ §8.5 karar 3; §8.17.8.3. _Durum:_ belirtilmemiş.
- [ ] **Açıklama derinlikleri (Default/Expert/Audit)** — _Kaynak:_ §8.17.8.4. _Durum:_ belirtilmemiş.
- [ ] **Past vs hypothetical etiketleme** — "Why this was allowed (at 14:02)" ile "Would this be allowed now?" ayrı etiketlenir. _Kaynak:_ E-1; X18. _Durum:_ belirtilmemiş.

#### Operasyon sinyalleri, metrikler ve alarmlar

- [ ] **Parola göçü bekleyen hesap sayısı telemetrisi** — _Kaynak:_ CR-37. _Durum:_ PD.

#### Ürün metrikleri

- [ ] **Passkey/kurtarma metrikleri** — Bkz. K04, K06. _Kaynak:_ (K04, K06'ya atıf). _Durum:_ belirtilmemiş.

#### Kiracı analitiği

- [ ] **Parola unutma ve kurtarma başarısı** — _Kaynak:_ IDP-36. _Durum:_ PD.

### K15 Güvenlik ve kriptografi

#### Veri şifreleme ve sır yönetimi

- [ ] **Kullanıcı başına PII anahtarı (DEK) ve crypto-shredding** — Alan seviyesinde zarf şifreleme; anahtar imhasından sonra PII okunamaz; imha gecikmesi 30 g (min 24 s); Merkle/özet zinciri ciphertext üzerinde; imha kanıtı. _Kaynak:_ §3.1b #17; §12.3.5; TN-77; U58. _Durum:_ gün-1; PD (imha gecikmesi).
- [ ] **PII vault ve kiracı KEK'i** — Ham assertion, KYC belgeleri, e-posta/telefon, adres; kiracı başına KEK ile crypto-shredding. _Kaynak:_ §10.1.7; T31. _Durum:_ belirtilmemiş.

#### Hesap numaralandırma ve kimlik bilgisi saldırıları

- [ ] **Kurtarma kanalı gizlilik değerli varlık; faktör izolasyonu** — Bir faktör başka sınıftan faktör elde ettiremez. _Kaynak:_ §12.3.2; TNI-6. _Durum:_ belirtilmemiş.

#### Kimlik protokolleri güvenliği

- [ ] **Sosyal girişte üretimde ortak anahtar yasağı** — _Kaynak:_ IDP-31. _Durum:_ belirtilmemiş (karar FROZEN).

#### Revocation ve olay müdahalesi

- [ ] **Containment (SOC)** — `instance.*`/`grant.revoke`/restriction Exercise'ları S9'dan S4'e; executor ignore ederse containment önerileri. _Kaynak:_ §8.6; §8.13; §8.17.9.7. _Durum:_ belirtilmemiş.
- [ ] **Timeout kuralı (authority-changing istekler)** — "Not confirmed — checking" → aynı nonce retry (AIS intent validity penceresi içinde) → sonra yalnız sonuç sorgusu → "Revoked" / "witness pending" / "Not recorded — try again". _Kaynak:_ §8.13; HL-5; TI-8; X26. _Durum:_ belirtilmemiş (kısa validity değeri ENGINEERING ASSUMPTION, tavan PD).
- [ ] **"Couldn't revoke … not recorded" kısayolu kısıtı** — Yalnız hiçbir deneme gönderilmemişse; aracılı yolda kullanılmaz. _Kaynak:_ §8.13; §8.17.7.2 notu; X26. _Durum:_ belirtilmemiş.
- [ ] **Revoke impact preview** — Cascade, running copies, açık task horizon'ları, offline pass'lar, değişmeyenler. _Kaynak:_ §8.17.7.3; X12. _Durum:_ belirtilmemiş.
- [ ] **Aftermath paneli** — Authority, Running work, Next step, Offline, Delivery, History satırları, her biri owner'ından. _Kaynak:_ §8.17.7.4; X12. _Durum:_ belirtilmemiş.
- [ ] **Revoke en fazla iki adımda, her authenticated yüzeyden** — _Kaynak:_ §8.17.7.3; X6; XI-5. _Durum:_ belirtilmemiş.

### K16 Gizlilik, rıza ve uyum

#### Takma adlar ve bağlanamazlık

- [ ] **Kanonik e-posta yalnız suistimal skoru ve kişi başı haklar için** — _Kaynak:_ §12.3.6; TN-80. _Durum:_ PD.

#### PII koruması ve redaksiyon

- [ ] **PII vault (alan şifreleme)** — Kişisel veriler ayrı PII vault'ta, tenant anahtarlı, `tenant_id` + RLS FORCE ve kişi × saklama sınıfı başına DEK ile tutulur (OP-74); authority log'da yalnız pseudonymous PartyRef bulunur. _Kaynak:_ §3.1b; §5.1; §5.16; §17.1.4; §17.6.9; CMP-15.9; I4; OP-42. _Durum:_ belirtilmemiş.
- [ ] **Redaksiyon geri çağırma değildir** — Önceki alıcılardan veri geri çağrılmaz. _Kaynak:_ §6.6; SI-15. _Durum:_ belirtilmemiş.
- [ ] **Derived okumada redaksiyon yeniden kontrolü** — _Kaynak:_ §17.6.7; SI-15. _Durum:_ belirtilmemiş.
- [ ] **Telemetride redaksiyon takibi** — Redakte body'den türetilmiş değer telemetride kalmaz. _Kaynak:_ §17.8.1; OP-47. _Durum:_ belirtilmemiş.

#### Rıza ve izinler

- [ ] **Kimlik verisi paylaşımı onayı (claim release)** — "Share with *App*…" ekranı. _Kaynak:_ §8.8. _Durum:_ belirtilmemiş.
- [ ] **Tam tercih merkezi** — Kanal (e-posta, SMS, arama, push) ve konu (kampanya, bülten, ürün haberleri) bazında izin ve geri çekme. _Kaynak:_ IDP-37; TN-133. _Durum:_ PD (kanal/konu listesi).
- [ ] **İzinler yetki değildir** — Pazarlama izni Grant değil, karar girdisi değil. _Kaynak:_ IDP-37. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **Belge onayları (kullanım koşulları, KVKK aydınlatma, gizlilik politikası)** — _Kaynak:_ IDP-37; TN-132. _Durum:_ belirtilmemiş (karar FROZEN).

#### Veri sahibi hakları, silme ve saklama

- [ ] **Veri taşınabilirlik ve silme talepleri ekranı (S11)** — _Kaynak:_ §8.5 S11. _Durum:_ belirtilmemiş.
- [ ] **Taşınabilirlik export'u (GDPR Art. 15/20)** — Gözlenen veri dahil, türetilmiş veri (risk skoru, profil) hariç; şemada bayrak. _Kaynak:_ §17.6.10; OP-43. _Durum:_ PD.
- [ ] **Veri sahibi talebi ≤30 gün** — _Kaynak:_ §12.3.5; TN-78. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Silmede saklama süresi ve redaksiyon beyanı** — _Kaynak:_ §8.10; X38. _Durum:_ belirtilmemiş (saklama PD).
- [ ] **KVKK silme/yok etme/anonimleştirme eşlemesi** — Silme = mezar taşı + SCIM 404; yok etme = sert silme + kripto parçalama + yedek sona erme; anonimleştirme = denetim satırında özne referansının koparılması. _Kaynak:_ §12.3.5; TN-78. _Durum:_ belirtilmemiş (FROZEN tavanlar).
- [ ] **Silme talebinde crypto-shredding (GDPR Art.17)** — Kişisel alanlar silinir veya crypto-shred edilir; tombstone + değişmez "silme olgusu" satırı; authority log'da PartyRef kalır. _Kaynak:_ §14.9; §17.6.7, §17.6.9; OP-42. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **Crypto-shredding tamamlanma tavanı beyanı** — "Anında silme" iddia edilmez. _Kaynak:_ CR-32 madde 3. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **KVKK periyodik imha işi (≤6 ay)** — _Kaynak:_ §12.3.5; §14.9; TN-78. _Durum:_ PD (aralık).
- [ ] **Hareketsizlik ve imha saatleri ayrı** — _Kaynak:_ §12.3.5; TN-78. _Durum:_ belirtilmemiş.
- [ ] **GDPR m.17(3) istisnaları ve "beyond use" yedek ilkesi** — _Kaynak:_ §12.3.5. _Durum:_ belirtilmemiş.
- [ ] **Mezar taşı karar/risk/dolandırıcılık listesi girdisi değil** — _Kaynak:_ §12.3.5; TN-76. _Durum:_ belirtilmemiş (FROZEN).

#### Otomatik karar ve üçüncü taraf araçlar

- [ ] **reCAPTCHA kullanılmaz (KVKK/CNIL)** — _Kaynak:_ §12.3.6; TN-81. _Durum:_ PD.

#### Mevzuat ve standart eşlemeleri

- [ ] **NIST SP 800-63B-4 kurtarma uyumu** — _Kaynak:_ §12.3.2; TN-52–59. _Durum:_ belirtilmemiş (FROZEN NIST SHALL).
- [ ] **CIS 5.3 / PCI DSS 8.2.6 atıl hesap eşikleri** — _Kaynak:_ §12.3.1; TN-51. _Durum:_ PD.
- [ ] **WCAG/EAA uyumu satış gereksinimi** — _Kaynak:_ §12.4.3; TN-107. _Durum:_ belirtilmemiş (FROZEN).

### K17 Dağıtım, operasyon, yüksek erişilebilirlik ve felaket kurtarma

#### Cell topolojisi ve altyapı

- [ ] **Özel alan adı sertifika ve DNS otomasyonu** — Konfor ücretlendirilebilir. _Kaynak:_ §12.1.2. _Durum:_ belirtilmemiş.

#### Provider bağımsızlığı ve keşif

- [ ] **Provider custody ≠ root** — "Hosted by Suiss Access — the host holds no authority here". _Kaynak:_ §8.17.9.7; INV-29. _Durum:_ belirtilmemiş.

### K18 Açık kaynak, ticari model ve paketleme

#### Açık kaynak bileşenler

- [ ] **Açık kaynak experience backend** — _Kaynak:_ CMP-16. _Durum:_ belirtilmemiş.

#### Suiss bağımsızlığı ve kilitlenmeme (anti-hostage)

- [ ] **Hash/TOTP dışa aktarımı ücretsiz (kilitlenmeme)** — Müşteri parola hash'lerini ve TOTP/OTP sırlarını ücretsiz dışa aktarabilir. _Kaynak:_ §12.3.7; B19, MKT-D9, TN-86. _Durum:_ PD (§12.3.7).

#### Paketleme

- [ ] **Rol yapısı** — Protocol + hosted infrastructure + product + developer service + enterprise control plane; consumer gömülü. _Kaynak:_ §18.3; B16. _Durum:_ belirtilmemiş.

#### Ücretlendirilemez güvenlik ve temel yüzeyler

- [ ] **Özel alan adının varlığı ücretlendirilemez** — Sertifika/DNS otomasyonu konforu ücretlendirilebilir. _Kaynak:_ §12.1.2, §18.6; TN-10. _Durum:_ belirtilmemiş.
- [ ] **Özel alan adı RP ID'si ücretlendirilmez** — _Kaynak:_ RR-45, TN-17. _Durum:_ belirtilmemiş.

#### Pazara giriş, sertifika ve topluluk

- [ ] **Satış dili yasak iddiaları** — "anında her yerde iptal", "agent'ı durdurur", throughput garantisi, "Keycloak'tan hızlı", "passkey ile ele geçirilemez" vb. yasaktır; SLA yalnız availability içindir. _Kaynak:_ B15. _Durum:_ belirtilmemiş.

### K19 Geliştirme ve kalite güvencesi

#### Kalite ilkeleri ve iddia disiplini

- [ ] **İddia dili disiplini** — Ürün dilinde izin verilen ve verilmeyen garanti ifadeleri tablosu. _Kaynak:_ §1.4, §3.3a; B15. _Durum:_ belirtilmemiş.
- [ ] **Forbidden-claims tablosunun makine-okunur hâli ile çeviri denetimi** — _Kaynak:_ X35. _Durum:_ belirtilmemiş.
- [ ] **Kullanıcı araştırması / pilotlarla UX hipotez doğrulaması** — _Kaynak:_ §8.4, §8.17.13; OQ-6. _Durum:_ HYPOTHESIS.

#### Protokol, kiracı ve bileşen güvenlik testleri

- [ ] **Kurtarma paralel yeniden bağlama kabul testi** — _Kaynak:_ §12.3.2; TN-54. _Durum:_ belirtilmemiş.

### Bu aşamada doğrulanacak sınırlar

#### Ürün kapsamı

- [ ] **Suiss kabuğu müşteri realm'ine dayatılmaz** — _Kaynak:_ X4; X40. _Durum:_ belirtilmemiş.

#### Yetki modeli

- [ ] **İzinler ve tercihler (consent/preferences) yetki değildir** — _Kaynak:_ IDP-37. _Durum:_ belirtilmemiş.
- [ ] **Mezar taşı (tombstone) karar girdisi değil** — _Kaynak:_ TN-76. _Durum:_ belirtilmemiş.
- [ ] **Hesap/Party birleştirme authority birleştirmez; birleştirme geri alınamaz** — OAuth Grant Management `merge` reddedildi. _Kaynak:_ INV-39; TN-67. _Durum:_ belirtilmemiş.
- [ ] **Kurtarma authority miras bırakmaz** — _Kaynak:_ INV-13; TN-53. _Durum:_ belirtilmemiş.

#### Kiracı genişletilebilirliği

- [ ] **Kiracı korunan mesaj anahtarlarını ezemez; "ezme + doğrulayıcı" seçeneği yok** — _Kaynak:_ X35. _Durum:_ belirtilmemiş.

#### Kiracı ve hesap modeli

- [ ] **E-posta eşleşmesiyle otomatik hesap bağlama/birleştirme yok (nOAuth sınıfı)** — E-posta anahtar değildir. _Kaynak:_ §7.1; §7.3; §10.2.6; §12.1.1; IDP-31; MD-5; TN-3; TN-65. _Durum:_ belirtilmemiş.
- [ ] **İlk davet kabulünde sahip/yönetici yok; tarayıcı tıklaması belirteci tüketmez** — _Kaynak:_ TN-89. _Durum:_ belirtilmemiş.
- [ ] **Tüketici/TR ücretsiz posta/ISS/üniversite alan adlarında otomatik katılım yok** — _Kaynak:_ TN-90. _Durum:_ belirtilmemiş.
- [ ] **Beyan yoksa DNS ile sahiplik kurtarma yolu yok** — _Kaynak:_ TN-92. _Durum:_ belirtilmemiş.
- [ ] **Kurtarma soğuması vaka başına kısaltılamaz** — Destek, yönetici ve break-glass dahil. _Kaynak:_ TN-55. _Durum:_ belirtilmemiş.
- [ ] **AAL2 hesapta tek e-posta bağlantısı kurtarma sayılmaz** — _Kaynak:_ TN-52. _Durum:_ belirtilmemiş.
- [ ] **Kişi dışa aktarımında gizli materyal yok** — Hash, MFA sırrı, OTP, kurtarma kodu ve WebAuthn özel materyali dışa aktarılmaz. _Kaynak:_ TN-79. _Durum:_ belirtilmemiş.
- [ ] **Oturum/refresh/rıza/denetim geçmişi göçte taşınmaz** — _Kaynak:_ §12.3.7. _Durum:_ belirtilmemiş.
- [ ] **CXF RP'den RP'ye passkey göç aracı değildir; passkey alan adı değişiminde taşınamaz** — _Kaynak:_ TN-17; TN-87. _Durum:_ belirtilmemiş.

#### Kimlik doğrulama yöntemleri

- [ ] **Dış sistemden gelen hash'ler doğrudan taşınmaz (tembel göç)** — _Kaynak:_ §10.2.1. _Durum:_ belirtilmemiş.
- [ ] **Tek kullanımlık e-postayı bloklama yok** — _Kaynak:_ TN-81. _Durum:_ belirtilmemiş.

#### Denetim, saklama ve gözlemlenebilirlik

- [ ] **Kullanıcı güvenlik geçmişinde risk skoru gösterilmez** — _Kaynak:_ OP-43. _Durum:_ belirtilmemiş.

#### Güvenlik sertleştirme ve geliştirme süreci

- [ ] **SVG yükleme yok / sanitize edilir** — _Kaynak:_ §14.3. _Durum:_ belirtilmemiş.

#### Kullanıcı arayüzü ve terminoloji

- [ ] **"Verified app" rozeti yok** — _Kaynak:_ §8.8; §8.17.12. _Durum:_ belirtilmemiş.
- [ ] **Ayrı Access bildirim merkezi / activity-feed-as-attention yok** — _Kaynak:_ §8.17.12; X27. _Durum:_ belirtilmemiş.

#### Ürün iddiaları ve vaat edilmeyenler

- [ ] **"Silindi" / "anında silme" iddiası yok; crypto-shred "GDPR silmesi" olarak pazarlanmaz** — Crypto-shredding silme değildir. _Kaynak:_ CR-32; HL-9; N-42; OP-42; SA-50. _Durum:_ belirtilmemiş.
- [ ] **Operatörün okuyamaması / "Suiss can't see your data" iddiası yok** — _Kaynak:_ §13.8; N-22. _Durum:_ belirtilmemiş.

#### İş modeli ve lisans

- [ ] **Data/identity hostage, proprietary canonical format ve müşteri verisinden eğitim/analitik moat'ı yok** — _Kaynak:_ B11. _Durum:_ belirtilmemiş.

## Aşama 9 — Ajanlar ve MCP

Ajan kimliği ve Mandate'leri, token vault, Executor servisi, MCP authorization profili, ID-JAG/XAA, ajan kaydı, MCP gateway, gölge ajan keşfi.

### K01 Kimlik doğrulama yöntemleri

#### Genel model ve tipli sonuç

- [ ] **Agent Instance'ın requirement karşılama kuralı** — Agent, CT2'de actor-side term'leri yalnız `attestation.runtime` ve donanıma bağlı KeyBinding ile karşılar; insan varlığı dahil hiçbir insan term'ini karşılayamaz ve step-up yalnız kullanıcının kendi Instance'ında karşılanır (`not-satisfiable-by-actor`). Agent'ın `approve` eligible set'ine girmesi CT3 genişletmedir. _Kaynak:_ §8.17.5.4, §8.18.3, §13.7.3; X19. _Durum:_ PD.

#### Sertifika, donanım ve cihaz anahtarları

- [ ] **Donanım anahtarı attestation kontrol listeleri** — Android key attestation, Apple App Attest ve TPM için ayrı kontrol listeleri; attestation yalnız claim'dir. _Kaynak:_ §12.2.1; L21. _Durum:_ belirtilmemiş.

#### İstemci kimlik doğrulaması

- [ ] **Attestation tabanlı istemci kimlik doğrulaması (`attest_jwt_client_auth`)** — Client Attestation JWT + PoP; DPoP ortak anahtar modu (aynı anahtar hem attestation hem gönderici kısıtı için). Taslak izleniyor. _Kaynak:_ §11.12.4, §11.21.1 #22, §11.21.2; §12.2.1; AG-31. _Durum:_ WATCH (talep üzerine).

#### İş yükü kimliği

- [ ] **SPIFFE / workload kimliğiyle istemci doğrulama (JWT-SVID, X.509-SVID)** — JWT-SVID birinci sınıf istemci kimlik doğrulamasıdır (`jwt-spiffe` assertion tipi); X.509-SVID mTLS (SAN URI'de SPIFFE ID) ve WIT-SVID + Client Attestation PoP de desteklenir. SPIFFE/WIMSE issuer'ları actor-binding Acceptance'ıyla kabul edilir ve kimlikleri actor binding girdisidir; SPIFFE Bundle Endpoint zorunludur. _Kaynak:_ §4.3; §7.9.11.1; §11.12.1, §11.21.1 #10; AG-30, L25. _Durum:_ belirtilmemiş (ADOPT; taslak etiketiyle bugün).
- [ ] **WIMSE WIT/WPT kabulü** — WIT (`wit+jwt`) KeyBinding/actor-binding girdisi, WPT (`application/wpt+jwt`) taşıma kanıtıdır; WIT `cnf`'i Instance KeyBinding olabilir. _Kaynak:_ §11.12.2, §11.21.1 #32, §11.21.3. _Durum:_ WATCH (talep üzerine).
- [ ] **Bulut iş yükü federasyonu (AWS/GCP OIDC → `jwt-bearer`)** — Bulut iş yükü OIDC token'ı actor-binding Claim'i olarak kabul edilir; authority vermez. _Kaynak:_ §11.21.1 #35; AG-30, L25. _Durum:_ belirtilmemiş (ADOPT).
- [ ] **Hiyerarşik iş yükü tanımlayıcıları (`spiffe://`, `wimse://`)** — Claim ve Grant selector'ı olarak kullanılabilir; joker kalıp yetki vermez. _Kaynak:_ §11.9.2, §11.12.1, §11.21.1 #15. _Durum:_ belirtilmemiş (ADOPT).

### K02 Kimlik protokolleri ve federasyon

#### Issuer, discovery ve anahtar yayını

- [ ] **AS metadata ajan alanları** — `identity_chaining_requested_token_types_supported`, `authorization_grant_profiles_supported`, genişletilmiş `grant_types_supported`, `entity_profiles_supported` (opsiyonel), CIBA ve `authorization_challenge_endpoint` alanları. _Kaynak:_ §11.21.5. _Durum:_ belirtilmemiş.

#### Grant tipleri ve temel akışlar

- [ ] **`requested_token_type` değerleri** — `access_token`, `id_token`, `refresh_token`, `jwt`, `id-jag`, `txn_token`. _Kaynak:_ §11.21.2. _Durum:_ belirtilmemiş.

#### Token exchange ve delegasyon

- [ ] **RFC 8693 Token Exchange** — Token exchange yeni bir karardır, `projection.issue` Exercise Request'idir; downscoping zorunludur, daha geniş token üretemez. Subject token: access/ID token/JWT/SAML2 (Acceptance'lı issuer); requested: access token ya da ID-JAG; ayrıştırıcı ≥ 4 seviye iç içe `act` destekler. _Kaynak:_ §2.2.1; §9.4 A, §9.9, §9.9.4; §10.4.4; §11.10.2, §11.21.1 #8, §11.21.2; CMP-15.1; CR-52; F13; L22; T42 madde 1. _Durum:_ belirtilmemiş (PROFILE); CMP-15.1/T42'ye göre yol haritası (OAuth 2.1/OIDC temelinden sonra).
- [ ] **Token Exchange: `act` / `may_act`** — Exchange edilmiş token ve `act`/`may_act` taşıyıcıları projection ve ipucudur, lineage Access'tedir; yalnız Grant AgencyTerms ile verilir. Basis'i geçersizleşince lineage kaskadıyla prospektif olarak geçersizleşir. _Kaynak:_ §5.6, §5.11; §10.4.4; C12; INV-5; PI-10. _Durum:_ belirtilmemiş.
- [ ] **Token Exchange: cross-domain / cross-realm** — Hedef domain kaynak issuer için `actor-binding` Acceptance'a sahip olmalı; sonuç hedef domain Grant'ından türer. _Kaynak:_ §10.4.4. _Durum:_ belirtilmemiş.
- [ ] **Token takasında kiracı kısıtı** — Token exchange'de tenant kısıtı uygulanır (CVE-2026-18215 sınıfı). _Kaynak:_ §12.1.3 kural 11. _Durum:_ belirtilmemiş.
- [ ] **Identity & Authorization Chaining (taşıyıcı)** — `identity-chaining-17` ile alanlar arası kimlik taşıma; lineage'ı korumaz, Access proof'u ayrıca taşınır, authority §9.15A'dan gelir. _Kaynak:_ §9.4 E, §9.4.2; §11.11.6, §11.20. _Durum:_ belirtilmemiş (PROFILE §9.4; ADOPT §11.11.6).
- [ ] **Transaction Tokens (Txn-Token) profili** — Domain içi / PEP'ler arası call chain bağlamını audit-only taşır, basis değildir; `tctx` içine ExerciseID/intent digest konabilir. RFC olunca normatif olur. _Kaynak:_ §9.4 E, §9.9.2; §11.12.3, §11.21.1 #23; AG-30. _Durum:_ belirtilmemiş (PROFILE, informative); `tctx` kısmı PD.
- [ ] **Ajan delegasyon zinciri taslakları (`delegation_chain`)** — Taslaklar izlenir; `delegation_chain` yalnız PROFILE seçeneğidir, kanonik zincir Access lineage kaydıdır. _Kaynak:_ §9.4.2. _Durum:_ WATCH (talep üzerine).
- [ ] **AuthZEN token değişimi bağlaması** — `draft-gazitt-oauth-authzen-token-exchange-01` izlenir. _Kaynak:_ §9.4.2. _Durum:_ WATCH (talep üzerine).

#### Yetkilendirme isteği ve token uzantıları

- [ ] **MCP kanonik URI kuralları** — Geçerli/geçersiz kanonik URI biçimleri; küçük harf şema/host; sonlandırıcı eğik çizgisiz tercih. _Kaynak:_ §11.4.3. _Durum:_ belirtilmemiş.

#### İstemci kaydı ve istemci kimliği

- [ ] **DCR (RFC 7591/7592) geriye uyumluluk profili** — Yalnız legacy; varsayılan kapalı, initial access token ile. Hız sınırı, kayıt üst sınırı, TTL temizliği, wildcard redirect reddi, issuer damgalı kimlik bilgisi, `application_type` onurlandırma, politika sıkılaşınca geriye dönük geçersiz kılma. _Kaynak:_ §9.4.2; §10.1.2, §10.4.6; §11.4.5 #31–35, §11.21.1 #7; AS-A1; CMP-15.1. _Durum:_ belirtilmemiş (PROFILE; varsayılan kapalı).
- [ ] **CIMD (Client ID Metadata Document) -02 desteği** — URL'nin istemci kimliği olduğu kayıt; `-02` implemente, `-00` uyumluluğu belgelenir. CIMD `client_id` actor değildir; varsayılan kapalı, realm başına. _Kaynak:_ §2.2.1; §4.3; §9.4.2; §10.1.2, §10.4.6; §11.3, §11.3.1; AG-3; AS-S1. _Durum:_ PD (§11.3); belirtilmemiş (ADOPT, varsayılan kapalı).
- [ ] **CIMD: `client_id_metadata_document_supported` yorumu** — Alanın yokluğu "desteklenmiyor" olarak yorumlanır. _Kaynak:_ §11.3.3; AG-3. _Durum:_ PD.
- [ ] **CIMD: Client Identifier URL kuralları** — https zorunlu, path zorunlu, userinfo/fragment/`.`/`..` yasak, basit string karşılaştırması, `localhost` client_id olamaz. _Kaynak:_ §11.3.2, §11.4.5 #10. _Durum:_ belirtilmemiş.
- [ ] **CIMD: doküman şeması doğrulaması** — `client_id` eşleşmesi, `redirect_uris` (yönlendirmesiz grant'lar muaf), MCP ek şartı `client_name`; geçerli JSON. _Kaynak:_ §11.3.3; AS-M11, AS-M13. _Durum:_ belirtilmemiş.
- [ ] **CIMD: AS doğrulama sırası** — 200 kontrolü, yönlendirme takip etmeme, `client_id` = URL = getirilen URL, `redirect_uri` tam eşleşme. _Kaynak:_ §11.3.4; AS-M11/M12. _Durum:_ belirtilmemiş.
- [ ] **CIMD: getirme başarısızlığında istek iptali (fail-closed)** — Taslaktaki SHOULD, Access'te MUST. _Kaynak:_ §11.3.4; AG-4. _Durum:_ PD.
- [ ] **CIMD: getirme parametreleri yapılandırılabilir** — HTTP metodu, Accept, TLS, zaman aşımı, hız sınırı, User-Agent identity plane'in beyanlı parametreleridir. _Kaynak:_ §11.3.4, §11.4.5 #11. _Durum:_ EA.
- [ ] **CIMD: önbellekleme** — HTTP cache başlıklarına saygı; hata/bozuk doküman önbelleklenmez; üst/alt TTL sınırları identity plane config'i. _Kaynak:_ §11.3.5, §11.4.5 #15; AS-S5. _Durum:_ belirtilmemiş.
- [ ] **CIMD: `logo_uri` önceden getirme ve sunucu tarafı önbellek** — _Kaynak:_ §11.3.5, §11.4.5 #16. _Durum:_ belirtilmemiş.
- [ ] **CIMD: doküman hash anlık görüntüsü ve değişiklikte yeniden onay** — Authority-etkili alanlar (`redirect_uris`, `token_endpoint_auth_method`, `scope`, `grant_types`, `jwks`) değişince onay kayıtları geçersizleşir ve AAS'li yeniden onay istenir; Grant revoke edilmez. _Kaynak:_ §11.3.6, §11.4.5 #17; AG-5. _Durum:_ PD.
- [ ] **CIMD: alan adı el değiştirmesi = yeni istemci** — Eski istemcinin onay kayıtları iptal, introspection `active=false`, etkilenen Instance'larda `session_epoch` artışı hızlandırıcı. _Kaynak:_ §11.3.6; AG-5. _Durum:_ PD.
- [ ] **CIMD: `application_type` okunması** — AS `application_type`'ı CIMD dokümanından da okur (yalnız DCR değil). _Kaynak:_ §11.3.9, §11.4.5 #8. _Durum:_ belirtilmemiş.
- [ ] **CIMD: alan adı tabanlı güven politikası** — CIMD kabulü için alan adı politikası; identity plane config'i (MD-14 commit'i). _Kaynak:_ §11.3, §11.4.5 #18; AS-A2. _Durum:_ belirtilmemiş.
- [ ] **İstemci kayıt yolu öncelik sırası** — Ön kayıt → CIMD → DCR yedek → kullanıcıya sor (istemci tarafı); AS tarafı `client_id` çözümleme sırası ayrıca tanımlıdır. _Kaynak:_ §9.13.8 k.3; §11.3.8; IDP-1. _Durum:_ belirtilmemiş.
- [ ] **Tek istemci resolver (yerel/DCR/CIMD/OIDF) ve `trust_level` alanı** — URL `client_id` önce OIDF sonra CIMD ile çözülür, asla yerel kayda düşmez; `trust_level` politika girdisidir. _Kaynak:_ §10.1.2; IDI-10; IDP-1. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **Uzak belge getirme SSRF korumalı ve önbellekli** — _Kaynak:_ §10.1.2, §10.7.1. _Durum:_ belirtilmemiş.
- [ ] **Attestation-Based Client Authentication** — RFC olunca normatif profil olur; DPoP birleşik modu desteklenir (Client Instance Key = DPoP Key). _Kaynak:_ §9.4 D. _Durum:_ belirtilmemiş (PROFILE).
- [ ] **SPIFFE ile OAuth istemci kimlik doğrulaması** — `draft-ietf-oauth-spiffe-client-auth-02` identity plane istemci kimlik doğrulaması olarak profillenir; sonucu `identity-binding.workload` Claim'idir. _Kaynak:_ §9.4.2. _Durum:_ belirtilmemiş (PROFILE, RFC olunca normatif).

#### MCP, ID-JAG ve ajan protokolleri

- [ ] **MCP Authorization Server (OAuth 2.1 AS profili) ve ajan kimliği** — Identity plane AS'nin MCP profili; confidential ve public istemciler için OAuth 2.1, her token issuance `projection.issue`'dur. Tam IdP kapsamında MCP ve ajan kimliği. _Kaynak:_ §11.0, §11.4; §18.2; AG-1; AS-M1; F21. _Durum:_ belirtilmemiş (FROZEN plane ataması); Faz 2 (MCP profili, §18.13 çıkarım).
- [ ] **ID-JAG üretimi (IdP AS rolü)** — Access'in ürettiği ID-JAG / Cross App Access, kullanıcının/ajan FOR(P) Instance'ının `projection.issue` kararıyla verilen, authority scope içermeyen bir kimlik iddiası projection'ıdır; authorization grant semantiği reddedilir. `typ: oauth-id-jag+jwt`, ES256 realm JOSE imzası, kısa `exp`, MCP profilinde `resource` zorunlu, SSO kadar sıkı istemci kimlik doğrulaması, `actor_token` gelirse `act` lineage'dan. _Kaynak:_ §2.2.1; §5.13, §7.3; §8.18.5; §9 bölüm notu, §9.3A, §9.13.8 k.2; §10.4.4; §11.11, §11.11.2; AG-27; L27; MD-18; MKT-10; MKT-D1; P48; PI-3. _Durum:_ PD (yetenek, §11.11); parite kalemi.
- [ ] **ID-JAG tüketimi (Resource AS rolü, `jwt-bearer` grant)** — Gelen ID-JAG `actor-binding`/`predicate-input` Claim taşıyıcısıdır (jti, iss, sub, scope… eşlemesi), authorization grant değildir. Beş adım doğrulama (imza/issuer, `typ`, `aud`, istemci sürekliliği, `exp`/`iat`/`jti`); Grant'a dayalı projection üretilir, Grant yoksa `invalid_grant` veya REQUIRE_ACTION. _Kaynak:_ §2.2.1; §9.3A, §9.4 E, §9.13.8 k.2; §11.11.3, §11.21.2; AG-29; L27; MD-18; MKT-10; MKT-D1. _Durum:_ PD (§11.11.3); PROFILE (§9.4 E).
- [ ] **ID-JAG `jti` tek kullanım ve fail-closed replay önbelleği** — `jti` TTL = `exp`; önbellek tazeliği kanıtlanamazsa kabul edilmez; her ID-JAG en fazla bir `projection.issue` girdisi. _Kaynak:_ §11.11.3, §11.11.4; AG-29. _Durum:_ PD.
- [ ] **Uygulamalar arası bağlantı politikası (CrossAppConnection)** — `(requesting_client_id, resource_as_issuer, resource_identifier, allowed_scopes, subject_policy)` Grant şablonu + Acceptance'a derlenir; `subject_mapper` = pairwise PartyRef; değişiklik MD-14 commit'i. _Kaynak:_ §11.11.2; AG-28. _Durum:_ PD.
- [ ] **MCP Enterprise-Managed Authorization (EMA)** — Access identity plane kurumsal SSO IdP AS rolündedir; ID-JAG ile birlikte Claim/assertion taşıyıcısı olarak profillenir, Access authorization grant'ı olarak reddedilir. `audience`/`resource` profil kısıtları; istemci CIMD'yi `client_id` olarak kullanabilir. _Kaynak:_ §9.4 E; §11.11.5. _Durum:_ belirtilmemiş (PROFILE / REJECT).
- [ ] **A2A `securitySchemes`'te identity plane** — `openIdConnectUrl` keşfi, `authorizationCode`, `clientCredentials`, `deviceCode`, RFC 8705 mTLS'e bağlı token. _Kaynak:_ §11.15; AG-34. _Durum:_ PD.
- [ ] **`entity_profiles` / `sub_profile` / `client_profile` arayüzü** — Instance `party-kind`/`agent-kind` Claim'inin projection'ı. _Kaynak:_ §11.17, §11.21.1 #20. _Durum:_ WATCH (talep üzerine) (arayüz hazır).
- [ ] **Upstream token'ın ajana verilmesi (token broker)** — Upstream token release bir Access kararıdır ve Exercise'tır; CT2+ için broker varsayılan PEP'tir; token `exp` ≤ ValidityContract horizon. _Kaynak:_ CMP-15.1 notu; MD-13. _Durum:_ belirtilmemiş.

#### Workload ve cihaz kimliği girdileri

- [ ] **SPIFFE (ID, SVID, Workload API, Federation) girdisi** — SVID, `identity-binding.workload` + KeyBinding Claim'ine eşlenir; SPIFFE federation authority federation değildir. _Kaynak:_ §9.4 D, §9.13; L25. _Durum:_ belirtilmemiş (ADOPT).
- [ ] **IETF WIMSE (WIT/WPT)** — Bilgilendirici olarak profillenir, RFC olunca normatif olur; WIT bearer olarak kullanılamaz, WPT Actor Intent Statement'ın yerine geçmez. _Kaynak:_ §9.4 D, §9.9.3 k.2. _Durum:_ belirtilmemiş (PROFILE, informative).

### K03 Oturum ve token yönetimi

#### Token ömürleri ve ValidityContract

- [ ] **Ajan projection'larında kısa varsayılan horizon** — Ajan exact-intent token'ı intent validity kadar yaşar ve tek kullanımlıktır (`jti`/nonce tüketilir); bounds token varsayılanı ≤ 15 dk, yönetimde üst sınır ≤ 60 dk'dır. Consumption-bearing action bounds token'la yapılamaz. _Kaynak:_ §9.9.3 k.4; §11.9.4; AG-22. _Durum:_ PD (15 dk EA).

#### Token içeriği ve claim'ler

- [ ] **İç içe `act` yalnız lineage kaydından** — `act` gelen `subject_token`/`actor_token`'dan kopyalanmaz, Access lineage kaydından üretilir; böylece splicing yapısal olarak imkânsızdır. _Kaynak:_ §9.9.4; P53. _Durum:_ belirtilmemiş (FROZEN, türetilmiş).
- [ ] **Ayrıştırıcı ≥ 4 seviye iç içe `act` desteği** — _Kaynak:_ §11.10.4; AG-25. _Durum:_ PD.
- [ ] **`may_act` ipucu** — `may_act`, exchange isteyebilecek actor kümesinin ipucudur ve Grant AgencyTerms'ünden türetilir; yetki vermez. _Kaynak:_ §9.9.4; P53. _Durum:_ PD.
- [ ] **`agent_instance_id` interop claim'i** — Opsiyonel `agent_instance_id` interop için desteklenir; InstanceID ValidityContract `holder` alanındadır. _Kaynak:_ §9.4.2, §9.9.4. _Durum:_ belirtilmemiş (arayüz hazır).
- [ ] **Ajan access token hedef şekli** — `sub` (FOR(P) için P'nin pairwise PartyRef'i / OWN için holder), `act` (yalnız lineage'dan), opsiyonel `sub_profile`/`agent_*` ve `delegation_chain`, `scope` etiket, `authorization_details` tek authority yeri, `cnf` zorunlu, `txn` opsiyonel, `tenant` yalnız görüntüleme, `client_id` actor değil. _Kaynak:_ §11.21.4. _Durum:_ belirtilmemiş.

#### Token vault

- [ ] **Token vault: "Connected account for agents"** — Upstream bağlantı S2/S11'de, hangi delegation'la hangi agent tarafından kullanıldığıyla gösterilir; "agent has your token" denmez. _Kaynak:_ §8.8, §8.9. _Durum:_ belirtilmemiş.
- [ ] **Token vault release = Access kararı** — Ajanın upstream token istemesi Exercise'a bağlı bir release kararıdır; `exp` ≤ ValidityContract horizon'dur. CT2+ sınıflarda varsayılan broker-as-PEP'tir. _Kaynak:_ §8.18.5; E36, MD-13. _Durum:_ belirtilmemiş (broker-as-PEP varsayılan).

### K06 Giriş deneyimi, UI bileşenleri ve markalama

#### Özel amaçlı bileşenler

- [ ] **Ajan bağlantıları bileşeni** — Hangi ajanın hangi bağlı hesabı kullandığını gösterir, tek tıkla iptal. _Kaynak:_ §12.4.1; TN-133. _Durum:_ gün-1.

#### Deneyim invariant'ları

- [ ] **Agent'lar agent olarak gösterilir (agent rozeti)** — "AI agent · acting for *X* · operated by *Y*"; tür, capacity ve operatör görünür; "Human" rozeti agent'a verilmez. _Kaynak:_ §6.4; §8.10; A-12; XI-17. _Durum:_ belirtilmemiş.

#### Dürüst durum metinleri

- [ ] **Agent durum gösterimi** — "Authority revoked. Agent: running / paused (confirmed) / unknown". _Kaynak:_ §13.8. _Durum:_ belirtilmemiş.

#### Offline ve uzun süren iş gösterimi

- [ ] **Uzun süren agent işi göstergesi** — "Authority re-checked every 15 min; next check by 14:30". _Kaynak:_ §8.17.5.8. _Durum:_ belirtilmemiş.

#### End-customer ve merchant deneyimi

- [ ] **Agent prose ≠ effect gerçeği** — Müşteriye güvenilir gerçek yalnız canonical kayıt render eden yüzeyden gelir. _Kaynak:_ §8.17.5.11; X30. _Durum:_ belirtilmemiş.

#### Onay ve consent ekranları

- [ ] **MCP/CIMD onay ekranı = Approval Surface** — CIMD istemcileri için varsayılan onay ekranı; Grant AAS ile oluşur. _Kaynak:_ §11.4.5 #5, §11.6. _Durum:_ belirtilmemiş.
- [ ] **Onay ekranında redirect/`client_id` hostname'inin gösterimi** — _Kaynak:_ §11.3.6 (§8.5), §11.4.5 #9; AS-M14. _Durum:_ belirtilmemiş.
- [ ] **Yalnız loopback yönlendirmeli istemciye ek uyarı** — Sessiz onay yok; SHOULD → MUST. _Kaynak:_ §11.3.9; §11.4.5 #9; AG-6; AS-S8. _Durum:_ PD.
- [ ] **`client_name`/`logo_uri` authority-opaque gösterim** — İstemci beyanı olarak gösterilir. _Kaynak:_ §11.3. _Durum:_ belirtilmemiş.
- [ ] **CIMD görsel alan değişikliği uyarısı** — `client_name`/`logo_uri` değişince yalnız ekranda uyarı. _Kaynak:_ §11.3.6; AG-5. _Durum:_ PD.
- [ ] **Sunucu tarafı OAuth/MCP consent kaydı (tekrar sormayı engelleme)** — `(user_id, client_id, resource, scopes, source, metadata_hash, grant_ref)` identity plane'de UI kaydı olarak tutulur, authority değildir; her upstream yönlendirmesinden önce `grant_ref` geçerliliği kontrol edilir, Grant revoke/lapse olunca onay yeniden istenir. _Kaynak:_ §9.14.5 k.3; §11.4.5 #26, §11.6 kural 1; P58. _Durum:_ PD (kayıt alanları).
- [ ] **İnsan gerektiren requirement'ta "This must be done by you" yolu** — `not-satisfiable-by-actor` durumunda coordinator principal onayına ya da principal'ın kendi Instance'ından yapılmasına yönlendirir; yol requirement'tan okunur. _Kaynak:_ §11.16.3. _Durum:_ belirtilmemiş.

### K07 Yetki modeli

#### Roller, gruplar ve rule-shaped seçim

- [ ] **Rule-shaped Grant selector olarak iş yükü URI'si** — _Kaynak:_ §11.9.2, §11.12.1. _Durum:_ belirtilmemiş

#### Requirement'lar, onay ve quorum

- [ ] **Runtime attestation requirement'ı** — `attestation.runtime` Claim'i Instance/KeyBinding'e bağlıdır. _Kaynak:_ §5.9. _Durum:_ belirtilmemiş

#### Ajan yetkisi

- [ ] **Ajan = Party altında Instance** — Ajana özgü authority primitive yoktur; authority yalnız Grant'tan, capacity basis Grant'ın AgencyTerms'ünden gelir. Mandate yalnız daraltır ve yalnız holder Party'nin kendi Instance'ına bağlanır; başkasının Instance'ına `mandate.bind` protocol rejection'dır. _Kaynak:_ §11.9.1; AG-19, F15. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Ajan Grant şablonu farkları** — Zorunlu budget, delegasyon derinliği ≤ 1, `downstreamHolderClass` = aynı operatörün ajanları, eşik-bitişik tekrar ve mass-selection guard'ları. _Kaynak:_ §11.9.1, §11.10.4. _Durum:_ PD (guard'lar POLICY DEFAULT)

### K08 Karar, uygulama ve doğrulama

#### Türetilmiş indeks, arama ve okuma tutarlılığı

- [ ] **Agent'ın kendi durum özeti** — `check` + kendi Instance summary döner; principal'ın diğer delegation'larını göstermez. _Kaynak:_ §9.7. _Durum:_ belirtilmemiş.

#### PEP uygulaması ve SDK

- [ ] **Executor re-check noktaları, checkpoint ve stop teyidi** — Envelope dışı effect, horizon/checkpoint, pause/takeover/recovery sonrası ve semantic event alındığında Executor Access'e yeniden sorar; continuation'da sorar ve control capability ile stop teyidi verir. _Kaynak:_ §7.9.7.2; §13.4 U5; E31. _Durum:_ belirtilmemiş.
- [ ] **Effect attestation, outcome state ve post-hoc conformance** — Attestation ExerciseID'ye bağlı Claim'dir; attest edilen outcome envelope'a karşı doğrulanır. Durum unattested, attested-conforming veya attested-nonconforming olur; "unknown" first-class sonuç değeridir. SDK desteklenir; Activity'de "Reported done / not done / Result unknown / Differs from allowed" reporter adıyla gösterilir. _Kaynak:_ §2.6; §2.7 Executor; §5.4; §7.9.7.2; §8.5 S6, §8.7, §8.8; §8.17.10.3; INV-18. _Durum:_ belirtilmemiş.
- [ ] **Outside authority sınıflandırması** — Yalnız pencere sonrası, envelope dışı veya hiçbir Exercise'a bağlanamayan effect için. _Kaynak:_ §8.10, §8.17.5.5; INV-19. _Durum:_ belirtilmemiş.

#### MCP Resource Server profili

- [ ] **MCP ontology eşlemesi** — client = Instance, tool = ActionRef, `tools/call` = Exercise/exact-intent, liste = DERIVED disclosure, token = projection, elicitation ≠ approval, handle ≠ protocol nesnesi. _Kaynak:_ §11.2; AG-2. _Durum:_ belirtilmemiş (FROZEN semantik), wire PD.
- [ ] **MCP Resource Server: Decision PEP / Verifier conformance profili** — MCP sunucusu domain'in PEP'idir; Access profil ve referans PEP SDK sunar. _Kaynak:_ §11.5; AG-1. _Durum:_ belirtilmemiş.
- [ ] **MCP/OAuth RS conformance beyanı** — RS davranış yükümlülükleri Verifier Profile'da conformance beyanı olarak yer alır. _Kaynak:_ §9.12.4. _Durum:_ belirtilmemiş.
- [ ] **RS MUST listesi (RS-M1…RS-M19)** — PRM, token doğrulama (+`cnf`, horizon, introspection), audience, 401, passthrough yasağı, isteği işlemeden önce doğrulama, scope hiyerarşisi, header/body uyuşmazlığı, Origin, `cacheScope` kuralları, bağlam çıkarmama. _Kaynak:_ §11.5.1. _Durum:_ belirtilmemiş.
- [ ] **RS davranış listesi (27 madde)** — `POST /mcp`, PRM endpoint, GET/DELETE → 405, 401 + `WWW-Authenticate`, DPoP challenge, JWKS imza doğrulama, `exp`/`nbf` + horizon, CR/LF yasağı, `Mcp-Param-*` sır yasağı, metadata < 5 s, SSE `X-Accel-Buffering: no`, yerelde yalnız 127.0.0.1. _Kaynak:_ §11.5.6. _Durum:_ belirtilmemiş.
- [ ] **Protected Resource Metadata (RFC 9728) yayını** — `resource`, `authorization_servers` (MUST), minimal `scopes_supported`, `bearer_methods_supported: ["header"]`, `authorization_details_types_supported`, `signed_metadata`, BCP 47 çoğullama, well-known URI kuralları. _Kaynak:_ §11.5.2, §11.5.6. _Durum:_ belirtilmemiş (ADOPT).
- [ ] **PRM = PEP yapılandırması** — MD-14 config'i; Claim kaynağı/authority belgesi değil; Domain Metadata'yla karışmaz. _Kaynak:_ §11.5.2; AG-10. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Access PEP profili: `dpop_bound_access_tokens_required: true`** — veya mTLS bağlı token; DPoP algoritmaları ilan edilir. _Kaynak:_ §11.5.2, §11.5.6; AG-9. _Durum:_ PD.
- [ ] **Scope challenge motoru** — 401/403 `insufficient_scope` + `scope` + `resource_metadata`; tek challenge'da tüm scope'lar; `offline_access` challenge'a konmaz; REQUIRE_ACTION ayrımı. _Kaynak:_ §11.5.1 SHOULD, §11.5.6 #7–9, §11.21.1 #14. _Durum:_ belirtilmemiş (ADOPT).
- [ ] **Stateless MCP çekirdeği uyumu** — Her POST bağımsız karar birimi; continuation ADP'de (horizon, `continue`); `clientInfo`/`clientCapabilities`/`serverInfo` asla Claim/karar girdisi değil; `Mcp-Session-Id` yok sayılır. _Kaynak:_ §11.5.3; AG-11. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **`tools/call` her seferinde kendi kararı** — Scope etikettir; liste/önbellek yetki değildir; ALLOW envelope'a bağlı (INV-19). _Kaynak:_ §11.2, §11.5.4, §11.7 CVE tablosu. _Durum:_ belirtilmemiş.
- [ ] **`cacheScope` disclosure kuralı** — Liste viewer-scoped disclosure; `public` yalnız tamamı Public-Grant-türevli ve viewer'dan bağımsız listede; aksi `private`; şüphede `private`; SDK önbellek anahtarı `(Instance, capacity, aud, applied_pos)`; önbellekteki öğe tool çağrısı yetkisi değildir. _Kaynak:_ §11.5.4; AG-12; AGI-5. _Durum:_ PD.
- [ ] **Garanti: `cacheScope` yanlış etiketlemesiyle çapraz kiracı ifşası önleme** — Access PEP SDK'lı conformant PEP'te UDC; kendi kodunda NG. _Kaynak:_ §11.5.4 (§13 adayı); AG-12. _Durum:_ PD.
- [ ] **State handle ve `requestState` kuralları** — Authority taşımaz; HMAC/AEAD, kısa TTL, tek kullanım, `(actor Instance, capacity, aud, intent digest)`'e bağlı; handle `<instance_id>` bağlı, CSPRNG; REQUIRE_ACTION'da yalnız nonce referansı. _Kaynak:_ §11.5.5; AG-13; AGI-6. _Durum:_ PD.
- [ ] **MRTR ile yeniden POST yeni karar ister** — ALLOW devralınmaz; elicitation cevabı approval değildir. _Kaynak:_ §11.5.5. _Durum:_ PD.
- [ ] **`server/discover` varsayılan yetkilendirme** — Kimlik doğrulamasız yoklama yalnız Public Grant + token-bağımsız sonuçla (`public`). _Kaynak:_ §11.5.7; AG-14. _Durum:_ PD.
- [ ] **`subscriptions/listen` = long-running exercise** — Açılış ADP kararı; `min(token exp, horizon)`'da kapanış; aynı stream'de token yenileme yok; checkpoint'te `continue`, DENY'da anında kapanış; SSF/Access event'inde yeniden sorma. _Kaynak:_ §11.5.7; A-8; AG-15. _Durum:_ PD.
- [ ] **Garanti: `subscriptions/listen` horizon sonrası olay taşımaz** — UDC (SDK'lı conformant PEP), NG (kendi kodu). _Kaynak:_ §11.5.7; AG-15. _Durum:_ PD.
- [ ] **Upstream için ayrı projection (RS passthrough yok)** — RS istemci token'ını upstream'e geçirmez. _Kaynak:_ §11.5.6 #10; RS-M8, RS-M10. _Durum:_ belirtilmemiş.
- [ ] **`delegation_chain` claim'i (PROFILE seçeneği)** — İmzalı lineage excerpt'i (MD-3, P51); çevrimdışı doğrulama PAP ile. _Kaynak:_ §11.10.4, §11.21.1 #18; AG-24. _Durum:_ PD.

#### Bağlantı profilleri ve ValidityContract varyantları

- [ ] **Local agent offline: `revalidate-on-reconnect` bounds token** — _Kaynak:_ §11.19. _Durum:_ belirtilmemiş.

#### Ürün kapsamı ve yol haritası

- [ ] **Agent delegation wedge: bütçeli, süreli, geri alınabilir yetki + REQUIRE_ACTION + revoke** — _Kaynak:_ §18.8.1 H6, §18.13. _Durum:_ Faz 2 (§18.13 çıkarım).

### K09 Ajanlar ve MCP

#### Ajan kimliği ve modeli

- [ ] **Ajan = actor-capable Party + Instance (birinci sınıf)** — Ajan users tablosunun varyantı değil, kendi Party + Instance kaydı olan birinci sınıf aktördür; Instance, Mandate ve capacity kurallarına tabidir, ayrı bir security universe değildir. _Kaynak:_ I2; §2.2.3, §5.17, §6.10, §7.9.6.1; AGI-n, F15, F18. _Durum:_ belirtilmemiş
- [ ] **Ajan oluşturma** — Regime inception, `operated-by` / `agent-kind` Claim'leri, `party.register` + self-anchor (root = org) ve çalışınca `instance.create`. _Kaynak:_ §7.9.13 satır 2. _Durum:_ belirtilmemiş
- [ ] **Ajan Party Claim'leri (`operated-by`, `agent-kind`, `sponsored-by`)** — _Kaynak:_ §10.1.5 (→ §11). _Durum:_ belirtilmemiş
- [ ] **Ajan kimlik kaydı: `IdentitySubject`** — Identity plane iç kaydı; authority plane'e yalnız Claim olarak çıkar (`party-kind=agent`, `agent-kind = cloud|local|enterprise|robot`, InstanceID, operatör/sponsor ilişkileri). _Kaynak:_ §11.9.2; AG-20. _Durum:_ PD
- [ ] **`AgentIdentity` alanlarının Access eşlemesi** — WorkloadUri, blueprint → şablon, owner/sponsor → ilişki Claim'leri (`operated-by`, `sponsored-by`), tenant → AuthorityDomain, status → Instance lifecycle, trusted issuers → Acceptance, `default_token_ttl` → horizon şablonu. _Kaynak:_ §11.9.2; AG-20. _Durum:_ PD
- [ ] **Ajan ölçek seviyeleri: blueprint / Instance / Exercise** — Audit ve iptal birimi Instance; replika başına Instance zorunlu değil (aynı KeyBinding = tek Instance); görev başına Instance önerilir. _Kaynak:_ §11.9.3; AG-21. _Durum:_ PD
- [ ] **Ajan = Instance, otonom ajanın `sub`'ı** — Otonom ajanda `sub` ajandır ve `act` yoktur; operatör Party'sinin ajanında ayrım InstanceID ile yapılır. _Kaynak:_ §9.9.4. _Durum:_ PD
- [ ] **InstanceID ≠ KeyBinding ≠ Attestation ayrımı** — Instance'ın mantıksal kimliği, güncel anahtar bağlaması (DPoP/mTLS/WIT cnf) ve runtime attestation ayrı tutulur; attestation yalnız Claim'dir. _Kaynak:_ L21. _Durum:_ belirtilmemiş
- [ ] **Agent gerçek dünya kimliği / runtime config** — Identity Binding / attestation ile. _Kaynak:_ §13.4 U20. _Durum:_ belirtilmemiş
- [ ] **Platform issuer için `actor-binding` Acceptance (ajanlar ilk sunumda Instance)** — Grant yine ayrıca gerekir. _Kaynak:_ §11.21.1 (carleton notu). _Durum:_ belirtilmemiş

#### Ajan yetki sınırları ve delegasyon

- [ ] **Agent sınırları (Grant ∩ Mandate ∩ budget)** — Agent yalnız kendi Instance'ı ve Mandate'i içinde exercise eder; kullanıcının Instance'ı olmadan Grant/genişletme/approval yapamaz; Mandate revoke, instance.terminate, suspend ile durdurulur. Prompt-injection savunması Access dışındadır, ama instruction-provenance ne olursa olsun ajan Grant ∩ Mandate dışına çıkamaz. _Kaynak:_ §2.5, §13.2; RR-12. _Durum:_ belirtilmemiş
- [ ] **Agent delegation zinciri sınırı (depth ≤ 1)** — Agent'a delegable Grant şablonu: depth ≤ 1, `downstreamHolderClass` = aynı operatörün agent'ları. _Kaynak:_ §9.4 A, §9.9.4, §13.7.6; C15. _Durum:_ PD
- [ ] **Agent budget template zorunlulukları** — Consumption-bearing her agent Grant'ı: per-intent cap + günlük window BudgetTerm + count/window. _Kaynak:_ §13.7.6; X10. _Durum:_ PD
- [ ] **Agent alt delegation görünürlüğü** — "Agent A passed part of this to Sub-agent B: ≤ 1,000 TRY". _Kaynak:_ §8.17.7.1. _Durum:_ belirtilmemiş
- [ ] **Personal-delegate issuer varsayılanı** — Inference-üreten issuer Claim'leri varsayılan olarak yalnız narrowing use'larda kabul edilir. _Kaynak:_ §7.9.6.2; E23. _Durum:_ belirtilmemiş
- [ ] **Trust/risk skoru yalnız Claim, yalnız daraltır** — Hiçbir skor (ör. `agent_trust_score`) Grant/Acceptance ikame etmez veya onay atlatmaz. _Kaynak:_ §9.4.2, §11.17; AG-36, AGI-7, CI-2. _Durum:_ PD
- [ ] **Executor seam** — Executor runtime operatörü actor değildir; continuation'ı actor Instance'ı ister. _Kaynak:_ §7.9.7. _Durum:_ belirtilmemiş

#### Ajan sözleşmesi (A-1…A-12)

- [ ] **A-1 Basis ve capacity açık beyanı** — FOR(P) veya OWN; SDK capacity'siz istek kurmaz; commit modunda eksikse protocol hatası. _Kaynak:_ §8.18.2, §8.18.5. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **A-2 ALLOW envelope'a bağlı** — Parametre değişirse yeni istek. _Kaynak:_ §8.18.2. _Durum:_ belirtilmemiş
- [ ] **A-3 DENY nonce için terminal** — Döngüsel yeniden deneme yok. _Kaynak:_ §8.18.2; C30. _Durum:_ belirtilmemiş
- [ ] **A-4 REQUIRE_ACTION ≠ DENY** — Aynı nonce proof eklenince yeniden değerlendirilir. _Kaynak:_ §8.18.2. _Durum:_ belirtilmemiş
- [ ] **A-5 Prose approval değildir** — Sohbetteki "evet" veya sohbet cevabı approval/contribution sayılmaz; onay user'ın kendi Instance'ından exact digest'e bağlı contribution olmalıdır. MCP consent/elicitation da approval değildir. _Kaynak:_ §7.9.6.3, §8.18.2, §8.18.5. _Durum:_ belirtilmemiş
- [ ] **A-6 Agent canonical özeti yazmaz** — Not "Requester's note" olarak ayrı. _Kaynak:_ §8.17.6.2, §8.18.2. _Durum:_ belirtilmemiş
- [ ] **A-7 Veri/açıklama asla talimat değildir** — Access cevapları, açıklamaları, reason/remediation kodları ve event'leri agent için typed planlama verisidir. MCP tool description authority-opaque'tır; MCP server kimliği tool doğruluğu anlamına gelmez. _Kaynak:_ §6.6, §7.6, §8.18.2, §8.18.5, §9.4.1; A-7, E-7, SI-16. _Durum:_ belirtilmemiş
- [ ] **A-8 Long-running iş continuation ister** — Horizon öncesi, checkpoint'lerde, pause/takeover sonrası. _Kaynak:_ §8.18.2. _Durum:_ belirtilmemiş
- [ ] **A-9 Bölme (structuring) yolu yok** — Lineage budget + RestrictionPolicy kümülatif kurallar. _Kaynak:_ §8.18.2. _Durum:_ belirtilmemiş
- [ ] **A-10 Advisory cache'lenip credential gibi kullanılmaz** — _Kaynak:_ §8.18.2, §8.18.5. _Durum:_ belirtilmemiş
- [ ] **A-11 Agent kendi durumunu sorabilir** — Kendi Instance'ının exercisable özeti, kalan budget, horizon (advisory). _Kaynak:_ §8.18.2. _Durum:_ belirtilmemiş
- [ ] **A-12 Agent kendini agent olarak tanıtır** — Rozet, principal ve operatör görünür. _Kaynak:_ §8.18.2; XI-17. _Durum:_ belirtilmemiş
- [ ] **Ajan sözleşmesi normlarının MCP/OAuth uygulanışı** — A-1 (capacity'siz `tools/call` kurulamaz), A-7 (tool açıklaması, discover sonucu, `resource_name`, `client_name`, Agent Card, RAR `locations`, hata gövdeleri instruction değil), A-8 (AG-15), A-10 (liste/önbellek yetki değil), A-12 (AB YZ Yasası m. 50 ifşası). _Kaynak:_ §11.16.2; AG-37, MD-19. _Durum:_ belirtilmemiş (FROZEN)

#### İnsan döngüsü (HITL) ve onay

- [ ] **Çalıştırma ortasında insan onayı: tek soyutlama = REQUIRE_ACTION nonce'u** — Ayrı "pending authorization" nesnesi yok; onay Approval Surface + AAS, `target` = intent digest, WYSIWYS; yüzey token/kodu onay kanıtı değildir. _Kaynak:_ §11.14.2; AG-33, AGI-8, P54. _Durum:_ belirtilmemiş (FROZEN soyutlama)
- [ ] **Agent davranışı: JIT authority request** — DENY/REQUIRE sonrası typed intent + structured reason coordinator'a; REQUIRE'da aynı nonce, DENY'da yeni nonce. _Kaynak:_ §8.17.5.2. _Durum:_ belirtilmemiş
- [ ] **İnsan varlığı gerektiren requirement ajan tarafından karşılanamaz** — `REQUIRE_ACTION` + `not-satisfiable-by-actor`; coordinator bunu principal onayına veya "This must be done by you" yoluna çevirir; hiçbir yüzeyde `interaction_required`'a çevrilmez. _Kaynak:_ §8.18.3, §11.16.3; AGI-4. _Durum:_ belirtilmemiş
- [ ] **Agent ↔ coordinator ↔ insan zinciri** — Access yalnız karar ve insan eyleminin kaydı noktalarında konuşur; yönlendirme/hatırlatma coordinator'ındır. _Kaynak:_ §8.18.4, §11.16.4; X5. _Durum:_ belirtilmemiş
- [ ] **Üç bağlama modeli akış olarak** — Sahip önceden imzalı (FOR(sahip) Grant / `mandate.bind` / `local_requirements`), sahip aracılı ağ geçidi (Coordinator → Approval Surface → AAS), sunucu aracılı challenge-response (REQUIRE_ACTION + CIBA + AAS). _Kaynak:_ §11.14.3, §11.21.1 #31. _Durum:_ belirtilmemiş
- [ ] **HITL yüzeyi: `interaction_required` / `interaction_uri`** — Approval Surface adresi, aynı nonce + contribution ile `commit`. _Kaynak:_ §11.14.2. _Durum:_ WATCH (talep üzerine); eşleme PD
- [ ] **HITL yüzeyi: deferred token response (`deferral_code`)** — `exercise_ref` taşıyıcısı, actor KeyBinding'e kısıtlı. _Kaynak:_ §11.14.2. _Durum:_ WATCH (talep üzerine)
- [ ] **HITL yüzeyi: txn-challenge** — RS challenge = REQUIRE_ACTION taşıyıcısı; sonuç exact-intent projection. _Kaynak:_ §11.14.2. _Durum:_ WATCH (talep üzerine)
- [ ] **HITL yüzeyi: AuthZEN AARP (`/access-requests`)** — Görev tutamağı = `exercise_ref`; DENY nonce terminal. _Kaynak:_ §11.14.2, §11.21.2. _Durum:_ WATCH (talep üzerine)

#### One (asistan) ve kullanıcı deneyimi

- [ ] **One: ayrıcalıksız, sınırlı agent** — One yalnız user'ın Grant'ı ∩ Mandate içinde exercise eder; kendine Grant veremez; intent'i yalnız hazırlar (taslak), tetiklemez. Listede diğer agent'larla aynı biçimde görünür. _Kaynak:_ §7.9.6, §8.17.5.1, §8.17.7.1; E23, E24. _Durum:_ belirtilmemiş
- [ ] **Agent "Stop" ortak etkileşimi** — Executor pause isteği + Access suspend/revoke; iki ayrı satır, tek "Stopped" durumu yok. _Kaynak:_ §8.17.7.5; X13. _Durum:_ belirtilmemiş
- [ ] **Tekrar eden onaylardan delegation önerisi** — "You approved 6 similar refunds… Give Agent A access…?"; S1 exact preview, kendiliğinden yürürlüğe girmez. _Kaynak:_ §8.17.11.1; X8, XI-19. _Durum:_ belirtilmemiş

#### Ajan yaşam döngüsü, sorumluluk ve iptal

- [ ] **Zorunlu aktif insan sorumlusu ve otomatik askı** — Her ajan Party'sinin en az bir aktif insan sorumlusu olur; sorumlu ayrılırsa ajanın Mandate ve Instance'ları otomatik askıya alınır; askı/atama Changes'ta görünür. _Kaynak:_ AG-41, IDP-35, SI-21, TN-95, X13. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Ajan kaydı (registry) yüzeyi ve API'si** — Her ajan için sorumlular, yetkiler, bağlı hesaplar, son çalışma, durum; mevcut model üzerinde yüzey. _Kaynak:_ AG-41. _Durum:_ PD (yüzey ayrıntısı)
- [ ] **Ajan kaydı/registry = keşif ve Claim kaynağı** — Registry issuer'ı ancak Acceptance ile; Singapur CSA "trusted registry" kontrolü Party/Instance kaydı + Acceptance'lı registry Claim'i ile. _Kaynak:_ §11.17; AG-36. _Durum:_ PD
- [ ] **MCP / CIMD client ve ajan kaydı** — Ajan kayıtları sayısı fatura birimi değildir. _Kaynak:_ §18.5. _Durum:_ belirtilmemiş
- [ ] **Ajanlar koltuk değildir** — Agent/Instance sayısı fatura birimi değildir; attribution korunur. _Kaynak:_ §18.5; B5. _Durum:_ belirtilmemiş (FROZEN STRATEGY)
- [ ] **Toplu ajan iptali: `POST /agents/{id}/revoke-all`** — Bir ajanın bütün Instance'larının `instance.terminate` kümesidir; endpoint bunun kolaylık yüzeyidir. _Kaynak:_ §9.16.2 k.6, §11.9.3, §11.21.2; P59. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Ajana özgü olaylar** — `instance-terminated`, `mandate-ended`, `authority-narrowed`, `projection-invalidated` (ajan token ailesi); CAEP boşluğunu kapatır. _Kaynak:_ §9.16.2 k.5; P59. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Ajana özgü CAEP olaylarının Access semantic event'lerine eşlenmesi** — `authority-revoked`, `instance-terminated` … outbound CAEP'e yaklaşık eşlenir. _Kaynak:_ §11.20. _Durum:_ belirtilmemiş
- [ ] **Gölge ajan / NHI keşfi aşama 1** — Kayıtsız istemciler, Instance'ı belirsiz token'lar, kullanılmayan bağlantılar ve Grant'lar raporlanır; dış keşif sinyalleri SSF ile (yalnız daraltır). _Kaynak:_ AG-43; E38. _Durum:_ gün-1
- [ ] **Gölge ajan / NHI keşfi aşama 2** — AG-39 bağlayıcılarıyla bağlı servislerde üçüncü taraf uygulama izinleri taranır; kayıtsız ajanlar raporlanır; aksiyon ayrı Exercise. _Kaynak:_ AG-43. _Durum:_ PD (aşama 2 zamanlaması)

#### Ajan token claim'leri ve protokol taşıyıcıları

- [ ] **İmzalı hop başına `delegation_chain` (projection)** — Her ajan hop'unun imzalı delegation zinciri; projection ve ipucudur, lineage kayıtlardadır. _Kaynak:_ §2.2.1; L22. _Durum:_ Faz 3
- [ ] **Delegation Chain Splicing yapısal önleme** — Token exchange çıktısındaki `act` yalnız lineage'dan; gelen token'lar yalnız Claim girdisi. Garanti: iki geçerli token'dan sahte zincir üretilemez (BS). _Kaynak:_ §11.10.2 (§13 adayı); AG-23, AGI-1. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **`sub_profile`** — Ajan alt profil bilgisi taşıyan claim; arayüz hazır. _Kaynak:_ §2.2.1, §9.4.2. _Durum:_ Faz 3 (§2.2.1); WATCH (talep üzerine) (§9.4.2)
- [ ] **`agent_instance_id`** — Ajanın çalışan örneğinin kimliği; InstanceID'nin (pairwise) projection'ı; arayüz hazır. _Kaynak:_ §2.2.1, §9.4.2, §11.9.3, §11.17. _Durum:_ Faz 3 (§2.2.1); WATCH (talep üzerine) (§9.4.2, §11.17)
- [ ] **Ajan claim'leri `agent_platform`, `agent_model`, `agent_runtime`** — InstanceID/Attestation projection'ı; authority girdisi değil. _Kaynak:_ §11.17, §11.21.1 #21, §11.21.4. _Durum:_ WATCH (talep üzerine) (arayüz hazır)
- [ ] **Client instance assertion / ID continuation assertion / token exchange `cnf` taşıyıcıları** — _Kaynak:_ §11.17. _Durum:_ WATCH (talep üzerine)
- [ ] **Attestation tabanlı client auth** — Ajan/client için attestation'a dayalı client kimlik doğrulaması. _Kaynak:_ §2.2.1. _Durum:_ Faz 3
- [ ] **Transaction token** — İşlem bağlamını taşıyan transaction token desteği. _Kaynak:_ §2.2.1. _Durum:_ Faz 3
- [ ] **ID-JAG üretimi (Token Exchange)** — _Kaynak:_ §10.4.4 (→ §11.11). _Durum:_ belirtilmemiş

#### Token vault ve credential broker

- [ ] **Ajan credential broker / token vault** — Upstream OAuth token custody'si identity plane capability'sidir; upstream token'ın ajana verilmesi/kullanılması (release) bir Access kararıdır (Exercise). Agent token'ı kendi yetkisi sayamaz; vault'ta token bulunması yetki değildir. _Kaynak:_ §2.2.1, §2.5, §7.1, §7.6, §8.18.5, §11.13, §12.0.2, §18.2 IS NOT tablosu; AG-32, AG-40, AGI-2, CMP-15.1 notu, E36, L28, MD-13. _Durum:_ Faz 3 (§2.2.1); FROZEN kural, PD tercih (§11.13); PROPOSED FOR FREEZE (§7.1)
- [ ] **Exercise'sız release yok (release kuralı)** — Vault yalnız ALLOW almış geçerli bir Exercise referansına karşı release yapar ve bunu her release yolunda zorlar; release kaydı Access projection'ıdır; possession ≠ authority. _Kaynak:_ §7.9.12.4, §13.4 G59, U66; E36, EI-26. _Durum:_ belirtilmemiş (aday)
- [ ] **Broker-as-PEP modu / upstream token yolu (a)** — CT2+ sınıflarda varsayılan ve zorunlu: broker/yürütücü çağrıyı kendisi yapar ve her çağrıyı intent ⊑ Grant olarak denetler. _Kaynak:_ §7.1, §7.3, §11.13 akış; AG-32, AG-40, E36. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Upstream token yolu (b): kısa ömürlü dar token ajana; `exp` ≤ horizon** — Yalnız CT0–CT1 ve realm/domain açarsa; `cnf`'siz upstream token kısa ömürlü, tek audience'lı, `exp` ≤ ValidityContract horizon; ömür ≤ 1 saat veya upstream iptal adresi; aşarsa/bilgi eksikse teslim reddedilip broker-as-PEP moduna düşülür; mümkünse RFC 8693 ile daraltma. _Kaynak:_ §7.1, §11.13, §13.4 U65; AG-32, AG-40, E36. _Durum:_ PD (1 saat eşiği)
- [ ] **Upstream token içeriği NOT GUARANTEED** — Risk release Exercise'ında beyan edilir. _Kaynak:_ §7.6, §12.0.2; E36. _Durum:_ belirtilmemiş
- [ ] **Sınıflandırılmamış action CT2 sayılır; bilinmeyen upstream yürütücüye gider** — _Kaynak:_ AG-40 (4), (6). _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Token ömrü/iptal bilgisinin otomatik öğrenilmesi** — `expires_in`, upstream `revocation_endpoint` ve AG-39 tanımlarından. _Kaynak:_ AG-40 (5). _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Broker/vault veri modeli (Resource / Connection / TokenSet)** — Connection identity plane config'i (`scope_mapping` authority üretemez); TokenSet kiracı başına DEK ile zarf şifreli. _Kaynak:_ §11.13, §11.21.1 #34. _Durum:_ belirtilmemiş
- [ ] **Federe kimlik bilgisi kasası: otomatik yenileme** — _Kaynak:_ §11.21.1 #34. _Durum:_ belirtilmemiş
- [ ] **LLM kimlik bilgisi izolasyonu** — Ajan modeli hiçbir kimlik bilgisini görmez; upstream token model bağlamına konamaz; Access katkısı `cnf`, kısa ömür/tek audience, runtime beyanı Claim'i. _Kaynak:_ §11.13; AG-40 (7), AGI-3. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **AIMS kuralları** — "LLM ajanın credential'larına erişemez" ve "local UI confirmation alone yetki değildir" kuralları normatif olarak alınır. _Kaynak:_ §9.4 D. _Durum:_ belirtilmemiş
- [ ] **Access Executor servisi** — Access ile birlikte sunulan ayrı servis (`services/executor/`); AG-39 katalogundaki servisler için hazır yürütücüler; resmî MCP sunucusu varsa onu kullanır, yoksa Suiss yazar; yalnız herkese açık parçaları kullanır; müşteri kendi yürütücüsünü aynı kurallarla bağlayabilir; protocol'de ayrıcalıklı yol yok. _Kaynak:_ §18.7 B21; AG-39, AG-40, OP-62. _Durum:_ belirtilmemiş (FROZEN STRATEGY)

#### MCP

- [ ] **MCP authorization server profili (PRM, `resource`, `iss`, CIMD, AS metadata)** — MCP için AS profili; CIMD ve AS metadata profili. _Kaynak:_ §2.2.1, §4.3, §10.1.2, §10.4.6 (→ §11.3–11.4). _Durum:_ belirtilmemiş
- [ ] **MCP Authorization profili (RS + PEP eşlemesi)** — MCP server = RS + PEP, MCP client = agent Instance, token = Access projection. RFC 8707 zorunludur. _Kaynak:_ §9.4 G, §9.4.1. _Durum:_ belirtilmemiş (PROFILE, hedef)
- [ ] **MCP client/server profili (IdP SDK)** — _Kaynak:_ §18.3, §18.9 D4 notu. _Durum:_ Faz 2 (MCP profili, §18.13 çıkarım)
- [ ] **MCP tool → ActionRef, tool call → Exercise Request / `kind=intent`** — _Kaynak:_ §9.3A, §9.4.1. _Durum:_ belirtilmemiş
- [ ] **Token passthrough yok** — RS upstream'i kendi `projection.issue` kararıyla aldığı ayrı token ile çağırır. _Kaynak:_ §9.9.3 k.9; L24, P48. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **MCP REQUIRE_ACTION eşlemesi ve SEP-2848 asenkron onay** — SEP-2643/2848 Final olursa REQUIRE_ACTION bu yapılara eşlenir; o zamana kadar RS challenge kullanılır. _Kaynak:_ §9.9.5, §11.8.4, §11.14.2; P54. _Durum:_ WATCH (talep üzerine)
- [ ] **MCP elicitation yalnız adres iletimi** — `elicitation/create` ve MRTR `input_required` yalnız Approval Surface adresini iletmek için kullanılır. Cevap approval değildir. _Kaynak:_ §9.9.5; EI-18. _Durum:_ belirtilmemiş
- [ ] **Sender-constraint olmayan MCP istemcilerine yalnız Public kapsam** — DPoP/AIS üretmeyen istemciler (bugünkü Claude/ChatGPT bağlayıcıları) Access PEP profilinde yalnız `Anonymous`/Public Grant kullanır; FOR(P) authority bearer token ile verilmez. _Kaynak:_ §11.8.3, §12.10; AG-18, PI-11, RR-44. _Durum:_ PD (§11.8.3); §13'e RR adayı (§12.10)
- [ ] **MCP gateway = Access Proxy MCP modu** — Access'e entegre olmayan MCP sunucularının önünde PEP; MCP trafiğini ayrıştırır, her araç çağrısında karar sorar, uygular ve kaydeder. _Kaynak:_ AG-42, B22, IDP-30. _Durum:_ belirtilmemiş (FROZEN karar), PD (sabitleme politikası)
- [ ] **MCP gateway: araç listesi sabitleme (pin) ve değişiklik tespiti** — Tool poisoning savunması. _Kaynak:_ AG-42. _Durum:_ PD
- [ ] **Proxy AS: dinamik kayıtlı her istemci için kullanıcı onayı (AS-M15)** — _Kaynak:_ §11.6; AS-M15. _Durum:_ belirtilmemiş
- [ ] **MCP liste önbelleği `cacheScope` izolasyonu** — Yalnız Public-Grant-türevli listeler `public` işaretlenir; çapraz kiracı ifşası yok (Access PEP SDK'lı conformant PEP). _Kaynak:_ §13.4 U63; AG-12. _Durum:_ belirtilmemiş
- [ ] **MCP `subscriptions/listen` horizon sınırı** — Stream ValidityContract horizon'u sonrasında olay taşımaz. _Kaynak:_ §13.4 U64; AG-15. _Durum:_ belirtilmemiş
- [ ] **MCP conformance suite** — MCP conformance dış suite olarak CI'da. _Kaynak:_ §14.8 SA-T2; SA-43. _Durum:_ belirtilmemiş
- [ ] **COAZ ihtiyacının ADP + MCP profiliyle karşılanması** — _Kaynak:_ §9.4 B. _Durum:_ WATCH (talep üzerine)

#### A2A

- [ ] **A2A task transport + Access extension** — A2A extension authority request, causal ref, REQUIRE_ACTION ve continuation taşır. Agent Card authority değildir. _Kaynak:_ §9.4 G, §9.4.1, §9.7, §9.9.5. _Durum:_ belirtilmemiş (ADOPT + EXTEND)
- [ ] **A2A görev durumlarının REQUIRE_ACTION eşlemesi** — `TASK_STATE_AUTH_REQUIRED` / `TASK_STATE_INPUT_REQUIRED` + extension üyeleri kullanılır. _Kaynak:_ §9.9.5, §11.15. _Durum:_ belirtilmemiş
- [ ] **A2A Agent Card = Claim** — Kart imzası issuer imzasıdır, authority vermez; imzalayan anahtar Acceptance ile; `securitySchemes`/beceriler authority-opaque. _Kaynak:_ §11.15; AG-34. _Durum:_ PD
- [ ] **Agent Card imzalama servisi (`POST /agent-cards/sign`)** — A2A Agent Card'larının RFC 8785 JCS + JWS (JOSE ES256) ile imzalanması. _Kaynak:_ §2.2.1, §11.15, §11.21.1 #33, §11.21.2; MKT-D4. _Durum:_ Faz 3 (§2.2.1); WATCH (talep üzerine) (§11.15)
- [ ] **A2A mTLS SAN'daki SPIFFE ID → actor-binding Claim'i** — _Kaynak:_ §11.15; AG-34. _Durum:_ PD
- [ ] **A2A görev devri = alt-delegasyon veya ayrı Exercise** — Görev mesajı authority taşımaz. _Kaynak:_ §11.15; AG-34. _Durum:_ PD

#### Senaryolar ve uyumluluk

- [ ] **Walkthrough: Cloud agent** — Her oturum/görev bir Instance; AIS ile ADP; REQUIRE_ACTION → CIBA/push daveti → AAS → aynı nonce ile `commit`; kısa ömürlü exact-intent; SSF ile re-query. _Kaynak:_ §11.19. _Durum:_ belirtilmemiş
- [ ] **Walkthrough: Local agent** — Cihaz-bağlı Instance; aynı cihazda platform authenticator ile AAS. _Kaynak:_ §11.19. _Durum:_ belirtilmemiş
- [ ] **Walkthrough: Enterprise agent** — SPIFFE/SCIM workload Party; rule-shaped Grant; SCIM deprovision → actor-binding fail closed; ID-JAG ile gelirse tüketim adımları. _Kaynak:_ §11.19. _Durum:_ belirtilmemiş
- [ ] **Walkthrough: Başka organizasyon** — Bridging Grant veya cross-domain delegation; identity chaining yalnız kimlik. _Kaynak:_ §11.19. _Durum:_ belirtilmemiş
- [ ] **Walkthrough: MCP proxy / credential broker** — Proxy PEP'tir (actor değil); ilk bağlantıda AS-M15 onayı = AAS; Grant revoke → tokenset silinir. _Kaynak:_ §11.6, §11.19. _Durum:_ belirtilmemiş
- [ ] **Ortak kural: Suiss'e özel SDK/endpoint/Claim class/trust anchor gerekmez** — _Kaynak:_ §11.19; PI-13. _Durum:_ belirtilmemiş
- [ ] **Ajan regülasyonu eşlemesi** — Agent = Party/Instance; Mandate; audit. _Kaynak:_ §14.9 sektörel tablo. _Durum:_ WATCH (talep üzerine)

### K10 Yönetişim

#### Onay, quorum ve görevler ayrılığı

- [ ] **Kurumsal ajanda yüksek sonuçlu action'larda yönetici `approve`** — _Kaynak:_ §11.19 enterprise satırı. _Durum:_ belirtilmemiş

### K11 Yönetim API'si, konsol, SDK'lar ve geliştirici araçları

#### SDK'lar

- [ ] **Access PEP SDK: MCP RS desteği / referans MCP Resource Server** — PRM sunumu, `WWW-Authenticate`, DPoP doğrulaması, `Authorized<R,A>`; Rust ekosistemindeki RS boşluğunu doldurur. _Kaynak:_ §11.0 plane tablosu; §11.5; §11.8.1; AG-16; P40. _Durum:_ PD (yeterlilik EA).

#### Genişletme noktaları ve entegrasyon yüzeyleri

- [ ] **Satıcıya özgü interop eki (tarih damgalı)** — Claude/OpenAI kuralları normatif profilden ayrı ekte. _Kaynak:_ §11.8.3; AG-18. _Durum:_ PD.
- [ ] **Ajan registry API'si** — _Kaynak:_ AG-41. _Durum:_ PD (K09'da da var).

### K12 Entegrasyonlar ve yardımcı servisler

#### Diğer Suiss ürün seam'leri

- [ ] **Executor seam ve continuation hook'ları** — Intent envelope, Decision, ValidityContract ve continuation sağlanır; effect ve stop Executor'dadır; Executor Contract stop/confirmed-stopped Claim'leri ve effect attestation sağlar. _Kaynak:_ §7.3; §7.9.7; §9.4 H; §9.7; E31. _Durum:_ belirtilmemiş (PROFILE).
- [ ] **Executor control durumu (aftermath'te)** — Running / paused (confirmed) / unknown, runtime raporundan. _Kaynak:_ §8.17.7.4. _Durum:_ belirtilmemiş.

#### Ajan ve yürütücü entegrasyonları

- [ ] **Access Executor servisi (kayıtlı yürütücü)** — Araç tanımları ve yürütme (upstream API çağrısı, yeniden deneme, sonuç); karar vermez; ayrı süreç/proje olarak Access ile birlikte teslim edilir, müşterinin kendi kayıtlı yürütücüsü de olabilir. CT2+ işlemlerde upstream token ajana verilmez, vault'ta kalır ve yürütücü iş başına kullanım alır. _Kaynak:_ §2.5; AG-40; B21; F7. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Token vault upstream kataloğu** — En yaygın 20–30 servis (Google, Microsoft, GitHub, Slack, Notion, Salesforce, Atlassian…) için küratörlü OAuth/OIDC metadata, scope kataloğu, yenileme ve iptal kuralları; tanım veridir, upstream eklemek `idp.*` domain action'ıdır, hazır tanım authority vermez. _Kaynak:_ AG-39; E36; EI-26; F23. _Durum:_ belirtilmemiş (FROZEN katalog), PD (servis listesi).
- [ ] **Claude / ChatGPT MCP bağlayıcı interop'u** — CIMD seçimi koşulları, form kodlu token endpoint, 401 zorunluluğu, RS256 `private_key_jwt` opt-in, `id_token_hint`, bilinmeyen alan toleransı. _Kaynak:_ §11.8.3. _Durum:_ belirtilmemiş.
- [ ] **SPIFFE / WIMSE kimliklerinin tüketimi** — Workload kimlikleri actor binding girdisi olarak alınır; workload federation authority federation değildir. _Kaynak:_ §4.3; §4.4 K7; L25. _Durum:_ belirtilmemiş.

### K13 Denetim, kayıt, şeffaflık ve dışa aktarım

#### Exercise ve karar kayıtları

- [ ] **Upstream token release kaydı** — Her kullanım Exercise olarak kaydedilir; release kaydı projection'dır (BS). _Kaynak:_ §11.13 adım 4; AG-32; AG-39; AG-40. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **MCP gateway çağrı kaydı** — Her araç çağrısı kaydedilir. _Kaynak:_ AG-42. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **`_meta` audit bağlamı (SEP-2817)** — PEP'in iddiasıdır; Exercise kaydı esastır. _Kaynak:_ §11.8.4. _Durum:_ WATCH (talep üzerine).

#### Atıf ve inkâr edilemezlik

- [ ] **Instance düzeyinde audit atfı** — `agent_instance_id` Instance'ı, ExerciseID eylemi tanımlar. _Kaynak:_ §11.9.3; AG-21. _Durum:_ PD.

#### Audit yüzeyleri ve kullanıcıya görünür geçmiş

- [ ] **Ajan askısı/sorumlu atamasının Changes'ta görünmesi** — _Kaynak:_ AG-41; SI-21. _Durum:_ belirtilmemiş (FROZEN).

### K14 Sinyaller, gözlemlenebilirlik ve analitik

#### SSF/CAEP verici ve alıcı

- [ ] **Gelen keşif sinyalleri SSF ile (yalnız daraltır)** — Ajan keşif sinyalleri SSF üzerinden alınır ve yalnız daraltır. _Kaynak:_ AG-43; E38. _Durum:_ gün-1.

#### Risk ve tehdit sinyalleri

- [ ] **Cihaz attestation sinyalleri (App Attest, Play Integrity, relay OID izleme)** — `runtime-attestation`/`device-posture` Claim'i olarak. _Kaynak:_ §10.1.2, §10.1.3. _Durum:_ belirtilmemiş.
- [ ] **Gölge (shadow) ajan keşfi ve raporlaması** — Kayıt dışı ajanların keşfi ve raporlanması (güvenlik aracı). _Kaynak:_ §4.4 katman testi; AG-43. _Durum:_ gün-1 (aşama 1).

#### Kiracı analitiği

- [ ] **Ajan göstergeleri** — Aktif ajan, ret oranı, en çok kullanılan bağlantılar. _Kaynak:_ IDP-36. _Durum:_ PD.

### K15 Güvenlik ve kriptografi

#### OAuth, MCP ve ajan güvenliği

- [ ] **CIMD SSRF savunması** — RFC 6890 özel adres engeli `client_id` URL'i ve doküman içi tüm URL'ler için; IP doğrulaması elle yazılmaz; DNS kontrol/kullanım pinleme; çıkış vekili; bilinmeyen şemalar getirilmez; SHOULD → MUST. _Kaynak:_ §11.3.6; §11.4.5 #12; AS-S7. _Durum:_ belirtilmemiş.
- [ ] **CIMD getirme sınırları** — Yönlendirme takip edilmez, yalnız 200, 5 KB'ta okuma kesilir, zaman aşımı, istemci başına hız sınırı. _Kaynak:_ §11.3.6; §11.4.5 #11. _Durum:_ EA/PD (değerler).
- [ ] **CIMD'de simetrik sır reddi** — Simetrik `token_endpoint_auth_method` veya `client_secret` varsa ret; yalnız public key. _Kaynak:_ §11.3.1; §11.4.5 #14. _Durum:_ belirtilmemiş.
- [ ] **Onay CSRF/clickjacking korumaları** — `frame-ancestors 'none'`/`X-Frame-Options: DENY`, CSRF token'ı. _Kaynak:_ §11.4.5 #28. _Durum:_ belirtilmemiş.
- [ ] **Onay çerezi sertleştirmesi** — `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`, imzalı ve `client_id`'ye bağlı; onaydan önce çerez/state kurulmaz. _Kaynak:_ §11.4.5 #6, #27; §11.6 kural 2, 4. _Durum:_ belirtilmemiş.
- [ ] **`state` kuralları** — CSPRNG, yalnız onaydan sonra sunucuda, tam eşleşme, doğrulamadan sonra silinir, TTL ≤ 10 dk. _Kaynak:_ §11.6 kural 3. _Durum:_ belirtilmemiş.
- [ ] **Onayın kimliği doğrulanmış kullanıcıya bağlanması** — Anonim tarayıcı oturumuna değil. _Kaynak:_ §11.4.5 #30; §11.6 kural 5. _Durum:_ belirtilmemiş.
- [ ] **Confused deputy savunması (iki katman: AAS Grant + UI kaydı)** — İstemci `client_id`'si Grant AgencyTerms'üne actor-binding kısıtı olarak girebilir. _Kaynak:_ §11.6; P58. _Durum:_ belirtilmemiş.
- [ ] **DNS rebinding savunması** — `Origin` geçersizse 403; yerelde yalnız 127.0.0.1. _Kaynak:_ §11.5.6 #20–21; RS-M15. _Durum:_ belirtilmemiş.
- [ ] **Başlık/gövde uyuşmazlığı reddi** — 400 + `-32020 HeaderMismatch`; gövde otoritedir; base64 sentinel çözülür; CR/LF yasak; `Mcp-Param-*`'ta sır yok. _Kaynak:_ §11.5.6 #22–24; §11.7; RS-M14. _Durum:_ belirtilmemiş.
- [ ] **Attestation = Claim, Acceptance ile issuer kabulü (iki model)** — Donanım kökü (pinned key/sertifika zinciri) veya attester (`tbot`) modeli; attester'ın imzalayabileceği Claim class'ı Acceptance'ta; seçim domain'in; attester ele geçirilmesi Acceptance revoke/lapse. _Kaynak:_ §11.12.4; AG-31. _Durum:_ PD.
- [ ] **Workload kimliği = actor-binding Claim'i / KeyBinding** — SPIFFE trust domain ≠ AuthorityDomain; JWT-SVID kuralları (`aud`, `exp`, bundle JWK). _Kaynak:_ §11.12; §11.12.1; AG-30. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **InstanceID ≠ KeyBinding ≠ Attestation ayrımı** — _Kaynak:_ §11.0 #5; §11.9.1; L21. _Durum:_ belirtilmemiş.
- [ ] **Garanti: sahiplik ≠ authority** — Vault token'ı, state handle, `requestState`, consent kaydı, CIMD kaydı authority değildir. _Kaynak:_ AGI-2; MD-13. _Durum:_ belirtilmemiş (aday invariant).
- [ ] **Garanti: Inbound ID-JAG, `act` zinciri, Agent Card, güven skoru karara yalnız Acceptance use'u olarak girer** — _Kaynak:_ AGI-7. _Durum:_ belirtilmemiş (aday invariant).
- [ ] **Garanti: ajanın kendi isteğine contribution yalnız kullanıcının kendi Instance'ından AAS ile** — _Kaynak:_ A-5; AGI-8; EI-18. _Durum:_ belirtilmemiş (aday invariant).
- [ ] **Doyensec ID-JAG bulgularının kapatılması** — Horizon + revoke; yüksek riskli action'da RequirementTerm → REQUIRE_ACTION; `resource` doğrulama + ActionRef namespace; `jti` tek kullanım. _Kaynak:_ §11.11.4. _Durum:_ PD.

#### Revocation ve olay müdahalesi

- [ ] **Executor revocation'ı yok sayarsa dürüst mesaj** — Horizon öncesi/sonrası ayrımı; containment yalnız ikinci durumda. _Kaynak:_ §8.13. _Durum:_ belirtilmemiş.

### K16 Gizlilik, rıza ve uyum

#### Takma adlar ve bağlanamazlık

- [ ] **EMA `email` minimizasyonu** — E-posta yalnız JIT provisioning için `identity-binding` Claim'i olarak alınır; PartyRef birincil anahtarı `sub`. _Kaynak:_ §11.11.5; E26. _Durum:_ belirtilmemiş.

#### Mevzuat ve standart eşlemeleri

- [ ] **AB Yapay Zekâ Yasası m. 50 ifşa yükümlülüğü (A-12)** — _Kaynak:_ §11.16.2, §11.18. _Durum:_ belirtilmemiş.
- [ ] **CSA/NIST/OWASP/WEF ortak 8 gereksiniminin Access eşlemesi** — Benzersiz ajan kimliği, kısa ömürlü kimlik bilgisi, güvenilir kayıt, kesişim, her adımda yeniden yetkilendirme, inkâr edilemezlik, merkezî karar kaydı, kullanıcı/ajan başlatmalı ayrım; satır başına garanti sınıfı. _Kaynak:_ §11.18; AG-35. _Durum:_ PD.

### K17 Dağıtım, operasyon, yüksek erişilebilirlik ve felaket kurtarma

#### Yüksek erişilebilirlik ve failover

- [ ] **ID-JAG `jti` önbelleği failover'da fail-closed** — _Kaynak:_ §11.11.3. _Durum:_ PD.

#### Performans ve kapasite

- [ ] **Ajan token yük profili ile horizon birlikte tasarım** — 15 dk değeri yük profiliyle (§17) doğrulanır. _Kaynak:_ §11.9.4. _Durum:_ EA.
- [ ] **Yanıt süresi hedefleri** — Token/keşif < 10 s; RS metadata < 5 s; ters vekil/WAF yanıtı tutmamalı. _Kaynak:_ §11.4.5 #25, §11.5.6 #25. _Durum:_ belirtilmemiş.

### K19 Geliştirme ve kalite güvencesi

#### Access conformance ve test vektörleri

- [ ] **Delegasyon değişmezleri conformance test listesi** — _Kaynak:_ §11.10.4; AG-26. _Durum:_ belirtilmemiş (FROZEN).

#### Dış conformance süitleri ve interop

- [ ] **MCP conformance süitinin CI'a bağlanması** — _Kaynak:_ §9.17.5. _Durum:_ yol haritası.
- [ ] **Üç conformance süiti birlikte CI'da** — MCP `auth` süiti + OIDF süiti + Access vektörleri (T12); biri diğerinin yerine geçmez. _Kaynak:_ §11.8.2; AG-17. _Durum:_ PD.

### Bu aşamada doğrulanacak sınırlar

#### Ürün kapsamı

- [ ] **Access sır tutmaz (PAM/vault değil)** — Secret custody ve vault paylaşımı Access'te yoktur. _Kaynak:_ §8.17.12; §10.1.1 seam; §10.9.1. _Durum:_ belirtilmemiş.
- [ ] **Ajan çalıştırıcı / orkestratör değil** — _Kaynak:_ §2.5. _Durum:_ belirtilmemiş.
- [ ] **Ayrı MCP gateway ürünü yazılmaz** — _Kaynak:_ AG-42. _Durum:_ belirtilmemiş.
- [ ] **Prompt enjeksiyonu savunmasının sahibi değil; enjeksiyon önlenmez, yalnız sınırlanır** — Instruction-provenance Access'in sorumluluğu değildir. _Kaynak:_ §11.0 #8; §11.20; L28. _Durum:_ NG.
- [ ] **Access upstream çağrıyı kendisi yapmaz; Executor karar vermez** — _Kaynak:_ AG-40; F7. _Durum:_ belirtilmemiş.

#### Kimlik ve protokol

- [ ] **Ajan kimliği alanında reddedilenler** — COAZ-MCP (insan Subject / ajan Context modeli); `draft-li-oauth-delegated-authorization` yerel türetme; `draft-sharif-openid-agent-identity` trust score'un authority olarak kullanımı; `draft-drake-agent-identity-registry` iptal edilemez kimlik; Biscuit. _Kaynak:_ §11.10.3; §11.17; §11.21.1 #25; AG-36; AG-38. _Durum:_ REJECT.

#### Token modeli

- [ ] **Token'daki actor/`act` zinciri authority veya lineage kanıtı değildir** — Önceki aktörler token'dan doğrulanmaz. _Kaynak:_ §9.9.4 k.3; §11.0 #4; §11.10.1; L22. _Durum:_ belirtilmemiş.
- [ ] **Aynı stream üzerinde token yenileme yok** — _Kaynak:_ AG-15. _Durum:_ belirtilmemiş.

#### Yetki modeli

- [ ] **Ajana özgü authority primitive ve `Principal` tipi yok** — _Kaynak:_ §11.9.1; AG-19; C5; F15. _Durum:_ belirtilmemiş.
- [ ] **LLM sağlayıcısı kendiliğinden authority sahibi değildir** — _Kaynak:_ §11.9.1; §11.19; EI-6. _Durum:_ belirtilmemiş.
- [ ] **`clientInfo`/`clientCapabilities`/`serverInfo` güvenlik kararı girdisi değil** — _Kaynak:_ AG-11. _Durum:_ belirtilmemiş.
- [ ] **Keşif authority üretmez; keşfin eksiksizliği garanti edilmez** — _Kaynak:_ AG-43. _Durum:_ belirtilmemiş.

#### Kiracı genişletilebilirliği

- [ ] **Vendor'a özgü kurallar normatif profil değildir** — _Kaynak:_ AG-18. _Durum:_ belirtilmemiş.

#### Ajan ve MCP

- [ ] **CIMD istemcilerinde simetrik sır yok** — _Kaynak:_ §11.3.1; §11.4.5 (c). _Durum:_ belirtilmemiş.
- [ ] **Onaydan önce state çerezi yok** — _Kaynak:_ §11.4.5 #6. _Durum:_ belirtilmemiş.
- [ ] **`Mcp-Session-Id` üretilmez/yansıtılmaz** — _Kaynak:_ §11.5.3; §11.5.6 #11. _Durum:_ belirtilmemiş.
- [ ] **Ajanın token vault'a doğrudan erişimi yok** — _Kaynak:_ §11.13. _Durum:_ belirtilmemiş.
- [ ] **CT2+ sınıflarda upstream token ajana verilmez, model bağlamına konmaz** — _Kaynak:_ AG-40. _Durum:_ belirtilmemiş.
- [ ] **Upstream token içeriğinin Grant'ı aşmaması garanti edilmez** — _Kaynak:_ §11.13; AG-32. _Durum:_ NG.
- [ ] **Bilgi akışı (taint) kontrolü karar semantiğinde yok** — §9.17 backlog'undadır. _Kaynak:_ §11.7; §11.20. _Durum:_ WATCH.

#### Federasyon, şema ve güven

- [ ] **ID-JAG authorization grant semantiği yok; IdP grantor olamaz** — _Kaynak:_ §9.4 E; §9.13.8 k.2; MD-18; MKT-10. _Durum:_ belirtilmemiş.

## Aşama 10 — Kurumsal protokoller

SCIM, SAML, LDAP, Kerberos, RADIUS, WS-Fed, OpenID Federation, FAPI 2, CIBA, upstream federasyon, EUDI, e-Devlet, SSO kataloğu, self-servis SSO portalı, uyumluluk laboratuvarı.

### Spec dışı ön koşullar

- [ ] **OCSP/CRL alma ve önbellekleme bileşeni** — sertifika ve PIV ile girişte iptal kontrolü.
- [ ] **Kerberos, LDAP ve RADIUS uyumluluk test ortamı** — test AD/KDC, LDAP istemcileri, RADIUS istemcileri.
- [ ] **Uyumluluk laboratuvarı için üçüncü taraf test hesapları** — Entra, Okta, Salesforce, Workday, ServiceNow vb.

### K01 Kimlik doğrulama yöntemleri

#### Sertifika, donanım ve cihaz anahtarları

- [ ] **Sertifika / PIV / CAC / mTLS ile kimlik doğrulama** — X.509 sertifika bir login credential türüdür; subject+issuer `identity-binding`'e eşlenir, CA güveni Acceptance ile kurulur. AAL3/CT3'e kadar karşılar, kiracı başına açılır. _Kaynak:_ §2.2.1; §5.6; §10.1.2, §10.2, §10.2.5. _Durum:_ belirtilmemiş (kiracı başına).
- [ ] **PIV/CAC iptal kontrolü fail-closed (OCSP/CRL)** — İptal kontrolü doğrulanamazsa ret. _Kaynak:_ §10.2.5; MD-8. _Durum:_ belirtilmemiş.
- [ ] **mTLS client auth için ayrı host/port (`mtls_endpoint_aliases`)** — Tarayıcı çakışmasını önlemek için mTLS ayrı host/port'tan sunulur ve metadata'da ilan edilir. _Kaynak:_ §10.2.5, §10.4.3. _Durum:_ belirtilmemiş.
- [ ] **Mobil imza (operatör tabanlı, TR)** — Upstream assertion olarak modellenir; assurance eşlemesi Acceptance'tadır. _Kaynak:_ §10.2.5, §10.9.1. _Durum:_ belirtilmemiş.

#### Federasyon ve kurumsal SSO

- [ ] **Upstream (federe) IdP ile giriş (broker)** — Access identity plane RP / federation broker olarak çalışır; upstream kimlik doğrulaması `authentication` / attribute Claim'i olarak girer. "Sign in with *Provider*" düğmesi kullanılır ("Trusted provider" ifadesi yasak); bağlantı kaydı ve güveni ayrı CT3 Exercise'larıdır. _Kaynak:_ §7.1, §7.3; §8.8; §12.3.8; E18, TN-95. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Kurumsal SSO ile giriş (upstream SAML/OIDC)** — Çalışanlar için kurumsal SSO; Enterprise'da varsayılandır ve assurance Acceptance eşlemesine bağlıdır. Federasyon bağlantısının varlığı ücretlendirilmez (aday). _Kaynak:_ §1.7; §2.2.1; §10.2, §10.2.6; §18.6, §18.9 D-11; H13. _Durum:_ belirtilmemiş (Enterprise'da varsayılan; D-11 aday).
- [ ] **Upstream IdP Claim'inin protokol başına eşlemesi (OIDC/SAML)** — Subject `(iss, sub)` veya NameID+EntityID'dir; `acr`, `amr`, `auth_time`, RFC 9207 `iss` ve assertion digest eşlenir. _Kaynak:_ §10.1.2; IDP-1. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **JIT provisioning** — İlk SSO girişinde `IdentitySubject` oluşturulur; grup/rol yalnız Acceptance ile selection'a girer. _Kaynak:_ §10.2.6. _Durum:_ belirtilmemiş.
- [ ] **SP-initiated SSO tercihli, IdP-initiated varsayılan kapalı** — _Kaynak:_ §10.2.6, §10.6.1. _Durum:_ belirtilmemiş.

#### Kenar protokoller ve işletim sistemi girişi

- [ ] **SPNEGO / Kerberos ile kimlik doğrulama (HTTP Negotiate)** — Ayrı HTTP/1.1 endpoint, tarayıcı allowlist'i ve başarısızlıkta zorunlu normal login fallback'i. Kerberos/SPNEGO kenar gateway'i ayrı, izole bir süreçtir; C FFI yalnız bu süreçte, ASN.1 ayrıştırma parser worker'ındadır. _Kaynak:_ §10.6.4; §16.3.1 CMP-23.3; §16.4.0 MD-1; IDP-17, OP-8, T35. _Durum:_ Faz 1.
- [ ] **LDAP bind ile kimlik doğrulama (kenar)** — `ldap-bind` method class ile `authentication` Claim'i. _Kaynak:_ §10.1.2, §10.6.3. _Durum:_ Faz 1.
- [ ] **RADIUS gateway** — RADIUS kenar protokol gateway'i ayrı süreç olarak sunulur. _Kaynak:_ §16.3.1 CMP-23.4; T35. _Durum:_ belirtilmemiş.

#### İstemci kimlik doğrulaması

- [ ] **mTLS istemci kimlik doğrulaması (RFC 8705)** — `tls_client_auth` / `self_signed_tls_client_auth` ve `cnf.x5t#S256` bağlama. _Kaynak:_ §11.21.1 #11, §11.21.2. _Durum:_ belirtilmemiş.

### K02 Kimlik protokolleri ve federasyon

#### Genel kapsam ve identity plane sınırları

- [ ] **Kenar protokoller kapsamda, ayrı gateway süreçlerinde** — Identity plane OIDC, SAML, SCIM ile LDAP/Kerberos/RADIUS/WS-Fed gateway'lerini (ayrı süreçler) destekler; kenar protokoller aşamalandırılır, atılmaz. _Kaynak:_ §13.2; P-ID-4; MD-1, MD-18. _Durum:_ Faz 1–2 (protokole göre).
- [ ] **Kenar gateway süreç izolasyonu ve etki alanı** — LDAP/Kerberos/RADIUS/WS-Fed gateway'i eski protokol bind'ini identity plane authentication olayına çevirir; ayrı süreç ve ayrı seccomp/Landlock profiliyle çalışır. Ele geçirilirse etki o gateway'den bind eden kullanıcılar ve o realm ile sınırlıdır. _Kaynak:_ §13.2 blast radius tablosu; SA-7. _Durum:_ belirtilmemiş.

#### Grant tipleri ve temel akışlar

- [ ] **SAML 2.0 Bearer assertion (RFC 7522)** — Legacy, kiracı başına. _Kaynak:_ §10.4.1. _Durum:_ belirtilmemiş (kiracı başına).

#### Yetkilendirme isteği ve token uzantıları

- [ ] **JAR (RFC 9101)** — JWT-secured Authorization Request; PAR ile kullanılır, yüksek-sonuç profilde zorunlu; imzalı ve isteğe bağlı şifreli request object. _Kaynak:_ §2.2.1; §9.4 A; §10.4.3; §13.2 kripto tablosu; §15.3.3 CR-4; CMP-15.1; MD-3. _Durum:_ belirtilmemiş (ADOPT).
- [ ] **JARM** — JWT-secured Authorization Response Mode; yüksek-sonuç profilde zorunlu, içerik şifrelemesi kapsamında. _Kaynak:_ §2.2.1; §9.4 A; §10.4.3; §13.2 kripto tablosu; §15.3.3 CR-4; CMP-15.1; MD-3. _Durum:_ belirtilmemiş (ADOPT).
- [ ] **RAR metadata keşfi (`/.well-known/authorization-details-types`)** — SPP RAR type görünümü. _Kaynak:_ §11.5.2, §11.21.1 #28, §11.21.2. _Durum:_ WATCH (talep üzerine).

#### Sender-constraint: DPoP ve mTLS

- [ ] **mTLS sertifika-bağlı token ve client auth (RFC 8705)** — `mtls_endpoint_aliases`, iletilmiş sertifika başlıklarını soyma, tek SAN kuralı; ücretlendirilemez güvenlik yüzeyi. _Kaynak:_ §2.2.1; §10.4.3; §12.2.1; §18.6 madde 5; B3; I3; TN-32. _Durum:_ PD (§12.2.1).

#### Yüksek güvence profilleri ve CIBA

- [ ] **FAPI 2.0 Security Profile + Message Signing** — Client başına `profile=fapi2`: sender-constrained, yalnız confidential, `private_key_jwt`/mTLS, PAR zorunlu, PKCE S256, RFC 9207, RSA imza yok, JAR/JARM/HTTP Message Signatures, auth code ≤60 s. Refresh rotasyonu §10.5.1'de yok, §12.2.1'de var; FAPI 1.0 da üretime alınır. _Kaynak:_ §2.2.1; §4.11; §9.4 A; §10.5.1; §12.2.1; §16.10 T42 madde 1; CR-52; IDP-12; TN-27. _Durum:_ belirtilmemiş (ADOPT; karar FROZEN); T42'ye göre yol haritası.
- [ ] **CIBA Core 1.0 (yalnız davet)** — Kullanıcıyı Approval Surface / onay cihazına çağırır; onay kanalıdır, onay authority'si değildir, onay AAS'dir. Poll varsayılan, ping opsiyonel; `/bc-authorize`, `login_hint_token`/`id_token_hint`, serbest `login_hint` yalnız kiracı izniyle, `binding_message` gösterilir ama bağlamaz, `slow_down`; PSD2 dinamik bağlama karşılığı. _Kaynak:_ §2.2.1; §9.4 B, §9.9.5, §9.14.5 k.2; §10.5.3; §11.14.2, §11.21.1 #13, §11.21.2; §14.8 SA-T2; §14.9; F8; IDP-14; P58; T42 madde 1. _Durum:_ PD (PROFILE); T42'ye göre yol haritası.
- [ ] **CIBA ↔ REQUIRE_ACTION / Exercise eşlemesi** — Backchannel isteği bir `projection.issue` commit'idir; `auth_req_id` ↔ nonce / `exercise_ref` taşıyıcısı, polling `authorization_pending` = nonce açık. _Kaynak:_ §9.14.5; §10.5.3. _Durum:_ belirtilmemiş.
- [ ] **CIBA + RAR karşılığı** — CIBA daveti → Approval Surface → AAS → `projection.issue` RAR `kind=intent` zinciri; neyin onaylandığı token'dan değil AAS ve DecisionRecord'dan doğrulanır. _Kaynak:_ §9.14.5 k.2. _Durum:_ belirtilmemiş.
- [ ] **FAPI-CIBA profili** — §10.5.1 kurallarını devralır. _Kaynak:_ §10.5.3. _Durum:_ belirtilmemiş.

#### Algoritmalar, imza ve şifreleme

- [ ] **JWE ile içerik gizliliği (ID Token / UserInfo / JAR / JARM)** — İstemci talep ederse ID Token, UserInfo, JAR/JARM şifrelenir; birincil `ECDH-ES+A256KW` + `A256GCM`. Authority plane'de JWE kullanılmaz. _Kaynak:_ §13.2 kripto tablosu; §15.1.1, §15.3.3; CR-4; RR-36. _Durum:_ belirtilmemiş (FROZEN; küme PD).
- [ ] **JWE: RSA-OAEP-256 legacy opt-in** — Legacy client için client başına açık opt-in. _Kaynak:_ CR-4. _Durum:_ PD.

#### Consent ve kullanıcı yüzeyi

- [ ] **`ui_locales` upstream sağlayıcılara iletimi** — _Kaynak:_ §12.4.3; TN-108. _Durum:_ PD.
- [ ] **Upstream IdP erişilemez durumu** — "*Provider* isn't responding. Try another sign-in method…"; hesap durumu değişmez, başka hesaba otomatik bağlama yok. _Kaynak:_ §8.13. _Durum:_ belirtilmemiş.

#### Upstream IdP ve kimlik federasyonu

- [ ] **Upstream IdP federasyonu / SAML-OIDC brokering (`idp.upstream.*`)** — Dış IdP'lerin (Entra, Okta, Google, Keycloak…) upstream olarak bağlanması; yönetilen broker müşteri tarafında upstream bağlantı olarak desteklenir. Bağlantı kaydı bir `idp.upstream.*` domain action'ı, upstream güveni use-typed actor-binding Acceptance meta-Exercise'ıdır; ikisi ayrı Exercise, reserved, CT3, soğuma + tüm root'lara bildirim. _Kaynak:_ §2.4, §2.7; §4.9; §5.13, §5.17; §12.3.8; C18; CMP-15.10; F16; MD-14; TN-95. _Durum:_ belirtilmemiş (FROZEN, §12.3.8).
- [ ] **Identity federation (OIDC, SAML gateway, OIDF, WS-Fed) — foreign Party tanıma** — Başka IdP'ler yalnız issuer'dır; sonuç her zaman `actor-binding` Claim'idir. Authority kabulü değildir, authority için Grant gerekir. _Kaynak:_ §5.13; §7.9.11.3; §9.15A.1, §9.15A.5; AP-12; E19; INV-17; P31. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Birleştirme anahtarı `(iss, sub)` / Entra `(tid, oid)`** — Federation'da `sub` ve `iss` eşleşmesi zorunludur; `login_hint` kimlik kanıtı sayılmaz. _Kaynak:_ §12.1.1, §12.3.3; §14.3 advisory tablosu (Kanidm GHSA-x8cg); TN-3, TN-66. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **`sub` değişiminde çakışma olayı** — Otomatik yeniden bağlama yok; kullanıcı/yönetici akışına düşer. _Kaynak:_ §12.3.3; TN-66. _Durum:_ PD.
- [ ] **Kiracının kendi AS'si (conformant provider)** — Kiracı kendi issuer/anahtar/ValidityContract'ıyla token basabilir, Acceptance (foreign-authority) ile girer; gün-1'de ürün özelliği değil, yasak da değil. _Kaynak:_ §12.1.1; TN-8. _Durum:_ PD (özellik; gün-1'de yok).
- [ ] **Ham upstream assertion PII vault'ta, Claim'de yalnız digest** — _Kaynak:_ §10.1.2 kural 1. _Durum:_ belirtilmemiş.
- [ ] **Upstream `amr`/`acr`/`AuthnContextClassRef` → assurance yalnız Acceptance eşleme tablosuyla** — Eşleme yoksa en düşük sınıf. _Kaynak:_ §10.1.2 kural 2; IDP-27. _Durum:_ belirtilmemiş (karar FROZEN).

#### OpenID Federation

- [ ] **OpenID Federation 1.0/1.1 — identity federation rolü** — OpenID Federation ile kimlik federasyonu; identity plane protokolüdür. Suiss opsiyonel OIDF trust anchor işletebilir (D9). _Kaynak:_ §2.2.1, §2.4; §7 giriş, §7.6; §18.2, §18.9 D9; L26; MKT-D3. _Durum:_ belirtilmemiş.
- [ ] **OpenID Federation: trust bootstrap rolü (Access entity types)** — Issuer/provider güven başlatma; trust chain Acceptance değil, Acceptance girdisidir. Identity issuer'ın authority issuer rolü entity-type/metadata policy ile engellenebilir. _Kaynak:_ §4.3; §9.4 D; AP-12; L26. _Durum:_ belirtilmemiş (PROFILE + EXTEND).
- [ ] **OIDF entity statement ve trust chain (identity ve authority tarafı)** — Identity tarafı CMP-15.10; authority Domain Metadata'nın OIDF entity statement'ı CMP-14. _Kaynak:_ CMP-14; CMP-15.10; OP-6. _Durum:_ belirtilmemiş.
- [ ] **OpenID Federation: Leaf rolü (OP/AS, RP)** — Leaf fetch/list sunmaz. _Kaynak:_ §10.7.1; IDP-19. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **OpenID Federation: Intermediate/TA rolü (opsiyonel)** — fetch, list, resolve, trust mark status endpoint'leri. _Kaynak:_ §10.7.1; IDP-19. _Durum:_ belirtilmemiş (opsiyonel).
- [ ] **OIDF entity statement doğrulaması (25 adım) ve zincir çözümleme (8 adım)** — `min(exp)`, uzunluk sınırı, döngü tespiti, offline `trust-chain+json`. _Kaynak:_ §10.7.1; IDP-19. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **OIDF metadata politikası (7 operatör, yalnız daraltır, çelişkide ret)** — _Kaynak:_ §10.7.1; IDP-19. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **OIDF trust mark (`trust_mark_type`, status sorgusu, önbellek)** — _Kaynak:_ §10.7.1. _Durum:_ belirtilmemiş.
- [ ] **Trust mark kullanımı ve consent rozeti** — Trust mark yalnız açıkça kaydedilmiş bir Acceptance'ın `predicate-input`'u olabilir; onay atlatmaz. Consent ekranında "doğrulanmış federasyon üyesi" rozeti yalnız render'a ek bilgidir (§9.13.8 daraltmaya da izin verir; §10.7.1'e göre render daraltılamaz). _Kaynak:_ §9.13.8 k.5; §10.7.1; IDP-20; P57. _Durum:_ PD (§9.13.8); karar FROZEN (§10.7.1).
- [ ] **OIDF chain-kısıtlı Acceptance ve zincir kaybında ileriye dönük kesim** — Claim'in girdi olması için Acceptance aktif olmalı, chain çözülmeli ve chain tazeliği ≤ Δ olmalıdır. Zincir kaybı Acceptance'ı revoke etmez, lapse'tir ve Claim'i ileriye dönük keser; zincir dönünce otomatik yeniden başlar. _Kaynak:_ §9.13.8 k.4; §10.7.1; IDI-12; IDP-20; P57. _Durum:_ PD (kural); karar FROZEN (§10.7.1).
- [ ] **OIDF otomatik ve açık kayıt** — Kiracı başına varsayılan kapalı; `jti`+`exp` replay kontrolü. _Kaynak:_ §10.7.1; IDP-19. _Durum:_ belirtilmemiş (varsayılan kapalı).
- [ ] **OIDF önbellek ve TA oran sınırı** — _Kaynak:_ §10.7.1. _Durum:_ belirtilmemiş.

#### SAML

- [ ] **SAML 2.0 IdP (Web SSO, assertion üretimi)** — SAML 2.0 kimlik sağlayıcısı, kenar gateway; realm anahtarlarıyla imzalı assertion üretir. Protokol mantığı gateway'de, XML ayrıştırma/XMLDSig izole worker'dadır. _Kaynak:_ §2.2.1, §2.4; §7 giriş, §7.6; §10.6 tablo; §12.1.2; §16.3.1 CMP-23.1; §17.12; §18.2, §18.13; MD-18; OP-2; OP-5. _Durum:_ Faz 1 (§10.6); §18.13'e göre yol haritası ("Sonrası", çıkarım).
- [ ] **SAML: HTTP-Redirect binding** — Ham DEFLATE, orijinal URL-encoded değerlerle imza dizisi, 302/303. _Kaynak:_ §10.6.1. _Durum:_ Faz 1.
- [ ] **SAML: HTTP-POST binding** — _Kaynak:_ §10.6.1. _Durum:_ Faz 1.
- [ ] **SAML: metadata yayını** — `validUntil` +14 gün, `cacheDuration` PT6H, otomatik yeniden imza; birden fazla sertifika yayınlanabilir. _Kaynak:_ §10.6.1. _Durum:_ Faz 1.
- [ ] **SAML: imzalı assertion / response (SP başına `sign_response`/`sign_assertion`)** — Enveloped, exclusive c14n; varsayılan ikisi birden. _Kaynak:_ §10.6.1. _Durum:_ Faz 1.
- [ ] **SAML: şifreli assertion (EncryptedAssertion)** — SP talep ederse; önce imzala sonra şifrele, aes256-gcm + rsa-oaep; `EncryptedAttribute` üretilmez, `xmlenc#rsa-1_5` kapalı. _Kaynak:_ §10.6.1; §13.2 kripto tablosu; §15.1.1, §15.3.3; CR-4; RR-36. _Durum:_ Faz 1 (§10.6.1); FROZEN (CR-4).
- [ ] **SAML NameID: persistent (varsayılan, pairwise, rastgele 32 bayt)** — Affiliation (`SPNameQualifier`) desteği; HMAC ile durumsuz türetme kullanılmaz, kullanıcı isteğinde değer yenilenebilir. _Kaynak:_ §10.6.1; IDP-15, IDP-24. _Durum:_ Faz 1.
- [ ] **SAML NameID: transient** — _Kaynak:_ §10.6.1. _Durum:_ Faz 1.
- [ ] **SAML NameID: emailAddress (yalnız SP gerektirir ve kiracı izin verirse)** — _Kaynak:_ §10.6.1. _Durum:_ belirtilmemiş.
- [ ] **SAML NameID: unspecified (legacy, SP başına)** — _Kaynak:_ §10.6.1. _Durum:_ belirtilmemiş.
- [ ] **SAML AuthnRequest işleme** — ForceAuthn/IsPassive önceliği, `NoPassive`, `InvalidNameIDPolicy`, Scoping ayrıştırma (proxy'leme yok, RequesterID audit'e), imzalı AuthnRequest zorunluluğu (`AuthnRequestsSigned`), AuthnRequest/LogoutRequest replay saklama. _Kaynak:_ §10.6.1. _Durum:_ belirtilmemiş.
- [ ] **SAML ACS URL tam eşleşme doğrulaması** — Eşleşme yoksa hata kullanıcıya gösterilir. _Kaynak:_ §10.6.1; IDP-15. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **SAML Response/Assertion 10 normatif kural** — Şema sırası, Destination/InResponseTo/Issuer, audience mantığı, bearer SubjectConfirmation, AuthnStatement (assurance'dan `AuthnContextClassRef`), ID üretimi vb. _Kaynak:_ §10.6.1. _Durum:_ belirtilmemiş.
- [ ] **SAML attribute'ları (`NameFormat` uri varsayılan, SP başına override)** — `FriendlyName` eşleşmede kullanılmaz. _Kaynak:_ §10.6.1. _Durum:_ belirtilmemiş.
- [ ] **SAML IdP-initiated SSO (opt-in)** — `allow_idp_initiated` varsayılan false; açıksa RelayState HMAC, yalnız `isDefault` ACS, kısa assertion ömrü. _Kaynak:_ §10.6.1; IDP-15. _Durum:_ belirtilmemiş (varsayılan kapalı).
- [ ] **SAML zaman pencereleri** — NotBefore −60 s, NotOnOrAfter +5 dk, kayma ±3 dk, OneTimeUse kapalı, UTC. _Kaynak:_ §10.6.1. _Durum:_ PD.
- [ ] **SAML imza doğrulama kuralları** — İmza doğrulama yalnız c14n sonrası referansı çözülmüş elemana; DocType red; yalnız 5 önceden tanımlı entity; `max_declarations ≤ 32`; 8 XSW + 3 yeni sınıf regresyon; quick-xml ≥ 0.41. _Kaynak:_ §14.6; MD-18; SA-29. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **SAML imza algoritması: rsa-sha256 istisnası, ECDSA tercihi** — SAML'de rsa-sha256 ekosistem istisnası olarak desteklenir; ECDSA tercih edilir. _Kaynak:_ §13.2 kripto tablosu; CR-2; MD-3 tablosu. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **SAML iki fazlı sertifika rotasyonu** — T0 ekle, ≥14 gün bekle, T1 geçiş, T1+Δ kaldır; Entra için manuel prosedür. _Kaynak:_ §10.6.1. _Durum:_ belirtilmemiş.
- [ ] **SAML SP uyumluluk profilleri** — AWS, AWS IAM SAML, AWS IAM Identity Center, Entra/M365, Google Workspace, Salesforce, ServiceNow, Workday, Slack, Zoom, Atlassian için gereksinim profilleri. _Kaynak:_ §10.6.1. _Durum:_ belirtilmemiş.
- [ ] **SP şablonu başına NameID biçimi ve attribute eşlemesi** — _Kaynak:_ §10.6.1 "Profillerden çıkan IdP kuralları". _Durum:_ belirtilmemiş.
- [ ] **Elle kurulum için PEM sertifika indirme ve SSO URL gösterimi** — _Kaynak:_ §10.6.1. _Durum:_ belirtilmemiş.
- [ ] **SAML SLO (best effort)** — Ön kanal, `PartialLogout`, yerel çıkış her zaman başarılı (`session_epoch` artışı). _Kaynak:_ §10.6 tablo, §10.6.1. _Durum:_ Faz 2.
- [ ] **SAML ECP (MS zengin istemciler)** — _Kaynak:_ §10.6, §10.6.1. _Durum:_ Faz 2.
- [ ] **SAML upstream SP rolü** — _Kaynak:_ §10.6 tablo. _Durum:_ Faz 2.
- [ ] **SAML Artifact binding** — _Kaynak:_ §10.6, §10.6.1. _Durum:_ Faz 3 / WATCH (talep üzerine).
- [ ] **SAML MDQ (metadata sorgu)** — _Kaynak:_ §10.6, §10.6.1; IDP-33. _Durum:_ Faz 3 / WATCH (talep üzerine).

#### Eski protokol gateway'leri (WS-Fed, LDAP, Kerberos, RADIUS)

- [ ] **WS-Federation passive requestor gateway** — Kenar gateway, ayrı süreç; XML ayrıştırma izole worker'da. SAML 1.1/2.0 token, SAML XML/imza kurallarını devralır; legacy MS/ADFS göçü için. _Kaynak:_ §2.2.1, §2.4; §7 giriş, §7.3, §7.6; §10.6.5; §18.2, §18.13; CMP-23.5; IDP-18; OP-2. _Durum:_ Faz 2 (HYPOTHESIS); §18.13'e göre yol haritası ("Sonrası").
- [ ] **LDAP gateway (bind tüketen uygulamalar için, salt okunur)** — Kenar gateway, ayrı süreç: bind, search, unbind, abandon, StartTLS, WhoAmI, paged results; ldap3_proto codec, semantik Access'te. _Kaynak:_ §2.2.1, §2.4; §7 giriş, §7.3, §7.6; §10.6 tablo, §10.6.3; §18.2, §18.3, §18.13; CMP-23.2; IDP-16; OP-5. _Durum:_ Faz 1 (§10.6); §18.13'e göre yol haritası ("Sonrası").
- [ ] **LDAP: RootDSE ve dolu `cn=Subschema`** — _Kaynak:_ §10.6.3. _Durum:_ belirtilmemiş.
- [ ] **LDAP: sahte OU ağaç modeli (`groupOfNames`+`posixGroup`, `memberOf`, deterministik uid/gidNumber)** — _Kaynak:_ §10.6.3. _Durum:_ belirtilmemiş.
- [ ] **LDAP: filtre çevirisi (derinlik 16, zincir eşleme kuralı 1.2.840.113556.1.4.1941, DN normalizasyon, limitler)** — _Kaynak:_ §10.6.3. _Durum:_ belirtilmemiş.
- [ ] **LDAP: HMAC'li opak paged results çerezi** — _Kaynak:_ §10.6.3. _Durum:_ belirtilmemiş.
- [ ] **LDAP: ayrı LDAP credential sınıfı, `dn=token`, bağlantı sonrası yetki düşürme** — _Kaynak:_ §10.6.3; IDP-16. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **LDAP: LDAPS varsayılan, StartTLS varsayılan kapalı, TLS'siz düz bind 13** — _Kaynak:_ §10.6.3; IDP-16. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **LDAP: SASL EXTERNAL** — _Kaynak:_ §10.6 tablo, §10.6.3. _Durum:_ Faz 2.
- [ ] **LDAP: RFC 3062 parola değişimi (yalnız LDAP credential sınıfı)** — Bildirim, `session_epoch` artışı, SEC18 cooling. _Kaynak:_ §10.6, §10.6.3; IDP-16. _Durum:_ Faz 2.
- [ ] **Kerberos/SPNEGO acceptor (RFC 4559, keytab)** — Kenar gateway, ayrı süreç; SPN birebir, AES256, kvno takibi, keytab kasada. _Kaynak:_ §2.2.1, §2.4; §7 giriş, §7.6; §10.6 tablo, §10.6.4; §18.2, §18.13; IDP-17. _Durum:_ Faz 1 (§10.6); §18.13'e göre yol haritası ("Sonrası").
- [ ] **Kerberos S4U2Proxy** — _Kaynak:_ §10.6, §10.6.4; IDP-17. _Durum:_ Faz 2.
- [ ] **Kerberos C FFI izole gateway süreci** — Kerberos (MIT krb5 vb.) ana süreçten ve signer'dan izole ayrı gateway sürecinde; ASan, fuzz hedefi Kerberos ASN.1 girişi. _Kaynak:_ §14.5 C FFI profili; RR-28. _Durum:_ belirtilmemiş.
- [ ] **RADIUS gateway (RadSec, PAP yalnız TLS içinde)** — Kenar gateway, ayrı süreç; VPN/ağ erişimi için `authentication` Claim'i, eduroam dahil plan. _Kaynak:_ §2.2.1, §2.4; §7 giriş, §7.6; §10.6.5; §18.2, §18.13; IDP-18, IDP-33. _Durum:_ Faz 2 (HYPOTHESIS); §18.13'e göre yol haritası ("Sonrası").

#### SCIM

- [ ] **SCIM 2.0 sunucu (gelen provisioning, Users/Groups CRUD)** — RFC 7643/7644 kurumsal provisioning/deprovisioning sunucusu. Provision edilen User/Group kaydı identity plane'dedir; SCIM DELETE tombstone semantiği §12'dedir. _Kaynak:_ §2.2.1, §2.2.2 #3; §7.1, §7.3; §10.6 tablo; §18.2, §18.3, §18.13; CMP-15.4; E15; IDP-23; MD-4. _Durum:_ Faz 1 (§10.6; §18.13 çıkarım).
- [ ] **SCIM: PATCH motoru (atomik)** — add/remove/replace kuralları, `noTarget`, tüm istek atomik. _Kaynak:_ §10.6.2; IDP-23. _Durum:_ Faz 1.
- [ ] **SCIM: filtre (ABNF, errata, DoS limitleri)** — _Kaynak:_ §10.6.2. _Durum:_ Faz 1.
- [ ] **SCIM filter: yetkisiz sorgu reddi ve derinlik sınırı** — Enumeration'a karşı yetkisiz SCIM filter sorgusu reddedilir; filter derinliği ≤ 32. _Kaynak:_ CR-10, CR-40. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **SCIM: indeks sayfalama** — _Kaynak:_ §10.6, §10.6.2. _Durum:_ Faz 1.
- [ ] **SCIM: imleç sayfalama (RFC 9865)** — _Kaynak:_ §10.6, §10.6.2. _Durum:_ Faz 2.
- [ ] **SCIM: ServiceProviderConfig / Schemas / ResourceTypes** — _Kaynak:_ §10.6 tablo. _Durum:_ Faz 1.
- [ ] **SCIM: durum kodları (409/412 ayrımı, scimType)** — _Kaynak:_ §10.6.2. _Durum:_ belirtilmemiş.
- [ ] **SCIM: attribute projeksiyonu (always/default/never)** — _Kaynak:_ §10.6.2. _Durum:_ belirtilmemiş.
- [ ] **SCIM: istemci başına tolerans katmanı (17 madde, Entra `aadOptscim062020`)** — _Kaynak:_ §10.6.2; IDP-23. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **SCIM: SET (RFC 9967)** — `sub_id` format `scim`, `txn`/`version`, 12 olay URI'si, notice/full, `Set-Txn`, parola SET'te taşınmaz, akış yönetimi SSF. _Kaynak:_ §10.6, §10.6.2; IDP-23. _Durum:_ Faz 2.
- [ ] **SCIM: cihaz şeması (RFC 9944)** — RFC setinde. _Kaynak:_ §10.6.2. _Durum:_ belirtilmemiş.
- [ ] **SCIM: Bulk** — _Kaynak:_ §10.6 tablo. _Durum:_ Faz 3 / WATCH (talep üzerine).
- [ ] **SCIM: `/Me`** — _Kaynak:_ §10.6 tablo. _Durum:_ Faz 3 / WATCH (talep üzerine).
- [ ] **Gelen SCIM bir Claim kaynağıdır** — SCIM client domain action ile kaydedilir; SCIM grubu `member` Claim'idir, SCIM yazımı Grant değildir. Grup üyeliği yalnız Acceptance ile selection'a girer (yalnız Acceptance'ta beyan edilen `subject-selection`/`identity-binding` attribute'larına güvenilir), Grant ancak Acceptance + rule-shaped Grant şablonuyla oluşur; grup başına tek üyelik issuer'ı, SCIM istemcisi grantor olamaz, SCIM token revoke ve Acceptance cutoff ile durdurulur. _Kaynak:_ §9.4 D, §9.13.8 k.7; §10.1.2, §10.6.2; §13.2; IDP-23; INV-16; MD-4; SEC9. _Durum:_ belirtilmemiş (ADOPT; karar FROZEN).
- [ ] **SCIM `subject-selection` Acceptance'ı CT3** — IdP bağlantısı ve SCIM `subject-selection` Acceptance'ı (`acceptance.establish`) CT3'tür. _Kaynak:_ §13.7.1. _Durum:_ PD.
- [ ] **Giden SCIM 2.0 client (Access → hedef uygulama provisioning)** — Kullanıcı ve grup yaşam döngüsü SCIM destekleyen uygulamalara itilir; realm config (`idp.*` domain action). Access hedefteki hesabın varlığını beyan etmez, hedefin raporu Claim'dir; SCIM kaynaklı Claim'ler authority'ye Claim Ingest üzerinden, sıra yalnız issuer-sırası kaynaklarından. _Kaynak:_ §7.1; §10.6 tablo, §10.6.2; §16.5; CMP-15.4; IDP-29; RT15. _Durum:_ Faz 1.
- [ ] **SCIM deprovisioning (ücretsiz)** — Deprovisioning daraltma sınıfıdır, hiçbir pakette ücretli değildir, fair-use aşımında da çalışır. _Kaynak:_ §18.6; B3, B19. _Durum:_ belirtilmemiş (FROZEN STRATEGY).

#### Doğrulanabilir kimlik bilgileri ve dijital cüzdan

- [ ] **W3C VC Data Model 2.0 ingest** — VC yalnız Claim ingest taşıyıcısıdır. _Kaynak:_ §9.4 D. _Durum:_ belirtilmemiş (PROFILE).
- [ ] **SD-JWT VC** — Bilgilendirici olarak profillenir. _Kaynak:_ §9.4 D. _Durum:_ belirtilmemiş (PROFILE, informative).
- [ ] **OID4VCI 1.0 / OID4VP 1.0 / HAIP 1.0** — Claim girdisi olarak profillenir; sunum yetki değildir. _Kaynak:_ §9.4 D; AP-7. _Durum:_ belirtilmemiş (PROFILE).
- [ ] **OID4VP verifier (RP) — ayrı servis** — Sunum `identity-binding.person`/attribute Claim'i üretir. _Kaynak:_ §10.7.2; IDP-21. _Durum:_ PD.
- [ ] **VC formatları: SD-JWT VC ve mdoc (ISO 18013-5 mDL)** — SD-JWT ADOPT; VC/OID4VCI/OID4VP/HAIP PROFILE. _Kaynak:_ §10.7.2. _Durum:_ belirtilmemiş.
- [ ] **OID4VP same-device ve cross-device (QR) modları, DCQL ile minimum attribute** — _Kaynak:_ §10.7.2; IDP-21. _Durum:_ PD.
- [ ] **EUDI trusted list / LoTL issuer güveni** — Acceptance'ın `schema-definition` ve `actor-binding` girdisi. _Kaynak:_ §10.7.2. _Durum:_ PD.
- [ ] **`loa_eidas=high` yalnız PID sunumundan** — _Kaynak:_ §10.3.2, §10.7.2; IDP-21. _Durum:_ PD.
- [ ] **VC issuer rolü** — _Kaynak:_ §10.7.2; IDP-21. _Durum:_ WATCH.
- [ ] **DID çözümü: `did:web`, `did:jwk` (verifier tarafı)** — Diğer yöntemler WATCH. _Kaynak:_ §10.7.2. _Durum:_ belirtilmemiş (çıkarım; diğerleri WATCH).
- [ ] **eIDAS 2.0 / EUDI Wallet** — Identity plane federasyonu ile; Access'te Claim olarak. _Kaynak:_ §14.9 sektörel tablo. _Durum:_ WATCH (talep üzerine).

#### Sektörel ve bölgesel entegrasyonlar

- [ ] **CAS protokolü** — _Kaynak:_ IDP-33. _Durum:_ WATCH (talep üzerine).
- [ ] **eduGAIN / `eduPerson*` / REFEDS (R&S, SIRTFI, MFA) profilleri** — _Kaynak:_ IDP-33. _Durum:_ WATCH (talep üzerine).
- [ ] **e-Devlet upstream bağlayıcısı (kamu kurumu müşterileri)** — Gelen kimlik actor-binding Acceptance'lı Claim. _Kaynak:_ IDP-34; TN-95. _Durum:_ PD (kapsam).

### K03 Oturum ve token yönetimi

#### Token sınıfları ve karar modeli

- [ ] **Kenar gateway'lerde yalnız kimlik iddiası** — Kenar gateway süreçleri yalnız kimlik iddiası token'ları üretir ve ADP çağırmaz. _Kaynak:_ §9 bölüm notu; IDI-11, P-ID-5. _Durum:_ belirtilmemiş.

#### Sender-constrained token ve DPoP

- [ ] **mTLS vs DPoP seçimi** — M2M/FAPI için mTLS; tarayıcı/mobil/SPA için DPoP. _Kaynak:_ §10.4.3. _Durum:_ belirtilmemiş.

### K04 Hesap yaşam döngüsü ve kurtarma

#### İK kaynaklı yaşam döngüsü ve sağlama

- [ ] **SCIM sağlama/sağlama kaldırma → hesap durumu + Claim** — _Kaynak:_ §12.3.5; TN-75. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Deprovisioning (ücretsiz, tavansız)** — SCIM ve diğer yollarla sağlama kaldırma hiçbir ticari tavana takılmaz. _Kaynak:_ §18.6, §18.7; B3, B19. _Durum:_ belirtilmemiş
- [ ] **AD senkronizasyonu (LDAP çekme varsayılan; SCIM itme ve ajan alternatif)** — Parola için delegasyon ya da SPNEGO. _Kaynak:_ §10.6 tablo, §10.6.4; IDP-17. _Durum:_ Faz 1

### K05 Kiracılık, realm ve B2B organizasyonlar

#### Identity Realm

- [ ] **External IdP ile çalışma** — Bir domain Suiss Identity plane'i hiç kullanmadan yalnız external IdP ile çalışabilir. _Kaynak:_ §9.13.2, §9.17.4. _Durum:_ belirtilmemiş.

#### Kurumsal SSO ve SCIM

- [ ] **SSO zorlaması** — Org RestrictionPolicy + parola/API token/oturum/OAuth süpürmesi; bekleyen davet akıbeti açık; servis hesapları dahil önizleme. _Kaynak:_ §12.3.8; TN-94. _Durum:_ belirtilmemiş (FROZEN önizleme), PD.
- [ ] **SCIM otoriterliği** — SCIM etkinken davetler kapalı/erişim talebine indirgenir; SCIM sağlama kaldırma davetleri iptal eder; `subject-selection` Acceptance (CT3). _Kaynak:_ §12.3.8; TN-95. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Self-servis SSO/SCIM kurulum portalı** — Kurulum bağlantısı veya `<OrganizationSSO />`; Entra/Okta/Google Workspace/ADFS/JumpCloud/OneLogin/Ping sihirbazları + genel SAML/OIDC; alan adı doğrulama, SCIM kurulumu, bağlantı testi; IdP yalnız doğrulanmış alan adlarını kapsar; tek kullanımlık süreli bağlantı; ücretsiz. _Kaynak:_ §12.3.8; TN-134. _Durum:_ FROZEN (kapsam, CT3), PD (sihirbaz listesi).

### K06 Giriş deneyimi, UI bileşenleri ve markalama

#### Özel amaçlı bileşenler

- [ ] **`<OrganizationSSO />` bileşeni** — _Kaynak:_ §12.3.8; TN-134. _Durum:_ belirtilmemiş.

#### Giriş akışı ve yöntemler

- [ ] **Device flow onay ekranında client, konum, kod bağlamı** — _Kaynak:_ §10.4.1. _Durum:_ belirtilmemiş.
- [ ] **FiPA akışında tarayıcıya düşüş (`redirect_to_web`)** — _Kaynak:_ §10.5.2. _Durum:_ WATCH.

#### Onay ve consent ekranları

- [ ] **Federasyon üyeliği rozeti** — Trust mark render'a "doğrulanmış federasyon üyesi" rozeti ekleyebilir; render'dan alan çıkarılamaz. _Kaynak:_ §9.13.8 k.5. _Durum:_ PD.

### K08 Karar, uygulama ve doğrulama

#### İşlem imzalama ve onay ekranı

- [ ] **PSD2 SCA dynamic linking (AAS → H(AAS)), decoupled teslim CIBA** — _Kaynak:_ §10.3.4. _Durum:_ belirtilmemiş.

### K09 Ajanlar ve MCP

#### Ajan yaşam döngüsü, sorumluluk ve iptal

- [ ] **SCIM `/Agents`, `/AgenticApplications` taşıyıcısı** — SCIM üzerinden ajan provisioning; `owners` → ilişki Claim'i, `roles` Grant yazmaz. _Kaynak:_ §2.2.1, §11.17, §11.21.2. _Durum:_ Faz 3 (§2.2.1); WATCH (talep üzerine) (§11.17)

### K10 Yönetişim

#### JML ve offboarding

- [ ] **Upstream grup mapping'i reserved** — Mapping, protocol mapper ve JIT/SCIM kaynak bağlama CT3 requirement'ı taşır. _Kaynak:_ §5.17; C18. _Durum:_ belirtilmemiş

### K11 Yönetim API'si, konsol, SDK'lar ve geliştirici araçları

#### Genişletme noktaları ve entegrasyon yüzeyleri

- [ ] **SSO uygulama kataloğu (50–100 SaaS için SAML/OIDC şablonları)** — Şablon veridir; şablondan bağlantı `idp.*` domain action; L6 reserved requirement. _Kaynak:_ IDP-28. _Durum:_ PD (kapsam, öncelik).
- [ ] **SSO self-servis kurulum portalı** — Ücretsiz. _Kaynak:_ §18.6; D-11; TN-134. _Durum:_ belirtilmemiş.
- [ ] **RAR metadata endpoint'i (SPP görünümü)** — `authorization_details_types_metadata_endpoint` kabul edilen SPP'lerin RAR görünümü olarak sunulabilir. _Kaynak:_ §9.13.8 k.8. _Durum:_ WATCH (talep üzerine).

### K12 Entegrasyonlar ve yardımcı servisler

#### Sinyal girdileri: cihaz, risk, KYC, DLP

- [ ] **Verifiable credentials / status girdisi** — OID4VCI/VP, SD-JWT VC Claim girdisi; Token Status List / Bitstring Status List offline status projection'ı. _Kaynak:_ §4.4 K14. _Durum:_ belirtilmemiş.

#### Dizin, HR ve SCIM

- [ ] **HR / dizin (SCIM gelen) öznitelikleri Claim olarak** — Gerçek dünya kayıtlarının (istihdam vb.) öznitelikleri ve üyelikler SCIM/HR'den Claim olarak alınır; seçim yalnız subject-selection Acceptance'la yapılır. _Kaynak:_ §2.5; §7.3. _Durum:_ belirtilmemiş.
- [ ] **SCIM sağlama (Claim ingest yolu)** — _Kaynak:_ §12.2.2, §12.3.5; TN-43, TN-75. _Durum:_ PD.
- [ ] **SCIM olayları (RFC 9967 URN'leri)** — _Kaynak:_ §12.2.2; TN-43. _Durum:_ PD; WATCH (RFC numaraları).
- [ ] **SCIM `/Bulk` yok** — Bkz. Bilinçli olarak olmayanlar. _Kaynak:_ §12.5.4; TN-125. _Durum:_ belirtilmemiş.
- [ ] **Active Directory ile birlikte çalışma** — Access AD'nin yerine geçmez, AD ile birlikte çalışır. _Kaynak:_ §Kısaca; IDP-38. _Durum:_ belirtilmemiş.

#### SSO ve birlikte çalışabilirlik

- [ ] **IdP'ye özel SSO sihirbazları** — Entra, Okta, Google Workspace, ADFS, JumpCloud, OneLogin, Ping + genel SAML/OIDC. _Kaynak:_ §12.3.8; TN-134. _Durum:_ PD.
- [ ] **Uyumluluk (interop) laboratuvarı** — SCIM istemcileri (Entra, Okta, Google Workspace, OneLogin, JumpCloud) ve SAML SP'leri (Salesforce, ServiceNow, Workday, AWS, Google Workspace, Slack, Zoom, Atlassian, ADFS, Shibboleth SP, SimpleSAMLphp) için CI test matrisi. _Kaynak:_ IDP-40. _Durum:_ PD (liste).
- [ ] **Farklılık profilleri (veri olarak, katalog şablonuna bağlı)** — Profil yalnız biçim farklarını tolere eder. _Kaynak:_ IDP-28; IDP-40. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **Herkese açık uyumluluk tablosu** — Hangi sistem, hangi sürüm test edildi. _Kaynak:_ IDP-40. _Durum:_ belirtilmemiş.
- [ ] **Bildirimden profile süreci** — Her interop sorunu → test vakası + profil. _Kaynak:_ IDP-40. _Durum:_ belirtilmemiş.

#### Federasyon ve envanter görünümü

- [ ] **OIDF trust anchor / schema katalog görünümü** — Opsiyonel, ücretsiz, kabul zorunluluğu yok; registry değil keşif görünümü. _Kaynak:_ §18.9 D9. _Durum:_ belirtilmemiş (D9 recommended default).

### K13 Denetim, kayıt, şeffaflık ve dışa aktarım

#### Identity plane denetim log'u

- [ ] **SAML her imzanın audit'e yazılması; RequesterID audit'i** — _Kaynak:_ §10.6.1. _Durum:_ belirtilmemiş.

#### Dışa aktarım adaptörleri ve akışlar

- [ ] **RFC 9967 SCIM olay profili** — _Kaynak:_ §17.6.8; OP-41. _Durum:_ WATCH.

### K15 Güvenlik ve kriptografi

#### İmza algoritmaları ve hash

- [ ] **SAML algoritmaları** — rsa-sha256 varsayılan; rsa-sha384/512, ecdsa-sha256/384; SHA-1 yalnız uyarı loglayan bayrakla. _Kaynak:_ §10.4.5; §10.6.1. _Durum:_ belirtilmemiş.

#### Anahtar hiyerarşisi ve kapsamı

- [ ] **Domain Metadata OIDF kabında iç nesne ayrı imzalı** — _Kaynak:_ §10.1.7; §10.7.1. _Durum:_ belirtilmemiş.

#### Süreç izolasyonu ve signer

- [ ] **Parser worker izolasyonu** — SAML/XML ve ASN.1 (gerekirse BER/CBOR) yok edilebilir, yetkisiz, anahtarsız worker'da; ağ syscall'ı yok, şemalı IPC, RLIMIT + timeout; bellek bozulması signer'a ulaşmaz. _Kaynak:_ §10.6.1; §13.2; IDP-15; MD-18; OP-2; U43. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Kenar protokol gateway'leri ayrı süreç** — SAML, LDAP, Kerberos, RADIUS, WS-Fed gateway'leri izole süreçlerdir; Kerberos C FFI ayrı imaj varyantında. _Kaynak:_ §2.2.1; §7 giriş; §7.6; §10.6.4; MD-1; P-ID-5. _Durum:_ belirtilmemiş.
- [ ] **Kenar gateway'ler issuer değil** — Gateway başına iç kimlik, mTLS iç kanal. _Kaynak:_ §10.1.2 kural 3; IDP-26. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **Kenar süreçler authority plane'e ve identity deposuna doğrudan yazamaz** — _Kaynak:_ IDI-11; P-ID-5. _Durum:_ belirtilmemiş.

#### Kimlik protokolleri güvenliği

- [ ] **SAML XSW savunması** — Tek ayrıştırıcı, duplicate ID reddi, referans eşitliği. _Kaynak:_ §10.6.1; IDI-8. _Durum:_ belirtilmemiş.
- [ ] **SAML XXE/DoS savunması** — DTD reddi, 1 MB sınırı, sıkıştırma oranı > 100 reddi, derinlik limiti. _Kaynak:_ §10.6.1. _Durum:_ belirtilmemiş.
- [ ] **Golden SAML savunması** — İmza anahtarı HSM/KMS'te, imza audit'i, rutin rotasyon. _Kaynak:_ §10.6.1. _Durum:_ belirtilmemiş.
- [ ] **LDAP güvenliği** — Unauthenticated bind reddi, anonim yalnız RootDSE, DIGEST-MD5 yok. _Kaynak:_ §10.6.3. _Durum:_ belirtilmemiş.
- [ ] **Interop profillerinin güvenlik kontrollerini gevşetememesi** — İmza, süre, audience/recipient, parser izolasyonu. _Kaynak:_ IDP-40. _Durum:_ belirtilmemiş (karar FROZEN).

### K16 Gizlilik, rıza ve uyum

#### Veri minimizasyonu ve seçici açıklama

- [ ] **OID4VP'de DCQL ile veri minimizasyonu** — _Kaynak:_ §10.7.2. _Durum:_ belirtilmemiş.

### K17 Dağıtım, operasyon, yüksek erişilebilirlik ve felaket kurtarma

#### Dağıtım biçimleri ve profiller

- [ ] **Kerberos ayrı imaj varyantı** — _Kaynak:_ §10.6.4; P-ID-5. _Durum:_ belirtilmemiş.

#### Cell topolojisi ve altyapı

- [ ] **Ortak 7 katmanlı kenar altyapı** — Realm çözümleme, IdentitySubject deposu, Claim issuer kanalı, anahtar/HSM soyutlaması, audit, oran sınırı, sağlık/metrik. _Kaynak:_ §10.6. _Durum:_ belirtilmemiş.
- [ ] **Keytab kasada, bellekten yükleme** — _Kaynak:_ §10.6.4. _Durum:_ belirtilmemiş.
- [ ] **SAML metadata otomatik yeniden imza** — _Kaynak:_ §10.6.1. _Durum:_ belirtilmemiş.

### K18 Açık kaynak, ticari model ve paketleme

#### Açık protokol ve yönetişim

- [ ] **Suiss OIDF trust anchor işletebilir (zorunsuz)** — Suiss trust anchor işletebilir ancak bu zorunlu değildir. _Kaynak:_ §9.17 anti-hostage k.3. _Durum:_ belirtilmemiş.

#### Açık kaynak bileşenler

- [ ] **Açık kaynak SAML IdP test süiti (ayrı depo)** — Herhangi bir SAML IdP'yi test eden bağımsız, tarafsız süit (standart uyum, XSW/yorum enjeksiyonu regresyonları, gerçek SP profilleri); ayrı depoda açık kaynak; Access CI'ında her derlemede koşar. _Kaynak:_ B24, D4, IDP-40, OP-62, SA-58, T42. _Durum:_ PD (kapsam ve yayın zamanı); varlık FROZEN.

#### Paketleme

- [ ] **Identity bundle opsiyonel; Enterprise'da varsayılan external IdP** — Authority plane external IdP ile kullanılabilir; authority özelliği/fiyatı Suiss Identity'ye bağlanamaz. Enterprise'da varsayılan external IdP'dir. _Kaynak:_ §2.2; B7, H13, P-ID-2. _Durum:_ belirtilmemiş.

#### Ücretlendirilemez güvenlik ve temel yüzeyler

- [ ] **Kurumsal SSO ücretsiz ("SSO tax" reddi)** — _Kaynak:_ D-11. _Durum:_ belirtilmemiş (D-11 aday).
- [ ] **Self-servis SSO/SCIM kurulum portalı ücretsiz** — _Kaynak:_ §12.3.8, §18.9; TN-134. _Durum:_ belirtilmemiş.

#### Pazara giriş, sertifika ve topluluk

- [ ] **SSO katalogu workforce satışı giriş koşulu** — _Kaynak:_ IDP-28. _Durum:_ PD.
- [ ] **Kerberos "satış kapısı"; protokol sırası satışa göre değişebilir** — _Kaynak:_ §10.6; IDP-25. _Durum:_ PD.

### K19 Geliştirme ve kalite güvencesi

#### Dış conformance süitleri ve interop

- [ ] **Interop laboratuvarı (her sürümde CI)** — _Kaynak:_ IDP-40. _Durum:_ PD.

#### Protokol, kiracı ve bileşen güvenlik testleri

- [ ] **SAML XSW regresyon derlemi ve XML c14n fuzz (öncelik 1), CVE regresyon derlemi** — _Kaynak:_ §10.6.1. _Durum:_ belirtilmemiş.
- [ ] **SAML SP profillerinden 21 aksiyon uygulama planı** — _Kaynak:_ §10.6.1. _Durum:_ belirtilmemiş.

### Bu aşamada doğrulanacak sınırlar

#### Ürün kapsamı

- [ ] **KDC değil; AD'nin yerine geçen Windows domain sunucusu değil** — _Kaynak:_ §10.6.4; IDP-17; IDP-38. _Durum:_ belirtilmemiş.
- [ ] **SCIM desteklemeyen uygulamalar için uygulamaya özel provisioning bağlayıcısı yok** — _Kaynak:_ E22; IDP-29. _Durum:_ belirtilmemiş.
- [ ] **SCIM `/Bulk`'a yatırım yok; Auth0 iş sınırları tekrarlanmaz** — _Kaynak:_ TN-125. _Durum:_ belirtilmemiş.
- [ ] **eduGAIN'e özel yatırım yok; akademik federasyon öncelikli değil** — _Kaynak:_ IDP-33. _Durum:_ belirtilmemiş.
- [ ] **VC issuer rolü yok** — _Kaynak:_ §10.7.2; IDP-21. _Durum:_ WATCH.

#### Kimlik ve protokol

- [ ] **CIBA push modu yok** — _Kaynak:_ §10.5.3; IDP-14. _Durum:_ HYPOTHESIS.
- [ ] **FAPI'de bearer token, public client, `none`/`client_secret_*` auth yok; fapi2'de RSA/PS256 yok** — _Kaynak:_ §10.5.1; IDP-12. _Durum:_ belirtilmemiş.
- [ ] **HRD varsayılan kapalı; istemci ipucu realm politikasını ezmez** — _Kaynak:_ TN-98. _Durum:_ varsayılan kapalı.
- [ ] **SAML kısıtları** — SAML proxy'leme yok; `EncryptedAttribute` üretilmez; PSS/Ed25519 SAML'de üretilmez; `FriendlyName` ile eşleme yok. _Kaynak:_ §10.6.1. _Durum:_ belirtilmemiş.
- [ ] **samael kütüphanesi kullanılmaz** — İç ayrıntı sınırında. _Kaynak:_ §10.6.1. _Durum:_ belirtilmemiş.
- [ ] **LDAP yazma operasyonları yok (salt okunur)** — Add/Delete/ModDN 53 döner; kontrollü LDAP yazma yalnız talep üzerine izlenir. _Kaynak:_ §10.6; §10.6.3; CMP-23.2; IDP-16; IDP-38. _Durum:_ yok; kontrollü yazma WATCH.
- [ ] **LDAP SCRAM ve DIGEST-MD5 yok** — _Kaynak:_ §10.6.3. _Durum:_ belirtilmemiş.
- [ ] **NTLM ve MS-CHAPv2 yok** — _Kaynak:_ §10.6.4; §10.6.5; IDP-17; IDP-18. _Durum:_ belirtilmemiş.
- [ ] **AD hash sync (DCSync) önerilmez** — _Kaynak:_ §10.6.4; IDP-17. _Durum:_ belirtilmemiş.

#### Kimlik doğrulama yöntemleri

- [ ] **Access kendi yöntemleriyle eIDAS "High" iddia etmez** — _Kaynak:_ §10.3.2. _Durum:_ belirtilmemiş.

#### Federasyon, şema ve güven

- [ ] **SCIM provisioning Grant yazmak değil** — _Kaynak:_ §9.4 D; §9.13.8 k.7. _Durum:_ belirtilmemiş.
- [ ] **OIDF trust chain / trust mark kabul değil** — Trust mark onay atlatmaz, render daraltamaz. _Kaynak:_ §9.13; §9.13.8; PI-3. _Durum:_ belirtilmemiş.

#### Güvenlik sertleştirme ve geliştirme süreci

- [ ] **Keycloak bir oracle değildir** — _Kaynak:_ §14.8. _Durum:_ belirtilmemiş.

## Aşama 11 — Entegrasyonlar ve servisler

Forward-auth ve Access Proxy, Linux ve SSH, İK provisioning, İYS izin olayları, PAM/fraud/IGA/SIEM entegrasyonları, Suiss ürünleriyle dikişler.

### K01 Kimlik doğrulama yöntemleri

#### Genel model ve tipli sonuç

- [ ] **Ödeme şablonunda uygulama-kontrollü faktör (TR)** — Ödeme şablonu uygulama-kontrollü faktör sınıfını ister; TR ödeme şablonunda CT2 için phishing-resistant authenticator **ve** uygulama-kontrollü faktör birlikte gerekir. SMS sınırları ve SIM değişikliği kontrolü uygulanır. _Kaynak:_ §9.14.5 k.1; §13.7.3, §14.9; MD-11, SA-54. _Durum:_ belirtilmemiş (SA-54 FROZEN).

#### Passkey / WebAuthn: yöntem ve güvence

- [ ] **W3C SPC (Secure Payment Confirmation) assertion** — Ödeme bağlamında onay assertion'ı SPC ile alınabilir; SPC assertion bir `authentication` Claim'idir. Gösterilen veri canonical render ile eşleşmezse onay olmaz. _Kaynak:_ §9.4 G, §9.4.1. _Durum:_ belirtilmemiş (PROFILE, informative; Pay/Experience owner).

#### OTP, TOTP ve kurtarma kodları

- [ ] **SIM değişimi sonrası 90 gün SIM yöntemi yasağı** — SIM-swap sinyali Claim olarak gelir ve RestrictionPolicy girdisidir. _Kaynak:_ §10.2.2, §10.3.4; IDP-9. _Durum:_ PD.

#### Kenar protokoller ve işletim sistemi girişi

- [ ] **Linux konsol girişi, `sudo` ve `access ssh login` (PAM/NSS)** — PAM ile konsol girişi ve `sudo`, yerel FIDO2 passkey ya da tarayıcı/telefon onayıyla yapılır; `sudo` step-up'tır ve CT'ye göre RequirementTerm uygular. CLI `access ssh login` komutu ve Linux istemci servisi (daemon, PAM ve NSS modülleri) sunulur. _Kaynak:_ §16.4.3a OP-62; IDP-32. _Durum:_ belirtilmemiş (karar FROZEN).

### K02 Kimlik protokolleri ve federasyon

#### Eski protokol gateway'leri (WS-Fed, LDAP, Kerberos, RADIUS)

- [ ] **Kısa ömürlü SSH sertifikası ve Linux PAM/NSS bağlantısı** — Access'te kalan yeteneklerdir; genel sır custody'si ise ayrı ürün katmanıdır. _Kaynak:_ §7.1; IDP-32. _Durum:_ belirtilmemiş.

#### Workload ve cihaz kimliği girdileri

- [ ] **IoT cihaz attestation (Matter DAC/PAI/PAA, BRSKI/EST/MUD, FDO, zero-touch) Claim kaynağı olarak** — Ayrı protokol uygulaması WATCH. _Kaynak:_ §10.9.2. _Durum:_ WATCH.

#### Sektörel ve bölgesel entegrasyonlar

- [ ] **Dış KYC/IDV sağlayıcısından kimlik tespiti Claim'i** — Kim doğruladı, yöntem, IAL/LoA, zaman; requirement/predicate girdisi. _Kaynak:_ §10.3.1, §10.9.1; IDP-34. _Durum:_ belirtilmemiş (karar FROZEN).

### K04 Hesap yaşam döngüsü ve kurtarma

#### İK kaynaklı yaşam döngüsü ve sağlama

- [ ] **İK kaynaklı alım: gelen SCIM, toplu API, CSV yükleme** — İK verisi (departman, unvan, yönetici, tarih, istihdam durumu) İK issuer Claim'i. _Kaynak:_ IDP-35. _Durum:_ gün-1
- [ ] **Hazır İK bağlayıcıları (Workday, SAP SuccessFactors, BambooHR, HiBob, Personio, TR İK yazılımları)** — Ayrı servis, aşamalı. _Kaynak:_ IDP-35. _Durum:_ PD (liste ve sıra)
- [ ] **Passkey kurulum daveti (işe girişte)** — _Kaynak:_ IDP-35. _Durum:_ belirtilmemiş
- [ ] **İleri tarihli başlama/çıkış kayıtlarının otomatik işlenmesi** — _Kaynak:_ IDP-35. _Durum:_ belirtilmemiş

### K06 Giriş deneyimi, UI bileşenleri ve markalama

#### Experience yüzeyleri (S1–S11)

- [ ] **End-customer profili / delegation sayfaları** — One, Work, Pay ve üçüncü taraf ajan uygulamalarının delegation sayfaları gömülü yüzeylerdir. _Kaynak:_ §18.3, §18.8.1 H5. _Durum:_ belirtilmemiş.

#### Offline ve uzun süren iş gösterimi

- [ ] **Kasiyer POS offline görünümü** — "Offline since 14:02 · can act offline until 18:00 · offline limit left: 3 voids, 2,000 TRY". _Kaynak:_ §8.17.5.8. _Durum:_ belirtilmemiş.

#### End-customer ve merchant deneyimi

- [ ] **End-customer deneyimi** — Merchant agent'ı her zaman "AI agent · acting for *M*"; tek seferlik ödeme ve kalıcı merchant yetkisi ayrı fiil ve preview; kalıcı yetkiler görülebilir/iptal edilebilir. _Kaynak:_ §8.17.5.11; X30. _Durum:_ belirtilmemiş.
- [ ] **Tek seferlik ödeme yüzeyi** — "Pay 300 TRY to M, once" exact tutar/alıcı/amaç ile. _Kaynak:_ §8.17.5.11. _Durum:_ belirtilmemiş.
- [ ] **"Kartımı kaydet" — merchant'a kalıcı Grant (S1 end-customer profili)** — "Let *M* charge your card: up to 500 TRY per order, until …". _Kaynak:_ §8.17.5.11. _Durum:_ belirtilmemiş.
- [ ] **"Merchants that can charge you" (S2)** — Kalıcı merchant yetkilerini görme/iptal; scheme artifact Pay'de linkli ayrı nesnedir. _Kaynak:_ §8.11; §8.17.5.11, §8.17.7.2. _Durum:_ belirtilmemiş.
- [ ] **Pay "mandate" satırının Access delegation'ına linki** — "SEPA mandate MR-221 · based on your delegation to *M* (≤ 500 EUR/month)"; iptaller ayrı satır. _Kaynak:_ §8.11. _Durum:_ belirtilmemiş.

### K07 Yetki modeli

#### Grant ve delegasyon

- [ ] **Commitment-scoped Grant** — `while commitment.active` koşulu konur ("Ends with Work commitment *X*"); Work authority'yi bitirebilir, başlatamaz. _Kaynak:_ §7.9.5.4; §8.8, §8.17.5.1, §8.17.7.2; E5 (EI-5), E8. _Durum:_ belirtilmemiş

#### Roller, gruplar ve rule-shaped seçim

- [ ] **İK kaynağı kabulü `subject-selection` Acceptance ve CT3** — _Kaynak:_ IDP-35; TN-95. _Durum:_ belirtilmemiş (karar FROZEN)

#### Requirement'lar, onay ve quorum

- [ ] **Gate satisfied ≠ ALLOW** — Work, Access requirement'ını karşılayamaz. _Kaynak:_ §13.4 G30. _Durum:_ belirtilmemiş

#### Özel yetki alanları

- [ ] **Ödeme authority'si** — initiate, approve, refund, payout, hold-create ve add-beneficiary authority'leri Access'te tutulur; principal'ın koyduğu ödeme limitleri BudgetTerm'dir. _Kaynak:_ §7.9.9.1–2; E21. _Durum:_ belirtilmemiş
- [ ] **Merchant authority** — Müşteri ödeme aracı Anchor'ından merchant'a verilen Grant'tır. _Kaynak:_ §7.9.9.3. _Durum:_ belirtilmemiş

#### Approval Act Statement ve contribution akışı

- [ ] **Work Gate entegrasyonu (opsiyonel)** — AAS `work_gate` ile Work Approval Declaration'ını karşılar; Access Work'ü bilmek zorunda değildir. _Kaynak:_ §9.14, §9.14.1; P29, PI-14. _Durum:_ belirtilmemiş (FROZEN)

### K08 Karar, uygulama ve doğrulama

#### Envelope bağı ve intent

- [ ] **Ödeme envelope'u (Pay)** — amount ≤, recipient =, purpose. _Kaynak:_ §2.7 Pay. _Durum:_ belirtilmemiş.

#### Altyapı PEP'leri (proxy, SSH, Linux)

- [ ] **Forward-auth uç noktası (Nginx `auth_request`, Traefik ForwardAuth, Caddy `forward_auth`, Envoy `ext_authz`)** — Proxy PEP'tir, her istek gerçek Access kararı; karar önbelleği ValidityContract'a bağlı. _Kaynak:_ IDP-30. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **Access Proxy (Envoy veya Caddy motoru)** — Hazır paketlenmiş kapı (Docker imajı, Kubernetes şablonu); tek ayar dosyası, yapılandırma aracı motora (ve Traefik'e) çevirir; iki motor ortak davranış testlerinden geçer. _Kaynak:_ IDP-30. _Durum:_ PD (motor listesi).
- [ ] **Uygulamaya giden kimlik: Access imzalı kısa ömürlü token** — Düz kimlik header'ı yalnız uyumluluk için ve yalnız proxy-üzerinden erişim koşuluyla. _Kaynak:_ IDP-30. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **SSH sertifika otoritesi (kısa ömürlü OpenSSH kullanıcı sertifikası = projection)** — Principal ve kısıtlar (`force-command`, `source-address`) Grant'tan türer; sunucu realm SSH CA'ya güvenir. _Kaynak:_ IDP-32. _Durum:_ PD (ömür).
- [ ] **Linux istemcisi (NSS/PAM daemon, Rust)** — Kullanıcı/grup çözümlemesi, konsol girişi, `sudo` step-up. _Kaynak:_ IDP-32. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **Linux çevrimdışı önbellek ValidityContract horizon'u içinde, aşılırsa fail-closed** — Yerel acil erişim yalnız reserved break-glass Grant ile. _Kaynak:_ IDP-32; MD-8, SI-22. _Durum:_ PD (süreler).

#### Offline doğrulama ve verifier

- [ ] **POS/edge için portable authority artefaktı ve offline slice (Serve)** — Restoran POS/edge cihazlarında Access'e bağlanmadan doğrulanabilen yetki artefaktı; offline pencere ve limit tanımlıdır, revocation exposure profile'a koşulludur. _Kaynak:_ §2.7 Serve; §8.17.5.8; X17. _Durum:_ belirtilmemiş (UNDER DECLARED CAPABILITY).

### K09 Ajanlar ve MCP

#### Ajan kimliği ve modeli

- [ ] **Ajanlara dar kapsamlı kısa ömürlü SSH sertifikası** — _Kaynak:_ IDP-32. _Durum:_ belirtilmemiş

### K10 Yönetişim

#### Onay, quorum ve görevler ayrılığı

- [ ] **Work Gate entegrasyonu** — Intent-bound veya coordination Gate digest'i; Gate satisfied ≠ ALLOW. _Kaynak:_ §7.9.5.3; E7, EI-4. _Durum:_ belirtilmemiş

#### Erişim gözden geçirme ve IGA

- [ ] **IGA entegrasyonu; kararlar Exercise talebi olarak gelir** — Review, certification, role mining, JML ve SoD analizi IGA'dadır; kararlar Exercise talebi olarak gelir; Access who/why/impact sorgularını cevaplar. _Kaynak:_ §7.3, §7.9.12.3, §10.1.1 seam; E22, IDP-39. _Durum:_ belirtilmemiş

### K11 Yönetim API'si, konsol, SDK'lar ve geliştirici araçları

#### Komut satırı ve operasyon araçları

- [ ] **`access ssh login` komut satırı aracı** — Tarayıcıda passkey/MFA ile sertifika alır. _Kaynak:_ IDP-32. _Durum:_ belirtilmemiş.
- [ ] **Access Proxy yapılandırma aracı (tek ayar dosyası → motor ayarı)** — _Kaynak:_ IDP-30. _Durum:_ PD.

#### Genişletme noktaları ve entegrasyon yüzeyleri

- [ ] **Enterprise connector'ları** — _Kaynak:_ §18.3. _Durum:_ belirtilmemiş.

### K12 Entegrasyonlar ve yardımcı servisler

#### Genel entegrasyon ilkeleri

- [ ] **Generic Domain Product sözleşmesi** — Ürün schema yayınlar, domain truth'unu tutar, Claim üretir, PEP'tir ve karar ister; Anchor/Grant/Acceptance yazmaz. _Kaynak:_ §7.9.10.3; E16. _Durum:_ belirtilmemiş.
- [ ] **Yeni ürün yeni ontoloji gerektirmez** — "Suiss Ride" ve "Suiss Health" örnekleriyle sınanmıştır. _Kaynak:_ §7.9.10.3. _Durum:_ belirtilmemiş.
- [ ] **Domain predicate tüketimi (Commerce, Serve, Pay, Money vb.)** — Domain ürünlerinin hesapladığı typed predicate'ler attributable girdi olarak tüketilir; Access yeniden hesaplamaz. _Kaynak:_ §2.6 Test A/C; §2.7. _Durum:_ belirtilmemiş.
- [ ] **Ayrı güvenlik katmanlarının authority kısmına karar** — PAM kasası, fraud motoru, SIEM, DLP ayrı ürün katmanlarıdır; Access yetki kısmına karar verir, olay ve sinyal üretir; entegrasyon ve Access içinde kalan parçalar IDP-39'dadır. _Kaynak:_ §Kısaca; §2.5; E22; IDP-39; L28. _Durum:_ belirtilmemiş.
- [ ] **Yardımcı servislerde ayrıcalıklı yol yok** — Servisler yalnız herkese açık parçaları kullanır; müşteri kendi executor/proxy'sini aynı parçalarla yapabilir. _Kaynak:_ OP-62; B21, B22; E24. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).

#### Work ve koordinasyon

- [ ] **Work seam / coordinator entegrasyonu** — Eligible set, contribution, ExerciseID referansı ve `commitment.active` Claim'i; Work Gate ve dikkat yönetimi yapar, authority yaratamaz ve Access requirement'ını karşılayamaz. _Kaynak:_ §7.3; §7.9.5; §13.2; E7–E9; G30. _Durum:_ belirtilmemiş.
- [ ] **Work entegrasyonu: Gate geçme authority'si** — Work Gate'lerinde onay authority'si ve Gate'i geçme yetkisi Access'tedir; `WorkRef/StepRef/purpose` opak constraint olarak karşılaştırılır. _Kaynak:_ §2.7 Work; F8. _Durum:_ belirtilmemiş.
- [ ] **Work Protocol entegrasyonu (receipt/PAP/export doğrulama)** — Work, herhangi bir conformant Access provider'ın receipt/PAP/export'unu doğrular; ortak regime ve imzalı kayıt ailesi kullanılır. _Kaynak:_ §9.4 H; §9.14.1; §9.17.4. _Durum:_ belirtilmemiş.
- [ ] **Third-party Work-benzeri koordinatör uyumluluğu** — Aynı sözleşmeyle çalışır; compatible coordinator Needs Attention eşdeğeri sunar. _Kaynak:_ §7.9.5.8; §7.9.16; IA-7; X5. _Durum:_ belirtilmemiş.
- [ ] **Work Needs Attention entegrasyonu (tek aksiyon kuyruğu)** — Approval, authority missing, genişletme talebi, quorum katkısı Work item'ı olarak; Access'te "N approvals waiting for you →" linki. _Kaynak:_ §8.17.6.5; IA-1; X5, X6. _Durum:_ belirtilmemiş.
- [ ] **Approval = tek tören, iki kayıt** — Access contribution Exercise + Work Declaration (ExerciseID cite); kısmi başarısızlık dürüst yazılır. _Kaynak:_ §8.17.6.1; X7. _Durum:_ belirtilmemiş.
- [ ] **Pure coordination Gate onayı** — `work.gate.satisfy`; "doesn't give anyone new authority". _Kaynak:_ §8.17.6.1. _Durum:_ belirtilmemiş.
- [ ] **Decline yalnız Work Declaration** — Access'te negatif contribution yok. _Kaynak:_ §8.17.6.1; X7. _Durum:_ belirtilmemiş.
- [ ] **Commitment bağı (Work)** — Envanter satırı CommitmentRef'e link, Work rozetiyle durum. _Kaynak:_ §8.17.7.2; IA-3. _Durum:_ belirtilmemiş.

#### Diğer Suiss ürün seam'leri

- [ ] **One seam** — One Party'sinin domain'e kabulü, user→One Grant'ları ve FOR(user) capacity'si. _Kaynak:_ §7.3; §7.9.6. _Durum:_ belirtilmemiş.
- [ ] **Relay seam** — Access event içeriğini üretir; Relay teslim eder. _Kaynak:_ §7.3; §7.9.8; E30. _Durum:_ belirtilmemiş.
- [ ] **Money / Pay seam ve scheme artefaktları (AP2 / PSD2)** — Pay PEP olarak karar ister; effect attestation Claim'i döner; AP2/PSD2 gibi scheme artefaktları Pay'indir ve GrantID/ExerciseID'ye referans verebilir. _Kaynak:_ §7.3; §7.9.9; §9.4 G; §9.4.1; E21. _Durum:_ belirtilmemiş (Pay PROFILE).
- [ ] **Mevzuat şablonları (PSD2 SCA, TR GKD / TR ödeme)** — Domain'de kurulu şablon kuralları karar yolunda uygulanır. _Kaynak:_ §13.4 U62; MD-11. _Durum:_ belirtilmemiş.
- [ ] **Commerce seam** — Refund authority Grant'ı, `order.refundable` predicate'i, seller membership Claim'i, merchant admin Grant'ı ve `commerce.policy.update` Exercise'ı. _Kaynak:_ §7.3; §7.9.10.1. _Durum:_ belirtilmemiş.
- [ ] **Serve seam** — Void, refund, menu edit, cash drawer ve store admin Grant'ları; `on-shift` Claim'i; offline POS projection'ları. _Kaynak:_ §7.3; §7.9.10.2. _Durum:_ belirtilmemiş.
- [ ] **Cross-product backlog: Work/Executor/Pay/Commerce/IGA/Security seam'leri** — Gate'e çeviri, Needs Attention item türleri, Briefing bölümü, Live üç şerit, Approval Surface profile genişletmesi, Executor paused Claim'leri, verifier applied raporları, Pay limit renderer, Commerce "Why can't I…?", IGA review tüketimi, security dashboard'ları, PEP SDK/sandbox/replay. _Kaynak:_ §8.17.13. _Durum:_ yol haritası (Candidate).

#### Güvenlik ekosistemi: PAM, sır kasası, HSM

- [ ] **PAM entegrasyonu (AuthZEN karar API'si; Teleport ve CyberArk hazır)** — "Kim, hangi koşulla (JIT, approval, süre)" kararı ve SSH sertifikası Access'te; PAM oturumu Exercise referansıyla açılır, oturum kaydı/kasa PAM'dedir. _Kaynak:_ §7.3; §7.6; E22; IDP-39. _Durum:_ PD (liste).
- [ ] **Sır kasası (Vault) entegrasyonu ve sır serbest bırakma kararı** — Genel amaçlı sır kasası ayrı katmandır; sırrın serbest bırakılmasının authority kararı Access'tedir ve release Exercise referansına bağlıdır. _Kaynak:_ §2.5; §7.3; §7.9.12.4. _Durum:_ belirtilmemiş.

#### Sinyal girdileri: cihaz, risk, KYC, DLP

- [ ] **MDM entegrasyonu (posture Claim'i)** — Identity plane, cihaz yönetimi kaynağından gelen `posture.*` Claim'ini requirement/restriction olarak tüketir ("managed browser" gibi kurallarda girdi). _Kaynak:_ §2.5; §2.6; §7.6; §7.9.12.2. _Durum:_ belirtilmemiş.
- [ ] **MDM compliance statement gösterimi** — "Compliant per Acme MDM (statement)". _Kaynak:_ §8.10; §8.17.8.2. _Durum:_ belirtilmemiş.
- [ ] **MDM/posture, KYC/IDV, biyometri, RASP, bot yönetimi sinyalleri Claim olarak** — _Kaynak:_ §10.1.1 seam; §10.9.1. _Durum:_ belirtilmemiş.
- [ ] **Risk / fraud entegrasyonu** — `risk.*` Claim'i DENY, REQUIRE, containment veya ValidityContract kısaltma üretebilir; SSF sinyali veya dış çağrı noktası ile gelir, yalnız daraltır. _Kaynak:_ §7.9.12.1; CI-2; E38; IDP-39; TN-135. _Durum:_ belirtilmemiş (karar FROZEN).
- [ ] **Dış KYC sonucunun Claim olarak kabulü** — Uzaktan kimlik tespiti dış sağlayıcıda yapılır; sonuç Claim olarak kabul edilir. _Kaynak:_ §Kısaca; IDP-34. _Durum:_ belirtilmemiş.
- [ ] **DLP / veri sınıflandırma entegrasyonu** — Label Claim'leri tüketilir; disclosure authority Access'tedir. _Kaynak:_ §7.1; §7.6; F11. _Durum:_ belirtilmemiş.

#### Dizin, HR ve SCIM

- [ ] **HR membership source (Sync from HR)** — Kabul edilmiş membership source'un normal etkisi, rol satırında kaynağıyla gösterilir. _Kaynak:_ §8.6; §8.17.9.8. _Durum:_ belirtilmemiş.
- [ ] **İK bağlayıcı servisi (Access yanında ayrı servis)** — _Kaynak:_ IDP-35. _Durum:_ PD.

#### SSF/CAEP, olay yayını ve Relay

- [ ] **Relay ile semantic event teslimi** — Otomatik; güvenlik teslimata dayanmaz; "notifications delayed" durumu. _Kaynak:_ §8.6; §8.13. _Durum:_ belirtilmemiş.
- [ ] **Relay entegrasyonu (SSF receiver / webhook tüketimi)** — _Kaynak:_ §12.4.2; §17.3.1; E30; TN-136. _Durum:_ belirtilmemiş.
- [ ] **Güvenlik açısından önemli authority olaylarının anlık teslimi** — Yeni alt delegation, yeni domain'e kabul, Instance sonlandırma; "If you didn't expect this: Revoke / Review". _Kaynak:_ §8.6. _Durum:_ PD (varsayılan açık).
- [ ] **Hazır log/olay akışları (Datadog, Splunk, Kafka, AWS EventBridge)** — _Kaynak:_ §12.4.2; TN-136. _Durum:_ yol haritası (WATCH).

#### SIEM

- [ ] **SIEM projection ("copy — not the record")** — SIEM akışı salt-okunur audit projection'ıdır ve `access.audit.export` Exercise'ı veya SSF aboneliği ile sağlanır; SIEM kopyası kaynak değildir. Alan eşlemesi (OCSF) §17'dedir. _Kaynak:_ §7.6; §7.9.12.5; §8.5 S9; §8.12; §9.16.1; AP-14; X22. _Durum:_ belirtilmemiş.
- [ ] **Hazır SIEM akışları / connector'ları (OCSF; Splunk, Sentinel, Datadog, Elastic)** — Vendor-özel connector konfor olarak ücretli olabilir. _Kaynak:_ §18.6; IDP-39; TN-136. _Durum:_ PD (liste).

#### Yardımcı servisler

- [ ] **Access Proxy servisi (Envoy/Caddy paketleri)** — Ayrı servis, yapılandırma aracıyla; forward-auth uç noktası; kiracının kendi proxy'si aynı kararları alır. _Kaynak:_ §18.7 B22; IDP-30; OP-62 `services/proxy/`. _Durum:_ belirtilmemiş (FROZEN STRATEGY).
- [ ] **İYS izin olayı** — Her pazarlama izni değişikliği İYS'nin istediği alanlarla (izin tarihi, kaynak, kanal, alıcı, alıcı türü) olay olarak yayınlanır; Relay bağlıysa İYS'ye Relay yazar ve kayıt durumu Access'e geri bildirilir, değilse kiracı olayı kendi İYS entegratörüne iletir. _Kaynak:_ §18.7 B23; IDP-37; E40. _Durum:_ belirtilmemiş (FROZEN STRATEGY).
- [ ] **Linux client servisi (daemon, PAM, NSS)** — _Kaynak:_ IDP-32; OP-62. _Durum:_ belirtilmemiş.

### K13 Denetim, kayıt, şeffaflık ve dışa aktarım

#### Dışa aktarım adaptörleri ve akışlar

- [ ] **Export adaptörleri** — OCSF + Parquet (S3/Security Lake), SET push/poll, CAEP/SSF, OTLP log, HTTP olay toplayıcı, syslog/CEF/LEEF; OCSF denetim akışı dışa aktarımı dahil. _Kaynak:_ §17.6.8; IDP-39; OP-41. _Durum:_ PD (adaptör seti).
- [ ] **OCSF IAM alan hizalaması** — Kanonik şema Access'indir; OCSF alan adlarıyla hizalanır. _Kaynak:_ §17.6.8; OP-41. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **SIEM projection ("copy — not the record")** — _Kaynak:_ §17.6.8, §17.6.13; X22. _Durum:_ belirtilmemiş.

### K14 Sinyaller, gözlemlenebilirlik ve analitik

#### Dikkat, bildirim ve onay yükü

- [ ] **Semantik bildirim ihtiyacı (Relay'e)** — Step-up gerekli, onaylayıcı gerekli, güvenlik müdahalesi, authority iptal/daraltma: kime, neden, hangi intent'e bağlı, ne zamana kadar. _Kaynak:_ §2.7 Relay. _Durum:_ belirtilmemiş.

### K15 Güvenlik ve kriptografi

#### Revocation ve olay müdahalesi

- [ ] **Access unavailable + acil durdurma** — "Authority can't be changed right now. You can still ask the runtime to pause (Work control)". _Kaynak:_ §8.13. _Durum:_ belirtilmemiş.

### K16 Gizlilik, rıza ve uyum

#### İfşa kapsamı ve görünürlük

- [ ] **Müşteriye merchant iç kararları açıklanmaz** — Ne gösterileceği merchant'ın kararıdır. _Kaynak:_ §8.17.5.11. _Durum:_ belirtilmemiş.

#### Rıza ve izinler

- [ ] **Consent (contribution sınıfı) vs scheme consent ayrımı** — PSD2/OB consent Pay UI'ında yönetilir, Grant'a link ile bağlanır. _Kaynak:_ §8.11. _Durum:_ belirtilmemiş.
- [ ] **Pazarlama izni İYS kaydı** — Relay üzerinden (B23); bkz. İYS izin olayı. _Kaynak:_ §18.7 B23. _Durum:_ belirtilmemiş.

#### Mevzuat ve standart eşlemeleri

- [ ] **PSD2 SCA desteği** — _Kaynak:_ §10.3.4; §18.2; H17. _Durum:_ belirtilmemiş.

### K17 Dağıtım, operasyon, yüksek erişilebilirlik ve felaket kurtarma

#### Dağıtım biçimleri ve profiller

- [ ] **Access Proxy paketleri (Docker imajı, Kubernetes şablonu)** — _Kaynak:_ IDP-30. _Durum:_ PD.

### K18 Açık kaynak, ticari model ve paketleme

#### Paketleme

- [ ] **Zorunlu bundle yok; standalone satış** — Work/One/Pay ile zorunlu bundle yok; standalone fiyat listesi yayınlanır. _Kaynak:_ B8, D8. _Durum:_ belirtilmemiş.
- [ ] **Packaging ≠ ownership** — Admin konsolu Work Gate'i gömülü gösterebilir. _Kaynak:_ §8.17.9.5. _Durum:_ belirtilmemiş.

### K19 Geliştirme ve kalite güvencesi

#### Dış conformance süitleri ve interop

- [ ] **Access Proxy iki motor ortak davranış testleri** — _Kaynak:_ IDP-30. _Durum:_ belirtilmemiş.

### Bu aşamada doğrulanacak sınırlar

#### Ürün kapsamı

- [ ] **Bitişik güvenlik ürünleri Access'te ve ayrı Suiss servisi olarak yok** — PAM oturum aracılığı/kaydı (SSH/sunucu dahil), genel sır kasası ve credential injection, DLP/sınıflandırma/label, SIEM arama/korelasyon, MDM, genel risk/fraud skorlama motoru, IGA (kampanya tabanlı access review, rol madenciliği, çok aşamalı onay, SoD raporlaması) Access'te bulunmaz; bunlar için ayrı Suiss servisi de yazılmaz. _Kaynak:_ §7.6; §8.17.12; E22; F11; IDP-32; IDP-39; L28. _Durum:_ belirtilmemiş.
- [ ] **Payment mandate ≠ Access Mandate; Pay authorization ≠ ALLOW; network token ≠ authority** — _Kaynak:_ §7.9.9.3; E21. _Durum:_ belirtilmemiş.
- [ ] **KYC uygulaması değil; IAL3 IDV yok** — NFC kimlik, yüz eşleştirme, canlılık, uzaktan tespit yapılmaz. _Kaynak:_ §10.3.1; IDP-34. _Durum:_ belirtilmemiş.
- [ ] **Access Proxy motoru sıfırdan yazılmaz** — _Kaynak:_ IDP-30. _Durum:_ belirtilmemiş.
- [ ] **Access İYS'ye doğrudan yazmaz** — İYS'ye yalnız Relay yazar; Relay yoksa kiracının entegratörü. _Kaynak:_ IDP-37; B23. _Durum:_ belirtilmemiş.

#### Yetki modeli

- [ ] **Risk motoru kalıcı otomatik kilit koymaz; risk authority yaratmaz** — _Kaynak:_ TN-46. _Durum:_ belirtilmemiş.

#### Onay ve kanıt

- [ ] **Work Gate Access requirement'ını karşılayamaz, DENY'ı aşamaz** — _Kaynak:_ E7; EI-4. _Durum:_ belirtilmemiş.

## Aşama 12 — Yönetişim

Yetki gözden geçirme, JML, SoD, destek erişimi, break-glass, devredilmiş yönetim, onay yüzeyi.

### Spec dışı ön koşullar

- [ ] **Destek vaka sistemi bağlayıcısı** — destek Grant'ındaki PurposeRef'in (vaka numarası) doğrulanması.

### K01 Kimlik doğrulama yöntemleri

#### Push ile doğrulama

- [ ] **Login push ≠ authority onayı (ayrı bildirim şablonları)** — Login push bir identity plane ceremony'sidir; bildirim içi authority onayı ayrı kurala (CT1 + H(AAS)) tabidir ve aynı şablonu paylaşmaz. _Kaynak:_ §8.6, §8.17.11.4; X-L7. _Durum:_ belirtilmemiş.

#### Step-up ve yeniden doğrulama

- [ ] **Assurance gereğinin somut eyleme çevrilmesi** — Approval'da gereken assurance (human presence, phishing-resistant, freshness) "Confirm with your passkey" gibi somut eylemle gösterilir. _Kaynak:_ §8.17.6.3. _Durum:_ belirtilmemiş.

### K02 Kimlik protokolleri ve federasyon

#### Uç noktalar

- [ ] **Endpoint: `GET`/`POST /consent` (proxy senaryosu)** — Approval Surface; proxy senaryosunda MUST. _Kaynak:_ §11.4.5, §11.6. _Durum:_ belirtilmemiş.

#### Token exchange ve delegasyon

- [ ] **Destek erişiminde `sub` + `act` (delegation biçimi)** — Token daima özneyi (`sub` = kullanıcı) ve eylemde bulunanı (`act` = operatör) taşır; `act` ipucudur, lineage doğrular. _Kaynak:_ §8.16 değişmez #1; §12.3.4; L22; TN-70. _Durum:_ belirtilmemiş (FROZEN; model BY SEMANTICS).

### K03 Oturum ve token yönetimi

#### Token içeriği ve claim'ler

- [ ] **Destek erişimi için standart `at+jwt` delegation biçimi** — `sub` = kullanıcı, `act` = operatör; authority RAR'dadır, ayrı token tipi yoktur. _Kaynak:_ §11.21.3; MD-9, TN-70, TNI-13. _Durum:_ belirtilmemiş.

### K04 Hesap yaşam döngüsü ve kurtarma

#### Genel çerçeve ve veri modeli

- [ ] **`is_breakglass` hesap niteliği (birinci sınıf, izinli, alarmlı)** — Bayrak authority üretmez. _Kaynak:_ F19; MKT-D11. _Durum:_ belirtilmemiş

#### İK kaynaklı yaşam döngüsü ve sağlama

- [ ] **Ayrılan çalışan: anında askı, oturum kapatma, CAEP sinyali, ajan askısı, veri saklama** — _Kaynak:_ IDP-35; AG-41, TN-H5. _Durum:_ belirtilmemiş (karar FROZEN)
- [ ] **Hareket eden çalışan (mover) birikmesinin kesilmesi** — Rule-shaped holding episode modeliyle seçim düşünce episode kapanır; extensional Grant'lar için offboarding'de açık seçim. _Kaynak:_ §12.3.5; TN-75. _Durum:_ belirtilmemiş (FROZEN)

### K05 Kiracılık, realm ve B2B organizasyonlar

#### Kiracılık kavramlarının UI ve yönetimde görünümü

- [ ] **Kiracı başı FGAP bayrağı / devredilmiş yönetim dersleri** — Hiyerarşi taşımada iki uçta izin, credential sahip alanı değişmez, mapper'lar yükseltme yüzeyidir (atıf). _Kaynak:_ §8.17.9.8 notu; TN-Y2; X20. _Durum:_ belirtilmemiş.

### K06 Giriş deneyimi, UI bileşenleri ve markalama

#### Özel amaçlı bileşenler

- [ ] **Destek erişimi talep/onay bileşeni** — _Kaynak:_ §12.3.4; TN-137. _Durum:_ belirtilmemiş.

#### Deneyim invariant'ları

- [ ] **WYSIWYS: exact intent yoksa onay yok** — Onay yüzeyleri yalnız kabul edilmiş schema'dan, AAS'ten deterministik typed render yapar; `render_digest` render'dan hesaplanır, `material_fields` görünür olmak zorundadır; digest'e uymayan içerik onaylanamaz. _Kaynak:_ §6.4; §9.14.5 k.1; §10.5.4; P58; PI-17; XI-8. _Durum:_ belirtilmemiş (FROZEN, türetilmiş).

#### Experience yüzeyleri (S1–S11)

- [ ] **S3 Approval Surface (trusted, Work Gate ile ortak)** — Onay için conformant yüzey (Suiss veya üçüncü taraf); AAS'yi kurar, exact intent, sıfat, render ve material field'ları gösterir; sonuç `contribute(approve, digest)` + Work Declaration. _Kaynak:_ §8.5; §9.14, §9.14.1; AP-6; X3, X7. _Durum:_ belirtilmemiş.

#### Onay ve consent ekranları

- [ ] **Material fields ve effect class** — Effect class'a göre gösterilmesi zorunlu materyal alanlar (Work ile aynı küme). _Kaynak:_ §9.13.3, §9.14. _Durum:_ belirtilmemiş.

#### Onay sınıfları (CT) ve conformance

- [ ] **Approval Surface conformance** — CT1 conformant (Acceptance'lı); CT2 conformant tam render; CT3 tam render + quorum varsa ≥1 contribution bağımsız surface'ten. _Kaynak:_ §13.7.3; U7. _Durum:_ PD.
- [ ] **CT3 için bağımsız Approval Surface render yolu** — Suiss-hosted domain'lerde CT3 için bağımsız (Suiss dışı veya platform-trusted) render yolu sunulur. _Kaynak:_ §13.2 (custody ≠ root paragrafı). _Durum:_ PD.
- [ ] **Bildirim içi hızlı onay (yalnız CT1)** — Conformant tam render + H(AAS) ile bildirimden onay yalnız CT1'de; CT2/CT3'te yok. _Kaynak:_ §13.7.3; SEC26. _Durum:_ PD.
- [ ] **Batch onay (yalnız CT1)** — ≤10 item, aynı requester + action class, item başına ayrı AAS + assertion; CT2/CT3'te yok. _Kaynak:_ §13.7.3; SEC26. _Durum:_ PD.

### K07 Yetki modeli

#### Roller, gruplar ve rule-shaped seçim

- [ ] **Rule-shaped Grant ile departman/unvana göre temel yetkiler (JML)** — Pozisyon değişiminde otomatik seçim; reserved/CT3 Grant'ta 24 saat soğuma. _Kaynak:_ IDP-35; C13, TN-109. _Durum:_ belirtilmemiş (karar FROZEN)

#### Özel yetki alanları

- [ ] **Exceptional authority (break-glass, legal order, containment) reserved Grant** — İstisnai yetki yalnız önceden verilmiş, reserved, requirement'lı, süreli Grant olarak vardır. _Kaynak:_ §13.4 G29; F19, INV-28. _Durum:_ belirtilmemiş

#### Tenant, göç ve devredilmiş yönetim

- [ ] **Devredilmiş yönetim = meta-action Grant'ları** — Realm başına kademeli açma bayrağı vardır; otomatik v1→v2 göç vaadi yoktur. _Kaynak:_ §12.5.2; TN-114. _Durum:_ FROZEN (model), PD (bayrak)

### K08 Karar, uygulama ve doğrulama

#### İşlem imzalama ve onay ekranı

- [ ] **CT3 bağımsız render yolu gereksinimi** — CT3 işlemler için onay ekranının bağımsız render yolu gereksinimi Access'te tanımlanır. _Kaynak:_ §2.5. _Durum:_ belirtilmemiş.
- [ ] **Authority onayı push bildiriminde yalnız CT1 + H(AAS)** — CT2+ için bildirim içi onay yok. _Kaynak:_ §12.4.1; TN-100. _Durum:_ belirtilmemiş (FROZEN).

### K10 Yönetişim

#### Destek erişimi: model

- [ ] **Destek erişimi = kullanıcının FOR(P) delegasyon Grant'ı (impersonation yok)** — Destek personeli kullanıcının kimliğine bürünemez, kullanıcının KeyBinding'iyle AIS üretemez ve kullanıcı olarak oturum açamaz; kendi Instance'ıyla, kullanıcının süreli, dar, iptal edilebilir ve kaskad eden (CT2 `grant.issue`) FOR(kullanıcı) Grant'ının Exercise'ıyla çalışır (alternatif basis: reserved break-glass Grant). Her eylem operatörün Instance'ına attribute edilir; Grant revoke/süre sonu ile durur. _Kaynak:_ must-never #19; §2.2.2 #4, §5.7, §7.1, §7.3, §8.16, §10.2.6, §12.3.4, §13.2, §13.4 G53; E37, INV-28, MD-9, TN-70, TNI-13, X37. _Durum:_ belirtilmemiş (FROZEN, §12.3.4; X37 PROPOSED FOR FREEZE)
- [ ] **Destek erişimi projection'ı (`sub` = kullanıcı, `act` = operatör)** — `act` zorunludur; standart `at+jwt` ve RFC 8693 delegation biçimi kullanılır; reserved Grant + AAS ile verilir. _Kaynak:_ §9.9.4, §11.21.3; MD-9, P53, TN-70, TNI-13. _Durum:_ PD (wire); FROZEN (türetilmiş)
- [ ] **12 destek değişmezi** — `sub`/`act`; ayrıcalık kesişimi; yasak liste `idp.account.*` reserved; typed gerekçe zorunlu; ≤60 dk; eylem başı denetim; özneye bildirim; kullanıcı yasaklayabilir; derinlik 0; Grant yoksa DENY; öznenin oturumları etkilenmez; artefakt redaksiyonu. Destek Grant'ı süreli, kayıtlı ve kullanıcıya görünür. _Kaynak:_ §2.2.2 #4, §5.7, §12.3.4, §13.4 U57; E37, MD-9, MKT-D8, TN-71 (§8.16'ya atıf). _Durum:_ PD (şablon), FROZEN (1,2,6,10,11)
- [ ] **Destek erişimi hedefi: `idp.account.*` action namespace'i** — `read`, `profile.update`, `credential.*`, `email.change`, `delete`, `export`; kaynakların root'u kullanıcının self-anchor'ı; yasak eylemler reserved bayraklı. _Kaynak:_ §8.16, §12.3.4; E34. _Durum:_ belirtilmemiş
- [ ] **Destek: ayrıcalık kesişimi** — Destek Grant'ı ⊆ kullanıcının holding'i; operatörün OWN authority'si basis olamaz. _Kaynak:_ §8.16 #2. _Durum:_ belirtilmemiş (BY SEMANTICS)
- [ ] **Destek: yasak işlem listesi (reserved `idp.account.*`)** — Credential/MFA değişimi, birincil e-posta/telefon, hesap silme, ödeme, toplu export, rol yükseltme, davet, yeni API anahtarı/uzun ömürlü token; bu eylemler namespace'te reserved bayraklıdır. _Kaynak:_ §8.16 #3; E34. _Durum:_ PD (şablonda dışlama)
- [ ] **Typed PurposeRef (vaka referansı) zorunlu** — Authority taşıyan alan typed PurposeRef'tir; serbest metin gerekçe redakte edilebilir gövdede, WorkRef'te veya vaka sisteminde durur. _Kaynak:_ §5.3, §8.16 #4, §12.3.4; E37, TN-73. _Durum:_ PD (zorunluluk); typed alan FROZEN
- [ ] **Destek: mutlak tavan 60 dk, uzatma yeni rıza** — _Kaynak:_ §8.16 #5. _Durum:_ PD
- [ ] **Destek: başlangıç/bitiş/eylem başına denetim, operatöre atıf** — _Kaynak:_ §8.16 #6. _Durum:_ belirtilmemiş (BY SEMANTICS)
- [ ] **Destek: özneye bildirim** — Changes + Relay anlık teslim. _Kaynak:_ §8.16 #7; SI-21. _Durum:_ PD (anlık teslim açık)
- [ ] **Destek: kullanıcı yasaklayabilir (self-restriction)** — Rıza yolunda varsayılan yok; self-restriction break-glass'ı da daraltır (beyanlı muafiyet yoksa). _Kaynak:_ §8.16 #8. _Durum:_ PD
- [ ] **Destek: özyinelemeli devretme yok (depth 0)** — "Can pass on: No" sabit. _Kaynak:_ §8.16 #9. _Durum:_ PD
- [ ] **Destek: Grant yoksa DENY** — _Kaynak:_ §8.16 #10. _Durum:_ belirtilmemiş
- [ ] **Destek: kullanıcının oturumlarını etkilemez** — Operatör Instance'ı ayrı; revoke kullanıcı oturumlarına dokunmaz. _Kaynak:_ §8.16 #11. _Durum:_ belirtilmemiş
- [ ] **Destek artefaktı redaksiyonu** — HAR/log/ekran kaydı ayrı Grant ile okunur; token/çerez alanları yüklemede otomatik redakte. _Kaynak:_ §8.16 #12, §12.3.4; TN-74. _Durum:_ PD (UNDER DECLARED CAPABILITY)
- [ ] **OrgPolicy rızası yalnız FOR(org)** — Yalnız organizasyonun kendi kaynaklarında geçerlidir; DualApproval → contribution term; BreakGlass → reserved Grant. _Kaynak:_ §5.7, §12.3.4; INV-4, MD-9, TN-72. _Durum:_ belirtilmemiş (FROZEN)

#### Destek erişimi: deneyim

- [ ] **Destek erişimi deneyimi akışı** — Talep (S1: "Give *Acme Support* access…"), aktif (S2 Acting for you + operatör banner'ı), kullanım (S6), bitiş, break-glass. _Kaynak:_ §8.16 Deneyim. _Durum:_ belirtilmemiş
- [ ] **"Request support access" / "Emergency access (break-glass)"** — Impersonation yerine kullanılan arayüz eylemleri. _Kaynak:_ §8.10. _Durum:_ belirtilmemiş
- [ ] **Destek erişimi: tek tıkla talep ve onay** — Uygulama içi/e-posta/push onay isteği. _Kaynak:_ §12.3.4; TN-137. _Durum:_ PD (kanallar)
- [ ] **Önceden süreli destek izni** — Kullanıcı hesap ayarlarında (ör. 24 s) destek izni açar. _Kaynak:_ §12.3.4; TN-137. _Durum:_ PD
- [ ] **B2B destek: organizasyon kaynaklarına önceden erişim** — _Kaynak:_ §12.3.4; TN-137. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **"Kullanıcının gözünden gör" salt okuma modu** — Yazma ve consumption-bearing action yok; okuma kayda girer. _Kaynak:_ §12.3.4; TN-137. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Operatör kalıcı banner'ı** — "Acting for Ayşe K. with her support access (case #4411) · read-only · ends 15:30 · every action is recorded under your name". _Kaynak:_ §8.16; X37. _Durum:_ belirtilmemiş

#### Break-glass (authority düzeyi)

- [ ] **Break-glass = önceden verilmiş reserved Grant (≥2)** — Acil durum erişimi önceden verilmiş, reserved, requirement'lı, zaman sınırlı Grant'larla (en az 2; ayrı Party/Instance; yalnız bulut; Joint(k) seçeneği) yapılır; expiry her zaman çalışır. Örnek: "Emergency access: Security on-call can terminate any instance for 4 hours after 2 approvals". Destek erişimi için de bir yoldur. _Kaynak:_ F19; §5.7, §5.8, §8.16, §8.17.9.4, §9.9.4, §12.3.8; INV-28, MD-9, TN-93. _Durum:_ FROZEN (model), PD (operasyon)
- [ ] **Break-glass operasyon disiplini ve 90 gün tatbikatı** — En az 2 hesap, farklı phishing-resistant yöntem, kritik alarm; üç aylık muafiyet testi, personel ayrılışında kasa rotasyonu, "drill" PurposeRef. _Kaynak:_ §5.7, §6.2, §12.3.8; INV-28, TN-93. _Durum:_ PD
- [ ] **Break-glass hesabı (SSO'dan bağımsız, donanım anahtarlı, kullanımı alarm üretir)** — _Kaynak:_ §10.2.5, §10.2.6. _Durum:_ belirtilmemiş
- [ ] **Break-glass kullanım alarmı ve sınıflandırma** — En yüksek önem alarmı; tatbikat/acil/suistimal sınıflandırması; CT3 %100 örnekleme. _Kaynak:_ §12.3.8; TN-93. _Durum:_ PD
- [ ] **Break-glass politika muafiyeti beyanı (CT3)** — Muafiyet yalnız RestrictionPolicy içeriğinde beyanlıdır ve yalnız engelleyici politikalardan; muafiyeti beyan eden `policy.set` CT3'tür; self-restriction muafiyeti yalnız rootTerms'te beyanlıysa. Break-glass kendi zaman sınırı + zorunlu sonradan inceleme taşır. _Kaynak:_ §5.7, §5.8, §12.3.8, §12.6, §13.7.1, §13.7.3; TN-71 #8, TN-93. _Durum:_ belirtilmemiş (FROZEN); PD (§13.7)
- [ ] **Break-glass kullanımında `notify-subject` requirement'ı** — "*Acme Security* used emergency access on your account (incident #…)". _Kaynak:_ §8.16, §12.3.4; INV-28, TN-71 #7. _Durum:_ belirtilmemiş (UNDER DECLARED POLICY)
- [ ] **İstisnai yetki (legal order, emergency, incident)** — Yalnız önceden verilmiş reserved Grant'ların Exercise'ıdır. _Kaynak:_ §6.1, §6.2, §6.6; CI-13, SI-22. _Durum:_ belirtilmemiş
- [ ] **Authority acil durumu Exercise yoluyla** — Örn. Security Party'nin narrowing `policy.set`'i. _Kaynak:_ §17.7.3; RT3, RT9. _Durum:_ belirtilmemiş
- [ ] **Exercise dışı kill switch yok** — _Kaynak:_ §8.17.9.4. _Durum:_ belirtilmemiş

#### Operatör break-glass (altyapı)

- [ ] **Operatör break-glass yolu (ayrı kod yolu)** — Her cell'de ayrı, DB'den bağımsız altyapı erişimi (config okuma, sağlık, feature flag, toptan `session_epoch` artırımı, leader'ı sağlıksız işaretleme); authority kararı üretemez/yazamaz, kullanıcı verisine erişemez; authority düzeyinde break-glass yalnız G29 yoluyla. _Kaynak:_ CMP-25; §13.4 G63, §17.7.3; OP-46, SI-22. _Durum:_ belirtilmemiş (FROZEN kapsam, PD süreler)
- [ ] **Break-glass: bağımsız kod yolu ve asgari bağımlılık** — Rate limiter/risk/MFA çağrılmaz; DB/Redis/dış IdP bağımlılığı yok. _Kaynak:_ §17.7.3 ilke 1–2; OP-46. _Durum:_ belirtilmemiş
- [ ] **Break-glass: donanım anahtarı / M-of-N çevrimdışı kimlik** — FIDO2 açık anahtarları veya M-of-N imzalı kısa ömürlü belge; ağ çağrısız doğrulama. _Kaynak:_ CMP-25; §17.7.3 ilke 3–4. _Durum:_ belirtilmemiş
- [ ] **Break-glass: silinemez iz ve alarm** — Yerel dosya + syslog + SIEM; bütün nöbetçilere alarm; her kullanım alarm. _Kaynak:_ §17.7.3 ilke 6–7, §17.8.2. _Durum:_ belirtilmemiş
- [ ] **Break-glass: 15 dk tek kullanım, rotasyon, çeyreklik tatbikat, hücre başına kimlik** — _Kaynak:_ §17.7.3 ilke 8–10; OP-57 madde 9. _Durum:_ PD (süreler)
- [ ] **Operatör erişim log'ları** — DB okuma, HSM kullanımı loglanır; operatör authority state'e yazamaz. _Kaynak:_ §17.8.2; SEC19. _Durum:_ belirtilmemiş

#### Onay, quorum ve görevler ayrılığı

- [ ] **Quorum deneyimi** — "needs 2 of {CFO, Treasurer, CEO} · not the requester · different devices"; aynı Party'nin iki onayı bir sayılır; aggregate threshold "counts as one approval". _Kaynak:_ §8.17.6.4. _Durum:_ belirtilmemiş
- [ ] **SoD (görevler ayrılığı) = independence term** — `contributor ≠ actor principal`; `approve:<class>` Grant'larında başka principal'dan contribution yalnız domain SoD beyan ettiğinde (org şablonu) zorunlu. _Kaynak:_ §2.4, §5.9, §13.7.3; SEC10. _Durum:_ PD (§13.7.3)
- [ ] **Independence şartlarının görünürlüğü** — "Different people, different devices"; "independent" kelimesi kullanılmaz. _Kaynak:_ §8.10, §8.17.6.3. _Durum:_ belirtilmemiş (UNDER DECLARED POLICY)
- [ ] **Governance quorum'ları coordinator'da (Work Gate veya IGA)** — Access'te pending change / istek kuyruğu yok. _Kaynak:_ §8.17.9.5, §12.5.2; C26, X5. _Durum:_ belirtilmemiş
- [ ] **Approver'lar koltuksuz katılım** — Approval Surface'ten katılım koltuk gerektirmez. _Kaynak:_ §18.5, §18.7 B5. _Durum:_ belirtilmemiş

#### Erişim gözden geçirme ve IGA

- [ ] **Access review / IGA access review veri desteği** — Erişim gözden geçirmeleri aynı authority semantiği üzerindedir; Access "who/why/revoke impact" sorgularını sağlar, reviewer kararı Exercise'tır; kampanya UX'i Access'te değil. _Kaynak:_ §2.4, §8.17.12, §8.17.13. _Durum:_ belirtilmemiş
- [ ] **Review sonucunun authority-sensitive action olması** — Gözden geçirme sonuçları authority-sensitive action olarak uygulanır (rubber-stamp'e karşı). _Kaynak:_ LFP-18. _Durum:_ belirtilmemiş
- [ ] **Temel yetki gözden geçirme kampanyaları** — Yöneticiye ekibinin Grant'ları sunulur; "kalsın" onay kaydı, "kaldır" `grant.revoke` Exercise'ı; kampanya authority üretmez. _Kaynak:_ IDP-39. _Durum:_ belirtilmemiş (karar FROZEN)
- [ ] **Envanter hijyeni** — Kullanılmayan, süresi yaklaşan, geniş delegation'lar Briefing/Changes'da. _Kaynak:_ §8.17.12. _Durum:_ belirtilmemiş

#### JML ve offboarding

- [ ] **JML uçtan uca (İK → işe giren / pozisyon değiştiren / ayrılan)** — Joiner-Mover-Leaver olaylarına dayalı yetki değişiklikleri. _Kaynak:_ §2.4; IDP-29, IDP-35. _Durum:_ belirtilmemiş (karar FROZEN)
- [ ] **HR/SCIM kaynaklı mover/leaver etkisi (rule-shaped kapanış)** — Üyelik Claim'i değişince rule-shaped Grant holder'ı bırakır ("E's Finance role ended (HR, 6 Oct)"; doğrudan Grant'lar kalır uyarısı). Rejoin yeni episode açar ve eski Mandate pin'i explicit rebind ister. _Kaynak:_ §7.9.13 satır 13–15, §8.6, §8.17.9.6; INV-31. _Durum:_ belirtilmemiş
- [ ] **Offboarding sayfası: kanal başına açık seçim** — Doğrudan Grant'lar, Instance'lar, rule-shaped holding'ler, self-anchor, yeniden giriş için explicit disposition; varsayılan yok; "Offboarded" yalnız commit sonrası. _Kaynak:_ §8.17.9.6, §12.3.5; E6, TN-75, X20. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Ajan sorumlusu ayrılınca otomatik askı (JML bağlantısı)** — SCIM sağlama kaldırma / hesap devre dışı → ajan askıya (K09'da da var). _Kaynak:_ AG-41. _Durum:_ belirtilmemiş (FROZEN)

#### Ayrıcalıklı erişim ve süreli yetki

- [ ] **PAM authority kısmı / JIT elevation** — Ayrıcalıklı erişimin JIT aktivasyonu, onay eşiği ve süreli yetkisi authority plane'dedir; JIT elevation = requirement'lı standing Grant + Gate (PIM/Teleport uyarlaması). _Kaynak:_ §2.5, §4.5, §8.17.12. _Durum:_ belirtilmemiş

#### Olay müdahalesi ve containment

- [ ] **Containment** — Restriction yetkili Party tek bir narrowing Exercise'ıyla, quorum olmadan kısıtlar; SOC containment reserved Grant ile yapılır. _Kaynak:_ §6.6, §7.9.12.1; SI-4. _Durum:_ belirtilmemiş
- [ ] **Olay müdahalesi (incident response) runbook** — Containment Exercise → cihaz → oturum → token; `party.compromise` overlay (occurredAt bilinmiyorsa 72 s geri); açık pencere dürüstçe gösterilir. _Kaynak:_ §12.2.4; TN-48. _Durum:_ PD (runbook), FROZEN (SI-4, SI-22)

#### Ekosistem sınırından gelen kurallar

- [ ] **Güvenilir onay yüzeyi** — Onayda sorumluluklar ayrıdır: Access tam onay yetkisini, digest'i ve assurance'ı; onay yüzeyi sadık render'ı ve kullanıcı eylemini; Work/domain onayın nedenini; Executor/domain etkiyi sahiplenir. Genel bildirim veya ajan metni onay artefaktı sayılmaz. _Kaynak:_ §7.4; E32. _Durum:_ belirtilmemiş (FROZEN).

### K11 Yönetim API'si, konsol, SDK'lar ve geliştirici araçları

#### Yönetim yazma yolu ve yetki modeli

- [ ] **Delege yönetim** — Yönetim yetkisinin alt yöneticilere devredilmesi. _Kaynak:_ §2.2.1. _Durum:_ belirtilmemiş.

#### Konsol: rol, kaynak ve domain ekranları

- [ ] **Exact typed preview** — Genişletmeler trusted surface'te typed preview ile yapılır. _Kaynak:_ §6.4; XI-4. _Durum:_ belirtilmemiş.

### K12 Entegrasyonlar ve yardımcı servisler

#### Diğer Suiss ürün seam'leri

- [ ] **PSD2 SCA dinamik bağlama (RTS Art. 5)** — Approval Surface profilinde onay tutar + alıcıya bağlıdır (AAS intent digest, WYSIWYS); yeni alıcı CT2. _Kaynak:_ §9.4 G; §14.9; SA-54. _Durum:_ belirtilmemiş (FROZEN; ADOPT ilke).

### K13 Denetim, kayıt, şeffaflık ve dışa aktarım

#### Özel olay denetimleri

- [ ] **Operasyonel erişim log'u** — Yönetici/destek/operatör eylemleri append-only, tamper-evident; canonical değil, karar girdisi değil (NIST AU, PCI Req.10). _Kaynak:_ §14.9; SA-51; TI-18. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Destek erişiminde başlangıç/bitiş/eylem başı atıflı denetim** — _Kaynak:_ §12.3.4; TN-71 #6. _Durum:_ belirtilmemiş (FROZEN).

#### Audit yüzeyleri ve kullanıcıya görünür geçmiş

- [ ] **Destek operatörü Exercise'larının kullanıcıya görünmesi** — S6 "Viewed sign-in settings — by Mehmet Y. … on your behalf". _Kaynak:_ §8.16. _Durum:_ belirtilmemiş.

### K14 Sinyaller, gözlemlenebilirlik ve analitik

#### Dikkat, bildirim ve onay yükü

- [ ] **Attention modeli** — Otomatik / insan / asla otomatik tablosu bağlayıcıdır. _Kaynak:_ §8.6; X23. _Durum:_ belirtilmemiş.
- [ ] **Approval fatigue kontrolleri** — Consequence-ranked tek kuyruk, dedup, öneri; yüksek sonuçlu onay bildirimden yapılamaz; "what this does / doesn't do" satırı; istek oranı/push-bombing koruması. _Kaynak:_ §8.17.11.4. _Durum:_ belirtilmemiş (eşikler §8.17.14 OQ2'de açık).
- [ ] **Access'in ranking'e katkısı yalnız fact** — Intent sınıfı, tutar, reserved, budget yakınlığı. _Kaynak:_ §8.17.11.1. _Durum:_ belirtilmemiş.

### K15 Güvenlik ve kriptografi

#### Onay ekranı güvenliği

- [ ] **Exact intent rendering yalnız kabul edilmiş schema'dan** — Kabul edilmemiş schema → onay kapalı (fail closed). _Kaynak:_ §8.13; §8.17.6.2; E10. _Durum:_ belirtilmemiş.
- [ ] **Authority-opaque gövdenin intent digest'ine karşı doğrulanması** — Eşleşmezse onay kapalı; Access gövdeyi istemez. _Kaynak:_ §8.17.6.2. _Durum:_ belirtilmemiş (wire biçimi OQ1).
- [ ] **Onay ekranı malzeme alanları** — Hedef, tutar, alıcı, geri alınabilirlik, principal/agent bağlamı, approver sıfatı, kalan requirement'lar, geçerlilik. _Kaynak:_ §8.17.6.1; §8.17.6.2. _Durum:_ belirtilmemiş.
- [ ] **Eligible set kontrolü** — Approve düğmesi yalnız eligible set'teyse; değilse "You can't approve this. Eligible: …". _Kaynak:_ §8.17.6.1. _Durum:_ belirtilmemiş.
- [ ] **Bildirimle onay sınırı** — Yüksek sonuçlu sınıflarda bildirim yalnız davettir; düşük sonuçlu sınıflarda conformant render + assurance ile hızlı onay. _Kaynak:_ §8.17.6.3. _Durum:_ belirtilmemiş (eşikler Security'de).
- [ ] **Batch onay kuralı** — Yüksek sonuçlularda yok; düşüklerde her item ayrı digest'li contribution; "Approve all" yok. _Kaynak:_ §8.17.6.3. _Durum:_ belirtilmemiş.
- [ ] **Push-bombing koruması (delegation versiyonu dahil)** — Requester inisiyatifli sheet açılışı yasak. _Kaynak:_ §8.17.4.3; §8.17.5.1; §8.17.11.4. _Durum:_ belirtilmemiş.

### K19 Geliştirme ve kalite güvencesi

#### Access conformance ve test vektörleri

- [ ] **Approval Surface WYSIWYS conformance testi** — _Kaynak:_ §9.14.5 k.1. _Durum:_ belirtilmemiş.

### Bu aşamada doğrulanacak sınırlar

#### Ürün kapsamı

- [ ] **Trusted rendering / approval UI sahibi değil** — _Kaynak:_ §2.5; L28. _Durum:_ belirtilmemiş.

#### Yetki modeli

- [ ] **Disposition'sız offboarding yok (varsayılan disposition yok)** — _Kaynak:_ §8.17.9.6. _Durum:_ belirtilmemiş.

#### Yönetim, operatör ve destek erişimi

- [ ] **Break-glass ayrıcalık değildir** — `is_breakglass` bayrağı authority taşımaz, kayıt/denetim/requirement muafiyeti vermez; break-glass authority kararı üretemez ve kullanıcı verisi okuyamaz. _Kaynak:_ OP-46; TN-93. _Durum:_ belirtilmemiş.
- [ ] **DB'de duran acil durum admin hesabı yok** — _Kaynak:_ OP-46. _Durum:_ belirtilmemiş.
- [ ] **v1 → v2 devredilmiş yönetim otomatik göç vaadi yok** — _Kaynak:_ TN-114. _Durum:_ belirtilmemiş.

## Aşama 13 — Dayanıklılık, ölçek ve şeffaflık

HA, çok bölge, cell ve placement, handover ve recovery, DR, bozulmuş mod, kapasite, witness ve replica, Record Export ve replay, yük testi.

### Spec dışı ön koşullar

- [ ] **Üretime benzer çok AZ'li ön üretim ortamı** — failover, PITR tatbikatı, N-1 yükseltme ve hata enjeksiyonu testleri.
- [ ] **Commit throughput ve p99 ölçümleri** — EA değerlerinin ölçülmesi. Kaynak: OQ-1.

### K02 Kimlik protokolleri ve federasyon

#### Authority federasyonu (domain'ler arası)

- [ ] **Yerel AuthorityDomain deployment pattern'i** — Tesis, robot filosu veya ayrık ağ kendi domain'i olarak çalışabilir ve ana domain'e bridging Grant ile bağlanır; bu bir profile class'ı değildir. _Kaynak:_ §9.12, §9.15A.4; P31. _Durum:_ belirtilmemiş (FROZEN).

### K03 Oturum ve token yönetimi

#### Oturum yüzeyi ve çıkış

- [ ] **Oturum iptali ve logout ücretsiz, tavansız** — Logout ve oturum iptali daraltma sınıfıdır, kapasite sayacına girmez. _Kaynak:_ §18.5, §18.6, §18.7; B3, B19. _Durum:_ belirtilmemiş (FROZEN STRATEGY).

#### Epoch'lar ve hızlı iptal

- [ ] **İptal yayılım hedefleri** — Aynı node 0 ms; aynı cluster p99 < 250 ms; cluster'lar/bölgeler arası p99 < 500 ms. DB erişilemezken bu süreler verilmez. _Kaynak:_ §13.4 U35; §13.7.9; §13.11 EP-3; §17.5.1; MD-7, OP-21, OP-32. _Durum:_ EA.
- [ ] **DR promote sonrası toptan epoch artırımı** — Async DR profilinde promote sonrası bütün `session_epoch` ve refresh aileleri toptan artırılır; herkes yeniden login olur. _Kaynak:_ §16.7.1; §17.4.8; HL-31, OP-29, T28. _Durum:_ belirtilmemiş (FROZEN).

#### Introspection ve RS doğrulaması

- [ ] **Bozulmuş mod (identity degraded window)** — Identity DB erişilemezken önceden imzalı, ömrü beyanlı self-contained token'lar RS'in yerel doğrulamasında (JWKS ve epoch cache bellekte) ömürleri içinde kabul edilir. Yeni login/refresh/revocation reddedilir, yeni token basılmaz; 60–300 s fail-open pencereleri hiçbir token sınıfı için kabul edilmez. _Kaynak:_ §13.4 U39; §16.7.1; §17.7.2; EP-6, HL-22, OP-45, RR-25. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Gecikme katmanları A/B/C** — A: her istek p99 < 1 ms; B: refresh 50–200 ms; C: asenkron outbox. _Kaynak:_ §12.2.1; TN-38. _Durum:_ EA.

#### İmza anahtarları ve token saklama

- [ ] **Restore sonrası aynı `kid`'ler** — Restore sonrası JWKS aynı `kid`'leri sunar (tatbikat maddesi). _Kaynak:_ §17.10.3; OP-57. _Durum:_ belirtilmemiş (FROZEN).

### K05 Kiracılık, realm ve B2B organizasyonlar

#### Authority log anahtarlama ve yerleşim

- [ ] **Placement Directory** — DomainID/realm/tenant → cell eşlemesi; yalnız yönlendirme içindir, karar girdisi değildir, hücreler onsuz çalışır. _Kaynak:_ §17.1.4, §17.4.9; CMP-26. _Durum:_ belirtilmemiş (OPERATIONAL).
- [ ] **Silo kaçış yolu (`placement_id`)** — Düzenlemeye tabi kiracıyı ayrı kümeye taşıma; realm yerleşimi domain hücresini izler. _Kaynak:_ §12.1.1; TN-9. _Durum:_ EA.
- [ ] **Dedicated cell** — Tek büyük domain/organizasyon için ayrılmış cell (şema/DB-per-tenant yerine). _Kaynak:_ §17.2.2, §17.9.1, §18.5; OP-12, OP-48. _Durum:_ belirtilmemiş.
- [ ] **Cell değişimi** — HANDOFF/ACCEPTANCE mührüyle yapılır, semantik etkisi yoktur; domain ve realm kimliği cell'den bağımsızdır. _Kaynak:_ §5.16, §7.1; TI-2. _Durum:_ belirtilmemiş.
- [ ] **Veri yerleşimi (residency) ve realm residency beyanı** — Veri yerleşimi cell ekseniyle sağlanır; realm residency beyanı cell bölgesini belirler. Türkiye bölgesinde veri yerleşimi sertifika listesindedir. _Kaynak:_ §14.9; §17.4.9; MD-5; OP-30; SA-56. _Durum:_ belirtilmemiş (FROZEN, §17.4.9).

#### Realm yönetişimi

- [ ] **Realm rehome (`idp.realm.rehome`)** — Yönetişim domain'ini değiştiren reserved, CT3, iki uçlu Exercise; eski ve yeni domain'de commit edilir. _Kaynak:_ §5.16, §7.1; §12.1.1 2a. _Durum:_ belirtilmemiş.

#### Realm ve tenant başına operasyonel ayarlar

- [ ] **Domain ve tenant boyutunda kotalar** — Kotalar protocol rejection'dır. _Kaynak:_ T27. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Realm/tenant başına `rate_limit_rps`** — Identity API'lerinde noisy-neighbor koruması. _Kaynak:_ §17.5.5; OP-35. _Durum:_ POLICY DEFAULT.

### K06 Giriş deneyimi, UI bileşenleri ve markalama

#### Enumeration direnci ve giriş mesajları

- [ ] **Identity plane unavailable mesajı** — "Sign-in isn't available right now. Things already allowed keep working within their limits."; step-up gerektirenler DENY/REQUIRE kalır. _Kaynak:_ §8.13. _Durum:_ belirtilmemiş.

#### Deneyim invariant'ları

- [ ] **Degraded-state UX (bozulmuş durumda güvenli varsayılan)** — Her arızada owner, UNKNOWN, eksik bilgi ve fail-closed güvenli varsayılan görünür (Access unavailable, Relay delayed, effect receipt lost, executor ignores revocation, foreign provider unreachable, IdP stale, domain unavailable, forced migration, Work↔Access uyuşmazlığı, inventory stale, verifier saati belirsiz vb.). _Kaynak:_ §6.4; §8.13; X26; XI-20. _Durum:_ belirtilmemiş.

#### Dürüst durum metinleri

- [ ] **`witnessed_through` nitelemesi ("Revoked — confirming (witness pending)")** — Witness/replica ack bekleyen kayıt bu nitelikle gösterilir, ack ile nitelik kalkar; `witnessed_through` alanı UI niteliğinin kaynağıdır. _Kaynak:_ §8.7; §9.5; X14. _Durum:_ belirtilmemiş.

#### Experience yüzeyleri (S1–S11)

- [ ] **S7'de "Recovery not available" beyanı** — Recovery entry kurulamıyorsa domain oluşturma ekranı bunu beyan eder; witness/replica yokluğu S7'de görünür. _Kaynak:_ §13.6; RR-5. _Durum:_ belirtilmemiş.

### K07 Yetki modeli

#### Çalışma zamanı, log ve atomiklik

- [ ] **Tek authoritative lineage** — Domain'de tek lineage vardır; recovery sonrası N dışı eski-provider kayıtları geçersizdir. _Kaynak:_ §13.4 G21. _Durum:_ belirtilmemiş
- [ ] **Group commit** — Bağımsız commit'ler tek tx/WAL flush'ta birleştirilir; semantiği değiştirmez. _Kaynak:_ §17.1.2; OP-9. _Durum:_ FROZEN TECHNICAL (zorunluluk), EA (sayılar)
- [ ] **Rebuild-diff ve divergence quarantine** — Fold farkı commit'i durdurur; yeniden değerlendirme farkı divergence beyanı + quarantine (genişletici effect'ler DENY, kaldırma CT3). _Kaynak:_ §16.5; G32, RT2, RT3, RT9. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Toplu episode (O(1) işaret + tembel hesap)** — Toplu meta-Exercise domain'i kilitlemez. _Kaynak:_ §16.5; RT19, TI-RT9. _Durum:_ belirtilmemiş (FROZEN; iş sınırı EA)
- [ ] **Zaman disiplini (≥ 2 bağımsız kaynak)** — Monotonic sınırlı ilerleme, witness cosign çapraz kontrolü; uyuşmazlıkta commit durur; backdating yok. _Kaynak:_ §16.5; FA-3, RT4, TI-RT2. _Durum:_ belirtilmemiş (FROZEN; hedef ≤ 250 ms EA)
- [ ] **Hot domain/key: retry/rejection, commit'siz ALLOW yok** — _Kaynak:_ §16.7. _Durum:_ belirtilmemiş

#### Handover, recovery ve bölge

- [ ] **Kooperatif handover (`domain.handover`)** — Freeze, root AIS, witness'lı C_k, Record Export, record-fold, handover batch, fencing, `superseded-at C_{h+1}`, drain. _Kaynak:_ §16.6 HO-1…HO-9; T22. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Forced recovery (`domain.recover`)** — Fence/kapsam kanıtı yoksa root'un recovery yoludur: replica'dan fold, değerlendirici-tarafı witness sorgusu, R*, N < R* DENY, beyanlı kayıp suffix, witness fencing, witness beyanlı recovery re-anchor. _Kaynak:_ §16.6 FR-0…FR-6; §17.4.1, §17.10.3; SEC21, SEC22, T22, U24. _Durum:_ belirtilmemiş (FROZEN, §16.6)
- [ ] **Binding re-anchor (self-handover, OP-60)** — Aynı provider içinde binding key rotasyonu `domain.handover`'ın self-handover profilidir; çift imzalı geçiş; `superseded-at` prospektif. _Kaynak:_ §16.6.1; §17.14; CR-45, OP-60, RB-0…RB-6. _Durum:_ belirtilmemiş (FROZEN TECHNICAL; zamanlama PD)
- [ ] **Divergence çıkışı durdurmaz** — Yeniden değerlendirme farkı handover/recovery'yi durdurmaz. _Kaynak:_ §16.7; G32, K-1. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Multi-region: tek yetkili cell/epoch ve HANDOFF/ACCEPTANCE** — Active-active canonical yazma yoktur; cell/bölge değişimi planlı mühürleme (q, e) → hedefte replay + kabul (q, e+1) ile yapılır, pozisyon asla yeniden kullanılmaz; şüphede fail-closed. _Kaynak:_ §17.4.1; EI-20, FA-2, FA-13, T28. _Durum:_ belirtilmemiş (FROZEN)
- [ ] **Domain residency beyanı** — Genesis'te veya sözleşmede yapılır; cell bölgesini belirler. _Kaynak:_ §17.4.1; T28. _Durum:_ belirtilmemiş

### K08 Karar, uygulama ve doğrulama

#### Advisory check ve önbellek

- [ ] **Advisory sıcak yol hedefleri** — p99 hedefleri: projection doğrulama < 5 µs, check isabeti < 100 µs, ıskası < 5 ms, search < 50 ms. Commit yolu ayrıdır. _Kaynak:_ §9.7A.6; P46. _Durum:_ EA.
- [ ] **Commit p99 hedefleri** — Online commit ≤ 30 ms; witness-before-ack ≤ 750 ms; ≥ 2.000 commit/s/domain. _Kaynak:_ §17.5.1; OP-32. _Durum:_ EA.

#### Projection'lar ve yetki artefaktları

- [ ] **Inclusion proof bundle** — Payload digest + leaf çekirdeği + yalnız `artifacts` alanının açılışı + Merkle path + witness'lı checkpoint (+ consistency_path); seçici açıklamayı delmez. _Kaynak:_ OP-1; T19. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Inclusion proof gereksinimleri** — Eski provider anahtarıyla imzalı artefakt için exact içerik bağı + commitment'a dahil olma (Merkle yolu) + bağımsız witness'lı checkpoint; Work Gate receipt doğrulaması dahil. _Kaynak:_ §13.3; P18; SEC25. _Durum:_ belirtilmemiş.
- [ ] **Recovery/handover sonrası eski-anahtarlı artefakt reddi** — `superseded-at` anahtarlı artefakt (PAP, VC, receipt, token) yalnız `N_cited`'e karşı exact-content inclusion proof ile veya yeniden issue edilerek kabul edilir. Kooperatif handover'da `superseded-at C_{h+1}` + handover predicate + drain; recovery'de Domain Metadata tazeliği + witness'lı checkpoint + exact-content inclusion uygulanır. _Kaynak:_ §9.8, §9.10; §13.4 U12, U27; P4, P18; RT13. _Durum:_ belirtilmemiş (FROZEN).

#### Offline doğrulama ve verifier

- [ ] **Federation Verifier ve foreign Domain Metadata cache** — Tazelik bağımsız witness cosign'ıyla ≤ Δ (yoksa ≤ 1 saat). _Kaynak:_ §16.5; T29. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Authority hub keşfi ve hub cache** — Viewer-scoped snapshot; consequential okuma/export kayıtlı Exercise; global registry yok. _Kaynak:_ §16.5; T30. _Durum:_ belirtilmemiş (FROZEN).

#### İptal, tazelik ve status

- [ ] **Witness/replica-before-ack (revocation/CT3)** — Revocation ve CT3 commit'leri kapsayan checkpoint + ≥1 bağımsız witness cosign + replica olmadan ack edilmez; revocation commit anında etkilidir. _Kaynak:_ §16.5; §17.1.1 adım 14; SEC23; T18; TI-13. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Epoch ↔ ValidityContract doğrulama yolu tablosu (EP-1…EP-10)** — Her doğrulama yolunun cache miss, partition, restart davranışı ve azami bayatlığı beyanlıdır; "DB düşse dahi doğrulama" ile "iptal ≤ 250 ms" aynı yolda birlikte vaat edilmez. _Kaynak:_ §13.11; MD-7. _Durum:_ belirtilmemiş (semantik FROZEN, sayılar PD, gecikme EA).

### K10 Yönetişim

#### Break-glass (authority düzeyi)

- [ ] **Offline PAP ile break-glass sürekliliği** — _Kaynak:_ §12.3.8; SEC27, TN-93. _Durum:_ belirtilmemiş

#### Olay müdahalesi ve containment

- [ ] **Divergence quarantine root/Security Party kararıdır** — Provider yalnız kanıt bildirir; restriction yazamaz; divergence ve post-recovery quarantine kaldırma CT3 (bkz. K17). _Kaynak:_ §9.15; RT3, RT9. _Durum:_ belirtilmemiş (FROZEN)

### K11 Yönetim API'si, konsol, SDK'lar ve geliştirici araçları

#### Decision lab, sandbox ve conformance

- [ ] **Decision lab: Replay** — Geçmiş DecisionRecord'u StateBasis ile yeniden değerlendirir; farklıysa evaluator uyumsuzluğu bulgusu; audit yetkisi gerekir. _Kaynak:_ §8.17.10.4; INV-27. _Durum:_ belirtilmemiş.

#### Doğrulama ve replay araçları

- [ ] **Replay CLI** — Export'u Suiss'siz doğrular (zincir, Merkle, witness, q−1 yeniden değerlendirme). _Kaynak:_ §17.6.13; §18.3; CMP-17; T34. _Durum:_ belirtilmemiş.
- [ ] **Replica agent** — _Kaynak:_ §9.1. _Durum:_ belirtilmemiş.

#### Komut satırı ve operasyon araçları

- [ ] **Rolling upgrade uyumluluk komutu** — Makine-okunur çıkış kodları: 0 rolling mümkün, 3 recreate, 4 özellik kapalı. _Kaynak:_ §17.10.2; OP-56. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).

### K12 Entegrasyonlar ve yardımcı servisler

#### Yardımcı servisler

- [ ] **Bağımsız witness / archival replica hizmeti (başka provider'lardaki domain'lere)** — _Kaynak:_ §17.12; §18.7 B13; H10. _Durum:_ HYPOTHESIS.
- [ ] **Replica agent ve witness listesi** — Suiss açık replica agent + witness listesi sunar; consumer için bağımsız witness/replica operatörü önerir ve maliyetini üstlenebilir. _Kaynak:_ §18.9 D5. _Durum:_ belirtilmemiş (D5 recommended default).

### K13 Denetim, kayıt, şeffaflık ve dışa aktarım

#### Kayıt formatı ve seçici açıklama

- [ ] **Inclusion proof yalnız `artifacts`'ı açar** — Lineage, dependency, consumption kapalı kalır. _Kaynak:_ §17.6.1 kural 5; T19. _Durum:_ belirtilmemiş.

#### Authority log bütünlüğü

- [ ] **Authority Merkle yıllık shard** — _Kaynak:_ §17.6.2; §17.11; OP-37. _Durum:_ WATCH.
- [ ] **Transparency log** — Exercise record için şeffaflık logu (assurance aracı; in-toto/Sigstore/CT deseni). _Kaynak:_ §4.4 katman testi; K15. _Durum:_ belirtilmemiş.
- [ ] **Derived katman canonical'ı ezmez** — Rebuild-diff hakemi canonical log'u ezmez. _Kaynak:_ §13.4 G33; TI-RT4. _Durum:_ belirtilmemiş.

#### Checkpoint, witness ve replica

- [ ] **Checkpoint yapısı** — Hash chain/Merkle kökü + pozisyon + sürüm vektörüdür ve provider tarafından imzalı Claim'dir; witness co-sign ayrı Claim'dir. _Kaynak:_ §9.16; P32. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Checkpoint cadence ve heartbeat** — 60 s / 1.000 kayıt + out-of-cycle; değişiklik olmasa da heartbeat checkpoint üretilir, witness'a gönderilir, log'a Claim olarak ingest edilir, witness cosign ve status list `iat`'i tazelenir. _Kaynak:_ §9.15, §9.16; §16.5; CMP-6; T16; TI-RT5. _Durum:_ PD (cadence).
- [ ] **Checkpoint aralığı (MMD) beyanı** — Authority 60 s / 1.000 kayıt + heartbeat; identity ≤ 1 s. _Kaynak:_ §17.6.3; OP-38; T16. _Durum:_ POLICY DEFAULT (authority), EA (identity).
- [ ] **Checkpoint coalescing** — Revocation fırtınasında tek checkpoint + tek witness gönderimi. _Kaynak:_ §17.6.3; OP-38. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **Witness co-sign (≥ 2, ≥ 1 bağımsız) ve witness bağımsızlığı** — `witnessed_through` okuma cevabında yer alır; Suiss-hosted'da en az bir witness Suiss dışıdır, Suiss kendi host ettiği domain'de bağımsız witness sayılmaz. "Equivocation tespit edilebilir" ve "kayıpsız" iddiaları bağımsız witness ve provider-dışı replica ister. _Kaynak:_ §6.6; §7.1, §7.2; §13.3; §13.7.7; B13; SEC21–SEC23; SI-12. _Durum:_ PD.
- [ ] **Witness protokolü ve gossip** — Consistency-proof doğrulayan, binding-farkında cosign'cılar; aynı size için farklı root equivocation kanıtıdır. _Kaynak:_ §16.6; CMP-6; T17. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Equivocation tespiti** — ≥ 1 bağımsız witness + checkpoint karşılaştırması (gossip) ile; declared witness/gossip capability altında UDC, yoksa NG. _Kaynak:_ §9.16; §13.3; P4; U9. _Durum:_ belirtilmemiş.
- [ ] **Provider dışına checkpoint kopyalama / witness seçimi** — Domain checkpoint'leri kendi depolamasına veya üçüncü taraf witness/transparency log'a kopyalar; witness seçimi domain'indir. _Kaynak:_ §9.16; P32. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Witness/replica-before-ack** — Revocation sınıfı ve CT3 commit'leri bağımsız witness co-sign'ı ve önek'in provider-dışı replica'ya ulaşması olmadan ack edilmez; Suiss-hosted'da zorunlu. _Kaynak:_ §13.3; SEC23; U10. _Durum:_ PD.
- [ ] **Provider-dışı replica / Replica Mirror (mirror-before-witness)** — Domain/root kontrolündeki provider-dışı replica'ya sürekli CBOR sequence aktarımı (Record Export akışı); replica capability Genesis/Domain Metadata'da beyanlı. _Kaynak:_ §13.3; §17.6.4; CMP-21; SEC23; T21; TI-13. _Durum:_ belirtilmemiş (FROZEN); PD (§13.3).
- [ ] **"Existed by T" zaman sabitlemesi** — Witness'lı zaman sabitlemesi; PQ re-anchor uzantısı. _Kaynak:_ §13.4 U21, U68. _Durum:_ belirtilmemiş.
- [ ] **Release checkpoint'inin Access witness'larıyla co-sign'ı** — Yazılım sürümü (release) bir log girdisidir. _Kaynak:_ §14.7 F-7; OP-68; SA-39; U49. _Durum:_ belirtilmemiş (FROZEN).

#### Identity plane denetim log'u

- [ ] **Identity audit kaydı checkpoint'e ≤ 1 s** — Tamper-evident checkpoint, witness co-sign; log başına yayınlanır. _Kaynak:_ §13.4 U52; §13.7.9. _Durum:_ EA.
- [ ] **Tiled log + yıllık shard (identity)** — C2SP tlog-tiles deseni. _Kaynak:_ §17.6.2; OP-37. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).

#### Denetime erişim ve disclosure

- [ ] **Audit export ve consequential okumalar kayıtlı Exercise** — `access.audit.export` ve portable artefakt üreten okumalar kayıtlıdır; diğer okumalar telemetridir, canonical kayıt değildir. _Kaynak:_ §6.6; §13.4 G28; SI-15. _Durum:_ belirtilmemiş.
- [ ] **Audit-scope explain/replay/export her pakette** — _Kaynak:_ §18.3, §18.6; B3; SEC24; X22. _Durum:_ belirtilmemiş.

#### Redaksiyon ve saklama

- [ ] **Identity denetim log'u sıcak/soğuk katman** — PG 30–90 gün; S3'te OCSF + Parquet soğuk katman; opsiyonel ClickHouse. _Kaynak:_ §17.6.7; OP-40. _Durum:_ POLICY DEFAULT.
- [ ] **Uzun sıcak denetim penceresi (12 ay, PCI)** — Policy minimumu ücretsiz baseline'dır. _Kaynak:_ §18.6; MKT-D16; SEC32. _Durum:_ belirtilmemiş (farklılaşma HYPOTHESIS).
- [ ] **Domain kayıtlarının decommission'ı** — Önce export/handover penceresi, sonra crypto-shredding. _Kaynak:_ §18.7 B12. _Durum:_ belirtilmemiş.

#### Record Export ve bağımsız doğrulama

- [ ] **Record Export Package (audit export)** — Kendi kendine doğrulanabilir, ücretsiz ve tam dışa aktarım: domain, range, records (AIS dahil), checkpoints, versions, schemas, SPP'ler, claims, export_exercise; streaming CBOR sequence. Export bir Exercise'tır; SIEM vb. için de kullanılır. _Kaynak:_ §2.4; §2.5; §8.17.4.1; §9.16; §17.6.13; §18.7 B3; AP-13, AP-14; CMP-12; P32; T34. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Audit export'un koruması gerekenler** — Provenance, attribution, StateBasis, Exercise↔Decision↔contribution↔Claim ilişkileri ve redaction sonrası digest doğrulanabilirliği. _Kaynak:_ §7.9.12.5. _Durum:_ belirtilmemiş.
- [ ] **Tam export her zaman mümkün (anti-hostage)** — Export domain'in kendi authority'si ile yapılır; ticari koşula bağlanamaz. _Kaynak:_ §9.17 anti-hostage k.2. _Durum:_ belirtilmemiş.
- [ ] **Domain kayıt dışa aktarımı (B3 tam export/replay), kişi dışa aktarımından ayrı** — _Kaynak:_ §12.3.5; TN-79. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Suiss/provider olmadan doğrulama, replay ve devralma** — Açık spec + export + herhangi bir conformant evaluator ile üçüncü taraf kayıtları doğrular, record-fold ile kökleri ve state'i yeniden üretir, kararları yeniden değerlendirir ve lineage'ı devralabilir; uyuşmazlık imzalı divergence set olarak beyan edilir. _Kaynak:_ §6.5; §9.16; §16.1 A3; INV-27; P32; PI-6; TI-RT1. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Redakte export'tan doğrulama ve "replay coverage" beyanı** — Redaksiyonda leaf/zincir/Merkle yeniden hesaplanabilir; redacted kayıtlar digest seviyesinde replay destekler ve bu açıkça beyan edilir. _Kaynak:_ §9.16; §16.6; §17.6.13; T19. _Durum:_ belirtilmemiş.
- [ ] **Provider değerlendirme hatasının tespiti** — Export + open evaluator ile replay erişimi olan taraf tespit edebilir (UDC). _Kaynak:_ §9.16. _Durum:_ belirtilmemiş.
- [ ] **Örneklemeli bağımsız yeniden değerlendirme (sampling replay agent)** — CT3 %100, CT2 %1 bağımsız tarafça open reference evaluator ile; uyuşmazlık imzalı kanıt olarak divergence quarantine'e gider, çıkışı durdurmaz. _Kaynak:_ §13.3; §13.7.7; §17.6.13; §18.6; CMP-12; G32; SA-19; T34; U13. _Durum:_ PD / POLICY DEFAULT.
- [ ] **Divergence quarantine** — Divergent kaydın genişletici effect'leri DENY overlay'i altında; root/Security Party `policy.set`; kaldırma CT3. _Kaynak:_ §13.6; RT3; TI-RT1. _Durum:_ belirtilmemiş.

#### Audit yüzeyleri ve kullanıcıya görünür geçmiş

- [ ] **Forced provider migration beyanı** — "Recovered from previous provider at record position N… Revocations made after 11:02 must be repeated." _Kaynak:_ §8.13; §8.17.9.7; E20. _Durum:_ belirtilmemiş.
- [ ] **`domain-recovered` bildirimi** — Bütün root katılımcılarına ve domain admin'lerine. _Kaynak:_ §13.6. _Durum:_ belirtilmemiş.

#### Provider beyanları ve şeffaflık yayınları

- [ ] **Durability profili beyanı** — `durability: single-node` Domain Metadata ve realm DR beyanında yayımlanır. _Kaynak:_ HL-40; OP-48. _Durum:_ belirtilmemiş.

### K14 Sinyaller, gözlemlenebilirlik ve analitik

#### Revocation ve sonuç görünürlüğü

- [ ] **`witnessed_through`** — Derived okumalarda witness'lı pozisyonu döndürür. _Kaynak:_ §9.5, §9.11. _Durum:_ belirtilmemiş.
- [ ] **Failure ownership tablosu** — Access erişilemezliği, Relay gecikmesi, receipt kaybı, IdP bayatlığı, provider erişilemezliği, Executor'ın iptali yok sayması gibi durumların sahipliği tanımlıdır. _Kaynak:_ §7.9.14. _Durum:_ belirtilmemiş.

#### Operasyon sinyalleri, metrikler ve alarmlar

- [ ] **Sev-1 alarmlar** — Fence kanıtsız promote, rebuild-diff farkı. _Kaynak:_ §17.4.4, §17.8.2. _Durum:_ belirtilmemiş.
- [ ] **Degraded mode alarmı** — 0–60 s alarm, >300 s sev-1. _Kaynak:_ §17.7.2; OP-45. _Durum:_ PD.
- [ ] **Hız sınırı gözlemlenebilirlik panosu** — Kova başına anlık yüzde, 24 s/1 s ortalama, en çok tüketen 10, olay tipleri, eşik uyarısı; istekten türetilmiş metrik etiketi yok. _Kaynak:_ §12.5.4; TN-127. _Durum:_ PD.
- [ ] **Hash dışı CPU oranı metriği** — Login'de toplam/Argon2 CPU < 1,10. _Kaynak:_ §17.5.1; OP-32. _Durum:_ EA.

### K15 Güvenlik ve kriptografi

#### Anahtar hiyerarşisi ve kapsamı

- [ ] **Binding re-anchor (self-handover)** — Aynı provider içinde binding değişimi; re-anchor sonrası eski binding anahtarı yeni üretim için `superseded`. _Kaynak:_ §9.10; CR-45; OP-60; U71. _Durum:_ belirtilmemiş.
- [ ] **Recovery anahtarları provider dışında** — `domain.recover` entry'sinin anahtarları provider/operatör tarafından custody edilemez; provider operatörü recovery yapamaz. _Kaynak:_ SEC20; U16. _Durum:_ belirtilmemiş (FROZEN).

#### Anahtar yaşam döngüsü, rotasyon ve felaket kurtarma

- [ ] **Binding key DR (HSM-içi klon)** — _Kaynak:_ CR-30. _Durum:_ belirtilmemiş (FROZEN).

#### Veri şifreleme ve sır yönetimi

- [ ] **Workload identity ile sır bootstrap'ı** — Env/K8s Secret kullanılmaz. _Kaynak:_ CR-35; OP-63. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Yedek/dump'ta açık sır yok** — Tek istisna `basis_ref` anahtarı. _Kaynak:_ CR-35. _Durum:_ belirtilmemiş (FROZEN).

#### Süreç izolasyonu ve signer

- [ ] **Signer barındırma (dedicated host / çekirdek izolasyonu)** — _Kaynak:_ CR-40 madde 4. _Durum:_ PD.
- [ ] **Dedicated compute (B4)** — Co-tenant mikromimari yan kanalını kaldırır (`mitigations=auto,nosmt`). _Kaynak:_ MD-17; SA-25; U54. _Durum:_ HYPOTHESIS (fiyat).

#### Platform ve çalışma zamanı sertleştirmesi

- [ ] **İmaj doğrulama (admission)** — cosign sertifika kimliği/issuer doğrulaması; policy-controller veya Kyverno. _Kaynak:_ §14.5; U49. _Durum:_ belirtilmemiş.

#### Kiracı izolasyonu ve kimlik tanımlayıcıları

- [ ] **Gürültülü komşu koruması** — Aşım protocol rejection'dır, başka domain'i etkilemez. _Kaynak:_ §12.1.3; TN-24. _Durum:_ belirtilmemiş.

#### Hız sınırlama ve yük atma

- [ ] **Ürün limit değerleri** — Commit 20/s sürekli, 100 burst; check 60/dk; istek ≤ 256 KB. _Kaynak:_ §17.5.5 (→ §13.7.4). _Durum:_ POLICY DEFAULT.
- [ ] **Load shedding eşlemesi** — Authority "busy — retry"; identity 503/429; shedding asla ALLOW üretmez. _Kaynak:_ §17.5.6; OP-36. _Durum:_ belirtilmemiş (FROZEN).

#### Güvenlik ilkeleri: fail-closed, downgrade, compromise

- [ ] **Degraded mode yalnız beyanlı yollarla** — Yalnız TI-9/SEC27/SI-22 yollarıyla; yayılım hedefleri (250 ms/1 s) EA. _Kaynak:_ §9.11.2; MD-8. _Durum:_ EA (hedefler).
- [ ] **Recovery / handover sonrası inclusion proof** — Eski provider anahtarlı artefakt yalnız exact-content inclusion proof'uyla kabul edilir. _Kaynak:_ §6.5; §6.6; PI-15; SI-11. _Durum:_ belirtilmemiş.
- [ ] **Divergence quarantine** — Divergent kaydın genişletici effect'leri DENY overlay'i altındadır; kaldırma CT3'tür. _Kaynak:_ §6.8; §7.1; §7.2; TI-RT1. _Durum:_ belirtilmemiş.
- [ ] **`nonce-closed/pre-recovery` (K-3)** — Recovery öncesi AIS'ler devam eden lineage'da Exercise açamaz. _Kaynak:_ §6.8; §7.2; SEC22 R1; TI-RT3. _Durum:_ belirtilmemiş.
- [ ] **Domain Metadata tazeliği witness cosign ile** — Metadata'nın kendi `iat`'i tazelik kanıtı değildir; bağımsız witness ≤ Δ (yoksa ≤ 1 sa) cosign'ı gerekir. _Kaynak:_ §9.10 adım 6; §9.15; P18; TI-RT5. _Durum:_ belirtilmemiş (FROZEN).

### K16 Gizlilik, rıza ve uyum

#### Veri sahibi hakları, silme ve saklama

- [ ] **Restore sonrası yeniden shred** — Silme olguları geri yüklenen veriye yeniden uygulanmadan ortam trafiğe açılmaz; KMS yedekleri shred listesine tabidir. _Kaynak:_ §17.6.9; OP-42, OP-57. _Durum:_ belirtilmemiş.

#### Veri yerleşimi

- [ ] **Veri yerleşimi (cell = residency birimi)** — Hücreler arası replikasyon yok. _Kaynak:_ §17.4.9; OP-30. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Residency/DR sınıfları ve RPO beyanı** — Regional ve multi-region sync sınıfları; RPO residency sınıfıyla birlikte beyan edilir. _Kaynak:_ §17.4.1; §18.6; T28. _Durum:_ belirtilmemiş.

### K17 Dağıtım, operasyon, yüksek erişilebilirlik ve felaket kurtarma

#### Dağıtım biçimleri ve profiller

- [ ] **Dağıtım biçimleri** — Suiss-hosted paylaşılan cell, dedicated cell, self-host (small provider veya cell), third-party provider. _Kaynak:_ §17.9.1; OP-48. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Suiss-hosted operasyon** — Yönetilen teslim modeli. _Kaynak:_ §4.5. _Durum:_ belirtilmemiş.
- [ ] **Self-host profili ve çıkış hakkı** — Müşteri kendi altyapısında çalıştırabilir; Suiss-hosted'dan çıkış hakkı korunur. _Kaynak:_ §4.5; §4.8 eksen 5; B10. _Durum:_ belirtilmemiş.
- [ ] **Small-provider / single-node profili** — Tek binary ve tek komutla kurulur (tek binary + PG + HSM/soft-HSM); `durability: single-node` olarak beyan edilip yayımlanır, garanti satırları UDC → HL olarak beyan edilir; authority plane'de witness/replica (SEC23) yine zorunludur. _Kaynak:_ §2.2.1; §4.8 eksen 7; §17.9.1; HL-40; OP-7; OP-48–OP-51; T8; T36. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Helm chart (birinci sınıf) + opsiyonel operator** — _Kaynak:_ §17.9.4; OP-51; T36. _Durum:_ PD.

#### Cell topolojisi ve altyapı

- [ ] **Placement directory** — Tenant↔domain ve domain → cell eşlemesini tutar; hücre değişimi T28 ile; realm domain hücresini izler. _Kaynak:_ §5.1; §5.16; §12.1.1; TN-9. _Durum:_ EA.
- [ ] **Cell topolojisi** — ≥ 3 AZ, canonical PG primary + ≥ 2 sync standby, derived cluster, NATS, HSM. _Kaynak:_ §17.4.1. _Durum:_ belirtilmemiş.
- [ ] **Hücre başına hosted altyapı yığını** — Cell başına Kubernetes, OpenTofu, Argo CD, Cilium + Envoy Gateway, SPIFFE/SPIRE. _Kaynak:_ §17.9.4; T36. _Durum:_ FROZEN (T36); PD (§17.9.4).
- [ ] **OpenTofu yalnız altyapı** — _Kaynak:_ §12.5.3; T36. _Durum:_ belirtilmemiş.
- [ ] **Topoloji fazları** — Küçük (~100) → Faz 1 (~100 bin, tek bölge 3 AZ) → Faz 2 (iki cluster) → Faz 3 (bölge başına hücre) → büyük (~10M). _Kaynak:_ §17.9.8; OP-54. _Durum:_ PD.
- [ ] **Soğuk başlatma** — Readiness cache dolana kadar down; JWKS yüklenemezse başlamaz; 0–5 s jitter. _Kaynak:_ §17.9.7; OP-53. _Durum:_ PD.
- [ ] **Kubernetes yaşam döngüsü** — preStop 5 s, drain 2 s, shutdown 15 s, grace 45 s; PDB; zone'da sert topology spread; göç sırasında liveness up. _Kaynak:_ §17.9.3; OP-50. _Durum:_ PD.

#### Commit ve dayanıklılık

- [ ] **Witness/replica-before-ack** — Commit, bağımsız witness ve provider-dışı replica'ya ulaşmadan ack edilmez (UNDER DECLARED CAPABILITY). _Kaynak:_ §6.7, §7.4; SEC23; TI-6, TI-13. _Durum:_ belirtilmemiş.
- [ ] **Provider-dışı replica ve witness kümesi** — Domain Metadata'da beyan edilir. _Kaynak:_ §9.15. _Durum:_ belirtilmemiş.
- [ ] **Replica'lar yalnız advisory okuma** — Replica'dan ALLOW verilmez. _Kaynak:_ §9.7A.2 k.1; P43. _Durum:_ belirtilmemiş (FROZEN).

#### Yüksek erişilebilirlik ve failover

- [ ] **Senkron replikasyon (`ANY 1`, ≥ 2 sync standby, farklı AZ)** — Standart profilde zorunlu, single-node'da kalkar; güvenlik yazmaları `on`, yalnız telemetri `local`. _Kaynak:_ §4.8 eksen 7; §17.4.3; FA-1; OP-24; OPI-4. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **DB primary failover'da ack'li kayıt kaybı yok** — Sync standby; identity plane ≥ 2 sync standby `ANY 1`; AZ kaybında güvenlik yazmaları kaybolmaz. _Kaynak:_ OP-24; U32. _Durum:_ belirtilmemiş.
- [ ] **Failover orkestratörü (CNPG/Patroni) ve fence şartı** — Yalnız aynı cluster içinde promote. _Kaynak:_ §17.4.4; FA-13; OP-25. _Durum:_ PD (araç), FROZEN (şart).
- [ ] **Region kaybında iki yazar yok** — Cross-cell fence. _Kaynak:_ FA-13; U33. _Durum:_ belirtilmemiş.
- [ ] **Plansız bölge kaybında koşullu devam** — Kanıtlı fence + son head kapsamı; yoksa fail-closed. _Kaynak:_ §17.4.1; FA-13. _Durum:_ belirtilmemiş.
- [ ] **Split-brain kuralı** — Grace 0 + failover 30 s; security event'leri senkron commit. _Kaynak:_ SA-47; SA-T16. _Durum:_ PD.
- [ ] **Sequencer graceful step-down** — Lease açıkça bırakılır, yeni leader beklemeden devralır. _Kaynak:_ §17.4.10; OP-31. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **Identity plane DB failover davranışı** — Havuz tahliyesi, `target_session_attrs=read-write`. _Kaynak:_ §16.7.1. _Durum:_ belirtilmemiş.
- [ ] **Read replica kuralı** — Güvenlik okumaları primary'den; profil ekranı için LSN tabanlı read-your-writes. _Kaynak:_ §17.4.6; OP-27; OPI-2. _Durum:_ belirtilmemiş (FROZEN).

#### Arıza davranışı ve bozulmuş mod

- [ ] **Failure contract'lar (authority) / failure modları tablosu** — Leader çökmesi, failover, AZ/bölge kaybı, ağ bölünmesi, zaman uyuşmazlığı/saat sapması, HSM/witness/NATS/derived kesintisi vb. için dürüst davranış tablosu. _Kaynak:_ §16.7; §17.4.2. _Durum:_ belirtilmemiş (normatif).
- [ ] **Failure contract'lar (identity)** — PG failover, standby yokluğu, epoch cache stale, DB erişilemez, bölge kaybı, Argon2 havuzu, signer erişilemez. _Kaynak:_ §16.7.1. _Durum:_ belirtilmemiş.
- [ ] **Hata enjeksiyonu davranışları** — DB kaybı → introspection `active=false`; refresh 503 + Retry-After; HSM down → DENY/503; signer çökmesi → imza yok, ALLOW yok. _Kaynak:_ §14.8. _Durum:_ belirtilmemiş.
- [ ] **Bozulmuş mod yalnız beyanlı yollarla** — TI-9, SEC27 ve SI-22 yolları dışında bozulmuş mod yoktur. _Kaynak:_ §6.2; §12.0.4; INV-26. _Durum:_ belirtilmemiş.
- [ ] **Identity bozulmuş mod ve kademeli bozulma tablosu** — Yeni login/refresh/kayıt/admin yazma/iptal 503; JWT doğrulama sürer. _Kaynak:_ §17.7.2; OP-45. _Durum:_ belirtilmemiş (FROZEN).

#### Yedekleme, geri yükleme ve felaket kurtarma

- [ ] **Yedekleme (pgBackRest/wal-g) ve PITR** — Tam/fark/artımlı, şifreli, çoklu depo, bütünlük doğrulaması. _Kaynak:_ §2.2.1; §17.10.3; OP-57. _Durum:_ PD (araç).
- [ ] **PITR sonrası authority log tamamlama** — Replica'dan suffix + witness checkpoint karşılaştırması. _Kaynak:_ §17.10.3; OP-57. _Durum:_ belirtilmemiş.
- [ ] **Record-fold ile rebuild / state kurma** — Derived yapılar ve devralan provider'ın state'i log kayıtlarından yeniden kurulur; rebuild-diff, Genesis'ten fold hakemliği yapılır; snapshot yalnız hızlandırıcıdır. _Kaynak:_ §6.7, §6.8; §7.1; §9.15; P4; TI-16; TI-RT1; TI-RT4. _Durum:_ belirtilmemiş (FROZEN §9.15).
- [ ] **Domain düzeyinde yeniden kurma (authority plane)** — Genesis'ten fold, HANDOFF/ACCEPTANCE ile bağımsız hedefe. _Kaynak:_ §17.10.5; HL-32; OP-59. _Durum:_ belirtilmemiş.
- [ ] **Cluster PITR ile yan restore + seçici/mantıksal aktarım (identity/realm)** — Ayrı ortama kurtarma ve realm için mantıksal kopyalama belgelenen yoldur. _Kaynak:_ §17.10.5; HL-32; OP-59. _Durum:_ belirtilmemiş.
- [ ] **Commitment-eşleşen kopyadan geri yükleme** — Meşru bir geri yüklemedir. _Kaynak:_ §6.7, §6.8; §16.7; FA-14; TI-1; TI-RT11. _Durum:_ belirtilmemiş.
- [ ] **Depolama sessiz bozulması tespiti** — Page checksum, ECC, commitment doğrulama. _Kaynak:_ §16.7; FA-14. _Durum:_ belirtilmemiş.
- [ ] **Identity plane async DR profili** — Tek bölge + async kopya; RPO > 0 beyanlı; promote sonrası herkes yeniden login olur. _Kaynak:_ §16.7.1; §17.4.8; HL-31; OP-29. _Durum:_ belirtilmemiş.
- [ ] **Periyodik kurtarma tatbikatı (9 madde)** — _Kaynak:_ §17.10.3; OP-57. _Durum:_ FROZEN (maddeler), PD (çeyreklik).

#### Provider değişimi ve domain kurtarma

- [ ] **Kooperatif provider handover (`domain.handover`)** — Eski + yeni provider + meta-anchor root katkısıyla, pozisyon tabanlı kesimle kayıpsız yapılır; eski anahtarlar `superseded-at C_{h+1}` olur, handover drain uygulanır; çıkış replay divergence ile durdurulmaz. _Kaynak:_ §6.5; §7.9.11.2; §9.15; §13.2; AP-13; E20; G32; P4; PI-15; U27. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Forced recovery (`domain.recover`)** — Eski provider ulaşılamaz veya kötü niyetliyse root'un meta-Exercise'ı (rootTerms recovery entry) ile yapılır; k-of-n offline recovery anahtarı (org 3-of-5, küçük 2-of-3, ≥ 2 donanım-bağlı), provider imzası gerekmez, domain kilitlenmez; checkpoint N cite edilir ve kayıp suffix riski beyan edilir. _Kaynak:_ §6.5; §7.9.11.2; §9.13.7; §9.15; §13.6; §13.7.7; P4; PI-15; SEC20–SEC22; U24. _Durum:_ belirtilmemiş (FROZEN); PD (§13.6 parametreleri).
- [ ] **Rollback guard (R*)** — Değerlendirici her witness'ın ve replica'nın en yüksek checkpoint'ini kendisi sorgular; N < R* ise DENY; replica yoksa REQUIRE_ACTION + beyanlı kayıp suffix. _Kaynak:_ §9.15; §13.6; SEC22. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Çatallanma beyanı** — Recovery çatallanma pozisyonunu ve çelişen Claim'leri beyan eder; N kayıtlarla desteklenen dalı izler. _Kaynak:_ §13.6. _Durum:_ belirtilmemiş.
- [ ] **Kayıp revocation'ların keşfi ve yeniden yapılması (PR-2…PR-5)** — Decision Receipt'ler, witness log'ları, eski provider export'u ve PEP ack Claim'leriyle keşfedilen kayıp suffix revocation'ları prospective olarak yeniden yapılır; kayıp draw'larda BudgetTerm daraltılır. Witness/replica-before-ack + rollback guard ile ack edilmiş revocation/CT3 kaybı olmaz. _Kaynak:_ §6.5; §9.15; §13.6; SEC23; U10. _Durum:_ belirtilmemiş.
- [ ] **Post-recovery quarantine (SEC22 R1)** — Eski projection'lar yalnız inclusion proof veya re-issue ile kabul edilir; CT2+ REQUIRE_ACTION; `nonce-closed/pre-recovery`; kaldırma CT3 gerektirir. _Kaynak:_ §9.6; §9.15; §13.6 PR-1; SEC22 R1; U28. _Durum:_ belirtilmemiş.
- [ ] **Divergence quarantine** — Divergent kaydın genişletici effect'leri DENY edilir; uyuşmazlık çıkışı durdurmaz; kaldırma CT3 gerektirir. _Kaynak:_ §9.15; G32; TI-RT1. _Durum:_ belirtilmemiş.
- [ ] **Eski provider'ın yazmayı fiilen kesmesi (fencing)** — _Kaynak:_ U11. _Durum:_ belirtilmemiş.
- [ ] **Provider çıkışı / taşınabilirlik** — Divergence çıkışı durdurmaz (DORA çıkış eşlemesi). _Kaynak:_ §14.9; G32. _Durum:_ belirtilmemiş.
- [ ] **Suiss-hosted domain'lerde recovery yolu varsayılan beyanlı** — _Kaynak:_ §6.5; §9.17 anti-hostage k.4; PI-15. _Durum:_ belirtilmemiş.
- [ ] **Forced provider migration UX** — "Changes after 11:02 may be lost. If you revoked anything after 11:02, revoke it again"; eski provider'ın sonraki kararları geçersizdir. _Kaynak:_ §8.13; §8.17.9.7; E20. _Durum:_ belirtilmemiş.
- [ ] **Handover/recovery geçmişi gösterimi** — _Kaynak:_ §8.12; §8.17.9.7. _Durum:_ belirtilmemiş.

#### Sürüm, yükseltme ve göç

- [ ] **Rolling upgrade ve N-1 / karışık sürüm güvenliği** — Uyumluluk metadata'sı, sürüm kapısı + activation record, DB'de uçucu durum ve outbox cache invalidation; farklı semantikle commit yok. _Kaynak:_ §17.10.2; G64; OP-56. _Durum:_ belirtilmemiş (FROZEN TECHNICAL).
- [ ] **Leader seçiminde semantik sürüm kapısı** — _Kaynak:_ §17.4.10; §17.10.2; OP-56. _Durum:_ belirtilmemiş.

#### Performans ve kapasite

- [ ] **Identity plane performans hedefi** — Aynı donanım ve Argon2 maliyetinde daha yüksek login/sn; login'in refresh'i aç bırakmaması. _Kaynak:_ §4.10; MKT-8. _Durum:_ EA.
- [ ] **Kapasite planı ve performans bütçeleri** — İstek türü başına bütçe; iç hedef. _Kaynak:_ CR-17; OP-72. _Durum:_ EA.
- [ ] **Kapasite planlama yöntemi (Little yasası)** — _Kaynak:_ §17.5.1. _Durum:_ EA.

### K18 Açık kaynak, ticari model ve paketleme

#### Açık kaynak bileşenler

- [ ] **Açık ve tekrarlanabilir ölçek ölçümü** — Yük testi düzeneği açık kaynak; sonuçlar ortam bilgisiyle her sürümde yayınlanır; ölçülmemiş sayı satışta kullanılmaz. _Kaynak:_ §17.14; OP-61. _Durum:_ FROZEN TECHNICAL (düzenek), EA (hedefler).

#### Suiss bağımsızlığı ve kilitlenmeme (anti-hostage)

- [ ] **Çıkış protocol özelliği; wind-down** — Non-payment dahil okuma/export/handover penceresi açık kalır. _Kaynak:_ B10. _Durum:_ belirtilmemiş.
- [ ] **Healthy defensibility** — Savunulabilirlik veriyi/DomainID'yi rehin tutmaya değil, implementasyon, deneyim ve ekosisteme dayanır. _Kaynak:_ §9.17.3. _Durum:_ belirtilmemiş.
- [ ] **Suiss-hosted domain'lerde witness/replica temini** — Root seçer; Suiss tek taraflı değiştiremez. _Kaynak:_ D5. _Durum:_ belirtilmemiş (D5 default).

#### Ticari model ve fiyat ekseni

- [ ] **Kota ve fatura askısı yalnız protocol rejection** — Ticari durum authority üretmez/silmez. _Kaynak:_ §12.1.1; TN-1. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Fiyat ekseni yalnız fiziksel farklar** — Availability, kapasite rezervasyonu, residency, retention, izolasyon, destek/SLA, konfor. _Kaynak:_ B4. _Durum:_ belirtilmemiş.
- [ ] **Kapasite rezervasyonu (sayaç değil)** — Authority commit throughput ve identity login/Argon2 kapasitesi; daraltma/çıkış kapsam dışı. _Kaynak:_ §18.5; B5, B18, H9. _Durum:_ HYPOTHESIS (H9).
- [ ] **Fair-use aşımında yalnız genişletici commit reddi** — Revocation, suspend, narrowing ingest, export/handover/recover her zaman çalışır. _Kaynak:_ B18, D7. _Durum:_ belirtilmemiş.
- [ ] **Ücretli hizmet katmanı ve seçenekler (kod açık, ücretli olan hizmet)** — Hosted provider/hosted identity plane operasyon sınıfı, multi-region DR, ayrılmış altyapı (dedicated cell/HSM partition/compute), uzun retention, SIEM connector, enterprise tooling, destek/SLA, self-host destek aboneliği, yönetilen onboarding, DNS/sertifika otomasyonu. _Kaynak:_ §9.17, §18.5, §18.6; B4, D4, H9, H14. _Durum:_ HYPOTHESIS (H9).
- [ ] **Dedicated compute (B4 opsiyonu, ücretli)** — Ayrılmış hesaplama kaynağı ücretli maliyet seçeneği olarak sunulur. _Kaynak:_ B4, CR-40 madde 4, DL-10, MD-17, SA-25. _Durum:_ HYPOTHESIS (fiyat).

### Bu aşamada doğrulanacak sınırlar

#### Ürün kapsamı

- [ ] **Suiss zorunlu witness, registry veya trust anchor değil** — _Kaynak:_ §9.16; §9.17. _Durum:_ belirtilmemiş.

#### Karar ve tutarlılık

- [ ] **Anonymous istek `domain.recover` yapamaz** — _Kaynak:_ §9.13.7. _Durum:_ belirtilmemiş.

#### Federasyon, şema ve güven

- [ ] **Suiss kendi host ettiği domain için bağımsız witness / provider-dışı replica sayılmaz** — _Kaynak:_ B13. _Durum:_ belirtilmemiş.

#### Kriptografi

- [ ] **Re-anchor'da kayıt başına yeniden imza yok** — _Kaynak:_ CR-45 RA-4. _Durum:_ belirtilmemiş (FROZEN).

#### Veri, depolama ve yüksek erişilebilirlik

- [ ] **Active-active canonical yazma ve aynı domain için iki eşzamanlı authoritative writer yok** — Bir domain'in aynı anda tek yetkili cell/epoch'u vardır; last-writer-wins, quorum'suz çok-primary ve kıtalar arası sync yazma yoktur. _Kaynak:_ §7.9.11.2; §17.4.1; E20; OP-28; OP-54; OPI-5; T28. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Async kopya promote edilmez (authority)** — _Kaynak:_ §17.4.1; FA-13; OP-S12; T28. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Cluster'lar arası otomatik failover yok; fence kanıtsız promote yok** — _Kaynak:_ OP-25; OP-54. _Durum:_ belirtilmemiş.
- [ ] **Tek standby ile `synchronous_commit=on` yok; güvenlik yazmalarında `local` yok** — _Kaynak:_ OP-24. _Durum:_ belirtilmemiş.
- [ ] **Asenkron replica'dan güvenlik okuması yok** — _Kaynak:_ OP-27; OPI-2. _Durum:_ belirtilmemiş.
- [ ] **Kiracı/realm bazında satır düzeyinde geri yükleme yok** — Ürün özelliği olarak vaat edilmez (identity plane dahil). _Kaynak:_ HL-32; N-58; OP-59. _Durum:_ belirtilmemiş.

#### Denetim, saklama ve gözlemlenebilirlik

- [ ] **Redaksiyonun replica/export kopyalarına yayılması vaat edilmez** — _Kaynak:_ N-11; OP-40. _Durum:_ belirtilmemiş.

## Aşama 14 — İleri güvence

Formel doğrulama, PQC, sabit zaman ve yan kanal testleri, sertifikalar, bağımsız denetim, bug bounty, CRA hazırlığı.

### Spec dışı ön koşullar

- [ ] **Sabit zaman testleri için gürültüsüz ölçüm ortamı** — dudect ve ctgrind.
- [ ] **Lean araç zinciri ve DRT koşum düzeneği** — Rust ↔ Lean karşılaştırmalı testinin CI'a kurulması (MD-15).

### K01 Kimlik doğrulama yöntemleri

#### Genel model ve tipli sonuç

- [ ] **PQ hazırlığı (kimlik doğrulamada)** — Kimlik doğrulama yöntemlerinde post-quantum hazırlığı. _Kaynak:_ §2.2.1. _Durum:_ belirtilmemiş.

#### Passkey / WebAuthn: doğrulama politikaları

- [ ] **WebAuthn ML-DSA algoritmaları** — _Kaynak:_ §10.2.4, §10.8.1. _Durum:_ WATCH.

### K08 Karar, uygulama ve doğrulama

#### Projection'lar ve yetki artefaktları

- [ ] **Verifier PQ anchor tutma (pin)** — Verifier PQ checkpoint/anahtarlarını kırılmadan önce pin'leyebilir veya Verifier Profile'a gömebilir. _Kaynak:_ §15.18. _Durum:_ belirtilmemiş.
- [ ] **Referans taşıma (büyük PQ artefaktı)** — Bütçeyi aşan projection digest + fetch ile sunulur. _Kaynak:_ CR-43. _Durum:_ PD.

### K13 Denetim, kayıt, şeffaflık ve dışa aktarım

#### Checkpoint, witness ve replica

- [ ] **Son PQ re-anchor checkpoint'inin yayını** — Domain Metadata'da boyut ve zaman yayımlanır. _Kaynak:_ RR-35. _Durum:_ belirtilmemiş.

#### Provider beyanları ve şeffaflık yayınları

- [ ] **Formel doğrulama manifestosu** — Hedef, araç, teorem, statü, varsayımlar makine-okunur; `planned|modelled|proved|DRT-linked`. _Kaynak:_ CR-46, CR-50. _Durum:_ belirtilmemiş (FROZEN).

### K14 Sinyaller, gözlemlenebilirlik ve analitik

#### Operasyon sinyalleri, metrikler ve alarmlar

- [ ] **Hibrit KEX kırılma telemetrisi ve alarm** — _Kaynak:_ CR-12. _Durum:_ belirtilmemiş.

### K15 Güvenlik ve kriptografi

#### Kripto çevikliği ve post-kuantum

- [ ] **Algoritma emekliliği (üç adım)** — _Kaynak:_ §15.16. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **ML-DSA-65 opt-in PQ imza profili** — Post-quantum imza opt-in; domain/realm seçer (CT3). _Kaynak:_ §3.4; §4.8 eksen 11; §9.15.1 k.1; §13.2; CR-41; MD-3; P60. _Durum:_ belirtilmemiş (FROZEN; opt-in).
- [ ] **ML-DSA-44 boyut kısıtlı profil** — QR/NFC offline PAP için. _Kaynak:_ CR-41; CR-43. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **ML-DSA-87 CNSA profili** — _Kaynak:_ CR-41. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Kendi ince ML-DSA COSE/JWS katmanı** — aws-lc-rs üzerinde, Kernel'de. _Kaynak:_ CR-41 madde 4. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Hibrit imza deseni (çift COSE_Sign1)** — Aynı payload üzerinde klasik + ML-DSA imza. _Kaynak:_ CR-42 madde 4. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Composite imza** — Tek algoritma kimliği, iki bileşen zorunlu; RFC olunca CT3 ile. _Kaynak:_ CR-42; SAI-44. _Durum:_ WATCH.
- [ ] **PQ boyut bütçesi testleri** — Header ≤ 8 KB, cookie ≤ 4 KB, QR/NFC. _Kaynak:_ CR-43. _Durum:_ PD.
- [ ] **PQ re-anchoring ("existed by T")** — RA-1…RA-7: ML-DSA ile re-anchor checkpoint, bağımsız PQ witness cosign, consistency proof, PQ inclusion bundle; kayıtlar yeniden imzalanmaz. Algoritma kırılması ilanından sonra bundle'sız klasik artefakt reddedilir; kapsanan kayıtlar doğrulanabilir kalır. _Kaynak:_ §9.10; §13.2; CR-45; FA-5; MD-19.3; P3; U68. _Durum:_ belirtilmemiş (FROZEN; kadans PD).
- [ ] **JWE PQ yöntemi** — _Kaynak:_ §10.8.3. _Durum:_ WATCH.

#### Transport ve servis kimliği

- [ ] **İç mTLS'te ML-DSA kimlik doğrulaması** — _Kaynak:_ CR-12 madde 4. _Durum:_ WATCH.

#### Sabit zaman ve yan kanal

- [ ] **Yan kanal korumaları** — Kriptografik yan kanal saldırılarına karşı önlemler. _Kaynak:_ §2.2.1 (Kripto satırı). _Durum:_ belirtilmemiş.
- [ ] **ARM64 DIT** — _Kaynak:_ CR-39 madde 6. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Zamanlama/boyut dolgusu (içerik deterministik)** — _Kaynak:_ CR-40 madde 3. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Paylaşılan HSM partition / co-tenant yan kanal risk beyanı** — Baseline'da müşteriye bildirilir. _Kaynak:_ §18.5; §18.6; HL-8; HL-17; RT12. _Durum:_ belirtilmemiş.

#### Hesap numaralandırma ve kimlik bilgisi saldırıları

- [ ] **HTTP/2 Timeless Timing savunması** — _Kaynak:_ §10.2.1 madde 7. _Durum:_ WATCH.

#### Güvence, denetim ve tehdit modeli

- [ ] **Formel model: Lean modeli + Kani hedefleri (release kapısı)** — Authority algebra'nın Lean modeli; kernel fonksiyonları için Kani hedefleri (ör. zincir derinliği değişmezi). _Kaynak:_ §3.3a; F13; F20; L10; MD-15. _Durum:_ belirtilmemiş.
- [ ] **Formel doğrulama kapsam beyanı** — "Property *P* of model *M* is machine-checked (Lean/Kani/TLA+); see scope". _Kaynak:_ §8.10; MD-15; X41. _Durum:_ belirtilmemiş.
- [ ] **Periyodik bağımsız crystal-box denetim** — Identity plane, Kernel, verifier'lar ve kripto için kod ve tasarımın bağımsız dış denetimi; ilki ilk açık sürümden önce; raporlar yayınlanır. _Kaynak:_ §18.12; MD-16. _Durum:_ belirtilmemiş (ilki ilk açık sürüm öncesi).
- [ ] **Red team (teknik + semantik)** — AS-16 SAML/XML, AS-17 LDAP, AS-18 SCIM, AS-19 parola/login/recovery yüzeyleri ilk açık release'ten önce red team'den geçer. _Kaynak:_ §14.3; SA-8. _Durum:_ EA (takvim).
- [ ] **AiTM / BitM purple-team laboratuvarı** — Evilginx sınıfı ve CuddlePhish ile periyodik lab. _Kaynak:_ §14.3; SA-12. _Durum:_ PD.
- [ ] **Blast radius / trust model beyanı** — Her bileşen (root, provider, operatör, IdP, issuer, publisher, PEP, verifier, executor, surface, witness, gateway, SCIM, parser worker, co-tenant, destek) için güven ve "asla" sınırı ile containment lever'ı yayımlanır. _Kaynak:_ §13.2; SA-7; SEC5. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Security verdict ve beyan edilmiş sınırlar** — "SECURE WITH DECLARED LIMITS"; DL-1…DL-10 açıkça yayımlanır. _Kaynak:_ §13.1; SEC1. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Residual risk register (RR-1…RR-45)** — Her risk owner, kabul gerekçesi ve izleme sinyaliyle. _Kaynak:_ §13.9. _Durum:_ belirtilmemiş.
- [ ] **Known Hard Limits listesi (HL-1…HL-40)** — Hiçbir hard limit ürün vaadine girmez. _Kaynak:_ §13.5; RT28. _Durum:_ belirtilmemiş.

### K16 Gizlilik, rıza ve uyum

#### Mevzuat ve standart eşlemeleri

- [ ] **Sektörel uyum eşlemesi** — PCI DSS, HIPAA, FedRAMP/OMB M-22-09, SOC 2/ISO 27001, NIS2, DORA (kanıt paketi + çıkış), eIDAS 2.0, PSD2 SCA, TR ödeme, OWASP ASVS 5.0, WCAG 2.2, residency; yeni iddia üretmez. _Kaynak:_ §14.9; SA-53. _Durum:_ belirtilmemiş.
- [ ] **NIST SP 800-63-4 uyum eşlemesi** — _Kaynak:_ §10.3.1. _Durum:_ belirtilmemiş.
- [ ] **TR ÖHY/BS Tebliği GKD şablonu** — Dokümantasyon m.22/7, yılda iki test, SPK VII-128.10; mevzuat uygunluğu NOT GUARANTEED. _Kaynak:_ §10.3.4; IDP-9. _Durum:_ PD.
- [ ] **PCI DSS 4.0 Req 8 ve OMB M-22-09 authentication gereksinimleri** — _Kaynak:_ §10.3.4. _Durum:_ belirtilmemiş.
- [ ] **Denetim kaydı uyum eşlemesi (PCI DSS 4 Req. 10, NIST AU-9/AU-10)** — Akışlı export ile karşılanır, PCI audit penceresi gereksinimleri dahil; uzun sıcak pencere ücretli olabilir. _Kaynak:_ §17.6.7; §18.2; §18.6; H17. _Durum:_ belirtilmemiş.
- [ ] **EUDI Wallet hazırlığı (Ara 2026 / Ara 2027 takvimi)** — _Kaynak:_ §10.7.2. _Durum:_ PD.
- [ ] **NIS2/DORA kanıt paketi** — SBOM, denetim raporları, PSIRT, SLA. _Kaynak:_ §14.9. _Durum:_ belirtilmemiş.
- [ ] **OWASP ASVS 5.0 kontrol listesi** — Hedef L3 identity plane, L2 diğer (çıkarım). _Kaynak:_ §14.9; SA-55. _Durum:_ PD.
- [ ] **FIPS 140-3 uyum profili (kamu, finans, FedRAMP)** — ES256/ESP256; FIPS ve PQ profili aynı anda seçilemez. _Kaynak:_ §14.9; CR-15; HL-27. _Durum:_ belirtilmemiş (FROZEN; §14.9'a göre düşük öncelik).
- [ ] **HIPAA BAA** — Ticari karar. _Kaynak:_ §14.9. _Durum:_ belirtilmemiş.

#### Cyber Resilience Act (CRA)

- [ ] **CRA uyumu ve hazırlığı** — Suiss üretici rolünde (self-host binary, SDK, mobil), ürün varsayılan Class I; Art.14 PSIRT runbook; CRA-C1 açık zafiyet kanalı (security.txt + SECURITY.md), CRA-C2 CVD + GHSA, CRA-C3 CNA (GitHub CNA/RustSec); tam uyum 11 Aralık 2027. _Kaynak:_ §2.2.1; §14.9; §18.9 D-10; §18.11; D-10; MD-12; SA-48. _Durum:_ PD (Adem kararına kadar); D-10 Adem onayı bekliyor ("hemen").
- [ ] **CRA bildirim süreleri** — 24 saat erken uyarı, 72 saat bildirim, 14 gün / 1 ay nihai rapor. _Kaynak:_ §18.11. _Durum:_ belirtilmemiş.
- [ ] **Yayınlanmış güvenlik destek süresi** — Her major sürüm için. _Kaynak:_ §14.9. _Durum:_ belirtilmemiş (açık soru).

#### Sertifikasyon ve denetim

- [ ] **SOC 2 Type II (custodial hizmet) + crystal-box denetimleri** — Identity plane, Kernel, verifier'lar ve kripto denetlenir; ilki ilk açık release'ten önce; raporlar yayınlanır. _Kaynak:_ §14.4; §18.9 D6; §18.12; MD-16; SA-17. _Durum:_ belirtilmemiş (FROZEN; D6 default).
- [ ] **Sertifika hedef listesi** — OpenID Certified (OP Basic, Config, Dynamic, Form Post, oturum kapatma), FAPI 2.0 OP, ISO 27001/27017/27018, SOC 2 Type I/II, BDDK dış hizmet uyum, HIPAA, FedRAMP. _Kaynak:_ IDP-12; SA-56. _Durum:_ WATCH (talep üzerine).

### K17 Dağıtım, operasyon, yüksek erişilebilirlik ve felaket kurtarma

#### Sürüm, yükseltme ve göç

- [ ] **Güvenlik düzeltme desteği (son iki minor)** — _Kaynak:_ OP-68. _Durum:_ PD.

### K18 Açık kaynak, ticari model ve paketleme

#### Açık protokol ve yönetişim

- [ ] **Vendor-neutral protocol governance (neutral vakıf/SDO)** — Protokol neutral bir vakıf/SDO tarafından yönetilir; Suiss tek başına normatif değişiklik yapamaz. Genişleme yerel ve namespaced'dir, kapalı kümeler governance ister; upstream WG'lerle (AuthZEN, SSF/CAEP, OAuth RAR) çalışılır. _Kaynak:_ §7.1, §9.17, §9.17.1; D3, P34. _Durum:_ belirtilmemiş (FROZEN; D3 default).
- [ ] **Conformance ≠ endorsement** — Suite'i geçmek Suiss onayı veya ticari ilişki gerektirmez; Suiss-hosted da suite'e tabidir. _Kaynak:_ §9.1, §9.17; B9, P2. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Upstream standart katkıları (backlog)** — Katkılar: ADP'nin AuthZEN WG'ye profil olarak sunulması, Access SSF event türlerinin SSF WG'ye, consistency_token boşluğu, AARP eşlemesi, ajan CAEP olayları, MCP SEP eşlemesi, `act` profili, RAR type kaydı, A2A extension, Txn-Token/WIMSE güncellemesi. _Kaynak:_ §9.17.5. _Durum:_ yol haritası.

#### Ücretlendirilemez güvenlik ve temel yüzeyler

- [ ] **Güvenlik düzeltmeleri her zaman açık sürümde** — Ücretli destek yalnız erken bildirim (CVD ambargosuyla sınırlı) ve uygulama yardımıdır. _Kaynak:_ B20. _Durum:_ belirtilmemiş.

#### Pazara giriş, sertifika ve topluluk

- [ ] **Hedef sertifikalar: OIDF FAPI 2.0 OP sertifikası** — _Kaynak:_ §10.4.7, §10.5.1; IDP-12. _Durum:_ WATCH (sertifika tarihi).
- [ ] **Referans ve topluluk** — Suiss ürünleri ilk üretim müşterisi (ayrıcalıksız), 5–10 tasarım ortağı (Türkiye öncelikli), vaka çalışmaları, açık yol haritası, protocol RFC süreci, forum, katkıcı rehberi. _Kaynak:_ B24. _Durum:_ belirtilmemiş (ilk açık sürüm öncesi tasarım ortakları).
- [ ] **Açık kaynak güvenlik fonlarına başvuru** — NGI Zero Commons, OSTIF, Alpha-Omega, STF, GitHub SOSF. _Kaynak:_ §14.4; SA-18. _Durum:_ HYPOTHESIS.

#### Güvenlik açığı yönetimi ve yayın şeffaflığı

- [ ] **Bug bounty (ilk açık sürümle)** — _Kaynak:_ §14.4; SA-57. _Durum:_ belirtilmemiş (FROZEN); ödül tablosu/platform PD.
- [ ] **Açık güvenlik sayfası** — GHSA duyuruları, denetim raporları, CVD politikası ve düzeltme süreleri tek yerde. _Kaynak:_ B20, SA-57. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **CVE ataması ve advisory kanalları** — Önce GitHub CNA, sonra kendi CNA; RustSec + npm/GitHub advisory; Go vuln DB yalnız Go profili etkinleşirse. _Kaynak:_ SA-15. _Durum:_ PD.
- [ ] **PSIRT runbook ve CRA Art.14 bildirim akışı** — Triage, CVSS v4, advisory, ENISA/CSIRT bildirimi. _Kaynak:_ §14.4; MD-12, SA-16. _Durum:_ belirtilmemiş (runbook FROZEN, süreler PD).

### K19 Geliştirme ve kalite güvencesi

#### Release kapısı ve formel doğrulama

- [ ] **Release kapısı (DRT: Rust Kernel ↔ Lean yürütülebilir model)** — Normatif/conformance vektörleri, DRT (Rust ↔ Lean) ve kanıtlar geçmeden semantik sürüm release edilmez; frozen semantiği yalnız model karşı-örneği açar. _Kaynak:_ §3.2, §6.8; F20, MD-15, SA-42, TI-RT12, U56. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **Formel doğrulama katmanlı planı** — fuzz, Kani, Flux, Loom/Shuttle, Lean, DRT, TLA+, Stateright. _Kaynak:_ CR-46…CR-48; T38. _Durum:_ yol haritası (`planned`; efor HYPOTHESIS).
- [ ] **Kani hedefleri CR-K1…CR-K9** — _Kaynak:_ CR-47. _Durum:_ belirtilmemiş (FROZEN; efor HYPOTHESIS).
- [ ] **Grant cebiri Lean modeli** — Pozitif cebir için ayrı bir Lean modeli yazılır. _Kaynak:_ §5.8; INV-8. _Durum:_ belirtilmemiş.

#### Protokol, kiracı ve bileşen güvenlik testleri

- [ ] **Fuzzing ve crystal-box denetim** — _Kaynak:_ CR-50 R5, SA-17, T42 madde 4. _Durum:_ belirtilmemiş.

### Bu aşamada doğrulanacak sınırlar

#### Kriptografi

- [ ] **Composite bileşenlerin ayrı kabulü (stripping) yok** — _Kaynak:_ CR-42; SAI-44. _Durum:_ belirtilmemiş (FROZEN).
- [ ] **PQ JWE yok (şifreli identity token'lar klasik)** — _Kaynak:_ CR-4; RR-36. _Durum:_ belirtilmemiş.
- [ ] **SAML'de PQ yok** — _Kaynak:_ §10.8.3. _Durum:_ belirtilmemiş.
- [ ] **WebAuthn/passkey'de PQC yok** — _Kaynak:_ CR-43; HL-19. _Durum:_ belirtilmemiş.
- [ ] **Tarayıcıya dönük TLS'te ML-DSA sertifikası yok** — _Kaynak:_ CR-12 madde 5. _Durum:_ belirtilmemiş.
- [ ] **FIPS + PQC aynı anda yok** — _Kaynak:_ CR-44; HL-27. _Durum:_ WATCH.

#### İş modeli ve lisans

- [ ] **Suiss sertifika/assessment hizmeti satmaz; denetim "Suiss sertifikası" olarak satılmaz** — _Kaynak:_ §18.12; D3. _Durum:_ belirtilmemiş.

#### Ekosistem sınırından gelen kurallar

- [ ] **Formel doğrulamanın ve derleyicinin kapsamadıkları** — Async runtime ve HTTP katmanı formel doğrulamanın kapsamı dışındadır (HL-15 → HL-29); derleyici sabit zaman garantisi vermez (HL-16). Bunlar bilinen kalıcı sınırlar olarak beyan edilir. _Kaynak:_ §14; SA-13, HL-15, HL-16, HL-29. _Durum:_ belirtilmemiş (FROZEN; NG).

