## 20. Açık Sorular, Adem Kararları ve Kalan İşler

### 20.1 Adem kararları
- **D1–D9:** §18'de.
- **D-10:** CRA rolü. Varsayılan: Suiss manufacturer, Class I (MD-12). Onay bekliyor.
- **D-11 (aday):** SSO'nun ücretsiz olması (§18).
- **Türetilmiş, Adem görsün:** Passkey RP ID için özel alan adı ücretlendirilemez (B3'ten).
- **MD-1 dil kararı:** Rust tek backend. Bedeli 12–18 geliştirici-ayı ek AS işi (HYPOTHESIS). **Adem tarafından kabul edildi;** risk azaltma T42'dedir.

### 20.2 Açık teknik sorular
- OQ-MD1 Rust witness/NATS/SPIFFE istemci olgunluğu; OQ-MD2 Cedar forbid-only + REQUIRE spike'ı; OQ-MD3 identity plane outbox algoritması; OQ-MD4 Kernel Wasm/FFI performansı.
- OQ-CR1 Ed25519 doğrulama denklemi (cofactored/cofactorless); OQ-CR2 aws-lc-rs `no_std`/Wasm derlenebilirliği; OQ-CR4 V6 test vektörü sınıfının içeriği ve CR-51 listesine girişi. (OQ-CR3 kapandı → OP-60.)
- OQ-1: commit throughput/p99 ölçümleri; bütün EA sayıları ölçülmedi.
- Opak `basis_ref` ile içerik-pozisyonu karşılaştırması (P44).
- Sign-out'taki `instance.terminate`'i hangi actor yapar (kullanıcının Instance'ı mı, identity plane servis Party'si mi).
- Bölüm sonlarındaki "açık sorular" ve "doğrulanamayan iddialar" listeleri (§4, §10.13, §11.23, §12.11–12.12, §14.10, §15.22–15.23, §17.12, §17.15) bu bölümün parçasıdır.

### 20.3 Kalan editoryal işler
1. §13 numaralandırması §13.13'tedir. "§13'e aday" satırlarının kaynak bölümlerdeki metinleri (§9.11.2, §10.12, §11, §12.10, §15.20, §17.13) henüz yeni G/U/N/HL/RR numaralarına atıf vermiyor.
2. ~~§10.2.1 kural 1 identifier-first olarak düzeltilecek~~ — tamamlandı: §10.2.1 ve CR-40 TN-96'ya göre düzeltildi.
3. §6 PI-15 ve §13 U27'ye aynı-provider self-handover notu eklenecek.
4. SYNC-DERIVED tablolar `domain_id` ile anahtarlanır; ek olarak `tenant_id` + RLS FORCE (§17'deki "çıkarım" etiketi kaldırılacak).
5. §13.7.1 CT3 örneklerine kalıcı silme, realm imza anahtarı rotasyonu, yönetici göç dışa aktarımı; hesap durumu DENY overlay PD satırı eklenecek.
6. §12'deki T20/T26/T27/T33 cümleleri §16.10'a taşınacak.
7. §12 ve diğer bölümlerde tam metin duran C/INV/E/X/SI kopyaları kanonik yere atfa indirilecek (çelişkide kanonik metin kazanır).
8. Ek A emekli ID listesi: HL-25, HL-26, HL-28, HL-30, RR-40, RR-41, RR-42; yerel etiket aileleri CRA-C, X-L, TN-H/G/K/O/Y, OP-S, CR-K, EP, SA-T, RB, SL; §13 numaraları G57–G64, U60–U71, N-50–N-59, HL-35–HL-40, RR-43–RR-45, EP-10; RR-39 rezerv.
