CyberWelat Secure Chat – Şifreli ve Güvenli Mesajlaşmanın Yeni Adı

CyberWelat Secure Chat, modern çağın dijital iletişim ihtiyaçları için özel olarak geliştirilmiş, AES şifreleme teknolojisiyle donatılmış, Windows (.exe) ve Linux sistemlerinde sorunsuz çalışan, kullanımı kolay ama etkili bir güvenli mesajlaşma istemcisidir.
🚀 Başlıca Özellikler

✅ Askeri Düzeyde Şifreleme (AES-256)
Tüm mesajlarınız, AES algoritması ile uçtan uca şifrelenerek gönderilir. Anahtarlar sadece istemci tarafında girilir ve hiçbir zaman açık hâlde iletilmez. Güvenlik, bu uygulamanın temelidir.

✅ Modern, Kullanıcı Dostu Arayüz
Tkinter kütüphanesi kullanılarak tasarlanmış şık ve sade bir arayüz sunar. Kullanıcı deneyimi ön planda tutularak herkesin rahatlıkla kullanabileceği şekilde tasarlanmıştır.

✅ Sunucuya Kolay Bağlantı
IP adresi, port, şifreleme anahtarı ve kullanıcı adı girerek saniyeler içinde güvenli sohbet odasına katılabilirsiniz. .onion (Tor) adres desteğiyle anonim bağlantı desteği de sunar!

✅ Mesajlarda Emoji Desteği 😎🎉🔥
Sohbetinize renk katmak için en popüler emojiler tek tıkla mesajlarınıza eklenebilir.

✅ Renk Kodlu Mesajlaşma
Kimin ne zaman ne yazdığını kolayca ayırt edebilmeniz için mesajlar saat bilgisiyle birlikte farklı renklerde gösterilir. Sistem mesajları, sizin mesajlarınız ve diğer kullanıcıların mesajları özel renk stilleriyle biçimlendirilmiştir.

✅ Çapraz Platform Uyumluluğu
Hem Windows (.exe) olarak paketlenebilir hem de Linux sistemlerde Python ortamında çalıştırılabilir. Kodlar sade, optimize ve portatif olacak şekilde yapılandırılmıştır.

✅ Gerçek Zamanlı Sohbet
Tüm mesajlar eş zamanlı olarak alınıp gösterilir. Arka planda çalışan threading altyapısı sayesinde kesintisiz bir deneyim sunar.
🔐 Şifreleme Teknolojisi

CyberWelat Secure Chat, AES (Advanced Encryption Standard) algoritmasını CFB (Cipher Feedback) modunda kullanır.

    Mesajlarınız şifrelenmeden önce rastgele oluşturulmuş bir IV (Initialization Vector) ile karıştırılır.
    Ardından mesaj, 256-bit’lik kullanıcı anahtarıyla şifrelenir.
    Sonuçta oluşan şifreli veri, base64 formatında kodlanarak gönderilir.
    Karşı taraf bu mesajı kendi anahtarı ile çözümler.
    Anahtar her bağlantıda kullanıcı tarafından girilir ve ağda hiçbir zaman düz metin olarak dolaşmaz.

Bu sayede üçüncü tarafların mesaj içeriğine ulaşması imkânsız hale gelir. Gerçek bir uçtan uca şifreleme mimarisi!
🧠 Teknik Altyapı

    Programlama Dili: Python 3.x
    Arayüz: Tkinter
    Kriptografi: cryptography kütüphanesi üzerinden AES/CFB
    Ağ İletişimi: socket
    Çoklu İş Parçacığı: threading
    Emoji Uyumu: emoji + Unicode
    Dosya Uyumluluğu: .py olarak Linux’ta, .exe olarak Windows’ta çalıştırılabilir

👤 Geliştirici İmzası

    Uygulama, dijital güvenliğe önem veren kullanıcılar için CyberWelat tarafından özel olarak geliştirilmiştir.
    Amacımız, sade ama güçlü çözümlerle herkesin gizliliğini koruyabileceği bir dijital dünya inşa etmek.

🛡️ Kendi Sunucunuzu Kurabilirsiniz:

    Kişisel kullanım için server.py dosyasını GitHub’dan indirip kendi güvenli sohbet sunucunuzu kurabilirsiniz.

🌐 CyberWelat Sohbet Odası:

    CyberWelat’ın özel sohbet odasına katılmak isteyenler, sadece Linux sürümünü kullanarak .onion adresi üzerinden iletişime geçebilir.
    Sohbet odasının anahtarı için doğrudan CyberWelat’a ulaşmak gerekmektedir.

İndirme Linkleri

    Windows için hazır çalıştırılabilir dosya (EXE):
    https://hyper-v5.com.tr/HyperChat.exe
    Linux için kaynak kodu (GitHub):
    https://github.com/cyberwelat/HyperChat
