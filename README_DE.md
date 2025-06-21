# Dsls-OTP: Eine quantenresistente Netzwerksicherheitslösung optimiert mit OTP

[English](READM.md) / [简体中文](README_CN.md) / [日本語](README_JP.md) / [Français](README_FR.md) / Deutsch

## ✨ Projektübersicht

Dsls-OTP ist eine quantenresistente Netzwerksicherheitslösung, die mit Einmal-Pad (OTP)-Verschlüsselung optimiert wurde. Durch die Kombination eines optimierten OTP-Mechanismus mit modernen Verschlüsselungsalgorithmen und quantenresistenten Technologien bietet es außergewöhnlichen Datenschutz. Die integrierte Netzwerkübertragungsfunktion macht die sichere Dateiübertragung einfach und effizient und ist an verschiedene Netzwerkumgebungen anpassbar.

Ob für ressourcenbeschränkte eingebettete Geräte oder leistungsstarke Standardanwendungen, Dsls-OTP bietet flexible Lösungen.

---

## 🚀 Hauptfunktionen

- **Höchste Sicherheit**: Verwendet branchenführende Verschlüsselungsalgorithmen wie AES-GCM und ChaCha20 in Kombination mit Kyber und Dilithium für Quantenresistenz, um zukünftige Bedrohungen abzuwehren.
- **Unterstützung mehrerer Modi**: Bietet leichte und Standardmodi, um den Leistungsanforderungen verschiedener Geräte gerecht zu werden.
- **Effiziente Übertragung**: Eingebaute Netzwerkübertragungsfunktionen ermöglichen eine schnelle und sichere verschlüsselte Dateiübertragung und verbessern die Betriebseffizienz erheblich.
- **Intelligente Schlüsselverwaltung**: Enthält Tools zur Erstellung und Verwaltung von ECC-Schlüsselpaaren, die Schlüsseloperationen vereinfachen und gleichzeitig die Sicherheit gewährleisten.
- **Breite Anwendungsszenarien**: Von persönlichem Datenschutz bis hin zur Dateiübertragung auf Unternehmensebene bietet Dsls-OTP eine All-in-One-Lösung für verschiedene Anforderungen.

---

## 📦 Verzeichnisstruktur

```
Dsls-OTP/
├── python/
│   ├── dsls-otp.py       # Hauptprogrammdatei
│   ├── requirements.txt  # Abhängigkeitsliste
├── README.md             # Projektdokumentation
├── LICENSE               # Lizenzdatei
```

---

## 📖 Verwendung

### 1. Datei verschlüsseln
```bash
python dsls-otp.py encrypt --input <Eingabedateipfad> --output <Ausgabedateipfad> --receiver-key <Empfänger-Öffentlicher-Schlüssel-Dateipfad> [--lightweight]
```

### 2. Datei entschlüsseln
```bash
python dsls-otp.py decrypt --input <Eingabedateipfad> --output <Ausgabedateipfad> --private-key <Privater-Schlüssel-Dateipfad> [--password <Privater-Schlüssel-Passwort>]
```

### 3. Schlüsselpaar generieren
```bash
python dsls-otp.py keygen --private-key <Privater-Schlüssel-Speicherpfad> --public-key <Öffentlicher-Schlüssel-Speicherpfad> [--password <Privater-Schlüssel-Passwort>]
```

### 4. Verschlüsselte Datei über das Netzwerk senden
```bash
python dsls-otp.py send --input <Eingabedateipfad> --receiver-key <Empfänger-Öffentlicher-Schlüssel-Dateipfad> --target <Ziel-IP:Port> [--lightweight]
```

### 5. Netzwerkdatei empfangen und entschlüsseln
```bash
python dsls-otp.py receive --output <Ausgabedateipfad> --private-key <Privater-Schlüssel-Dateipfad> [--listen <Listen-Adresse:Port>] [--password <Privater-Schlüssel-Passwort>]
```

---

## 🔧 Abhängigkeiten

- **Python**: Version 3.8 oder höher
- **Erforderliche Bibliotheken**: Installieren Sie diese mit folgendem Befehl:
  ```bash
  pip install -r requirements.txt
  ```

---

## 🛠️ Hinweise

- Stellen Sie sicher, dass der öffentliche Schlüssel des Empfängers und der private Schlüssel des Absenders sicher gespeichert werden.
- Beim Verwenden des Leichtgewichtsmodus können einige Sicherheitsparameter reduziert werden, um die Leistung zu verbessern.

---

## 📜 Lizenz

Dieses Projekt ist unter der GNU AFFERO-Lizenz Open Source. Weitere Informationen finden Sie in der [LICENSE](LICENSE)-Datei.

---

## ❤️ Community und Support

Wenn Sie Fragen oder Vorschläge haben, senden Sie diese bitte über [Issues](https://github.com/DslsDZC/Dsls-OTP/issues) oder treten Sie unserer Community-Diskussion bei.

---

## ⭐ Wie man beiträgt

1. Forken Sie dieses Repository.
2. Erstellen Sie Ihren Branch (`git checkout -b feature/AmazingFeature`).
3. Committen Sie Ihre Änderungen (`git commit -m 'Add some AmazingFeature'`).
4. Pushen Sie zum Branch (`git push origin feature/AmazingFeature`).
5. Öffnen Sie eine Pull-Anfrage.

---

## 🌟 Danksagungen

Vielen Dank an alle Entwickler, die Code, Dokumentation und Vorschläge zu diesem Projekt beigetragen haben!

<p align="center">
  <a href="https://github.com/DslsDZC/Dsls-OTP/graphs/contributors">
    <img src="https://contrib.rocks/image?repo=DslsDZC/Dsls-OTP" alt="Contributors">
  </a>
</p>
