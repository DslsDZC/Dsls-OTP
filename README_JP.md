# Dsls-OTP: 量子耐性を備えたネットワーク暗号化ソリューション

[English](README.md) / [简体中文](README_CN.md) / 日本語 / [Français](README_FR.md) / [Deutsch](README_DE.md)

## ✨ プロジェクト概要

Dsls-OTP は、ワンタイムパッド（OTP）暗号化を最適化した量子耐性ネットワーク暗号化ソリューションです。最適化された OTP メカニズム、最新の暗号化アルゴリズム、および量子耐性技術を組み合わせることで、卓越したデータ保護を提供します。内蔵のネットワーク伝送機能により、安全なファイル転送が簡単かつ効率的になり、さまざまなネットワーク環境に適応します。

リソースが限られた組み込みデバイスから高性能な標準アプリケーションまで、Dsls-OTP は柔軟なソリューションを提供します。

---

## 🚀 主な機能

- **最高レベルのセキュリティ**: AES-GCM や ChaCha20 などの業界をリードする暗号化アルゴリズムを使用し、Kyber や Dilithium と組み合わせることで量子耐性を実現し、将来の脅威に対する保護を保証します。
- **マルチモード対応**: 軽量モードと標準モードを提供し、さまざまなデバイスの性能要件に適応します。
- **効率的な伝送**: 内蔵のネットワーク伝送機能により、高速かつ安全な暗号化ファイルの送受信を実現し、運用効率を大幅に向上させます。
- **インテリジェントな鍵管理**: ECC 鍵ペアの生成および管理ツールを含み、鍵操作を簡素化しながらセキュリティを確保します。
- **幅広い適用シナリオ**: 個人データ保護から企業レベルのファイル転送まで、Dsls-OTP はさまざまなニーズに対応するオールインワンソリューションを提供します。

---

## 📦 ファイル構成

```
Dsls-OTP/
├── python/
│   ├── dsls-otp.py       # メインプログラムファイル
│   ├── requirements.txt  # 依存関係リスト
├── README.md             # プロジェクトドキュメント
├── LICENSE               # ライセンスファイル
```

---

## 📖 使用方法

### 1. ファイルを暗号化する
```bash
python dsls-otp.py encrypt --input <入力ファイルパス> --output <出力ファイルパス> --receiver-key <受信者公開鍵ファイルパス> [--lightweight]
```

### 2. ファイルを復号化する
```bash
python dsls-otp.py decrypt --input <入力ファイルパス> --output <出力ファイルパス> --private-key <秘密鍵ファイルパス> [--password <秘密鍵パスワード>]
```

### 3. 鍵ペアを生成する
```bash
python dsls-otp.py keygen --private-key <秘密鍵保存パス> --public-key <公開鍵保存パス> [--password <秘密鍵パスワード>]
```

### 4. 暗号化ファイルをネットワーク経由で送信する
```bash
python dsls-otp.py send --input <入力ファイルパス> --receiver-key <受信者公開鍵ファイルパス> --target <ターゲットIP:ポート> [--lightweight]
```

### 5. ネットワークファイルを受信して復号化する
```bash
python dsls-otp.py receive --output <出力ファイルパス> --private-key <秘密鍵ファイルパス> [--listen <リッスンアドレス:ポート>] [--password <秘密鍵パスワード>]
```

---

## 🔧 依存関係

- **Python**: バージョン 3.8 以上
- **必要なライブラリ**: 以下のコマンドでインストールしてください
  ```bash
  pip install -r requirements.txt
  ```

---

## 🛠️ 注意事項

- 受信者の公開鍵と送信者の秘密鍵を安全に保管してください。
- 軽量モードを使用する場合、一部のセキュリティパラメータが性能向上のために低下する可能性があります。

---

## 📜 ライセンス

このプロジェクトは GNU AFFERO ライセンスの下でオープンソース化されています。詳細については [LICENSE](LICENSE) ファイルを参照してください。

---

## ❤️ コミュニティとサポート

質問や提案がある場合は、[Issues](https://github.com/DslsDZC/Dsls-OTP/issues) を通じて送信するか、コミュニティディスカッションに参加してください。

---

## ⭐ 貢献方法

1. このリポジトリをフォークします。
2. ブランチを作成します（`git checkout -b feature/AmazingFeature`）。
3. 変更をコミットします（`git commit -m 'Add some AmazingFeature'`）。
4. ブランチにプッシュします（`git push origin feature/AmazingFeature`）。
5. プルリクエストを開きます。

---

## 🌟 謝辞

このプロジェクトにコード、ドキュメント、提案を提供してくれたすべての開発者に感謝します！

<p align="center">
  <a href="https://github.com/DslsDZC/Dsls-OTP/graphs/contributors">
    <img src="https://contrib.rocks/image?repo=DslsDZC/Dsls-OTP" alt="Contributors">
  </a>
</p>
