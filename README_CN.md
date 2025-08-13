# Dsls-OTP: 基于量子抗性的网络加密优化方案

[English](README.md) / 简体中文 / [日本語](README_JP.md) / [Français](README_FR.md) / [Deutsch](README_DE.md)

![Static Badge](https://img.shields.io/badge/License_GNU_AFFERO-0?logo=gnu&color=8A2BE2)
<img src="https://img.shields.io/badge/python-3.10 ~ 3.13 -blue.svg" alt="python">

## ✨ 项目概述

Dsls-OTP 是一种基于一次性密码本（OTP）加密优化的量子抗性网络加密解决方案。通过结合优化的 OTP 机制、现代加密算法和量子抗性技术，它提供了卓越的数据保护能力。内置的网络传输功能使得安全文件传输变得简单高效，适应各种网络环境。

无论是资源受限的嵌入式设备，还是高性能的标准应用，Dsls-OTP 都能提供灵活的解决方案。

---

## 🚀 主要功能

- **顶级安全性**：采用 AES-GCM 和 ChaCha20 等行业领先的加密算法，并结合 Kyber 和 Dilithium 提供量子抗性，确保抵御未来威胁。
- **多模式支持**：提供轻量模式和标准模式，以适应不同设备的性能需求。
- **高效传输**：内置网络传输功能，实现快速、安全的加密文件发送和接收，大幅提升操作效率。
- **智能密钥管理**：内置 ECC 密钥对生成和管理工具，简化密钥操作，同时确保安全性。
- **广泛的应用场景**：从个人数据保护到企业级文件传输，Dsls-OTP 提供一站式解决方案，满足多种需求。

---

## 📦 文件结构

```
Dsls-OTP/
├── python/
│   ├── dsls-otp.py       # 主程序文件
│   ├── requirements.txt  # 依赖列表
├── README.md             # 项目文档
├── LICENSE               # 许可证文件
```

---

## 📖 使用方法

### 1. 加密文件
```bash
python dsls-otp.py encrypt <输入文件路径> <输出文件路径> --receiver-key <接收方公钥文件路径> [--lightweight]
```

### 2. 解密文件
```bash
python dsls-otp.py decrypt <输入文件路径> <输出文件路径> --private-key <私钥文件路径> [--password <私钥密码>]
```

### 3. 生成密钥对
```bash
python dsls-otp.py keygen --private-key <私钥保存路径> --public-key <公钥保存路径> [--password <私钥密码>]
```

### 4. 通过网络发送加密文件
```bash
python dsls-otp.py send <输入文件路径> <接收方公钥文件路径> --target <目标IP:端口> [--lightweight]
```

### 5. 接收并解密网络文件
```bash
python dsls-otp.py receive <输出文件路径> <私钥文件路径> [--listen <监听地址:端口>] [--password <私钥密码>]
```

---

## 🔧 依赖

- **Python**：版本 3.8 或更高
- **所需库**：使用以下命令安装
  ```bash
  pip install -r requirements.txt
  ```
  **PQC库集成**:
  当前实现使用secrets.token_bytes模拟Kyber操作，实际部署需集成:
    -liboqs-python
    -OpenQuantumSafe

---

## 🛠️ 注意事项

- 请确保接收方的公钥和发送方的私钥安全存储。
- 使用轻量模式时，某些安全参数可能会降低以提升性能。

---

## 📜 许可证

本项目基于 GNU AFFERO 许可证开源。详情请参阅 [LICENSE](LICENSE) 文件。

---

## ❤️ 社区与支持

如果您有任何问题或建议，请通过 [Issues](https://github.com/DslsDZC/Dsls-OTP/issues) 提交，或加入我们的社区讨论。

---

## ⭐ 如何贡献

1. Fork 此仓库。
2. 创建您的分支（`git checkout -b feature/AmazingFeature`）。
3. 提交更改（`git commit -m 'Add some AmazingFeature'`）。
4. 推送到分支（`git push origin feature/AmazingFeature`）。
5. 打开一个 Pull Request。

---

## 🌟 致谢

感谢所有为本项目贡献代码、文档和建议的开发者！

<p align="center">
  <a href="https://github.com/DslsDZC/Dsls-OTP/graphs/contributors">
    <img src="https://contrib.rocks/image?repo=DslsDZC/Dsls-OTP" alt="Contributors">
  </a>
</p>
