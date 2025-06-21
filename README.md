# Dsls-OTP：高效安全的文件加密与网络传输工具


## ✨ 项目简介

Dsls-OTP 是一款集高效、安全与便捷于一体的文件加密、解密与网络传输工具。通过优化的一次性密码（OTP）机制，结合现代加密算法与抗量子攻击技术，提供卓越的数据保护能力。其内置的网络传输功能，让文件的安全传递变得简单高效，适配多种网络环境。

无论是资源受限的嵌入式设备，还是需要高性能的标准应用场景，Dsls-OTP 都能灵活应对。

---

## 🚀 核心特点

- **顶级安全性**：采用 AES-GCM 和 ChaCha20 等业界领先的加密算法，结合 Kyber 和 Dilithium 提供抗量子攻击能力，确保数据免受未来威胁。
- **多模式支持**：提供轻量级模式和标准模式，灵活适配不同设备性能需求。
- **高效传输能力**：内置网络传输功能，支持加密文件的快速、安全发送与接收，显著提升操作效率。
- **智能化密钥管理**：内置 ECC 密钥对生成与管理工具，简化密钥操作，同时确保安全性。
- **广泛应用场景**：从个人数据保护到企业级文件传输，Dsls-OTP 提供一站式解决方案，满足多种需求。

---

## 📦 文件结构

```
Dsls-OTP/
├── python/
│   ├── dsls-otp.py       # 主程序文件
│   ├──requirements.txt   # 依赖库列表
├── README.md             # 项目说明文件
├── LICENSE               # 许可证文件


---

## 📖 使用方法

### 1. 加密文件
```bash
python dsls-otp.py encrypt --input <输入文件路径> --output <输出文件路径> --receiver-key <接收方公钥文件路径> [--lightweight]
```

### 2. 解密文件
```bash
python dsls-otp.py decrypt --input <输入文件路径> --output <输出文件路径> --private-key <私钥文件路径> [--password <私钥密码>]
```

### 3. 生成密钥对
```bash
python dsls-otp.py keygen --private-key <私钥保存路径> --public-key <公钥保存路径> [--password <私钥密码>]
```

### 4. 通过网络发送加密文件
```bash
python dsls-otp.py send --input <输入文件路径> --receiver-key <接收方公钥文件路径> --target <目标IP:端口> [--lightweight]
```

### 5. 接收并解密网络文件
```bash
python dsls-otp.py receive --output <输出文件路径> --private-key <私钥文件路径> [--listen <监听地址:端口>] [--password <私钥密码>]
```

---

## 🔧 环境依赖

- **Python**：3.8 或更高版本
- **依赖库**：通过以下命令安装
  ```bash
  pip install -r requirements.txt
  ```


---

## 🛠️ 注意事项

- 请确保接收方的公钥和发送方的私钥安全存储。
- 使用轻量模式时，某些安全参数可能会降低以提高性能。

---

## 📜 许可证

本项目基于 MIT 许可证开源，详情请查看 [LICENSE](LICENSE) 文件。

---

## ❤️ 社区与支持

如果您有任何问题或建议，请通过 [Issues](https://github.com/DslsDZC/Dsls-OTP/issues) 提交，或者加入我们的社区讨论。

---

## ⭐ 如何贡献

1. Fork 本仓库
2. 创建您的分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开一个 Pull Request

---

## 🌟 感谢

感谢所有为本项目贡献代码、文档和建议的开发者！

<p align="center">
  <a href="https://github.com/DslsDZC/Dsls-OTP/graphs/contributors">
    <img src="https://contrib.rocks/image?repo=DslsDZC/Dsls-OTP" alt="Contributors">
  </a>
</p>
