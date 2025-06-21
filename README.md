<<<<<<< HEAD
# Dsls-OTP: A Quantum-Resistant Network Encryption Optimized with OTP
=======
# Dsls-OTP：基于OPT加密优化的抗无穷算力的一种网络传输加密
>>>>>>> 3cd8352 (更新 README 文件以更准确地描述项目功能，优化代码以提高性能和安全性，添加新的密钥生成和加密功能)

English / [简体中文](README_CN.md) / [日本語](README_JP.md) / [Français](README_FR.md) / [Deutsch](README_DE.md) 

![Static Badge](https://img.shields.io/badge/License_GNU_AFFERO-0?logo=gnu&color=8A2BE2)
<img src="https://img.shields.io/badge/python-3.10 ~ 3.13 -blue.svg" alt="python">

<<<<<<< HEAD
## ✨ Project Overview
=======
Dsls-OTP 是基于OPT加密优化的抗无穷算力的一种网络传输加密。通过优化的一次性密码（OTP）机制，结合现代加密算法与抗量子攻击技术，提供卓越的数据保护能力。其内置的网络传输功能，让文件的安全传递变得简单高效，适配多种网络环境。
>>>>>>> 3cd8352 (更新 README 文件以更准确地描述项目功能，优化代码以提高性能和安全性，添加新的密钥生成和加密功能)

Dsls-OTP is a quantum-resistant network encryption solution optimized with one-time pad (OTP) encryption. By combining an optimized OTP mechanism with modern encryption algorithms and quantum-resistant technologies, it provides exceptional data protection. Its built-in network transmission functionality makes secure file transfer simple and efficient, adaptable to various network environments.

Whether for resource-constrained embedded devices or high-performance standard applications, Dsls-OTP offers flexible solutions.

---

## 🚀 Key Features

- **Top-Level Security**: Utilizes industry-leading encryption algorithms like AES-GCM and ChaCha20, combined with Kyber and Dilithium for quantum resistance, ensuring protection against future threats.
- **Multi-Mode Support**: Offers lightweight and standard modes to adapt to different device performance requirements.
- **Efficient Transmission**: Built-in network transmission capabilities enable fast and secure encrypted file sending and receiving, significantly improving operational efficiency.
- **Intelligent Key Management**: Includes ECC key pair generation and management tools, simplifying key operations while ensuring security.
- **Wide Application Scenarios**: From personal data protection to enterprise-level file transfer, Dsls-OTP provides an all-in-one solution for various needs.

---

## 📦 File Structure

```
Dsls-OTP/
├── python/
<<<<<<< HEAD
│   ├── dsls-otp.py       # Main program file
│   ├── requirements.txt  # Dependency list
├── README.md             # Project documentation
├── LICENSE               # License file
=======
│   ├── dsls-otp.py       # 主程序文件
│   ├──requirements.txt   # 依赖库列表
├── README.md             # 项目说明文件
├── LICENSE               # 许可证文件
```

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
>>>>>>> 3cd8352 (更新 README 文件以更准确地描述项目功能，优化代码以提高性能和安全性，添加新的密钥生成和加密功能)
```

---

## 📖 Usage

### 1. Encrypt a File
```bash
python dsls-otp.py encrypt --input <input file path> --output <output file path> --receiver-key <receiver public key file path> [--lightweight]
```

### 2. Decrypt a File
```bash
python dsls-otp.py decrypt --input <input file path> --output <output file path> --private-key <private key file path> [--password <private key password>]
```

### 3. Generate Key Pair
```bash
python dsls-otp.py keygen --private-key <private key save path> --public-key <public key save path> [--password <private key password>]
```

### 4. Send Encrypted File Over Network
```bash
python dsls-otp.py send --input <input file path> --receiver-key <receiver public key file path> --target <target IP:port> [--lightweight]
```

### 5. Receive and Decrypt Network File
```bash
python dsls-otp.py receive --output <output file path> --private-key <private key file path> [--listen <listen address:port>] [--password <private key password>]
```

---

## 🔧 Dependencies

- **Python**: Version 3.8 or higher
- **Required Libraries**: Install using the following command
  ```bash
  pip install -r requirements.txt
  ```

---

## 🛠️ Notes

- Ensure the receiver's public key and sender's private key are securely stored.
- When using lightweight mode, some security parameters may be reduced to improve performance.

---

## 📜 License

This project is open-sourced under the  GNU AFFERO License. See the [LICENSE](LICENSE) file for details.

---

## ❤️ Community and Support

If you have any questions or suggestions, please submit them via [Issues](https://github.com/DslsDZC/Dsls-OTP/issues) or join our community discussions.

---

## ⭐ How to Contribute

1. Fork this repository.
2. Create your branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

---

## 🌟 Acknowledgments

Thanks to all developers who contributed code, documentation, and suggestions to this project!

<p align="center">
  <a href="https://github.com/DslsDZC/Dsls-OTP/graphs/contributors">
    <img src="https://contrib.rocks/image?repo=DslsDZC/Dsls-OTP" alt="Contributors">
  </a>
</p>
