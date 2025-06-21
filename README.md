# Dsls-OTP: A Quantum-Resistant Network Encryption Optimized with OTP

English / [简体中文](README_CN.md) / [日本語](README_JP.md) / [Français](README_FR.md) / [Deutsch](README_DE.md) 

![Static Badge](https://img.shields.io/badge/License_GNU_AFFERO-0?style=for-the-badge&logo=gnu&color=8A2BE2)
<img src="https://img.shields.io/badge/python-3.10 ~ 3.13 -blue.svg" alt="python">

## ✨ Project Overview

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
│   ├── dsls-otp.py       # Main program file
│   ├── requirements.txt  # Dependency list
├── README.md             # Project documentation
├── LICENSE               # License file
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
