# Dsls-OTP: Quantum-Resistant Network Encryption Optimization Solution

English / [简体中文](README_CN.md) / [日本語](README_JP.md) / [Français](README_FR.md) / [Deutsch](README_DE.md)

![Static Badge](https://img.shields.io/badge/License_GNU_AFFERO-0?logo=gnu&color=8A2BE2)
<img src="https://img.shields.io/badge/python-3.10 ~ 3.13 -blue.svg" alt="python">

The next update will support lattice-based fully homomorphic encryption.

## ✨ Project Overview

Dsls-OTP is a quantum-resistant network encryption solution based on optimized One-Time Pad (OTP) cryptography. By combining enhanced OTP mechanisms, modern encryption algorithms, and quantum-resistant technology, it delivers superior data protection capabilities. Built-in network transmission functionality enables simple and efficient secure file transfers across diverse network environments.

Whether for resource-constrained embedded devices or high-performance standard applications, Dsls-OTP provides flexible solutions.

---

## 🚀 Key Features

- **Top-Tier Security**: Employs industry-leading encryption algorithms including AES-GCM and ChaCha20, augmented with Kyber and Dilithium for quantum resistance, ensuring protection against future threats.
- **Multi-Mode Support**: Offers lightweight and standard modes to accommodate different device performance requirements.
- **Efficient Transmission**: Built-in network transfer enables rapid, secure encrypted file sending/receiving, significantly improving operational efficiency.
- **Intelligent Key Management**: Integrated ECC key pair generation and management tools simplify key operations while maintaining security.
- **Broad Application Scope**: Provides a comprehensive solution for diverse needs, from personal data protection to enterprise-grade file transfers.

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

## 📖 Usage Instructions

### 1. Encrypt File
```bash
python dsls-otp.py encrypt <input_file> <output_file> --receiver-key <public_key_path> [--lightweight]
```

### 2. Decrypt File
```bash
python dsls-otp.py decrypt <input_file> <output_file> --private-key <private_key_path> [--password <key_password>]
```

### 3. Generate Key Pair
```bash
python dsls-otp.py keygen --private-key <private_key_path> --public-key <public_key_path> [--password <key_password>]
```

### 4. Send Encrypted File via Network
```bash
python dsls-otp.py send <input_file> <receiver_pubkey_path> --target <ip:port> [--lightweight]
```

### 5. Receive & Decrypt Network File
```bash
python dsls-otp.py receive <output_file> <private_key_path> [--listen <address:port>] [--password <key_password>]
```

---

## 🔧 Dependencies

- **Python**: Version 3.8 or higher
- **Required Libraries**: Install using:
  ```bash
  pip install -r requirements.txt
  ```
  **PQC Library Integration**:  
  Current implementation uses `secrets.token_bytes` to simulate Kyber operations. For production deployment, integrate:
    - liboqs-python
    - OpenQuantumSafe

---

## 🛠️ Important Notes

- Ensure secure storage of receiver's public keys and sender's private keys.
- Security parameters may be reduced in lightweight mode to enhance performance.

---

## 📜 License

This project is open-sourced under the GNU AFFERO License. See [LICENSE](LICENSE) for details.

---

## ❤️ Community & Support

For questions or suggestions, please submit via [Issues](https://github.com/DslsDZC/Dsls-OTP/issues) or join our community discussions.

---

## ⭐ Contributing

1. Fork this repository
2. Create your branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 🌟 Acknowledgments

Gratitude to all developers who contributed code, documentation, and suggestions to this project!

<p align="center">
  <a href="https://github.com/DslsDZC/Dsls-OTP/graphs/contributors">
    <img src="https://contrib.rocks/image?repo=DslsDZC/Dsls-OTP" alt="Contributors">
  </a>
</p>