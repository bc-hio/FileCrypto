# FileCrypto · Python 文件加解密工具

零第三方依赖的文件加解密工具：纯 Python 标准库 + Tkinter 图形界面，**全程本地运行，不上传任何数据**。
默认使用 AES-256-GCM，支持批量/文件夹处理、文本加密、强密码生成、文件摘要与覆写擦除。

> 完整说明见 [使用说明.md](使用说明.md)。本项目采用 **MIT 许可证**，详见 [LICENSE](LICENSE)。

## 特性

- **标准 AEAD 加密**：默认 AES-256-GCM，可选 ChaCha20-Poly1305；缺少 `cryptography` 时回退到内置 SHAKE-256 + HMAC-SHA256 方案。
- **密钥派生**：PBKDF2-HMAC-SHA256（12 万 ~ 400 万次迭代，四档预设）或 scrypt（n=2¹³ ~ 2¹⁶），每文件独立 16 字节随机盐；支持「密码 + 密钥文件」双因子。
- **密码归一化**：派生前统一做 Unicode NFC 归一化，避免「密码一样却打不开」。
- **弱口令检测**：内置约 300 条常见弱口令字典（含 leet 变形、键盘序列、中文组合）与结构规则，命中时封顶为「极弱」并弹窗劝阻。
- **分块流式处理**：默认 1 MiB 分块（64 KiB ~ 16 MiB 可调），内存占用与文件大小无关。
- **完整性认证**：每块独立认证标签 + 文件尾 EOF 认证块，可检测密码错误、内容篡改与截断；文件头带密码校验令牌，支持「秒判密码错误」。
- **原子写盘**：先写 `.part` 再替换，失败或取消不留残缺文件。
- **七个功能页**：文件加解密 / 批量与文件夹 / 文本加密 / 工具箱 / 设置 / 日志 / 帮助（含内置自检）。

## 快速开始

### 方式一：直接用 Windows 便携版

1. 把本仓库的 `_internal.zip` 解压到与 `FileCrypto.exe` 同级目录，确保解压后存在 `_internal\` 文件夹；
2. 双击 `FileCrypto.exe` 即可运行。

或直接 `git clone` 后解压：

```bash
git clone https://github.com/bc-hio/FileCrypto.git
cd FileCrypto
# 解压 _internal.zip 到当前目录，然后双击 FileCrypto.exe
```

### 方式二：从源码运行

```bash
python file_crypto_ui.py
```

需要 Python 3.8+（自带 tkinter）。要启用 AES-256-GCM / ChaCha20-Poly1305，另装 `cryptography`：

```bash
pip install cryptography
```

不装也能用，程序会自动回退到内置算法并在界面提示。

## 仓库结构

```
FileCrypto/
├── file_crypto_ui.py   图形界面主程序（7 个功能页）
├── fcrypt_core.py      加解密核心引擎，也可当命令行工具用
├── FileCrypto.exe      Windows 便携版可执行文件
├── _internal.zip       exe 依赖的运行时，解压到同级目录即可
├── 使用说明.md          完整使用说明与文件格式规格
└── LICENSE             MIT 许可证
```

## 命令行模式

```bash
py -3 fcrypt_core.py encrypt -i 照片.jpg -o 照片.jpg.fcrypt -p 密码
py -3 fcrypt_core.py decrypt -i 照片.jpg.fcrypt -p 密码
py -3 fcrypt_core.py encrypt -i 数据.bin -a aes-256-gcm -k scrypt -f key.bin
py -3 fcrypt_core.py selftest          # 运行内置回归测试
```

## 安全提醒

- 密码丢失无法找回，请用密码管理器妥善保存；密钥文件请与密文分开存放。
- **覆写擦除在 SSD/NVMe/写时复制文件系统上基本无效**（磨损均衡、TRIM、快照都会留下旧数据）。
  需要真正销毁数据时请使用**整盘加密**（BitLocker / LUKS / FileVault）并销毁密钥。
- 本工具只做文件级加密，不提供任何网络传输或云存储功能。

## 许可

本项目采用 **MIT 许可证**，详见 [LICENSE](LICENSE)。

Copyright (c) 2026 bc_hio
