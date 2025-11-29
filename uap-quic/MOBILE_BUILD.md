# 📱 移动端编译指南

## 前置要求

### 1. 安装 gomobile

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
```

**注意**：`gomobile init` 会下载 Android NDK 和 iOS 工具链，可能需要一些时间。

### 2. iOS 开发环境要求

- macOS 系统
- Xcode 已安装（用于 iOS 工具链）
- 确保 `xcode-select` 指向正确的 Xcode 路径：
  ```bash
  sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
  ```

## 编译 iOS Framework

### 步骤 1: 进入项目根目录

```bash
cd /Users/arronlee/Documents/uap-quic
```

### 步骤 2: 编译为 .xcframework

```bash
gomobile bind -target=ios -o Uap.xcframework uap-quic/pkg/sdk
```

**命令说明**：
- `-target=ios`: 指定目标平台为 iOS
- `-o Uap.xcframework`: 输出文件名（会在当前目录生成）
- `uap-quic/pkg/sdk`: SDK 包的导入路径

### 步骤 3: 验证输出

编译成功后，会在项目根目录生成：

```
Uap.xcframework/
├── Info.plist
├── ios-arm64/
│   └── Uap.framework/
│       ├── Headers/
│       ├── Info.plist
│       ├── Modules/
│       └── Uap
└── ios-arm64_x86_64-simulator/
    └── Uap.framework/
        ├── Headers/
        ├── Info.plist
        ├── Modules/
        └── Uap
```

**输出位置**：`/Users/arronlee/Documents/uap-quic/Uap.xcframework`

## 在 Xcode 中使用

### 1. 导入 Framework

1. 打开 Xcode 项目
2. 选择项目 Target → **General** → **Frameworks, Libraries, and Embedded Content**
3. 点击 **+** 按钮
4. 选择 **Add Other...** → **Add Files...**
5. 选择 `Uap.xcframework` 文件
6. 确保 **Embed** 设置为 **Embed & Sign**

### 2. 在 Swift 代码中使用

```swift
import Uap

// 启动 VPN
UapStart("your-token", "uaptest.org:443", 1080, "smart", "")

// 检查状态
if UapIsRunning() {
    print("VPN 正在运行")
}

// 停止 VPN
UapStop()
```

### 3. 在 Objective-C 代码中使用

```objc
#import <Uap/Uap.h>

// 启动 VPN
NSError *error = nil;
UapStart(@"your-token", @"uaptest.org:443", 1080, @"smart", @"", &error);

// 检查状态
if (UapIsRunning()) {
    NSLog(@"VPN 正在运行");
}

// 停止 VPN
UapStop();
```

## 常见问题

### 1. 编译错误：找不到 CGO 工具链

```bash
# 确保 CGO 已启用
export CGO_ENABLED=1

# 重新编译
gomobile bind -target=ios -o Uap.xcframework uap-quic/pkg/sdk
```

### 2. 编译错误：证书问题

如果遇到签名相关错误，可以添加 `-iosversion` 参数指定最低 iOS 版本：

```bash
gomobile bind -target=ios -iosversion=13.0 -o Uap.xcframework uap-quic/pkg/sdk
```

### 3. 只编译特定架构

如果需要只编译 arm64（真机）或 x86_64（模拟器），可以使用：

```bash
# 只编译真机架构
gomobile bind -target=ios/arm64 -o Uap.xcframework uap-quic/pkg/sdk

# 只编译模拟器架构
gomobile bind -target=ios/amd64 -o Uap.xcframework uap-quic/pkg/sdk
```

### 4. 清理缓存

如果遇到奇怪的编译错误，可以清理 gomobile 缓存：

```bash
rm -rf ~/go/pkg/gomobile
gomobile init
```

## 完整编译示例

```bash
# 1. 安装 gomobile（如果未安装）
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init

# 2. 进入项目目录
cd /Users/arronlee/Documents/uap-quic

# 3. 编译 iOS Framework
gomobile bind -target=ios -o Uap.xcframework uap-quic/pkg/sdk

# 4. 验证输出
ls -lh Uap.xcframework
```

## 输出文件说明

- **Uap.xcframework**: 通用 Framework，包含真机和模拟器架构
- **Uap.framework**: 单个架构的 Framework（在 xcframework 内部）
- **Headers/**: Objective-C/Swift 头文件
- **Uap**: 编译后的二进制文件

## 注意事项

1. **网络权限**: iOS 应用需要在 `Info.plist` 中声明网络权限
2. **后台运行**: 如果需要在后台运行，需要配置 Background Modes
3. **Network Extension**: 如果使用 Network Extension，需要额外的配置和证书
4. **内存限制**: iOS Network Extension 有 15MB 内存限制，当前代码已优化

