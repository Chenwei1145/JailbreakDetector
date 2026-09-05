# 越狱检测器 / Jailbreak Detector

独立的 SwiftUI RootHide 越狱可见性检测器，用于评估普通 App 能看到的越狱痕迹。项目只读文件、环境变量和当前进程加载镜像，不执行越狱或修改系统文件。

## 本地 WSL 编译

```bash
cd /mnt/c/Users/39437/Documents/Codex/TheosProjects/越狱检测器
export THEOS=$HOME/theos
./build_jailbreak_detector.sh
```

产物在 `JailbreakDetector/output/`（`.ipa` 和 `.deb`）。

## GitHub Actions

推送后，GitHub Actions 会在 macOS runner 上使用 Xcode SDK 和 Theos 构建，并在 Actions 的 Artifacts 中提供构建产物。

---

This is a standalone SwiftUI RootHide jailbreak-visibility detector. It only reads files, environment variables, and loaded images; it does not jailbreak or modify system files.
