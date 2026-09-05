import SwiftUI
import UIKit
import Foundation
import Darwin
import MachO

struct Detection: Identifiable {
    let id = UUID()
    let title: String
    let detail: String
    let detected: Bool
    let weight: Int
}

@MainActor
final class Detector: ObservableObject {
    @Published var checks: [Detection] = []
    @Published var lastScan = Date()

    var score: Int {
        let total = checks.reduce(0) { $0 + $1.weight }
        guard total > 0 else { return 0 }
        return Int((Double(checks.filter(\.detected).reduce(0) { $0 + $1.weight }) / Double(total) * 100).rounded())
    }

    var verdict: String {
        switch score {
        case 70...: return "高度疑似 RootHide / 越狱环境"
        case 30...: return "发现部分越狱迹象"
        default: return "未发现可见的越狱迹象"
        }
    }

    func scan() {
        var result: [Detection] = []
        result.append(checkPath("RootHide jbroot 目录", paths: ["/var/jb", "/var/jb/basebin", "/var/jb/usr/bin/jbctl"], weight: 30))
        result.append(checkPath("RootHide 配置/版本文件", paths: ["/var/jb/basebin/.version", "/var/jb/.jbroot"], weight: 15))
        result.append(checkPath("RootHide 注入组件", paths: ["/var/jb/usr/lib/TweakInject/ElleKit.dylib", "/var/jb/usr/lib/libjailbreak.dylib"], weight: 20))
        result.append(checkLoadedImage(weight: 15))
        result.append(checkLoadedImages(weight: 10))
        result.append(checkEnvironment(weight: 10))
        result.append(checkKnownJailbreakApps(weight: 10))
        result.append(checkJailbreakURLSchemes(weight: 10))
        result.append(checkSubstrateArtifacts(weight: 15))
        result.append(checkSuspiciousMounts(weight: 10))
        result.append(checkWritableSystemLocations(weight: 10))
        result.append(checkLegacyArtifacts(weight: 10))
        result.append(checkSymlinkExposure(weight: 10))
        result.append(checkHookSymbols(weight: 10))
        result.append(checkProcessIdentity(weight: 5))
        let suite = SecuritySuiteAdapter.scan()
        result.append(Detection(title: "IOSSecuritySuite 综合检测", detail: suite.detail, detected: suite.detected, weight: 25))
        checks = result
        lastScan = Date()
    }

    private func checkPath(_ title: String, paths: [String], weight: Int) -> Detection {
        let hit = paths.first { FileManager.default.fileExists(atPath: $0) }
        return Detection(title: title, detail: hit ?? "未找到相关路径", detected: hit != nil, weight: weight)
    }

    private func checkLoadedImage(weight: Int) -> Detection {
        let names = ["/usr/lib/libjailbreak.dylib", "/var/jb/usr/lib/libjailbreak.dylib", "/var/jb/usr/lib/TweakInject/ElleKit.dylib"]
        let hit = names.first { path in path.withCString { dlopen($0, RTLD_NOLOAD | RTLD_LAZY) != nil } }
        return Detection(title: "当前进程已加载 RootHide 库", detail: hit ?? "未检测到已加载库", detected: hit != nil, weight: weight)
    }

    private func checkLoadedImages(weight: Int) -> Detection {
        let needles = ["ellekit", "tweakinject", "libjailbreak", "substitute", "substrate", "libhooker"]
        var hit: String?
        for index in 0..<_dyld_image_count() {
            guard let pointer = _dyld_get_image_name(index), let name = String(validatingUTF8: pointer)?.lowercased() else { continue }
            if let needle = needles.first(where: { name.contains($0) }) { hit = "\(needle): \(name)"; break }
        }
        return Detection(title: "动态加载镜像扫描", detail: hit ?? "未发现已加载注入组件", detected: hit != nil, weight: weight)
    }

    private func checkEnvironment(weight: Int) -> Detection {
        let keys = ["DYLD_INSERT_LIBRARIES", "_MSSafeMode", "ROOT_HIDE", "JBROOT"]
        let hit = keys.first { key in key.withCString { getenv($0) != nil } }
        return Detection(title: "越狱相关环境变量", detail: hit ?? "未发现相关变量", detected: hit != nil, weight: weight)
    }

    private func checkKnownJailbreakApps(weight: Int) -> Detection {
        let paths = ["/Applications/Sileo.app", "/Applications/Zebra.app", "/Applications/Installer.app", "/Applications/Filza.app", "/var/jb/Applications/Sileo.app", "/var/jb/Applications/Zebra.app", "/var/jb/Applications/Filza.app"]
        let hit = paths.first { FileManager.default.fileExists(atPath: $0) }
        return Detection(title: "常见越狱 App 路径", detail: hit ?? "未找到 Sileo/Zebra 等路径", detected: hit != nil, weight: weight)
    }

    private func checkJailbreakURLSchemes(weight: Int) -> Detection {
        let schemes = ["sileo://", "zbra://", "installer://", "filza://", "cydia://"]
        let hit = schemes.first { UIApplication.shared.canOpenURL(URL(string: $0)!) }
        return Detection(title: "越狱 App URL Scheme", detail: hit ?? "未发现可打开的越狱 URL Scheme", detected: hit != nil, weight: weight)
    }

    private func checkSubstrateArtifacts(weight: Int) -> Detection {
        let paths = ["/Library/MobileSubstrate/MobileSubstrate.dylib", "/Library/MobileSubstrate/DynamicLibraries", "/usr/lib/TweakInject", "/usr/lib/substitute-loader.dylib", "/usr/lib/libhooker.dylib", "/var/jb/usr/lib/TweakInject", "/var/jb/usr/lib/ellekit"]
        let hit = paths.first { FileManager.default.fileExists(atPath: $0) }
        return Detection(title: "Substrate / 注入文件痕迹", detail: hit ?? "未发现常见注入目录或动态库", detected: hit != nil, weight: weight)
    }

    private func checkSuspiciousMounts(weight: Int) -> Detection {
        var info = statfs()
        for path in ["/var/jb", "/private/preboot", "/var/containers/Bundle/Application"] where statfs(path, &info) == 0 {
            var mountBytes = info.f_mntfromname
            let mountCapacity = MemoryLayout.size(ofValue: mountBytes)
            let mount = withUnsafePointer(to: &mountBytes) { ptr in
                ptr.withMemoryRebound(to: CChar.self, capacity: mountCapacity) { String(cString: $0) }
            }.lowercased()
            if mount.contains("jbroot") || mount.contains("rootless") || mount.contains("roothide") {
                return Detection(title: "文件系统挂载痕迹", detail: mount, detected: true, weight: weight)
            }
        }
        return Detection(title: "文件系统挂载痕迹", detail: "未发现 jbroot/rootless 挂载名称", detected: false, weight: weight)
    }

    private func checkWritableSystemLocations(weight: Int) -> Detection {
        let paths = ["/private", "/var/root", "/usr/lib", "/var/jb"]
        let hit = paths.first { FileManager.default.isWritableFile(atPath: $0) }
        return Detection(title: "系统目录写入权限", detail: hit.map { "普通 App 可写入：\($0)" } ?? "未发现异常写入权限", detected: hit != nil, weight: weight)
    }

    // Checks used by common libraries such as IOSSecuritySuite/DTTJailbreakDetection.
    private func checkLegacyArtifacts(weight: Int) -> Detection {
        let paths = ["/Applications/Cydia.app", "/Library/MobileSubstrate", "/usr/sbin/sshd", "/etc/apt", "/var/lib/dpkg", "/private/var/stash", "/private/var/lib/apt"]
        let hit = paths.first { FileManager.default.fileExists(atPath: $0) }
        return Detection(title: "传统越狱文件检测", detail: hit ?? "未发现传统 Cydia/apt/SSH 路径", detected: hit != nil, weight: weight)
    }

    private func checkSymlinkExposure(weight: Int) -> Detection {
        let paths = ["/var/jb", "/usr/lib/TweakInject", "/Library/MobileSubstrate"]
        for path in paths {
            if let destination = try? FileManager.default.destinationOfSymbolicLink(atPath: path), !destination.isEmpty {
                return Detection(title: "越狱符号链接检测", detail: "\(path) → \(destination)", detected: true, weight: weight)
            }
        }
        return Detection(title: "越狱符号链接检测", detail: "未发现可读取的越狱符号链接", detected: false, weight: weight)
    }

    private func checkHookSymbols(weight: Int) -> Detection {
        let symbols = ["MSHookFunction", "MSHookMessageEx", "fishhook_rebind_symbols", "substrate_initialize", "ellekit_init"]
        // Swift/Xcode does not expose the RTLD_DEFAULT macro.  Darwin defines
        // the default symbol handle as (void *)-2, which is accepted by dlsym.
        let defaultHandle = UnsafeMutableRawPointer(bitPattern: -2)
        let hit = symbols.first { symbol in symbol.withCString { dlsym(defaultHandle, $0) != nil } }
        return Detection(title: "Hook 框架符号检测", detail: hit ?? "未解析到常见 Hook 符号", detected: hit != nil, weight: weight)
    }

    private func checkProcessIdentity(weight: Int) -> Detection {
        var process = utsname()
        uname(&process)
        var machineBytes = process.machine
        let machineCapacity = MemoryLayout.size(ofValue: machineBytes)
        let machine = withUnsafePointer(to: &machineBytes) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: machineCapacity) { String(cString: $0) }
        }
        let parent = getppid()
        return Detection(title: "进程/系统环境信息", detail: "设备 \(machine)，父进程 PID \(parent)", detected: parent != 1, weight: weight)
    }
}

struct ContentView: View {
    @StateObject private var detector = Detector()

    var body: some View {
        NavigationView {
            List {
                Section {
                    VStack(spacing: 8) {
                        Text("RootHide Detector").font(.title2.bold())
                        Text(detector.verdict).font(.headline)
                        Text("检测评分 \(detector.score)/100").foregroundColor(detector.score >= 30 ? .orange : .secondary)
                        ProgressView(value: Double(detector.score), total: 100)
                    }.frame(maxWidth: .infinity).padding(.vertical, 8)
                }
                Section("检测项目") {
                    ForEach(detector.checks) { item in
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: item.detected ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                                .foregroundColor(item.detected ? .orange : .green)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(item.title).font(.body.bold())
                                Text(item.detail).font(.caption).foregroundColor(.secondary)
                            }
                            Spacer()
                        }
                    }
                }
                Section {
                    Button { detector.scan() } label: { Label("重新扫描", systemImage: "arrow.clockwise") }
                    Text("上次扫描：\(Self.timeString(detector.lastScan))")
                        .font(.caption).foregroundColor(.secondary)
                }
                Section("说明") {
                    Text("RootHide 的设计目标就是隐藏越狱痕迹。普通 App 受沙盒限制时，检测结果可能为阴性；本工具只能评估当前进程可见的迹象，不能证明设备绝对未越狱。")
                        .font(.footnote).foregroundColor(.secondary)
                }
            }
            .navigationTitle("越狱检测")
        }
        .onAppear { detector.scan() }
    }

    private static func timeString(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .none
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }

}

@main
struct JailbreakDetectorApp: App {
    var body: some Scene { WindowGroup { ContentView() } }
}
