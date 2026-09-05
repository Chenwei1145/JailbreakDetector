import Foundation
#if canImport(IOSSecuritySuite)
import IOSSecuritySuite
#endif

enum SecuritySuiteAdapter {
    static func scan() -> (detected: Bool, detail: String) {
#if canImport(IOSSecuritySuite)
        let jailbroken = IOSSecuritySuite.amIJailbroken()
        let debugged = IOSSecuritySuite.amIBeingDebugged()
        let emulator = IOSSecuritySuite.amIRunInEmulator()
        let reverseEngineered = IOSSecuritySuite.amIReverseEngineered()
        return (jailbroken || debugged || emulator || reverseEngineered,
                "IOSSecuritySuite: jailbroken=\(jailbroken), debugged=\(debugged), emulator=\(emulator), reverseEngineered=\(reverseEngineered)")
#else
        return (false, "IOSSecuritySuite Framework 未嵌入（使用内置检测）")
#endif
    }
}
