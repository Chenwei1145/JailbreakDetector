TARGET = iphone:clang:latest:15.0
# arm64 runs on the A13 and avoids the incompatible arm64e Swift ABI warning
# emitted by the Linux cross-toolchain.
ARCHS = arm64
INSTALL_TARGET_PROCESSES = JailbreakDetector

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = JailbreakDetector

JailbreakDetector_FILES = App.swift
JailbreakDetector_RESOURCE_DIRS = Resources
JailbreakDetector_FRAMEWORKS = UIKit SwiftUI Foundation
# Let Theos invoke ldid's default ad-hoc signer.  The bundled entitlements
# file is intentionally empty; passing GNU-style --entitlements to ldid is
# invalid (ldid accepts -S[entitlements.xml] instead).
JailbreakDetector_SWIFT_VERSION = 5

include $(THEOS_MAKE_PATH)/application.mk

after-clean::
	@rm -rf .theos packages
