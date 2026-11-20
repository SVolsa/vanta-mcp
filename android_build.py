"""Locate a standalone Android SDK, JDK and NDK for the APK builders."""
import os
import platform
from pathlib import Path
import shutil


EXE = ".exe" if os.name == "nt" else ""
WORKSPACE_TOOLS = Path(__file__).resolve().parent.parent / ".tools"


def android_sdk():
    configured = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    local = os.environ.get("LOCALAPPDATA")
    sdk = Path(configured) if configured else (Path(local) / "Android/Sdk" if local else None)
    if sdk is None or not sdk.is_dir():
        raise RuntimeError("Set ANDROID_HOME to your installed Android SDK")
    return sdk


def build_tools(sdk):
    configured = os.environ.get("VANTA_BUILD_TOOLS")
    directory = Path(configured) if configured else sdk / "build-tools/36.0.0"
    if not (directory / ("aapt2" + EXE)).is_file():
        raise RuntimeError("Install Android SDK Build Tools 36.0.0 or set VANTA_BUILD_TOOLS")
    return directory


def platform_jar(sdk):
    path = sdk / "platforms/android-35/android.jar"
    if not path.is_file():
        raise RuntimeError("Install Android SDK Platform 35")
    return path


def java(name):
    filename = name + EXE
    if os.environ.get("JAVA_HOME"):
        path = Path(os.environ["JAVA_HOME"]) / "bin" / filename
        if path.is_file():
            return path
        raise RuntimeError(f"JAVA_HOME does not provide {filename}")
    found = shutil.which(name)
    if found:
        return Path(found)
    bundled = WORKSPACE_TOOLS / "jdk17/jdk-17.0.20.1+1/bin" / filename
    if bundled.is_file():
        return bundled
    raise RuntimeError("Install JDK 17 and set JAVA_HOME")


def ndk_tools(sdk):
    configured = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
    installed = sdk / "ndk"
    versions = [entry for entry in installed.iterdir() if entry.is_dir() and
                all(part.isdigit() for part in entry.name.split("."))] if installed.is_dir() else []
    if configured:
        ndk = Path(configured)
    elif versions:
        ndk = max(versions, key=lambda entry: tuple(map(int, entry.name.split("."))))
    else:
        ndk = WORKSPACE_TOOLS / "android-ndk-r26b"
    host = {"Windows": "windows-x86_64", "Linux": "linux-x86_64", "Darwin": "darwin-x86_64"}.get(platform.system())
    if not host:
        raise RuntimeError("Unsupported Android NDK host platform")
    directory = ndk / "toolchains/llvm/prebuilt" / host / "bin"
    if not (directory / ("clang" + EXE)).is_file():
        raise RuntimeError("Install an Android NDK with Clang or set ANDROID_NDK_HOME")
    return directory
