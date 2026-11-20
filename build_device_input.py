"""Build the optional Android Vanta Device Input development APK."""
from pathlib import Path
import subprocess
import tempfile
import uuid
import zipfile
from android_build import EXE, android_sdk, build_tools, java, platform_jar

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "device-input"


def run(*args):
    subprocess.run([str(value) for value in args], check=True, timeout=90)


def main():
    sdk = android_sdk()
    build = build_tools(sdk)
    android_jar = platform_jar(sdk)

    def tool(name):
        return build / (name + EXE)

    out = HERE / "out/device-input"
    out.mkdir(parents=True, exist_ok=True)
    key, password = out / "dev-signing.p12", out / "dev-signing.password"
    if not key.exists():
        password.write_text(uuid.uuid4().hex, encoding="ascii")
        run(java("keytool"), "-genkeypair", "-keystore", key, "-storetype", "PKCS12",
            "-storepass:file", password, "-keypass:file", password, "-alias", "vanta-dev",
            "-keyalg", "RSA", "-validity", "3650", "-dname", "CN=Vanta Device Input Development")
    with tempfile.TemporaryDirectory(prefix="vanta-device-input-") as temp:
        work = Path(temp)
        classes, resources = work / "classes", work / "res.zip"
        classes.mkdir()
        run(java("javac"), "-encoding", "UTF-8", "-source", "8", "-target", "8", "-classpath", android_jar,
            "-d", classes, *sorted(SOURCE.glob("*.java")))
        run(java("java"), "-cp", build / "lib/d8.jar", "com.android.tools.r8.D8", "--lib", android_jar,
            "--min-api", "24", "--output", work, *sorted(classes.rglob("*.class")))
        run(tool("aapt2"), "compile", "--dir", SOURCE / "res", "-o", resources)
        apk = work / "unsigned.apk"
        run(tool("aapt2"), "link", "-I", android_jar, "--manifest", SOURCE / "AndroidManifest.xml", "-o", apk, resources)
        with zipfile.ZipFile(apk, "a", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(work / "classes.dex", "classes.dex")
        aligned = work / "aligned.apk"
        run(tool("zipalign"), "-f", "4", apk, aligned)
        output = out / "vanta-device-input.apk"
        signer = build / "lib/apksigner.jar"
        run(java("java"), "-jar", signer, "sign", "--ks", key, "--ks-pass", f"file:{password}",
            "--out", output, aligned)
        run(java("java"), "-jar", signer, "verify", output)
        print(output)


if __name__ == "__main__":
    main()
