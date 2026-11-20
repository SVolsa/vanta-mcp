"""Build a disposable signed base APK, split APK and native debug symbols."""
import argparse
from pathlib import Path
import subprocess
import tempfile
import uuid
import zipfile
from android_build import EXE, android_sdk, build_tools, java, ndk_tools, platform_jar

HERE = Path(__file__).resolve().parent
PACKAGE = "dev.vanta.inspectionprobe"


def run(*args):
    result = subprocess.run([str(value) for value in args], capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))


def write_manifest(file, split, revision, extract):
    base = f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{PACKAGE}" android:versionCode="{revision}" android:versionName="{revision}.0"'
    if split:
        content = base + ' split="diagnostics"><application android:hasCode="false"/></manifest>'
    else:
        content = base + f"""><uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35"/>
        <application android:label="Vanta Inspection Probe" android:debuggable="true" android:extractNativeLibs="{str(extract).lower()}">
            <activity android:name=".InspectionProbe" android:exported="true"/>
            <activity android:name=".DeviceUseProbe" android:exported="true" android:theme="@android:style/Theme.Material.Light.NoActionBar"/>
            <receiver android:name=".InspectionProbe$ProbeReceiver" android:exported="true" android:permission="android.permission.DUMP"/>
        </application></manifest>"""
    file.write_text(content, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--abi", choices=["x86_64", "arm64-v8a"], default="x86_64")
    parser.add_argument("--revision", type=int, choices=range(1, 100), default=1)
    parser.add_argument("--native-variant", choices=["good", "missing-dependency", "wrong-abi", "misaligned"])
    args = parser.parse_args()
    out = HERE / "out" / f"inspection-probe-{uuid.uuid4().hex[:12]}"
    out.mkdir(parents=True)
    sdk = android_sdk()
    tools = build_tools(sdk)
    platform = platform_jar(sdk)
    llvm = ndk_tools(sdk)
    triple = "x86_64-linux-android24" if args.abi == "x86_64" else "aarch64-linux-android24"
    symbols = out / "symbols"
    symbols.mkdir()
    unstripped = symbols / "libvanta_probe.so"
    with tempfile.TemporaryDirectory(prefix="vanta-inspection-probe-") as temp:
        work = Path(temp)
        clang = llvm/("clang"+EXE)
        dependency = work/"libvanta_probe_dep.so"
        extract = args.native_variant not in {"good", "misaligned"}
        link = []
        if args.native_variant:
            dependency_source = work/"dependency.c"
            dependency_source.write_text("int vanta_probe_revision(void) { return 1; }\n", encoding="ascii")
            run(clang, f"--target={triple}", "-shared", "-fPIC", "-Wl,-soname,libvanta_probe_dep.so",
                "-Wl,-z,max-page-size=16384", dependency_source, "-o", dependency)
            link = ["-Wl,--no-as-needed", dependency]
        main_triple = ("aarch64-linux-android24" if args.abi == "x86_64" else "x86_64-linux-android24") if args.native_variant == "wrong-abi" else triple
        alignment = 4096 if args.native_variant == "misaligned" else 16384
        run(clang, f"--target={main_triple}", f"-DVANTA_PROBE_REVISION={args.revision}", "-shared", "-fPIC", "-g", "-O0",
            "-Wl,--build-id=sha1", f"-Wl,-z,max-page-size={alignment}", HERE/"test-app/inspection-probe.c",
            *([] if args.native_variant == "wrong-abi" else link), "-o", unstripped)
        password = work/"password.txt"
        password.write_text(uuid.uuid4().hex, encoding="ascii")
        key = work/"test.p12"
        run(java("keytool"),"-genkeypair","-keystore",key,"-storetype","PKCS12",
            "-storepass:file",password,"-keypass:file",password,"-alias","test","-keyalg","RSA",
            "-validity","2","-dname","CN=Disposable Vanta Inspection Probe")
        classes = work/"classes"
        classes.mkdir()
        source = work/"InspectionProbe.java"
        source.write_text((HERE/"test-app/InspectionProbe.java").read_text(encoding="utf-8")
                          .replace("Vanta Inspection Probe v1",f"Vanta Inspection Probe v{args.revision}"), encoding="utf-8")
        run(java("javac"),"-encoding","UTF-8","-source","8","-target","8","-classpath",platform,"-d",classes,source,HERE/"test-app/DeviceUseProbe.java")
        run(java("java"),"-cp",tools/"lib/d8.jar","com.android.tools.r8.D8","--lib",platform,
            "--min-api","24","--output",work,*sorted((classes/"dev/vanta/inspectionprobe").glob("*.class")))
        stripped = work/"libvanta_probe.so"
        run(llvm/("llvm-strip"+EXE),"--strip-debug","-o",stripped,unstripped)
        resources = work/"resources.zip"
        run(tools/("aapt2"+EXE),"compile","--dir",HERE/"test-app/res","-o",resources)
        for name, split in [("base",False),("split_diagnostics",True)]:
            manifest = work/"AndroidManifest.xml"
            write_manifest(manifest, split, args.revision, extract)
            raw, aligned = work/f"{name}.raw.apk", work/f"{name}.aligned.apk"
            run(tools/("aapt2"+EXE),"link","-I",platform,"--manifest",manifest,"-o",raw,*(() if split else (resources,)))
            compression = zipfile.ZIP_DEFLATED if extract else zipfile.ZIP_STORED
            if not split:
                with zipfile.ZipFile(raw,"a",compression=zipfile.ZIP_DEFLATED) as apk:
                    apk.write(work/"classes.dex","classes.dex")
                    apk.write(stripped,f"lib/{args.abi}/libvanta_probe.so",compress_type=compression)
            elif args.native_variant in {"good", "misaligned"}:
                with zipfile.ZipFile(raw,"a",compression=compression) as apk:
                    apk.write(dependency,f"lib/{args.abi}/{dependency.name}")
            page_align = ("-P", "16" if args.native_variant == "good" else "4") if not extract else ()
            run(tools/("zipalign"+EXE),*page_align,"-f","4",raw,aligned)
            preserve = ("--alignment-preserved", "true") if not extract else ()
            run(java("java"),"-jar",tools/"lib/apksigner.jar","sign","--ks",key,
                "--ks-pass",f"file:{password}",*preserve,"--out",out/f"{name}.apk",aligned)
    print(out)


if __name__ == "__main__":
    main()
