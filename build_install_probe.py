"""Build one clearly named, permission-free APK solely for install/uninstall acceptance."""
from pathlib import Path
import subprocess
import uuid
from android_build import EXE, android_sdk, build_tools, java, platform_jar

HERE=Path(__file__).resolve().parent

def main():
    out=HERE/'out/usb-install-probe'
    out.mkdir(parents=True,exist_ok=True)
    sdk=android_sdk()
    tools=build_tools(sdk)
    platform=platform_jar(sdk)
    password=out/('password-'+uuid.uuid4().hex+'.txt')
    keystore=out/('test-'+uuid.uuid4().hex+'.p12')
    def run(args):
        r=subprocess.run([str(a) for a in args],capture_output=True,timeout=30)
        if r.returncode:raise RuntimeError(r.stderr.decode('utf-8',errors='replace'))
    try:
        password.write_text(uuid.uuid4().hex,encoding='ascii')
        run([java('keytool'),'-genkeypair','-keystore',keystore,'-storetype','PKCS12',
             '-storepass:file',password,'-keypass:file',password,'-alias','test','-keyalg','RSA',
             '-validity','2','-dname','CN=Disposable Vanta Install Probe'])
        run([tools/('aapt2'+EXE),'link','-I',platform,'--manifest',HERE/'test-app/AndroidManifest.xml','-o',out/'base.apk'])
        run([tools/('zipalign'+EXE),'-f','4',out/'base.apk',out/'aligned.apk'])
        run([java('java'),'-jar',tools/'lib/apksigner.jar','sign','--ks',keystore,
             '--ks-pass','file:'+str(password),'--out',out/'test.apk',out/'aligned.apk'])
        run([java('java'),'-jar',tools/'lib/apksigner.jar','verify',out/'test.apk'])
        print(out/'test.apk')
    finally:
        password.unlink(missing_ok=True)
        keystore.unlink(missing_ok=True)

if __name__=='__main__':main()
