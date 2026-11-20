#include <jni.h>

JNIEXPORT void JNICALL Java_dev_vanta_inspectionprobe_InspectionProbe_crashProbe(
    JNIEnv *env, jclass type) {
    (void)env;
    (void)type;
    volatile int revision = VANTA_PROBE_REVISION;
    (void)revision;
    __builtin_trap();
}
