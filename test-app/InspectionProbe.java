package dev.vanta.inspectionprobe;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.SystemClock;

public final class InspectionProbe extends Activity {
    private static native void crashProbe();

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setTitle("Vanta Inspection Probe v1");
        if (getIntent().getBooleanExtra("load_only", false)) {
            System.loadLibrary("vanta_probe");
            android.util.Log.i("VantaInspectionProbe", "Native probe loaded");
        }
        if (getIntent().getBooleanExtra("crash", false)) {
            System.loadLibrary("vanta_probe");
            crashProbe();
        }
        finish();
    }

    public static final class ProbeReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            if ("dev.vanta.inspectionprobe.ANR".equals(intent.getAction())) {
                SystemClock.sleep(25000);
            }
        }
    }
}
