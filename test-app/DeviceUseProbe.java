package dev.vanta.inspectionprobe;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public final class DeviceUseProbe extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setTitle("Vanta Device Use Probe");
        if (getIntent().getBooleanExtra("keep_awake", false)) {
            getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        }
        if (getIntent().getBooleanExtra("secure", false)) {
            getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        }
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(32, 32, 32, 32);
        if (Build.VERSION.SDK_INT >= 30) {
            page.setOnApplyWindowInsetsListener((view, insets) -> {
                android.graphics.Insets safe = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                view.setPadding(32 + safe.left, 32 + safe.top, 32 + safe.right, 32 + safe.bottom);
                return insets;
            });
        }
        page.setFocusableInTouchMode(true);
        TextView label = new TextView(this);
        label.setText("Ready");
        label.setTextSize(22);
        page.addView(label);
        Button button = new Button(this);
        button.setText("Count tap");
        final int[] clicks = {0};
        button.setOnClickListener(view -> label.setText("Tapped " + ++clicks[0]));
        page.addView(button);
        EditText edit = new EditText(this);
        edit.setHint("Enter probe text");
        edit.setInputType(InputType.TYPE_CLASS_TEXT);
        page.addView(edit);
        EditText password = new EditText(this);
        password.setHint("Probe password");
        password.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        password.setText("probe-placeholder");
        page.addView(password);
        TextView gesture = new TextView(this);
        gesture.setText("Gesture probe");
        int probeHeight = Math.round(300 * getResources().getDisplayMetrics().density);
        page.addView(gesture, new LinearLayout.LayoutParams(-1, probeHeight));
        gesture.setOnTouchListener((view, event) -> {
            if (event.getActionMasked() == MotionEvent.ACTION_UP) {
                gesture.setText("Gesture probe " + (event.getEventTime() - event.getDownTime()) + " ms");
            }
            return true;
        });
        if (getIntent().getBooleanExtra("replay", false)) {
            edit.setId(probeId("probe_input"));
            edit.setOnFocusChangeListener((view, focused) -> {
                if (focused) Log.i("VantaReplayProbe", "Replay input focused");
            });
            ScrollView scroll = new ScrollView(this);
            scroll.setId(probeId("probe_scroll"));
            scroll.setFillViewport(true);
            scroll.addView(page);
            View spacer = new View(this);
            page.addView(spacer, new LinearLayout.LayoutParams(-1, getResources().getDisplayMetrics().heightPixels));
            Button submit = new Button(this);
            submit.setId(probeId("probe_submit"));
            submit.setText("Submit");
            page.addView(submit);
            TextView result = new TextView(this);
            result.setId(probeId("probe_result"));
            result.setText("Pending");
            page.addView(result);
            submit.setOnClickListener(view -> {
                Log.i("VantaReplayProbe", "Test form submitted");
                result.postDelayed(() -> result.setText("Saved: " + edit.getText()), 1400);
            });
            setContentView(scroll);
        } else {
            setContentView(page);
        }
        page.requestFocus();
    }

    private int probeId(String name) {
        return getResources().getIdentifier(name, "id", getPackageName());
    }
}
