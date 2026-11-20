package dev.vanta.deviceinput;

import android.app.KeyguardManager;
import android.inputmethodservice.InputMethodService;
import android.os.PowerManager;
import android.text.InputType;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public final class VantaKeyboard extends InputMethodService {
    private static VantaKeyboard active;

    @Override
    public void onCreate() {
        super.onCreate();
        active = this;
    }

    @Override
    public void onDestroy() {
        if (active == this) active = null;
        super.onDestroy();
    }

    @Override
    public View onCreateInputView() {
        LinearLayout panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        int inset = Math.round(8 * getResources().getDisplayMetrics().density);
        panel.setPadding(inset, inset, inset, inset);
        TextView name = new TextView(this);
        name.setText("Vanta Device Input · Unicode testing");
        panel.addView(name);
        Button switcher = new Button(this);
        switcher.setText("Choose another keyboard");
        switcher.setOnClickListener(view -> getSystemService(InputMethodManager.class).showInputMethodPicker());
        panel.addView(switcher);
        return panel;
    }

    private static boolean protectedInput(int type) {
        int kind = type & InputType.TYPE_MASK_CLASS;
        int variant = type & InputType.TYPE_MASK_VARIATION;
        if (kind == InputType.TYPE_CLASS_TEXT) {
            return variant == InputType.TYPE_TEXT_VARIATION_PASSWORD
                || variant == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                || variant == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD;
        }
        return kind == InputType.TYPE_CLASS_NUMBER && variant == InputType.TYPE_NUMBER_VARIATION_PASSWORD;
    }

    static String commit(String target, String text) {
        VantaKeyboard ime = active;
        if (ime == null || !ime.isInputViewShown()) return "keyboard_not_visible";
        PowerManager power = ime.getSystemService(PowerManager.class);
        KeyguardManager keyguard = ime.getSystemService(KeyguardManager.class);
        if (power == null || keyguard == null || !power.isInteractive() || keyguard.isKeyguardLocked()) {
            return "device_not_interactive";
        }
        EditorInfo editor = ime.getCurrentInputEditorInfo();
        InputConnection connection = ime.getCurrentInputConnection();
        if (editor == null || connection == null || !target.equals(editor.packageName)) return "editor_changed";
        if (editor.inputType == InputType.TYPE_NULL || protectedInput(editor.inputType)) return "protected_or_unsupported_editor";
        return connection.commitText(text, 1) ? "accepted" : "editor_disconnected";
    }
}
