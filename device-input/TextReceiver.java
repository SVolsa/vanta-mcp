package dev.vanta.deviceinput;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Base64;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;

public final class TextReceiver extends BroadcastReceiver {
    private static final String ACTION = "dev.vanta.deviceinput.COMMIT_TEXT";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (!isOrderedBroadcast() || !ACTION.equals(intent.getAction())) return;
        String target = intent.getStringExtra("target_package");
        String encoded = intent.getStringExtra("text_b64");
        if (target == null || !target.matches("[A-Za-z_][A-Za-z0-9_.]{1,254}")
                || encoded == null || !encoded.matches("[A-Za-z0-9_-]{1,4096}")) {
            finish("invalid_arguments");
            return;
        }
        try {
            byte[] utf8 = Base64.decode(encoded, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
            String text = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(utf8)).toString();
            if (text.isEmpty() || text.length() > 512 || containsControl(text)) {
                finish("invalid_text");
                return;
            }
            finish(VantaKeyboard.commit(target, text));
        } catch (IllegalArgumentException | CharacterCodingException error) {
            finish("invalid_text");
        } catch (RuntimeException error) {
            finish("editor_disconnected");
        }
    }

    private static boolean containsControl(String text) {
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isISOControl(c) && c != '\n' && c != '\t') return true;
        }
        return false;
    }

    private void finish(String result) {
        setResultCode("accepted".equals(result) ? 1 : 0);
        setResultData(result);
    }
}
