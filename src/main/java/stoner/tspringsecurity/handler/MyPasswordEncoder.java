package stoner.tspringsecurity.handler;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.DigestUtils;

@Component
public class MyPasswordEncoder implements PasswordEncoder {

    private static final String SALT_PREFIX = "6bcaaG81";

    @Override
    public String encode(CharSequence charSequence) {
        return digest(charSequence);
    }

    @Override
    public boolean matches(CharSequence charSequence, String s) {
        String s1 = digest(charSequence);
        return s.equals(s1);
    }

    public static String digest(CharSequence charSequence) {
        return DigestUtils.md5DigestAsHex(SALT_PREFIX.concat(charSequence.toString()).getBytes());
    }
}
