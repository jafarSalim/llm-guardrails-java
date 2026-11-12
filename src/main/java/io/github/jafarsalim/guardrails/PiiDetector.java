package io.github.jafarsalim.guardrails;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds personal and secret data. Patterns that have a checksum (cards: Luhn, IBAN: mod 97) are only
 * reported when the checksum is valid, which removes most false alarms from order numbers and IDs.
 */
public final class PiiDetector {
    private record Rule(String category, Pattern pattern) {}

    private static final List<Rule> RULES = List.of(
        new Rule("EMAIL", Pattern.compile("(?<![\\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}(?![\\w-])")),
        new Rule("API_KEY", Pattern.compile("\\b(?:sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,})\\b")),
        new Rule("JWT", Pattern.compile("\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b")),
        new Rule("IBAN", Pattern.compile("\\b[A-Z]{2}\\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\\b")),
        // Issuer prefixes: Visa 4, Mastercard 51-55 and 2221-2720, Amex 34/37, Discover 6011/65, JCB 35
        new Rule("CREDIT_CARD", Pattern.compile("(?<![\\w-])(?=4|5[1-5]|2[2-7]|3[47]|35|6011|65)(?:\\d[ -]?){12,18}\\d(?![\\w-])")),
        new Rule("PHONE", Pattern.compile("(?<![\\w+])(?<!\\d[ .-])(?:\\+\\d{1,3}[ .-]?)?(?:\\(\\d{2,4}\\)[ .-]?|\\d{2,4}[ .-])\\d{3,4}[ .-]?\\d{3,4}(?![ .-]?\\d)")),
        new Rule("IP_ADDRESS", Pattern.compile("\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b"))
    );

    public List<Finding> find(String text) {
        List<Finding> out = new ArrayList<>();
        boolean[] taken = new boolean[text.length() + 1];
        for (Rule r : RULES) {
            Matcher m = r.pattern.matcher(text);
            while (m.find()) {
                String s = m.group();
                if (overlaps(taken, m.start(), m.end()) || !valid(r.category, s)) continue;
                for (int i = m.start(); i < m.end(); i++) taken[i] = true;
                out.add(new Finding(Finding.Kind.PII, r.category, m.start(), m.end(), s, 1.0, r.category.toLowerCase().replace('_', ' ')));
            }
        }
        out.sort((a, b) -> Integer.compare(a.start(), b.start()));
        return out;
    }

    private static boolean overlaps(boolean[] taken, int s, int e) {
        for (int i = s; i < e; i++) if (taken[i]) return true;
        return false;
    }

    static boolean valid(String category, String s) {
        return switch (category) {
            case "CREDIT_CARD" -> luhn(s.replaceAll("[ -]", ""));
            case "IBAN" -> iban(s.replace(" ", ""));
            case "PHONE" -> s.replaceAll("\\D", "").length() >= 9 && !s.matches("\\d{4}[ .-]\\d{2}[ .-]\\d{2}.*");
            default -> true;
        };
    }

    /** Luhn checksum used by payment cards (13 to 19 digits). */
    public static boolean luhn(String digits) {
        if (digits.length() < 13 || digits.length() > 19 || !digits.chars().allMatch(Character::isDigit)) return false;
        int sum = 0;
        boolean dbl = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int d = digits.charAt(i) - '0';
            if (dbl && (d *= 2) > 9) d -= 9;
            sum += d;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    /** ISO 13616 IBAN check: move the first 4 characters to the end, letters to numbers, mod 97 == 1. */
    public static boolean iban(String s) {
        if (s.length() < 15 || s.length() > 34) return false;
        String r = s.substring(4) + s.substring(0, 4);
        StringBuilder num = new StringBuilder();
        for (char c : r.toCharArray()) {
            if (Character.isDigit(c)) num.append(c);
            else if (c >= 'A' && c <= 'Z') num.append(c - 'A' + 10);
            else return false;
        }
        return new BigInteger(num.toString()).mod(BigInteger.valueOf(97)).intValue() == 1;
    }
}
