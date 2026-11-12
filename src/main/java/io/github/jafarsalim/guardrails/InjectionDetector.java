package io.github.jafarsalim.guardrails;

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scores text for prompt-injection signals. Each rule has a weight; the risk is 1 - prod(1 - w)
 * over the rules that fire, so independent signals add up but never exceed 1.
 * The text is normalized first (NFKC, lower case, zero-width characters removed) so simple
 * obfuscation does not hide a phrase, and any hidden characters found are themselves a signal.
 */
public final class InjectionDetector {
    private record Rule(String category, double weight, Pattern pattern, String reason) {}

    private static final int F = Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE;
    private static final List<Rule> RULES = List.of(
        new Rule("OVERRIDE", 0.75, Pattern.compile("\\b(ignore|disregard|forget|override|bypass)\\b[^.\\n]{0,40}\\b(previous|prior|above|earlier|all|your|the system|any)\\b[^.\\n]{0,25}\\b(instructions?|rules|prompts?|guidelines|directions|constraints)\\b", F),
            "asks to ignore earlier instructions"),
        new Rule("OVERRIDE", 0.55, Pattern.compile("\\b(new|updated|real|actual) (instructions?|rules|system prompt)\\s*[:\\-]", F), "announces replacement instructions"),
        new Rule("EXFILTRATION", 0.7, Pattern.compile("\\b(reveal|print|show|repeat|output|leak|tell me|what (is|are))\\b[^.\\n]{0,30}\\b(system prompt|hidden (prompt|instructions)|initial instructions|your instructions|developer message|the prompt above)\\b", F),
            "tries to extract the system prompt"),
        new Rule("ROLEPLAY", 0.6, Pattern.compile("\\b(you are now|act as|pretend (to be|you are)|from now on,? you)\\b[^.\\n]{0,40}\\b(dan|unrestricted|unfiltered|jailbroken|no (rules|restrictions|limits|filters)|developer mode|evil)\\b", F),
            "role-play designed to drop the rules"),
        new Rule("ROLEPLAY", 0.65, Pattern.compile("\\b(developer|god|admin|sudo|debug|jailbreak) mode\\s+(is\\s+)?(now\\s+)?(enabled|activated|unlocked)\\b", F), "claims a privileged mode"),
        new Rule("DELIMITER", 0.7, Pattern.compile("<\\|im_start\\|>\\s*system|<<SYS>>[^<]{0,80}\\b(disclose|reveal|ignore|bypass|output)\\b", F), "fake system turn in chat-template syntax"),
        new Rule("DELIMITER", 0.6, Pattern.compile("(?m)^\\s*(system|assistant|developer)\\s*:\\s*\\S", F), "a line that pretends to be another chat role"),
        new Rule("DELIMITER", 0.45, Pattern.compile("(<\\|?(im_start|im_end|system|endoftext)\\|?>|\\[/?(INST|SYS)\\]|<<SYS>>)", F),
            "fake chat-format delimiters"),
        new Rule("EXFILTRATION", 0.65, Pattern.compile("!\\[[^\\]]*\\]\\(https?://[^)\\s]*[?&][^)\\s]*=", F), "markdown image that would send data to a URL"),
        new Rule("TOOL_ABUSE", 0.65, Pattern.compile("\\b(send|email|forward|post|upload)\\b[^.\\n]{0,40}\\b(api keys?|passwords?|credentials|secrets?|tokens?|conversation|chat history)\\b[^.\\n]{0,30}\\b(to|at)\\b", F),
            "asks to send secrets somewhere"),
        new Rule("AUTHORITY", 0.6, Pattern.compile("\\b(safety|content|security) (checks|filters|rules|policy|policies)\\b[^.\\n]{0,15}\\b(are |is )?(now )?(disabled|off|removed|suspended|lifted)\\b", F), "claims the safety rules are switched off"),
        new Rule("OVERRIDE", 0.65, Pattern.compile("\\b(no longer applies|(is|are) (now )?outdated|stop following|follow (mine|my (instructions|rules)) instead|regardless of (the |any |your )?(criteria|instructions|rules|policy)|you have no (previous|prior) instructions)\\b", F), "says earlier instructions no longer count"),
        new Rule("EXFILTRATION", 0.65, Pattern.compile("\\b(repeat|print|copy|output)\\b[^.\\n]{0,15}\\b(the )?(text|words|everything|all) (above|before this)\\b|\\binclude everything in your (system )?prompt\\b", F), "asks to copy out earlier hidden text"),
        new Rule("AUTHORITY", 0.35, Pattern.compile("\\b(this is|message from) (your|the) (developer|administrator|admin|creator|openai|anthropic)\\b", F), "claims authority over the model")
    );

    private static final Pattern HIDDEN = Pattern.compile("[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\uFEFF]|[\\x{E0000}-\\x{E007F}]");
    private static final Pattern B64 = Pattern.compile("[A-Za-z0-9+/]{24,}={0,2}");

    public List<Finding> find(String text) {
        List<Finding> out = new ArrayList<>();
        Matcher h = HIDDEN.matcher(text);
        int hidden = 0;
        while (h.find()) hidden++;
        if (hidden >= 3) out.add(new Finding(Finding.Kind.INJECTION, "HIDDEN_TEXT", 0, text.length(), "", 0.5, hidden + " invisible characters"));
        // Hidden characters can split a word ("Ign\u200Bore") or join two ("Nice\u200BIgnore"): try both readings.
        String norm = Normalizer.normalize(HIDDEN.matcher(text).replaceAll(""), Normalizer.Form.NFKC);
        scan(norm, out, "");
        if (hidden > 0) {
            int before = out.size();
            List<Finding> spaced = new ArrayList<>();
            scan(Normalizer.normalize(HIDDEN.matcher(text).replaceAll(" "), Normalizer.Form.NFKC), spaced, "");
            for (Finding f : spaced) if (out.subList(0, before).stream().noneMatch(o -> o.reason().equals(f.reason()))) out.add(f);
        }
        String deleet = norm.replace('0', 'o').replace('1', 'i').replace('3', 'e').replace('4', 'a').replace('5', 's').replace('7', 't');
        if (!deleet.equals(norm)) { // "1gn0re prev1ous" -> "ignore previous"
            List<Finding> extra = new ArrayList<>();
            scan(deleet, extra, "leetspeak: ");
            for (Finding f : extra) if (out.stream().noneMatch(o -> o.category().equals(f.category()))) out.add(f);
        }
        Matcher b = B64.matcher(norm);
        while (b.find()) { // look inside base64 blobs for the same phrases
            try {
                String dec = new String(Base64.getDecoder().decode(b.group()), StandardCharsets.UTF_8);
                int before = out.size();
                scan(dec, out, "base64: ");
                if (out.size() > before) out.add(new Finding(Finding.Kind.INJECTION, "ENCODED", b.start(), b.end(), b.group(), 0.3, "instructions hidden in base64"));
            } catch (IllegalArgumentException ignored) {
                // not base64 after all
            }
        }
        return out;
    }

    private static void scan(String s, List<Finding> out, String prefix) {
        for (Rule r : RULES) {
            Matcher m = r.pattern.matcher(s);
            if (m.find()) out.add(new Finding(Finding.Kind.INJECTION, r.category, m.start(), m.end(), m.group(), r.weight, prefix + r.reason));
        }
    }

    /** Combined risk in [0, 1]. */
    public static double risk(List<Finding> fs) {
        double keep = 1.0;
        for (Finding f : fs) if (f.kind() == Finding.Kind.INJECTION) keep *= 1 - f.weight();
        return 1 - keep;
    }
}
