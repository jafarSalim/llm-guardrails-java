package io.github.jafarsalim.guardrails;

import java.util.LinkedHashMap;
import java.util.Map;

/** Remembers which placeholder stands for which original value, so a model's answer can be restored. */
public final class Vault {
    private final Map<String, String> byPlaceholder = new LinkedHashMap<>();
    private final Map<String, String> byValue = new LinkedHashMap<>();
    private final Map<String, Integer> counters = new LinkedHashMap<>();

    String placeholder(String category, String value) {
        return byValue.computeIfAbsent(category + "\u0000" + value, k -> {
            int n = counters.merge(category, 1, Integer::sum);
            String p = "[" + category + "_" + n + "]";
            byPlaceholder.put(p, value);
            return p;
        });
    }

    /** Puts the original values back into text that contains placeholders (for example the model's answer). */
    public String unmask(String text) {
        String out = text;
        for (var e : byPlaceholder.entrySet()) out = out.replace(e.getKey(), e.getValue());
        return out;
    }

    public int size() {
        return byPlaceholder.size();
    }
}
