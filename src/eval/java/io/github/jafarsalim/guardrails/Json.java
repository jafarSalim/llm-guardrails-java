package io.github.jafarsalim.guardrails;

import java.util.List;
import java.util.Map;

/** Just enough JSON for the evaluation files: read a string field from one flat object, write lists. */
final class Json {
    static String field(String line, String name) {
        int i = line.indexOf("\"" + name + "\"");
        i = line.indexOf('"', line.indexOf(':', i) + 1) + 1;
        StringBuilder out = new StringBuilder();
        while (line.charAt(i) != '"') {
            char c = line.charAt(i++);
            if (c != '\\') { out.append(c); continue; }
            char e = line.charAt(i++);
            switch (e) {
                case 'n' -> out.append('\n');
                case 't' -> out.append('\t');
                case 'u' -> { out.append((char) Integer.parseInt(line.substring(i, i + 4), 16)); i += 4; }
                default -> out.append(e);
            }
        }
        return out.toString();
    }

    static String esc(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c == '\n') b.append("\\n");
            else if (c < 0x20 || (c >= 0x200B && c <= 0x200F) || Character.isSurrogate(c)) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    static String list(List<String> xs) {
        StringBuilder b = new StringBuilder("[");
        for (int i = 0; i < xs.size(); i++) b.append(i > 0 ? "," : "").append(esc(xs.get(i)));
        return b.append(']').toString();
    }

    static String map(Map<String, List<String>> m, int max) {
        StringBuilder b = new StringBuilder("{");
        int k = 0;
        for (var e : m.entrySet()) b.append(k++ > 0 ? "," : "").append(esc(e.getKey())).append(':').append(list(e.getValue().subList(0, Math.min(max, e.getValue().size()))));
        return b.append('}').toString();
    }
}
