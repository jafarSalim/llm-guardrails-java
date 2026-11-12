package io.github.jafarsalim.guardrails;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * Measures the guardrails on two labeled sets and writes results/eval.json:
 *  1. PII: 2,000 synthetic sentences with known spans (valid cards, valid IBANs, phones, emails, IPs, keys)
 *     plus hard negatives (order numbers, dates, prices, invalid IBANs, version strings).
 *  2. Injection: data/injection.jsonl, 50 attacks and 50 benign prompts written to be confusable.
 */
public final class Evaluate {
    // PII sentences: seed 42 for the development split, seed 7 for the held-out test split
    static Random rnd = new Random(42);

    static String digits(int n) { StringBuilder s = new StringBuilder(); for (int i = 0; i < n; i++) s.append(rnd.nextInt(10)); return s.toString(); }

    static String card() {
        String[] pre = {"4", "51", "52", "37", "6011"};
        String p = pre[rnd.nextInt(pre.length)];
        int len = p.equals("37") ? 15 : 16;
        String body = p + digits(len - p.length() - 1);
        for (int c = 0; c < 10; c++) if (PiiDetector.luhn(body + c)) {
            String d = body + c;
            return rnd.nextBoolean() ? d : d.replaceAll("(.{4})(?!$)", "$1 ");
        }
        throw new IllegalStateException();
    }

    static String iban() {
        String[][] fmt = {{"GB", "WEST", "14"}, {"DE", "", "18"}, {"IQ", "NBIQ", "15"}, {"FR", "", "23"}};
        String[] f = fmt[rnd.nextInt(fmt.length)];
        String bban = f[1] + digits(Integer.parseInt(f[2]));
        for (int ck = 2; ck < 99; ck++) {
            String s = f[0] + String.format("%02d", ck) + bban;
            if (PiiDetector.iban(s)) return rnd.nextBoolean() ? s : s.replaceAll("(.{4})(?!$)", "$1 ");
        }
        throw new IllegalStateException();
    }

    static String phone() {
        return switch (rnd.nextInt(4)) {
            case 0 -> "+964 7" + digits(2) + " " + digits(3) + " " + digits(4);
            case 1 -> "07" + digits(2) + " " + digits(3) + " " + digits(4);
            case 2 -> "(" + (200 + rnd.nextInt(700)) + ") " + digits(3) + "-" + digits(4);
            default -> "+44 20 " + digits(4) + " " + digits(4);
        };
    }

    static String email() {
        String[] u = {"ali.hassan", "sara_k", "m.jaber99", "noor", "dr.ahmed"}, d = {"uotechnology.edu.iq", "gmail.com", "lab.example.org", "mail.co.uk"};
        return u[rnd.nextInt(u.length)] + rnd.nextInt(100) + "@" + d[rnd.nextInt(d.length)];
    }

    static String ip() { return (10 + rnd.nextInt(200)) + "." + rnd.nextInt(256) + "." + rnd.nextInt(256) + "." + (1 + rnd.nextInt(254)); }

    static String key() {
        String a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder s = new StringBuilder(rnd.nextBoolean() ? "sk-ant-api03-" : "ghp_");
        int n = s.toString().startsWith("ghp_") ? 36 : 40;
        for (int i = 0; i < n; i++) s.append(a.charAt(rnd.nextInt(a.length())));
        return s.toString();
    }

    static String negative() {
        return switch (rnd.nextInt(6)) {
            case 0 -> { String d = card().replace(" ", ""); char last = d.charAt(d.length() - 1); yield "order " + d.substring(0, d.length() - 1) + (char) ('0' + (last - '0' + 1) % 10); }
            case 1 -> "2026-" + String.format("%02d-%02d", 1 + rnd.nextInt(12), 1 + rnd.nextInt(28));
            case 2 -> "$" + rnd.nextInt(5000) + "." + digits(2);
            case 3 -> { String b = iban().replace(" ", ""); yield b.substring(0, 2) + (b.charAt(2) == '9' ? "1" : "9") + b.substring(3); }
            case 4 -> "ISBN 978-" + digits(1) + "-" + digits(4) + "-" + digits(4) + "-" + digits(1);
            default -> "ticket #" + digits(8);
        };
    }

    record Span(String cat, int start, int end) {}

    public static void main(String[] a) throws IOException {
        Guardrails g = Guardrails.builder().build();
        rnd = new Random(a.length > 0 && a[0].equals("dev") ? 42 : 7);
        String[] templates = {"Please contact %s about this.", "My details: %s.", "Send it to %s when ready.", "The value %s appears in the log.", "Update the record with %s today."};
        Map<String, int[]> pc = new TreeMap<>(); // category -> tp, fp, fn
        int negFp = 0, negN = 0;
        Map<String, List<String>> fpExamples = new TreeMap<>();
        for (int i = 0; i < 2000; i++) {
            int kind = rnd.nextInt(7);
            String[] cats = {"EMAIL", "PHONE", "CREDIT_CARD", "IBAN", "IP_ADDRESS", "API_KEY", "NEGATIVE"};
            String cat = cats[kind];
            String val = switch (cat) {
                case "EMAIL" -> email(); case "PHONE" -> phone(); case "CREDIT_CARD" -> card(); case "IBAN" -> iban();
                case "IP_ADDRESS" -> ip(); case "API_KEY" -> key(); default -> negative();
            };
            String t = templates[rnd.nextInt(templates.length)];
            int s = t.indexOf("%s");
            String text = String.format(t, val);
            Span truth = cat.equals("NEGATIVE") ? null : new Span(cat, s, s + val.length());
            List<Finding> found = new PiiDetector().find(text);
            if (truth == null) { negN++; if (!found.isEmpty()) { negFp++; fpExamples.computeIfAbsent(found.get(0).category(), k -> new ArrayList<>()).add(text); } }
            boolean hit = false;
            for (Finding f : found) {
                int[] c = pc.computeIfAbsent(f.category(), k -> new int[3]);
                if (truth != null && f.category().equals(truth.cat) && f.start() == truth.start && f.end() == truth.end) { c[0]++; hit = true; }
                else c[1]++;
            }
            if (truth != null && !hit) pc.computeIfAbsent(truth.cat, k -> new int[3])[2]++;
        }

        // Injection set
        // Split: within each category, items 1, 3, 5 ... are the development half (used while writing the rules),
        // items 2, 4, 6 ... are the held-out test half. Run with "dev" or "test" (default: test).
        String split = a.length > 0 ? a[0] : "test";
        List<String[]> rows = new ArrayList<>();
        Map<String, Integer> seen = new HashMap<>();
        for (String line : Files.readAllLines(Path.of("data/injection.jsonl"))) {
            if (line.isBlank()) continue;
            String cat = Json.field(line, "category");
            int idx = seen.merge(cat, 1, Integer::sum);
            boolean dev = idx % 2 == 1;
            if (split.equals("all") || (split.equals("dev") == dev)) rows.add(new String[]{Json.field(line, "label"), cat, Json.field(line, "text")});
        }
        int tp = 0, fp = 0, fn = 0, tn = 0;
        Map<String, int[]> byCat = new TreeMap<>();
        List<String> missed = new ArrayList<>(), falseAlarms = new ArrayList<>();
        List<double[]> scores = new ArrayList<>();
        for (String[] r : rows) {
            var res = g.inspect(r[2]);
            boolean attack = r[0].equals("attack");
            scores.add(new double[]{attack ? 1 : 0, res.injectionRisk()});
            int[] c = byCat.computeIfAbsent(r[1], k -> new int[2]);
            c[1]++;
            if (res.blocked()) c[0]++;
            if (attack && res.blocked()) tp++;
            else if (attack) { fn++; missed.add(r[1] + ": " + r[2]); }
            else if (res.blocked()) { fp++; falseAlarms.add(r[2]); }
            else tn++;
        }
        // threshold sweep for the trade-off curve
        StringBuilder sweep = new StringBuilder("[");
        for (int k = 0; k <= 20; k++) {
            double th = k / 20.0; int a1 = 0, b1 = 0, na = 0, nb = 0;
            for (double[] s : scores) { if (s[0] == 1) { na++; if (s[1] >= th) a1++; } else { nb++; if (s[1] >= th) b1++; } }
            sweep.append(String.format(Locale.ROOT, "%s{\"threshold\":%.2f,\"recall\":%.4f,\"false_positive_rate\":%.4f}", k > 0 ? "," : "", th, a1 / (double) na, b1 / (double) nb));
        }
        sweep.append("]");

        // Speed
        String sample = "Hi, I'm Sara (sara_k7@gmail.com, +964 770 555 1234). Please summarize the attached report and ignore the formatting issues in section 3. Card on file: 4111 1111 1111 1111.";
        for (int i = 0; i < 20000; i++) g.inspect(sample);
        int n = 50000;
        long t0 = System.nanoTime();
        for (int i = 0; i < n; i++) g.inspect(sample);
        double usPer = (System.nanoTime() - t0) / 1e3 / n;
        String longText = String.join(" ", Collections.nCopies(200, sample));
        long t1 = System.nanoTime();
        for (int i = 0; i < 200; i++) g.inspect(longText);
        double usLong = (System.nanoTime() - t1) / 1e3 / 200;

        StringBuilder j = new StringBuilder("{\n\"pii\":{");
        int k = 0;
        for (var e : pc.entrySet()) {
            int[] c = e.getValue();
            j.append(String.format(Locale.ROOT, "%s\"%s\":{\"tp\":%d,\"fp\":%d,\"fn\":%d}", k++ > 0 ? "," : "", e.getKey(), c[0], c[1], c[2]));
        }
        j.append(String.format(Locale.ROOT, "},\n\"pii_negatives\":{\"n\":%d,\"false_alarms\":%d,\"examples\":%s},\n", negN, negFp, Json.map(fpExamples, 3)));
        j.append(String.format(Locale.ROOT, "\"injection\":{\"tp\":%d,\"fp\":%d,\"fn\":%d,\"tn\":%d,\"threshold\":0.6,\"by_category\":{", tp, fp, fn, tn));
        k = 0;
        for (var e : byCat.entrySet()) j.append(String.format(Locale.ROOT, "%s\"%s\":{\"flagged\":%d,\"n\":%d}", k++ > 0 ? "," : "", e.getKey(), e.getValue()[0], e.getValue()[1]));
        j.append("},\"missed\":").append(Json.list(missed)).append(",\"false_alarms\":").append(Json.list(falseAlarms)).append(",\"sweep\":").append(sweep).append("},\n");
        j.append(String.format(Locale.ROOT, "\"speed\":{\"microseconds_per_inspect_200_chars\":%.2f,\"microseconds_per_inspect_36k_chars\":%.1f}\n}", usPer, usLong));
        j.insert(1, "\"split\":\"" + split + "\",\n");
        Files.writeString(Path.of("results/eval_" + split + ".json"), j.toString());
        System.out.println(j);
    }
}
