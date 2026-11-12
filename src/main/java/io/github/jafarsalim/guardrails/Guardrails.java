package io.github.jafarsalim.guardrails;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * The entry point.
 * <pre>
 * Guardrails g = Guardrails.builder().blockAbove(0.6).build();
 * Guardrails.Result r = g.inspect(userText);
 * if (r.blocked()) ... else send(r.maskedText()); later: r.vault().unmask(modelAnswer)
 * </pre>
 */
public final class Guardrails {
    private final PiiDetector pii = new PiiDetector();
    private final InjectionDetector inj = new InjectionDetector();
    private final double blockAbove;
    private final Set<String> maskCategories;

    private Guardrails(double blockAbove, Set<String> maskCategories) {
        this.blockAbove = blockAbove;
        this.maskCategories = maskCategories;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private double blockAbove = 0.6;
        private Set<String> mask = Set.of("EMAIL", "PHONE", "CREDIT_CARD", "IBAN", "IP_ADDRESS", "API_KEY", "JWT");

        public Builder blockAbove(double risk) { this.blockAbove = risk; return this; }
        public Builder mask(Set<String> categories) { this.mask = Set.copyOf(categories); return this; }
        public Guardrails build() { return new Guardrails(blockAbove, mask); }
    }

    public record Result(String maskedText, Vault vault, List<Finding> findings, double injectionRisk, boolean blocked) {
        public List<Finding> pii() { return findings.stream().filter(f -> f.kind() == Finding.Kind.PII).toList(); }
        public List<Finding> injection() { return findings.stream().filter(f -> f.kind() == Finding.Kind.INJECTION).toList(); }
    }

    public Result inspect(String text) {
        List<Finding> p = pii.find(text);
        List<Finding> i = inj.find(text);
        Vault v = new Vault();
        StringBuilder sb = new StringBuilder();
        int last = 0;
        for (Finding f : p) {
            if (!maskCategories.contains(f.category())) continue;
            sb.append(text, last, f.start()).append(v.placeholder(f.category(), f.match()));
            last = f.end();
        }
        sb.append(text.substring(last));
        List<Finding> all = new ArrayList<>(p);
        all.addAll(i);
        double risk = InjectionDetector.risk(i);
        return new Result(sb.toString(), v, all, risk, risk >= blockAbove);
    }
}
