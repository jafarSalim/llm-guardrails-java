package io.github.jafarsalim.guardrails;

/** One thing the guardrails found: what kind, where in the text, and why. */
public record Finding(Kind kind, String category, int start, int end, String match, double weight, String reason) {
    public enum Kind { PII, INJECTION }
}
