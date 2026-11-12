#!/usr/bin/env bash
# Builds and tests with the JDK alone (no Maven or Gradle needed).
#   ./build.sh          compile and package build/llm-guardrails-0.1.0.jar
#   ./build.sh test     run the tests
#   ./build.sh eval     run the evaluation, writes results/eval.json
set -euo pipefail
cd "$(dirname "$0")"
rm -rf build/classes && mkdir -p build/classes
javac --release 17 -d build/classes $(find src/main -name "*.java")
jar --create --file build/llm-guardrails-0.1.0.jar -C build/classes .
case "${1:-}" in
  test) javac --release 17 -cp build/classes -d build/test $(find src/test -name "*.java") && java -cp build/classes:build/test io.github.jafarsalim.guardrails.GuardrailsTest ;;
  eval) javac --release 17 -cp build/classes -d build/eval $(find src/eval -name "*.java") && java -cp build/classes:build/eval io.github.jafarsalim.guardrails.Evaluate "${2:-test}" ;;
esac
