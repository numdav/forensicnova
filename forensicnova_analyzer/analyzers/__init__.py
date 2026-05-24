"""ForensicNova analyzers package.

A modular collection of "analyzers" — components that take a local
dump file on disk plus context, and produce a structured result dict.

Each analyzer is a class with a uniform run() interface so the async
runner (Stage E2.4 / E3+) can dispatch on the analyzer_name without
caring about the implementation.

Current members:

  NoOpAnalyzer        — Stage E2.3. Reads the dump end-to-end and
                        recomputes MD5+SHA1 as an independent
                        third-witness coherence check. No real
                        forensic analysis. Exists to validate the
                        orchestration pipeline before plugging in
                        Volatility 3.

  VolatilityAnalyzer  — Stage E3. Subprocess wrapper around vol3 with
                        preset support (currently "fast"; E4 will add
                        "full" and "custom") and per-plugin timeout +
                        graceful degradation. Performs the same
                        triple-witness hashing as NoOpAnalyzer, then
                        runs the preset plugin list serially.

Future members (planned):

  MispEnricher       — Stage F. Post-process Volatility findings against
                        a MISP instance for IOC enrichment.

A plugin-style registry mapping analyzer_name -> class will be
introduced when there is more than a handful of analyzers; for now
the runner imports the concrete classes directly from this package.
"""

from forensicnova_analyzer.analyzers.noop import NoOpAnalyzer  # noqa: F401
from forensicnova_analyzer.analyzers.volatility import (  # noqa: F401
    VolatilityAnalyzer,
)
