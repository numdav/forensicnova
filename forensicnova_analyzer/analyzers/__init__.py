"""ForensicNova analyzers package.

A modular collection of "analyzers" — components that take a local
dump file on disk plus context, and produce a structured result dict.

Each analyzer is a class with a uniform run() interface so the async
runner (Stage E2.4 / E3+) can dispatch on the analyzer_name without
caring about the implementation.

Current members:

  NoOpAnalyzer   — Stage E2.3. Reads the dump end-to-end and recomputes
                   MD5+SHA1 as an independent third-witness coherence
                   check. No real forensic analysis. Exists to validate
                   the orchestration pipeline before plugging in
                   Volatility 3 in Stage E3.

Future members (planned):

  VolatilityAnalyzer  — Stage E3. Subprocess wrapper around vol3 with
                        preset support (fast / full / custom) and
                        plugin whitelisting.

  MispEnricher       — Stage F. Post-process Volatility findings against
                        a MISP instance for IOC enrichment.

A plugin-style registry mapping analyzer_name -> class will be
introduced in E3 when there is more than one analyzer to dispatch.
For Stage E2.3 the runner imports NoOpAnalyzer directly.
"""

from forensicnova_analyzer.analyzers.noop import NoOpAnalyzer  # noqa: F401
