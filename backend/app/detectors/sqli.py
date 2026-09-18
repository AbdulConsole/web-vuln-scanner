"""
SQL Injection detector (Section 10.A).

Uses only safe, non-destructive probing: single-quote error triggering and
boolean-based differential comparison. Deliberately does NOT implement
time-based blind detection (e.g. SLEEP()/WAITFOR) -- that technique works
by making the target do extra work, which conflicts with Section 19's
"remain stable and respectful of target resources" requirement when
applied across every discovered parameter. Stated here as a scope
limitation, not an oversight.
"""
from __future__ import annotations

from app.detectors.base import BaseDetector, DetectionContext, DetectorFinding
from app.detectors.manager import register_detector
from app.detectors.probing import ParamTarget, collect_param_targets
from app.detectors.signatures import SQL_ERROR_SIGNATURES
from app.models.enums import Severity


@register_detector
class SqlInjectionDetector(BaseDetector):
    name = "sql_injection"
    vulnerability_type = "sql_injection"
    description = (
        "Tests request parameters for SQL injection using safe, "
        "non-destructive error-based and boolean-based probes."
    )
    default_severity = Severity.HIGH

    async def detect(self, context: DetectionContext) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []
        max_targets = self.config.get("max_targets", 100)
        targets = collect_param_targets(context, max_targets=max_targets)

        for target in targets:
            finding = await self._test_target(target, context)
            if finding is not None:
                findings.append(finding)

        return findings

    async def _test_target(
        self, target: ParamTarget, context: DetectionContext
    ) -> DetectorFinding | None:
        baseline_value = target.baseline_values.get(target.parameter_name, "1")

        # 1. Error-based probe: a single quote is often enough to break a
        # naively-concatenated SQL string and surface a DB error message.
        quote_response = await target.send(context.engine, baseline_value + "'")
        if quote_response.ok and quote_response.text:
            lowered = quote_response.text.lower()
            for signature in SQL_ERROR_SIGNATURES:
                if signature in lowered:
                    return self._build_confirmed_finding(target, context, signature)

        # 2. Boolean-based differential probe: a TRUE and a FALSE condition
        # should produce identical output from a properly parameterized
        # query, but different output if the condition is evaluated by the
        # database as part of the query logic.
        true_response = await target.send(context.engine, f"{baseline_value}' OR '1'='1")
        false_response = await target.send(context.engine, f"{baseline_value}' AND '1'='2")

        if (
            true_response.ok
            and false_response.ok
            and true_response.text is not None
            and false_response.text is not None
            and true_response.status_code == false_response.status_code
        ):
            true_len = len(true_response.text)
            false_len = len(false_response.text)
            if true_len != false_len:
                relative_diff = abs(true_len - false_len) / max(true_len, false_len, 1)
                if relative_diff > 0.05:
                    return self._build_probable_finding(
                        target, context, true_len, false_len
                    )

        return None

    def _build_confirmed_finding(
        self, target: ParamTarget, context: DetectionContext, signature: str
    ) -> DetectorFinding:
        payload = target.baseline_values.get(target.parameter_name, "1") + "'"
        evidence = self.generate_evidence(
            "sql_error_signature",
            {
                "parameter": target.parameter_name,
                "payload": payload,
                "matched_signature": signature,
            },
        )
        return self.make_finding(
            url=target.url,
            method=target.method,
            parameter=target.parameter_name,
            title=f"SQL Injection in parameter '{target.parameter_name}'",
            description=(
                f"Injecting a single quote into '{target.parameter_name}' "
                f'produced a database error message in the response '
                f'(matched signature: "{signature}"). This strongly suggests '
                f"the parameter is concatenated directly into a SQL query "
                f"without parameterization."
            ),
            confidence=0.9,
            exploitability=0.7,
            impact=0.85,
            exposure=context.default_exposure,
            severity=Severity.HIGH,
            evidence=[evidence],
            remediation=(
                "Use parameterized queries / prepared statements for all "
                "database access; never concatenate user input into SQL "
                "strings. Apply least-privilege database credentials so a "
                "successful injection has minimal blast radius."
            ),
            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
        )

    def _build_probable_finding(
        self, target: ParamTarget, context: DetectionContext, true_len: int, false_len: int
    ) -> DetectorFinding:
        baseline_value = target.baseline_values.get(target.parameter_name, "1")
        evidence = self.generate_evidence(
            "boolean_differential",
            {
                "parameter": target.parameter_name,
                "true_payload": f"{baseline_value}' OR '1'='1",
                "false_payload": f"{baseline_value}' AND '1'='2",
                "true_response_length": true_len,
                "false_response_length": false_len,
            },
        )
        return self.make_finding(
            url=target.url,
            method=target.method,
            parameter=target.parameter_name,
            title=f"Possible boolean-based SQL Injection in parameter '{target.parameter_name}'",
            description=(
                f"Injecting a TRUE and a FALSE SQL condition into "
                f"'{target.parameter_name}' produced responses of noticeably "
                f"different size ({true_len} vs {false_len} bytes), which is "
                f"consistent with boolean-based blind SQL injection. This is "
                f"a probable, not confirmed, finding -- manual verification "
                f"is recommended."
            ),
            confidence=0.5,
            exploitability=0.4,
            impact=0.6,
            exposure=context.default_exposure,
            severity=Severity.MEDIUM,
            evidence=[evidence],
            remediation=(
                "Use parameterized queries / prepared statements for all "
                "database access. Verify manually whether this parameter "
                "genuinely influences a SQL WHERE clause."
            ),
            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
        )
