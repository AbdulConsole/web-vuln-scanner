"""initial schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-09-13

NOTE ON PROVENANCE: this migration was hand-authored to mirror the ORM
models in app/models exactly, rather than produced by
`alembic revision --autogenerate` against a live database -- this
authoring environment has no database or network access to run that
command. Before relying on this in a real deployment, run
`alembic check` (or `--autogenerate` against an empty database and diff
the result) locally to confirm it matches the models with zero drift.
"""
from __future__ import annotations

import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "targets",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("base_url", sa.String(2048), nullable=False),
        sa.Column("allowed_domains", sa.JSON(), nullable=False),
        sa.Column("scan_config", sa.JSON(), nullable=False),
        sa.Column("auth_config", sa.JSON(), nullable=True),
    )

    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "target_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("targets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("urls_crawled", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("requests_sent", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("config_snapshot", sa.JSON(), nullable=False),
        sa.Column("error", sa.String(2000), nullable=True),
    )
    op.create_index("ix_scans_target_id", "scans", ["target_id"])
    op.create_index("ix_scans_status", "scans", ["status"])

    op.create_table(
        "urls",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("content_type", sa.String(255), nullable=True),
        sa.Column("response_time_ms", sa.Float(), nullable=True),
        sa.Column("depth", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source_url", sa.String(2048), nullable=True),
    )
    op.create_index("ix_urls_scan_id", "urls", ["scan_id"])
    op.create_index("ix_urls_url", "urls", ["url"])

    op.create_table(
        "forms",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "url_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("urls.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("action", sa.String(2048), nullable=False),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("inputs", sa.JSON(), nullable=False),
    )
    op.create_index("ix_forms_url_id", "forms", ["url_id"])

    op.create_table(
        "parameters",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "url_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("urls.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("source", sa.String(10), nullable=False),
        sa.Column("sample_value", sa.String(1000), nullable=True),
    )
    op.create_index("ix_parameters_url_id", "parameters", ["url_id"])

    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("parameter", sa.String(255), nullable=True),
        sa.Column("vulnerability_type", sa.String(100), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.String(4000), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("exploitability", sa.Float(), nullable=False),
        sa.Column("impact", sa.Float(), nullable=False),
        sa.Column("exposure", sa.String(20), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("priority_rank", sa.Integer(), nullable=True),
        sa.Column("remediation", sa.String(4000), nullable=True),
        sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("detector_name", sa.String(100), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_finding_confidence_range",
        ),
        sa.CheckConstraint(
            "exploitability >= 0.0 AND exploitability <= 1.0",
            name="ck_finding_exploitability_range",
        ),
        sa.CheckConstraint(
            "impact >= 0.0 AND impact <= 1.0", name="ck_finding_impact_range"
        ),
        sa.CheckConstraint(
            "risk_score IS NULL OR (risk_score >= 0.0 AND risk_score <= 100.0)",
            name="ck_finding_risk_score_range",
        ),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index(
        "ix_findings_vulnerability_type", "findings", ["vulnerability_type"]
    )
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_risk_score", "findings", ["risk_score"])
    op.create_index("ix_findings_priority_rank", "findings", ["priority_rank"])
    op.create_index("ix_findings_status", "findings", ["status"])

    op.create_table(
        "evidence",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "finding_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(100), nullable=False),
        sa.Column("sanitized_payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_evidence_finding_id", "evidence", ["finding_id"])

    op.create_table(
        "risk_score_breakdowns",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "finding_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("factor_name", sa.String(100), nullable=False),
        sa.Column("raw_value", sa.Float(), nullable=False),
        sa.Column("weight", sa.Float(), nullable=False),
        sa.Column("contribution", sa.Float(), nullable=False),
    )
    op.create_index(
        "ix_risk_score_breakdowns_finding_id", "risk_score_breakdowns", ["finding_id"]
    )

    op.create_table(
        "reports",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column(
            "scan_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("format", sa.String(10), nullable=False),
        sa.Column(
            "generated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("storage_path", sa.String(2048), nullable=False),
    )
    op.create_index("ix_reports_scan_id", "reports", ["scan_id"])

    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)


def downgrade() -> None:
    op.drop_table("users")
    op.drop_table("reports")
    op.drop_table("risk_score_breakdowns")
    op.drop_table("evidence")
    op.drop_table("findings")
    op.drop_table("parameters")
    op.drop_table("forms")
    op.drop_table("urls")
    op.drop_table("scans")
    op.drop_table("targets")
