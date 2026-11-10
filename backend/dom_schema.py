"""Versioned, bounded structural snapshots. No page text, input values or URL queries."""
from __future__ import annotations

from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    field_validator,
    model_validator,
)

DOM_SCHEMA = "dom-v1"
Count = Annotated[int, Field(strict=True, ge=0, le=5000)]


def clean_origin(value: str) -> str:
    p = urlsplit(value)
    if (p.scheme not in ("http", "https") or not p.hostname or p.username or p.password
            or p.query or p.fragment or p.path not in ("", "/") or len(value) > 256):
        raise ValueError("Expected a query-free HTTP(S) origin")
    _ = p.port
    return f"{p.scheme}://{p.netloc.lower()}"


class Bounded(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OriginCount(Bounded):
    origin: str = Field(max_length=256)
    count: Count
    _origin = field_validator("origin")(clean_origin)


class CredentialForm(Bounded):
    action_origin: str | None = Field(default=None, max_length=256)
    action_scheme: Literal["http", "https", "other", "invalid"]
    method: Literal["get", "post", "dialog"]
    password_count: Count
    hidden_password_count: Count
    has_action: StrictBool
    action_same_page: StrictBool

    @field_validator("action_origin")
    @classmethod
    def origin(cls, value):
        return clean_origin(value) if value else value

    @model_validator(mode="after")
    def consistent(self):
        if self.hidden_password_count > self.password_count:
            raise ValueError("Hidden password count exceeds total")
        if self.action_scheme in ("http", "https"):
            if not self.action_origin or not self.action_origin.startswith(self.action_scheme + "://"):
                raise ValueError("Action scheme/origin mismatch")
        elif self.action_origin:
            raise ValueError("Non-HTTP action must not contain an origin")
        return self


class Refresh(Bounded):
    origin: str = Field(max_length=256)
    delay_seconds: Annotated[float, Field(strict=True, ge=0, le=86400, allow_inf_nan=False)]
    _origin = field_validator("origin")(clean_origin)


class DomFeatures(Bounded):
    form_count: Count
    password_count: Count
    orphan_password_count: Count
    hidden_password_count: Count
    credential_forms: list[CredentialForm] = Field(max_length=32)
    link_count: Count
    placeholder_link_count: Count
    unusual_link_count: Count
    link_origins: list[OriginCount] = Field(max_length=32)
    iframe_count: Count
    inaccessible_frame_count: Count
    iframe_origins: list[OriginCount] = Field(max_length=32)
    accessible_frame_form_count: Count
    script_count: Count
    resource_count: Count
    resource_origins: list[OriginCount] = Field(max_length=32)
    title_present: StrictBool
    title_length: Annotated[int, Field(strict=True, ge=0, le=10000)]
    title_has_host: StrictBool
    meta_refresh: list[Refresh] = Field(max_length=8)
    truncated: StrictBool

    @model_validator(mode="after")
    def consistent(self):
        if self.hidden_password_count > self.password_count or self.orphan_password_count > self.password_count:
            raise ValueError("Password counters inconsistent")
        if self.placeholder_link_count > self.link_count or self.unusual_link_count > self.link_count:
            raise ValueError("Link counters inconsistent")
        if self.inaccessible_frame_count > self.iframe_count:
            raise ValueError("Frame counters inconsistent")
        for rows, total in ((self.link_origins, self.link_count), (self.iframe_origins, self.iframe_count),
                            (self.resource_origins, self.resource_count)):
            if sum(row.count for row in rows) > total or len({row.origin for row in rows}) != len(rows):
                raise ValueError("Origin aggregates inconsistent")
        if sum(f.password_count for f in self.credential_forms) > self.password_count:
            raise ValueError("Form password count exceeds total")
        return self


class DomSnapshot(Bounded):
    schema_version: str = Field(max_length=32)
    state: Literal["inspected", "partial", "unavailable", "not_requested", "failed", "incompatible"]
    page_origin: str | None = Field(default=None, max_length=256)
    features: DomFeatures | None = None
    reason: Literal["permission", "unsupported", "timeout", "navigation_changed", "extraction", "schema", "bounds"] | None = None

    @field_validator("page_origin")
    @classmethod
    def origin(cls, value):
        return clean_origin(value) if value else value

    @model_validator(mode="after")
    def needs_features(self):
        if self.state in ("inspected", "partial") and (not self.features or not self.page_origin):
            raise ValueError("Inspected snapshots require features and page origin")
        if self.state not in ("inspected", "partial") and self.features is not None:
            raise ValueError("Unavailable snapshots cannot contain successful feature data")
        return self
