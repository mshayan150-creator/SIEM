"""Strict ECS subset. Nested ECS objects are required; arbitrary fields are rejected."""
import re
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

ShortText = Annotated[str, Field(min_length=1, max_length=256)]


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", populate_by_name=False)


class Event(StrictModel):
    dataset: ShortText
    outcome: Literal["success", "failure", "unknown"]
    action: ShortText
    code: ShortText | None = None
    id: ShortText | None = None


class Source(StrictModel):
    ip: IPv4Address | IPv6Address

    @field_validator("ip", mode="plain")
    @classmethod
    def parse_ip(cls, value: object) -> IPv4Address | IPv6Address:
        if not isinstance(value, str) or "%" in value:
            raise ValueError("source.ip must be an IPv4/IPv6 string without a zone ID")
        address = ip_address(value)
        if isinstance(address, IPv6Address) and address.ipv4_mapped:
            return address.ipv4_mapped
        return address


class User(StrictModel):
    name: ShortText


class Host(StrictModel):
    name: ShortText


class Telemetry(StrictModel):
    host: Host | None = None
    timestamp: datetime = Field(alias="@timestamp")
    event: Event
    source: Source
    user: User
    message: Annotated[str, Field(min_length=1, max_length=8192)]

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, value: object) -> datetime:
        if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", value
        ):
            raise ValueError("@timestamp must be an RFC3339 string")
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError("@timestamp must include a timezone")
        return parsed.astimezone(UTC)


class Batch(StrictModel):
    events: Annotated[list[Telemetry], Field(min_length=1, max_length=500)]


class Threat(StrictModel):
    id: str
    tactic: str
    technique: str


class Incident(StrictModel):
    id: str
    timestamp: str = Field(alias="@timestamp")
    severity: Literal["critical", "high"]
    rule_id: str
    title: str
    threat: Threat
    affected_asset: dict[str, str]
    evidence: list[Telemetry]
    evidence_count: int
    description: str


class Accepted(StrictModel):
    accepted: int
    duplicate: bool
