"""The parameters of each tier 3 detector, as a spec writes them.

A spec with ``evaluator: model`` names a detector and its parameters in a
``model`` block. The block is validated here, at load, so a typo in a shipped
spec fails the catalog load and never reaches a sweep. The models are pure
pydantic: :mod:`soc_ai.hunting.spec` imports them, and the spec module must
load without the grid helpers the detectors use.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field, model_validator

__all__ = [
    "DETECTOR_IDS",
    "CrossPlaneSilence",
    "CrossPlaneSilenceParams",
    "LogonChain",
    "LogonChainParams",
    "ModelTest",
]


class CrossPlaneSilenceParams(BaseModel):
    """What detector 1 reads, and the bars a silence must pass.

    The recent window is compared hour by hour with the same hours of the
    week in earlier weeks. That is the hour-of-week baseline of the tier 2
    rate test, read over the hours the score needs and no others.
    """

    model_config = {"extra": "forbid"}

    # The recent read, in complete hours.
    window_hours: int = Field(default=6, ge=2, le=48)
    # How many earlier weeks give the expected count of each hour.
    baseline_weeks: int = Field(default=4, ge=1, le=8)
    # A plane with less history than this is learning.
    min_history_days: int = Field(default=7, ge=1, le=56)
    # How many hours in a row the plane must stay silent.
    min_silent_hours: int = Field(default=2, ge=1, le=24)
    # An hour is silent at or under this share of its expected count.
    floor_share: float = Field(default=0.1, ge=0.0, lt=1.0)
    # An hour with a smaller expected count cannot fall silent. A plane that
    # always dips at the weekend expects nothing then.
    min_expected: float = Field(default=5.0, gt=0.0)
    # The silent hour also sits this many dispersions under its expected count.
    threshold: float = Field(default=3.0, gt=0.0)
    # The live plane holds this share of its expected count in every silent hour.
    live_share: float = Field(default=0.5, gt=0.0, le=1.0)
    # One plane silent on more than this share of the machines that ship it,
    # and on at least grid_min_machines of them, is a grid condition.
    grid_share: float = Field(default=0.5, gt=0.0, le=1.0)
    grid_min_machines: int = Field(default=3, ge=2, le=1000)

    @model_validator(mode="after")
    def _the_bars_can_be_met(self) -> CrossPlaneSilenceParams:
        if self.min_history_days > self.baseline_weeks * 7:
            raise ValueError(
                f"min_history_days {self.min_history_days} is longer than the baseline of "
                f"{self.baseline_weeks} weeks, so no plane could ever be measured"
            )
        if self.min_silent_hours > self.window_hours:
            raise ValueError(
                f"min_silent_hours {self.min_silent_hours} is longer than the window of "
                f"{self.window_hours} hours, so the detector could never fire"
            )
        return self


class LogonChainParams(BaseModel):
    """What detector 2 reads, and the bars a chain must pass."""

    model_config = {"extra": "forbid"}

    # The recent read: the sessions and the attempts, in hours.
    window_hours: int = Field(default=2, ge=1, le=48)
    # The edge set is learned over this many days before the recent window.
    learning_days: int = Field(default=30, ge=1, le=90)
    # An edge set younger than this is learning.
    warm_days: int = Field(default=14, ge=1, le=90)
    # How soon after the session the attempt must come.
    chain_minutes: int = Field(default=15, ge=1, le=240)
    # The most logon documents the recent read keeps. A fuller window is
    # stated in a note, never scored as a whole one.
    max_events: int = Field(default=5000, ge=100, le=10000)

    @model_validator(mode="after")
    def _warmth_fits_the_learning_window(self) -> LogonChainParams:
        if self.warm_days > self.learning_days:
            raise ValueError(
                f"warm_days {self.warm_days} is longer than the learning window of "
                f"{self.learning_days} days, so the edge set could never be warm"
            )
        return self


class CrossPlaneSilence(BaseModel):
    """The ``model`` block of a cross-plane silence spec."""

    model_config = {"extra": "forbid"}

    detector: Literal["cross_plane_silence"]
    params: CrossPlaneSilenceParams = Field(default_factory=CrossPlaneSilenceParams)


class LogonChain(BaseModel):
    """The ``model`` block of a logon chain spec."""

    model_config = {"extra": "forbid"}

    detector: Literal["logon_chain"]
    params: LogonChainParams = Field(default_factory=LogonChainParams)


# One block per detector, chosen by the ``detector`` key. An unknown detector
# id fails at load and names the known ones.
ModelTest = Annotated[CrossPlaneSilence | LogonChain, Field(discriminator="detector")]

DETECTOR_IDS: tuple[str, ...] = ("cross_plane_silence", "logon_chain")
