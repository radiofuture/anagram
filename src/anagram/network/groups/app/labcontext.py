"""The labs of the person on this device, in one object.

`AppLabs` gives the port `LabContext` of the app (readable labs,
the lab list, the lab policy) and the parts that the lab space bridge
(`labspace`) uses. The `Client` composition root makes one
(`Client.lab_context`)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from anagram.identity.api import Device
    from anagram.network.groups.app.labkeys import LabKeys
    from anagram.network.groups.app.labrecords import LabPolicy, LabSpace
    from anagram.network.groups.app.labroster import LabRoster
    from anagram.network.groups.app.labs import Labs


@dataclass(frozen=True)
class AppLabs:
    device: Device
    roster: LabRoster
    keys: LabKeys
    space: LabSpace
    labs: Labs

    def readable_labs(self) -> list[str]:
        return self.keys.readable_labs()

    def lab_list(self) -> list[dict]:
        return self.labs.lab_list()

    def lab_policy(self, lab_id: str) -> LabPolicy:
        return self.space.lab_policy(lab_id)
