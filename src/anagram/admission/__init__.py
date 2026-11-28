"""Admission and growth (layer L4): how a community
grows. Node invites, lab invites, reader invites, the vouch record ("who
invited whom"), and the admission policy of the node (today: invite only). See spec/admission.md.

- `formats`: the invite formats (locked).
- `model`: one model for each way in (endorsement, claim, policy).
- `check`: the checks that the lab roster (L3) uses (port `AdmissionCheck`).
- `app/`: join by invite in the app (`join`).
- `node/`: `AdmissionService` (`service`, port `RegistrationGate`), reader
  invites (`reader`), the routes of invites and claims (`routes`), and the
  admission tables with their lock contract (`store`).
"""

from __future__ import annotations
