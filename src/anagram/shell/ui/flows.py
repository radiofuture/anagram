"""The "What leaves this computer" list.

One entry for each flow of data across a trust boundary
(spec/threat-model.md). The UI
shows this list as it is. A lab manager can give it to an ethics board or a
data office. Keep the words plain. Add an entry when a new flow is added.
"""

from __future__ import annotations

FLOWS: tuple[dict, ...] = (
    {
        "id": "files-stay",
        "to": "Nobody",
        "what": "Your files, the text in them, and the chips that Anagram makes from them.",
        "when": "Never. Anagram reads your files on this computer.",
        "can_see": "Only you.",
    },
    {
        "id": "timestamps",
        "to": "The community server",
        "what": "A fingerprint of each finding and of each new batch of source files. "
        "A fingerprint does not show the content.",
        "when": "When you make the proof of a finding, and automatically for your sources.",
        "can_see": "That someone added an entry, and when. Not who, not what.",
    },
    {
        "id": "identity",
        "to": "The community server",
        "what": "Your name, institution, lab, and the public keys of your devices. "
        "Also your email address, and your ORCID iD if you link one.",
        "when": "When you join, when you change your details, and when you link an ORCID iD.",
        "can_see": "Members see your name, institution, and lab. The keys are in a public log. "
        "Only the community server keeps your email address and ORCID iD. A member who "
        "knows one of them can find you if you are findable.",
    },
    {
        "id": "locked-copies",
        "to": "The community server",
        "what": "Locked copies of the findings and files that you share.",
        "when": "When you share a finding.",
        "can_see": "The community server stores locked copies. It cannot open them. "
        "It sees file sizes and who received a copy.",
    },
    {
        "id": "ring-members",
        "to": "People you share with",
        "what": "The finding, its files, and its proof.",
        "when": "When you share a finding with a ring.",
        "can_see": "People you share with keep what they already saw. Removing them stops "
        "access to new versions only.",
    },
    {
        "id": "public",
        "to": "Everyone",
        "what": "A finding that you share with the Public ring.",
        "when": "Only when you share with Public. This cannot be taken back.",
        "can_see": "Anyone.",
    },
    {
        "id": "recovery-backup",
        "to": "The community server",
        "what": "A locked backup of your keys. Only your recovery kit opens it.",
        "when": "When you join and when you make a new recovery kit.",
        "can_see": "Nobody without your recovery kit.",
    },
    {
        "id": "guardians",
        "to": "Your recovery guardians",
        "what": "One locked piece of your key backup each.",
        "when": "Only if you choose guardians.",
        "can_see": "One piece is not enough. The number of guardians that you choose "
        "must act together.",
    },
    {
        "id": "matching",
        "to": "The matching enclave of the network, through your community server",
        "what": "The matching lines that you approve (what you offer and what you want), "
        "your consent, and a member credential, sealed to the enclave key.",
        "when": "Once a day while matching is on. While it is off, a sealed filler of the "
        "same size, so the community server cannot tell the difference.",
        "can_see": "The community server passes on sealed messages of a fixed size and "
        "cannot open them. In this version the enclave runs in a simulated mode, so the "
        "operator of the enclave can read your lines. It never gets your files. Even with "
        "a real enclave, three risks remain: someone with physical access to the cloud's "
        "machine, a break of the keys of the chip maker or of the cloud that checks the machine, and side channels that leak which "
        "memory the enclave uses.",
    },
    {
        "id": "match-drafting",
        "to": "Nobody",
        "what": "The draft of your matching lines. Anagram drafts them on this computer "
        "with a local model, or you type them.",
        "when": "When you click 'Draft' on the Network matching screen.",
        "can_see": "Only you, until you approve the lines.",
    },
    {
        "id": "match-peer",
        "to": "A person you match with",
        "what": "Your reveal card (name, institution, lab, email address, and your ORCID iD "
        "if you add it), and the record of your community server.",
        "when": "Only when you and that person both say yes to the same proposal.",
        "can_see": "That person. If one of you does not say yes, neither side learns who "
        "the other person was.",
    },
    {
        "id": "orcid",
        "to": "ORCID",
        "what": "Your ORCID sign-in. If you add 'My ORCID works', a request for your "
        "public ORCID record.",
        "when": "Only if you link an ORCID iD or join with one, and when Anagram reads "
        "your public works.",
        "can_see": "ORCID sees that you signed in to this community.",
    },
    {
        "id": "institution-search",
        "to": "ROR (the Research Organization Registry)",
        "what": "The words that you type in the institution search.",
        "when": "Only while you search for an institution.",
        "can_see": "ROR sees the search words. Nothing else.",
    },
    {
        "id": "model-provider",
        "to": "A model provider that you select (off by default)",
        "what": "Excerpts of your items, your questions, and the passages of an answer. "
        "Never text that other people wrote, and never your keys.",
        "when": "Only if you select a model that is not on this computer, and only for "
        "the sources where you permit it. Lab text only if your lab permits that model.",
        "can_see": "The provider that you select. A local model keeps all text on this computer.",
    },
    # Connected sources.
    {
        "id": "connected-sources",
        "to": "Google, Notion, or Zotero (only for a source that you connect)",
        "what": "Requests to read the folders, mail, and pages that you selected. "
        "They see which items Anagram reads and when.",
        "when": "When you connect this source, and continuously while it is connected.",
        "can_see": "The service. Not the community server, not your lab.",
    },
    {
        "id": "source-sign-in",
        "to": "Nobody",
        "what": "The sign-in for a connected service. It stays in the keychain of this computer.",
        "when": "Never. When you remove the last source of an account, Anagram also ends "
        "the sign-in at the service.",
        "can_see": "Only this computer.",
    },
    # The update check.
    {
        "id": "update-check",
        "to": "The Anagram release server (only in a release build)",
        "what": "One request for a signed file that names the newest version. "
        "No data about you or your work.",
        "when": "One time each day while the app runs. A build with no release server "
        "sends nothing.",
        "can_see": "Your IP address and the time of the request.",
    },
    # Understanding and assistant access.
    {
        "id": "assistant",
        "to": "Your AI assistant and the company that runs it (only an assistant that you add)",
        "what": "Search results, passages, and the text of items that the assistant asks "
        "for. Never text that other people wrote, and never an item that you marked "
        "private. A proposal of the assistant (for example lines for matching) stays "
        "on this computer until you approve it.",
        "when": "Only after you add the assistant in Account, Assistant access, and only "
        "from the places that you open to it, until its end date. Lab places only if your "
        "lab permits assistants (and assistants of a company, for an assistant that does "
        "not run on this computer only). At most 200,000 characters each day.",
        "can_see": "The assistant and its company. They keep what they read. Anagram "
        "records each read. Stop the access of the assistant to stop new reads.",
    },
)
