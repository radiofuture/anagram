"""Fake labs for the synthetic community.

All names, places, proteins, strains, and compounds here are invented.

The need and offer chips use one shared label set. A pair of labs is a planted
match when each lab needs a thing that the other lab offers.
"""

from __future__ import annotations

from dataclasses import dataclass

# Plain chip labels. Vocabulary IDs are not decided yet (see the build plan,
# "Matching"). Each chip gets a placeholder id "tbd:<kind>/<slug>".
STRUCTURES = "experimental protein structures"
CRYO_EM_TIME = "cryo-EM instrument time"
AFFINITY = "binding-affinity prediction"
GPU_PIPELINES = "GPU compute pipelines"
MICROBIOME_MODELS = "in vivo microbiome models"
SMALL_MOLECULES = "small-molecule libraries"
HTS_ASSAYS = "high-throughput screening assays"


@dataclass(frozen=True)
class Institution:
    key: str
    name: str
    kind: str  # "university" or "company"


@dataclass(frozen=True)
class Person:
    slug: str
    name: str
    role: str  # "pi", "scientist", or "manager"
    title: str
    email: str


@dataclass(frozen=True)
class Mail:
    subject: str
    sender: tuple[str, str]
    to: tuple[str, str]
    body: str
    quoted_from: tuple[str, str]
    quoted: str
    date: str


@dataclass(frozen=True)
class Lab:
    slug: str
    name: str
    institution: str
    field: str
    has: str
    needs: str
    topics: tuple[str, ...]
    need_chips: tuple[str, ...]
    offer_chips: tuple[str, ...]
    people: tuple[Person, ...]
    plan: tuple[str, str]  # file stem, markdown body
    deck: tuple[str, tuple[tuple[str, tuple[str, ...]], ...]]  # title, slides
    pi_mail: Mail
    library: tuple[tuple[str, tuple[str, ...], int, str], ...]  # title, authors, year, venue
    notebook: tuple[str, str]
    figure: tuple[str, str, str]  # stem, caption, style ("micrograph" or "bars")
    dataset: tuple[str, tuple[str, ...]]  # stem, columns
    repo: tuple[str, tuple[tuple[str, tuple[tuple[str, str], ...]], ...]]  # name, commits
    large: tuple[str, str]  # file name, header text
    manager_note: tuple[str, str]
    vendor_mail: Mail

    @property
    def id(self) -> str:
        return f"fake-lab-{self.slug}"


INSTITUTIONS: dict[str, Institution] = {
    "northbridge": Institution("northbridge", "Northbridge University", "university"),
    "lakeshore": Institution("lakeshore", "Lakeshore University", "university"),
    "helix": Institution("helix", "Helix Therapeutics", "company"),
}


CHEN = Lab(
    slug="chen",
    name="Chen Lab",
    institution="northbridge",
    field="Structural biology (cryo-EM)",
    has="Membrane protein structures, cryo-EM time",
    needs="Binding-affinity prediction",
    topics=("cryo-electron microscopy", "membrane transport proteins", "structural biology"),
    need_chips=(AFFINITY, SMALL_MOLECULES),
    offer_chips=(STRUCTURES, CRYO_EM_TIME),
    people=(
        Person(
            "mei-lin-chen", "Mei-Lin Chen", "pi", "Associate Professor", "mchen@northbridge.example"
        ),
        Person(
            "tomas-reyes",
            "Tomas Reyes",
            "scientist",
            "Postdoctoral Fellow",
            "treyes@northbridge.example",
        ),
        Person(
            "priya-natarajan",
            "Priya Natarajan",
            "manager",
            "Lab Manager",
            "pnatarajan@northbridge.example",
        ),
    ),
    plan=(
        "2026-q4-project-plan",
        "# Chen Lab: Q4 project plan\n\n"
        "## Where we are\n\n"
        "We have three new experimental cryo-EM structures of the NbT7 sodium-coupled\n"
        "transporter: apo (2.9 A), outward-open with substrate (2.6 A), and an\n"
        "inhibitor-bound state (3.1 A). The ligand pocket in the outward-open map is well resolved.\n\n"
        "## What blocks us\n\n"
        "We cannot rank ligands. We have no binding-affinity prediction in the lab, and\n"
        "docking scores do not agree with our two measured Kd values. We also need a\n"
        "small-molecule library to soak or co-incubate with the protein for more\n"
        "ligand-bound maps.\n\n"
        "## What we can offer\n\n"
        "- Unpublished membrane protein structures (NbT7, MscQ channel) as training data.\n"
        "- About 40 hours per month of free Krios time at the Northbridge cryo-EM core.\n",
    ),
    deck=(
        "NbT7 transporter: three states, one pocket",
        (
            ("Outline", ("NbT7 biology", "Three cryo-EM states", "Open questions")),
            (
                "Three states of NbT7",
                ("Apo 2.9 A", "Outward-open + substrate 2.6 A", "Inhibitor 3.1 A"),
            ),
            (
                "What we need",
                ("Binding-affinity prediction for pocket ligands", "A compound library to screen"),
            ),
        ),
    ),
    pi_mail=Mail(
        subject="Re: NbT7 pocket and your affinity model?",
        sender=("Mei-Lin Chen", "mchen@northbridge.example"),
        to=("Daniel Ortiz", "dortiz@westfield.example"),
        body=(
            "Hi Daniel,\n\n"
            "Thanks for the note. We still have no way to predict affinity for the\n"
            "NbT7 pocket. If you know a group with a model that can use our maps as\n"
            "training data, please tell me. Do not share the maps yet.\n\n"
            "Best,\nMei-Lin\n"
        ),
        quoted_from=("Daniel Ortiz", "dortiz@westfield.example"),
        quoted=(
            "Mei-Lin, I saw the NbT7 poster. Our docking runs on the outward-open\n"
            "model gave poor enrichment. I heard someone at your own university trains\n"
            "affinity models on GPUs. Worth a coffee?\n"
        ),
        date="Tue, 06 Oct 2026 09:14:00 -0400",
    ),
    library=(
        (
            "Conformational cycle of a fictional sodium-coupled transporter",
            ("Reyes, T.", "Chen, M."),
            2025,
            "Journal of Imaginary Structural Biology",
        ),
        (
            "Resolution limits in small membrane protein cryo-EM",
            ("Ito, K.", "Larsen, B."),
            2024,
            "Synthetic Methods in Microscopy",
        ),
        (
            "Ligand pockets that docking scores miss",
            ("Abara, N.",),
            2023,
            "Notional Chemistry Letters",
        ),
    ),
    notebook=(
        "notebook-2026-10",
        "# Notebook: Tomas Reyes, October 2026\n\n"
        "- 10-02: Grid batch G14, 3.5 mg/ml NbT7 in LMNG. Ice thin, good spread.\n"
        "- 10-05: Collected 11,200 movies on Krios 2. Raw stack in raw/.\n"
        "- 10-08: Outward-open map at 2.6 A. Extra density in the pocket.\n"
        "- 10-09: Tried four docking poses. None fit the density. Need real affinity\n"
        "  numbers or a model trained on structures like ours.\n",
    ),
    figure=("nbt7-class2d", "2D class averages of NbT7 in LMNG, grid G14", "micrograph"),
    dataset=(
        "nbt7-grid-screening",
        ("grid_id", "detergent", "conc_mg_ml", "ice_nm", "particles", "resolution_A", "note"),
    ),
    repo=(
        "nbt7-processing",
        (
            (
                "Add README for NbT7 processing",
                (("README.md", "# nbt7-processing\n\nScripts for NbT7 cryo-EM processing.\n"),),
            ),
            (
                "Add particle filter script",
                (
                    (
                        "filter_particles.py",
                        "# Filter particles by CTF fit and ice thickness.\nMAX_CTF_A = 4.0\nMAX_ICE_NM = 60\n",
                    ),
                ),
            ),
            (
                "Tighten ice limit after G14",
                (
                    (
                        "filter_particles.py",
                        "# Filter particles by CTF fit and ice thickness.\nMAX_CTF_A = 4.0\nMAX_ICE_NM = 45\n",
                    ),
                ),
            ),
        ),
    ),
    large=(
        "G14_movies_stack.mrcs",
        "MRC-like movie stack, NbT7 grid G14, Krios 2, synthetic bytes",
    ),
    manager_note=(
        "freezer-and-booking-log",
        "Chen Lab: freezer and microscope booking log\n\n"
        "-80 freezer B, rack 3: NbT7 preps P31-P36, MscQ preps M08-M10.\n"
        "Krios 2 bookings: 10-05 (Tomas), 10-19 (open), 10-26 (open).\n"
        "Unused Krios hours this month: about 40. Core asks us to share or release them.\n",
    ),
    vendor_mail=Mail(
        subject="Re: Grid order 4471 delayed",
        sender=("Priya Natarajan", "pnatarajan@northbridge.example"),
        to=("Order Desk", "orders@gridsupply.example"),
        body="Hello,\n\nPlease ship the 200 mesh grids first. The gold grids can wait.\n\nPriya\n",
        quoted_from=("Order Desk", "orders@gridsupply.example"),
        quoted="Your order 4471 (gold and 200 mesh copper grids) is delayed by two weeks.\n",
        date="Thu, 01 Oct 2026 15:02:00 -0400",
    ),
)

OKAFOR = Lab(
    slug="okafor",
    name="Okafor Lab",
    institution="northbridge",
    field="Computational chemistry, ML",
    has="Affinity models, GPU pipelines",
    needs="Experimental structures for training",
    topics=("binding affinity prediction", "machine learning for chemistry", "molecular docking"),
    need_chips=(STRUCTURES, HTS_ASSAYS),
    offer_chips=(AFFINITY, GPU_PIPELINES),
    people=(
        Person(
            "chidi-okafor",
            "Chidi Okafor",
            "pi",
            "Assistant Professor",
            "cokafor@northbridge.example",
        ),
        Person(
            "hanna-lindqvist",
            "Hanna Lindqvist",
            "scientist",
            "Postdoctoral Fellow",
            "hlindqvist@northbridge.example",
        ),
        Person(
            "marcus-bell",
            "Marcus Bell",
            "manager",
            "Research Engineer and Lab Manager",
            "mbell@northbridge.example",
        ),
    ),
    plan=(
        "okabind-v4-plan",
        "# OkaBind v4 plan\n\n"
        "## Status\n\n"
        "OkaBind v3 predicts binding affinity with RMSE 1.1 pKd on our held-out set.\n"
        "We offer binding-affinity prediction for any pocket, free for academic partners.\n"
        "It runs on our 16-GPU pipeline in under a minute per 10,000 ligands.\n\n"
        "## Gap\n\n"
        "v3 fails on membrane proteins. We have almost no experimental structures of\n"
        "transporters or channels for training. We need experimental structures with\n"
        "ligands, and screening assay data to check predictions.\n\n"
        "## Offer\n\n"
        "- Binding-affinity prediction for any pocket, free for academic partners.\n"
        "- Time on the GPU pipeline.\n",
    ),
    deck=(
        "OkaBind: fast affinity prediction",
        (
            ("OkaBind v3", ("Graph model on pocket and ligand", "RMSE 1.1 pKd", "16-GPU pipeline")),
            ("Where it fails", ("Membrane proteins", "Few experimental structures in training")),
            ("Asks", ("Experimental structures for training", "Assay data for validation")),
        ),
    ),
    pi_mail=Mail(
        subject="Re: Spin-out timeline",
        sender=("Chidi Okafor", "cokafor@northbridge.example"),
        to=("Ruth Keller", "rkeller@northbridge-ventures.example"),
        body=(
            "Ruth,\n\n"
            "Agreed. We keep OkaBind v4 inside the lab until the spin-out terms are\n"
            "set. I still want an academic structure partner for membrane proteins.\n\n"
            "Chidi\n"
        ),
        quoted_from=("Ruth Keller", "rkeller@northbridge-ventures.example"),
        quoted=(
            "Chidi, the board likes the affinity work. Two pharma screening groups\n"
            "already sell similar predictions, so expect them to see you as a\n"
            "competitor. Keep the v4 benchmarks private for now.\n"
        ),
        date="Mon, 05 Oct 2026 11:40:00 -0400",
    ),
    library=(
        (
            "Graph networks for pocket-ligand affinity",
            ("Okafor, C.", "Lindqvist, H."),
            2025,
            "Imaginary Machine Learning Review",
        ),
        (
            "Why affinity models fail on membrane proteins",
            ("Sato, Y.",),
            2024,
            "Notional Computational Chemistry",
        ),
        (
            "Benchmark leakage in docking data sets",
            ("Moreau, P.", "Diaz, L."),
            2023,
            "Fictional Informatics",
        ),
    ),
    notebook=(
        "training-log-2026-10",
        "# Training log: Hanna Lindqvist\n\n"
        "- 10-01: v4 run 17, 3.2M complexes, loss flat after epoch 40.\n"
        "- 10-04: Membrane subset RMSE 2.3 pKd. Soluble subset 1.0.\n"
        "- 10-07: Only 41 membrane protein structures with ligands in training.\n"
        "  We need new experimental structures, ideally cryo-EM of transporters.\n",
    ),
    figure=("okabind-rmse-by-family", "OkaBind v4 RMSE by protein family", "bars"),
    dataset=(
        "okabind-v4-eval",
        ("complex_id", "family", "n_atoms", "pred_pkd", "true_pkd", "abs_err", "note"),
    ),
    repo=(
        "okabind",
        (
            (
                "Initial OkaBind training loop",
                (("README.md", "# okabind\n\nAffinity model training code.\n"),),
            ),
            (
                "Add membrane subset split",
                (("splits.py", "MEMBRANE_FAMILIES = ['transporter', 'channel']\nHOLDOUT = 0.1\n"),),
            ),
            (
                "Weight membrane complexes x3",
                (
                    (
                        "splits.py",
                        "MEMBRANE_FAMILIES = ['transporter', 'channel']\nHOLDOUT = 0.1\nMEMBRANE_WEIGHT = 3\n",
                    ),
                ),
            ),
        ),
    ),
    large=("okabind-v4-run17.ckpt", "Model checkpoint, OkaBind v4 run 17, synthetic bytes"),
    manager_note=(
        "gpu-cluster-notes",
        "Okafor Lab: GPU cluster notes\n\n"
        "Nodes g01-g04, 4 GPUs each. Queue 'okabind' has priority on weekends.\n"
        "Idle GPU hours last month: about 900. We can host external jobs.\n",
    ),
    vendor_mail=Mail(
        subject="Re: GPU node g03 warranty",
        sender=("Marcus Bell", "mbell@northbridge.example"),
        to=("Support", "support@clusterparts.example"),
        body="Hi,\n\nPlease send the replacement board for g03. Ticket below.\n\nMarcus\n",
        quoted_from=("Support", "support@clusterparts.example"),
        quoted="Ticket 99812: node g03 board is covered until March 2027.\n",
        date="Wed, 07 Oct 2026 08:20:00 -0400",
    ),
)

VARGA = Lab(
    slug="varga",
    name="Varga Lab",
    institution="lakeshore",
    field="Microbiome, gnotobiotic mouse models",
    has="In vivo microbiome models",
    needs="Small-molecule libraries",
    topics=("gut microbiome", "gnotobiotic mouse models", "host-microbe interactions"),
    need_chips=(SMALL_MOLECULES,),
    offer_chips=(MICROBIOME_MODELS,),
    people=(
        Person("eszter-varga", "Eszter Varga", "pi", "Professor", "evarga@lakeshore.example"),
        Person(
            "samuel-osei",
            "Samuel Osei",
            "scientist",
            "Postdoctoral Fellow and acting Lab Manager",
            "sosei@lakeshore.example",
        ),
    ),
    plan=(
        "lk12-colonisation-plan",
        "# LK-12 colonisation plan\n\n"
        "## Model\n\n"
        "Germ-free mice colonised with a defined 12-strain community (LK-12) give a\n"
        "stable in vivo microbiome model. We see a repeatable bile-acid shift after\n"
        "Bacteroides sp. LK-12a takes over.\n\n"
        "## Need\n\n"
        "We want to block the LK-12a bile-acid enzyme with small molecules. We have no\n"
        "compound library and no screening robot.\n\n"
        "## Offer\n\n"
        "- Gnotobiotic isolator slots and the LK-12 in vivo microbiome model.\n",
    ),
    deck=(
        "LK-12: a defined gut community in germ-free mice",
        (
            (
                "LK-12 model",
                ("12 defined strains", "Stable for 8 weeks", "Repeatable bile-acid shift"),
            ),
            ("Target", ("LK-12a bile-acid enzyme", "No inhibitors known")),
            ("Need", ("A small-molecule library", "Partners with screening")),
        ),
    ),
    pi_mail=Mail(
        subject="Re: Inhibitor screen for LK-12a?",
        sender=("Eszter Varga", "evarga@lakeshore.example"),
        to=("Ana Kowalczyk", "akowalczyk@lakeshore.example"),
        body=(
            "Ana,\n\n"
            "Thanks. A 2,000-compound academic set is too small. I will look for an\n"
            "industry partner with a full library. We can offer mouse studies.\n\n"
            "Eszter\n"
        ),
        quoted_from=("Ana Kowalczyk", "akowalczyk@lakeshore.example"),
        quoted=(
            "Eszter, our core only has the 2,000-compound teaching set. Pharma groups\n"
            "often want in vivo microbiome data. Maybe trade isolator time for a screen?\n"
        ),
        date="Fri, 02 Oct 2026 16:05:00 -0500",
    ),
    library=(
        (
            "A defined twelve-strain community in germ-free mice",
            ("Varga, E.", "Osei, S."),
            2025,
            "Imaginary Microbiome Journal",
        ),
        (
            "Bile-acid enzymes of fictional Bacteroides",
            ("Novak, J.",),
            2024,
            "Notional Microbiology",
        ),
        (
            "Small-molecule control of gut bacteria",
            ("Haddad, R.", "Lee, S."),
            2023,
            "Synthetic Pharmacology Reports",
        ),
    ),
    notebook=(
        "isolator-log-2026-10",
        "# Isolator log: Samuel Osei\n\n"
        "- 10-01: Isolator 3, 10 germ-free mice colonised with LK-12.\n"
        "- 10-06: Day 5 stool qPCR, LK-12a at 38 percent.\n"
        "- 10-09: Bile-acid shift seen again. Need small-molecule inhibitors to test.\n",
    ),
    figure=("lk12-abundance", "Relative abundance of LK-12 strains, day 0 to day 14", "bars"),
    dataset=(
        "lk12-stool-qpcr",
        ("mouse_id", "isolator", "day", "lk12a_pct", "total_16s_log10", "bile_ratio", "note"),
    ),
    repo=(
        "lk12-analysis",
        (
            (
                "Add qPCR import",
                (("README.md", "# lk12-analysis\n\nqPCR and bile-acid analysis.\n"),),
            ),
            ("Add abundance plot", (("abundance.py", "STRAINS = 12\nREFERENCE = 'LK-12a'\n"),)),
            (
                "Normalise to 16S copies",
                (("abundance.py", "STRAINS = 12\nREFERENCE = 'LK-12a'\nNORMALISE = '16S'\n"),),
            ),
        ),
    ),
    large=(
        "isolator3_metagenome_reads.fastq.bin",
        "Packed metagenome reads, isolator 3, synthetic bytes",
    ),
    manager_note=(
        "isolator-schedule",
        "Varga Lab: isolator schedule\n\n"
        "Isolators 1-4 in room B112. Isolator 4 is free from November.\n"
        "We can host external mouse studies in isolator 4.\n",
    ),
    vendor_mail=Mail(
        subject="Re: Germ-free breeder pairs",
        sender=("Samuel Osei", "sosei@lakeshore.example"),
        to=("Colony Desk", "colony@mousefacility.example"),
        body="Hello,\n\nPlease confirm the date for the four breeder pairs.\n\nSamuel\n",
        quoted_from=("Colony Desk", "colony@mousefacility.example"),
        quoted="Four germ-free breeder pairs are ready on 20 October.\n",
        date="Thu, 08 Oct 2026 10:11:00 -0500",
    ),
)

HELIX = Lab(
    slug="helix",
    name="Helix Discovery Team",
    institution="helix",
    field="High-throughput screening",
    has="Compound libraries, assays",
    needs="In vivo microbiome models; structures; affinity prediction",
    topics=("high-throughput screening", "drug discovery", "assay development"),
    need_chips=(MICROBIOME_MODELS, STRUCTURES, AFFINITY),
    offer_chips=(SMALL_MOLECULES, HTS_ASSAYS),
    people=(
        Person(
            "rachel-dumont", "Rachel Dumont", "pi", "Head of Discovery", "rdumont@helix-tx.example"
        ),
        Person(
            "kenji-watanabe",
            "Kenji Watanabe",
            "scientist",
            "Senior Scientist",
            "kwatanabe@helix-tx.example",
        ),
        Person(
            "laura-petrovic",
            "Laura Petrovic",
            "manager",
            "Lab Operations Manager",
            "lpetrovic@helix-tx.example",
        ),
    ),
    plan=(
        "discovery-priorities-2027",
        "# Helix Discovery: 2027 priorities\n\n"
        "## Assets\n\n"
        "- HX small-molecule libraries: 480,000 diversity compounds and 12,000 fragments.\n"
        "- 1536-well screening assays, about 200,000 wells per day.\n\n"
        "## Gaps\n\n"
        "- Gut programme: no in vivo microbiome model to test the HX-4410 series.\n"
        "- Transporter programme: no experimental structures of the target.\n"
        "- We need binding-affinity prediction for hit ranking, but not from groups\n"
        "  that compete with us (see legal note on the Northbridge spin-out)\n",
    ),
    deck=(
        "Discovery portfolio review",
        (
            ("Library", ("480k diversity set", "12k fragments", "HX-4410 series")),
            ("Screens", ("1536-well", "200k wells per day")),
            ("Gaps", ("In vivo microbiome model", "Transporter structures", "Affinity prediction")),
        ),
    ),
    pi_mail=Mail(
        subject="Re: Northbridge spin-out",
        sender=("Rachel Dumont", "rdumont@helix-tx.example"),
        to=("Legal", "legal@helix-tx.example"),
        body=(
            "Understood. Add the Okafor Lab to our block list for any matching\n"
            "service. We still want academic structure and microbiome partners.\n\n"
            "Rachel\n"
        ),
        quoted_from=("Legal", "legal@helix-tx.example"),
        quoted=(
            "The Okafor spin-out plans to sell affinity predictions to our customers.\n"
            "Treat that lab as a competitor. Do not start talks with it.\n"
        ),
        date="Wed, 07 Oct 2026 13:30:00 +0100",
    ),
    library=(
        (
            "Hit triage in very large screening libraries",
            ("Watanabe, K.", "Dumont, R."),
            2025,
            "Imaginary Drug Discovery Today",
        ),
        ("Gut bacterial enzymes as drug targets", ("Ferreira, A.",), 2024, "Notional Pharmacology"),
        (
            "Fragment soaking with cryo-EM",
            ("Kim, H.", "Ruiz, M."),
            2023,
            "Synthetic Structural Reports",
        ),
    ),
    notebook=(
        "hx4410-screen-notes",
        "# HX-4410 screen notes: Kenji Watanabe\n\n"
        "- 10-02: Primary screen of 480k against bacterial bile-acid enzyme panel.\n"
        "- 10-06: 312 hits above 50 percent inhibition. HX-4410 series is strongest.\n"
        "- 10-08: No in vivo model to check gut exposure. Ranking hits needs affinity\n"
        "  prediction or a structure of the target.\n",
    ),
    figure=("hx4410-plate-heatmap", "Plate 0412 inhibition, HX-4410 series", "micrograph"),
    dataset=(
        "hx-primary-screen",
        ("compound_id", "plate", "well", "inhibition_pct", "z_score", "series", "note"),
    ),
    repo=(
        "hts-pipeline",
        (
            (
                "Add plate reader import",
                (("README.md", "# hts-pipeline\n\nPlate import and hit calling.\n"),),
            ),
            ("Add hit calling", (("hits.py", "THRESHOLD_PCT = 50\nZ_MIN = 3.0\n"),)),
            (
                "Flag PAINS substructures",
                (("hits.py", "THRESHOLD_PCT = 50\nZ_MIN = 3.0\nFLAG_PAINS = True\n"),),
            ),
        ),
    ),
    large=("plate0412_raw_reads.bin", "Raw plate reader export, plate 0412, synthetic bytes"),
    manager_note=(
        "compound-store-inventory",
        "Helix Discovery: compound store inventory\n\n"
        "Store A: 480,000 diversity compounds, 10 mM in DMSO.\n"
        "Store B: 12,000 fragments, 100 mM.\n"
        "External plating allowed with an MTA. Contact operations.\n",
    ),
    vendor_mail=Mail(
        subject="Re: Acoustic dispenser service",
        sender=("Laura Petrovic", "lpetrovic@helix-tx.example"),
        to=("Field Service", "service@labrobotics.example"),
        body="Hello,\n\nThe 14 October slot works for us.\n\nLaura\n",
        quoted_from=("Field Service", "service@labrobotics.example"),
        quoted="We can service the acoustic dispenser on 14 October, 08:00 to 12:00.\n",
        date="Tue, 06 Oct 2026 07:45:00 +0100",
    ),
)

LABS: tuple[Lab, ...] = (CHEN, OKAFOR, VARGA, HELIX)
LABS_BY_SLUG: dict[str, Lab] = {lab.slug: lab for lab in LABS}

# Planted mutual matches before blocks (unordered pairs of lab slugs).
PLANTED_MATCHES: tuple[tuple[str, str], ...] = (
    ("chen", "okafor"),
    ("varga", "helix"),
    ("chen", "helix"),
    ("okafor", "helix"),
)

# (blocker lab slug, blocked target kind, blocked target lab slug, reason)
BLOCKS: tuple[tuple[str, str, str, str], ...] = (
    ("helix", "lab", "okafor", "Helix sees the Okafor spin-out as a competitor"),
)


def pair(a: str, b: str) -> tuple[str, str]:
    """Return an unordered pair in a fixed order."""
    return (a, b) if a <= b else (b, a)


def chip_matches(labs: tuple[Lab, ...] = LABS) -> set[tuple[str, str]]:
    """Return pairs where each lab needs a chip that the other lab offers."""
    out = set()
    for i, a in enumerate(labs):
        for b in labs[i + 1 :]:
            a_gets = set(a.need_chips) & set(b.offer_chips)
            b_gets = set(b.need_chips) & set(a.offer_chips)
            if a_gets and b_gets:
                out.add(pair(a.slug, b.slug))
    return out
