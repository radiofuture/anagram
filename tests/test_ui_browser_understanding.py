"""Browser test of Home, Ask, Timeline, and Assistant access (R4, review item
W2, step 15b). The Home field opens the Ask screen. With no model the same
field searches: the passages are the answer and one calm line says how to set
up a model. With a fake model the answer streams, each [n] goes to its source
row, and a reload shows the same answer. The timeline shows the weeks, and a
summary arrives live. Assistant access: the person adds an assistant, sees
the setup text, and stops it.

Skipped when Playwright or its Chromium is not installed. Set
ANAGRAM_UI_SHOTS=DIR to save screenshots at 1440 and 390 px, light and dark.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
from uikit import clean, copy, ready, until

sync_api = pytest.importorskip("playwright.sync_api")

from anagram.models.providers.fake import FakeTextModel  # noqa: E402
from anagram.sim.demo import Demo  # noqa: E402

SHOTS = os.environ.get("ANAGRAM_UI_SHOTS")
expect = sync_api.expect


@pytest.fixture(scope="module")
def person(tmp_path_factory):
    root = tmp_path_factory.mktemp("home")
    d = Demo(root / "demo", large_bytes=4096).start()
    p = d.people[0]
    d.autopilot(p)
    with p.service.session(index=True) as (_, idx):
        idx.scan()
    yield p
    d.stop()


def service(p):
    return p.server.app.state.ctx.service


def open_home(browser, p, width: int, scheme: str = "light"):
    ctx = browser.new_context(viewport={"width": width, "height": 900}, color_scheme=scheme)
    page = ctx.new_page()
    faults = clean(page)
    page.goto(p.url)
    ready(page, "home")
    return ctx, page, faults


def a_word(p) -> str:
    """A word that is in the library: the first long word of an item title."""
    with p.service.session(index=True) as (_, idx):
        titles = [r[0] for r in idx.store.q("SELECT text FROM chunk ORDER BY id LIMIT 50")]
    for title in titles:
        for word in title.split():
            if len(word) > 5 and word.isalpha():
                return word
    pytest.skip("the demo library has no title")


def shot(page, name: str) -> None:
    if SHOTS:
        Path(SHOTS).mkdir(parents=True, exist_ok=True)
        page.screenshot(
            path=str(Path(SHOTS) / f"{name}.png"), full_page=True, animations="disabled"
        )


@pytest.mark.parametrize("width", [1440, 390])
def test_with_no_model_home_searches(browser, person, width):
    ctx, page, faults = open_home(browser, person, width)
    try:
        field = page.get_by_role("searchbox", name=copy("ask.label_search"))
        expect(field).to_be_visible()
        # One heading that names the state (W12); the field label is for screen readers.
        expect(page.get_by_role("heading", level=1)).to_have_text(copy("home.title_search"))
        expect(page.locator("#ask-label")).to_have_class("rf-ui-sr-only")
        expect(page.get_by_role("link", name=copy("ask.setup_link"))).to_be_visible()
        # No figures: Home starts with the field.
        assert page.locator(".ag-figures").count() == 0
        field.fill(a_word(person))
        page.get_by_role("button", name=copy("ask.go_search")).click()
        ready(page, "ask")
        expect(page.get_by_role("heading", name=copy("ask.passages"))).to_be_visible()
        rows = page.locator(".ag-sources .ag-source")
        expect(rows.first).to_be_visible()
        assert page.locator(".ag-answer").count() == 0
        # No horizontal scroll at this width.
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        for scheme in ("light", "dark"):
            page.emulate_media(color_scheme=scheme)
            shot(page, f"home-search-{width}-{scheme}")
        assert faults == []
    finally:
        ctx.close()


def test_with_a_model_the_answer_streams_with_citations(browser, person):
    svc = service(person)
    model = FakeTextModel(
        ["The library holds this [1]. A second note agrees [2][1]."] * 3, pieces=8
    )
    before = svc.models.ask_model
    svc.models.ask_model = lambda client, cfg: (model, None)
    setup = svc.ask.ask_setup
    svc.ask.ask_setup = lambda: {**setup(), "model": {"label": "Test model"}}
    ctx, page, faults = open_home(browser, person, 1440)
    try:
        field = page.get_by_role("searchbox", name=copy("ask.label"))
        field.fill(a_word(person))
        page.get_by_role("button", name=copy("ask.go")).click()
        ready(page, "ask")
        answer = page.locator(".ag-answer")
        expect(answer).to_contain_text("A second note agrees")
        expect(page.get_by_role("heading", name=copy("ask.sources"))).to_be_visible()
        page.get_by_role("button", name=copy("ask.cite", n=1)).first.click()
        until(page, "document.querySelector('#ask-src-1').dataset.lit === 'true'")
        until(page, "document.activeElement.closest('#ask-src-1') !== null")
        assert model.calls and model.calls[0].purpose == "ask"
        # The address holds the thread: a reload shows the same answer, with no new call.
        until(page, "location.hash.startsWith('#/ask/')")
        calls = len(model.calls)
        page.reload()
        ready(page, "ask")
        expect(page.locator(".ag-answer")).to_contain_text("A second note agrees")
        assert len(model.calls) == calls
        page.go_back()
        ready(page, "home")
        for scheme in ("light", "dark"):
            page.emulate_media(color_scheme=scheme)
            shot(page, f"home-answer-1440-{scheme}")
        page.set_viewport_size({"width": 390, "height": 900})
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        for scheme in ("light", "dark"):
            page.emulate_media(color_scheme=scheme)
            shot(page, f"home-answer-390-{scheme}")
        assert faults == []
    finally:
        svc.models.ask_model = before
        svc.ask.ask_setup = setup
        ctx.close()


# --------------------------------------------- model settings (step 11b)

LOCAL_ID = re.compile("^llama3-2-")
OUT_OF_SOURCES = "No source permits this model to read its text."


def open_at(browser, p, hash_: str, screen: str, width: int = 1440):
    ctx = browser.new_context(viewport={"width": width, "height": 900})
    page = ctx.new_page()
    faults = clean(page)
    page.goto(p.url + hash_)
    ready(page, screen)
    return ctx, page, faults


def wait_for(page, check) -> None:
    for _ in range(100):
        if check():
            return
        page.wait_for_timeout(100)
    assert check()


def no_lab_model(p) -> None:
    """The model tests need no lab model as the default: a lab model of an
    earlier test (`test_a_pi_sets_the_lab_model`) must not stay."""
    with p.service.session() as c:
        lab = service(p).models.lab_policy(c)
    assert lab is None or not (lab.models or {}).get("profiles")


@pytest.fixture
def with_ollama(person):
    """A fake Ollama on this computer (no network), and a fresh model config."""
    from modelkit import FakeOllama

    from anagram.models.ollama_client import OllamaClient

    no_lab_model(person)
    before = person.service.ollama
    person.service.ollama = OllamaClient(transport=FakeOllama(tags=("llama3.2:latest",)))
    with person.service.session(index=True) as (_, idx):
        idx.store.set_meta("models", None)
    yield person
    person.service.ollama = before
    with person.service.session(index=True) as (_, idx):
        idx.store.set_meta("models", None)


@pytest.mark.parametrize("width", [1440, 390])
def test_with_ollama_the_model_needs_no_choice(browser, with_ollama, width):
    ctx, page, faults = open_at(browser, with_ollama, "#/account", "account", width)
    try:
        reads = page.get_by_label(copy("models.reads"))
        expect(reads).to_have_value(LOCAL_ID)
        expect(page.get_by_label(copy("models.answers"))).to_have_value(reads.input_value())
        expect(page.get_by_text("A local model keeps all text on this computer.")).to_be_visible()
        assert page.locator("#drafting-title, #settings-title").count() == 0  # the old sections
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        for scheme in ("light", "dark"):
            page.emulate_media(color_scheme=scheme)
            shot(page, f"models-{width}-{scheme}")
        assert faults == []
    finally:
        ctx.close()


@pytest.fixture
def no_ollama(person):
    """Ollama does not run on this computer (no network), and no model is set up."""
    from modelkit import FakeOllama

    from anagram.models.ollama_client import OllamaClient

    no_lab_model(person)
    before = person.service.ollama
    person.service.ollama = OllamaClient(transport=FakeOllama(down=True))
    with person.service.session(index=True) as (_, idx):
        idx.store.set_meta("models", None)
    yield person
    person.service.ollama = before
    with person.service.session(index=True) as (_, idx):
        idx.store.set_meta("models", None)


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_no_model_is_a_calm_line_with_one_next_step(browser, no_ollama, scheme):
    """Review item B12: no model is a normal state, not an error. The line has
    the normal text color, no status rule, and the one next step."""
    ctx, page, faults = open_at(browser, no_ollama, "#/account", "account")
    try:
        page.emulate_media(color_scheme=scheme)
        line = page.get_by_text("No model is selected. Anagram sorts your items with rules.")
        expect(line).to_be_visible()
        assert line.evaluate("e => e.closest('.ag-status') === null")
        body = page.evaluate(
            "getComputedStyle(document.querySelector('main') || document.body).color"
        )
        assert line.evaluate("e => getComputedStyle(e).color") == body
        assert page.locator("section[aria-labelledby=models-title] .ag-status").count() == 0
        step = page.get_by_role("button", name="Choose a model")
        expect(step).to_be_visible()
        step.click()
        until(page, "document.activeElement && document.activeElement.name === 'model-where'")
        shot(page, f"models-none-{scheme}")
        assert faults == []
    finally:
        ctx.close()


def test_a_university_model_is_added_and_used(browser, with_ollama):
    ctx, page, faults = open_at(browser, with_ollama, "#/account", "account")
    reads = page.get_by_label(copy("models.reads"))
    try:
        expect(reads).to_have_value(LOCAL_ID)
        page.get_by_text(copy("models.add")).click()
        page.locator("#model-where-university").check()
        line = copy("models.leaves_university", name=copy("models.university_name"))
        expect(page.get_by_text(line)).to_be_visible()
        page.get_by_label(copy("models.address"), exact=True).fill("https://llm.example.edu/v1")
        page.get_by_label(copy("models.model_name"), exact=True).fill("served-model")
        page.get_by_role("button", name=copy("models.add_use")).click()
        expect(reads).to_have_value(re.compile("^llm-example-edu-"))
        # An outside model needs sources: the state says it in one line.
        expect(page.get_by_text(OUT_OF_SOURCES)).to_be_visible()
        expect(page.get_by_text(copy("models.sources", name="llm.example.edu"))).to_be_visible()
        # Back to the local model: a local choice needs no yes.
        reads.select_option(label="llama3.2")
        expect(page.get_by_text(OUT_OF_SOURCES)).to_have_count(0)
        # To the outside model again: one yes, next to the line of what leaves.
        reads.select_option(label="llm.example.edu")
        use = page.get_by_role("button", name=copy("models.use", name="llm.example.edu"))
        expect(use).to_be_visible()
        page.get_by_role("button", name=copy("models.keep")).click()
        expect(use).to_have_count(0)
        expect(reads).to_have_value(LOCAL_ID)
        assert faults == []
    finally:
        ctx.close()


def test_one_choice_corrects_the_kind_of_an_item(browser, person):
    with person.service.session(index=True) as (_, idx):
        (first,) = idx.store.one("SELECT id FROM item ORDER BY id LIMIT 1")
    ref = f"item:{first}"
    svc = service(person)
    ctx, page, faults = open_at(browser, person, f"#/item/{ref}", "item", 390)
    try:
        page.get_by_label(copy("item.kind")).select_option("method")
        wait_for(page, lambda: svc.understanding.item(ref)["kind"] == "method")
        page.reload()
        ready(page, "item")
        expect(page.get_by_label(copy("item.kind"))).to_have_value("method")
        assert faults == []
    finally:
        ctx.close()


def test_a_pi_sets_the_lab_model(browser, person):
    """The new lab can be the first lab of the person, whose model is the
    default of the model settings: the test sets the lab back at the end,
    so the model tests of this module see no lab model in any order."""
    with person.service.session() as c:
        lab_id = c.labs.lab_create("Model Lab")["lab_id"]

    def policy():
        with person.service.session() as c:
            return c.lab_space.lab_policy(lab_id)

    ctx, page, faults = open_at(browser, person, f"#/lab/{lab_id}/settings", "lab", 390)
    try:
        page.locator("#lab-model-where-university").check()
        page.get_by_label(copy("models.address"), exact=True).fill("https://llm.example.edu/v1")
        page.get_by_label(copy("models.model_name"), exact=True).fill("served-model")
        page.get_by_label(copy("models.lab_text")).check()
        page.get_by_role("button", name=copy("models.lab_save")).click()
        wait_for(page, lambda: len(policy().disclosure.get("allow_external") or []) == 1)
        assert policy().models["profiles"][0]["base_url"] == "https://llm.example.edu/v1"
        expect(page.locator("#lab-model-where-university")).to_be_checked()
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        for scheme in ("light", "dark"):
            page.emulate_media(color_scheme=scheme)
            shot(page, f"lab-models-390-{scheme}")
        assert faults == []
    finally:
        ctx.close()
        service(person).models.set_lab_models(lab_id, {"profile": None})


def test_the_ask_screen_lists_earlier_questions_once(browser, person):
    # The same question two times: the list shows it once. The test asks
    # itself, so it needs no earlier test.
    for _ in range(2):
        service(person).ask.start_ask(a_word(person), wait=True)
    ctx, page, faults = open_home(browser, person, 1440)
    try:
        page.goto(person.url + "#/ask")
        ready(page, "ask")
        heading = page.get_by_role("heading", name=copy("ask.earlier"))
        expect(heading).to_be_visible()
        questions = page.locator(".ag-ask-again .ag-row-title").all_inner_texts()
        assert questions and len(questions) == len(set(questions))
        assert faults == []
    finally:
        ctx.close()


def test_the_timeline_shows_weeks_and_a_summary_arrives_live(browser, person):
    svc = service(person)
    model = FakeTextModel(["The week had a result [1]."])
    before = svc.models.ask_model
    svc.models.ask_model = lambda client, cfg: (model, None)
    try:
        for width in (1440, 390):
            ctx = browser.new_context(viewport={"width": width, "height": 900})
            page = ctx.new_page()
            faults = clean(page)
            page.goto(person.url + "#/timeline")
            ready(page, "timeline")
            expect(page.locator(".ag-week").first).to_be_visible()
            expect(page.locator(".ag-week-summary .ag-cite").first).to_be_visible()
            assert page.locator(".ag-week .ag-rows-item").count() > 0
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            for scheme in ("light", "dark"):
                page.emulate_media(color_scheme=scheme)
                shot(page, f"timeline-{width}-{scheme}")
            assert faults == []
            ctx.close()
        assert model.calls and all(c.purpose == "digest" for c in model.calls)
    finally:
        svc.models.ask_model = before


def test_assistant_access_is_added_and_stopped(browser, person):
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    page = ctx.new_page()
    faults = clean(page)
    try:
        page.goto(person.url + "#/account")
        ready(page, "account")
        expect(page.get_by_role("heading", name=copy("assistant.title"))).to_be_visible()
        name = copy("assistant.default_name")
        page.get_by_role("button", name=copy("assistant.add", name=name)).click()
        setup = page.get_by_label(copy("assistant.setup_label"))
        expect(setup).to_be_visible()  # the setup text of a new assistant is open
        assert '"mcpServers"' in setup.input_value()
        shot(page, "assistant-1440-light")
        page.get_by_role("button", name=copy("assistant.stop_name", name=name)).click()
        expect(page.get_by_role("button", name=copy("assistant.add", name=name))).to_be_visible()
        assert faults == []
    finally:
        ctx.close()


def test_the_person_approves_a_proposal_of_an_assistant(browser, person):
    """Open-agents stage 2: the proposal shows its exact lines; the approval
    is a click in the local UI."""
    from anagram.gateway import access, acts

    with person.service.session(index=True) as (_, idx):
        grant = access.add(idx, "Lab helper", ["private"], idx.now(), tools=list(access.TOOLS))
        lines = {"offers": ["Cryo-EM data of pumps"], "wants": ["A 300 kV microscope"]}
        acts.propose(idx, grant, tool="act.lines_propose", kind=acts.LINES, payload=lines,
                     disclosure="Nothing leaves this computer now.", now=idx.now())  # fmt: skip
    ctx = browser.new_context(viewport={"width": 390, "height": 844})
    page = ctx.new_page()
    faults = clean(page)
    try:
        page.goto(person.url + "#/account")
        ready(page, "account")
        title = copy("assistant.proposal_title", name="Lab helper")
        expect(page.get_by_text(title)).to_be_visible()
        expect(page.get_by_text("A 300 kV microscope")).to_be_visible()
        shot(page, "assistant-proposal-390-light")
        page.get_by_role("button", name=copy("assistant.approve")).click()
        expect(page.get_by_text(title)).to_have_count(0)
        with person.service.session() as c:
            draft = c.enclave.status()["draft"]
            assert [x["text"] for x in draft["offers"]] == ["Cryo-EM data of pumps"]
        assert faults == []
    finally:
        ctx.close()
        with person.service.session(index=True) as (_, idx):
            access.revoke(idx, grant.id, idx.now())


def test_a_negative_result_shows_one_quiet_word(browser, person):
    """Decision C12: the Library row and the item show the word, no icon."""
    with person.service.session(index=True) as (_, idx):
        (vid, iid) = idx.store.one(
            "SELECT v.id, v.item_id FROM version v ORDER BY v.id DESC LIMIT 1"
        )
        idx.store.x(
            "INSERT INTO fact (version_id, kind, value, score, data, enricher, enricher_version)"
            " VALUES (?, 'kind', 'finding', 0.9, ?, 'understand', 'test')",
            (vid, '{"by": "model", "polarity": "negative"}'),
        )
    ref = f"item:{iid}"
    word = copy("library.negative")
    ctx, page, faults = open_at(browser, person, f"#/item/{ref}", "item", 390)
    try:
        expect(page.get_by_test_id("polarity")).to_have_text(word)
        page.goto(person.url + "#/library/finding")
        ready(page, "library")
        row = page.locator(f'[id="item-{ref}"]')
        expect(row.locator(".ag-row-meta")).to_contain_text(word)
        assert row.locator("svg, img").count() == 0
        assert faults == []
    finally:
        ctx.close()
        with person.service.session(index=True) as (_, idx):
            idx.store.x(
                "DELETE FROM fact WHERE enricher_version = 'test' AND version_id = ?", (vid,)
            )
