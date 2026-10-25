import pytest

from hotelplatform import pii


def kinds(text):
    return [f.entity for f in pii.find_pii(text)]


@pytest.mark.parametrize(
    "text,entity",
    [
        ("write to priya.shah@example.org please", "EMAIL_ADDRESS"),
        ("call me on +1 415 555 0134", "PHONE_NUMBER"),
        ("card 4111 1111 1111 1111 exp 12/29", "CREDIT_CARD"),
        ("ssn 123-45-6789", "US_SSN"),
        ("IBAN GB82 WEST 1234 5698 7654 32", "IBAN_CODE"),
        ("from 192.168.10.24 last night", "IP_ADDRESS"),
        ("booking BR-1042 is mine", "BOOKING_ID"),
        ("Hi, my name is Lucía Romero and I'd like a cot", "PERSON"),
        ("Thanks,\nOwen Clarke", "PERSON"),
    ],
)
def test_finds_each_entity(text, entity):
    assert entity in kinds(text)


def test_card_needs_luhn_checksum():
    assert "CREDIT_CARD" not in kinds("order 4111 1111 1111 1112")
    assert pii.luhn_ok("4111111111111111")
    assert not pii.luhn_ok("1234")


def test_iban_needs_mod97():
    assert pii.iban_ok("GB82 WEST 1234 5698 7654 32")
    assert not pii.iban_ok("GB00 WEST 1234 5698 7654 32")
    assert "IBAN_CODE" not in kinds("code GB00 WEST 1234 5698 7654 32")


def test_overlaps_keep_the_longer_or_stronger_match():
    found = pii.find_pii("ssn 123-45-6789")
    assert [f.entity for f in found] == ["US_SSN"]  # the phone pattern also matches; the SSN wins


def test_safe_words_are_not_names():
    assert "PERSON" not in kinds("Hi Guest Services, I'm Looking for the spa")
    assert "PERSON" not in kinds("Dear Front Desk")


def test_known_names_found_anywhere():
    assert "PERSON" not in kinds("the booking for priya is fine")  # no context word, no known name
    assert "PERSON" in [f.entity for f in pii.find_pii("note about Priya Shah", names=("Priya Shah",))]


def test_nothing_in_plain_question():
    assert pii.find_pii("What time does the pool open at Beach Resort?") == []
    assert pii.find_pii("") == []


def test_scrub_text_replaces_everything_planted():
    text = (
        "Hi, my name is Owen Clarke. Email owen@example.com, phone +1 415 555 0134, card 4111 1111 1111 1111, "
        "ssn 123-45-6789, IBAN GB82 WEST 1234 5698 7654 32, booking BR-1042.\nThanks,\nOwen Clarke"
    )
    out = pii.scrub_text(text)
    for planted in ("Owen", "owen@example.com", "415 555", "4111", "123-45-6789", "GB82", "BR-1042"):
        assert planted not in out
    assert pii.booking_pseudonym("BR-1042") in out  # stable pseudonym, so one booking's rows still link up


def test_redact_record_keeps_ids_and_masks_whole_fields():
    rec = {
        "trace_id": "4f1c9a2e" * 4,
        "session_id": "s-123",
        "status": "ok",
        "sender_name": "Priya Shah",
        "question": "I'm Priya Shah, is breakfast included? Priya",
        "nested": [{"note": "call 415 555 0134"}],
    }
    out = pii.redact_record(rec)
    assert out["trace_id"] == rec["trace_id"] and out["session_id"] == "s-123" and out["status"] == "ok"
    assert out["sender_name"] == "[name]"
    assert "Priya" not in out["question"]
    assert "[phone]" in out["nested"][0]["note"]


def test_entities_helper():
    assert pii.entities("a@b.co and 4111 1111 1111 1111") == {"EMAIL_ADDRESS", "CREDIT_CARD"}
    assert pii.Finding("EMAIL_ADDRESS", 0, 4, 1.0).to_dict()["entity"] == "EMAIL_ADDRESS"
