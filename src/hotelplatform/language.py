"""Which language is this message in? Cheap, offline, good enough to route or refuse.

Stop-word counts for six Latin-script languages, and the Unicode script for the rest. The hotel apps answer in
English and Spanish (stage 1's decision 51); anything else gets a polite "English or Spanish, please" instead of a
guessed answer. Short messages ("ok", "pool?") have too little signal: they return "unknown", which the guardrail
treats as allowed.
"""

import re
import unicodedata

STOP_WORDS = {
    "en": "the is are and to of for in what when where how can do does my i you a an at with please there it this "
    "time open have we our".split(),
    "es": "el la los las es son y de del para en que qué cuándo dónde cómo puedo mi yo usted un una hay con por "
    "favor está tiene hora abierto".split(),
    "fr": "le la les est sont et de des pour dans que quand où comment je mon vous un une il y a avec "
    "s'il plaît".split(),
    "de": "der die das ist sind und zu von für in was wann wo wie kann ich mein sie ein eine es gibt mit bitte".split(),
    "pt": "o a os as é são e de do da para em que quando onde como posso meu eu você um uma há com por favor".split(),
    "it": "il lo la gli le è sono e di del per in che quando dove come posso mio io lei un una c'è con "
    "per favore".split(),
}
MIN_FOREIGN_HITS = 2  # stop-word hits needed to call a message a language other than English
WORD = re.compile(r"[^\W\d_]+(?:'[^\W\d_]+)?", re.UNICODE)
SCRIPTS = {"CJK": "zh", "HIRAGANA": "ja", "KATAKANA": "ja", "HANGUL": "ko", "CYRILLIC": "ru", "ARABIC": "ar",
           "HEBREW": "he", "DEVANAGARI": "hi", "THAI": "th", "GREEK": "el"}  # fmt: skip


def _script(text: str) -> str | None:
    counts: dict[str, int] = {}
    letters = 0
    for ch in text:
        if not ch.isalpha():
            continue
        letters += 1
        name = unicodedata.name(ch, "")
        for key, lang in SCRIPTS.items():
            if name.startswith(key):
                counts[lang] = counts.get(lang, 0) + 1
                break
    if not letters or not counts:
        return None
    lang, n = max(counts.items(), key=lambda kv: kv[1])
    return lang if n / letters > 0.3 else None


def detect(text: str) -> str:
    """ISO 639-1 code, or "unknown" when there isn't enough signal."""
    if not text or not text.strip():
        return "unknown"
    script = _script(text)
    if script:
        return script
    words = [w.lower() for w in WORD.findall(text)]
    if len(words) < 3:
        return "unknown"
    distinct = set(words)  # "per room per night" is one Italian stop word, not two
    scores = {lang: len(distinct & set(sw)) for lang, sw in STOP_WORDS.items()}
    if any(ch in text for ch in "¿¡ñ"):
        scores["es"] += 2
    best, score = max(scores.items(), key=lambda kv: kv[1])
    ties = [lang for lang, s in scores.items() if s == score]
    if score == 0 or (len(ties) > 1 and "en" not in ties):
        return "unknown"
    if len(ties) > 1:
        return "en"
    # One stop word is too little to call a message foreign: "Bookings per property?" has only "per" (Italian), and
    # blocking it as "not English or Spanish" was a real false alarm in stage 8's app tests.
    if best != "en" and score < MIN_FOREIGN_HITS:
        return "unknown"
    return best
