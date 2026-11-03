"""Rule-based detector for common Indian SMS / WhatsApp scam patterns.

All patterns live in ``CATEGORIES`` as plain data, so adding a new scam type
means adding one entry - no logic changes needed.

This is a helper, not a guarantee. A "Low" result does not prove a message
is safe.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import List, Pattern, Tuple


@dataclass(frozen=True)
class Category:
    """One scam pattern family."""

    key: str
    name: str
    weight: int
    patterns: Tuple[str, ...]
    reason: str

    def compiled(self) -> List[Pattern[str]]:
        return [re.compile(p, re.IGNORECASE) for p in self.patterns]


@dataclass
class Match:
    category: str
    name: str
    reason: str
    evidence: List[str] = field(default_factory=list)
    weight: int = 0


@dataclass
class Result:
    score: int
    level: str
    matches: List[Match]
    advice: List[str]

    @property
    def is_suspicious(self) -> bool:
        return self.level != "Low"


# ---------------------------------------------------------------------------
# Pattern data. Each regex is matched case-insensitively against the message.
# Hinglish words (Hindi written in Roman script) are included because most
# real scam messages in India mix English and Hindi. Hindi in Devanagari
# script is covered too; Devanagari patterns are written without the nukta
# (e.g. "करोडपति", not "करोड़पति") because messages are normalised first, see
# ``normalize``. They also skip ``\b``, which does not work reliably on
# Devanagari vowel signs.
# ---------------------------------------------------------------------------
CATEGORIES: Tuple[Category, ...] = (
    Category(
        key="digital_arrest",
        name="Digital arrest / fake police or CBI",
        weight=45,
        patterns=(
            r"\bdigital(ly)?\s+arrest",
            r"\b(cbi|ncb|ed|enforcement directorate|cyber ?crime (cell|branch|police)|crime branch|narcotics|customs officer|trai)\b",
            r"\barrest\s+warrant\b",
            r"\b(fir|case)\s+(has been\s+|is\s+)?(registered|filed|lodged)\b",
            r"\bmoney\s+laundering\b",
            r"\bgiraftaa?r\b",
            r"\bvideo\s+call\b.*\b(police|officer|inquiry|investigation)\b",
            r"\b(police|officer)\b.*\bvideo\s+call\b",
            r"\bdon'?t\s+(tell|inform)\s+(anyone|your family)\b",
            r"\bkisi\s+ko\s+mat\s+bata(na|o)?\b",
            # Hindi (Devanagari)
            r"डिजिटल\s*अरेस्ट",
            r"गिरफ्तार",
            r"(सीबीआई|सी\.बी\.आई|क्राइम\s*ब्रांच|साइबर\s*(क्राइम|सेल)|नारकोटिक्स|प्रवर्तन\s*निदेशालय)",
            r"(अरेस्ट|गिरफ्तारी)\s*वारंट",
            r"मनी\s*लॉ?न्ड्रिंग",
            r"(एफआईआर|मुकदमा|केस)\s*(दर्ज|रजिस्टर)",
            r"(पुलिस|अधिकारी|ऑफिसर).{0,40}वीडियो\s*कॉल",
            r"वीडियो\s*कॉल.{0,40}(पुलिस|अधिकारी|ऑफिसर|पूछताछ|जांच)",
            r"किसी\s*को\s*(भी\s*)?(मत|न|ना)\s*बता",
        ),
        reason="Mentions police/CBI/arrest. Real agencies never arrest anyone over a call or video call and never ask for money to 'settle' a case.",
    ),
    Category(
        key="upi_request",
        name="UPI collect / refund request",
        weight=35,
        patterns=(
            r"\b(collect|payment)\s+request\b",
            r"\benter\s+(your\s+)?(upi\s+)?pin\b",
            r"\bupi\s+pin\b",
            r"\bscan\s+(the\s+|this\s+)?qr\b.*\b(receive|get|refund|cashback)\b",
            r"\b(receive|get)\b.*\b(money|payment|refund)\b.*\b(scan|pin|approve)\b",
            r"\brefund\b.*\b(approve|accept|pin|link|click)\b",
            r"\bcashback\b.*\b(approve|accept|pin|scan)\b",
            r"\bgalti\s+se\b.*\b(bhej|transfer|send)",
            r"\b(sent|transferred)\s+(by\s+)?mistake\b",
            r"\bpaise\s+wapas\b",
            # Hindi (Devanagari)
            r"(यूपीआई|यू\.पी\.आई|UPI)\s*पिन",
            r"पिन\s*(डालें|डालो|डालिए|दर्ज)",
            r"गलती\s*से.{0,40}(भेज|ट्रांसफर|आ\s*गए|आ\s*गया)",
            r"पैसे\s*वापस",
            r"(रिफंड|कैशबैक).{0,40}(लिंक|क्लिक|पिन|स्कैन|अप्रूव)",
            r"(क्यूआर|QR)\s*(कोड)?\s*स्कैन",
        ),
        reason="Asks you to approve a UPI request, scan a QR or enter your PIN to 'receive' money. You never need a PIN to receive money.",
    ),
    Category(
        key="kyc_bank_block",
        name="KYC update / bank account blocked",
        weight=35,
        patterns=(
            r"\bkyc\b",
            r"\b(account|a/c|card|sim|pan|yono|net\s*banking)\b.{0,40}\b(block|blocked|suspend|suspended|deactivat|freez|frozen|closed?)\w*",
            r"\b(block|suspend|deactivat|freez)\w*\b.{0,40}\b(account|a/c|card|sim)\b",
            r"\bkhata\s+band\b",
            r"\bkhaata\s+band\b",
            r"\b(update|link)\s+(your\s+)?(pan|aadhaa?r)\b",
            r"\bpan\s+card\b.*\b(update|link|expire)",
            r"\belectricity\b.*\b(disconnect|cut|kat)\w*",
            r"\bbijli\b.*\b(kat|band|cut)\w*",
            # Hindi (Devanagari)
            r"(केवाईसी|के\.वाई\.सी)",
            r"(खाता|खाते|अकाउंट|एकाउंट|कार्ड|सिम).{0,40}(बंद|ब्लॉक|निलंबित|फ्रीज)",
            r"(पैन|आधार)\s*(कार्ड)?.{0,30}(अपडेट|लिंक)",
            r"बिजली.{0,60}(कट|काट|बंद)",
        ),
        reason="Says your bank account, card, SIM or electricity will be blocked unless you update KYC. Banks do not ask for KYC through SMS links or calls.",
    ),
    Category(
        key="fake_parcel",
        name="Fake parcel / courier / customs",
        weight=30,
        patterns=(
            r"\b(parcel|package|courier|shipment|consignment)\b.{0,60}\b(held|hold|seized|stuck|pending|undeliver|illegal|drugs|customs|return)\w*",
            r"\b(fedex|dhl|blue\s*dart|india\s*post|speed\s*post)\b.{0,60}\b(held|seized|illegal|drugs|address|fee|charge|update)\w*",
            r"\bcustoms\s+(duty|clearance|charge|fee)\b",
            r"\b(update|confirm|incomplete)\s+(your\s+)?(delivery\s+)?address\b",
            r"\bredeliver",
            # Hindi (Devanagari)
            r"(पार्सल|कूरियर|कुरियर|पैकेज|सामान).{0,60}(रुका|रोका|रोक\s*लिया|जब्त|कस्टम|ड्रग्स|अवैध|गैरकानूनी)",
            r"कस्टम\s*(ड्यूटी|शुल्क|चार्ज)",
            r"((पता|एड्रेस)\s*अपडेट|अधूरा\s*(पता|एड्रेस))",
        ),
        reason="Claims a parcel is held, seized or needs a fee/address update. Couriers don't ask for payment through random links.",
    ),
    Category(
        key="job_task",
        name="Job / task / part-time earning scam",
        weight=30,
        patterns=(
            r"\bpart[\s-]?time\b",
            r"\bwork\s+from\s+home\b",
            r"\b(daily|per\s+day)\s+(income|earning|salary)\b",
            r"\b(earn|kamao|kamaye|kamaiye)\b.{0,40}(₹|rs\.?|inr|\d{3,})",
            r"(₹|rs\.?|inr)\s*\d[\d,]*.{0,30}\b(per\s+day|daily|roz|rozana|per\s+task)\b",
            r"\b(like|subscribe|rate|review)\b.{0,30}\b(videos?|hotels?|products?|channels?)\b.{0,40}\b(earn|paid|pay|income|₹|rs)",
            r"\b(simple|easy)\s+tasks?\b",
            r"\bprepaid\s+task\b",
            r"\bghar\s+baithe\b",
            r"\btelegram\b.{0,40}\b(task|job|join|earn)\b",
            # Hindi (Devanagari)
            r"घर\s*बैठे.{0,40}(कमा|काम|इनकम|जॉब|नौकरी|पैसे)",
            r"पार्ट\s*टाइम",
            r"(रोज|रोजाना|प्रतिदिन|हर\s*दिन).{0,30}(कमाएं|कमाओ|कमाई|कमाइए|इनकम)",
            r"(कमाएं|कमाओ|कमाइए|कमाई).{0,40}(₹|रु|रुपये|\d{3,})",
            r"(वीडियो|चैनल|होटल|प्रोडक्ट).{0,30}(लाइक|सब्सक्राइब|रिव्यू|रेटिंग).{0,40}(कमाएं|कमाई|पैसे|₹|रु)",
            r"टेलीग्राम.{0,40}(टास्क|जॉब|नौकरी|जुड़|जुड|कमा)",
        ),
        reason="Offers easy money for simple tasks or part-time work. These usually end with you 'investing' money you never get back.",
    ),
    Category(
        key="lottery_prize",
        name="Lottery / prize / lucky draw",
        weight=30,
        patterns=(
            r"\b(lottery|lucky\s+draw|jackpot|kbc|kaun\s+banega\s+crorepati)\b",
            r"\byou\s+(have\s+)?won\b",
            r"\bcongratulations\b.{0,60}\b(won|winner|selected|prize|reward)\b",
            r"\b(prize|reward|gift)\s+(money|amount)\b",
            r"\b(processing|registration|tax)\s+fee\b",
            r"\b(inaam|inam)\b.{0,40}\b(jeet|mila|milega)\w*",
            r"\b(aapne|apne|tumne)\b.{0,30}\bjeet(a|e|i)\b",
            # Hindi (Devanagari)
            r"(लॉटरी|लकी\s*ड्रॉ|जैकपॉट|कौन\s*बनेगा\s*करोडपति|केबीसी)",
            r"(इनाम|ईनाम|पुरस्कार).{0,40}(जीत|मिला|मिलेगा)",
            r"(आपने|तुमने).{0,30}जीत(ा|े|ी)",
            r"(प्रोसेसिंग|रजिस्ट्रेशन|पंजीकरण)\s*(फीस|शुल्क)",
        ),
        reason="Says you won a lottery, prize or lucky draw. You cannot win a contest you never entered, and real prizes never ask for a fee.",
    ),
    Category(
        key="fake_investment",
        name="Fake investment / trading tips / crypto",
        weight=35,
        patterns=(
            r"\bguarantee(d|ed)?\s+(\d{1,3}\s*%\s*)?(returns?|profits?|income|gains?)\b",
            r"\b\d{1,3}\s*%\s*(daily|weekly|monthly|per\s+(day|week|month)|guaranteed|fixed)?\s*(returns?|profits?|gains?)\b",
            r"\b(returns?|profits?)\s+(of\s+)?\d{1,3}\s*%\s*(daily|weekly|monthly|per\s+(day|week|month)|guaranteed)",
            r"\b(double|triple|2x|3x|10x)\s+(your\s+)?(money|investment|amount|capital)\b",
            r"\b(paisa|paise|paisa\s+aapka)\s+(double|dugna|doguna)\b",
            r"\b(stock|share)\s+market\b.{0,60}\b(tips?|vip|guaranteed|sure\s*shot|jackpot|multibagger)\b",
            r"\b(vip|premium|exclusive)\s+(stock|share|trading|investment|crypto|ipo)\s+(group|tips|channel|club)\b",
            r"\bsure\s*shot\s+(tips?|calls?|profit|stock)\b",
            r"\b(ipo|otc|block\s+trade|institutional)\b.{0,40}\b(allotment\s+guaranteed|guaranteed\s+allotment|special\s+(account|quota)|discount(ed)?\s+(price|shares))\b",
            r"\b(crypto|bitcoin|btc|usdt|forex|binary\s+option)\w*\b.{0,60}\b(guaranteed|profit|double|returns?)\b",
            r"\binvest\w*\b.{0,30}(₹|rs\.?|inr)\s*\d[\d,]*.{0,40}\b(get|earn|receive|withdraw)\w*\b.{0,20}(₹|rs\.?|inr)\s*\d",
            r"\b(pakka|fixed|guaranteed)\s+(munafa|profit|return)\b",
            r"\b(nivesh|invest)\s+kar(o|ein|en|e|iye)\b.{0,50}\b(munafa|profit|returns?|double|kamao)\b",
            # Hindi (Devanagari)
            r"(गारंटी|गारंटीड|पक्का|फिक्स्ड).{0,20}(रिटर्न|मुनाफा|प्रॉफिट|लाभ)",
            r"(पैसा|पैसे|रकम|निवेश).{0,20}(डबल|दोगुना|दुगना|तिगुना)",
            r"\d{1,3}\s*%\s*(रोज|रोजाना|प्रतिदिन|हर\s*दिन|महीना|मासिक|हर\s*महीने)?\s*(का\s*)?(रिटर्न|मुनाफा|प्रॉफिट|लाभ)",
            r"(शेयर|स्टॉक)\s*(बाजार|मार्केट).{0,60}(टिप्स|ग्रुप|वीआईपी|VIP|गारंटी|पक्का)",
            r"(वीआईपी|VIP)\s*(ग्रुप|टिप्स|चैनल)",
            r"(क्रिप्टो|बिटकॉइन|फॉरेक्स).{0,60}(निवेश|मुनाफा|प्रॉफिट|रिटर्न|डबल)",
            r"(आईपीओ|IPO).{0,40}(अलॉटमेंट|एलॉटमेंट).{0,20}(गारंटी|पक्का)",
        ),
        reason="Promises guaranteed or very high returns, 'double money', or VIP stock / IPO / crypto tips, often through a WhatsApp or Telegram group and a trading app link. No real investment guarantees profit; check any advisor or app on sebi.gov.in before paying anything.",
    ),
    Category(
        key="otp_sharing",
        name="OTP / password sharing",
        weight=50,
        patterns=(
            r"\b(share|send|tell|forward|give|bata|batao|bhejo|bhej\s+do)\b.{0,30}\b(otp|one\s+time\s+password|verification\s+code|cvv|pin)\b",
            r"\b(otp|cvv|pin|verification\s+code)\b.{0,30}\b(share|send|tell|forward|bata|batao|bhejo|bhej\s+do)\b",
            r"\botp\b.{0,40}\b(received|aaya|aya)\b",
            # Hindi (Devanagari)
            r"(बताएं|बताइए|बताओ|बता\s*दो|भेजें|भेजो|भेज\s*दो|शेयर).{0,30}(ओटीपी|OTP|सीवीवी|CVV|(यूपीआई|एटीएम|UPI|ATM)\s*पिन)",
            r"(ओटीपी|OTP|सीवीवी|CVV|(यूपीआई|एटीएम|UPI|ATM)\s*पिन).{0,30}(बताएं|बताइए|बताओ|बता\s*दो|भेजें|भेजो|भेज\s*दो|शेयर)",
            r"(ओटीपी|OTP).{0,40}(आया|आएगा)",
        ),
        reason="Asks you to share an OTP, PIN or CVV. No bank, company or government office ever needs your OTP.",
    ),
    Category(
        key="suspicious_link",
        name="Suspicious link",
        weight=20,
        patterns=(
            r"\b(bit\.ly|tinyurl\.com|t\.co|cutt\.ly|is\.gd|rb\.gy|shorturl\.at|tiny\.cc|ow\.ly|goo\.gl)/\S+",
            r"https?://\d{1,3}(\.\d{1,3}){3}",
            r"https?://[^\s/]+\.(xyz|top|click|link|online|site|live|icu|buzz|shop|info|cc|tk|ml|ga|cf|gq)\b",
            r"\b[\w.-]*(sbi|hdfc|icici|axis|kotak|paytm|phonepe|gpay|amazon|flipkart|indiapost|kyc|rbi)[\w-]*-[\w.-]+\.(com|in|net|org|co)\b",
            r"\.apk\b",
        ),
        reason="Contains a shortened, look-alike or app-download (.apk) link. Don't open it.",
    ),
    Category(
        key="remote_access",
        name="Screen-sharing app request",
        weight=35,
        patterns=(
            r"\b(anydesk|teamviewer|quick\s*support|rustdesk|airdroid)\b",
            r"\bscreen\s*shar(e|ing)\b",
            # Hindi (Devanagari)
            r"(एनीडेस्क|टीमव्यूअर|क्विक\s*सपोर्ट)",
            r"स्क्रीन\s*शेयर",
        ),
        reason="Asks you to install a screen-sharing / remote-access app. With it, a scammer can see your OTPs and control your phone.",
    ),
    Category(
        key="urgency",
        name="Urgency / pressure",
        weight=10,
        patterns=(
            r"\b(urgent(ly)?|immediately|within\s+\d+\s*(hours?|hrs?|minutes?|mins?)|today\s+itself|last\s+(chance|warning|reminder)|final\s+(notice|warning))\b",
            r"\bturant\b",
            r"\bjaldi\b",
            r"\babhi\s+ke\s+abhi\b",
            r"\bwarna\b",
            # Hindi (Devanagari)
            r"(तुरंत|तुरन्त|फौरन)",
            r"(अभी\s*के\s*अभी|आज\s*ही|वरना|अंतिम\s*चेतावनी)",
            r"\d+\s*(घंटे|मिनट)\s*(के\s*अंदर|में)",
        ),
        reason="Pushes you to act immediately. Scammers rush you so you don't stop and check.",
    ),
)


ADVICE_SUSPICIOUS: Tuple[str, ...] = (
    "Do not click any link, call back, or reply to this message.",
    "Never share an OTP, UPI PIN, CVV or password with anyone - not even someone claiming to be from your bank or the police.",
    "You never need to enter a UPI PIN or scan a QR code to RECEIVE money.",
    "If you already lost money, call the National Cyber Crime Helpline 1930 immediately - the faster you report, the better the chance of freezing the money.",
    "Report the fraud online at https://cybercrime.gov.in and inform your bank.",
    "Check with the bank, courier or company using the number on their official website or app - never the number in the message.",
)

ADVICE_LOW: Tuple[str, ...] = (
    "No common scam pattern was found, but this is not a guarantee the message is safe.",
    "Never share an OTP, UPI PIN or CVV with anyone.",
    "If something feels wrong, call 1930 or report at https://cybercrime.gov.in.",
)

MEDIUM_AT = 25
HIGH_AT = 50


def _level(score: int) -> str:
    if score >= HIGH_AT:
        return "High"
    if score >= MEDIUM_AT:
        return "Medium"
    return "Low"


_COMPILED = [(c, c.compiled()) for c in CATEGORIES]

# Characters removed before matching: the Devanagari nukta (U+093C, the dot in
# letters like "ड़" and "फ़", which people type inconsistently) and invisible
# zero-width joiners / non-joiners / spaces that some keyboards insert.
_STRIP = dict.fromkeys(map(ord, "\u093c\u200b\u200c\u200d\ufeff"))


def normalize(message: str) -> str:
    """Return the text the patterns are matched against.

    Unicode is put in NFC form, the nukta and zero-width characters are
    removed and all whitespace is collapsed to single spaces. This makes
    "गिरफ़्तार" and "गिरफ्तार" (or the same word typed with a different
    keyboard) look the same to the patterns.
    """
    text = unicodedata.normalize("NFC", message or "").translate(_STRIP)
    return " ".join(text.split())


def analyze(message: str) -> Result:
    """Analyse a message and return its risk score, level, matches and advice."""
    text = normalize(message)
    matches: List[Match] = []
    for category, patterns in _COMPILED:
        evidence: List[str] = []
        for pattern in patterns:
            found = pattern.search(text)
            if found and found.group(0) not in evidence:
                evidence.append(found.group(0))
        if evidence:
            # One hit gives the base weight; extra distinct hits in the same
            # category add a little more, capped so one category can't dominate.
            bonus = min(len(evidence) - 1, 3) * 5
            matches.append(
                Match(
                    category=category.key,
                    name=category.name,
                    reason=category.reason,
                    evidence=evidence,
                    weight=category.weight + bonus,
                )
            )

    score = min(sum(m.weight for m in matches), 100)
    # Urgency alone is not enough to call something a scam.
    if matches and all(m.category == "urgency" for m in matches):
        score = min(score, MEDIUM_AT - 1)

    level = _level(score)
    advice = list(ADVICE_SUSPICIOUS if level != "Low" else ADVICE_LOW)
    return Result(score=score, level=level, matches=matches, advice=advice)
