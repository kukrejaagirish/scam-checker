"""Tests for Hindi (Devanagari) messages."""

import pytest

from scam_checker import analyze
from scam_checker.detector import normalize


@pytest.mark.parametrize(
    "message, category",
    [
        (
            "मैं सीबीआई अधिकारी बोल रहा हूँ। आपके आधार से मनी लॉन्ड्रिंग का केस दर्ज हुआ है। "
            "आप डिजिटल अरेस्ट में हैं, किसी को मत बताना।",
            "digital_arrest",
        ),
        (
            "भाई गलती से आपके नंबर पर 5000 रुपये भेज दिए, पैसे वापस कर दो। "
            "जो रिक्वेस्ट भेजी है उसमें यूपीआई पिन डालें।",
            "upi_request",
        ),
        (
            "प्रिय ग्राहक, आपका SBI खाता आज बंद कर दिया जाएगा। तुरंत केवाईसी अपडेट करें।",
            "kyc_bank_block",
        ),
        (
            "प्रिय उपभोक्ता, आपका बिजली कनेक्शन आज रात 9:30 बजे काट दिया जाएगा क्योंकि पिछला बिल "
            "अपडेट नहीं हुआ। तुरंत बिजली अधिकारी से संपर्क करें।",
            "kyc_bank_block",
        ),
        (
            "आपका पार्सल कस्टम में रोका गया है, उसमें ड्रग्स मिले हैं। कस्टम ड्यूटी भरें वरना केस होगा।",
            "fake_parcel",
        ),
        (
            "घर बैठे पार्ट टाइम काम करें, रोज 3000 रुपये कमाएं। वीडियो लाइक करो और पैसे कमाओ। "
            "टेलीग्राम पर जुड़ें।",
            "job_task",
        ),
        (
            "बधाई हो! कौन बनेगा करोड़पति लॉटरी में 25 लाख का इनाम जीता है। प्रोसेसिंग फीस 5000 रुपये भेजें।",
            "lottery_prize",
        ),
        (
            "आपके फोन पर एक ओटीपी आया होगा, वो जल्दी बताओ।",
            "otp_sharing",
        ),
        (
            "रिफंड पाने के लिए एनीडेस्क ऐप डाउनलोड करें और स्क्रीन शेयर करें।",
            "remote_access",
        ),
    ],
)
def test_hindi_scam_categories(message, category):
    result = analyze(message)
    assert category in [m.category for m in result.matches]
    assert result.is_suspicious


def test_hindi_digital_arrest_is_high_risk():
    result = analyze(
        "मैं सीबीआई अधिकारी बोल रहा हूँ। आप डिजिटल अरेस्ट में हैं, "
        "आपके नाम पर गिरफ्तारी वारंट है। किसी को मत बताना।"
    )
    assert result.level == "High"


@pytest.mark.parametrize(
    "message",
    [
        "कल शाम को मिलते हैं, खाना साथ में खाएंगे।",
        "मम्मी, मैं घर पहुंच गया। जल्दी सो जाना।",
        "आपका ऑर्डर कल तक डिलीवर हो जाएगा। धन्यवाद।",
        "बेटा, बिजली का बिल भर दिया है, चिंता मत करना।",
        "आपकी टीम मैच जीत गई, बधाई!",
        "घर बैठे बोर हो रहा हूँ यार",
        "लोकेशन पिन शेयर करो",
    ],
)
def test_normal_hindi_messages_stay_low(message):
    assert analyze(message).level == "Low"


def test_urgency_alone_in_hindi_is_not_a_scam():
    result = analyze("तुरंत घर आ जाओ, खाना ठंडा हो रहा है")
    assert [m.category for m in result.matches] == ["urgency"]
    assert result.level == "Low"


def test_nukta_spelling_variants_match_the_same():
    # "गिरफ़्तार" typed with the precomposed letter, with letter + nukta, and
    # without the nukta at all should all be caught.
    precomposed = "आप गिर\u095e\u094dतार हो सकते हैं"
    decomposed = "आप गिरफ\u093c\u094dतार हो सकते हैं"
    plain = "आप गिरफ्तार हो सकते हैं"
    for message in (precomposed, decomposed, plain):
        assert "digital_arrest" in [m.category for m in analyze(message).matches]


def test_normalize_removes_zero_width_characters():
    assert normalize("डिजिटल\u200d   अरेस्ट") == "डिजिटल अरेस्ट"


def test_mixed_hindi_and_english_message():
    result = analyze("Your SBI account blocked ho jayega, तुरंत KYC अपडेट करें: bit.ly/kyc-sbi")
    categories = [m.category for m in result.matches]
    assert "kyc_bank_block" in categories
    assert "suspicious_link" in categories
    assert result.level == "High"
