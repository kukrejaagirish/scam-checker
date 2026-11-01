import pytest

from scam_checker import analyze


@pytest.mark.parametrize(
    "message, category",
    [
        (
            "This is CBI officer. A money laundering case is registered on your Aadhaar. "
            "You are under digital arrest, stay on video call and don't tell anyone.",
            "digital_arrest",
        ),
        (
            "Aapke naam pe FIR registered hai, turant payment karo warna giraftaar ho jaoge",
            "digital_arrest",
        ),
        (
            "Sir I sent Rs 5000 to you by mistake, I have sent a collect request, "
            "please enter your UPI PIN to return it",
            "upi_request",
        ),
        (
            "Dear customer your SBI account will be blocked today. Update KYC now: http://sbi-kyc-update.xyz/login",
            "kyc_bank_block",
        ),
        (
            "Aapka khata band ho jayega, turant KYC update karein",
            "kyc_bank_block",
        ),
        (
            "Your FedEx parcel contains illegal drugs and is held by customs. Press 1 to talk to officer.",
            "fake_parcel",
        ),
        (
            "India Post: your package is pending due to incomplete address. Update your address here bit.ly/3xYzAb",
            "fake_parcel",
        ),
        (
            "Part time job! Like YouTube videos and earn Rs 3000 per day. Join our Telegram task group.",
            "job_task",
        ),
        (
            "Congratulations! You have won Rs 25,00,000 in KBC lucky draw. Pay processing fee to claim.",
            "lottery_prize",
        ),
        (
            "Bhai galti se OTP aa gaya tere phone pe, jaldi bata do OTP please",
            "otp_sharing",
        ),
        (
            "Install AnyDesk so our support team can fix your account",
            "remote_access",
        ),
    ],
)
def test_scam_messages_are_flagged(message, category):
    result = analyze(message)
    assert result.level in ("Medium", "High")
    assert category in {m.category for m in result.matches}


@pytest.mark.parametrize(
    "message",
    [
        "Hey, are we still meeting for dinner at 8 tonight?",
        "Mummy, main ghar pahunch gaya, khana kha ke soonga",
        "Your Swiggy order is out for delivery and will reach you in 20 minutes.",
        "Rs 450 debited from your account for electricity bill payment. Thank you.",
        "India jeet gaya match! Kya innings thi",
        "Happy birthday bhai, have a great year ahead!",
    ],
)
def test_normal_messages_are_low_risk(message):
    result = analyze(message)
    assert result.level == "Low", [m.category for m in result.matches]


def test_digital_arrest_with_otp_is_high():
    result = analyze(
        "CBI officer here. Arrest warrant issued in your name. Share the OTP you received "
        "immediately to verify, otherwise you will be arrested."
    )
    assert result.level == "High"
    assert result.score >= 50


def test_urgency_alone_is_not_high():
    result = analyze("Urgent! Call me back immediately, jaldi")
    assert result.level == "Low"
    assert result.score < 25


def test_score_is_capped_at_100():
    result = analyze(
        "CBI digital arrest! Your bank account blocked, update KYC, share OTP, enter UPI PIN, "
        "you won lottery, part time job earn Rs 5000 per day, parcel seized by customs, "
        "click bit.ly/abc turant"
    )
    assert result.score == 100
    assert result.level == "High"


def test_advice_has_helpline_and_portal():
    result = analyze("Your KYC is pending, account will be blocked")
    advice = " ".join(result.advice)
    assert "1930" in advice
    assert "cybercrime.gov.in" in advice
    assert "OTP" in advice


def test_low_result_still_mentions_helpline():
    advice = " ".join(analyze("See you tomorrow").advice)
    assert "1930" in advice
    assert "cybercrime.gov.in" in advice


def test_empty_message_is_low():
    result = analyze("")
    assert result.level == "Low"
    assert result.matches == []
