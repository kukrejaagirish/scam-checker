"""Tests for the fake investment / trading tips / crypto category (v0.3.0)."""

import pytest

from scam_checker import analyze


@pytest.mark.parametrize(
    "message",
    [
        # English
        "Join our VIP stock market tips WhatsApp group, guaranteed 5% daily returns. "
        "Download the trading app: https://xyz-trade.top/app.apk",
        "Invest Rs 10,000 and get Rs 30,000 in 7 days. 100% safe.",
        "Bitcoin trading platform with guaranteed profit, start with just Rs 2000",
        "Double your money in 30 days with our forex plan",
        "Sure shot tips for tomorrow, join our premium trading group now",
        "IPO allotment guaranteed through our institutional special account, pay now",
        "Earn 3% daily profit on USDT, withdraw anytime",
        # Hinglish
        "Bhai paisa double scheme hai, 10000 nivesh karo aur 1 mahine me double munafa pakka",
        "Share market VIP group join karo, pakka profit milega roz",
        # Hindi (Devanagari)
        "शेयर बाजार VIP ग्रुप से जुड़ें, रोजाना 10% मुनाफा गारंटी के साथ",
        "सिर्फ 30 दिन में आपका पैसा डबल, अभी निवेश करें",
        "बिटकॉइन में निवेश करें और पाएं 5% रोज का रिटर्न",
    ],
)
def test_investment_scams_are_flagged(message):
    result = analyze(message)
    assert "fake_investment" in {m.category for m in result.matches}
    assert result.level in ("Medium", "High")


@pytest.mark.parametrize(
    "message",
    [
        "Your SIP of Rs 5000 in HDFC Mutual Fund is processed. "
        "Mutual fund investments are subject to market risks.",
        "Your order to buy 10 shares of TCS was executed at Rs 3,450.",
        "Your FD of Rs 50,000 earns 7.1% interest p.a. and matures on 12-Dec-2026.",
        "Flat 50% off on all shoes today only!",
        "Sensex closed 0.8% higher today, IT stocks gained the most.",
        "Papa ne bola PPF me invest karna safe hai, kal bank chalenge",
        "आपकी SIP की किस्त ₹2,000 सफलतापूर्वक कट गई है।",
    ],
)
def test_normal_finance_messages_are_not_investment_scams(message):
    result = analyze(message)
    assert "fake_investment" not in {m.category for m in result.matches}
    assert result.level == "Low", [m.category for m in result.matches]


def test_trading_group_with_apk_link_is_high():
    result = analyze(
        "Congratulations, you are selected for our VIP trading group. Guaranteed 20% monthly "
        "returns. Install our app from bit.ly/vip-trade and deposit Rs 5000 turant."
    )
    assert result.level == "High"
    categories = {m.category for m in result.matches}
    assert {"fake_investment", "suspicious_link"} <= categories


def test_investment_reason_points_to_sebi():
    result = analyze("Guaranteed returns of 10% monthly, join now")
    match = next(m for m in result.matches if m.category == "fake_investment")
    assert "sebi.gov.in" in match.reason
