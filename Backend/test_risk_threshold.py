def check_risk(score):
    if score <= 30:
        return "Low Risk"
    elif score <= 60:
        return "Suspicious"
    else:
        return "High Risk"


tests = {
    30: "Low Risk",
    31: "Suspicious",
    60: "Suspicious",
    61: "High Risk"
}

for score, expected in tests.items():
    result = check_risk(score)

    if result == expected:
        print(f"PASS: Score {score} = {result}")
    else:
        print(f"FAIL: Score {score} = {result}")

from analyzer import classify_risk

tests = {
    30: "Low Risk",
    31: "Suspicious",
    60: "Suspicious",
    61: "High Risk"
}

for score, expected in tests.items():
    result = classify_risk(score)

    if result == expected:
        print(f"PASS: Score {score} = {result}")
    else:
        print(f"FAIL: Score {score} = {result}")