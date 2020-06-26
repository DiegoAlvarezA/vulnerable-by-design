## Version 1.4.1
## language: en

Feature:
  TOE:
    dsvw
  Category:
    Cross-Site Scripting (XSS)
  Location:
    http://localhost:65412 - v (field)
  CWE:
    CWE-79: https://cwe.mitre.org/data/definitions/79.html
  Rule:
    REQ.173: https://fluidattacks.com/web/rules/173/
  Goal:
    Inject a reflected XSS.
  Recommendation:
    Filter the user input

  Background:
  Hacker's software:
    | <Software name> |   <Version>    |
    | Windows         | 10.0.1809 (x64)|
    | Chrome          | 75.0.3770.142  |
  TOE information:
    Given I am accessing the site http://127.0.0.1:65412/
    And the server is running SQLite version 3
    And Python version 2.7.16

  Scenario: Normal use case
    Given I access to "http://127.0.0.1:65412/?v="
    When I pass a value to the parameter "?v=4.01"
    Then It just displays the value in the page footer
    """
    Powered by DSVW (v4.01)
    """

  Scenario: Static detection
    Given the python code (dsvw.py)
    And the lines where the "v" parameter is processed
    """
    32  elif "v" in params:
    33  content += re.sub(r"(v<b>)[^<]+(</b>)", r"\g<1>%s\g<2>" % params["v"],
        HTML_POSTFIX)
    """
    When I inspect the code
    Then I see the parameter is not filtered
    And I conclude that I could pass not just a number

  Scenario: Dynamic detection
    Given "http://127.0.0.1:65412/?v="
    When I insert in the parameter some html tags
    """
    http://127.0.0.1:65412/?v=0.2<p style="text-transform: uppercase;">hi</p>"
    """
    Then I get the output:
    """
    Powered by DSVW (v0.2
            HI
            )
    """
    And the html tags are interpreted correctly
    Then I conclude that I could pass some html tags in the parameter

  Scenario: Exploitation
    Given "http://127.0.0.1:65412/?v="
    And knowing that html tags are not filtered
    When I pass this XSS payload:
    """
    http://localhost:65412/?v=0.2<script>alert("XSS reflected")</script>
    """
    Then an alert pops up with the message
    Then I conclude that the application is vulnerable to reflected XSS

  Scenario: Remediation
    Given I have patched the code by removing all the html tags to the input
    And with "BeautifulSoup" library I can remove dangerous tags
    """
    34  soup = BeautifulSoup(params["v"])
    35 [s.extract() for s in soup(['script', 'style', 'img'])]
    36 content += re.sub(r"(v<b>)[^<]+(</b>)", r"\g<1>%s\g<2>" % soup.get_text
        (), HTML_POSTFIX)
    """
    When I pass the same XSS payload
    """
    http://localhost:65412/?v=0.2<script>alert("XSS reflected")</script>
    """
    Then It doesn't pop up the alert window
    Then I can confirm that the vulnerability was successfully patched

  Scenario: Scoring
  Severity scoring according to CVSSv3 standard
  Base: Attributes that are constants over time and organizations
    4.3/10 (Medium) - AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N
  Temporal: Attributes that measure the exploit's popularity and fixability
    4.1/10 (Medium) - E:F/RL:W/RC:C
  Environmental: Unique and relevant attributes to a specific user environment
    3.4/10 (Low) - CR:L/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X

  Scenario: Correlations
    No correlations have been found to this date 2019-08-13
