## Version 1.4.1
## language: en

Feature:
  TOE:
    seattle-sounds
  Category:
    Broken Access Control
  Location:
    http://192.168.1.19/download.php - item (param)
  CWE:
    CWE-34: https://cwe.mitre.org/data/definitions/34.html
  Rule:
    REQ.37: https://fluidattacks.com/web/rules/037/
  Goal:
    Inject a path to download a system file
  Recommendation:
    Apply path traversal filter properly

  Background:
  Hacker's software:
    | <Software name> |   <Version>    |
    | Ubuntu          | 18.04.2 LTS    |
    | Mozilla Firefox | 68.0.2         |
  TOE information:
    Given I am accessing the site http://192.168.1.19/
    And the server is running Apache version 2.4.16
    And PHP version 5.6.16

  Scenario: Normal use case
    Given I'm in the main page http://192.168.1.19/
    And there is a link called "Grab our stock brochure here!"
    When I click on the link
    Then It downloads a pdf file

  Scenario: Static detection
    Given the file "getfile.php"
    And locating the function where "item" parameter is filtered
    """
    6  $path = '/var/www/html/downloads/';
    7  if ($_COOKIE["level"] == "2") {
    8    $patterns = array();
    9    $patterns[0] = '/\.\.\//';
    10   $dl_file = preg_replace($patterns, '', $_GET['item']);
    11   $dl_file = filter_var($dl_file, FILTER_SANITIZE_URL);
    12   $fullPath = $path.$dl_file;
    13 }
    """
    When I inspect the code
    Then I notice that the "item" parameter is not correctly validated

  Scenario: Dynamic detection
    Given I can download a file by clicking on "Grab our stock brochure here!"
    And changing the level to 2
    When I inspect the request
    Then I see there is the "item" parameter
    And It seems that looks for a specific file
    Then I conclude I could specify another file's name
    And download it to my computer

  Scenario: Exploitation
    Given I could specify another file's name in the request
    And maybe make a path to get the 'passwd' file
    When I make a request with a path to 'passwd' file:
    """
    http://192.168.1.19/download.php?item=../../../../../../../../etc/passwd
    """
    Then I just get a blank page
    And It doesn't download anything
    When I change the 'item' parameter to:
    """
    item=....//....//....//....//....//....//....//....//etc/passwd
    """
    Then I get the 'passwd' file
    Then I conclude that the application is vulnerable to path traversal
    And It doesn't validate the user input properly

  Scenario: Remediation
    Given I have patched the code by using the "realpath()" function
    And It ensures the start of the string matches the intended full path:
    """
    6  $path = '/var/www/html/downloads/';
    7  if ($_COOKIE["level"] == "2") {
    8   $realBase = realpath($path);
    9   $userpath = $basepath . $_GET['item'];
    10  $realUserPath = realpath($userpath);
    11  if ($realUserPath === false || strpos($realUserPath, $realBase) !== 0){
    12    $fullPath = $path;
    13  } else {
    14    $fullPath = $realUserPath;
    15  }
    """
    When I send the request with 'item' parameter:
    """
    item=....//....//....//....//....//....//....//....//etc/passwd
    """
    Then It doesn't return anything
    Then I can confirm that the vulnerability was successfully patched

  Scenario: Scoring
  Severity scoring according to CVSSv3 standard
  Base: Attributes that are constants over time and organizations
    5.3/10 (Medium) - AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
  Temporal: Attributes that measure the exploit's popularity and fixability
    5.0/10 (Medium) - E:F/RL:W/RC:C
  Environmental: Unique and relevant attributes to a specific user environment
    4.4/10 (Medium) - CR:L/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:L/MI:X/MA:X

  Scenario: Correlations
    No correlations have been found to this date 2019-09-24
