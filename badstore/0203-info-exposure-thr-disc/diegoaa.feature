## Version 1.4.1
## language: en

Feature:
  TOE:
    badstore
  Category:
    Information Leakage and Improper Error Handling
  Location:
    http://192.168.0.79/badstore.cgi?action=submitpayment - Credit Card (field)
  CWE:
    CWE-203: https://cwe.mitre.org/data/definitions/203.html
    CWE-20: https://cwe.mitre.org/data/definitions/20.html
  Rule:
    REQ.161: https://fluidattacks.com/web/rules/161/
  Goal:
    Send a value that exceeds the allowed size in the server and get the error
  Recommendation:
    Validate data and specify the allowed size

  Background:
  Hacker's software:
    | <Software name> |   <Version>    |
    | Kali            | 2019.1 (x64)   |
    | Firefox         | 60.4.0esr      |
    | Burp suite      | 1.7.35         |
  TOE information:
    Given I am accessing the site http://192.168.0.79/
    And Apache/1.3.28 (Unix) mod_ssl/2.8.15 OpenSSL/0.9.7c
    And MySQL version 4.1.7-standard

  Scenario: Normal use case
    Given I access to:
    """
    http://192.168.0.79/cgi-bin/badstore.cgi?action=submitpayment
    """
    And add an Email and credit card number
    When I click on "Place Order" button
    Then I get this message:
    """
    Your Order Has Been Placed
    You have just bought the following:
    Purchased: 2 items at $24.00
    """

  Scenario: Static detection
    Given I don't have access to the source code
    Then I can't make a static detection

  Scenario: Dynamic detection
    When I access to the database with the default credentials
    And I search for the global variables
    Then I get a list of them
    And I see the variable "max_allowed_packet" is set to a low value (1 MB)
    """
    | max_allowed_packet | 1048576 |
    """
    Then I can conclude that it could be a possible buffer overflow attack

  Scenario: Exploitation
    Given the form to submit a payment
    And adding the email and credit card
    And click on "Place Order" button
    When I intercept the request with Burp Suite
    And modify the parameter for the credit card number
    And set it to a very long number
    Then I get an error from the server [evidence](error.png)
    And the order is not saved in the database
    Then I can conclude that the query exceeds the allowed size

  Scenario: Remediation
    Given the task to insert data into a database
    When the values are validated before being saved
    And validated according to the requirements
    Then the transaction can be done without problems
    But if the query expects a long value
    Then the variable "max_allowed_packet" must be set to a large size
    And set it according to what is required
    And for MySQL 4.0.1 and latest, the recommended limit is 1GB
    Then the MySQL server accepts packets between the specified value

  Scenario: Scoring
  Severity scoring according to CVSSv3 standard
  Base: Attributes that are constants over time and organizations
    5.7/10 (Medium) - AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N
  Temporal: Attributes that measure the exploit's popularity and fixability
    5.3/10 (Medium) - E:F/RL:O/RC:C
  Environmental: Unique and relevant attributes to a specific user environment
    5.3/10 (Medium) - CR:M

  Scenario: Correlations
    vbd/badstore/0521-weak-password-req
    When I try to login to mysql with default user and password
    Then I am able to login as root file[evidence](root-login.png)
    Then I conclude mysql server has weak credentials
