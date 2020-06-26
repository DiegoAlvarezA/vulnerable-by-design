## Version 1.4.1
## language: en

Feature:
  TOE:
    badstore
  Category:
    Broken Cryptography
  Location:
    http://localhost/
  CWE:
    CWE-327: https://cwe.mitre.org/data/definitions/327.html
    CWE-328: https://cwe.mitre.org/data/definitions/328.html
  Rule:
    REQ.147: https://fluidattacks.com/web/rules/147/
  Goal:
    Decrypt user password from database
  Recommendation:
    Use up-to-date cryptographic algorithms to encrypt data

  Background:
  Hacker's software:
    | <Software name> |   <Version>    |
    | Kali            | 2019.1 (x64)   |
    | Chrome          | 75.0.3770.142  |
  TOE information:
    Given I am accessing the site http://localhost/
    And Apache/1.3.28 (Unix) mod_ssl/2.8.15 OpenSSL/0.9.7c
    And MySQL version 4.1.7-standard

  Scenario: Normal use case
    Given I access to http://localhost/
    Then I can see some options that I can perform

  Scenario: Static detection
    Given I don't have access to the source code
    Then I can't make a static detection

  Scenario: Dynamic detection
    When I access to the database with th default credentials
    And I list the data from "userdb" table
    Then I get the column "passwd" seems to have and encrypted value
    """
    | passwd                           |
    +----------------------------------
    | 098F6BCD4621D373CADE4E832627B4F6 |
    """
    Then I can conclude that it could be possible decrypt it

  Scenario: Exploitation
    Given the value encrypted, I save it in a file
    Then I find the encryption type with the tool "hash-identifier"
    And I get this:
    """
    Possible Hashs:
    [+]  MD5
    """
    Then I decrypt it with john the ripper
    And I get the password:
    """
    secret
    """

  Scenario: Remediation
    When encrypt a password and store it in a database
    Then It must be encrypted with strongs functions
    And algorithms verified by experts in the field
    And such algorithms must perform salting and stretching
    Then the password is less vulnerable to brute force attacks

  Scenario: Scoring
  Severity scoring according to CVSSv3 standard
  Base: Attributes that are constants over time and organizations
    7.1/10 (High) - AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
  Temporal: Attributes that measure the exploit's popularity and fixability
    6.7/10 (Medium) - E:F/RL:T/RC:C
  Environmental: Unique and relevant attributes to a specific user environment
    5.9/10 (Medium) - CR:M/IR:L/AR:L/MAV:L/MAC:L/MPR:L/MUI:N/MS:U/MC:X/MI:X/MA:X

  Scenario: Correlations
    vbd/badstore/0521-weak-password-req
    When I try to login to mysql with default user and password
    Then I am able to login as root file[evidence](root-login.png)
    Then I conclude mysql server has weak credentials
