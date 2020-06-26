## Version 1.4.1
## language: en

Feature:
  TOE:
    node-goat
  Category:
    Broken Authentication and Session Management
  Location:
    http://localhost:4000/login - password (field)
  CWE:
    CWE-307: https://cwe.mitre.org/data/definitions/307.html
  Rule:
    REQ.134: https://fluidattacks.com/web/rules/134/
  Goal:
    Get the admin password by brute force attack
  Recommendation:
    Block IP after failed login attempts and make stronger passwords

  Background:
  Hacker's software:
    | <Software name> |   <Version>    |
    | Windows         | 10.0.1809 (x64)|
    | Chrome          | 75.0.3770.142  |
    | Burp suite      | 1.7.35         |
  TOE information:
    Given I am accessing the site http://localhost:4000
    And the server is running MongoDB version 2.1.18
    And Nodejs version 10.15.3
    And Express version 4.13.4

  Scenario: Normal use case
    Given I access to "http://localhost:4000/login"
    When I login in with a new user
    Then It redirects to "/dashboard"
    But if I try to login in with admin user and some password
    Then I get this message:
    """
    Invalid password
    """

  Scenario: Static detection
    Given the main file "server.js" and "session.js"
    When I inspect the code
    Then I notice that there is nothing to handle failed login attempts
    Then I conclude that I can send many requests without any restrictions

  Scenario: Dynamic detection
    Given I am in the login page
    When I try to login with a random user "user007"
    Then I get this error:
    """
    Invalid username
    """
    And I if try with "admin"
    Then I get this error:
    """
    Invalid password
    """
    Then I conclude that "admin" user y valid
    And I could brute force the password

  Scenario: Exploitation
    Given the application doesn't hanlde failed login attempts
    When I make a brute force attack with Burp Suite:
    Then I get the admin password [evidence](password.png)
    Then I conclude that the application is vulnerable to brute force attack

  Scenario: Remediation
    Given I have patched the code by using "express-brute" library
    And a function to handle login attempts by IP address
    """
    136 const bruteforce = new ExpressBrute(store, {
    137   freeRetries: 20,
    138   attachResetToRequest: false,
    139   refreshTimeoutOnRequest: false,
    140   minWait: 25 * 60 * 60 * 1000, // 1 day 1 hour
    141   maxWait: 25 * 60 * 60 * 1000, // 1 day 1 hour
    142   lifetime: 24 * 60 * 60, // 1 day (seconds not milliseconds)
    143   failCallback: failCallback,
    144   handleStoreError: handleStoreError
    145 });
    """
    And a function to block user account is available
    And the account is disabled for a period of time sufficient
    But not so long as to allow for a denial-of-service attack to be performed
    And the middlewares for "/login" route
    """
    147 app.post('/login',
    148   bruteforce.prevent,
    149   userBruteforce.getMiddleware({
    150   key: function (req, res, next) {
    151     // prevent too many attempts for the same username
    152     next(req.body.userName);
    153   }
    154   }), // error 403 if we hit this route too often
    155   function (req, res, next) {
    156     next();
    157   }
    158 );
    """
    When I try the same brute force attack
    And after 20 request of guessing the password
    Then the application blocks the IP address for one day
    And for additional protection, validate passwords with:
    """
    const PASS_RE =/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/;
    """
    Then I can confirm that the vulnerability was successfully patched

  Scenario: Scoring
  Severity scoring according to CVSSv3 standard
  Base: Attributes that are constants over time and organizations
    6.5/10 (Medium) - AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
  Temporal: Attributes that measure the exploit's popularity and fixability
    6.2/10 (Medium) - E:F/RL:W/RC:C
  Environmental: Unique and relevant attributes to a specific user environment
    7.9/10 (High) - CR:H/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:H/MI:X/MA:X

  Scenario: Correlations
    No correlations have been found to this date 2019-08-29
