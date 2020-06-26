## Version 1.4.1
## language: en

Feature:
  TOE:
    node-goat
  Category:
    Injection
  Location:
    http://localhost:4000/allocations/4 - threshold (field)
  CWE:
    CWE-943: https://cwe.mitre.org/data/definitions/943.html
  Rule:
    REQ.173: https://fluidattacks.com/web/rules/173/
  Goal:
    Modify the logic of the query
  Recommendation:
    validate input both frontend and backed. Avoid use of unsafe operations

  Background:
  Hacker's software:
    | <Software name> |   <Version>    |
    | Windows         | 10.0.1809 (x64)|
    | Chrome          | 75.0.3770.142  |
  TOE information:
    Given I am accessing the site http://localhost:4000
    And the server is running MongoDB version 2.1.18
    And Nodejs version 10.15.3
    And Express version 4.13.4

  Scenario: Normal use case
    Given I access to "http://localhost:4000/"
    And login in with a new user
    When I go to allocations tab
    And filter assets based on Stock by value 1
    Then I get this information:
    """
    Domestic Stocks : 6 %
    Funds: 5 %
    Bonds: 89 %
    """
    And if I filter by value 7
    Then I don't get any information
    And It is caused by the value is greater than "Stock"

  Scenario: Static detection
    Given the file "allocations-dao.js"
    And looking where allocations are returned
    """
    78 return {
    79 $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
    80 };
    """
    When I inspect the code
    Then I notice that values are not filtered
    And It uses unsafe operators ($where)

  Scenario: Dynamic detection
    Given I am in the Allocations tab
    And As with testing other types of injection
    And inspecting the source code, the input tag doesn't filter by number type
    When I insert a single quote in the input
    Then I get a database error:
    """
    Oops.. MongoError: SyntaxError: unterminated string literal :
    functionExpressionParser@src/mongo/scripting/mozjs/mongohelpers.js:48:25
    """
    Then I conclude that the application is not correctly sanitize the input.

  Scenario: Exploitation
    Given the application doesn't sanitize the user input
    And knowing data is return all assets allocation above the specified stocks
    When I pass this to force a True return:
    """
    1'; return 1 == '1
    """
    Then I get all database allocations documents [evidence](allocations.png)
    Then I conclude that the application is vulnerable to nosql injection

  Scenario: Remediation
    Given I have patched the code by changing "$where" to "$expr" operator
    And knowing "$expr" does not execute JavaScript, and is faster than "$where"
    And change the operator, parse and validate the input "threshold":
    """
    77 const parsedThreshold = parseInt(threshold, 10);
    78 if (parsedThreshold >= 0 && parsedThreshold <= 99) {
    79  return {$expr: { $and: [{ $eq: ["$userId", parsedUserId] },
         { $gt: ["$stocks", parsedThreshold] }] }};
    80 };
    81 throw `The user supplied threshold: ${parsedThreshold} was not valid.`;
    """
    When I pass the same input "1'; return 1 == '1"
    Then It doesn't show all allocations documents as before
    And also implementing a fix in allocations.html for input tags:
    """
    29 <input
    30  type="number"
    31  min="0"
    32  max="99"
    33  class="form-control"
    34  placeholder="Stocks Threshold"
    35  name="threshold"
    36 />
    """
    And It just allows numbers and displays the correct error if it occurs
    Then I can confirm that the vulnerability was successfully patched

  Scenario: Scoring
  Severity scoring according to CVSSv3 standard
  Base: Attributes that are constants over time and organizations
    5.3/10 (Medium) - AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
  Temporal: Attributes that measure the exploit's popularity and fixability
    5.0/10 (Medium) - E:F/RL:W/RC:C
  Environmental: Unique and relevant attributes to a specific user environment
    5.0/10 (Medium) - CR:M/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X

  Scenario: Correlations
    No correlations have been found to this date 2019-08-16
