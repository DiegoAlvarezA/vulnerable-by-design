## Version 1.4.1
## language: en

Feature:
  TOE:
    railsgoat
  Category:
    Broken Access Control
  Location:
    http://localhost:3000/users/8/pay - id (field)
  CWE:
    CWE-639: https://cwe.mitre.org/data/definitions/639.html
  Rule:
    REQ.191: https://fluidattacks.com/web/rules/191/
  Goal:
    Delete another user's payment
  Recommendation:
    Check if the payment belongs to the current user

  Background:
  Hacker's software:
    | <Software name> |   <Version>    |
    | Ubuntu          | 18.04.2 LTS    |
    | Mozilla Firefox | 68.0.2         |
  TOE information:
    Given I am accessing the site http://localhost:3000
    And the server is running Rails version 5.1.7
    And Ruby version 2.6.2
    And Sqlite3 version 1.3.13

  Scenario: Normal use case
    Given I'm logged in the application
    And I go to "Pay" tab
    When I submit a new "Direct Deposit"
    Then It is displayed in a table at the bottom page
    And there is the option to delete the payment
    When I hit the delete button
    Then the payment is deleted

  Scenario: Static detection
    Given the file "pay_controller.rb"
    And looking the function where payments are deleted
    """
    28 def destroy
    29   pay = Pay.find_by_id(params[:id])
    30   if pay.present? and pay.destroy
    31     flash[:success] = "Successfully Deleted Entry"
    32   else
    33     flash[:error] = "Unable to process that request at this time"
    34   end
    35   redirect_to user_pay_index_path
    36 end
    """
    When I inspect the function
    Then I notice that It doesn't check the payment id
    And if It belongs to the current user

  Scenario: Dynamic detection
    Given I can delete payments by hitting the button
    When I look the post request
    Then I see the payment id is sent in a parameter:
    """
    POST /users/8/pay/15 HTTP/1.1
    """
    Then I conclude that I could change the parameter for another one

  Scenario: Exploitation
    Given I could change the payment id
    And maybe for a minor one, according to the id sequence
    When I hit the delete button
    And I modify the payment id with "Tamper Data" extension for Firefox
    """
    POST /users/8/pay/14 HTTP/1.1
    """
    Then I get a successful message
    When I inspect the app database
    Then the payment with id 14 is deleted
    Then I conclude that the application is vulnerable to IDOR attack

  Scenario: Remediation
    Given I have patched the code by finding the payment in the current user
    """
    28 def destroy
    29   begin
    30     pay = current_user.pay.find(params[:id])
    31     if pay.present? and pay.destroy
    32       flash[:success] = "Successfully Deleted Entry"
    33     end
    34   rescue
    35     flash[:error] = "Unable to process that request"
    36   end
    37   redirect_to user_pay_index_path
    38 end
    """
    When I try to change the payment id for another one
    Then I just get the error message
    """
    Unable to process that request
    """
    Then I can confirm that the vulnerability was successfully patched

  Scenario: Scoring
  Severity scoring according to CVSSv3 standard
  Base: Attributes that are constants over time and organizations
    6.5/10 (Medium) - AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H
  Temporal: Attributes that measure the exploit's popularity and fixability
    6.2/10 (Medium) - E:F/RL:W/RC:C
  Environmental: Unique and relevant attributes to a specific user environment
    4.1/10 (Medium) - CR:X/IR:X/AR:M/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:L

  Scenario: Correlations
    No correlations have been found to this date 2019-09-04
