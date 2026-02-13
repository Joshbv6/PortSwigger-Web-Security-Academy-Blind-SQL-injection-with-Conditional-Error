# [Blind SQL Injection Lab – PortSwigger Web Security Academy(https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)]

This project contains a small Python script created to solve a Blind SQL Injection lab from the PortSwigger Web Security Academy.

🧪 Lab Description

The lab features a Blind SQL Injection vulnerability in a tracking cookie used for analytics.

The application performs a SQL query that includes the value of a submitted cookie.

The query results are not reflected in the response.

The application response does not change based on whether the query returns rows.

If the injected query causes a database error, the application returns a custom error message.

The database contains a table named:
```users```

With the following columns:
```
- username
- password
```

The goal of the lab is to exploit the blind SQL injection vulnerability to extract the password of the administrator user.

⚙️ Approach

Since no data is directly returned in the response, this lab is solved using error-based blind SQL injection techniques:

Inject payloads into the tracking cookie.

Trigger conditional database errors.

Infer true/false conditions based on whether the application returns the custom error message.

Extract the administrator password character by character.

The Python script automates this process by:

Sending crafted HTTP requests

Modifying the tracking cookie dynamically

Detecting error responses

Reconstructing the password step-by-step

🚀 Usage

Set the target lab URL inside the script.

Run the Python script.

The script will automatically enumerate and print the administrator password.

⚠️ Disclaimer

This script is intended strictly for educational purposes within the controlled environment of the PortSwigger Web Security Academy labs.
Do not use these techniques against systems without explicit authorization.
