import re
import requests
from urllib.parse import urlparse
from colorama import Fore

import colorama

print("Colorama version:", colorama.__version__)


red = Fore.RED
yellow = Fore.YELLOW
reset = Fore.RESET

print(f'''{red}

'########::'##::::'##:'####::'######::'##::::'##::'######:::'######:::::'###::::'##::: ##:
 ##.... ##: ##:::: ##:. ##::'##... ##: ##:::: ##:'##... ##:'##... ##:::'## ##::: ###:: ##:
 ##:::: ##: ##:::: ##:: ##:: ##:::..:: ##:::: ##: ##:::..:: ##:::..:::'##:. ##:: ####: ##:
 ########:: #########:: ##::. ######:: #########:. ######:: ##:::::::'##:::. ##: ## ## ##:
 ##.....::: ##.... ##:: ##:::..... ##: ##.... ##::..... ##: ##::::::: #########: ##. ####:
 ##:::::::: ##:::: ##:: ##::'##::: ##: ##:::: ##:'##::: ##: ##::: ##: ##.... ##: ##:. ###:
 ##:::::::: ##:::: ##:'####:. ######:: ##:::: ##:. ######::. ######:: ##:::: ##: ##::. ##:
..:::::::::..:::::..::....:::......:::..:::::..:::......::::......:::..:::::..::..::::..:: 
                                                                                                   
                                                                      {yellow} GITHUB: StarStark07
                                                                       MadeBy: Piyush Kumar {reset}''')

def is_https(url):
    return urlparse(url).scheme == 'https'

def extract_domain(url):
    return urlparse(url).netloc

def suspicious_domain(domain):
    suspicious_domains = ['phishing.com', 'malicious.com', 'fakebank.com']
    return domain in suspicious_domains

def suspicious_keywords(url):
    suspicious_keywords = ['login', 'password', 'verify', 'account', 'bank']
    for keyword in suspicious_keywords:
        if keyword in url:
            return True
    return False

def analyze_url(url):
    warnings = []

    if not is_https(url):
        warnings.append("Warning: URL is not using HTTPS.")

    domain = extract_domain(url)
    if suspicious_domain(domain):
        warnings.append("Warning: Suspicious domain detected.")

    if suspicious_keywords(url):
        warnings.append("Warning: Suspicious keywords detected in URL.")

    if not warnings:
        return "The URL appears to be safe."
    else:
        return "\n".join(warnings)

while True:
    url = input("Enter the URL to scan: ")
    print(analyze_url(url))

    choice = input("Do you want to analyze another URL? (Y/N): ")
    if choice.lower() != 'y' and choice.lower() != 'yes':
        print("Exiting...")
        break
