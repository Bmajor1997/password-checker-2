# Password Checker

import hashlib
import sys
import requests


def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f" Error fetching {response.status_code}, check the api and try again")


def get_passwords_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):  # Check password if it exists in API response
    sha1password = hashlib.sha1(password.encode('utf-8'))
    first5_char, tail = sha1password[:5], sha1password[5:]
    res = request_api_data(first5_char)
    print(res)
    return get_passwords_leaks_count(res, tail)


def main(args):
    for passwords in args:
        count = pwned_api_check(passwords)
        if count:
            print(f"{passwords} was found {count} many times. Your password should probably be changed")
    else:
        print("Your password was NOT found in any database, you are fine with this password.")
    return "done."


if __name__ == '__main__':
    main(sys.argv[1:])
