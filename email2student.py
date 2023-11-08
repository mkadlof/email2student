#!/usr/bin/env python3

import argparse
import re
import sys
from typing import List

import ldap

try:
    from ldap_config import LDAP_SERVER, LDAP_PORT, LDAP_BASE_DN
except ModuleNotFoundError:
    print("Cannot find ldap_config.py. Please create this file and define the following variables: LDAP_SERVER, LDAP_PORT, LDAP_BASE_DN", file=sys.stderr)
    sys.exit(1)

email_regex = re.compile(r'^[\w\-.]+@(?:[\w-]+\.)+[\w-]{2,4}$')


def make_ldap_connection() -> ldap.ldapobject.LDAPObject:
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    conn = ldap.initialize(f"ldaps://{LDAP_SERVER}:{LDAP_PORT}")
    return conn


def parse_list_of_emails_into_ldap_filter(emails: List[str]) -> str:
    ldap_filter = "(|"
    for email in emails:
        ldap_filter += f"(mail={email})"
    ldap_filter += ")"
    return ldap_filter


def validate_emails(emails: List[str]) -> None:
    for email in emails:
        if not re.match(email_regex, email):
            print(f"Invalid email address: {email}", file=sys.stderr)
            sys.exit(1)


def get_emails_from_file_or_from_stdin(args: argparse.Namespace) -> List[str]:
    # Read email addresses from stdin or from a file or from command line arguments
    if args.input_file:
        with open(args.input_file, "r") as file:
            emails = [line.strip() for line in file]
    elif args.email_list:
        emails = args.email_list
    else:
        emails = [line.strip() for line in sys.stdin]
    validate_emails(emails)
    return emails


def display_results(results: List[ldap.ldapobject.LDAPObject]) -> None:
    for dn, entry in results:
        mail = entry.get("mail", [])[0].decode("utf-8")
        gecos = entry.get("gecos", [])[0].decode("utf-8")
        uid = entry.get("uid", [])[0].decode("utf-8")
        index, sn, fn = gecos.split(" ", 2)
        fn = fn.rstrip()
        print(f"{index},{sn},{fn},{uid},{mail}")


def main():
    parser = argparse.ArgumentParser(description="Search LDAP records for email addresses. Email addresses can be provided as command line arguments or read from a file or from stdin.")
    parser.add_argument("-i", "--input-file", help="Path to a file containing a list of email addresses")
    parser.add_argument("-e", "--email-list", nargs="*", help="List of email addresses")
    args = parser.parse_args()

    emails = get_emails_from_file_or_from_stdin(args)
    search_filter = parse_list_of_emails_into_ldap_filter(emails)
    conn = make_ldap_connection()
    results = conn.search_s(LDAP_BASE_DN, ldap.SCOPE_SUBTREE, search_filter)
    conn.unbind()
    display_results(results)

    # Check if all email addresses were found, if not, print a warning, and list the missing email addresses
    if len(results) != len(emails):
        print("WARNING! Some email addresses were not found in the LDAP database.", file=sys.stderr)
        mails_from = []
        for r in results:
            mails_from.append(r[1].get("mail", [])[0].decode("utf-8"))
        for email in emails:
            if email not in mails_from:
                print(f"Missing email address: {email}", file=sys.stderr)


if __name__ == '__main__':
    main()
