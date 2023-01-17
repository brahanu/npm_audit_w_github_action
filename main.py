import json
import sys
import argparse


def parse_arguments():
    """
    #parses the script input argument:
     #severity: the minimal severity threshold the user cannot tolerate
     #title: a string to look for in npm audit report, which indicates which problems the user cannot tolerate
    #:return: PARSER instance with the given program inputs
    """
    PARSER = argparse.ArgumentParser(description="npm audit with github Action")
    PARSER.add_argument(
        "-s",
        "--severity",
        help="Severity threshold, the minimal severity the user cannot tolerate",
        choices=["low", "moderate", "high", "critical"],
        required=True,

    )
    PARSER.add_argument(
        "-t",
        "--title",
        help="String in the description of the security issue to look for",
        type=str,
        required=True,
    )

    return PARSER.parse_args()


def check_severity(severity, info, low,moderate, high, critical):
    """
    checks if there are security problems that are above the severity threshold, according to the npm audit report metadata.
    :param severity: the minimal severity threshold the user cannot tolerate
    :param info: int val, that indicates how many "info" type vulnerabilities there according to the npm audit report
    :param low: int val, that indicates how many "low" type vulnerabilities there according to the npm audit report
    :param moderate: int val, that indicates how many "moderate" type vulnerabilities there according to the npm audit report
    :param high: int val, that indicates how many "high" type vulnerabilities there according to the npm audit report
    :param critical: int val, that indicates how many "critical" type vulnerabilities there according to the npm audit report
    :return: True if there are security problems that are above the severity threshold, else False
    """
    failure = False

    if severity == "info" and info + low + moderate + high + critical > 0:
        failure = True
    elif severity == "low" and low + moderate + high + critical > 0:
        failure = True
    elif severity == "moderate" and moderate + high + critical > 0:
        failure = True
    elif severity == "high" and high + critical > 0:
        failure = True
    elif severity == "critical" and critical > 0:
        failure = True
    return failure


def check_title(title, vulner_data):
    """
    iterate on the npm audit json report, inside the Description rubric, and checks if the given title is found
    :param title:
    :param vulner_data: the vulnarabilities found by the npm report,
    :return: True if the title is found, False otherwise
    """
    for vul in vulner_data["description"]:
        if title in vul:
            return True
    return False


def run():

    ARGS = parse_arguments()
    severity = ARGS.severity
    title = ARGS.title
    # load the json file
    with open('audit.json','r') as json_file:
        npm_audit_data = json.load(json_file)
    """
    try:
        npm_audit_data = json.load(sys.stdin)  # need other way to load the json file
    except:
        print("Couldnt parse json from stdin")
        sys.exit(1)
    """
    vulnerabilities_metadata = npm_audit_data["metadata"]["vulnerabilities"]
    # parse the vulnerabilities_metadata rubric by severity
    try:
        info = vulnerabilities_metadata["info"]
        low = vulnerabilities_metadata["low"]
        moderate = vulnerabilities_metadata["moderate"]
        high = vulnerabilities_metadata["high"]
        critical = vulnerabilities_metadata["critical"]
    except:
        print("There are a problem with npm audit report Json format")
        sys.exit(1)
    # if there are no vulnerabilities we shouldnt procceed with testing
    if info + low + moderate + high + critical == 0:
        print("There are no known vulnerabilities in your code")
        sys.exit(0)

    elif not check_severity(severity, info, low, moderate, high, critical):
        print("There are Security issues in your code")
        sys.exit(1)
    elif not check_title(title, npm_audit_data["vulnerabilities"]):
        print("There are Security issues in your code")
        sys.exit(1)
    else:
        print("There are No known security issues with your code ")
        sys.exit(0)


run()
