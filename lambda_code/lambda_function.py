import json
import base64
from botocore.vendored import requests


def authenticate():
    client_id = "dddd68683a4f-c79f-11e8-8ba7-065392288efd"
    client_secret = "ABX7sJ6YYXVeqfDMR73uNAyay4PQegJmELpreZEu6PMAU"
    client_credentials = client_id + ":" + client_secret
    encoded_client_credentails = str(base64.b64encode(client_credentials.encode("utf-8")), "utf-8")
    response = requests.post(
        'https://pacbot.t-mobile.com/api/auth/oauth/token?grant_type=client_credentials',
        headers={'authorization': 'Basic ' + encoded_client_credentails,
                 'content-type': 'application/x-www-form-urlencoded'}, verify=False
    )
    TOKEN = response.json()['access_token']
    return TOKEN

def getPatchingDetails():
    TOKEN = authenticate()
    response = requests.get(
        'https://pacbot.t-mobile.com/api/compliance/v1/patching?ag=aws-all',
        headers={'Authorization': 'Bearer ' + TOKEN,
                 'Accept': 'application/json'}, verify=False
    )
    return response.json()

def getTaggingDetails():
    TOKEN = authenticate()
    response = requests.get(
        'https://pacbot.t-mobile.com/api/compliance/v1/tagging?ag=aws-all',
        headers={'Authorization': 'Bearer ' + TOKEN,
                 'Accept': 'application/json'}, verify=False
    )
    return response.json()
    
def getCertificateDetails():
    TOKEN = authenticate()
    response = requests.get(
        'https://pacbot.t-mobile.com/api/compliance/v1/certificates?ag=aws-all',
        headers={'Authorization': 'Bearer ' + TOKEN,
                 'Accept': 'application/json'}, verify=False
    )
    return response.json()
    
def getVulnerabilityDetails():
    TOKEN = authenticate()
    response = requests.get(
        'https://pacbot.t-mobile.com/api/vulnerability/v1/vulnerabilites?ag=aws-all',
        headers={'Authorization': 'Bearer ' + TOKEN,
                 'Accept': 'application/json'}, verify=False
    )
    return response.json()

def lambda_handler(event, context):
    # TODO implement
    print(event)
    speech_output = ""
    if(event['body']=="PatchingDetails"):
        patchingDetails = getPatchingDetails()
        patching_percentage = patchingDetails['data']['output']['patching_percentage']
        unpatched_instances = patchingDetails['data']['output']['unpatched_instances']
        patched_instances = patchingDetails['data']['output']['patched_instances']
        total_instances = patchingDetails['data']['output']['total_instances']
        speech_output = "Overall patching percentage is {} % .Total number of instances is {} . Out of which {} are patched and {} are unpatched".format(patching_percentage,total_instances,patched_instances,unpatched_instances)
    elif(event['body']=="TaggingDetails"):
        taggingDetails = getTaggingDetails()
        compliance = taggingDetails['data']['output']['compliance']
        untagged_assets = taggingDetails['data']['output']['untagged']
        tagged_assets = taggingDetails['data']['output']['tagged']
        total_assets = taggingDetails['data']['output']['assets']
        speech_output = "Overall compliance is {} .Total number of assets is {} . Out of which {} are tagged and {} are untagged".format(compliance,total_assets,tagged_assets,untagged_assets)
    elif(event['body']=="CertificateDetails"):
        certificateDetails = getCertificateDetails()
        total_certificate = certificateDetails['data']['output']['certificates']
        certificates_expiring = certificateDetails['data']['output']['certificates_expiring']
        speech_output = "There are a total of {} certificates out of which {} will be expiring soon ".format(total_certificate,certificates_expiring)       
    elif(event['body']=="VulnerabilityDetails"):
        vulnerabilityDetails = getVulnerabilityDetails()
        totalVulnerableAssets = vulnerabilityDetails['data']['output']['totalVulnerableAssets']
        hosts = vulnerabilityDetails['data']['output']['hosts']
        vulnerabilities = vulnerabilityDetails['data']['output']['vulnerabilities']        
        speech_output = "There are a total of {} hosts and {} vulnerable assets ".format(hosts,totalVulnerableAssets)

    return {
        "body" : speech_output
    }
