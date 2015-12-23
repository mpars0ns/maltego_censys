"""
This script is written by Mark Parsons and is to be used in Maltego to lookup SSL SHA1 certificates in Censys.io
Date: 12/22/2015
"""
import requests
import sys
import json
from MaltegoTransform import *


def main():
    mt = MaltegoTransform()
    sha1 = sys.argv[1]
    censys_uid = 'Enter_your_uid_here'
    censys_secret = 'Enter_your_uid_here'
    auth = (censys_uid, censys_secret)
    query = {'query': '443.https.tls.certificate.parsed.fingerprint_sha1: {s}'.format(s=sha1), 'fields': ['ip',
                                                                                                          'updated_at']}
    try:
        request = requests.post('https://www.censys.io/api/v1/search/ipv4', data=json.dumps(query), auth=auth)
        if request.status_code == 200:
            results = request.json()
            if results['metadata']['count'] > 0:
                for result in results['results']:
                    if 'ip' in result:
                        ip = result['ip']
                        updated = result['updated_at'][0]
                        newip = mt.addEntity("maltego.IPv4Address", ip)
                        newip.addAdditionalFields("property.last_updated", "Last updated time", True, updated)
                    else:
                        mt.addUIMessage("Hmm there is info on the SSL Hash but no ip info :( sadness")

            else:
                mt.addUIMessage("No IP addresses found with this ssl cert")
        if request.status_code == 400:
            results = request.json()
            mt.addUIMessage(str(results['error']))
        if request.status_code == 429:
            results = request.json()
            mt.addUIMessage(str(results['error']))
        if request.status_code == 404:
            mt.addUIMessage("No IP addresses found with this ssl cert")
        if request.status_code == 500:
            mt.addUIMessage("There has been a server error!!!")
        mt.returnOutput()

    except requests.exceptions.RequestException as e:
        mt.addUIMessage(str(e))
        mt.returnOutput()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print "User aborted."
