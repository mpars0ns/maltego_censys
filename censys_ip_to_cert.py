"""
This script is written by Mark Parsons and is to be used in Maltego to lookup IP addresses in Censys.io and look for
ssl certificates
Date: 12/22/2015
This assumes this script is first, uid is second, secreted is third, ip is fourth and the related object is 5th
"""
import requests
import json
from MaltegoTransform import *


def main():
    mt = MaltegoTransform()
    if len(sys.argv) != 5:
        mt.addException("You appear to be missing your uid and secret. Here is what was in your path: {s}".format(
            s=sys.argv))
        mt.throwExceptions()
    censys_uid = sys.argv[1]
    censys_secret = sys.argv[2]
    ip = sys.argv[3]
    auth = (censys_uid, censys_secret)
    page = 1
    query = {'query': 'ip: {ip}'.format(ip=ip), 'fields': ['443.https.tls.certificate.parsed.fingerprint_sha1',
                                                           '443.https.tls.certificate.parsed.issuer_dn',
                                                           '443.https.tls.certificate.parsed.subject_dn',
                                                           'updated_at'], 'page': page}
    try:
        request = requests.post('https://www.censys.io/api/v1/search/ipv4', data=json.dumps(query), auth=auth)
        if request.status_code == 200:
            results = request.json()
            pages = results['metadata']['pages']
            if results['metadata']['count'] > 0:
                parse_results(results['results'], mt)
                if pages > 1 > 4:
                    mt.addUIMessage("Found more than one page. Getting up to the first 100 results")
                    for i in range(2, 5):
                        page = i
                        query['page'] = page
                        request = requests.post('https://www.censys.io/api/v1/search/ipv4', data=json.dumps(query),
                                                auth=auth)
                        if request.status_code == 200:
                            results = request.json()
                            if results['metadata']['count'] > 0:
                                parse_results(results['results'], mt)
                        else:
                            if request.status_code == 400:
                                results = request.json()
                                mt.addException(str(results['error']))
                            if request.status_code == 429:
                                results = request.json()
                                mt.addException(str(results['error']))
                            if request.status_code == 404:
                                mt.addException("No info found")
                            if request.status_code == 500:
                                mt.addException("There has been a server error!!!")
                if pages < 5 > 1:
                    for i in range(2, pages):
                        page = i
                        query['page'] = page
                        request = requests.post('https://www.censys.io/api/v1/search/ipv4', data=json.dumps(query),
                                                auth=auth)
                        if request.status_code == 200:
                            results = request.json()
                            if results['metadata']['count'] > 0:
                                parse_results(results['results'], mt)
                        else:
                            if request.status_code == 400:
                                results = request.json()
                                mt.addException(str(results['error']))
                            if request.status_code == 429:
                                results = request.json()
                                mt.addException(str(results['error']))
                            if request.status_code == 404:
                                mt.addException("No info found")
                            if request.status_code == 500:
                                mt.addException("There has been a server error!!!")
            else:
                mt.addUIMessage("No SSL certs were found on this ip: {ip}".format(ip=ip))
            mt.returnOutput()
        else:
            if request.status_code == 400:
                results = request.json()
                mt.addException(str(results['error']))
            if request.status_code == 429:
                results = request.json()
                mt.addException(str(results['error']))
            if request.status_code == 404:
                mt.addException("No SSL certs were found on this ip: {ip}".format(ip=ip))
            if request.status_code == 500:
                mt.addException("There has been a server error!!!")
            mt.throwExceptions()

    except requests.exceptions.RequestException as e:
        mt.addException(str(e))
        mt.throwExceptions()


def parse_results(results, mt):
    for result in results:
        if '443.https.tls.certificate.parsed.fingerprint_sha1' in result:
            sha1 = result['443.https.tls.certificate.parsed.fingerprint_sha1'][0]
            issuer = result['443.https.tls.certificate.parsed.issuer_dn'][0]
            subject = result['443.https.tls.certificate.parsed.subject_dn'][0]
            updated = result['updated_at'][0]
            sslcert = mt.addEntity("censys.sslcertificate", sha1)
            sslcert.addAdditionalFields("property.issuer", "Cert Issuer", True, issuer)
            sslcert.addAdditionalFields("property.subject", "Cert Subject", True, subject)
            sslcert.addAdditionalFields("property.last_updated", "Last updated time", True, updated)
        else:
            mt.addUIMessage("Hmm there is info on the IP but not ssl :( ")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print "User aborted."
