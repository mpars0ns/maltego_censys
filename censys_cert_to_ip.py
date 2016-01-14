"""
This script is written by Mark Parsons and is to be used in Maltego to lookup SSL SHA1 certificates in Censys.io
Date: 12/22/2015
This assumes this script is first, uid is second, secreted is third, sha1 is fourth and the related object is 5th
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
    sha1 = sys.argv[3]
    censys_uid = sys.argv[1]
    censys_secret = sys.argv[2]
    auth = (censys_uid, censys_secret)
    page = 1
    query = {'query': '443.https.tls.certificate.parsed.fingerprint_sha1: {s}'.format(s=sha1),
             'fields': ['ip', '443.https.tls.certificate.parsed.subject.common_name.raw',
                        '443.https.tls.certificate.parsed.issuer.common_name.raw', 'updated_at'], 'page': page}
    try:
        request = requests.post('https://www.censys.io/api/v1/search/ipv4', data=json.dumps(query), auth=auth)
        if request.status_code == 200:
            results = request.json()
            pages = results['metadata']['pages']
            if results['metadata']['count'] > 0:
                process_results(results['results'], mt)
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
                                process_results(results['results'], mt)
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
                                process_results(results['results'], mt)
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
                mt.addUIMessage("No IP addresses found with this ssl cert")
            mt.returnOutput()
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
            mt.throwExceptions()
    except requests.exceptions.RequestException as e:
        mt.addException(str(e))
        mt.throwExceptions()


def process_results(results, mt):
    for result in results:
        if 'ip' in result:
            ip = result['ip']
            updated = result['updated_at'][0]
            if '443.https.tls.certificate.parsed.subject.common_name.raw' in result:
                subject = result['443.https.tls.certificate.parsed.subject.common_name.raw'][0]
                mt.addEntity("censys.subjectcn", subject)
            if '443.https.tls.certificate.parsed.issuer.common_name.raw' in result:
                issuer = result['443.https.tls.certificate.parsed.issuer.common_name.raw'][0]
                mt.addEntity("censys.issuercn", issuer)

            newip = mt.addEntity("maltego.IPv4Address", ip)

            newip.addAdditionalFields("property.last_updated", "Last updated time", True, updated)
        else:
            mt.addUIMessage("Hmm there is info on the SSL Hash but no ip info :( sadness")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print "User aborted."
