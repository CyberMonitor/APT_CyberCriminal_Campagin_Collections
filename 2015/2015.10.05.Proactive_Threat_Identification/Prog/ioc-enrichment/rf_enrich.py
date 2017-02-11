""" Indicator of Compromise (IOC) enrichment script.

Prints resulting enrichment to stdout.
"""
import re
import sys
import json
import argparse

from RFAPI import RFAPI

ipv4_regexp = '^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
ipv6_regexp = '((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?'
idn_regexp = '^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$'
hash_regexp = '(^[0-9a-f]{32}$)|(^[0-9a-f]{40}$)|(^[0-9a-f]{64}$)|(^[0-9a-f]{128}$)'

class RFEnricher(object):
    pattern_to_ioc = {  
        '{0}|{1}'.format(ipv4_regexp, ipv6_regexp):
        {
            'data_group': 'EnrichIpAddress',
            'function': 'enriched-ip-address',
            'id_prefix': 'ip'
        },
        idn_regexp: {
            'data_group': 'EnrichInternetDomainName',
            'function': 'enriched-internet-domain-name',
            'id_prefix': 'idn'        
        },
        hash_regexp: {
            'data_group': 'EnrichHash',
            'function': 'enriched-hash',
            'id_prefix': 'hash'
        }
    }

    def __init__(self, token):
        self.rfapi = RFAPI(token)

    def enrich(self, iocs):
        sys.stderr.write('Enriching {0} IOC(s)...\n'.format(len(iocs)))
        enrichment = {}
        for ioc in iocs:
            for pattern, query_config in self.pattern_to_ioc.items():
                if not re.match(pattern, ioc):
                    continue
                sys.stderr.write('\tProcessing {0} : {1}... '.format(query_config['id_prefix'], ioc))
                enrichment[ioc] = self.query_enrich_ioc(ioc, query_config)
                sys.stderr.write('Done.\n')
                break
            else:
                sys.stderr.write('Unable to match "{0}" with any supported IOC type.\n'.format(ioc))
        return enrichment

    def get_entity_id(self, id_prefix, name):
        if id_prefix != 'hash': 
            return "{0}:{1}".format(id_prefix, name)
        res = self.rfapi.query({
            'entity': {
                'name': name,
                'type': 'Hash',
                'limit': 1
            }
        })
        if len(res.get('entities', [])) == 0:
            return None
        return res['entities'][0]


    def query_enrich_ioc(self, text, query_config):
        entity_id = self.get_entity_id(query_config['id_prefix'], text)
        if not entity_id:
            return "No enrichment available."
        q = {
          "cluster": {
            "function": query_config['function'],
            "attributes": [
              {
                "entity": {
                  "id": entity_id
                }
              }
            ],
            "limit": 1,
            "data_group": query_config['data_group']
          },
          "output": {
            "inline_entities": True
          }
        }
        res = self.rfapi.query(q)
        if res['count']['events']['total'] == 0:
            return "No enrichment available."
        enr_data = res['events'][0]['stats']
        enr_data['rf_link'] = 'https://www.recordedfuture.com/live/sc/entity/' + entity_id
        return enr_data

def parse_args():
    parser = argparse.ArgumentParser(description="Recorded Future indicator enrichment")
    parser.add_argument('-f', action='store_true', default=False,
                        dest='is_file',
                        help='Read new-line separated IOCs from file')
    parser.add_argument('file_or_ioc', action='store', help='IOC to enrich (or file containing IOCs if -f is supplied)')
    parser.add_argument('-t', action="store", dest='token', default=None, help='Recorded Future API token. (default is read from the environment variable RECFUT_TOKEN)')
    arg_res = parser.parse_args()

    iocs = set()
    if arg_res.is_file:
        with open(arg_res.file_or_ioc) as f:
            for l in f:
                ioc = l.replace('\n', '').strip().lower()
                if len(ioc) > 0:
                    iocs.add(ioc)
    else:
        iocs.add(arg_res.file_or_ioc.lower())
    return iocs, arg_res.token

if __name__ == '__main__':
    iocs, token = parse_args()
    enrichment = RFEnricher(token).enrich(iocs)
    print json.dumps(enrichment, None, indent=2)







