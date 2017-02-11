"""Client library for the Recorded Future API.

"""

import json
import urllib
import urllib2
import httplib
import sys
import os
import copy

class RFAPI(object):
    """Provides simplified access to the Recorded Future API.

    Either supply a token to the constructor or set the environment variable RECFUT_TOKEN to your token.

    """
    _url = 'https://api.recordedfuture.com/query/?'
    _headers = {"Accept-encoding": "gzip"}
    _token = None

    def __init__(self, token=None):
        if not token:
            if 'RECFUT_TOKEN' not in os.environ:
                raise ValueError("Could not find environment variable RECFUT_TOKEN.")
            token = os.environ['RECFUT_TOKEN']
        self._token = token

    def query(self, q, tries_left=3):
        """Perform a standard query.

        Parameters
        ----------
        q : dict
            Your query.
        tries_left : int, optional
            Number of retries that should be attempted in case of server failures.

        """
        q = copy.deepcopy(q)
        q["token"] = self._token
        url_q = urllib.urlencode({"q":json.dumps(q)})

        try:
            data = urllib2.urlopen(self._url, data=url_q).read()
        except httplib.IncompleteRead as e:
            sys.stderr.write('Retrying...\nFailed query: {0}\nReturned partial result: {1}\n'.format(q, e.partial))
            if tries_left > 0:
                return self.query(q, tries_left-1)
            else:
                raise Exception("Max retries reached. IncompleteRead.")
        except Exception as e:
            raise Exception("Exception occurred during query:\nQuery was '{0}'\nException: {1}".format(q, e))

        if 'output' in q and q['output'].get('format', 'json') == 'csv':
            res = data
        else:
            res = json.loads(data)
            if res.get('status', '') == 'FAILURE':
                raise Exception("Server failure:\nQuery was '{0}'\nHTTP Status: {1}\tMessage: {2}".format(q, res.get('code','NONE'), res.get('error', 'NONE')))
        return res

    def paged_query(self, q, field=None, unique=False):
        """Generator for paged query results.

        Parameters
        ----------
        q : dict
            Your query.
        field : string, optional
            Dot-notation for getting specific fields.
        unique: bool, optional
            When using field, filter to unique values.

        """
        q = copy.deepcopy(q)
        seen = set()
        while True:
            res = self.query(q)
            for item in self._dot_index(field, res):
                if unique:
                    if item in seen:
                        continue
                    seen.add(item)
                yield item

            if 'next_page_start' not in res:
                break
            if 'instance' in q or 'reference' in q:
                key = 'instance' if 'instance' in q else 'reference'
                q[key]['page_start'] = res['next_page_start']
            elif 'source' in q:
                q['source']['page_start'] = res['next_page_start']
            elif 'entity' in q:
                # Special handling for entity queries.
                if len(res.get('entities', [])) == 0:
                    break
                q['entity']['page_start'] = res['next_page_start']
            else:
                raise Exception("Unable to page query. Unknown query type.")

    def batch_query(self, querylist):
        """Generator for combining query results for multiple queries.

        Parameters
        ----------
        querylist : list_like
            list of queries to be executed.

        """
        seen_references = set()
        for q in querylist:
            for res in self.paged_query(q):
                res['instances'] = [inst for inst in res['instances'] if inst['id'] not in seen_references]
                seen_references.update([inst['id'] for inst in res['instances']])
                yield res

    @staticmethod
    def _dot_index(index, data):
        """Internal method for indexing dicts by dot-notation.

        Parameters
        ----------
        index : string
            The dot-index.
        data : dict
            dict to index.

        """
        if index:
            for i in index.split('.'):
                data = map(lambda x : x[i], data) if type(data) == type([]) else data[i]
        return data if type(data) == type([]) else [data]

