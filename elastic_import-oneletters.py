#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import string
import itertools
from elasticsearch import Elasticsearch, helpers

INDEX = 'passwd'
INDEX_PREFIX = 'pwd_'
DOC_TYPE = 'account'

INDEX_CFG = {
    "settings": {
        "index": {
            #"number_of_shards": 8,
            "refresh_interval": -1,
            "number_of_replicas": 0
        },
        "analysis": {
            "filter": {
                "tld_filter": {
                    "type": "pattern_capture",
                    "preserve_original": False,
                    "patterns": ["\\.([^\\.]+?)$"]
                }
            },
            "analyzer": {
                "lc_analyzer": {
                    "type": "custom",
                    "tokenizer": "keyword",
                    "filter": ["lowercase"]
                },
                "user_analyzer": {
                    "type": "custom",
                    "tokenizer": "user_tokenizer",
                    "filter": ["lowercase"]
                },
                "domain_analyzer": {
                    "type": "custom",
                    "tokenizer": "domain_tokenizer",
                    "filter": ["lowercase"]
                },
                "domain_notld_analyzer": {
                    "type": "custom",
                    "tokenizer": "domain_notld_tokenizer",
                    "filter": ["lowercase"]
                },
                "tld_analyzer": {
                    "type": "custom",
                    "tokenizer": "tld_tokenizer",
                    "filter": ["lowercase"]
                }
            },
            "tokenizer": {
                "user_tokenizer": {
                    "type": "pattern",
                    "pattern": "(.+?)@",
                    "group": 1
                },
                "domain_tokenizer": {
                    "type": "pattern",
                    "pattern": "@(.+)",
                    "group": 1
                },
                "domain_notld_tokenizer": {
                    "type": "pattern",
                    "pattern": "@(.+)\\.",
                    "group": 1
                },
                "tld_tokenizer": {
                    "type": "pattern",
                    "pattern": "\\.([^\\.]+?)$",
                    "group": 1
                }
            },
            "normalizer": {
                "lc_normalizer": {
                    "type": "custom",
                    "char_filter": [],
                    "filter": ["lowercase"]
                }
            }
        }
    },
    "mappings": {
        DOC_TYPE: {
            "properties": {
                "email": {
                    "type": "text",
                    "analyzer": "simple",
                    "fields": {
                        "raw": {
                            "type": "keyword",
                            "normalizer": "lc_normalizer"
                        }
                    }
                },
                "username": {
                    "type": "text",
                    "analyzer": "simple",
                    "fields": {
                        "raw": {
                            "type": "keyword",
                            "normalizer": "lc_normalizer"
                        }
                    }
                },
                "domain": {
                    "type": "keyword",
                    "normalizer": "lc_normalizer"
                },
                "domain_notld": {
                    "type": "keyword",
                    "normalizer": "lc_normalizer"
                },
                "tld": {
                    "type": "keyword",
                    "normalizer": "lc_normalizer"
                },
                "password": {
                    "type": "text",
                    "analyzer": "simple",
                    "fields": {
                        "raw": {
                            "type": "keyword"
                        }
                    }
                },
                "password_length": {
                    "type": "short"
                },
                "source": {
                    "type": "short"
                }
            }
        }
    }
}


def parseCSV(csv_file):
    # schema: "email","username","domain","domain_notld","tld","password","source"
    count = 0
    with open(csv_file, 'r') as fd:
        for line in fd:
            count += 1
            if count % 100000 == 0:
                print('%s: %s' % (time.time(), count))
                sys.stdout.flush()
            if len(line) > 127:
                continue
            l_split = line.rstrip().split('","')
            if len(l_split) != 7:
                continue
            try:
                email = l_split[0][1:]
                username = l_split[1]
                domain = l_split[2]
                domain_notld = l_split[3]
                tld = l_split[4]
                password = l_split[5]
                password_length = len(password)
            except:
                continue
            try:
                source = int(l_split[6][:-1])
            except:
                source = None
            try:
                yield {
                    'email': email,
                    'username': username,
                    'domain': domain,
                    'domain_notld': domain_notld,
                    'tld': tld,
                    'password': password,
                    'password_length': password_length,
                    'source': source
                }
            except:
                continue


def run(csv_file):
    es = Elasticsearch()
    all_chars = string.ascii_lowercase + string.digits
    extras = '._-'
    indexes = set(itertools.chain(['misc'], all_chars))
    for x in list(indexes):
        if x.startswith(tuple(extras)):
            indexes.discard(x)
    for index in indexes:
        es.indices.delete(index=INDEX_PREFIX + index, ignore=[400, 404])
        es.indices.create(index=INDEX_PREFIX + index, body=INDEX_CFG, ignore=[400, 404])
        print('created index', INDEX_PREFIX + index)
        sys.stdout.flush()
    actions = (
        {'_index': '%s%s' % (INDEX_PREFIX, x['email'][:1].lower() if x['email'][:1].lower() in indexes else 'misc'),
         '_id': '%s%s' % (x['email'], x['password']),
         '_type': DOC_TYPE,
         '_source': x,
         'routing': x['email'].lower()
         }
               for x in parseCSV(csv_file))
    for ret in helpers.parallel_bulk(es, actions, chunk_size=60000, thread_count=6, request_timeout=480,
                                      raise_on_error=False, raise_on_exception=False):
        pass


if __name__ == '__main__':
    run(sys.argv[1])
