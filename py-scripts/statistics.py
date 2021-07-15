from elasticsearch import Elasticsearch

def get_empty_block_count(start, end):
    response = elastic.search(index="block", body={
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"Number": {"gte": start, "lte": end}}},
            {"range": {"TxnCount": {"lte": 0}}}
            ]}},
        "aggs": {"result": {"value_count": {
            "field": "Number"
        }}}
    })
    return response["aggregations"]["result"]["value"]


def get_transaction_count(start, end):
    response = elastic.search(index="block", body={
        "size": 0,
        "query": {"bool": {"filter": {
            "range": {"Number": {"gte": start, "lte": end}}
        }}},
        "aggs": {
            "normalCount": {"sum": {"field": "TxnCount"}},
            "nestedTransactions": {
                "nested": {"path": "Transactions"},
                "aggs": {"internalCount": {"sum": {"field": "Transactions.IntTxnCount"}}}
            }
        }})
    return response["aggregations"]

def get_txn_trend_for_each_day(start, end):
    response = elastic.search(index="block", body={
        "size": 0,
        "query": {"range": {"Number": {"gte": start, "lte": end}}},
        "aggs": {"txnTrend": {
            "date_histogram": {
                "field": "Timestamp",
                "calendar_interval": "1d"
            },
            "aggs": {
                "avgNormalCount": {"avg": {"field": "TxnCount"}},
                "nestedTransactions": {
                    "nested": {"path": "Transactions"},
                    "aggs": {"avgInternalCount": {"avg": {"field": "Transactions.IntTxnCount"}}}
                }}
            }
        }})
    return response["aggregations"]["txnTrend"]

def get_contract_count(start, end):
    response = elastic.search(index="code", body={
        "size": 0,
        "query": {"range": {"Number": {"gte": start, "lte": end}}},
        "aggs": {"nestedTransactions": {
            "nested": {"path": "Transactions"},
            "aggs": {"nestedContracts": {
                "nested": {"path": "Transactions.Contracts"},
                "aggs": {"contractCount": {"value_count": {"field": "Transactions.Contracts.Address"}}}
            }}
        }}
    })
    return response["aggregations"]["nestedTransactions"]["nestedContracts"]["contractCount"]["value"]

def get_account_count(start, end):
    response = elastic.search(index="state", body={
        "size": 0,
        "query": {"range": {"Number": {"gte": start, "lte": end}}},
        "aggs": {"result": {"scripted_metric": {
            "init_script": "state.transactions = []",
            "map_script": """
                for (t in params['_source']['Transactions']) {
                    state.transactions.add(t['Create'].getLength())
                }
            """,
            "combine_script": """
                int cnt = 0;
                for (t in state.transactions) {
                    cnt += t;
                }
                return cnt;
            """,
            "reduce_script": """
                int res = 0;
                for (s in states) {
                    res += s;
                }
                return res
            """
        }}}
    })
    return response["aggregations"]["result"]["value"]

elastic = Elasticsearch("http://127.0.0.1:9200", timeout=4000)
tc = get_transaction_count(1700000, 1750000)
print("There are %d empty blocks, %d normal transactions and %d internal transactions from 1700000 to 1750000."\
    % (get_empty_block_count(1700000, 1750000), tc["normalCount"]["value"], tc["nestedTransactions"]["internalCount"]["value"]))

cc = get_contract_count(0, 1750000)
ac = get_account_count(0, 1750000)
print("There are %d contracts and %d EOAs are created in the first 1.75m blocks" % (cc, ac - cc))