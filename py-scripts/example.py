from vulnerabilities import reentrancy
from elasticsearch import Elasticsearch
import json, subprocess

elastic = Elasticsearch("http://127.0.0.1:9200", timeout=4000)

# Step 1
reenterpoint_to_txns = reentrancy(elastic, 1700000, 1750000)
suspicious_transactions = []
transaction_to_rp = {}
for rp, txns in reenterpoint_to_txns.items():
    suspicious_transactions.extend(txns)
    for txn in txns:
        transaction_to_rp[txn] = rp
with open("./suspicious.json", "w") as f:
    f.write(json.dumps(suspicious_transactions, indent=4))

# Step 2
f = subprocess.Popen("replay Transactions --ipsfile /usr/share/elasticsearch/batch-replay-sample/cluster-hosts.json --tracer /usr/share/elasticsearch/tracer-scripts/reentrancy.js --result ./tmpresult --progress ./suspicious.json", shell=True)
f.wait()
result = {}
with open("./tmpresult") as f:
    for each_line in f.readlines():
        transaction = each_line.strip().strip('"')
        rp = transaction_to_rp[transaction]
        if rp not in result:
            result[rp] = []
        result[rp].append(transaction)
with open("./result.json", "w") as f:
    f.write(json.dumps(result, indent=4))

subprocess.Popen("rm ./suspicious.json", shell=True)
subprocess.Popen("rm ./tmpresult", shell=True)

print("\nDetection completed. Results are stored in result.json")
