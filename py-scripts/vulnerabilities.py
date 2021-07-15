from elasticsearch import Elasticsearch

def short_address_attack(elastic, start, end):
    response = elastic.search(index="block", body={
        "size": 0,
        "query": {"bool": {"filter": {"range": {"Number": {"gte": start, "lt": end}}}}},
        "aggs": {"result": {"scripted_metric": {
            "init_script": """
                state.results = new HashMap();
                state.results['malsToTxns'] = new HashMap();
                state.results['victims'] = [];
                state.results['tokens'] = [];
            """,
            "map_script": """
                void getX(Map funcSigs, Map tokenToX, Map txn) {
                    if (funcSigs.containsKey(txn['CallFunction'])) {
                    int x = funcSigs.get(txn['CallFunction']) - txn['CallParameter'].length();
                    if (x > 0 && x < 64) {
                        tokenToX.put(txn['ToAddress'].toLowerCase(), x);
                    }
                    }
                }
                String repeatX(int x) {
                    String res = "";
                    for (int i = 0; i < x; i++) {
                    res += "0";
                    }
                    return res;
                }
                void putTarget(Map malsToTxns, String address, String transaction) {
                    if (!malsToTxns.containsKey(address)) {
                    List temp = [];
                    malsToTxns.put(address, temp);
                    }
                    if (!malsToTxns.get(address).contains(transaction)) {
                    malsToTxns.get(address).add(transaction);
                    }
                }
                for (t in params['_source']['Transactions']) {
                    Map tokenToX = new HashMap();
                    getX(params['FuncSigs'], tokenToX, t);
                    for (it in t['InternalTxns']) {
                    getX(params['FuncSigs'], tokenToX, it);
                    }
                    if (!tokenToX.isEmpty()) {
                    for (log in t['Logs']) {
                        if (tokenToX.containsKey(log['Address'].toLowerCase()) && log['Topics'].getLength() == 3 && log['Topics'][0] == params['TransferSig']) {
                        String suffix = repeatX(tokenToX.get(log['Address']));
                        if (log['Topics'][2].endsWith(suffix) && log['Data'].endsWith(suffix) && log['Data'] != "0x0000000000000000000000000000000000000000000000000000000000000000") {
                            putTarget(state.results['malsToTxns'], "0x"+log['Topics'][2].substring(26), t['Hash']);
                            state.results['victims'].add("0x"+log['Topics'][1].substring(26));
                            state.results['tokens'].add(log['Address'].toLowerCase());
                        }
                        }
                    }
                    }
                }
            """,
            "combine_script": "return state.results;",
            "reduce_script": """
                Map res = new HashMap();
                res['malsToTxns'] = new HashMap();
                Set tokenSet = new HashSet();
                Set victimSet = new HashSet();
                for (s in states) {
                    for (malContract in s['malsToTxns'].keySet()) {
                    if (res['malsToTxns'].containsKey(malContract)) {
                        res['malsToTxns'].get(malContract).addAll(s['malsToTxns'].get(malContract));
                    } else {
                        res['malsToTxns'].put(malContract, s['malsToTxns'].get(malContract));
                    }
                    }
                    tokenSet.addAll(s['tokens']);
                    victimSet.addAll(s['victims']);
                }
                res['tokens'] = tokenSet.asList();
                res['victims'] = victimSet.asList();
                return res;
            """,
            "params": {
                "FuncSigs": {"0xa9059cbb": 130, "0x23b872dd": 194},
                "TransferSig": "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
            }
        }}}
    })
    return response["aggregations"]["result"]["value"]

def extcodesize_dos_attack(elastic, start, end):
    response = elastic.search(index="block", body={
        "size": 0,
        "query": {"bool": {"filter": {"range": {"Number": {"gte": start, "lt": end}}}}},
        "aggs": {"result": {"scripted_metric": {
            "init_script": "state.transactions = [];",
            "map_script": """
                for (t in params['_source']['Transactions']) {
                    int time = 0;
                    for (rcs in t['ReadCommittedState']) {
                    if (rcs['CodeSize'] != -1) {
                        time ++;
                    }
                    }
                    if (time > params['Threshold']) {
                        state.transactions.add(t['Hash']);
                    }
                }
            """,
            "combine_script": "return state.transactions;",
            "reduce_script": """
                List res = [];
                for (s in states) {
                    res.addAll(s)
                }
                return res;
            """,
            "params": {
                "Threshold": 100
            }
        }}}
    })
    return response["aggregations"]["result"]["value"]

def suicide_bomb_dos_attack(elastic, start, end):
    response = elastic.search(index="state", body={
        "size": 0,
        "query": {"bool": {"filter": {"range": {"Number": {"gte": start, "lt": end}}}}},
        "aggs": {"result": {"scripted_metric": {
            "init_script": "state.transactions = [];",
            "map_script": """
                for (t in params['_source']['Transactions']) {
                    int creationCnt = t['Create'].getLength();
                    int suicideCnt = t['Suicide'].getLength();
                    if (suicideCnt > 0 && creationCnt > params['Threshold']) {
                    state.transactions.add(t['Hash']);
                    }
                }
            """,
            "combine_script": "return state.transactions;",
            "reduce_script": """
                List res = [];
                for (s in states) {
                    res.addAll(s);
                }
                return res;
            """,
            "params": {
                "Threshold": 100
            }
        }}}
    })
    return response["aggregations"]["result"]["value"]

def airdrop_attack(elastic, start, end):
    response = elastic.search(index="block", body={
        "size": 0,
        "query": {"bool": {"filter": {"range": {"Number": {"gte": start, "lt": end}}}}},
        "aggs": {"result": {"scripted_metric": {
            "init_script": "state.malsToVicsAndTxnsAndTime = new HashMap();",
            "map_script": """
                for (t in params['_source']['Transactions']) {
                    Map createdAddrs = new HashMap();
                    for (it in t['InternalTxns']) {
                    if (it['Type'] == 240) {
                        createdAddrs.put(it['ConAddress'].toLowerCase(), true);
                    }
                    }
                    Set victims = new HashSet();
                    int time = 0;
                    for (log in t['Logs']) {
                    if (log['Topics'].getLength() == 3 && log['Topics'][0] == params['TransferSig']) {
                        String tokenAddr = log['Address'].toLowerCase();
                        String fromAddr = "0x" + log['Topics'][1].substring(26);
                        String toAddr = "0x" + log['Topics'][2].substring(26);
                        if (createdAddrs.containsKey(toAddr) && fromAddr != params['ZeroAddress']) {
                        createdAddrs[toAddr] = false;
                        }
                        if (createdAddrs.containsKey(fromAddr) && createdAddrs[fromAddr] && fromAddr != tokenAddr) {
                        victims.add(tokenAddr);
                        createdAddrs[fromAddr] = false;
                        time ++;
                        }
                    }
                    }
                    if (!victims.isEmpty()) {
                    String malAddr;
                    if (t['ToAddress'].length() > 0) {
                        malAddr = t['ToAddress'];
                    } else {
                        malAddr = t['ConAddress'];
                    }
                    if (!state.malsToVicsAndTxnsAndTime.containsKey(malAddr)) {
                        Map temp = new HashMap();
                        List temp1 = [];
                        List temp2 = [];
                        temp.put('vicTokens', temp1);
                        temp.put('malTxns', temp2);
                        temp.put('time', 0);
                        state.malsToVicsAndTxnsAndTime.put(malAddr, temp);
                    }
                    state.malsToVicsAndTxnsAndTime[malAddr]['vicTokens'].addAll(victims);
                    state.malsToVicsAndTxnsAndTime[malAddr]['malTxns'].add(t['Hash']);
                    state.malsToVicsAndTxnsAndTime[malAddr]['time'] += time;
                    }
                }
            """,
            "combine_script": "return state.malsToVicsAndTxnsAndTime;",
            "reduce_script": """
                Map res = new HashMap();
                for (malsToVicsAndTxnsAndTime in states) {
                    for (malAddr in malsToVicsAndTxnsAndTime.keySet()) {
                    if (res.containsKey(malAddr)) {
                        res[malAddr]['vicTokens'].addAll(malsToVicsAndTxnsAndTime[malAddr]['vicTokens']);
                        res[malAddr]['malTxns'].addAll(malsToVicsAndTxnsAndTime[malAddr]['malTxns']);
                        res[malAddr]['time'] += malsToVicsAndTxnsAndTime[malAddr]['time'];
                    } else {
                        res.put(malAddr, malsToVicsAndTxnsAndTime[malAddr]);
                    }
                    }
                }
                for (malAddr in res.keySet()) {
                    Set temp = new HashSet(res[malAddr]['vicTokens'].asCollection());
                    res[malAddr]['vicTokens'] = temp.asList();
                }
                return res;
            """,
            "params": {
                "TransferSig": "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                "ZeroAddress": "0x0000000000000000000000000000000000000000"
            }
        }}}
    })
    return response["aggregations"]["result"]["value"]

def integer_overflow(elastic, start, end):
    response = elastic.search(index="block", body={
        "size": 0,
        "query": {"bool": {"filter": {"range": {"Number": {"gte": start, "lt": end}}}}},
        "aggs": {"result": {"scripted_metric": {
            "init_script": "state.TxnsToVics = new HashMap();",
            "map_script": """
                String repeatX(int x) {
                    String res = "";
                    for (int i = 0; i < x; i++) {
                    res += "0";
                    }
                    return res;
                }
                for (t in params['_source']['Transactions']) {
                    Set vicTokens = new HashSet();
                    for (log in t['Logs']) {
                    if (log['Topics'].getLength() == 3 && log['Topics'][0] == params['TransferSig']) {
                        String value = log['Data'];
                        if (value.length() > 0 && value.substring(0, 34) != '0x'+repeatX(params['Threshold'])) {
                        vicTokens.add(log['Address'].toLowerCase());
                        }
                    }
                    }
                    if (!vicTokens.isEmpty()) {
                    state.TxnsToVics.put(t['Hash'], vicTokens.asList());
                    }
                }
            """,
            "combine_script": "return state.TxnsToVics;",
            "reduce_script": """
                Map res = new HashMap();
                for (s in states) {
                    res.putAll(s);
                }
                return res
            """,
            "params": {
                "Threshold": 32,
                "TransferSig": "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
            }
        }}}
    })
    return response["aggregations"]["value"]

def reentrancy(elastic, start, end):
    response = elastic.search(index="block", body={
        "size": 0,
        "query": {"bool": {"filter": {"range": {"Number": {"gte": start, "lt": end}}}}},
        "aggs": {"result": {"scripted_metric": {
            "init_script": "state.reenterPointToTxns = new HashMap();",
            "map_script": """
                for (t in params['_source']['Transactions']) {
                    boolean isTransfer;
                    boolean isReenter;
                    String reenterPoint;
                    for (int i = 0; i < t['IntTxnCount']; i++) {
                    Map it = t['InternalTxns'][i];
                    if (it['Type'] != 241 && it['Type'] != 250) {
                        continue;
                    }
                    String enterPoint;
                    enterPoint = it['ToAddress'].toLowerCase();
                    int startDepth = it['EvmDepth'];
                    isReenter = false;
                    for (int j = i+1; j < t['IntTxnCount']; j++) {
                        Map jt = t['InternalTxns'][j];
                        if (jt['EvmDepth'] <= startDepth) {
                        break;
                        }
                        if (jt['ToAddress'].toLowerCase() == enterPoint && jt['FromAddress'].toLowerCase() == it['FromAddress'].toLowerCase()) {
                        isReenter = true;
                        reenterPoint = enterPoint;
                        break;
                        }
                    }
                    if (isReenter) {
                        break;
                    }
                    }
                    for (int i = 0; i < t['IntTxnCount']; i++) {
                    Map it = t['InternalTxns'][i];
                    if (it['Value'].length() > 0 && it['Value'] != "0") {
                        isTransfer = true;
                    }
                    }
                    for (log in t['Logs']) {
                    if (log['Topics'].getLength() == 3 && log['Topics'][0] == params['TransferSig']) {
                        isTransfer = true;
                    }
                    }
                    if (isTransfer && isReenter) {
                    if (!state.reenterPointToTxns.containsKey(reenterPoint)) {
                        List temp = [];
                        state.reenterPointToTxns.put(reenterPoint, temp);
                    }
                    state.reenterPointToTxns[reenterPoint].add(t['Hash']);
                    }
                }
            """,
            "combine_script": "return state.reenterPointToTxns;",
            "reduce_script": """
                Map res = new HashMap();
                for (reenterPointToTxns in states) {
                    for (reenterPoint in reenterPointToTxns.keySet()) {
                    if (res.containsKey(reenterPoint)) {
                        res[reenterPoint].addAll(reenterPointToTxns[reenterPoint]);
                    } else {
                        res.put(reenterPoint, reenterPointToTxns[reenterPoint]);
                    }
                    }
                }
                return res;
            """,
            "params": {
                "TransferSig": "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
            }
        }}}
    })
    print("Querying costs %dh %dm %ds" % (response["took"]/3600000, response["took"]%3600000/60000, response["took"]%60000/1000))
    return response["aggregations"]["result"]["value"]

def bad_randomness(elastic, start, end):
    response = elastic.search(index="block", body={
        "size": 0,
        "query": {"bool": {"filter": {"range": {"Number": {"lt": start, "gte": end}}}}},
        "aggs": {"result": {"scripted_metric": {
            "init_script": "state.transactions = []",
            "map_script": """
                int number = params['_source']['Number'];
                for (t in params['_source']['Transactions']) {
                    int cnt = 0;
                    for (it in t['InternalTxns']) {
                    if (it['Value'].length() > 0 && it['Value'] != '0') {
                        cnt ++;
                    }
                    if (cnt == 2) {
                        state.transactions.add(t['Hash']);
                        break;
                    }
                    }
                }
            """,
            "combine_script": "return state.transactions",
            "reduce_script": """
                List res = [];
                for (s in states) {
                    res.addAll(s);
                }
                return res;
            """
        }}}
    })
    return response["aggregations"]["result"]["value"]

