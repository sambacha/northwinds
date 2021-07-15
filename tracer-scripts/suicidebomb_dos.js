{
    transactionStart: function(log, db) {
        this.contractToCreatedAccounts = {}
    },
    
    selfdestruct: function(log, db) {
        caller = toHex(log.contract.getCaller())
        createdAccount = log.stack.peek(0).toString(16)
        if (!(caller in this.contractToCreatedAccounts)) {
            this.contractToCreatedAccounts[caller] = {}
        }
        this.contractToCreatedAccounts[caller][createdAccount] = true
    },

    transactionEnd: function(log, db) {
        res = {}
        txnHash = toHex(log.getTxnHash())
        for (contract in this.contractToCreatedAccounts) {
            cnt = 0
            for (createdAccount in this.contractToCreatedAccounts[contract]) {
                cnt ++
            }
            res[contract] = {}
            res[contract]['numberOfNewAccounts'] = cnt
            res[contract]['hash'] = txnHash
        }
        return res
    }
}