{
    transactionStart: function(log, db) {
        this.contractToTime = {}
    },
    
    extcodesize: function(log, db) {
        codeContract = toHex(log.contract.getCodeAddress())
        account = log.stack.peek(0).toString(16)
        if (!(codeContract in this.contractToTime)) {
            this.contractToTime[codeContract] = {}
        }
        this.contractToTime[codeContract][account] = true
    },

    transactionEnd: function(log, db) {
        res = {}
        txnHash = toHex(log.getTxnHash())
        for (contract in this.contractToTime) {
            res[contract] = {}
            res[contract]['executions'] = Object.keys(this.contractToTime[contract]).length
            res[contract]['hash'] = txnHash
        }
        return res
    }
}