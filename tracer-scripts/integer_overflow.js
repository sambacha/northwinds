{
    commonVerification: function(log) {
        return toHex(log.contract.getSelfAddress()) in this.vicTokens
    },
    before: function(log) {
        this.source1 = log.stack.peek(0).valueOf()
        this.source2 = log.stack.peek(1).valueOf()
    },
    after: function(log) {
        taints = log.taint.peekStack(0)
        taintsLen = taints.length
        if (taintsLen == 0) {
            return
        }
        result = log.stack.peek(0).valueOf()
        if (result < this.source1 || result < this.source2) {
            newTaints = []
            for (i = 0; i < taintsLen; i++) {
                t = taints[i]
                if (t.length < 10) {
                    newTaints.push("overflow_"+t)
                } else {
                    newTaints.push(t)
                }
            }
            log.taint.clearStack(0)
            newTaintsLen = newTaints.length
            for (i = 0; i < newTaintsLen; i++) {
                log.taint.labelStack(0, newTaints[i])
            }
        }
    },

    transactionStart: function(log, db) {
        this.addrToInputIdToPc = {}
        this.addrToPcs = {}
        this.vicTokens = {}
        paraLen = log.params.length()
        for (i = 0; i < paraLen; i++) {
            this.vicTokens[log.params.get(i)] = true
        }
    },

    callStart: function(log, db) {
        if (!this.commonVerification(log)) {
            return
        }
        inputLen = log.contract.getInput().length
        inputId = 0
        for (i = 4; i < inputLen; i += 32) {
            log.taint.labelInput(i, 32, "arg"+inputId.toString())
            inputId ++
        }
    },

    add: function(log, db) {
        if (!this.commonVerification(log)) {
            return
        }
        this.before(log)
    },

    afterAdd: function(log, db) {
        if (!this.commonVerification(log)) {
            return
        }
        this.after(log)
    },

    mul: function(log, db) {
        if (!this.commonVerification(log)) {
            return
        }
        this.before(log)
    },

    afterMul: function(log, db) {
        if (!this.commonVerification(log)) {
            return
        }
        this.after(log)
    },

    jumpi: function(log, db) {
        if (!this.commonVerification(log)) {
            return
        }
        taints = log.taint.peekStack(1)
        taintsLen = taints.length
        if (taintsLen > 0) {
            pc = log.getPc()
            contract = toHex(log.contract.getSelfAddress())
            isJump = log.stack.peek(1).valueOf()
            for (i = 0; i < taintsLen; i++) {
                t = taints[i]
                if (t.length >= 10 && t.split("_")[0] == "overflow") {
                    inputId = t.split("_")[1]
                    if (!(contract in this.addrToInputIdToPc)) {
                        this.addrToInputIdToPc[contract] = {}
                    }
                    if (!(inputId in this.addrToInputIdToPc[contract])) {
                        this.addrToInputIdToPc[contract][inputId] = {}
                    }
                    if (!(pc in this.addrToInputIdToPc[contract][inputId])) {
                        this.addrToInputIdToPc[contract][inputId][pc] = isJump
                    }
                }
            }
        }
    },

    log: function(log, db) {
        if (!this.commonVerification(log)) {
            return
        }
        n = log.op.getN()
        if (n != 3) {
            return
        }
        eventSig = log.stack.peek(2).toString(16)
        if (eventSig != "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef") {
            return
        }
        offset = log.stack.peek(0).valueOf()
        size = log.stack.peek(1).valueOf()
        taints = log.taint.peekMemorySlice(offset, size)
        taintsLen = taints.length
        if (taintsLen > 0) {
            contract = toHex(log.contract.getSelfAddress())
            if (!(contract in this.addrToInputIdToPc)) {
                return
            }
            inputIdToPc = this.addrToInputIdToPc[contract]
            for (i = 0; i < taintsLen; i++) {
                t = taints[i]
                if (t in inputIdToPc) {
                    for (pc in inputIdToPc[t]) {
                        if (!(contract in this.addrToPcs)) {
                            this.addrToPcs[contract] = {}
                        }
                        if (!(pc in this.addrToPcs[contract])) {
                            this.addrToPcs[contract][pc] = inputIdToPc[t][pc]
                        }
                    }
                }
            }
        }
    },

    transactionEnd: function(log, db) {
        txnHash = toHex(log.getTxnHash())
        res = {}
        res["txnHash"] = txnHash
        res["pcs"] = this.addrToPcs
        return res
    }
}
