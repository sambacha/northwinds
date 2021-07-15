{
    transactionStart: function(log, db) {
        this.contracts = {}
    },

    callStart: function(log, db) {
        input = log.contract.getInput()
        inputLength = input.length
        log.taint.clearInput(0, inputLength)
    },

    // pseudo random number source
    afterBlockhash: function(log, db) {
        log.taint.labelStack(0, "blockhash")
    },
    
    afterCoinbase: function(log, db) {
        log.taint.labelStack(0, "coinbase")
    },

    afterTimestamp: function(log, db) {
        log.taint.labelStack(0, "timestamp")
    },

    afterNumber: function(log, db) {
        log.taint.labelStack(0, "number")
    },

    afterDifficulty: function(log, db) {
        log.taint.labelStack(0, "difficulty")
    },

    afterGaslimit: function(log, db) {
        log.taint.labelStack(0, "gaslimit")
    },

    // Comparison operations
    lt: function(log, db) {
        taints0 = log.taint.peekStack(0)
        taints0Len = taints0.length
        taints1 = log.taint.peekStack(1)
        taints1Len = taints1.length
        if (taints0Len < 2 && taints1Len < 2) {
            return
        }
        taints = taints0
        value = log.stack.peek(0).toString(16)
        taintsLen = taints0Len
        if (taints0Len < 2) {
            taints = taints1
            taintsLen = taints1Len
            value = log.stack.peek(1).toString(16)
        }
        tag = "randomness"
        for (i = 0; i < taintsLen; i++) {
            tag += "_"+taints[i]
        }
        tag += "_"+value
        log.taint.clearStack(0)
        log.taint.clearStack(1)
        log.taint.labelStack(0, tag)
    },

    gt: function(log, db) {
        this.lt(log, db)
    },

    slt: function(log, db) {
        this.lt(log, db)
    },

    sgt: function(log, db) {
        this.lt(log, db)
    },

    eq: function(log, db) {
        this.lt(log, db)
    },

    // Control decision
    jumpi: function(log, db) {
        taints = log.taint.peekStack(1)
        taintsLen = taints.length
        if (taintsLen == 0) {
            return
        }
        codeContract = toHex(log.contract.getCodeAddress())
        pc = log.getPc().toString()
        for (i = 0; i < taintsLen; i++) {
            tag = taints[i]
            if (tag.indexOf("randomness_") != -1) {
                lastIdx = tag.lastIndexOf("_")
                randomNumber = tag.substring(lastIdx+1)
                randomSources = {}
                j = 0
                nextIdx = tag.indexOf("_", j)
                while(nextIdx != lastIdx) {
                    endIdx = tag.indexOf("_", j+1)
                    randomSources[tag.substring(nextIdx+1, endIdx)] = true
                    j++
                    nextIdx = tag.indexOf("_", j)
                }
                this.contracts[codeContract] = {}
                this.contracts[codeContract][pc] = {"RandomNumber": randomNumber, "RandomSources": randomSources}
            }
        }
    },

    transactionEnd: function(log, db) {
        flag = false
        for (contracta in this.contracts) {
            for (pca in this.contracts[contracta]) {
                randomnessa = this.contracts[contracta][pca]
                for (contractb in this.contracts) {
                    if (contracta == contractb) {
                        continue
                    }
                    for (pcb in this.contracts[contractb]) {
                        randomnessb = this.contracts[contractb][pcb]
                        if (randomnessa["RandomNumber"] == randomnessb["RandomNumber"] && this.compareSources(randomnessa["RandomSources"], randomnessb["RandomSources"])) {
                            flag = true
                        }
                        // console.log(contracta, randomnessa)
                        // console.log(contractb, randomnessb)
                    }
                }
            }
        }
        contracts = []
        for (contract in this.contracts) {
            contracts.push(contract)
        }
        if (flag) {
            return {"Hash": toHex(log.getTxnHash()), "Contracts": contracts}
            // console.log(contracts)
        }
    },
    
    compareSources: function(source1Dict, source2Dict) {
        for (source in source1Dict) {
            if (!(source in source2Dict)) {
                return false
            }
        }
        return true
    }
}