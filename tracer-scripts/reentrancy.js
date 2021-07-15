{
    transactionStart: function(log, db) {
        this.tagToCodeSequence = {}
        this.invocationID = -1
        this.currentInvocation = []
    },

    callStart: function(log, db) {
        this.invocationID ++
        this.currentInvocation.push(this.invocationID)
        callIdentifier = {}
        callIdentifier["Type"] = "CallStart"
        callIdentifier["EvmDepth"] = log.getDepth()
        callIdentifier["DirectCallee"] = toHex(log.contract.getCodeAddress())
        callIdentifier["DirectCaller"] = toHex(log.contract.getDirectCaller())
        callIdentifier["InvocationID"] = this.currentInvocation[this.currentInvocation.length-1]
        for (tag in this.tagToCodeSequence) {
            this.tagToCodeSequence[tag].push(callIdentifier)
        }
    },

    callEnd: function(log, db) {
        this.currentInvocation.pop()
    },

    afterSha3: function(log, db) {
        log.taint.labelStack(0, "SHA3")
    },

    sload: function(log, db) {
        taints = log.taint.peekStack(0)
        taintsLen = taints.length
        if (taintsLen == 0) {
            return
        }
        for (i = 0; i < taintsLen; i++) {
            if (taints[i] == "SHA3") {
                key = log.stack.peek(0).toString(16)
                contextContract = toHex(log.contract.getSelfAddress())
                tag = contextContract+"_"+key
                log.taint.clearStack(0)
                log.taint.labelStack(0, tag)
                break
            }
        }
    },

    call: function(log, db) {
        taints = log.taint.peekStack(2)
        taintsLen = taints.length
        if (taintsLen == 0) {
            return
        }
        value = log.stack.peek(2).valueOf()
        if (value == 0) {
            return
        }
        ethTransferIdentifier = {}
        ethTransferIdentifier["Type"] = "ETHTransfer"
        ethTransferIdentifier["EvmDepth"] = log.getDepth()
        ethTransferIdentifier["InvocationID"] = this.currentInvocation[this.currentInvocation.length-1]
        ethTransferIdentifier["DirectCallee"] = toHex(log.contract.getCodeAddress())
        ethTransferIdentifier["DirectCaller"] = toHex(log.contract.getDirectCaller())
        for (i = 0; i < taintsLen; i++) {
            tag = taints[i]
            if (!(tag in this.tagToCodeSequence)) {
                this.tagToCodeSequence[tag] = []
            }
            this.tagToCodeSequence[tag].push(ethTransferIdentifier)
        }
    },

    callcode: function(log, db) {
        this.call(log, db)
    },

    create: function(log, db) {
        this.call(log, db)
    },

    create2: function(log, db) {
        this.call(log, db)
    },

    jumpi: function(log, db) {
        taints = log.taint.peekStack(1)
        taintsLen = taints.length
        if (taintsLen == 0) {
            return
        }
        condIdentifier = {}
        condIdentifier["Type"] = "Cond"
        condIdentifier["EvmDepth"] = log.getDepth()
        condIdentifier["InvocationID"] = this.currentInvocation[this.currentInvocation.length-1]
        condIdentifier["DirectCallee"] = toHex(log.contract.getCodeAddress())
        condIdentifier["DirectCaller"] = toHex(log.contract.getDirectCaller())
        for (i = 0; i < taintsLen; i++) {
            tag = taints[i]
            if (!(tag in this.tagToCodeSequence)) {
                this.tagToCodeSequence[tag] = []
            }
            this.tagToCodeSequence[tag].push(condIdentifier)
        }
    },

    sstore: function(log, db) {
        key = log.stack.peek(0).toString(16)
        contextContract = toHex(log.contract.getSelfAddress())
        tag = contextContract+"_"+key
        resetIdentifier = {}
        resetIdentifier["Type"] = "Reset"
        resetIdentifier["EvmDepth"] = log.getDepth()
        resetIdentifier["InvocationID"] = this.currentInvocation[this.currentInvocation.length-1]
        resetIdentifier["DirectCallee"] = toHex(log.contract.getCodeAddress())
        resetIdentifier["DirectCaller"] = toHex(log.contract.getDirectCaller())
        if (tag in this.tagToCodeSequence) {
            this.tagToCodeSequence[tag].push(resetIdentifier)
        }
    },

    transactionEnd: function(log, db) {
        for (tag in this.tagToCodeSequence) {
            codeSequence = this.tagToCodeSequence[tag]
            length = codeSequence.length
            for (i = 0; i < length; i++) {
                startCode = codeSequence[i]
                if (startCode["Type"] == "Cond") {
                    startDepth = startCode["EvmDepth"]
                    startCallee = startCode["DirectCallee"]
                    startCaller = startCode["DirectCaller"]
                    // for debug
                    // callList = []
                    reenterInvocationIDs = {}
                    condInRee = false
                    resetInRee = false
                    for (j = i+1; j < length; j++) {
                        code = codeSequence[j]
                        // for debug
                        // callList.push(code)
                        if (code["Type"] == "CallStart") {
                            if (code["EvmDepth"] <= startDepth) {
                                break
                            }
                            if (code["DirectCallee"] == startCallee && code["DirectCaller"] == startCaller) {
                                reenterInvocationIDs[code["InvocationID"]] = true
                            }
                        } else if (code["Type"] == "Cond" && code["InvocationID"] in reenterInvocationIDs) {
                            condInRee = true
                        } else if (code["Type"] == "Reset" && code["InvocationID"] in reenterInvocationIDs) {
                            resetInRee = true
                        } else if (code["Type"] == "Reset" && condInRee && resetInRee) {
                            if (code["DirectCallee"] == startCallee && code["InvocationID"] == startCode["InvocationID"]) {
                                // for debug
                                // console.log(tag, startCode, code)
                                // for (z = 0; z < callList.length; z++) {
                                //     console.log(callList[z])
                                // }
                                return toHex(log.getTxnHash())
                            } else if (code["DirectCallee"] != startCallee && code["Invocation"] > startCode["InvocationID"]) {
                                // for debug
                                // console.log(tag, startCode, code)
                                // for (z = 0; z < callList.length; z++) {
                                //     console.log(callList[z])
                                // }
                                return toHex(log.getTxnHash())
                            }
                        }
                    }
                } else if (startCode["Type"] == "ETHTransfer") {
                    startDepth = startCode["EvmDepth"]
                    startCallee = startCode["DirectCallee"]
                    startCaller = startCode["DirectCaller"]
                    // for debug
                    // callList = []
                    reenterInvocationIDs = {}
                    isReenter = false
                    for (j = i+1; j < length; j++) {
                        code = codeSequence[j]
                        // for debug
                        // callList.push(code)
                        if (code["Type"] == "CallStart") {
                            if (code["EvmDepth"] <= startDepth) {
                                break
                            }
                            if (code["DirectCallee"] == startCallee && code["DirectCaller"] == startCaller) {
                                reenterInvocationIDs[code["InvocationID"]] = true
                            }
                        } else if (code["Type"] == "ETHTransfer" && code["InvocationID"] in reenterInvocationIDs) {
                            isReenter = true
                        }  else if (code["Type"] == "Reset" && isReenter) {
                            if (code["DirectCallee"] == startCallee && code["InvocationID"] == startCode["InvocationID"]) {
                                // for debug
                                // console.log(tag, startCode, code)
                                // for (z = 0; z < callList.length; z++) {
                                //     console.log(callList[z])
                                // }
                                return toHex(log.getTxnHash())
                            } else if (code["DirectCallee"] != startCallee && code["InvocationID"] > startCode["InvocationID"]) {
                                // for debug
                                // console.log(tag, startCode, code)
                                // for (z = 0; z < callList.length; z++) {
                                //     console.log(callList[z])
                                // }
                                return toHex(log.getTxnHash())
                            }
                        }
                    }
                }
            }
        }
    }
}