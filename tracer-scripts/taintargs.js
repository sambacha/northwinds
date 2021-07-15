{
    transactionStart: function(log, db) {
        console.log("\nTransaction:", toHex(log.getTxnHash()))
    },

    callStart: function(log, db) {
        inputs = toHex(log.contract.getInput()).substring(2)
        console.log("Callee: ", toHex(log.contract.getSelfAddress()) ,"Inputs:", inputs)
        n = inputs.length
        for (i = 8; i < n; i += 64) {
            log.taint.labelInput(i/2, 32, inputs.substr(i, 64))
        }
    },

    sstore: function(log, db) {
        key = log.stack.peek(0).toString(16)
        value = log.stack.peek(1).toString(16)
        taints = log.taint.peekStack(1)
        taintsLen = taints.length
        if (taintsLen > 0) {
            for (i = 0; i < taintsLen; i++) {
                t = taints[i]
                console.log("Key: ", key, "Value: ", value, "Arg:", t)
            }
        } else {
            console.log("Key: ", key, "Value: ", value)
        }
    }
}