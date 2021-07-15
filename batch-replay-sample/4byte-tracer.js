{
    ids : {},
    
    store: function(id, size) {
        var key = "" + toHex(id) + "-" + size;
        this.ids[key] = this.ids[key] + 1 || 1;
    },

    main: function(ct, log) {
        if (!ct) {
            return;
        }
        var inSz = log.stack.peek(ct+1).valueOf();
        if (inSz >= 4) {
            var inOff = log.stack.peek(ct).valueOf();
            this.store(log.memory.slice(inOff, inOff+4), inSz-4);
        }
    },

    call: function(log, db) {
        if (isPrecompiled(toAddress(log.stack.peek(1).toString(16)))) {
            return;
        }
        this.main(3, log);
    },

    callcode: function(log, db) {
        if (isPrecompiled(toAddress(log.stack.peek(1).toString(16)))) {
            return;
        }
        this.main(3, log);
    },

    delegatecall: function(log, db) {
        if (isPrecompiled(toAddress(log.stack.peek(1).toString(16)))) {
            return;
        }
        this.main(2, log);      
    },

    staticcall: function(log, db) {
        if (isPrecompiled(toAddress(log.stack.peek(1).toString(16)))) {
            return;
        }
        this.main(2, log);
    },

    transactionEnd: function(log, db) {
        return this.ids;
    },
}