// vim: ts=4:sw=4

const BaseKeyType = require('./base_key_type');

const CLOSED_SESSIONS_MAX = 40;
const SESSION_RECORD_VERSION = 'v1';

function assertBuffer(value) {
    if (!Buffer.isBuffer(value)) {
        throw new TypeError("Buffer required");
    }
}


class SessionEntry {

    constructor() {
        this._chains = {};
        // Performance optimizations
        this._lastAccessed = Date.now();
        this._chainCount = 0;
        this._serializedCache = null;
        this._serializationVersion = 0;
    }

    toString() {
        const baseKey = this.indexInfo && this.indexInfo.baseKey &&
            this.indexInfo.baseKey.toString('base64');
        return `<SessionEntry [baseKey=${baseKey}]>`;
    }

    inspect() {
        return this.toString();
    }

    addChain(key, value) {
        assertBuffer(key);
        const id = key.toString('base64');
        if (this._chains.hasOwnProperty(id)) {
            throw new Error("Overwrite attempt");
        }
        this._chains[id] = value;
        this._chainCount++;
        this._lastAccessed = Date.now();
        this._invalidateCache();
    }

    getChain(key) {
        assertBuffer(key);
        this._lastAccessed = Date.now();
        return this._chains[key.toString('base64')];
    }

    hasChain(key) {
        assertBuffer(key);
        return this._chains.hasOwnProperty(key.toString('base64'));
    }

    deleteChain(key) {
        assertBuffer(key);
        const id = key.toString('base64');
        if (!this._chains.hasOwnProperty(id)) {
            throw new ReferenceError("Not Found");
        }
        delete this._chains[id];
        this._chainCount--;
        this._lastAccessed = Date.now();
        this._invalidateCache();
    }

    *chains() {
        for (const [k, v] of Object.entries(this._chains)) {
            yield [Buffer.from(k, 'base64'), v];
        }
    }

    // Performance helpers
    getChainCount() {
        return this._chainCount;
    }

    getLastAccessed() {
        return new Date(this._lastAccessed);
    }

    _invalidateCache() {
        this._serializedCache = null;
        this._serializationVersion++;
    }

    serialize() {
        // Use cache if available and valid
        if (this._serializedCache !== null) {
            return this._serializedCache;
        }

        const data = {
            registrationId: this.registrationId,
            currentRatchet: {
                ephemeralKeyPair: {
                    pubKey: this.currentRatchet.ephemeralKeyPair.pubKey.toString('base64'),
                    privKey: this.currentRatchet.ephemeralKeyPair.privKey.toString('base64')
                },
                lastRemoteEphemeralKey: this.currentRatchet.lastRemoteEphemeralKey.toString('base64'),
                previousCounter: this.currentRatchet.previousCounter,
                rootKey: this.currentRatchet.rootKey.toString('base64')
            },
            indexInfo: {
                baseKey: this.indexInfo.baseKey.toString('base64'),
                baseKeyType: this.indexInfo.baseKeyType,
                closed: this.indexInfo.closed,
                used: this.indexInfo.used,
                created: this.indexInfo.created,
                remoteIdentityKey: this.indexInfo.remoteIdentityKey.toString('base64')
            },
            _chains: this._serialize_chains(this._chains),
            // Performance metadata
            _lastAccessed: this._lastAccessed,
            _chainCount: this._chainCount,
            _serializationVersion: this._serializationVersion
        };
        if (this.pendingPreKey) {
            data.pendingPreKey = Object.assign({}, this.pendingPreKey);
            data.pendingPreKey.baseKey = this.pendingPreKey.baseKey.toString('base64');
        }

        // Cache the result
        this._serializedCache = data;
        return data;
    }

    static deserialize(data) {
        const obj = new this();
        obj.registrationId = data.registrationId;
        obj.currentRatchet = {
            ephemeralKeyPair: {
                pubKey: Buffer.from(data.currentRatchet.ephemeralKeyPair.pubKey, 'base64'),
                privKey: Buffer.from(data.currentRatchet.ephemeralKeyPair.privKey, 'base64')
            },
            lastRemoteEphemeralKey: Buffer.from(data.currentRatchet.lastRemoteEphemeralKey, 'base64'),
            previousCounter: data.currentRatchet.previousCounter,
            rootKey: Buffer.from(data.currentRatchet.rootKey, 'base64')
        };
        obj.indexInfo = {
            baseKey: Buffer.from(data.indexInfo.baseKey, 'base64'),
            baseKeyType: data.indexInfo.baseKeyType,
            closed: data.indexInfo.closed,
            used: data.indexInfo.used,
            created: data.indexInfo.created,
            remoteIdentityKey: Buffer.from(data.indexInfo.remoteIdentityKey, 'base64')
        };
        obj._chains = this._deserialize_chains(data._chains);
        if (data.pendingPreKey) {
            obj.pendingPreKey = Object.assign({}, data.pendingPreKey);
            obj.pendingPreKey.baseKey = Buffer.from(data.pendingPreKey.baseKey, 'base64');
        }

        // Restore performance metadata
        obj._lastAccessed = data._lastAccessed || Date.now();
        obj._chainCount = data._chainCount || Object.keys(obj._chains).length;
        obj._serializationVersion = data._serializationVersion || 0;
        obj._serializedCache = null; // Reset cache after deserialization

        return obj;
    }

    _serialize_chains(chains) {
        const r = {};
        for (const key of Object.keys(chains)) {
            const c = chains[key];
            const messageKeys = {};
            for (const [idx, key] of Object.entries(c.messageKeys)) {
                messageKeys[idx] = key.toString('base64');
            }
            r[key] = {
                chainKey: {
                    counter: c.chainKey.counter,
                    key: c.chainKey.key && c.chainKey.key.toString('base64')
                },
                chainType: c.chainType,
                messageKeys: messageKeys
            };
        }
        return r;
    }

    static _deserialize_chains(chains_data) {
        const r = {};
        for (const key of Object.keys(chains_data)) {
            const c = chains_data[key];
            const messageKeys = {};
            for (const [idx, key] of Object.entries(c.messageKeys)) {
                messageKeys[idx] = Buffer.from(key, 'base64');
            }
            r[key] = {
                chainKey: {
                    counter: c.chainKey.counter,
                    key: c.chainKey.key && Buffer.from(c.chainKey.key, 'base64')
                },
                chainType: c.chainType,
                messageKeys: messageKeys
            };
        }
        return r;
    }

}


const migrations = [{
    version: 'v1',
    migrate: function migrateV1(data) {
        const sessions = data._sessions;
        if (data.registrationId) {
            for (const key in sessions) {
                if (!sessions[key].registrationId) {
                    sessions[key].registrationId = data.registrationId;
                }
            }
        } else {
            for (const key in sessions) {
                if (sessions[key].indexInfo.closed === -1) {
                    console.error('V1 session storage migration error: registrationId',
                                  data.registrationId, 'for open session version',
                                  data.version);
                }
            }
        }
    }
}];


class SessionRecord {

    static createEntry() {
        return new SessionEntry();
    }

    static migrate(data) {
        let run = (data.version === undefined);
        for (let i = 0; i < migrations.length; ++i) {
            if (run) {
                console.info("Migrating session to:", migrations[i].version);
                migrations[i].migrate(data);
            } else if (migrations[i].version === data.version) {
                run = true;
            }
        }
        if (!run) {
            throw new Error("Error migrating SessionRecord");
        }
    }

    static deserialize(data) {
        if (data.version !== SESSION_RECORD_VERSION) {
            this.migrate(data);
        }
        const obj = new this();
        if (data._sessions) {
            for (const [key, entry] of Object.entries(data._sessions)) {
                obj.sessions[key] = SessionEntry.deserialize(entry);
            }
        }
        return obj;
    }

    constructor() {
        this.sessions = {};
        this.version = SESSION_RECORD_VERSION;
        
        // Performance optimizations - cache para operações frequentes
        this._openSessionCache = null;
        this._sortedSessionsCache = null;
        this._lastCleanup = Date.now();
        this._cleanupInterval = 5 * 60 * 1000; // 5 minutes
        this._batchOperations = [];
        this._batchSize = 10;
        this._performanceMetrics = {
            operationsCount: 0,
            cacheHits: 0,
            cacheMisses: 0,
            batchOperations: 0
        };
    }

    serialize() {
        // Processar operações em lote pendentes antes da serialização
        this._processBatchOperations();
        
        const _sessions = {};
        for (const [key, entry] of Object.entries(this.sessions)) {
            _sessions[key] = entry.serialize();
        }
        return {
            _sessions,
            version: this.version
        };
    }

    haveOpenSession() {
        this._performanceMetrics.operationsCount++;
        
        // Usar cache se disponível
        if (this._openSessionCache !== null) {
            this._performanceMetrics.cacheHits++;
            return this._openSessionCache !== false;
        }
        
        this._performanceMetrics.cacheMisses++;
        const openSession = this.getOpenSession();
        const result = (!!openSession && typeof openSession.registrationId === 'number');
        
        // Cache já foi definido em getOpenSession
        return result;
    }

    getSession(key) {
        assertBuffer(key);
        const session = this.sessions[key.toString('base64')];
        if (session && session.indexInfo.baseKeyType === BaseKeyType.OURS) {
            throw new Error("Tried to lookup a session using our basekey");
        }
        return session;
    }

    getOpenSession() {
        // Usar cache otimizado específico para sessão aberta
        if (this._openSessionCache !== null && this._openSessionCache !== false) {
            // Se temos uma sessão cached, verificar se ainda é válida
            if (typeof this._openSessionCache === 'object' && 
                !this.isClosed(this._openSessionCache)) {
                return this._openSessionCache;
            }
        }
        
        // Busca otimizada: parar no primeiro resultado
        for (const session of Object.values(this.sessions)) {
            if (!this.isClosed(session)) {
                this._openSessionCache = session; // Cache da sessão encontrada
                return session;
            }
        }
        
        this._openSessionCache = false; // Cache indicando que não há sessão aberta
        return null;
    }

    setSession(session) {
        const key = session.indexInfo.baseKey.toString('base64');
        this.sessions[key] = session;
        
        // Invalidar caches
        this._invalidateCaches();
        
        // Adicionar à operação de lote se aplicável
        this._addToBatch('setSession', { key, session });
    }

    getSessions() {
        this._performanceMetrics.operationsCount++;
        
        // Usar cache se disponível
        if (this._sortedSessionsCache !== null) {
            this._performanceMetrics.cacheHits++;
            return this._sortedSessionsCache;
        }
        
        this._performanceMetrics.cacheMisses++;
        
        // Return sessions ordered with most recently used first.
        const sorted = Array.from(Object.values(this.sessions)).sort((a, b) => {
            const aUsed = a.indexInfo.used || 0;
            const bUsed = b.indexInfo.used || 0;
            return aUsed === bUsed ? 0 : aUsed < bUsed ? 1 : -1;
        });
        
        // Cache do resultado
        this._sortedSessionsCache = sorted;
        return sorted;
    }

    closeSession(session) {
        if (this.isClosed(session)) {
            return;
        }
        
        session.indexInfo.closed = Date.now();
        this._invalidateCaches();
        this._addToBatch('closeSession', { session });
    }

    openSession(session) {
        if (!this.isClosed(session)) {
            return;
        }
        
        session.indexInfo.closed = -1;
        this._invalidateCaches();
        this._addToBatch('openSession', { session });
    }

    isClosed(session) {
        return session.indexInfo.closed !== -1;
    }

    removeOldSessions() {
        // Verificar se precisa fazer cleanup com base no intervalo
        const now = Date.now();
        if (now - this._lastCleanup < this._cleanupInterval) {
            return 0; // Skip cleanup se muito recente
        }
        
        let removedCount = 0;
        const sessionEntries = Object.entries(this.sessions);
        
        while (sessionEntries.length - removedCount > CLOSED_SESSIONS_MAX) {
            let oldestKey;
            let oldestSession;
            let oldestTime = Infinity;
            
            for (const [key, session] of sessionEntries) {
                if (session.indexInfo.closed !== -1 && session.indexInfo.closed < oldestTime) {
                    oldestKey = key;
                    oldestSession = session;
                    oldestTime = session.indexInfo.closed;
                }
            }
            
            if (oldestKey) {
                delete this.sessions[oldestKey];
                removedCount++;
                // Remove da lista para não processar novamente
                const index = sessionEntries.findIndex(([key]) => key === oldestKey);
                if (index !== -1) {
                    sessionEntries.splice(index, 1);
                }
            } else {
                break; // Não há mais sessões fechadas para remover
            }
        }
        
        if (removedCount > 0) {
            this._invalidateCaches();
            this._lastCleanup = now;
        }
        
        return removedCount;
    }

    deleteAllSessions() {
        const sessionCount = Object.keys(this.sessions).length;
        for (const key of Object.keys(this.sessions)) {
            delete this.sessions[key];
        }
        this._invalidateCaches();
        return sessionCount;
    }

    // ========== BATCH PROCESSING METHODS ==========

    /**
     * Adicionar múltiplas sessões de uma vez (otimizado)
     */
    setSessionsBatch(sessions) {
        const startTime = Date.now();
        
        for (const session of sessions) {
            const key = session.indexInfo.baseKey.toString('base64');
            this.sessions[key] = session;
        }
        
        // Invalidar caches uma única vez no final
        this._invalidateCaches();
        
        // Log da operação em lote
        this._performanceMetrics.batchOperations += sessions.length;
        
        return sessions.length;
    }

    /**
     * Fechar múltiplas sessões de uma vez
     */
    closeSessionsBatch(sessions) {
        const now = Date.now();
        let closedCount = 0;
        
        for (const session of sessions) {
            if (!this.isClosed(session)) {
                session.indexInfo.closed = now;
                closedCount++;
            }
        }
        
        if (closedCount > 0) {
            this._invalidateCaches();
        }
        
        return closedCount;
    }

    /**
     * Buscar múltiplas sessões por chaves (otimizado)
     */
    getSessionsBatch(keys) {
        const results = [];
        
        for (const key of keys) {
            const session = this.sessions[key.toString('base64')];
            if (session && session.indexInfo.baseKeyType !== BaseKeyType.OURS) {
                results.push(session);
            }
        }
        
        return results;
    }

    /**
     * Filtrar sessões por critérios (otimizado)
     */
    filterSessions(criteria) {
        const results = [];
        
        for (const session of Object.values(this.sessions)) {
            let matches = true;
            
            if (criteria.closed !== undefined) {
                const isClosed = this.isClosed(session);
                if (criteria.closed !== isClosed) {
                    matches = false;
                }
            }
            
            if (criteria.olderThan !== undefined) {
                const age = Date.now() - (session.indexInfo.created || 0);
                if (age < criteria.olderThan) {
                    matches = false;
                }
            }
            
            if (criteria.registrationId !== undefined) {
                if (session.registrationId !== criteria.registrationId) {
                    matches = false;
                }
            }
            
            if (matches) {
                results.push(session);
            }
        }
        
        return results;
    }

    // ========== PERFORMANCE OPTIMIZATION METHODS ==========

    /**
     * Invalidar todos os caches
     */
    _invalidateCaches() {
        this._openSessionCache = null;
        this._sortedSessionsCache = null;
    }

    /**
     * Adicionar operação ao lote para processamento em grupo
     */
    _addToBatch(operation, data) {
        this._batchOperations.push({ operation, data, timestamp: Date.now() });
        
        if (this._batchOperations.length >= this._batchSize) {
            this._processBatchOperations();
        }
    }

    /**
     * Processar operações em lote
     */
    _processBatchOperations() {
        if (this._batchOperations.length === 0) {
            return;
        }
        
        this._performanceMetrics.batchOperations += this._batchOperations.length;
        
        // Agrupar operações similares
        const groupedOps = {};
        for (const op of this._batchOperations) {
            if (!groupedOps[op.operation]) {
                groupedOps[op.operation] = [];
            }
            groupedOps[op.operation].push(op.data);
        }
        
        // Processar em grupos para melhor performance
        for (const [operation, dataList] of Object.entries(groupedOps)) {
            this._processBatchGroup(operation, dataList);
        }
        
        this._batchOperations = [];
    }

    /**
     * Processar um grupo de operações similares
     */
    _processBatchGroup(operation, dataList) {
        switch (operation) {
            case 'setSession':
                // Otimização para múltiplas sessões
                for (const { key, session } of dataList) {
                    // Operações de lote otimizadas aqui se necessário
                }
                break;
            case 'closeSession':
            case 'openSession':
                // Processamento em lote para abertura/fechamento
                break;
        }
    }

    /**
     * Limpar caches e operações pendentes
     */
    clearCache() {
        this._invalidateCaches();
        this._batchOperations = [];
        this._performanceMetrics = {
            operationsCount: 0,
            cacheHits: 0,
            cacheMisses: 0,
            batchOperations: 0
        };
    }

    /**
     * Obter estatísticas de desempenho
     */
    getStats() {
        const sessionCount = Object.keys(this.sessions).length;
        let closedCount = 0;
        let openCount = 0;
        
        for (const session of Object.values(this.sessions)) {
            if (this.isClosed(session)) {
                closedCount++;
            } else {
                openCount++;
            }
        }
        
        return {
            totalSessions: sessionCount,
            closedSessions: closedCount,
            openSessions: openCount,
            lastCleanup: this._lastCleanup,
            hasOpenSessionCache: this._openSessionCache !== null,
            hasSortedSessionsCache: this._sortedSessionsCache !== null,
            pendingBatchOperations: this._batchOperations.length,
            performanceMetrics: { ...this._performanceMetrics }
        };
    }

    /**
     * Get the total number of sessions
     */
    getSessionCount() {
        return Object.keys(this.sessions).length;
    }

    /**
     * Forçar processamento de operações pendentes
     */
    flushBatch() {
        this._processBatchOperations();
    }
}

module.exports = SessionRecord;
