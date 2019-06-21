module.exports = {
    backends: {
        file: require('./lib/backends/file'),
        inMemory: require('./lib/backends/inMemory').backend,
    },
    kms: require('./lib/KMS'),
};
