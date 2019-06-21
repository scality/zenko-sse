const { storage } = require('arsenal');
const { metadata } = storage.metadata.inMemory.metadata;
const { resetCount, ds } = storage.data.inMemory.datastore;

function cleanup() {
    metadata.buckets = new Map;
    metadata.keyMaps = new Map;
    // Set data store array back to empty array
    ds.length = 0;
    // Set data store key count back to 1
    resetCount();
}

module.exports = {
    cleanup,
};
