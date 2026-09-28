// LibraryStore — holds the two required Android .so blobs
const REQUIRED_LIBS = [
    "libstoreservicescore.so",
    "libCoreADI.so",
];
export class LibraryStore {
    libs;
    constructor(libs) {
        this.libs = libs;
    }
    static fromBlobs(storeservicescore, coreadi) {
        const map = new Map();
        map.set("libstoreservicescore.so", storeservicescore);
        map.set("libCoreADI.so", coreadi);
        return new LibraryStore(map);
    }
    get(name) {
        const data = this.libs.get(name);
        if (!data)
            throw new Error(`Library not loaded: ${name}`);
        return data;
    }
    get storeservicescore() {
        return this.get("libstoreservicescore.so");
    }
    get coreadi() {
        return this.get("libCoreADI.so");
    }
}
//# sourceMappingURL=library.js.map