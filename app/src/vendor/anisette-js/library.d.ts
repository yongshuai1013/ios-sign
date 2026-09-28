declare const REQUIRED_LIBS: readonly ["libstoreservicescore.so", "libCoreADI.so"];
export type LibraryName = (typeof REQUIRED_LIBS)[number];
export declare class LibraryStore {
    private libs;
    private constructor();
    static fromBlobs(storeservicescore: Uint8Array, coreadi: Uint8Array): LibraryStore;
    get(name: LibraryName): Uint8Array;
    get storeservicescore(): Uint8Array;
    get coreadi(): Uint8Array;
}
export {};
//# sourceMappingURL=library.d.ts.map