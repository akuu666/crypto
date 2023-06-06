export function pedersen(x: any, y: any): bigint;
export function sign(private_key: any, message: any, k: any): {
    r: bigint;
    s: bigint;
};
export function verify(stark_key: any, message_hash: any, r: any, s: any): any;
export function getPublicKey(private_key: any): bigint;
export const useCryptoCpp: boolean;
