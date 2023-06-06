export let entry: string;
export namespace output {
    let path: string;
    let filename: string;
    let libraryTarget: string;
    let globalObject: string;
    let library: string;
}
export namespace module {
    let rules: {
        test: RegExp;
        exclude: RegExp;
        use: {
            loader: string;
            options: {
                presets: string[];
            };
        };
    }[];
}
export let mode: string;
