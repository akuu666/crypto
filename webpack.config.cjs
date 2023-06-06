const path = require('path');
const webpack = require('webpack');

module.exports = {
  entry: './src/index.ts',  // Your TypeScript entry point
  output: {
    filename: 'bundle.js',  // The output bundle file
    path: path.resolve(__dirname, 'dist'),
  },
  resolve: {
    extensions: ['.ts', '.js'],  // Resolves .ts and .js extensions
    fallback: {
      "stream": require.resolve("stream-browserify"),  // Adds the fallback for 'stream'
      "assert": require.resolve("assert"),  // Adds the fallback for 'assert'
      "buffer": require.resolve("buffer/"),  // Adds the fallback for 'buffer'
      "path": require.resolve("path-browserify"),  // Adds the fallback for 'path'
      "crypto": require.resolve("crypto-browserify"),  // Adds the fallback for 'crypto'
      "fs": require.resolve("browserify-fs"),  // Adds the fallback for 'fs'
      "os": require.resolve("os-browserify/browser"),  // Adds the fallback for 'os'
      "process": require.resolve("process/browser")
    }
  },
  plugins: [
    new webpack.DefinePlugin({
      'process.env.NODE_ENV': JSON.stringify('production')
    }),
  ],
  module: {
    rules: [
      {
        test: /\.ts$/,  // Matches .ts files
        use: 'babel-loader',  // Uses Babel to transpile
        exclude: /node_modules/,
      },
    ],
  },
};
