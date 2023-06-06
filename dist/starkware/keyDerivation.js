"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.StarkExEc = void 0;
exports.getAccountPath = getAccountPath;
exports.getKeyPairFromPath = getKeyPairFromPath;
exports.grindKey = grindKey;

var _bip = require("bip39");

var _encUtils = require("enc-utils");

var _bn = _interopRequireDefault(require("bn.js"));

var _hash = _interopRequireDefault(require("hash.js"));

var _ethereumjsWallet = require("ethereumjs-wallet");

var _signature = require("./signature");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/* //////////////////////////////////////////////////////////////////////////////
// Copyright 2019 StarkWare Industries Ltd.                                    //
//                                                                             //
// Licensed under the Apache License, Version 2.0 (the "License").             //
// You may not use this file except in compliance with the License.            //
// You may obtain a copy of the License at                                     //
//                                                                             //
// https://www.starkware.co/open-source-license/                               //
//                                                                             //
// Unless required by applicable law or agreed to in writing,                  //
// software distributed under the License is distributed on an "AS IS" BASIS,  //
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    //
// See the License for the specific language governing permissions             //
// and limitations under the License.                                          //
////////////////////////////////////////////////////////////////////////////// */

/*
 Returns an integer from a given section of bits out of a hex string.
 hex is the target hex string to slice.
 start represents the index of the first bit to cut from the hex string (binary) in LSB order.
 end represents the index of the last bit to cut from the hex string.
*/
function getIntFromBits(hex, start) {
  var end = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : undefined;
  var bin = (0, _encUtils.hexToBinary)(hex);
  var bits = bin.slice(start, end);
  var int = (0, _encUtils.binaryToNumber)(bits);
  return int;
}
/*
 Calculates the stark path based on the layer, application, eth address and a given index.
 layer is a string representing the operating layer (usually 'starkex').
 application is a string representing the relevant application (For a list of valid applications,
 refer to https://starkware.co/starkex/docs/requirementsApplicationParameters.html).
 ethereumAddress is a string representing the ethereum public key from which we derive the stark
 key.
 index represents an index of the possible associated wallets derived from the seed.
*/


function getAccountPath(layer, application, ethereumAddress, index) {
  var layerHash = _hash.default.sha256().update(layer).digest('hex');

  var applicationHash = _hash.default.sha256().update(application).digest('hex');

  var layerInt = getIntFromBits(layerHash, -31);
  var applicationInt = getIntFromBits(applicationHash, -31); // Draws the 31 LSBs of the eth address.

  var ethAddressInt1 = getIntFromBits(ethereumAddress, -31); // Draws the following 31 LSBs of the eth address.

  var ethAddressInt2 = getIntFromBits(ethereumAddress, -62, -31);
  return "m/2645'/".concat(layerInt, "'/").concat(applicationInt, "'/").concat(ethAddressInt1, "'/").concat(ethAddressInt2, "'/").concat(index);
}

function hashKeyWithIndex(key, index) {
  return new _bn.default(_hash.default.sha256().update((0, _encUtils.hexToBuffer)((0, _encUtils.removeHexPrefix)(key) + (0, _encUtils.sanitizeBytes)((0, _encUtils.numberToHex)(index), 2))).digest('hex'), 16);
}
/*
 This function receives a key seed and produces an appropriate StarkEx key from a uniform
 distribution.
 Although it is possible to define a StarkEx key as a residue between the StarkEx EC order and a
 random 256bit digest value, the result would be a biased key. In order to prevent this bias, we
 deterministically search (by applying more hashes, AKA grinding) for a value lower than the largest
 256bit multiple of StarkEx EC order.
*/


function grindKey(keySeed, keyValLimit) {
  var sha256EcMaxDigest = new _bn.default('1 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000', 16);
  var maxAllowedVal = sha256EcMaxDigest.sub(sha256EcMaxDigest.mod(keyValLimit));
  var i = 0;
  var key = hashKeyWithIndex(keySeed, i);
  i += 1; // Make sure the produced key is devided by the Stark EC order, and falls within the range
  // [0, maxAllowedVal).

  while (!key.lt(maxAllowedVal)) {
    key = hashKeyWithIndex(keySeed.toString('hex'), i);
    i += 1;
  }

  return key.umod(keyValLimit).toString('hex');
}
/*
 Derives key-pair from given mnemonic string and path.
 mnemonic should be a sentence comprised of 12 words with single spaces between them.
 path is a formatted string describing the stark key path based on the layer, application and eth
 address.
*/


function getKeyPairFromPath(mnemonic, path) {
  var seed = (0, _bip.mnemonicToSeedSync)(mnemonic);

  var keySeed = _ethereumjsWallet.hdkey.fromMasterSeed(seed, 'hex').derivePath(path).getWallet().getPrivateKeyString();

  var starkEcOrder = _signature.starkEc.n;
  return _signature.starkEc.keyFromPrivate(grindKey(keySeed, starkEcOrder), 'hex');
}

var StarkExEc = _signature.starkEc.n;
exports.StarkExEc = StarkExEc;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9zdGFya3dhcmUva2V5RGVyaXZhdGlvbi5qcyJdLCJuYW1lcyI6WyJnZXRJbnRGcm9tQml0cyIsImhleCIsInN0YXJ0IiwiZW5kIiwidW5kZWZpbmVkIiwiYmluIiwiYml0cyIsInNsaWNlIiwiaW50IiwiZ2V0QWNjb3VudFBhdGgiLCJsYXllciIsImFwcGxpY2F0aW9uIiwiZXRoZXJldW1BZGRyZXNzIiwiaW5kZXgiLCJsYXllckhhc2giLCJoYXNoIiwic2hhMjU2IiwidXBkYXRlIiwiZGlnZXN0IiwiYXBwbGljYXRpb25IYXNoIiwibGF5ZXJJbnQiLCJhcHBsaWNhdGlvbkludCIsImV0aEFkZHJlc3NJbnQxIiwiZXRoQWRkcmVzc0ludDIiLCJoYXNoS2V5V2l0aEluZGV4Iiwia2V5IiwiQk4iLCJncmluZEtleSIsImtleVNlZWQiLCJrZXlWYWxMaW1pdCIsInNoYTI1NkVjTWF4RGlnZXN0IiwibWF4QWxsb3dlZFZhbCIsInN1YiIsIm1vZCIsImkiLCJsdCIsInRvU3RyaW5nIiwidW1vZCIsImdldEtleVBhaXJGcm9tUGF0aCIsIm1uZW1vbmljIiwicGF0aCIsInNlZWQiLCJoZGtleSIsImZyb21NYXN0ZXJTZWVkIiwiZGVyaXZlUGF0aCIsImdldFdhbGxldCIsImdldFByaXZhdGVLZXlTdHJpbmciLCJzdGFya0VjT3JkZXIiLCJlYyIsIm4iLCJrZXlGcm9tUHJpdmF0ZSIsIlN0YXJrRXhFYyJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7OztBQWdCQTs7QUFDQTs7QUFRQTs7QUFDQTs7QUFDQTs7QUFFQTs7OztBQTdCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBaUJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFNBQVNBLGNBQVQsQ0FBd0JDLEdBQXhCLEVBQTZCQyxLQUE3QixFQUFxRDtBQUFBLE1BQWpCQyxHQUFpQix1RUFBWEMsU0FBVztB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TUFBTVgsT0FBTyxHQUFHYyx3QkFDYkMsY0FEYSxDQUNFRixJQURGLEVBQ1EsS0FEUixFQUViRyxVQUZhLENBRUZKLElBRkUsRUFHYkssU0FIYSxHQUliQyxtQkFKYSxFQUFoQjs7QUFLQSxNQUFNQyxZQUFZLEdBQUdDLG1CQUFHQyxDQUF4QjtBQUNBLFNBQU9ELG1CQUFHRSxjQUFILENBQWtCdkIsUUFBUSxDQUFDQyxPQUFELEVBQVVtQixZQUFWLENBQTFCLEVBQW1ELEtBQW5ELENBQVA7QUFDRDs7QUFFTSxJQUFNSSxTQUFTLEdBQUdILG1CQUFHQyxDQUFyQiIsInNvdXJjZXNDb250ZW50IjpbIi8qIC8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuLy8gQ29weXJpZ2h0IDIwMTkgU3RhcmtXYXJlIEluZHVzdHJpZXMgTHRkLiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vXG4vLyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy9cbi8vIExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSBcIkxpY2Vuc2VcIikuICAgICAgICAgICAgIC8vXG4vLyBZb3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuICAgICAgICAgICAgLy9cbi8vIFlvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvL1xuLy8gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vXG4vLyBodHRwczovL3d3dy5zdGFya3dhcmUuY28vb3Blbi1zb3VyY2UtbGljZW5zZS8gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy9cbi8vICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvL1xuLy8gVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCAgICAgICAgICAgICAgICAgIC8vXG4vLyBzb2Z0d2FyZSBkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiBcIkFTIElTXCIgQkFTSVMsICAvL1xuLy8gV0lUSE9VVCBXQVJSQU5USUVTIE9SIENPTkRJVElPTlMgT0YgQU5ZIEtJTkQsIGVpdGhlciBleHByZXNzIG9yIGltcGxpZWQuICAgIC8vXG4vLyBTZWUgdGhlIExpY2Vuc2UgZm9yIHRoZSBzcGVjaWZpYyBsYW5ndWFnZSBnb3Zlcm5pbmcgcGVybWlzc2lvbnMgICAgICAgICAgICAgLy9cbi8vIGFuZCBsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvL1xuLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vICovXG5cbmltcG9ydCB7IG1uZW1vbmljVG9TZWVkU3luYyB9IGZyb20gJ2JpcDM5JztcbmltcG9ydCB7XG4gIGhleFRvQmluYXJ5LFxuICBiaW5hcnlUb051bWJlcixcbiAgaGV4VG9CdWZmZXIsXG4gIHJlbW92ZUhleFByZWZpeCxcbiAgc2FuaXRpemVCeXRlcyxcbiAgbnVtYmVyVG9IZXgsXG59IGZyb20gJ2VuYy11dGlscyc7XG5pbXBvcnQgQk4gZnJvbSAnYm4uanMnO1xuaW1wb3J0IGhhc2ggZnJvbSAnaGFzaC5qcyc7XG5pbXBvcnQgeyBoZGtleSB9IGZyb20gJ2V0aGVyZXVtanMtd2FsbGV0JztcblxuaW1wb3J0IHsgc3RhcmtFYyBhcyBlYyB9IGZyb20gJy4vc2lnbmF0dXJlJztcblxuLypcbiBSZXR1cm5zIGFuIGludGVnZXIgZnJvbSBhIGdpdmVuIHNlY3Rpb24gb2YgYml0cyBvdXQgb2YgYSBoZXggc3RyaW5nLlxuIGhleCBpcyB0aGUgdGFyZ2V0IGhleCBzdHJpbmcgdG8gc2xpY2UuXG4gc3RhcnQgcmVwcmVzZW50cyB0aGUgaW5kZXggb2YgdGhlIGZpcnN0IGJpdCB0byBjdXQgZnJvbSB0aGUgaGV4IHN0cmluZyAoYmluYXJ5KSBpbiBMU0Igb3JkZXIuXG4gZW5kIHJlcHJlc2VudHMgdGhlIGluZGV4IG9mIHRoZSBsYXN0IGJpdCB0byBjdXQgZnJvbSB0aGUgaGV4IHN0cmluZy5cbiovXG5mdW5jdGlvbiBnZXRJbnRGcm9tQml0cyhoZXgsIHN0YXJ0LCBlbmQgPSB1bmRlZmluZWQpIHtcbiAgY29uc3QgYmluID0gaGV4VG9CaW5hcnkoaGV4KTtcbiAgY29uc3QgYml0cyA9IGJpbi5zbGljZShzdGFydCwgZW5kKTtcbiAgY29uc3QgaW50ID0gYmluYXJ5VG9OdW1iZXIoYml0cyk7XG4gIHJldHVybiBpbnQ7XG59XG5cbi8qXG4gQ2FsY3VsYXRlcyB0aGUgc3RhcmsgcGF0aCBiYXNlZCBvbiB0aGUgbGF5ZXIsIGFwcGxpY2F0aW9uLCBldGggYWRkcmVzcyBhbmQgYSBnaXZlbiBpbmRleC5cbiBsYXllciBpcyBhIHN0cmluZyByZXByZXNlbnRpbmcgdGhlIG9wZXJhdGluZyBsYXllciAodXN1YWxseSAnc3RhcmtleCcpLlxuIGFwcGxpY2F0aW9uIGlzIGEgc3RyaW5nIHJlcHJlc2VudGluZyB0aGUgcmVsZXZhbnQgYXBwbGljYXRpb24gKEZvciBhIGxpc3Qgb2YgdmFsaWQgYXBwbGljYXRpb25zLFxuIHJlZmVyIHRvIGh0dHBzOi8vc3Rhcmt3YXJlLmNvL3N0YXJrZXgvZG9jcy9yZXF1aXJlbWVudHNBcHBsaWNhdGlvblBhcmFtZXRlcnMuaHRtbCkuXG4gZXRoZXJldW1BZGRyZXNzIGlzIGEgc3RyaW5nIHJlcHJlc2VudGluZyB0aGUgZXRoZXJldW0gcHVibGljIGtleSBmcm9tIHdoaWNoIHdlIGRlcml2ZSB0aGUgc3RhcmtcbiBrZXkuXG4gaW5kZXggcmVwcmVzZW50cyBhbiBpbmRleCBvZiB0aGUgcG9zc2libGUgYXNzb2NpYXRlZCB3YWxsZXRzIGRlcml2ZWQgZnJvbSB0aGUgc2VlZC5cbiovXG5leHBvcnQgZnVuY3Rpb24gZ2V0QWNjb3VudFBhdGgobGF5ZXIsIGFwcGxpY2F0aW9uLCBldGhlcmV1bUFkZHJlc3MsIGluZGV4KSB7XG4gIGNvbnN0IGxheWVySGFzaCA9IGhhc2hcbiAgICAuc2hhMjU2KClcbiAgICAudXBkYXRlKGxheWVyKVxuICAgIC5kaWdlc3QoJ2hleCcpO1xuICBjb25zdCBhcHBsaWNhdGlvbkhhc2ggPSBoYXNoXG4gICAgLnNoYTI1NigpXG4gICAgLnVwZGF0ZShhcHBsaWNhdGlvbilcbiAgICAuZGlnZXN0KCdoZXgnKTtcbiAgY29uc3QgbGF5ZXJJbnQgPSBnZXRJbnRGcm9tQml0cyhsYXllckhhc2gsIC0zMSk7XG4gIGNvbnN0IGFwcGxpY2F0aW9uSW50ID0gZ2V0SW50RnJvbUJpdHMoYXBwbGljYXRpb25IYXNoLCAtMzEpO1xuICAvLyBEcmF3cyB0aGUgMzEgTFNCcyBvZiB0aGUgZXRoIGFkZHJlc3MuXG4gIGNvbnN0IGV0aEFkZHJlc3NJbnQxID0gZ2V0SW50RnJvbUJpdHMoZXRoZXJldW1BZGRyZXNzLCAtMzEpO1xuICAvLyBEcmF3cyB0aGUgZm9sbG93aW5nIDMxIExTQnMgb2YgdGhlIGV0aCBhZGRyZXNzLlxuICBjb25zdCBldGhBZGRyZXNzSW50MiA9IGdldEludEZyb21CaXRzKGV0aGVyZXVtQWRkcmVzcywgLTYyLCAtMzEpO1xuICByZXR1cm4gYG0vMjY0NScvJHtsYXllckludH0nLyR7YXBwbGljYXRpb25JbnR9Jy8ke2V0aEFkZHJlc3NJbnQxfScvJHtldGhBZGRyZXNzSW50Mn0nLyR7aW5kZXh9YDtcbn1cblxuZnVuY3Rpb24gaGFzaEtleVdpdGhJbmRleChrZXksIGluZGV4KSB7XG4gIHJldHVybiBuZXcgQk4oXG4gICAgaGFzaFxuICAgICAgLnNoYTI1NigpXG4gICAgICAudXBkYXRlKFxuICAgICAgICBoZXhUb0J1ZmZlcihyZW1vdmVIZXhQcmVmaXgoa2V5KSArIHNhbml0aXplQnl0ZXMobnVtYmVyVG9IZXgoaW5kZXgpLCAyKSlcbiAgICAgIClcbiAgICAgIC5kaWdlc3QoJ2hleCcpLFxuICAgIDE2XG4gICk7XG59XG5cbi8qXG4gVGhpcyBmdW5jdGlvbiByZWNlaXZlcyBhIGtleSBzZWVkIGFuZCBwcm9kdWNlcyBhbiBhcHByb3ByaWF0ZSBTdGFya0V4IGtleSBmcm9tIGEgdW5pZm9ybVxuIGRpc3RyaWJ1dGlvbi5cbiBBbHRob3VnaCBpdCBpcyBwb3NzaWJsZSB0byBkZWZpbmUgYSBTdGFya0V4IGtleSBhcyBhIHJlc2lkdWUgYmV0d2VlbiB0aGUgU3RhcmtFeCBFQyBvcmRlciBhbmQgYVxuIHJhbmRvbSAyNTZiaXQgZGlnZXN0IHZhbHVlLCB0aGUgcmVzdWx0IHdvdWxkIGJlIGEgYmlhc2VkIGtleS4gSW4gb3JkZXIgdG8gcHJldmVudCB0aGlzIGJpYXMsIHdlXG4gZGV0ZXJtaW5pc3RpY2FsbHkgc2VhcmNoIChieSBhcHBseWluZyBtb3JlIGhhc2hlcywgQUtBIGdyaW5kaW5nKSBmb3IgYSB2YWx1ZSBsb3dlciB0aGFuIHRoZSBsYXJnZXN0XG4gMjU2Yml0IG11bHRpcGxlIG9mIFN0YXJrRXggRUMgb3JkZXIuXG4qL1xuZXhwb3J0IGZ1bmN0aW9uIGdyaW5kS2V5KGtleVNlZWQsIGtleVZhbExpbWl0KSB7XG4gIGNvbnN0IHNoYTI1NkVjTWF4RGlnZXN0ID0gbmV3IEJOKFxuICAgICcxIDAwMDAwMDAwIDAwMDAwMDAwIDAwMDAwMDAwIDAwMDAwMDAwIDAwMDAwMDAwIDAwMDAwMDAwIDAwMDAwMDAwIDAwMDAwMDAwJyxcbiAgICAxNlxuICApO1xuICBjb25zdCBtYXhBbGxvd2VkVmFsID0gc2hhMjU2RWNNYXhEaWdlc3Quc3ViKFxuICAgIHNoYTI1NkVjTWF4RGlnZXN0Lm1vZChrZXlWYWxMaW1pdClcbiAgKTtcbiAgbGV0IGkgPSAwO1xuICBsZXQga2V5ID0gaGFzaEtleVdpdGhJbmRleChrZXlTZWVkLCBpKTtcbiAgaSArPSAxO1xuICAvLyBNYWtlIHN1cmUgdGhlIHByb2R1Y2VkIGtleSBpcyBkZXZpZGVkIGJ5IHRoZSBTdGFyayBFQyBvcmRlciwgYW5kIGZhbGxzIHdpdGhpbiB0aGUgcmFuZ2VcbiAgLy8gWzAsIG1heEFsbG93ZWRWYWwpLlxuICB3aGlsZSAoIWtleS5sdChtYXhBbGxvd2VkVmFsKSkge1xuICAgIGtleSA9IGhhc2hLZXlXaXRoSW5kZXgoa2V5U2VlZC50b1N0cmluZygnaGV4JyksIGkpO1xuICAgIGkgKz0gMTtcbiAgfVxuICByZXR1cm4ga2V5LnVtb2Qoa2V5VmFsTGltaXQpLnRvU3RyaW5nKCdoZXgnKTtcbn1cblxuLypcbiBEZXJpdmVzIGtleS1wYWlyIGZyb20gZ2l2ZW4gbW5lbW9uaWMgc3RyaW5nIGFuZCBwYXRoLlxuIG1uZW1vbmljIHNob3VsZCBiZSBhIHNlbnRlbmNlIGNvbXByaXNlZCBvZiAxMiB3b3JkcyB3aXRoIHNpbmdsZSBzcGFjZXMgYmV0d2VlbiB0aGVtLlxuIHBhdGggaXMgYSBmb3JtYXR0ZWQgc3RyaW5nIGRlc2NyaWJpbmcgdGhlIHN0YXJrIGtleSBwYXRoIGJhc2VkIG9uIHRoZSBsYXllciwgYXBwbGljYXRpb24gYW5kIGV0aFxuIGFkZHJlc3MuXG4qL1xuZXhwb3J0IGZ1bmN0aW9uIGdldEtleVBhaXJGcm9tUGF0aChtbmVtb25pYywgcGF0aCkge1xuICBjb25zdCBzZWVkID0gbW5lbW9uaWNUb1NlZWRTeW5jKG1uZW1vbmljKTtcbiAgY29uc3Qga2V5U2VlZCA9IGhka2V5XG4gICAgLmZyb21NYXN0ZXJTZWVkKHNlZWQsICdoZXgnKVxuICAgIC5kZXJpdmVQYXRoKHBhdGgpXG4gICAgLmdldFdhbGxldCgpXG4gICAgLmdldFByaXZhdGVLZXlTdHJpbmcoKTtcbiAgY29uc3Qgc3RhcmtFY09yZGVyID0gZWMubjtcbiAgcmV0dXJuIGVjLmtleUZyb21Qcml2YXRlKGdyaW5kS2V5KGtleVNlZWQsIHN0YXJrRWNPcmRlciksICdoZXgnKTtcbn1cblxuZXhwb3J0IGNvbnN0IFN0YXJrRXhFYyA9IGVjLm47XG4iXX0=