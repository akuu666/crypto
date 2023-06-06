"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.constantPoints = void 0;
exports.getLimitOrderMsgHash = getLimitOrderMsgHash;
exports.getLimitOrderMsgHashWithFee = getLimitOrderMsgHashWithFee;
exports.getTransferMsgHash = getTransferMsgHash;
exports.getTransferMsgHashWithFee = getTransferMsgHashWithFee;
exports.maxEcdsaVal = void 0;
exports.pedersen = pedersen;
exports.shiftPoint = exports.prime = void 0;
exports.sign = sign;
exports.starkEc = void 0;
exports.verify = verify;

var _bn = _interopRequireDefault(require("bn.js"));

var _hash = _interopRequireDefault(require("hash.js"));

var _elliptic = require("elliptic");

var _assert = _interopRequireDefault(require("assert"));

var _constant_points = _interopRequireDefault(require("./constant_points"));

var _crypto = require("./crypto");

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
// Equals 2**251 + 17 * 2**192 + 1.
var prime = new _bn.default('800000000000011000000000000000000000000000000000000000000000001', 16); // Equals 2**251. This value limits msgHash and the signature parts.

exports.prime = prime;
var maxEcdsaVal = new _bn.default('800000000000000000000000000000000000000000000000000000000000000', 16); // Generate BN of used constants.

exports.maxEcdsaVal = maxEcdsaVal;
var zeroBn = new _bn.default('0', 16);
var oneBn = new _bn.default('1', 16);
var twoBn = new _bn.default('2', 16);
var threeBn = new _bn.default('3', 16);
var fourBn = new _bn.default('4', 16);
var fiveBn = new _bn.default('5', 16);
var twoPow22Bn = new _bn.default('400000', 16);
var twoPow31Bn = new _bn.default('80000000', 16);
var twoPow63Bn = new _bn.default('8000000000000000', 16); // Create a curve with stark curve parameters.

var starkEc = new _elliptic.ec(new _elliptic.curves.PresetCurve({
  type: 'short',
  prime: null,
  p: prime,
  a: '00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001',
  b: '06f21413 efbe40de 150e596d 72f7a8c5 609ad26c 15c915c1 f4cdfcb9 9cee9e89',
  n: '08000000 00000010 ffffffff ffffffff b781126d cae7b232 1e66a241 adc64d2f',
  hash: _hash.default.sha256,
  gRed: false,
  g: _constant_points.default[1]
}));
exports.starkEc = starkEc;

var constantPoints = _constant_points.default.map(function (coords) {
  return starkEc.curve.point(new _bn.default(coords[0], 16), new _bn.default(coords[1], 16));
});

exports.constantPoints = constantPoints;
var shiftPoint = constantPoints[0];
/*
  Checks that the string str start with '0x'.
*/

exports.shiftPoint = shiftPoint;

function hasHexPrefix(str) {
  return str.substring(0, 2) === '0x';
}
/*
 Asserts input is equal to or greater then lowerBound and lower then upperBound.
 Assert message specifies inputName.
 input, lowerBound, and upperBound should be of type BN.
 inputName should be a string.
*/


function assertInRange(input, lowerBound, upperBound) {
  var inputName = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : '';
  var messageSuffix = inputName === '' ? 'invalid length' : "invalid ".concat(inputName, " length");
  (0, _assert.default)(input.gte(lowerBound) && input.lt(upperBound), "Message not signable, ".concat(messageSuffix, "."));
}
/*
 Full specification of the hash function can be found here:
   https://starkware.co/starkex/docs/signatures.html#pedersen-hash-function
 shiftPoint was added for technical reasons to make sure the zero point on the elliptic curve does
 not appear during the computation. constantPoints are multiples by powers of 2 of the constant
 points defined in the documentation.
*/


function pedersen(input) {
  if (_crypto.useCryptoCpp) {
    if (typeof input[0] === 'string') {
      input[0] = BigInt("0x".concat(input[0]));
    }

    if (typeof input[1] === 'string') {
      input[1] = BigInt("0x".concat(input[1]));
    }

    return (0, _crypto.pedersen)(input[0], input[1]).toString(16);
  }

  var point = shiftPoint;

  for (var i = 0; i < input.length; i += 1) {
    var x = new _bn.default(input[i], 16);
    (0, _assert.default)(x.gte(zeroBn) && x.lt(prime), "Invalid input: ".concat(input[i]));

    for (var j = 0; j < 252; j += 1) {
      var pt = constantPoints[2 + i * 252 + j];
      (0, _assert.default)(!point.getX().eq(pt.getX()));

      if (x.and(oneBn).toNumber() !== 0) {
        point = point.add(pt);
      }

      x = x.shrn(1);
    }
  }

  return point.getX().toString(16);
}

function hashMsg(instructionTypeBn, vault0Bn, vault1Bn, amount0Bn, amount1Bn, nonceBn, expirationTimestampBn, token0, token1OrPubKey) {
  var condition = arguments.length > 9 && arguments[9] !== undefined ? arguments[9] : null;
  var packedMessage = instructionTypeBn;
  packedMessage = packedMessage.ushln(31).add(vault0Bn);
  packedMessage = packedMessage.ushln(31).add(vault1Bn);
  packedMessage = packedMessage.ushln(63).add(amount0Bn);
  packedMessage = packedMessage.ushln(63).add(amount1Bn);
  packedMessage = packedMessage.ushln(31).add(nonceBn);
  packedMessage = packedMessage.ushln(22).add(expirationTimestampBn);
  var msgHash = null;

  if (condition === null) {
    msgHash = pedersen([pedersen([token0, token1OrPubKey]), packedMessage.toString(16)]);
  } else {
    msgHash = pedersen([pedersen([pedersen([token0, token1OrPubKey]), condition]), packedMessage.toString(16)]);
  }

  var msgHashBN = new _bn.default(msgHash, 16);
  assertInRange(msgHashBN, zeroBn, maxEcdsaVal, 'msgHash');
  return msgHash;
}

function hashTransferMsgWithFee(instructionTypeBn, senderVaultIdBn, receiverVaultIdBn, amountBn, nonceBn, expirationTimestampBn, transferToken, receiverPublicKey, feeToken, feeVaultIdBn, feeLimitBn) {
  var condition = arguments.length > 11 && arguments[11] !== undefined ? arguments[11] : null;
  var packedMessage1 = senderVaultIdBn;
  packedMessage1 = packedMessage1.ushln(64).add(receiverVaultIdBn);
  packedMessage1 = packedMessage1.ushln(64).add(feeVaultIdBn);
  packedMessage1 = packedMessage1.ushln(32).add(nonceBn);
  var packedMessage2 = instructionTypeBn;
  packedMessage2 = packedMessage2.ushln(64).add(amountBn);
  packedMessage2 = packedMessage2.ushln(64).add(feeLimitBn);
  packedMessage2 = packedMessage2.ushln(32).add(expirationTimestampBn);
  packedMessage2 = packedMessage2.ushln(81).add(zeroBn);
  var msgHash = null;
  var tmpHash = pedersen([pedersen([transferToken, feeToken]), receiverPublicKey]);

  if (condition === null) {
    msgHash = pedersen([pedersen([tmpHash, packedMessage1.toString(16)]), packedMessage2.toString(16)]);
  } else {
    msgHash = pedersen([pedersen([pedersen([tmpHash, condition]), packedMessage1.toString(16)]), packedMessage2.toString(16)]);
  }

  var msgHashBN = new _bn.default(msgHash, 16);
  assertInRange(msgHashBN, zeroBn, maxEcdsaVal, 'msgHash');
  return msgHash;
}

function hashLimitOrderMsgWithFee(instructionTypeBn, vaultSellBn, vaultBuyBn, amountSellBn, amountBuyBn, nonceBn, expirationTimestampBn, tokenSell, tokenBuy, feeToken, feeVaultIdBn, feeLimitBn) {
  var packedMessage1 = amountSellBn;
  packedMessage1 = packedMessage1.ushln(64).add(amountBuyBn);
  packedMessage1 = packedMessage1.ushln(64).add(feeLimitBn);
  packedMessage1 = packedMessage1.ushln(32).add(nonceBn);
  var packedMessage2 = instructionTypeBn;
  packedMessage2 = packedMessage2.ushln(64).add(feeVaultIdBn);
  packedMessage2 = packedMessage2.ushln(64).add(vaultSellBn);
  packedMessage2 = packedMessage2.ushln(64).add(vaultBuyBn);
  packedMessage2 = packedMessage2.ushln(32).add(expirationTimestampBn);
  packedMessage2 = packedMessage2.ushln(17).add(zeroBn);
  var msgHash = null;
  var tmpHash = pedersen([pedersen([tokenSell, tokenBuy]), feeToken]);
  msgHash = pedersen([pedersen([tmpHash, packedMessage1.toString(16)]), packedMessage2.toString(16)]);
  var msgHashBN = new _bn.default(msgHash, 16);
  assertInRange(msgHashBN, zeroBn, maxEcdsaVal, 'msgHash');
  return msgHash;
}
/*
 Serializes the order message in the canonical format expected by the verifier.
 party_a sells amountSell coins of tokenSell from vaultSell.
 party_a buys amountBuy coins of tokenBuy into vaultBuy.
 Expected types:
 ---------------
 vaultSell, vaultBuy - uint31 (as int)
 amountSell, amountBuy - uint63 (as decimal string)
 tokenSell, tokenBuy - uint256 field element strictly less than the prime (as hex string with 0x)
 nonce - uint31 (as int)
 expirationTimestamp - uint22 (as int).
*/


function getLimitOrderMsgHash(vaultSell, vaultBuy, amountSell, amountBuy, tokenSell, tokenBuy, nonce, expirationTimestamp) {
  (0, _assert.default)(hasHexPrefix(tokenSell) && hasHexPrefix(tokenBuy), 'Hex strings expected to be prefixed with 0x.');
  var vaultSellBn = new _bn.default(vaultSell);
  var vaultBuyBn = new _bn.default(vaultBuy);
  var amountSellBn = new _bn.default(amountSell, 10);
  var amountBuyBn = new _bn.default(amountBuy, 10);
  var tokenSellBn = new _bn.default(tokenSell.substring(2), 16);
  var tokenBuyBn = new _bn.default(tokenBuy.substring(2), 16);
  var nonceBn = new _bn.default(nonce);
  var expirationTimestampBn = new _bn.default(expirationTimestamp);
  assertInRange(vaultSellBn, zeroBn, twoPow31Bn);
  assertInRange(vaultBuyBn, zeroBn, twoPow31Bn);
  assertInRange(amountSellBn, zeroBn, twoPow63Bn);
  assertInRange(amountBuyBn, zeroBn, twoPow63Bn);
  assertInRange(tokenSellBn, zeroBn, prime);
  assertInRange(tokenBuyBn, zeroBn, prime);
  assertInRange(nonceBn, zeroBn, twoPow31Bn);
  assertInRange(expirationTimestampBn, zeroBn, twoPow22Bn);
  var instructionType = zeroBn;
  return hashMsg(instructionType, vaultSellBn, vaultBuyBn, amountSellBn, amountBuyBn, nonceBn, expirationTimestampBn, tokenSell.substring(2), tokenBuy.substring(2));
}
/*
 Same as getLimitOrderMsgHash, but also requires the fee info.

 Expected types of fee info params:
 ---------------
 feeVaultId - uint31 (as int)
 feeLimit - uint63 (as decimal string)
 feeToken - uint256 field element strictly less than the prime (as hex string with 0x)
*/


function getLimitOrderMsgHashWithFee(vaultSell, vaultBuy, amountSell, amountBuy, tokenSell, tokenBuy, nonce, expirationTimestamp, feeToken, feeVaultId, feeLimit) {
  (0, _assert.default)(hasHexPrefix(tokenSell) && hasHexPrefix(tokenBuy), 'Hex strings expected to be prefixed with 0x.');
  var vaultSellBn = new _bn.default(vaultSell);
  var vaultBuyBn = new _bn.default(vaultBuy);
  var amountSellBn = new _bn.default(amountSell, 10);
  var amountBuyBn = new _bn.default(amountBuy, 10);
  var tokenSellBn = new _bn.default(tokenSell.substring(2), 16);
  var tokenBuyBn = new _bn.default(tokenBuy.substring(2), 16);
  var nonceBn = new _bn.default(nonce);
  var expirationTimestampBn = new _bn.default(expirationTimestamp);
  var feeTokenBn = new _bn.default(feeToken.substring(2), 16);
  var feeVaultIdBn = new _bn.default(feeVaultId);
  var feeLimitBn = new _bn.default(feeLimit);
  assertInRange(vaultSellBn, zeroBn, twoPow31Bn);
  assertInRange(vaultBuyBn, zeroBn, twoPow31Bn);
  assertInRange(amountSellBn, zeroBn, twoPow63Bn);
  assertInRange(amountBuyBn, zeroBn, twoPow63Bn);
  assertInRange(tokenSellBn, zeroBn, prime);
  assertInRange(tokenBuyBn, zeroBn, prime);
  assertInRange(nonceBn, zeroBn, twoPow31Bn);
  assertInRange(expirationTimestampBn, zeroBn, twoPow22Bn);
  assertInRange(feeTokenBn, zeroBn, prime);
  assertInRange(feeVaultIdBn, zeroBn, twoPow31Bn);
  assertInRange(feeLimitBn, zeroBn, twoPow63Bn);
  var instructionType = threeBn;
  return hashLimitOrderMsgWithFee(instructionType, vaultSellBn, vaultBuyBn, amountSellBn, amountBuyBn, nonceBn, expirationTimestampBn, tokenSell.substring(2), tokenBuy.substring(2), feeToken.substring(2), feeVaultIdBn, feeLimitBn);
}
/*
 Serializes the transfer message in the canonical format expected by the verifier.
 The sender transfer 'amount' coins of 'token' from vault with id senderVaultId to vault with id
 receiverVaultId. The receiver's public key is receiverPublicKey.
 If a condition is added, it is verified before executing the transfer. The format of the condition
 is defined by the application.
 Expected types:
 ---------------
 amount - uint63 (as decimal string)
 nonce - uint31 (as int)
 senderVaultId uint31 (as int)
 token - uint256 field element strictly less than the prime (as hex string with 0x)
 receiverVaultId - uint31 (as int)
 receiverPublicKey - uint256 field element strictly less than the prime (as hex string with 0x)
 expirationTimestamp - uint22 (as int).
 condition - uint256 field element strictly less than the prime (as hex string with 0x)
*/


function getTransferMsgHash(amount, nonce, senderVaultId, token, receiverVaultId, receiverPublicKey, expirationTimestamp, condition) {
  (0, _assert.default)(hasHexPrefix(token) && hasHexPrefix(receiverPublicKey) && (!condition || hasHexPrefix(condition)), 'Hex strings expected to be prefixed with 0x.');
  var amountBn = new _bn.default(amount, 10);
  var nonceBn = new _bn.default(nonce);
  var senderVaultIdBn = new _bn.default(senderVaultId);
  var tokenBn = new _bn.default(token.substring(2), 16);
  var receiverVaultIdBn = new _bn.default(receiverVaultId);
  var receiverPublicKeyBn = new _bn.default(receiverPublicKey.substring(2), 16);
  var expirationTimestampBn = new _bn.default(expirationTimestamp);
  assertInRange(amountBn, zeroBn, twoPow63Bn);
  assertInRange(nonceBn, zeroBn, twoPow31Bn);
  assertInRange(senderVaultIdBn, zeroBn, twoPow31Bn);
  assertInRange(tokenBn, zeroBn, prime);
  assertInRange(receiverVaultIdBn, zeroBn, twoPow31Bn);
  assertInRange(receiverPublicKeyBn, zeroBn, prime);
  assertInRange(expirationTimestampBn, zeroBn, twoPow22Bn);
  var instructionType = oneBn;
  var cond = null;

  if (condition) {
    cond = condition.substring(2);
    assertInRange(new _bn.default(cond, 16), zeroBn, prime, 'condition');
    instructionType = twoBn;
  }

  return hashMsg(instructionType, senderVaultIdBn, receiverVaultIdBn, amountBn, zeroBn, nonceBn, expirationTimestampBn, token.substring(2), receiverPublicKey.substring(2), cond);
}
/*
 Same as getTransferMsgHash, but also requires the fee info.

 Expected types of fee info params:
 ---------------
 feeVaultId - uint31 (as int)
 feeLimit - uint63 (as decimal string)
 feeToken - uint256 field element strictly less than the prime (as hex string with 0x)
*/


function getTransferMsgHashWithFee(amount, nonce, senderVaultId, token, receiverVaultId, receiverStarkKey, expirationTimestamp, condition, feeToken, feeVaultId, feeLimit) {
  (0, _assert.default)(hasHexPrefix(feeToken) && hasHexPrefix(token) && hasHexPrefix(receiverStarkKey) && (!condition || hasHexPrefix(condition)), 'Hex strings expected to be prefixed with 0x.');
  var amountBn = new _bn.default(amount, 10);
  var nonceBn = new _bn.default(nonce);
  var senderVaultIdBn = new _bn.default(senderVaultId);
  var tokenBn = new _bn.default(token.substring(2), 16);
  var receiverVaultIdBn = new _bn.default(receiverVaultId);
  var receiverStarkKeyBn = new _bn.default(receiverStarkKey.substring(2), 16);
  var expirationTimestampBn = new _bn.default(expirationTimestamp);
  var feeTokenBn = new _bn.default(feeToken.substring(2), 16);
  var feeVaultIdBn = new _bn.default(feeVaultId);
  var feeLimitBn = new _bn.default(feeLimit);
  assertInRange(amountBn, zeroBn, twoPow63Bn);
  assertInRange(nonceBn, zeroBn, twoPow31Bn);
  assertInRange(senderVaultIdBn, zeroBn, twoPow31Bn);
  assertInRange(tokenBn, zeroBn, prime);
  assertInRange(receiverVaultIdBn, zeroBn, twoPow31Bn);
  assertInRange(receiverStarkKeyBn, zeroBn, prime);
  assertInRange(expirationTimestampBn, zeroBn, twoPow22Bn);
  assertInRange(feeTokenBn, zeroBn, prime);
  assertInRange(feeVaultIdBn, zeroBn, twoPow31Bn);
  assertInRange(feeLimitBn, zeroBn, twoPow63Bn);
  var instructionType = fourBn;
  var cond = null;

  if (condition) {
    cond = condition.substring(2);
    assertInRange(new _bn.default(cond), zeroBn, prime, 'condition');
    instructionType = fiveBn;
  }

  return hashTransferMsgWithFee(instructionType, senderVaultIdBn, receiverVaultIdBn, amountBn, nonceBn, expirationTimestampBn, token.substring(2), receiverStarkKey.substring(2), feeToken.substring(2), feeVaultIdBn, feeLimitBn, cond);
}
/*
 The function _truncateToN in lib/elliptic/ec/index.js does a shift-right of delta bits,
 if delta is positive, where
   delta = msgHash.byteLength() * 8 - starkEx.n.bitLength().
 This function does the opposite operation so that
   _truncateToN(fixMsgHashLen(msgHash)) == msgHash.
*/


function fixMsgHashLen(msgHash) {
  // Convert to BN to remove leading zeros.
  var m = new _bn.default(msgHash, 16).toString(16);

  if (m.length <= 62) {
    // In this case, msgHash should not be transformed, as the byteLength() is at most 31,
    // so delta < 0 (see _truncateToN).
    return m;
  }

  (0, _assert.default)(m.length === 63); // In this case delta will be 4 so we perform a shift-left of 4 bits by adding a zero.

  return "".concat(m, "0");
}
/*
 Signs a message using the provided key.
 privateKey should be an elliptic.keyPair with a valid private key.
 Returns an elliptic.Signature.
*/


function sign(privateKey, msgHash) {
  var msgHashBN = new _bn.default(msgHash, 16); // Verify message hash has valid length.

  assertInRange(msgHashBN, zeroBn, maxEcdsaVal, 'msgHash');
  var msgSignature = privateKey.sign(fixMsgHashLen(msgHash));
  var r = msgSignature.r,
      s = msgSignature.s;
  var w = s.invm(starkEc.n); // Verify signature has valid length.

  assertInRange(r, oneBn, maxEcdsaVal, 'r');
  assertInRange(s, oneBn, starkEc.n, 's');
  assertInRange(w, oneBn, maxEcdsaVal, 'w');
  return msgSignature;
}
/*
 Verifies a message using the provided key.
 publicKey should be an elliptic.keyPair with a valid public key.
 msgSignature should be an elliptic.Signature.
 Returns a boolean true if the verification succeeds.
*/


function verify(publicKey, msgHash, msgSignature) {
  var msgHashBN = new _bn.default(msgHash, 16); // Verify message hash has valid length.

  assertInRange(msgHashBN, zeroBn, maxEcdsaVal, 'msgHash');
  var r = msgSignature.r,
      s = msgSignature.s;
  var w = s.invm(starkEc.n); // Verify signature has valid length.

  assertInRange(r, oneBn, maxEcdsaVal, 'r');
  assertInRange(s, oneBn, starkEc.n, 's');
  assertInRange(w, oneBn, maxEcdsaVal, 'w');
  return publicKey.verify(fixMsgHashLen(msgHash), msgSignature);
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9zdGFya3dhcmUvc2lnbmF0dXJlLmpzIl0sIm5hbWVzIjpbInByaW1lIiwiQk4iLCJtYXhFY2RzYVZhbCIsInplcm9CbiIsIm9uZUJuIiwidHdvQm4iLCJ0aHJlZUJuIiwiZm91ckJuIiwiZml2ZUJuIiwidHdvUG93MjJCbiIsInR3b1BvdzMxQm4iLCJ0d29Qb3c2M0JuIiwic3RhcmtFYyIsIkVsbGlwdGljQ3VydmUiLCJlQ3VydmVzIiwiUHJlc2V0Q3VydmUiLCJ0eXBlIiwicCIsImEiLCJiIiwibiIsImhhc2giLCJzaGEyNTYiLCJnUmVkIiwiZyIsImNvbnN0YW50UG9pbnRzSGV4IiwiY29uc3RhbnRQb2ludHMiLCJtYXAiLCJjb29yZHMiLCJjdXJ2ZSIsInBvaW50Iiwic2hpZnRQb2ludCIsImhhc0hleFByZWZpeCIsInN0ciIsInN1YnN0cmluZyIsImFzc2VydEluUmFuZ2UiLCJpbnB1dCIsImxvd2VyQm91bmQiLCJ1cHBlckJvdW5kIiwiaW5wdXROYW1lIiwibWVzc2FnZVN1ZmZpeCIsImd0ZSIsImx0IiwicGVkZXJzZW4iLCJ1c2VDcnlwdG9DcHAiLCJCaWdJbnQiLCJ0b1N0cmluZyIsImkiLCJsZW5ndGgiLCJ4IiwiaiIsInB0IiwiZ2V0WCIsImVxIiwiYW5kIiwidG9OdW1iZXIiLCJhZGQiLCJzaHJuIiwiaGFzaE1zZyIsImluc3RydWN0aW9uVHlwZUJuIiwidmF1bHQwQm4iLCJ2YXVsdDFCbiIsImFtb3VudDBCbiIsImFtb3VudDFCbiIsIm5vbmNlQm4iLCJleHBpcmF0aW9uVGltZXN0YW1wQm4iLCJ0b2tlbjAiLCJ0b2tlbjFPclB1YktleSIsImNvbmRpdGlvbiIsInBhY2tlZE1lc3NhZ2UiLCJ1c2hsbiIsIm1zZ0hhc2giLCJtc2dIYXNoQk4iLCJoYXNoVHJhbnNmZXJNc2dXaXRoRmVlIiwic2VuZGVyVmF1bHRJZEJuIiwicmVjZWl2ZXJWYXVsdElkQm4iLCJhbW91bnRCbiIsInRyYW5zZmVyVG9rZW4iLCJyZWNlaXZlclB1YmxpY0tleSIsImZlZVRva2VuIiwiZmVlVmF1bHRJZEJuIiwiZmVlTGltaXRCbiIsInBhY2tlZE1lc3NhZ2UxIiwicGFja2VkTWVzc2FnZTIiLCJ0bXBIYXNoIiwiaGFzaExpbWl0T3JkZXJNc2dXaXRoRmVlIiwidmF1bHRTZWxsQm4iLCJ2YXVsdEJ1eUJuIiwiYW1vdW50U2VsbEJuIiwiYW1vdW50QnV5Qm4iLCJ0b2tlblNlbGwiLCJ0b2tlbkJ1eSIsImdldExpbWl0T3JkZXJNc2dIYXNoIiwidmF1bHRTZWxsIiwidmF1bHRCdXkiLCJhbW91bnRTZWxsIiwiYW1vdW50QnV5Iiwibm9uY2UiLCJleHBpcmF0aW9uVGltZXN0YW1wIiwidG9rZW5TZWxsQm4iLCJ0b2tlbkJ1eUJuIiwiaW5zdHJ1Y3Rpb25UeXBlIiwiZ2V0TGltaXRPcmRlck1zZ0hhc2hXaXRoRmVlIiwiZmVlVmF1bHRJZCIsImZlZUxpbWl0IiwiZmVlVG9rZW5CbiIsImdldFRyYW5zZmVyTXNnSGFzaCIsImFtb3VudCIsInNlbmRlclZhdWx0SWQiLCJ0b2tlbiIsInJlY2VpdmVyVmF1bHRJZCIsInRva2VuQm4iLCJyZWNlaXZlclB1YmxpY0tleUJuIiwiY29uZCIsImdldFRyYW5zZmVyTXNnSGFzaFdpdGhGZWUiLCJyZWNlaXZlclN0YXJrS2V5IiwicmVjZWl2ZXJTdGFya0tleUJuIiwiZml4TXNnSGFzaExlbiIsIm0iLCJzaWduIiwicHJpdmF0ZUtleSIsIm1zZ1NpZ25hdHVyZSIsInIiLCJzIiwidyIsImludm0iLCJ2ZXJpZnkiLCJwdWJsaWNLZXkiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBZ0JBOztBQUNBOztBQUNBOztBQUNBOztBQUVBOztBQUNBOzs7O0FBdEJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQVVBO0FBQ08sSUFBTUEsS0FBSyxHQUFHLElBQUlDLFdBQUosQ0FDbkIsaUVBRG1CLEVBRW5CLEVBRm1CLENBQWQsQyxD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Ly8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vL1xuLy8gQ29weXJpZ2h0IDIwMTkgU3RhcmtXYXJlIEluZHVzdHJpZXMgTHRkLiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vXG4vLyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy9cbi8vIExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSBcIkxpY2Vuc2VcIikuICAgICAgICAgICAgIC8vXG4vLyBZb3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuICAgICAgICAgICAgLy9cbi8vIFlvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvL1xuLy8gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC8vXG4vLyBodHRwczovL3d3dy5zdGFya3dhcmUuY28vb3Blbi1zb3VyY2UtbGljZW5zZS8gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLy9cbi8vICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvL1xuLy8gVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCAgICAgICAgICAgICAgICAgIC8vXG4vLyBzb2Z0d2FyZSBkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiBcIkFTIElTXCIgQkFTSVMsICAvL1xuLy8gV0lUSE9VVCBXQVJSQU5USUVTIE9SIENPTkRJVElPTlMgT0YgQU5ZIEtJTkQsIGVpdGhlciBleHByZXNzIG9yIGltcGxpZWQuICAgIC8vXG4vLyBTZWUgdGhlIExpY2Vuc2UgZm9yIHRoZSBzcGVjaWZpYyBsYW5ndWFnZSBnb3Zlcm5pbmcgcGVybWlzc2lvbnMgICAgICAgICAgICAgLy9cbi8vIGFuZCBsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAvL1xuLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vICovXG5cbmltcG9ydCBCTiBmcm9tICdibi5qcyc7XG5pbXBvcnQgaGFzaCBmcm9tICdoYXNoLmpzJztcbmltcG9ydCB7IGN1cnZlcyBhcyBlQ3VydmVzLCBlYyBhcyBFbGxpcHRpY0N1cnZlIH0gZnJvbSAnZWxsaXB0aWMnO1xuaW1wb3J0IGFzc2VydCBmcm9tICdhc3NlcnQnO1xuXG5pbXBvcnQgY29uc3RhbnRQb2ludHNIZXggZnJvbSAnLi9jb25zdGFudF9wb2ludHMnO1xuaW1wb3J0IHsgcGVkZXJzZW4gYXMgcGVkZXJzZW5DcHAsIHVzZUNyeXB0b0NwcCB9IGZyb20gJy4vY3J5cHRvJztcblxuLy8gRXF1YWxzIDIqKjI1MSArIDE3ICogMioqMTkyICsgMS5cbmV4cG9ydCBjb25zdCBwcmltZSA9IG5ldyBCTihcbiAgJzgwMDAwMDAwMDAwMDAxMTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMScsXG4gIDE2XG4pO1xuLy8gRXF1YWxzIDIqKjI1MS4gVGhpcyB2YWx1ZSBsaW1pdHMgbXNnSGFzaCBhbmQgdGhlIHNpZ25hdHVyZSBwYXJ0cy5cbmV4cG9ydCBjb25zdCBtYXhFY2RzYVZhbCA9IG5ldyBCTihcbiAgJzgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCcsXG4gIDE2XG4pO1xuXG4vLyBHZW5lcmF0ZSBCTiBvZiB1c2VkIGNvbnN0YW50cy5cbmNvbnN0IHplcm9CbiA9IG5ldyBCTignMCcsIDE2KTtcbmNvbnN0IG9uZUJuID0gbmV3IEJOKCcxJywgMTYpO1xuY29uc3QgdHdvQm4gPSBuZXcgQk4oJzInLCAxNik7XG5jb25zdCB0aHJlZUJuID0gbmV3IEJOKCczJywgMTYpO1xuY29uc3QgZm91ckJuID0gbmV3IEJOKCc0JywgMTYpO1xuY29uc3QgZml2ZUJuID0gbmV3IEJOKCc1JywgMTYpO1xuY29uc3QgdHdvUG93MjJCbiA9IG5ldyBCTignNDAwMDAwJywgMTYpO1xuY29uc3QgdHdvUG93MzFCbiA9IG5ldyBCTignODAwMDAwMDAnLCAxNik7XG5jb25zdCB0d29Qb3c2M0JuID0gbmV3IEJOKCc4MDAwMDAwMDAwMDAwMDAwJywgMTYpO1xuXG4vLyBDcmVhdGUgYSBjdXJ2ZSB3aXRoIHN0YXJrIGN1cnZlIHBhcmFtZXRlcnMuXG5leHBvcnQgY29uc3Qgc3RhcmtFYyA9IG5ldyBFbGxpcHRpY0N1cnZlKFxuICBuZXcgZUN1cnZlcy5QcmVzZXRDdXJ2ZSh7XG4gICAgdHlwZTogJ3Nob3J0JyxcbiAgICBwcmltZTogbnVsbCxcbiAgICBwOiBwcmltZSxcbiAgICBhOiAnMDAwMDAwMDAgMDAwMDAwMDAgMDAwMDAwMDAgMDAwMDAwMDAgMDAwMDAwMDAgMDAwMDAwMDAgMDAwMDAwMDAgMDAwMDAwMDEnLFxuICAgIGI6ICcwNmYyMTQxMyBlZmJlNDBkZSAxNTBlNTk2ZCA3MmY3YThjNSA2MDlhZDI2YyAxNWM5MTVjMSBmNGNkZmNiOSA5Y2VlOWU4OScsXG4gICAgbjogJzA4MDAwMDAwIDAwMDAwMDEwIGZmZmZmZmZmIGZmZmZmZmZmIGI3ODExMjZkIGNhZTdiMjMyIDFlNjZhMjQxIGFkYzY0ZDJmJyxcbiAgICBoYXNoOiBoYXNoLnNoYTI1NixcbiAgICBnUmVkOiBmYWxzZSxcbiAgICBnOiBjb25zdGFudFBvaW50c0hleFsxXSxcbiAgfSlcbik7XG5cbmV4cG9ydCBjb25zdCBjb25zdGFudFBvaW50cyA9IGNvbnN0YW50UG9pbnRzSGV4Lm1hcCgoY29vcmRzKSA9PlxuICBzdGFya0VjLmN1cnZlLnBvaW50KG5ldyBCTihjb29yZHNbMF0sIDE2KSwgbmV3IEJOKGNvb3Jkc1sxXSwgMTYpKVxuKTtcbmV4cG9ydCBjb25zdCBzaGlmdFBvaW50ID0gY29uc3RhbnRQb2ludHNbMF07XG5cbi8qXG4gIENoZWNrcyB0aGF0IHRoZSBzdHJpbmcgc3RyIHN0YXJ0IHdpdGggJzB4Jy5cbiovXG5mdW5jdGlvbiBoYXNIZXhQcmVmaXgoc3RyKSB7XG4gIHJldHVybiBzdHIuc3Vic3RyaW5nKDAsIDIpID09PSAnMHgnO1xufVxuXG4vKlxuIEFzc2VydHMgaW5wdXQgaXMgZXF1YWwgdG8gb3IgZ3JlYXRlciB0aGVuIGxvd2VyQm91bmQgYW5kIGxvd2VyIHRoZW4gdXBwZXJCb3VuZC5cbiBBc3NlcnQgbWVzc2FnZSBzcGVjaWZpZXMgaW5wdXROYW1lLlxuIGlucHV0LCBsb3dlckJvdW5kLCBhbmQgdXBwZXJCb3VuZCBzaG91bGQgYmUgb2YgdHlwZSBCTi5cbiBpbnB1dE5hbWUgc2hvdWxkIGJlIGEgc3RyaW5nLlxuKi9cbmZ1bmN0aW9uIGFzc2VydEluUmFuZ2UoaW5wdXQsIGxvd2VyQm91bmQsIHVwcGVyQm91bmQsIGlucHV0TmFtZSA9ICcnKSB7XG4gIGNvbnN0IG1lc3NhZ2VTdWZmaXggPVxuICAgIGlucHV0TmFtZSA9PT0gJycgPyAnaW52YWxpZCBsZW5ndGgnIDogYGludmFsaWQgJHtpbnB1dE5hbWV9IGxlbmd0aGA7XG4gIGFzc2VydChcbiAgICBpbnB1dC5ndGUobG93ZXJCb3VuZCkgJiYgaW5wdXQubHQodXBwZXJCb3VuZCksXG4gICAgYE1lc3NhZ2Ugbm90IHNpZ25hYmxlLCAke21lc3NhZ2VTdWZmaXh9LmBcbiAgKTtcbn1cblxuLypcbiBGdWxsIHNwZWNpZmljYXRpb24gb2YgdGhlIGhhc2ggZnVuY3Rpb24gY2FuIGJlIGZvdW5kIGhlcmU6XG4gICBodHRwczovL3N0YXJrd2FyZS5jby9zdGFya2V4L2RvY3Mvc2lnbmF0dXJlcy5odG1sI3BlZGVyc2VuLWhhc2gtZnVuY3Rpb25cbiBzaGlmdFBvaW50IHdhcyBhZGRlZCBmb3IgdGVjaG5pY2FsIHJlYXNvbnMgdG8gbWFrZSBzdXJlIHRoZSB6ZXJvIHBvaW50IG9uIHRoZSBlbGxpcHRpYyBjdXJ2ZSBkb2VzXG4gbm90IGFwcGVhciBkdXJpbmcgdGhlIGNvbXB1dGF0aW9uLiBjb25zdGFudFBvaW50cyBhcmUgbXVsdGlwbGVzIGJ5IHBvd2VycyBvZiAyIG9mIHRoZSBjb25zdGFudFxuIHBvaW50cyBkZWZpbmVkIGluIHRoZSBkb2N1bWVudGF0aW9uLlxuKi9cbmV4cG9ydCBmdW5jdGlvbiBwZWRlcnNlbihpbnB1dCkge1xuICBpZiAodXNlQ3J5cHRvQ3BwKSB7XG4gICAgaWYgKHR5cGVvZiBpbnB1dFswXSA9PT0gJ3N0cmluZycpIHtcbiAgICAgIGlucHV0WzBdID0gQmlnSW50KGAweCR7aW5wdXRbMF19YCk7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgaW5wdXRbMV0gPT09ICdzdHJpbmcnKSB7XG4gICAgICBpbnB1dFsxXSA9IEJpZ0ludChgMHgke2lucHV0WzFdfWApO1xuICAgIH1cbiAgICByZXR1cm4gcGVkZXJzZW5DcHAoaW5wdXRbMF0sIGlucHV0WzFdKS50b1N0cmluZygxNik7XG4gIH1cblxuICBsZXQgcG9pbnQgPSBzaGlmdFBvaW50O1xuICBmb3IgKGxldCBpID0gMDsgaSA8IGlucHV0Lmxlbmd0aDsgaSArPSAxKSB7XG4gICAgbGV0IHggPSBuZXcgQk4oaW5wdXRbaV0sIDE2KTtcbiAgICBhc3NlcnQoeC5ndGUoemVyb0JuKSAmJiB4Lmx0KHByaW1lKSwgYEludmFsaWQgaW5wdXQ6ICR7aW5wdXRbaV19YCk7XG4gICAgZm9yIChsZXQgaiA9IDA7IGogPCAyNTI7IGogKz0gMSkge1xuICAgICAgY29uc3QgcHQgPSBjb25zdGFudFBvaW50c1syICsgaSAqIDI1MiArIGpdO1xuICAgICAgYXNzZXJ0KCFwb2ludC5nZXRYKCkuZXEocHQuZ2V0WCgpKSk7XG4gICAgICBpZiAoeC5hbmQob25lQm4pLnRvTnVtYmVyKCkgIT09IDApIHtcbiAgICAgICAgcG9pbnQgPSBwb2ludC5hZGQocHQpO1xuICAgICAgfVxuICAgICAgeCA9IHguc2hybigxKTtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIHBvaW50LmdldFgoKS50b1N0cmluZygxNik7XG59XG5cbmZ1bmN0aW9uIGhhc2hNc2coXG4gIGluc3RydWN0aW9uVHlwZUJuLFxuICB2YXVsdDBCbixcbiAgdmF1bHQxQm4sXG4gIGFtb3VudDBCbixcbiAgYW1vdW50MUJuLFxuICBub25jZUJuLFxuICBleHBpcmF0aW9uVGltZXN0YW1wQm4sXG4gIHRva2VuMCxcbiAgdG9rZW4xT3JQdWJLZXksXG4gIGNvbmRpdGlvbiA9IG51bGxcbikge1xuICBsZXQgcGFja2VkTWVzc2FnZSA9IGluc3RydWN0aW9uVHlwZUJuO1xuICBwYWNrZWRNZXNzYWdlID0gcGFja2VkTWVzc2FnZS51c2hsbigzMSkuYWRkKHZhdWx0MEJuKTtcbiAgcGFja2VkTWVzc2FnZSA9IHBhY2tlZE1lc3NhZ2UudXNobG4oMzEpLmFkZCh2YXVsdDFCbik7XG4gIHBhY2tlZE1lc3NhZ2UgPSBwYWNrZWRNZXNzYWdlLnVzaGxuKDYzKS5hZGQoYW1vdW50MEJuKTtcbiAgcGFja2VkTWVzc2FnZSA9IHBhY2tlZE1lc3NhZ2UudXNobG4oNjMpLmFkZChhbW91bnQxQm4pO1xuICBwYWNrZWRNZXNzYWdlID0gcGFja2VkTWVzc2FnZS51c2hsbigzMSkuYWRkKG5vbmNlQm4pO1xuICBwYWNrZWRNZXNzYWdlID0gcGFja2VkTWVzc2FnZS51c2hsbigyMikuYWRkKGV4cGlyYXRpb25UaW1lc3RhbXBCbik7XG4gIGxldCBtc2dIYXNoID0gbnVsbDtcbiAgaWYgKGNvbmRpdGlvbiA9PT0gbnVsbCkge1xuICAgIG1zZ0hhc2ggPSBwZWRlcnNlbihbXG4gICAgICBwZWRlcnNlbihbdG9rZW4wLCB0b2tlbjFPclB1YktleV0pLFxuICAgICAgcGFja2VkTWVzc2FnZS50b1N0cmluZygxNiksXG4gICAgXSk7XG4gIH0gZWxzZSB7XG4gICAgbXNnSGFzaCA9IHBlZGVyc2VuKFtcbiAgICAgIHBlZGVyc2VuKFtwZWRlcnNlbihbdG9rZW4wLCB0b2tlbjFPclB1YktleV0pLCBjb25kaXRpb25dKSxcbiAgICAgIHBhY2tlZE1lc3NhZ2UudG9TdHJpbmcoMTYpLFxuICAgIF0pO1xuICB9XG5cbiAgY29uc3QgbXNnSGFzaEJOID0gbmV3IEJOKG1zZ0hhc2gsIDE2KTtcbiAgYXNzZXJ0SW5SYW5nZShtc2dIYXNoQk4sIHplcm9CbiwgbWF4RWNkc2FWYWwsICdtc2dIYXNoJyk7XG4gIHJldHVybiBtc2dIYXNoO1xufVxuXG5mdW5jdGlvbiBoYXNoVHJhbnNmZXJNc2dXaXRoRmVlKFxuICBpbnN0cnVjdGlvblR5cGVCbixcbiAgc2VuZGVyVmF1bHRJZEJuLFxuICByZWNlaXZlclZhdWx0SWRCbixcbiAgYW1vdW50Qm4sXG4gIG5vbmNlQm4sXG4gIGV4cGlyYXRpb25UaW1lc3RhbXBCbixcbiAgdHJhbnNmZXJUb2tlbixcbiAgcmVjZWl2ZXJQdWJsaWNLZXksXG4gIGZlZVRva2VuLFxuICBmZWVWYXVsdElkQm4sXG4gIGZlZUxpbWl0Qm4sXG4gIGNvbmRpdGlvbiA9IG51bGxcbikge1xuICBsZXQgcGFja2VkTWVzc2FnZTEgPSBzZW5kZXJWYXVsdElkQm47XG4gIHBhY2tlZE1lc3NhZ2UxID0gcGFja2VkTWVzc2FnZTEudXNobG4oNjQpLmFkZChyZWNlaXZlclZhdWx0SWRCbik7XG4gIHBhY2tlZE1lc3NhZ2UxID0gcGFja2VkTWVzc2FnZTEudXNobG4oNjQpLmFkZChmZWVWYXVsdElkQm4pO1xuICBwYWNrZWRNZXNzYWdlMSA9IHBhY2tlZE1lc3NhZ2UxLnVzaGxuKDMyKS5hZGQobm9uY2VCbik7XG4gIGxldCBwYWNrZWRNZXNzYWdlMiA9IGluc3RydWN0aW9uVHlwZUJuO1xuICBwYWNrZWRNZXNzYWdlMiA9IHBhY2tlZE1lc3NhZ2UyLnVzaGxuKDY0KS5hZGQoYW1vdW50Qm4pO1xuICBwYWNrZWRNZXNzYWdlMiA9IHBhY2tlZE1lc3NhZ2UyLnVzaGxuKDY0KS5hZGQoZmVlTGltaXRCbik7XG4gIHBhY2tlZE1lc3NhZ2UyID0gcGFja2VkTWVzc2FnZTIudXNobG4oMzIpLmFkZChleHBpcmF0aW9uVGltZXN0YW1wQm4pO1xuICBwYWNrZWRNZXNzYWdlMiA9IHBhY2tlZE1lc3NhZ2UyLnVzaGxuKDgxKS5hZGQoemVyb0JuKTtcblxuICBsZXQgbXNnSGFzaCA9IG51bGw7XG4gIGNvbnN0IHRtcEhhc2ggPSBwZWRlcnNlbihbXG4gICAgcGVkZXJzZW4oW3RyYW5zZmVyVG9rZW4sIGZlZVRva2VuXSksXG4gICAgcmVjZWl2ZXJQdWJsaWNLZXksXG4gIF0pO1xuICBpZiAoY29uZGl0aW9uID09PSBudWxsKSB7XG4gICAgbXNnSGFzaCA9IHBlZGVyc2VuKFtcbiAgICAgIHBlZGVyc2VuKFt0bXBIYXNoLCBwYWNrZWRNZXNzYWdlMS50b1N0cmluZygxNildKSxcbiAgICAgIHBhY2tlZE1lc3NhZ2UyLnRvU3RyaW5nKDE2KSxcbiAgICBdKTtcbiAgfSBlbHNlIHtcbiAgICBtc2dIYXNoID0gcGVkZXJzZW4oW1xuICAgICAgcGVkZXJzZW4oW3BlZGVyc2VuKFt0bXBIYXNoLCBjb25kaXRpb25dKSwgcGFja2VkTWVzc2FnZTEudG9TdHJpbmcoMTYpXSksXG4gICAgICBwYWNrZWRNZXNzYWdlMi50b1N0cmluZygxNiksXG4gICAgXSk7XG4gIH1cblxuICBjb25zdCBtc2dIYXNoQk4gPSBuZXcgQk4obXNnSGFzaCwgMTYpO1xuICBhc3NlcnRJblJhbmdlKG1zZ0hhc2hCTiwgemVyb0JuLCBtYXhFY2RzYVZhbCwgJ21zZ0hhc2gnKTtcbiAgcmV0dXJuIG1zZ0hhc2g7XG59XG5cbmZ1bmN0aW9uIGhhc2hMaW1pdE9yZGVyTXNnV2l0aEZlZShcbiAgaW5zdHJ1Y3Rpb25UeXBlQm4sXG4gIHZhdWx0U2VsbEJuLFxuICB2YXVsdEJ1eUJuLFxuICBhbW91bnRTZWxsQm4sXG4gIGFtb3VudEJ1eUJuLFxuICBub25jZUJuLFxuICBleHBpcmF0aW9uVGltZXN0YW1wQm4sXG4gIHRva2VuU2VsbCxcbiAgdG9rZW5CdXksXG4gIGZlZVRva2VuLFxuICBmZWVWYXVsdElkQm4sXG4gIGZlZUxpbWl0Qm5cbikge1xuICBsZXQgcGFja2VkTWVzc2FnZTEgPSBhbW91bnRTZWxsQm47XG4gIHBhY2tlZE1lc3NhZ2UxID0gcGFja2VkTWVzc2FnZTEudXNobG4oNjQpLmFkZChhbW91bnRCdXlCbik7XG4gIHBhY2tlZE1lc3NhZ2UxID0gcGFja2VkTWVzc2FnZTEudXNobG4oNjQpLmFkZChmZWVMaW1pdEJuKTtcbiAgcGFja2VkTWVzc2FnZTEgPSBwYWNrZWRNZXNzYWdlMS51c2hsbigzMikuYWRkKG5vbmNlQm4pO1xuICBsZXQgcGFja2VkTWVzc2FnZTIgPSBpbnN0cnVjdGlvblR5cGVCbjtcbiAgcGFja2VkTWVzc2FnZTIgPSBwYWNrZWRNZXNzYWdlMi51c2hsbig2NCkuYWRkKGZlZVZhdWx0SWRCbik7XG4gIHBhY2tlZE1lc3NhZ2UyID0gcGFja2VkTWVzc2FnZTIudXNobG4oNjQpLmFkZCh2YXVsdFNlbGxCbik7XG4gIHBhY2tlZE1lc3NhZ2UyID0gcGFja2VkTWVzc2FnZTIudXNobG4oNjQpLmFkZCh2YXVsdEJ1eUJuKTtcbiAgcGFja2VkTWVzc2FnZTIgPSBwYWNrZWRNZXNzYWdlMi51c2hsbigzMikuYWRkKGV4cGlyYXRpb25UaW1lc3RhbXBCbik7XG4gIHBhY2tlZE1lc3NhZ2UyID0gcGFja2VkTWVzc2FnZTIudXNobG4oMTcpLmFkZCh6ZXJvQm4pO1xuXG4gIGxldCBtc2dIYXNoID0gbnVsbDtcbiAgY29uc3QgdG1wSGFzaCA9IHBlZGVyc2VuKFtwZWRlcnNlbihbdG9rZW5TZWxsLCB0b2tlbkJ1eV0pLCBmZWVUb2tlbl0pO1xuXG4gIG1zZ0hhc2ggPSBwZWRlcnNlbihbXG4gICAgcGVkZXJzZW4oW3RtcEhhc2gsIHBhY2tlZE1lc3NhZ2UxLnRvU3RyaW5nKDE2KV0pLFxuICAgIHBhY2tlZE1lc3NhZ2UyLnRvU3RyaW5nKDE2KSxcbiAgXSk7XG5cbiAgY29uc3QgbXNnSGFzaEJOID0gbmV3IEJOKG1zZ0hhc2gsIDE2KTtcbiAgYXNzZXJ0SW5SYW5nZShtc2dIYXNoQk4sIHplcm9CbiwgbWF4RWNkc2FWYWwsICdtc2dIYXNoJyk7XG4gIHJldHVybiBtc2dIYXNoO1xufVxuXG4vKlxuIFNlcmlhbGl6ZXMgdGhlIG9yZGVyIG1lc3NhZ2UgaW4gdGhlIGNhbm9uaWNhbCBmb3JtYXQgZXhwZWN0ZWQgYnkgdGhlIHZlcmlmaWVyLlxuIHBhcnR5X2Egc2VsbHMgYW1vdW50U2VsbCBjb2lucyBvZiB0b2tlblNlbGwgZnJvbSB2YXVsdFNlbGwuXG4gcGFydHlfYSBidXlzIGFtb3VudEJ1eSBjb2lucyBvZiB0b2tlbkJ1eSBpbnRvIHZhdWx0QnV5LlxuIEV4cGVjdGVkIHR5cGVzOlxuIC0tLS0tLS0tLS0tLS0tLVxuIHZhdWx0U2VsbCwgdmF1bHRCdXkgLSB1aW50MzEgKGFzIGludClcbiBhbW91bnRTZWxsLCBhbW91bnRCdXkgLSB1aW50NjMgKGFzIGRlY2ltYWwgc3RyaW5nKVxuIHRva2VuU2VsbCwgdG9rZW5CdXkgLSB1aW50MjU2IGZpZWxkIGVsZW1lbnQgc3RyaWN0bHkgbGVzcyB0aGFuIHRoZSBwcmltZSAoYXMgaGV4IHN0cmluZyB3aXRoIDB4KVxuIG5vbmNlIC0gdWludDMxIChhcyBpbnQpXG4gZXhwaXJhdGlvblRpbWVzdGFtcCAtIHVpbnQyMiAoYXMgaW50KS5cbiovXG5leHBvcnQgZnVuY3Rpb24gZ2V0TGltaXRPcmRlck1zZ0hhc2goXG4gIHZhdWx0U2VsbCxcbiAgdmF1bHRCdXksXG4gIGFtb3VudFNlbGwsXG4gIGFtb3VudEJ1eSxcbiAgdG9rZW5TZWxsLFxuICB0b2tlbkJ1eSxcbiAgbm9uY2UsXG4gIGV4cGlyYXRpb25UaW1lc3RhbXBcbikge1xuICBhc3NlcnQoXG4gICAgaGFzSGV4UHJlZml4KHRva2VuU2VsbCkgJiYgaGFzSGV4UHJlZml4KHRva2VuQnV5KSxcbiAgICAnSGV4IHN0cmluZ3MgZXhwZWN0ZWQgdG8gYmUgcHJlZml4ZWQgd2l0aCAweC4nXG4gICk7XG4gIGNvbnN0IHZhdWx0U2VsbEJuID0gbmV3IEJOKHZhdWx0U2VsbCk7XG4gIGNvbnN0IHZhdWx0QnV5Qm4gPSBuZXcgQk4odmF1bHRCdXkpO1xuICBjb25zdCBhbW91bnRTZWxsQm4gPSBuZXcgQk4oYW1vdW50U2VsbCwgMTApO1xuICBjb25zdCBhbW91bnRCdXlCbiA9IG5ldyBCTihhbW91bnRCdXksIDEwKTtcbiAgY29uc3QgdG9rZW5TZWxsQm4gPSBuZXcgQk4odG9rZW5TZWxsLnN1YnN0cmluZygyKSwgMTYpO1xuICBjb25zdCB0b2tlbkJ1eUJuID0gbmV3IEJOKHRva2VuQnV5LnN1YnN0cmluZygyKSwgMTYpO1xuICBjb25zdCBub25jZUJuID0gbmV3IEJOKG5vbmNlKTtcbiAgY29uc3QgZXhwaXJhdGlvblRpbWVzdGFtcEJuID0gbmV3IEJOKGV4cGlyYXRpb25UaW1lc3RhbXApO1xuXG4gIGFzc2VydEluUmFuZ2UodmF1bHRTZWxsQm4sIHplcm9CbiwgdHdvUG93MzFCbik7XG4gIGFzc2VydEluUmFuZ2UodmF1bHRCdXlCbiwgemVyb0JuLCB0d29Qb3czMUJuKTtcbiAgYXNzZXJ0SW5SYW5nZShhbW91bnRTZWxsQm4sIHplcm9CbiwgdHdvUG93NjNCbik7XG4gIGFzc2VydEluUmFuZ2UoYW1vdW50QnV5Qm4sIHplcm9CbiwgdHdvUG93NjNCbik7XG4gIGFzc2VydEluUmFuZ2UodG9rZW5TZWxsQm4sIHplcm9CbiwgcHJpbWUpO1xuICBhc3NlcnRJblJhbmdlKHRva2VuQnV5Qm4sIHplcm9CbiwgcHJpbWUpO1xuICBhc3NlcnRJblJhbmdlKG5vbmNlQm4sIHplcm9CbiwgdHdvUG93MzFCbik7XG4gIGFzc2VydEluUmFuZ2UoZXhwaXJhdGlvblRpbWVzdGFtcEJuLCB6ZXJvQm4sIHR3b1BvdzIyQm4pO1xuXG4gIGNvbnN0IGluc3RydWN0aW9uVHlwZSA9IHplcm9CbjtcbiAgcmV0dXJuIGhhc2hNc2coXG4gICAgaW5zdHJ1Y3Rpb25UeXBlLFxuICAgIHZhdWx0U2VsbEJuLFxuICAgIHZhdWx0QnV5Qm4sXG4gICAgYW1vdW50U2VsbEJuLFxuICAgIGFtb3VudEJ1eUJuLFxuICAgIG5vbmNlQm4sXG4gICAgZXhwaXJhdGlvblRpbWVzdGFtcEJuLFxuICAgIHRva2VuU2VsbC5zdWJzdHJpbmcoMiksXG4gICAgdG9rZW5CdXkuc3Vic3RyaW5nKDIpXG4gICk7XG59XG5cbi8qXG4gU2FtZSBhcyBnZXRMaW1pdE9yZGVyTXNnSGFzaCwgYnV0IGFsc28gcmVxdWlyZXMgdGhlIGZlZSBpbmZvLlxuXG4gRXhwZWN0ZWQgdHlwZXMgb2YgZmVlIGluZm8gcGFyYW1zOlxuIC0tLS0tLS0tLS0tLS0tLVxuIGZlZVZhdWx0SWQgLSB1aW50MzEgKGFzIGludClcbiBmZWVMaW1pdCAtIHVpbnQ2MyAoYXMgZGVjaW1hbCBzdHJpbmcpXG4gZmVlVG9rZW4gLSB1aW50MjU2IGZpZWxkIGVsZW1lbnQgc3RyaWN0bHkgbGVzcyB0aGFuIHRoZSBwcmltZSAoYXMgaGV4IHN0cmluZyB3aXRoIDB4KVxuKi9cbmV4cG9ydCBmdW5jdGlvbiBnZXRMaW1pdE9yZGVyTXNnSGFzaFdpdGhGZWUoXG4gIHZhdWx0U2VsbCxcbiAgdmF1bHRCdXksXG4gIGFtb3VudFNlbGwsXG4gIGFtb3VudEJ1eSxcbiAgdG9rZW5TZWxsLFxuICB0b2tlbkJ1eSxcbiAgbm9uY2UsXG4gIGV4cGlyYXRpb25UaW1lc3RhbXAsXG4gIGZlZVRva2VuLFxuICBmZWVWYXVsdElkLFxuICBmZWVMaW1pdFxuKSB7XG4gIGFzc2VydChcbiAgICBoYXNIZXhQcmVmaXgodG9rZW5TZWxsKSAmJiBoYXNIZXhQcmVmaXgodG9rZW5CdXkpLFxuICAgICdIZXggc3RyaW5ncyBleHBlY3RlZCB0byBiZSBwcmVmaXhlZCB3aXRoIDB4LidcbiAgKTtcbiAgY29uc3QgdmF1bHRTZWxsQm4gPSBuZXcgQk4odmF1bHRTZWxsKTtcbiAgY29uc3QgdmF1bHRCdXlCbiA9IG5ldyBCTih2YXVsdEJ1eSk7XG4gIGNvbnN0IGFtb3VudFNlbGxCbiA9IG5ldyBCTihhbW91bnRTZWxsLCAxMCk7XG4gIGNvbnN0IGFtb3VudEJ1eUJuID0gbmV3IEJOKGFtb3VudEJ1eSwgMTApO1xuICBjb25zdCB0b2tlblNlbGxCbiA9IG5ldyBCTih0b2tlblNlbGwuc3Vic3RyaW5nKDIpLCAxNik7XG4gIGNvbnN0IHRva2VuQnV5Qm4gPSBuZXcgQk4odG9rZW5CdXkuc3Vic3RyaW5nKDIpLCAxNik7XG4gIGNvbnN0IG5vbmNlQm4gPSBuZXcgQk4obm9uY2UpO1xuICBjb25zdCBleHBpcmF0aW9uVGltZXN0YW1wQm4gPSBuZXcgQk4oZXhwaXJhdGlvblRpbWVzdGFtcCk7XG4gIGNvbnN0IGZlZVRva2VuQm4gPSBuZXcgQk4oZmVlVG9rZW4uc3Vic3RyaW5nKDIpLCAxNik7XG4gIGNvbnN0IGZlZVZhdWx0SWRCbiA9IG5ldyBCTihmZWVWYXVsdElkKTtcbiAgY29uc3QgZmVlTGltaXRCbiA9IG5ldyBCTihmZWVMaW1pdCk7XG5cbiAgYXNzZXJ0SW5SYW5nZSh2YXVsdFNlbGxCbiwgemVyb0JuLCB0d29Qb3czMUJuKTtcbiAgYXNzZXJ0SW5SYW5nZSh2YXVsdEJ1eUJuLCB6ZXJvQm4sIHR3b1BvdzMxQm4pO1xuICBhc3NlcnRJblJhbmdlKGFtb3VudFNlbGxCbiwgemVyb0JuLCB0d29Qb3c2M0JuKTtcbiAgYXNzZXJ0SW5SYW5nZShhbW91bnRCdXlCbiwgemVyb0JuLCB0d29Qb3c2M0JuKTtcbiAgYXNzZXJ0SW5SYW5nZSh0b2tlblNlbGxCbiwgemVyb0JuLCBwcmltZSk7XG4gIGFzc2VydEluUmFuZ2UodG9rZW5CdXlCbiwgemVyb0JuLCBwcmltZSk7XG4gIGFzc2VydEluUmFuZ2Uobm9uY2VCbiwgemVyb0JuLCB0d29Qb3czMUJuKTtcbiAgYXNzZXJ0SW5SYW5nZShleHBpcmF0aW9uVGltZXN0YW1wQm4sIHplcm9CbiwgdHdvUG93MjJCbik7XG4gIGFzc2VydEluUmFuZ2UoZmVlVG9rZW5CbiwgemVyb0JuLCBwcmltZSk7XG4gIGFzc2VydEluUmFuZ2UoZmVlVmF1bHRJZEJuLCB6ZXJvQm4sIHR3b1BvdzMxQm4pO1xuICBhc3NlcnRJblJhbmdlKGZlZUxpbWl0Qm4sIHplcm9CbiwgdHdvUG93NjNCbik7XG5cbiAgY29uc3QgaW5zdHJ1Y3Rpb25UeXBlID0gdGhyZWVCbjtcbiAgcmV0dXJuIGhhc2hMaW1pdE9yZGVyTXNnV2l0aEZlZShcbiAgICBpbnN0cnVjdGlvblR5cGUsXG4gICAgdmF1bHRTZWxsQm4sXG4gICAgdmF1bHRCdXlCbixcbiAgICBhbW91bnRTZWxsQm4sXG4gICAgYW1vdW50QnV5Qm4sXG4gICAgbm9uY2VCbixcbiAgICBleHBpcmF0aW9uVGltZXN0YW1wQm4sXG4gICAgdG9rZW5TZWxsLnN1YnN0cmluZygyKSxcbiAgICB0b2tlbkJ1eS5zdWJzdHJpbmcoMiksXG4gICAgZmVlVG9rZW4uc3Vic3RyaW5nKDIpLFxuICAgIGZlZVZhdWx0SWRCbixcbiAgICBmZWVMaW1pdEJuXG4gICk7XG59XG5cbi8qXG4gU2VyaWFsaXplcyB0aGUgdHJhbnNmZXIgbWVzc2FnZSBpbiB0aGUgY2Fub25pY2FsIGZvcm1hdCBleHBlY3RlZCBieSB0aGUgdmVyaWZpZXIuXG4gVGhlIHNlbmRlciB0cmFuc2ZlciAnYW1vdW50JyBjb2lucyBvZiAndG9rZW4nIGZyb20gdmF1bHQgd2l0aCBpZCBzZW5kZXJWYXVsdElkIHRvIHZhdWx0IHdpdGggaWRcbiByZWNlaXZlclZhdWx0SWQuIFRoZSByZWNlaXZlcidzIHB1YmxpYyBrZXkgaXMgcmVjZWl2ZXJQdWJsaWNLZXkuXG4gSWYgYSBjb25kaXRpb24gaXMgYWRkZWQsIGl0IGlzIHZlcmlmaWVkIGJlZm9yZSBleGVjdXRpbmcgdGhlIHRyYW5zZmVyLiBUaGUgZm9ybWF0IG9mIHRoZSBjb25kaXRpb25cbiBpcyBkZWZpbmVkIGJ5IHRoZSBhcHBsaWNhdGlvbi5cbiBFeHBlY3RlZCB0eXBlczpcbiAtLS0tLS0tLS0tLS0tLS1cbiBhbW91bnQgLSB1aW50NjMgKGFzIGRlY2ltYWwgc3RyaW5nKVxuIG5vbmNlIC0gdWludDMxIChhcyBpbnQpXG4gc2VuZGVyVmF1bHRJZCB1aW50MzEgKGFzIGludClcbiB0b2tlbiAtIHVpbnQyNTYgZmllbGQgZWxlbWVudCBzdHJpY3RseSBsZXNzIHRoYW4gdGhlIHByaW1lIChhcyBoZXggc3RyaW5nIHdpdGggMHgpXG4gcmVjZWl2ZXJWYXVsdElkIC0gdWludDMxIChhcyBpbnQpXG4gcmVjZWl2ZXJQdWJsaWNLZXkgLSB1aW50MjU2IGZpZWxkIGVsZW1lbnQgc3RyaWN0bHkgbGVzcyB0aGFuIHRoZSBwcmltZSAoYXMgaGV4IHN0cmluZyB3aXRoIDB4KVxuIGV4cGlyYXRpb25UaW1lc3RhbXAgLSB1aW50MjIgKGFzIGludCkuXG4gY29uZGl0aW9uIC0gdWludDI1NiBmaWVsZCBlbGVtZW50IHN0cmljdGx5IGxlc3MgdGhhbiB0aGUgcHJpbWUgKGFzIGhleCBzdHJpbmcgd2l0aCAweClcbiovXG5leHBvcnQgZnVuY3Rpb24gZ2V0VHJhbnNmZXJNc2dIYXNoKFxuICBhbW91bnQsXG4gIG5vbmNlLFxuICBzZW5kZXJWYXVsdElkLFxuICB0b2tlbixcbiAgcmVjZWl2ZXJWYXVsdElkLFxuICByZWNlaXZlclB1YmxpY0tleSxcbiAgZXhwaXJhdGlvblRpbWVzdGFtcCxcbiAgY29uZGl0aW9uXG4pIHtcbiAgYXNzZXJ0KFxuICAgIGhhc0hleFByZWZpeCh0b2tlbikgJiZcbiAgICAgIGhhc0hleFByZWZpeChyZWNlaXZlclB1YmxpY0tleSkgJiZcbiAgICAgICghY29uZGl0aW9uIHx8IGhhc0hleFByZWZpeChjb25kaXRpb24pKSxcbiAgICAnSGV4IHN0cmluZ3MgZXhwZWN0ZWQgdG8gYmUgcHJlZml4ZWQgd2l0aCAweC4nXG4gICk7XG4gIGNvbnN0IGFtb3VudEJuID0gbmV3IEJOKGFtb3VudCwgMTApO1xuICBjb25zdCBub25jZUJuID0gbmV3IEJOKG5vbmNlKTtcbiAgY29uc3Qgc2VuZGVyVmF1bHRJZEJuID0gbmV3IEJOKHNlbmRlclZhdWx0SWQpO1xuICBjb25zdCB0b2tlbkJuID0gbmV3IEJOKHRva2VuLnN1YnN0cmluZygyKSwgMTYpO1xuICBjb25zdCByZWNlaXZlclZhdWx0SWRCbiA9IG5ldyBCTihyZWNlaXZlclZhdWx0SWQpO1xuICBjb25zdCByZWNlaXZlclB1YmxpY0tleUJuID0gbmV3IEJOKHJlY2VpdmVyUHVibGljS2V5LnN1YnN0cmluZygyKSwgMTYpO1xuICBjb25zdCBleHBpcmF0aW9uVGltZXN0YW1wQm4gPSBuZXcgQk4oZXhwaXJhdGlvblRpbWVzdGFtcCk7XG5cbiAgYXNzZXJ0SW5SYW5nZShhbW91bnRCbiwgemVyb0JuLCB0d29Qb3c2M0JuKTtcbiAgYXNzZXJ0SW5SYW5nZShub25jZUJuLCB6ZXJvQm4sIHR3b1BvdzMxQm4pO1xuICBhc3NlcnRJblJhbmdlKHNlbmRlclZhdWx0SWRCbiwgemVyb0JuLCB0d29Qb3czMUJuKTtcbiAgYXNzZXJ0SW5SYW5nZSh0b2tlbkJuLCB6ZXJvQm4sIHByaW1lKTtcbiAgYXNzZXJ0SW5SYW5nZShyZWNlaXZlclZhdWx0SWRCbiwgemVyb0JuLCB0d29Qb3czMUJuKTtcbiAgYXNzZXJ0SW5SYW5nZShyZWNlaXZlclB1YmxpY0tleUJuLCB6ZXJvQm4sIHByaW1lKTtcbiAgYXNzZXJ0SW5SYW5nZShleHBpcmF0aW9uVGltZXN0YW1wQm4sIHplcm9CbiwgdHdvUG93MjJCbik7XG4gIGxldCBpbnN0cnVjdGlvblR5cGUgPSBvbmVCbjtcbiAgbGV0IGNvbmQgPSBudWxsO1xuICBpZiAoY29uZGl0aW9uKSB7XG4gICAgY29uZCA9IGNvbmRpdGlvbi5zdWJzdHJpbmcoMik7XG4gICAgYXNzZXJ0SW5SYW5nZShuZXcgQk4oY29uZCwgMTYpLCB6ZXJvQm4sIHByaW1lLCAnY29uZGl0aW9uJyk7XG4gICAgaW5zdHJ1Y3Rpb25UeXBlID0gdHdvQm47XG4gIH1cbiAgcmV0dXJuIGhhc2hNc2coXG4gICAgaW5zdHJ1Y3Rpb25UeXBlLFxuICAgIHNlbmRlclZhdWx0SWRCbixcbiAgICByZWNlaXZlclZhdWx0SWRCbixcbiAgICBhbW91bnRCbixcbiAgICB6ZXJvQm4sXG4gICAgbm9uY2VCbixcbiAgICBleHBpcmF0aW9uVGltZXN0YW1wQm4sXG4gICAgdG9rZW4uc3Vic3RyaW5nKDIpLFxuICAgIHJlY2VpdmVyUHVibGljS2V5LnN1YnN0cmluZygyKSxcbiAgICBjb25kXG4gICk7XG59XG5cbi8qXG4gU2FtZSBhcyBnZXRUcmFuc2Zlck1zZ0hhc2gsIGJ1dCBhbHNvIHJlcXVpcmVzIHRoZSBmZWUgaW5mby5cblxuIEV4cGVjdGVkIHR5cGVzIG9mIGZlZSBpbmZvIHBhcmFtczpcbiAtLS0tLS0tLS0tLS0tLS1cbiBmZWVWYXVsdElkIC0gdWludDMxIChhcyBpbnQpXG4gZmVlTGltaXQgLSB1aW50NjMgKGFzIGRlY2ltYWwgc3RyaW5nKVxuIGZlZVRva2VuIC0gdWludDI1NiBmaWVsZCBlbGVtZW50IHN0cmljdGx5IGxlc3MgdGhhbiB0aGUgcHJpbWUgKGFzIGhleCBzdHJpbmcgd2l0aCAweClcbiovXG5leHBvcnQgZnVuY3Rpb24gZ2V0VHJhbnNmZXJNc2dIYXNoV2l0aEZlZShcbiAgYW1vdW50LFxuICBub25jZSxcbiAgc2VuZGVyVmF1bHRJZCxcbiAgdG9rZW4sXG4gIHJlY2VpdmVyVmF1bHRJZCxcbiAgcmVjZWl2ZXJTdGFya0tleSxcbiAgZXhwaXJhdGlvblRpbWVzdGFtcCxcbiAgY29uZGl0aW9uLFxuICBmZWVUb2tlbixcbiAgZmVlVmF1bHRJZCxcbiAgZmVlTGltaXRcbikge1xuICBhc3NlcnQoXG4gICAgaGFzSGV4UHJlZml4KGZlZVRva2VuKSAmJlxuICAgICAgaGFzSGV4UHJlZml4KHRva2VuKSAmJlxuICAgICAgaGFzSGV4UHJlZml4KHJlY2VpdmVyU3RhcmtLZXkpICYmXG4gICAgICAoIWNvbmRpdGlvbiB8fCBoYXNIZXhQcmVmaXgoY29uZGl0aW9uKSksXG4gICAgJ0hleCBzdHJpbmdzIGV4cGVjdGVkIHRvIGJlIHByZWZpeGVkIHdpdGggMHguJ1xuICApO1xuICBjb25zdCBhbW91bnRCbiA9IG5ldyBCTihhbW91bnQsIDEwKTtcbiAgY29uc3Qgbm9uY2VCbiA9IG5ldyBCTihub25jZSk7XG4gIGNvbnN0IHNlbmRlclZhdWx0SWRCbiA9IG5ldyBCTihzZW5kZXJWYXVsdElkKTtcbiAgY29uc3QgdG9rZW5CbiA9IG5ldyBCTih0b2tlbi5zdWJzdHJpbmcoMiksIDE2KTtcbiAgY29uc3QgcmVjZWl2ZXJWYXVsdElkQm4gPSBuZXcgQk4ocmVjZWl2ZXJWYXVsdElkKTtcbiAgY29uc3QgcmVjZWl2ZXJTdGFya0tleUJuID0gbmV3IEJOKHJlY2VpdmVyU3RhcmtLZXkuc3Vic3RyaW5nKDIpLCAxNik7XG4gIGNvbnN0IGV4cGlyYXRpb25UaW1lc3RhbXBCbiA9IG5ldyBCTihleHBpcmF0aW9uVGltZXN0YW1wKTtcbiAgY29uc3QgZmVlVG9rZW5CbiA9IG5ldyBCTihmZWVUb2tlbi5zdWJzdHJpbmcoMiksIDE2KTtcbiAgY29uc3QgZmVlVmF1bHRJZEJuID0gbmV3IEJOKGZlZVZhdWx0SWQpO1xuICBjb25zdCBmZWVMaW1pdEJuID0gbmV3IEJOKGZlZUxpbWl0KTtcblxuICBhc3NlcnRJblJhbmdlKGFtb3VudEJuLCB6ZXJvQm4sIHR3b1BvdzYzQm4pO1xuICBhc3NlcnRJblJhbmdlKG5vbmNlQm4sIHplcm9CbiwgdHdvUG93MzFCbik7XG4gIGFzc2VydEluUmFuZ2Uoc2VuZGVyVmF1bHRJZEJuLCB6ZXJvQm4sIHR3b1BvdzMxQm4pO1xuICBhc3NlcnRJblJhbmdlKHRva2VuQm4sIHplcm9CbiwgcHJpbWUpO1xuICBhc3NlcnRJblJhbmdlKHJlY2VpdmVyVmF1bHRJZEJuLCB6ZXJvQm4sIHR3b1BvdzMxQm4pO1xuICBhc3NlcnRJblJhbmdlKHJlY2VpdmVyU3RhcmtLZXlCbiwgemVyb0JuLCBwcmltZSk7XG4gIGFzc2VydEluUmFuZ2UoZXhwaXJhdGlvblRpbWVzdGFtcEJuLCB6ZXJvQm4sIHR3b1BvdzIyQm4pO1xuICBhc3NlcnRJblJhbmdlKGZlZVRva2VuQm4sIHplcm9CbiwgcHJpbWUpO1xuICBhc3NlcnRJblJhbmdlKGZlZVZhdWx0SWRCbiwgemVyb0JuLCB0d29Qb3czMUJuKTtcbiAgYXNzZXJ0SW5SYW5nZShmZWVMaW1pdEJuLCB6ZXJvQm4sIHR3b1BvdzYzQm4pO1xuXG4gIGxldCBpbnN0cnVjdGlvblR5cGUgPSBmb3VyQm47XG4gIGxldCBjb25kID0gbnVsbDtcbiAgaWYgKGNvbmRpdGlvbikge1xuICAgIGNvbmQgPSBjb25kaXRpb24uc3Vic3RyaW5nKDIpO1xuICAgIGFzc2VydEluUmFuZ2UobmV3IEJOKGNvbmQpLCB6ZXJvQm4sIHByaW1lLCAnY29uZGl0aW9uJyk7XG4gICAgaW5zdHJ1Y3Rpb25UeXBlID0gZml2ZUJuO1xuICB9XG4gIHJldHVybiBoYXNoVHJhbnNmZXJNc2dXaXRoRmVlKFxuICAgIGluc3RydWN0aW9uVHlwZSxcbiAgICBzZW5kZXJWYXVsdElkQm4sXG4gICAgcmVjZWl2ZXJWYXVsdElkQm4sXG4gICAgYW1vdW50Qm4sXG4gICAgbm9uY2VCbixcbiAgICBleHBpcmF0aW9uVGltZXN0YW1wQm4sXG4gICAgdG9rZW4uc3Vic3RyaW5nKDIpLFxuICAgIHJlY2VpdmVyU3RhcmtLZXkuc3Vic3RyaW5nKDIpLFxuICAgIGZlZVRva2VuLnN1YnN0cmluZygyKSxcbiAgICBmZWVWYXVsdElkQm4sXG4gICAgZmVlTGltaXRCbixcbiAgICBjb25kXG4gICk7XG59XG5cbi8qXG4gVGhlIGZ1bmN0aW9uIF90cnVuY2F0ZVRvTiBpbiBsaWIvZWxsaXB0aWMvZWMvaW5kZXguanMgZG9lcyBhIHNoaWZ0LXJpZ2h0IG9mIGRlbHRhIGJpdHMsXG4gaWYgZGVsdGEgaXMgcG9zaXRpdmUsIHdoZXJlXG4gICBkZWx0YSA9IG1zZ0hhc2guYnl0ZUxlbmd0aCgpICogOCAtIHN0YXJrRXgubi5iaXRMZW5ndGgoKS5cbiBUaGlzIGZ1bmN0aW9uIGRvZXMgdGhlIG9wcG9zaXRlIG9wZXJhdGlvbiBzbyB0aGF0XG4gICBfdHJ1bmNhdGVUb04oZml4TXNnSGFzaExlbihtc2dIYXNoKSkgPT0gbXNnSGFzaC5cbiovXG5mdW5jdGlvbiBmaXhNc2dIYXNoTGVuKG1zZ0hhc2gpIHtcbiAgLy8gQ29udmVydCB0byBCTiB0byByZW1vdmUgbGVhZGluZyB6ZXJvcy5cbiAgY29uc3QgbSA9IG5ldyBCTihtc2dIYXNoLCAxNikudG9TdHJpbmcoMTYpO1xuXG4gIGlmIChtLmxlbmd0aCA8PSA2Mikge1xuICAgIC8vIEluIHRoaXMgY2FzZSwgbXNnSGFzaCBzaG91bGQgbm90IGJlIHRyYW5zZm9ybWVkLCBhcyB0aGUgYnl0ZUxlbmd0aCgpIGlzIGF0IG1vc3QgMzEsXG4gICAgLy8gc28gZGVsdGEgPCAwIChzZWUgX3RydW5jYXRlVG9OKS5cbiAgICByZXR1cm4gbTtcbiAgfVxuICBhc3NlcnQobS5sZW5ndGggPT09IDYzKTtcbiAgLy8gSW4gdGhpcyBjYXNlIGRlbHRhIHdpbGwgYmUgNCBzbyB3ZSBwZXJmb3JtIGEgc2hpZnQtbGVmdCBvZiA0IGJpdHMgYnkgYWRkaW5nIGEgemVyby5cbiAgcmV0dXJuIGAke219MGA7XG59XG5cbi8qXG4gU2lnbnMgYSBtZXNzYWdlIHVzaW5nIHRoZSBwcm92aWRlZCBrZXkuXG4gcHJpdmF0ZUtleSBzaG91bGQgYmUgYW4gZWxsaXB0aWMua2V5UGFpciB3aXRoIGEgdmFsaWQgcHJpdmF0ZSBrZXkuXG4gUmV0dXJucyBhbiBlbGxpcHRpYy5TaWduYXR1cmUuXG4qL1xuZXhwb3J0IGZ1bmN0aW9uIHNpZ24ocHJpdmF0ZUtleSwgbXNnSGFzaCkge1xuICBjb25zdCBtc2dIYXNoQk4gPSBuZXcgQk4obXNnSGFzaCwgMTYpO1xuICAvLyBWZXJpZnkgbWVzc2FnZSBoYXNoIGhhcyB2YWxpZCBsZW5ndGguXG4gIGFzc2VydEluUmFuZ2UobXNnSGFzaEJOLCB6ZXJvQm4sIG1heEVjZHNhVmFsLCAnbXNnSGFzaCcpO1xuICBjb25zdCBtc2dTaWduYXR1cmUgPSBwcml2YXRlS2V5LnNpZ24oZml4TXNnSGFzaExlbihtc2dIYXNoKSk7XG4gIGNvbnN0IHsgciwgcyB9ID0gbXNnU2lnbmF0dXJlO1xuICBjb25zdCB3ID0gcy5pbnZtKHN0YXJrRWMubik7XG4gIC8vIFZlcmlmeSBzaWduYXR1cmUgaGFzIHZhbGlkIGxlbmd0aC5cbiAgYXNzZXJ0SW5SYW5nZShyLCBvbmVCbiwgbWF4RWNkc2FWYWwsICdyJyk7XG4gIGFzc2VydEluUmFuZ2Uocywgb25lQm4sIHN0YXJrRWMubiwgJ3MnKTtcbiAgYXNzZXJ0SW5SYW5nZSh3LCBvbmVCbiwgbWF4RWNkc2FWYWwsICd3Jyk7XG4gIHJldHVybiBtc2dTaWduYXR1cmU7XG59XG5cbi8qXG4gVmVyaWZpZXMgYSBtZXNzYWdlIHVzaW5nIHRoZSBwcm92aWRlZCBrZXkuXG4gcHVibGljS2V5IHNob3VsZCBiZSBhbiBlbGxpcHRpYy5rZXlQYWlyIHdpdGggYSB2YWxpZCBwdWJsaWMga2V5LlxuIG1zZ1NpZ25hdHVyZSBzaG91bGQgYmUgYW4gZWxsaXB0aWMuU2lnbmF0dXJlLlxuIFJldHVybnMgYSBib29sZWFuIHRydWUgaWYgdGhlIHZlcmlmaWNhdGlvbiBzdWNjZWVkcy5cbiovXG5leHBvcnQgZnVuY3Rpb24gdmVyaWZ5KHB1YmxpY0tleSwgbXNnSGFzaCwgbXNnU2lnbmF0dXJlKSB7XG4gIGNvbnN0IG1zZ0hhc2hCTiA9IG5ldyBCTihtc2dIYXNoLCAxNik7XG4gIC8vIFZlcmlmeSBtZXNzYWdlIGhhc2ggaGFzIHZhbGlkIGxlbmd0aC5cbiAgYXNzZXJ0SW5SYW5nZShtc2dIYXNoQk4sIHplcm9CbiwgbWF4RWNkc2FWYWwsICdtc2dIYXNoJyk7XG4gIGNvbnN0IHsgciwgcyB9ID0gbXNnU2lnbmF0dXJlO1xuICBjb25zdCB3ID0gcy5pbnZtKHN0YXJrRWMubik7XG4gIC8vIFZlcmlmeSBzaWduYXR1cmUgaGFzIHZhbGlkIGxlbmd0aC5cbiAgYXNzZXJ0SW5SYW5nZShyLCBvbmVCbiwgbWF4RWNkc2FWYWwsICdyJyk7XG4gIGFzc2VydEluUmFuZ2Uocywgb25lQm4sIHN0YXJrRWMubiwgJ3MnKTtcbiAgYXNzZXJ0SW5SYW5nZSh3LCBvbmVCbiwgbWF4RWNkc2FWYWwsICd3Jyk7XG4gIHJldHVybiBwdWJsaWNLZXkudmVyaWZ5KGZpeE1zZ0hhc2hMZW4obXNnSGFzaCksIG1zZ1NpZ25hdHVyZSk7XG59XG4iXX0=