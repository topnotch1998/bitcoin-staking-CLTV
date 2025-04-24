#!/usr/bin/env node

import * as commander from "commander";
import * as bitcoin from "bitcoinjs-lib";
import axios from "axios";
import { CLTVScript, parseCLTVScript, finalCLTVScripts } from "./src/script";
import Bignumber from "bignumber.js";
import { buildOPReturnScript } from "./src/script";
import { RedeemScriptType } from "./src/constant";
import coinSelect from "coinselect-segwit";
import { toXOnly } from "bitcoinjs-lib/src/psbt/bip371";
// @ts-ignore
import split from "coinselect-segwit/split";
import { Provider } from "./src/provider";
import * as ecc from "tiny-secp256k1";
import ECPairFactory from "ecpair";
import { getAddressType } from "./src/address";
import { stake } from "./src/stake";
import { redeem } from "./src/redeem";
import { BitcoinNetworkMap, CoreNetworkMap, FeeSpeedMap } from "./src/constant";

const ECPair = ECPairFactory(ecc);
bitcoin.initEccLib(ecc);
const lockTime = 1728499742; // CLTV timelock
const network = bitcoin.networks.testnet;

interface IUtxo {
  txid: string;
  vout: number;
  value: number;
  scriptpubkey?: string;
}

const getBtcUtxoByAddress = async (address: string) => {
  const url = `https://open-api-testnet.unisat.io/v1/indexer/address/${address}/utxo-data`;

  const config = {
    headers: {
      Authorization: `Bearer 50c50d3a720f82a3b93f164ff76989364bd49565b378b5c6a145c79251ee7672`,
    },
  };

  let cursor = 0;
  const size = 5000;
  const utxos: IUtxo[] = [];

  while (1) {
    const res = await axios.get(url, { ...config, params: { cursor, size } });

    if (res.data.code === -1) throw "Invalid Address";

    utxos.push(
      ...(res.data.data.utxo as any[]).map((utxo) => {
        return {
          scriptpubkey: utxo.scriptPk,
          txid: utxo.txid,
          value: utxo.satoshi,
          vout: utxo.vout,
        };
      })
    );

    cursor += res.data.data.utxo.length;

    if (cursor === res.data.data.total) break;
  }

  return utxos;
};

async function StakeProgram() {
  const amount = 100000;
  const account =
    "tb1p2vsa0qxsn96sulauasfgyyccfjdwp2rzg8h2ejpxcdauulltczuqw02jmj";
  const pubkey =
    "02c032c56d3af8899a15915d52c706c4659bc5ddb88ddf965bb334641ff9498d58";
  const provider = new Provider({
    network,
    bitcoinRpc: "mempool",
  });
  let addressType = getAddressType(account, network);
  let payment;
  if (addressType === "p2tr") {
    bitcoin.initEccLib(ecc);
    payment = bitcoin.payments.p2tr({
      internalPubkey: toXOnly(Buffer.from(pubkey, "hex")),
      network,
    });
  }
  // const btcUtxos = await getBtcUtxoByAddress(account);
  const fee = "f";
  const btcUtxos = await provider.getUTXOs(account);
  const bytesFee = await provider.getFeeRate(fee);

  const utxos = btcUtxos.map((utxo) => ({
    ...utxo,
    ...((addressType.includes("p2wpkh") || addressType.includes("p2tr")) && {
      witnessUtxo: {
        script: addressType.includes("p2sh")
          ? payment!.redeem!.output!
          : payment!.output!,
        value: utxo.value,
      },
    }),
    ...(addressType.includes("p2sh") && {
      redeemScript: payment!.redeem!.output,
    }),
    ...(addressType.includes("p2tr") && {
      isTaproot: true,
    }),
    sequence: 0xffffffff - 1,
  }));

  const redeemScript = CLTVScript.P2PKH({
    lockTime,
    pubkey: pubkey,
  });

  const lockScript = bitcoin.payments.p2sh({
    redeem: {
      output: redeemScript,
    },
    network,
  }).output;

  // Address for lock script
  const scriptAddress: string = bitcoin.address.fromOutputScript(
    lockScript!,
    network
  );

  const validatorAddress = "0xd82c24274EBbfe438788D684dC6034c3C67664A4"; //Validator address to delegate to.
  const rewardAddress = "0x3Df305c55DBfC8d43f8847183a48f9F0dB9a9411"; //Core address to claim CORE rewards.
  const chainId = "1112"; //Chain ID, Devnet 1112, Testnet 1115, Mainnet 1116

  const targets = [
    //time lock output
    {
      value: new Bignumber(amount).toNumber(),
      script: lockScript,
    },
    //OP_RETURN
    {
      script: buildOPReturnScript({
        chainId,
        validatorAddress,
        rewardAddress, // 20 bytes
        redeemScript: redeemScript.toString("hex"),
        coreFee: 0,
        isMultisig: false,
        lockTime,
        redeemScriptType: RedeemScriptType.PUBLIC_KEY_HASH_SCRIPT,
      }),
      value: 0,
    },
  ];

  let { inputs, outputs } = coinSelect(utxos, targets, bytesFee, account);

  const psbt = new bitcoin.Psbt({
    network,
  });

  inputs?.forEach((input) =>
    psbt.addInput({
      hash:
        typeof input.txid === "string" ? input.txid : Buffer.from(input.txid),
      index: input.vout,
      ...(input.nonWitnessUtxo
        ? {
            nonWitnessUtxo: Buffer.from(input.nonWitnessUtxo),
          }
        : {}),
      ...(input.witnessUtxo
        ? {
            witnessUtxo: {
              script: Buffer.from(input.witnessUtxo.script),
              value: input.witnessUtxo.value,
            },
          }
        : {}),
      ...(input.redeemScript
        ? { redeemScript: Buffer.from(input.redeemScript) }
        : {}),
      ...(input.witnessScript
        ? { witnessScript: Buffer.from(input.witnessScript) }
        : {}),
      ...(input.isTaproot ? { tapInternalKey: payment!.internalPubkey } : {}),
    })
  );
  const changeAddress = account;
  outputs?.forEach((output) => {
    if (!output.address && !output.script) {
      output.address = changeAddress;
    }
    psbt.addOutput({
      ...(output.script
        ? { script: Buffer.from(output.script) }
        : { address: output.address! }),
      value: output.value ?? 0,
    });
  });

  console.log(psbt.toBase64());

  // const keyPair = ECPair.fromPrivateKey(
  //   Buffer.from(
  //     "203f5a3885af05ee699250081c65588bddf4c85cd0757dd8ad5206a5de04a78c",
  //     "hex"
  //   )
  // );
  // const signer = keyPair.tweak(
  //   bitcoin.crypto.taggedHash("TapTweak", toXOnly(keyPair.publicKey))
  // );
  // psbt.signAllInputs(signer);
  // psbt.finalizeAllInputs();

  // const txId = await provider.broadcast(psbt.extractTransaction().toHex());
  // console.log(`txId: ${txId}`);

  console.log(`CLTV script address: ${scriptAddress}`);
  console.log(`redeem script: ${redeemScript.toString("hex")}`);
}

async function RedeemProgram() {
  const account = "2N6curCvgPQZYBj1an4YXBUpJMiTcia4dSH";
  let network;
  const redeemScript =
    "041ed00667b17576a914932b2cc158dd6005259d8fad8d65a1b7fb320d6388ac";
  const fee = "f";
  const bitcoinRpc = "mempool";
  const destAddress =
    "tb1p2vsa0qxsn96sulauasfgyyccfjdwp2rzg8h2ejpxcdauulltczuqw02jmj";

  let witness = false;

  if (account.length === 34 || account.length === 35) {
    const addr = bitcoin.address.fromBase58Check(account);
    network =
      addr.version === bitcoin.networks.bitcoin.pubKeyHash ||
      addr.version === bitcoin.networks.bitcoin.scriptHash
        ? bitcoin.networks.bitcoin
        : bitcoin.networks.testnet;
  } else {
    const addr = bitcoin.address.fromBech32(account);
    network =
      addr.prefix === bitcoin.networks.bitcoin.bech32
        ? bitcoin.networks.bitcoin
        : bitcoin.networks.testnet;
    witness = true;
  }

  const { options, type } = parseCLTVScript({
    witness,
    cltvScript: redeemScript,
  });

  const provider = new Provider({
    network,
    bitcoinRpc,
  });

  const bytesFee = await provider.getFeeRate(fee);

  //check private key with lock script
  const res = await provider.getUTXOs(account);
  console.log("bytesFee", bytesFee);
  console.log("utxos", res);
  const redeemScriptBuf = Buffer.from(redeemScript, "hex");

  const script = (witness ? bitcoin.payments.p2wsh : bitcoin.payments.p2sh)({
    redeem: {
      output: redeemScriptBuf,
      network,
    },
    network,
  }).output;

  const rawTxMap: Record<string, string> = {};

  if (!witness) {
    for (let i = 0; i < res.length; i++) {
      const utxo = res[i];
      if (!rawTxMap[utxo.txid]) {
        const hex = await provider.getRawTransaction(utxo.txid);
        rawTxMap[utxo.txid] = hex;
      }
    }
  }

  const utxos = res.map((utxo) => ({
    ...utxo,
    ...(!witness && {
      nonWitnessUtxo: Buffer.from(rawTxMap[utxo.txid], "hex"),
    }),
    ...(witness && {
      witnessUtxo: {
        script: script!,
        value: utxo.value,
      },
    }),
    ...(!witness
      ? {
          redeemScript: redeemScriptBuf,
        }
      : {
          witnessScript: redeemScriptBuf,
        }),
  }));

  let {
    inputs,
    outputs,
    fee: finalFee,
  } = split(
    utxos,
    [
      {
        address: destAddress,
      },
    ],
    bytesFee
  );
  console.log("fee", finalFee);
  console.log("selecte inputs", inputs);
  if (!inputs) {
    throw new Error("insufficient balance");
  }

  if (!outputs) {
    throw new Error("failed to caculate transaction fee");
  }

  //Update transaction fee by re-caculating signatures
  let signatureSize = 0;
  inputs!.forEach(() => {
    if (
      type === RedeemScriptType.MULTI_SIG_SCRIPT &&
      options.m &&
      options.m >= 1
    ) {
      signatureSize += (72 * options.m) / (witness ? 4 : 1);
    } else if (type === RedeemScriptType.PUBLIC_KEY_HASH_SCRIPT) {
      signatureSize += (72 + 66) / (witness ? 4 : 1);
    } else if (type === RedeemScriptType.PUBLIC_KEY_SCRIPT) {
      signatureSize += 72 / (witness ? 4 : 1);
    }
  });
  const signatureSizeFee = new Bignumber(signatureSize)
    .multipliedBy(new Bignumber(bytesFee))
    .toNumber();

  outputs[0].value = Math.floor(outputs[0].value! - signatureSizeFee);

  const psbt = new bitcoin.Psbt({
    network,
  });

  psbt.setLocktime(options.lockTime);

  inputs?.forEach((input: any) =>
    psbt.addInput({
      hash:
        typeof input.txid === "string" ? input.txid : Buffer.from(input.txid),
      index: input.vout,
      ...(input.nonWitnessUtxo
        ? {
            nonWitnessUtxo: Buffer.from(input.nonWitnessUtxo),
          }
        : {}),
      ...(input.witnessUtxo
        ? {
            witnessUtxo: {
              script: Buffer.from(input.witnessUtxo.script),
              value: input.witnessUtxo.value,
            },
          }
        : {}),
      ...(input.redeemScript
        ? { redeemScript: Buffer.from(input.redeemScript) }
        : {}),
      ...(input.witnessScript
        ? { witnessScript: Buffer.from(input.witnessScript) }
        : {}),
      sequence: 0xffffffff - 1,
    })
  );

  outputs?.forEach((output: any) => {
    psbt.addOutput({
      ...(output.script
        ? { script: Buffer.from(output.script) }
        : { address: output.address! }),
      value: output.value ?? 0,
    });
  });

  console.log(psbt.toHex());

  // inputs.forEach((input, idx) => {
  //   psbt.signInput(idx, keyPair);
  // });

  // if (!psbt.validateSignaturesOfAllInputs(validatorSignature)) {
  //   throw new Error("signature is invalid");
  // }

  // psbt.txInputs.forEach((input, idx) => {
  //   psbt.finalizeInput(idx, finalCLTVScripts);
  // });

  // const txId = await provider.broadcast(psbt.extractTransaction().toHex());

  // return {
  //   txId,
  // };
}

async function pushTx() {
  const bitcoinRpc = "mempool";
  const psbtHex =
    "70736274ff01005e0200000001d3b726253c8d1137c2177f201524968bfa2413d3f517f023005aa4f79edb8f610000000000feffffff0139eb0000000000002251205321d780d099750e7fbcec128213184c9ae0a86241eeacc826c37bce7febc0b81ed00667000100fdc90102000000000103e060e7bad545a1ffc029ec163a1ea3d1672775523c1319f8469719dd837a35790000000000ffffffffeb576618d1ab9b9f8ee9e6ee6d66fe7fc6490414d96c13107d2650dd4ce85cb80000000000fffffffff7fef8cfb3ccd20cf2b16b43fe98af0b7851c800976a49ab2d557cbda6bea3172400000000ffffffff02a08601000000000017a91492b3a4fab34097a1a407669b933e29e559fd78b8870000000000000000536a4c505341542b0104583df305c55dbfc8d43f8847183a48f9f0db9a9411d82c24274ebbfe438788d684dc6034c3c67664a400041ed00667b17576a914932b2cc158dd6005259d8fad8d65a1b7fb320d6388ac0140e3b9566f27c70eba8c108eee9bea2bab7395b2a1240c88757da240ca43c816ac4911df8a20b25f2e06700c701fe61674dab96f62b133bbcee71535a8d872100b0140abc95a8a867c6cb8bbdf017cf8780fcfa86e315bcba8481c4f01c663488f2e6e511c5315f1cf251872d04dd17658224fada61da972215ac779fac0ec79cf7a070140aeb8915fb35653af154f392a83b4ee8dbc98f7112306c55780d08417a8d67935dbe1a1ee416ab47a6f8a3c8198ff408b4870fcc4e44abe5cfe53794a0cdaa4a700000000220202c032c56d3af8899a15915d52c706c4659bc5ddb88ddf965bb334641ff9498d58483045022100aaafbc15d26d379b27dc5f891002010c9c31f648cbdf29af580fdcb29871d5da022035b2aa0ad68c308cb83599b523f37945390f48105527e7197bd181efab2313c601010420041ed00667b17576a914932b2cc158dd6005259d8fad8d65a1b7fb320d6388ac0000";

  const psbt = bitcoin.Psbt.fromHex(psbtHex);

  const provider = new Provider({
    network,
    bitcoinRpc,
  });

  psbt.txInputs.forEach((input, idx) => {
    psbt.finalizeInput(idx, finalCLTVScripts);
  });
  const txId = await provider.broadcast(psbt.extractTransaction().toHex());
  console.log(txId);
  // return {
  //   txId,
  // };
}

// StakeProgram();
// RedeemProgram();
pushTx();

// const program = new commander.Command();

// program
//   .version("1.0.0")
//   .description("Core chain self custody BTC staking command line tool.");

// program
//   .command("stake")
//   .description("Stake BTC")

//   .requiredOption(
//     "-acc, --account <account>",
//     "The Bitcon address used to stake."
//   )
//   .requiredOption(
//     "-privkey, --privatekey <privatekey>",
//     "The private key used to sign the transaction, which should be associated with --account. Hex format."
//   )
//   .requiredOption(
//     "-amt, --amount <amount>",
//     "Amount of BTC to stake, measured in SAT."
//   )

//   .option(
//     "-bn, --bitcoinnetwork <bitcoinnetwork>",
//     "The Bitcoin network to operate on, choose between 1~2. 1)Mainnet 2)Testnet, default to 1)Mainnet."
//   )
//   .option(
//     "-cn, --corenetwork <corenetwork>",
//     "The Core network to transmit the stake transaction to, choose between 1~3. 1)Mainnet 2)Devnet 3)Testnet, default to 1)Mainnet."
//   )
//   .requiredOption(
//     "-lt, --locktime <locktime>",
//     "The unix timestamp in seconds to lock the BTC assets up to. e.g. 1711983981"
//   )
//   .option(
//     "-pubkey, --publickey <publickey>",
//     "The public key used to redeem the BTC assets when locktime expires. Default to the public key associated with --privatekey."
//   )
//   .requiredOption(
//     "-raddr, --rewardaddress <rewardaddress>",
//     "Core address used to claim staking rewards."
//   )
//   .requiredOption(
//     "-vaddr, --validatoraddress <validatoraddress>",
//     "Core validator address to stake to."
//   )
//   .option("-w, --witness", "Use segwit or not.")
//   .option(
//     "-br, --bitcoinrpc <bitcoinrpc>",
//     "The Bitcoin RPC service to use, default to https://mempool.space/. "
//   )
//   .option(
//     "--fee <fee>",
//     "Transaction fee s)slow a)average f)fast, please choose in (s, a ,f) OR a customized number in SAT, default to a)average."
//   )
//   .action(async (args) => {
//     const bitcoinnetwork = BitcoinNetworkMap[args.bitcoinnetwork];
//     const corenetwork = CoreNetworkMap[args.corenetwork];
//     const fee = FeeSpeedMap[args.fee];

//     await stake({
//       lockTime: args.locktime,
//       amount: args.amount,
//       validatorAddress: args.validatoraddress,
//       rewardAddress: args.rewardaddress,
//       publicKey: args.publickey,
//       account: args.account,
//       bitcoinNetwork: bitcoinnetwork,
//       coreNetwork: corenetwork,
//       privateKey: args.privatekey,
//       witness: args.witness,
//       bitcoinRpc: args.bitcoinrpc,
//       fee: fee || args.fee,
//     });
//   });

// program
//   .command("redeem")
//   .description("Redeem BTC")
//   .requiredOption(
//     "-acc, --account <account>",
//     "The locked P2SH/P2WSH script address."
//   )
//   .requiredOption(
//     "-r, --redeemscript <redeemscript>",
//     "The redeem script which was returned in the stake action."
//   )
//   .requiredOption(
//     "-privkey, --privatekey <privatekey>",
//     "The private key associated --publickey in the stake action. Hex format."
//   )
//   .requiredOption(
//     "-d, --destaddress <destaddress>",
//     "The Bitcoin address to receive the redeemed BTC assets."
//   )
//   .option(
//     "-br, --bitcoinrpc <bitcoinrpc>",
//     "The Bitcoin RPC service to use, default to https://mempool.space/. "
//   )
//   .option(
//     "--fee <fee>",
//     "Transaction fee s)slow a)average f)fast, please choose in (s, a ,f) OR a customized number in SAT, default to a)average."
//   )
//   .action(async (args) => {
//     const fee = FeeSpeedMap[args.fee];

//     await redeem({
//       account: args.account,
//       redeemScript: args.redeemscript,
//       privateKey: args.privatekey,
//       destAddress: args.destaddress,
//       bitcoinRpc: args.bitcoinRpc,
//       fee: fee || args.fee,
//     });
//   });

// program.parse(process.argv);
