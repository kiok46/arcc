# ARCC
ARCC - Allowable Revocable Contract Chain System for Bitcoin Cash

ARCC allows the payer to take back the money while still allowing the payee to withdraw some funds from the contract based on restrictions of time and amount.

There can be a range of applications/mechanisms possible including but not limited to, Streaming Services, Pay as you use, Recurring payments, Milestone based payouts, Project funding, Pocket money, Parking tickets etc.

<h3>Whitepaper 📜</h3>

[whitepaper.pdf](https://github.com/kiok46/arcc/blob/main/whitepaper.pdf)


<h3>Implementation 🧱</h3>
An Implementation of ARCC contract could be found here:

[https://github.com/cashkit/arcc-poc](https://github.com/cashkit/arcc-poc)

![Screenshot 2021-07-24 at 8 18 22 PM](https://user-images.githubusercontent.com/7335120/126872166-89be7458-fe45-40e8-9037-4d6d868f26d5.png)


<h3>Existing solutions 👀</h3>

- [Mecenas](https://github.com/KarolTrzeszczkowski/Mecenas-recurring-payment-EC-plugin/blob/master/mecenas_v1.1.spedn): Mentioned in the whitepaper.

- [Streaming Mecenas](https://cashscript.org/docs/guides/covenants/#simulating-state): Mentioned in the whitepaper.

- [CashChannels](https://blog.bitjson.com/cashchannels-recurring-payments-for-bitcoin-cash/): Mentioned in the whitepaper.

<h3>Special thanks for improvement suggestions 🎉</h3>

- EmergentReasons (https://twitter.com/EmergentReasons)

- BitJson (https://twitter.com/bitjson)

<h3>Contracts 📄</h3>

> Different contract versions are available in the contracts/ folder

- <h4> Featured Contracts 🎖</h4>

    - [arcc with accumulation](https://github.com/kiok46/arcc/blob/main/contracts/arcc_with_accumulation.cash)
    - [arcc without accumulation](https://github.com/kiok46/arcc/blob/main/contracts/arcc_without_accumulation.cash)

```solidity
// ARCC with Accumulation
pragma cashscript ^0.6.3;

/**
 * @param: payerPkh: Payer's PubKeyHash.
 * @param: payeeLockScript: P2PKH or P2SH hash.
 * @param: expiration: Blockheight after which the the contract becomes obsolete. defaults to 6 months, i.e initial validFrom + 25920
 * @param: epoch: Each epoch represents a timeframe, eg: epoch = 1 is 1 block.
 * @param: maxAmountPerEpoch: Max amount allowed to be spend by payee per epoch.
 * @param: remainingTime: The remaining time after which a new epoch will start.
 * @param: remaningAmount: Remaining amount that can be withdrawan from the contract by payee before next epoch starts.
 * @param: validFrom: The blockheight/time of contract/state creation.
 *
 */
contract Agreement(
        bytes20 payerPkh,
        bytes payeeLockScript,
        bytes4 expiration,
        bytes4 epoch,
        bytes4 maxAmountPerEpoch,
        bytes4 remainingTime,
        bytes4 remainingAmount,
        bytes4 validFrom
    ){

    /*
    * Can only be used by the payer.
    * @param: pk: signature of payerPk.
    * @param: s: signature of payerPk.
    */
    function revoke(
        pubkey pk,
        sig s
    ){
        // Make sure that it's the payer who signs and revokes the funds.
        require(hash160(pk) == payerPkh);
        require(checkSig(s, pk));
    }

    /**
     * Can only be used by anyone but can only be paid to payee.
     * @param: payeeSig: Public Key or either Payer, Payee or third party making the transaction as the funds can only be received by the Payee because of covenants.
     * @param: s: signature that matches the public key.
     * @param: amountToNextState: Amount sent should be greater than 546 i.e the dust limit
     * otherwise the next state of contract will not be spendable by payee. Need more funds.
     * @param: amount: Amount to be sent to the payeeLockScript
     *
     * Note: It's the responsibility of the payee to calculate the miner fee when making a transaction.
     * Hence, amountToNextState = inputValue - amount - minerfee
     */
    function spend(
        pubkey pk,
        sig s,
        int amountToNextState,
        int amount,
    ){
        // Only necessary castings are used to reduce size. All other casting which either increase
        // the number of operations or keep the size same are ignored.

        // Check for a valid signature.
        require(checkSig(s, pk));

        // After the contract is initiated the value of maxAmountPerEpoch is never changed, hence it's checking is not included in the contract's code.
        // At the time of creating the contract, payer and payee must make sure that value of sameMaxAmountPerEpoch is >= 546 and
        // less than 4 byte integer limit i.e ~ 21 BCH or 2,147,483,647;
        // require(sameMaxAmountPerEpoch >= 546);
        int sameMaxAmountPerEpoch = int(maxAmountPerEpoch);

        // Expects epoch to be >= 0; Since it's a static variable. It's value is not checked here.
        // At the time of creating the contract, payer and payee must make sure that value of epoch is >= 0;
        // require(sameEpoch >= 0);
        // For cases where epoch is 0, the contract is not bound by time but only by amount.
        int sameEpoch = int(epoch);

        // Each transaction rewrites the validFrom variable because it's the locktime of the transaction.
        // passedTime is the number of blocks passed after the last transaction was done and is used to calculate the remainingTime.
        int passedTime = int(tx.locktime) - int(validFrom);
        require(passedTime >= 0);

        // Require that the locktime of the transaction is less than the expiration.
        // After expiration the contract will only be spendable by the Payer.
        require(int(tx.locktime) <= int(expiration));

        // Default values to handle the case of epoch == 0.
        int newRemainingAmount = sameMaxAmountPerEpoch - amount;

        // The assignment newRemainingTime = sameEpoch enforces that the next epoch has started but this variable can be overwritten if conditions are different.
        // Useful for cases when: Epoch == 0 or timeDifference(defined later) == 0.
        int newRemainingTime = sameEpoch;
    
        // Note:
        // 1. remainingAmount is expected to be in the range of (0 to maxAmountPerEpoch) at time of contract creation.
        // 2. Start of a new epoch also means end of the previous one, just like a day in real life.
        // that's why the value of remainingTime should never be 0. except when epoch = 0.

        if (sameEpoch != 0){
            // timeDifference == 0, marks the beginning of a new epoch.
            int timeDifference = int(remainingTime) - (passedTime % sameEpoch);

            // Next two lines are for timeDifference <= 0 but also covers some edge cases. 
            // The payee must accumulate the partial amount left only from the previous epoch.
            newRemainingAmount = sameMaxAmountPerEpoch + int(remainingAmount) - amount;
            // This condition will be true when passed time is greater than remaining time and completely 
            // ignores the fact that there might be some missed epochs.
            // When there is a missed epoch, remainingAmount will be overwritten.
            newRemainingTime = sameEpoch - abs(timeDifference);

            // This condition will be true in two cases:
            // 1. When previous transaction was done in the same epoch.
            // 2. When there is a missed epoch, remainingAmount will be overwritten.
            if (timeDifference > 0) {
                if (passedTime < sameEpoch){
                    // If this condition passes then that means there is still time left for the new
                    // epoch to start and payee can only spend from the remaining amount.
                    // The calculated value may be negative here but that would mean that the contract execution will fail because of the checks below.
                    newRemainingAmount = int(remainingAmount) - amount;
                }
                newRemainingTime = timeDifference;
            }

            if (passedTime >= (sameEpoch + int(remainingTime))){
                // Accumulation of absolute epoch(s) being missed.
                // Spendable amount should be upto a multiple of maxAmountPerEpoch but less than 4 bytes integer limit i.e 21 BCH or 2,147,483,647;
                // Note: It's the responsibility of the payee to calculate the withdrawal amount, Contract will only verify the correctness.

                // Let's assume that 3 epochs have passed since the last transaction, in the last transaction the payee spend 2000 out of 3000 maxAmountPerEpoch.
                // The remainingAmount would be 1000 and since 3 epochs have passed, the missed amount should be 1000 + 3 * 3000 = 10000.
                
                newRemainingAmount = sameMaxAmountPerEpoch;

                // Missed amount from all previously missed epochs, 10000 - 1000 = 9000.
                int missedAmount = amount - int(remainingAmount);
 
                // Total missed epochs
                // Since missedEpochs is calculated by the contract itself, payer can be assured that payee cannot spend more than allowed.
                // for example: passedTime = 7, epoch = 2, missedEpochs = (7 - 7%2)/2 = (7 - 1)/2 = 6/2 = 3
                int missedEpochs = (passedTime - (passedTime % sameEpoch))/sameEpoch;

                // Same logic as streaming mecenas, checking the correctness.
                require(missedAmount / missedEpochs == sameMaxAmountPerEpoch);
                require(missedAmount % missedEpochs == 0);
            }
        }

        // There is no need to check for the remaining time to be within the range as the calculation is only done by the contract.
        // require(within(newRemainingTime, 0, sameEpoch + 1));

        // Enforces that the newRemainingAmount should be within the range.
        // for example: when remainingAmount is less than maxAmountPerEpoch but the user tries to spend amount greater
        // than remainingAmount and the new epoch has not started yet.
        require(within(newRemainingAmount, 0, sameMaxAmountPerEpoch + 1));
        // Create a new contract with timelock as the current block height or provided locktime during contract building.
        // Note that the constructor parameters are added in the reverse order.
        // So validFrom is actually the first statement in the contract bytecode.
        bytes nextState = 0x04 + tx.locktime + 0x04 + bytes4(newRemainingAmount) + 0x04 + bytes4(newRemainingTime) + tx.bytecode.split(15)[1];

        // Create a simulated state(Helps in enforcing spendable restrictions) by sending the money to the new contract state.
        bytes toPayee = bytes8(amount) + payeeLockScript;
        bytes32 toContract = new OutputP2SH(bytes8(amountToNextState), hash160(nextState));

        require(hash256(toPayee + toContract) == tx.hashOutputs);
    }
}
```

<h3>TODOs ✔️</h3>

- Automated tests.
- Atleast one alternative solution from blockheight.
- Support for amount > 4 bytes i.e 8 bytes.

<h3>Debugging 🕵️‍♂️</h3>

- [meep](https://github.com/gcash/meep): Bitcoin Cash Script Debugger


<h3>Tests 🧪</h3>

- [Manual Tests](https://github.com/kiok46/arcc/blob/main/ARCC_Manual_Tests.pages)

<h3>Transactions Examples</h3>

- <h4>ARCC with Accumulation</h4>

    - Regular transaction https://explorer.bitcoin.com/bch/tx/67a35520ea353ae15c82b678cff475818623190faf819d53997d2d7c3d7cd151
    - Revoke transaction https://explorer.bitcoin.com/bch/tx/bf32c5345169c978eb1d84461fcc12aca8de8a98a6bacf5f6561a134e6c652d8
    - Accumulation https://explorer.bitcoin.com/bch/tx/cb07f6713360405ccd27dd62921165c6295c1fc8a270b1347bdd126c7f8914f5


<h3>Feedback?</h3>

- Please open an issue here.
- Message me on https://t.me/arccsystem

<h3>Donations 🍕/⛰?</h3>

bitcoincash:qrsyeaegerl6ux8y6pc9357077v3dk2e9srx8s4qgd

![qrcode](https://user-images.githubusercontent.com/7335120/126893698-e52988f4-0681-44e3-b403-6f1fa0f9ca52.png)
