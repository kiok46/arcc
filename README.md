# ARCC
ARCC - Allowable Revocable Contract Chain System for Bitcoin Cash

ARCC allows the payer to take back the money while still allowing the payee to withdraw some funds from the contract based on restrictions of time and amount.

There can be a range of applications/mechanisms possible including but not limited to, Streaming Services, Pay as you use, Recurring payments, Milestone based payouts, Project funding, Pocket money etc.

<h3>Whitepaper</h3>

[whitepaper.pdf](https://github.com/kiok46/arcc/blob/main/whitepaper.pdf)


<h3>Implementation</h3>
An Implementation of ARCC contract could be found here:

[https://github.com/cashkit/arcc-poc](https://github.com/cashkit/arcc-poc)

![Screenshot 2021-07-24 at 8 18 22 PM](https://user-images.githubusercontent.com/7335120/126872166-89be7458-fe45-40e8-9037-4d6d868f26d5.png)

<h3>Debugging</h3>

- [meep](https://github.com/gcash/meep): Bitcoin Cash Script Debugger


<h3>Existing solutions</h3>

- [Mecenas](https://github.com/KarolTrzeszczkowski/Mecenas-recurring-payment-EC-plugin/blob/master/mecenas_v1.1.spedn): Mentioned in the whitepaper.

- [Streaming Mecenas](https://cashscript.org/docs/guides/covenants/#simulating-state): Mentioned in the whitepaper.

- [CashChannels](https://blog.bitjson.com/cashchannels-recurring-payments-for-bitcoin-cash/): Mentioned in the whitepaper.


<h3>Contracts</h3>

- [Agreement.cash](https://github.com/kiok46/arcc/blob/main/contracts/Agreement.cash)

```solidity
pragma cashscript ^0.6.3;

/**
 * @param: payerPk: Pubkey of the payer.
 * @param: payeePk: Pubkey of the payee.
 * @param: epoch: Each epoch represents a timeframe, epoch = 1 is 1 block.
 * @param: maxAmountPerEpoch: Max amount allowed to be spend by payee per epoch.
 * @param: remainingTime: The remaining time after which a new epoch will start.
 * @param: remaningAmount: Remaining amount that can be withdrawan from the contract by payee before next epoch starts.
 * @param: validFrom: The blockheight/time of contract/state creation.
 *
 * - Expected improvements in near future.
 * 1. I recently received a suggestion from bitjson regarding privacy.
    I am thinking of adding a contract deadline in the ARCC itself. For me to explore more on this idea.
    I think I need to spend some time on 3 cases. (There may be more cases though and suggestions are welcome.)

    1. Accumulation: If I add a deadline when implementing an accumulation strategy in the contract then the number of epochs passed would matter.
    2. Non-Accumulation: If a deadline only accounts for only those epochs where at least 1 transaction was done, then it can simply keep a track of the epochs passed just like it keeps a track of the remaining amount. (i.e a reversed counter)
    3. Hard deadline: Expiration after a block-height, payee won’t be able to pull any funds from the contract after that.
 *
 * 2. A way to perform accumulation but have a signal(bool) to notify whether this contract supports it or
    not or the contract should be able to signal that some epochs have remaining funds. That would be cool! :D
 *
 * These changes or any different version of the contract will be available in the contracts folder of the root directory.
 */
contract Agreement(
        pubkey payerPk,
        pubkey payeePk,
        bytes4 epoch,
        bytes4 maxAmountPerEpoch,
        // bool supportAccumulationFlag,
        // bytes4 deadline,
        bytes4 remainingTime,
        bytes4 remainingAmount,
        bytes4 validFrom)
    {

    /*
    * Can only be used by the payer.
    * @param: payerSig: signature of payerPk.
    */
    function revoke(sig payerSig){
        require(checkSig(payerSig, payerPk));
    }

    /**
     * Can only be used by payee.
     * @param: payeeSig: signature of the payee.
     * @param: amountToNextState: Amount sent should be greater than 546 i.e the dust limit
     * otherwise the next state of contract will not be spendable by payee. Need more funds.
     * @param: amount: Amount to be sent to the payeePkh
     *
     * Note: It's the responsibility of the payee to calculate the miner fee when making a transaction.
     * Hence, amountToNextState = inputValue - amount - minerfee
     */
    function spend(
        sig payeeSig,
        int amountToNextState,
        int amount,
    ) {
        // Only necessary castings are used to reduce size. All other casting which either increase
        // the number of operations or keep the size same are ignored.
        
        // Check payee's signature.
        require(checkSig(payeeSig, payeePk));

        // After the contract is initiated the value of maxAmountPerEpoch is never changed, hence it's checking is not included in the contract's code.
        // At the time of creating the contract, payer and payee must make sure that value of sameMaxAmountPerEpoch is >= 546 and less than 4 byte integer limit i.e ~ 21 BCH or 2,147,483,647;
        // require(sameMaxAmountPerEpoch >= 546);
        int sameMaxAmountPerEpoch = int(maxAmountPerEpoch);

        // Make sure that the amount being spent is greater than 546 and less than maxAmountPerEpoch.
        require(within(amount, 546, sameMaxAmountPerEpoch + 1));

        // Expects epoch to be >= 0; Since it's a static variable. It's value is not checked here.
        // At the time of creating the contract, payer and payee must make sure that value of epoch is >= 0;
        // require(sameEpoch >= 0);
        // For cases where epoch is 0, the contract is not bound by time but only by amount. 
        int sameEpoch = int(epoch);

        // Each transaction rewrites the validFrom variable because it's the locktime of the transaction.
        // passedTime is the number of blocks passed after the last transaction was done and is used to calculate the remainingTime.
        int passedTime = int(tx.locktime) - int(validFrom);
        require(passedTime >= 0);
        
        // Default values to handle the case of epoch == 0.
        int newRemainingAmount = sameMaxAmountPerEpoch;
        // The assignment newRemainingTime = sameEpoch enforces that the next epoch has started but this variable can be overwritten if conditions are different.
        // Useful for cases when: Epoch == 0 or timeDifference(defined later) == 0.
        int newRemainingTime = sameEpoch;

        if (sameEpoch != 0){
            newRemainingAmount = sameMaxAmountPerEpoch - amount;
            // timeDifference == 0(defined below), marks the beginning of a new epoch.
            // Start of a new epoch also means end of the previous one, just like a day in real life.
            // That's why the value of remainingTime should never be 0. except when epoch is 0.

            int timeDifference = int(remainingTime) - (passedTime % sameEpoch);
            if (timeDifference > 0) {

                // If this condition fails then payee can spend upto maxAmountPerEpoch otherwise payee can only spend upto remaining amount.
                if (passedTime < sameEpoch){
                    // remainingAmount is expected to be in the range of (0 to maxAmountPerEpoch) at time of contract creation.
                    // The calculated value may be negative here but that would mean that the contract execution will fail because of the checks below.
                    newRemainingAmount = int(remainingAmount) - amount;
                }
                newRemainingTime = timeDifference;
            }
            if (timeDifference < 0) {
                // When a new epoch has already started but no transactions are done yet.
                // Spendable amount should be upto maxAmountPerEpoch.
                newRemainingTime = sameEpoch - abs(timeDifference);
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
    
        // Create a simulated state(Helps in enforcing spendable restrictions) by sending the money to the new contract with same
        // parameters except the timelock/validFrom.
        bytes34 toRecipient = new OutputP2PKH(bytes8(amount), hash160(payeePk));
        bytes32 toContract = new OutputP2SH(bytes8(amountToNextState), hash160(nextState));

        require(hash256(toRecipient + toContract) == tx.hashOutputs);
    }
}
```

<h3>Tests</h3>

- [Manual Tests](https://github.com/kiok46/arcc/blob/main/ARCC_Manual_Tests.pages)


<h3>Feedback?</h3>

- Open an issue here. ✔️
or
- Email me: kuldeepbb.grewal@gmail.com

<h3>Donations 🍕/⛰?</h3>

bitcoincash:qrsyeaegerl6ux8y6pc9357077v3dk2e9srx8s4qgd

![qrcode](https://user-images.githubusercontent.com/7335120/126893698-e52988f4-0681-44e3-b403-6f1fa0f9ca52.png)
