# ARCC
ARCC - Allowable Revocable Contract Chain System for Bitcoin Cash


<h3>Whitepaper</h3>

[whitepaper.pdf](https://github.com/kiok46/arcc/blob/main/whitepaper.pdf)


<h3>Implementation</h3>
An Implementation of ARCC contract could be found here:

[https://github.com/cashkit/arcc](https://github.com/cashkit/arcc)


![arcc_ss](https://user-images.githubusercontent.com/7335120/125753256-3153b572-a68b-4a70-934f-2b744f85070b.png)


<h3>Contract</h3>

```solidity
pragma cashscript ^0.6.3;

/**
 * @param: payerPk: Pubkey of the payer.
 * @param: payeePk: Pubkey of the payee.
 * @param: epoch: Each epoch represents a timeframe.
 * @param: maxAmountPerEpoch: Max amount allowed to be spend by payee per epoch.
 * @param: remainingTime: The remaining time after which a new epoch will get started.
 * @param: remaningAmount: Remaining amount that can be withdrawan from the contract by payee before next epoch starts.
 * @param: validFrom: The blockheight/time of contract/state creation.
 */
contract Agreement(
        pubkey payerPk,
        pubkey payeePk,
        bytes4 epoch,
        bytes4 maxAmountPerEpoch,
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
     * otherwise the contract will not execute.
     * @param: amount: Amount to be sent to the payeePkh
     */
    function spend(
        sig payeeSig,
        int amountToNextState,
        int amount,
    ) {
        // Check payee's signatures.
        require(checkSig(payeeSig, payeePk));

        // Only necessary casting used to reduce size. All other casting which either increase
        // the number of operations or keep the size same are ignored.
        int sameMaxAmountPerEpoch = int(maxAmountPerEpoch);
        require(sameMaxAmountPerEpoch >= 546);
        require(within(amount, 546, sameMaxAmountPerEpoch + 1));

        // Time based checking
        // Make sure that we are not spending a contract with a blockheight less than the current height.
        int sameEpoch = int(epoch);
        require(sameEpoch >= 0);

        // require(tx.time >= int(validFrom));
        int passedTime = int(tx.locktime) - int(validFrom);
        require(passedTime >= 0);

        int newRemainingTime = int(remainingTime);
        require(within(newRemainingTime, 0, sameEpoch + 1));

        int newRemainingAmount = int(remainingAmount) - amount;
        require(within(newRemainingAmount, 0, sameMaxAmountPerEpoch + 1));

        // This `if` statement will execute in the following cases:
        // Case 1: Epoch is set to 0 which means the remainingTime will also be 0(given the initial condition was remainingTime = epoch = 0)
        //         and hence the passedTime will always be greater than or equal to remainingTime.
        //         This helps in cases where there is no need for a time.
        //         i.e epoch is set to 0 at the time of contract creation. The contracts will be dependent on the amount and maxAmountPerEpoch,
        //         and this if statement will always execute. The value of remainingAmount will always be maxAmountPerEpoch.
        // Case 2: If the passedTime is much bigger, then it means that payee has missed some epochs without fetching funds
        //         from the contract.
        //         Note: This means that if no amount was redeemed in the last epoch then that amount is no longer redeemable.
        //         The amount is not burned but simply ignored.
        //         Since the spending functionality can easily be implemented in the 'outside' world of Bitcoin Script,
        //         it's better not to include a logic which can be covered by a layer of frontend.      
        // Case 3: Payee is making a transaction within an epoch window but it's already half way through.
        if (passedTime >= newRemainingTime){
            newRemainingAmount = sameMaxAmountPerEpoch - amount;
            int timeSinceLastEpoch = 0;
            // Case 1
            if (sameEpoch == 0) {
                // This condition needs timeSinceLastEpoch = 0
                newRemainingAmount = sameMaxAmountPerEpoch;
            // Case 2
            } else if (passedTime > sameEpoch){
                timeSinceLastEpoch = passedTime % sameEpoch;
            // Case 3
            } else {
                // If epoch is passed then reset the remainingAmount to maxAmountPerEpoch
                // but subtract the amount that will be spend in this transaction.
                timeSinceLastEpoch = passedTime - newRemainingTime;
            }
            newRemainingTime = sameEpoch - timeSinceLastEpoch;
        } else {
            newRemainingTime = newRemainingTime - passedTime;
        }

        // Create a new contract with timelock as the current or provided locktime during contract building.
        // Note that the constructor parameters are added in the reverse order.
        // So initial block is actually the first statement in the contract bytecode.
        bytes nextState = 0x04 + tx.locktime + 0x04 + bytes4(newRemainingAmount) + 0x04 + bytes4(newRemainingTime) + tx.bytecode.split(15)[1];
    
        // Create a simulated state(Helps in enforcing spendable restrictions) by sending the money to the new contract with same
        // parameters except the timelock.
        bytes34 toRecipient = new OutputP2PKH(bytes8(amount), hash160(payeePk));
        bytes32 toContract = new OutputP2SH(bytes8(amountToNextState), hash160(nextState));

        require(hash256(toRecipient + toContract) == tx.hashOutputs);
    }
}
```
