# ARCC
ARCC - Allowable Revocable Contract Chain System for Bitcoin Cash


<h3>Whitepaper</h3>

[whitepaper.pdf](https://github.com/kiok46/arcc/blob/main/whitepaper.pdf)


<h3>Implementation</h3>
An Implementation of ARCC contract could be found here:

[https://github.com/cashkit/arcc](https://github.com/cashkit/arcc)


<img width="1440" alt="Screenshot 2021-07-12 at 3 26 57 PM" src="https://user-images.githubusercontent.com/7335120/125268752-a535e580-e325-11eb-8ea7-d53715ea318a.png">


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
    * @param: payerSig: signature of payer.
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
        // Make sure that only payee can make this transaction.
        require(checkSig(payeeSig, payeePk));
        int iEpoch = int(epoch);
        // As a safety measure as this amount is used in further calculations.
        require(within(amount, 546, int(maxAmountPerEpoch) + 1));
        // Make sure that we are not spending a contract with a blockheight less than the current height.
        require(tx.time >= int(validFrom));

        // This will be used to check whether a new epoch has started.
        int passedTime = int(tx.locktime) - int(validFrom);
        require(passedTime >= 0);
        // Make sure that we are waiting atleast `epoch` to be able to spend funds again.

        // This block will execute when passedTime is less than remaining time
        // i.e the epoch is not half way through yet.
        int newRemainingTime = int(remainingTime) - passedTime;
        int newRemainingAmount = int(remainingAmount) - amount;

        // This `if` statement will execute in the following cases:
        // Case 1: Epoch is set to 0 which means the remainingTime will also be always 0 and hence the passedTime will
        //         always be greater than or equal to remainingTime. This helps in cases where there is no need for a time.
        //         i.e epoch is set to 0 at the time of contract creation.
        //         The contracts will be dependent on the amount and this if statement will always execute.
        //         The value of remainingAmount will always be maxAmountPerEpoch.
        // Case 2: If the passedTime is much biger then it means that payee has missed some epochs without fetching funds
        //         from the contract.
        //         Note: This means that if no amount was redeemed in the last epoch then that amount is no longer redeemable.
        //         Since the spending functionality can easily be implemented in the 'outside' world of Bitcoin Script,
        //         it's better not to include a logic which can be covered by a layer of frontend.      
        // Case 3: Payee is making a transaction within an epoch window but it's already half way through.
        if (passedTime >= newRemainingTime){
            newRemainingAmount = int(maxAmountPerEpoch) - amount;
            // This is just a placeholder value the real value will be updated in the code below.
            int timeSinceLastEpoch = 0;
            // Case 1
            if (iEpoch == 0 ) {
                // This condition needs timeSinceLastEpoch = 0
                newRemainingAmount = int(maxAmountPerEpoch);
            // Case 2
            } else if (passedTime > iEpoch){
                timeSinceLastEpoch = passedTime % iEpoch;
            // Case 3
            } else {
                // If epoch is passed then reset the remainingAmount to maxAmountPerEpoch
                // but subtract the amount that will be spend in this transaction.
                timeSinceLastEpoch = passedTime - newRemainingTime;
            }
            newRemainingTime = iEpoch - timeSinceLastEpoch;
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