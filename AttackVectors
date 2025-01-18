# Assignment-1 The Attack Vectors

## 1. Signature Replay Attacks
Signature replay attacks in Solidity are a type of attack where an attacker resubmits a previously valid signature to perform unauthorized actions. A secure implementation needs to protect against Signature Replay Attacks by for example keeping track of all processed message hashes and only allowing new message hashes to be processed. A malicious user could attack a contract without such a control and get message hash that was sent by another user processed multiple times.
This lodeProtocol code below shows an example.

```solidity
        function verifyKYC(
        address[] calldata listOfAddresses,
        address rootAddress,
        bytes32 merkleRoot,
        bytes memory rootAddressSignature,
        bytes memory lodeProtocolSignature
        ) external {
        if (rootAddress == address(0)) revert InvalidInput("Root address cannot be zero");
        if (listOfAddresses.length == 0) revert InvalidInput("Address list cannot be empty");

        uint256 currentNonce = nonce[rootAddress];
        uint256 timestamp = block.timestamp;
        bytes32 commonHash = keccak256(
            abi.encodePacked(listOfAddresses, rootAddress, merkleRoot, currentNonce, timestamp, address(this), block.chainid, timestamp)
        );

        if (recoverSigner(commonHash, rootAddressSignature) != rootAddress) {
            revert InvalidSignature("Invalid root address signature");
        }

        if (recoverSigner(commonHash, lodeProtocolSignature) != owner()) {
            revert UnauthorizedAction("Invalid Lode Protocol admin signature");
        }

        nonce[rootAddress]++;
```
The code is exploited by replaying the same signed message with identical block.timestamp and nonce values, allowing an attacker to reuse valid signatures within a short time frame, bypassing the verifyKYC function's security checks.

Below is the poc
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;


import { Test, console2 } from "forge-std/Test.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Vm, VmSafe} from "forge-std/Vm.sol";
import {LodeProtocolKYC} from "../src/lode.sol";


contract LodeProtocolTest is Test {
   using MessageHashUtils for bytes32;
   using ECDSA for bytes32;


   uint256 rootPrivateKey = 0x1010101010101010101010101010101010101010101010101010101010101010;
   uint256 LodePrivateKey = 0x4010141010101010101010104010101010101010101010101010101010102310;


   VmSafe.Wallet wallet1 = vm.createWallet(uint256(rootPrivateKey));
   VmSafe.Wallet wallet2 = vm.createWallet(uint256(LodePrivateKey));


   address rootAddress = wallet1.addr;
   address owner = wallet2.addr;
   LodeProtocolKYC lode;


   address user = makeAddr("user");


   bytes rootAddressSignature;
   bytes lodeProtocolSignature;
   address[] listOfAddresses;
   bytes32 merkleRoot = keccak256(abi.encode("test"));
  
   event EmitListOfArrays(address[] listOfAddress);
     
   function setUp() public {
       vm.deal(user, 2 ether);
       vm.startPrank(owner);
       lode = new LodeProtocolKYC(owner);
       vm.stopPrank();
   }


   function testVerifyKYC() public {
       listOfAddresses.push(rootAddress);
       listOfAddresses.push(rootAddress);
       uint nonce = 0;
      
       bytes32 messageHash = keccak256(
           abi.encodePacked(
               listOfAddresses,
               rootAddress,
               merkleRoot,
               nonce,
               block.timestamp,
               address(lode),
               block.chainid,
               block.timestamp
           )
       );
      
       bytes32 msgHash = MessageHashUtils.toEthSignedMessageHash(messageHash);


       (uint8 v1, bytes32 r1, bytes32 s2) = vm.sign(LodePrivateKey, msgHash);
       (uint8 v, bytes32 r, bytes32 s) = vm.sign(rootPrivateKey, msgHash);


       rootAddressSignature = abi.encodePacked(r, s, v);
       lodeProtocolSignature = abi.encodePacked(r1, s2, v1);




       lode.verifyKYC(
           listOfAddresses,
           rootAddress,
           merkleRoot,
           rootAddressSignature,
           lodeProtocolSignature
       );
   }


   function testFailVerifyKYC() public {
       listOfAddresses.push(rootAddress);
       listOfAddresses.push(rootAddress);
       uint nonce = 0;
      
       bytes32 messageHash = keccak256(
           abi.encodePacked(
               listOfAddresses,
               rootAddress,
               merkleRoot,
               nonce,
               block.timestamp,
               address(lode),
               block.chainid,
               block.timestamp
           )
       );
      
       bytes32 msgHash = MessageHashUtils.toEthSignedMessageHash(messageHash);


       (uint8 v1, bytes32 r1, bytes32 s2) = vm.sign(LodePrivateKey, msgHash);
       (uint8 v, bytes32 r, bytes32 s) = vm.sign(rootPrivateKey, msgHash);


       rootAddressSignature = abi.encodePacked(r, s, v);
       lodeProtocolSignature = abi.encodePacked(r1, s2, v1);


       skip(10);


       lode.verifyKYC(
           listOfAddresses,
           rootAddress,
           merkleRoot,
           rootAddressSignature,
           lodeProtocolSignature
       );
   }
}

```
The provided code demonstrates how a replay attack can exploit the verifyKYC function due to improper use of block.timestamp in the message hash. Since the block.timestamp is included twice in the commonHash but not explicitly validated outside the function, an attacker can reuse signatures (rootAddressSignature and lodeProtocolSignature) within the same timestamp window (e.g., a single block or limited period) to bypass protections, effectively replaying the transaction. The same messageHash (including a constant nonce and block.timestamp) is reused. The skip(10) call advances time but does not affect the reused messageHash since it’s based on the unchanged initial timestamp.
The verifyKYC function accepts the replayed signature, allowing the action to repeat, proving a replay vulnerability.

## 2. Access Control
Access control checks make sure that only authorized users, like the contract owner or a trusted administrator, can perform certain actions. Without these checks, anyone could execute sensitive functions, which could result loss of funds. For example, a contract that lets users withdraw funds. If the access control is not set up properly, anyone could call the withdraw function and steal money from the contract.
Common vulnerabilities related to access control The most common vulnerabilities related to access control can be narrowed down as below.

Missed Modifier Validations — It is important to have access control validations on critical functions that execute actions like modifying the owner, transfer of funds and tokens, pausing and unpausing the contracts, etc. Missing validations either in the modifier or inside require or conditional statements will most probably lead to compromise of the contract or loss of funds.

Example of a code without Access Control
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    // Deposit function that allows anyone to deposit ETH
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // function that allows the owner to withdraw all funds
    function withdrawFunds() external {
        payable(msg.sender).transfer(address(this).balance);  // Vulnerability: No access control
    }
}
```
Since there is no access control, any user whether they are the contract owner or not can call the withdrawFunds() function and steal the entire contract's balance. This could be exploited by malicious actors who discover the lack of restrictions and drain the funds. if an attacker interacts with the contract and calls withdrawFunds(), they will be able to withdraw all the money in the contract.

## 3. Logical Issues
These errors may be the result of a simple typo, a misunderstanding of the specification, or a larger programming mistake. These tend to have severe implications on the security and functionality of the smart contract.

```solidity
function divideNft(address nftAddress, uint256 tokenId, uint256 amount) onlyNftOwner(nftAddress, tokenId) onlyNftOwner(nftAddress ,tokenId) external {
```
In the code above, the logical issue is that the onlyNFTOwner is performs the check twice which can increase gas cost. Even though it doesn't affect the protocol funds, it might reduce the number of users on the platform due to high gas cost

## 4. Public Burn Function
Public Burn Function may allow anyone to call burn function and burn tokens in a contract. It can be dangerous. There has been many instance in past where contracts had public burn functions and they were exploited well.
Example is the code below

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./IERC20.sol";

contract ERC20 is IERC20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(
        address indexed owner, address indexed spender, uint256 value
    );

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    string public name;
    string public symbol;
    uint8 public decimals;

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }

    function transfer(address recipient, uint256 amount)
        external
        returns (bool)
    {
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;
        emit Transfer(msg.sender, recipient, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount)
        external
        returns (bool)
    {
        allowance[sender][msg.sender] -= amount;
        balanceOf[sender] -= amount;
        balanceOf[recipient] += amount;
        emit Transfer(sender, recipient, amount);
        return true;
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function _burn(address from, uint256 amount) public {
        balanceOf[from] -= amount;
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external {
        _burn(from, amount);
    }
}
```
It can be prevented by implementing correct access controls like onlyOwner or by making the function internal with correct access control logic.

## 5. Denial of Service with Failed Call

External calls can fail accidentally or deliberately, which can cause a DoS condition in the contract. To minimize the damage caused by such failures, it is better to isolate each external call into its own transaction that can be initiated by the recipient of the call. This is especially relevant for payments, where it is better to let users withdraw funds rather than push funds to them automatically (this also reduces the chance of problems with the gas limit). Consider a simplified smart contract where players deposit ETH and the contract refunds these deposits at the end of the game. If the refund process uses the call method, it can activate the fallback function of recipient addresses. A malicious contract can disrupt this process by having a fallback function that reverts the transaction, causing the refund to fail and potentially locking the funds within the contract.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address recipient, uint256 amount) external returns (bool);
}

contract PaymentProcessor {

    address public owner;
    mapping(address => uint256) public balances;

    event PaymentProcessed(address indexed recipient, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    // Vulnerable method: tries to push payments to users
    function pay(address[] calldata recipients, uint256[] calldata amounts) external {
        require(recipients.length == amounts.length, "Mismatched input arrays");

        for (uint i = 0; i < recipients.length; i++) {
            address recipient = recipients[i];
            uint256 amount = amounts[i];
            
            // Transfer payment to recipient, this external call can fail
            (bool success, ) = recipient.call{value: amount}("");
            require(success, "Payment failed");  // This line is vulnerable
            emit PaymentProcessed(recipient, amount);
        }
    }

    // Function to allow the owner to deposit funds
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // Function to withdraw funds for testing purposes
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Withdraw failed");
    }
}
```
To stop this
1. protocols should avoid combining multiple calls in a single transaction, especially when calls are executed as part of a loop
2. Always assume that external calls can fail

## 6. Arithmetic Over/Under Flows
Arithmetic overflow occurs when the result of a mathematical operation exceeds the maximum value that the program can store. For example, in Solidity, if you have a uint8 (unsigned integer of 8 bits), the maximum value it can hold is 2^8−1=255. If you attempt to store a value larger than 255, it will wrap around to a smaller value.

Arithmetic underflow is the opposite of overflow. It happens when a calculation produces a value too low to be stored in the associated data type. This causes the calculation to wrap around and start from the next largest possible value.
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract OverflowUnderflowExample {

    uint8 public balance;

    // Event to log balance changes
    event BalanceChanged(uint8 newBalance);

    constructor() {
        balance = 0;
    }

    // Function that allows users to deposit an amount, this can overflow
    function deposit(uint8 amount) external {
        balance += amount;
        emit BalanceChanged(balance);
    }

    // Function that allows users to withdraw an amount, this can underflow
    function withdraw(uint8 amount) external {
        require(balance >= amount, "Insufficient balance");
        balance -= amount;
        emit BalanceChanged(balance);
    }
}
```
In the deposit function, the balance variable is of type uint8, which can store values between 0 and 255. If you try to deposit an amount that would push the balance above 255, it will overflow and wrap around, which means that balance could end up with a small number unexpectedly.

In the withdraw function, if a user tries to withdraw more than their current balance (e.g., trying to withdraw 1 when the balance is 0), an underflow could occur. The contract would incorrectly allow the withdrawal by wrapping the balance to the maximum value of uint8, which is 255.

## 7. Unprotected Ether Withdrawal
Due to missing or insufficient access controls, malicious parties can withdraw some or all Ether from the contract account.

This bug is sometimes caused by unintentionally exposing initialization functions. By wrongly naming a function intended to be a constructor, the constructor code ends up in the runtime byte code and can be called by anyone to re-initialize the contract.
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UnprotectedWithdrawal {

    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Function to deposit ether into the contract
    function deposit() external payable {}

    // Vulnerable function that allows anyone to withdraw ether
    function withdraw(uint256 amount) external {
        // No access control here, anyone can call this function
        payable(msg.sender).transfer(amount);
    }
}
```
The withdraw function in this contract allows anyone to withdraw ether from the contract by simply calling it and specifying the amount they wish to withdraw.

## 8. Wrong inheritance
Multiple inheritance introduces ambiguity called the Diamond Problem: if two or more base contracts define the same function, which one should be called in the child contract?  If a smart contract inherits from multiple contracts and the same function is defined in more than one base contract, the order of inheritance determines which function is used. If the order is not carefully managed, this can result in security vulnerabilities. For instance, if a critical function is overridden by a less secure version due to the inheritance order, it could lead to unauthorized access or other security issues.
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract A {
    // Function to change the owner of the contract
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function changeOwner(address _newOwner) public virtual {
        owner = _newOwner;
    }
}

contract B {
    // A more insecure implementation of the same function
    function changeOwner(address _newOwner) public virtual {
        owner = _newOwner;
    }
}

contract C is A, B {
    // Inheriting both A and B, but the inheritance order leads to ambiguity
}
```
## 9. reentrancy
One of the major dangers of calling external contracts is that they can take over the control flow. In the reentrancy attack, a malicious contract calls back into the calling contract before the first invocation of the function is finished. This may cause the different invocations of the function to interact in undesirable ways.  Typically, a function will transfer funds and then update the state. However, if the state update is not performed before the fund transfer, an attacker can recursively call the function, leading to multiple withdrawals before the state is updated. This vulnerability can lead to significant financial losses, as seen in high-profile incidents like the DAO hack in 2016, where over $50 million worth of Ether was stolen.
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vulnerable {
    mapping(address => uint256) public balances;

    // Fallback function to accept Ether
    receive() external payable {}

    // Deposit function to add funds to an account
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Withdraw function susceptible to reentrancy attack
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // The state should be updated after the transfer, not before!
        balances[msg.sender] -= amount;

        // Transfer the Ether
        payable(msg.sender).transfer(amount);
    }
}
```
In the withdraw function, the contract first checks if the user has enough balance and then subtracts the balance.
However, after this check and before the state is updated (balances[msg.sender] -= amount), the contract transfers Ether to the user (payable(msg.sender).transfer(amount)).
The attacker can create a malicious contract that calls the withdraw function on the vulnerable contract while it is still in the process of transferring funds.
This call allows the attacker to repeatedly withdraw funds before the state change is recorded, draining the contract’s funds.

## 10. Authorization through tx.origin
tx.origin is a global variable in Solidity which returns the address of the account that sent the transaction. Using the variable for authorization could make a contract vulnerable if an authorized account calls into a malicious contract. A call could be made to the vulnerable contract that passes the authorization check since tx.origin returns the original sender of the transaction which in this case is the authorized account
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {

    address public owner;
    
    // Constructor sets the initial owner of the contract
    constructor() {
        owner = msg.sender;
    }

    // Function to withdraw Ether, only allows the owner or tx.origin to access
    function withdraw(uint256 amount) public {
        // Vulnerability: tx.origin is used for authorization
        require(tx.origin == owner, "Only the owner can withdraw");

        // Transfer Ether to the caller
        payable(msg.sender).transfer(amount);
    }

    // Function to deposit Ether to the contract
    function deposit() public payable {}
}
```
If a user (the owner) calls another contract that then calls the withdraw function on the vulnerable contract, the check tx.origin == owner will pass, because tx.origin will return the address of the original sender (the owner), even though the actual call was made by a malicious contract.

## 11. Use of Deprecated Solidity Functions
Several functions and operators in Solidity are deprecated. Using them leads to reduced code quality. With new major versions of the Solidity compiler, deprecated functions and operators may result in side effects and compile errors.

```solidity
    // Function to withdraw Ether, only allows the owner or tx.origin to access
    function withdraw(uint256 amount) public {
        // Vulnerability: tx.origin is used for authorization
        require(tx.origin == owner, "Only the owner can withdraw");

        // Transfer Ether to the caller
        payable(msg.sender).transfer(amount);
    }
```

This is applicable to the ##10. whicch uses an old authorization check, tx.origin. If a user (the owner) calls another contract that then calls the withdraw function on the vulnerable contract, the check tx.origin == owner will pass, because tx.origin will return the address of the original sender (the owner), even though the actual call was made by a malicious contract. To fix this vulnerability, replace the use of tx.origin with msg.sender, which refers to the immediate sender of the function call (i.e., the address directly calling the contract)

## 12. Precision Loss in Calculations
Solidity mathematic procedures are similar to other programming languages. The following arithmetic operations are applicable to Solidity: Addition, Subtraction, Multiplication, Division (x / y), Modulus (x% y), Exponential (x**y) In the case of performing Integer division, Solidity may truncate the result. Hence we must multiply before dividing to prevent such loss in precision.
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {

    // Function to calculate the percentage of a value
    function calculatePercentage(uint256 value, uint256 percentage) public pure returns (uint256) {
        // Vulnerability: Integer division truncates the result, causing precision loss
        return value * percentage / 100;
    }
}
```
If the input value = 1000 and percentage = 33, the calculation should ideally be 1000 * 33 / 100 = 330.
However, if value = 1001 and percentage = 33, the calculation becomes 1001 * 33 = 33033, and when divided by 100, it results in 330, which truncates the precision lost from the original 330.33.

## 13. Function Default Visibility
Functions that do not have a function visibility type specified are public by default. This can lead to a vulnerability if a developer forgot to set the visibility and a malicious user is able to make unauthorized or unintended state changes.
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    uint256 public contractBalance;

    // Function with no visibility specifier
    // By default, this function is public and can be called by anyone
    function addFunds() payable {
        contractBalance += msg.value;
    }

    // Function to withdraw all funds
    function withdrawAll(address payable recipient) {
        require(contractBalance > 0, "No funds available");
        recipient.transfer(contractBalance);
        contractBalance = 0;
    }
}
```
Both addFunds() and withdrawAll() in the example are unintentionally public, meaning anyone can call them, potentially resulting in unauthorized access.

## 14. Loop through long arrays
executing functions in Ethereum costs gas (money), and transactions have a gas limit by definition (the gas limit of a single block). If for some reason your smart contract uses a very long array, and at some point, you need to iterate through it, you might reach the gas limit making the function unexecutable.
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    // Store a list of addresses
    address[] public addresses;

    // Add an address to the array
    function addAddress(address _address) public {
        addresses.push(_address);
    }

    // Perform a batch action on all addresses
    function distributeEther() public payable {
        require(msg.value > 0, "No Ether provided");
        uint256 length = addresses.length;

        require(length > 0, "No addresses to distribute Ether");

        // Vulnerable: Looping through a long array
        uint256 amountPerAddress = msg.value / length;
        for (uint256 i = 0; i < length; i++) {
            payable(addresses[i]).transfer(amountPerAddress);
        }
    }
}
```
The distributeEther function iterates through the entire addresses array. If the array becomes excessively large, the gas required to execute the loop may exceed the block gas limit, rendering the function unexecutable.

## 15. Unchecked Call Return Value
The return value of a message call is not checked. Execution will resume even if the called contract throws an exception. If the call fails accidentally or an attacker forces the call to fail, this may cause unexpected behaviour in the subsequent program logic.
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    // Allow users to send Ether to another address
    function sendEther(address payable recipient) public payable {
        require(msg.value > 0, "No Ether provided");

        // Vulnerable: The return value of `call` is not checked
        recipient.call{value: msg.value}("");
        
        // Logic continues even if the call fails
        // Potentially leaves Ether stuck in the contract
    }
}
```
The call method is used to transfer Ether to recipient, but its return value (which indicates success or failure) is not checked. If the call fails (e.g., the recipient contract has a receive or fallback function that reverts), the transaction proceeds as if the transfer succeeded.



