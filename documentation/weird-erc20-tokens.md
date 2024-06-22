# Weird ERC20 tokens


## Missing Return Values

### example tokens
```USDT```,```BNB```,```OMG```
### Proof of Code

Missing value
```
// Copyright (C) 2017, 2018, 2019, 2020 dbrock, rain, mrchico, d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

contract MissingReturnToken {
    // --- ERC20 Data ---
    string  public constant name = "Token";
    string  public constant symbol = "TKN";
    uint8   public constant decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint)                      public balanceOf;
    mapping (address => mapping (address => uint)) public allowance;

    event Approval(address indexed src, address indexed guy, uint wad);
    event Transfer(address indexed src, address indexed dst, uint wad);

    // --- Math ---
    function add(uint x, uint y) internal pure returns (uint z) {
        require((z = x + y) >= x);
    }
    function sub(uint x, uint y) internal pure returns (uint z) {
        require((z = x - y) <= x);
    }

    // --- Init ---
    constructor(uint _totalSupply) public {
        totalSupply = _totalSupply;
        balanceOf[msg.sender] = _totalSupply;
        emit Transfer(address(0), msg.sender, _totalSupply);
    }

    // --- Token ---
    function transfer(address dst, uint wad) external {
        transferFrom(msg.sender, dst, wad);
    }
    function transferFrom(address src, address dst, uint wad) public {
        require(balanceOf[src] >= wad, "insufficient-balance");
        if (src != msg.sender && allowance[src][msg.sender] != type(uint).max) {
            require(allowance[src][msg.sender] >= wad, "insufficient-allowance");
            allowance[src][msg.sender] = sub(allowance[src][msg.sender], wad);
        }
        balanceOf[src] = sub(balanceOf[src], wad);
        balanceOf[dst] = add(balanceOf[dst], wad);
        emit Transfer(src, dst, wad);
    }
    function approve(address usr, uint wad) external {
        allowance[msg.sender][usr] = wad;
        emit Approval(msg.sender, usr, wad);
    }
}
```

# Fee on Transfer
## example tokens
```STA```,```PAXG```, some that may likely charge in the future: ```USDT```, ```USDC```

## Proof of Code
```
// Copyright (C) 2020 d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

import {ERC20} from "./ERC20.sol";

contract TransferFeeToken is ERC20 {

    uint immutable fee;

    // --- Init ---
    constructor(uint _totalSupply, uint _fee) ERC20(_totalSupply) public {
        fee = _fee;
    }

    // --- Token ---
    function transferFrom(address src, address dst, uint wad) override public returns (bool) {
        require(balanceOf[src] >= wad, "insufficient-balance");
        if (src != msg.sender && allowance[src][msg.sender] != type(uint).max) {
            require(allowance[src][msg.sender] >= wad, "insufficient-allowance");
            allowance[src][msg.sender] = sub(allowance[src][msg.sender], wad);
        }

        balanceOf[src] = sub(balanceOf[src], wad);
        balanceOf[dst] = add(balanceOf[dst], sub(wad, fee));
        balanceOf[address(0)] = add(balanceOf[address(0)], fee);

        emit Transfer(src, dst, sub(wad, fee));
        emit Transfer(src, address(0), fee);

        return true;
    }
}
```

## Reentrant calls

```ERC777``` tokens
### Proof of Code
```
// Copyright (C) 2020 d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

import {ERC20} from "./ERC20.sol";

contract ReentrantToken is ERC20 {
    // --- Init ---
    constructor(uint _totalSupply) ERC20(_totalSupply) public {}

    // --- Call Targets ---
    mapping (address => Target) public targets;
    struct Target {
        bytes   data;
        address addr;
    }
    function setTarget(address addr, bytes calldata data) external {
        targets[msg.sender] = Target(data, addr);
    }

    // --- Token ---
    function transferFrom(address src, address dst, uint wad) override public returns (bool res) {
        res = super.transferFrom(src, dst, wad);
        Target memory target = targets[src];
        if (target.addr != address(0)) {
            (bool status,) = target.addr.call{gas: gasleft()}(target.data);
            require(status, "call failed");
        }
    }
}
```


(2) false value returns
```
// Copyright (C) 2017, 2018, 2019, 2020 dbrock, rain, mrchico, d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

contract ReturnsFalseToken {
    // --- ERC20 Data ---
    string  public constant name = "Token";
    string  public constant symbol = "TKN";
    uint8   public constant decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint)                      public balanceOf;
    mapping (address => mapping (address => uint)) public allowance;

    event Approval(address indexed src, address indexed guy, uint wad);
    event Transfer(address indexed src, address indexed dst, uint wad);

    // --- Math ---
    function add(uint x, uint y) internal pure returns (uint z) {
        require((z = x + y) >= x);
    }
    function sub(uint x, uint y) internal pure returns (uint z) {
        require((z = x - y) <= x);
    }

    // --- Init ---
    constructor(uint _totalSupply) public {
        totalSupply = _totalSupply;
        balanceOf[msg.sender] = _totalSupply;
        emit Transfer(address(0), msg.sender, _totalSupply);
    }

    // --- Token ---
    function transfer(address dst, uint wad) external returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }
    function transferFrom(address src, address dst, uint wad) public returns (bool) {
        require(balanceOf[src] >= wad, "insufficient-balance");
        if (src != msg.sender && allowance[src][msg.sender] != type(uint).max) {
            require(allowance[src][msg.sender] >= wad, "insufficient-allowance");
            allowance[src][msg.sender] = sub(allowance[src][msg.sender], wad);
        }
        balanceOf[src] = sub(balanceOf[src], wad);
        balanceOf[dst] = add(balanceOf[dst], wad);
        emit Transfer(src, dst, wad);
        return false;
    }
    function approve(address usr, uint wad) external returns (bool) {
        allowance[msg.sender][usr] = wad;
        emit Approval(msg.sender, usr, wad);
        return false;
    }
}
```


# Balance Modifications Outside of Transfers (rebasing/airdrops)
## example contracts/protocol
```Ampleforth style rebasing tokens```, 
```Compound style airdrops of governance tokens```,
```mintable/burnable tokens```,
```Balancer, Uniswap-V2```

# Upgradable Tokens
## example tokens
```USDT```, ```USDC```
## Proof of Code
```
// Copyright (C) 2020 d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

import {ERC20} from "./ERC20.sol";

contract Proxy {
    bytes32 constant ADMIN_KEY = bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1);
    bytes32 constant IMPLEMENTATION_KEY = bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1);

    // --- init ---

    constructor(uint totalSupply) public {

        // Manual give()
        bytes32 slot = ADMIN_KEY;
        address usr = msg.sender;
        assembly { sstore(slot, usr) }

        upgrade(address(new ERC20(totalSupply)));

    }

    // --- auth ---

    modifier auth() { require(msg.sender == owner(), "unauthorised"); _; }

    function owner() public view returns (address usr) {
        bytes32 slot = ADMIN_KEY;
        assembly { usr := sload(slot) }
    }

    function give(address usr) public auth {
        bytes32 slot = ADMIN_KEY;
        assembly { sstore(slot, usr) }
    }

    // --- upgrade ---

    function implementation() public view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_KEY;
        assembly { impl := sload(slot) }
    }

    function upgrade(address impl) public auth {
        bytes32 slot = IMPLEMENTATION_KEY;
        assembly { sstore(slot, impl) }
    }

    // --- proxy ---

    fallback() external payable {
        address impl = implementation();
        (bool success, bytes memory returndata) = impl.delegatecall{gas: gasleft()}(msg.data);
        require(success);
        assembly { return(add(returndata, 0x20), mload(returndata)) }
    }

    receive() external payable { revert("don't send me ETH!"); }
}
```

# Flash Mintable Tokens
## example token
```DAI```
## Proof
[MakerDAO flash mint module ](https://docs.makerdao.com/smart-contract-modules/flash-mint-module)

# Tokens with Blocklists
## example tokens
```USDC```, ```USDT```
## Proof of Code
```
// Copyright (C) 2020 d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

import {ERC20} from "./ERC20.sol";

contract BlockableToken is ERC20 {
    // --- Access Control ---
    address owner;
    modifier auth() { require(msg.sender == owner, "unauthorised"); _; }

    // --- BlockList ---
    mapping(address => bool) blocked;
    function block(address usr) auth public { blocked[usr] = true; }
    function allow(address usr) auth public { blocked[usr] = false; }

    // --- Init ---
    constructor(uint _totalSupply) ERC20(_totalSupply) public {
        owner = msg.sender;
    }

    // --- Token ---
    function transferFrom(address src, address dst, uint wad) override public returns (bool) {
        require(!blocked[src], "blocked");
        require(!blocked[dst], "blocked");
        return super.transferFrom(src, dst, wad);
    }
}
```

# Pausable Tokens
## example tokens
```BNB```, ```ZIL```
## Proof of Code
```
// Copyright (C) 2020 d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

import {ERC20} from "./ERC20.sol";

contract PausableToken is ERC20 {
    // --- Access Control ---
    address owner;
    modifier auth() { require(msg.sender == owner, "unauthorised"); _; }

    // --- Pause ---
    bool live = true;
    function stop() auth external { live = false; }
    function start() auth external { live = true; }

    // --- Init ---
    constructor(uint _totalSupply) ERC20(_totalSupply) public {
        owner = msg.sender;
    }

    // --- Token ---
    function approve(address usr, uint wad) override public returns (bool) {
        require(live, "paused");
        return super.approve(usr, wad);
    }
    function transfer(address dst, uint wad) override public returns (bool) {
        require(live, "paused");
        return super.transfer(dst, wad);
    }
    function transferFrom(address src, address dst, uint wad) override public returns (bool) {
        require(live, "paused");
        return super.transferFrom(src, dst, wad);
    }
}
```

# Approval Race Protections
## example token
```USDC```, ```KNC```
## Proof of Code
```
// Copyright (C) 2020 d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

import {ERC20} from "./ERC20.sol";

contract ApprovalRaceToken is ERC20 {
    // --- Init ---
    constructor(uint _totalSupply) ERC20(_totalSupply) public {}

    // --- Token ---
    function approve(address usr, uint wad) override public returns (bool) {
        require(allowance[msg.sender][usr] == 0, "unsafe-approve");
        return super.approve(usr, wad);
    }
}
```

# Revert on Approval To Zero Address
## example tokens
```BNB```
## Proof of Code
```
// Copyright (C) 2020 d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

import {ERC20} from "./ERC20.sol";

contract ApprovalWithZeroValueToken is ERC20 {
    // --- Init ---
    constructor(uint _totalSupply) ERC20(_totalSupply) public {}

    // --- Token ---
    function approve(address usr, uint wad) override public returns (bool) {
        require(wad > 0, "no approval with zero value");
        return super.approve(usr, wad);
    }
}
```

# Revert on Zero Value Transfers
## example tokens
```LEND```
## Proof of Code
```
// Copyright (C) 2020 d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

import {ERC20} from "./ERC20.sol";

contract RevertZeroToken is ERC20 {
    // --- Init ---
    constructor(uint _totalSupply) ERC20(_totalSupply) public {}

    // --- Token ---
    function transferFrom(address src, address dst, uint wad) override public returns (bool) {
        require(wad != 0, "zero-value-transfer");
        return super.transferFrom(src, dst, wad);
    }
}
```

# Multiple Token Addresses
## example contract
```
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

/*
    Provides two contracts:

    1. ProxiedToken: The underlying token, state modifications must be made through a proxy
    2. TokenProxy: Proxy contract, appends the original msg.sender to any calldata provided by the user

    The ProxiedToken can have many trusted frontends (TokenProxy's).
    The frontends should append the address of their caller to calldata when calling into the backend.
    Admin users of the ProxiedToken can add new delegators.
*/

contract ProxiedToken {
    // --- ERC20 Data ---
    string  public constant name = "Token";
    string  public constant symbol = "TKN";
    uint8   public constant decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint)                      public balanceOf;
    mapping (address => mapping (address => uint)) public allowance;

    event Approval(address indexed src, address indexed guy, uint wad);
    event Transfer(address indexed src, address indexed dst, uint wad);

    // --- Math ---
    function add(uint x, uint y) internal pure returns (uint z) {
        require((z = x + y) >= x);
    }
    function sub(uint x, uint y) internal pure returns (uint z) {
        require((z = x - y) <= x);
    }

    // --- Init ---
    constructor(uint _totalSupply) public {
        admin[msg.sender] = true;
        totalSupply = _totalSupply;
        balanceOf[msg.sender] = _totalSupply;
        emit Transfer(address(0), msg.sender, _totalSupply);
    }

    // --- Access Control ---
    mapping(address => bool) public admin;
    function rely(address usr) external auth { admin[usr] = true; }
    function deny(address usr) external auth { admin[usr] = false; }
    modifier auth() { require(admin[msg.sender], "non-admin-call"); _; }

    mapping(address => bool) public delegators;
    modifier delegated() { require(delegators[msg.sender], "non-delegator-call"); _; }
    function setDelegator(address delegator, bool status) external auth {
        delegators[delegator] = status;
    }

    // --- Token ---
    function transfer(address dst, uint wad) delegated external returns (bool) {
        return _transferFrom(_getCaller(), _getCaller(), dst, wad);
    }
    function transferFrom(address src, address dst, uint wad) delegated external returns (bool) {
        return _transferFrom(_getCaller(), src, dst, wad);
    }
    function approve(address usr, uint wad) delegated external returns (bool) {
        return _approve(_getCaller(), usr, wad);
    }

    // --- Internals ---
    function _transferFrom(
        address caller, address src, address dst, uint wad
    ) internal returns (bool) {
        require(balanceOf[src] >= wad, "insufficient-balance");
        if (src != caller && allowance[src][caller] != type(uint).max) {
            require(allowance[src][caller] >= wad, "insufficient-allowance");
            allowance[src][caller] = sub(allowance[src][caller], wad);
        }
        balanceOf[src] = sub(balanceOf[src], wad);
        balanceOf[dst] = add(balanceOf[dst], wad);
        emit Transfer(src, dst, wad);
        return true;
    }
    function _approve(address caller, address usr, uint wad) internal returns (bool) {
        allowance[caller][usr] = wad;
        emit Approval(caller, usr, wad);
        return true;
    }
    // grabs the first word after the calldata and masks it with 20bytes of 1's
    // to turn it into an address
    function _getCaller() internal pure returns (address result) {
        bytes memory array = msg.data;
        uint256 index = msg.data.length;
        assembly {
            result := and(mload(add(array, index)), 0xffffffffffffffffffffffffffffffffffffffff)
        }
        return result;
    }
}

contract TokenProxy {
    address payable immutable public impl;
    constructor(address _impl) public {
        impl = payable(_impl);
    }

    receive() external payable { revert("don't send me ETH!"); }

    fallback() external payable {
        address _impl = impl; // pull impl onto the stack
        assembly {
            // get free data pointer
            let ptr := mload(0x40)

            // write calldata to ptr
            calldatacopy(ptr, 0, calldatasize())
            // store msg.sender after the calldata
            mstore(add(ptr, calldatasize()), caller())

            // call impl with the contents of ptr as caldata
            let result := call(gas(), _impl, callvalue(), ptr, add(calldatasize(), 32), 0, 0)

            // copy the returndata to ptr
            let size := returndatasize()
            returndatacopy(ptr, 0, size)

            switch result
            // revert if the call failed
            case 0 { revert(ptr, size) }
            // return ptr otherwise
            default { return(ptr, size) }
        }
    }

}
```

# Low Decimals
## example tokens
```USDC``` has 6 decimal, ```Gemini USDC``` has 2 decimal
## Proof of code
```
// Copyright (C) 2020 d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

import {ERC20} from "./ERC20.sol";

contract LowDecimalToken is ERC20 {
    constructor(uint _totalSupply) ERC20(_totalSupply) public {
        decimals = 2;
    }
}
```

# High Decimals
## example tokens
```YAM-v2``` has 24 decimal

## Proof of Code
```
// Copyright (C) 2020 d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

import {ERC20} from "./ERC20.sol";

contract HighDecimalToken is ERC20 {
    constructor(uint _totalSupply) ERC20(_totalSupply) public {
        decimals = 50;
    }
}
```

# ```transferFrom``` with ```src == msg.sender```
## example tokens and protocols
```DSToken``` will not attempt to decrease allowance, 
```OpenZeppelin, Uniswap-v2``` always attempt to decrease allowance

## Proof of Code
(1) will not attempt to decrease allowance
```
// Copyright (C) 2017, 2018, 2019, 2020 dbrock, rain, mrchico, d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

contract Math {
    // --- Math ---
    function add(uint x, uint y) internal pure returns (uint z) {
        require((z = x + y) >= x);
    }
    function sub(uint x, uint y) internal pure returns (uint z) {
        require((z = x - y) <= x);
    }
}

contract ERC20 is Math {
    // --- ERC20 Data ---
    string  public constant name = "Token";
    string  public constant symbol = "TKN";
    uint8   public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint)                      public balanceOf;
    mapping (address => mapping (address => uint)) public allowance;

    event Approval(address indexed src, address indexed guy, uint wad);
    event Transfer(address indexed src, address indexed dst, uint wad);

    // --- Init ---
    constructor(uint _totalSupply) public {
        totalSupply = _totalSupply;
        balanceOf[msg.sender] = _totalSupply;
        emit Transfer(address(0), msg.sender, _totalSupply);
    }

    // --- Token ---
    function transfer(address dst, uint wad) virtual public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }
    function transferFrom(address src, address dst, uint wad) virtual public returns (bool) {
        require(balanceOf[src] >= wad, "insufficient-balance");
        if (src != msg.sender && allowance[src][msg.sender] != type(uint).max) {
            require(allowance[src][msg.sender] >= wad, "insufficient-allowance");
            allowance[src][msg.sender] = sub(allowance[src][msg.sender], wad);
        }
        balanceOf[src] = sub(balanceOf[src], wad);
        balanceOf[dst] = add(balanceOf[dst], wad);
        emit Transfer(src, dst, wad);
        return true;
    }
    function approve(address usr, uint wad) virtual public returns (bool) {
        allowance[msg.sender][usr] = wad;
        emit Approval(msg.sender, usr, wad);
        return true;
    }
}
```
(2) will always attempt to decrease allowance
```
// Copyright (C) 2017, 2018, 2019, 2020 dbrock, rain, mrchico, d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

contract Math {
    // --- Math ---
    function add(uint x, uint y) internal pure returns (uint z) {
        require((z = x + y) >= x);
    }
    function sub(uint x, uint y) internal pure returns (uint z) {
        require((z = x - y) <= x);
    }
}

contract TransferFromSelfToken is Math {
    // --- ERC20 Data ---
    string  public constant name = "Token";
    string  public constant symbol = "TKN";
    uint8   public constant decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint)                      public balanceOf;
    mapping (address => mapping (address => uint)) public allowance;

    event Approval(address indexed src, address indexed guy, uint wad);
    event Transfer(address indexed src, address indexed dst, uint wad);

    // --- Init ---
    constructor(uint _totalSupply) public {
        totalSupply = _totalSupply;
        balanceOf[msg.sender] = _totalSupply;
        emit Transfer(address(0), msg.sender, _totalSupply);
    }

    // --- Token ---
    function transfer(address dst, uint wad) virtual public returns (bool) {
        _transfer(msg.sender, dst, wad);
        return true;
    }
    function transferFrom(address src, address dst, uint wad) virtual public returns (bool) {
        if (allowance[src][msg.sender] != type(uint).max) {
            require(allowance[src][msg.sender] >= wad, "insufficient-allowance");
            allowance[src][msg.sender] = sub(allowance[src][msg.sender], wad);
        }
        _transfer(src, dst, wad);
        return true;
    }
    function approve(address usr, uint wad) virtual public returns (bool) {
        allowance[msg.sender][usr] = wad;
        emit Approval(msg.sender, usr, wad);
        return true;
    }

    // --- Internal ---
    function _transfer(address src, address dst, uint wad) private {
        require(balanceOf[src] >= wad, "insufficient-balance");
        balanceOf[src] = sub(balanceOf[src], wad);
        balanceOf[dst] = add(balanceOf[dst], wad);
        emit Transfer(src, dst, wad);
    }
}
```

# Non ```string``` metadata
## example tokens
```MKR```
## Proof of Code
```
// Copyright (C) 2017, 2018, 2019, 2020 dbrock, rain, mrchico, d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

contract Math {
    // --- Math ---
    function add(uint x, uint y) internal pure returns (uint z) {
        require((z = x + y) >= x);
    }
    function sub(uint x, uint y) internal pure returns (uint z) {
        require((z = x - y) <= x);
    }
}

contract ERC20 is Math {
    // --- ERC20 Data ---
    bytes32 public constant name = "Token";
    bytes32 public constant symbol = "TKN";
    uint8   public constant decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint)                      public balanceOf;
    mapping (address => mapping (address => uint)) public allowance;

    event Approval(address indexed src, address indexed guy, uint wad);
    event Transfer(address indexed src, address indexed dst, uint wad);

    // --- Init ---
    constructor(uint _totalSupply) public {
        totalSupply = _totalSupply;
        balanceOf[msg.sender] = _totalSupply;
        emit Transfer(address(0), msg.sender, _totalSupply);
    }

    // --- Token ---
    function transfer(address dst, uint wad) virtual public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }
    function transferFrom(address src, address dst, uint wad) virtual public returns (bool) {
        require(balanceOf[src] >= wad, "insufficient-balance");
        if (src != msg.sender && allowance[src][msg.sender] != type(uint).max) {
            require(allowance[src][msg.sender] >= wad, "insufficient-allowance");
            allowance[src][msg.sender] = sub(allowance[src][msg.sender], wad);
        }
        balanceOf[src] = sub(balanceOf[src], wad);
        balanceOf[dst] = add(balanceOf[dst], wad);
        emit Transfer(src, dst, wad);
        return true;
    }
    function approve(address usr, uint wad) virtual public returns (bool) {
        allowance[msg.sender][usr] = wad;
        emit Approval(msg.sender, usr, wad);
        return true;
    }
}
```
# Revert on Transfer to the Zero Address
## example protocol
```openZeppelin``` reverts when attempting to transfer to address(0)
## Proof of Code
```
// Copyright (C) 2020 d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

import {ERC20} from "./ERC20.sol";

contract RevertToZeroToken is ERC20 {
    // --- Init ---
    constructor(uint _totalSupply) ERC20(_totalSupply) public {}

    // --- Token ---
    function transferFrom(address src, address dst, uint wad) override public returns (bool) {
        require(dst != address(0), "transfer-to-zero");
        return super.transferFrom(src, dst, wad);
    }
}
```
# No Revert on Failure
## example tokens
```ZRX```, ```EURS```
## Proof of Code
```
// Copyright (C) 2017, 2018, 2019, 2020 dbrock, rain, mrchico, d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

contract NoRevertToken {
    // --- ERC20 Data ---
    string  public constant name = "Token";
    string  public constant symbol = "TKN";
    uint8   public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint)                      public balanceOf;
    mapping (address => mapping (address => uint)) public allowance;

    event Approval(address indexed src, address indexed guy, uint wad);
    event Transfer(address indexed src, address indexed dst, uint wad);

    // --- Init ---
    constructor(uint _totalSupply) public {
        totalSupply = _totalSupply;
        balanceOf[msg.sender] = _totalSupply;
        emit Transfer(address(0), msg.sender, _totalSupply);
    }

    // --- Token ---
    function transfer(address dst, uint wad) external returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }
    function transferFrom(address src, address dst, uint wad) virtual public returns (bool) {
        if (balanceOf[src] < wad) return false;                        // insufficient src bal
        if (balanceOf[dst] >= (type(uint256).max - wad)) return false; // dst bal too high

        if (src != msg.sender && allowance[src][msg.sender] != type(uint).max) {
            if (allowance[src][msg.sender] < wad) return false;        // insufficient allowance
            allowance[src][msg.sender] = allowance[src][msg.sender] - wad;
        }

        balanceOf[src] = balanceOf[src] - wad;
        balanceOf[dst] = balanceOf[dst] + wad;

        emit Transfer(src, dst, wad);
        return true;
    }
    function approve(address usr, uint wad) virtual external returns (bool) {
        allowance[msg.sender][usr] = wad;
        emit Approval(msg.sender, usr, wad);
        return true;
    }
}
```

# Revert on Large Approvals & Transfers
## example tokens
```UNI```, ```COMP```
## Proof of Code
```
// Copyright (C) 2017, 2018, 2019, 2020 dbrock, rain, mrchico, d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

contract Uint96ERC20 {
    // --- ERC20 Data ---
    string  public constant name = "Token";
    string  public constant symbol = "TKN";
    uint8   public decimals = 18;
    uint96  internal supply;

    mapping (address => uint96)                      internal balances;
    mapping (address => mapping (address => uint96)) internal allowances;

    event Approval(address indexed src, address indexed guy, uint wad);
    event Transfer(address indexed src, address indexed dst, uint wad);

    // --- Math ---
    function add(uint96 x, uint96 y) internal pure returns (uint96 z) {
        require((z = x + y) >= x);
    }
    function sub(uint96 x, uint96 y) internal pure returns (uint96 z) {
        require((z = x - y) <= x);
    }
    function safe96(uint256 n) internal pure returns (uint96) {
        require(n < 2**96);
        return uint96(n);
    }

    // --- Init ---
    constructor(uint96 _supply) public {
        supply = _supply;
        balances[msg.sender] = _supply;
        emit Transfer(address(0), msg.sender, _supply);
    }

    // --- Getters ---
    function totalSupply() external view returns (uint) {
        return supply;
    }
    function balanceOf(address usr) external view returns (uint) {
        return balances[usr];
    }
    function allowance(address src, address dst) external view returns (uint) {
        return allowances[src][dst];
    }

    // --- Token ---
    function transfer(address dst, uint wad) virtual public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }
    function transferFrom(address src, address dst, uint wad) virtual public returns (bool) {
        uint96 amt = safe96(wad);

        if (src != msg.sender && allowances[src][msg.sender] != type(uint96).max) {
            allowances[src][msg.sender] = sub(allowances[src][msg.sender], amt);
        }

        balances[src] = sub(balances[src], amt);
        balances[dst] = add(balances[dst], amt);
        emit Transfer(src, dst, wad);
        return true;
    }
    function approve(address usr, uint wad) virtual public returns (bool) {
        uint96 amt;
        if (wad == type(uint).max) {
            amt = type(uint96).max;
        } else {
            amt = safe96(wad);
        }

        allowances[msg.sender][usr] = amt;

        emit Approval(msg.sender, usr, amt);
        return true;
    }
}
```
# Code Injection Via Token Name
## Proof
[reference](https://hackernoon.com/how-one-hacker-stole-thousands-of-dollars-worth-of-cryptocurrency-with-a-classic-code-injection-a3aba5d2bff0)

# Unusual Permit Function
## example token
```DAI```, ```RAI```, ```GLM```, ```STAKE```, ```CHAI```, ```HAKKA```, ```USDFL```, ```HNY```
## Proof of Code
```
// Copyright (C) 2017, 2018, 2019, 2020 dbrock, rain, mrchico, d-xo
// SPDX-License-Identifier: AGPL-3.0-only

pragma solidity >=0.6.12;

contract Math {
    // --- Math ---
    function add(uint x, uint y) internal pure returns (uint z) {
        require((z = x + y) >= x);
    }
    function sub(uint x, uint y) internal pure returns (uint z) {
        require((z = x - y) <= x);
    }
}

contract DaiPermit is Math {
    // --- ERC20 Data ---
    string  public constant name = "Token";
    string  public constant symbol = "TKN";
    uint8   public decimals = 18;
    uint256 public totalSupply;
	bytes32 public constant PERMIT_TYPEHASH = 0xea2aa0a1be11a07ed86d755c93467f4f82362b452371d1ba94d1715123511acb;
	bytes32 public immutable DOMAIN_SEPARATOR = keccak256(
        abi.encode(
            keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
            keccak256(bytes(name)),
            keccak256(bytes('1')),
            block.chainid,
            address(this)
        )
    );

    mapping (address => uint)                      public balanceOf;
    mapping (address => mapping (address => uint)) public allowance;
    mapping (address => uint)                      public nonces;

    event Approval(address indexed src, address indexed guy, uint wad);
    event Transfer(address indexed src, address indexed dst, uint wad);

    // --- Init ---
    constructor(uint _totalSupply) public {
        totalSupply = _totalSupply;
        balanceOf[msg.sender] = _totalSupply;
        emit Transfer(address(0), msg.sender, _totalSupply);
    }

    // --- Token ---
    function transfer(address dst, uint wad) virtual public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }
    function transferFrom(address src, address dst, uint wad) virtual public returns (bool) {
        require(balanceOf[src] >= wad, "insufficient-balance");
        if (src != msg.sender && allowance[src][msg.sender] != type(uint).max) {
            require(allowance[src][msg.sender] >= wad, "insufficient-allowance");
            allowance[src][msg.sender] = sub(allowance[src][msg.sender], wad);
        }
        balanceOf[src] = sub(balanceOf[src], wad);
        balanceOf[dst] = add(balanceOf[dst], wad);
        emit Transfer(src, dst, wad);
        return true;
    }
    function approve(address usr, uint wad) virtual public returns (bool) {
        allowance[msg.sender][usr] = wad;
        emit Approval(msg.sender, usr, wad);
        return true;
    }
	function permit(address holder, address spender, uint256 nonce, uint256 expiry,
                    bool allowed, uint8 v, bytes32 r, bytes32 s) external
    {
        bytes32 digest =
            keccak256(abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(PERMIT_TYPEHASH,
                                     holder,
                                     spender,
                                     nonce,
                                     expiry,
                                     allowed))
        ));

        require(holder != address(0), "Dai/invalid-address-0");
        require(holder == ecrecover(digest, v, r, s), "Dai/invalid-permit");
        require(expiry == 0 || block.timestamp <= expiry, "Dai/permit-expired");
        require(nonce == nonces[holder]++, "Dai/invalid-nonce");
        uint wad = allowed ? type(uint256).max : 0;
        allowance[holder][spender] = wad;
    }
}
```
# Transfer of less than ```amount```
## example tokens
```cUSDCv3```