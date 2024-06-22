// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {SafeNFT} from "../src/Claim.sol";
import {SafeNftAttacker} from "../src/ClaimExploit.sol";

contract ClaimTest is Test {
    SafeNftAttacker public safeNftattacker;
    SafeNFT public safenft;
    uint256  price = 0.01 ether ;
    function setUp() public {
        safenft = new SafeNFT("NFT", "NonFungi", price );
        safeNftattacker = new SafeNftAttacker(address(safenft));
        deal(address(safeNftattacker), 1 ether);
        
    }

    function test_attack() public {
        vm.startPrank(address(safeNftattacker));
        safeNftattacker.attackSafeNFT(price);
        vm.stopPrank();
    }
}
