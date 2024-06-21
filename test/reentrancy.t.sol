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
