//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "hardhat/console.sol";
import "./Greeter.sol";

/**
 * @title Caller
 * @dev test CALL op
 */
contract Caller {

    address theGreeter;

    constructor(address greeter) {
        console.log("test");
        theGreeter = greeter;
    }

    function set_value(uint256 num) public{
        Greeter gt = Greeter(theGreeter);
        gt.set_value(num);
    }

    function set_value_failing(uint256 num) public{
        Greeter gt = Greeter(theGreeter);
        try gt.set_value_failing(num) {} catch {}
    }    
}