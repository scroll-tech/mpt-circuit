//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "hardhat/console.sol";

/**
 * @title Greeter
 * @dev Store & retrieve value in a variable
 */
contract Greeter {

    uint256 number;

    constructor(uint256 num) {
        number = num;
    }

    function retrieve() public view returns (uint256){
        return number;
    }

    function retrieve_failing() public view returns (uint256){
        require(false);
        return number;
    }

    function set_value(uint256 num) public{
        number = num;
    }

    function set_value_failing(uint256 num) public{
        number = num;
        require(false);
    }
}