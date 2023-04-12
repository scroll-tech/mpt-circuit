// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

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

    function set_value_and_receive(uint256 num) public payable {
        number = num;
    }

    function set_value_and_receive_failing(uint256 num) public payable {
        number = num;
        revert("deliberately");
    }
}

/**
 * @title MultiGreeter
 * @dev Store & retrieve value in a variable, has 2 slots
 */
contract MutipleGreeter {
    mapping(uint => uint256) public values;

    constructor() {
    }

    function retrieve(uint which) public view returns (uint256){
        return values[which];
    }

    function set_multiple(uint num, uint256 val) public {
        for (uint i = 0; i < num; i++){
            values[i] = val;
        }
    }

    function set_one(uint which, uint256 val) public{
        values[which] = val;
    }

}
