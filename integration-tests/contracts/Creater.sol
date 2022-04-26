//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "./Greeter.sol";


/**
 * @title Greeter
 * @dev Store & retrieve value in a variable
 */
contract FailCreate {

    constructor(uint256 num) {
        require(num != 0);
    }
}

/**
 * @title Creater
 * @dev test CREATE op
 */
contract Creater {

    address theGreeter;

    constructor() {
    }

    function disp(uint256 num) public{
        Greeter ct = new Greeter(num);
        theGreeter = address(ct);
    }

    function disp_failing(uint256 num) public{
        try new FailCreate(num) returns (FailCreate ct) {
            theGreeter = address(ct);
        }catch {
            theGreeter = address(0);
        }
    }

    function disp_result() public view returns (address){
        return theGreeter;
    }    
}