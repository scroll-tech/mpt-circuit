//SPDX-License-Identifier: Unlicense
/**
 * Test destruct
*/

pragma solidity ^0.8.0;

/**
 * @title TestEdgeSelfDestruct
 * @dev test edge case in selfdestruct
 */
contract TestEdgeSelfDestruct {
    constructor() {
        SelfDestruct sd = new SelfDestruct();
        sd.log();
    }
}


contract SelfDestruct {
    event Log();
    constructor() {
        selfdestruct(payable(address(0)));
    }
    function log() external {
        emit Log();
    }
}

contract Suicider {

    function my_suicide() public{
        selfdestruct(payable(msg.sender));
    }
}

/**
 * @title SuiciderCreater
 * @dev test SelfDesturct
 */
contract SuiciderCreater {

    address theSuicider;

    constructor() {
    }

    function give_birth() public{
        theSuicider = address(new Suicider());
    }

    function birth_result() public view returns (address){
        return theSuicider;
    }    
}