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

    function disp_external(uint256 num) external returns (address){
        Greeter ct = new Greeter(num);
        return address(ct);
    }

    function disp_failing(uint256 num) public{
        try new FailCreate(num) returns (FailCreate ct) {
            theGreeter = address(ct);
        }catch {
            theGreeter = address(0);
        }
    }

    function disp_external_failing(uint256 num) external returns (address){
        try new FailCreate(num) returns (FailCreate ct) {
            return address(ct);
        }catch {
            return address(0);
        }
    }

    function disp_result() public view returns (address){
        return theGreeter;
    }    
}


/**
 * @title Deep-Caller
 * @dev test CALL op
 */
contract CreaterDeep {

    address nextCaller;
    address theGreeter;

    constructor(address caller) {
        
        nextCaller = caller;
    }

    function callAddress() public view returns (address){
        return nextCaller;
    }

    function status() public view returns (address){
        return theGreeter;
    }

    function deep_disp(uint256 num) public{
        Creater cr = Creater(nextCaller);
        theGreeter = cr.disp_external(num);
    }

    function deep_disp_failing(uint256 num) public{
        Creater cr = Creater(nextCaller);
        theGreeter = cr.disp_external_failing(num);
    }    

    function deep_disp_failing_outer(uint256 num) public{
        Creater cr = Creater(nextCaller);
        theGreeter = cr.disp_external(num);
        revert("deliberately");
    }    

    function deep_disp_failing_both(uint256 num) public{
        Creater cr = Creater(nextCaller);
        theGreeter = cr.disp_external_failing(num);
        revert("deliberately");
    }

}