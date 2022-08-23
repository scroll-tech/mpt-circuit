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

    function callAddress() public view returns (address){
        return theGreeter;
    }

    function set_value(uint256 num) public{
        Greeter gt = Greeter(theGreeter);
        gt.set_value(num);
    }

    function set_value_failing(uint256 num) public{
        Greeter gt = Greeter(theGreeter);
        try gt.set_value_failing(num) {} catch {}
    }

    function pay_failing(uint256 num) public {
        Greeter gt = Greeter(theGreeter);
        try gt.set_value_and_receive{value: 100}(num) {} catch {}
    }
}

/**
 * @title Deep-Caller
 * @dev test CALL op
 */
contract CallerDeep {

    address nextCaller;
    uint256 setter;

    constructor(address caller) {
        
        nextCaller = caller;
    }

    function callAddress() public view returns (address){
        return nextCaller;
    }

    function status() public view returns (uint256){
        return setter;
    }

    function set_value_deep(uint256 num) public{
        Caller cr = Caller(nextCaller);
        cr.set_value(num);
        setter = num;
    }

    function set_value_failing_deep(uint256 num) public{
        Caller cr = Caller(nextCaller);
        cr.set_value_failing(num);
        setter = num;
    }    

    function set_value_failing_outer(uint256 num) public{
        Caller cr = Caller(nextCaller);
        cr.set_value(num);
        setter = num;
        revert("deliberately");
    }    

    function set_value_failing_both(uint256 num) public{
        Caller cr = Caller(nextCaller);
        cr.set_value_failing(num);
        setter = num;
        revert("deliberately");
    }

    function deep_pay_failing(uint256 num) public {
        Caller cr = Caller(nextCaller);
        cr.pay_failing(num);
        setter = num;
    }
}