# Dangerous-External-Call
Module detecting dangerous external call.

# Example
```solidity
contract A {
    function depositFor(address token, uint _amount,address user ) public {
        //...
        IERC20(token).safeTransferFrom(msg.sender, address(this), _amount); //vulnerable point
        //...
    }
}
```
https://ftmscan.com/address/0x660184ce8af80e0b1e5a1172a16168b15f4136bf#code#L1115   
https://rekt.news/grim-finance-rekt/   
   
Attacker can input fake token address because there is no verification of token address.

# Cases
The following lists security incidents that could have been prevented using new detector

