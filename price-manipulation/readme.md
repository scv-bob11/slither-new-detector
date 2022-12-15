# Price-Manipulation
Module detecting likelihood of price manipulation.

# Example
```solidity
contract A {
    // ...
   function getprice() public view returns (uint256 _price) {
        uint256 lpTokenA=tokenA.balanceOf(_lpaddr); 
        uint256 lpTokenB=tokenB.balanceOf(_lpaddr); 
        _price = lpTokenA * 10**18 / lpTokenB;
    }
    // ...
}
```
Spot price is vulerable to flash loan attack.


# Cases
The following lists security incidents that could have been prevented using new detector

