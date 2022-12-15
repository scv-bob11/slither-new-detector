# Arbitary-Calldata
Module detecting arbitary-calldata.

# Example
```solidity
contract A {
    //..
    function permit(address token, bytes calldata data) {
        require(isListed[token], "");
        (bool success, ) = token.call(data);
        require(success, "")
    }
}
```
Attacker can call any function.

# Cases
The following lists security incidents that could have been prevented using new detector

