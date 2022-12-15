# Access-Control
Module detecting improper access control.

# Example
```solidity
contract A {
    address token;

    function setToken(address _token) public {
        token = _token;
    }
}
```
Bob can calls `setToken` to change token address.

# Cases
The following lists security incidents that could have been prevented using new detector

