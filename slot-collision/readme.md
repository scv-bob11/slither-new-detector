# Slot-Collision
Module detecting likelihood of slot collision.

# Example
```solidity
contract Proxy is TransparentUpgradeableProxy {
    address proxyOwner;
    // ... 
}

contract Impl {
    bool isInit;
    address owner;
    
    modifier initializer () {
        require(!isInit, "already initialized");
        _;
        isInit = true;
    }
    
    function init(address _owner) initializer public {
        owner = _owner;
    }
    // ...
}
```
There is a collision between proxyOwner and isInit.
By chance, isInit always is false.
So attacker can change owner by calling init().

# Cases
The following lists security incidents that could have been prevented using new detector
