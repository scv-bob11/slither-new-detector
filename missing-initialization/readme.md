# Missing-Initialization
Module detecting missing initialization used to check conditions.

# Example
```solidity
contract A {
    uint public state_variable = 0;
    bool public initialized = false;
    modifier not_initialized(){
        require(initialized == false);
        _;
    }
    function initialize(uint _state_variable) public not_initialized {
        state_variable = _state_variable;
    }
}
```
Bob calls `initialize`. However, Alice can also call `initialize`.

# Cases
The following lists security incidents that could have been prevented using new detector

[Valuedefi incident: re-initialize()](https://github.com/scv-bob11/slither-new-detector/tree/main/missing-initialization/Valuedefi_incident_re-initialize()_KOR.pdf)
![캡처](https://user-images.githubusercontent.com/112525820/195969236-11ee9421-0ff4-4df3-87c0-1f0eff07a9c0.PNG)

