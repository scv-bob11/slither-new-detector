# Voting-Amplification
Module detecting voting amplification.

# Example
```solidity
contract A {
    // ...
    function transferFrom(address from, address to, uint256 value) public returns (bool) {
        _transfer(from, to, value);
        _approve(from, msg.sender, allowance(from, msg.sender).sub(value));
        _moveDelegates(delegates[msg.sender], delegates[to], value); // vulnerable point
        return true;
    }
    // ...
}
```
https://etherscan.io/address/0xa2cd3d43c775978a96bdbf12d733d5a1ed94fb18#code#L533

When defi project just copy&paste code with vulnerability, the above pattern appears.

### More
https://medium.com/bulldax-finance/sushiswap-delegation-double-spending-bug-5adcc7b3830f
https://medium.com/valixconsulting/sushiswap-voting-vulnerability-of-sushi-token-and-its-forks-56f220d4c9ba

# Cases
The following lists security incidents that could have been prevented using new detector


