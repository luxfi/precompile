// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TestToken {
    string public name; string public symbol; uint8 public constant decimals = 0;
    uint256 public totalSupply;
    mapping(address=>uint256) public balanceOf;
    mapping(address=>mapping(address=>uint256)) public allowance;
    event Transfer(address indexed from,address indexed to,uint256 v);
    event Approval(address indexed o,address indexed s,uint256 v);
    constructor(string memory n,string memory s,uint256 supply){name=n;symbol=s;totalSupply=supply;balanceOf[msg.sender]=supply;emit Transfer(address(0),msg.sender,supply);}
    function transfer(address to,uint256 v) external returns(bool){_xfer(msg.sender,to,v);return true;}
    function approve(address sp,uint256 v) external returns(bool){allowance[msg.sender][sp]=v;emit Approval(msg.sender,sp,v);return true;}
    function transferFrom(address f,address to,uint256 v) external returns(bool){uint256 a=allowance[f][msg.sender];require(a>=v,"allow");if(a!=type(uint256).max)allowance[f][msg.sender]=a-v;_xfer(f,to,v);return true;}
    function _xfer(address f,address to,uint256 v) internal{require(balanceOf[f]>=v,"bal");balanceOf[f]-=v;balanceOf[to]+=v;emit Transfer(f,to,v);}
}
