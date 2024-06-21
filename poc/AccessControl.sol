// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract MiddyBank {

    address adminAddress;

    error Middey__InsufficientFunds(address _userAddress, uint balance);

    error Middey__NotAnActiveUser();

    mapping(address => Register) UserInfo;

    mapping(uint => address) LoanID;

    mapping(uint => LoanInfo) loanInfo;

    uint loanid;

    event emitLoanId(uint LoanId, uint LoanRequestAmount);

    struct LoanInfo{
        address user;
        bool ispending;
        uint loanId;

    }

    struct Register {
        string username;
        bool active;
        address userAddress;
    }

    constructor(address) {
        adminAddress = payable(msg.sender);
    }



    function registerUser(string memory _username, bool _active, address _userAddress) internal {
        UserInfo[_userAddress] = Register({
            username : _username,
            active : _active,
            userAddress : _userAddress

        });
    }

    function checkUserBalance(address _userAddress) public view returns(uint256){
        return _userAddress.balance;
    }

    function approveLoan(uint _loanID, bool loanPending, address _userAddress, uint amount) payable external {

        require(!loanPending, "Your loan has suceeded");
        (bool sent, ) = _userAddress.call{value: amount}("");
        require(sent, "Failed to send Ether");

    }

    function requestLoan (uint256 LoanRequestAmount) external{
        address LoanRequestaddress = msg.sender;
        uint256 balance = checkUserBalance(LoanRequestaddress);

        if(!UserInfo[LoanRequestaddress].active){
            revert Middey__NotAnActiveUser();
        }
        
        if(balance <= 1.0 ether){
            revert Middey__InsufficientFunds({
            _userAddress : LoanRequestaddress, 
            balance : balance
        });
        
        } 
        loanid++ ; // Get current LoanID and increment the counter
        LoanID[loanid] = LoanRequestaddress;
        emit emitLoanId(loanid, LoanRequestAmount);

    }
}