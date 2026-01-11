/**
 * Contract Template Library
 *
 * Pre-audited, production-ready contract templates
 */

import { ContractTemplate, TemplateParameter } from "../../utils/types";

// ===========================================
//          Template Registry
// ===========================================

export const CONTRACT_TEMPLATES: ContractTemplate[] = [
  // ERC20 Templates
  {
    id: "erc20-standard",
    name: "ERC20 Standard Token",
    description: "Basic ERC20 token with standard functionality",
    category: "token",
    features: ["transfer", "approve", "allowance"],
    parameters: [
      {
        name: "name",
        type: "string",
        required: true,
        description: "Token name",
      },
      {
        name: "symbol",
        type: "string",
        required: true,
        description: "Token symbol",
      },
      {
        name: "initialSupply",
        type: "uint256",
        required: true,
        description: "Initial token supply (in wei)",
      },
    ],
    baseCode: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract {{name}}Token is ERC20 {
    constructor() ERC20("{{name}}", "{{symbol}}") {
        _mint(msg.sender, {{initialSupply}});
    }
}`,
  },

  {
    id: "erc20-mintable-burnable",
    name: "ERC20 Mintable & Burnable",
    description: "ERC20 token with mint and burn capabilities",
    category: "token",
    features: ["transfer", "mint", "burn", "ownable"],
    parameters: [
      {
        name: "name",
        type: "string",
        required: true,
        description: "Token name",
      },
      {
        name: "symbol",
        type: "string",
        required: true,
        description: "Token symbol",
      },
      {
        name: "initialSupply",
        type: "uint256",
        required: true,
        description: "Initial token supply",
      },
    ],
    baseCode: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract {{name}}Token is ERC20, ERC20Burnable, Ownable {
    constructor(address initialOwner)
        ERC20("{{name}}", "{{symbol}}")
        Ownable(initialOwner)
    {
        _mint(msg.sender, {{initialSupply}});
    }

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }
}`,
  },

  {
    id: "erc20-pausable",
    name: "ERC20 Pausable",
    description: "ERC20 token with emergency pause functionality",
    category: "token",
    features: ["transfer", "pause", "unpause", "ownable"],
    parameters: [
      {
        name: "name",
        type: "string",
        required: true,
        description: "Token name",
      },
      {
        name: "symbol",
        type: "string",
        required: true,
        description: "Token symbol",
      },
      {
        name: "initialSupply",
        type: "uint256",
        required: true,
        description: "Initial token supply",
      },
    ],
    baseCode: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract {{name}}Token is ERC20, ERC20Pausable, Ownable {
    constructor(address initialOwner)
        ERC20("{{name}}", "{{symbol}}")
        Ownable(initialOwner)
    {
        _mint(msg.sender, {{initialSupply}});
    }

    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    function _update(address from, address to, uint256 value)
        internal
        override(ERC20, ERC20Pausable)
    {
        super._update(from, to, value);
    }
}`,
  },

  // ERC721 Templates
  {
    id: "erc721-standard",
    name: "ERC721 NFT Collection",
    description: "Basic NFT collection with URI storage",
    category: "nft",
    features: ["mint", "transfer", "uri"],
    parameters: [
      {
        name: "name",
        type: "string",
        required: true,
        description: "Collection name",
      },
      {
        name: "symbol",
        type: "string",
        required: true,
        description: "Collection symbol",
      },
      {
        name: "baseUri",
        type: "string",
        required: false,
        defaultValue: "",
        description: "Base URI for token metadata",
      },
    ],
    baseCode: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract {{name}}NFT is ERC721, ERC721URIStorage, Ownable {
    uint256 private _nextTokenId;

    constructor(address initialOwner)
        ERC721("{{name}}", "{{symbol}}")
        Ownable(initialOwner)
    {}

    function safeMint(address to, string memory uri) public onlyOwner {
        uint256 tokenId = _nextTokenId++;
        _safeMint(to, tokenId);
        _setTokenURI(tokenId, uri);
    }

    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721, ERC721URIStorage)
        returns (string memory)
    {
        return super.tokenURI(tokenId);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, ERC721URIStorage)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}`,
  },

  // Multi-Sig Wallet
  {
    id: "multisig-wallet",
    name: "Multi-Signature Wallet",
    description: "Secure multi-signature wallet requiring multiple confirmations",
    category: "wallet",
    features: ["submit", "confirm", "execute", "revoke"],
    parameters: [
      {
        name: "owners",
        type: "address[]",
        required: true,
        description: "Array of owner addresses",
      },
      {
        name: "required",
        type: "uint256",
        required: true,
        description: "Number of required confirmations",
      },
    ],
    baseCode: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MultiSigWallet {
    event Deposit(address indexed sender, uint amount, uint balance);
    event SubmitTransaction(
        address indexed owner,
        uint indexed txIndex,
        address indexed to,
        uint value,
        bytes data
    );
    event ConfirmTransaction(address indexed owner, uint indexed txIndex);
    event RevokeConfirmation(address indexed owner, uint indexed txIndex);
    event ExecuteTransaction(address indexed owner, uint indexed txIndex);

    address[] public owners;
    mapping(address => bool) public isOwner;
    uint public numConfirmationsRequired;

    struct Transaction {
        address to;
        uint value;
        bytes data;
        bool executed;
        uint numConfirmations;
    }

    mapping(uint => mapping(address => bool)) public isConfirmed;
    Transaction[] public transactions;

    modifier onlyOwner() {
        require(isOwner[msg.sender], "not owner");
        _;
    }

    modifier txExists(uint _txIndex) {
        require(_txIndex < transactions.length, "tx does not exist");
        _;
    }

    modifier notExecuted(uint _txIndex) {
        require(!transactions[_txIndex].executed, "tx already executed");
        _;
    }

    modifier notConfirmed(uint _txIndex) {
        require(!isConfirmed[_txIndex][msg.sender], "tx already confirmed");
        _;
    }

    constructor(address[] memory _owners, uint _numConfirmationsRequired) {
        require(_owners.length > 0, "owners required");
        require(
            _numConfirmationsRequired > 0 &&
                _numConfirmationsRequired <= _owners.length,
            "invalid number of required confirmations"
        );

        for (uint i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            require(owner != address(0), "invalid owner");
            require(!isOwner[owner], "owner not unique");
            isOwner[owner] = true;
            owners.push(owner);
        }

        numConfirmationsRequired = _numConfirmationsRequired;
    }

    receive() external payable {
        emit Deposit(msg.sender, msg.value, address(this).balance);
    }

    function submitTransaction(
        address _to,
        uint _value,
        bytes memory _data
    ) public onlyOwner {
        uint txIndex = transactions.length;

        transactions.push(
            Transaction({
                to: _to,
                value: _value,
                data: _data,
                executed: false,
                numConfirmations: 0
            })
        );

        emit SubmitTransaction(msg.sender, txIndex, _to, _value, _data);
    }

    function confirmTransaction(
        uint _txIndex
    ) public onlyOwner txExists(_txIndex) notExecuted(_txIndex) notConfirmed(_txIndex) {
        Transaction storage transaction = transactions[_txIndex];
        transaction.numConfirmations += 1;
        isConfirmed[_txIndex][msg.sender] = true;

        emit ConfirmTransaction(msg.sender, _txIndex);
    }

    function executeTransaction(
        uint _txIndex
    ) public onlyOwner txExists(_txIndex) notExecuted(_txIndex) {
        Transaction storage transaction = transactions[_txIndex];

        require(
            transaction.numConfirmations >= numConfirmationsRequired,
            "cannot execute tx"
        );

        transaction.executed = true;

        (bool success, ) = transaction.to.call{value: transaction.value}(
            transaction.data
        );
        require(success, "tx failed");

        emit ExecuteTransaction(msg.sender, _txIndex);
    }

    function revokeConfirmation(
        uint _txIndex
    ) public onlyOwner txExists(_txIndex) notExecuted(_txIndex) {
        Transaction storage transaction = transactions[_txIndex];

        require(isConfirmed[_txIndex][msg.sender], "tx not confirmed");

        transaction.numConfirmations -= 1;
        isConfirmed[_txIndex][msg.sender] = false;

        emit RevokeConfirmation(msg.sender, _txIndex);
    }

    function getOwners() public view returns (address[] memory) {
        return owners;
    }

    function getTransactionCount() public view returns (uint) {
        return transactions.length;
    }

    function getTransaction(
        uint _txIndex
    )
        public
        view
        returns (
            address to,
            uint value,
            bytes memory data,
            bool executed,
            uint numConfirmations
        )
    {
        Transaction storage transaction = transactions[_txIndex];

        return (
            transaction.to,
            transaction.value,
            transaction.data,
            transaction.executed,
            transaction.numConfirmations
        );
    }
}`,
  },

  // Timelock Controller
  {
    id: "timelock-controller",
    name: "Timelock Controller",
    description: "Time-delayed execution for governance operations",
    category: "governance",
    features: ["schedule", "execute", "cancel", "roles"],
    parameters: [
      {
        name: "minDelay",
        type: "uint256",
        required: true,
        description: "Minimum delay in seconds before execution",
      },
      {
        name: "proposers",
        type: "address[]",
        required: true,
        description: "Addresses that can propose",
      },
      {
        name: "executors",
        type: "address[]",
        required: true,
        description: "Addresses that can execute",
      },
    ],
    baseCode: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/governance/TimelockController.sol";

contract SecureTimelock is TimelockController {
    constructor(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors,
        address admin
    ) TimelockController(minDelay, proposers, executors, admin) {}
}`,
  },
];

// ===========================================
//          Template Functions
// ===========================================

/**
 * Get all available templates
 */
export function getTemplates(): ContractTemplate[] {
  return CONTRACT_TEMPLATES;
}

/**
 * Get template by ID
 */
export function getTemplateById(id: string): ContractTemplate | undefined {
  return CONTRACT_TEMPLATES.find((t) => t.id === id);
}

/**
 * Get templates by category
 */
export function getTemplatesByCategory(category: string): ContractTemplate[] {
  return CONTRACT_TEMPLATES.filter((t) => t.category === category);
}

/**
 * Get template categories
 */
export function getTemplateCategories(): string[] {
  const categories = new Set(CONTRACT_TEMPLATES.map((t) => t.category));
  return Array.from(categories);
}

/**
 * Render template with parameters
 */
export function renderTemplate(
  template: ContractTemplate,
  params: Record<string, unknown>
): string {
  // Validate required parameters
  for (const param of template.parameters) {
    if (param.required && !(param.name in params)) {
      throw new Error(`Missing required parameter: ${param.name}`);
    }
  }

  // Apply default values
  const finalParams: Record<string, unknown> = {};
  for (const param of template.parameters) {
    finalParams[param.name] = params[param.name] ?? param.defaultValue;
  }

  // Replace placeholders in template
  let code = template.baseCode;
  for (const [key, value] of Object.entries(finalParams)) {
    const placeholder = new RegExp(`\\{\\{${key}\\}\\}`, "g");
    code = code.replace(placeholder, String(value));
  }

  return code;
}

/**
 * Search templates by keyword
 */
export function searchTemplates(keyword: string): ContractTemplate[] {
  const lower = keyword.toLowerCase();
  return CONTRACT_TEMPLATES.filter(
    (t) =>
      t.name.toLowerCase().includes(lower) ||
      t.description.toLowerCase().includes(lower) ||
      t.features.some((f) => f.toLowerCase().includes(lower))
  );
}
