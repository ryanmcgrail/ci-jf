"""Auto-generated mapping from CWE Weakness ID to its corresponding Root Pillar ID.

Source: cwec_v4.20.xml
"""

from __future__ import annotations

WEAKNESS_TO_ROOT_PILLAR: dict[int, int] = {
    # --- Root Pillar CWE-284: Improper Access Control (148 weaknesses) ---
    9: 284,  # J2EE Misconfiguration: Weak Access Permissions for EJB Methods
    13: 284,  # ASP.NET Misconfiguration: Password in Configuration File
    202: 284,  # Exposure of Sensitive Information Through Data Queries
    250: 284,  # Execution with Unnecessary Privileges
    256: 284,  # Plaintext Storage of a Password
    257: 284,  # Storing Passwords in a Recoverable Format
    258: 284,  # Empty Password in Configuration File
    259: 284,  # Use of Hard-coded Password
    260: 284,  # Password in Configuration File
    261: 284,  # Weak Encoding for Password
    262: 284,  # Not Using Password Aging
    263: 284,  # Password Aging with Long Expiration
    266: 284,  # Incorrect Privilege Assignment
    267: 284,  # Privilege Defined With Unsafe Actions
    268: 284,  # Privilege Chaining
    269: 284,  # Improper Privilege Management
    270: 284,  # Privilege Context Switching Error
    271: 284,  # Privilege Dropping / Lowering Errors
    272: 284,  # Least Privilege Violation
    276: 284,  # Incorrect Default Permissions
    277: 284,  # Insecure Inherited Permissions
    278: 284,  # Insecure Preserved Inherited Permissions
    279: 284,  # Incorrect Execution-Assigned Permissions
    281: 284,  # Improper Preservation of Permissions
    282: 284,  # Improper Ownership Management
    283: 284,  # Unverified Ownership
    284: 284,  # Improper Access Control (Root Pillar)
    285: 284,  # Improper Authorization
    286: 284,  # Incorrect User Management
    287: 284,  # Improper Authentication
    288: 284,  # Authentication Bypass Using an Alternate Path or Channel
    289: 284,  # Authentication Bypass by Alternate Name
    290: 284,  # Authentication Bypass by Spoofing
    291: 284,  # Reliance on IP Address for Authentication
    293: 284,  # Using Referer Field for Authentication
    294: 284,  # Authentication Bypass by Capture-replay
    295: 284,  # Improper Certificate Validation
    296: 284,  # Improper Following of a Certificate's Chain of Trust
    297: 284,  # Improper Validation of Certificate with Host Mismatch
    298: 284,  # Improper Validation of Certificate Expiration
    299: 284,  # Improper Check for Certificate Revocation
    300: 284,  # Channel Accessible by Non-Endpoint
    301: 284,  # Reflection Attack in an Authentication Protocol
    302: 284,  # Authentication Bypass by Assumed-Immutable Data
    303: 284,  # Incorrect Implementation of Authentication Algorithm
    304: 284,  # Missing Critical Step in Authentication
    305: 284,  # Authentication Bypass by Primary Weakness
    306: 284,  # Missing Authentication for Critical Function
    307: 284,  # Improper Restriction of Excessive Authentication Attempts
    308: 284,  # Use of Single-factor Authentication
    309: 284,  # Use of Password System for Primary Authentication
    321: 284,  # Use of Hard-coded Cryptographic Key
    322: 284,  # Key Exchange without Entity Authentication
    350: 284,  # Reliance on Reverse DNS Resolution for a Security-Critical Action
    370: 284,  # Missing Check for Certificate Revocation after Initial Check
    419: 284,  # Unprotected Primary Channel
    420: 284,  # Unprotected Alternate Channel
    421: 284,  # Race Condition During Access to Alternate Channel
    422: 284,  # Unprotected Windows Messaging Channel ('Shatter')
    425: 284,  # Direct Request ('Forced Browsing')
    520: 284,  # .NET Misconfiguration: Use of Impersonation
    521: 284,  # Weak Password Requirements
    522: 284,  # Insufficiently Protected Credentials
    523: 284,  # Unprotected Transport of Credentials
    549: 284,  # Missing Password Field Masking
    551: 284,  # Incorrect Behavior Order: Authorization Before Parsing and Canonicalization
    555: 284,  # J2EE Misconfiguration: Plaintext Password in Configuration File
    556: 284,  # ASP.NET Misconfiguration: Use of Identity Impersonation
    566: 284,  # Authorization Bypass Through User-Controlled SQL Primary Key
    599: 284,  # Missing Validation of OpenSSL Certificate
    603: 284,  # Use of Client-Side Authentication
    612: 284,  # Improper Authorization of Index Containing Sensitive Information
    618: 284,  # Exposed Unsafe ActiveX Method
    620: 284,  # Unverified Password Change
    623: 284,  # Unsafe ActiveX Control Marked Safe For Scripting
    639: 284,  # Authorization Bypass Through User-Controlled Key
    640: 284,  # Weak Password Recovery Mechanism for Forgotten Password
    645: 284,  # Overly Restrictive Account Lockout Mechanism
    647: 284,  # Use of Non-Canonical URL Paths for Authorization Decisions
    648: 284,  # Incorrect Use of Privileged APIs
    708: 284,  # Incorrect Ownership Assignment
    732: 284,  # Incorrect Permission Assignment for Critical Resource
    749: 284,  # Exposed Dangerous Method or Function
    766: 284,  # Critical Data Element Declared Public
    782: 284,  # Exposed IOCTL with Insufficient Access Control
    798: 284,  # Use of Hard-coded Credentials
    804: 284,  # Guessable CAPTCHA
    836: 284,  # Use of Password Hash Instead of Password for Authentication
    842: 284,  # Placement of User into Incorrect Group
    862: 284,  # Missing Authorization
    863: 284,  # Incorrect Authorization
    923: 284,  # Improper Restriction of Communication Channel to Intended Endpoints
    925: 284,  # Improper Verification of Intent by Broadcast Receiver
    926: 284,  # Improper Export of Android Application Components
    927: 284,  # Use of Implicit Intent for Sensitive Communication
    939: 284,  # Improper Authorization in Handler for Custom URL Scheme
    940: 284,  # Improper Verification of Source of a Communication Channel
    941: 284,  # Incorrectly Specified Destination in a Communication Channel
    942: 284,  # Permissive Cross-domain Security Policy with Untrusted Domains
    1004: 284,  # Sensitive Cookie Without 'HttpOnly' Flag
    1022: 284,  # Use of Web Link to Untrusted Target with window.opener Access
    1191: 284,  # On-Chip Debug and Test Interface With Improper Access Control
    1220: 284,  # Insufficient Granularity of Access Control
    1222: 284,  # Insufficient Granularity of Address Regions Protected by Register Locks
    1224: 284,  # Improper Restriction of Write-Once Bit Fields
    1230: 284,  # Exposure of Sensitive Information Through Metadata
    1231: 284,  # Improper Prevention of Lock Bit Modification
    1233: 284,  # Security-Sensitive Hardware Controls with Missing Lock Bit Protection
    1243: 284,  # Sensitive Non-Volatile Information Not Protected During Debug
    1244: 284,  # Internal Asset Exposed to Unsafe Debug Access Level or State
    1252: 284,  # CPU Hardware Not Configured to Support Exclusivity of Write and Execute Operations
    1256: 284,  # Improper Restriction of Software Interfaces to Hardware Features
    1257: 284,  # Improper Access Control Applied to Mirrored or Aliased Memory Regions
    1259: 284,  # Improper Restriction of Security Token Assignment
    1260: 284,  # Improper Handling of Overlap Between Protected Memory Ranges
    1262: 284,  # Improper Access Control for Register Interface
    1263: 284,  # Improper Physical Access Control
    1267: 284,  # Policy Uses Obsolete Encoding
    1268: 284,  # Policy Privileges are not Assigned Consistently Between Control and Data Agents
    1270: 284,  # Generation of Incorrect Security Tokens
    1274: 284,  # Improper Access Control for Volatile Memory Containing Boot Code
    1275: 284,  # Sensitive Cookie with Improper SameSite Attribute
    1276: 284,  # Hardware Child Block Incorrectly Connected to Parent System
    1283: 284,  # Mutable Attestation or Measurement Reporting Data
    1290: 284,  # Incorrect Decoding of Security Identifiers
    1292: 284,  # Incorrect Conversion of Security Identifiers
    1294: 284,  # Insecure Security Identifier Mechanism
    1296: 284,  # Incorrect Chaining or Granularity of Debug Components
    1297: 284,  # Unprotected Confidential Information on Device is Accessible by OSAT Vendors
    1299: 284,  # Missing Protection Mechanism for Alternate Hardware Interface
    1302: 284,  # Missing Source Identifier in Entity Transactions on a System-On-Chip (SOC)
    1304: 284,  # Improperly Preserved Integrity of Hardware Configuration State During a Power Save/Restore Operation
    1311: 284,  # Improper Translation of Security Attributes by Fabric Bridge
    1312: 284,  # Missing Protection for Mirrored Regions in On-Chip Fabric Firewall
    1313: 284,  # Hardware Allows Activation of Test or Debug Logic at Runtime
    1314: 284,  # Missing Write Protection for Parametric Data Values
    1315: 284,  # Improper Setting of Bus Controlling Capability in Fabric End-point
    1316: 284,  # Fabric-Address Map Allows Programming of Unwarranted Overlaps of Protected and Unprotected Ranges
    1317: 284,  # Improper Access Control in Fabric Bridge
    1320: 284,  # Improper Protection for Outbound Error Messages and Alert Signals
    1323: 284,  # Improper Management of Sensitive Trace Data
    1328: 284,  # Security Version Number Mutable to Older Versions
    1334: 284,  # Unauthorized Error Injection Can Degrade Hardware Redundancy
    1390: 284,  # Weak Authentication
    1391: 284,  # Use of Weak Credentials
    1392: 284,  # Use of Default Credentials
    1393: 284,  # Use of Default Password
    1394: 284,  # Use of Default Cryptographic Key

    # --- Root Pillar CWE-435: Improper Interaction Between Multiple Correctly-Behaving Entities (11 weaknesses) ---
    14: 435,  # Compiler Removal of Code to Clear Buffers
    115: 435,  # Misinterpretation of Input
    435: 435,  # Improper Interaction Between Multiple Correctly-Behaving Entities (Root Pillar)
    436: 435,  # Interpretation Conflict
    437: 435,  # Incomplete Model of Endpoint Features
    439: 435,  # Behavioral Change in New Version or Environment
    444: 435,  # Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')
    650: 435,  # Trusting HTTP Permission Methods on the Server Side
    733: 435,  # Compiler Optimization Removal or Modification of Security-critical Code
    1037: 435,  # Processor Optimization Removal or Modification of Security-critical Code
    1038: 435,  # Insecure Automated Optimizations

    # --- Root Pillar CWE-664: Improper Control of a Resource Through its Lifetime (324 weaknesses) ---
    8: 664,  # J2EE Misconfiguration: Entity Bean Declared Remote
    15: 664,  # External Control of System or Configuration Setting
    22: 664,  # Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
    23: 664,  # Relative Path Traversal
    24: 664,  # Path Traversal: '../filedir'
    25: 664,  # Path Traversal: '/../filedir'
    26: 664,  # Path Traversal: '/dir/../filename'
    27: 664,  # Path Traversal: 'dir/../../filename'
    28: 664,  # Path Traversal: '..\filedir'
    29: 664,  # Path Traversal: '\..\filename'
    30: 664,  # Path Traversal: '\dir\..\filename'
    31: 664,  # Path Traversal: 'dir\..\..\filename'
    32: 664,  # Path Traversal: '...' (Triple Dot)
    33: 664,  # Path Traversal: '....' (Multiple Dot)
    34: 664,  # Path Traversal: '....//'
    35: 664,  # Path Traversal: '.../...//'
    36: 664,  # Absolute Path Traversal
    37: 664,  # Path Traversal: '/absolute/pathname/here'
    38: 664,  # Path Traversal: '\absolute\pathname\here'
    39: 664,  # Path Traversal: 'C:dirname'
    40: 664,  # Path Traversal: '\\UNC\share\name\' (Windows UNC Share)
    41: 664,  # Improper Resolution of Path Equivalence
    42: 664,  # Path Equivalence: 'filename.' (Trailing Dot)
    43: 664,  # Path Equivalence: 'filename....' (Multiple Trailing Dot)
    44: 664,  # Path Equivalence: 'file.name' (Internal Dot)
    45: 664,  # Path Equivalence: 'file...name' (Multiple Internal Dot)
    46: 664,  # Path Equivalence: 'filename ' (Trailing Space)
    47: 664,  # Path Equivalence: ' filename' (Leading Space)
    48: 664,  # Path Equivalence: 'file name' (Internal Whitespace)
    49: 664,  # Path Equivalence: 'filename/' (Trailing Slash)
    50: 664,  # Path Equivalence: '//multiple/leading/slash'
    51: 664,  # Path Equivalence: '/multiple//internal/slash'
    52: 664,  # Path Equivalence: '/multiple/trailing/slash//'
    53: 664,  # Path Equivalence: '\multiple\\internal\backslash'
    54: 664,  # Path Equivalence: 'filedir\' (Trailing Backslash)
    55: 664,  # Path Equivalence: '/./' (Single Dot Directory)
    56: 664,  # Path Equivalence: 'filedir*' (Wildcard)
    57: 664,  # Path Equivalence: 'fakedir/../realdir/filename'
    58: 664,  # Path Equivalence: Windows 8.3 Filename
    59: 664,  # Improper Link Resolution Before File Access ('Link Following')
    61: 664,  # UNIX Symbolic Link (Symlink) Following
    62: 664,  # UNIX Hard Link
    64: 664,  # Windows Shortcut Following (.LNK)
    65: 664,  # Windows Hard Link
    66: 664,  # Improper Handling of File Names that Identify Virtual Resources
    67: 664,  # Improper Handling of Windows Device Names
    69: 664,  # Improper Handling of Windows ::DATA Alternate Data Stream
    72: 664,  # Improper Handling of Apple HFS+ Alternate Data Stream Path
    73: 664,  # External Control of File Name or Path
    98: 664,  # Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')
    114: 664,  # Process Control
    118: 664,  # Incorrect Access of Indexable Resource ('Range Error')
    119: 664,  # Improper Restriction of Operations within the Bounds of a Memory Buffer
    120: 664,  # Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
    121: 664,  # Stack-based Buffer Overflow
    122: 664,  # Heap-based Buffer Overflow
    123: 664,  # Write-what-where Condition
    124: 664,  # Buffer Underwrite ('Buffer Underflow')
    125: 664,  # Out-of-bounds Read
    126: 664,  # Buffer Over-read
    127: 664,  # Buffer Under-read
    134: 664,  # Use of Externally-Controlled Format String
    178: 664,  # Improper Handling of Case Sensitivity
    192: 664,  # Integer Coercion Error
    194: 664,  # Unexpected Sign Extension
    195: 664,  # Signed to Unsigned Conversion Error
    196: 664,  # Unsigned to Signed Conversion Error
    197: 664,  # Numeric Truncation Error
    200: 664,  # Exposure of Sensitive Information to an Unauthorized Actor
    201: 664,  # Insertion of Sensitive Information Into Sent Data
    203: 664,  # Observable Discrepancy
    204: 664,  # Observable Response Discrepancy
    205: 664,  # Observable Behavioral Discrepancy
    206: 664,  # Observable Internal Behavioral Discrepancy
    207: 664,  # Observable Behavioral Discrepancy With Equivalent Products
    208: 664,  # Observable Timing Discrepancy
    209: 664,  # Generation of Error Message Containing Sensitive Information
    210: 664,  # Self-generated Error Message Containing Sensitive Information
    211: 664,  # Externally-Generated Error Message Containing Sensitive Information
    212: 664,  # Improper Removal of Sensitive Information Before Storage or Transfer
    213: 664,  # Exposure of Sensitive Information Due to Incompatible Policies
    214: 664,  # Invocation of Process Using Visible Sensitive Information
    215: 664,  # Insertion of Sensitive Information Into Debugging Code
    219: 664,  # Storage of File with Sensitive Data Under Web Root
    220: 664,  # Storage of File With Sensitive Data Under FTP Root
    221: 664,  # Information Loss or Omission
    222: 664,  # Truncation of Security-relevant Information
    223: 664,  # Omission of Security-relevant Information
    224: 664,  # Obscured Security-relevant Information by Alternate Name
    226: 664,  # Sensitive Information in Resource Not Removed Before Reuse
    243: 664,  # Creation of chroot Jail Without Changing Working Directory
    244: 664,  # Improper Clearing of Heap Memory Before Release ('Heap Inspection')
    324: 664,  # Use of a Key Past its Expiration Date
    356: 664,  # Product UI does not Warn User of Unsafe Actions
    359: 664,  # Exposure of Private Personal Information to an Unauthorized Actor
    362: 664,  # Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
    363: 664,  # Race Condition Enabling Link Following
    364: 664,  # Signal Handler Race Condition
    366: 664,  # Race Condition within a Thread
    367: 664,  # Time-of-check Time-of-use (TOCTOU) Race Condition
    368: 664,  # Context Switching Race Condition
    372: 664,  # Incomplete Internal State Distinction
    374: 664,  # Passing Mutable Objects to an Untrusted Method
    375: 664,  # Returning a Mutable Object to an Untrusted Caller
    377: 664,  # Insecure Temporary File
    378: 664,  # Creation of Temporary File With Insecure Permissions
    379: 664,  # Creation of Temporary File in Directory with Insecure Permissions
    384: 664,  # Session Fixation
    385: 664,  # Covert Timing Channel
    386: 664,  # Symbolic Name not Mapping to Correct Object
    400: 664,  # Uncontrolled Resource Consumption
    401: 664,  # Missing Release of Memory after Effective Lifetime
    402: 664,  # Transmission of Private Resources into a New Sphere ('Resource Leak')
    403: 664,  # Exposure of File Descriptor to Unintended Control Sphere ('File Descriptor Leak')
    404: 664,  # Improper Resource Shutdown or Release
    405: 664,  # Asymmetric Resource Consumption (Amplification)
    406: 664,  # Insufficient Control of Network Message Volume (Network Amplification)
    407: 664,  # Inefficient Algorithmic Complexity
    409: 664,  # Improper Handling of Highly Compressed Data (Data Amplification)
    410: 664,  # Insufficient Resource Pool
    412: 664,  # Unrestricted Externally Accessible Lock
    413: 664,  # Improper Resource Locking
    414: 664,  # Missing Lock Check
    415: 664,  # Double Free
    416: 664,  # Use After Free
    426: 664,  # Untrusted Search Path
    427: 664,  # Uncontrolled Search Path Element
    428: 664,  # Unquoted Search Path or Element
    432: 664,  # Dangerous Signal Handler not Disabled During Sensitive Operations
    433: 664,  # Unparsed Raw Web Content Delivery
    434: 664,  # Unrestricted Upload of File with Dangerous Type
    441: 664,  # Unintended Proxy or Intermediary ('Confused Deputy')
    453: 664,  # Insecure Default Variable Initialization
    454: 664,  # External Initialization of Trusted Variables or Data Stores
    456: 664,  # Missing Initialization of a Variable
    457: 664,  # Use of Uninitialized Variable
    459: 664,  # Incomplete Cleanup
    460: 664,  # Improper Cleanup on Thrown Exception
    466: 664,  # Return of Pointer Value Outside of Expected Range
    470: 664,  # Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
    471: 664,  # Modification of Assumed-Immutable Data (MAID)
    472: 664,  # External Control of Assumed-Immutable Web Parameter
    473: 664,  # PHP External Variable Modification
    479: 664,  # Signal Handler Use of a Non-reentrant Function
    487: 664,  # Reliance on Package-level Scope
    488: 664,  # Exposure of Data Element to Wrong Session
    491: 664,  # Public cloneable() Method Without Final ('Object Hijack')
    492: 664,  # Use of Inner Class Containing Sensitive Data
    493: 664,  # Critical Public Variable Without Final Modifier
    495: 664,  # Private Data Structure Returned From A Public Method
    496: 664,  # Public Data Assigned to Private Array-Typed Field
    497: 664,  # Exposure of Sensitive System Information to an Unauthorized Control Sphere
    498: 664,  # Cloneable Class Containing Sensitive Information
    499: 664,  # Serializable Class Containing Sensitive Data
    500: 664,  # Public Static Field Not Marked Final
    501: 664,  # Trust Boundary Violation
    502: 664,  # Deserialization of Untrusted Data
    514: 664,  # Covert Channel
    515: 664,  # Covert Storage Channel
    524: 664,  # Use of Cache Containing Sensitive Information
    525: 664,  # Use of Web Browser Cache Containing Sensitive Information
    527: 664,  # Exposure of Version-Control Repository to an Unauthorized Control Sphere
    528: 664,  # Exposure of Core Dump File to an Unauthorized Control Sphere
    529: 664,  # Exposure of Access Control List Files to an Unauthorized Control Sphere
    530: 664,  # Exposure of Backup File to an Unauthorized Control Sphere
    531: 664,  # Inclusion of Sensitive Information in Test Code
    532: 664,  # Insertion of Sensitive Information into Log File
    535: 664,  # Exposure of Information Through Shell Error Message
    536: 664,  # Servlet Runtime Error Message Containing Sensitive Information
    537: 664,  # Java Runtime Error Message Containing Sensitive Information
    538: 664,  # Insertion of Sensitive Information into Externally-Accessible File or Directory
    539: 664,  # Use of Persistent Cookies Containing Sensitive Information
    540: 664,  # Inclusion of Sensitive Information in Source Code
    541: 664,  # Inclusion of Sensitive Information in an Include File
    543: 664,  # Use of Singleton Pattern Without Synchronization in a Multithreaded Context
    548: 664,  # Exposure of Information Through Directory Listing
    550: 664,  # Server-generated Error Message Containing Sensitive Information
    552: 664,  # Files or Directories Accessible to External Parties
    553: 664,  # Command Shell in Externally Accessible Directory
    558: 664,  # Use of getlogin() in Multithreaded Application
    565: 664,  # Reliance on Cookies without Validation and Integrity Checking
    567: 664,  # Unsynchronized Access to Shared Data in a Multithreaded Context
    568: 664,  # finalize() Method Without super.finalize()
    572: 664,  # Call to Thread run() instead of start()
    574: 664,  # EJB Bad Practices: Use of Synchronization Primitives
    580: 664,  # clone() Method Without super.clone()
    582: 664,  # Array Declared Public, Final, and Static
    583: 664,  # finalize() Method Declared Public
    588: 664,  # Attempt to Access Child of a Non-structure Pointer
    590: 664,  # Free of Memory not on the Heap
    591: 664,  # Sensitive Data Storage in Improperly Locked Memory
    593: 664,  # Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created
    598: 664,  # Use of HTTP Request With Sensitive Query String
    601: 664,  # URL Redirection to Untrusted Site ('Open Redirect')
    607: 664,  # Public Static Final Field References Mutable Object
    608: 664,  # Struts: Non-private Field in ActionForm Class
    609: 664,  # Double-Checked Locking
    610: 664,  # Externally Controlled Reference to a Resource in Another Sphere
    611: 664,  # Improper Restriction of XML External Entity Reference
    613: 664,  # Insufficient Session Expiration
    615: 664,  # Inclusion of Sensitive Information in Source Code Comments
    619: 664,  # Dangling Database Cursor ('Cursor Injection')
    642: 664,  # External Control of Critical State Data
    651: 664,  # Exposure of WSDL File Containing Sensitive Information
    662: 664,  # Improper Synchronization
    663: 664,  # Use of a Non-reentrant Function in a Concurrent Context
    664: 664,  # Improper Control of a Resource Through its Lifetime (Root Pillar)
    665: 664,  # Improper Initialization
    666: 664,  # Operation on Resource in Wrong Phase of Lifetime
    667: 664,  # Improper Locking
    668: 664,  # Exposure of Resource to Wrong Sphere
    669: 664,  # Incorrect Resource Transfer Between Spheres
    672: 664,  # Operation on a Resource after Expiration or Release
    673: 664,  # External Influence of Sphere Definition
    681: 664,  # Incorrect Conversion between Numeric Types
    689: 664,  # Permission Race Condition During Resource Copy
    704: 664,  # Incorrect Type Conversion or Cast
    706: 664,  # Use of Incorrectly-Resolved Name or Reference
    761: 664,  # Free of Pointer not at Start of Buffer
    762: 664,  # Mismatched Memory Management Routines
    763: 664,  # Release of Invalid Pointer or Reference
    764: 664,  # Multiple Locks of a Critical Resource
    765: 664,  # Multiple Unlocks of a Critical Resource
    767: 664,  # Access to Critical Private Variable via Public Method
    770: 664,  # Allocation of Resources Without Limits or Throttling
    771: 664,  # Missing Reference to Active Allocated Resource
    772: 664,  # Missing Release of Resource after Effective Lifetime
    773: 664,  # Missing Reference to Active File Descriptor or Handle
    774: 664,  # Allocation of File Descriptors or Handles Without Limits or Throttling
    775: 664,  # Missing Release of File Descriptor or Handle after Effective Lifetime
    778: 664,  # Insufficient Logging
    779: 664,  # Logging of Excessive Data
    784: 664,  # Reliance on Cookies without Validation and Integrity Checking in a Security Decision
    786: 664,  # Access of Memory Location Before Start of Buffer
    787: 664,  # Out-of-bounds Write
    788: 664,  # Access of Memory Location After End of Buffer
    789: 664,  # Memory Allocation with Excessive Size Value
    805: 664,  # Buffer Access with Incorrect Length Value
    806: 664,  # Buffer Access Using Size of Source Buffer
    820: 664,  # Missing Synchronization
    821: 664,  # Incorrect Synchronization
    822: 664,  # Untrusted Pointer Dereference
    823: 664,  # Use of Out-of-range Pointer Offset
    824: 664,  # Access of Uninitialized Pointer
    825: 664,  # Expired Pointer Dereference
    826: 664,  # Premature Release of Resource During Expected Lifetime
    827: 664,  # Improper Control of Document Type Definition
    828: 664,  # Signal Handler with Functionality that is not Asynchronous-Safe
    829: 664,  # Inclusion of Functionality from Untrusted Control Sphere
    830: 664,  # Inclusion of Web Functionality from an Untrusted Source
    831: 664,  # Signal Handler Function Associated with Multiple Signals
    832: 664,  # Unlock of a Resource that is not Locked
    833: 664,  # Deadlock
    843: 664,  # Access of Resource Using Incompatible Type ('Type Confusion')
    908: 664,  # Use of Uninitialized Resource
    909: 664,  # Missing Initialization of Resource
    910: 664,  # Use of Expired File Descriptor
    911: 664,  # Improper Update of Reference Count
    913: 664,  # Improper Control of Dynamically-Managed Code Resources
    915: 664,  # Improperly Controlled Modification of Dynamically-Determined Object Attributes
    918: 664,  # Server-Side Request Forgery (SSRF)
    920: 664,  # Improper Restriction of Power Consumption
    921: 664,  # Storage of Sensitive Data in a Mechanism without Access Control
    922: 664,  # Insecure Storage of Sensitive Information
    1021: 664,  # Improper Restriction of Rendered UI Layers or Frames
    1042: 664,  # Static Member Data Element outside of a Singleton Class Element
    1046: 664,  # Creation of Immutable Text Using String Concatenation
    1049: 664,  # Excessive Data Query Operations in a Large Data Table
    1050: 664,  # Excessive Platform Resource Consumption within a Loop
    1051: 664,  # Initialization with Hard-Coded Network Resource Configuration Data
    1052: 664,  # Excessive Use of Hard-Coded Literals in Initialization
    1058: 664,  # Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element
    1063: 664,  # Creation of Class Instance within a Static Code Block
    1067: 664,  # Excessive Execution of Sequential Searches of Data Resource
    1072: 664,  # Data Resource Access without Use of Connection Pooling
    1073: 664,  # Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses
    1084: 664,  # Invokable Control Element with Excessive File or Data Access Operations
    1088: 664,  # Synchronous Access of Remote Resource without Timeout
    1089: 664,  # Large Data Table with Excessive Number of Indices
    1091: 664,  # Use of Object without Invoking Destructor Method
    1094: 664,  # Excessive Index Range Scan for a Data Resource
    1096: 664,  # Singleton Class Instance Creation without Proper Locking or Synchronization
    1176: 664,  # Inefficient CPU Computation
    1188: 664,  # Initialization of a Resource with an Insecure Default
    1221: 664,  # Incorrect Register Defaults or Module Parameters
    1223: 664,  # Race Condition for Write-Once Attributes
    1229: 664,  # Creation of Emergent Resource
    1232: 664,  # Improper Lock Behavior After Power State Transition
    1234: 664,  # Hardware Internal or Debug Modes Allow Override of Locks
    1235: 664,  # Incorrect Use of Autoboxing and Unboxing for Performance Critical Operations
    1239: 664,  # Improper Zeroization of Hardware Register
    1246: 664,  # Improper Write Handling in Limited-write Non-Volatile Memories
    1249: 664,  # Application-Level Admin Tool with Inconsistent View of Underlying Operating System
    1250: 664,  # Improper Preservation of Consistency Between Independent Representations of Shared State
    1251: 664,  # Mirrored Regions with Different Values
    1254: 664,  # Incorrect Comparison Logic Granularity
    1255: 664,  # Comparison Logic is Vulnerable to Power Side-Channel Attacks
    1258: 664,  # Exposure of Sensitive System Information Due to Uncleared Debug Information
    1264: 664,  # Hardware Logic with Insecure De-Synchronization between Control and Data Channels
    1265: 664,  # Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls
    1266: 664,  # Improper Scrubbing of Sensitive Data from Decommissioned Device
    1271: 664,  # Uninitialized Value on Reset for Registers Holding Security Settings
    1272: 664,  # Sensitive Information Uncleared Before Debug/Power State Transition
    1273: 664,  # Device Unlock Credential Sharing
    1282: 664,  # Assumed-Immutable Data is Stored in Writable Memory
    1295: 664,  # Debug Messages Revealing Unnecessary Information
    1298: 664,  # Hardware Logic Contains Race Conditions
    1300: 664,  # Improper Protection of Physical Side Channels
    1301: 664,  # Insufficient or Incomplete Data Removal within Hardware Component
    1321: 664,  # Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')
    1325: 664,  # Improperly Controlled Sequential Memory Allocation
    1327: 664,  # Binding to an Unrestricted IP Address
    1330: 664,  # Remanent Data Readable after Memory Erase
    1333: 664,  # Inefficient Regular Expression Complexity
    1342: 664,  # Information Exposure through Microarchitectural State after Transient Execution
    1386: 664,  # Insecure Operation on Windows Junction / Mount Point
    1389: 664,  # Incorrect Parsing of Numbers with Different Radices
    1419: 664,  # Incorrect Initialization of Resource
    1420: 664,  # Exposure of Sensitive Information during Transient Execution
    1421: 664,  # Exposure of Sensitive Information in Shared Microarchitectural Structures during Transient Execution
    1422: 664,  # Exposure of Sensitive Information caused by Incorrect Data Forwarding during Transient Execution
    1423: 664,  # Exposure of Sensitive Information caused by Shared Microarchitectural Predictor State that Influences Transient Execution
    1429: 664,  # Missing Security-Relevant Feedback for Unexecuted Operations in Hardware Interface
    1431: 664,  # Driving Intermediate Cryptographic State/Results to Hardware Module Outputs

    # --- Root Pillar CWE-682: Incorrect Calculation (14 weaknesses) ---
    128: 682,  # Wrap-around Error
    131: 682,  # Incorrect Calculation of Buffer Size
    135: 682,  # Incorrect Calculation of Multi-Byte String Length
    190: 682,  # Integer Overflow or Wraparound
    191: 682,  # Integer Underflow (Wrap or Wraparound)
    193: 682,  # Off-by-one Error
    369: 682,  # Divide By Zero
    467: 682,  # Use of sizeof() on a Pointer Type
    468: 682,  # Incorrect Pointer Scaling
    469: 682,  # Use of Pointer Subtraction to Determine Size
    680: 682,  # Integer Overflow to Buffer Overflow
    682: 682,  # Incorrect Calculation (Root Pillar)
    1335: 682,  # Incorrect Bitwise Shift of Integer
    1339: 682,  # Insufficient Precision or Accuracy of a Real Number

    # --- Root Pillar CWE-691: Insufficient Control Flow Management (39 weaknesses) ---
    179: 691,  # Incorrect Behavior Order: Early Validation
    180: 691,  # Incorrect Behavior Order: Validate Before Canonicalize
    181: 691,  # Incorrect Behavior Order: Validate Before Filter
    248: 691,  # Uncaught Exception
    382: 691,  # J2EE Bad Practices: Use of System.exit()
    395: 691,  # Use of NullPointerException Catch to Detect NULL Pointer Dereference
    396: 691,  # Declaration of Catch for Generic Exception
    397: 691,  # Declaration of Throws for Generic Exception
    408: 691,  # Incorrect Behavior Order: Early Amplification
    430: 691,  # Deployment of Wrong Handler
    431: 691,  # Missing Handler
    455: 691,  # Non-exit on Failed Initialization
    480: 691,  # Use of Incorrect Operator
    481: 691,  # Assigning instead of Comparing
    482: 691,  # Comparing instead of Assigning
    483: 691,  # Incorrect Block Delimitation
    584: 691,  # Return Inside Finally Block
    600: 691,  # Uncaught Exception in Servlet
    617: 691,  # Reachable Assertion
    670: 691,  # Always-Incorrect Control Flow Implementation
    674: 691,  # Uncontrolled Recursion
    691: 691,  # Insufficient Control Flow Management (Root Pillar)
    696: 691,  # Incorrect Behavior Order
    698: 691,  # Execution After Redirect (EAR)
    705: 691,  # Incorrect Control Flow Scoping
    768: 691,  # Incorrect Short Circuit Evaluation
    776: 691,  # Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')
    783: 691,  # Operator Precedence Logic Error
    799: 691,  # Improper Control of Interaction Frequency
    834: 691,  # Excessive Iteration
    835: 691,  # Loop with Unreachable Exit Condition ('Infinite Loop')
    837: 691,  # Improper Enforcement of a Single, Unique Action
    841: 691,  # Improper Enforcement of Behavioral Workflow
    1190: 691,  # DMA Device Enabled Too Early in Boot Phase
    1193: 691,  # Power-On of Untrusted Execution Core Before Enabling Fabric Access Control
    1279: 691,  # Cryptographic Operations are run Before Supporting Units are Ready
    1280: 691,  # Access Control Check Implemented After Asset is Accessed
    1281: 691,  # Sequence of Processor Instructions Leads to Unexpected Behavior
    1322: 691,  # Use of Blocking Code in Single-threaded, Non-blocking Context

    # --- Root Pillar CWE-693: Protection Mechanism Failure (77 weaknesses) ---
    5: 693,  # J2EE Misconfiguration: Data Transmission Without Encryption
    6: 693,  # J2EE Misconfiguration: Insufficient Session-ID Length
    184: 693,  # Incomplete List of Disallowed Inputs
    311: 693,  # Missing Encryption of Sensitive Data
    312: 693,  # Cleartext Storage of Sensitive Information
    313: 693,  # Cleartext Storage in a File or on Disk
    314: 693,  # Cleartext Storage in the Registry
    315: 693,  # Cleartext Storage of Sensitive Information in a Cookie
    316: 693,  # Cleartext Storage of Sensitive Information in Memory
    317: 693,  # Cleartext Storage of Sensitive Information in GUI
    318: 693,  # Cleartext Storage of Sensitive Information in Executable
    319: 693,  # Cleartext Transmission of Sensitive Information
    323: 693,  # Reusing a Nonce, Key Pair in Encryption
    325: 693,  # Missing Cryptographic Step
    326: 693,  # Inadequate Encryption Strength
    327: 693,  # Use of a Broken or Risky Cryptographic Algorithm
    328: 693,  # Use of Weak Hash
    329: 693,  # Generation of Predictable IV with CBC Mode
    330: 693,  # Use of Insufficiently Random Values
    331: 693,  # Insufficient Entropy
    332: 693,  # Insufficient Entropy in PRNG
    333: 693,  # Improper Handling of Insufficient Entropy in TRNG
    334: 693,  # Small Space of Random Values
    335: 693,  # Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)
    336: 693,  # Same Seed in Pseudo-Random Number Generator (PRNG)
    337: 693,  # Predictable Seed in Pseudo-Random Number Generator (PRNG)
    338: 693,  # Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
    339: 693,  # Small Seed Space in PRNG
    340: 693,  # Generation of Predictable Numbers or Identifiers
    341: 693,  # Predictable from Observable State
    342: 693,  # Predictable Exact Value from Previous Values
    343: 693,  # Predictable Value Range from Previous Values
    344: 693,  # Use of Invariant Value in Dynamically Changing Context
    345: 693,  # Insufficient Verification of Data Authenticity
    346: 693,  # Origin Validation Error
    347: 693,  # Improper Verification of Cryptographic Signature
    348: 693,  # Use of Less Trusted Source
    349: 693,  # Acceptance of Extraneous Untrusted Data With Trusted Data
    351: 693,  # Insufficient Type Distinction
    352: 693,  # Cross-Site Request Forgery (CSRF)
    353: 693,  # Missing Support for Integrity Check
    354: 693,  # Improper Validation of Integrity Check Value
    357: 693,  # Insufficient UI Warning of Dangerous Operations
    360: 693,  # Trust of System Event Data
    450: 693,  # Multiple Interpretations of UI Input
    494: 693,  # Download of Code Without Integrity Check
    526: 693,  # Cleartext Storage of Sensitive Information in an Environment Variable
    602: 693,  # Client-Side Enforcement of Server-Side Security
    614: 693,  # Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
    616: 693,  # Incomplete Identification of Uploaded File Variables (PHP)
    646: 693,  # Reliance on File Name or Extension of Externally-Supplied File
    649: 693,  # Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking
    692: 693,  # Incomplete Denylist to Cross-Site Scripting
    693: 693,  # Protection Mechanism Failure (Root Pillar)
    757: 693,  # Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')
    759: 693,  # Use of a One-Way Hash without a Salt
    760: 693,  # Use of a One-Way Hash with a Predictable Salt
    780: 693,  # Use of RSA Algorithm without OAEP
    807: 693,  # Reliance on Untrusted Inputs in a Security Decision
    916: 693,  # Use of Password Hash With Insufficient Computational Effort
    924: 693,  # Improper Enforcement of Message Integrity During Transmission in a Communication Channel
    1039: 693,  # Inadequate Detection or Handling of Adversarial Input Perturbations in Automated Recognition Mechanism
    1204: 693,  # Generation of Weak Initialization Vector (IV)
    1240: 693,  # Use of a Cryptographic Primitive with a Risky Implementation
    1241: 693,  # Use of Predictable Algorithm in Random Number Generator
    1248: 693,  # Semiconductor Defects in Hardware Logic with Security-Sensitive Implications
    1253: 693,  # Incorrect Selection of Fuse Values
    1269: 693,  # Product Released in Non-Release Configuration
    1278: 693,  # Missing Protection Against Hardware Reverse Engineering Using Integrated Circuit (IC) Imaging Techniques
    1291: 693,  # Public Key Re-Use for Signing both Debug and Production Code
    1293: 693,  # Missing Source Correlation of Multiple Independent Data
    1318: 693,  # Missing Support for Security Features in On-chip Fabrics or Buses
    1319: 693,  # Improper Protection against Electromagnetic Fault Injection (EM-FI)
    1326: 693,  # Missing Immutable Root of Trust in Hardware
    1338: 693,  # Improper Protections Against Hardware Overheating
    1385: 693,  # Missing Origin Validation in WebSockets
    1428: 693,  # Reliance on HTTP instead of HTTPS

    # --- Root Pillar CWE-697: Incorrect Comparison (16 weaknesses) ---
    183: 697,  # Permissive List of Allowed Inputs
    185: 697,  # Incorrect Regular Expression
    186: 697,  # Overly Restrictive Regular Expression
    187: 697,  # Partial String Comparison
    478: 697,  # Missing Default Case in Multiple Condition Expression
    486: 697,  # Comparison of Classes by Name
    595: 697,  # Comparison of Object References Instead of Object Contents
    597: 697,  # Use of Wrong Operator in String Comparison
    625: 697,  # Permissive Regular Expression
    697: 697,  # Incorrect Comparison (Root Pillar)
    777: 697,  # Regular Expression without Anchors
    839: 697,  # Numeric Range Comparison Without Minimum Check
    1023: 697,  # Incomplete Comparison with Missing Factors
    1024: 697,  # Comparison of Incompatible Types
    1025: 697,  # Comparison Using Wrong Factors
    1077: 697,  # Floating Point Comparison with Incorrect Operator

    # --- Root Pillar CWE-703: Improper Check or Handling of Exceptional Conditions (21 weaknesses) ---
    7: 703,  # J2EE Misconfiguration: Missing Custom Error Page
    12: 703,  # ASP.NET Misconfiguration: Missing Custom Error Page
    252: 703,  # Unchecked Return Value
    273: 703,  # Improper Check for Dropped Privileges
    274: 703,  # Improper Handling of Insufficient Privileges
    280: 703,  # Improper Handling of Insufficient Permissions or Privileges
    390: 703,  # Detection of Error Condition Without Action
    391: 703,  # Unchecked Error Condition
    392: 703,  # Missing Report of Error Condition
    394: 703,  # Unexpected Status Code or Return Value
    544: 703,  # Missing Standardized Error Handling Mechanism
    690: 703,  # Unchecked Return Value to NULL Pointer Dereference
    703: 703,  # Improper Check or Handling of Exceptional Conditions (Root Pillar)
    754: 703,  # Improper Check for Unusual or Exceptional Conditions
    755: 703,  # Improper Handling of Exceptional Conditions
    756: 703,  # Missing Custom Error Page
    1247: 703,  # Improper Protection Against Voltage and Clock Glitches
    1261: 703,  # Improper Handling of Single Event Upsets
    1332: 703,  # Improper Handling of Faults that Lead to Instruction Skips
    1351: 703,  # Improper Handling of Hardware Behavior in Exceptionally Cold Environments
    1384: 703,  # Improper Handling of Physical or Environmental Conditions

    # --- Root Pillar CWE-707: Improper Neutralization (129 weaknesses) ---
    20: 707,  # Improper Input Validation
    74: 707,  # Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')
    75: 707,  # Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)
    76: 707,  # Improper Neutralization of Equivalent Special Elements
    77: 707,  # Improper Neutralization of Special Elements used in a Command ('Command Injection')
    78: 707,  # Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
    79: 707,  # Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
    80: 707,  # Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
    81: 707,  # Improper Neutralization of Script in an Error Message Web Page
    82: 707,  # Improper Neutralization of Script in Attributes of IMG Tags in a Web Page
    83: 707,  # Improper Neutralization of Script in Attributes in a Web Page
    84: 707,  # Improper Neutralization of Encoded URI Schemes in a Web Page
    85: 707,  # Doubled Character XSS Manipulations
    86: 707,  # Improper Neutralization of Invalid Characters in Identifiers in Web Pages
    87: 707,  # Improper Neutralization of Alternate XSS Syntax
    88: 707,  # Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')
    89: 707,  # Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
    90: 707,  # Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')
    91: 707,  # XML Injection (aka Blind XPath Injection)
    93: 707,  # Improper Neutralization of CRLF Sequences ('CRLF Injection')
    94: 707,  # Improper Control of Generation of Code ('Code Injection')
    95: 707,  # Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
    96: 707,  # Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')
    97: 707,  # Improper Neutralization of Server-Side Includes (SSI) Within a Web Page
    99: 707,  # Improper Control of Resource Identifiers ('Resource Injection')
    102: 707,  # Struts: Duplicate Validation Forms
    105: 707,  # Struts: Form Field Without Validator
    106: 707,  # Struts: Plug-in Framework not in Use
    108: 707,  # Struts: Unvalidated Action Form
    109: 707,  # Struts: Validator Turned Off
    112: 707,  # Missing XML Validation
    113: 707,  # Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting')
    116: 707,  # Improper Encoding or Escaping of Output
    117: 707,  # Improper Output Neutralization for Logs
    129: 707,  # Improper Validation of Array Index
    130: 707,  # Improper Handling of Length Parameter Inconsistency
    138: 707,  # Improper Neutralization of Special Elements
    140: 707,  # Improper Neutralization of Delimiters
    141: 707,  # Improper Neutralization of Parameter/Argument Delimiters
    142: 707,  # Improper Neutralization of Value Delimiters
    143: 707,  # Improper Neutralization of Record Delimiters
    144: 707,  # Improper Neutralization of Line Delimiters
    145: 707,  # Improper Neutralization of Section Delimiters
    146: 707,  # Improper Neutralization of Expression/Command Delimiters
    147: 707,  # Improper Neutralization of Input Terminators
    148: 707,  # Improper Neutralization of Input Leaders
    149: 707,  # Improper Neutralization of Quoting Syntax
    150: 707,  # Improper Neutralization of Escape, Meta, or Control Sequences
    151: 707,  # Improper Neutralization of Comment Delimiters
    152: 707,  # Improper Neutralization of Macro Symbols
    153: 707,  # Improper Neutralization of Substitution Characters
    154: 707,  # Improper Neutralization of Variable Name Delimiters
    155: 707,  # Improper Neutralization of Wildcards or Matching Symbols
    156: 707,  # Improper Neutralization of Whitespace
    157: 707,  # Failure to Sanitize Paired Delimiters
    158: 707,  # Improper Neutralization of Null Byte or NUL Character
    159: 707,  # Improper Handling of Invalid Use of Special Elements
    160: 707,  # Improper Neutralization of Leading Special Elements
    161: 707,  # Improper Neutralization of Multiple Leading Special Elements
    162: 707,  # Improper Neutralization of Trailing Special Elements
    163: 707,  # Improper Neutralization of Multiple Trailing Special Elements
    164: 707,  # Improper Neutralization of Internal Special Elements
    165: 707,  # Improper Neutralization of Multiple Internal Special Elements
    166: 707,  # Improper Handling of Missing Special Element
    167: 707,  # Improper Handling of Additional Special Element
    168: 707,  # Improper Handling of Inconsistent Special Elements
    170: 707,  # Improper Null Termination
    172: 707,  # Encoding Error
    173: 707,  # Improper Handling of Alternate Encoding
    175: 707,  # Improper Handling of Mixed Encoding
    176: 707,  # Improper Handling of Unicode Encoding
    177: 707,  # Improper Handling of URL Encoding (Hex Encoding)
    182: 707,  # Collapse of Data into Unsafe Value
    228: 707,  # Improper Handling of Syntactically Invalid Structure
    229: 707,  # Improper Handling of Values
    230: 707,  # Improper Handling of Missing Values
    231: 707,  # Improper Handling of Extra Values
    232: 707,  # Improper Handling of Undefined Values
    233: 707,  # Improper Handling of Parameters
    234: 707,  # Failure to Handle Missing Parameter
    235: 707,  # Improper Handling of Extra Parameters
    236: 707,  # Improper Handling of Undefined Parameters
    237: 707,  # Improper Handling of Structural Elements
    238: 707,  # Improper Handling of Incomplete Structural Elements
    239: 707,  # Failure to Handle Incomplete Element
    240: 707,  # Improper Handling of Inconsistent Structural Elements
    241: 707,  # Improper Handling of Unexpected Data Type
    462: 707,  # Duplicate Key in Associative List (Alist)
    463: 707,  # Deletion of Data Structure Sentinel
    464: 707,  # Addition of Data Structure Sentinel
    554: 707,  # ASP.NET Misconfiguration: Not Using Input Validation Framework
    564: 707,  # SQL Injection: Hibernate
    606: 707,  # Unchecked Input for Loop Condition
    621: 707,  # Variable Extraction Error
    622: 707,  # Improper Validation of Function Hook Arguments
    624: 707,  # Executable Regular Expression Error
    626: 707,  # Null Byte Interaction Error (Poison Null Byte)
    627: 707,  # Dynamic Variable Evaluation
    641: 707,  # Improper Restriction of Names for Files and Other Resources
    643: 707,  # Improper Neutralization of Data within XPath Expressions ('XPath Injection')
    644: 707,  # Improper Neutralization of HTTP Headers for Scripting Syntax
    652: 707,  # Improper Neutralization of Data within XQuery Expressions ('XQuery Injection')
    694: 707,  # Use of Multiple Resources with Duplicate Identifier
    707: 707,  # Improper Neutralization (Root Pillar)
    781: 707,  # Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code
    790: 707,  # Improper Filtering of Special Elements
    791: 707,  # Incomplete Filtering of Special Elements
    792: 707,  # Incomplete Filtering of One or More Instances of Special Elements
    793: 707,  # Only Filtering One Instance of a Special Element
    794: 707,  # Incomplete Filtering of Multiple Instances of Special Elements
    795: 707,  # Only Filtering Special Elements at a Specified Location
    796: 707,  # Only Filtering Special Elements Relative to a Marker
    797: 707,  # Only Filtering Special Elements at an Absolute Position
    838: 707,  # Inappropriate Encoding for Output Context
    914: 707,  # Improper Control of Dynamically-Identified Variables
    917: 707,  # Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')
    943: 707,  # Improper Neutralization of Special Elements in Data Query Logic
    1173: 707,  # Improper Use of Validation Framework
    1174: 707,  # ASP.NET Misconfiguration: Improper Model Validation
    1236: 707,  # Improper Neutralization of Formula Elements in a CSV File
    1284: 707,  # Improper Validation of Specified Quantity in Input
    1285: 707,  # Improper Validation of Specified Index, Position, or Offset in Input
    1286: 707,  # Improper Validation of Syntactic Correctness of Input
    1287: 707,  # Improper Validation of Specified Type of Input
    1288: 707,  # Improper Validation of Consistency within Input
    1289: 707,  # Improper Validation of Unsafe Equivalence in Input
    1336: 707,  # Improper Neutralization of Special Elements Used in a Template Engine
    1426: 707,  # Improper Validation of Generative AI Output
    1427: 707,  # Improper Neutralization of Input Used for LLM Prompting

    # --- Root Pillar CWE-710: Improper Adherence to Coding Standards (165 weaknesses) ---
    11: 710,  # ASP.NET Misconfiguration: Creating Debug Binary
    103: 710,  # Struts: Incomplete validate() Method Definition
    104: 710,  # Struts: Form Bean Does Not Extend Validation Class
    107: 710,  # Struts: Unused Validation Form
    110: 710,  # Struts: Validator Without Form Field
    111: 710,  # Direct Use of Unsafe JNI
    174: 710,  # Double Decoding of the Same Data
    188: 710,  # Reliance on Data/Memory Layout
    198: 710,  # Use of Incorrect Byte Ordering
    242: 710,  # Use of Inherently Dangerous Function
    245: 710,  # J2EE Bad Practices: Direct Management of Connections
    246: 710,  # J2EE Bad Practices: Direct Use of Sockets
    253: 710,  # Incorrect Check of Function Return Value
    358: 710,  # Improperly Implemented Security Check for Standard
    383: 710,  # J2EE Bad Practices: Direct Use of Threads
    393: 710,  # Return of Wrong Status Code
    424: 710,  # Improper Protection of Alternate Path
    440: 710,  # Expected Behavior Violation
    446: 710,  # UI Discrepancy for Security Feature
    447: 710,  # Unimplemented or Unsupported Feature in UI
    448: 710,  # Obsolete Feature in UI
    449: 710,  # The UI Performs the Wrong Action
    451: 710,  # User Interface (UI) Misrepresentation of Critical Information
    474: 710,  # Use of Function with Inconsistent Implementations
    475: 710,  # Undefined Behavior for Input to API
    476: 710,  # NULL Pointer Dereference
    477: 710,  # Use of Obsolete Function
    484: 710,  # Omitted Break Statement in Switch
    489: 710,  # Active Debug Code
    506: 710,  # Embedded Malicious Code
    507: 710,  # Trojan Horse
    508: 710,  # Non-Replicating Malicious Code
    509: 710,  # Replicating Malicious Code (Virus or Worm)
    510: 710,  # Trapdoor
    511: 710,  # Logic/Time Bomb
    512: 710,  # Spyware
    546: 710,  # Suspicious Comment
    547: 710,  # Use of Hard-coded, Security-relevant Constants
    560: 710,  # Use of umask() with chmod-style Argument
    561: 710,  # Dead Code
    562: 710,  # Return of Stack Variable Address
    563: 710,  # Assignment to Variable without Use
    570: 710,  # Expression is Always False
    571: 710,  # Expression is Always True
    573: 710,  # Improper Following of Specification by Caller
    575: 710,  # EJB Bad Practices: Use of AWT Swing
    576: 710,  # EJB Bad Practices: Use of Java I/O
    577: 710,  # EJB Bad Practices: Use of Sockets
    578: 710,  # EJB Bad Practices: Use of Class Loader
    579: 710,  # J2EE Bad Practices: Non-serializable Object Stored in Session
    581: 710,  # Object Model Violation: Just One of Equals and Hashcode Defined
    585: 710,  # Empty Synchronized Block
    586: 710,  # Explicit Call to Finalize()
    587: 710,  # Assignment of a Fixed Address to a Pointer
    589: 710,  # Call to Non-ubiquitous API
    594: 710,  # J2EE Framework: Saving Unserializable Objects to Disk
    605: 710,  # Multiple Binds to the Same Port
    628: 710,  # Function Call with Incorrectly Specified Arguments
    636: 710,  # Not Failing Securely ('Failing Open')
    637: 710,  # Unnecessary Complexity in Protection Mechanism (Not Using 'Economy of Mechanism')
    638: 710,  # Not Using Complete Mediation
    653: 710,  # Improper Isolation or Compartmentalization
    654: 710,  # Reliance on a Single Factor in a Security Decision
    655: 710,  # Insufficient Psychological Acceptability
    656: 710,  # Reliance on Security Through Obscurity
    657: 710,  # Violation of Secure Design Principles
    671: 710,  # Lack of Administrator Control over Security
    675: 710,  # Multiple Operations on Resource in Single-Operation Context
    676: 710,  # Use of Potentially Dangerous Function
    683: 710,  # Function Call With Incorrect Order of Arguments
    684: 710,  # Incorrect Provision of Specified Functionality
    685: 710,  # Function Call With Incorrect Number of Arguments
    686: 710,  # Function Call With Incorrect Argument Type
    687: 710,  # Function Call With Incorrectly Specified Argument Value
    688: 710,  # Function Call With Incorrect Variable or Reference as Argument
    695: 710,  # Use of Low-Level Functionality
    710: 710,  # Improper Adherence to Coding Standards (Root Pillar)
    758: 710,  # Reliance on Undefined, Unspecified, or Implementation-Defined Behavior
    785: 710,  # Use of Path Manipulation Function without Maximum-sized Buffer
    912: 710,  # Hidden Functionality
    1007: 710,  # Insufficient Visual Distinction of Homoglyphs Presented to User
    1041: 710,  # Use of Redundant Code
    1043: 710,  # Data Element Aggregating an Excessively Large Number of Non-Primitive Elements
    1044: 710,  # Architecture with Number of Horizontal Layers Outside of Expected Range
    1045: 710,  # Parent Class with a Virtual Destructor and a Child Class without a Virtual Destructor
    1047: 710,  # Modules with Circular Dependencies
    1048: 710,  # Invokable Control Element with Large Number of Outward Calls
    1053: 710,  # Missing Documentation for Design
    1054: 710,  # Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer
    1055: 710,  # Multiple Inheritance from Concrete Classes
    1056: 710,  # Invokable Control Element with Variadic Parameters
    1057: 710,  # Data Access Operations Outside of Expected Data Manager Component
    1059: 710,  # Insufficient Technical Documentation
    1060: 710,  # Excessive Number of Inefficient Server-Side Data Accesses
    1061: 710,  # Insufficient Encapsulation
    1062: 710,  # Parent Class with References to Child Class
    1064: 710,  # Invokable Control Element with Signature Containing an Excessive Number of Parameters
    1065: 710,  # Runtime Resource Management Control Element in a Component Built to Run on Application Servers
    1066: 710,  # Missing Serialization Control Element
    1068: 710,  # Inconsistency Between Implementation and Documented Design
    1069: 710,  # Empty Exception Block
    1070: 710,  # Serializable Data Element Containing non-Serializable Item Elements
    1071: 710,  # Empty Code Block
    1074: 710,  # Class with Excessively Deep Inheritance
    1075: 710,  # Unconditional Control Flow Transfer outside of Switch Block
    1076: 710,  # Insufficient Adherence to Expected Conventions
    1078: 710,  # Inappropriate Source Code Style or Formatting
    1079: 710,  # Parent Class without Virtual Destructor Method
    1080: 710,  # Source Code File with Excessive Number of Lines of Code
    1082: 710,  # Class Instance Self Destruction Control Element
    1083: 710,  # Data Access from Outside Expected Data Manager Component
    1085: 710,  # Invokable Control Element with Excessive Volume of Commented-out Code
    1086: 710,  # Class with Excessive Number of Child Classes
    1087: 710,  # Class with Virtual Method without a Virtual Destructor
    1090: 710,  # Method Containing Access of a Member Element from Another Class
    1092: 710,  # Use of Same Invokable Control Element in Multiple Architectural Layers
    1093: 710,  # Excessively Complex Data Representation
    1095: 710,  # Loop Condition Value Update within the Loop
    1097: 710,  # Persistent Storable Data Element without Associated Comparison Control Element
    1098: 710,  # Data Element containing Pointer Item without Proper Copy Control Element
    1099: 710,  # Inconsistent Naming Conventions for Identifiers
    1100: 710,  # Insufficient Isolation of System-Dependent Functions
    1101: 710,  # Reliance on Runtime Component in Generated Code
    1102: 710,  # Reliance on Machine-Dependent Data Representation
    1103: 710,  # Use of Platform-Dependent Third Party Components
    1104: 710,  # Use of Unmaintained Third Party Components
    1105: 710,  # Insufficient Encapsulation of Machine-Dependent Functionality
    1106: 710,  # Insufficient Use of Symbolic Constants
    1107: 710,  # Insufficient Isolation of Symbolic Constant Definitions
    1108: 710,  # Excessive Reliance on Global Variables
    1109: 710,  # Use of Same Variable for Multiple Purposes
    1110: 710,  # Incomplete Design Documentation
    1111: 710,  # Incomplete I/O Documentation
    1112: 710,  # Incomplete Documentation of Program Execution
    1113: 710,  # Inappropriate Comment Style
    1114: 710,  # Inappropriate Whitespace Style
    1115: 710,  # Source Code Element without Standard Prologue
    1116: 710,  # Inaccurate Source Code Comments
    1117: 710,  # Callable with Insufficient Behavioral Summary
    1118: 710,  # Insufficient Documentation of Error Handling Techniques
    1119: 710,  # Excessive Use of Unconditional Branching
    1120: 710,  # Excessive Code Complexity
    1121: 710,  # Excessive McCabe Cyclomatic Complexity
    1122: 710,  # Excessive Halstead Complexity
    1123: 710,  # Excessive Use of Self-Modifying Code
    1124: 710,  # Excessively Deep Nesting
    1125: 710,  # Excessive Attack Surface
    1126: 710,  # Declaration of Variable with Unnecessarily Wide Scope
    1127: 710,  # Compilation with Insufficient Warnings or Errors
    1164: 710,  # Irrelevant Code
    1177: 710,  # Use of Prohibited Code
    1189: 710,  # Improper Isolation of Shared Resources on System-on-a-Chip (SoC)
    1192: 710,  # Improper Identifier for IP Block used in System-On-Chip (SOC)
    1209: 710,  # Failure to Disable Reserved Bits
    1242: 710,  # Inclusion of Undocumented Features or Chicken Bits
    1245: 710,  # Improper Finite State Machines (FSMs) in Hardware Logic
    1277: 710,  # Firmware Not Updateable
    1303: 710,  # Non-Transparent Sharing of Microarchitectural Resources
    1310: 710,  # Missing Ability to Patch ROM Code
    1329: 710,  # Reliance on Component That is Not Updateable
    1331: 710,  # Improper Isolation of Shared Resources in Network On Chip (NoC)
    1341: 710,  # Multiple Releases of Same Resource or Handle
    1357: 710,  # Reliance on Insufficiently Trustworthy Component
    1395: 710,  # Dependency on Vulnerable Third-Party Component
    1434: 710,  # Insecure Setting of Generative AI/ML Model Inference Parameters
}

__all__ = ["WEAKNESS_TO_ROOT_PILLAR"]
