# Cybersecurity Tools Suite

A comprehensive collection of threat intelligence and security analysis tools for Cybersecurity professionals.

## 🛠️ Tools Included

### 1. Shodan Threat Intelligence Tool
Advanced threat intelligence gathering using Shodan's database of internet-connected devices.

### 2. Shodan Exploit Search Module
Dedicated exploit database search with advanced filtering and analysis capabilities.

### 3. MITRE ATLAS Tool
AI/ML security threat analysis using MITRE's Adversarial Threat Landscape for Artificial Intelligence Systems (ATLAS) framework.

---

## 📊 Shodan Threat Intelligence Tool

### Features

#### 🔐 Secure Authentication
- **API Key Protection**: Uses `getpass` to hide API key during input
- **Authentication Validation**: Verifies API key and displays account information
- **Session Management**: Maintains secure connection throughout session

#### 🔍 20 Threat Intelligence Functions

1. **Host Lookup** - Get comprehensive information on any IP address
   - Organization details
   - Operating system detection
   - Open ports and services
   - Vulnerability detection
   - Geographic location

2. **Search Shodan** - Advanced database searches
   - Custom query support
   - Filters by country, city, port, product
   - Banner analysis
   - Vulnerability correlation

3. **Search Exploits** - Dedicated exploit database (Advanced Module)
   - CVE number search
   - Keyword-based discovery
   - Advanced filtering (type, platform, port)
   - Multiple output formats (text, JSON)
   - Export capabilities

4. **Count Search Results** - Query result statistics
   - Total result counts
   - Geographic distribution
   - Faceted analysis

5. **DNS Lookup** - Forward DNS resolution
   - Domain to IP translation
   - Multiple record support

6. **DNS Reverse** - Reverse DNS lookup
   - IP to domain mapping
   - PTR record analysis

7. **Get Ports** - List all monitored ports
   - Comprehensive port list
   - Shodan crawling scope

8. **Get Protocols** - Available protocol filters
   - Supported protocols
   - Filter documentation

9. **Get Services** - Service fingerprinting data
   - Service identification
   - Version detection

10. **Account Info** - View account details
    - Plan information
    - Credit balance
    - Usage statistics

11. **API Plan Info** - Detailed plan features
    - Rate limits
    - Feature availability
    - Usage quotas

12. **Search Facets** - Available search facets
    - Filtering options
    - Aggregation capabilities

13. **Search Filters** - Query filter documentation
    - Syntax guide
    - Example queries

14. **Honeypot Score** - Honeypot probability detection
    - Score calculation (0.0 - 1.0)
    - Risk assessment
    - False positive reduction

15. **Query Tags** - Popular search tags
    - Trending queries
    - Community insights

16. **Scan Internet** - Submit IPs for scanning
    - On-demand scans
    - Scan queue management

17. **Scan Status** - Check scan progress
    - Real-time status
    - Result retrieval

18. **Network Alerts** - List configured alerts
    - Alert management
    - Notification settings

19. **Create Alert** - Set up network monitoring
    - CIDR range support
    - Custom alert rules

20. **Notifier List** - Available notification channels
    - Email, Slack, webhook support
    - Integration options

#### 💻 User-Friendly Interface
- **Clean UI**: Clear screen between operations
- **Visual Formatting**: Organized output with separators
- **Error Handling**: Comprehensive error catching for all operations
- **User Control**: Pause after each operation
- **Interactive Menus**: Intuitive navigation

#### 🛡️ Error Handling
- API error handling with user-friendly messages
- Network timeout management
- JSON parsing error recovery
- Rate limit detection and notification
- Graceful degradation

---

## 🔎 Shodan Exploit Search Module

### Features

#### 🎯 Advanced Search Capabilities
- **CVE Search**: Exact CVE number matching (e.g., CVE-2021-44228)
- **Keyword Search**: Natural language queries
- **Advanced Filters**: 
  - Exploit type (remote, local, webapps)
  - Platform (Windows, Linux, PHP, etc.)
  - Port number
  - Author name

#### 📊 Multiple Output Formats
1. **Text Output (Summary)** - Concise information display
2. **Text Output (Detailed)** - Comprehensive analysis
3. **JSON Output** - Machine-readable format
4. **File Export** - Save results (JSON/TXT)

#### 📈 Data Analysis
- **Statistics Generation**:
  - Total results and CVE counts
  - Exploit type distribution
  - Platform breakdown
  - Source attribution
  - Code availability metrics

#### 🔧 Intelligent Parsing
- Automatic CVE format detection
- Robust JSON handling
- Missing data graceful handling
- Unicode support

#### 🚨 Error Recovery
- API error handling with suggestions
- JSON parsing fallbacks
- Rate limit detection
- Connection retry logic

---

## 🤖 MITRE ATLAS Tool

### Overview
MITRE ATLAS (Adversarial Threat Landscape for Artificial Intelligence Systems) provides a knowledge base of adversary tactics and techniques targeting AI/ML systems.

### Features

#### 🔍 Search & Discovery
1. **Technique Search by Keyword**
   - Natural language queries
   - Description matching
   - Partial name matching

2. **Technique Lookup by ID**
   - Direct ATLAS ID search (e.g., AML.T0043)
   - Fast exact matching

3. **List All Techniques**
   - Summary view (technique names and IDs)
   - Detailed view (full descriptions)
   - Organized display

4. **List All Tactics**
   - Complete ATLAS kill chain
   - Tactic descriptions
   - ATLAS ID references

5. **Filter by Tactic**
   - Get techniques for specific tactics
   - Kill chain phase analysis

#### 📋 ATLAS Kill Chain (12 Tactics)

1. **Reconnaissance (AML.TA0001)**
   - Gather information about ML systems
   - Identify model architecture
   - Discover training data sources

2. **Resource Development (AML.TA0002)**
   - Develop attack capabilities
   - Create adversarial examples
   - Build attack infrastructure

3. **Initial Access (AML.TA0003)**
   - Compromise ML systems
   - Exploit model APIs
   - Supply chain attacks

4. **ML Model Access (AML.TA0004)**
   - Gain access to model artifacts
   - Extract model parameters
   - Query model APIs

5. **Execution (AML.TA0005)**
   - Run malicious code
   - Execute model attacks
   - Trigger backdoors

6. **Persistence (AML.TA0006)**
   - Maintain access
   - Install backdoors
   - Compromise model updates

7. **Defense Evasion (AML.TA0007)**
   - Avoid detection systems
   - Evade ML-based security
   - Hide malicious behavior

8. **Discovery (AML.TA0008)**
   - Learn about ML environment
   - Discover model family
   - Identify vulnerabilities

9. **Collection (AML.TA0009)**
   - Gather training data
   - Extract sensitive information
   - Model inversion attacks

10. **ML Attack Staging (AML.TA0010)**
    - Prepare model attacks
    - Craft adversarial examples
    - Poison training data

11. **Exfiltration (AML.TA0011)**
    - Steal model weights
    - Extract training data
    - Leak sensitive information

12. **Impact (AML.TA0012)**
    - Disrupt ML services
    - Manipulate model outputs
    - Deny service availability

#### 🎯 Key ATLAS Techniques Included

- **AML.T0043**: Adversarial Example Generation
- **AML.T0044**: Model Inversion
- **AML.T0020**: Data Poisoning
- **AML.T0018**: Model Backdoor
- **AML.T0057**: Model Extraction
- **AML.T0045**: Membership Inference
- **AML.T0010**: Supply Chain Compromise
- **AML.T0015**: Evade ML Model
- **AML.T0033**: Discover ML Model Family
- **AML.T0049**: Denial of ML Service

#### 💾 Data Management
- **Export to JSON**: Save technique/tactic data
- **Export Options**: 
  - Full ATLAS data
  - Techniques only
  - Tactics only
- **UTF-8 Support**: International character handling

#### 📊 Statistics & Analytics
- Total technique count
- Total tactic count
- Mitigation availability
- Case study references
- Technique distribution by tactic

#### 🔄 Data Sources
- **Primary**: MITRE ATLAS GitHub repository
- **Fallback**: ATLAS website API
- **Offline Mode**: Pre-loaded sample techniques
- **Auto-refresh**: Update data on demand

---

## 🚀 Installation

### Prerequisites
```bash
# Python 3.7 or higher required
python --version
