# Mt. Gox 2011 Codebase Analysis

This repository contains forensic analysis of the Mt. Gox Bitcoin Exchange codebase from 2010-2011, conducted using Claude AI. The analysis incorporates the original source code, hacker-leaked database dumps from the June 2011 breach, server logs, and git commit history to provide a comprehensive security assessment of the world's first major cryptocurrency exchange.

## Executive Summary

This analysis examines the **Mt. Gox Bitcoin Exchange** codebase developed by Jed McCaleb between November 2010 and February 2011. The platform was a moderately sophisticated financial application built with PHP (Lithium framework) that was successfully attacked in June 2011, demonstrating the real-world impact of security vulnerabilities and the effectiveness of partial remediation efforts.

### Key Findings

**Attack Timeline & Impact:**
- **June 18, 2011**: Mt. Gox shut down following database compromise
- **Attack Vector**: SQL injection in undocumented WordPress installation allowed complete database dump
- **Outcome**: ~2,000 BTC stolen through early withdrawals; market price crashed from $17 to $0.01
- **Prevented Loss**: Tens of thousands of BTC saved through security improvements implemented March-May 2011

**Security Improvements That Limited Damage:**
1. **Password Hashing Upgrade** (March 2011): Migrated from unsalted MD5 to salted crypt() via lazy migration
   - Prevented mass password compromise via rainbow tables
   - Forced attackers to brute-force passwords individually
   - Appropriate solution for 2011 constrained PHP environment
2. **SQL Injection Remediation**: Fixed vulnerabilities throughout main application
   - Prevented direct database manipulation after initial breach
3. **Race Condition Fixes**: Implemented proper locking around withdrawals
   - **Critical Success**: Blocked attempted exploitation of $1000/day withdrawal limit
   - With BTC at $0.01, attackers attempted to withdraw 100,000 BTC/day but were prevented by lock contention

**Contributing Factors to Breach:**
- Original platform built with weak security (unsalted MD5, SQL injections, race conditions)
- Undocumented WordPress installation shared database credentials with main application
- Retained admin access for "audits" after ownership transfer to Mark Karpelès
- **Weak password for admin account** (UserID=1) despite proper salting - brute-forced within days
- Documentation gap during ownership transfer left WordPress unsecured

**Forensic Evidence:**
The analysis leverages unique direct evidence from leaked data published by attackers:
- Database dump showing mixed password hashes (salted `$1$...` vs. plain MD5)
- Server logs confirming Chinese IP (125.214.251.194) accessing compromised admin account
- Leaked archive timestamps showing multi-week password cracking effort (June 18 - July 3)
- Git commit history documenting security improvements between February-June 2011
- Final commit: `"CLOSING MTGOX DUE TO COMPROMISED USER DATABASE"`

### Technical Assessment

**Architecture**: Clean MVC design using Lithium framework enabled complete backend rewrite in 2 weeks post-breach

**Security Vulnerabilities** (Original Codebase):
- Multiple SQL injection points (63 files using `mysql_query()`)
- Weak password hashing (unsalted MD5)
- Race conditions in financial transactions
- Missing input validation
- Insecure session management

**Remediation Effectiveness**:
- Password hashing: Salted implementation worked correctly; weak user passwords remained vulnerable to brute force (fundamental limitation)
- SQL injection: Main app secured; WordPress remained unknown/vulnerable
- Withdrawal locking: Successfully prevented catastrophic withdrawal exploit despite $0.01 price manipulation

### Historical Context

This codebase predates the infamous 2014 Mt. Gox collapse (850,000 BTC lost). The June 2011 breach was the **first major cryptocurrency exchange security incident**, demonstrating that incremental security improvements have measurable impact even when perfect security isn't achieved.

**Timeline:**
- **Nov 2010 - Feb 2011**: Original development by Jed McCaleb
- **March 2011**: Mt. Gox sold to Mark Karpelès
- **March-May 2011**: Security improvements implemented
- **June 2011**: Database compromised via WordPress SQL injection
- **Post-breach**: Complete backend rewrite; platform resumed operations
- **February 2014**: Separate collapse incident (different codebase, unrelated issues)

### Key Lessons

1. **Defense in depth works**: Multiple security layers prevented total loss even with database compromise
2. **Prioritization matters**: Focusing on critical fixes (locking, SQL injection, password hashing) limited damage
3. **Documentation is security-critical**: Unknown components (WordPress) cannot be secured
4. **Password strength is user responsibility**: Even proper hashing cannot protect weak passwords from brute force
5. **Quick incident response**: Shutdown prevented extended exploitation of discovered vulnerabilities
6. **Legacy access is dangerous**: Retained admin accounts create unnecessary risk after ownership transfer

## Full Analysis

For the complete technical analysis including:
- Detailed code structure and architecture review
- Comprehensive security vulnerability assessment
- Git history and development timeline
- Attack chain reconstruction with forensic evidence
- Security improvement documentation
- Lessons learned and recommendations

See **[REPORT.md](REPORT.md)** for the full 1,100+ line analysis.

## Analysis Methodology

This analysis was conducted using:
- **Claude AI** (Anthropic) for code review and security assessment
- **Source Materials**:
  - Original Mt. Gox codebase (2010-2011)
  - Git commit history with security improvement documentation
  - Hacker-leaked database dumps (published July 2011)
  - Server logs showing unauthorized access
  - Public information about the June 2011 breach

The combination of source code access and real-world breach data provides unique insight into how theoretical vulnerabilities translate into actual attacks and how partial security improvements can limit damage.

## Repository Purpose

This analysis serves as:
- Historical documentation of early cryptocurrency infrastructure
- Case study in vulnerability remediation under time constraints
- Educational resource demonstrating defense-in-depth principles
- Forensic analysis showing the gap between security theory and practice

---

**Note**: This is historical analysis for educational purposes. The codebase contains critical security vulnerabilities and should not be used as a template for modern applications.

**Analysis Date**: October 27, 2025
